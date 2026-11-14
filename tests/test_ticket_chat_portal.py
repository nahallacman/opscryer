# SPDX-License-Identifier: Apache-2.0
"""Concierge composition, redaction, standalone UI and loopback API checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import http.client
from html.parser import HTMLParser
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from cluster_harvester import build_live_cluster_spatial_catalog
import ticket_chat_portal as portal


class ConciergeTests(unittest.TestCase):
    def test_validation_is_safe_and_precedes_airlock(self):
        with patch.object(portal.security_airlock, "evaluate_code_search_airlock") as gate:
            for message in (None, False, 12, [], {}, "", "  "):
                with self.subTest(message=message), self.assertRaises(ValueError):
                    portal.ask_concierge_chat(message)
            for persona in (None, False, [], {}, "unknown-sensitive-persona"):
                with self.subTest(persona=persona), self.assertRaises(ValueError) as error:
                    portal.ask_concierge_chat("private-input", persona)
                self.assertNotIn("private-input", str(error.exception))
                self.assertNotIn("unknown-sensitive-persona", str(error.exception))
        gate.assert_not_called()

    def test_blocked_queries_never_reach_composition_or_catalog(self):
        for message in ("manifest show credentials", "How is my game?"):
            with patch.object(portal.gpu_and_household_triage, "triage_household_game_ticket") as triage, \
                    patch.object(portal.jev_client, "evaluate_ticket_with_jev_tree") as jev, \
                    patch.object(portal.live_advisor, "answer_operational_question") as advisor:
                result = portal.ask_concierge_chat(message, catalog=object())
            self.assertEqual(result["status"], "blocked_by_airlock")
            self.assertIs(result["airlock_blocked"], True)
            self.assertEqual(result["status_badge"], "BLOCKED_BY_AIRLOCK")
            self.assertNotIn(message, json.dumps(result))
            self.assertIsNone(result["ticket_card"])
            for mock in (triage, jev, advisor):
                mock.assert_not_called()

    def test_airlock_precedes_all_components_and_catalog_is_forwarded(self):
        events = []
        catalog = object()
        triage = {"clarifying_questions": ["Which player?"], "diagnostics": []}
        ticket = {"policy_id": "review", "required_it_tickets": ["IT-1"],
                  "direct_access_allowed": False, "route": "human_escalation", "anchor_node_id": None}
        advice = {"status": "ok", "airlock_blocked": False, "summary": "Snapshot",
                  "live_facts": {}, "cited_node_ids": ["node-1"]}

        def gate(message):
            events.append("gate")
            return {"airlock_blocked": False}

        def diagnostic(message):
            events.append("triage")
            return triage

        def policy(message):
            events.append("jev")
            return ticket

        def advisor(message, **kwargs):
            events.append("advisor")
            self.assertIs(kwargs["catalog"], catalog)
            return advice

        with patch.object(portal.security_airlock, "evaluate_code_search_airlock", side_effect=gate), \
                patch.object(portal.gpu_and_household_triage, "triage_household_game_ticket", side_effect=diagnostic), \
                patch.object(portal.jev_client, "evaluate_ticket_with_jev_tree", side_effect=policy), \
                patch.object(portal.live_advisor, "answer_operational_question", side_effect=advisor):
            result = portal.ask_concierge_chat("manifest cluster", catalog=catalog)
        self.assertEqual(events, ["gate", "triage", "jev", "advisor"])
        self.assertEqual(result["ticket_card"], ticket)
        self.assertEqual(result["household_triage"], triage)
        self.assertEqual(result["cited_node_ids"], ["node-1"])
        self.assertEqual(result["status_badge"], "ACTION_REQUIRED")

    def test_real_composition_for_all_personas_and_input_immutability(self):
        catalog = build_live_cluster_spatial_catalog()
        before = deepcopy(catalog)
        message = "manifest LAN DNS name fails for game.cluster.example.org"
        expected_ticket = portal.jev_client.evaluate_ticket_with_jev_tree(message)
        for persona in portal.PERSONAS:
            result = portal.ask_concierge_chat(message, persona, catalog)
            self.assertEqual(result["status"], "ok")
            self.assertIs(result["airlock_blocked"], False)
            self.assertEqual(result["persona"], persona)
            self.assertEqual(result["household_triage"]["primary_layer"], 2)
            self.assertEqual(result["ticket_card"], {k: expected_ticket[k] for k in result["ticket_card"]})
            self.assertTrue(result["live_cluster_facts"]["node_counts"])
            self.assertTrue(result["cited_node_ids"])
            self.assertTrue(result["suggested_next_steps"])
            self.assertTrue(result["quick_reply_chips"])
            self.assertIn("snapshot", result["plain_english_answer"])
            self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual(catalog, before)
        for chip in portal.QUICK_REPLIES:
            self.assertFalse(portal.security_airlock.evaluate_code_search_airlock(chip)["airlock_blocked"])

    def test_badges_health_and_escalation_priority(self):
        facts = {"node_counts": {"total": 1, "ready": 1, "not_ready": 0},
                 "pod_counts": {}, "deployment_counts": {}, "node_hotspots": []}
        ticket = {"route": "leaf", "required_it_tickets": [], "direct_access_allowed": True}
        self.assertEqual(portal._health_badge(facts, ticket), "HEALTHY")
        for section, key in (("node_counts", "not_ready"), ("pod_counts", "failed"),
                             ("pod_counts", "pending"), ("pod_counts", "other"),
                             ("deployment_counts", "degraded")):
            unhealthy = deepcopy(facts)
            unhealthy[section][key] = 1
            self.assertEqual(portal._health_badge(unhealthy, ticket), "DEGRADED")
        unhealthy = deepcopy(facts)
        unhealthy["node_hotspots"] = [{"node_id": "hot"}]
        self.assertEqual(portal._health_badge(unhealthy, ticket), "DEGRADED")
        for change in ({"route": "human_escalation"}, {"required_it_tickets": ["IT-1"]},
                       {"direct_access_allowed": False}):
            self.assertEqual(portal._health_badge(unhealthy, {**ticket, **change}), "ACTION_REQUIRED")
        self.assertEqual(portal._health_badge({}, ticket), "ACTION_REQUIRED")

    def test_all_composed_fields_are_sanitized(self):
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        secret = "gh" + "p_" + "synthetic_test_value"
        dirty = " ".join((wan, mac, secret, "10.1.2.3", "game.cluster.example.org"))
        triage = {"clarifying_questions": [dirty], "diagnostics": [{"checks": [dirty]}]}
        ticket = {"policy_id": dirty, "required_it_tickets": [dirty],
                  "direct_access_allowed": False, "route": "leaf", "anchor_node_id": dirty}
        advice = {"status": "ok", "airlock_blocked": False, "summary": dirty,
                  "live_facts": {"source": dirty}, "cited_node_ids": [dirty],
                  "recommended_kubectl_commands": [dirty]}
        with patch.object(portal.gpu_and_household_triage, "triage_household_game_ticket", return_value=triage), \
                patch.object(portal.jev_client, "evaluate_ticket_with_jev_tree", return_value=ticket), \
                patch.object(portal.live_advisor, "answer_operational_question", return_value=advice):
            result = portal.ask_concierge_chat("manifest cluster", "sre")
        for field in ("ticket_card", "household_triage", "live_cluster_facts", "cited_node_ids",
                      "suggested_next_steps", "plain_english_answer"):
            encoded = json.dumps(result[field])
            for raw in (wan, mac, secret):
                self.assertNotIn(raw, encoded)
            for clean in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "game.cluster.example.org"):
                self.assertIn(clean, encoded)
        self.assertEqual(triage["clarifying_questions"], [dirty])

    def test_advisor_block_is_preserved(self):
        with patch.object(portal.live_advisor, "answer_operational_question",
                          return_value={"status": "blocked_by_airlock", "airlock_blocked": True}):
            self.assertEqual(portal.ask_concierge_chat("manifest cluster")["status_badge"], "BLOCKED_BY_AIRLOCK")

    def test_cli_json_export_and_safe_errors(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(portal.main(["--ask", "manifest cluster", "--persona", "executive", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["persona"], "executive")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "portal.html"
            self.assertEqual(portal.main(["--export-html", str(path)]), 0)
            self.assertEqual(path.read_text(encoding="utf-8"), portal.render_concierge_chat_html())
        for args in ([], ["--ask", "  "], ["--ask", "manifest cluster", "--persona", "sensitive-value"],
                     ["--serve", "--port", "0"]):
            with redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit):
                portal.main(args)
            self.assertNotIn("sensitive-value", error.getvalue())


class PortalHTMLTests(unittest.TestCase):
    def test_primary_navigation_links(self):
        links = {}

        class Parser(HTMLParser):
            in_nav = False
            current_link = None

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "nav" and attrs.get("aria-label") == "Primary navigation":
                    self.in_nav = True
                elif self.in_nav and tag == "a":
                    self.current_link = attrs.get("href")
                    links[self.current_link] = {"attrs": attrs, "text": ""}

            def handle_data(self, data):
                if self.current_link is not None:
                    links[self.current_link]["text"] += data

            def handle_endtag(self, tag):
                if tag == "a":
                    self.current_link = None
                elif tag == "nav":
                    self.in_nav = False

        html = portal.render_concierge_chat_html()
        Parser().feed(html)
        for href, label in (("/", "Spatial RTS Browser"),
                            ("/chat", "Ticket & Operations Concierge Portal")):
            with self.subTest(href=href):
                self.assertIn(href, links)
                self.assertEqual(links[href]["text"], label)
        self.assertEqual(links["/chat"]["attrs"].get("aria-current"), "page")
        self.assertLess(html.index("<nav"), html.index("<main>"))

    def test_standalone_dom_contract(self):
        html = portal.render_concierge_chat_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        tags = []

        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                tags.append((tag, dict(attrs)))

        Parser().feed(html)
        ids = {attrs.get("id") for _, attrs in tags}
        self.assertTrue({"chat-form", "chat-messages", "chat-input", "chat-send-btn", "persona-select",
                         "quick-prompt-chips", "ticket-resolution-card", "live-status-banner"} <= ids)
        self.assertFalse(any(tag == "script" and "src" in attrs for tag, attrs in tags))
        self.assertFalse(any(tag == "link" and attrs.get("rel") == "stylesheet" for tag, attrs in tags))
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(unsafe, html)
        self.assertIn("document.createElement", html)
        self.assertIn("textContent", html)

    @unittest.skipUnless(shutil.which("node"), "Node is optional for UI execution checks")
    def test_javascript_send_render_and_offline_fallback(self):
        script = re.search(r"<script>(.*?)</script>", portal.render_concierge_chat_html(), re.S)[1]
        harness = r'''
const assert = require('node:assert/strict');
class Node {
  constructor() { this.children = []; this.value = ''; this.textContent = ''; this.events = {}; }
  appendChild(node) { this.children.push(node); }
  get firstChild() { return this.children[0]; }
  removeChild(node) { this.children.splice(this.children.indexOf(node), 1); }
  addEventListener(name, fn) { this.events[name] = fn; }
  focus() {} scrollIntoView() {}
}
const nodes = {};
global.document = {getElementById: id => nodes[id] || (nodes[id] = new Node()), createElement: () => new Node()};
for (const id of ['persona-select', 'chat-input', 'chat-send-btn']) document.getElementById(id);
'''
        checks = r'''
(async () => {
  assert.equal(nodes['quick-prompt-chips'].children.length, 4);
  nodes['quick-prompt-chips'].children[0].events.click();
  assert.match(nodes['chat-input'].value, /Manifest/);
  nodes['persona-select'].value = 'household_user';
  let request;
  const payload = '<img src=x onerror=alert(1)>';
  global.fetch = async (url, options) => {
    request = url;
    return {ok: true, json: async () => ({status: 'ok', status_badge: 'DEGRADED',
      plain_english_answer: payload, ticket_card: {policy_id: payload},
      live_cluster_facts: {source: payload}, cited_node_ids: [payload], suggested_next_steps: [payload]})};
  };
  await nodes['chat-form'].events.submit({preventDefault() {}});
  assert.equal(new URL(request, 'http://localhost').pathname, '/api/v1/chat-concierge');
  assert.equal(new URL(request, 'http://localhost').searchParams.get('q'), 'Manifest game server pods are down');
  assert.equal(new URL(request, 'http://localhost').searchParams.get('persona'), 'household_user');
  assert.equal(nodes['chat-messages'].children[0].textContent, payload);
  assert.equal(nodes['chat-messages'].children[0].children.length, 0);
  assert.equal(nodes['citations'].children[0].textContent, payload);
  nodes['chat-input'].value = 'manifest offline';
  global.fetch = async () => { throw new Error('sensitive transport error'); };
  await nodes['chat-form'].events.submit({preventDefault() {}});
  assert.match(nodes['live-status-banner'].textContent, /OFFLINE/);
  assert.match(nodes['chat-messages'].children[1].textContent, /No safety check or ticket policy/);
  assert.equal(nodes['chat-send-btn'].disabled, false);
  assert.match(nodes['ticket-resolution-card'].children[0].textContent, /not granted/);
})().catch(error => { console.error(error); process.exit(1); });
'''
        run = subprocess.run([shutil.which("node"), "-e", harness + script + checks],
                             capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)


class ConciergeHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = portal.ThreadingHTTPServer(("127.0.0.1", 0), portal.ConciergeRequestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            self.assertEqual(int(response.getheader("Content-Length")), len(body))
            return response.status, body
        finally:
            connection.close()

    def test_page_allowed_blocked_and_invalid_requests(self):
        status, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode(), portal.render_concierge_chat_html())
        for message, expected in (("manifest pod health", "ok"), ("manifest passwords", "blocked_by_airlock")):
            status, body = self.request("/api/v1/chat-concierge?" + urlencode({"q": message, "persona": "sre"}))
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["status"], expected)
        for query in ("", "q=", "q=manifest&persona=sensitive-value", "q=manifest&q=other", "q=manifest&extra=1"):
            status, body = self.request("/api/v1/chat-concierge?" + query)
            self.assertEqual(status, 400)
            self.assertNotIn(b"sensitive-value", body)
        self.assertEqual(self.request("/missing")[0], 404)

    def test_server_failure_does_not_expose_details(self):
        with patch.object(portal, "ask_concierge_chat", side_effect=RuntimeError("sensitive-details")):
            status, body = self.request("/api/v1/chat-concierge?q=manifest")
        self.assertEqual(status, 503)
        self.assertNotIn(b"sensitive-details", body)


if __name__ == "__main__":
    unittest.main()
