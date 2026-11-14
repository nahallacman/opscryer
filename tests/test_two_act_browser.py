# SPDX-License-Identifier: Apache-2.0
"""Two-act status and real loopback HTTP integration tests."""

import http.client
import io
import json
import socketserver
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

import opscryer_browser as browser
import opscryer_suite_hub as suite_hub
import model_tier_copilot as model_copilot
import game_observability_loop as game_debug
import jev_knowledge_explorer as kb_explorer
import storage_zfs_cockpit as storage_cockpit
import secops_vulnerability_cockpit as secops_cockpit
import environment_adapters as adapters
from capacity_planner import render_capacity_planner_html, summarize_cluster_capacity
from chat_walkthrough import run_multi_persona_chat_walkthrough
from cluster_diff_engine import summarize_live_cluster_health
from dogfood_graph import query_node_at_progressive_zoom
from executive_command_center import (
    build_executive_posture_dossier, render_executive_command_center_html,
)
from gitops_release_cockpit import (
    evaluate_release_readiness_scorecard, render_gitops_cockpit_html,
)
from gameday_simulator import (
    list_gameday_scenarios, render_gameday_simulator_html, simulate_gameday_scenario,
)
from incident_commander import build_active_incidents_catalog, render_incident_commander_html
from live_advisor import answer_operational_question
from live_currencies import build_enriched_live_currencies
from network_topology_inspector import (
    render_network_inspector_html, trace_ingress_to_hardware_routes,
)
from oscal_compliance import build_oscal_hud_posture_report
from opscryer_suite_hub import build_suite_application_catalog, render_suite_hub_html
from playbook_studio import build_playbook_studio_catalog, render_playbook_studio_html
from telemetry_sanitizer import build_two_act_hackathon_demo_plan
from ticket_chat_portal import PERSONAS, ask_concierge_chat, render_concierge_chat_html


class TwoActStatusTests(unittest.TestCase):
    def test_portal_telemetry_provenance_preserves_snapshot_inputs(self):
        catalog = json.loads(game_debug.DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        for source in ("live_kubectl", "offline_fallback", "custom_snapshot", None):
            if source is None:
                catalog.pop("source", None)
            else:
                catalog["source"] = source
            before = json.dumps(catalog, sort_keys=True)
            expected = "live_kubectl" if source == "live_kubectl" else "offline_fallback"
            for build in (build_active_incidents_catalog, summarize_cluster_capacity,
                          game_debug.inspect_game_server_fleet,
                          lambda value: game_debug.trace_game_debugging_loop(catalog=value)):
                with self.subTest(source=source, build=build):
                    self.assertEqual(build(catalog)["telemetry_source"], expected)
            for render in (render_incident_commander_html, render_capacity_planner_html,
                           game_debug.render_game_debug_html):
                with self.subTest(source=source, render=render):
                    html = render(catalog)
                    self.assertIn('<strong id="telemetry-source">' + expected + '</strong>', html)
            self.assertEqual(json.dumps(catalog, sort_keys=True), before)

    def test_standalone_html_links_to_ticket_concierge_portal(self):
        html = browser.render_standalone_browser_html()
        body = html.split("<body>", 1)[1].split("<script>", 1)[0]
        self.assertIn('<nav class="page-navigation" aria-label="Portal navigation">', body)
        self.assertIn('<a href="/chat">Ticket Concierge Portal</a>', body)

    def test_default_and_both_acts_match_plan_without_live_connections(self):
        self.assertEqual(browser.build_two_act_browser_status(),
                         browser.build_two_act_browser_status(1))
        for act in (1, 2):
            with self.subTest(act=act):
                status = browser.build_two_act_browser_status(act)
                selected = build_two_act_hackathon_demo_plan()["acts"][act - 1]
                for key in ("act", "mode", "title", "steps"):
                    self.assertEqual(status[key], selected[key])
                self.assertFalse(status["live_connections"])
                self.assertEqual(status["telemetry_status"],
                                 "offline" if act == 1 else "not_connected")
                self.assertEqual(status["sanitizer"], selected.get("sanitizer"))
                self.assertEqual(len(status["api_routes"]), 3)
                self.assertEqual(json.loads(json.dumps(status)), status)

    def test_invalid_acts_are_rejected(self):
        for act in (None, True, False, "1", 1.0, 0, 3, [], {}):
            with self.subTest(act=act), self.assertRaises(ValueError):
                browser.build_two_act_browser_status(act)

    def test_status_is_detached(self):
        status = browser.build_two_act_browser_status(2)
        status["steps"].clear()
        status["api_routes"].clear()
        fresh = browser.build_two_act_browser_status(2)
        self.assertTrue(fresh["steps"])
        self.assertEqual(len(fresh["api_routes"]), 3)


class TwoActHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), browser._build_frontend_handler())
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
            self.assertEqual(int(response.getheader("Content-Length")), len(body))
            return response.status, response.getheader("Content-Type"), body
        finally:
            connection.close()

    def get_json(self, path, expected_status=200):
        status, content_type, body = self.request(path)
        self.assertEqual(status, expected_status)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        return json.loads(body)

    def test_eight_concurrent_metrics_requests_return_200(self):
        arrivals = threading.Barrier(8, timeout=5)

        def poll_metrics(*, allow_kubectl):
            arrivals.wait()
            return {"ok": True}

        with patch("live_metrics_poller.poll_live_cluster_metrics", side_effect=poll_metrics), \
                ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(executor.map(
                self.request, ["/api/v1/live-metrics"] * 8))

        self.assertEqual(len(responses), 8)
        for status, content_type, body in responses:
            self.assertEqual(status, 200)
            self.assertEqual(content_type, "application/json; charset=utf-8")
            self.assertEqual(json.loads(body), {"ok": True})

    def test_server_socket_can_be_reused_after_request(self):
        self.assertTrue(self.server.allow_reuse_address)
        self.assertTrue(self.server.daemon_threads)
        with browser._ReusableTCPServer(
                ("127.0.0.1", 0), browser._build_frontend_handler()) as server:
            address = server.server_address
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            connection = http.client.HTTPConnection(*address, timeout=5)
            try:
                connection.request("GET", "/api/v1/two-act-status")
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 200)
            finally:
                connection.close()
                thread.join(timeout=5)
        with browser._ReusableTCPServer(
                address, browser._build_frontend_handler()) as rebound:
            self.assertEqual(rebound.server_address, address)

    def test_status_route_defaults_and_both_acts(self):
        self.assertEqual(self.get_json("/api/v1/two-act-status"),
                         browser.build_two_act_browser_status())
        for act in (1, 2):
            self.assertEqual(self.get_json(f"/api/v1/two-act-status?act={act}"),
                             browser.build_two_act_browser_status(act))

    def test_zoom_default_and_all_levels_preserve_disclosure(self):
        self.assertEqual(self.get_json("/api/v1/dogfood-zoom"),
                         query_node_at_progressive_zoom())
        for level in range(5):
            with self.subTest(level=level):
                payload = self.get_json(f"/api/v1/dogfood-zoom?zoom_level={level}")
                self.assertEqual(payload, query_node_at_progressive_zoom(zoom_level=level))
                self.assertTrue(all(node["zoom_level"] <= level for node in payload["nodes"]))
        root = self.get_json("/api/v1/dogfood-zoom")
        self.assertEqual(len(root["rts_currencies"]), 7)
        self.assertNotIn("automated_test_commands", json.dumps(root))
        self.assertNotIn("cli_commands", json.dumps(root))

    def test_zoom_node_selection_and_encapsulation(self):
        nodes = query_node_at_progressive_zoom(zoom_level=4)["nodes"]
        node_id = next(node["id"] for node in nodes if node["zoom_level"] == 4)
        for level in (0, 4):
            self.assertEqual(self.get_json(
                f"/api/v1/dogfood-zoom?node_id={node_id}&zoom_level={level}"),
                query_node_at_progressive_zoom(node_id, level))

    def test_oscal_returns_unassessed_report(self):
        report = self.get_json("/api/v1/oscal-summary")
        self.assertEqual(report, build_oscal_hud_posture_report())
        self.assertEqual(report["summary"]["counts"]["BLUE"], 9)

    def test_live_snapshot_health_and_currencies(self):
        self.assertEqual(self.get_json("/api/v1/live-cluster-health"),
                         summarize_live_cluster_health())
        self.assertEqual(self.get_json("/api/v1/live-cluster-currencies"),
                         {"rts_currencies": build_enriched_live_currencies()})

    def test_live_metrics_portal_and_explicit_collection(self):
        import live_metrics_poller as metrics

        status, content_type, body = self.request("/metrics-live")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body.decode("utf-8"), metrics.render_live_metrics_html())
        with patch.object(metrics, "poll_live_cluster_metrics", return_value={"ok": True}) as poll:
            for query, live in (("", False), ("?live=0", False), ("?live=1", True)):
                self.assertEqual(self.get_json("/api/v1/live-metrics" + query), {"ok": True})
                poll.assert_called_with(allow_kubectl=live)

    def test_live_metrics_default_and_disabled_match_offline_poller(self):
        from live_metrics_poller import poll_live_cluster_metrics

        with patch("cluster_harvester.harvest_live_k8s_cluster") as harvest:
            expected = poll_live_cluster_metrics(allow_kubectl=False)
            for route in ("/api/v1/live-metrics", "/api/v1/live-metrics?live=0"):
                with self.subTest(route=route):
                    self.assertEqual(self.get_json(route), expected)
            harvest.assert_not_called()

    def test_operational_portals_expose_live_metrics_controls_without_collection(self):
        with patch("live_metrics_poller.poll_live_cluster_metrics") as poll:
            for route in ("/incidents", "/capacity", "/games"):
                with self.subTest(route=route):
                    status, _, body = self.request(route)
                    self.assertEqual(status, 200)
                    html = body.decode("utf-8")
                    self.assertIn("<a href='/metrics-live'>Live Metrics</a>", html)
                    self.assertIn('<button id="live-refresh" type="button">Refresh Live Metrics</button>', html)
                    self.assertIn('fetch("/api/v1/live-metrics?live=1", {cache: "no-store"})', html)
                    self.assertIn('id="live-refresh-status" role="status" aria-live="polite"', html)
            poll.assert_not_called()

    def test_live_metrics_queries_rejected_before_collection(self):
        with patch("live_metrics_poller.poll_live_cluster_metrics") as poll:
            for route in ("/api/v1/live-metrics", "/api/v1/graph/catalog"):
                for query in ("live=", "live=2", "live=invalid", "live=0&live=1",
                              "other=private-input",
                              "live=%", "live=%FF", "live", "&"):
                    self.assertEqual(self.get_json(route + "?" + query, 400),
                                     {"error": "Invalid query parameters"})
            for query in ("live=0", "live=1", "unexpected=1", "other=private-input", "&"):
                self.assertEqual(self.get_json("/metrics-live?" + query, 400),
                                 {"error": "Invalid query parameters"})
            poll.assert_not_called()

    def test_graph_catalog_live_metrics_update_matching_nodes(self):
        from cluster_diff_engine import DEFAULT_CATALOG_PATH

        snapshot = json.loads(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        node_id = snapshot["nodes"][0]["id"]
        metrics = {"rts_currencies": [{"label": "Fresh"}],
                   "telemetry_mode": "LIVE_KUBECTL",
                   "node_metrics": [{"node_id": node_id, "name": "test-node",
                                     "cpu_percent": 23, "ram_percent": 45, "ready": True}]}
        with patch("live_metrics_poller.poll_live_cluster_metrics", return_value=metrics) as poll:
            payload = self.get_json("/api/v1/graph/catalog?live=1")
            poll.assert_called_once_with(allow_kubectl=True)
            self.assertEqual(payload["rts_currencies"], metrics["rts_currencies"])
            self.assertEqual(payload["node_metrics"], metrics["node_metrics"])
            self.assertEqual(payload["nodes"][0]["metrics"]["cpu_percent"], 23)
            poll.reset_mock()
            expected = dict(snapshot, rts_currencies=build_enriched_live_currencies())
            for query in ("", "?live=0"):
                with self.subTest(query=query):
                    cached = self.get_json("/api/v1/graph/catalog" + query)
                    self.assertEqual(cached, expected)
            poll.assert_not_called()

    def test_live_advisor_returns_grounded_answer(self):
        question = "manifest node health"
        payload = self.get_json("/api/v1/live-cluster-ask?q=" + quote(question))
        self.assertEqual(payload, answer_operational_question(question))
        self.assertFalse(payload["airlock_blocked"])
        self.assertTrue(payload["cited_node_ids"])

    def test_core_and_extension_html_portal_routes_return_200(self):
        for path in ("/", "/chat", "/incidents", "/capacity", "/network",
                     "/gitops", "/executive", "/hub", "/metrics-live",
                     "/adapters", "/docs"):
            with self.subTest(path=path):
                status, content_type, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(content_type, "text/html; charset=utf-8")
                self.assertTrue(body.startswith(b"<!DOCTYPE html>"))

    def test_chat_and_portal_serve_concierge_html(self):
        for path in ("/chat", "/portal"):
            with self.subTest(path=path):
                status, content_type, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(content_type, "text/html; charset=utf-8")
                self.assertEqual(body, render_concierge_chat_html().encode("utf-8"))

    def test_hub_serves_suite_launchpad_html(self):
        status, content_type, body = self.request("/hub")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_suite_hub_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))

    def test_suite_catalog_returns_application_catalog(self):
        self.assertEqual(self.get_json("/api/v1/suite-catalog"),
                         build_suite_application_catalog())

    def test_suite_catalog_rejects_parameters_without_calling_helper(self):
        with patch("opscryer_suite_hub.build_suite_application_catalog") as catalog:
            for query in ("?q=private-input", "?catalog=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/suite-catalog" + query, 400),
                                     {"error": "Invalid query parameters"})
            catalog.assert_not_called()

    def test_executive_serves_command_center_html(self):
        status, content_type, body = self.request("/executive")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_executive_command_center_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))

    def test_executive_summary_returns_posture_dossier(self):
        self.assertEqual(self.get_json("/api/v1/executive-summary"),
                         build_executive_posture_dossier())

    def test_executive_summary_rejects_parameters_without_calling_helper(self):
        with patch("executive_command_center.build_executive_posture_dossier") as dossier:
            for query in ("?q=private-input", "?catalog=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/executive-summary" + query, 400),
                                     {"error": "Invalid query parameters"})
            dossier.assert_not_called()

    def test_gitops_serves_release_cockpit_html(self):
        status, content_type, body = self.request("/gitops")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_gitops_cockpit_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))

    def test_gitops_cockpit_returns_release_readiness_scorecard(self):
        self.assertEqual(self.get_json("/api/v1/gitops-cockpit"),
                         evaluate_release_readiness_scorecard())

    def test_gitops_cockpit_rejects_parameters_without_calling_helper(self):
        with patch("gitops_release_cockpit.evaluate_release_readiness_scorecard") as scorecard:
            for query in ("?q=private-input", "?catalog=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/gitops-cockpit" + query, 400),
                                     {"error": "Invalid query parameters"})
            scorecard.assert_not_called()

    def test_network_serves_network_inspector_html(self):
        status, content_type, body = self.request("/network")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_network_inspector_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))
        self.assertIn(b"Network &amp; OIDC Route Inspector", body)

    def test_network_inspector_returns_routes(self):
        self.assertEqual(self.get_json("/api/v1/network-inspector"),
                         trace_ingress_to_hardware_routes())

    def test_network_inspector_rejects_parameters_without_calling_helper(self):
        with patch("network_topology_inspector.trace_ingress_to_hardware_routes") as routes:
            for query in ("?q=private-input", "?catalog=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/network-inspector" + query, 400),
                                     {"error": "Invalid query parameters"})
            routes.assert_not_called()

    def test_capacity_serves_capacity_planner_html(self):
        status, content_type, body = self.request("/capacity")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_capacity_planner_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))
        self.assertIn(b"Capacity Planner", body)

    def test_capacity_planner_returns_summary(self):
        self.assertEqual(self.get_json("/api/v1/capacity-planner"),
                         summarize_cluster_capacity())

    def test_capacity_planner_rejects_parameters_without_calling_helper(self):
        with patch("capacity_planner.summarize_cluster_capacity") as summary:
            for query in ("?q=private-input", "?drain_node=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/capacity-planner" + query, 400),
                                     {"error": "Invalid query parameters"})
            summary.assert_not_called()

    def test_incidents_serves_incident_commander_html(self):
        status, content_type, body = self.request("/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_incident_commander_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))
        self.assertIn(b"Incident Commander", body)

    def test_incident_commander_returns_catalog(self):
        self.assertEqual(self.get_json("/api/v1/incident-commander"),
                         build_active_incidents_catalog())

    def test_incident_commander_rejects_parameters_without_calling_helper(self):
        with patch("incident_commander.build_active_incidents_catalog") as catalog:
            for query in ("?q=private-input", "?incident_id=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/incident-commander" + query, 400),
                                     {"error": "Invalid query parameters"})
            catalog.assert_not_called()

    def test_playbooks_serves_playbook_studio_html(self):
        status, content_type, body = self.request("/playbooks")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_playbook_studio_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))
        self.assertIn(b"Jev Decision Tree &amp; Ticket Playbook Studio", body)

    def test_playbook_studio_returns_catalog(self):
        self.assertEqual(self.get_json("/api/v1/playbook-studio"),
                         build_playbook_studio_catalog())

    def test_playbook_studio_rejects_parameters_without_calling_helper(self):
        with patch("playbook_studio.build_playbook_studio_catalog") as catalog:
            for query in ("?q=private-input", "?catalog=private-input",
                          "?unexpected=1", "?q=%FF", "?q=%", "?q=a&q=b",
                          "?q", "?q=", "?&"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/playbook-studio" + query, 400),
                                     {"error": "Invalid query parameters"})
            catalog.assert_not_called()

    def test_models_serves_model_copilot_html(self):
        status, content_type, body = self.request("/models")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, model_copilot.render_model_copilot_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))

    def test_storage_serves_cockpit_html_and_json(self):
        self.assertEqual(self.request("/storage"),
                         (200, "text/html; charset=utf-8",
                          storage_cockpit.render_storage_cockpit_html().encode("utf-8")))
        self.assertEqual(self.get_json("/api/v1/storage-cockpit"),
                         storage_cockpit.summarize_storage_topology())

    def test_storage_rejects_queries_without_calling_helpers(self):
        with patch.object(storage_cockpit, "render_storage_cockpit_html") as render, \
                patch.object(storage_cockpit, "summarize_storage_topology") as summarize:
            for path in ("/storage", "/api/v1/storage-cockpit"):
                for query in ("q=private-input", "catalog=private-input", "q=%FF",
                              "q=%", "q=a&q=b", "q", "&"):
                    with self.subTest(path=path, query=query):
                        self.assertEqual(self.get_json(path + "?" + query, 400),
                                         {"error": "Invalid query parameters"})
            render.assert_not_called()
            summarize.assert_not_called()

    def test_storage_helper_error_does_not_echo_input(self):
        for path, helper in (("/storage", "render_storage_cockpit_html"),
                             ("/api/v1/storage-cockpit", "summarize_storage_topology")):
            with self.subTest(path=path), patch.object(
                    storage_cockpit, helper, side_effect=ValueError("private-input")):
                self.assertEqual(self.get_json(path, 400),
                                 {"error": "Invalid query parameters"})

    def test_secops_serves_cockpit_html_and_json(self):
        self.assertEqual(self.request("/secops"),
                         (200, "text/html; charset=utf-8",
                          secops_cockpit.render_secops_cockpit_html().encode("utf-8")))
        self.assertEqual(self.get_json("/api/v1/secops-cockpit"),
                         secops_cockpit.build_secops_posture_catalog())

    def test_secops_rejects_queries_without_calling_helpers(self):
        with patch.object(secops_cockpit, "render_secops_cockpit_html") as render, \
                patch.object(secops_cockpit, "build_secops_posture_catalog") as summarize:
            for path in ("/secops", "/api/v1/secops-cockpit"):
                for query in ("q=private-input", "catalog=private-input", "q=%FF",
                              "q=%", "q=a&q=b", "q", "&"):
                    with self.subTest(path=path, query=query):
                        self.assertEqual(self.get_json(path + "?" + query, 400),
                                         {"error": "Invalid query parameters"})
            render.assert_not_called()
            summarize.assert_not_called()

    def test_secops_helper_error_does_not_echo_input(self):
        for path, helper in (("/secops", "render_secops_cockpit_html"),
                             ("/api/v1/secops-cockpit", "build_secops_posture_catalog")):
            with self.subTest(path=path), patch.object(
                    secops_cockpit, helper, side_effect=ValueError("private-input")):
                self.assertEqual(self.get_json(path, 400),
                                 {"error": "Invalid query parameters"})

    def test_kb_serves_knowledge_explorer_html(self):
        self.assertEqual(self.request("/kb"),
                         (200, "text/html; charset=utf-8",
                          kb_explorer.render_jev_knowledge_html().encode("utf-8")))

    def test_kb_default_and_query_return_helper_results(self):
        self.assertEqual(self.get_json("/api/v1/kb-explorer"),
                         kb_explorer.build_jev_knowledge_catalog())
        for question in (*kb_explorer.SAMPLE_QUERIES, "unrecognized question"):
            with self.subTest(question=question):
                self.assertEqual(self.get_json("/api/v1/kb-explorer?q=" + quote(question)),
                                 kb_explorer.build_jev_knowledge_catalog(query=question))

    def test_kb_invalid_queries_do_not_call_helper_or_echo_input(self):
        with patch.object(kb_explorer, "build_jev_knowledge_catalog") as build:
            for query in ("q", "q=", "q=+%20", "q=%E2%80%83", "q=%", "q=%GG",
                          "q=%FF", "q=%C3%28", "q=private-input&q=other",
                          "unexpected=private-input", "q=private-input&unexpected=1",
                          "q=private-input%00", "q=private-input%0A",
                          "q=private-input%7F", "q=private-input%C2%85"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/kb-explorer?" + query, 400),
                                     {"error": "Invalid query parameters"})
            build.assert_not_called()
        self.assertEqual(self.get_json("/kb?q=private-input", 400),
                         {"error": "Invalid query parameters"})

    def test_kb_helper_error_does_not_echo_input(self):
        with patch.object(kb_explorer, "build_jev_knowledge_catalog",
                          side_effect=ValueError("private-input")):
            self.assertEqual(self.get_json("/api/v1/kb-explorer?q=database", 400),
                             {"error": "Invalid query parameters"})

    def test_games_serves_game_debug_html(self):
        status, content_type, body = self.request("/games")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, game_debug.render_game_debug_html().encode("utf-8"))

    def test_game_debug_default_and_all_games(self):
        self.assertEqual(self.get_json("/api/v1/game-debug-loop"),
                         game_debug.trace_game_debugging_loop())
        for game in game_debug.GAME_PROFILES:
            with self.subTest(game=game):
                self.assertEqual(self.get_json("/api/v1/game-debug-loop?game=" + game),
                                 game_debug.trace_game_debugging_loop(game))

    def test_game_debug_rejects_invalid_queries_without_echo(self):
        with patch.object(game_debug, "trace_game_debugging_loop") as trace:
            for query in ("unexpected=private-input", "game=a&game=b",
                          "game=minecraft&unexpected=1", "game", "&",
                          "game=%", "game=%GG", "game=%FF", "game=%C3%28"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/game-debug-loop?" + query, 400),
                                     {"error": "Invalid query parameters"})
            trace.assert_not_called()
        for game in ("private-input", "", " ", "private-input\x00"):
            with self.subTest(game=game):
                self.assertEqual(self.get_json(
                    "/api/v1/game-debug-loop?game=" + quote(game), 400),
                    {"error": "Invalid query parameters"})

    def test_game_debug_helper_error_does_not_echo_input(self):
        with patch.object(game_debug, "trace_game_debugging_loop",
                          side_effect=ValueError("private-input")):
            self.assertEqual(self.get_json("/api/v1/game-debug-loop", 400),
                             {"error": "Invalid query parameters"})

    def test_model_copilot_returns_benchmark(self):
        self.assertEqual(self.get_json("/api/v1/model-copilot"),
                         model_copilot.build_model_copilot_benchmark_matrix())

    def test_model_copilot_question_returns_comparison(self):
        question = "Manifest node health: what should we do?"
        expected = {"airlock_blocked": False, "tiers": {}, "status": "ok"}
        with patch.object(model_copilot, "run_dual_tier_model_comparison",
                          return_value=expected) as compare, \
                patch.object(model_copilot, "build_model_copilot_benchmark_matrix") as matrix:
            self.assertEqual(self.get_json("/api/v1/model-copilot?q=" + quote(question)),
                             expected)
            compare.assert_called_once_with(question)
            matrix.assert_not_called()

    def test_model_copilot_airlock_returns_403_without_echo(self):
        question = "Manifest database password access"
        payload = self.get_json("/api/v1/model-copilot?q=" + quote(question), 403)
        self.assertEqual(payload, model_copilot.run_dual_tier_model_comparison(question))
        self.assertIs(payload["airlock_blocked"], True)
        self.assertNotIn(question, json.dumps(payload))

    def test_model_copilot_rejects_invalid_queries_without_calling_helpers(self):
        with patch.object(model_copilot, "run_dual_tier_model_comparison") as compare, \
                patch.object(model_copilot, "build_model_copilot_benchmark_matrix") as matrix:
            for query in ("q", "q=", "q=+%20", "q=%E2%80%83", "&",
                          "q=private-input&q=other", "q=private-input&unexpected=1",
                          "catalog=private-input", "q=%", "q=%GG", "q=%FF", "q=%C3%28",
                          "q=private-input%00", "q=private-input%0A", "q=private-input%7F"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/model-copilot?" + query, 400),
                                     {"error": "Invalid query parameters"})
            compare.assert_not_called()
            matrix.assert_not_called()

    def test_model_copilot_value_error_returns_fixed_error(self):
        for query, helper in (("", "build_model_copilot_benchmark_matrix"),
                              ("?q=manifest", "run_dual_tier_model_comparison")):
            with self.subTest(query=query), patch.object(
                    model_copilot, helper, side_effect=ValueError("private-input")):
                self.assertEqual(self.get_json("/api/v1/model-copilot" + query, 400),
                                 {"error": "Invalid query parameters"})

    def test_simulator_serves_gameday_html(self):
        status, content_type, body = self.request("/simulator")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertEqual(body, render_gameday_simulator_html().encode("utf-8"))
        self.assertTrue(body.startswith(b"<!DOCTYPE html>"))

    def test_gameday_simulator_default_and_all_scenarios(self):
        self.assertEqual(self.get_json("/api/v1/gameday-simulator"),
                         simulate_gameday_scenario())
        for scenario in list_gameday_scenarios()["scenarios"]:
            scenario_id = scenario["scenario_id"]
            with self.subTest(scenario=scenario_id):
                self.assertEqual(self.get_json(
                    "/api/v1/gameday-simulator?scenario=" + quote(scenario_id)),
                    simulate_gameday_scenario(scenario_id))

    def test_gameday_simulator_rejects_invalid_parameters_without_calling_helper(self):
        with patch("gameday_simulator.simulate_gameday_scenario") as simulate:
            for query in ("?unexpected=private-input", "?scenario=a&scenario=b",
                          "?scenario=node_down_nodebeta02&unexpected=1",
                          "?scenario", "?scenario=%", "?scenario=%GG", "?scenario=%FF"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/gameday-simulator" + query, 400),
                                     {"error": "Invalid query parameters"})
            simulate.assert_not_called()

    def test_gameday_simulator_rejects_unknown_scenarios_without_echo(self):
        for scenario in ("private-input", "", " ", "private-input\x00"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.get_json(
                    "/api/v1/gameday-simulator?scenario=" + quote(scenario), 400),
                    {"error": "Invalid query parameters"})

    def test_chat_walkthrough_returns_helper_result(self):
        self.assertEqual(self.get_json("/api/v1/chat-walkthrough"),
                         run_multi_persona_chat_walkthrough())

    def test_chat_walkthrough_rejects_parameters_without_calling_helper(self):
        with patch("chat_walkthrough.run_multi_persona_chat_walkthrough") as walkthrough:
            for query in ("?q=private-input", "?persona=sre", "?unexpected=1", "?q=%FF"):
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/chat-walkthrough" + query, 400),
                                     {"error": "Invalid query parameters"})
            walkthrough.assert_not_called()

    def test_concierge_default_and_all_personas_return_helper_result(self):
        question = "Manifest cluster health overview"
        for persona in (None, *PERSONAS):
            with self.subTest(persona=persona):
                path = "/api/v1/chat-concierge?q=" + quote(question)
                if persona is not None:
                    path += "&persona=" + persona
                self.assertEqual(self.get_json(path), ask_concierge_chat(
                    question, persona=persona or "household_user"))

    def test_concierge_airlock_returns_403_without_echo(self):
        question = "Are nodes healthy?"
        payload = self.get_json("/api/v1/chat-concierge?q=" + quote(question), 403)
        self.assertEqual(payload, ask_concierge_chat(question))
        self.assertIs(payload["airlock_blocked"], True)
        self.assertNotIn(question, json.dumps(payload))

    def test_invalid_concierge_queries_do_not_call_helper_or_echo(self):
        queries = (
            "", "q", "q=", "q=+%20", "q=%E2%80%83",
            "q=private-input&q=other", "q=private-input&unexpected=1",
            "q=%", "q=%GG", "q=%FF", "q=%C3%28",
            "q=private-input%00", "q=private-input%0A", "q=private-input%7F",
            "q=private-input&persona=", "q=private-input&persona=private-input",
            "q=private-input&persona=sre&persona=developer",
            "persona=sre",
        )
        with patch("ticket_chat_portal.ask_concierge_chat") as concierge:
            for query in queries:
                with self.subTest(query=query):
                    self.assertEqual(self.get_json("/api/v1/chat-concierge?" + query, 400),
                                     {"error": "Invalid query parameters"})
            concierge.assert_not_called()

    def test_concierge_value_error_returns_fixed_error(self):
        with patch("ticket_chat_portal.ask_concierge_chat",
                   side_effect=ValueError("private-input")):
            self.assertEqual(self.get_json("/api/v1/chat-concierge?q=manifest", 400),
                             {"error": "Invalid query parameters"})

    def test_multi_plane_routes_return_helper_results_and_reject_parameters(self):
        from chaos_blast_radius import verify_all_six_chaos_planes
        from live_gitops_signals import derive_live_gitops_and_ci_signals
        from oidc_rbac_verifier import audit_cluster_ingress_oidc_posture
        from openbao_kms_provenance import audit_openbao_secret_provenance

        for route, helper in (
            ("chaos", verify_all_six_chaos_planes),
            ("oidc", audit_cluster_ingress_oidc_posture),
            ("openbao", audit_openbao_secret_provenance),
            ("gitops", derive_live_gitops_and_ci_signals),
        ):
            path = "/api/v1/live-cluster-" + route
            with self.subTest(route=route):
                self.assertEqual(self.get_json(path), helper())
                with patch(helper.__module__ + "." + helper.__name__) as mocked:
                    for query in ("?q=private-input", "?unexpected=1", "?q=%FF"):
                        self.assertEqual(self.get_json(path + query, 400),
                                         {"error": "Invalid query parameters"})
                    mocked.assert_not_called()

    def test_live_advisor_airlock_returns_403_without_echo(self):
        question = "Are nodes healthy?"
        payload = self.get_json("/api/v1/live-cluster-ask?q=" + quote(question), 403)
        self.assertEqual(payload, {"status": "blocked_by_airlock",
                                  "airlock_blocked": True, "cited_node_ids": []})
        self.assertNotIn(question, json.dumps(payload))

    def test_invalid_live_queries_do_not_call_helpers_or_echo_input(self):
        with patch("live_advisor.answer_operational_question") as advisor, \
                patch("cluster_diff_engine.summarize_live_cluster_health") as health, \
                patch("live_currencies.build_enriched_live_currencies") as currencies:
            for path in (
                "live-cluster-health?q=private-input",
                "live-cluster-currencies?q=private-input",
                "live-cluster-ask", "live-cluster-ask?q", "live-cluster-ask?q=",
                "live-cluster-ask?q=+%20", "live-cluster-ask?q=%E2%80%83",
                "live-cluster-ask?q=private-input&q=other",
                "live-cluster-ask?q=private-input&unexpected=1",
                "live-cluster-ask?q=%", "live-cluster-ask?q=%GG",
                "live-cluster-ask?q=%FF", "live-cluster-ask?q=%C3%28",
                "live-cluster-ask?q=private-input%00",
                "live-cluster-ask?q=private-input%0A",
                "live-cluster-ask?q=private-input%7F",
            ):
                with self.subTest(path=path):
                    self.assertEqual(self.get_json("/api/v1/" + path, 400),
                                     {"error": "Invalid query parameters"})
            advisor.assert_not_called()
            health.assert_not_called()
            currencies.assert_not_called()

    def test_live_advisor_value_error_returns_fixed_error(self):
        with patch("live_advisor.answer_operational_question",
                   side_effect=ValueError("private-input")):
            self.assertEqual(self.get_json("/api/v1/live-cluster-ask?q=manifest", 400),
                             {"error": "Invalid query parameters"})

    def test_invalid_queries_return_json_without_echoing_input(self):
        for path in (
            "two-act-status?act=0", "two-act-status?act=3",
            "two-act-status?act=true", "two-act-status?act=1.0",
            "two-act-status?act=", "two-act-status?act=1&act=2",
            "two-act-status?unexpected=1", "dogfood-zoom?zoom_level=-1",
            "dogfood-zoom?zoom_level=5", "dogfood-zoom?zoom_level=bad",
            "dogfood-zoom?zoom_level=", "dogfood-zoom?node_id=",
            "dogfood-zoom?node_id=a&node_id=b", "oscal-summary?act=1",
            "two-act-status?act=%3Cscript%3E",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.get_json("/api/v1/" + path, 400),
                                 {"error": "Invalid query parameters"})
        self.assertEqual(self.get_json("/api/v1/dogfood-zoom?node_id=missing", 404),
                         {"error": "Unknown dogfood node"})
        self.assertEqual(self.get_json("/api/v1/missing", 404),
                         {"error": "Unknown API route"})

    def test_existing_html_response_is_unchanged(self):
        for path in ("/", "/index.html", "/?mode=remote",
                     "/chat?mode=remote", "/portal?mode=remote"):
            status, content_type, body = self.request(path)
            self.assertEqual(status, 200)
            self.assertEqual(content_type, "text/html; charset=utf-8")
            self.assertEqual(body.decode("utf-8"), browser.render_standalone_browser_html())

    def test_serve_command_uses_integrated_handler(self):
        handler = browser._build_frontend_handler()
        with patch.object(browser, "_build_frontend_handler", return_value=handler), \
                patch.object(browser.socketserver, "TCPServer") as server, \
                patch("builtins.print"):
            self.assertEqual(browser.main(["--serve", "--port", "8088"]), 0)
            server.assert_called_once_with(("127.0.0.1", 8088), handler)
            server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_serve_port_in_use_exits_with_actionable_error(self):
        with patch.object(browser.socketserver, "TCPServer",
                          side_effect=OSError("private-input")), \
                redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as raised:
                browser.main(["--serve", "--port", "8088"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "Requested --port is already in use; stop the existing server or choose another --port",
            error.getvalue())
        self.assertNotIn("private-input", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())


class GameDebugHTTPTests(unittest.TestCase):
    request = TwoActHTTPTests.request
    get_json = TwoActHTTPTests.get_json

    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), game_debug._build_game_debug_handler())
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_standalone_html_routes(self):
        expected = game_debug.render_game_debug_html().encode("utf-8")
        for path in ("/", "/games"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path),
                                 (200, "text/html; charset=utf-8", expected))

    def test_standalone_json_and_markdown_routes(self):
        for game in (None, *game_debug.GAME_PROFILES):
            query = "" if game is None else "?game=" + game
            with self.subTest(game=game):
                self.assertEqual(self.get_json("/api/v1/game-debug-loop" + query),
                                 game_debug.trace_game_debugging_loop(game or "minecraft"))
                self.assertEqual(self.request("/games/debug.md" + query),
                                 (200, "text/markdown; charset=utf-8",
                                  game_debug.render_game_debug_markdown(
                                      game or "minecraft").encode("utf-8")))

    def test_standalone_rejects_invalid_queries_and_unknown_paths(self):
        for path in ("/api/v1/game-debug-loop", "/games/debug.md"):
            for query in ("game=private-input", "game=", "game", "&",
                          "game=minecraft&game=factorio", "unexpected=private-input",
                          "game=%", "game=%GG", "game=%FF", "game=minecraft%00"):
                with self.subTest(path=path, query=query):
                    self.assertEqual(self.get_json(path + "?" + query, 400),
                                     {"error": "Invalid game observability request"})
        for path in ("/?game=minecraft", "/games?unexpected=private-input"):
            self.assertEqual(self.get_json(path, 400),
                             {"error": "Invalid game observability request"})
        self.assertEqual(self.get_json("/private-input", 404), {"error": "Not found"})


class KnowledgeExplorerHTTPTests(unittest.TestCase):
    request = TwoActHTTPTests.request
    get_json = TwoActHTTPTests.get_json

    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), kb_explorer._build_kb_explorer_handler())
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_standalone_routes(self):
        expected = kb_explorer.render_jev_knowledge_html().encode("utf-8")
        for path in ("/", "/kb"):
            self.assertEqual(self.request(path), (200, "text/html; charset=utf-8", expected))
        for question in (None, "How 2 database?"):
            query = "" if question is None else "?q=" + quote(question)
            self.assertEqual(self.get_json("/api/v1/kb-explorer" + query),
                             kb_explorer.build_jev_knowledge_catalog(query=question))

    def test_standalone_rejects_invalid_requests_without_echo(self):
        for path in ("/?q=private-input", "/kb?unexpected=private-input",
                     "/api/v1/kb-explorer?q", "/api/v1/kb-explorer?q=",
                     "/api/v1/kb-explorer?q=%", "/api/v1/kb-explorer?q=%GG",
                     "/api/v1/kb-explorer?q=%FF", "/api/v1/kb-explorer?q=%00",
                     "/api/v1/kb-explorer?q=a&q=b",
                     "/api/v1/kb-explorer?unexpected=private-input"):
            with self.subTest(path=path):
                self.assertEqual(self.get_json(path, 400),
                                 {"error": "Invalid knowledge explorer request"})
        self.assertEqual(self.get_json("/private-input", 404), {"error": "Not found"})


class EnvironmentAdaptersHTTPTests(unittest.TestCase):
    request = TwoActHTTPTests.request
    get_json = TwoActHTTPTests.get_json

    def test_standalone_and_browser_routes(self):
        for handler in (adapters._build_adapters_handler(), browser._build_frontend_handler()):
            with self.subTest(handler=handler.__name__), socketserver.TCPServer(
                    ("127.0.0.1", 0), handler) as self.server:
                thread = threading.Thread(target=self.server.serve_forever, daemon=True)
                thread.start()
                try:
                    self.assertEqual(self.request("/adapters"),
                                     (200, "text/html; charset=utf-8",
                                      adapters.render_adapters_html().encode("utf-8")))
                    api = "/api/v1/environment-adapters"
                    for name in (None, *adapters.ADAPTER_PROFILES):
                        query = "" if name is None else "?adapter=" + name
                        self.assertEqual(self.get_json(api + query),
                                         adapters.build_adapter_compatibility_catalog(name))
                    for path in ("/adapters?adapter=local_host", "/adapters?private-input=x",
                                 *(api + "?" + query for query in (
                                     "adapter=private-input", "adapter=", "adapter", "adapter=%",
                                     "adapter=%FF", "adapter=%00", "adapter=a&adapter=b",
                                     "private-input=x"))):
                        self.assertEqual(self.get_json(path, 400),
                                         {"error": "Invalid environment adapter request"})
                finally:
                    self.server.shutdown()
                    thread.join(timeout=5)


class EnvironmentAdaptersCLITests(unittest.TestCase):
    def test_exports(self):
        for name in (None, *adapters.ADAPTER_PROFILES):
            selection = [] if name is None else ["--adapter", name]
            for mode in ([], ["--json"], ["--markdown"]):
                with self.subTest(name=name, mode=mode), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(adapters.main(mode + selection), 0)
                    if mode == ["--markdown"]:
                        self.assertEqual(output.getvalue(), adapters.render_adapters_markdown(name))
                    else:
                        self.assertEqual(json.loads(output.getvalue()),
                                         adapters.build_adapter_compatibility_catalog(name))

    def test_serve_binds_loopback(self):
        for args, port in ((["--serve"], 8105), (["--serve", "--port", "8106"], 8106)):
            with patch.object(adapters, "ThreadingHTTPServer") as server, \
                    patch.object(adapters, "_build_adapters_handler") as handler, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(adapters.main(args), 0)
                server.assert_called_once_with(("127.0.0.1", port), handler.return_value)
                server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_arguments_use_fixed_error(self):
        for args in (["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                     ["--adapter", "private-input"], ["--adapter"], ["--unknown-private-input"],
                     ["--json", "--markdown"], ["--json", "--serve"], ["--ad", "local_host"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    adapters.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("Invalid environment adapter request", error.getvalue())
                self.assertNotIn("private-input", error.getvalue())


class StorageCockpitHTTPTests(unittest.TestCase):
    request = TwoActHTTPTests.request
    get_json = TwoActHTTPTests.get_json
    tearDownClass = classmethod(TwoActHTTPTests.tearDownClass.__func__)

    @classmethod
    def setUpClass(cls):
        cls.catalog = {"nodes": [], "source": "custom_storage_catalog"}
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), storage_cockpit._build_storage_cockpit_handler(cls.catalog))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    def test_standalone_routes_use_custom_catalog(self):
        for path in ("/", "/storage"):
            self.assertEqual(self.request(path),
                             (200, "text/html; charset=utf-8",
                              storage_cockpit.render_storage_cockpit_html(
                                  self.catalog).encode("utf-8")))
        self.assertEqual(self.get_json("/api/v1/storage-cockpit"),
                         storage_cockpit.summarize_storage_topology(self.catalog))

    def test_invalid_requests_do_not_echo_input(self):
        for path in ("/", "/storage", "/api/v1/storage-cockpit"):
            for query in ("catalog=private-input", "q=%", "q=%FF", "&"):
                self.assertEqual(self.get_json(path + "?" + query, 400),
                                 {"error": "Invalid storage cockpit request"})
        self.assertEqual(self.get_json("/private-input", 404), {"error": "Not found"})


class StorageCockpitCLITests(unittest.TestCase):
    def test_json_markdown_and_custom_catalog_exports(self):
        for args in ([], ["--json"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(storage_cockpit.main(args), 0)
                self.assertEqual(json.loads(output.getvalue()),
                                 storage_cockpit.summarize_storage_topology())
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            catalog.write_text('{"nodes": [], "source": "custom_storage_catalog"}',
                               encoding="utf-8")
            for mode in ("--json", "--markdown"):
                with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(storage_cockpit.main([mode, "--catalog", str(catalog)]), 0)
                    if mode == "--json":
                        self.assertEqual(json.loads(output.getvalue()),
                                         storage_cockpit.summarize_storage_topology(catalog))
                    else:
                        self.assertEqual(output.getvalue(),
                                         storage_cockpit.render_storage_cockpit_markdown(catalog))

    def test_serve_uses_loopback_and_requested_port(self):
        for args, port in ((["--serve"], 8101), (["--serve", "--port", "8102"], 8102)):
            with self.subTest(args=args), \
                    patch.object(storage_cockpit, "ThreadingHTTPServer") as server, \
                    patch.object(storage_cockpit, "_build_storage_cockpit_handler") as handler, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(storage_cockpit.main(args), 0)
                server.assert_called_once_with(("127.0.0.1", port), handler.return_value)
                server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_arguments_and_catalogs_use_fixed_error(self):
        for args in (["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                     ["--catalog", "private-input"], ["--unknown-private-input"],
                     ["--json", "--markdown"], ["--json", "--serve"], ["--catalog"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    storage_cockpit.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("Invalid storage cockpit request", error.getvalue())
                self.assertNotIn("private-input", error.getvalue())


class SecOpsCockpitHTTPTests(unittest.TestCase):
    request = TwoActHTTPTests.request
    get_json = TwoActHTTPTests.get_json
    tearDownClass = classmethod(TwoActHTTPTests.tearDownClass.__func__)

    @classmethod
    def setUpClass(cls):
        cls.catalog = {"nodes": [], "source": "custom_secops_catalog"}
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), secops_cockpit._build_secops_cockpit_handler(cls.catalog))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    def test_standalone_routes_use_custom_catalog(self):
        for path in ("/", "/secops"):
            self.assertEqual(self.request(path),
                             (200, "text/html; charset=utf-8",
                              secops_cockpit.render_secops_cockpit_html(
                                  self.catalog).encode("utf-8")))
        self.assertEqual(self.get_json("/api/v1/secops-cockpit"),
                         secops_cockpit.build_secops_posture_catalog(self.catalog))

    def test_invalid_requests_do_not_echo_input(self):
        for path in ("/", "/secops", "/api/v1/secops-cockpit"):
            for query in ("catalog=private-input", "q=%", "q=%FF", "&"):
                self.assertEqual(self.get_json(path + "?" + query, 400),
                                 {"error": "Invalid secops cockpit request"})
        self.assertEqual(self.get_json("/private-input", 404), {"error": "Not found"})


class SecOpsCockpitCLITests(unittest.TestCase):
    def test_json_markdown_and_custom_catalog_exports(self):
        for args in ([], ["--json"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(secops_cockpit.main(args), 0)
                self.assertEqual(json.loads(output.getvalue()),
                                 secops_cockpit.build_secops_posture_catalog())
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            catalog.write_text('{"nodes": [], "source": "custom_secops_catalog"}',
                               encoding="utf-8")
            for mode in ("--json", "--markdown"):
                with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(secops_cockpit.main([mode, "--catalog", str(catalog)]), 0)
                    if mode == "--json":
                        self.assertEqual(json.loads(output.getvalue()),
                                         secops_cockpit.build_secops_posture_catalog(catalog))
                    else:
                        self.assertEqual(output.getvalue(),
                                         secops_cockpit.render_secops_cockpit_markdown(catalog))

    def test_serve_uses_loopback_and_requested_port(self):
        for args, port in ((["--serve"], 8102), (["--serve", "--port", "8103"], 8103)):
            with self.subTest(args=args), \
                    patch.object(secops_cockpit, "ThreadingHTTPServer") as server, \
                    patch.object(secops_cockpit, "_build_secops_cockpit_handler") as handler, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(secops_cockpit.main(args), 0)
                server.assert_called_once_with(("127.0.0.1", port), handler.return_value)
                server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_arguments_and_catalogs_use_fixed_error(self):
        for args in (["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                     ["--catalog", "private-input"], ["--unknown-private-input"],
                     ["--json", "--markdown"], ["--json", "--serve"], ["--catalog"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    secops_cockpit.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("Invalid secops cockpit request", error.getvalue())
                self.assertNotIn("private-input", error.getvalue())


class KnowledgeExplorerCLITests(unittest.TestCase):
    def test_json_markdown_and_custom_catalog_exports(self):
        for args in ([], ["--json"], ["--json", "--query", "How 2 database?"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(kb_explorer.main(args), 0)
                self.assertEqual(json.loads(output.getvalue()),
                                 kb_explorer.build_jev_knowledge_catalog(
                                     query=args[-1] if "--query" in args else None))
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            catalog.write_text(kb_explorer.DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"),
                               encoding="utf-8")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(kb_explorer.main([
                    "--markdown", "--query", "How 2 storage?", "--catalog", str(catalog)]), 0)
                self.assertEqual(output.getvalue(), kb_explorer.render_jev_knowledge_markdown(
                    query="How 2 storage?", catalog=catalog))

    def test_serve_uses_loopback_and_requested_port(self):
        for args, port in ((["--serve"], 8100), (["--serve", "--port", "8101"], 8101)):
            with self.subTest(args=args), patch.object(kb_explorer, "ThreadingHTTPServer") as server, \
                    patch.object(kb_explorer, "_build_kb_explorer_handler") as handler, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(kb_explorer.main(args), 0)
                server.assert_called_once_with(("127.0.0.1", port), handler.return_value)
                server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_requests_use_fixed_error(self):
        for args in (["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                     ["--query", ""], ["--query", "  "], ["--query", "private-input\x00"],
                     ["--query", "private-input\n"], ["--catalog", "private-input"],
                     ["--unknown-private-input"], ["--json", "--markdown"],
                     ["--json", "--serve"], ["--query"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    kb_explorer.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("Invalid knowledge explorer request", error.getvalue())
                self.assertNotIn("private-input", error.getvalue())


class GameDebugCLITests(unittest.TestCase):
    def test_json_and_markdown_exports(self):
        for args in ([], ["--json"], ["--json", "--game", "factorio"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(game_debug.main(args), 0)
                self.assertEqual(json.loads(output.getvalue()),
                                 game_debug.trace_game_debugging_loop(
                                     "factorio" if "factorio" in args else "minecraft"))
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(game_debug.main(["--markdown", "--game", "romm"]), 0)
            self.assertEqual(output.getvalue(), game_debug.render_game_debug_markdown("romm"))

    def test_serve_uses_loopback_and_requested_port(self):
        for args, port in ((["--serve"], 8099), (["--serve", "--port", "8100"], 8100)):
            with self.subTest(args=args), patch.object(game_debug, "ThreadingHTTPServer") as server, \
                    patch.object(game_debug, "_build_game_debug_handler") as handler, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(game_debug.main(args), 0)
                server.assert_called_once_with(("127.0.0.1", port), handler.return_value)
                server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_arguments_and_catalogs_use_fixed_error(self):
        for args in (["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                     ["--game", "private-input"], ["--catalog", "private-input"],
                     ["--unknown-private-input"], ["--json", "--markdown"],
                     ["--json", "--serve"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    game_debug.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("Invalid game observability request", error.getvalue())
                self.assertNotIn("private-input", error.getvalue())


class SuiteHubCLITests(unittest.TestCase):
    def test_default_and_json_print_catalog_without_starting_server(self):
        for args in ([], ["--json"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as output, \
                    patch.object(suite_hub.socketserver, "TCPServer") as server:
                self.assertEqual(suite_hub.main(args), 0)
                self.assertEqual(json.loads(output.getvalue()), build_suite_application_catalog())
                server.assert_not_called()

    def test_export_bundle_writes_catalog_and_prints_manifest(self):
        with tempfile.TemporaryDirectory() as directory, \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(suite_hub.main(["--export-suite-bundle", directory]), 0)
            manifest = json.loads(output.getvalue())
            self.assertEqual(manifest["file_count"], 9)
            self.assertTrue(all((Path(directory) / name).is_file()
                                for name in manifest["files"]))
            self.assertEqual(json.loads((Path(directory) / "suite-catalog.json")
                                        .read_text(encoding="utf-8")),
                             build_suite_application_catalog())

    def test_serve_uses_integrated_handler_on_loopback(self):
        for args, port in ((["--serve"], 8095), (["--serve", "--port", "8096"], 8096)):
            with self.subTest(args=args), \
                    patch.object(browser, "_build_frontend_handler") as handler, \
                    patch.object(suite_hub.socketserver, "TCPServer") as server, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(suite_hub.main(args), 0)
                server.assert_called_once_with(("127.0.0.1", port), handler.return_value)
                server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_arguments_and_export_errors_do_not_echo_input(self):
        for args in (["--port", "0"], ["--port", "65536"],
                     ["--port", "private-input"], ["--unknown-private-input"],
                     ["--json", "--serve"], ["--export-suite-bundle", ""]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    suite_hub.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertNotIn("private-input", error.getvalue())


class LiveCLITests(unittest.TestCase):
    def test_live_flags_print_helper_results_without_starting_server(self):
        for args, expected in (
            (["--live-health"], summarize_live_cluster_health()),
            (["--live-advisor", "manifest node health"],
             answer_operational_question("manifest node health")),
            (["--live-advisor", "Are nodes healthy?"],
             {"status": "blocked_by_airlock", "airlock_blocked": True,
              "cited_node_ids": []}),
        ):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as output, \
                    patch.object(browser.socketserver, "TCPServer") as server:
                self.assertEqual(browser.main(args), 0)
                self.assertEqual(json.loads(output.getvalue()), expected)
                server.assert_not_called()

    def test_invalid_cli_question_is_rejected_without_echo(self):
        for question in ("", "   ", "private-input\x00", "private-input\n"):
            with self.subTest(question=question), \
                    patch("live_advisor.answer_operational_question") as advisor, \
                    redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as raised:
                    browser.main(["--live-advisor", question])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("invalid operational question", error.getvalue())
                self.assertNotIn("private-input", error.getvalue())
                advisor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
