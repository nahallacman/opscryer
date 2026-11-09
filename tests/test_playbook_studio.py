# SPDX-License-Identifier: Apache-2.0
"""STAGE-133 catalog, presentation, CLI, loopback HTTP and OPSEC contracts."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html import unescape
from html.parser import HTMLParser
import http.client
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch

import playbook_studio as studio
from opscryer_backend import CONTRACT_VERSION
from tests.test_opscryer_public_smoke import opsec_findings


PERSONAS = ("household_user", "developer", "sre", "executive")
EXPORTS = (studio.build_playbook_studio_catalog,
           studio.render_playbook_studio_markdown, studio.render_playbook_studio_html)
ROUTES = (("/", "text/html"), ("/playbooks", "text/html"),
          ("/api/v1/playbook-studio", "application/json"),
          ("/playbooks/studio.md", "text/markdown"))


def fixture():
    """A small offline graph independent of the bundled live snapshot."""
    node = {
        "id": "k8s/Node//nodebeta02", "label": "nodebeta02",
        "kind": "kubernetes_node", "domain": "deployments_k8s",
        "summary": "Offline healthy node", "primary_url": "https://ops.cluster.example.org",
        "drilldown_children": [], "resource_kind": "Node",
        "metrics": {"cpu_percent": 10, "ram_percent": 20},
        "resource": {"kind": "Node", "metadata": {"name": "nodebeta02"},
                     "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
    }
    return {"schema_version": CONTRACT_VERSION, "nodes": [node], "edges": [],
            "node_count": 1, "edge_count": 0}


def opsec_fixture():
    # Assemble synthetic probes in memory. Assertions must never print them.
    probes = [str(IPv4Address(0x08080808)), ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))]
    probes += [prefix + "synthetic133" for prefix in
               ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
    catalog = fixture()
    catalog["nodes"][0]["id"] = "probe " + " ".join(probes) + " 172.20.1.2 ops.cluster.example.org"
    return catalog


class Document(HTMLParser):
    """Inspect rendered elements and JSON/script boundaries without running JS."""

    def __init__(self, source):
        super().__init__()
        self.elements = []
        self.scripts = []
        self.current_script = None
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs))
        if tag == "script":
            self.current_script = {"attrs": attrs, "text": ""}
            self.scripts.append(self.current_script)

    def handle_endtag(self, tag):
        if tag == "script":
            self.current_script = None

    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script["text"] += data


class OpsecAssertions:
    def assert_opsec_clean(self, value):
        if not isinstance(value, (str, bytes)):
            value = json.dumps(value, allow_nan=False)
        if isinstance(value, str):
            value = value.encode("utf-8")
        findings = opsec_findings(value)
        self.assertEqual(findings, dict.fromkeys(findings, 0),
                         "Prohibited telemetry detected; values withheld")


class PlaybookStudioTests(OpsecAssertions, unittest.TestCase):
    def test_catalog_structure_personas_policy_and_airlock(self):
        data = studio.build_playbook_studio_catalog(fixture())
        self.assertEqual(set(data), {"schema_version", "read_only", "decision_tree",
                                    "ticket_templates", "personas", "playbook_Matrix"})
        self.assertEqual(data["schema_version"], "1.0")
        self.assertIs(data["read_only"], True)
        self.assertEqual(data["personas"], list(PERSONAS))
        tree = data["decision_tree"]
        self.assertEqual([level["level"] for level in tree["levels"]],
                         ["L0", "L1", "L2", "L3", "L4"])
        self.assertEqual(tree["levels"][0]["stage"], "security_airlock")
        self.assertIn(tree["root_node_id"], tree["nodes"])
        self.assertGreater(tree["confidence_threshold"], 0)
        self.assertLessEqual(tree["confidence_threshold"], 1)
        rules = tree["predicate_routing_rules"]
        self.assertEqual(rules["required_fields"],
                         ["predicate_id", "evaluated_value", "calibrated_probability"])
        self.assertIs(rules["additional_fields_allowed"], False)
        self.assertEqual(tree["fail_closed"]["route"], "human_escalation")
        self.assertIs(tree["fail_closed"]["direct_access_allowed"], False)
        self.assertEqual(tree["fail_closed"]["required_it_tickets"], [])
        leaves = [node for node in tree["nodes"].values() if node["kind"] == "leaf"]
        self.assertEqual(len(data["ticket_templates"]), 3)
        for template, leaf in zip(data["ticket_templates"], leaves):
            self.assertEqual(set(template), {"node_id", "policy_id", "direct_access_allowed",
                                             "required_it_tickets", "anchor_node_id"})
            for key, value in template.items():
                self.assertEqual(value, leaf[key])
        matrix = data["playbook_Matrix"]
        self.assertEqual(len(matrix), len(studio.CANONICAL_PROMPTS) * 4 + 1)
        self.assertEqual({(item["prompt"], item["persona"]) for item in matrix[:-1]},
                         {(prompt, persona) for prompt in studio.CANONICAL_PROMPTS for persona in PERSONAS})
        for prompt in studio.CANONICAL_PROMPTS:
            responses = [item["response"] for item in matrix[:-1] if item["prompt"] == prompt]
            for persona, response in zip(PERSONAS, responses):
                self.assertEqual(response["persona"], persona)
                self.assertEqual(response["status"], "ok")
                self.assertEqual(response["ticket_card"], responses[0]["ticket_card"])
                self.assertIsInstance(response["suggested_next_steps"], list)
                self.assertTrue(response["plain_english_answer"])
        blocked = matrix[-1]
        self.assertEqual(blocked["prompt"], studio.BLOCKED_PROMPT)
        self.assertEqual(blocked["status_code"], 403)
        self.assertIs(blocked["airlock_blocked"], True)
        self.assertEqual(blocked["reason"], "secret_hunting_blocked")
        self.assertEqual(blocked["response"]["status"], "blocked_by_airlock")
        self.assertIs(blocked["response"]["airlock_blocked"], True)
        self.assertIsNone(blocked["response"]["ticket_card"])
        self.assertEqual(blocked["response"]["cited_node_ids"], [])
        self.assert_opsec_clean(data)

    def test_all_exports_preserve_input_and_results_are_detached(self):
        catalog = fixture()
        before = deepcopy(catalog)
        expected = studio.build_playbook_studio_catalog(catalog)
        for export in EXPORTS:
            with self.subTest(export=export.__name__):
                self.assert_opsec_clean(export(catalog))
                self.assertEqual(catalog, before)
        mutated = studio.build_playbook_studio_catalog(catalog)
        mutated["personas"].clear()
        mutated["decision_tree"]["levels"][0]["stage"] = "caller mutation"
        mutated["playbook_Matrix"][0]["response"]["cited_node_ids"].clear()
        mutated["ticket_templates"][0]["required_it_tickets"].append("caller mutation")
        self.assertEqual(studio.build_playbook_studio_catalog(catalog), expected)
        self.assertEqual(catalog, before)

    def test_default_path_and_string_catalog_inputs(self):
        self.assertEqual(studio.build_playbook_studio_catalog(),
                         studio.build_playbook_studio_catalog(studio.DEFAULT_CATALOG_PATH))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            for export in EXPORTS:
                expected = export(fixture())
                for value in (path, str(path)):
                    self.assertEqual(export(value), expected)
                    self.assert_opsec_clean(export(value))

    def assert_catalog_rejected(self, catalog):
        for export in EXPORTS:
            with self.subTest(export=export.__name__):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(ValueError) as error:
                        export(catalog)
                self.assertEqual(str(error.exception), "Invalid playbook studio catalog")
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")
                self.assert_opsec_clean(str(error.exception))

    def test_malformed_catalogs_fail_closed_without_input_echo(self):
        duplicate, dangling, count_mismatch = fixture(), fixture(), fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        duplicate["node_count"] = 2
        dangling["edges"] = [{"source": dangling["nodes"][0]["id"],
                              "target": "private-untrusted-input", "relation": "hosted_on"}]
        dangling["edge_count"] = 1
        count_mismatch["node_count"] = 2
        for index, value in enumerate((False, 7, [], {}, {"nodes": "private-untrusted-input"},
                                       duplicate, dangling, count_mismatch)):
            with self.subTest(case=index):
                self.assert_catalog_rejected(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-untrusted-input.json"
            self.assert_catalog_rejected(path)
            for content in ('{"private-untrusted-input":', '[]',
                            '{"nodes":[],"nodes":[],"private-untrusted-input":true}'):
                path.write_text(content, encoding="utf-8")
                self.assert_catalog_rejected(path)

    def test_nonfinite_catalogs_rejected_before_credential_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for label in ("nan", "inf", "-inf"):
                for field in ("metrics", "token"):
                    with self.subTest(number=label, field=field):
                        catalog = fixture()
                        catalog["nodes"][0][field] = {"private-untrusted-input": float(label)}
                        self.assert_catalog_rejected(catalog)
                        path.write_text(json.dumps(catalog), encoding="utf-8")
                        self.assert_catalog_rejected(path)

    def test_markdown_structure_and_complete_matrix(self):
        report = studio.render_playbook_studio_markdown(fixture())
        self.assertTrue(report.startswith("# Jev Decision Tree & Ticket Playbook Studio\n"))
        for section in ("Decision Tree Levels", "Predicate Routing", "Ticket Templates",
                        "Persona Comparison", "Airlock Verification"):
            self.assertIn("\n## " + section + "\n", report)
        self.assertIn("No tickets are filed", report)
        self.assertIn("| Prompt | Persona | Status | Response | Ticket policy | Suggested next steps | Citations |", report)
        for level in range(5):
            self.assertIn("| L" + str(level) + " |", report)
        matrix = report.split("## Persona Comparison\n", 1)[1].split(
            "## Airlock Verification\n", 1)[0]
        rows = [line for line in matrix.splitlines() if line.startswith("| ")][2:]
        self.assertEqual(len(rows), len(studio.CANONICAL_PROMPTS) * len(PERSONAS) + 1)
        prompts = [unescape(re.sub(r"\\(.)", r"\1", line.split(" | ", 1)[0][2:]))
                   for line in rows]
        for prompt in studio.CANONICAL_PROMPTS:
            self.assertEqual(prompts.count(prompt), len(PERSONAS))
        for persona in PERSONAS:
            self.assertIn(persona.replace("_", "\\_"), report)
        self.assertIn("| 403 | True |", report)
        self.assertIn("blocked\\_by\\_airlock", report)
        self.assert_opsec_clean(report)

    def test_html_dom_structure_unique_ids_and_safe_updates(self):
        source = studio.render_playbook_studio_html(fixture())
        self.assertTrue(source.startswith("<!DOCTYPE html>"))
        document = Document(source)
        ids = [attrs["id"] for _, attrs in document.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for identity in ("playbook-tree-grid", "playbook-routing", "playbook-template-grid",
                         "playbook-persona-buttons", "playbook-status", "playbook-matrix-grid",
                         "playbook-airlock-grid", "playbook-data"):
            self.assertIn(identity, ids)
        sections = [attrs for tag, attrs in document.elements if tag == "section"]
        self.assertEqual(len(sections), 4)
        for attrs in sections:
            self.assertIn(attrs["aria-labelledby"], ids)
        self.assertLess(source.index("<nav"), source.index("<h1>"))
        self.assertIn(("a", {"href": "/playbooks", "aria-current": "page"}), document.elements)
        self.assertIn(("div", {"id": "playbook-persona-buttons", "role": "group",
                               "aria-label": "Filter by persona"}), document.elements)
        self.assertIn(("p", {"id": "playbook-status", "role": "status", "aria-live": "polite"}),
                      document.elements)
        self.assertEqual(len(document.scripts), 2)
        evidence, script = document.scripts
        self.assertEqual(evidence["attrs"], {"id": "playbook-data", "type": "application/json"})
        self.assertEqual(json.loads(evidence["text"]), studio.build_playbook_studio_catalog(fixture()))
        for expression in ("document.createElement", ".textContent =", 'addEventListener("click"',
                           'button.type = "button"', 'setAttribute("aria-pressed"',
                           'persona === "all" || item.persona === persona', 'select("all")'):
            self.assertIn(expression, script["text"])
        self.assertNotRegex(script["text"],
                            r"(?i)\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc|eval|"
                            r"setTimeout|setInterval|createContextualFragment|parseFromString)\b")
        self.assertNotRegex(script["text"], r"\bFunction\s*\(")
        self.assertNotRegex(script["text"], r"(?i)\bdocument\s*\.\s*(?:write|writeln)\s*\(")
        for _, attrs in document.elements:
            self.assertFalse(any(key.lower().startswith("on") for key in attrs))
            self.assertNotIn("srcdoc", attrs)
            self.assertFalse(any(re.match(r"(?i)\s*javascript:", value or "") for value in attrs.values()))
        self.assertFalse(any("src" in item["attrs"] for item in document.scripts))
        self.assert_opsec_clean(source)

    def test_xss_and_markdown_escaping_at_render_boundary(self):
        attack = '</script><img src=x onerror=alert(1)> & [click](javascript:alert(1)) | *bold* `x`\n# injected'
        data = studio.build_playbook_studio_catalog(fixture())
        data["playbook_Matrix"][0]["prompt"] = attack
        data["playbook_Matrix"][0]["response"]["plain_english_answer"] = attack
        data["ticket_templates"][0]["policy_id"] = attack
        data["decision_tree"]["levels"][0]["description"] = attack
        with patch.object(studio, "build_playbook_studio_catalog", return_value=data):
            source = studio.render_playbook_studio_html(fixture())
            report = studio.render_playbook_studio_markdown(fixture())
        document = Document(source)
        self.assertEqual(len(document.scripts), 2)
        self.assertFalse(any(tag == "img" for tag, _ in document.elements))
        self.assertNotIn(attack, source)
        evidence = document.scripts[0]["text"]
        self.assertNotRegex(evidence, r"[<>&]")
        self.assertEqual(json.loads(evidence), data)
        for literal in ("<img", "</script>", "\n# injected", "[click](javascript:", "*bold*", "`x`"):
            self.assertNotIn(literal, report)
        for escaped in ("&lt;img", "&amp;", r"\[click\]\(javascript:alert\(1\)\)",
                        r"\|", r"\*bold\*", r"\`x\`", r"\# injected"):
            self.assertIn(escaped, report)
        # An injected pipe remains within its original seven-cell table row.
        row = next(line for line in report.splitlines() if line.startswith("| &lt;/script"))
        self.assertEqual(len(re.findall(r"(?<!\\)\|", row)), 8)
        self.assert_opsec_clean(source)
        self.assert_opsec_clean(report)

    def test_opsec_across_exports_and_test_source(self):
        catalog = opsec_fixture()
        before = deepcopy(catalog)
        for export in EXPORTS:
            with self.subTest(export=export.__name__):
                self.assert_opsec_clean(export(catalog))
        encoded = json.dumps(studio.build_playbook_studio_catalog(catalog))
        for safe in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "[REDACTED]", "172.20.1.2", "ops.cluster.example.org"):
            self.assertIn(safe, encoded)
        self.assertTrue(catalog == before, "Caller telemetry changed; values withheld")
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertNotIn(b"\r", source)
        self.assert_opsec_clean(source)


class PlaybookStudioCLITests(OpsecAssertions, unittest.TestCase):
    def invoke(self, flags, rejected=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if rejected:
                with self.assertRaises(SystemExit) as error:
                    studio.main(flags)
                self.assertEqual(error.exception.code, 2)
            else:
                self.assertEqual(studio.main(flags), 0)
        self.assert_opsec_clean(stdout.getvalue())
        self.assert_opsec_clean(stderr.getvalue())
        if rejected:
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Invalid playbook studio request", stderr.getvalue())
            self.assertNotIn("private-untrusted-input", stderr.getvalue())
        else:
            self.assertEqual(stderr.getvalue(), "")
        return stdout.getvalue()

    def test_cli_default_json_markdown_and_catalog(self):
        self.assertEqual(json.loads(self.invoke([])), studio.build_playbook_studio_catalog())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for catalog in (fixture(), opsec_fixture()):
                path.write_text(json.dumps(catalog), encoding="utf-8")
                for flags in ([], ["--json"], ["--markdown"]):
                    output = self.invoke([*flags, "--catalog", str(path)])
                    if "--markdown" in flags:
                        self.assertEqual(output, studio.render_playbook_studio_markdown(catalog))
                    else:
                        self.assertEqual(json.loads(output), studio.build_playbook_studio_catalog(catalog))

    def test_cli_invalid_flags_ports_and_catalogs_never_echo_input(self):
        for index, flags in enumerate((
                ["--private-untrusted-input"], ["--j"], ["--catalog"],
                ["--json", "--markdown"], ["--serve", "--json"], ["--serve", "--markdown"],
                ["--port", "private-untrusted-input"],
                *(["--port", value] for value in ("0", "-1", "65536")),
                ["--catalog", "private-untrusted-input.json"])):
            with self.subTest(case=index):
                self.invoke(flags, rejected=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for content in ('{"private-untrusted-input":', '[]', '{"nodes":NaN}'):
                path.write_text(content, encoding="utf-8")
                self.invoke(["--catalog", str(path)], rejected=True)

    def test_cli_help_documents_all_flags(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as error:
                studio.main(["--help"])
        self.assertEqual(error.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        for flag in ("--json", "--markdown", "--catalog", "--serve", "--port"):
            self.assertIn(flag, stdout.getvalue())
        self.assert_opsec_clean(stdout.getvalue())

    def test_cli_serve_binds_only_loopback_and_closes_server(self):
        with patch.object(studio, "ThreadingHTTPServer") as server:
            instance = server.return_value.__enter__.return_value
            instance.serve_forever.side_effect = KeyboardInterrupt
            for flags, port in ((["--serve"], 8097), (["--serve", "--port", "18097"], 18097)):
                output = self.invoke(flags)
                self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                self.assertIn(f"http://127.0.0.1:{port}/playbooks", output)
            self.assertEqual(instance.serve_forever.call_count, 2)
            self.assertEqual(server.return_value.__exit__.call_count, 2)


class PlaybookStudioHTTPTests(OpsecAssertions, unittest.TestCase):
    def setUp(self):
        self.catalog = fixture()
        self.server = studio.ThreadingHTTPServer(("127.0.0.1", 0),
                                                 studio._build_playbook_handler(self.catalog))
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def request(self, path, status=200, content_type="application/json", method="GET"):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            self.assertEqual(response.status, status)
            self.assertEqual(response.getheader("Content-Type"), content_type + "; charset=utf-8")
            self.assertEqual(int(response.getheader("Content-Length")), len(body.encode("utf-8")))
            for name, value in (("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
                                ("X-Content-Type-Options", "nosniff")):
                self.assertEqual(response.getheader(name), value)
            self.assert_opsec_clean(body)
            self.assertNotIn("private-untrusted-input", body)
            return body
        finally:
            connection.close()

    def test_loopback_html_json_markdown_routes_and_input_immutability(self):
        before = deepcopy(self.catalog)
        for path, content_type in ROUTES:
            body = self.request(path, content_type=content_type)
            if content_type == "application/json":
                self.assertEqual(json.loads(body), studio.build_playbook_studio_catalog(self.catalog))
            elif content_type == "text/html":
                self.assertEqual(body, studio.render_playbook_studio_html(self.catalog))
            else:
                self.assertEqual(body, studio.render_playbook_studio_markdown(self.catalog))
        self.assertEqual(self.catalog, before)

    def test_bad_routes_queries_and_methods_fail_closed_without_logging(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            for path, _ in ROUTES:
                self.assertEqual(json.loads(self.request(path + "?private-untrusted-input=x", status=400)),
                                 {"error": "Invalid playbook studio request"})
            self.assertEqual(json.loads(self.request("/private-untrusted-input", status=404)),
                             {"error": "Not found"})
            self.assertEqual(json.loads(self.request("/playbooks", status=501, method="POST")),
                             {"error": "Invalid HTTP request"})
        self.assertEqual(stderr.getvalue(), "")

    def test_invalid_catalog_and_unexpected_failure_have_generic_errors(self):
        self.catalog.clear()
        for path, _ in ROUTES:
            self.assertEqual(json.loads(self.request(path, status=400)),
                             {"error": "Invalid playbook studio request"})
        with patch.object(studio, "build_playbook_studio_catalog",
                          side_effect=RuntimeError("private-untrusted-input")):
            for path, _ in ROUTES:
                self.assertEqual(json.loads(self.request(path, status=503)),
                                 {"error": "Playbook studio unavailable"})

    def test_opsec_across_all_http_outputs(self):
        self.catalog.update(opsec_fixture())
        before = deepcopy(self.catalog)
        for path, content_type in ROUTES:
            self.request(path, content_type=content_type)
        self.assertTrue(self.catalog == before, "Caller telemetry changed; values withheld")


if __name__ == "__main__":
    unittest.main()
