# SPDX-License-Identifier: Apache-2.0
"""STAGE-139 offline grounding, fail-closed boundaries, presentation and transport."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
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
from urllib.parse import urlencode

import model_tier_copilot as copilot
from opscryer_backend import CONTRACT_VERSION, validate_spatial_graph_contract
from tests.test_opscryer_public_smoke import opsec_findings


def fixture():
    """Explicit policy anchor, failed node and real hardware edge; no gate mocks.

    Historical observations model raw snapshot volume, not additional retrieved
    facts. Compression assertions apply to this fixture, not arbitrary tiny graphs.
    """
    nodes = []
    for identity, label, kind, domain, summary in (
        ("root-company", "Offline company", "company_root", "company_org", "Policy root"),
        ("host-mini", "nodebeta02 hardware", "server", "hardware_topology", "Physical host"),
        ("node-mini", "nodebeta02", "kubernetes_node", "deployments_k8s",
         "Manifest nodebeta02 NotReady failed pods GitLab runner game lag governance OSCAL"),
    ):
        nodes.append({"id": identity, "label": label, "kind": kind, "domain": domain,
                      "summary": summary, "primary_url": "https://ops.cluster.example.org",
                      "drilldown_children": []})
    nodes[0]["drilldown_children"] = ["host-mini"]
    nodes[1]["drilldown_children"] = ["node-mini"]
    nodes[2].update(resource_kind="Node", metrics={"cpu_percent": 20, "ram_percent": 30},
                    resource={"kind": "Node", "metadata": {"name": "nodebeta02"},
                              "status": {"conditions": [{"type": "Ready", "status": "False"}]}})
    return {"schema_version": CONTRACT_VERSION, "root_id": "root-company",
            "nodes": nodes, "node_count": len(nodes), "edge_count": 2,
            "edges": [{"source": "root-company", "target": "host-mini", "relation": "contains"},
                      {"source": "node-mini", "target": "host-mini", "relation": "hosted_on"}],
            "observation_history": [{"sample": index, "node": "node-mini", "ready": False,
                                     "source": "offline historical observation"}
                                    for index in range(600)]}


EXPORTS = (
    lambda catalog: copilot.build_dual_tier_context_pack(catalog=catalog),
    lambda catalog: copilot.run_dual_tier_model_comparison(catalog=catalog),
    copilot.build_model_copilot_benchmark_matrix,
    copilot.render_model_copilot_markdown,
    copilot.render_model_copilot_html,
)


class Document(HTMLParser):
    """Inspect element identities and script boundaries without executing input."""

    def __init__(self, source):
        super().__init__()
        self.elements, self.scripts = [], []
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


@contextmanager
def serving(catalog):
    server = copilot.ThreadingHTTPServer(("127.0.0.1", 0),
                                          copilot._build_model_copilot_handler(catalog))
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01},
                              daemon=True)
    worker.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError("Loopback server failed to stop")


class ModelTierCopilotTests(unittest.TestCase):
    def assert_clean(self, value):
        if not isinstance(value, (str, bytes)):
            value = json.dumps(value, allow_nan=False)
        if isinstance(value, str):
            value = value.encode("utf-8")
        findings = opsec_findings(value)
        self.assertEqual(findings, dict.fromkeys(findings, 0),
                         "Prohibited telemetry detected; values withheld")

    def assert_playbook(self, playbook):
        for key in ("immediate_actions", "diagnostic_commands", "verification_criteria"):
            self.assertTrue(playbook[key])
            self.assertTrue(all(isinstance(step, str) and step.strip() for step in playbook[key]))
        self.assertIn("kubectl describe node nodebeta02", playbook["diagnostic_commands"])
        for command in playbook["diagnostic_commands"]:
            self.assertRegex(command, r"^kubectl (get|describe) ")
        actions = " ".join(playbook["immediate_actions"]).lower()
        for term in ("read-only", "capacity", "ticket", "approval"):
            self.assertIn(term, actions)
        self.assertIn("Ready", " ".join(playbook["verification_criteria"]))
        self.assertIn("incident commander", playbook["escalation_policy"])
        for key in ("policy_id", "direct_access_allowed", "required_it_tickets",
                    "anchor_present_in_snapshot"):
            self.assertIn(key, playbook["required_ticket"])
        self.assertTrue(playbook["cited_node_ids"])

    def test_context_compression_grounding_and_actionable_playbook(self):
        catalog = fixture()
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        with patch.object(copilot, "urlopen", side_effect=AssertionError("Unexpected network")):
            data = copilot.build_dual_tier_context_pack(catalog=catalog)
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["status"], "ok")
        self.assertIs(data["read_only"], True)
        self.assertIs(data["airlock_blocked"], False)
        metrics = data["compression_metrics"]

        def tokens(value):
            encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                                 separators=(",", ":")).encode("utf-8")
            return (len(encoded) + 3) // 4

        self.assertEqual(metrics["raw_snapshot_estimated_tokens"], tokens(catalog))
        for tier in ("low_power", "high_power"):
            self.assertEqual(metrics[tier + "_pack_tokens"], tokens(data[tier + "_model_pack"]))
        self.assertLess(metrics["low_power_pack_tokens"], 400)
        self.assertGreater(metrics["compression_ratio_percent"], 95)
        self.assertEqual(metrics["compression_ratio_percent"], round(
            100 * (1 - metrics["low_power_pack_tokens"] / metrics["raw_snapshot_estimated_tokens"]), 4))
        self.assert_playbook(data["what_to_do_playbook"])
        high = data["high_power_model_pack"]
        self.assertTrue(high["bm25_evidence"])
        self.assertTrue(high["hardware_lineage"])
        self.assertTrue(any("host-mini" in path["path_ids"] for path in high["hardware_lineage"]))
        for key in ("jev_decision", "selected_incidents", "capacity", "resource_audit",
                    "drain_simulation", "architectural_synthesis"):
            self.assertTrue(high[key])
        self.assert_clean(data)

    def test_comparison_citation_accuracy_and_shared_policy_parity(self):
        catalog = fixture()
        with patch.object(copilot, "urlopen", side_effect=AssertionError("Unexpected network")):
            data = copilot.run_dual_tier_model_comparison(catalog=catalog)
        self.assertEqual(data["status_code"], 200)
        self.assertTrue(data["deterministic_demo"])
        self.assertTrue(data["jev_ticket_routing_parity"])
        self.assertEqual(data["citation_accuracy_percent"], 100)
        self.assertEqual(data["policy_accuracy_percent"], 100)
        self.assert_playbook(data["what_to_do_playbook"])
        graph_ids = {node["id"] for node in catalog["nodes"]}
        low, high = (data["tiers"][key] for key in ("low_power", "high_power"))
        for tier in (low, high):
            self.assertEqual(tier["status"], "ok")
            self.assertTrue(tier["cited_node_ids"])
            self.assertLessEqual(set(tier["cited_node_ids"]), graph_ids)
            self.assertEqual(tier["cited_node_ids"], tier["context_pack"]["cited_node_ids"])
            self.assertEqual(tier["citation_count"], len(tier["cited_node_ids"]))
            self.assertEqual(tier["valid_citation_count"], tier["citation_count"])
            self.assertEqual(tier["citation_accuracy_percent"], 100)
            self.assertEqual(tier["policy_accuracy_percent"], 100)
            self.assertGreater(tier["grounded_input_estimated_tokens"],
                               tier["context_pack_estimated_tokens"])
            for key in ("diagnostic_commands", "verification_criteria", "required_ticket",
                        "escalation_policy"):
                self.assertEqual(tier[key], data["what_to_do_playbook"][key])
            self.assertEqual(tier["what_to_do"], data["what_to_do_playbook"]["immediate_actions"])
        self.assertLessEqual(set(low["cited_node_ids"]), set(high["cited_node_ids"]))
        self.assertLess(low["context_pack_estimated_tokens"], high["context_pack_estimated_tokens"])
        self.assert_clean(data)

    def test_benchmark_four_operational_scenarios_and_secret_denial(self):
        matrix = copilot.build_model_copilot_benchmark_matrix(fixture())
        self.assertEqual(matrix["scenario_count"], 5)
        self.assertEqual(matrix["passed_count"], 5)
        self.assertTrue(matrix["passed"])
        self.assertEqual([row["scenario_id"] for row in matrix["scenarios"]],
                         ["hardware_outage", "cicd_runner_failure", "household_game_lag",
                          "governance_oscal_posture", "airlock_blocked_secret"])
        for row in matrix["scenarios"]:
            self.assertTrue(row["passed"])
            data = row["comparison"]
            self.assertEqual(data["airlock_blocked"], row["expected_airlock_blocked"])
            self.assertEqual(data["status_code"], 403 if row["expected_airlock_blocked"] else 200)
            if not row["expected_airlock_blocked"]:
                self.assertEqual(data["citation_accuracy_percent"], 100)
                self.assertEqual(data["policy_accuracy_percent"], 100)
                self.assert_playbook(data["what_to_do_playbook"])
        self.assert_clean(matrix)

    def test_airlock_blocks_before_retrieval_analysis_or_provider_calls(self):
        for question in ("Manifest database password private-untrusted-input", "unsupported intent"):
            with self.subTest(case=question.split()[0]), \
                    patch.object(copilot, "KnowledgeGraphBackendEngine") as engine, \
                    patch.object(copilot.jev_client, "explain_jev_decision_path") as decision, \
                    patch.object(copilot.incident_commander, "build_active_incidents_catalog") as incidents, \
                    patch.object(copilot.capacity_planner, "summarize_cluster_capacity") as capacity, \
                    patch.object(copilot, "urlopen") as network:
                context = copilot.build_dual_tier_context_pack(question, fixture())
                data = copilot.run_dual_tier_model_comparison(question, fixture(), provider="ollama")
                for output in (context, data):
                    self.assertEqual(output["status_code"], 403)
                    self.assertTrue(output["airlock_blocked"])
                    self.assertNotIn(question, json.dumps(output))
                    self.assert_clean(output)
                self.assertEqual(context["what_to_do_playbook"]["diagnostic_commands"], [])
                for tier in data["tiers"].values():
                    for key in ("what_to_do", "diagnostic_commands", "cited_node_ids"):
                        self.assertEqual(tier[key], [])
                    self.assertEqual(tier["status"], "blocked")
                for dependency in (engine, decision, incidents, capacity, network):
                    dependency.assert_not_called()

    def test_missing_policy_anchor_is_preserved_as_denial(self):
        catalog = fixture()
        catalog = json.loads(json.dumps(catalog).replace('"root-company"', '"cluster-home"'))
        data = copilot.run_dual_tier_model_comparison(catalog=catalog)
        self.assertEqual(data["status_code"], 403)
        matrix = copilot.build_model_copilot_benchmark_matrix(catalog)
        self.assertEqual(matrix["passed_count"], 1)
        self.assertFalse(matrix["passed"])
        for row in matrix["scenarios"]:
            self.assertEqual(row["comparison"]["status_code"], 403)
        self.assertNotIn("root-company", json.dumps(catalog))

    def test_all_exports_preserve_caller_catalog_and_return_detached_results(self):
        catalog = fixture()
        before = deepcopy(catalog)
        for index, export in enumerate(EXPORTS):
            with self.subTest(export=index):
                expected = export(catalog)
                self.assertEqual(catalog, before)
                self.assert_clean(expected)
                if isinstance(expected, dict):
                    mutated = export(catalog)
                    # Mutate nested lists and dictionaries, not just the outer result.
                    def damage(value):
                        if isinstance(value, dict):
                            for item in list(value.values()):
                                damage(item)
                            value["caller_mutation"] = True
                        elif isinstance(value, list):
                            for item in value:
                                damage(item)
                            value.clear()
                    damage(mutated)
                    self.assertEqual(export(catalog), expected)
                    self.assertEqual(catalog, before)

    def assert_rejected(self, catalog):
        for index, export in enumerate(EXPORTS):
            with self.subTest(export=index):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(ValueError) as raised:
                        export(catalog)
                self.assertEqual(str(raised.exception), "Invalid model copilot catalog")
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")
                self.assert_clean(str(raised.exception))

    def test_malformed_catalogs_fail_closed_without_untrusted_input_echo(self):
        duplicate, dangling, mismatch, malformed = (fixture() for _ in range(4))
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        duplicate["node_count"] += 1
        dangling["edges"][0]["target"] = "private-untrusted-input"
        mismatch["node_count"] += 1
        malformed["nodes"][2]["resource"]["status"] = "private-untrusted-input"
        for index, catalog in enumerate((False, 7, [], {}, {"nodes": "private-untrusted-input"},
                                         duplicate, dangling, mismatch, malformed)):
            with self.subTest(case=index):
                self.assert_rejected(catalog)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-untrusted-input.json"
            self.assert_rejected(path)
            for content in ('{"private-untrusted-input":', '[]',
                            '{"nodes":[],"nodes":[],"private-untrusted-input":true}'):
                path.write_text(content, encoding="utf-8")
                self.assert_rejected(path)

    def test_nonfinite_catalogs_rejected_even_inside_secret_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for number in ("nan", "inf", "-inf"):
                for field in ("metrics", "token"):
                    with self.subTest(number=number, field=field):
                        catalog = fixture()
                        catalog["nodes"][2][field] = {"private-untrusted-input": float(number)}
                        self.assert_rejected(catalog)
                        path.write_text(json.dumps(catalog), encoding="utf-8")
                        self.assert_rejected(path)

    def test_catalog_path_string_and_default_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            for export in EXPORTS:
                expected = export(fixture())
                self.assertEqual(export(path), expected)
                self.assertEqual(export(str(path)), expected)
                with patch.object(copilot, "DEFAULT_CATALOG_PATH", path):
                    self.assertEqual(export(None), expected)
        self.assertEqual(copilot.build_dual_tier_context_pack(),
                         copilot.build_dual_tier_context_pack(catalog=copilot.DEFAULT_CATALOG_PATH))

    def test_markdown_structure_and_complete_scenario_sections(self):
        report = copilot.render_model_copilot_markdown(fixture())
        self.assertTrue(report.startswith("# Dual-Tier AI Model Grounding & What-To-Do Copilot\n"))
        self.assertIn("Benchmark scenarios passed: 5 / 5", report)
        for title in ("Context Compression Metrics", "What To Do Now",
                      "Low-Power vs. High-Power Model Comparison"):
            self.assertEqual(report.count("\n### " + title + "\n"), 5)
        self.assertEqual(report.count("\n## "), 5)
        self.assertIn("| Metric | Low-Power Model | High-Power Model |", report)
        self.assertIn("HTTP 403", report)
        self.assertIn("No operational guidance is available", report)
        self.assert_clean(report)

    def test_html_structure_unique_ids_and_text_only_dom_updates(self):
        source = copilot.render_model_copilot_html(fixture())
        self.assertTrue(source.startswith("<!DOCTYPE html>"))
        doc = Document(source)
        ids = [attrs["id"] for _, attrs in doc.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for identity in ("copilot-scenario-buttons", "copilot-compression-grid", "copilot-status",
                         "copilot-what-to-do", "copilot-tier-comparison", "model-copilot-data"):
            self.assertIn(identity, ids)
        self.assertEqual(sum(tag == "main" for tag, _ in doc.elements), 1)
        for _, attrs in doc.elements:
            for key in ("aria-labelledby", "aria-describedby"):
                for target in attrs.get(key, "").split():
                    self.assertIn(target, ids)
            self.assertFalse(any(key.lower().startswith("on") for key in attrs))
            self.assertFalse(any(value.lower().startswith("javascript:") for value in attrs.values()))
        self.assertEqual(len(doc.scripts), 2)
        evidence, script = doc.scripts
        self.assertEqual(evidence["attrs"]["type"], "application/json")
        self.assertEqual(json.loads(evidence["text"]),
                         copilot.build_model_copilot_benchmark_matrix(fixture()))
        js = script["text"]
        for pattern in (r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc)\b",
                        r"document\s*\.\s*write(?:ln)?\s*\(", r"\beval\s*\(",
                        r"\bnew\s+Function\b", r"\b(?:fetch|XMLHttpRequest)\b"):
            self.assertNotRegex(js, pattern)
        for fragment in ("element.textContent =", "document.createElement(tag)",
                         'button.addEventListener("click"', 'add(element, "meter"',
                         '"Low-Power Model"', '"High-Power Model"'):
            self.assertIn(fragment, js)
        self.assertIn("color-scheme:dark", source)
        self.assert_clean(source)

    def test_untrusted_evidence_is_escaped_in_html_and_markdown(self):
        payload = '</script><img src=x onerror="alert(1)"> & [click](javascript:alert(1)) | *bold*\n# injected'
        matrix = copilot.build_model_copilot_benchmark_matrix(fixture())
        matrix["notice"] = payload
        matrix["scenarios"][0]["comparison"]["tiers"]["low_power"]["synthesis"] = payload
        with patch.object(copilot, "build_model_copilot_benchmark_matrix", return_value=matrix):
            source = copilot.render_model_copilot_html()
            report = copilot.render_model_copilot_markdown()
        doc = Document(source)
        self.assertEqual(len(doc.scripts), 2)
        self.assertFalse(any(tag == "img" for tag, _ in doc.elements))
        self.assertNotIn(payload, source)
        self.assertIn(r"\u003c/script\u003e", source)
        self.assertEqual(json.loads(doc.scripts[0]["text"])["notice"], payload)
        self.assertNotIn("<img", report)
        self.assertNotIn("[click](", report)
        self.assertNotIn("\n# injected", report)
        for escaped in ("&lt;img", r"\[click\]\(javascript:alert\(1\)\)", r"\|", r"\*bold\*"):
            self.assertIn(escaped, report)
        for line in report.splitlines():
            if line.startswith("| Grounded response |"):
                self.assertEqual(len(re.split(r"(?<!\\)\|", line)), 5)
        self.assert_clean(source)
        self.assert_clean(report)

    def run_cli(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = copilot.main(argv)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assert_clean(stdout.getvalue())
        return stdout.getvalue()

    def test_cli_json_markdown_question_and_catalog_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            for flags in ([], ["--json"]):
                data = json.loads(self.run_cli(flags + ["--catalog", str(path)]))
                self.assertEqual(data, copilot.build_model_copilot_benchmark_matrix(fixture()))
            report = self.run_cli(["--markdown", "--catalog", str(path)])
            self.assertEqual(report, copilot.render_model_copilot_markdown(fixture()))
            for question, status in ((copilot.DEFAULT_QUESTION, 200), ("Manifest password", 403)):
                data = json.loads(self.run_cli(["--json", "--question", question,
                                               "--catalog", str(path)]))
                self.assertEqual(data["status_code"], status)

    def test_cli_invalid_flags_fail_without_input_echo(self):
        cases = (["--private-untrusted-input"], ["--json", "--markdown"],
                 ["--port", "private-untrusted-input"], ["--port", "0"], ["--port", "65536"],
                 ["--question", ""], ["--question", "private-untrusted-input\n"],
                 ["--markdown", "--question", "private-untrusted-input"],
                 ["--serve", "--question", "private-untrusted-input"],
                 ["--catalog", "private-untrusted-input.json"])
        for index, args in enumerate(cases):
            with self.subTest(case=index):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        copilot.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn("Invalid model copilot request", stderr.getvalue())
                self.assertNotIn("private-untrusted-input", stderr.getvalue())
                self.assert_clean(stderr.getvalue())

    def test_cli_serve_binds_only_ipv4_loopback_and_honors_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            for flags, port in (([], 8098), (["--port", "18098"], 18098)):
                with patch.object(copilot, "DEFAULT_CATALOG_PATH", path), \
                        patch.object(copilot, "ThreadingHTTPServer") as server:
                    running = server.return_value.__enter__.return_value
                    running.serve_forever.side_effect = KeyboardInterrupt
                    output = self.run_cli(["--serve"] + flags)
                    self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                    running.serve_forever.assert_called_once_with()
                    self.assertIn("http://127.0.0.1:" + str(port) + "/models", output)

    def request(self, address, path, method="GET"):
        connection = http.client.HTTPConnection(*address, timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            headers = dict(response.getheaders())
            status = response.status
        finally:
            connection.close()
        self.assert_clean(body)
        self.assert_clean(headers)
        self.assertEqual(int(headers["Content-Length"]), len(body.encode("utf-8")))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        return status, headers["Content-Type"], body

    def test_loopback_http_routes_and_optional_question(self):
        catalog = fixture()
        before = deepcopy(catalog)
        stderr = io.StringIO()
        with redirect_stderr(stderr), serving(catalog) as address:
            for route, content_type, expected in (
                ("/", "text/html", copilot.render_model_copilot_html(catalog)),
                ("/models", "text/html", copilot.render_model_copilot_html(catalog)),
                ("/models/copilot.md", "text/markdown", copilot.render_model_copilot_markdown(catalog)),
                ("/api/v1/model-copilot", "application/json", None),
            ):
                status, mime, body = self.request(address, route)
                self.assertEqual(status, 200)
                self.assertEqual(mime, content_type + "; charset=utf-8")
                if expected is None:
                    self.assertEqual(json.loads(body), copilot.build_model_copilot_benchmark_matrix(catalog))
                else:
                    self.assertEqual(body, expected)
            for question, expected_status in ((copilot.DEFAULT_QUESTION, 200),
                                               ("Manifest password private-untrusted-input", 403)):
                status, _, body = self.request(address, "/api/v1/model-copilot?" + urlencode({"q": question}))
                self.assertEqual(status, expected_status)
                self.assertEqual(json.loads(body), copilot.run_dual_tier_model_comparison(question, catalog))
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(catalog, before)

    def test_http_invalid_queries_unknown_routes_and_methods_never_echo(self):
        with serving(fixture()) as address:
            for query in ("q=", "q=a&q=b", "other=private-untrusted-input", "q=%ZZ", "q=%FF",
                          "q=%00private-untrusted-input", "q=%0A", "q"):
                status, _, body = self.request(address, "/api/v1/model-copilot?" + query)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {"error": "Invalid model copilot request"})
            for route in ("/", "/models", "/models/copilot.md"):
                status, _, _ = self.request(address, route + "?q=private-untrusted-input")
                self.assertEqual(status, 400)
            status, _, body = self.request(address, "/private-untrusted-input")
            self.assertEqual(status, 404)
            self.assertEqual(json.loads(body), {"error": "Not found"})
            status, _, body = self.request(address, "/models", method="POST")
            self.assertEqual(status, 501)
            self.assertEqual(json.loads(body), {"error": "Invalid HTTP request"})

    def test_http_catalog_and_internal_errors_are_generic(self):
        with serving({"nodes": "private-untrusted-input"}) as address:
            for route in ("/models", "/models/copilot.md", "/api/v1/model-copilot"):
                status, _, body = self.request(address, route)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {"error": "Invalid model copilot request"})
        with serving(fixture()) as address, patch.object(
                copilot, "render_model_copilot_html", side_effect=RuntimeError("private-untrusted-input")):
            status, _, body = self.request(address, "/models")
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(body), {"error": "Model copilot unavailable"})

    def test_opsec_across_exports_cli_http_and_test_source(self):
        # Construct synthetic probes only in memory; never include them in failures.
        probes = [str(IPv4Address(0x08080808)), ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))]
        probes += [prefix + "synthetic139" for prefix in
                   ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        catalog = fixture()
        catalog["nodes"][2]["summary"] += " " + " ".join(probes) + " 172.20.1.2 ops.cluster.example.org"
        before = deepcopy(catalog)
        outputs = [export(catalog) for export in EXPORTS]
        for output in outputs:
            self.assert_clean(output)
        encoded = json.dumps(outputs[0])
        for marker in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "172.20.1.2", "ops.cluster.example.org"):
            self.assertIn(marker, encoded)
        self.assertTrue(all(probe not in encoded for probe in probes), "Unscrubbed probe; values withheld")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            self.run_cli(["--json", "--catalog", str(path)])
            self.run_cli(["--markdown", "--catalog", str(path)])
        with serving(catalog) as address:
            for route in ("/", "/models", "/models/copilot.md", "/api/v1/model-copilot",
                          "/api/v1/model-copilot?" + urlencode({"q": copilot.DEFAULT_QUESTION})):
                self.assertEqual(self.request(address, route)[0], 200)
        self.assertEqual(catalog, before)
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assert_clean(source)


if __name__ == "__main__":
    unittest.main()
