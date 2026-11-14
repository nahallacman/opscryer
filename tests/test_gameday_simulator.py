# SPDX-License-Identifier: Apache-2.0
"""STAGE-127 offline game-day, rendering, CLI, HTTP and OPSEC contracts."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html import escape
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

import gameday_simulator as gameday
from opscryer_backend import CONTRACT_VERSION
from tests.test_opscryer_public_smoke import opsec_findings


SCENARIOS = (
    "node_down_nodebeta02", "gitlab_runner_crashloop", "ingress_oidc_bypass",
    "gpu_thermal_hotspot", "combined_multi_plane_stress",
)


def fixture():
    """Healthy targets make increases observable without bundled live data."""
    nodes = []
    for name in ("nodebeta02", "nodegamma03"):
        nodes.append({
            "id": "k8s/Node//" + name, "label": name, "kind": "kubernetes_node",
            "domain": "deployments_k8s", "summary": "Offline healthy node",
            "primary_url": "https://ops.cluster.example.org", "drilldown_children": [],
            "resource_kind": "Node", "metrics": {"cpu_percent": 10, "ram_percent": 20},
            "resource": {"kind": "Node", "metadata": {"name": name},
                         "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
        })
    return {"schema_version": CONTRACT_VERSION, "nodes": nodes, "edges": [],
            "node_count": len(nodes), "edge_count": 0}


class Document(HTMLParser):
    """Record DOM structure and script text without executing JavaScript."""

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


class GamedayTests(unittest.TestCase):
    def assert_opsec_clean(self, value):
        if not isinstance(value, (str, bytes)):
            value = json.dumps(value, allow_nan=False)
        if isinstance(value, str):
            value = value.encode("utf-8")
        findings = opsec_findings(value)
        self.assertEqual(findings, dict.fromkeys(findings, 0),
                         "Prohibited telemetry detected; values withheld")

    def test_scenario_listing_is_complete_fresh_and_simulation_only(self):
        first = gameday.list_gameday_scenarios()
        original = deepcopy(first)
        self.assertIs(first["simulation_only"], True)
        self.assertEqual(first["schema_version"], "1.0")
        self.assertEqual([item["scenario_id"] for item in first["scenarios"]], list(SCENARIOS))
        for item in first["scenarios"]:
            for key in ("title", "category", "target_node_id", "description"):
                self.assertTrue(item[key])
        first["scenarios"][0]["title"] = "caller mutation"
        first["scenarios"].pop()
        self.assertEqual(gameday.list_gameday_scenarios(), original)
        self.assert_opsec_clean(original)

    def test_all_faults_have_positive_deltas_and_preserve_caller_catalog(self):
        catalog = fixture()
        before = deepcopy(catalog)
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                result = gameday.simulate_gameday_scenario(scenario, catalog)
                self.assertEqual(result["scenario_id"], scenario)
                self.assertIs(result["simulation_only"], True)
                self.assertIs(result["live_cluster_modified"], False)
                self.assertEqual(result["baseline"]["incident_counts"]["total"], 0)
                if scenario != "ingress_oidc_bypass":
                    self.assertGreater(result["delta"]["incident_counts"]["total"], 0)
                if scenario in ("ingress_oidc_bypass", "combined_multi_plane_stress"):
                    self.assertGreater(result["delta"]["routing_anomaly_counts"]["total"], 0)
                for plane in ("incident_counts", "node_counts", "pod_counts", "routing_anomaly_counts"):
                    for key, delta in result["delta"][plane].items():
                        if isinstance(delta, (int, float)):
                            self.assertEqual(delta, result["simulated"][plane][key]
                                             - result["baseline"][plane][key])
                if scenario in ("gpu_thermal_hotspot", "combined_multi_plane_stress"):
                    self.assertEqual(result["delta"]["node_metrics"]["k8s/Node//nodegamma03"],
                                     {"cpu_percent": 82, "ram_percent": 68})
                self.assertEqual(catalog, before)
                self.assertEqual(result, gameday.simulate_gameday_scenario(scenario, catalog))
                self.assert_opsec_clean(result)
                result["baseline"]["node_counts"]["total"] = -999
                self.assertEqual(catalog, before)

    def test_default_and_catalog_path_inputs(self):
        self.assertEqual(gameday.simulate_gameday_scenario()["scenario_id"], SCENARIOS[0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            expected = gameday.simulate_gameday_scenario(catalog=fixture())
            for value in (path, str(path)):
                self.assertEqual(gameday.simulate_gameday_scenario(catalog=value), expected)

    def test_unknown_scenarios_fail_closed_without_echo(self):
        for index, scenario in enumerate(("private-untrusted-input", "", None, [], {}, 7)):
            for export in (gameday.simulate_gameday_scenario, gameday.render_gameday_markdown):
                with self.subTest(case=index, export=export.__name__):
                    with self.assertRaisesRegex(ValueError, "^Unknown gameday scenario$"):
                        export(scenario, fixture())

    def assert_catalog_rejected(self, catalog):
        for export in (gameday.simulate_gameday_scenario, gameday.render_gameday_markdown,
                       gameday.render_gameday_simulator_html):
            with self.subTest(export=export.__name__):
                with self.assertRaisesRegex(ValueError, "^Invalid gameday catalog$"):
                    export(catalog=catalog)

    def test_malformed_catalogs_fail_closed_without_echo(self):
        duplicate, dangling, broken = fixture(), fixture(), fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        duplicate["node_count"] += 1
        dangling["edges"] = [{"source": dangling["nodes"][0]["id"],
                              "target": "private-untrusted-input", "relation": "hosted_on"}]
        dangling["edge_count"] = 1
        broken["nodes"][0]["resource"]["status"]["conditions"] = [None]
        for index, catalog in enumerate((False, [], {}, {"nodes": "private-untrusted-input"},
                                         duplicate, dangling, broken)):
            with self.subTest(case=index):
                self.assert_catalog_rejected(catalog)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-untrusted-input.json"
            self.assert_catalog_rejected(path)
            path.write_text('{"private-untrusted-input":', encoding="utf-8")
            self.assert_catalog_rejected(path)

    def test_nonfinite_numbers_rejected_even_inside_redacted_fields(self):
        for label, number in (("nan", float("nan")), ("inf", float("inf")),
                              ("negative_inf", -float("inf"))):
            for field in ("metrics", "token"):
                with self.subTest(number=label, field=field):
                    catalog = fixture()
                    catalog["nodes"][0][field] = {"cpu_percent": number}
                    self.assert_catalog_rejected(catalog)

    def test_markdown_sections_all_scenarios_and_catalog_immutability(self):
        catalog = fixture()
        before = deepcopy(catalog)
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                report = gameday.render_gameday_markdown(scenario, catalog)
                self.assertTrue(report.startswith("# Game-Day Simulation Report\n"))
                for title in ("Scenario Summary", "Baseline vs. Simulated KPI Delta",
                              "Newly Triggered Incidents", "Tabletop Containment Checklist"):
                    self.assertIn("## " + title, report)
                self.assertIn("Simulation only", report)
                self.assertIn("| KPI | Baseline | Simulated | Delta |", report)
                self.assertIn("- [ ]", report)
                self.assert_opsec_clean(report)
        self.assertEqual(catalog, before)

    def test_html_structure_unique_ids_evidence_and_safe_dom_updates(self):
        catalog = fixture()
        before = deepcopy(catalog)
        source = gameday.render_gameday_simulator_html(catalog)
        document = Document(source)
        self.assertTrue(source.startswith("<!DOCTYPE html>"))
        ids = [attrs["id"] for _, attrs in document.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for identity in ("gameday-scenario-buttons", "gameday-kpi-grid", "gameday-delta-table",
                         "gameday-delta-rows", "gameday-runbook", "gameday-status", "gameday-data"):
            self.assertIn(identity, ids)
        self.assertLess(source.index("<nav"), source.index("<h1>"))
        self.assertIn(("tbody", {"id": "gameday-delta-rows"}), document.elements)
        self.assertEqual(len(document.scripts), 2)
        evidence, script = document.scripts
        self.assertEqual(evidence["attrs"], {"id": "gameday-data", "type": "application/json"})
        payload = json.loads(evidence["text"])
        self.assertIs(payload["simulation_only"], True)
        self.assertEqual([item["scenario_id"] for item in payload["scenarios"]], list(SCENARIOS))
        self.assertEqual(payload["simulations"],
                         [gameday.simulate_gameday_scenario(s, catalog) for s in SCENARIOS])
        self.assertIn("createElement", script["text"])
        self.assertIn(".textContent =", script["text"])
        self.assertIn('addEventListener("click"', script["text"])
        self.assertIn('button.type = "button"', script["text"])
        self.assertIn('setAttribute("aria-pressed"', script["text"])
        self.assertNotRegex(source, r"(?i)\b(?:innerHTML|outerHTML|insertAdjacentHTML|write|writeln|eval|Function)\s*(?:[=(])")
        self.assertNotRegex(source, r"(?i)\b(?:srcdoc|on\w+)\s*=")
        self.assertNotRegex(source, r"(?i)(?:javascript:|<script\b[^>]*\bsrc\s*=)")
        self.assertEqual(catalog, before)
        self.assert_opsec_clean(source)

    def test_xss_and_markdown_payloads_are_escaped_at_export_boundary(self):
        attack = '</script><img src=x onerror=alert(1)> & [click](javascript:alert(1)) | *bold* `x`\n# injected'
        listing = gameday.list_gameday_scenarios()
        listing["scenarios"][0]["title"] = attack
        with patch.object(gameday, "list_gameday_scenarios", return_value=listing):
            source = gameday.render_gameday_simulator_html(fixture())
            document = Document(source)
            self.assertEqual(len(document.scripts), 2)
            self.assertFalse(any(tag == "img" for tag, _ in document.elements))
            self.assertNotIn(attack, source)
            self.assertEqual(json.loads(document.scripts[0]["text"])["scenarios"][0]["title"], attack)
            self.assertNotRegex(document.scripts[0]["text"], r"[<>&]")
            report = gameday.render_gameday_markdown(catalog=fixture())
        expected = re.sub(r"([\\`*_{}\[\]()#+.!|>~$-])", r"\\\1",
                          escape(" ".join(attack.split()), quote=True))
        self.assertIn("- Title: " + expected, report)
        self.assertNotIn("<img", report)
        self.assertNotIn("\n# injected", report)
        self.assertNotIn("[click](javascript:", report)

    def test_opsec_across_exports_and_test_source(self):
        # Synthetic probes are assembled in memory; never show their values.
        probes = [str(IPv4Address(0x08080808)), ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))]
        probes += [prefix + "synthetic127" for prefix in
                   ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        catalog = fixture()
        identity = "probe " + " ".join(probes) + " 172.20.1.2 ops.cluster.example.org"
        catalog["nodes"][0]["id"] = identity
        before = deepcopy(catalog)
        for scenario in SCENARIOS:
            self.assert_opsec_clean(gameday.simulate_gameday_scenario(scenario, catalog))
            self.assert_opsec_clean(gameday.render_gameday_markdown(scenario, catalog))
        self.assert_opsec_clean(gameday.render_gameday_simulator_html(catalog))
        self.assertEqual(catalog, before)
        result = json.dumps(gameday.simulate_gameday_scenario(catalog=catalog))
        for safe in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "[REDACTED]", "172.20.1.2", "ops.cluster.example.org"):
            self.assertIn(safe, result)
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertNotIn(b"\r", source)
        self.assert_opsec_clean(source)


class GamedayCLITests(unittest.TestCase):
    assert_opsec_clean = GamedayTests.assert_opsec_clean

    def invoke(self, flags, rejected=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if rejected:
                with self.assertRaises(SystemExit) as error:
                    gameday.main(flags)
                self.assertEqual(error.exception.code, 2)
            else:
                self.assertEqual(gameday.main(flags), 0)
        self.assert_opsec_clean(stdout.getvalue())
        self.assert_opsec_clean(stderr.getvalue())
        if rejected:
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Invalid gameday simulator request", stderr.getvalue())
            self.assertNotIn("private-untrusted-input", stderr.getvalue())
        else:
            self.assertEqual(stderr.getvalue(), "")
        return stdout.getvalue()

    def test_cli_json_markdown_scenario_and_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            for scenario in SCENARIOS:
                for flags in ([], ["--json"], ["--markdown"]):
                    with self.subTest(scenario=scenario, mode=flags):
                        output = self.invoke([*flags, "--catalog", str(path), "--scenario", scenario])
                        if "--markdown" in flags:
                            self.assertEqual(output, gameday.render_gameday_markdown(scenario, fixture()))
                        else:
                            self.assertEqual(json.loads(output), gameday.simulate_gameday_scenario(scenario, fixture()))
            self.assertEqual(json.loads(self.invoke(["--json"]))["scenario_id"], SCENARIOS[0])

    def test_cli_invalid_flags_and_catalogs_do_not_echo(self):
        for index, flags in enumerate((
                ["--private-untrusted-input"], ["--scenario", "private-untrusted-input"],
                ["--scenario"], ["--json", "--markdown"], ["--serve", "--json"],
                ["--j"], ["--port", "private-untrusted-input"],
                *(["--port", value] for value in ("0", "-1", "65536")),
                ["--catalog", "private-untrusted-input.json"])):
            with self.subTest(case=index):
                self.invoke(flags, rejected=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for content in ('{"private-untrusted-input":', '[]', '{"nodes":NaN}'):
                path.write_text(content, encoding="utf-8")
                self.invoke(["--catalog", str(path)], rejected=True)

    def test_cli_serve_binds_only_loopback(self):
        with patch.object(gameday, "ThreadingHTTPServer") as server:
            server.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
            self.invoke(["--serve"])
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8096))
            self.invoke(["--serve", "--port", "18096"])
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 18096))


class GamedayHTTPTests(unittest.TestCase):
    assert_opsec_clean = GamedayTests.assert_opsec_clean

    def setUp(self):
        self.catalog = fixture()
        self.before = deepcopy(self.catalog)
        self.server = gameday.ThreadingHTTPServer(("127.0.0.1", 0),
                                                  gameday._build_gameday_handler(self.catalog))
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.catalog, self.before)

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

    def test_html_json_and_markdown_routes(self):
        for path in ("/", "/simulator"):
            self.assertEqual(self.request(path, content_type="text/html"),
                             gameday.render_gameday_simulator_html(self.catalog))
        for scenario in SCENARIOS:
            query = "?" + urlencode({"scenario": scenario})
            self.assertEqual(json.loads(self.request("/api/v1/gameday-simulator" + query)),
                             gameday.simulate_gameday_scenario(scenario, self.catalog))
            self.assertEqual(self.request("/simulator/report.md" + query, content_type="text/markdown"),
                             gameday.render_gameday_markdown(scenario, self.catalog))
        self.assertEqual(json.loads(self.request("/api/v1/gameday-simulator"))["scenario_id"], SCENARIOS[0])
        self.assertEqual(self.request("/simulator/report.md", content_type="text/markdown"),
                         gameday.render_gameday_markdown(catalog=self.catalog))

    def test_bad_routes_queries_and_methods_fail_closed(self):
        for path in ("/api/v1/gameday-simulator?scenario=private-untrusted-input",
                     "/simulator/report.md?scenario=private-untrusted-input",
                     "/api/v1/gameday-simulator?scenario=", "/api/v1/gameday-simulator?scenario",
                     "/api/v1/gameday-simulator?private-untrusted-input=x",
                     "/api/v1/gameday-simulator?scenario=x&scenario=y",
                     "/api/v1/gameday-simulator?scenario=%FF", "/simulator?scenario=x", "/?scenario=x"):
            with self.subTest(path=path):
                self.assertEqual(json.loads(self.request(path, status=400)),
                                 {"error": "Invalid gameday simulator request"})
        self.assertEqual(json.loads(self.request("/private-untrusted-input", status=404)),
                         {"error": "Not found"})
        self.assertEqual(json.loads(self.request("/simulator", status=501, method="POST")),
                         {"error": "Invalid HTTP request"})

    def test_unexpected_failure_returns_generic_unavailable_response(self):
        with patch.object(gameday, "simulate_gameday_scenario",
                          side_effect=RuntimeError("private-untrusted-input")):
            self.assertEqual(json.loads(self.request("/api/v1/gameday-simulator", status=503)),
                             {"error": "Gameday simulator unavailable"})


if __name__ == "__main__":
    unittest.main()
