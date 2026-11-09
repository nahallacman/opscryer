# SPDX-License-Identifier: Apache-2.0
"""Offline incident extraction, safe exports, CLI and loopback HTTP contracts."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import http.client
from html import escape
from html.parser import HTMLParser
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

from golden_path_gates import _opsec_count
import incident_commander as commander
from opscryer_backend import CONTRACT_VERSION
import opscryer_browser


def graph_node(identity, kind, domain="deployments_k8s", **extra):
    return {"id": identity, "label": identity, "kind": kind, "domain": domain,
            "summary": "Synthetic offline evidence", "primary_url": "https://ops.cluster.example.org",
            "drilldown_children": [], **extra}


def fixture(healthy=False):
    nodes = [graph_node("root", "company_root", "company_org"),
             graph_node("hardware", "server", "hardware_topology")]

    def resource(name, kind, status, spec=None, metrics=None):
        nodes.append(graph_node(name, "kubernetes_" + kind.lower(), resource_kind=kind,
                                resource={"kind": kind,
                                          "metadata": {"name": name, "namespace": "apps"},
                                          "spec": spec or {}, "status": status},
                                metrics=metrics or {}))

    resource("worker", "Node", {"conditions": [{"type": "Ready", "status": "True"}]})
    if not healthy:
        resource("down", "Node", {"conditions": [{"type": "Ready", "status": "False"}]})
        resource("hot-cpu", "Node", {"conditions": [{"type": "Ready", "status": "True"}]},
                 metrics={"cpu_percent": 80, "ram_percent": 10})
        resource("hot-ram", "Node", {"conditions": [{"type": "Ready", "status": "True"}]},
                 metrics={"cpu_percent": 10, "ram_percent": 75})
        resource("failed", "Pod", {"phase": "Failed"})
        resource("pending", "Pod", {"phase": "Pending"})
        resource("crashing", "Pod", {"phase": "Failed", "containerStatuses": [
            {"state": {"waiting": {"reason": "CrashLoopBackOff"}}}]})
        resource("unavailable", "Deployment", {}, {"replicas": 2})
        resource("partial", "Deployment", {"readyReplicas": 1}, {"replicas": 2})
    resource("running", "Pod", {"phase": "Running"})
    resource("completed", "Pod", {"phase": "Succeeded"})
    resource("ready", "Deployment", {"readyReplicas": 2}, {"replicas": 2})
    resource("scaled-zero", "Deployment", {}, {"replicas": 0})
    edges = [{"source": "worker", "target": "hardware", "relation": "hosted_on"},
             {"source": "hardware", "target": "root", "relation": "contained_by"}]
    edges.extend({"source": node["id"], "target": "worker", "relation": "scheduled_on"}
                 for node in nodes[3:])
    return {"schema_version": CONTRACT_VERSION, "nodes": nodes, "edges": edges}


class IncidentCatalogTests(unittest.TestCase):
    def test_extraction_priority_counts_and_shortest_hardware_lineage(self):
        active = commander.build_active_incidents_catalog(fixture())
        records = active["incidents"]
        self.assertEqual(active["summary_counts"], {
            "total": 8, "by_severity": {"SEV-1": 1, "SEV-2": 3, "SEV-3": 3, "SEV-4": 1},
            "by_category": {"node_not_ready": 1, "node_hotspot": 2, "pod_failed": 1,
                            "pod_pending": 1, "pod_crash_loop": 1, "deployment_degraded": 2}})
        expected = {"down": ("SEV-1", "node_not_ready"),
                    "hot-cpu": ("SEV-3", "node_hotspot"),
                    "hot-ram": ("SEV-3", "node_hotspot"),
                    "failed": ("SEV-2", "pod_failed"), "pending": ("SEV-4", "pod_pending"),
                    "crashing": ("SEV-2", "pod_crash_loop"),
                    "unavailable": ("SEV-2", "deployment_degraded"),
                    "partial": ("SEV-3", "deployment_degraded")}
        # There are eight affected resources; the total assertion below catches double counting.
        self.assertEqual(len(records), len(expected))
        for record in records:
            identity = record["affected_node_id"]
            self.assertEqual((record["severity"], record["category"]), expected[identity])
            self.assertEqual(record["hardware_lineage_ids"], [identity, "worker", "hardware"])
            self.assertEqual(record["namespace"], "" if identity in {"down", "hot-cpu", "hot-ram"}
                             else "apps")
            self.assertRegex(record["incident_id"], r"^INC-[0-9a-f]{20}$")
        self.assertEqual(len({record["incident_id"] for record in records}), len(records))
        self.assertEqual([record["severity"] for record in records],
                         sorted(record["severity"] for record in records))
        self.assertIn("not live paging", active["notice"])

    def test_determinism_path_inputs_and_input_immutability(self):
        catalog = fixture()
        before = deepcopy(catalog)
        expected = commander.build_active_incidents_catalog(catalog)
        self.assertEqual(catalog, before)
        catalog["nodes"].reverse()
        catalog["edges"].reverse()
        self.assertEqual(commander.build_active_incidents_catalog(catalog), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            for value in (path, str(path)):
                self.assertEqual(commander.build_active_incidents_catalog(value), expected)

    def test_healthy_snapshot_and_unreachable_or_containment_lineage(self):
        active = commander.build_active_incidents_catalog(fixture(healthy=True))
        self.assertEqual(active["incidents"], [])
        self.assertEqual(active["summary_counts"]["total"], 0)
        self.assertTrue(all(count == 0 for count in active["summary_counts"]["by_severity"].values()))
        catalog = fixture()
        catalog["edges"] = [{"source": "failed", "target": "root", "relation": "contained_by"}]
        records = {item["affected_node_id"]: item for item in
                   commander.build_active_incidents_catalog(catalog)["incidents"]}
        self.assertEqual(records["failed"]["hardware_lineage_ids"], ["failed", "root"])
        self.assertEqual(records["pending"]["hardware_lineage_ids"], [])

    def test_invalid_catalogs_fail_closed_before_policy_evaluation(self):
        duplicate = fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        dangling = fixture()
        dangling["edges"][0]["target"] = "private-invalid-target"
        invalid = ([], False, {}, {"nodes": []}, duplicate, dangling)
        with patch.object(commander.jev_client, "explain_jev_decision_path") as policy:
            for catalog in invalid:
                for function in (commander.build_active_incidents_catalog,
                                 commander.build_blameless_pir_markdown,
                                 lambda value: commander.generate_incident_runbook(catalog=value)):
                    with self.subTest(catalog_type=type(catalog).__name__, function=function):
                        with self.assertRaises(ValueError) as error:
                            function(catalog)
                        self.assertNotIn("private-invalid-target", str(error.exception))
            policy.assert_not_called()


class RunbookAndPIRTests(unittest.TestCase):
    def test_default_and_selected_runbooks_are_read_only_with_policy_breadcrumbs(self):
        catalog = fixture()
        before = deepcopy(catalog)
        records = commander.build_active_incidents_catalog(catalog)["incidents"]
        self.assertEqual(commander.generate_incident_runbook(catalog=catalog)["incident"], records[0])
        for record in records:
            result = commander.generate_incident_runbook(record["incident_id"], catalog)
            self.assertEqual(result["incident"], record)
            self.assertIs(result["simulation_only"], True)
            self.assertGreaterEqual(len(result["diagnostic_commands"]), 3)
            for command in result["diagnostic_commands"]:
                self.assertRegex(command, r"^kubectl (?:get |describe |rollout history )")
            self.assertIn("rollback", " ".join(result["containment_checklist"]))
            self.assertIn("approval", " ".join(result["containment_checklist"]))
            self.assertTrue(result["jev_decision"]["plain_english_why"])
            self.assertIn("breadcrumbs", result["jev_decision"])
            if record["affected_node_id"] == "partial":
                self.assertIn("kubectl rollout history deployment partial --namespace apps",
                              result["diagnostic_commands"])
        self.assertEqual(catalog, before)

    def test_idle_and_unknown_incident_ids(self):
        result = commander.generate_incident_runbook(catalog=fixture(healthy=True))
        self.assertIsNone(result["incident"])
        self.assertEqual(result["diagnostic_commands"], [])
        self.assertIn("No active incidents", result["containment_checklist"][0])
        for identity in ("", "private-unknown-id"):
            with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "^Unknown incident ID$"):
                commander.generate_incident_runbook(identity, fixture())

    def test_shell_metacharacters_and_option_injection_use_collection_queries(self):
        for name, namespace, expected in (("bad; echo injected", "apps", " --namespace apps"),
                                           ("--help", "apps", " --namespace apps"),
                                           ("failed", "apps; echo injected", " --all-namespaces")):
            catalog = fixture()
            node = next(node for node in catalog["nodes"] if node["id"] == "failed")
            node["resource"]["metadata"].update(name=name, namespace=namespace)
            record = next(item for item in commander.build_active_incidents_catalog(catalog)["incidents"]
                          if item["affected_node_id"] == "failed")
            commands = commander.generate_incident_runbook(record["incident_id"], catalog)["diagnostic_commands"]
            self.assertEqual(commands[:2], ["kubectl get pods" + expected + " -o wide",
                                            "kubectl describe pods" + expected])
            self.assertNotIn("injected", " ".join(commands))

    def test_pir_sections_evidence_and_empty_snapshot(self):
        catalog = fixture()
        before = deepcopy(catalog)
        report = commander.build_blameless_pir_markdown(catalog)
        self.assertTrue(report.startswith("# Blameless Post-Incident Review (PIR)\n"))
        for text in ("## Incident summary", "### Diagnostic runbook",
                     "### Containment and rollback review", "### Jev policy breadcrumbs",
                     "### Learning and follow-up", "without assigning blame", "remain unconfirmed",
                     "    kubectl get", "- [ ]"):
            self.assertIn(text, report)
        for record in commander.build_active_incidents_catalog(catalog)["incidents"]:
            self.assertIn(record["incident_id"], report)
        self.assertEqual(report, commander.build_blameless_pir_markdown(catalog))
        self.assertEqual(catalog, before)
        self.assertIn("No active incidents were identified",
                      commander.build_blameless_pir_markdown(fixture(healthy=True)))

    def test_pir_escapes_untrusted_html_and_markdown(self):
        catalog = fixture()
        node = next(node for node in catalog["nodes"] if node["id"] == "failed")
        node["resource"]["metadata"]["name"] = "<script>alert(1)</script>\n## forged | [link](bad)"
        report = commander.build_blameless_pir_markdown(catalog)
        self.assertNotIn("<script>", report)
        self.assertNotIn("\n## forged", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn(r"\| \[link\]\(bad\)", report)


class IncidentHTMLTests(unittest.TestCase):
    def test_dom_ids_navigation_and_no_unsafe_dom_updates(self):
        tags = []

        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                tags.append((tag, dict(attrs)))

        html = commander.render_incident_commander_html(fixture())
        Parser().feed(html)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertTrue({"html", "title", "nav", "h1", "pre"} <= {tag for tag, _ in tags})
        ids = [attrs["id"] for _, attrs in tags if "id" in attrs]
        self.assertTrue({"incident-kpi-grid", "incidents-grid", "incident-evidence-json",
                         "incident-severity-filters", "runbook-panel"} <= set(ids))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(identity.strip() for identity in ids))
        # Every script ID lookup must target an existing dashboard element.
        for identity in re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", html):
            self.assertIn(identity, ids)
        self.assertTrue({"/", "/chat", "/incidents", "/capacity", "/network", "/gitops",
                         "/executive", "/hub", "/incidents/pir.md"} <= {
            attrs.get("href") for tag, attrs in tags if tag == "a"})
        filters = [attrs for tag, attrs in tags if tag == "button" and "data-severity" in attrs]
        self.assertEqual([attrs["data-severity"] for attrs in filters],
                         ["All", "SEV-1", "SEV-2", "SEV-3", "SEV-4"])
        for attrs in filters:
            self.assertEqual(attrs["type"], "button")
            self.assertEqual(attrs["aria-pressed"],
                             "true" if attrs["data-severity"] == "All" else "false")
        self.assertLess(html.index("<nav>"), html.index("<h1>"))
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(unsafe, html)
        self.assertFalse(any(tag == "script" and "src" in attrs for tag, attrs in tags))
        self.assertFalse(any(tag == "link" and attrs.get("rel") == "stylesheet" for tag, attrs in tags))

    def test_embedded_evidence_is_html_escaped(self):
        evidence = {"summary": '<img src=x onerror="alert(1)"> & evidence'}
        with patch.object(commander, "build_active_incidents_catalog", return_value=evidence):
            html = commander.render_incident_commander_html()
        self.assertNotIn("<img", html)
        self.assertIn("&lt;img", html)
        self.assertIn("&amp; evidence", html)


class IncidentCLITests(unittest.TestCase):
    def test_json_markdown_and_selected_incident_flags(self):
        catalog = fixture()
        expected = commander.build_active_incidents_catalog(catalog)
        identity = expected["incidents"][-1]["incident_id"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            for flags, result in ((["--json"], expected),
                                  (["--json", "--incident-id", identity],
                                   commander.generate_incident_runbook(identity, catalog)),
                                  (["--incident-id", identity],
                                   commander.generate_incident_runbook(identity, catalog))):
                with self.subTest(flags=flags), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(commander.main(["--catalog", str(path)] + flags), 0)
                self.assertEqual(json.loads(output.getvalue()), result)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(commander.main(["--catalog", str(path), "--markdown"]), 0)
            self.assertEqual(output.getvalue(), commander.build_blameless_pir_markdown(catalog))

    def test_invalid_flags_catalogs_and_ids_have_fixed_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-invalid-file.json"
            path.write_text("private-invalid-json", encoding="utf-8")
            with patch.object(commander, "DEFAULT_CATALOG_PATH", fixture()):
                for args in (["--catalog", str(path)], ["--incident-id", "private-unknown-id"],
                             ["--markdown", "--incident-id", "private-unknown-id"],
                             ["--json", "--markdown"], ["--port", "0"],
                             ["--port", "private-invalid-port"], ["--private-invalid-option"]):
                    with self.subTest(args=args), redirect_stderr(io.StringIO()) as error, \
                            redirect_stdout(io.StringIO()) as output:
                        with self.assertRaises(SystemExit) as raised:
                            commander.main(args)
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(output.getvalue(), "")
                    self.assertIn("Invalid incident commander arguments", error.getvalue())
                    self.assertNotIn("private-", error.getvalue())


class IncidentHTTPTests(unittest.TestCase):
    def start_server(self, handler):
        server = commander.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        return server

    def request(self, server, path):
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(int(response.getheader("Content-Length")), len(body))
            self.assertEqual(_opsec_count(body), 0)
            return response.status, response.getheader("Content-Type"), body
        finally:
            connection.close()

    def test_standalone_pages_api_selected_runbook_and_markdown(self):
        catalog = fixture()
        server = self.start_server(commander._build_incident_handler(catalog))
        expected = commander.build_active_incidents_catalog(catalog)
        for path in ("/", "/incidents"):
            status, content_type, body = self.request(server, path)
            self.assertEqual(status, 200)
            self.assertIn("text/html", content_type)
            self.assertTrue(body.startswith(b"<!DOCTYPE html>"))
            self.assertEqual(body.decode(), commander.render_incident_commander_html(catalog))
            self.assertIn(b'<a href="/incidents/pir.md">PIR Markdown</a>', body)
            self.assertIn('<pre id="incident-evidence-json">' +
                          escape(json.dumps(expected, indent=2, allow_nan=False)) + '</pre>',
                          body.decode())
        status, content_type, body = self.request(server, "/api/v1/incident-commander")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        self.assertEqual(json.loads(body), expected)
        identity = expected["incidents"][0]["incident_id"]
        status, _, body = self.request(server, "/api/v1/incident-commander?" +
                                       urlencode({"incident_id": identity}))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), commander.generate_incident_runbook(identity, catalog))
        status, content_type, body = self.request(server, "/incidents/pir.md")
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", content_type)
        self.assertEqual(body.decode(), commander.build_blameless_pir_markdown(catalog))

    def test_standalone_invalid_requests_and_failure_redaction(self):
        server = self.start_server(commander._build_incident_handler(fixture()))
        for path in ("/api/v1/incident-commander?incident_id=private-unknown-id",
                     "/api/v1/incident-commander?incident_id=",
                     "/api/v1/incident-commander?incident_id=a&incident_id=b",
                     "/api/v1/incident-commander?private-parameter=x",
                     "/incidents/pir.md?incident_id=x"):
            status, _, body = self.request(server, path)
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body), {"error": "Invalid incident request"})
        self.assertEqual(self.request(server, "/missing")[0], 404)
        with patch.object(commander, "build_active_incidents_catalog",
                          side_effect=RuntimeError("private-exception-details")):
            status, _, body = self.request(server, "/api/v1/incident-commander")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"error": "Incident commander unavailable"})
        invalid_server = self.start_server(commander._build_incident_handler({}))
        self.assertEqual(self.request(invalid_server, "/api/v1/incident-commander")[0], 400)

    def test_browser_incident_routes_and_api_query_validation(self):
        handler = opscryer_browser._build_frontend_handler()
        with patch.object(handler, "log_message"):
            server = self.start_server(handler)
            with patch.object(commander, "DEFAULT_CATALOG_PATH", fixture()):
                status, content_type, body = self.request(server, "/incidents")
                self.assertEqual(status, 200)
                self.assertIn("text/html", content_type)
                self.assertEqual(body.decode(), commander.render_incident_commander_html())
                status, content_type, body = self.request(server, "/api/v1/incident-commander")
                self.assertEqual(status, 200)
                self.assertIn("application/json", content_type)
                self.assertEqual(json.loads(body), commander.build_active_incidents_catalog())
                self.assertEqual(self.request(server, "/api/v1/incident-commander?extra=1")[0], 400)


class IncidentOPSECTests(unittest.TestCase):
    def test_all_exports_scrub_sensitive_telemetry_without_mutating_input(self):
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        secret = "gh" + "p_" + "synthetic_test_value"
        dirty = " ".join((wan, mac, secret, "10.1.2.3", "game.cluster.example.org"))
        catalog = fixture()
        node = next(node for node in catalog["nodes"] if node["id"] == "failed")
        node["resource"]["metadata"]["name"] = dirty
        before = deepcopy(catalog)
        active = commander.build_active_incidents_catalog(catalog)
        identity = next(item["incident_id"] for item in active["incidents"]
                        if item["affected_node_id"] == "failed")
        with patch.object(commander, "DEFAULT_CATALOG_PATH", catalog):
            outputs = (json.dumps(active),
                       json.dumps(commander.generate_incident_runbook(identity, catalog)),
                       commander.build_blameless_pir_markdown(catalog),
                       commander.render_incident_commander_html())
        for output in outputs:
            self.assertEqual(_opsec_count(output.encode("utf-8")), 0)
            self.assertTrue(all(raw not in output for raw in (wan, mac, secret)))
            for clean in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "game.cluster.example.org"):
                self.assertIn(clean, output)
        self.assertEqual(catalog, before)

    def test_bundled_snapshot_exports_and_test_source_have_zero_opsec_violations(self):
        active = commander.build_active_incidents_catalog()
        self.assertTrue(active["incidents"])
        outputs = (json.dumps(active), json.dumps(commander.generate_incident_runbook()),
                   commander.build_blameless_pir_markdown(), commander.render_incident_commander_html())
        for output in outputs:
            self.assertEqual(_opsec_count(output.encode("utf-8")), 0)
        self.assertEqual(_opsec_count(Path(__file__).read_bytes()), 0)


if __name__ == "__main__":
    unittest.main()
