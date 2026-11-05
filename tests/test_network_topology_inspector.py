# SPDX-License-Identifier: Apache-2.0
"""Offline route evidence, rendering boundaries, CLI and OPSEC checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import network_topology_inspector as inspector
from golden_path_gates import _opsec_count


def node(identity, kind, namespace=None, **fields):
    metadata = {"name": identity}
    if namespace is not None:
        metadata["namespace"] = namespace
    return {"id": identity, "resource": {
        "kind": kind, "metadata": metadata, **fields}}


def fixture(configured=False):
    ingress = node("ingress", "Ingress", "monitoring", spec={"rules": [{
        "host": "metrics.cluster.example.org", "http": {"paths": [{"path": "/",
        "backend": {"service": {"name": "service", "port": {"number": 80}}}}]}}]})
    if configured:
        prefix = "nginx.ingress.kubernetes.io/"
        ingress["resource"]["metadata"]["annotations"] = {
            prefix + "auth-url": "https://auth.cluster.example.org/outpost.goauthentik.io/auth/nginx",
            prefix + "auth-signin": "https://auth.cluster.example.org/outpost.goauthentik.io/start?rd=$escaped_request_uri"}
        ingress["resource"]["spec"]["tls"] = [{"hosts": ["metrics.cluster.example.org"]}]
    pod = node("pod", "Pod", "monitoring", spec={"nodeName": "worker"},
               status={"phase": "Running"})
    pod["resource"]["metadata"].update(labels={"app": "metrics"},
        ownerReferences=[{"kind": "Deployment", "name": "deployment"}])
    return {"source": "synthetic-offline", "nodes": [
        node("monitoring", "Namespace"), ingress,
        node("service", "Service", "monitoring", spec={"selector": {"app": "metrics"}}),
        node("deployment", "Deployment", "monitoring", spec={"replicas": 1},
             status={"readyReplicas": 1}), pod, node("worker", "Node")], "edges": []}


def get_node(data, identity):
    return next(item for item in data["nodes"] if item["id"] == identity)


def link(source, target, relation):
    return {"source": source, "target": target, "relation": relation}


EXPORTERS = (inspector.trace_ingress_to_hardware_routes,
             inspector.build_namespace_exposure_matrix,
             inspector.detect_routing_anomalies,
             inspector.export_network_mermaid_diagram,
             inspector.render_network_inspector_html)


class RouteTests(unittest.TestCase):
    def test_metadata_resolves_complete_lineage(self):
        report = inspector.trace_ingress_to_hardware_routes(fixture())
        self.assertEqual(report["ingress_count"], 1)
        route = report["routes"][0]
        self.assertEqual(route["hosts"], ["metrics.cluster.example.org"])
        self.assertEqual(route["namespace_node_id"], "monitoring")
        service = route["services"][0]
        self.assertEqual(service["name"], "service")
        pod = service["pods"][0]
        self.assertEqual(pod["hardware_nodes"][0]["name"], "worker")
        self.assertEqual(pod["workloads"][0]["name"], "deployment")
        self.assertTrue(pod["hardware_observed"])
        self.assertFalse(report["provenance"]["live_collection"])
        self.assertFalse(report["oidc_posture"]["enforcement_verified"])

    def test_directed_graph_and_cyclic_ownership_deduplicate(self):
        data = fixture()
        get_node(data, "ingress")["resource"]["spec"] = {}
        get_node(data, "service")["resource"]["spec"] = {}
        get_node(data, "pod")["resource"]["spec"] = {}
        data["nodes"].append(node("replicaset", "ReplicaSet", "monitoring"))
        data["edges"] = [link("ingress", "service", "routes_to"),
            link("service", "deployment", "routes_to"),
            link("deployment", "replicaset", "owns_workload"),
            link("replicaset", "deployment", "owns_workload"),
            link("replicaset", "pod", "owns_workload"),
            link("pod", "worker", "runs_on_hardware")]
        data["edges"] += deepcopy(data["edges"])
        service = inspector.trace_ingress_to_hardware_routes(data)["routes"][0]["services"][0]
        self.assertEqual(len(service["pods"]), 1)
        self.assertEqual(len(service["pods"][0]["hardware_nodes"]), 1)
        self.assertEqual({w["name"] for w in service["workloads"]},
                         {"deployment", "replicaset"})

    def test_namespace_boundaries_and_missing_backends(self):
        data = fixture()
        get_node(data, "service")["resource"]["metadata"]["namespace"] = "other"
        data["edges"] = [link("ingress", "service", "routes_to")]
        route = inspector.trace_ingress_to_hardware_routes(data)["routes"][0]
        self.assertEqual(route["services"], [])
        self.assertEqual(route["missing_services"], ["service"])

    def test_no_inference_from_namespace_or_absent_hardware(self):
        data = fixture()
        get_node(data, "service")["resource"]["spec"] = {}
        service = inspector.trace_ingress_to_hardware_routes(data)["routes"][0]["services"][0]
        self.assertEqual(service["pods"], [])
        self.assertFalse(service["pods_observed"])
        data = fixture()
        data["nodes"] = [n for n in data["nodes"] if n["id"] != "worker"]
        pod = inspector.trace_ingress_to_hardware_routes(data)["routes"][0]["services"][0]["pods"][0]
        self.assertEqual(pod["assigned_node_name"], "worker")
        self.assertEqual(pod["hardware_nodes"], [])
        self.assertFalse(pod["hardware_observed"])

    def test_default_and_legacy_backends(self):
        for backend in ({"service": {"name": "service"}}, {"serviceName": "service"}):
            with self.subTest(backend=backend):
                data = fixture()
                get_node(data, "ingress")["resource"]["spec"] = {"defaultBackend": backend}
                route = inspector.trace_ingress_to_hardware_routes(data)["routes"][0]
                self.assertEqual(route["hosts"], [])
                self.assertEqual(route["services"][0]["name"], "service")


class ExposureAndAnomalyTests(unittest.TestCase):
    def test_configured_and_unknown_oidc_remain_unverified(self):
        for configured in (False, True):
            with self.subTest(configured=configured):
                report = inspector.build_namespace_exposure_matrix(fixture(configured))
                self.assertEqual((report["namespace_count"], report["ingress_count"],
                                  report["service_count"]), (1, 1, 1))
                row = report["namespaces"][0]
                self.assertEqual(row["chaos_isolation_plane"], "control_plane")
                self.assertEqual(row["cross_plane_barrier_status"], "assumed")
                self.assertEqual(row["oidc_posture"]["configured_count"], int(configured))
                self.assertEqual(row["oidc_posture"]["unknown_count"], int(not configured))
                self.assertEqual(row["oidc_posture"]["status"],
                                 "configured_observed_fields" if configured else "unknown")
                self.assertTrue(row["simulation_only"])
                self.assertFalse(row["live_enforcement_verified"])
                self.assertFalse(row["oidc_posture"]["enforcement_verified"])

    def test_unmapped_declared_and_default_namespaces(self):
        data = {"nodes": [node("unmapped", "Namespace"), node("service", "Service")], "edges": []}
        rows = inspector.build_namespace_exposure_matrix(data)["namespaces"]
        self.assertEqual([row["namespace"] for row in rows], ["default", "unmapped"])
        self.assertEqual(rows[0]["service_count"], 1)
        for row in rows:
            self.assertIsNone(row["chaos_isolation_plane"])
            self.assertEqual(row["cross_plane_barrier_status"], "unmapped")
            self.assertEqual(row["oidc_posture"]["status"], "no_ingresses_observed")

    def test_orphan_degraded_and_oidc_findings(self):
        data = fixture()
        data["nodes"].append(node("orphan", "Service", "monitoring"))
        get_node(data, "pod")["resource"]["status"]["phase"] = "Pending"
        report = inspector.detect_routing_anomalies(data)
        self.assertEqual(report["summary_counts"], {"orphan_service": 1,
            "degraded_endpoints": 1, "ingress_oidc_unverified": 1})
        self.assertEqual(report["finding_count"], 3)
        for finding in report["findings"]:
            for command in finding["inspection_commands"]:
                self.assertRegex(command, r"^kubectl (get|describe) ")
            if finding["category"] == "degraded_endpoints":
                self.assertEqual([r["name"] for r in finding["resources"]], ["pod"])
            elif finding["category"] == "ingress_oidc_unverified":
                self.assertFalse(finding["enforcement_verified"])

    def test_healthy_or_unknown_health_has_no_degraded_findings(self):
        for unknown in (False, True):
            data = fixture(True)
            if unknown:
                for identity in ("pod", "deployment"):
                    get_node(data, identity)["resource"].pop("status")
            self.assertEqual(inspector.detect_routing_anomalies(data)["findings"], [])

    def test_unready_pods_controllers_and_endpoint_records(self):
        for kind in ("pod-condition", "container", "controller", "Endpoints", "EndpointSlice"):
            with self.subTest(kind=kind):
                data = fixture(True)
                if kind == "pod-condition":
                    get_node(data, "pod")["resource"]["status"]["conditions"] = [
                        {"type": "Ready", "status": "False"}]
                elif kind == "container":
                    get_node(data, "pod")["resource"]["status"]["containerStatuses"] = [{"ready": False}]
                elif kind == "controller":
                    get_node(data, "deployment")["resource"]["status"]["readyReplicas"] = 0
                    data["edges"] = [link("service", "deployment", "routes_to")]
                else:
                    data["nodes"].append(node("endpoints", kind, "monitoring"))
                report = inspector.detect_routing_anomalies(data)
                self.assertEqual(report["summary_counts"]["degraded_endpoints"], 1)

    def test_cross_namespace_matching_pod_does_not_back_service(self):
        data = fixture(True)
        get_node(data, "pod")["resource"]["metadata"]["namespace"] = "other"
        data["edges"] = [link("service", "pod", "routes_to")]
        report = inspector.detect_routing_anomalies(data)
        self.assertEqual(report["summary_counts"]["orphan_service"], 1)

    def test_untrusted_names_never_enter_shell_commands(self):
        data = {"nodes": [node("orphan; echo injected", "Service", "bad;namespace")], "edges": []}
        finding = inspector.detect_routing_anomalies(data)["findings"][0]
        for command in finding["inspection_commands"]:
            self.assertIn("--all-namespaces", command)
            self.assertNotIn(";", command)
            self.assertNotIn("injected", command)


class RenderingTests(unittest.TestCase):
    def test_mermaid_observed_links_and_generated_identifiers(self):
        diagram = inspector.export_network_mermaid_diagram(fixture())
        self.assertTrue(diagram.startswith("flowchart LR\n"))
        self.assertIn('Ingress: metrics.cluster.example.org #40;ingress#41;', diagram)
        self.assertIn('Namespace: monitoring', diagram)
        self.assertIn('Hardware: worker', diagram)
        self.assertEqual(len(re.findall(r"^    n\d+ --> n\d+$", diagram, re.M)), 2)
        self.assertEqual(len(re.findall(r'^    n\d+\["', diagram, re.M)), 3)

    def test_mermaid_omits_non_home_hosts_and_missing_hardware(self):
        data = fixture()
        get_node(data, "ingress")["resource"]["spec"]["rules"][0]["host"] = "example.invalid"
        self.assertEqual(inspector.export_network_mermaid_diagram(data), "flowchart LR\n")
        data = fixture()
        data["nodes"] = [n for n in data["nodes"] if n["id"] != "worker"]
        self.assertNotIn("Hardware:", inspector.export_network_mermaid_diagram(data))

    def test_mermaid_catalog_labels_cannot_inject_syntax(self):
        data = fixture()
        attack = '\"]; evil-->injected; <script>&'
        get_node(data, "ingress")["resource"]["metadata"]["name"] = attack
        diagram = inspector.export_network_mermaid_diagram(data)
        self.assertNotIn(attack, diagram)
        self.assertIn("#34;", diagram)
        self.assertIn("#60;", diagram)
        self.assertEqual(diagram.count(" --> "), 2)

    def test_html_embedded_json_roundtrips_without_script_injection(self):
        data = fixture()
        attack = '</script><img src=x onerror="alert(1)">&'
        data["source"] = attack
        html = inspector.render_network_inspector_html(data)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        HTMLParser().feed(html)
        self.assertNotIn(attack, html)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("document.write", html)
        self.assertNotRegex(html, r'<script\b[^>]*\bsrc=')
        self.assertIn("td.textContent = value", html)
        payload = re.search(r'<script id="network-data" type="application/json">(.*?)</script>',
                            html, re.S)[1]
        self.assertNotIn("<", payload)
        evidence = json.loads(payload)
        self.assertEqual(evidence["routes"]["source"], attack)
        self.assertEqual(evidence["routes"]["ingress_count"], 1)
        self.assertEqual(evidence["mermaid"], inspector.export_network_mermaid_diagram(data))
        for route in ("/", "/chat", "/incidents", "/capacity", "/network"):
            self.assertIn('href="' + route + '"', html)


class CatalogAndOpsecTests(unittest.TestCase):
    def test_empty_catalog(self):
        data = {"nodes": [], "edges": []}
        self.assertEqual(inspector.trace_ingress_to_hardware_routes(data)["routes"], [])
        self.assertEqual(inspector.build_namespace_exposure_matrix(data)["namespaces"], [])
        self.assertEqual(inspector.detect_routing_anomalies(data)["finding_count"], 0)
        self.assertEqual(inspector.export_network_mermaid_diagram(data), "flowchart LR\n")
        self.assertIn("No ingress routes observed.", inspector.render_network_inspector_html(data))

    def test_invalid_catalogs_fail_without_echoing_input(self):
        duplicate = fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        cases = [[], {}, {"nodes": {}}, {"nodes": [None]},
                 {"nodes": [{"id": "private-input", "resource": []}]},
                 {"nodes": [], "edges": {}},
                 {"nodes": [], "edges": [link("absent", "missing", "routes_to")]},
                 {"nodes": [], "source": float("nan")}, duplicate]
        for export in EXPORTERS:
            for index, data in enumerate(cases):
                with self.subTest(export=export.__name__, case=index):
                    with self.assertRaisesRegex(ValueError, "^Invalid cluster catalog$"):
                        export(data)

    def test_paths_and_input_immutability_and_repeatability(self):
        data = fixture()
        original = deepcopy(data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            for export in EXPORTERS:
                with self.subTest(export=export.__name__):
                    result = export(data)
                    self.assertEqual(result, export(data))
                    self.assertEqual(result, export(path))
                    self.assertEqual(result, export(str(path)))
                    self.assertEqual(data, original)
            path.write_text("{invalid", encoding="utf-8")
            for export in EXPORTERS:
                with self.assertRaises(ValueError):
                    export(path)
                with self.assertRaises(ValueError):
                    export(path.with_name("missing.json"))

    def test_synthetic_sensitive_telemetry_is_scrubbed_in_every_export(self):
        # Build synthetic markers at runtime to keep this source public-safe.
        wan = ".".join(map(str, (93, 184, 216, 34)))
        mac = ":".join(("AA", "BB", "CC", "12", "34", "56"))
        credentials = [prefix + "syntheticcredential" for prefix in
                       ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        data = fixture()
        data["source"] = " ".join([wan, mac, *credentials,
                                   "10.2.3.4", "172.20.2.3", "172.20.1.2", "metrics.cluster.example.org"])
        for export in EXPORTERS:
            with self.subTest(export=export.__name__):
                result = export(data)
                text = result if isinstance(result, str) else json.dumps(result)
                self.assertEqual(_opsec_count(text.encode("utf-8")), 0)
                # Avoid reflecting sensitive fixture values in failure messages.
                self.assertFalse(any(marker in text for marker in [wan, mac, *credentials]))
                if export is not inspector.export_network_mermaid_diagram:
                    self.assertIn("203.0.113.1", text)
                    self.assertIn("AA:BB:CC:XX:XX:XX", text)
                    for allowed in ("10.2.3.4", "172.20.2.3", "172.20.1.2", "metrics.cluster.example.org"):
                        self.assertIn(allowed, text)

    def test_bundled_snapshot_and_test_source_have_zero_opsec_violations(self):
        for export in EXPORTERS:
            with self.subTest(export=export.__name__):
                result = export()
                text = result if isinstance(result, str) else json.dumps(result)
                self.assertEqual(_opsec_count(text.encode("utf-8")), 0)
        self.assertEqual(_opsec_count(Path(__file__).read_bytes()), 0)


class CliTests(unittest.TestCase):
    def test_json_default_and_mermaid_catalog_flags(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            for flags in ([], ["--json"], ["--mermaid"]):
                with self.subTest(flags=flags):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(inspector.main([*flags, "--catalog", str(path)]), 0)
                    text = output.getvalue()
                    self.assertEqual(_opsec_count(text.encode("utf-8")), 0)
                    if flags == ["--mermaid"]:
                        self.assertEqual(text, inspector.export_network_mermaid_diagram(data))
                    else:
                        report = json.loads(text)
                        self.assertEqual(set(report), {"routes", "exposure", "anomalies", "mermaid"})
                        self.assertEqual(report["routes"]["ingress_count"], 1)

    def test_serve_defaults_custom_port_and_keyboard_interrupt(self):
        for flags, port in (([], 8092), (["--port", "18092"], 18092)):
            with self.subTest(port=port):
                with patch.object(inspector, "_load_catalog", return_value=fixture()), \
                     patch.object(inspector, "ThreadingHTTPServer") as server, \
                     redirect_stdout(io.StringIO()):
                    server.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
                    self.assertEqual(inspector.main(["--serve", *flags]), 0)
                    self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                    server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_invalid_flags_ports_and_catalogs_have_fixed_errors(self):
        for flags in (["--json", "--mermaid"], ["--serve", "--json"],
                      ["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                      ["--unknown-private-input"], ["--j"],
                      ["--catalog", "missing-private-input.json"]):
            with self.subTest(case=flags[0]):
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    with self.assertRaises(SystemExit) as caught:
                        inspector.main(flags)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("Invalid network inspector arguments", errors.getvalue())
                self.assertNotIn("private-input", errors.getvalue())
                self.assertEqual(_opsec_count(errors.getvalue().encode("utf-8")), 0)

    def test_help_documents_supported_flags(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            inspector.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        for flag in ("--json", "--mermaid", "--serve", "--port", "--catalog"):
            self.assertIn(flag, output.getvalue())


if __name__ == "__main__":
    unittest.main()
