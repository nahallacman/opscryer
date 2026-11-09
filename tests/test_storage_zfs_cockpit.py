# SPDX-License-Identifier: Apache-2.0
"""Offline storage evidence, presentation, transport, and OPSEC contracts."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

import storage_zfs_cockpit as cockpit
from golden_path_gates import _opsec_count


def node(identity, kind, name, namespace="default", spec=None, status=None,
         **metadata):
    return {"id": identity, "resource_kind": kind, "namespace": namespace,
            "resource": {"kind": kind,
                         "metadata": {"name": name, "namespace": namespace,
                                      **metadata},
                         "spec": spec or {}, "status": status or {}}}


def storage_catalog():
    storage_class = node("class", "StorageClass", "openzfs-iscsi-csi")
    storage_class["resource"]["provisioner"] = "democratic-csi"
    return {
        "source": "offline storage fixture", "example": True,
        "collected_at": "2026-10-30T00:00:00Z", "errors": ["partial snapshot"],
        "nodes": [
            node("pod", "Pod", "database-1", "apps",
                 spec={"nodeName": "worker.cluster.example.org", "volumes": [
                     {"persistentVolumeClaim": {"claimName": "data"}},
                     {"persistentVolumeClaim": {"claimName": "missing"}}]},
                 status={"phase": "Running", "conditions": [
                     {"type": "Ready", "status": "False"}]},
                 labels={"cnpg.io/cluster": "database"},
                 ownerReferences=[{"kind": "Cluster", "name": "database"}]),
            node("pv", "PersistentVolume", "disk", spec={
                "storageClassName": "openzfs-iscsi-csi", "capacity": {"storage": "8Gi"},
                "claimRef": {"namespace": "apps", "name": "data"}},
                status={"phase": "Bound"}),
            node("claim", "PersistentVolumeClaim", "data", "apps", spec={
                "storageClassName": "openzfs-iscsi-csi", "volumeName": "disk",
                "resources": {"requests": {"storage": "8Gi"}}},
                status={"phase": "Bound", "capacity": {"storage": "8Gi"}}),
            node("cluster", "Cluster", "database", "apps", spec={
                "storage": {"storageClass": "openzfs-iscsi-csi", "size": "8Gi"},
                "walStorage": {"storageClass": "zfs-nfs", "size": "2Gi"}}),
            node("seaweed", "StatefulSet", "seaweed-filer", "storage", spec={
                "volumeClaimTemplates": [{"metadata": {"name": "files"},
                    "spec": {"storageClassName": "zfs-nfs"}}]}),
            node("csi", "Pod", "democratic-iscsi-controller", "storage-system"),
            node("nfs", "DaemonSet", "zfs-nfs-node", "storage-system"),
            node("operator", "Deployment", "operator", "cnpg-system"),
            node("owner", "Namespace", "apps"), storage_class,
        ],
        "edges": [{"source": "owner", "target": "pod", "relation": "owns_workload"}],
    }


@contextmanager
def serving(catalog):
    server = ThreadingHTTPServer(("127.0.0.1", 0),
                                cockpit._build_storage_cockpit_handler(catalog))
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01},
                    daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(address, path, method="GET"):
    connection = HTTPConnection(*address, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode("utf-8")
    finally:
        connection.close()


class StorageTopologyTests(unittest.TestCase):
    def setUp(self):
        self.catalog = storage_catalog()

    def test_provenance_classes_and_unknown_health(self):
        result = cockpit.summarize_storage_topology(self.catalog)
        self.assertEqual(result["source"], "offline storage fixture")
        self.assertIs(result["example"], True)
        self.assertEqual(result["provenance"], {
            "mode": "offline_snapshot", "live_collection": False,
            "collected_at": "2026-10-30T00:00:00Z", "errors": ["partial snapshot"]})
        iscsi, nfs = result["storage_classes"]
        self.assertTrue(iscsi["observed"])
        self.assertEqual(iscsi["provisioner"], "democratic-csi")
        self.assertEqual(iscsi["claim_ids"], ["claim"])
        self.assertEqual(iscsi["workload_ids"], ["cluster", "pod"])
        self.assertFalse(nfs["observed"])
        self.assertIsNone(nfs["node_id"])
        self.assertIsNone(nfs["provisioner"])
        self.assertEqual(nfs["workload_ids"], ["cluster", "seaweed"])
        self.assertIn("ZFS pool health and bindings are unknown", result["notice"])
        self.assertIn("no live storage checks", result["notice"])

    def test_component_roles_protocols_and_independent_readiness(self):
        groups = cockpit.summarize_storage_topology(self.catalog)["components"]
        self.assertEqual([(r["role"], r["protocol"]) for r in groups["democratic_csi"]],
                         [("controller", "iscsi"), ("node", "nfs")])
        self.assertEqual(groups["seaweedfs"][0]["role"], "filer")
        operator, pod = groups["cloudnativepg"]
        self.assertEqual(operator["role"], "operator")
        self.assertEqual(pod["role"], "database")
        self.assertEqual(pod["phase"], "Running")
        self.assertEqual(pod["ready_condition"], "False")
        self.assertEqual(pod["node_name"], "worker.cluster.example.org")
        self.assertIsNone(groups["democratic_csi"][0]["phase"])

    def test_claims_volumes_templates_and_resolved_lineage(self):
        result = cockpit.summarize_storage_topology(self.catalog)
        claim = result["persistent_volume_claims"][0]
        self.assertEqual(claim["requested_storage"], "8Gi")
        self.assertEqual(claim["capacity"], {"storage": "8Gi"})
        self.assertEqual(claim["volume_name"], "disk")
        volume = result["persistent_volumes"][0]
        self.assertEqual(volume["capacity"], {"storage": "8Gi"})
        self.assertEqual(volume["claim_ref"], {"namespace": "apps", "name": "data"})
        edges = {(e["source"], e["relation"], e["target"]["node_id"])
                 for e in result["lineage"]}
        self.assertTrue({("claim", "bound_to", "pv"),
                         ("pod", "owned_by", "cluster"),
                         ("pod", "member_of_cluster", "cluster"),
                         ("pod", "uses_claim", "claim"),
                         ("owner", "owns_workload", "pod")} <= edges)
        missing = next(e["target"] for e in result["lineage"]
                       if e["relation"] == "uses_claim" and e["target"]["name"] == "missing")
        self.assertEqual(missing, {"kind": "PersistentVolumeClaim", "namespace": "apps",
                                   "name": "missing", "node_id": None})
        workloads = {r["node_id"]: r for r in result["stateful_workloads"]}
        self.assertEqual(workloads["cluster"]["wal_storage"]["size"], "2Gi")
        self.assertEqual(workloads["seaweed"]["claim_templates"][0]["metadata"]["name"], "files")

    def test_references_do_not_resolve_across_namespaces(self):
        self.catalog["nodes"][2]["namespace"] = "other"
        self.catalog["nodes"][2]["resource"]["metadata"]["namespace"] = "other"
        result = cockpit.summarize_storage_topology(self.catalog)
        uses = [e for e in result["lineage"] if e["relation"] == "uses_claim"]
        self.assertTrue(all(e["target"]["node_id"] is None for e in uses))
        self.assertEqual(result["storage_classes"][0]["workload_ids"], ["cluster"])

    def test_callers_and_returned_nested_values_are_independent(self):
        before = deepcopy(self.catalog)
        result = cockpit.summarize_storage_topology(self.catalog)
        cockpit.render_storage_cockpit_markdown(self.catalog)
        cockpit.render_storage_cockpit_html(self.catalog)
        self.assertEqual(self.catalog, before)
        result["provenance"]["errors"].append("changed")
        result["persistent_volumes"][0]["claim_ref"]["name"] = "changed"
        result["stateful_workloads"][0]["storage"]["size"] = "changed"
        self.assertEqual(self.catalog, before)
        self.assertNotEqual(result, cockpit.summarize_storage_topology(self.catalog))

    def test_deterministic_graph_order_and_file_inputs(self):
        expected = cockpit.summarize_storage_topology(self.catalog)
        self.catalog["nodes"].reverse()
        self.catalog["edges"].reverse()
        self.assertEqual(cockpit.summarize_storage_topology(self.catalog), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            for value in (path, str(path)):
                self.assertEqual(cockpit.summarize_storage_topology(value), expected)

    def test_empty_and_default_catalogs_remain_offline(self):
        empty = cockpit.summarize_storage_topology({"nodes": []})
        self.assertEqual(empty["components"], {"democratic_csi": [], "seaweedfs": [],
                                                "cloudnativepg": []})
        for key in ("persistent_volume_claims", "persistent_volumes", "stateful_workloads", "lineage"):
            self.assertEqual(empty[key], [])
        self.assertTrue(all(not c["observed"] for c in empty["storage_classes"]))
        bundled = cockpit.summarize_storage_topology()
        self.assertFalse(bundled["provenance"]["live_collection"])
        self.assertEqual(_opsec_count(json.dumps(bundled).encode()), 0)

    def test_invalid_catalogs_fail_closed_with_fixed_error(self):
        invalid = [[], {}, {"nodes": {}}, {"nodes": [None]}, {"nodes": [{"id": " "}]},
                   {"nodes": [{"id": "a"}, {"id": "a"}]},
                   {"nodes": [], "edges": {}}, {"nodes": [], "extra": float("nan")},
                   {"nodes": [], "extra": float("inf")}, {"nodes": [], "extra": object()},
                   {"nodes": [], 1: "invalid key"}, {"nodes": [], "extra": (1,)}]
        for change in ({"resource": []}, {"resource_kind": 3},
                       {"resource": {"kind": "Pod", "metadata": []}},
                       {"resource": {"kind": "Other"}},
                       {"resource": {"kind": "Pod", "metadata": {"namespace": "other"}}}):
            entry = node("a", "Pod", "test")
            entry.update(change)
            invalid.append({"nodes": [entry]})
        for spec in ({"volumes": {}}, {"volumes": [None]},
                     {"volumes": [{"persistentVolumeClaim": {}}]},
                     {"template": []}, {"storageClassName": 1},
                     {"volumeClaimTemplates": "invalid"}, {"walStorage": []}):
            invalid.append({"nodes": [node("a", "Pod", "test", spec=spec)]})
        invalid.extend([
            {"nodes": [node("a", "Pod", "test", labels={"app": 1})]},
            {"nodes": [node("a", "Pod", "test", ownerReferences=[{"kind": "Cluster"}])]},
            {"nodes": [node("a", "Pod", "test", status={"conditions": [{"status": True}]})]},
            {"nodes": [node("a", "Cluster", "test", spec={"storage": "invalid"})]},
            {"nodes": [node("a", "Pod", "test"), node("b", "Pod", "test")]},
            {"nodes": [{"id": "a"}], "edges": [
                {"source": "a", "target": "missing", "relation": "uses_claim"}]},
            {"nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "a"}]},
        ])
        recursive = {"nodes": []}
        recursive["extra"] = recursive
        invalid.append(recursive)
        for index, catalog in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaisesRegex(ValueError, "^Invalid storage cockpit catalog$"):
                    cockpit.summarize_storage_topology(catalog)

    def test_missing_and_malformed_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for content in (None, "{broken", "[]"):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "^Invalid storage cockpit catalog$"):
                    cockpit.summarize_storage_topology(path)

    def test_sanitizer_collisions_fail_closed(self):
        first = ".".join(map(str, [8, 8, 8, 8]))
        second = ".".join(map(str, [1, 1, 1, 1]))
        for catalog in ({"nodes": [{"id": first}, {"id": second}]},
                        {"nodes": [], "extra": {first: 1, second: 2}}):
            with self.assertRaisesRegex(ValueError, "^Invalid storage cockpit catalog$"):
                cockpit.summarize_storage_topology(catalog)


class StorageRenderingTests(unittest.TestCase):
    def test_markdown_sections_unknowns_and_literal_cells(self):
        catalog = storage_catalog()
        catalog["source"] = '<script>alert(1)</script> | [link](https://example.cluster.example.org)\n*bold*'
        markdown = cockpit.render_storage_cockpit_markdown(catalog)
        for section in ("Snapshot provenance", "Storage classes / OpenZFS ZFS context",
                        "ZFS / Democratic-CSI controllers and nodes", "SeaweedFS", "CloudNativePG",
                        "Persistent volume claims", "Persistent volumes", "Stateful workloads",
                        "Storage lineage", "Operator portals"):
            self.assertIn("## " + section, markdown)
        self.assertIn("&lt;script&gt;alert\\(1\\)&lt;/script&gt; \\| \\[link\\]", markdown)
        self.assertIn(r"\*bold\*", markdown)
        self.assertIn("Unknown", markdown)
        self.assertNotIn("<script>", markdown)
        self.assertIn("No observations", cockpit.render_storage_cockpit_markdown({"nodes": []}))

    def test_html_embeds_exact_summary_without_script_breakout(self):
        catalog = storage_catalog()
        catalog["source"] = '</script><img src=x onerror=alert(1)> & \u2028'
        html = cockpit.render_storage_cockpit_html(catalog)
        payload = re.search(r'<script id="storage-cockpit-data" type="application/json">(.*?)</script>',
                            html, re.DOTALL).group(1)
        self.assertEqual(json.loads(payload), cockpit.summarize_storage_topology(catalog))
        self.assertNotIn("<", payload)
        self.assertNotIn(">", payload)
        self.assertNotIn("&", payload)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn("innerHTML", html)
        self.assertIn("element.textContent = text", html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('aria-label="Filter by storage class"', html)
        self.assertIn('href="/storage" aria-current="page"', html)
        self.assertIn("ZFS pool health", html)


class StorageCLITests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "catalog.json"
        self.path.write_text(json.dumps(storage_catalog()), encoding="utf-8")

    def invoke(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = cockpit.main(arguments)
        self.assertEqual(code, 0)
        self.assertEqual(errors.getvalue(), "")
        return output.getvalue()

    def test_default_json_explicit_json_and_markdown(self):
        expected = cockpit.summarize_storage_topology(self.path)
        for flags in ([], ["--json"]):
            self.assertEqual(json.loads(self.invoke(["--catalog", str(self.path), *flags])), expected)
        self.assertEqual(self.invoke(["--catalog", str(self.path), "--markdown"]),
                         cockpit.render_storage_cockpit_markdown(self.path))
        self.assertFalse(json.loads(self.invoke([]))["provenance"]["live_collection"])

    def test_invalid_flags_and_files_have_fixed_sanitized_errors(self):
        for index, arguments in enumerate((
                ["--json", "--markdown"], ["--serve", "--json"], ["--unknown"],
                ["--mark"], ["--catalog"], ["--port", "bad"], ["--port", "0"],
                ["--port", "65536"], ["--catalog", str(self.path.parent / "missing.json")])):
            with self.subTest(case=index):
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    with self.assertRaises(SystemExit) as caught:
                        cockpit.main(arguments)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("error: Invalid storage cockpit request", errors.getvalue())
                self.assertEqual(_opsec_count(errors.getvalue().encode()), 0)

    def test_help(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            cockpit.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        for flag in ("--json", "--markdown", "--serve", "--catalog", "--port"):
            self.assertIn(flag, output.getvalue())

    def test_serve_binds_loopback_and_shuts_down_on_interrupt(self):
        with patch.object(cockpit, "ThreadingHTTPServer") as server:
            instance = server.return_value.__enter__.return_value
            instance.serve_forever.side_effect = KeyboardInterrupt
            output = self.invoke(["--catalog", str(self.path), "--serve", "--port", "8123"])
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8123))
            instance.serve_forever.assert_called_once_with()
            server.return_value.__exit__.assert_called_once()
            self.assertIn("http://127.0.0.1:8123/storage", output)


class StorageHTTPTests(unittest.TestCase):
    def test_success_routes_content_and_security_headers(self):
        catalog = storage_catalog()
        with serving(catalog) as address:
            for route in ("/", "/storage", "/api/v1/storage-cockpit"):
                with self.subTest(route=route):
                    status, headers, body = request(address, route)
                    self.assertEqual(status, 200)
                    self.assertEqual(int(headers["Content-Length"]), len(body.encode("utf-8")))
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(headers["Referrer-Policy"], "no-referrer")
                    self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                    if route.startswith("/api/"):
                        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
                        self.assertEqual(json.loads(body), cockpit.summarize_storage_topology(catalog))
                    else:
                        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
                        self.assertEqual(body, cockpit.render_storage_cockpit_html(catalog))

    def test_unknown_queries_and_unsupported_methods(self):
        with serving(storage_catalog()) as address:
            for path, method, code, error in (
                    ("/missing", "GET", 404, "Not found"),
                    ("/storage/", "GET", 404, "Not found"),
                    ("/storage?collect=true", "GET", 400, "Invalid storage cockpit request"),
                    ("/?live=true", "GET", 400, "Invalid storage cockpit request"),
                    ("/api/v1/storage-cockpit?format=json", "GET", 400, "Invalid storage cockpit request"),
                    ("/storage", "POST", 501, "Invalid HTTP request")):
                with self.subTest(path=path, method=method):
                    status, _, body = request(address, path, method)
                    self.assertEqual(status, code)
                    self.assertEqual(json.loads(body), {"error": error})

    def test_invalid_catalog_and_unexpected_failure_are_generic(self):
        with serving({"nodes": "invalid"}) as address:
            for path in ("/storage", "/api/v1/storage-cockpit"):
                status, _, body = request(address, path)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {"error": "Invalid storage cockpit request"})
        with patch.object(cockpit, "summarize_storage_topology", side_effect=RuntimeError("private detail")):
            with serving(storage_catalog()) as address:
                status, _, body = request(address, "/api/v1/storage-cockpit")
                self.assertEqual(status, 503)
                self.assertEqual(json.loads(body), {"error": "Storage cockpit unavailable"})


class StorageOPSECTests(unittest.TestCase):
    def test_all_exports_and_http_outputs_have_zero_violations(self):
        # Construct synthetic probes in memory; never store or print raw identifiers.
        wan = ".".join(map(str, [8, 8, 8, 8]))
        mac = ":".join(["AA", "BB", "CC", "11", "22", "33"])
        tokens = [prefix + "syntheticfixture" for prefix in
                  ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        probe = " ".join([wan, mac, *tokens, "10.1.2.3", "172.20.1.2",
                          "172.16.1.2", "nas.cluster.example.org"])
        catalog = storage_catalog()
        catalog["source"] = probe
        catalog["errors"] = [probe]
        catalog["nodes"][0]["resource"]["spec"]["nodeName"] = probe
        before = deepcopy(catalog)
        summary = cockpit.summarize_storage_topology(catalog)
        outputs = [json.dumps(summary), cockpit.render_storage_cockpit_markdown(catalog),
                   cockpit.render_storage_cockpit_html(catalog)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with serving(catalog) as address:
                for path in ("/", "/storage", "/api/v1/storage-cockpit",
                             "/storage?value=" + wan, "/missing/" + wan):
                    outputs.append(request(address, path)[2])
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(catalog == before, "Input was mutated")
        for index, output in enumerate(outputs):
            with self.subTest(output=index):
                self.assertEqual(_opsec_count(output.encode()), 0)
                self.assertTrue(all(value not in output for value in [wan, mac, *tokens]),
                                "Unsanitized probe escaped")
        for value in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "[REDACTED]",
                      "10.1.2.3", "172.20.1.2", "172.16.1.2", "nas.cluster.example.org"):
            self.assertIn(value, summary["source"])

    def test_cli_redacts_probes_in_success_and_failure_output(self):
        token = "gh" + "p_" + "syntheticfixture"
        catalog = {"nodes": [], "source": token}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            for mode in ("--json", "--markdown"):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(cockpit.main([mode, "--catalog", str(path)]), 0)
                self.assertTrue(token not in output.getvalue(), "Credential escaped")
                self.assertEqual(_opsec_count(output.getvalue().encode()), 0)
        for arguments in (["--" + token], ["--port", token], ["--catalog", token]):
            output = io.StringIO()
            with redirect_stderr(output), self.assertRaises(SystemExit) as caught:
                cockpit.main(arguments)
            self.assertEqual(caught.exception.code, 2)
            self.assertTrue(token not in output.getvalue(), "Credential escaped")
            self.assertEqual(_opsec_count(output.getvalue().encode()), 0)

    def test_test_source_has_license_and_zero_opsec_violations(self):
        content = Path(__file__).read_bytes()
        self.assertTrue(content.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertEqual(_opsec_count(content), 0)


if __name__ == "__main__":
    unittest.main()
