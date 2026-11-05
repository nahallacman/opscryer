# SPDX-License-Identifier: Apache-2.0
"""Health aggregation, deterministic diffs, CLI and telemetry redaction checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cluster_diff_engine as engine
from cluster_harvester import build_live_cluster_spatial_catalog


def resource(kind, name, namespace="default", spec=None, status=None, metrics=None):
    return {"id": f"k8s/{kind}/{namespace}/{name}", "resource_kind": kind,
            "resource": {"kind": kind, "metadata": {"name": name, "namespace": namespace},
                         "spec": spec or {}, "status": status or {}},
            "metrics": metrics or {}}


def fixture():
    nodes = [
        resource("Node", "ready", status={"conditions": [{"type": "Ready", "status": "True"}]},
                 metrics={"cpu_percent": 80.0, "ram_percent": 25.0}),
        resource("Node", "unknown", status={"conditions": [{"type": "Ready", "status": "Unknown"}]},
                 metrics={"cpu_percent": 1.0, "ram_percent": 75.0}),
        resource("Node", "missing", metrics={"cpu_percent": 79.9, "ram_percent": 74.9}),
        resource("Deployment", "healthy", spec={"replicas": 2}, status={"readyReplicas": 2}),
        resource("Deployment", "partial", spec={"replicas": 2}, status={"readyReplicas": 1}),
        resource("Deployment", "zero", spec={"replicas": 0}),
        resource("Deployment", "default"),
    ]
    for index, phase in enumerate(("Running", "Succeeded", "Failed", "Pending", "Unknown", "Failed")):
        nodes.append(resource("Pod", f"pod-{index}", "gitlab", status={"phase": phase}))
    nodes.append(resource("Ingress", "web", "apps", spec={"rules": [
        {"host": "web.cluster.example.org", "http": {"paths": [
            {"backend": {"service": {"name": name}}} for name in ("web", "api", "web")]}},
        {"host": "external.example", "http": {"paths": [{"backend": {"serviceName": "external"}}]}},
        {"host": "legacy.cluster.example.org", "http": {"paths": [{"backend": {"serviceName": "old"}}]}},
        {"host": "default.cluster.example.org"}], "defaultBackend": {"service": {"name": "fallback"}}}))
    return {"source": "test_snapshot", "example": True, "nodes": nodes}


class ClusterDiffEngineTests(unittest.TestCase):
    def test_health_categories_thresholds_and_ingress_targets(self):
        catalog = fixture()
        before = deepcopy(catalog)
        summary = engine.summarize_live_cluster_health(catalog)
        self.assertEqual(summary["source"], "test_snapshot")
        self.assertTrue(summary["example"])
        self.assertEqual(summary["node_counts"], {"total": 3, "ready": 1, "not_ready": 2})
        self.assertEqual(summary["ready_nodes"], ["ready"])
        self.assertEqual(summary["not_ready_nodes"], ["missing", "unknown"])
        self.assertEqual(summary["pod_counts"], {"total": 6, "running": 1, "succeeded": 1,
                                                "failed": 2, "pending": 1, "other": 1})
        self.assertEqual(summary["failed_pods_by_namespace"], {"gitlab": {
            "count": 2, "pod_ids": ["k8s/Pod/gitlab/pod-2", "k8s/Pod/gitlab/pod-5"]}})
        self.assertEqual(summary["deployment_counts"], {"total": 4, "ready": 1,
                                                       "scaled_zero": 1, "degraded": 2})
        self.assertEqual([h["name"] for h in summary["node_hotspots"]], ["ready", "unknown"])
        self.assertEqual(summary["ingress_hosts"], {
            "web.cluster.example.org": [{"service": "api", "namespace": "apps"},
                              {"service": "web", "namespace": "apps"}],
            "legacy.cluster.example.org": [{"service": "old", "namespace": "apps"}],
            "default.cluster.example.org": [{"service": "fallback", "namespace": "apps"}]})
        self.assertEqual(catalog, before)
        catalog["nodes"].reverse()
        self.assertEqual(summary, engine.summarize_live_cluster_health(catalog))

    def test_bundled_live_catalog_reports_observed_health(self):
        catalog = json.loads(engine.DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        summary = engine.summarize_live_cluster_health()
        self.assertEqual(summary["source"], catalog["source"])
        self.assertEqual(summary["example"], catalog["example"])
        self.assertIn("nodebeta02", summary["not_ready_nodes"])
        hardware = [n for n in catalog["nodes"] if n.get("resource_kind") == "Node"]
        lowpowered = next(n for n in hardware if n["label"] == "nodealpha01")
        hotspot = next(h for h in summary["node_hotspots"] if h["name"] == "nodealpha01")
        self.assertEqual(hotspot["ram_percent"], lowpowered["metrics"]["ram_percent"])
        self.assertIn("gitlab", summary["failed_pods_by_namespace"])

    def test_default_loading_and_missing_file_fallback_do_not_collect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            with patch.object(engine, "DEFAULT_CATALOG_PATH", path), \
                    patch.object(engine, "build_live_cluster_spatial_catalog",
                                 return_value=fixture()) as build:
                self.assertTrue(engine.summarize_live_cluster_health()["example"])
                build.assert_called_once_with()
                path.write_text(json.dumps(fixture()), encoding="utf-8")
                build.reset_mock()
                engine.summarize_live_cluster_health()
                build.assert_not_called()
                path.write_text("invalid", encoding="utf-8")
                with self.assertRaises(ValueError):
                    engine.summarize_live_cluster_health()
                build.assert_not_called()
        with patch("cluster_harvester.subprocess.run") as run:
            engine.summarize_live_cluster_health(build_live_cluster_spatial_catalog())
            run.assert_not_called()

    def test_diff_additions_removals_status_and_metric_changes(self):
        previous = fixture()
        current = deepcopy(previous)
        current["nodes"].pop()
        current["nodes"].append(resource("Pod", "new", status={"phase": "Pending"}))
        current["nodes"][0]["resource"]["status"]["conditions"][0]["status"] = "False"
        current["nodes"][0]["metrics"].update(cpu_percent=85, ram_percent=20)
        current["nodes"][3]["resource"]["status"]["readyReplicas"] = 1
        current["nodes"][7]["resource"]["status"]["phase"] = "Failed"
        untouched = deepcopy((previous, current))
        diff = engine.compute_catalog_diff(previous, current)
        self.assertEqual(diff["added_node_ids"], ["k8s/Pod/default/new"])
        self.assertEqual(diff["removed_node_ids"], ["k8s/Ingress/apps/web"])
        self.assertEqual(diff["status_transitions"], [
            {"node_id": "k8s/Deployment/default/healthy", "previous_status": "ready", "current_status": "degraded"},
            {"node_id": "k8s/Node/default/ready", "previous_status": "Ready", "current_status": "NotReady"},
            {"node_id": "k8s/Pod/gitlab/pod-0", "previous_status": "Running", "current_status": "Failed"}])
        self.assertEqual(diff["metrics_deltas"], {"k8s/Node/default/ready": {
            "cpu_percent": {"previous": 80.0, "current": 85, "delta": 5.0},
            "ram_percent": {"previous": 25.0, "current": 20, "delta": -5.0}}})
        self.assertEqual((previous, current), untouched)
        current["nodes"].reverse()
        self.assertEqual(diff, engine.compute_catalog_diff(previous, current))

    def test_empty_unchanged_missing_and_nonfinite_metrics(self):
        empty = {"nodes": []}
        self.assertEqual(engine.compute_catalog_diff(empty, empty), {
            "added_node_ids": [], "removed_node_ids": [], "status_transitions": [], "metrics_deltas": {}})
        summary = engine.summarize_live_cluster_health(empty)
        self.assertEqual(summary["node_counts"]["total"], 0)
        self.assertEqual(summary["ingress_hosts"], {})
        previous = {"nodes": [resource("Node", "metrics", metrics={
            "cpu_percent": float("nan"), "ram_percent": float("inf"), "flag": True,
            "cpu_used": "1m", "missing": 1})]}
        current = deepcopy(previous)
        current["nodes"][0]["metrics"] = {"cpu_percent": 100, "ram_percent": 100,
                                           "flag": False, "cpu_used": "2m", "new": 2}
        self.assertEqual(engine.compute_catalog_diff(previous, current)["metrics_deltas"], {})
        self.assertEqual(engine.summarize_live_cluster_health(previous)["node_hotspots"], [])

    def test_sanitizes_summary_and_diff_without_mutating_input(self):
        wan = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        secret = "gh" + "p_" + "examplecredential"
        catalog = {"source": " ".join((wan, mac, secret)), "nodes": [
            resource("Node", wan), resource("Pod", secret, mac, status={"phase": "Failed"})]}
        original = deepcopy(catalog)
        for payload in (engine.summarize_live_cluster_health(catalog),
                        engine.compute_catalog_diff({"nodes": []}, catalog)):
            encoded = json.dumps(payload, allow_nan=False)
            for value in (wan, mac, secret):
                self.assertNotIn(value, encoded)
            self.assertIn("203.0.113.1", encoded)
        self.assertEqual(catalog, original)

    def test_invalid_catalog_identities_are_rejected(self):
        node = resource("Node", "duplicate")
        for catalog in (None, [], {}, {"nodes": {}}, {"nodes": [None]},
                        {"nodes": [{}]}, {"nodes": [node, node]}):
            with self.subTest(catalog=catalog), self.assertRaises(ValueError):
                engine.compute_catalog_diff(catalog, {"nodes": []})

    def test_cli_custom_catalog_json_text_and_safe_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            result = subprocess.run([sys.executable, engine.__file__, "--catalog", str(path), "--json"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), engine.summarize_live_cluster_health(fixture()))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(engine.main(["--catalog", str(path)]), 0)
            self.assertIn("NotReady nodes: missing, unknown", output.getvalue())
            for content in (None, "private diagnostic", '{"nodes": [null]}'):
                if content is None:
                    path.unlink()
                else:
                    path.write_text(content, encoding="utf-8")
                output = io.StringIO()
                with redirect_stderr(output), self.assertRaises(SystemExit) as error:
                    engine.main(["--catalog", str(path), "--json"])
                self.assertEqual(error.exception.code, 2)
                self.assertIn("unable to load a valid cluster catalog", output.getvalue())
                self.assertNotIn("private diagnostic", output.getvalue())


if __name__ == "__main__":
    unittest.main()
