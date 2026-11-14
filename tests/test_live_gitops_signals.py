# SPDX-License-Identifier: Apache-2.0
"""Grounding, provenance, sanitization and CLI contracts for GitOps signals."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import live_gitops_signals as gitops


def node(kind, name, namespace="", status=None, **extra):
    return {"id": f"k8s/{kind}/{namespace}/{name}", "label": name,
            "resource_kind": kind, "namespace": namespace,
            "resource": {"kind": kind,
                         "metadata": {"name": name, "namespace": namespace},
                         "status": status or {}}, **extra}


class LiveGitOpsSignalsTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {"source": "test_snapshot", "example": True, "nodes": [
            node("Node", "one", status={"conditions": [{"type": "Ready", "status": "True"}]},
                 metrics={"cpu_percent": 20, "ram_percent": 60}),
            node("Node", "two"),
            node("Pod", "gitlab-runner-one", "gitlab"),
            node("Deployment", "gitlab-runner", "gitlab"),
            node("Deployment", "gitlab", "gitlab"),
            node("Service", "argocd", "argocd"),
            node("Ingress", "jenkins", "devops-tools"),
            node("Service", "prometheus", "monitoring"),
            node("Deployment", "renovate-exporter", "monitoring"),
            node("Pod", "renovate-exporter-abc", "monitoring", {"phase": "Failed"}),
            node("Pod", "gitlab-runner-unrelated", "other"),
            node("Service", "unrelated", "other")]}

    def assert_contract(self, signals, catalog):
        self.assertEqual(set(signals), {c[0] for c in gitops.live_currencies._CURRENCIES})
        ids = {n["id"] for n in catalog["nodes"]}
        for signal in signals.values():
            self.assertEqual(signal["source"], catalog["source"])
            self.assertEqual(signal["example"], catalog["example"])
            self.assertTrue(signal["evidence"])
            for item in signal["dropdown_items"]:
                self.assertIn(item["target_id"], ids)

    def test_grounded_inventory_metrics_and_missing_api_data(self):
        before = deepcopy(self.catalog)
        signals = gitops.derive_live_gitops_and_ci_signals(self.catalog)
        self.assert_contract(signals, self.catalog)
        self.assertEqual(signals["nodes"]["display_value"], "1/2 Ready")
        self.assertEqual(signals["cpu_load"]["display_value"], "20.0% Avg (1/2 nodes)")
        self.assertEqual(signals["ram_load"]["display_value"], "60.0% Avg (1/2 nodes)")
        self.assertEqual(signals["network_load"]["display_value"], "3 routes (Ingress/Service)")
        self.assertEqual(signals["build_supply"]["display_value"], "1 runner pods / 1 deployments")
        for key in ("renovate_failures", "open_mrs"):
            self.assertFalse(signals[key]["available"])
            self.assertEqual(signals[key]["display_value"], "Unavailable")
            self.assertTrue(signals[key]["dropdown_items"])
        signals["nodes"]["dropdown_items"].clear()
        self.assertEqual(self.catalog, before)

    def test_builder_receives_signals_and_all_seven_are_enriched(self):
        self.catalog["rts_currencies"] = [{"currency_id": "nodes", "display_value": "old",
                                           "dropdown_items": [{"target_id": "missing"}]}]
        before = deepcopy(self.catalog)
        with patch.object(gitops.live_currencies, "build_enriched_live_currencies",
                          wraps=gitops.live_currencies.build_enriched_live_currencies) as builder:
            result = gitops.enrich_all_seven_live_currencies(self.catalog)
        self.assertIn("extra_signals", builder.call_args.kwargs)
        self.assertEqual(len(builder.call_args.kwargs["extra_signals"]), 7)
        self.assert_contract({c["currency_id"]: c for c in result}, self.catalog)
        self.assertEqual(result[0]["display_value"], "1/2 Ready")
        self.assertEqual(self.catalog, before)

    def test_renovate_terminal_status_and_job_pod_deduplication(self):
        job = node("Job", "renovate-run", "devops-tools", {
            "conditions": [{"type": "Failed", "status": "True"}]})
        job["resource"]["metadata"]["uid"] = "run-one"
        pod = node("Pod", "renovate-run-pod", "devops-tools", {"phase": "Failed"})
        pod["resource"]["metadata"]["ownerReferences"] = [{"kind": "Job", "uid": "run-one"}]
        self.catalog["nodes"].extend([
            job, pod, node("Pod", "renovate-ok", "devops-tools", {"phase": "Succeeded"}),
            node("Pod", "renovate-active", "devops-tools", {"phase": "Running"})])
        signal = gitops.derive_live_gitops_and_ci_signals(self.catalog)["renovate_failures"]
        self.assertTrue(signal["available"])
        self.assertEqual(signal["display_value"], "1 failed / 2 terminal Renovate workloads")
        self.assertEqual(len(signal["dropdown_items"]), 2)

    def test_zero_observed_failures_and_label_matching(self):
        run = node("Pod", "scheduled-123", "devops-tools", {"phase": "Succeeded"})
        run["resource"]["metadata"]["labels"] = {"app": "renovate"}
        self.catalog["nodes"].append(run)
        signal = gitops.derive_live_gitops_and_ci_signals(self.catalog)["renovate_failures"]
        self.assertTrue(signal["available"])
        self.assertEqual(signal["display_value"], "0 failed / 1 terminal Renovate workloads")

    def test_empty_missing_and_invalid_metrics(self):
        empty = gitops.enrich_all_seven_live_currencies({"nodes": []})
        self.assertTrue(all(not c["available"] and not c["dropdown_items"] for c in empty))
        for value in (None, True, -1, 101, float("nan"), float("inf"), "20"):
            with self.subTest(value=value):
                self.catalog["nodes"][0]["metrics"] = {"cpu_percent": value}
                result = gitops.derive_live_gitops_and_ci_signals(self.catalog)
                self.assertFalse(result["cpu_load"]["available"])
                self.assertFalse(result["ram_load"]["available"])

    def test_metadata_fallback_and_no_annotation_matches(self):
        runner = self.catalog["nodes"][2]
        runner.pop("namespace")
        runner.pop("resource_kind")
        runner["label"] = "worker"
        runner["resource"]["metadata"]["name"] = "worker"
        runner["resource"]["metadata"]["labels"] = {"app": "gitlab_runner"}
        unrelated = node("Pod", "unrelated", "gitlab")
        unrelated["resource"]["metadata"]["annotations"] = {"note": "gitlab-runner renovate"}
        self.catalog["nodes"].append(unrelated)
        result = gitops.derive_live_gitops_and_ci_signals(self.catalog)
        self.assertEqual(len(result["build_supply"]["dropdown_items"]), 2)
        self.assertFalse(result["renovate_failures"]["available"])

    def test_sanitization_and_input_validation(self):
        public = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        secret = "gh" + "p_" + "testcredential"
        self.catalog["source"] = f"{public} {mac} {secret}"
        self.catalog["nodes"][0]["id"] = f"host/{public}"
        for function in (gitops.derive_live_gitops_and_ci_signals,
                         gitops.enrich_all_seven_live_currencies):
            encoded = json.dumps(function(self.catalog))
            for sensitive in (public, mac, secret):
                self.assertNotIn(sensitive, encoded)
            self.assertIn("203.0.113.1", encoded)
            self.assertIn("AA:BB:CC:XX:XX:XX", encoded)
            for invalid in ({}, {"nodes": [None]}, {"nodes": [{"id": "x"}, {"id": "x"}]}):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    function(invalid)

    def test_live_snapshot_paths_and_cli(self):
        snapshot = json.loads(gitops.DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        self.assert_contract(gitops.derive_live_gitops_and_ci_signals(), snapshot)
        self.assertEqual(len(gitops.enrich_all_seven_live_currencies()), 7)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            expected = gitops.enrich_all_seven_live_currencies(path)
            with patch.object(gitops, "DEFAULT_CATALOG_PATH", path):
                self.assertEqual(gitops.enrich_all_seven_live_currencies(), expected)
            for flags in (["--json"], []):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(gitops.main(["--catalog", str(path)] + flags), 0)
                if flags:
                    self.assertEqual(json.loads(output.getvalue()), expected)
                else:
                    self.assertIn("Build Supply:", output.getvalue())
        error = io.StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit) as caught:
            gitops.main(["--catalog", "missing-catalog.json", "--json"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("unable to derive", error.getvalue())


if __name__ == "__main__":
    unittest.main()
