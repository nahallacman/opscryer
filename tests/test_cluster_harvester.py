# SPDX-License-Identifier: Apache-2.0
"""Deterministic live collection, sanitation, graph and CLI checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

import cluster_harvester as cluster
import opscryer_backend as backend
from opscryer_backend import KnowledgeGraphBackendEngine, validate_spatial_graph_contract
from golden_path_gates import _opsec_count
from tests.test_opscryer_public_smoke import ROOT, opsec_findings, scan_public_files


class ClusterHarvesterTests(unittest.TestCase):
    def test_default_is_offline_fresh_and_contract_valid(self):
        with patch.object(cluster.subprocess, "run") as run, patch.object(cluster.shutil, "which") as which:
            catalog = cluster.build_live_cluster_spatial_catalog()
            self.assertEqual(catalog, cluster.build_live_cluster_spatial_catalog())
            run.assert_not_called()
            which.assert_not_called()
        self.assertTrue(catalog["example"])
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        hardware = [n for n in catalog["nodes"] if n.get("resource_kind") == "Node"]
        self.assertEqual({n["label"] for n in hardware},
                         {"nodealpha01", "nodebeta02", "nodegamma03"})
        addresses = {n["resource"]["status"]["addresses"][0]["address"] for n in hardware}
        self.assertEqual(addresses, {"10.20.3.2", "10.20.3.10", "10.20.3.13"})
        ingresses = [n for n in catalog["nodes"] if n.get("resource_kind") == "Ingress"]
        self.assertEqual(len(ingresses), 12)
        self.assertTrue(all(n["primary_url"].endswith(".cluster.example.org") for n in ingresses))
        self.assertEqual({n["resource"]["status"]["loadBalancer"]["ingress"][0]["ip"]
                          for n in ingresses}, {"172.20.1." + str(i) for i in range(210, 222)})
        catalog["nodes"].clear()
        self.assertTrue(cluster.build_live_cluster_spatial_catalog()["nodes"])

    def test_seven_currencies_metrics_and_reference_integrity(self):
        catalog = cluster.build_live_cluster_spatial_catalog()
        currencies = {c["currency_id"]: c for c in catalog["rts_currencies"]}
        self.assertEqual(set(currencies), {"nodes", "cpu_load", "ram_load", "network_load",
                                           "build_supply", "renovate_failures", "open_mrs"})
        self.assertEqual(currencies["nodes"]["display_value"], "3/3 Ready")
        self.assertEqual(currencies["cpu_load"]["display_value"], "7.0% Avg (3/3 nodes)")
        ids = {n["id"] for n in catalog["nodes"]}
        self.assertTrue(all(d["target_id"] in ids for c in currencies.values()
                            for d in c["dropdown_items"]))
        for key in ("network_load", "build_supply", "renovate_failures", "open_mrs"):
            self.assertFalse(currencies[key]["available"])
        self.assertTrue({"runs_on_hardware", "routes_to", "contains"}.issubset(
            {e["relation"] for e in catalog["edges"]}))

    def test_live_commands_are_bounded_read_only_and_sanitized(self):
        snapshot = cluster._offline_snapshot()
        # Assemble forbidden public patterns dynamically to keep source scans clean.
        wan = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        secret = "gh" + "p_" + "examplecredential"
        snapshot["items"][0]["metadata"]["annotations"] = {
            "wan": wan, "device": mac, "token": secret}
        raw = json.dumps({"items": snapshot["items"]})
        responses = [subprocess.CompletedProcess([], 0, raw, ""),
                     subprocess.CompletedProcess([], 0, snapshot["top_nodes"], "")]
        with patch.object(cluster.shutil, "which", return_value="kubectl"), \
                patch.object(cluster.subprocess, "run", side_effect=responses) as run:
            live = cluster.harvest_live_k8s_cluster(timeout=2)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["kubectl", *cluster.GET_ARGS], ["kubectl", *cluster.TOP_ARGS]])
        self.assertTrue(all(call.kwargs["timeout"] == 2 and not call.kwargs["shell"]
                            for call in run.call_args_list))
        self.assertEqual(live["source"], "live_kubectl")
        self.assertFalse(live["example"])
        for payload in (live, cluster.build_live_cluster_spatial_catalog(live)):
            encoded = json.dumps(payload)
            for value in (wan, mac, secret):
                self.assertNotIn(value, encoded)
            self.assertIn("203.0.113.1", encoded)
            self.assertIn("AA:BB:CC:XX:XX:XX", encoded)
            self.assertIn("[REDACTED]", encoded)

    def test_missing_kubectl_fallback_never_executes(self):
        with patch.object(cluster.shutil, "which", return_value=None), \
                patch.object(cluster.subprocess, "run") as run:
            snapshot = cluster.harvest_live_k8s_cluster()
        run.assert_not_called()
        self.assertEqual(snapshot["errors"], ["kubectl_unavailable"])
        self.assertTrue(snapshot["example"])

    def test_get_failures_fall_back_without_disclosing_errors(self):
        cases = [OSError("private diagnostic"), subprocess.TimeoutExpired("kubectl", 1),
                 subprocess.CompletedProcess([], 1, "", "private diagnostic"),
                 subprocess.CompletedProcess([], 0, "broken json", ""),
                 subprocess.CompletedProcess([], 0, '{"items": {}}', "")]
        for case in cases:
            with self.subTest(case=type(case).__name__), \
                    patch.object(cluster.shutil, "which", return_value="kubectl"), \
                    patch.object(cluster.subprocess, "run", side_effect=[case]):
                snapshot = cluster.harvest_live_k8s_cluster()
            self.assertEqual(snapshot["errors"], ["inventory_unavailable"])
            self.assertNotIn("private diagnostic", json.dumps(snapshot))

    def test_top_failure_retains_live_inventory_and_unknown_metrics(self):
        inventory = json.dumps({"items": cluster._offline_snapshot()["items"]})
        with patch.object(cluster.shutil, "which", return_value="kubectl"), \
                patch.object(cluster.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 0, inventory, ""),
                    subprocess.TimeoutExpired("kubectl", 1)]):
            snapshot = cluster.harvest_live_k8s_cluster()
        self.assertFalse(snapshot["example"])
        self.assertEqual(snapshot["errors"], ["node_metrics_unavailable"])
        currencies = cluster.build_live_cluster_spatial_catalog(snapshot)["rts_currencies"]
        self.assertEqual(currencies[1]["display_value"], "Unavailable")

    def test_metrics_ignore_bad_rows_and_report_coverage(self):
        snapshot = cluster._offline_snapshot()
        snapshot["top_nodes"] = ("NAME CPU CPU% MEMORY MEMORY%\n"
                                 "nodealpha01 10m 2% 10Mi 3%\n"
                                 "nodebeta02 10m <unknown> 10Mi 3%\n"
                                 "nodegamma03 10m nan% 10Mi 3%\n"
                                 "absent 10m 90% 10Mi 90%\n")
        before = deepcopy(snapshot)
        catalog = cluster.build_live_cluster_spatial_catalog(snapshot)
        self.assertEqual(catalog["rts_currencies"][1]["display_value"], "2.0% Avg (1/3 nodes)")
        self.assertEqual(snapshot, before)

    def test_namespace_synthesis_duplicate_names_and_empty_list(self):
        items = [{"kind": "Pod", "metadata": {"name": "same", "namespace": ns}}
                 for ns in ("first", "second")]
        catalog = cluster.build_live_cluster_spatial_catalog({"items": items})
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        self.assertEqual(len(catalog["nodes"]), 5)
        self.assertEqual(len(cluster.build_live_cluster_spatial_catalog({"items": []})["nodes"]), 1)
        with self.assertRaises(ValueError):
            cluster.build_live_cluster_spatial_catalog({"items": items + [items[0]]})
        for snapshot in ([], {}, {"items": {}}, {"items": [{"kind": "Pod"}]}):
            with self.assertRaises(ValueError):
                cluster.build_live_cluster_spatial_catalog(snapshot)

    def test_invalid_timeout_is_rejected_before_lookup(self):
        with patch.object(cluster.shutil, "which") as which:
            for timeout in (0, -1, True, None, "15", float("nan"), float("inf")):
                with self.assertRaises(ValueError):
                    cluster.harvest_live_k8s_cluster(timeout)
            which.assert_not_called()

    def test_cli_json_and_export_default_offline_and_explicit_live(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "catalog.json"
            out = io.StringIO()
            with patch.object(cluster, "harvest_live_k8s_cluster") as harvest, redirect_stdout(out):
                self.assertEqual(cluster.main(["--json", "--export", str(target)]), 0)
                harvest.assert_not_called()
            self.assertEqual(json.loads(out.getvalue()), json.loads(target.read_text(encoding="utf-8")))
            self.assertNotIn(b"\r\n", target.read_bytes())
        with patch.object(cluster, "harvest_live_k8s_cluster", return_value=cluster._offline_snapshot()) as harvest, \
                redirect_stdout(io.StringIO()):
            cluster.main(["--harvest-live"])
            harvest.assert_called_once_with()

    def test_named_fallback_entities_support_bm25_and_paths(self):
        catalog = cluster.build_live_cluster_spatial_catalog()
        self.assertEqual(catalog["source"], "offline_fallback")
        self.assertTrue(catalog["example"])
        engine = KnowledgeGraphBackendEngine(catalog)
        for name in ("nodegamma03", "nodealpha01", "nodebeta02", "ollama",
                     "factorio", "minecraft", "defectdojo", "trivy", "argon"):
            with self.subTest(entity=name):
                result = engine.search(name)
                self.assertEqual(result["algorithm"], "BM25")
                exact = [n for n in result["results"] if n["label"] == name]
                self.assertTrue(exact)
                route = engine.shortest_path(exact[0]["id"], "k8s/Node//nodegamma03")
                self.assertTrue(route["path_found"])
                self.assertEqual(route["hop_count"], len(route["path_ids"]) - 1)
        route = engine.shortest_path("k8s/Service/game-servers/minecraft",
                                     "k8s/Node//nodegamma03")
        self.assertEqual(route["path_ids"], ["k8s/Service/game-servers/minecraft",
                         "k8s/Pod/game-servers/minecraft-pod", "k8s/Node//nodegamma03"])

    def test_backend_cli_loads_export_for_search_path_and_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "cluster catalog.json"
            with redirect_stdout(io.StringIO()):
                cluster.main(["--export", str(target)])
            for flags in (["--search", "ollama"],
                          ["--shortest-path", "k8s/Service/game-servers/minecraft",
                           "k8s/Node//nodegamma03"], []):
                result = subprocess.run([sys.executable, str(ROOT / "opscryer_backend.py"),
                                         "--catalog", str(target), *flags],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                if "--search" in flags:
                    self.assertTrue(any(n["label"] == "ollama" for n in payload["results"]))
                elif "--shortest-path" in flags:
                    self.assertTrue(payload["path_found"])
                    self.assertEqual(payload["hop_count"], 2)
                else:
                    self.assertEqual(validate_spatial_graph_contract(payload), [])
                    self.assertEqual(payload["source"], "offline_fallback")

    def test_backend_cli_catalog_errors_are_generic(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "catalog.json"
            for data in (None, "private diagnostic", "{}", '{"nodes": []}'):
                if data is not None:
                    target.write_text(data, encoding="utf-8")
                out = io.StringIO()
                with redirect_stderr(out), self.assertRaises(SystemExit) as error:
                    backend.main(["--catalog", str(target)])
                self.assertEqual(error.exception.code, 2)
                self.assertIn("unable to load a valid graph catalog", out.getvalue())
                self.assertNotIn("private diagnostic", out.getvalue())

    def test_repository_export_is_contract_valid_lf_and_opsec_clean(self):
        content = (ROOT / "live-cluster-sanitized.json").read_bytes()
        catalog = json.loads(content)
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        self.assertIn(catalog["source"], ("live_" + "kubectl", "offline_fallback"))
        self.assertEqual(catalog["example"], catalog["source"] == "offline_fallback")
        self.assertNotIn(b"\r", content)
        self.assertTrue(content.endswith(b"\n"))
        self.assertFalse(any(opsec_findings(content).values()))
        self.assertEqual(_opsec_count(content), 0)
        self.assertFalse(any(scan_public_files(ROOT).values()))


if __name__ == "__main__":
    unittest.main()
