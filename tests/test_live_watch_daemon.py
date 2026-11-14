# SPDX-License-Identifier: Apache-2.0
"""Bounded watch composition, snapshot grounding and sanitized feed checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

from cluster_harvester import build_live_cluster_spatial_catalog
import live_watch_daemon as watch
from tests.test_opscryer_public_smoke import opsec_findings


class LiveWatchDaemonTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_live_cluster_spatial_catalog()

    def test_status_card_contract_and_snapshot_only_behavior(self):
        before = deepcopy(self.catalog)
        health = watch.summarize_live_cluster_health(self.catalog)
        with patch.object(watch, "ContinuousClusterPoller") as poller, \
                patch.object(watch.time, "sleep") as sleep, \
                patch("live_poller.harvest_live_k8s_cluster") as harvest:
            result = watch.build_live_watch_status_card(self.catalog)
        self.assertEqual(set(result), {"source", "example", "status_badge",
                         "node_counts", "pod_counts", "deployment_counts",
                         "hotspots_count", "notice"})
        for key in ("source", "example", "node_counts", "pod_counts", "deployment_counts"):
            self.assertEqual(result[key], health[key])
        self.assertEqual(result["hotspots_count"], len(health["node_hotspots"]))
        self.assertIn("supplied snapshot without background polling", result["notice"])
        self.assertEqual(self.catalog, before)
        poller.assert_not_called()
        sleep.assert_not_called()
        harvest.assert_not_called()
        result["node_counts"]["total"] = -1
        self.assertEqual(self.catalog, before)
        self.assertEqual(watch.build_live_watch_status_card(self.catalog)["node_counts"],
                         health["node_counts"])

    def test_status_card_accepts_paths_and_defaults_to_bundled_snapshot(self):
        expected = watch.build_live_watch_status_card(self.catalog)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "snapshot.json"
            target.write_text(json.dumps(self.catalog), encoding="utf-8")
            for catalog in (target, str(target)):
                self.assertEqual(watch.build_live_watch_status_card(catalog), expected)
            with patch.object(watch, "DEFAULT_CATALOG_PATH", target):
                self.assertEqual(watch.build_live_watch_status_card(), expected)
        bundled = Path(watch.__file__).with_name("live-cluster-sanitized.json")
        self.assertEqual(watch.build_live_watch_status_card(),
                         watch.build_live_watch_status_card(bundled))

    def test_status_card_badge_tracks_each_health_indicator(self):
        healthy = {
            "source": "live_" + "kubectl", "example": False,
            "nodes": [
                {"id": "node", "resource_kind": "Node", "resource": {
                    "status": {"conditions": [{"type": "Ready", "status": "True"}]}}},
                {"id": "pod", "resource_kind": "Pod",
                 "resource": {"status": {"phase": "Running"}}},
                {"id": "deployment", "resource_kind": "Deployment", "resource": {
                    "spec": {"replicas": 1}, "status": {"readyReplicas": 1}}},
            ],
        }
        self.assertEqual(watch.build_live_watch_status_card(healthy)["status_badge"], "HEALTHY")
        for phase in ("Running", "Succeeded"):
            for replicas in (0, 1):
                snapshot = deepcopy(healthy)
                snapshot.update(source="offline_fallback", example=True)
                snapshot["nodes"][1]["resource"]["status"]["phase"] = phase
                snapshot["nodes"][2]["resource"]["spec"]["replicas"] = replicas
                self.assertEqual(watch.build_live_watch_status_card(snapshot)["status_badge"],
                                 "HEALTHY")
        degraded = []
        snapshot = deepcopy(healthy)
        snapshot["nodes"][0]["resource"]["status"]["conditions"] = []
        degraded.append(snapshot)
        for phase in ("Failed", "Pending", "Unknown"):
            snapshot = deepcopy(healthy)
            snapshot["nodes"][1]["resource"]["status"]["phase"] = phase
            degraded.append(snapshot)
        snapshot = deepcopy(healthy)
        snapshot["nodes"][2]["resource"]["status"]["readyReplicas"] = 0
        degraded.append(snapshot)
        for metric, value in (("cpu_percent", 80), ("ram_percent", 75)):
            snapshot = deepcopy(healthy)
            snapshot["nodes"][0]["metrics"] = {metric: value}
            card = watch.build_live_watch_status_card(snapshot)
            self.assertEqual(card["hotspots_count"], 1)
            degraded.append(snapshot)
        degraded.append({"nodes": []})
        for index, snapshot in enumerate(degraded):
            with self.subTest(case=index):
                self.assertEqual(watch.build_live_watch_status_card(snapshot)["status_badge"],
                                 "DEGRADED")

    def test_status_card_sanitizes_metadata_without_mutating_input(self):
        public = str(IPv4Address(0x08080404))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        secret = "gh" + "p_" + "synthetic_test_value"
        self.catalog["source"] = " ".join((public, mac, secret, "10.1.2.3", "router.cluster.example.org"))
        before = deepcopy(self.catalog)
        result = watch.build_live_watch_status_card(self.catalog)
        encoded = json.dumps(result).encode()
        self.assertEqual(opsec_findings(encoded), dict.fromkeys(opsec_findings(encoded), 0))
        self.assertEqual(watch.sanitize(result), result)
        for allowed in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "router.cluster.example.org"):
            self.assertIn(allowed, result["source"])
        self.assertNotIn(secret, result["source"])
        self.assertEqual(self.catalog, before)

    def test_status_card_rejects_invalid_catalogs_and_unreadable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "invalid.json"
            target.write_text("{invalid", encoding="utf-8")
            for catalog in ([], 42, {}, {"nodes": [None]}, target,
                            Path(directory) / "missing.json"):
                with self.subTest(catalog_type=type(catalog).__name__), \
                        self.assertRaisesRegex(ValueError, "^Unable to load valid cluster catalog$"):
                    watch.build_live_watch_status_card(catalog)
            with patch.object(watch, "DEFAULT_CATALOG_PATH", target), \
                    self.assertRaises(ValueError):
                watch.build_live_watch_status_card()

    def test_default_offline_cycle_contract_and_no_sleep(self):
        with patch("live_poller.harvest_live_k8s_cluster") as harvest, \
                patch.object(watch.time, "sleep") as sleep:
            result = watch.run_continuous_watch_cycle()
        self.assertEqual(set(result), {"schema_version", "iterations_completed",
                         "latest_health", "latest_diff", "latest_currencies",
                         "grounded_answers", "opsec_clean"})
        self.assertEqual(result["schema_version"], watch.SCHEMA_VERSION)
        self.assertEqual(result["iterations_completed"], 1)
        self.assertIsNone(result["latest_diff"])
        self.assertEqual(result["grounded_answers"], [])
        self.assertEqual(len(result["latest_currencies"]), 7)
        self.assertTrue(result["opsec_clean"])
        self.assertEqual(watch.sanitize(result), result)
        harvest.assert_not_called()
        sleep.assert_not_called()

    def test_consecutive_diffs_and_questions_use_each_current_snapshot(self):
        snapshots = [deepcopy(self.catalog) for _ in range(3)]
        pod = next(n for n in snapshots[1]["nodes"]
                   if n.get("resource_kind") == "Pod")
        pod["resource"]["status"]["phase"] = "Failed"
        pod["metrics"] = {"cpu": 10}
        snapshots[2] = deepcopy(snapshots[1])
        last_pod = next(n for n in snapshots[2]["nodes"] if n["id"] == pod["id"])
        last_pod["resource"]["status"]["phase"] = "Running"
        last_pod["metrics"]["cpu"] = 20
        before = deepcopy(snapshots)
        questions = ["manifest node health", "show credentials"]
        with patch.object(watch, "ContinuousClusterPoller") as factory, \
                patch.object(watch.time, "sleep") as sleep, \
                patch.object(watch, "compute_catalog_diff",
                             wraps=watch.compute_catalog_diff) as diff, \
                patch.object(watch, "answer_operational_question",
                             wraps=watch.answer_operational_question) as answer:
            factory.return_value.poll_once.side_effect = snapshots
            result = watch.run_continuous_watch_cycle(3, 7, True, questions=questions)
        factory.assert_called_once_with(interval_seconds=7, harvest_live=True)
        self.assertEqual(factory.return_value.poll_once.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(7), call(7)])
        self.assertEqual(diff.call_args_list, [call(snapshots[0], snapshots[1]),
                                               call(snapshots[1], snapshots[2])])
        self.assertEqual(answer.call_args_list,
                         [call(q, catalog=s) for s in snapshots for q in questions])
        self.assertEqual(result["iterations_completed"], 3)
        self.assertEqual(result["latest_health"],
                         watch.summarize_live_cluster_health(snapshots[-1]))
        self.assertEqual(result["latest_currencies"],
                         watch.build_enriched_live_currencies(snapshots[-1]))
        self.assertEqual(result["latest_diff"],
                         watch.compute_catalog_diff(snapshots[-2], snapshots[-1]))
        self.assertEqual(result["grounded_answers"][0]["status"], "ok")
        self.assertEqual(result["grounded_answers"][1]["status"], "blocked_by_airlock")
        self.assertEqual(snapshots, before)

    def test_live_collection_is_explicit_and_bounded(self):
        snapshot = {"source": "live_" + "kubectl", "example": False, "items": []}
        with patch("live_poller.harvest_live_k8s_cluster", return_value=snapshot) as harvest:
            result = watch.run_continuous_watch_cycle(harvest_live=True)
        harvest.assert_called_once_with(timeout=15)
        self.assertEqual(result["latest_health"]["source"], "live_kubectl")

    def test_complete_sanitized_lf_feed_is_published_each_cycle(self):
        public = str(IPv4Address(0x08080404))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        secret = "gh" + "p_" + "synthetic_test_value"
        payload = " ".join((public, mac, secret, "10.1.2.3", "router.cluster.example.org"))
        self.catalog["source"] = payload
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(watch, "ContinuousClusterPoller") as factory, \
                patch.object(watch, "answer_operational_question",
                             return_value={"summary": payload}), \
                patch.object(watch, "_export", wraps=watch._export) as export, \
                patch.object(watch.time, "sleep") as sleep:
            target = Path(directory) / "feed.json"
            factory.return_value.poll_once.return_value = self.catalog

            def check_first_export(_interval):
                first = json.loads(target.read_text(encoding="utf-8"))
                self.assertEqual(first["iterations_completed"], 1)
                self.assertIsNone(first["latest_diff"])

            sleep.side_effect = check_first_export
            result = watch.run_continuous_watch_cycle(
                2, output_path=target, questions=["manifest health"])
            content = target.read_bytes()
            self.assertNotIn(b"\r", content)
            self.assertTrue(content.endswith(b"\n"))
            self.assertEqual(json.loads(content), result)
            self.assertEqual(export.call_count, 2)
            self.assertEqual(list(Path(directory).iterdir()), [target])
        encoded = json.dumps(result)
        self.assertEqual(opsec_findings(content), dict.fromkeys(opsec_findings(content), 0))
        for allowed in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "router.cluster.example.org"):
            self.assertIn(allowed, encoded)

    def test_invalid_inputs_fail_before_polling(self):
        inputs = ([{"iterations": value} for value in (0, -1, 1.5, True, "2", None)]
                  + [{"interval_seconds": value}
                     for value in (0, 4, -1, True, "5", None, float("nan"), float("inf"))]
                  + [{"questions": value} for value in ("manifest health", [None], [1], {})])
        with patch.object(watch, "ContinuousClusterPoller") as factory:
            for kwargs in inputs:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    watch.run_continuous_watch_cycle(**kwargs)
        factory.assert_not_called()

    def test_failed_cycle_preserves_previous_export(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(watch, "ContinuousClusterPoller") as factory, \
                patch.object(watch.time, "sleep"):
            target = Path(directory) / "feed.json"
            factory.return_value.poll_once.side_effect = [self.catalog, OSError("private detail")]
            with self.assertRaises(OSError):
                watch.run_continuous_watch_cycle(2, output_path=target)
            self.assertEqual(json.loads(target.read_bytes())["iterations_completed"], 1)

    def test_cli_json_and_text(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(watch.time, "sleep") as sleep, \
                redirect_stdout(io.StringIO()) as output:
            target = Path(directory) / "feed.json"
            self.assertEqual(watch.main(["--iterations", "2", "--interval", "6",
                                         "--output", str(target), "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue()), json.loads(target.read_bytes()))
            sleep.assert_called_once_with(6)
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(watch.main([]), 0)
        self.assertIn("Watch cycles completed: 1", output.getvalue())

    def test_cli_rejects_invalid_arguments_and_hides_errors(self):
        for args in (["--iterations", "0"], ["--iterations", "-1"],
                     ["--iterations", "1.5"], ["--interval", "4"],
                     ["--interval", "nan"], ["--interval", "inf"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                watch.main(args)
            self.assertEqual(raised.exception.code, 2)
        for error, expected in ((OSError("private detail"), 1), (KeyboardInterrupt(), 0)):
            with patch.object(watch, "run_continuous_watch_cycle", side_effect=error), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(watch.main(["--harvest-live"]), expected)
            self.assertNotIn("private detail", output.getvalue())

    def test_source_license_lf_and_opsec(self):
        for path in (Path(watch.__file__), Path(__file__)):
            content = path.read_bytes()
            self.assertTrue(content.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
            self.assertNotIn(b"\r", content)
            self.assertEqual(opsec_findings(content), dict.fromkeys(opsec_findings(content), 0))


if __name__ == "__main__":
    unittest.main()
