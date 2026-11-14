# SPDX-License-Identifier: Apache-2.0
"""Offline defaults, retained live snapshots, bounded CLI and OPSEC checks."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cluster_harvester as cluster
from golden_path_gates import _opsec_count
import live_poller as poller
from opscryer_backend import validate_spatial_graph_contract


class LivePollerTests(unittest.TestCase):
    def live_snapshot(self, name="observed"):
        return {"source": "live_" + "kubectl", "example": False, "errors": [],
                "items": [{"kind": "Node", "metadata": {"name": name}}]}

    def test_interval_and_timeout_validation(self):
        for value in (float("nan"), float("inf"), -float("inf"), 4.99, 0,
                      -5, True, "30", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                poller.ContinuousClusterPoller(interval_seconds=value)
        for value in (5, 5.5, 30):
            self.assertEqual(poller.ContinuousClusterPoller(value).interval_seconds, value)
        for value in (0, -1, float("nan"), float("inf"), True, "15"):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                poller.ContinuousClusterPoller(timeout=value)

    def test_constructor_and_status_do_not_collect(self):
        with patch.object(poller, "harvest_live_k8s_cluster") as harvest:
            instance = poller.ContinuousClusterPoller(harvest_live=True)
            status = instance.status()
            self.assertEqual(status["poll_count"], 0)
            self.assertIsNone(status["source"])
            self.assertFalse(status["stale"])
            status["poll_count"] = 99
            self.assertEqual(instance.status()["poll_count"], 0)
            harvest.assert_not_called()

    def test_default_reads_bundled_catalog_without_kubectl(self):
        expected = json.loads(poller.DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        with patch.object(cluster.subprocess, "run") as run, \
                patch.object(cluster.shutil, "which") as which, \
                patch.object(poller, "harvest_live_k8s_cluster") as harvest:
            catalog = poller.poll_live_cluster_once()
            run.assert_not_called()
            which.assert_not_called()
            harvest.assert_not_called()
        for key, value in expected.items():
            self.assertEqual(catalog[key], value)
        self.assertFalse(catalog["stale"])
        self.assertEqual(validate_spatial_graph_contract(catalog), [])

    def test_missing_file_builds_offline_without_kubectl(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(poller, "DEFAULT_CATALOG_PATH", Path(directory) / "missing.json"), \
                patch.object(cluster.subprocess, "run") as run, \
                patch.object(cluster.shutil, "which") as which:
            catalog = poller.poll_live_cluster_once()
            self.assertEqual(catalog["source"], "offline_fallback")
            self.assertEqual(catalog["consecutive_failures"], 0)
            self.assertIsNone(catalog["last_error"])
            run.assert_not_called()
            which.assert_not_called()

    def test_failure_retains_live_catalog_and_recovery_resets_status(self):
        live = self.live_snapshot()
        failure = {"items": [], "source": "offline_fallback", "example": True,
                   "errors": ["inventory_unavailable"]}
        recovered = self.live_snapshot("recovered")
        with patch.object(poller, "harvest_live_k8s_cluster",
                          side_effect=[live, failure, failure, recovered]) as harvest, \
                patch.object(poller, "build_live_cluster_spatial_catalog",
                             wraps=cluster.build_live_cluster_spatial_catalog) as build:
            instance = poller.ContinuousClusterPoller(harvest_live=True, timeout=7)
            good = instance.poll_once()
            good["nodes"].clear()
            for count in (1, 2):
                stale = instance.poll_once()
                self.assertEqual(stale["source"], "live_kubectl")
                self.assertFalse(stale["example"])
                self.assertTrue(stale["nodes"])
                self.assertTrue(stale["stale"])
                self.assertEqual(stale["consecutive_failures"], count)
                self.assertEqual(stale["last_error"], "inventory_unavailable")
                self.assertEqual(instance.status()["consecutive_failures"], count)
                stale["nodes"].clear()
            fresh = instance.poll_once()
            self.assertFalse(fresh["stale"])
            self.assertEqual(fresh["consecutive_failures"], 0)
            self.assertIsNone(fresh["last_error"])
            self.assertIn("recovered", [node["label"] for node in fresh["nodes"]])
            self.assertEqual(instance.status()["poll_count"], 4)
            self.assertEqual(harvest.call_count, 4)
            harvest.assert_called_with(timeout=7)
            self.assertEqual(build.call_args_list[0].args, (live,))

    def test_initial_live_fallback_has_no_live_data_to_retain(self):
        for error in ("kubectl_unavailable", "inventory_unavailable", "unknown"):
            snapshot = {"items": [], "source": "offline_fallback", "errors": [error]}
            with patch.object(poller, "harvest_live_k8s_cluster", return_value=snapshot):
                catalog = poller.poll_live_cluster_once(harvest_live=True)
            self.assertFalse(catalog["stale"])
            self.assertEqual(catalog["source"], "offline_fallback")
            self.assertEqual(catalog["consecutive_failures"], 1)
            self.assertEqual(catalog["last_error"], error if error != "unknown"
                             else "inventory_unavailable")

    def test_sanitized_export_and_lf_source_files(self):
        snapshot = cluster.build_live_cluster_spatial_catalog(self.live_snapshot())
        snapshot["summary"] = " ".join((".".join(map(str, (8, 8, 4, 4))),
                                       ":".join(("AA", "BB", "CC", "DD", "EE", "FF")),
                                       "gh" + "p_" + "examplecredential"))
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "input.json", Path(directory) / "out.json"
            source.write_text(json.dumps(snapshot), encoding="utf-8")
            with patch.object(poller, "DEFAULT_CATALOG_PATH", source):
                catalog = poller.poll_live_cluster_once(export_path=target)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), catalog)
            self.assertEqual(_opsec_count(target.read_bytes()), 0)
            self.assertNotIn(b"\r", target.read_bytes())
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()),
                             ["input.json", "out.json"])
        self.assertEqual(_opsec_count(json.dumps(catalog).encode()), 0)
        for path in (Path(poller.__file__), Path(__file__)):
            content = path.read_bytes()
            self.assertTrue(content.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
            self.assertNotIn(b"\r", content)
            self.assertEqual(_opsec_count(content), 0)

    def test_export_retains_stale_live_snapshot(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(poller, "harvest_live_k8s_cluster", side_effect=[
                    self.live_snapshot(), {"items": [], "source": "offline_fallback",
                                           "errors": ["kubectl_unavailable"]}]):
            target = Path(directory) / "cache.json"
            instance = poller.ContinuousClusterPoller(harvest_live=True, export_path=target)
            instance.poll_once()
            stale = instance.poll_once()
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), stale)
            self.assertEqual(stale["last_error"], "kubectl_unavailable")
            self.assertTrue(stale["stale"])

    def test_cli_bounded_loop_json_and_no_final_sleep(self):
        output = io.StringIO()
        with patch.object(poller.time, "sleep") as sleep, redirect_stdout(output):
            self.assertEqual(poller.main(["--max-polls", "2", "--interval", "5", "--json"]), 0)
        sleep.assert_called_once_with(5)
        results = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(results), 2)
        self.assertEqual(_opsec_count(output.getvalue().encode()), 0)

    def test_cli_live_export_and_text(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(poller, "harvest_live_k8s_cluster",
                             return_value=self.live_snapshot()) as harvest, \
                patch.object(poller.time, "sleep") as sleep, \
                redirect_stdout(io.StringIO()) as output:
            target = Path(directory) / "export.json"
            result = poller.main(["--harvest-live", "--max-polls", "1", "--export", str(target)])
            self.assertEqual(result, 0)
            self.assertIn("live_kubectl", output.getvalue())
            self.assertTrue(target.is_file())
            harvest.assert_called_once_with(timeout=15)
            sleep.assert_not_called()

    def test_cli_rejects_invalid_arguments(self):
        for args in (["--interval", "nan"], ["--interval", "4"],
                     ["--interval", "inf"], ["--max-polls", "0"], ["--max-polls", "-2"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                poller.main(args)
            self.assertEqual(raised.exception.code, 2)

    def test_cli_interrupt_and_errors_do_not_expose_exception_text(self):
        for error, expected in ((KeyboardInterrupt(), 0), (OSError("private detail"), 1)):
            with patch.object(poller.ContinuousClusterPoller, "poll_once", side_effect=error), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(poller.main(["--max-polls", "1"]), expected)
            self.assertNotIn("private detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
