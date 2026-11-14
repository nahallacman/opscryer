# SPDX-License-Identifier: Apache-2.0
"""Rehearsal coverage, timing, live opt-in and safe failure reporting."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from golden_path_gates import _opsec_count
import demo_rehearsal as demo
import live_e2e_runner as e2e


class DemoRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        server_class = e2e.ThreadingHTTPServer

        def server(address, handler):
            if address != ("127.0.0.1", 0):
                raise AssertionError("Expected ephemeral loopback")
            instance = server_class(address, handler)
            cls.servers.append(instance)
            return instance

        with patch.object(e2e, "ThreadingHTTPServer", side_effect=server), \
                patch("live_poller.harvest_live_k8s_cluster") as harvest:
            cls.report = demo.run_hackathon_demo_rehearsal()
            harvest.assert_not_called()

    def test_offline_rehearsal_executes_both_acts_chat_and_http(self):
        self.assertTrue(self.report["passed"])
        checks = {c["name"]: c for c in self.report["checks"]}
        for name, mode in (("Act 1: OFFLINE_PUBLIC_STANDALONE", "OFFLINE_PUBLIC_STANDALONE"),
                           ("Act 2: SANITIZED_LIVE_HOME_NETWORK", "SANITIZED_LIVE_HOME_NETWORK")):
            self.assertEqual(checks[name]["details"]["mode"], mode)
        for persona in demo.PERSONAS:
            self.assertEqual(checks["ask_concierge_chat:" + persona]["details"]["persona"], persona)
        self.assertTrue(checks["ask_concierge_chat:airlock_block"]["details"]["airlock_blocked"])
        self.assertEqual(checks["GET /chat"]["details"]["status_code"], 200)
        self.assertEqual(len([name for name in checks if name.startswith("GET ")]), 12)
        self.assertEqual(len(self.servers), 1)
        self.assertEqual(self.servers[0].socket.fileno(), -1)

    def test_timings_summary_serialization_and_opsec(self):
        report = self.report
        for item in [report, *report["checks"]]:
            self.assertIsInstance(item["elapsed_ms"], (int, float))
            self.assertGreaterEqual(item["elapsed_ms"], 0)
        self.assertEqual(report["summary"], {"total": len(report["checks"]),
                                           "passed": len(report["checks"]), "failed": 0})
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)
        self.assertEqual(_opsec_count(json.dumps(report).encode()), 0)
        table = demo.render_scorecard(report)
        for text in ("Phase", "Step", "Result", "Elapsed ms", "PASS", "GET /chat"):
            self.assertIn(text, table)

    def test_presentation_readiness_summary(self):
        report = dict(self.report, elapsed_ms=1000.0)
        with patch.object(demo, "run_hackathon_demo_rehearsal", return_value=report) as run:
            summary = demo.verify_presentation_readiness()
        run.assert_called_once_with(harvest_live=False)
        self.assertEqual(summary, {
            "ready": True,
            "total_checks": report["summary"]["total"],
            "passed_checks": report["summary"]["passed"],
            "failed_checks": 0,
            "elapsed_ms": 1000.0,
            "entrypoints_present": True,
            "suite_portals_ready": True,
            "notice": report["notice"],
        })
        self.assertEqual(json.loads(json.dumps(summary, allow_nan=False)), summary)
        self.assertEqual(_opsec_count(json.dumps(summary).encode()), 0)

    def test_presentation_readiness_requires_each_suite_portal(self):
        portals = {
            "incident_commander": "render_incident_commander_html",
            "capacity_planner": "render_capacity_planner_html",
            "network_topology_inspector": "render_network_inspector_html",
            "gitops_release_cockpit": "render_gitops_cockpit_html",
            "executive_command_center": "render_executive_command_center_html",
            "opscryer_suite_hub": "render_suite_hub_html",
            "gameday_simulator": "render_gameday_simulator_html",
            "playbook_studio": "render_playbook_studio_html",
            "model_tier_copilot": "render_model_copilot_html",
            "game_observability_loop": "render_game_debug_html",
            "jev_knowledge_explorer": "render_jev_knowledge_html",
            "storage_zfs_cockpit": "render_storage_cockpit_html",
            "secops_vulnerability_cockpit": "render_secops_cockpit_html",
            "live_metrics_poller": "render_live_metrics_html",
            "environment_adapters": "render_adapters_html",
            "openapi_spec": "render_api_docs_html",
            "scale_benchmark": "render_scale_benchmark_html",
        }
        report = dict(self.report, elapsed_ms=1000.0)
        for module_name in portals:
            for failure in ("import", "missing_renderer", "render", "text", "none"):
                calls = []

                def load(name):
                    calls.append(name)
                    if name == module_name and failure == "import":
                        print("private diagnostic")
                        raise ImportError("private diagnostic")

                    def render():
                        if name == module_name:
                            if failure == "render":
                                print("private diagnostic")
                                raise RuntimeError("private diagnostic")
                            if failure == "text":
                                return "portal unavailable"
                            if failure == "none":
                                return None
                        return "<!DOCTYPE html><html><body>Portal</body></html>"

                    if name == module_name and failure == "missing_renderer":
                        return SimpleNamespace()
                    return SimpleNamespace(**{portals[name]: render})

                with self.subTest(module=module_name, failure=failure), \
                        patch.object(demo, "run_hackathon_demo_rehearsal", return_value=report), \
                        patch.object(demo, "import_module", side_effect=load), \
                        redirect_stdout(io.StringIO()) as out, \
                        redirect_stderr(io.StringIO()) as err:
                    summary = demo.verify_presentation_readiness()
                self.assertFalse(summary["suite_portals_ready"])
                self.assertFalse(summary["ready"])
                self.assertTrue(summary["entrypoints_present"])
                self.assertEqual(calls, list(portals))
                self.assertEqual(out.getvalue() + err.getvalue(), "")
                self.assertNotIn("private diagnostic", json.dumps(summary))
                self.assertEqual(summary["failed_checks"], report["summary"]["failed"])

    def test_presentation_readiness_forwards_live_opt_in_and_failure(self):
        report = dict(self.report, passed=False, elapsed_ms=1000.0,
                      summary={"total": 2, "passed": 1, "failed": 1})
        with patch.object(demo, "run_hackathon_demo_rehearsal", return_value=report) as run, \
                self.ready_portals():
            summary = demo.verify_presentation_readiness(harvest_live=True)
        run.assert_called_once_with(harvest_live=True)
        self.assertFalse(summary["ready"])
        self.assertTrue(summary["entrypoints_present"])
        self.assertEqual((summary["total_checks"], summary["passed_checks"],
                          summary["failed_checks"]), (2, 1, 1))

    def test_presentation_readiness_requires_each_entrypoint(self):
        for name in ("Act 1: OFFLINE_PUBLIC_STANDALONE",
                     "Act 2: SANITIZED_LIVE_HOME_NETWORK", "GET /", "GET /chat",
                     "GET /api/v1/two-act-status?act=1",
                     "GET /api/v1/two-act-status?act=2"):
            checks = [check for check in self.report["checks"] if check["name"] != name]
            report = dict(self.report, checks=checks, elapsed_ms=1000.0,
                          summary={"total": len(checks), "passed": len(checks), "failed": 0})
            with self.subTest(name=name), patch.object(
                    demo, "run_hackathon_demo_rehearsal", return_value=report), \
                    self.ready_portals():
                summary = demo.verify_presentation_readiness()
            self.assertFalse(summary["ready"])
            self.assertFalse(summary["entrypoints_present"])

    def test_presentation_readiness_total_latency_budget(self):
        for elapsed, ready in ((35000.0, True), (35000.001, False)):
            report = dict(self.report, elapsed_ms=elapsed)
            with self.subTest(elapsed=elapsed), patch.object(
                    demo, "run_hackathon_demo_rehearsal", return_value=report), \
                    self.ready_portals():
                summary = demo.verify_presentation_readiness()
            self.assertEqual(summary["ready"], ready)
            self.assertEqual(summary["elapsed_ms"], elapsed)

    def ready_portals(self):
        # The summary test renders every real portal; these cases isolate
        # entrypoint, flag and budget logic from expensive graph rendering.
        class Portal:
            def __getattr__(self, name):
                return lambda: "<!DOCTYPE html><html><body>Portal</body></html>"

        return patch.object(demo, "import_module", return_value=Portal())

    def test_presentation_readiness_rejects_invalid_live_flag(self):
        with patch.object(demo, "verify_act") as act:
            with self.assertRaises(ValueError):
                demo.verify_presentation_readiness(harvest_live="yes")
            act.assert_not_called()

    def test_invalid_live_flag_rejected_before_io(self):
        with patch.object(demo, "verify_act") as act:
            for value in (None, 0, 1, "yes", []):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    demo.run_hackathon_demo_rehearsal(value)
            act.assert_not_called()

    def test_live_collection_uses_harvested_snapshot(self):
        catalog = json.loads(Path(demo.__file__).with_name(
            "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        catalog.update(source="live_kubectl", example=False, stale=False, consecutive_failures=0)
        with patch.object(demo, "ContinuousClusterPoller") as poller, \
                patch.object(demo, "_verify_http", return_value=None):
            poller.return_value.poll_once.return_value = catalog
            report = demo.run_hackathon_demo_rehearsal(True)
        poller.assert_called_once_with(harvest_live=True)
        poller.return_value.poll_once.assert_called_once_with()
        self.assertTrue(report["passed"])
        walkthrough = next(c for c in report["checks"] if c["name"].startswith("Snapshot health"))
        self.assertEqual(walkthrough["details"]["chat"]["live_cluster_facts"]["source"], "live_kubectl")

    def test_requested_live_fallback_is_failure(self):
        with patch("live_poller.harvest_live_k8s_cluster", return_value={
                "items": [], "source": "offline_fallback", "errors": []}), \
                patch.object(demo, "_verify_http", return_value=None):
            report = demo.run_hackathon_demo_rehearsal(True)
        self.assertFalse(report["passed"])
        self.assertFalse(next(c for c in report["checks"] if c["name"] == "Live collection")["passed"])

    def test_failed_act_is_detected_and_independent_steps_continue(self):
        def broken_act(number):
            print("private diagnostic")
            return {"passed": False, "error": "private diagnostic"}

        with patch.object(demo, "verify_act", side_effect=broken_act), \
                patch.object(demo, "_verify_http", return_value=None), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            report = demo.run_hackathon_demo_rehearsal()
        self.assertFalse(report["passed"])
        self.assertEqual(out.getvalue() + err.getvalue(), "")
        self.assertNotIn("private diagnostic", json.dumps(report))
        self.assertTrue(next(c for c in report["checks"] if c["name"] == "Bundled snapshot")["passed"])
        self.assertEqual(report["summary"]["failed"], 2)

    def test_http_failure_is_recorded_and_server_closed(self):
        handler = e2e._build_frontend_handler()

        class WrongChat(handler):
            def do_GET(self):
                if self.path == "/chat":
                    self._send_bytes(200, b"wrong page", "text/html; charset=utf-8")
                else:
                    super().do_GET()

        with patch.object(e2e, "_build_frontend_handler", return_value=WrongChat):
            report = demo.run_hackathon_demo_rehearsal()
        self.assertFalse(report["passed"])
        checks = {c["name"]: c for c in report["checks"]}
        self.assertFalse(checks["GET /chat"]["passed"])
        self.assertTrue(checks["GET /api/v1/two-act-status?act=2"]["passed"])

    def test_collection_exception_is_safe_and_http_still_runs(self):
        with patch.object(demo, "ContinuousClusterPoller", side_effect=OSError("private diagnostic")), \
                patch.object(demo, "_verify_http", return_value=None) as http:
            report = demo.run_hackathon_demo_rehearsal()
        self.assertFalse(report["passed"])
        http.assert_called_once()
        self.assertNotIn("private diagnostic", json.dumps(report))

    def test_cli_json_table_flags_and_exit_codes(self):
        for args, passed in (([], True), (["--json"], False),
                             (["--harvest-live", "--json"], True)):
            report = dict(self.report, passed=passed)
            with self.subTest(args=args), \
                    patch.object(demo, "run_hackathon_demo_rehearsal", return_value=report) as run, \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(demo.main(args), 0 if passed else 1)
            run.assert_called_once_with(harvest_live="--harvest-live" in args)
            if "--json" in args:
                self.assertEqual(json.loads(output.getvalue())["passed"], passed)
            else:
                self.assertIn("Elapsed ms", output.getvalue())
        for args in ([], ["--json"]):
            with patch.object(demo, "run_hackathon_demo_rehearsal", side_effect=OSError("private diagnostic")), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(demo.main(args), 1)
            self.assertNotIn("private diagnostic", output.getvalue())
            if args:
                self.assertEqual(json.loads(output.getvalue())["error"], "rehearsal_unavailable")


if __name__ == "__main__":
    unittest.main()
