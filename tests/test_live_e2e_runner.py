# SPDX-License-Identifier: Apache-2.0
"""Real loopback smoke coverage, live opt-ins, failure reporting and cleanup."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from golden_path_gates import _opsec_count
import live_e2e_runner as runner


class LiveE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        server_class = runner.ThreadingHTTPServer

        def server(address, handler):
            if address != ("127.0.0.1", 0):
                raise AssertionError("Server must use ephemeral loopback")
            instance = server_class(address, handler)
            cls.servers.append(instance)
            return instance

        with patch.object(runner, "ThreadingHTTPServer", side_effect=server), \
                patch("live_poller.harvest_live_k8s_cluster") as harvest, \
                patch.object(runner, "probe_local_ollama_models") as probe:
            cls.report = runner.run_live_e2e_verification()
            harvest.assert_not_called()
            probe.assert_not_called()

    def test_offline_end_to_end_covers_integrations_and_all_required_routes(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["poller_status"]["poll_count"], 1)
        checks = {check["name"]: check for check in self.report["checks"]}
        self.assertEqual(len([name for name in checks if name.startswith("GET ")]), 12)
        for name in ("ContinuousClusterPoller", "summarize_live_cluster_health",
                     "enrich_all_seven_live_currencies", "answer_operational_question",
                     "verify_all_six_chaos_planes", "audit_openbao_secret_provenance",
                     "audit_cluster_ingress_oidc_posture", "evaluate_live_oscal_posture",
                     "run_multi_persona_chat_walkthrough",
                     "ask_concierge_chat:airlock_block", "loopback_http_server"):
            self.assertTrue(checks[name]["passed"], name)
        for persona in ("household_user", "developer", "executive", "sre"):
            details = checks["ask_concierge_chat:" + persona]["details"]
            self.assertEqual(details["persona"], persona)
            self.assertFalse(details["airlock_blocked"])
        concierge = checks["GET /api/v1/chat-concierge?q=minecraft&persona=household_user"]
        self.assertEqual(concierge["details"]["status_code"], 200)
        advisor = checks["GET /api/v1/live-cluster-ask?q=nodebeta02"]
        self.assertEqual(advisor["details"]["status_code"], 403)
        self.assertEqual(len(self.servers), 1)
        self.assertEqual(self.servers[0].socket.fileno(), -1)
        self.assertEqual(json.loads(json.dumps(self.report)), self.report)
        self.assertEqual(_opsec_count(json.dumps(self.report).encode()), 0)

    def test_walkthrough_uses_polled_snapshot_and_records_transcript(self):
        snapshot = json.loads(Path(runner.__file__).with_name(
            "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        snapshot["source"] = "walkthrough_test_snapshot"
        with patch.object(runner.ContinuousClusterPoller, "poll_once", return_value=snapshot), \
                patch.object(runner, "run_multi_persona_chat_walkthrough",
                             wraps=runner.run_multi_persona_chat_walkthrough) as walkthrough, \
                patch.object(runner, "_verify_http", return_value=None):
            report = runner.run_live_e2e_verification()
        self.assertTrue(report["passed"])
        walkthrough.assert_called_once_with(catalog=snapshot)
        self.assertIs(walkthrough.call_args.kwargs["catalog"], snapshot)
        check = next(c for c in report["checks"]
                     if c["name"] == "run_multi_persona_chat_walkthrough")
        self.assertEqual(check["details"], runner.run_multi_persona_chat_walkthrough(snapshot))

    def test_invalid_walkthrough_fails_its_check_and_continues(self):
        original = next(c["details"] for c in self.report["checks"]
                        if c["name"] == "run_multi_persona_chat_walkthrough")
        for case in ("summary", "turns", "airlock", "snapshot", "citations", "oscal"):
            result = deepcopy(original)
            if case == "summary":
                result["summary"]["blocked"] = 0
            elif case == "turns":
                result["turns"].pop()
            elif case == "airlock":
                result["turns"][2]["response"]["ticket_card"] = {"unexpected": True}
            elif case == "snapshot":
                result["turns"][0]["response"]["live_cluster_facts"] = {}
            elif case == "citations":
                result["turns"][0]["response"]["cited_node_ids"] = ["missing-node"]
            else:
                result["turns"][-1]["response"]["oscal_posture"]["controls"][0]["status"] = "passed"
            with self.subTest(case=case), \
                    patch.object(runner, "run_multi_persona_chat_walkthrough", return_value=result), \
                    patch.object(runner, "_verify_http", return_value=None):
                report = runner.run_live_e2e_verification()
            self.assertFalse(report["passed"])
            self.assertEqual([c["name"] for c in report["checks"] if not c["passed"]],
                             ["run_multi_persona_chat_walkthrough"])

    def test_invalid_configuration_rejected_before_io(self):
        with patch.object(runner, "ContinuousClusterPoller") as poller:
            for timeout in (0, -1, True, None, "15", float("nan"), float("inf")):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    runner.run_live_e2e_verification(timeout=timeout)
            for kwargs in ({"harvest_live": "yes"}, {"probe_ollama": 1}):
                with self.assertRaises(ValueError):
                    runner.run_live_e2e_verification(**kwargs)
            poller.assert_not_called()

    def test_requested_live_collection_and_probe_receive_timeout(self):
        snapshot = json.loads(Path(runner.__file__).with_name(
            "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        snapshot.update(source="live_kubectl", example=False, stale=False,
                        consecutive_failures=0)
        with patch.object(runner, "ContinuousClusterPoller") as poller, \
                patch.object(runner, "probe_local_ollama_models", return_value={
                    "source": "ollama_api_tags", "available": True, "models": []}) as probe, \
                patch.object(runner, "_verify_http", return_value=None):
            poller.return_value.poll_once.return_value = snapshot
            poller.return_value.status.return_value = {"poll_count": 1}
            report = runner.run_live_e2e_verification(True, True, timeout=7)
        self.assertTrue(report["passed"], [c["name"] for c in report["checks"] if not c["passed"]])
        poller.assert_called_once_with(harvest_live=True, timeout=7)
        poller.return_value.poll_once.assert_called_once_with()
        probe.assert_called_once_with(live_http=True, timeout=7)

    def test_opted_in_services_cannot_pass_with_offline_fallback(self):
        with patch.object(runner, "probe_local_ollama_models", return_value={
                "source": "offline_fixture", "available": False}), \
                patch("live_poller.harvest_live_k8s_cluster", return_value={
                    "items": [], "source": "offline_fallback", "errors": []}), \
                patch.object(runner, "_verify_http", return_value=None):
            report = runner.run_live_e2e_verification(True, True)
        self.assertFalse(report["passed"])
        failed = {c["name"] for c in report["checks"] if not c["passed"]}
        self.assertTrue({"live_collection", "probe_local_ollama_models"} <= failed)

    def test_broken_integration_is_recorded_without_leaking_diagnostics(self):
        def broken(*args, **kwargs):
            print("private diagnostic")
            raise RuntimeError("private diagnostic")

        with patch.object(runner, "run_multi_persona_chat_walkthrough", side_effect=broken), \
                patch.object(runner, "_verify_http", return_value=None), \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as error:
            report = runner.run_live_e2e_verification()
        self.assertFalse(report["passed"])
        self.assertNotIn("private diagnostic", json.dumps(report))
        self.assertEqual(output.getvalue() + error.getvalue(), "")
        self.assertTrue(next(c for c in report["checks"]
                             if c["name"] == "evaluate_live_oscal_posture")["passed"])

    def test_bad_http_body_fails_and_server_is_closed(self):
        handler = runner._build_frontend_handler()

        class WrongBody(handler):
            def do_GET(self):
                if self.path == "/":
                    self._send_bytes(200, b"wrong page", "text/html; charset=utf-8")
                else:
                    super().do_GET()

        server_class = runner.ThreadingHTTPServer
        servers = []

        def server(*args):
            instance = server_class(*args)
            servers.append(instance)
            return instance

        with patch.object(runner, "_build_frontend_handler", return_value=WrongBody), \
                patch.object(runner, "ThreadingHTTPServer", side_effect=server):
            report = runner.run_live_e2e_verification()
        self.assertFalse(report["passed"])
        self.assertFalse(next(c for c in report["checks"] if c["name"] == "GET /")["passed"])
        self.assertTrue(next(c for c in report["checks"] if c["name"] == "GET /chat")["passed"])
        self.assertEqual(servers[0].socket.fileno(), -1)

    def test_bind_failure_and_poll_failure_fail_closed(self):
        with patch.object(runner.ContinuousClusterPoller, "poll_once",
                          side_effect=OSError("private diagnostic")), \
                patch.object(runner, "ThreadingHTTPServer",
                             side_effect=OSError("private diagnostic")):
            report = runner.run_live_e2e_verification()
        self.assertFalse(report["passed"])
        self.assertTrue(all(not c["passed"] for c in report["checks"]))
        self.assertNotIn("private diagnostic", json.dumps(report))

    def test_final_report_is_sanitized(self):
        unsafe = {"source": "ollama_api_tags", "available": True,
                  "models": [{"name": ".".join(("8", "8", "4", "4"))},
                             {"name": ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))},
                             {"name": "gh" + "p_" + "examplecredential"}]}
        with patch.object(runner, "probe_local_ollama_models", return_value=unsafe), \
                patch.object(runner, "_verify_http", return_value=None):
            report = runner.run_live_e2e_verification(probe_ollama=True)
        encoded = json.dumps(report)
        self.assertTrue(report["passed"])
        self.assertIn("203.0.113.1", encoded)
        self.assertIn("AA:BB:CC:XX:XX:XX", encoded)
        self.assertEqual(_opsec_count(encoded.encode()), 0)

    def test_cli_flags_json_text_and_failure_exit_codes(self):
        for args, passed in ((["--harvest-live", "--probe-ollama", "--json"], True),
                             (["--json"], False), ([], True)):
            with self.subTest(args=args), \
                    patch.object(runner, "run_live_e2e_verification", return_value={
                        "passed": passed, "checks": []}) as verify, \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runner.main(args), 0 if passed else 1)
            verify.assert_called_once_with(harvest_live="--harvest-live" in args,
                                           probe_ollama="--probe-ollama" in args)
            if "--json" in args:
                self.assertEqual(json.loads(output.getvalue())["passed"], passed)
            else:
                self.assertIn("PASS", output.getvalue())
        with patch.object(runner, "run_live_e2e_verification", side_effect=OSError("private detail")), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(["--json"]), 1)
        self.assertEqual(json.loads(output.getvalue())["error"], "verification_unavailable")
        self.assertNotIn("private detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
