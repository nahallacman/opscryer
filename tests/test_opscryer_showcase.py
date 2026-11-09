# SPDX-License-Identifier: Apache-2.0
"""End-to-end showcase, CLI and fail-closed scorecard tests."""

from contextlib import redirect_stderr, redirect_stdout
from contextlib import ExitStack
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import opscryer_showcase as showcase


class ShowcaseTests(unittest.TestCase):
    def test_master_executes_nine_epics_and_both_acts(self):
        report = showcase.verify_all_epics()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["epics_verified"], 9)
        self.assertEqual([e["epic_id"] for e in report["epics"]],
                         [f"EPIC-{n}" for n in range(1, 10)])
        self.assertTrue(all(e["tests_run"] > 0 and e["passed"] for e in report["epics"]))
        self.assertEqual(report["epics"][4]["scope"],
                         "planned_graph_walkthrough_and_offline_cluster_contracts")
        self.assertEqual([a["act"] for a in report["acts"]], [1, 2])
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)

    def test_act_two_sanitizes_before_graph_exchange(self):
        with patch.object(showcase.opscryer_backend, "KnowledgeGraphBackendEngine",
                          wraps=showcase.opscryer_backend.KnowledgeGraphBackendEngine) as engine:
            result = showcase.verify_act(2)
        self.assertTrue(result["passed"])
        self.assertEqual(result["mode"], "SANITIZED_LIVE_HOME_NETWORK")
        self.assertFalse(result["live_connections"])
        clean = result["telemetry"]
        self.assertEqual(clean["wan"], "203.0.113.1")
        self.assertEqual(clean["mac"], "AA:BB:CC:XX:XX:XX")
        self.assertEqual(clean["lan"], ["10.20.3.2", "172.20.1.2", "172.16.0.2"])
        self.assertEqual(clean["hostname"], "gpu.cluster.example.org")
        self.assertEqual(engine.call_args.args[0]["nodes"][0]["telemetry"], clean)

    def test_broken_sanitizer_fails_without_leaking_payload(self):
        with patch.object(showcase.telemetry_sanitizer,
                          "sanitize_live_home_telemetry_for_demo", side_effect=lambda data: data):
            report = showcase.verify_act(2)
        self.assertFalse(report["passed"])
        self.assertNotIn("telemetry", report)
        self.assertNotIn("synthetic-demo-value", json.dumps(report))

    def test_act_two_verifies_cluster_catalogs_without_live_collection(self):
        with patch.object(showcase.cluster_harvester, "harvest_live_k8s_cluster") as harvest:
            report = showcase.verify_act(2)
        harvest.assert_not_called()
        self.assertTrue(report["passed"])
        self.assertEqual(report["cluster"], {
            "generated_contract": True, "bundled_contract": True,
            "opsec_clean": True, "artifact": "live-cluster-sanitized.json"})
        self.assertIn("tests.test_cluster_harvester", showcase.EPIC_TESTS["EPIC-5"])

    def test_cluster_artifact_failures_are_closed_and_private(self):
        catalog = showcase.cluster_harvester.build_live_cluster_spatial_catalog()
        wan = str(showcase.IPv4Address(0x08080808))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        token = "gh" + "p_" + "privatecredential"
        payloads = [b"private diagnostic", b"{}"]
        for value in (wan, mac, token):
            data = {**catalog, "diagnostic": value}
            payloads.append(json.dumps(data).encode())
            escaped = "".join("\\u%04x" % ord(char) for char in value)
            payloads.append(json.dumps(data).replace(value, escaped).encode())
        payloads.append(json.dumps({**catalog, "example": False}).encode())
        payloads.append(json.dumps({**catalog, "root_id": "missing"}).encode())
        payloads.append(json.dumps({**catalog, "password": "privatecredential"}).encode())
        for index, payload in enumerate(payloads):
            with self.subTest(case=index), patch.object(
                    showcase.Path, "read_bytes", return_value=payload):
                report = showcase.verify_act(2)
            self.assertFalse(report["passed"])
            self.assertNotIn("cluster", report)
            self.assertNotIn("telemetry", report)
            for private in (wan, mac, token, "private diagnostic", "privatecredential"):
                self.assertNotIn(private, json.dumps(report))
        with patch.object(showcase.Path, "read_bytes", side_effect=OSError("private diagnostic")):
            self.assertFalse(showcase.verify_act(2)["passed"])

    def test_epic_five_includes_continuous_live_suites(self):
        self.assertEqual(showcase.EPIC_TESTS["EPIC-5"], (
            "tests.test_dogfood_graph", "tests.test_cluster_harvester",
            "tests.test_live_poller", "tests.test_cluster_diff_engine",
            "tests.test_live_advisor", "tests.test_live_currencies",
            "tests.test_live_watch_daemon", "tests.test_openbao_kms_provenance",
            "tests.test_oidc_rbac_verifier", "tests.test_chaos_blast_radius",
            "tests.test_live_gitops_signals", "tests.test_live_ollama_probe",
            "tests.test_live_e2e_runner", "tests.test_network_topology_inspector"))

    def test_wave_c_suites_are_registered_once_without_master_recursion(self):
        self.assertEqual(showcase.EPIC_TESTS["EPIC-4"], (
            "tests.test_security_airlock", "tests.test_secops_vulnerability_cockpit"))
        self.assertEqual(showcase.EPIC_TESTS["EPIC-3"], (
            "tests.test_opscryer_backend", "tests.test_model_tier_copilot"))
        self.assertEqual(showcase.EPIC_TESTS["EPIC-2"], (
            "tests.test_jev_client", "tests.test_playbook_studio",
            "tests.test_jev_knowledge_explorer"))
        self.assertEqual(showcase.EPIC_TESTS["EPIC-1"], (
            "tests.test_opscryer_public_smoke", "tests.test_two_act_browser",
            "tests.test_demo_rehearsal", "tests.test_opscryer_suite_hub"))
        self.assertEqual(showcase.EPIC_TESTS["EPIC-9"], (
            "tests.test_oscal_compliance", "tests.test_telemetry_sanitizer",
            "tests.test_edge_case_hardening", "tests.test_executive_command_center"))
        self.assertEqual(showcase.EPIC_TESTS["EPIC-7"], (
            "tests.test_noc_golden_signals", "tests.test_incident_commander",
            "tests.test_gameday_simulator", "tests.test_storage_zfs_cockpit"))
        self.assertEqual(showcase.EPIC_TESTS["EPIC-6"], (
            "tests.test_golden_path_gates", "tests.test_gitops_release_cockpit"))
        modules = [module for suites in showcase.EPIC_TESTS.values() for module in suites]
        for module in ("tests.test_live_e2e_runner", "tests.test_demo_rehearsal",
                       "tests.test_edge_case_hardening", "tests.test_chat_walkthrough",
                       "tests.test_incident_commander", "tests.test_capacity_planner",
                       "tests.test_gameday_simulator",
                       "tests.test_storage_zfs_cockpit",
                       "tests.test_playbook_studio",
                       "tests.test_jev_knowledge_explorer",
                       "tests.test_model_tier_copilot",
                       "tests.test_network_topology_inspector",
                       "tests.test_gitops_release_cockpit",
                       "tests.test_executive_command_center",
                       "tests.test_opscryer_suite_hub",
                       "tests.test_secops_vulnerability_cockpit",
                       "tests.test_game_observability_loop"):
            with self.subTest(module=module):
                self.assertEqual(modules.count(module), 1)
        self.assertNotIn("tests.test_opscryer_showcase", modules)

    def test_epic_eight_includes_triage_portal_walkthrough_and_capacity_planner(self):
        self.assertEqual(showcase.EPIC_TESTS["EPIC-8"], (
            "tests.test_gpu_and_household_triage", "tests.test_ticket_chat_portal",
            "tests.test_chat_walkthrough", "tests.test_capacity_planner",
            "tests.test_game_observability_loop"))

    def test_wave_b6_checks_use_bundled_snapshot_without_network(self):
        bundled = json.loads(Path(showcase.__file__).with_name(
            "live-cluster-sanitized.json").read_bytes())
        normalized = showcase.opscryer_backend.KnowledgeGraphBackendEngine(bundled).catalog()
        providers = (
            (showcase.ticket_chat_portal, "ask_concierge_chat"),
            (showcase.chaos_blast_radius, "verify_all_six_chaos_planes"),
            (showcase.openbao_kms_provenance, "audit_openbao_secret_provenance"),
            (showcase.oidc_rbac_verifier, "audit_cluster_ingress_oidc_posture"),
            (showcase.live_gitops_signals, "enrich_all_seven_live_currencies"),
            (showcase.oscal_compliance, "evaluate_live_oscal_posture"),
        )
        with ExitStack() as stack:
            mocks = [(name, stack.enter_context(patch.object(
                module, name, wraps=getattr(module, name)))) for module, name in providers]
            network = stack.enter_context(patch(
                "socket.socket", side_effect=AssertionError("network attempted")))
            harvest = stack.enter_context(patch.object(
                showcase.cluster_harvester, "harvest_live_k8s_cluster"))
            # OSCAL also audits the local checkout with read-only Git commands.
            # Keep those real while rejecting any collection subprocess.
            original_run = subprocess.run

            def local_git_only(args, **kwargs):
                self.assertEqual(args[0], "git")
                self.assertIn(args[3], ("rev-parse", "ls-files", "log"))
                return original_run(args, **kwargs)

            run = stack.enter_context(patch("subprocess.run", side_effect=local_git_only))
            report = showcase.verify_act(2)
        self.assertTrue(report["passed"], report)
        for name, mock in mocks:
            self.assertIn(name, report["checks"])
            if name == "ask_concierge_chat":
                mock.assert_called_once_with("manifest node health", catalog=bundled)
            else:
                # The advisor also composes chaos, provenance and OIDC reports.
                # Require the explicit showcase call and ground every nested call.
                self.assertEqual(sum(not call.args and call.kwargs == {"catalog": bundled}
                                     for call in mock.call_args_list), 1, name)
                self.assertTrue(all((call.args[0] if call.args else call.kwargs.get("catalog"))
                                    in (bundled, normalized)
                                    for call in mock.call_args_list), name)
        network.assert_not_called()
        harvest.assert_not_called()
        for invocation in run.call_args_list:
            self.assertEqual(invocation.args[0][0], "git")
            self.assertIn(invocation.args[0][3], ("rev-parse", "ls-files", "log"))

    def test_invalid_wave_b6_evidence_fails_privately(self):
        for module, function, invalid in (
            (showcase.ticket_chat_portal, "ask_concierge_chat", {}),
            (showcase.chaos_blast_radius, "verify_all_six_chaos_planes", {}),
            (showcase.openbao_kms_provenance, "audit_openbao_secret_provenance", {}),
            (showcase.oidc_rbac_verifier, "audit_cluster_ingress_oidc_posture", {}),
            (showcase.live_gitops_signals, "enrich_all_seven_live_currencies", []),
            (showcase.oscal_compliance, "evaluate_live_oscal_posture", {}),
        ):
            for raises in (False, True):
                def broken(*args, **kwargs):
                    print("private diagnostic")
                    print("private diagnostic", file=sys.stderr)
                    if raises:
                        raise RuntimeError("private diagnostic")
                    return invalid

                with self.subTest(function=function, raises=raises), \
                        patch.object(module, function, side_effect=broken):
                    output, errors = io.StringIO(), io.StringIO()
                    with redirect_stdout(output), redirect_stderr(errors):
                        report = showcase.verify_act(2)
                self.assertFalse(report["passed"])
                self.assertNotIn("cluster", report)
                self.assertNotIn("telemetry", report)
                self.assertNotIn("private diagnostic", json.dumps(report))
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(errors.getvalue(), "")

    def test_live_checks_use_bundled_snapshot_without_network_or_collection(self):
        bundled = json.loads(Path(showcase.__file__).with_name(
            "live-cluster-sanitized.json").read_bytes())
        # Isolate the original continuous-live calls; the Wave-B6 composition
        # (which also calls the advisor and currency builder) is checked above.
        with patch.object(showcase, "_verify_wave_b6_catalog"), \
                patch.object(showcase.cluster_diff_engine, "summarize_live_cluster_health",
                          wraps=showcase.cluster_diff_engine.summarize_live_cluster_health) as health, \
                patch.object(showcase.live_currencies, "build_enriched_live_currencies",
                             wraps=showcase.live_currencies.build_enriched_live_currencies) as currencies, \
                patch.object(showcase.live_advisor, "answer_operational_question",
                             wraps=showcase.live_advisor.answer_operational_question) as advisor, \
                patch("subprocess.run", side_effect=AssertionError("collection attempted")) as run, \
                patch("socket.socket", side_effect=AssertionError("network attempted")) as network, \
                patch.object(showcase.cluster_harvester, "harvest_live_k8s_cluster") as harvest:
            report = showcase.verify_act(2)
        self.assertTrue(report["passed"], report)
        health.assert_called_once_with(bundled)
        currencies.assert_called_once_with(bundled)
        advisor.assert_called_once_with(
            "manifest node health", catalog=bundled, provider="deterministic")
        for mock in (run, network, harvest):
            mock.assert_not_called()
        for check in ("summarize_live_cluster_health", "build_enriched_live_currencies",
                      "answer_operational_question"):
            self.assertIn(check, report["checks"])

    def test_invalid_live_evidence_fails_act_and_epic_privately(self):
        class Passing(unittest.TestCase):
            def runTest(self):
                pass

        for module, function, invalid in (
            (showcase.cluster_diff_engine, "summarize_live_cluster_health", {}),
            (showcase.live_currencies, "build_enriched_live_currencies", []),
            (showcase.live_advisor, "answer_operational_question", {}),
        ):
            for raises in (False, True):
                def broken(*args, **kwargs):
                    print("private diagnostic")
                    print("private diagnostic", file=sys.stderr)
                    if raises:
                        raise RuntimeError("private diagnostic")
                    return invalid

                with self.subTest(function=function, raises=raises), \
                        patch.object(module, function, side_effect=broken), \
                        patch.object(unittest.TestLoader, "loadTestsFromNames",
                                     side_effect=lambda _: unittest.TestSuite([Passing()])):
                    output, errors = io.StringIO(), io.StringIO()
                    with redirect_stdout(output), redirect_stderr(errors):
                        act = showcase.verify_act(2)
                        epic = showcase._run_epic("EPIC-5", ())
                self.assertFalse(act["passed"])
                self.assertFalse(epic["passed"])
                self.assertNotIn("cluster", act)
                self.assertNotIn("telemetry", act)
                self.assertNotIn("private diagnostic", json.dumps([act, epic]))
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(errors.getvalue(), "")

    def test_invalid_generated_cluster_fails_act_and_epic(self):
        class Passing(unittest.TestCase):
            def runTest(self):
                pass

        with patch.object(showcase.cluster_harvester, "build_live_cluster_spatial_catalog",
                          return_value={}), patch.object(
                              unittest.TestLoader, "loadTestsFromNames",
                              return_value=unittest.TestSuite([Passing()])):
            self.assertFalse(showcase.verify_act(2)["passed"])
            self.assertFalse(showcase._run_epic("EPIC-5", ())["passed"])

    def test_broken_act_one_dependency_fails(self):
        with patch.object(showcase.opscryer_backend.KnowledgeGraphBackendEngine,
                          "search", return_value={"results": []}):
            self.assertFalse(showcase.verify_act(1)["passed"])

    def test_act_dependency_diagnostics_are_withheld(self):
        def noisy_dependency(*args):
            print("private diagnostic")
            print("private diagnostic", file=sys.stderr)
            raise RuntimeError("private diagnostic")

        for act in (1, 2):
            with self.subTest(act=act), patch.object(
                    showcase.opscryer_browser, "build_two_act_browser_status",
                    side_effect=noisy_dependency):
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    code = showcase.main(["--act", str(act), "--json"])
                report = json.loads(output.getvalue())
                self.assertEqual(code, 1)
                self.assertFalse(report["passed"])
                self.assertNotIn("private diagnostic", output.getvalue())
                self.assertEqual(errors.getvalue(), "")

    def test_invalid_act_values(self):
        for act in (True, False, None, "1", 1.0, 0, 3, [], {}):
            with self.subTest(act=act), self.assertRaises(ValueError):
                showcase.verify_act(act)

    def test_missing_suite_fails_closed(self):
        record = showcase._run_epic("EPIC-1", ("tests.no_such_showcase_suite",))
        self.assertFalse(record["passed"])
        self.assertGreater(record["errors"], 0)

    def test_failing_skipped_and_empty_suites_cannot_pass(self):
        class Failure(unittest.TestCase):
            def runTest(self):
                print("private diagnostic")
                self.fail("private diagnostic")

        class Skipped(unittest.TestCase):
            @unittest.skip("no evidence")
            def runTest(self):
                pass

        for cases in ([Failure()], [Skipped()], []):
            with self.subTest(cases=cases), patch.object(
                    unittest.TestLoader, "loadTestsFromNames",
                    return_value=unittest.TestSuite(cases)):
                output = io.StringIO()
                with redirect_stdout(output):
                    report = showcase._run_epic("EPIC-1", ())
                self.assertFalse(report["passed"])
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("private diagnostic", json.dumps(report))

    def test_master_counts_failures_and_continues(self):
        def epic(epic_id, modules):
            return {"epic_id": epic_id, "passed": epic_id != "EPIC-4"}

        with patch.object(showcase, "_run_epic", side_effect=epic):
            report = showcase.verify_all_epics()
        self.assertFalse(report["passed"])
        self.assertEqual(report["epics_verified"], 8)
        self.assertEqual(len(report["epics"]), 9)

    def test_act_failure_fails_master_even_when_epics_pass(self):
        with patch.object(showcase, "_run_epic", return_value={"passed": True}), \
                patch.object(showcase, "verify_act", return_value={"passed": False}):
            report = showcase.verify_all_epics()
        self.assertEqual(report["epics_verified"], 9)
        self.assertFalse(report["passed"])

    def test_cli_both_acts_from_another_directory(self):
        script = Path(showcase.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            for act in (1, 2):
                result = subprocess.run([sys.executable, str(script), "--act", str(act), "--json"],
                                        cwd=directory, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                report = json.loads(result.stdout)
                self.assertTrue(report["passed"])
                self.assertEqual(report["acts"][0]["act"], act)

    def test_cli_master_json_and_failure_exit(self):
        for passed in (True, False):
            report = {"passed": passed, "epics_verified": 9 if passed else 8}
            with patch.object(showcase, "verify_all_epics", return_value=report) as verify:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = showcase.main(["--verify-all-epics", "--act", "2", "--json"])
                verify.assert_called_once_with()
                self.assertEqual(code, 0 if passed else 1)
                self.assertEqual(json.loads(output.getvalue()), report)

    def test_cli_master_json_from_another_directory(self):
        script = Path(showcase.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(script), "--verify-all-epics", "--json"],
                cwd=directory, capture_output=True, text=True, timeout=360)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertTrue(report["passed"])
        self.assertEqual(report["epics_verified"], 9)
        self.assertEqual([act["mode"] for act in report["acts"]], [
            "OFFLINE_PUBLIC_STANDALONE", "SANITIZED_LIVE_HOME_NETWORK"])
        self.assertEqual(report["acts"][1]["telemetry"]["wan"], "203.0.113.1")
        self.assertEqual(report["acts"][1]["telemetry"]["mac"], "AA:BB:CC:XX:XX:XX")

    def test_cli_default_and_human_output(self):
        with patch.object(showcase, "verify_all_epics", return_value={
                "passed": True, "epics_verified": 9, "acts": []}) as verify:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(showcase.main([]), 0)
            verify.assert_called_once_with()
            self.assertIn("Epics verified: 9/9", output.getvalue())

    def test_cli_rejects_invalid_act(self):
        result = subprocess.run([sys.executable, showcase.__file__, "--act", "3", "--json"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
