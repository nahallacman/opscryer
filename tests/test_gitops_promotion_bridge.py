# SPDX-License-Identifier: Apache-2.0
"""Unit and behavioral tests for gitops_promotion_bridge.py (Wave 3 M11)."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from urllib.parse import urlsplit

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import action_cards
import event_stream
from gitops_promotion_bridge import (
    ARGO_PROD_APP_PATH,
    MIN_REQUIRED_TESTS_RUN,
    PROD_ACTION_TARGET_NODE_ID,
    PROD_HELM_TEMPLATE_PATH,
    SCHEMA_VERSION,
    compute_environment_bundle_drift,
    evaluate_promotion_readiness,
    get_promotion_bridge_state,
    handle_gitops_promotion_api,
    reset_promotion_bridge,
    stage_gitops_prod_promotion,
)


class TestGitOpsPromotionBridge(unittest.TestCase):
    """Comprehensive test suite for the 2-Stage GitOps Dev-to-Prod Promotion Bridge."""

    def setUp(self) -> None:
        reset_promotion_bridge()
        action_cards.reset_action_ledger()
        event_stream.reset_event_buffer()

    def tearDown(self) -> None:
        reset_promotion_bridge()
        action_cards.reset_action_ledger()
        event_stream.reset_event_buffer()

    # ------------------------------------------------------------------
    # 1. State & Bundle SHA-256 Drift Detection Tests
    # ------------------------------------------------------------------

    def test_01_default_state_and_reset_promotion_bridge(self) -> None:
        state = get_promotion_bridge_state()
        self.assertEqual(state["dev_environment_state"]["deployment"], "opscryer-suite-dev")
        self.assertEqual(state["dev_environment_state"]["namespace"], "dev-envs")
        self.assertEqual(state["prod_environment_state"]["deployment"], "opscryer-prod")
        self.assertEqual(state["prod_environment_state"]["namespace"], "security")
        self.assertFalse(state["prod_environment_state"]["direct_prod_apply_allowed"])
        self.assertEqual(state["staged_promotions"], [])

        # Stage one promotion then verify reset clears it
        code, _ = stage_gitops_prod_promotion()
        self.assertEqual(code, 200)
        self.assertEqual(len(get_promotion_bridge_state()["staged_promotions"]), 1)

        reset_res = reset_promotion_bridge()
        self.assertEqual(reset_res["status"], "reset")
        self.assertEqual(len(get_promotion_bridge_state()["staged_promotions"]), 0)

    def test_02_bundle_drift_in_sync_identical_manifests(self) -> None:
        manifest_a = {
            "opscryer_browser.py": "sha256-aaa111",
            "action_cards.py": "sha256-bbb222",
            "pqc_security.py": "sha256-ccc333",
        }
        manifest_b = {
            "pqc_security.py": "sha256-ccc333",
            "opscryer_browser.py": "sha256-aaa111",
            "action_cards.py": "sha256-bbb222",
        }
        drift = compute_environment_bundle_drift(
            dev_manifest=manifest_a, prod_manifest=manifest_b
        )
        self.assertEqual(drift["schema_version"], SCHEMA_VERSION)
        self.assertEqual(drift["drift_status"], "IN_SYNC")
        self.assertEqual(drift["dev_bundle_sha256"], drift["prod_bundle_sha256"])
        self.assertEqual(drift["changed_modules"], [])
        self.assertEqual(drift["added_modules"], [])
        self.assertEqual(drift["removed_modules"], [])
        self.assertFalse(drift["promotion_required"])

    def test_03_bundle_drift_dev_ahead_added_and_changed_modules(self) -> None:
        prod_manifest = {
            "opscryer_browser.py": "sha256-v2",
            "action_cards.py": "sha256-v2",
        }
        dev_manifest = {
            "opscryer_browser.py": "sha256-v3-updated",
            "action_cards.py": "sha256-v2",
            "gitops_promotion_bridge.py": "sha256-v3-new",
            "otlp_trace_exporter.py": "sha256-v3-new",
        }
        drift = compute_environment_bundle_drift(
            dev_manifest=dev_manifest, prod_manifest=prod_manifest
        )
        self.assertEqual(drift["drift_status"], "DEV_AHEAD")
        self.assertNotEqual(drift["dev_bundle_sha256"], drift["prod_bundle_sha256"])
        self.assertEqual(drift["changed_modules"], ["opscryer_browser.py"])
        self.assertEqual(
            drift["added_modules"],
            ["gitops_promotion_bridge.py", "otlp_trace_exporter.py"],
        )
        self.assertEqual(drift["removed_modules"], [])
        self.assertTrue(drift["promotion_required"])

    def test_04_bundle_drift_prod_drift_when_prod_has_untracked_modules(self) -> None:
        dev_manifest = {
            "opscryer_browser.py": "sha256-v2",
            "action_cards.py": "sha256-v2",
        }
        prod_manifest = {
            "opscryer_browser.py": "sha256-v2",
            "action_cards.py": "sha256-v2",
            "untracked_emergency_patch.py": "sha256-extra",
        }
        drift = compute_environment_bundle_drift(
            dev_manifest=dev_manifest, prod_manifest=prod_manifest
        )
        self.assertEqual(drift["drift_status"], "PROD_DRIFT")
        self.assertEqual(drift["removed_modules"], ["untracked_emergency_patch.py"])
        self.assertEqual(drift["added_modules"], [])
        self.assertEqual(drift["changed_modules"], [])
        self.assertTrue(drift["promotion_required"])

    def test_05_bundle_drift_prod_drift_hotfix_marker_and_explicit_flag(self) -> None:
        dev_manifest = {"opscryer_browser.py": "sha256-clean-v2"}
        prod_manifest_hotfix = {"opscryer_browser.py": "hotfix-manual-edit-999"}
        drift_hotfix = compute_environment_bundle_drift(
            dev_manifest=dev_manifest, prod_manifest=prod_manifest_hotfix
        )
        self.assertEqual(drift_hotfix["drift_status"], "PROD_DRIFT")
        self.assertEqual(drift_hotfix["changed_modules"], ["opscryer_browser.py"])
        self.assertTrue(drift_hotfix["promotion_required"])

        prod_manifest_flagged = {
            "modules": {"opscryer_browser.py": "sha256-other"},
            "out_of_band_drift": True,
        }
        drift_flagged = compute_environment_bundle_drift(
            dev_manifest=dev_manifest, prod_manifest=prod_manifest_flagged
        )
        self.assertEqual(drift_flagged["drift_status"], "PROD_DRIFT")
        self.assertTrue(drift_flagged["promotion_required"])

    def test_06_default_environment_drift_is_dev_ahead(self) -> None:
        drift = compute_environment_bundle_drift()
        self.assertEqual(drift["drift_status"], "DEV_AHEAD")
        self.assertIn("gitops_promotion_bridge.py", drift["added_modules"])
        self.assertTrue(drift["promotion_required"])

    # ------------------------------------------------------------------
    # 2. Stage 1 Promotion Readiness Evaluator Tests
    # ------------------------------------------------------------------

    def test_07_evaluate_readiness_passes_with_default_healthy_posture(self) -> None:
        readiness = evaluate_promotion_readiness()
        self.assertTrue(readiness["stage1_passed"])
        self.assertTrue(readiness["ready_for_stage2_action_card"])
        self.assertEqual(readiness["blocking_reasons"], [])
        self.assertTrue(
            readiness["stage1_checks"]["stage1a_merge_gate_attestation"]["passed"]
        )
        self.assertTrue(
            readiness["stage1_checks"]["stage1b_dev_synthetic_probes"]["passed"]
        )

    def test_08_evaluate_readiness_rejects_unit_test_failures_or_errors(self) -> None:
        readiness_fail = evaluate_promotion_readiness(
            test_attestation={
                "tests_passed": False,
                "failures": 2,
                "errors": 0,
                "opsec_violations": 0,
                "tests_run": 240,
            }
        )
        self.assertFalse(readiness_fail["stage1_passed"])
        self.assertFalse(readiness_fail["ready_for_stage2_action_card"])
        self.assertGreaterEqual(len(readiness_fail["blocking_reasons"]), 1)

        readiness_err = evaluate_promotion_readiness(
            test_attestation={
                "tests_passed": True,
                "failures": 0,
                "errors": 1,
                "opsec_violations": 0,
                "tests_run": 240,
            }
        )
        self.assertFalse(readiness_err["stage1_passed"])
        self.assertTrue(
            any("errors must be 0" in r for r in readiness_err["blocking_reasons"])
        )

    def test_09_evaluate_readiness_rejects_nonzero_opsec_violations(self) -> None:
        readiness = evaluate_promotion_readiness(
            test_attestation={
                "tests_passed": True,
                "failures": 0,
                "errors": 0,
                "opsec_violations": 3,
                "tests_run": 250,
            }
        )
        self.assertFalse(readiness["stage1_passed"])
        self.assertFalse(readiness["ready_for_stage2_action_card"])
        self.assertTrue(
            any("opsec_violations must be 0" in r for r in readiness["blocking_reasons"])
        )

    def test_10_evaluate_readiness_rejects_insufficient_tests_run(self) -> None:
        readiness = evaluate_promotion_readiness(
            test_attestation={
                "tests_passed": True,
                "failures": 0,
                "errors": 0,
                "opsec_violations": 0,
                "tests_run": MIN_REQUIRED_TESTS_RUN - 1,
            }
        )
        self.assertFalse(readiness["stage1_passed"])
        self.assertTrue(
            any("tests_run must be >=" in r for r in readiness["blocking_reasons"])
        )

    def test_11_evaluate_readiness_rejects_failing_dev_synthetic_probes(self) -> None:
        for failing_probe in ("healthz", "readyz", "metrics", "mcp"):
            probes = {"healthz": 200, "readyz": 200, "metrics": 200, "mcp": 200}
            probes[failing_probe] = 503
            readiness = evaluate_promotion_readiness(dev_probes=probes)
            self.assertFalse(readiness["stage1_passed"])
            self.assertFalse(readiness["ready_for_stage2_action_card"])
            self.assertTrue(
                any(failing_probe in r for r in readiness["blocking_reasons"])
            )

    # ------------------------------------------------------------------
    # 3. Stage 2 Action Card Promotion Stager Tests
    # ------------------------------------------------------------------

    def test_12_stage_promotion_returns_409_and_never_stages_card_when_stage1_fails(
        self,
    ) -> None:
        status_code, resp = stage_gitops_prod_promotion(
            test_attestation={
                "tests_passed": False,
                "failures": 1,
                "errors": 0,
                "opsec_violations": 1,
                "tests_run": 210,
            }
        )
        self.assertEqual(status_code, 409)
        self.assertEqual(resp["error"], "Stage 1 promotion gates not satisfied")
        self.assertFalse(resp["readiness"]["stage1_passed"])

        # Verify zero Action Cards were staged in the ledger
        _, ledger_status = action_cards.get_action_status()
        self.assertEqual(ledger_status["total_cards"], 0)
        self.assertEqual(len(get_promotion_bridge_state()["staged_promotions"]), 0)

    def test_13_stage_promotion_returns_409_when_dev_probes_fail(self) -> None:
        status_code, resp = stage_gitops_prod_promotion(
            dev_probes={"healthz": 200, "readyz": 500, "metrics": 200, "mcp": 200}
        )
        self.assertEqual(status_code, 409)
        self.assertEqual(resp["error"], "Stage 1 promotion gates not satisfied")
        _, ledger_status = action_cards.get_action_status()
        self.assertEqual(ledger_status["total_cards"], 0)

    def test_14_stage_promotion_succeeds_and_creates_signed_action_card(self) -> None:
        status_code, resp = stage_gitops_prod_promotion(
            operator_id="release-engineer-01",
            source_branch="feat/opscryer-wave3-release",
            target_branch="main",
        )
        self.assertEqual(status_code, 200)
        self.assertIn("action_id", resp)
        self.assertTrue(resp["action_id"].startswith("act-"))
        self.assertEqual(resp["action_card"]["action_id"], resp["action_id"])
        self.assertEqual(resp["action_card"]["action_type"], "promote_to_prod")
        self.assertEqual(
            resp["action_card"]["target_node_id"], PROD_ACTION_TARGET_NODE_ID
        )
        self.assertEqual(resp["action_card"]["status"], "STAGED")

        # Confirm card exists in action_cards ledger
        ledger_code, card_in_ledger = action_cards.get_action_status(
            action_id=resp["action_id"]
        )
        self.assertEqual(ledger_code, 200)
        self.assertEqual(card_in_ledger["action_id"], resp["action_id"])

    def test_15_stage_promotion_enforces_k_of_n_threshold_lock_on_security_tier(
        self,
    ) -> None:
        status_code, resp = stage_gitops_prod_promotion()
        self.assertEqual(status_code, 200)
        worrisomeness = resp["worrisomeness"]
        self.assertTrue(worrisomeness["escalate_to_threshold"])
        self.assertEqual(worrisomeness["mode"], "threshold")
        self.assertGreaterEqual(worrisomeness["required_k"], 2)
        self.assertGreaterEqual(worrisomeness["required_n"], 3)
        self.assertIn(
            "CRITICAL_TIER_OR_LARGE_BLAST_RADIUS", worrisomeness["signals_triggered"]
        )

    def test_16_stage_promotion_enforces_gitops_plan_and_opsec_clean_compare_url(
        self,
    ) -> None:
        status_code, resp = stage_gitops_prod_promotion(
            operator_id="operator-lead",
            source_branch="feat/opscryer-wave3-release",
            target_branch="main",
        )
        self.assertEqual(status_code, 200)
        self.assertFalse(resp["direct_prod_apply_allowed"])
        self.assertFalse(resp["promotion_plan"]["direct_prod_apply_allowed"])
        self.assertEqual(resp["argo_app"], ARGO_PROD_APP_PATH)
        self.assertEqual(resp["prod_chart"], PROD_HELM_TEMPLATE_PATH)

        expected_url = (
            "https://gitlab.example.org/platform/infra-gitops/-/compare/"
            "main...feat/opscryer-wave3-release"
        )
        self.assertEqual(resp["compare_url"], expected_url)
        self.assertEqual(resp["promotion_plan"]["compare_url"], expected_url)
        parsed = urlsplit(resp["compare_url"])
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "gitlab.example.org")

    def test_17_stage_promotion_publishes_event_to_event_stream(self) -> None:
        status_code, resp = stage_gitops_prod_promotion()
        self.assertEqual(status_code, 200)
        events, _, _, _ = event_stream._DEFAULT_BUFFER.get_events_since(
            0, topics={"system"}, inclusive=True
        )
        matching = [
            e for e in events if e.get("event_type") == "gitops_promotion_staged"
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["data"]["action_id"], resp["action_id"])

    # ------------------------------------------------------------------
    # 4. HTTP API Dispatcher Tests
    # ------------------------------------------------------------------

    def test_18_http_api_get_status_returns_200_with_dual_environment_posture(
        self,
    ) -> None:
        code, body = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/status", method="GET"
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["schema_version"], SCHEMA_VERSION)
        self.assertIn("drift", body)
        self.assertIn("readiness", body)
        self.assertIn("staged_promotions", body)
        self.assertIn("dual_environment_posture", body)
        self.assertEqual(
            body["dual_environment_posture"]["dev-envs"]["deployment"],
            "opscryer-suite-dev",
        )
        self.assertEqual(
            body["dual_environment_posture"]["security"]["deployment"],
            "opscryer-prod",
        )
        self.assertFalse(
            body["dual_environment_posture"]["security"]["direct_prod_apply_allowed"]
        )

    def test_19_http_api_post_stage_success_and_409_rejection(self) -> None:
        # 1. Successful stage via POST JSON string
        payload = json.dumps(
            {
                "operator_id": "operator-alpha",
                "source_branch": "feat/wave3-m11",
                "target_branch": "main",
            }
        )
        code_ok, resp_ok = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/stage", method="POST", body=payload
        )
        self.assertEqual(code_ok, 200)
        self.assertTrue(resp_ok["action_id"].startswith("act-"))
        self.assertIn("main...feat/wave3-m11", resp_ok["compare_url"])

        # Verify GET status reflects the newly staged promotion
        code_st, resp_st = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/status", method="GET"
        )
        self.assertEqual(code_st, 200)
        self.assertEqual(resp_st["staged_count"], 1)

        # 2. Rejected stage via POST when probes fail
        code_409, resp_409 = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/stage",
            method="POST",
            body={"dev_probes": {"mcp": 502}},
        )
        self.assertEqual(code_409, 409)
        self.assertFalse(resp_409["readiness"]["stage1_passed"])

    def test_20_http_api_405_404_and_400_edge_cases(self) -> None:
        # Invalid method on /status
        code_405_a, _ = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/status", method="POST"
        )
        self.assertEqual(code_405_a, 405)

        # Invalid method on /stage
        code_405_b, _ = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/stage", method="GET"
        )
        self.assertEqual(code_405_b, 405)

        # Unknown sub-route
        code_404, _ = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/unknown", method="GET"
        )
        self.assertEqual(code_404, 404)

        # Malformed JSON body
        code_400_json, _ = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/stage", method="POST", body="{bad json"
        )
        self.assertEqual(code_400_json, 400)

        # Invalid branch traversal attempt
        code_400_branch, _ = handle_gitops_promotion_api(
            "/api/v1/gitops-promotion/stage",
            method="POST",
            body={"source_branch": "feat/../exploit", "target_branch": "main"},
        )
        self.assertEqual(code_400_branch, 400)


if __name__ == "__main__":
    unittest.main()
