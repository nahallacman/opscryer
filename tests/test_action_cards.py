# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit and behavioral tests for action_cards.py."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import time
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from action_cards import (
    canonical_parameter_hash,
    preview_action_dry_run,
    evaluate_outcome_worrisomeness,
    ActionCardLedger,
    stage_action_card,
    approve_action_card,
    reject_action_card,
    get_action_status,
    reset_action_ledger,
    handle_action_api,
    PERMITTED_ACTION_TYPES,
)
from pqc_security import (
    split_secret_shares,
    generate_pqc_keypair,
    pqc_sign,
)


class TestCanonicalParameterHash(unittest.TestCase):
    """Test deterministic canonical parameter hashing."""

    def test_empty_dict_hash_matches_known_digest(self):
        # Empty dict canonical representation is "{}"
        expected = hashlib.sha256(b"{}").hexdigest()
        self.assertEqual(canonical_parameter_hash({}), expected)
        self.assertEqual(expected, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")

    def test_key_ordering_invariance(self):
        params1 = {"replicas": 0, "force": True, "grace_period": 30}
        params2 = {"force": True, "grace_period": 30, "replicas": 0}
        self.assertEqual(canonical_parameter_hash(params1), canonical_parameter_hash(params2))

    def test_nested_key_ordering_invariance(self):
        params1 = {"spec": {"b": 2, "a": 1}, "name": "workload"}
        params2 = {"name": "workload", "spec": {"a": 1, "b": 2}}
        self.assertEqual(canonical_parameter_hash(params1), canonical_parameter_hash(params2))

    def test_non_dict_raises_type_error(self):
        with self.assertRaises(TypeError):
            canonical_parameter_hash(["not", "a", "dict"])
        with self.assertRaises(TypeError):
            canonical_parameter_hash("string")


class TestDryRunBlastRadius(unittest.TestCase):
    """Test dry-run simulation across all 5 action types and graph fixtures."""

    def setUp(self):
        self.custom_catalog = {
            "schema_version": "1.0-separable-spatial-graph-contract",
            "nodes": [
                {"id": "node-ctrl-01", "label": "Control Node", "kind": "Node", "namespace": "kube-system", "tier": "control-plane"},
                {"id": "node-worker-01", "label": "Worker Node 1", "kind": "Node", "namespace": "default", "tier": "worker"},
                {"id": "pod-db", "label": "Database Pod", "kind": "Pod", "namespace": "storage-system", "tier": "storage"},
                {"id": "pod-api", "label": "API Gateway Pod", "kind": "Pod", "namespace": "ingress-nginx"},
                {"id": "pod-app", "label": "Application Pod", "kind": "Pod", "namespace": "default"},
            ],
            "edges": [
                {"source": "pod-db", "target": "node-ctrl-01", "relation": "runs_on_hardware"},
                {"source": "pod-api", "target": "node-ctrl-01", "relation": "runs_on_hardware"},
                {"source": "pod-app", "target": "node-worker-01", "relation": "runs_on_hardware"},
                {"source": "pod-api", "target": "pod-app", "relation": "routes_to"},
                {"source": "pod-app", "target": "pod-db", "relation": "routes_to"},
            ],
        }

    def test_restart_node_impact(self):
        preview = preview_action_dry_run(
            "restart_node", "node-ctrl-01", {"grace_period": 10}, catalog=self.custom_catalog
        )
        self.assertEqual(preview["status"], "DRY_RUN_COMPLETED")
        self.assertIn("node-ctrl-01", preview["impacted_nodes"])
        self.assertIn("pod-db", preview["impacted_nodes"])
        self.assertIn("pod-api", preview["impacted_nodes"])
        self.assertTrue(preview["critical_tier_impacted"])
        self.assertTrue(preview["cascading_risk"])

    def test_isolate_workload_impact(self):
        preview = preview_action_dry_run(
            "isolate_workload", "pod-app", {"network_policy": "quarantine"}, catalog=self.custom_catalog
        )
        self.assertEqual(preview["status"], "DRY_RUN_COMPLETED")
        self.assertIn("pod-app", preview["impacted_nodes"])
        # Caller pod-api and downstream pod-db should be traversed
        self.assertIn("pod-api", preview["impacted_nodes"])
        self.assertIn("pod-db", preview["impacted_nodes"])

    def test_scale_deployment_impact(self):
        # Scale to 0 predicts SLO breach
        preview_zero = preview_action_dry_run(
            "scale_deployment", "pod-app", {"replicas": 0}, catalog=self.custom_catalog
        )
        self.assertTrue(preview_zero["slo_breach_predicted"])

        # Scale to 2 replicas normal
        preview_up = preview_action_dry_run(
            "scale_deployment", "pod-app", {"replicas": 2}, catalog=self.custom_catalog
        )
        self.assertFalse(preview_up["slo_breach_predicted"])

    def test_scale_deployment_negative_replicas_raises_value_error(self):
        with self.assertRaises(ValueError):
            preview_action_dry_run("scale_deployment", "pod-app", {"replicas": -3}, catalog=self.custom_catalog)

    def test_drain_traffic_impact(self):
        preview = preview_action_dry_run(
            "drain_traffic", "node-worker-01", catalog=self.custom_catalog
        )
        self.assertEqual(preview["status"], "DRY_RUN_COMPLETED")
        self.assertIn("node-worker-01", preview["impacted_nodes"])
        self.assertIn("pod-app", preview["impacted_nodes"])

    def test_revoke_lease_impact(self):
        preview = preview_action_dry_run(
            "revoke_lease", "node-ctrl-01", {"lease_id": "lease-master-1"}, catalog=self.custom_catalog
        )
        self.assertEqual(preview["status"], "DRY_RUN_COMPLETED")
        self.assertIn("node-ctrl-01", preview["impacted_nodes"])

    def test_target_node_not_found_raises_key_error(self):
        with self.assertRaises(KeyError):
            preview_action_dry_run("restart_node", "node-ghost-404", catalog=self.custom_catalog)

    def test_unsupported_action_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            preview_action_dry_run("format_hard_drive", "node-worker-01", catalog=self.custom_catalog)


class TestOutcomeWorrisomenessPredictor(unittest.TestCase):
    """Test 4-signal composite outcome predictor and threshold escalation."""

    def test_zero_signals_benign_action_defaults_to_single_master_key(self):
        preview = {
            "impacted_node_count": 1,
            "critical_tier_impacted": False,
            "cascading_risk": False,
            "slo_breach_predicted": False,
            "impacted_nodes": ["node-leaf-01"],
        }
        res = evaluate_outcome_worrisomeness(preview, "node-leaf-01")
        self.assertFalse(res["escalate_to_threshold"])
        self.assertEqual(res["mode"], "single")
        self.assertEqual(res["required_k"], 1)
        self.assertEqual(res["required_n"], 1)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(len(res["signals_triggered"]), 0)

    def test_signal_1_critical_tier_escalates_to_threshold(self):
        preview = {
            "impacted_node_count": 1,
            "critical_tier_impacted": True,
            "cascading_risk": False,
            "slo_breach_predicted": False,
            "impacted_nodes": ["node-ctrl-01"],
        }
        res = evaluate_outcome_worrisomeness(preview, "node-ctrl-01")
        self.assertTrue(res["escalate_to_threshold"])
        self.assertEqual(res["mode"], "threshold")
        self.assertEqual(res["required_k"], 2)
        self.assertEqual(res["required_n"], 3)
        self.assertIn("CRITICAL_TIER_OR_LARGE_BLAST_RADIUS", res["signals_triggered"])

    def test_signal_1_large_blast_radius_escalates_to_threshold(self):
        preview = {
            "impacted_node_count": 5,  # > K=3
            "critical_tier_impacted": False,
            "cascading_risk": False,
            "slo_breach_predicted": False,
            "impacted_nodes": ["n1", "n2", "n3", "n4", "n5"],
        }
        res = evaluate_outcome_worrisomeness(preview, "n1", K=3)
        self.assertTrue(res["escalate_to_threshold"])
        self.assertEqual(res["required_k"], 2)

    def test_signal_2_cascading_or_slo_breach_escalates(self):
        preview = {
            "impacted_node_count": 2,
            "critical_tier_impacted": False,
            "cascading_risk": True,
            "slo_breach_predicted": False,
            "impacted_nodes": ["n1", "n2"],
        }
        res = evaluate_outcome_worrisomeness(preview, "n1")
        self.assertTrue(res["escalate_to_threshold"])
        self.assertIn("CASCADING_DISRUPTION_OR_SLO_BREACH", res["signals_triggered"])

    def test_signal_3_active_security_alert_escalates(self):
        preview = {
            "impacted_node_count": 1,
            "critical_tier_impacted": False,
            "cascading_risk": False,
            "slo_breach_predicted": False,
            "impacted_nodes": ["pod-target"],
        }
        alerts = [
            {"target_node_id": "pod-target", "rule_id": "sigma-proc-injection", "severity": "high"}
        ]
        res = evaluate_outcome_worrisomeness(preview, "pod-target", active_alerts=alerts)
        self.assertTrue(res["escalate_to_threshold"])
        self.assertIn("ACTIVE_SECURITY_ALERT", res["signals_triggered"])

    def test_signal_4_mutation_velocity_escalates(self):
        preview = {
            "impacted_node_count": 1,
            "critical_tier_impacted": False,
            "cascading_risk": False,
            "slo_breach_predicted": False,
            "impacted_nodes": ["node-1"],
        }
        now = time.time()
        # 6 mutations in last 30s (> 5 threshold)
        history = [{"timestamp": now - 10, "target": "node-1"} for _ in range(6)]
        res = evaluate_outcome_worrisomeness(preview, "node-1", mutation_history=history)
        self.assertTrue(res["escalate_to_threshold"])
        self.assertIn("ANOMALOUS_MUTATION_VELOCITY_OR_DRIFT", res["signals_triggered"])

    def test_multi_signal_escalates_to_critical_3_of_5(self):
        preview = {
            "impacted_node_count": 6,  # Signal 1
            "critical_tier_impacted": True,
            "cascading_risk": True,  # Signal 2
            "slo_breach_predicted": True,
            "impacted_nodes": ["n1", "n2", "n3", "n4", "n5", "n6"],
        }
        alerts = [{"target_node_id": "n1", "rule": "cve-exploit"}]  # Signal 3
        now = time.time()
        history = [{"timestamp": now - 5, "target": "n1"} for _ in range(7)]  # Signal 4

        res = evaluate_outcome_worrisomeness(
            preview, "n1", active_alerts=alerts, mutation_history=history
        )
        self.assertTrue(res["escalate_to_threshold"])
        self.assertEqual(res["mode"], "threshold")
        self.assertEqual(res["required_k"], 3)
        self.assertEqual(res["required_n"], 5)
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertEqual(len(res["signals_triggered"]), 4)


class TestActionCardLedger(unittest.TestCase):
    """Test ActionCardLedger thread safety, lifecycle, idempotency, and anti-tamper."""

    def setUp(self):
        self.ledger = ActionCardLedger()

    def test_stage_and_single_master_key_approve_execute(self):
        card = self.ledger.stage_card(
            "nodegamma03", "scale_deployment", {"replicas": 3}, ttl_seconds=3600.0
        )
        self.assertEqual(card["status"], "STAGED")
        aid = card["action_id"]

        status_code, resp = self.ledger.approve_card(
            aid, parameters_sha256=card["parameters_sha256"]
        )
        self.assertEqual(status_code, 200)
        self.assertEqual(resp["status"], "EXECUTED")
        self.assertFalse(resp["cached"])
        self.assertIsNotNone(resp["execution_result"])

    def test_idempotent_replay_within_ttl(self):
        card = self.ledger.stage_card("nodegamma03", "scale_deployment", {"replicas": 3})
        aid = card["action_id"]

        # First execution
        code1, resp1 = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"])
        self.assertEqual(code1, 200)
        self.assertFalse(resp1["cached"])

        # Second submission (replay) within TTL
        code2, resp2 = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"])
        self.assertEqual(code2, 200)
        self.assertTrue(resp2["cached"])
        self.assertEqual(resp2["execution_result"], resp1["execution_result"])

    def test_tamper_detection_fails_closed_with_409(self):
        card = self.ledger.stage_card("nodegamma03", "scale_deployment", {"replicas": 2})
        aid = card["action_id"]

        # Submit tampered hash corresponding to {"replicas": 0}
        tampered_hash = canonical_parameter_hash({"replicas": 0})
        code, resp = self.ledger.approve_card(aid, parameters_sha256=tampered_hash)
        self.assertEqual(code, 409)
        self.assertEqual(resp["code"], "TAMPER_DETECTED")

    def test_ttl_expiration_fails_closed_with_409(self):
        # Stage card with 0.05s TTL
        card = self.ledger.stage_card("nodegamma03", "scale_deployment", {"replicas": 2}, ttl_seconds=0.05)
        aid = card["action_id"]

        time.sleep(0.08)
        code, resp = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"])
        self.assertEqual(code, 409)
        self.assertEqual(resp["code"], "ACTION_CARD_EXPIRED")

    def test_rejection_lifecycle(self):
        card = self.ledger.stage_card("nodegamma03", "restart_node")
        aid = card["action_id"]

        code, resp = self.ledger.reject_card(aid, reason="Operator maintenance window cancelled")
        self.assertEqual(code, 200)
        self.assertEqual(resp["status"], "REJECTED")

        # Approving rejected card fails with 409
        app_code, app_resp = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"])
        self.assertEqual(app_code, 409)
        self.assertEqual(app_resp["code"], "ACTION_CARD_REJECTED")

    def test_cannot_reject_executed_card(self):
        card = self.ledger.stage_card("nodegamma03", "scale_deployment", {"replicas": 1})
        aid = card["action_id"]
        self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"])

        code, resp = self.ledger.reject_card(aid, reason="Too late")
        self.assertEqual(code, 409)
        self.assertEqual(resp["code"], "CANNOT_REJECT_EXECUTED_ACTION")

    def test_threshold_share_aggregation_and_deduplication(self):
        # Stage a critical card on nodebeta02 (control plane triggers Signal 1 -> 2-of-3 threshold)
        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]
        self.assertEqual(card["worrisomeness"]["mode"], "threshold")
        self.assertEqual(card["worrisomeness"]["required_k"], 2)

        # Keyholder 1 submits share
        c1 = {"key_id": "auditor-alpha", "data": "share1"}
        code1, resp1 = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"], credential=c1)
        self.assertEqual(code1, 200)
        self.assertEqual(resp1["status"], "STAGED")
        self.assertEqual(resp1["shares_collected"], 1)

        # Keyholder 1 submits duplicate share -> deduplicated
        code1_dup, resp1_dup = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"], credential=c1)
        self.assertEqual(code1_dup, 200)
        self.assertEqual(resp1_dup["shares_collected"], 1)

        # Keyholder 2 submits distinct share -> reaches threshold k=2
        c2 = {"key_id": "auditor-beta", "data": "share2"}
        code2, resp2 = self.ledger.approve_card(aid, parameters_sha256=card["parameters_sha256"], credential=c2)
        self.assertEqual(code2, 200)
        self.assertEqual(resp2["status"], "EXECUTED")
        self.assertEqual(resp2["shares_collected"], 2)
        self.assertIsNotNone(resp2["execution_result"])


class TestActionCardRESTAPI(unittest.TestCase):
    """Test handle_action_api dispatching and HTTP status code contract."""

    def setUp(self):
        reset_action_ledger()

    def test_dry_run_endpoint_get_descriptor(self):
        code, resp = handle_action_api("/api/v1/actions/dry-run", "GET", {})
        self.assertEqual(code, 200)
        self.assertEqual(resp["supported_methods"], ["POST"])

    def test_dry_run_endpoint_post(self):
        body = {
            "action_type": "restart_node",
            "target_node_id": "nodegamma03",
            "parameters": {"grace_period": 15},
        }
        code, resp = handle_action_api("/api/v1/actions/dry-run", "POST", {}, body=body)
        self.assertEqual(code, 200)
        self.assertEqual(resp["status"], "DRY_RUN_COMPLETED")
        self.assertIn("action_preview", resp)
        self.assertIn("worrisomeness", resp)

    def test_dry_run_missing_fields_returns_400(self):
        code, resp = handle_action_api("/api/v1/actions/dry-run", "POST", {}, body={"action_type": "restart_node"})
        self.assertEqual(code, 400)
        self.assertEqual(resp["code"], "MISSING_REQUIRED_FIELD")

    def test_stage_and_status_endpoints(self):
        body = {
            "action_type": "scale_deployment",
            "target_node_id": "nodegamma03",
            "parameters": {"replicas": 4},
        }
        code, card = handle_action_api("/api/v1/actions/stage", "POST", {}, body=body)
        self.assertEqual(code, 200)
        aid = card["action_id"]

        # GET status by ID
        code_st, resp_st = handle_action_api("/api/v1/actions/status", "GET", {"action_id": aid})
        self.assertEqual(code_st, 200)
        self.assertEqual(resp_st["action_id"], aid)

        # GET status listing
        code_list, resp_list = handle_action_api("/api/v1/actions/status", "GET", {})
        self.assertEqual(code_list, 200)
        self.assertGreaterEqual(resp_list["total_cards"], 1)

    def test_approve_and_reject_rest_endpoints(self):
        # Stage card
        _, card = handle_action_api(
            "/api/v1/actions/stage", "POST", {},
            body={"action_type": "scale_deployment", "target_node_id": "nodegamma03", "parameters": {"replicas": 2}}
        )
        aid = card["action_id"]

        # Approve
        code_app, resp_app = handle_action_api(
            "/api/v1/actions/approve", "POST", {},
            body={"action_id": aid, "parameters_sha256": card["parameters_sha256"]}
        )
        self.assertEqual(code_app, 200)
        self.assertEqual(resp_app["status"], "EXECUTED")

        # Reject executed card returns 409
        code_rej, resp_rej = handle_action_api(
            "/api/v1/actions/reject", "POST", {},
            body={"action_id": aid, "reason": "Too late"}
        )
        self.assertEqual(code_rej, 409)


class TestThresholdValidationAndStatusFiltering(unittest.TestCase):
    """Rigorous regression tests for threshold approval validation and status query filtering."""

    def setUp(self):
        reset_action_ledger()
        self.ledger = ActionCardLedger()

    def test_approve_threshold_empty_credential_rejected_with_400(self):
        # Stage card on control plane node -> escalates to 2-of-3 threshold
        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]
        self.assertEqual(card["worrisomeness"]["mode"], "threshold")

        # 1. Empty dict credential
        code1, resp1 = self.ledger.approve_card(aid, credential={})
        self.assertEqual(code1, 400)
        self.assertEqual(resp1["code"], "INVALID_CREDENTIALS")

        # 2. None credential
        code2, resp2 = self.ledger.approve_card(aid, credential=None)
        self.assertEqual(code2, 400)
        self.assertEqual(resp2["code"], "INVALID_CREDENTIALS")

        # Verify card remains STAGED and not executed
        _, status_resp = self.ledger.get_card_status(aid)
        self.assertEqual(status_resp["status"], "STAGED")

    def test_approve_threshold_malformed_credential_rejected_with_400(self):
        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]

        # Malformed: arbitrary dict without x/data or signature/public_key
        code, resp = self.ledger.approve_card(aid, credential={"random_key": "arbitrary_val"})
        self.assertEqual(code, 400)
        self.assertEqual(resp["code"], "INVALID_CREDENTIALS")

    def test_approve_threshold_invalid_shamir_share_format_rejected_with_403(self):
        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]

        # Out-of-bounds x coordinate
        code_zero, resp_zero = self.ledger.approve_card(aid, credential={"x": 0, "data": "deadbeef"})
        self.assertEqual(code_zero, 403)
        self.assertEqual(resp_zero["code"], "INVALID_SHAMIR_SHARE")

        code_large, resp_large = self.ledger.approve_card(aid, credential={"x": 256, "data": "deadbeef"})
        self.assertEqual(code_large, 403)
        self.assertEqual(resp_large["code"], "INVALID_SHAMIR_SHARE")

        # Non-hex data
        code_hex, resp_hex = self.ledger.approve_card(aid, credential={"x": 1, "data": "not_valid_hex_!@#"})
        self.assertEqual(code_hex, 403)
        self.assertEqual(resp_hex["code"], "INVALID_SHAMIR_SHARE")

    def test_approve_threshold_tampered_shamir_shares_fails_closed_with_403(self):
        secret = b"CriticalRebootAuthorization2026"
        shares = split_secret_shares(secret, k=2, n=3)

        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]

        # Submit valid share 1
        code1, resp1 = self.ledger.approve_card(aid, credential=shares[0])
        self.assertEqual(code1, 200)
        self.assertEqual(resp1["status"], "STAGED")
        self.assertEqual(resp1["shares_collected"], 1)

        # Corrupt share 2 by inverting byte data
        corrupt_share = copy.deepcopy(shares[1])
        corrupt_bytes = bytearray(bytes.fromhex(corrupt_share["data"]))
        corrupt_bytes[0] ^= 0xFF
        corrupt_share["data"] = bytes(corrupt_bytes).hex()

        # Submit tampered share 2 -> reconstruction fails
        code2, resp2 = self.ledger.approve_card(aid, credential=corrupt_share)
        self.assertEqual(code2, 403)
        self.assertEqual(resp2["code"], "INVALID_SHAMIR_SHARE")

        # Ledger state remains STAGED
        _, status_resp = self.ledger.get_card_status(aid)
        self.assertEqual(status_resp["status"], "STAGED")

    def test_approve_threshold_valid_shamir_shares_execute_card(self):
        secret = b"ValidAuthorizationThresholdKey2026"
        shares = split_secret_shares(secret, k=2, n=3)

        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]

        # Share 1
        c1, r1 = self.ledger.approve_card(aid, credential=shares[0])
        self.assertEqual(c1, 200)
        self.assertEqual(r1["status"], "STAGED")

        # Duplicate Share 1 deduplicated
        c1_dup, r1_dup = self.ledger.approve_card(aid, credential=shares[0])
        self.assertEqual(c1_dup, 200)
        self.assertEqual(r1_dup["shares_collected"], 1)

        # Share 2 -> Reaches threshold k=2 and executes
        c2, r2 = self.ledger.approve_card(aid, credential=shares[1])
        self.assertEqual(c2, 200)
        self.assertEqual(r2["status"], "EXECUTED")
        self.assertFalse(r2["cached"])
        self.assertIsNotNone(r2["execution_result"])

    def test_approve_threshold_unauthorized_signer_rejected_with_403(self):
        pub1, priv1 = generate_pqc_keypair(tree_height=2)
        pub_rogue, priv_rogue = generate_pqc_keypair(tree_height=2)

        card = self.ledger.stage_card("nodebeta02", "restart_node")
        aid = card["action_id"]
        # Set authorized keys on the card
        card_obj = self.ledger._cards[aid]
        card_obj["worrisomeness"]["authorized_keys"] = [pub1["root"]]

        payload = aid.encode("utf-8")
        sig_rogue = pqc_sign(payload, priv_rogue)
        cred_rogue = {"signature": sig_rogue, "public_key": pub_rogue}

        code, resp = self.ledger.approve_card(aid, credential=cred_rogue)
        self.assertEqual(code, 403)
        self.assertEqual(resp["code"], "UNAUTHORIZED_KEY")

    def test_handle_action_api_status_filter_executed_returns_zero_for_staged(self):
        # Stage two cards
        stage_action_card("nodealpha01", "restart_node")
        stage_action_card("nodealpha01", "restart_node")

        # Filter by EXECUTED (should be 0)
        code, resp = handle_action_api("/api/v1/actions/status", "GET", {"status_filter": ["EXECUTED"]})
        self.assertEqual(code, 200)
        self.assertEqual(resp["total_cards"], 0)
        self.assertEqual(len(resp["cards"]), 0)

        # Filter by STAGED (should be 2)
        code_s, resp_s = handle_action_api("/api/v1/actions/status", "GET", {"status_filter": "STAGED"})
        self.assertEqual(code_s, 200)
        self.assertEqual(resp_s["total_cards"], 2)

    def test_handle_action_api_status_filter_invalid_value_returns_400(self):
        code, resp = handle_action_api("/api/v1/actions/status", "GET", {"status_filter": ["NON_EXISTENT_STATE"]})
        self.assertEqual(code, 400)
        self.assertEqual(resp["code"], "INVALID_PARAMETER_VALUE")

    def test_handle_action_api_limit_parameter_bounds(self):
        for _ in range(5):
            stage_action_card("nodealpha01", "restart_node")

        # Valid limit = 2
        code, resp = handle_action_api("/api/v1/actions/status", "GET", {"limit": ["2"]})
        self.assertEqual(code, 200)
        self.assertEqual(resp["total_cards"], 5)
        self.assertEqual(len(resp["cards"]), 2)

        # Invalid limit = 0
        code_zero, resp_zero = handle_action_api("/api/v1/actions/status", "GET", {"limit": ["0"]})
        self.assertEqual(code_zero, 400)
        self.assertEqual(resp_zero["code"], "INVALID_PARAMETER_VALUE")

        # Invalid limit = -1
        code_neg, resp_neg = handle_action_api("/api/v1/actions/status", "GET", {"limit": ["-1"]})
        self.assertEqual(code_neg, 400)
        self.assertEqual(resp_neg["code"], "INVALID_PARAMETER_VALUE")

        # Invalid limit = non-int
        code_str, resp_str = handle_action_api("/api/v1/actions/status", "GET", {"limit": ["abc"]})
        self.assertEqual(code_str, 400)
        self.assertEqual(resp_str["code"], "INVALID_PARAMETER_VALUE")


if __name__ == "__main__":
    unittest.main()
