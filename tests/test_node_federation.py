# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for Multipurpose Node Federation, 3-Regime Governance & Severance Doctrines."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from node_federation import (
    DEFAULT_FEDERATION_DOMAINS,
    ActiveMastersRegistry,
    GovernanceRegimeEngine,
    GovernanceRegimeId,
    MasterLease,
    SeveranceState,
    TRUST_TIER_CAPTAIN_ELIGIBLE,
    TRUST_TIER_ROOT_AUTHORITY,
    TRUST_TIER_SENATOR_ELIGIBLE,
    TRUST_TIER_WORKER_ONLY,
    VectorClock,
    compute_canary_expected_digest,
    compute_governance_regime,
    create_persist_resist_regrow_warrant,
    deterministic_vector_clock_compare,
    evaluate_canary_peer_quorum,
    evaluate_severance_state,
    execute_encrypt_and_rest,
    execute_master_unseal,
    generate_canary_challenge,
    handle_federation_api,
    hard_wipe_file,
    issue_trust_tier_certificate,
    reconcile_reconnected_contingent,
    solve_canary_challenge,
    validate_directive_against_manifest,
    verify_canary_proof,
    verify_persist_resist_regrow_warrant,
    verify_trust_tier_certificate,
    zeroize_bytearray,
    zeroize_dict_secrets,
)
from pqc_security import generate_pqc_keypair


class VectorClockTests(unittest.TestCase):
    """Test pure-stdlib Vector Clock causal ordering and concurrency."""

    def test_init_and_validation(self):
        vc = VectorClock()
        self.assertEqual(vc.to_dict(), {})
        self.assertEqual(vc.get("node-a"), 0)

        vc_init = VectorClock({"node-a": 2, "node-b": 5})
        self.assertEqual(vc_init.get("node-a"), 2)
        self.assertEqual(vc_init.get("node-b"), 5)

        with self.assertRaises(TypeError):
            VectorClock("invalid")  # type: ignore

        with self.assertRaises(ValueError):
            VectorClock({"node-a": -1})

        with self.assertRaises(ValueError):
            vc.increment("")

    def test_increment_and_copy(self):
        vc = VectorClock()
        self.assertEqual(vc.increment("node-1"), 1)
        self.assertEqual(vc.increment("node-1"), 2)
        self.assertEqual(vc.increment("node-2"), 1)

        copy_vc = vc.copy()
        self.assertTrue(vc.is_equal(copy_vc))
        copy_vc.increment("node-1")
        self.assertFalse(vc.is_equal(copy_vc))
        self.assertTrue(copy_vc.is_causally_newer(vc))

    def test_causal_dominance_and_concurrency(self):
        vc1 = VectorClock({"a": 2, "b": 3})
        vc2 = VectorClock({"a": 2, "b": 2})
        vc3 = VectorClock({"a": 3, "b": 2})

        self.assertTrue(vc1.is_causally_newer(vc2))
        self.assertFalse(vc2.is_causally_newer(vc1))
        self.assertFalse(vc1.is_concurrent(vc2))

        # vc1 {"a": 2, "b": 3} vs vc3 {"a": 3, "b": 2} -> Concurrent!
        self.assertTrue(vc1.is_concurrent(vc3))
        self.assertTrue(vc3.is_concurrent(vc1))
        self.assertFalse(vc1.is_causally_newer(vc3))
        self.assertFalse(vc3.is_causally_newer(vc1))

    def test_merge_component_wise_max(self):
        vc1 = VectorClock({"a": 2, "b": 5, "c": 1})
        vc2 = VectorClock({"a": 4, "b": 3, "d": 7})
        vc1.merge(vc2)
        self.assertEqual(vc1.to_dict(), {"a": 4, "b": 5, "c": 1, "d": 7})

    def test_concurrent_thread_increments(self):
        vc = VectorClock()
        num_threads = 8
        increments_per_thread = 50

        def worker(node_id: str):
            for _ in range(increments_per_thread):
                vc.increment(node_id)

        threads = [
            threading.Thread(target=worker, args=(f"node-{i % 2}",))
            for i in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected_total = num_threads * increments_per_thread
        actual_total = vc.get("node-0") + vc.get("node-1")
        self.assertEqual(actual_total, expected_total)

    def test_deterministic_tie_breaker(self):
        v1 = VectorClock({"a": 2, "b": 3})  # sum = 5
        v2 = VectorClock({"a": 1, "b": 5})  # sum = 6
        self.assertEqual(deterministic_vector_clock_compare(v1, v2), -1)
        self.assertEqual(deterministic_vector_clock_compare(v2, v1), 1)

        # Equal sums: deterministic hash tie-break
        v3 = VectorClock({"a": 2, "b": 3})
        v4 = VectorClock({"a": 3, "b": 2})
        comp = deterministic_vector_clock_compare(v3, v4)
        self.assertIn(comp, (-1, 1))
        self.assertEqual(deterministic_vector_clock_compare(v4, v3), -comp)


class TrustTierCertificatesTests(unittest.TestCase):
    """Test root-attested Trust Tier Certificates and cryptographic anti-poisoning."""

    @classmethod
    def setUpClass(cls):
        cls.root_pub, cls.root_priv = generate_pqc_keypair(tree_height=4)
        cls.node_pub, cls.node_priv = generate_pqc_keypair(tree_height=4)

    def test_issue_and_verify_valid_certificate(self):
        cert = issue_trust_tier_certificate(
            node_id="opscryer-captain-01",
            tier=TRUST_TIER_CAPTAIN_ELIGIBLE,
            permitted_domains=["k8s-infra", "observability"],
            node_pubkey=self.node_pub,
            root_privkey=self.root_priv,
            ttl_seconds=3600.0,
        )
        self.assertTrue(verify_trust_tier_certificate(cert, self.root_pub))
        self.assertEqual(cert["node_id"], "opscryer-captain-01")
        self.assertEqual(cert["tier"], TRUST_TIER_CAPTAIN_ELIGIBLE)

    def test_expired_certificate_rejected(self):
        t0 = 1000.0
        cert = issue_trust_tier_certificate(
            node_id="node-expired",
            tier=TRUST_TIER_WORKER_ONLY,
            permitted_domains=["k8s-infra"],
            node_pubkey=self.node_pub,
            root_privkey=self.root_priv,
            ttl_seconds=10.0,
            current_time=t0,
        )
        self.assertTrue(verify_trust_tier_certificate(cert, self.root_pub, current_time=t0 + 5.0))
        self.assertFalse(verify_trust_tier_certificate(cert, self.root_pub, current_time=t0 + 15.0))

    def test_tampered_certificate_rejected(self):
        cert = issue_trust_tier_certificate(
            node_id="worker-01",
            tier=TRUST_TIER_WORKER_ONLY,
            permitted_domains=["k8s-infra"],
            node_pubkey=self.node_pub,
            root_privkey=self.root_priv,
        )
        tampered = dict(cert)
        tampered["tier"] = TRUST_TIER_CAPTAIN_ELIGIBLE  # Privilege escalation attack!
        self.assertFalse(verify_trust_tier_certificate(tampered, self.root_pub))

    def test_wrong_root_key_rejected(self):
        cert = issue_trust_tier_certificate(
            node_id="worker-01",
            tier=TRUST_TIER_SENATOR_ELIGIBLE,
            permitted_domains=["k8s-infra"],
            node_pubkey=self.node_pub,
            root_privkey=self.root_priv,
        )
        attacker_pub, _ = generate_pqc_keypair(tree_height=4)
        self.assertFalse(verify_trust_tier_certificate(cert, attacker_pub))


class ActiveMastersRegistryTests(unittest.TestCase):
    """Test domain-scoped multi-master sharding and fencing tokens."""

    @classmethod
    def setUpClass(cls):
        cls.root_pub, cls.root_priv = generate_pqc_keypair(tree_height=4)
        cls.captain_pub, cls.captain_priv = generate_pqc_keypair(tree_height=4)
        cls.worker_pub, cls.worker_priv = generate_pqc_keypair(tree_height=4)

        cls.captain_cert = issue_trust_tier_certificate(
            node_id="captain-01",
            tier=TRUST_TIER_CAPTAIN_ELIGIBLE,
            permitted_domains=["k8s-infra", "security"],
            node_pubkey=cls.captain_pub,
            root_privkey=cls.root_priv,
        )
        cls.worker_cert = issue_trust_tier_certificate(
            node_id="worker-01",
            tier=TRUST_TIER_WORKER_ONLY,
            permitted_domains=["k8s-infra"],
            node_pubkey=cls.worker_pub,
            root_privkey=cls.root_priv,
        )

    def test_acquire_valid_lease(self):
        registry = ActiveMastersRegistry(self.root_pub)
        clock = VectorClock({"captain-01": 1})
        ok, lease, msg = registry.acquire_lease("k8s-infra", "captain-01", self.captain_cert, clock)
        self.assertTrue(ok)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.master_node_id, "captain-01")
        self.assertTrue(registry.validate_fencing_token("k8s-infra", lease.fencing_token))

    def test_reject_worker_only_cert(self):
        registry = ActiveMastersRegistry(self.root_pub)
        clock = VectorClock({"worker-01": 1})
        ok, lease, msg = registry.acquire_lease("k8s-infra", "worker-01", self.worker_cert, clock)
        self.assertFalse(ok)
        self.assertIn("not eligible", msg)

    def test_reject_unauthorized_domain(self):
        registry = ActiveMastersRegistry(self.root_pub)
        clock = VectorClock({"captain-01": 1})
        # captain_cert only permits k8s-infra and security
        ok, lease, msg = registry.acquire_lease("database", "captain-01", self.captain_cert, clock)
        self.assertFalse(ok)
        self.assertIn("does not permit domain", msg)

    def test_lease_renewal_and_release(self):
        registry = ActiveMastersRegistry(self.root_pub)
        clock = VectorClock({"captain-01": 1})
        now = time.time()
        ok, lease, _ = registry.acquire_lease("k8s-infra", "captain-01", self.captain_cert, clock, ttl_seconds=20.0, current_time=now)
        self.assertTrue(ok)

        # Renew
        ok_renew, _ = registry.renew_lease("k8s-infra", "captain-01", lease.fencing_token, ttl_seconds=30.0, current_time=now + 5.0)
        self.assertTrue(ok_renew)

        # Wrong token renewal fails
        ok_bad_token, _ = registry.renew_lease("k8s-infra", "captain-01", "wrong:token", current_time=now + 5.0)
        self.assertFalse(ok_bad_token)

        # Graceful release
        ok_rel, _ = registry.release_lease("k8s-infra", "captain-01", lease.fencing_token)
        self.assertTrue(ok_rel)
        self.assertIsNone(registry.get_active_master("k8s-infra", current_time=now + 6.0))

    def test_byzantine_revocation(self):
        registry = ActiveMastersRegistry(self.root_pub)
        clock = VectorClock({"captain-01": 1})
        ok, lease, _ = registry.acquire_lease("k8s-infra", "captain-01", self.captain_cert, clock)
        self.assertTrue(ok)

        voucher = {
            "voucher_id": "voucher-001",
            "accused_master_id": "captain-01",
            "violation_type": "MANIFEST_BREACH",
            "reporting_peers": ["peer-02", "peer-03"],
        }
        ok_rev, msg = registry.revoke_lease_byzantine("k8s-infra", voucher, min_reporting_peers=2)
        self.assertTrue(ok_rev)
        self.assertIsNone(registry.get_active_master("k8s-infra"))

        # Old fencing token is fenced out
        self.assertFalse(registry.validate_fencing_token("k8s-infra", lease.fencing_token))


class DirectedObjectiveManifestTests(unittest.TestCase):
    """Test Directed Objective Manifest invariant adherence."""

    def test_manifest_validation(self):
        manifest = {
            "manifest_id": "dom-001",
            "domain": "k8s-infra",
            "target_states": {
                "allowed_action_types": ["restart_node", "drain_traffic", "scale_deployment"],
            },
            "invariants": [
                {"rule": "no_drain_protected_nodes", "protected": ["control-plane-01", "control-plane-02"]},
                {"rule": "max_blast_radius", "limit": 3},
            ],
        }

        # Conforming directive
        valid_dir = {"action_type": "restart_node", "target_node_id": "worker-05", "blast_radius": 1}
        ok, _ = validate_directive_against_manifest(valid_dir, manifest)
        self.assertTrue(ok)

        # Forbidden action type
        forbidden_dir = {"action_type": "delete_all", "target_node_id": "worker-05"}
        ok, msg = validate_directive_against_manifest(forbidden_dir, manifest)
        self.assertFalse(ok)
        self.assertIn("forbidden", msg)

        # Protected node drain violation
        drain_protected = {"action_type": "drain_traffic", "target_node_id": "control-plane-01"}
        ok, msg = validate_directive_against_manifest(drain_protected, manifest)
        self.assertFalse(ok)
        self.assertIn("cannot drain protected node", msg)

        # Excessive blast radius violation
        excessive_blast = {"action_type": "restart_node", "target_node_id": "worker-01", "blast_radius": 5}
        ok, msg = validate_directive_against_manifest(excessive_blast, manifest)
        self.assertFalse(ok)
        self.assertIn("blast radius 5 exceeds limit 3", msg)


class ExecutionCanariesTests(unittest.TestCase):
    """Test deterministic peer-verified execution canary challenges."""

    @classmethod
    def setUpClass(cls):
        cls.node_pub, cls.node_priv = generate_pqc_keypair(tree_height=4)

    def test_hash_chain_challenge_solve_and_verify(self):
        t0 = 1000.0
        challenge = generate_canary_challenge("candidate-01", "k8s-infra", challenge_type="hash_chain", iterations=100, current_time=t0)
        self.assertEqual(challenge["challenge_type"], "hash_chain")
        proof = solve_canary_challenge(challenge, self.node_priv, current_time=t0 + 1.0)
        self.assertTrue(verify_canary_proof(challenge, proof, self.node_pub))

    def test_graph_assertion_challenge_solve_and_verify(self):
        t0 = 1000.0
        challenge = generate_canary_challenge("candidate-01", "k8s-infra", challenge_type="graph_assertion", current_time=t0)
        proof = solve_canary_challenge(challenge, self.node_priv, current_time=t0 + 1.0)
        self.assertTrue(verify_canary_proof(challenge, proof, self.node_pub))

    def test_canary_timeout_rejection(self):
        t0 = 1000.0
        challenge = generate_canary_challenge("candidate-01", "k8s-infra", current_time=t0)
        proof = solve_canary_challenge(challenge, self.node_priv, current_time=t0 + 10.0)  # Deadline was t0 + 5.0
        self.assertFalse(verify_canary_proof(challenge, proof, self.node_pub))

    def test_peer_quorum_evaluation(self):
        votes = [
            {"peer_id": "peer-1", "approved": True},
            {"peer_id": "peer-2", "approved": True},
            {"peer_id": "peer-3", "approved": False},
        ]
        # 2 of 3 is 66.7% >= 66% -> True
        self.assertTrue(evaluate_canary_peer_quorum(votes, total_eligible_peers=3, quorum_ratio=0.66))

        # 1 of 3 -> False
        self.assertFalse(evaluate_canary_peer_quorum(votes[:1], total_eligible_peers=3, quorum_ratio=0.66))


class GovernanceRegimeTests(unittest.TestCase):
    """Test 3-regime scale-adaptive governance and <= 5% overhead proof."""

    def test_compute_governance_regime_boundaries(self):
        # Regime 1: Captain of a ship (N <= 7)
        for n in (1, 4, 7):
            r = compute_governance_regime(n)
            self.assertEqual(r["regime_id"], 1)
            self.assertEqual(r["voting_body_size"], 1)
            self.assertEqual(r["decision_overhead"], 0.0)
            self.assertTrue(r["overhead_bounded_under_5pct"])

        # Regime 2: Senate (8 <= N <= 64)
        for n in (8, 16, 36, 64):
            r = compute_governance_regime(n)
            self.assertEqual(r["regime_id"], 2)
            self.assertGreaterEqual(r["voting_body_size"], 2)
            self.assertLessEqual(r["voting_body_size"], 8)
            if n == 64:
                self.assertTrue(r["overhead_bounded_under_5pct"])

        # Regime 3: Capped Hierarchical Council (N > 64, M_max = 13)
        for n in (65, 100, 500, 1000):
            r = compute_governance_regime(n)
            self.assertEqual(r["regime_id"], 3)
            self.assertEqual(r["voting_body_size"], 13)
            self.assertEqual(r["quorum_threshold"], 7)
            self.assertTrue(r["overhead_bounded_under_5pct"])
            # Exact overhead proof check: at N=65, Theta(65) = 156 / 4160 = 0.0375 <= 0.05
            if n == 65:
                self.assertAlmostEqual(r["decision_overhead"], 0.0375, places=4)
                self.assertLessEqual(r["decision_overhead"], 0.05)

    def test_negative_node_count_rejected(self):
        with self.assertRaises(ValueError):
            compute_governance_regime(0)
        with self.assertRaises(ValueError):
            compute_governance_regime(-10)

    def test_regime_engine_hysteresis_and_debounce(self):
        t0 = 1000.0
        engine = GovernanceRegimeEngine(initial_node_count=7, debounce_seconds=5.0)
        self.assertEqual(engine.active_regime["regime_id"], 1)

        # Flap to 8 and immediately back to 7 within 1.0s -> remains Regime 1
        res1 = engine.update_node_count(8, current_time=t0 + 1.0)
        self.assertTrue(res1["pending_transition"])
        self.assertEqual(engine.active_regime["regime_id"], 1)

        res2 = engine.update_node_count(7, current_time=t0 + 2.0)
        self.assertFalse(res2["pending_transition"])
        self.assertEqual(engine.active_regime["regime_id"], 1)

        # Sustained N=8 for > 5.0s -> commits to Regime 2
        engine.update_node_count(8, current_time=t0 + 3.0)
        res_committed = engine.update_node_count(8, current_time=t0 + 9.0)
        self.assertFalse(res_committed["pending_transition"])
        self.assertEqual(engine.active_regime["regime_id"], 2)


class SeveranceDoctrinesTests(unittest.TestCase):
    """Test severance states, ENCRYPT_AND_REST sealing, and PERSIST_RESIST_REGROW warrants."""

    @classmethod
    def setUpClass(cls):
        cls.master_pub, cls.master_priv = generate_pqc_keypair(tree_height=4)

    def test_severance_state_transitions(self):
        # Heartbeat fresh <= 5.0s -> ACTIVE
        s1 = evaluate_severance_state(elapsed_since_master_heartbeat=2.0)
        self.assertEqual(s1["state"], "ACTIVE")
        self.assertTrue(s1["mutations_allowed"])

        # Heartbeat missed 5.0s < dt <= 30.0s -> SOFT_QUARANTINE
        s2 = evaluate_severance_state(elapsed_since_master_heartbeat=15.0)
        self.assertEqual(s2["state"], "SOFT_QUARANTINE")
        self.assertFalse(s2["mutations_allowed"])

        # Heartbeat lost > 30.0s without warrant -> ENCRYPT_AND_REST (default)
        s3 = evaluate_severance_state(elapsed_since_master_heartbeat=45.0)
        self.assertEqual(s3["state"], "ENCRYPT_AND_REST")
        self.assertFalse(s3["mutations_allowed"])
        self.assertTrue(s3["resting_dormant"])

    def test_persist_resist_regrow_warrant(self):
        t0 = 1000.0
        warrant = create_persist_resist_regrow_warrant(
            warrant_id="warrant-01",
            contingent_id="contingent-alpha",
            authorized_nodes=["node-01", "node-02"],
            permitted_operations=["local_remediation", "spawn_replacement_worker"],
            resource_budget={"max_replacement_workers": 2, "max_delta_operations": 50},
            valid_duration_seconds=3600.0,
            master_privkey=self.master_priv,
            canonical_manifest_hash="abc123hash",
            current_time=t0,
        )
        ok, msg = verify_persist_resist_regrow_warrant(warrant, self.master_pub, "node-01", current_time=t0 + 100.0)
        self.assertTrue(ok)

        # Severance evaluation with valid warrant -> PERSIST_RESIST_REGROW
        s = evaluate_severance_state(
            elapsed_since_master_heartbeat=60.0,
            active_warrant=warrant,
            master_pubkey=self.master_pub,
            target_node_id="node-01",
            current_time=t0 + 100.0,
        )
        self.assertEqual(s["state"], "PERSIST_RESIST_REGROW")
        self.assertTrue(s["autonomous_regrow_allowed"])

    def test_zeroization_and_sealing(self):
        buf = bytearray(b"super_secret_key_material_12345")
        zeroize_bytearray(buf)
        self.assertEqual(buf, bytearray(b"\x00" * 31))

        secrets_dict = {"token": bytearray(b"secret_token"), "nested": {"password": "pass"}}
        zeroize_dict_secrets(secrets_dict)
        self.assertEqual(secrets_dict, {})

        # Test execute_encrypt_and_rest & execute_master_unseal
        with tempfile.TemporaryDirectory() as tmpdir:
            seal_path = Path(tmpdir) / "sealed_state.json"
            node_ctx = {
                "state": {"node_id": "worker-01", "cluster_secret": "omega-42"},
                "secrets_buffer": bytearray(b"ram_secret"),
            }
            res = execute_encrypt_and_rest(node_ctx, self.master_pub, seal_path)
            self.assertEqual(res["status"], "RESTING")
            self.assertTrue(seal_path.exists())

            # Unseal with master private key
            sealed_data = json.loads(seal_path.read_text(encoding="utf-8"))
            unseal_res = execute_master_unseal(sealed_data, self.master_priv)
            self.assertEqual(unseal_res["status"], "RESTORED")
            self.assertEqual(unseal_res["state"]["cluster_secret"], "omega-42")

            # Hard wipe file
            hard_wipe_file(seal_path)
            self.assertFalse(seal_path.exists())

    def test_quarantine_merge_conflict_reconciliation(self):
        master_state = {
            "vector_clock": {"master": 5, "res-a": 2, "res-b": 1},
            "data": {"res-a": "canonical_a", "res-b": "canonical_b"},
        }
        contingent_delta = {
            "contingent_id": "contingent-01",
            "regrown_nodes": ["regrown-worker-01"],
            "operations": [
                # Non-conflicting: updates res-c
                {
                    "op_id": "op-1",
                    "key": "res-c",
                    "value": "new_c",
                    "vector_clock": {"contingent-01": 2},
                    "base_vector_clock": {"res-c": 0},
                },
                # Conflicting: modifies res-a while master advanced
                {
                    "op_id": "op-2",
                    "key": "res-a",
                    "value": "conflicting_a",
                    "vector_clock": {"contingent-01": 3},
                    "base_vector_clock": {"res-a": 1},  # Master is at 2!
                },
            ],
        }

        staged_cards = []
        def mock_stage_card(target_node_id, action_type, parameters):
            card_id = f"card-{len(staged_cards) + 1}"
            staged_cards.append((target_node_id, action_type, parameters))
            return {"action_id": card_id, "status": "STAGED"}

        res = reconcile_reconnected_contingent(
            canonical_state=master_state,
            contingent_delta_log=contingent_delta,
            stage_action_card_fn=mock_stage_card,
        )

        self.assertEqual(res["status"], "QUARANTINE_MERGED")
        self.assertEqual(res["applied_causally_count"], 1)
        self.assertEqual(res["conflicts_count"], 1)
        # Canonical master value preserved
        self.assertEqual(master_state["data"]["res-a"], "canonical_a")
        # Non-conflicting applied
        self.assertEqual(master_state["data"]["res-c"], "new_c")
        self.assertEqual(len(staged_cards), 1)


class FederationAPITests(unittest.TestCase):
    """Test HTTP handlers for /api/v1/federation/* routes."""

    def test_get_status(self):
        status, payload = handle_federation_api("/api/v1/federation/status", method="GET")
        self.assertEqual(status, 200)
        self.assertIn("cluster_regime", payload)
        self.assertIn("node_count", payload)
        self.assertIn("active_masters", payload)

    def test_heartbeat_post_and_get_loopback(self):
        # GET Loopback
        status_get, desc = handle_federation_api("/api/v1/federation/heartbeat", method="GET")
        self.assertEqual(status_get, 200)
        self.assertEqual(desc["endpoint"], "/api/v1/federation/heartbeat")

        # POST Heartbeat
        body = {"node_id": "test-node-01", "vector_clock": {"test-node-01": 2}}
        status_post, resp = handle_federation_api("/api/v1/federation/heartbeat", method="POST", body=body)
        self.assertEqual(status_post, 200)
        self.assertEqual(resp["status"], "accepted")

    def test_severance_post_and_get_loopback(self):
        status_get, desc = handle_federation_api("/api/v1/federation/severance", method="GET")
        self.assertEqual(status_get, 200)

        body = {"node_id": "severed-node-01", "elapsed_since_heartbeat": 50.0}
        status_post, resp = handle_federation_api("/api/v1/federation/severance", method="POST", body=body)
        self.assertEqual(status_post, 200)
        self.assertEqual(resp["evaluated_state"], "ENCRYPT_AND_REST")

    def test_reconcile_post_and_get_loopback(self):
        status_get, desc = handle_federation_api("/api/v1/federation/reconcile", method="GET")
        self.assertEqual(status_get, 200)

        body = {
            "contingent_id": "contingent-01",
            "delta_log": [{"key": "test", "value": 1}],
            "regrown_nodes": ["node-regrown-1"],
        }
        status_post, resp = handle_federation_api("/api/v1/federation/reconcile", method="POST", body=body)
        self.assertEqual(status_post, 200)
        self.assertEqual(resp["status"], "quarantined")
        self.assertTrue(resp["requires_master_review"])


if __name__ == "__main__":
    unittest.main()
