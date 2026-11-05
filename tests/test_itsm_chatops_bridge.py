# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Milestone 13: Bi-Directional ITSM & Signed ChatOps Callback Bridge."""

from __future__ import annotations

import pathlib
import sys
import time
import unittest

SUITE_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(SUITE_ROOT))

import action_cards
import event_stream
import itsm_chatops_bridge
from itsm_chatops_bridge import (
    correlate_incident_to_itsm_ticket,
    handle_chatops_callback,
    handle_itsm_api,
    list_itsm_tickets,
    reset_itsm_bridge,
    sign_chatops_callback_hmac,
    sign_chatops_callback_pqc,
)
import pqc_security


class TestItsmChatopsBridge(unittest.TestCase):
    """Comprehensive unit tests for ITSM ticket correlation and signed ChatOps callbacks."""

    def setUp(self) -> None:
        reset_itsm_bridge()
        action_cards.reset_action_ledger()
        event_stream.reset_event_buffer()
        self.secret = "enterprise-chatops-shared-hmac-secret-2026"

    def tearDown(self) -> None:
        reset_itsm_bridge()
        action_cards.reset_action_ledger()
        event_stream.reset_event_buffer()

    def _build_hmac_callback(
        self,
        callback_id: str,
        command: str,
        arguments: dict | None = None,
        timestamp: float | None = None,
        secret: str | None = None,
    ) -> dict:
        payload = {
            "callback_id": callback_id,
            "timestamp": time.time() if timestamp is None else timestamp,
            "command": command,
            "arguments": arguments or {},
        }
        payload["hmac_signature"] = sign_chatops_callback_hmac(payload, secret or self.secret)
        return payload

    def test_01_correlate_security_incident_creates_ticket_and_publishes_event(self) -> None:
        """Correlating a new OCSF security incident creates an OPEN ticket and publishes SSE event."""
        incident = {
            "source_type": "security_incident",
            "rule_id": "sigma-k8s-priv-exec",
            "target_node_id": "node-alpha-01",
            "severity": "HIGH",
            "summary": "Privileged shell execution detected on node-alpha-01",
        }
        ticket = correlate_incident_to_itsm_ticket(incident, provider="gitlab_issues")

        self.assertTrue(ticket["ticket_id"].startswith("ITSM-"))
        self.assertEqual(ticket["external_key"], "GL-ISSUE-1")
        self.assertEqual(ticket["provider"], "gitlab_issues")
        self.assertEqual(ticket["status"], "OPEN")
        self.assertEqual(ticket["occurrence_count"], 1)
        self.assertFalse(ticket["deduplicated"])
        self.assertEqual(
            ticket["correlation_key"],
            ["security_incident", "sigma-k8s-priv-exec", "node-alpha-01"],
        )

        events, _, _, _ = event_stream._DEFAULT_BUFFER.get_events_since(0, topics={"security"}, inclusive=True)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "itsm_ticket_correlated")
        self.assertEqual(events[0]["data"]["ticket_id"], ticket["ticket_id"])

    def test_02_idempotent_deduplication_prevents_security_ticket_storms(self) -> None:
        """Repeated security incidents with the same composite key increment occurrence_count."""
        incident = {
            "source_type": "security_incident",
            "rule_id": "sigma-c2-network-beacon",
            "target_node_id": "node-alpha-01",
            "severity": "CRITICAL",
            "summary": "Outbound C2 beacon from node-alpha-01",
        }
        first = correlate_incident_to_itsm_ticket(incident, provider="pagerduty_incident")
        second = correlate_incident_to_itsm_ticket(incident, provider="pagerduty_incident")
        third = correlate_incident_to_itsm_ticket(incident, provider="pagerduty_incident")

        self.assertEqual(first["ticket_id"], second["ticket_id"])
        self.assertEqual(second["ticket_id"], third["ticket_id"])
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertTrue(third["deduplicated"])
        self.assertEqual(third["occurrence_count"], 3)
        self.assertEqual(len(third["timeline"]), 3)

        listing = list_itsm_tickets()
        self.assertEqual(listing["total_tickets"], 1)
        self.assertEqual(listing["deduplication_metrics"]["total_occurrences"], 3)
        self.assertEqual(listing["deduplication_metrics"]["deduplicated_count"], 2)

    def test_03_correlate_jev_escalation_and_deduplicate_by_tree_id(self) -> None:
        """Low-confidence Jev escalations correlate and deduplicate by (jev_escalation, tree_id, node)."""
        escalation = {
            "source_type": "jev_escalation",
            "tree_id": "jev-storage-latency-tree",
            "target_node_id": "node-beta-02",
            "confidence": 0.42,
            "summary": "Storage latency confidence below deflection threshold",
        }
        t1 = correlate_incident_to_itsm_ticket(escalation, provider="enterprise_servicedesk")
        t2 = correlate_incident_to_itsm_ticket(escalation, provider="enterprise_servicedesk")

        self.assertEqual(t1["ticket_id"], t2["ticket_id"])
        self.assertEqual(t1["source_type"], "jev_escalation")
        self.assertEqual(t1["tree_id"], "jev-storage-latency-tree")
        self.assertIsNone(t1["rule_id"])
        self.assertAlmostEqual(t1["confidence"], 0.42)
        self.assertEqual(t2["occurrence_count"], 2)
        self.assertTrue(t2["deduplicated"])
        self.assertEqual(t1["external_key"], "ESD-INC-00001")

    def test_04_distinct_composite_keys_create_separate_tickets(self) -> None:
        """Incidents on different nodes or rules produce distinct ITSM tickets."""
        t_node1 = correlate_incident_to_itsm_ticket(
            {
                "source_type": "security_incident",
                "rule_id": "sigma-auth-failed-burst",
                "target_node_id": "node-alpha-01",
                "severity": "MEDIUM",
                "summary": "Auth burst on alpha-01",
            },
            provider="jira_webhook",
        )
        t_node2 = correlate_incident_to_itsm_ticket(
            {
                "source_type": "security_incident",
                "rule_id": "sigma-auth-failed-burst",
                "target_node_id": "node-alpha-02",
                "severity": "MEDIUM",
                "summary": "Auth burst on alpha-02",
            },
            provider="jira_webhook",
        )
        self.assertNotEqual(t_node1["ticket_id"], t_node2["ticket_id"])
        self.assertEqual(list_itsm_tickets()["total_tickets"], 2)

    def test_05_list_itsm_tickets_filtering_and_status_counts(self) -> None:
        """list_itsm_tickets filters by status and provider and reports status counts."""
        correlate_incident_to_itsm_ticket(
            {"rule_id": "r-1", "target_node_id": "node-alpha-01", "summary": "Alert 1"},
            provider="gitlab_issues",
        )
        correlate_incident_to_itsm_ticket(
            {"rule_id": "r-2", "target_node_id": "node-alpha-02", "summary": "Alert 2"},
            provider="pagerduty_incident",
        )

        gl_only = list_itsm_tickets(provider_filter="gitlab_issues")
        self.assertEqual(gl_only["returned_count"], 1)
        self.assertEqual(gl_only["tickets"][0]["provider"], "gitlab_issues")
        self.assertEqual(gl_only["counts_by_status"]["OPEN"], 2)

    def test_06_opsec_scrubbing_on_ticket_creation(self) -> None:
        """Ticket fields are scrubbed via security_airlock and telemetry_sanitizer."""
        raw_token = "gh" + "p_SecretTokenValue1234567890"
        wan_ip = ".".join(("8", "8", "8", "8"))
        incident = {
            "source_type": "security_incident",
            "rule_id": "sigma-token-leak",
            "target_node_id": "node-alpha-01\u200b",
            "severity": "HIGH",
            "summary": f"Detected token {raw_token} from WAN IP {wan_ip}",
        }
        ticket = correlate_incident_to_itsm_ticket(incident, provider="enterprise_servicedesk")
        self.assertEqual(ticket["target_node_id"], "node-alpha-01")
        self.assertNotIn(raw_token, ticket["summary"])
        self.assertIn("[REDACTED]", ticket["summary"])

    def test_07_chatops_hmac_sha256_valid_and_invalid_signature(self) -> None:
        """ChatOps callback verifies valid HMAC-SHA256 signature and rejects tampered signatures with 401."""
        valid_cb = self._build_hmac_callback(
            callback_id="cb-hmac-001",
            command="get_incident_status",
            arguments={},
        )
        code, resp = handle_chatops_callback(valid_cb, shared_secret=self.secret)
        self.assertEqual(code, 200)
        self.assertEqual(resp["tier"], "TIER_1_RECON")

        bad_cb = self._build_hmac_callback(
            callback_id="cb-hmac-002",
            command="get_incident_status",
            arguments={},
            secret="wrong-secret-key",
        )
        code_bad, resp_bad = handle_chatops_callback(bad_cb, shared_secret=self.secret)
        self.assertEqual(code_bad, 401)
        self.assertEqual(resp_bad["error"], "Invalid ChatOps callback signature")

    def test_08_chatops_pqc_wots_signature_verification(self) -> None:
        """ChatOps callback verifies Post-Quantum WOTS+ Merkle signature and rejects invalid pubkey."""
        pubkey, privkey = pqc_security.generate_pqc_keypair(tree_height=2, seed=b"chatops-pqc-seed-32-bytes-000001")
        payload = {
            "callback_id": "cb-pqc-001",
            "timestamp": time.time(),
            "command": "query_graph",
            "arguments": {"limit": 3},
        }
        payload["pqc_signature"] = sign_chatops_callback_pqc(payload, privkey)

        code, resp = handle_chatops_callback(payload, master_pubkey=pubkey)
        self.assertEqual(code, 200)
        self.assertEqual(resp["tier"], "TIER_1_RECON")
        self.assertEqual(resp["command"], "query_graph")

        other_pub, _ = pqc_security.generate_pqc_keypair(tree_height=2, seed=b"other-pqc-seed-32-bytes-00000002")
        payload_bad = {
            "callback_id": "cb-pqc-002",
            "timestamp": time.time(),
            "command": "query_graph",
            "arguments": {"limit": 3},
            "pqc_signature": payload["pqc_signature"],
        }
        code_bad, resp_bad = handle_chatops_callback(payload_bad, master_pubkey=other_pub)
        self.assertEqual(code_bad, 401)
        self.assertEqual(resp_bad["error"], "Invalid ChatOps callback signature")

    def test_09_chatops_replay_protection_rejects_duplicate_callback_id_with_409(self) -> None:
        """Replaying an already-processed callback_id is rejected with HTTP 409."""
        cb = self._build_hmac_callback(
            callback_id="cb-replay-test-01",
            command="get_incident_status",
            arguments={},
        )
        code1, _ = handle_chatops_callback(cb, shared_secret=self.secret)
        self.assertEqual(code1, 200)

        code2, resp2 = handle_chatops_callback(cb, shared_secret=self.secret)
        self.assertEqual(code2, 409)
        self.assertEqual(resp2["error"], "Replay detected: callback_id already processed")

    def test_10_chatops_stale_timestamp_rejected_with_401(self) -> None:
        """Callbacks older than 300 seconds or skewed into the future are rejected with HTTP 401."""
        stale_cb = self._build_hmac_callback(
            callback_id="cb-stale-01",
            command="get_incident_status",
            timestamp=time.time() - 450.0,
        )
        code, resp = handle_chatops_callback(stale_cb, shared_secret=self.secret)
        self.assertEqual(code, 401)
        self.assertEqual(resp["error"], "Callback timestamp expired")

    def test_11_tier1_recon_commands_execute_and_scrub_outputs(self) -> None:
        """All 4 Tier 1 recon commands execute immediately and return HTTP 200 with TIER_1_RECON."""
        commands_and_args = [
            ("query_graph", {"limit": 2}),
            ("get_incident_status", {"limit": 5}),
            ("preview_dry_run", {"action_type": "restart_node", "target_node_id": "node-alpha-01"}),
            ("get_system_context", {"tier": "local_gpu"}),
        ]
        for idx, (cmd, args) in enumerate(commands_and_args):
            cb = self._build_hmac_callback(
                callback_id=f"cb-tier1-{idx}",
                command=cmd,
                arguments=args,
            )
            code, resp = handle_chatops_callback(cb, shared_secret=self.secret)
            self.assertEqual(code, 200, f"Failed on Tier 1 command {cmd}: {resp}")
            self.assertEqual(resp["tier"], "TIER_1_RECON")
            self.assertIn("result", resp)

    def test_12_tier2_end_to_end_ticket_lifecycle_open_to_staged_to_resolved_via_shamir(self) -> None:
        """Full ITSM ticket lifecycle: OPEN -> ACTION_STAGED -> RESOLVED via 2-of-3 Shamir shares."""
        # Step 1: Correlate incident -> OPEN ticket
        ticket = correlate_incident_to_itsm_ticket(
            {
                "source_type": "security_incident",
                "rule_id": "sigma-k8s-priv-exec",
                "target_node_id": "node-alpha-01",
                "severity": "CRITICAL",
                "summary": "Unauthorized shell in workload container",
            },
            provider="gitlab_issues",
        )
        ticket_id = ticket["ticket_id"]
        self.assertEqual(ticket["status"], "OPEN")

        # Step 2: Stage Action Card via ChatOps linked to ticket_id -> ACTION_STAGED
        stage_cb = self._build_hmac_callback(
            callback_id="cb-stage-001",
            command="stage_action_card",
            arguments={
                "ticket_id": ticket_id,
                "action_type": "isolate_workload",
                "target_node_id": "node-alpha-01",
                "parameters": {"isolation_policy": "strict"},
            },
        )
        code_stage, resp_stage = handle_chatops_callback(stage_cb, shared_secret=self.secret)
        self.assertEqual(code_stage, 200)
        self.assertEqual(resp_stage["tier"], "TIER_2_ACTION_CARD")
        action_id = resp_stage["result"]["action_card"]["action_id"]
        self.assertEqual(resp_stage["result"]["linked_ticket"]["status"], "ACTION_STAGED")
        self.assertEqual(resp_stage["result"]["linked_ticket"]["linked_action_card_id"], action_id)

        # Step 3: Split secret into 2-of-3 Shamir shares and submit Share 1 -> remains ACTION_STAGED
        shares = pqc_security.split_secret_shares(b"enterprise-remediation-unlock-key", 2, 3)
        share1_cb = self._build_hmac_callback(
            callback_id="cb-share-001",
            command="submit_action_share",
            arguments={
                "action_id": action_id,
                "ticket_id": ticket_id,
                "credential": shares[0],
            },
        )
        code_s1, resp_s1 = handle_chatops_callback(share1_cb, shared_secret=self.secret)
        self.assertEqual(code_s1, 200)
        self.assertEqual(resp_s1["result"]["approval"]["status"], "STAGED")
        self.assertEqual(resp_s1["result"]["linked_ticket"]["status"], "ACTION_STAGED")

        # Step 4: Submit Share 2 -> Action Card reaches EXECUTED & ticket transitions to RESOLVED
        share2_cb = self._build_hmac_callback(
            callback_id="cb-share-002",
            command="submit_action_share",
            arguments={
                "action_id": action_id,
                "ticket_id": ticket_id,
                "credential": shares[1],
            },
        )
        code_s2, resp_s2 = handle_chatops_callback(share2_cb, shared_secret=self.secret)
        self.assertEqual(code_s2, 200)
        self.assertEqual(resp_s2["result"]["approval"]["status"], "EXECUTED")
        self.assertEqual(resp_s2["result"]["linked_ticket"]["status"], "RESOLVED")

        # Verify ticket state in ledger
        resolved_tickets = list_itsm_tickets(status_filter="RESOLVED")
        self.assertEqual(resolved_tickets["returned_count"], 1)
        self.assertEqual(resolved_tickets["tickets"][0]["ticket_id"], ticket_id)

    def test_13_tier2_single_share_1of1_resolves_ticket(self) -> None:
        """Submitting a 1-of-1 Shamir share executes the Action Card and resolves the linked ITSM ticket."""
        ticket = correlate_incident_to_itsm_ticket(
            {
                "source_type": "jev_escalation",
                "tree_id": "jev-cache-flush",
                "target_node_id": "node-alpha-01",
                "confidence": 0.55,
                "summary": "Cache pressure escalation",
            },
            provider="enterprise_servicedesk",
        )
        tid = ticket["ticket_id"]

        stage_cb = self._build_hmac_callback(
            callback_id="cb-1of1-stage",
            command="stage_action_card",
            arguments={
                "ticket_id": tid,
                "action_type": "restart_node",
                "target_node_id": "node-alpha-01",
            },
        )
        _, stage_resp = handle_chatops_callback(stage_cb, shared_secret=self.secret)
        aid = stage_resp["result"]["action_card"]["action_id"]

        share_1of1 = pqc_security.split_secret_shares(b"single-operator-master-key", 1, 1)[0]
        approve_cb = self._build_hmac_callback(
            callback_id="cb-1of1-approve",
            command="submit_action_share",
            arguments={"action_id": aid, "credential": share_1of1},
        )
        code, approve_resp = handle_chatops_callback(approve_cb, shared_secret=self.secret)
        self.assertEqual(code, 200)
        self.assertEqual(approve_resp["result"]["approval"]["status"], "EXECUTED")
        self.assertEqual(approve_resp["result"]["linked_ticket"]["status"], "RESOLVED")

    def test_14_tier2_reject_action_card_records_rejection_on_ticket(self) -> None:
        """reject_action_card rejects the staged Action Card and records the rejection on the ITSM ticket."""
        ticket = correlate_incident_to_itsm_ticket(
            {"rule_id": "sigma-test-reject", "target_node_id": "node-alpha-01", "summary": "Test rejection"},
            provider="gitlab_issues",
        )
        tid = ticket["ticket_id"]

        stage_cb = self._build_hmac_callback(
            callback_id="cb-rej-stage",
            command="stage_action_card",
            arguments={"ticket_id": tid, "action_type": "drain_traffic", "target_node_id": "node-alpha-01"},
        )
        _, stage_resp = handle_chatops_callback(stage_cb, shared_secret=self.secret)
        aid = stage_resp["result"]["action_card"]["action_id"]

        reject_cb = self._build_hmac_callback(
            callback_id="cb-rej-exec",
            command="reject_action_card",
            arguments={"action_id": aid, "ticket_id": tid, "reason": "False positive verified by SOC"},
        )
        code, rej_resp = handle_chatops_callback(reject_cb, shared_secret=self.secret)
        self.assertEqual(code, 200)
        self.assertEqual(rej_resp["result"]["rejection"]["status"], "REJECTED")
        self.assertEqual(rej_resp["result"]["linked_ticket"]["status"], "TRIAGED")
        self.assertEqual(
            rej_resp["result"]["linked_ticket"]["rejection_reason"],
            "False positive verified by SOC",
        )

    def test_15_airlock_blocks_forbidden_direct_mutations_with_403(self) -> None:
        """Direct mutation commands via ChatOps are strictly blocked with HTTP 403 and airlock_blocked=True."""
        forbidden_commands = ["restart_node", "execute_action", "delete_pod", "kill_container"]
        for idx, cmd in enumerate(forbidden_commands):
            cb = self._build_hmac_callback(
                callback_id=f"cb-forbidden-{idx}",
                command=cmd,
                arguments={"target_node_id": "node-alpha-01"},
            )
            code, resp = handle_chatops_callback(cb, shared_secret=self.secret)
            self.assertEqual(code, 403, f"Expected 403 for forbidden command {cmd}")
            self.assertTrue(resp["airlock_blocked"])
            self.assertEqual(
                resp["error"],
                "Direct mutation via ChatOps is forbidden by the Two-Tier Airlock; "
                "stage or approve an Action Card instead",
            )

    def test_16_http_api_dispatcher_endpoints(self) -> None:
        """handle_itsm_api routes POST /api/v1/itsm/correlate, GET /api/v1/itsm/tickets, and POST /api/v1/itsm/chatops-callback."""
        # 1. POST /api/v1/itsm/correlate
        c_code, c_resp = handle_itsm_api(
            "/api/v1/itsm/correlate",
            method="POST",
            body={
                "provider": "jira_webhook",
                "incident": {
                    "source_type": "security_incident",
                    "rule_id": "sigma-api-test",
                    "target_node_id": "node-alpha-01",
                    "severity": "HIGH",
                    "summary": "API correlation test",
                },
            },
        )
        self.assertEqual(c_code, 200)
        self.assertEqual(c_resp["status"], "correlated")
        self.assertFalse(c_resp["deduplicated"])
        tid = c_resp["ticket"]["ticket_id"]

        # 2. GET /api/v1/itsm/tickets
        l_code, l_resp = handle_itsm_api(
            "/api/v1/itsm/tickets",
            method="GET",
            query={"status": ["OPEN"], "provider": ["jira_webhook"], "limit": ["10"]},
        )
        self.assertEqual(l_code, 200)
        self.assertEqual(l_resp["returned_count"], 1)
        self.assertEqual(l_resp["tickets"][0]["ticket_id"], tid)

        # 3. POST /api/v1/itsm/chatops-callback
        cb_body = self._build_hmac_callback(
            callback_id="cb-api-route-01",
            command="get_incident_status",
            arguments={"ticket_id": tid},
            secret=itsm_chatops_bridge.DEFAULT_CHATOPS_SHARED_SECRET,
        )
        cb_code, cb_resp = handle_itsm_api(
            "/api/v1/itsm/chatops-callback",
            method="POST",
            body=cb_body,
        )
        self.assertEqual(cb_code, 200)
        self.assertEqual(cb_resp["result"]["ticket"]["ticket_id"], tid)

    def test_17_resolved_ticket_allows_new_ticket_on_subsequent_recurrence(self) -> None:
        """Once a ticket is RESOLVED, a new incident with the same composite key opens a fresh ticket."""
        incident = {
            "source_type": "security_incident",
            "rule_id": "sigma-recurring-alert",
            "target_node_id": "node-alpha-01",
            "severity": "HIGH",
            "summary": "Recurring alert instance",
        }
        first_ticket = correlate_incident_to_itsm_ticket(incident)
        first_tid = first_ticket["ticket_id"]

        # Stage and resolve via 1-of-1 share
        stage_cb = self._build_hmac_callback(
            callback_id="cb-rec-stage",
            command="stage_action_card",
            arguments={"ticket_id": first_tid, "action_type": "restart_node", "target_node_id": "node-alpha-01"},
        )
        _, stage_resp = handle_chatops_callback(stage_cb, shared_secret=self.secret)
        aid = stage_resp["result"]["action_card"]["action_id"]

        share = pqc_security.split_secret_shares(b"resolve-secret", 1, 1)[0]
        resolve_cb = self._build_hmac_callback(
            callback_id="cb-rec-resolve",
            command="submit_action_share",
            arguments={"action_id": aid, "credential": share},
        )
        handle_chatops_callback(resolve_cb, shared_secret=self.secret)

        # Now correlate the same incident again -> should create a new OPEN ticket
        second_ticket = correlate_incident_to_itsm_ticket(incident)
        self.assertNotEqual(first_tid, second_ticket["ticket_id"])
        self.assertFalse(second_ticket["deduplicated"])
        self.assertEqual(second_ticket["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()
