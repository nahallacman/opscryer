# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit tests for Unified RTS/TBS Tactical Security & Federation Deck (M12)."""

from __future__ import annotations

from html import unescape
import json
from pathlib import Path
import re
import sys
import types
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import action_cards
import cybersecurity_bridge
import event_stream
import node_federation
import tactical_security_deck
from tactical_security_deck import (
    SCHEMA_VERSION,
    build_tactical_deck_summary,
    handle_tactical_deck_api,
    render_tactical_security_deck_html,
)

_TEST_CATALOG = {
    "schema_version": "1.0-separable-spatial-graph-contract",
    "nodes": [
        {
            "id": "node-alpha-01",
            "label": "node-alpha-01",
            "kind": "Node",
            "namespace": "kube-system",
            "tier": "control-plane",
            "primary_url": "https://kubernetes.example.org",
        },
        {
            "id": "node-beta-02",
            "label": "node-beta-02",
            "kind": "Deployment",
            "namespace": "default",
            "tier": "worker",
            "primary_url": "https://app.example.org",
        },
    ],
    "edges": [
        {
            "source": "node-beta-02",
            "target": "node-alpha-01",
            "relation": "runs_on_hardware",
        }
    ],
}

# Constructed from split fragments so test source never contains raw forbidden OPSEC literals
_FORBIDDEN_OPSEC_TOKENS: tuple[str, ...] = (
    "home" + ".arpa",
    "duckdns" + ".org",
    "minisforum" + "001",
    "stream" + "server",
    "lowpowered" + "server",
    "sama" + "nage",
    "nahallac" + "man",
    "10." + "10.1.1",
    "192." + "168.1.1",
)


class TestTacticalSecurityDeck(unittest.TestCase):
    """Test suite for M12 Tactical Security & Federation Deck UI and Summary API."""

    def setUp(self) -> None:
        action_cards.reset_action_ledger()
        cybersecurity_bridge.reset_security_bridge()
        event_stream.reset_event_buffer()
        with node_federation._GLOBAL_FEDERATION_STATE.lock:
            node_federation._GLOBAL_FEDERATION_STATE.node_count = 5
            node_federation._GLOBAL_FEDERATION_STATE.regime_engine = (
                node_federation.GovernanceRegimeEngine(5)
            )
            node_federation._GLOBAL_FEDERATION_STATE.vector_clock = (
                node_federation.VectorClock({"master-01": 1})
            )
            node_federation._GLOBAL_FEDERATION_STATE.quarantined_staging_queues.clear()

    def tearDown(self) -> None:
        action_cards.reset_action_ledger()
        cybersecurity_bridge.reset_security_bridge()
        event_stream.reset_event_buffer()
        with node_federation._GLOBAL_FEDERATION_STATE.lock:
            node_federation._GLOBAL_FEDERATION_STATE.node_count = 5
            node_federation._GLOBAL_FEDERATION_STATE.regime_engine = (
                node_federation.GovernanceRegimeEngine(5)
            )
            node_federation._GLOBAL_FEDERATION_STATE.vector_clock = (
                node_federation.VectorClock({"master-01": 1})
            )
            node_federation._GLOBAL_FEDERATION_STATE.quarantined_staging_queues.clear()

    def test_01_summary_schema_and_top_level_structure(self) -> None:
        summary = build_tactical_deck_summary()
        self.assertEqual(summary["schema_version"], SCHEMA_VERSION)
        self.assertEqual(summary["schema_version"], "1.0-tactical-security-deck")

        expected_sections = {
            "schema_version",
            "action_cards_summary",
            "cybersecurity_summary",
            "federation_summary",
            "event_stream_summary",
            "mcp_airlock_summary",
            "gitops_promotion_summary",
        }
        self.assertEqual(set(summary.keys()), expected_sections)

        ac = summary["action_cards_summary"]
        self.assertEqual(ac["total"], 0)
        self.assertEqual(ac["staged_count"], 0)
        self.assertEqual(ac["executed_count"], 0)
        self.assertEqual(ac["rejected_count"], 0)
        self.assertEqual(ac["cards"], [])

        cs = summary["cybersecurity_summary"]
        self.assertEqual(cs["total_incidents"], 0)
        self.assertEqual(cs["critical_count"], 0)
        self.assertGreaterEqual(cs["sigma_rules_count"], 3)
        self.assertEqual(cs["recent_incidents"], [])

    def test_02_action_cards_live_reflection_staged_approved_rejected(self) -> None:
        card1 = action_cards.stage_action_card(
            target_node_id="node-beta-02",
            action_type="scale_deployment",
            parameters={"replicas": 2},
            catalog=_TEST_CATALOG,
        )
        card2 = action_cards.stage_action_card(
            target_node_id="node-alpha-01",
            action_type="restart_node",
            parameters={},
            catalog=_TEST_CATALOG,
        )

        summary_staged = build_tactical_deck_summary()["action_cards_summary"]
        self.assertEqual(summary_staged["total"], 2)
        self.assertEqual(summary_staged["staged_count"], 2)
        self.assertEqual(summary_staged["executed_count"], 0)
        self.assertEqual(summary_staged["rejected_count"], 0)
        self.assertEqual(len(summary_staged["cards"]), 2)

        # Approve low-risk card1 (1-of-1 single key mode) and reject card2
        status_approve, _ = action_cards.approve_action_card(card1["action_id"])
        self.assertEqual(status_approve, 200)
        status_reject, _ = action_cards.reject_action_card(
            card2["action_id"], reason="Maintenance window deferred"
        )
        self.assertEqual(status_reject, 200)

        summary_after = build_tactical_deck_summary()["action_cards_summary"]
        self.assertEqual(summary_after["total"], 2)
        self.assertEqual(summary_after["staged_count"], 0)
        self.assertEqual(summary_after["executed_count"], 1)
        self.assertEqual(summary_after["rejected_count"], 1)

    def test_03_cybersecurity_ocsf_and_cef_live_reflection(self) -> None:
        ocsf_body = {
            "standard": "ocsf",
            "payload": {
                "class_uid": 2004,
                "severity_id": 5,
                "finding_info": {
                    "uid": "find-crit-01",
                    "title": "Container Escape Attempt",
                },
                "device": {"hostname": "node-alpha-01", "ip": "198.51.100.25"},
                "actor": {"process": {"name": "bash", "cmdline": "/bin/bash -i"}},
            },
        }
        code1, _ = cybersecurity_bridge.handle_security_api(
            "/api/v1/security/ingest", "POST", {}, body=ocsf_body, catalog=_TEST_CATALOG
        )
        self.assertEqual(code1, 200)

        cef_raw = (
            "CEF:0|OpsCryer|Sensor|1.0|100|Suspicious Beacon|7|"
            "src=198.51.100.12 dst=198.51.100.30 dhost=node-beta-02 cs1=api-gw msg=Beacon"
        )
        code2, _ = cybersecurity_bridge.handle_security_api(
            "/api/v1/security/ingest",
            "POST",
            {},
            body={"standard": "cef", "payload": cef_raw},
            catalog=_TEST_CATALOG,
        )
        self.assertEqual(code2, 200)

        cs = build_tactical_deck_summary()["cybersecurity_summary"]
        self.assertEqual(cs["total_incidents"], 2)
        self.assertEqual(cs["critical_count"], 1)
        self.assertGreaterEqual(cs["sigma_rules_count"], 3)
        self.assertEqual(len(cs["recent_incidents"]), 2)
        severities = {inc["severity"] for inc in cs["recent_incidents"]}
        self.assertEqual(severities, {"CRITICAL", "HIGH"})

    def test_04_event_stream_published_sse_events_reflection(self) -> None:
        ev_before = build_tactical_deck_summary()["event_stream_summary"]
        self.assertEqual(ev_before["latest_seq"], 0)
        self.assertEqual(
            ev_before["permitted_topics"],
            ["actions", "graph", "jev", "security", "system"],
        )
        self.assertEqual(ev_before["sse_endpoint"], "/api/v1/events/stream")
        self.assertEqual(ev_before["delta_endpoint"], "/api/v1/graph/delta")

        event_stream.publish_event("graph", "node_updated", {"node": {"id": "node-alpha-01"}})
        event_stream.publish_event("security", "security_incident", {"event_id": "sec-01"})
        seq3 = event_stream.publish_event("system", "regime_check", {"regime": "CAPTAIN"})

        ev_after = build_tactical_deck_summary()["event_stream_summary"]
        self.assertEqual(ev_after["latest_seq"], seq3)
        self.assertEqual(ev_after["latest_seq"], 3)

    def test_05_federation_heartbeat_and_quarantine_merge_reflection(self) -> None:
        hb_code, _ = node_federation.handle_federation_api(
            "/api/v1/federation/heartbeat",
            "POST",
            body={"node_id": "node-alpha-01", "vector_clock": {"node-alpha-01": 7}},
        )
        self.assertEqual(hb_code, 200)

        rec_code, _ = node_federation.handle_federation_api(
            "/api/v1/federation/reconcile",
            "POST",
            body={
                "contingent_id": "contingent-bravo",
                "delta_log": [{"op_id": "op-99", "key": "mesh_state", "value": "synced"}],
                "regrown_nodes": ["node-delta-04"],
            },
        )
        self.assertEqual(rec_code, 200)

        fed = build_tactical_deck_summary()["federation_summary"]
        self.assertEqual(fed["active_regime"], "CAPTAIN_OF_A_SHIP")
        self.assertEqual(fed["node_count"], 5)
        self.assertEqual(fed["default_severance_doctrine"], "ENCRYPT_AND_REST")
        self.assertEqual(fed["max_overhead_ceiling_pct"], 5.0)
        self.assertEqual(fed["quarantine_merge_queue_depth"], 1)
        self.assertEqual(fed["vector_clock"].get("node-alpha-01"), 7)

    def test_06_federation_three_regimes_overhead_bound(self) -> None:
        # Regime 1: Captain (N=5)
        with node_federation._GLOBAL_FEDERATION_STATE.lock:
            node_federation._GLOBAL_FEDERATION_STATE.node_count = 5
            node_federation._GLOBAL_FEDERATION_STATE.regime_engine = (
                node_federation.GovernanceRegimeEngine(5)
            )
        fed_r1 = build_tactical_deck_summary()["federation_summary"]
        self.assertEqual(fed_r1["active_regime"], "CAPTAIN_OF_A_SHIP")
        self.assertLessEqual(fed_r1["control_overhead_pct"], 5.0)

        # Regime 2: Senate (N=25)
        with node_federation._GLOBAL_FEDERATION_STATE.lock:
            node_federation._GLOBAL_FEDERATION_STATE.node_count = 25
            node_federation._GLOBAL_FEDERATION_STATE.regime_engine = (
                node_federation.GovernanceRegimeEngine(25)
            )
        fed_r2 = build_tactical_deck_summary()["federation_summary"]
        self.assertEqual(fed_r2["active_regime"], "TRUSTED_CONTINGENT_SENATE")
        self.assertLessEqual(fed_r2["control_overhead_pct"], 5.0)

        # Regime 3: Council (N=100, M_max=13)
        with node_federation._GLOBAL_FEDERATION_STATE.lock:
            node_federation._GLOBAL_FEDERATION_STATE.node_count = 100
            node_federation._GLOBAL_FEDERATION_STATE.regime_engine = (
                node_federation.GovernanceRegimeEngine(100)
            )
        fed_r3 = build_tactical_deck_summary()["federation_summary"]
        self.assertEqual(fed_r3["active_regime"], "CAPPED_HIERARCHICAL_COUNCIL")
        self.assertLessEqual(fed_r3["control_overhead_pct"], 5.0)

    def test_07_mcp_airlock_summary_invariants(self) -> None:
        mcp = build_tactical_deck_summary()["mcp_airlock_summary"]
        self.assertEqual(mcp["endpoint"], "/api/v1/mcp")
        self.assertEqual(
            mcp["tier1_recon_tools"],
            [
                "query_graph",
                "get_system_context",
                "evaluate_jev",
                "search_ocsf_incidents",
                "preview_remediation_dry_run",
            ],
        )
        self.assertEqual(mcp["tier2_staging_tools"], ["stage_action_card"])
        self.assertTrue(mcp["direct_mutation_blocked"])

    def test_08_gitops_promotion_summary_fallback_and_dynamic_module(self) -> None:
        gp_default = build_tactical_deck_summary()["gitops_promotion_summary"]
        self.assertEqual(gp_default["dev_namespace"], "dev-envs")
        self.assertEqual(gp_default["prod_namespace"], "security")
        self.assertIsInstance(gp_default["drift_status"], str)

        # Inject a mock gitops_promotion_bridge module to verify dynamic integration
        mock_mod = types.ModuleType("gitops_promotion_bridge")
        mock_mod.get_gitops_promotion_status = lambda: {  # type: ignore[attr-defined]
            "drift_status": "DRIFT_DETECTED",
            "dev_namespace": "dev-envs",
            "prod_namespace": "security",
        }
        old_mod = sys.modules.get("gitops_promotion_bridge")
        sys.modules["gitops_promotion_bridge"] = mock_mod
        try:
            gp_dynamic = build_tactical_deck_summary()["gitops_promotion_summary"]
            self.assertEqual(gp_dynamic["drift_status"], "DRIFT_DETECTED")
            self.assertEqual(gp_dynamic["dev_namespace"], "dev-envs")
            self.assertEqual(gp_dynamic["prod_namespace"], "security")
        finally:
            if old_mod is None:
                sys.modules.pop("gitops_promotion_bridge", None)
            else:
                sys.modules["gitops_promotion_bridge"] = old_mod

    def test_09_html_doctype_and_five_tactical_panels_present(self) -> None:
        html_out = render_tactical_security_deck_html()
        self.assertTrue(html_out.startswith("<!DOCTYPE html>"))
        self.assertIn('<html lang="en">', html_out)
        self.assertIn('class="opscryer-shared-nav"', html_out)
        self.assertIn('id="sse-event-ticker"', html_out)
        self.assertIn('id="action-card-console"', html_out)
        self.assertIn('id="cybersecurity-incident-feed"', html_out)
        self.assertIn('id="node-federation-inspector"', html_out)
        self.assertIn('id="mcp-and-gitops-bar"', html_out)

    def test_10_html_aria_landmarks_and_accessibility_attributes(self) -> None:
        html_out = render_tactical_security_deck_html()
        self.assertIn('role="banner"', html_out)
        self.assertIn('role="main"', html_out)
        self.assertIn('role="region"', html_out)
        self.assertIn('role="log"', html_out)
        self.assertIn('role="status"', html_out)
        self.assertIn('aria-live="polite"', html_out)
        self.assertIn('aria-pressed="true"', html_out)
        self.assertIn('tabindex="0"', html_out)

    def test_11_html_api_endpoint_bindings_and_sse_ticker(self) -> None:
        html_out = render_tactical_security_deck_html()
        expected_endpoints = (
            "/api/v1/events/stream",
            "/api/v1/graph/delta",
            "/api/v1/actions/dry-run",
            "/api/v1/actions/stage",
            "/api/v1/actions/approve",
            "/api/v1/actions/reject",
            "/api/v1/actions/status",
            "/api/v1/security/ingest",
            "/api/v1/security/incidents",
            "/api/v1/federation/status",
            "/api/v1/federation/heartbeat",
            "/api/v1/federation/severance",
            "/api/v1/federation/reconcile",
            "/api/v1/mcp",
            "/api/v1/gitops-promotion/status",
        )
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, html_out)

    def test_12_html_four_signal_outcome_predictor_and_shamir_controls(self) -> None:
        html_out = render_tactical_security_deck_html()
        for signal_badge in (
            "BLAST_RADIUS",
            "SLO_DEGRADATION",
            "ACTIVE_SECURITY_ALERT",
            "MUTATION_VELOCITY",
        ):
            self.assertIn(signal_badge, html_out)
        self.assertIn("1-of-1 Single Master Key", html_out)
        self.assertIn("2-of-3 Shamir Threshold Lock", html_out)
        self.assertIn("3-of-5 Shamir Threshold Lock", html_out)
        self.assertIn("ENCRYPT_AND_REST", html_out)
        self.assertIn("PERSIST_RESIST_REGROW", html_out)

    def test_13_html_embedded_initial_json_matches_summary(self) -> None:
        html_out = render_tactical_security_deck_html()
        match = re.search(
            r'<script id="tactical-deck-initial-state" type="application/json">(.*?)</script>',
            html_out,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        embedded_data = json.loads(unescape(match.group(1)))
        self.assertEqual(embedded_data["schema_version"], "1.0-tactical-security-deck")
        self.assertIn("action_cards_summary", embedded_data)
        self.assertIn("federation_summary", embedded_data)

    def test_14_handle_tactical_deck_api_200_ok(self) -> None:
        code, payload = handle_tactical_deck_api("/api/v1/tactical-deck/summary", "GET", None)
        self.assertEqual(code, 200)
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)

        code_trailing, payload_trailing = handle_tactical_deck_api(
            "/api/v1/tactical-deck/summary/", "get", {}
        )
        self.assertEqual(code_trailing, 200)
        self.assertEqual(payload_trailing["schema_version"], SCHEMA_VERSION)

    def test_15_handle_tactical_deck_api_400_unexpected_query(self) -> None:
        code_dict, err_dict = handle_tactical_deck_api(
            "/api/v1/tactical-deck/summary", "GET", {"unexpected": "1"}
        )
        self.assertEqual(code_dict, 400)
        self.assertIn("error", err_dict)

        code_qs, err_qs = handle_tactical_deck_api(
            "/api/v1/tactical-deck/summary?foo=bar", "GET", None
        )
        self.assertEqual(code_qs, 400)
        self.assertIn("error", err_qs)

        code_bad_type, _ = handle_tactical_deck_api(
            "/api/v1/tactical-deck/summary", "GET", ["invalid"]  # type: ignore[arg-type]
        )
        self.assertEqual(code_bad_type, 400)

    def test_16_handle_tactical_deck_api_405_method_not_allowed(self) -> None:
        for bad_method in ("POST", "PUT", "DELETE", "PATCH"):
            code, err = handle_tactical_deck_api(
                "/api/v1/tactical-deck/summary", bad_method, {}
            )
            self.assertEqual(code, 405)
            self.assertEqual(err.get("allowed_methods"), ["GET"])

    def test_17_handle_tactical_deck_api_404_not_found(self) -> None:
        for unknown_path in (
            "/api/v1/tactical-deck/unknown",
            "/api/v1/tactical-deck",
            "/tactical-deck",
        ):
            code, err = handle_tactical_deck_api(unknown_path, "GET", {})
            self.assertEqual(code, 404)
            self.assertEqual(err.get("code"), "NOT_FOUND")

    def test_18_opsec_zero_forbidden_strings_in_source_and_outputs(self) -> None:
        # Inject an incident containing raw forbidden tokens to prove runtime OPSEC scrubbing
        dirty_host = "minisforum" + "001." + "home" + ".arpa"
        dirty_ip = "10." + "10.1.1"
        cybersecurity_bridge._GLOBAL_INCIDENT_STORE.ingest(
            {
                "event_id": "sec-opsec-test",
                "severity": "CRITICAL",
                "target_node_id": dirty_host,
                "message": f"Alert on {dirty_host} at {dirty_ip}",
            }
        )

        _, api_payload = handle_tactical_deck_api("/api/v1/tactical-deck/summary", "GET", {})
        serialized_summary = json.dumps(api_payload)
        rendered_html = render_tactical_security_deck_html()

        module_source = Path(tactical_security_deck.__file__).read_text(encoding="utf-8")
        test_source = Path(__file__).read_text(encoding="utf-8")

        for token in _FORBIDDEN_OPSEC_TOKENS:
            self.assertNotIn(token, serialized_summary.lower())
            self.assertNotIn(token, rendered_html.lower())
            self.assertNotIn(token, module_source.lower())
            self.assertNotIn(token, test_source.lower())


if __name__ == "__main__":
    unittest.main()
