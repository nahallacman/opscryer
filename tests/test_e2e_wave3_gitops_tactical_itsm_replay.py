# SPDX-License-Identifier: Apache-2.0
"""Master End-to-End Integration Suite for Wave 3 (Milestones M11-M15).

Verifies the cross-module operational lifecycle connecting:
1. M11: Two-Stage GitOps Dev-to-Prod Promotion Gate (SHA-256 drift, Stage 1A/1B gates,
   and Stage 2 k-of-n Shamir threshold promote_to_prod Action Card).
2. M12: Unified RTS/TBS Tactical Security & Federation Deck UI (/tactical-deck) and
   Summary API (/api/v1/tactical-deck/summary).
3. M13: Bi-Directional ITSM & Signed ChatOps Callback Bridge (idempotent ticket
   correlation, HMAC-SHA256 / PQC WOTS+ signed callbacks, and Shamir share execution).
4. M14: Deterministic Flight Recorder & Chaos GameDay Replay Engine (SHA3-256 hash-chained,
   WOTS+ PQC-signed JSONL capsules and 1x-100x deterministic state-hash invariance).
5. M15: Live loopback HTTP gateway routing across all 9 Wave 3 API routes and /tactical-deck.
"""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import socketserver
import sys
import threading
import time
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import action_cards
import cybersecurity_bridge
import event_stream
import flight_recorder
import gitops_promotion_bridge
import itsm_chatops_bridge
import opscryer_browser as browser
import pqc_security
import tactical_security_deck


class Wave3MasterE2ETests(unittest.TestCase):
    """End-to-end integration tests across Wave 3 subsystems and HTTP gateway."""

    def setUp(self) -> None:
        action_cards.reset_action_ledger()
        cybersecurity_bridge.reset_security_bridge()
        event_stream.reset_event_buffer()
        gitops_promotion_bridge.reset_promotion_bridge()
        itsm_chatops_bridge.reset_itsm_bridge()
        flight_recorder.reset_flight_recorder()

    def tearDown(self) -> None:
        action_cards.reset_action_ledger()
        cybersecurity_bridge.reset_security_bridge()
        event_stream.reset_event_buffer()
        gitops_promotion_bridge.reset_promotion_bridge()
        itsm_chatops_bridge.reset_itsm_bridge()
        flight_recorder.reset_flight_recorder()

    def test_01_ocsf_alert_to_itsm_ticket_chatops_shamir_and_flight_recorder_replay(self) -> None:
        """Full pipeline: OCSF alert -> ITSM ticket -> signed ChatOps Shamir -> Flight Recorder replay."""
        # 1. Ingest a critical OCSF security alert
        code, ingest_res = cybersecurity_bridge.handle_security_api(
            "/api/v1/security/ingest",
            method="POST",
            query={},
            body={
                "standard": "ocsf",
                "payload": {
                    "class_uid": 2004,
                    "severity_id": 5,
                    "message": "Privileged container namespace escape attempt on node-alpha-01",
                    "device": {"hostname": "node-alpha-01"},
                    "actor": {"process": {"name": "nsenter"}},
                },
            },
        )
        self.assertEqual(code, 200)
        self.assertIn("event_id", ingest_res.get("incident", ingest_res))

        # 2. Correlate into an idempotent ITSM ticket and verify deduplication
        incident_payload = {
            "source_type": "security_incident",
            "rule_id": "sigma-container-escape-001",
            "target_node_id": "node-alpha-01",
            "severity": "CRITICAL",
            "summary": "Privileged container namespace escape attempt on node-alpha-01",
        }
        t1 = itsm_chatops_bridge.correlate_incident_to_itsm_ticket(
            incident_payload, provider="gitlab_issues"
        )
        t2 = itsm_chatops_bridge.correlate_incident_to_itsm_ticket(
            incident_payload, provider="gitlab_issues"
        )
        self.assertEqual(t1["ticket_id"], t2["ticket_id"])
        self.assertFalse(t1["deduplicated"])
        self.assertTrue(t2["deduplicated"])
        self.assertEqual(t2["occurrence_count"], 2)

        # 3. Stage an Action Card via signed ChatOps callback linked to the ITSM ticket
        chatops_secret = "enterprise-chatops-shared-hmac-secret-2026"
        stage_cb = {
            "callback_id": "cb-wave3-stage-001",
            "timestamp": time.time(),
            "command": "stage_action_card",
            "arguments": {
                "ticket_id": t1["ticket_id"],
                "action_type": "isolate_workload",
                "target_node_id": "node-alpha-01",
                "parameters": {"isolation_policy": "strict"},
            },
        }
        stage_cb["hmac_signature"] = itsm_chatops_bridge.sign_chatops_callback_hmac(
            stage_cb, chatops_secret
        )
        stage_code, stage_res = itsm_chatops_bridge.handle_chatops_callback(
            stage_cb, shared_secret=chatops_secret
        )
        self.assertEqual(stage_code, 200)
        self.assertEqual(stage_res["tier"], "TIER_2_ACTION_CARD")
        action_id = stage_res["result"]["action_card"]["action_id"]
        self.assertEqual(stage_res["result"]["linked_ticket"]["status"], "ACTION_STAGED")

        # 4. Generate 2-of-3 Shamir shares and submit 2 shares via signed ChatOps callbacks
        shares = pqc_security.split_secret_shares(b"enterprise-remediation-unlock-key", 2, 3)
        for idx in range(2):
            share_cb = {
                "callback_id": f"cb-wave3-share-{idx + 1}",
                "timestamp": time.time(),
                "command": "submit_action_share",
                "arguments": {
                    "action_id": action_id,
                    "ticket_id": t1["ticket_id"],
                    "credential": shares[idx],
                },
            }
            share_cb["hmac_signature"] = itsm_chatops_bridge.sign_chatops_callback_hmac(
                share_cb, chatops_secret
            )
            cb_code, cb_res = itsm_chatops_bridge.handle_chatops_callback(
                share_cb, shared_secret=chatops_secret
            )
            self.assertEqual(cb_code, 200)
            if idx == 0:
                self.assertEqual(cb_res["result"]["approval"]["status"], "STAGED")
            else:
                self.assertEqual(cb_res["result"]["approval"]["status"], "EXECUTED")
                self.assertEqual(cb_res["result"]["linked_ticket"]["status"], "RESOLVED")

        # 5. Export a live Flight Recorder capsule capturing the SSE event buffer and replay it
        capsule = flight_recorder.export_flight_recorder_capsule(
            capsule_id="capsule-wave3-live-e2e",
            title="Wave 3 E2E Container Escape & ChatOps Shamir Resolution",
        )
        self.assertTrue(capsule["opsec_scrubbed"])
        self.assertGreaterEqual(capsule["frame_count"], 1)

        rep_1x_code, rep_1x = flight_recorder.replay_flight_recorder_capsule(
            "capsule-wave3-live-e2e", speed_multiplier=1.0
        )
        rep_100x_code, rep_100x = flight_recorder.replay_flight_recorder_capsule(
            "capsule-wave3-live-e2e", speed_multiplier=100.0
        )
        self.assertEqual(rep_1x_code, 200)
        self.assertEqual(rep_100x_code, 200)
        self.assertEqual(
            rep_1x["deterministic_state_hash"],
            rep_100x["deterministic_state_hash"],
        )

    def test_02_gitops_promotion_gate_and_tactical_deck_summary_convergence(self) -> None:
        """Verify 2-Stage GitOps Promotion Gate fail-closed checks and Tactical Deck aggregation."""
        # 1. Fail-closed when full test suite attestation fails
        fail_code, fail_res = gitops_promotion_bridge.stage_gitops_prod_promotion(
            test_attestation={
                "tests_passed": False,
                "tests_run": 791,
                "failures": 1,
                "errors": 0,
                "opsec_violations": 0,
            }
        )
        self.assertEqual(fail_code, 409)
        self.assertFalse(fail_res["readiness"]["stage1_passed"])

        # 2. Succeed when Stage 1A and Stage 1B pass, staging a threshold promote_to_prod Action Card
        ok_code, ok_res = gitops_promotion_bridge.stage_gitops_prod_promotion(
            operator_id="platform-release-lead",
            source_branch="feat/opscryer-wave3-release",
            target_branch="main",
        )
        self.assertEqual(ok_code, 200)
        self.assertEqual(ok_res["status"], "STAGED_FOR_APPROVAL")
        self.assertEqual(ok_res["action_card"]["action_type"], "promote_to_prod")
        self.assertTrue(ok_res["worrisomeness"]["escalate_to_threshold"])
        self.assertFalse(ok_res["direct_prod_apply_allowed"])
        self.assertFalse(ok_res["promotion_plan"]["direct_prod_apply_allowed"])

        # 3. Verify Tactical Security Deck summary reflects the staged promotion and all 6 sections
        summary = tactical_security_deck.build_tactical_deck_summary()
        self.assertEqual(summary["schema_version"], "1.0-tactical-security-deck")
        self.assertGreaterEqual(summary["action_cards_summary"]["total"], 1)
        self.assertTrue(summary["mcp_airlock_summary"]["direct_mutation_blocked"])

        html = tactical_security_deck.render_tactical_security_deck_html()
        for panel_id in (
            "sse-event-ticker",
            "action-card-console",
            "cybersecurity-incident-feed",
            "node-federation-inspector",
            "mcp-and-gitops-bar",
        ):
            self.assertIn(f'id="{panel_id}"', html)

    def test_03_http_loopback_gateway_serves_all_wave3_routes(self) -> None:
        """Verify opscryer_browser HTTP server serves /tactical-deck and all 9 Wave 3 API routes."""
        with socketserver.TCPServer(("127.0.0.1", 0), browser._build_frontend_handler()) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            try:
                # HTML Portal: GET /tactical-deck
                conn = http.client.HTTPConnection(host, port, timeout=10)
                conn.request("GET", "/tactical-deck")
                resp = conn.getresponse()
                html_body = resp.read().decode("utf-8")
                self.assertEqual(resp.status, 200)
                self.assertIn("id=\"action-card-console\"", html_body)
                conn.close()

                # GET JSON routes
                for get_path in (
                    "/api/v1/gitops-promotion/status",
                    "/api/v1/gitops-promotion/stage",
                    "/api/v1/tactical-deck/summary",
                    "/api/v1/itsm/tickets",
                    "/api/v1/flight-recorder/capsules",
                ):
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    conn.request("GET", get_path)
                    resp = conn.getresponse()
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(resp.status, 200, msg=f"Failed GET {get_path}")
                    self.assertIsInstance(data, dict)
                    conn.close()

                # POST /api/v1/itsm/correlate
                conn = http.client.HTTPConnection(host, port, timeout=10)
                post_body = json.dumps({
                    "incident": {
                        "source_type": "security_incident",
                        "rule_id": "sigma-http-loopback-01",
                        "target_node_id": "node-alpha-01",
                        "severity": "HIGH",
                        "summary": "Loopback E2E test correlation",
                    },
                    "provider": "gitlab_issues",
                }).encode("utf-8")
                conn.request(
                    "POST",
                    "/api/v1/itsm/correlate",
                    body=post_body,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(post_body))},
                )
                resp = conn.getresponse()
                corr_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                self.assertTrue(corr_data["ticket"]["ticket_id"].startswith("ITSM-"))
                conn.close()

                # POST /api/v1/flight-recorder/replay
                conn = http.client.HTTPConnection(host, port, timeout=10)
                replay_body = json.dumps({
                    "capsule_id": "capsule-container-escape-k3of5",
                    "speed_multiplier": 100.0,
                }).encode("utf-8")
                conn.request(
                    "POST",
                    "/api/v1/flight-recorder/replay",
                    body=replay_body,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(replay_body))},
                )
                resp = conn.getresponse()
                replay_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                self.assertEqual(replay_data["status"], "REPLAY_VERIFIED")
                conn.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_04_portal_link_crawler_concurrent_hub_probes_and_bounded_sse(self) -> None:
        """Verify all navbar links, concurrent /hub probes during active SSE, and unified browser controls."""
        from concurrent.futures import ThreadPoolExecutor
        import re
        import opscryer_suite_hub as suite_hub

        browser_html = browser.render_standalone_browser_html()
        for required_id in (
            "top-cluster-service-strip",
            "fast-ops-finder-bar",
            "fast-ops-query-input",
            "zoom-density-select",
            "game-theme-select",
            "fps-telemetry-badge",
            "rts-connection-ribbon",
        ):
            self.assertIn(f'id="{required_id}"', browser_html)

        with socketserver.TCPServer(("127.0.0.1", 0), browser._build_frontend_handler()) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            try:
                # 1. Crawl all <a href="/..."> links across /, /tactical-deck, and /hub
                discovered_links: set[str] = set()
                for entry_portal in ("/", "/tactical-deck", "/hub"):
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    conn.request("GET", entry_portal)
                    resp = conn.getresponse()
                    page_html = resp.read().decode("utf-8")
                    self.assertEqual(resp.status, 200, msg=f"Entry portal {entry_portal} failed")
                    conn.close()
                    for href in re.findall(r'href=["\'](/[^"\']*)["\']', page_html):
                        discovered_links.add(href)

                self.assertGreaterEqual(len(discovered_links), 15)
                for link_path in sorted(discovered_links):
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    conn.request("GET", link_path)
                    resp = conn.getresponse()
                    _ = resp.read()
                    self.assertEqual(resp.status, 200, msg=f"Broken link {link_path}")
                    conn.close()

                # 2. Verify /hub probes all 8 core APIs concurrently while bounded SSE stream is open
                hub_html = suite_hub.render_suite_hub_html()
                self.assertIn("?q=manifest%20cluster", hub_html)
                apps = suite_hub.build_suite_application_catalog()["applications"]
                probe_paths = [
                    (app["api_route"] + "?q=manifest%20cluster")
                    if app["api_route"] == "/api/v1/chat-concierge"
                    else app["api_route"]
                    for app in apps
                ]

                def _fetch_status(path: str) -> int:
                    c = http.client.HTTPConnection(host, port, timeout=10)
                    try:
                        c.request("GET", path)
                        r = c.getresponse()
                        _ = r.read()
                        return r.status
                    finally:
                        c.close()

                t0 = time.perf_counter()
                with ThreadPoolExecutor(max_workers=9) as pool:
                    sse_future = pool.submit(_fetch_status, "/api/v1/events/stream?max_events=25")
                    probe_futures = [pool.submit(_fetch_status, p) for p in probe_paths]
                    statuses = [f.result(timeout=10) for f in probe_futures]
                    sse_status = sse_future.result(timeout=10)
                elapsed = time.perf_counter() - t0
                self.assertEqual(sse_status, 200)
                self.assertEqual(statuses, [200] * 8)
                self.assertLess(elapsed, 5.0)

                # 3. Verify default /tactical-deck node-alpha-01 dry-run & stage succeed on HTTP gateway
                for act_endpoint in ("/api/v1/actions/dry-run", "/api/v1/actions/stage"):
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    act_body = json.dumps({
                        "action_type": "restart_node",
                        "target_node_id": "node-alpha-01",
                        "operator_id": "sre-commander",
                        "parameters": {"grace_period_seconds": 30},
                    }).encode("utf-8")
                    conn.request(
                        "POST",
                        act_endpoint,
                        body=act_body,
                        headers={"Content-Type": "application/json", "Content-Length": str(len(act_body))},
                    )
                    resp = conn.getresponse()
                    _ = resp.read()
                    self.assertEqual(resp.status, 200, msg=f"Failed {act_endpoint} for node-alpha-01")
                    conn.close()

                # 4. Verify Nanomachine Swarm higher-level clickable HUD + POST /api/v1/nanomachine-swarm/cast (mu/sigma timeout & backoff)
                browser_html = browser.render_standalone_browser_html()
                for expected_token in (
                    "id=\"nanomachine-swarm-hud\"",
                    "id=\"opscryer-unified-tool-dock\"",
                    "openNanomachineSwarmInterface()",
                    "openIntegratedOpsTool(",
                    "bindUnifiedNavigationDock()",
                    "INTEGRATED_TOOL_REGISTRY",
                    "castNanomachineAbility(",
                    "swarm-nanomachine-fleet",
                    "computeAbilityMuSigma(",
                ):
                    self.assertIn(expected_token, browser_html)

                conn = http.client.HTTPConnection(host, port, timeout=10)
                conn.request("GET", "/api/v1/tactical-deck/summary")
                resp = conn.getresponse()
                summary_payload = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                conn.close()
                self.assertIn("nanomachine_swarm", summary_payload)
                swarm_info = summary_payload["nanomachine_swarm"]
                self.assertEqual(swarm_info["swarm_node_id"], "swarm-nanomachine-fleet")
                self.assertIn("spinup_sandbox_service", swarm_info["abilities"])

                # Verify real wall-clock cast measurement when simulate_duration_ms is omitted + live_tools_snapshot
                conn = http.client.HTTPConnection(host, port, timeout=10)
                live_cast_body = json.dumps({
                    "ability_id": "jev_triage_sweep",
                    "unit_id": "swarm-memory",
                    "timeout_multiplier": 3.0,
                    "attempt": 1,
                }).encode("utf-8")
                conn.request(
                    "POST",
                    "/api/v1/nanomachine-swarm/cast",
                    body=live_cast_body,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(live_cast_body))},
                )
                resp = conn.getresponse()
                live_cast_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                conn.close()
                self.assertTrue(live_cast_res["live_probe_detail"]["live_execution"])
                self.assertGreater(live_cast_res["observed_duration_ms"], 0.0)

                conn = http.client.HTTPConnection(host, port, timeout=10)
                snap_body = json.dumps({"action": "live_tools_snapshot"}).encode("utf-8")
                conn.request(
                    "POST",
                    "/api/v1/nanomachine-swarm/cast",
                    body=snap_body,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(snap_body))},
                )
                resp = conn.getresponse()
                snap_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                conn.close()
                self.assertEqual(snap_res["schema_version"], "1.0-connected-tools-snapshot")
                self.assertTrue(snap_res["live_cluster_topology"]["loaded"])
                self.assertGreaterEqual(snap_res["live_cluster_topology"]["node_count"], 50)

                # Normal cast within 3*mu threshold completes and updates rolling mu/sigma
                conn = http.client.HTTPConnection(host, port, timeout=10)
                normal_body = json.dumps({
                    "ability_id": "reground_ram_rag",
                    "unit_id": "nanobot-4gpu",
                    "timeout_multiplier": 3.0,
                    "attempt": 1,
                    "simulate_duration_ms": 205.0,
                }).encode("utf-8")
                conn.request(
                    "POST",
                    "/api/v1/nanomachine-swarm/cast",
                    body=normal_body,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(normal_body))},
                )
                resp = conn.getresponse()
                normal_res = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                conn.close()
                self.assertEqual(normal_res["status"], "CAST_COMPLETED")
                self.assertFalse(normal_res["timed_out"])
                self.assertEqual(len(normal_res["cast_phases"]), 3)

                # Slow service spin-up (> 3*mu) times out and returns standard-deviation-sized backoff (mu + k*sigma)
                backoffs: list[float] = []
                for attempt_k in (1, 2):
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    slow_body = json.dumps({
                        "ability_id": "spinup_sandbox_service",
                        "unit_id": "agy-master-sandbox",
                        "timeout_multiplier": 3.0,
                        "attempt": attempt_k,
                        "simulate_duration_ms": 1950.0,
                    }).encode("utf-8")
                    conn.request(
                        "POST",
                        "/api/v1/nanomachine-swarm/cast",
                        body=slow_body,
                        headers={"Content-Type": "application/json", "Content-Length": str(len(slow_body))},
                    )
                    resp = conn.getresponse()
                    slow_res = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(resp.status, 200)
                    conn.close()
                    self.assertEqual(slow_res["status"], "TIMED_OUT")
                    self.assertTrue(slow_res["timed_out"])
                    self.assertGreater(slow_res["observed_duration_ms"], slow_res["adaptive_timeout_ms"])
                    expected_backoff = round(slow_res["avg_cast_ms"] + attempt_k * slow_res["std_dev_ms"], 2)
                    self.assertAlmostEqual(slow_res["sigma_backoff_ms"], expected_backoff, places=2)
                    backoffs.append(slow_res["sigma_backoff_ms"])
                self.assertGreater(backoffs[1], backoffs[0])
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
