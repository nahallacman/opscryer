# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit test suite for Deterministic Flight Recorder & Chaos GameDay Replay (Piece M14).

Covers:
1. Pre-seeded built-in GameDay capsules (capsule-container-escape-k3of5,
   capsule-prolonged-severance-encrypt-and-rest, capsule-warrant-reconnect-quarantine-merge)
   and deterministic state hash invariance across 1.0x and 100.0x replay speeds.
2. Custom PQC-signed capsule export, live telemetry snapshot collection, JSONL
   round-trip serialization, and OPSEC / security_airlock scrubbing.
3. Adversarial tamper detection (422 TAMPER_DETECTED) across frame payloads,
   prev_frame_hash links, final_chain_hash, WOTS+ signature chunks, and public keys.
4. HTTP REST API dispatcher (/api/v1/flight-recorder/capsules, /export, /replay).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import threading
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import action_cards
import cybersecurity_bridge
import event_stream
import flight_recorder
from flight_recorder import (
    BUILTIN_CAPSULE_ESCAPE,
    BUILTIN_CAPSULE_IDS,
    BUILTIN_CAPSULE_SEVERANCE,
    BUILTIN_CAPSULE_WARRANT_MERGE,
    GENESIS_CHAIN_HASH,
    capsule_from_jsonl,
    capsule_to_jsonl,
    export_flight_recorder_capsule,
    get_flight_recorder_capsule,
    handle_flight_recorder_api,
    list_flight_recorder_capsules,
    replay_flight_recorder_capsule,
    reset_flight_recorder,
)
import pqc_security


class TestFlightRecorderAndGameDayReplay(unittest.TestCase):
    """Test suite for flight_recorder.py deterministic export, verification, and replay."""

    def setUp(self) -> None:
        reset_flight_recorder()
        event_stream.reset_event_buffer()
        action_cards.reset_action_ledger()
        cybersecurity_bridge.reset_security_bridge()

    def tearDown(self) -> None:
        reset_flight_recorder()

    def test_01_list_builtin_gameday_capsules(self) -> None:
        """Verify all 3 built-in GameDay capsules are pre-seeded, chained, and PQC-signed."""
        capsules = list_flight_recorder_capsules()
        self.assertEqual(len(capsules), 3)
        found_ids = [c["capsule_id"] for c in capsules]
        self.assertEqual(tuple(found_ids), BUILTIN_CAPSULE_IDS)

        for cap in capsules:
            self.assertTrue(cap["opsec_scrubbed"])
            self.assertGreater(cap["frame_count"], 0)
            self.assertEqual(len(cap["frames"]), cap["frame_count"])
            self.assertEqual(cap["frames"][0]["prev_frame_hash"], GENESIS_CHAIN_HASH)
            self.assertEqual(cap["final_chain_hash"], cap["frames"][-1]["frame_hash"])
            self.assertIn("pqc_signature", cap)
            self.assertIn("signer_pubkey", cap)
            self.assertEqual(cap["pqc_signature"]["algorithm"], "WOTS-Merkle-SHA3")

    def test_02_replay_capsule_container_escape_k3of5_1x_and_100x(self) -> None:
        """Replay capsule-container-escape-k3of5 at 1.0x and 100.0x and assert identical state hash."""
        status_1x, report_1x = replay_flight_recorder_capsule(
            BUILTIN_CAPSULE_ESCAPE, speed_multiplier=1.0
        )
        self.assertEqual(status_1x, 200)
        self.assertEqual(report_1x["status"], "REPLAY_VERIFIED")
        self.assertTrue(report_1x["verified"])
        self.assertEqual(report_1x["capsule_id"], BUILTIN_CAPSULE_ESCAPE)
        self.assertEqual(report_1x["frames_replayed"], 5)
        self.assertEqual(report_1x["speed_multiplier"], 1.0)

        inv = report_1x["invariants_verified"]
        self.assertGreaterEqual(inv["sigma_hits"], 1)
        self.assertEqual(inv["required_k"], 3)
        self.assertEqual(inv["required_n"], 5)
        self.assertEqual(inv["action_card_status"], "EXECUTED")
        self.assertTrue(inv["idempotent_replay_cached"])

        status_100x, report_100x = replay_flight_recorder_capsule(
            BUILTIN_CAPSULE_ESCAPE, speed_multiplier=100.0
        )
        self.assertEqual(status_100x, 200)
        self.assertEqual(report_100x["status"], "REPLAY_VERIFIED")
        self.assertEqual(report_100x["speed_multiplier"], 100.0)
        self.assertEqual(
            report_1x["deterministic_state_hash"],
            report_100x["deterministic_state_hash"],
        )

    def test_03_replay_capsule_prolonged_severance_encrypt_and_rest_1x_and_100x(self) -> None:
        """Replay capsule-prolonged-severance-encrypt-and-rest at 1.0x and 100.0x speeds."""
        status_1x, report_1x = replay_flight_recorder_capsule(
            BUILTIN_CAPSULE_SEVERANCE, speed_multiplier=1.0
        )
        self.assertEqual(status_1x, 200)
        self.assertEqual(report_1x["status"], "REPLAY_VERIFIED")
        self.assertTrue(report_1x["verified"])
        self.assertEqual(report_1x["frames_replayed"], 4)

        inv = report_1x["invariants_verified"]
        self.assertEqual(
            inv["severance_transitions"],
            ["ACTIVE", "SOFT_QUARANTINE", "ENCRYPT_AND_REST"],
        )
        self.assertEqual(inv["severance_state"], "ENCRYPT_AND_REST")
        self.assertTrue(inv["ram_secrets_zeroized"])
        self.assertTrue(inv["master_unseal_verified"])

        status_100x, report_100x = replay_flight_recorder_capsule(
            BUILTIN_CAPSULE_SEVERANCE, speed_multiplier=100.0
        )
        self.assertEqual(status_100x, 200)
        self.assertEqual(
            report_1x["deterministic_state_hash"],
            report_100x["deterministic_state_hash"],
        )

    def test_04_replay_capsule_warrant_reconnect_quarantine_merge_1x_and_100x(self) -> None:
        """Replay capsule-warrant-reconnect-quarantine-merge at 1.0x and 100.0x speeds."""
        status_1x, report_1x = replay_flight_recorder_capsule(
            BUILTIN_CAPSULE_WARRANT_MERGE, speed_multiplier=1.0
        )
        self.assertEqual(status_1x, 200)
        self.assertEqual(report_1x["status"], "REPLAY_VERIFIED")
        self.assertTrue(report_1x["verified"])
        self.assertEqual(report_1x["frames_replayed"], 3)

        inv = report_1x["invariants_verified"]
        self.assertEqual(inv["severance_state"], "PERSIST_RESIST_REGROW")
        self.assertEqual(inv["quarantine_merge_status"], "QUARANTINE_MERGED")
        self.assertTrue(inv["canonical_master_keys_preserved"])
        self.assertEqual(inv["conflicts_staged"], 1)

        status_100x, report_100x = replay_flight_recorder_capsule(
            BUILTIN_CAPSULE_WARRANT_MERGE, speed_multiplier=100.0
        )
        self.assertEqual(status_100x, 200)
        self.assertEqual(
            report_1x["deterministic_state_hash"],
            report_100x["deterministic_state_hash"],
        )

    def test_05_export_custom_capsule_and_replay(self) -> None:
        """Export a custom capsule with explicit frames, verify hash chain, and replay."""
        custom_frames = [
            {
                "frame_type": "severance_evaluation",
                "logical_ts": 1700010000.0,
                "payload": {
                    "target_node_id": "node-edge-02",
                    "elapsed_since_master_heartbeat": 3.0,
                    "grace_period": 5.0,
                    "severance_threshold": 30.0,
                },
            },
            {
                "frame_type": "severance_evaluation",
                "logical_ts": 1700010020.0,
                "payload": {
                    "target_node_id": "node-edge-02",
                    "elapsed_since_master_heartbeat": 20.0,
                    "grace_period": 5.0,
                    "severance_threshold": 30.0,
                },
            },
        ]
        cap = export_flight_recorder_capsule(
            capsule_id="capsule-custom-edge-check",
            title="Custom Edge Quarantine Capsule",
            frames=custom_frames,
        )
        self.assertEqual(cap["capsule_id"], "capsule-custom-edge-check")
        self.assertEqual(cap["frame_count"], 2)
        self.assertEqual(cap["frames"][0]["frame_index"], 0)
        self.assertEqual(cap["frames"][0]["prev_frame_hash"], GENESIS_CHAIN_HASH)
        self.assertEqual(cap["frames"][1]["frame_index"], 1)
        self.assertEqual(cap["frames"][1]["prev_frame_hash"], cap["frames"][0]["frame_hash"])
        self.assertEqual(cap["final_chain_hash"], cap["frames"][1]["frame_hash"])

        # Verify capsule was registered in store and can be replayed by ID
        stored = get_flight_recorder_capsule("capsule-custom-edge-check")
        self.assertIsNotNone(stored)

        code, rep = replay_flight_recorder_capsule("capsule-custom-edge-check", speed_multiplier=25.0)
        self.assertEqual(code, 200)
        self.assertEqual(rep["status"], "REPLAY_VERIFIED")
        self.assertEqual(rep["invariants_verified"]["severance_state"], "SOFT_QUARANTINE")

    def test_06_export_live_snapshot_when_frames_none(self) -> None:
        """Verify live telemetry collection when frames=None."""
        event_stream.publish_event("system", "node_heartbeat_ok", {"node_id": "node-alpha-01"})
        action_cards.stage_action_card(
            target_node_id="node-edge-01",
            action_type="restart_node",
            parameters={"reason": "live-snapshot-test"},
            catalog=flight_recorder._CLEAN_REPLAY_CATALOG,
        )

        live_cap = export_flight_recorder_capsule(
            capsule_id="capsule-live-snapshot-01",
            title="Live Telemetry Snapshot",
            frames=None,
        )
        self.assertGreaterEqual(live_cap["frame_count"], 3)
        frame_types = {f["frame_type"] for f in live_cap["frames"]}
        self.assertIn("event_stream_snapshot", frame_types)
        self.assertIn("action_card_snapshot", frame_types)
        self.assertIn("federation_status_snapshot", frame_types)

        code, rep = replay_flight_recorder_capsule(live_cap, speed_multiplier=50.0)
        self.assertEqual(code, 200)
        self.assertTrue(rep["verified"])

    def test_07_jsonl_serialization_round_trip(self) -> None:
        """Verify capsule_to_jsonl and capsule_from_jsonl preserve cryptographic integrity."""
        original = get_flight_recorder_capsule(BUILTIN_CAPSULE_ESCAPE)
        self.assertIsNotNone(original)
        assert original is not None

        jsonl_str = capsule_to_jsonl(original)
        lines = [ln for ln in jsonl_str.splitlines() if ln.strip()]
        # 1 header line + 5 frame lines = 6 lines
        self.assertEqual(len(lines), 6)

        restored = capsule_from_jsonl(jsonl_str)
        self.assertEqual(restored["capsule_id"], original["capsule_id"])
        self.assertEqual(restored["final_chain_hash"], original["final_chain_hash"])
        self.assertEqual(restored["pqc_signature"], original["pqc_signature"])
        self.assertEqual(len(restored["frames"]), len(original["frames"]))

        code_orig, rep_orig = replay_flight_recorder_capsule(original, speed_multiplier=10.0)
        code_rest, rep_rest = replay_flight_recorder_capsule(restored, speed_multiplier=10.0)
        self.assertEqual(code_orig, 200)
        self.assertEqual(code_rest, 200)
        self.assertEqual(
            rep_orig["deterministic_state_hash"],
            rep_rest["deterministic_state_hash"],
        )

    def test_08_opsec_and_security_airlock_scrubbing(self) -> None:
        """Verify OPSEC sanitizer scrubs secrets, WAN IPs, zero-width chars, and restricted tokens."""
        restricted_domain = "".join(("ho", "me", ".", "ar", "pa"))
        restricted_host = "".join(("minis", "forum", "001"))
        restricted_ip = ".".join(("192", "168", "1", "99"))
        wan_ip = ".".join(("8", "8", "8", "8"))

        dirty_frames = [
            {
                "frame_type": "custom_frame",
                "logical_ts": 1700020000.0,
                "payload": {
                    "target_host": f"https://portal.{restricted_domain}",
                    "node_name": f"{restricted_host}\u200b",
                    "internal_ip": restricted_ip,
                    "wan_ip": wan_ip,
                    "password": "super-secret-password-123",
                    "auth_header": "Bearer secret-jwt-token-xyz",
                },
            }
        ]
        scrubbed_cap = export_flight_recorder_capsule(
            capsule_id="capsule-opsec-scrub-test",
            title=f"Incident on {restricted_host}",
            frames=dirty_frames,
        )
        serialized = json.dumps(scrubbed_cap)
        self.assertNotIn(restricted_domain, serialized)
        self.assertNotIn(restricted_host, serialized)
        self.assertNotIn(restricted_ip, serialized)
        self.assertNotIn(wan_ip, serialized)
        self.assertNotIn("super-secret-password-123", serialized)
        self.assertNotIn("\u200b", serialized)

        payload_out = scrubbed_cap["frames"][0]["payload"]
        self.assertEqual(payload_out["target_host"], "https://portal.example.org")
        self.assertEqual(payload_out["node_name"], "node-alpha-01")
        self.assertEqual(payload_out["internal_ip"], "203.0.113.10")
        self.assertEqual(payload_out["wan_ip"], "203.0.113.1")
        self.assertEqual(payload_out["password"], "[REDACTED]")
        self.assertEqual(payload_out["auth_header"], "Bearer [REDACTED]")

    def test_09_tamper_detection_frame_payload_modified(self) -> None:
        """Verify modifying any frame payload field triggers 422 TAMPER_DETECTED."""
        cap = get_flight_recorder_capsule(BUILTIN_CAPSULE_ESCAPE)
        assert cap is not None
        tampered = copy.deepcopy(cap)
        tampered["frames"][1]["payload"]["expected_k"] = 1

        code, res = replay_flight_recorder_capsule(tampered)
        self.assertEqual(code, 422)
        self.assertEqual(res["status"], "TAMPER_DETECTED")
        self.assertFalse(res["verified"])
        self.assertIn("frame_hash mismatch", res["error"])

    def test_10_tamper_detection_prev_frame_hash_broken(self) -> None:
        """Verify breaking the prev_frame_hash link between frames triggers 422 TAMPER_DETECTED."""
        cap = get_flight_recorder_capsule(BUILTIN_CAPSULE_SEVERANCE)
        assert cap is not None
        tampered = copy.deepcopy(cap)
        tampered["frames"][2]["prev_frame_hash"] = "f" * 64

        code, res = replay_flight_recorder_capsule(tampered)
        self.assertEqual(code, 422)
        self.assertEqual(res["status"], "TAMPER_DETECTED")
        self.assertFalse(res["verified"])
        self.assertIn("prev_frame_hash mismatch", res["error"])

    def test_11_tamper_detection_final_chain_hash_modified(self) -> None:
        """Verify altering final_chain_hash triggers 422 TAMPER_DETECTED."""
        cap = get_flight_recorder_capsule(BUILTIN_CAPSULE_WARRANT_MERGE)
        assert cap is not None
        tampered = copy.deepcopy(cap)
        tampered["final_chain_hash"] = "a" * 64

        code, res = replay_flight_recorder_capsule(tampered)
        self.assertEqual(code, 422)
        self.assertEqual(res["status"], "TAMPER_DETECTED")
        self.assertFalse(res["verified"])

    def test_12_tamper_detection_pqc_signature_corrupted(self) -> None:
        """Verify corrupting a WOTS+ signature chunk triggers 422 TAMPER_DETECTED."""
        cap = get_flight_recorder_capsule(BUILTIN_CAPSULE_ESCAPE)
        assert cap is not None
        tampered = copy.deepcopy(cap)
        first_chunk = tampered["pqc_signature"]["signature_chunks"][0]
        # Flip the first hex character of chunk 0 to invalidate the WOTS+ chain
        flipped_char = "0" if first_chunk[0] != "0" else "1"
        tampered["pqc_signature"]["signature_chunks"][0] = flipped_char + first_chunk[1:]

        code, res = replay_flight_recorder_capsule(tampered)
        self.assertEqual(code, 422)
        self.assertEqual(res["status"], "TAMPER_DETECTED")
        self.assertFalse(res["verified"])
        self.assertIn("PQC signature verification failed", res["error"])

    def test_13_tamper_detection_wrong_signer_pubkey(self) -> None:
        """Verify substituting an unauthorized WOTS+ public key triggers 422 TAMPER_DETECTED."""
        cap = get_flight_recorder_capsule(BUILTIN_CAPSULE_SEVERANCE)
        assert cap is not None
        tampered = copy.deepcopy(cap)
        rogue_pub, _ = pqc_security.generate_pqc_keypair(tree_height=2, seed=b"rogue-attacker-seed-000000000000")
        tampered["signer_pubkey"] = rogue_pub

        code, res = replay_flight_recorder_capsule(tampered)
        self.assertEqual(code, 422)
        self.assertEqual(res["status"], "TAMPER_DETECTED")
        self.assertFalse(res["verified"])

    def test_14_speed_multiplier_bounds_validation(self) -> None:
        """Verify speed_multiplier outside [1.0, 100.0] or non-numeric returns 400."""
        invalid_speeds = [0.0, 0.99, -5.0, 100.01, 500.0, float("nan"), float("inf"), True, "fast"]
        for bad_speed in invalid_speeds:
            code, res = replay_flight_recorder_capsule(
                BUILTIN_CAPSULE_ESCAPE,
                speed_multiplier=bad_speed,  # type: ignore[arg-type]
            )
            self.assertEqual(code, 400, f"Expected 400 for speed={bad_speed}")
            self.assertEqual(res["status"], "INVALID_SPEED_MULTIPLIER")
            self.assertFalse(res["verified"])

    def test_15_replay_unknown_capsule_id_returns_404(self) -> None:
        """Verify replaying a non-existent capsule_id returns 404 CAPSULE_NOT_FOUND."""
        code, res = replay_flight_recorder_capsule("capsule-does-not-exist-404")
        self.assertEqual(code, 404)
        self.assertEqual(res["status"], "CAPSULE_NOT_FOUND")
        self.assertFalse(res["verified"])

    def test_16_http_api_get_capsules_and_filter(self) -> None:
        """Test GET /api/v1/flight-recorder/capsules listing and single capsule_id filter."""
        code, body = handle_flight_recorder_api("/api/v1/flight-recorder/capsules", method="GET")
        self.assertEqual(code, 200)
        self.assertEqual(body["total_capsules"], 3)
        self.assertEqual(len(body["capsules"]), 3)

        # Filtered query for a specific built-in capsule
        code_f, body_f = handle_flight_recorder_api(
            "/api/v1/flight-recorder/capsules",
            method="GET",
            query={"capsule_id": [BUILTIN_CAPSULE_WARRANT_MERGE]},
        )
        self.assertEqual(code_f, 200)
        self.assertEqual(body_f["total_capsules"], 1)
        self.assertEqual(body_f["capsules"][0]["capsule_id"], BUILTIN_CAPSULE_WARRANT_MERGE)

        # Filtered query for unknown capsule returns 404
        code_404, _ = handle_flight_recorder_api(
            "/api/v1/flight-recorder/capsules",
            method="GET",
            query={"capsule_id": ["unknown-capsule"]},
        )
        self.assertEqual(code_404, 404)

    def test_17_http_api_post_export_and_get_descriptor(self) -> None:
        """Test POST and GET on /api/v1/flight-recorder/export."""
        code_get, desc = handle_flight_recorder_api("/api/v1/flight-recorder/export", method="GET")
        self.assertEqual(code_get, 200)
        self.assertEqual(desc["endpoint"], "/api/v1/flight-recorder/export")

        export_req = {
            "capsule_id": "capsule-api-exported-01",
            "title": "API Exported Capsule",
            "frames": [
                {
                    "frame_type": "severance_evaluation",
                    "logical_ts": 1700030000.0,
                    "payload": {
                        "target_node_id": "node-edge-01",
                        "elapsed_since_master_heartbeat": 40.0,
                    },
                }
            ],
        }
        code_post, resp = handle_flight_recorder_api(
            "/api/v1/flight-recorder/export",
            method="POST",
            body=json.dumps(export_req),
        )
        self.assertEqual(code_post, 200)
        self.assertEqual(resp["status"], "EXPORTED")
        self.assertEqual(resp["capsule_id"], "capsule-api-exported-01")
        self.assertEqual(resp["frame_count"], 1)
        self.assertIn("jsonl", resp)

    def test_18_http_api_post_replay_by_id_and_inline_capsule(self) -> None:
        """Test POST /api/v1/flight-recorder/replay by capsule_id, inline capsule, and tampered capsule."""
        # 1. Replay by capsule_id
        code_id, resp_id = handle_flight_recorder_api(
            "/api/v1/flight-recorder/replay",
            method="POST",
            body={"capsule_id": BUILTIN_CAPSULE_ESCAPE, "speed_multiplier": 50.0},
        )
        self.assertEqual(code_id, 200)
        self.assertEqual(resp_id["status"], "REPLAY_VERIFIED")
        self.assertEqual(resp_id["speed_multiplier"], 50.0)

        # 2. Replay by inline capsule object
        cap_obj = get_flight_recorder_capsule(BUILTIN_CAPSULE_SEVERANCE)
        assert cap_obj is not None
        code_inline, resp_inline = handle_flight_recorder_api(
            "/api/v1/flight-recorder/replay",
            method="POST",
            body={"capsule": cap_obj, "speed_multiplier": 100.0},
        )
        self.assertEqual(code_inline, 200)
        self.assertEqual(resp_inline["status"], "REPLAY_VERIFIED")

        # 3. Replay tampered inline capsule -> 422 TAMPER_DETECTED
        tampered = copy.deepcopy(cap_obj)
        tampered["frames"][0]["payload"]["elapsed_since_master_heartbeat"] = 999.0
        code_tamp, resp_tamp = handle_flight_recorder_api(
            "/api/v1/flight-recorder/replay",
            method="POST",
            body={"capsule": tampered, "speed_multiplier": 100.0},
        )
        self.assertEqual(code_tamp, 422)
        self.assertEqual(resp_tamp["status"], "TAMPER_DETECTED")

    def test_19_http_api_error_handling_and_method_not_allowed(self) -> None:
        """Verify 400, 404, and 405 responses across HTTP API dispatcher routes."""
        code_405, _ = handle_flight_recorder_api("/api/v1/flight-recorder/capsules", method="POST")
        self.assertEqual(code_405, 405)

        code_del, _ = handle_flight_recorder_api("/api/v1/flight-recorder/replay", method="DELETE")
        self.assertEqual(code_del, 405)

        code_404, _ = handle_flight_recorder_api("/api/v1/flight-recorder/unknown", method="GET")
        self.assertEqual(code_404, 404)

        code_bad_json, _ = handle_flight_recorder_api(
            "/api/v1/flight-recorder/replay",
            method="POST",
            body="{malformed-json",
        )
        self.assertEqual(code_bad_json, 400)

        code_missing, _ = handle_flight_recorder_api(
            "/api/v1/flight-recorder/replay",
            method="POST",
            body={},
        )
        self.assertEqual(code_missing, 400)

    def test_20_thread_safe_concurrent_exports_and_replays(self) -> None:
        """Verify thread safety under concurrent capsule export and deterministic replay."""
        num_threads = 6
        barrier = threading.Barrier(num_threads)
        hashes_collected: list[str] = []
        errors: list[str] = []
        lock = threading.Lock()

        def worker(tid: int) -> None:
            try:
                barrier.wait()
                export_flight_recorder_capsule(
                    capsule_id=f"capsule-thread-{tid}",
                    title=f"Concurrent Capsule {tid}",
                    frames=[
                        {
                            "frame_type": "severance_evaluation",
                            "logical_ts": 1700040000.0 + tid,
                            "payload": {
                                "target_node_id": "node-edge-01",
                                "elapsed_since_master_heartbeat": 2.0,
                            },
                        }
                    ],
                )
                code, rep = replay_flight_recorder_capsule(
                    BUILTIN_CAPSULE_ESCAPE,
                    speed_multiplier=100.0 if (tid % 2 == 0) else 1.0,
                )
                with lock:
                    # Record state hash if replay succeeded; otherwise record error
                    if code == 200 and rep.get("verified"):
                        hashes_collected.append(rep["deterministic_state_hash"])
                    else:
                        errors.append(f"Thread {tid} failed with code={code}")
            except Exception as exc:
                with lock:
                    errors.append(str(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(hashes_collected), num_threads)
        # All threads (both 1.0x and 100.0x) must produce the exact same state hash
        self.assertEqual(len(set(hashes_collected)), 1)


if __name__ == "__main__":
    unittest.main()
