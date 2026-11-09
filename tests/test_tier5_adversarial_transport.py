# SPDX-License-Identifier: Apache-2.0
"""Tier 5 Adversarial Coverage Hardening Suite: Connectability & Transport Whitebox.

Targets whitebox edge cases, unexercised branches, exception handling paths,
and boundary conditions in:
1. http_transport.py (circuit breakers, status code matrix, HTTPResponseBytes, retry loop)
2. webhook_notifier.py (URL hierarchy, OPSEC sanitization, severities, convenience triggers)
3. metrics_exporter.py (Prometheus formatting, label escaping, collectors, numeric bounds)
4. opscryer_browser.py (probes, query param allowlists, HEAD requests, 405 handling, logging)
"""

from __future__ import annotations

import concurrent.futures
import datetime
import http.client
import io
import json
import logging
import math
import os
from pathlib import Path
import re
import socket
import socketserver
import sys
import threading
import time
from typing import Any
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
from urllib.request import Request

# Ensure target modules can be imported
_SUITE_ROOT = Path(__file__).resolve().parent.parent
if str(_SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SUITE_ROOT))

from http_transport import (
    NON_RETRYABLE_STATUS_CODES,
    RETRYABLE_STATUS_CODES,
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitBreakerRegistry,
    CircuitState,
    HTTPResponseBytes,
    clear_circuit_breakers,
    get_circuit_breaker,
    reset_circuit_breakers,
    urlopen_with_retry,
)
import metrics_exporter
import opscryer_config
from webhook_notifier import (
    SCHEMA_VERSION,
    VALID_SEVERITIES,
    build_webhook_payload,
    dispatch_webhook_event,
    get_default_cluster_metadata,
    notify_cluster_degraded,
    notify_hotspot_detected,
    notify_jev_escalation,
    resolve_webhook_url,
)
from opscryer_browser import (
    GATEWAY_VERSION,
    StructuredJsonFormatter,
    _build_frontend_handler,
    configure_gateway_logging,
    get_effective_log_level,
)


class TestTier5HttpTransportWhitebox(unittest.TestCase):
    """Whitebox adversarial tests for http_transport.py."""

    def setUp(self) -> None:
        reset_circuit_breakers(clear=True)

    def tearDown(self) -> None:
        reset_circuit_breakers(clear=True)

    def test_http_response_bytes_read_boundaries_and_context_manager(self) -> None:
        """Whitebox: HTTPResponseBytes read() behavior with various amounts and context manager."""
        payload = b"0123456789abcdef"
        resp = HTTPResponseBytes(payload)

        # Basic bytes container compatibility
        self.assertEqual(bytes(resp), payload)
        self.assertEqual(len(resp), 16)
        self.assertEqual(resp[:4], b"0123")

        # read(None) returns all bytes
        self.assertEqual(resp.read(None), payload)

        # read(0) returns empty bytes
        self.assertEqual(resp.read(0), b"")

        # read(5) returns first 5 bytes
        self.assertEqual(resp.read(5), b"01234")

        # read(100) returns all bytes when amount exceeds length
        self.assertEqual(resp.read(100), payload)

        # read(-1): self[:-1] slices off the last byte in the current implementation
        self.assertEqual(resp.read(-1), payload[:-1])

        # Context manager protocol
        with resp as r:
            self.assertIs(r, resp)
            self.assertEqual(r.read(4), b"0123")

    def test_status_code_matrix_breaker_recording_asymmetry(self) -> None:
        """Whitebox: Behavioral asymmetry between non-retryable 4xx codes on circuit breakers.

        In http_transport.py:
        - 400, 401, 403, 404, 405, 410, 422: in NON_RETRYABLE_STATUS_CODES -> fail fast, NO breaker failure.
        - 408, 409, 418: NOT in NON_RETRYABLE_STATUS_CODES and NOT retryable -> fail fast, DOES record breaker failure!
        """
        breaker_name_400 = "cb_status_400"
        b_400 = get_circuit_breaker(breaker_name_400, failure_threshold=2)

        # 1. Status 400: must fail fast without recording breaker failure
        mock_opener_400 = MagicMock()
        mock_opener_400.side_effect = urllib.error.HTTPError("http://api", 400, "Bad Request", {}, None)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urlopen_with_retry("http://api", circuit_breaker_name=breaker_name_400, opener=mock_opener_400)
        self.assertEqual(ctx.exception.code, 400)
        self.assertEqual(b_400.snapshot()["consecutive_failures"], 0)
        self.assertEqual(b_400.snapshot()["total_failures"], 0)
        self.assertEqual(b_400.state, CircuitState.CLOSED)

        # 2. Status 404: must fail fast without recording breaker failure
        breaker_name_404 = "cb_status_404"
        b_404 = get_circuit_breaker(breaker_name_404, failure_threshold=2)
        mock_opener_404 = MagicMock()
        mock_opener_404.side_effect = urllib.error.HTTPError("http://api", 404, "Not Found", {}, None)
        with self.assertRaises(urllib.error.HTTPError):
            urlopen_with_retry("http://api", circuit_breaker_name=breaker_name_404, opener=mock_opener_404)
        self.assertEqual(b_404.snapshot()["consecutive_failures"], 0)

        # 3. Status 408 (Request Timeout) & 409 (Conflict): NOT in NON_RETRYABLE_STATUS_CODES
        # They fail fast (not retryable), BUT they record breaker failure!
        breaker_name_408 = "cb_status_408"
        b_408 = get_circuit_breaker(breaker_name_408, failure_threshold=2)
        mock_opener_408 = MagicMock()
        mock_opener_408.side_effect = urllib.error.HTTPError("http://api", 408, "Request Timeout", {}, None)

        with self.assertRaises(urllib.error.HTTPError):
            urlopen_with_retry("http://api", circuit_breaker_name=breaker_name_408, opener=mock_opener_408)
        self.assertEqual(b_408.snapshot()["consecutive_failures"], 1)
        self.assertEqual(b_408.snapshot()["total_failures"], 1)

        # Second failure trips b_408 to OPEN
        with self.assertRaises(urllib.error.HTTPError):
            urlopen_with_retry("http://api", circuit_breaker_name=breaker_name_408, opener=mock_opener_408)
        self.assertEqual(b_408.state, CircuitState.OPEN)
        self.assertEqual(b_408.snapshot()["total_trips"], 1)

    def test_circuit_breaker_snapshot_telemetry_and_cooldown_coherency(self) -> None:
        """Whitebox: Diagnostic snapshot fields, zero cooldown when CLOSED, positive when OPEN."""
        breaker = CircuitBreaker("snapshot_test_cb", failure_threshold=3, recovery_timeout=20.0)

        # Initial pristine snapshot
        snap0 = breaker.snapshot()
        self.assertEqual(snap0["name"], "snapshot_test_cb")
        self.assertEqual(snap0["state"], "CLOSED")
        self.assertEqual(snap0["consecutive_failures"], 0)
        self.assertEqual(snap0["failure_threshold"], 3)
        self.assertEqual(snap0["recovery_timeout"], 20.0)
        self.assertEqual(snap0["total_requests"], 0)
        self.assertEqual(snap0["total_failures"], 0)
        self.assertEqual(snap0["total_trips"], 0)
        self.assertEqual(snap0["cooldown_remaining_seconds"], 0.0)

        # Record failures to trip
        breaker.allow_request()
        breaker.record_failure()
        breaker.allow_request()
        breaker.record_failure()
        breaker.allow_request()
        breaker.record_failure()

        self.assertEqual(breaker.state, CircuitState.OPEN)
        snap1 = breaker.snapshot()
        self.assertEqual(snap1["state"], "OPEN")
        self.assertEqual(snap1["total_requests"], 3)
        self.assertEqual(snap1["total_failures"], 3)
        self.assertEqual(snap1["total_trips"], 1)
        self.assertGreater(snap1["cooldown_remaining_seconds"], 18.0)
        self.assertLessEqual(snap1["cooldown_remaining_seconds"], 20.0)

    def test_circuit_breaker_open_error_subclassing_and_attributes(self) -> None:
        """Whitebox: CircuitBreakerOpenError subclasses URLError and OSError, exposing breaker details."""
        err = CircuitBreakerOpenError(breaker_name="upstream_service", cooldown_remaining=12.456)
        self.assertIsInstance(err, urllib.error.URLError)
        self.assertIsInstance(err, OSError)
        self.assertEqual(err.breaker_name, "upstream_service")
        self.assertAlmostEqual(err.cooldown_remaining, 12.46, places=2)
        self.assertIn("Circuit breaker 'upstream_service' is OPEN", str(err))
        self.assertIn("12.46s", str(err))

        # Negative cooldown remaining clamped to 0.0
        err_neg = CircuitBreakerOpenError("neg_cb", -5.0)
        self.assertEqual(err_neg.cooldown_remaining, 0.0)

    def test_circuit_breaker_registry_reset_and_clear_isolated_boundaries(self) -> None:
        """Whitebox: Registry operations with non-existent names, snapshot lists, and clear."""
        registry = CircuitBreakerRegistry()
        b1 = registry.get_or_create("service_a", failure_threshold=2)
        b2 = registry.get_or_create("service_b", failure_threshold=5)

        b1.allow_request()
        b1.record_failure()
        b1.allow_request()
        b1.record_failure()
        self.assertEqual(b1.state, CircuitState.OPEN)

        # reset for non-existent name is safe no-op
        registry.reset("non_existent_service", clear=False)
        self.assertEqual(b1.state, CircuitState.OPEN)

        # clear for non-existent name is safe no-op
        registry.reset("non_existent_service", clear=True)
        self.assertEqual(len(registry.get_all_snapshots()), 2)

        # Reset specific breaker retains other breakers
        registry.reset("service_a", reset_metrics=True, clear=False)
        self.assertEqual(b1.state, CircuitState.CLOSED)
        self.assertEqual(b1.snapshot()["total_failures"], 0)

        # Clear specific breaker deletes it from registry
        registry.reset("service_a", clear=True)
        snaps = registry.get_all_snapshots()
        self.assertNotIn("service_a", snaps)
        self.assertIn("service_b", snaps)

    def test_urlopen_with_retry_urlerror_valueerror_fast_fail(self) -> None:
        """Whitebox: URLError wrapping ValueError (e.g. invalid scheme) fails fast without retry."""
        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.URLError(ValueError("unknown url type: 'badproto'"))
        mock_sleep = MagicMock()

        with self.assertRaises(urllib.error.URLError) as ctx:
            urlopen_with_retry("badproto://host", max_retries=3, opener=mock_opener, sleep_fn=mock_sleep)

        self.assertIsInstance(ctx.exception.reason, ValueError)
        self.assertEqual(mock_opener.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 0)

    def test_urlopen_with_retry_response_variations(self) -> None:
        """Whitebox: Handling opener returning HTTPResponseBytes, BytesIO, or context manager with non-bytes read."""
        # 1. Opener returning HTTPResponseBytes (which is a context manager)
        mock_opener1 = MagicMock()
        mock_opener1.return_value = HTTPResponseBytes(b'{"status":"http_response_bytes"}')
        res1 = urlopen_with_retry("http://api", opener=mock_opener1)
        self.assertEqual(res1, b'{"status":"http_response_bytes"}')

        # 2. Opener returning context manager whose .read() returns bytearray
        class BytearrayResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                return bytearray(b"bytearray_response")

        mock_opener2 = MagicMock()
        mock_opener2.return_value = BytearrayResponse()
        res2 = urlopen_with_retry("http://api", opener=mock_opener2)
        self.assertEqual(res2, b"bytearray_response")

        # 3. Opener returning context manager whose .read() returns None or non-bytes
        class NonBytesResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                return None

        mock_opener3 = MagicMock()
        mock_opener3.return_value = NonBytesResponse()
        res3 = urlopen_with_retry("http://api", opener=mock_opener3)
        self.assertEqual(res3, b"")

    def test_urlopen_with_retry_float_max_retries_and_extreme_backoff(self) -> None:
        """Whitebox: Float max_retries casting and zero/extreme backoff factors."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.HTTPError("http://api", 503, "Unavailable", {}, None),
            io.BytesIO(b"ok"),
        ]
        mock_sleep = MagicMock()

        res = urlopen_with_retry(
            "http://api",
            max_retries=1.9,  # int(1.9) == 1 retry
            backoff_factor=0.05,
            opener=mock_opener,
            sleep_fn=mock_sleep,
            jitter=False,
        )
        self.assertEqual(res, b"ok")
        self.assertEqual(mock_opener.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1)
        self.assertAlmostEqual(mock_sleep.call_args[0][0], 0.05)

    def test_request_headers_and_body_preserved_across_retries(self) -> None:
        """Whitebox: Request object headers and byte payload are preserved unmodified across retry attempts."""
        req = Request(
            "http://api.internal/endpoint",
            data=b'{"query":"system_health"}',
            headers={"X-Correlation-ID": "corr-uuid-9999", "Authorization": "Bearer fake"},
            method="POST",
        )
        captured_requests: list[Request] = []

        def mock_opener(r: Request, **kwargs) -> io.BytesIO:
            captured_requests.append(r)
            if len(captured_requests) == 1:
                raise urllib.error.HTTPError("http://api.internal/endpoint", 503, "Unavailable", {}, None)
            return io.BytesIO(b'{"status":"recovered"}')

        mock_sleep = MagicMock()
        res = urlopen_with_retry(req, max_retries=2, opener=mock_opener, sleep_fn=mock_sleep, jitter=False)
        self.assertEqual(res, b'{"status":"recovered"}')
        self.assertEqual(len(captured_requests), 2)

        # Both attempts must carry identical method, data, and headers
        for captured in captured_requests:
            self.assertEqual(captured.get_method(), "POST")
            self.assertEqual(captured.data, b'{"query":"system_health"}')
            self.assertEqual(captured.get_header("X-correlation-id"), "corr-uuid-9999")

    def test_circuit_breaker_concurrency_reset_invariance(self) -> None:
        """Whitebox: Concurrent threads tripping breaker and resetting metrics produce clean invariance."""
        breaker = get_circuit_breaker("concurrent_invariance_cb", failure_threshold=2)

        def worker_trip(thread_id: int):
            for _ in range(50):
                breaker.record_failure()

        def worker_reset():
            for _ in range(20):
                breaker.reset(reset_metrics=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            f_trips = [executor.submit(worker_trip, i) for i in range(4)]
            f_resets = [executor.submit(worker_reset) for _ in range(4)]
            for f in f_trips + f_resets:
                f.result()

        # Final reset produces pristine state without residual deadlock or metric corruption
        breaker.reset(reset_metrics=True)
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        snap = breaker.snapshot()
        self.assertEqual(snap["total_requests"], 0)
        self.assertEqual(snap["total_failures"], 0)
        self.assertEqual(snap["total_trips"], 0)



class TestTier5WebhookNotifierWhitebox(unittest.TestCase):
    """Whitebox adversarial tests for webhook_notifier.py."""

    def setUp(self) -> None:
        opscryer_config.reset_config()

    def tearDown(self) -> None:
        opscryer_config.reset_config()

    def test_url_resolution_hierarchy_whitespace_fallthrough(self) -> None:
        """Whitebox: Whitespace strings at each tier fall through cleanly to lower tiers."""
        # Tier 1 with whitespace string falls through to Tier 2 (env)
        with patch.dict(os.environ, {"OPSCRYER_WEBHOOK_URL": "https://env.example.com/webhook"}):
            with patch.object(opscryer_config, "get_config_value", return_value="https://config.example.com/webhook"):
                self.assertEqual(resolve_webhook_url("   \t\n  "), "https://env.example.com/webhook")

        # Tier 2 with whitespace string falls through to Tier 3 (config)
        with patch.dict(os.environ, {"OPSCRYER_WEBHOOK_URL": "   \n  "}):
            with patch.object(opscryer_config, "get_config_value", return_value="https://config.example.com/webhook"):
                self.assertEqual(resolve_webhook_url(None), "https://config.example.com/webhook")

        # Tier 3 with whitespace string falls through to Tier 4 (None)
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(opscryer_config, "get_config_value", return_value="   "):
                self.assertIsNone(resolve_webhook_url(None))

    def test_severity_validation_edge_cases_and_normalization(self) -> None:
        """Whitebox: Normalization of whitespace/case severities and rejection of invalid types."""
        # Valid severities with weird whitespace and casing
        valid_cases = [
            ("  critical  ", "critical"),
            ("HIGH\n", "high"),
            ("\tWarning ", "warning"),
            ("Info", "info"),
            ("  LOW  ", "low"),
        ]
        for raw, expected in valid_cases:
            payload = build_webhook_payload("test_event", raw, "Test summary")
            self.assertEqual(payload["severity"], expected)

        # Invalid severities
        invalid_cases = ["", "   ", "fatal", "emergency", "alert", "notice", "panic", "debug"]
        for bad_sev in invalid_cases:
            with self.assertRaises(ValueError):
                build_webhook_payload("test_event", bad_sev, "Test summary")

            # dispatch_webhook_event fails closed (returns False)
            ok = dispatch_webhook_event(
                event_type="test_event",
                severity=bad_sev,
                summary="Test summary",
                webhook_url="https://hooks.test/sink",
            )
            self.assertFalse(ok)

    def test_opsec_scrubbing_deeply_nested_structures(self) -> None:
        """Whitebox: Scrubbing sensitive tokens deeply nested inside dicts, lists, and tuples."""
        captured_payload: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured_payload
            captured_payload = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        nested_details = {
            "tier1": {
                "tier2": [
                    {
                        "tier3": (
                            {
                                "client_secret": "raw_oauth_secret_12345",
                                "auth_token": "bearer eyJhbGciOi...",
                                "ssh_key": "private_ssh_key_content",
                                "safe_metric": 99.9,
                            },
                        )
                    }
                ]
            }
        }

        ok = dispatch_webhook_event(
            event_type="nested_test",
            severity="info",
            summary="Nested scrubbing test",
            details=nested_details,
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(captured_payload)
        assert captured_payload is not None

        # Verify deepest values
        t3 = captured_payload["details"]["tier1"]["tier2"][0]["tier3"][0]
        self.assertEqual(t3["client_secret"], "[REDACTED]")
        self.assertEqual(t3["auth_token"], "[REDACTED]")
        self.assertEqual(t3["ssh_key"], "[REDACTED]")
        self.assertEqual(t3["safe_metric"], 99.9)

        # Raw string check
        raw_json = json.dumps(captured_payload)
        self.assertNotIn("raw_oauth_secret_12345", raw_json)
        self.assertNotIn("private_ssh_key_content", raw_json)

    def test_opsec_scrubbing_pem_block_regex_variants(self) -> None:
        """Whitebox: All standard RFC 7468 PEM armor block types are redacted."""
        pem_headers = [
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...\n-----END EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\nMIIDdz...\n-----END CERTIFICATE-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...\n-----END OPENSSH PRIVATE KEY-----",
        ]

        for pem in pem_headers:
            with self.subTest(pem=pem.splitlines()[0]):
                captured: dict | None = None

                def mock_opener(req: Request, **kwargs) -> io.BytesIO:
                    nonlocal captured
                    captured = json.loads(req.data.decode("utf-8"))
                    return io.BytesIO(b'{"status":"ok"}')

                ok = dispatch_webhook_event(
                    event_type="pem_test",
                    severity="warning",
                    summary="PEM scrubbing test",
                    details={"error_log": f"Failure reason: {pem}"},
                    webhook_url="https://hooks.test/sink",
                    opener=mock_opener,
                )
                self.assertTrue(ok)
                self.assertIsNotNone(captured)
                assert captured is not None
                raw_json = json.dumps(captured)
                self.assertNotIn("BEGIN", raw_json)
                self.assertIn("Failure reason: [REDACTED]", captured["details"]["error_log"])

    def test_non_serializable_and_cyclic_details_fail_closed(self) -> None:
        """Whitebox: Cyclic references and non-serializable objects fail closed cleanly."""
        mock_opener = MagicMock()

        # 1. Cyclic dictionary
        cyclic_dict: dict[str, Any] = {"name": "cycle"}
        cyclic_dict["self"] = cyclic_dict

        ok1 = dispatch_webhook_event(
            event_type="cyclic_test",
            severity="critical",
            summary="Cyclic dict test",
            details=cyclic_dict,
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertFalse(ok1)
        self.assertEqual(mock_opener.call_count, 0)

        # 2. Unserializable function / object
        ok2 = dispatch_webhook_event(
            event_type="unserializable_test",
            severity="warning",
            summary="Unserializable object test",
            details={"func": lambda x: x, "lock": threading.Lock()},
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertFalse(ok2)
        self.assertEqual(mock_opener.call_count, 0)

    def test_convenience_triggers_extreme_and_invalid_values(self) -> None:
        """Whitebox: notify_cluster_degraded with NaN/Inf scores fails closed without crash."""
        mock_opener = MagicMock()

        # NaN health score: json.dumps with allow_nan=False catches it and returns False
        ok_nan = notify_cluster_degraded(
            score=float("nan"),
            reason="NaN calculation",
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertFalse(ok_nan)

        # Inf health score: returns False cleanly
        ok_inf = notify_cluster_degraded(
            score=float("inf"),
            reason="Inf calculation",
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertFalse(ok_inf)

        # notify_hotspot_detected with unicode and non-primitive value
        captured: dict | None = None

        def capturing_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured
            captured = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        ok_hotspot = notify_hotspot_detected(
            node_id="worker-node-\u26a1-01",
            metric="gpu_temp_celsius",
            value=84.5,
            details={"ambient_c": 26},
            webhook_url="https://hooks.test/sink",
            opener=capturing_opener,
        )
        self.assertTrue(ok_hotspot)
        self.assertIsNotNone(captured)
        assert captured is not None
        self.assertEqual(captured["details"]["node_id"], "worker-node-\u26a1-01")
        self.assertEqual(captured["details"]["value"], 84.5)

    def test_cluster_metadata_merging_and_defaults(self) -> None:
        """Whitebox: Ambient cluster metadata merging and custom overrides."""
        defaults = get_default_cluster_metadata()
        self.assertEqual(defaults["engine"], "opscryer")
        self.assertIn("cluster_id", defaults)
        self.assertIn("environment", defaults)

        payload = build_webhook_payload(
            event_type="meta_test",
            severity="info",
            summary="Metadata test",
            cluster_metadata={"cluster_id": "custom-cluster-09", "datacenter": "dc-west"},
        )
        meta = payload["cluster_metadata"]
        self.assertEqual(meta["cluster_id"], "custom-cluster-09")
        self.assertEqual(meta["datacenter"], "dc-west")
        self.assertEqual(meta["engine"], "opscryer")

    def test_scrub_sensitive_entries_non_string_keys_and_unicode(self) -> None:
        """Whitebox: Scrubbing details with integer keys, _key suffix matching, and unicode emojis."""
        custom_id = "custom-evt-uuid-007"
        custom_ts = "2026-10-31T09:00:00Z"
        details_with_non_str_keys = {
            101: "safe_val",
            "api_key": "raw_secret_key",
            "emoji_key": "Redacted due to _key suffix",
            "emoji_message": "Alert \U0001F525 Fire!",
        }

        payload = build_webhook_payload(
            event_type="unicode_test_\u2728",
            severity="warning",
            summary="Emergency alert \U0001F6A8 in datacenter",
            details=details_with_non_str_keys,
            event_id=custom_id,
            timestamp=custom_ts,
        )

        self.assertEqual(payload["event_id"], custom_id)
        self.assertEqual(payload["timestamp"], custom_ts)
        self.assertEqual(payload["event_type"], "unicode_test_\u2728")
        self.assertIn("\U0001F6A8", payload["summary"])
        self.assertEqual(payload["details"]["api_key"], "[REDACTED]")
        self.assertEqual(payload["details"]["101"], "safe_val")
        # Confirms _key suffix in emoji_key triggers OPSEC redaction
        self.assertEqual(payload["details"]["emoji_key"], "[REDACTED]")
        # Confirms non-sensitive emoji_message preserves unicode emoji
        self.assertIn("\U0001F525", payload["details"]["emoji_message"])

    def test_convenience_triggers_missing_details_and_defaults(self) -> None:
        """Whitebox: Convenience triggers with details=None correctly initialize and merge fields."""
        captured: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured
            captured = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        # 1. notify_cluster_degraded with details=None
        ok1 = notify_cluster_degraded(
            score=0.25,
            reason="Disk pressure",
            details=None,
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertTrue(ok1)
        self.assertIsNotNone(captured)
        self.assertEqual(captured["details"]["health_score"], 0.25)
        self.assertEqual(captured["details"]["reason"], "Disk pressure")

        # 2. notify_jev_escalation with details=None
        ok2 = notify_jev_escalation(
            ticket_id="TICKET-888",
            reason="Low model confidence",
            details=None,
            webhook_url="https://hooks.test/sink",
            opener=mock_opener,
        )
        self.assertTrue(ok2)
        self.assertEqual(captured["details"]["ticket_id"], "TICKET-888")
        self.assertEqual(captured["details"]["escalation_reason"], "Low model confidence")



class TestTier5MetricsExporterWhitebox(unittest.TestCase):
    """Whitebox adversarial tests for metrics_exporter.py."""

    def setUp(self) -> None:
        metrics_exporter.reset_metrics()

    def tearDown(self) -> None:
        metrics_exporter.reset_metrics()

    def test_prometheus_escaping_boundary_and_special_characters(self) -> None:
        """Whitebox: HELP documentation and label value escaping according to OpenMetrics specs."""
        # _escape_help escapes backslash and newline
        self.assertEqual(
            metrics_exporter._escape_help("Backslash \\ and \n newline"),
            "Backslash \\\\ and \\n newline",
        )

        # _escape_label_value escapes backslash, quote, and newline
        self.assertEqual(
            metrics_exporter._escape_label_value('Quotes " backslash \\ and \n newline'),
            'Quotes \\" backslash \\\\ and \\n newline',
        )

        # Metric family output test with quotes and backslashes in labels
        mf = metrics_exporter.MetricFamily("complex_metric", "Help with \\ backslash\nand newline", "gauge")
        mf.add_sample("complex_metric", {"label_key": 'val"with\\and\n'}, 42)
        text = metrics_exporter.format_prometheus_text([mf])

        self.assertIn('# HELP complex_metric Help with \\\\ backslash\\nand newline', text)
        self.assertIn('complex_metric{label_key="val\\"with\\\\and\\n"} 42', text)

    def test_format_value_all_numeric_permutations(self) -> None:
        """Whitebox: Number formatting for integers, booleans, floats, NaN, and Inf."""
        # Integers format as exact integers without decimals
        self.assertEqual(metrics_exporter._format_value(0), "0")
        self.assertEqual(metrics_exporter._format_value(-42), "-42")
        self.assertEqual(metrics_exporter._format_value(1000000), "1000000")

        # Booleans format as float values (1.0 / 0.0)
        self.assertEqual(metrics_exporter._format_value(True), "1.0")
        self.assertEqual(metrics_exporter._format_value(False), "0.0")

        # Floats with integer value have .1f precision
        self.assertEqual(metrics_exporter._format_value(0.0), "0.0")
        self.assertEqual(metrics_exporter._format_value(5.0), "5.0")
        self.assertEqual(metrics_exporter._format_value(-10.0), "-10.0")

        # Floating point with fraction
        self.assertEqual(metrics_exporter._format_value(1.2345), "1.2345")

        # Special IEEE 754 values
        self.assertEqual(metrics_exporter._format_value(float("nan")), "NaN")
        self.assertEqual(metrics_exporter._format_value(float("inf")), "+Inf")
        self.assertEqual(metrics_exporter._format_value(float("-inf")), "-Inf")

    def test_counter_and_gauge_negative_and_extreme_amounts(self) -> None:
        """Whitebox: Counter rejects negative increments, Gauge accepts negative/Inf values."""
        counter = metrics_exporter.Counter("test_counter_bounds", "Documentation")

        # Increment by 0 is valid
        counter.inc(0.0, service="api")
        self.assertEqual(counter.get(service="api"), 0.0)

        # Increment by negative amount raises ValueError
        with self.assertRaises(ValueError) as ctx:
            counter.inc(-1.0, service="api")
        self.assertIn("non-negative amounts", str(ctx.exception))

        # Gauge accepts negative, zero, and special values
        gauge = metrics_exporter.Gauge("test_gauge_bounds", "Documentation")
        gauge.set(-15, node="worker-1")
        self.assertEqual(gauge.get(node="worker-1"), -15)

        gauge.set(float("inf"), node="worker-inf")
        self.assertEqual(gauge.get(node="worker-inf"), float("inf"))

        family = gauge.collect()
        text = metrics_exporter.format_prometheus_text([family])
        self.assertIn('test_gauge_bounds{node="worker-1"} -15', text)
        self.assertIn('test_gauge_bounds{node="worker-inf"} +Inf', text)

    def test_custom_collector_exception_resilience(self) -> None:
        """Whitebox: Faulty custom collectors (throwing exceptions or returning None) do not crash registry."""
        registry = metrics_exporter.MetricsRegistry()

        # Collector 1: throws an unhandled exception
        def failing_collector():
            raise RuntimeError("Database connection timed out during collection")

        # Collector 2: returns None instead of a list
        def returning_none_collector():
            return None

        # Collector 3: valid collector
        def valid_collector():
            mf = metrics_exporter.MetricFamily("valid_custom_metric", "Valid help", "gauge")
            mf.add_sample("valid_custom_metric", {"tier": "custom"}, 123)
            return [mf]

        registry.register_collector(failing_collector)
        registry.register_collector(returning_none_collector)
        registry.register_collector(valid_collector)

        # collect_all must not crash
        families = registry.collect_all()
        family_names = [f.name for f in families]
        self.assertIn("valid_custom_metric", family_names)
        self.assertIn("opscryer_uptime_seconds", family_names)

        # generate_latest output includes valid metric
        text = registry.generate_latest()
        self.assertIn("valid_custom_metric", text)
        self.assertIn('valid_custom_metric{tier="custom"} 123', text)

    def test_parse_currency_rate_edge_cases(self) -> None:
        """Whitebox: parse_currency_rate edge cases, invalid inputs, and fallback chains."""
        # Non-dict inputs return 0.0
        self.assertEqual(metrics_exporter.parse_currency_rate(None), 0.0)
        self.assertEqual(metrics_exporter.parse_currency_rate([]), 0.0)
        self.assertEqual(metrics_exporter.parse_currency_rate("string"), 0.0)

        # available: False returns 0.0
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": False, "count": 100}), 0.0)

        # Non-finite numbers fall through to display_value parsing
        curr_nan = {"available": True, "count": float("nan"), "display_value": "45% CPU"}
        self.assertEqual(metrics_exporter.parse_currency_rate(curr_nan), 45.0)

        # display_value without match returns 0.0
        curr_no_match = {"available": True, "display_value": "No data present"}
        self.assertEqual(metrics_exporter.parse_currency_rate(curr_no_match), 0.0)

    def test_concurrent_counter_and_gauge_multi_label_storm(self) -> None:
        """Whitebox: Multi-threaded storm of counter increments and gauge updates across label permutations."""
        counter = metrics_exporter.Counter("storm_counter", "Multi-label counter storm")
        gauge = metrics_exporter.Gauge("storm_gauge", "Multi-label gauge storm")

        num_threads = 8
        ops_per_thread = 50

        def worker(thread_idx: int):
            for i in range(ops_per_thread):
                endpoint = f"/api/v1/endpoint_{thread_idx % 3}"
                method = "GET" if i % 2 == 0 else "POST"
                counter.inc(1.0, method=method, endpoint=endpoint)
                gauge.set(float(i * thread_idx), host=f"node-{thread_idx}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            for f in futures:
                f.result()

        # Validate total counter increments match num_threads * ops_per_thread
        mf_counter = counter.collect()
        total_counter_sum = sum(s.value for s in mf_counter.samples)
        self.assertEqual(total_counter_sum, num_threads * ops_per_thread)

        # Validate gauge samples collected
        mf_gauge = gauge.collect()
        self.assertEqual(len(mf_gauge.samples), num_threads)

    def test_metrics_registry_reset_and_http_request_recording(self) -> None:
        """Whitebox: HTTP request recording across various methods and statuses with clean reset."""
        metrics_exporter.reset_metrics()

        test_triplets = [
            ("GET", "/healthz", 200),
            ("POST", "/api/v1/graph/deflect-ticket", 200),
            ("GET", "/readyz", 503),
            ("POST", "/healthz", 405),
            ("DELETE", "/api/v1/unknown", 404),
        ]

        for method, endpoint, status in test_triplets:
            metrics_exporter.record_http_request(method, endpoint, status)

        text = metrics_exporter.generate_latest_metrics()
        for method, endpoint, status in test_triplets:
            expected_sample = f'opscryer_http_requests_total{{endpoint="{endpoint}",method="{method}",status="{status}"}} 1'
            self.assertIn(expected_sample, text)

        # Reset zeroes the counter
        metrics_exporter.reset_metrics()
        text_after = metrics_exporter.generate_latest_metrics()
        self.assertNotIn("opscryer_http_requests_total{", text_after)



class TestTier5OpsCryerBrowserProbesWhitebox(unittest.TestCase):
    """Whitebox adversarial tests for probe routes and logging in opscryer_browser.py."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.handler_class = _build_frontend_handler()
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), cls.handler_class)
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server)

    @classmethod
    def stop_server(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        self.handler_class._readiness_override = None

    def _http_request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            res = conn.getresponse()
            resp_headers = {k.lower(): v for k, v in res.getheaders()}
            resp_body = res.read()
            return res.status, resp_headers, resp_body
        finally:
            conn.close()

    def test_healthz_query_param_allowlist_boundaries(self) -> None:
        """Whitebox: GET /healthz accepts only k8s_liveness, timestamp, probe, and rejects all others."""
        # 1. Allowed query parameters individually
        for param in ("k8s_liveness=1", "timestamp=1234567890", "probe=liveness"):
            status, _, body = self._http_request("GET", f"/healthz?{param}")
            self.assertEqual(status, 200, f"/healthz?{param} must return 200")
            data = json.loads(body.decode("utf-8"))
            self.assertEqual(data.get("status"), "ok")

        # 2. Combined allowed query parameters
        status, _, body = self._http_request("GET", "/healthz?k8s_liveness=true&timestamp=100&probe=health")
        self.assertEqual(status, 200)

        # 3. Disallowed query parameters must return 400 Bad Request
        disallowed = [
            "unexpected=1",
            "k8s_liveness=1&malicious=true",
            "probe=test&extra=99",
            "format=json",
        ]
        for bad_query in disallowed:
            status, _, body = self._http_request("GET", f"/healthz?{bad_query}")
            self.assertEqual(status, 400, f"/healthz?{bad_query} must return 400")
            data = json.loads(body.decode("utf-8"))
            self.assertEqual(data.get("error"), "Invalid query parameters")

    def test_readyz_query_param_allowlist_boundaries(self) -> None:
        """Whitebox: GET /readyz query parameter allowlist enforcement."""
        # Allowed query parameters
        status, _, body = self._http_request("GET", "/readyz?k8s_liveness=ready&timestamp=999")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "ready")

        # Disallowed query parameters return 400
        status, _, body = self._http_request("GET", "/readyz?format=yaml")
        self.assertEqual(status, 400)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("error"), "Invalid query parameters")

    def test_metrics_query_param_zero_tolerance(self) -> None:
        """Whitebox: GET /metrics rejects any query parameter with 400 Bad Request."""
        for param in ("format=json", "k8s_liveness=1", "probe=metrics", "foo=bar"):
            status, _, body = self._http_request("GET", f"/metrics?{param}")
            self.assertEqual(status, 400, f"/metrics?{param} must return 400")

    def test_probes_head_request_headers_and_empty_body(self) -> None:
        """Whitebox: HEAD /healthz, /readyz, /metrics return headers with exactly zero bytes body."""
        for route in ("/healthz", "/readyz", "/metrics"):
            status, headers, body = self._http_request("HEAD", route)
            self.assertEqual(status, 200, f"HEAD {route} must return 200 OK")
            self.assertIn("content-length", headers)
            self.assertGreater(int(headers["content-length"]), 0)
            self.assertEqual(len(body), 0, f"HEAD {route} body must be empty")

    def test_probes_post_method_405_method_not_allowed(self) -> None:
        """Whitebox: POST /healthz, /readyz, /metrics return 405 Method Not Allowed."""
        for route in ("/healthz", "/readyz", "/metrics"):
            status, headers, body = self._http_request(
                "POST", route, body=b'{"action":"trigger"}', headers={"Content-Type": "application/json"}
            )
            self.assertEqual(status, 405, f"POST {route} must return 405 Method Not Allowed")
            data = json.loads(body.decode("utf-8"))
            self.assertEqual(data.get("error"), "method not allowed")
            self.assertEqual(data.get("allowed_method"), "GET")

    def test_readyz_subsystem_readiness_override_and_failure_reporting(self) -> None:
        """Whitebox: Detailed failure reasons returned by /readyz when subsystems are unavailable."""
        # 1. Manual readiness override disabled
        self.handler_class._readiness_override = False
        status, _, body = self._http_request("GET", "/readyz")
        self.assertEqual(status, 503)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "not_ready")
        self.assertEqual(data.get("reason"), "manual readiness override disabled")

        # 2. Manual readiness override enabled
        self.handler_class._readiness_override = True
        status, _, body = self._http_request("GET", "/readyz")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "ready")

    def test_structured_json_formatter_deep_context_and_unicode_safety(self) -> None:
        """Whitebox: StructuredJsonFormatter emits valid single-line JSON with full metadata and unicode."""
        formatter = StructuredJsonFormatter()

        record = logging.LogRecord(
            name="opscryer.gateway",
            level=logging.WARNING,
            pathname="opscryer_browser.py",
            lineno=250,
            msg="Upstream timeout: %s - %s",
            args=("Cluster 01", "\U0001F6A8 Alert!"),
            exc_info=None,
        )
        record.client_ip = "172.20.1.100"
        record.method = "POST"
        record.path = "/api/v1/graph/deflect-ticket"
        record.status_code = 504
        record.duration_ms = 45.2
        record.command = "POST"
        record.pid = 12345
        record.error = "Gateway Timeout"

        formatted = formatter.format(record)

        # Must be single line (no raw newlines)
        self.assertNotIn("\n", formatted.strip())

        # Must parse as valid JSON
        entry = json.loads(formatted)
        self.assertEqual(entry["level"], "WARNING")
        self.assertEqual(entry["logger"], "opscryer.gateway")
        self.assertIn("\U0001F6A8 Alert!", entry["message"])
        self.assertEqual(entry["client_ip"], "172.20.1.100")
        self.assertEqual(entry["method"], "POST")
        self.assertEqual(entry["path"], "/api/v1/graph/deflect-ticket")
        self.assertEqual(entry["status_code"], 504)
        self.assertEqual(entry["duration_ms"], 45.2)
        self.assertEqual(entry["subsystem"], "gateway")
        self.assertIn("timestamp", entry)

    def test_structured_json_formatter_chained_exceptions(self) -> None:
        """Whitebox: StructuredJsonFormatter formats chained exceptions (cause & context) as valid JSON."""
        formatter = StructuredJsonFormatter()

        try:
            try:
                raise ConnectionResetError("Socket abruptly closed by peer")
            except ConnectionResetError as inner:
                raise urllib.error.URLError("Upstream transport failure") from inner
        except urllib.error.URLError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="opscryer.gateway",
            level=logging.ERROR,
            pathname="opscryer_browser.py",
            lineno=300,
            msg="Chained exception trapped",
            args=(),
            exc_info=exc_info,
        )

        formatted = formatter.format(record)
        entry = json.loads(formatted)
        self.assertIn("exc_info", entry)
        self.assertIn("Socket abruptly closed by peer", entry["exc_info"])
        self.assertIn("Upstream transport failure", entry["exc_info"])

    def test_readyz_empty_catalog_rejection(self) -> None:
        """Whitebox: GET /readyz returns 503 when backend engine catalog has zero nodes."""
        class MockEmptyEngine:
            def catalog(self):
                return {"nodes": []}

        with patch.object(self.handler_class, "_get_backend_engine", return_value=MockEmptyEngine()):
            status, _, body = self._http_request("GET", "/readyz")
            self.assertEqual(status, 503)
            data = json.loads(body.decode("utf-8"))
            self.assertEqual(data.get("status"), "not_ready")
            self.assertFalse(data.get("graph_loaded"))
            self.assertIn("graph engine contains no nodes", data.get("reason", ""))



if __name__ == "__main__":
    unittest.main()
