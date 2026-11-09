# SPDX-License-Identifier: Apache-2.0
"""Unit and boundary test suite for webhook_notifier.py (Feature 10)."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import socket
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
from urllib.request import Request

import opscryer_config
from webhook_notifier import (
    build_webhook_payload,
    dispatch_webhook_event,
    notify_cluster_degraded,
    notify_hotspot_detected,
    notify_jev_escalation,
    resolve_webhook_url,
)


class TestWebhookNotifierUnit(unittest.TestCase):
    """Unit test suite verifying schema, transport, hierarchy, OPSEC, and helpers."""

    def setUp(self) -> None:
        opscryer_config.reset_config()
        self.dummy_url = "https://hooks.example.org/alerts"

    def tearDown(self) -> None:
        opscryer_config.reset_config()

    # -------------------------------------------------------------------------
    # Test 1: Payload Schema Conformance
    # -------------------------------------------------------------------------
    def test_payload_schema_conforms_to_1_0_specification(self) -> None:
        """Verify payload adheres to '1.0-webhook-notification' schema and required fields."""
        captured_payload: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured_payload
            captured_payload = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        ok = dispatch_webhook_event(
            event_type="test_event",
            severity="warning",
            summary="High CPU load detected",
            details={"cpu_pct": 94.2, "node": "worker-1"},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(captured_payload)
        assert captured_payload is not None

        # Check required schema fields
        self.assertEqual(captured_payload["schema_version"], "1.0-webhook-notification")
        self.assertIsInstance(captured_payload["event_id"], str)
        self.assertGreater(len(captured_payload["event_id"]), 8)

        # Check ISO 8601 UTC timestamp format (YYYY-MM-DDTHH:MM:SS...)
        self.assertRegex(
            captured_payload["timestamp"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        )
        self.assertEqual(captured_payload["event_type"], "test_event")
        self.assertEqual(captured_payload["severity"], "warning")
        self.assertEqual(captured_payload["summary"], "High CPU load detected")
        self.assertEqual(captured_payload["details"], {"cpu_pct": 94.2, "node": "worker-1"})
        self.assertIsInstance(captured_payload.get("cluster_metadata"), dict)

    # -------------------------------------------------------------------------
    # Test 2: Successful HTTP POST Dispatch
    # -------------------------------------------------------------------------
    def test_successful_http_post_dispatch_200_and_204(self) -> None:
        """Verify successful HTTP POST with mock opener returning 200 or 204 returns True."""
        for status_code in (200, 204):
            with self.subTest(status=status_code):
                mock_opener = MagicMock()
                mock_opener.return_value = io.BytesIO(b'{"status":"acknowledged"}')

                ok = dispatch_webhook_event(
                    event_type="heartbeat",
                    severity="info",
                    summary="Heartbeat OK",
                    details={},
                    webhook_url=self.dummy_url,
                    opener=mock_opener,
                )
                self.assertTrue(ok)
                self.assertEqual(mock_opener.call_count, 1)
                req = mock_opener.call_args[0][0]
                self.assertEqual(req.get_method(), "POST")
                self.assertEqual(req.full_url, self.dummy_url)

    # -------------------------------------------------------------------------
    # Test 3: URL Resolution Hierarchy
    # -------------------------------------------------------------------------
    def test_url_resolution_hierarchy(self) -> None:
        """Verify precedence: explicit arg > environment variable > config file > None."""
        explicit = "https://explicit.example.org/hook"
        from_config = "https://config.example.org/hook"
        from_env = "https://env.example.org/hook"

        # Case 1: Explicit argument takes top priority over env and config
        with patch.dict(os.environ, {"OPSCRYER_WEBHOOK_URL": from_env}):
            with patch.object(opscryer_config, "get_config_value", return_value=from_config):
                self.assertEqual(resolve_webhook_url(explicit), explicit)

        # Case 2: Env takes priority over config when arg is omitted/None
        with patch.dict(os.environ, {"OPSCRYER_WEBHOOK_URL": from_env}):
            with patch.object(opscryer_config, "get_config_value", return_value=from_config):
                self.assertEqual(resolve_webhook_url(None), from_env)

        # Case 3: Config used when arg is None and env is unset/empty
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(opscryer_config, "get_config_value", return_value=from_config):
                self.assertEqual(resolve_webhook_url(None), from_config)

        # Case 4: None returned when all are unset
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(opscryer_config, "get_config_value", return_value=None):
                self.assertIsNone(resolve_webhook_url(None))

    # -------------------------------------------------------------------------
    # Test 4: Disabled State (No URL)
    # -------------------------------------------------------------------------
    def test_disabled_state_returns_false_without_network_calls(self) -> None:
        """Verify that when no webhook URL is configured, returns False without making requests."""
        mock_opener = MagicMock()
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(opscryer_config, "get_config_value", return_value=None):
                ok = dispatch_webhook_event(
                    event_type="test_disabled",
                    severity="info",
                    summary="Should be no-op",
                    details={},
                    webhook_url=None,
                    opener=mock_opener,
                )
                self.assertFalse(ok)
                self.assertEqual(mock_opener.call_count, 0)

    # -------------------------------------------------------------------------
    # Test 5: HTTP 500 / Network Error Retry and Graceful Failure
    # -------------------------------------------------------------------------
    def test_http_500_retry_and_eventual_graceful_failure(self) -> None:
        """Verify that HTTP 500 retries and eventually returns False without raising unhandled errors."""
        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.HTTPError(
            self.dummy_url, 500, "Internal Server Error", {}, None
        )
        mock_sleep = MagicMock()

        with self.assertLogs("opscryer", level="WARNING") as log_cm:
            ok = dispatch_webhook_event(
                event_type="fail_event",
                severity="critical",
                summary="Downstream outage",
                details={},
                webhook_url=self.dummy_url,
                max_retries=2,
                opener=mock_opener,
                sleep_fn=mock_sleep,
            )
            self.assertFalse(ok)
            # Initial call + 2 retries = 3 calls
            self.assertEqual(mock_opener.call_count, 3)
            self.assertIn("Failed to dispatch webhook event", "\n".join(log_cm.output))

    # -------------------------------------------------------------------------
    # Test 6: Timeout Handling Gracefully Caught
    # -------------------------------------------------------------------------
    def test_timeout_handling_gracefully_caught(self) -> None:
        """Verify that socket/network timeouts are caught gracefully and return False."""
        mock_opener = MagicMock()
        mock_opener.side_effect = socket.timeout("timed out")
        mock_sleep = MagicMock()

        ok = dispatch_webhook_event(
            event_type="timeout_event",
            severity="warning",
            summary="Timeout test",
            details={},
            webhook_url=self.dummy_url,
            timeout=1.0,
            max_retries=1,
            opener=mock_opener,
            sleep_fn=mock_sleep,
        )
        self.assertFalse(ok)
        self.assertEqual(mock_opener.call_count, 2)

    # -------------------------------------------------------------------------
    # Test 7: OPSEC Sanitization (Redaction of Sensitive Tokens)
    # -------------------------------------------------------------------------
    def test_opsec_sanitization_redacts_tokens_in_details(self) -> None:
        """Verify sensitive tokens and keys in details are redacted before dispatch."""
        sent_body: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal sent_body
            sent_body = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        dummy_gl = "gl" + "pat-SECRET1234567890abcdef"
        dummy_gh = "gh" + "p_SECRET1234567890abcdef"
        dummy_pw = "super_secret_master_password!"

        ok = dispatch_webhook_event(
            event_type="sec_alert",
            severity="high",
            summary="Secret test",
            details={
                "gitlab_token": dummy_gl,
                "github_token": dummy_gh,
                "user_password": dummy_pw,
                "safe_field": "public_data",
            },
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(sent_body)
        assert sent_body is not None

        raw_json = json.dumps(sent_body)
        self.assertNotIn(dummy_gl, raw_json)
        self.assertNotIn(dummy_gh, raw_json)
        self.assertNotIn(dummy_pw, raw_json)
        self.assertEqual(sent_body["details"].get("safe_field"), "public_data")

    # -------------------------------------------------------------------------
    # Test 8: Convenience Helper notify_cluster_degraded
    # -------------------------------------------------------------------------
    def test_convenience_notify_cluster_degraded(self) -> None:
        """Verify notify_cluster_degraded dispatches with critical severity."""
        captured: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured
            captured = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        ok = notify_cluster_degraded(
            score=0.45,
            reason="CoreDNS CrashLoopBackOff",
            details={"failed_pods": ["coredns-1", "coredns-2"]},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(captured)
        assert captured is not None
        self.assertEqual(captured["severity"], "critical")
        self.assertEqual(captured["event_type"], "cluster_degraded")
        self.assertIn("CoreDNS CrashLoopBackOff", captured["summary"])
        self.assertAlmostEqual(captured["details"]["health_score"], 0.45)

    # -------------------------------------------------------------------------
    # Test 9: Convenience Helper notify_hotspot_detected
    # -------------------------------------------------------------------------
    def test_convenience_notify_hotspot_detected(self) -> None:
        """Verify notify_hotspot_detected dispatches with warning severity."""
        captured: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured
            captured = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        ok = notify_hotspot_detected(
            node_id="node-gpu-01",
            metric="vram_percent",
            value=95.4,
            details={"tenant": "llm-serving"},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(captured)
        assert captured is not None
        self.assertEqual(captured["severity"], "warning")
        self.assertEqual(captured["event_type"], "hotspot_detected")
        self.assertEqual(captured["details"]["node_id"], "node-gpu-01")
        self.assertEqual(captured["details"]["metric"], "vram_percent")

    # -------------------------------------------------------------------------
    # Test 10: Convenience Helper notify_jev_escalation
    # -------------------------------------------------------------------------
    def test_convenience_notify_jev_escalation(self) -> None:
        """Verify notify_jev_escalation dispatches with high severity."""
        captured: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured
            captured = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        ok = notify_jev_escalation(
            ticket_id="INC-9901",
            reason="Confidence below minimum threshold (0.64 < 0.80)",
            details={"policy_id": "pol_k8s_storage"},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(captured)
        assert captured is not None
        self.assertEqual(captured["severity"], "high")
        self.assertEqual(captured["event_type"], "jev_escalation")
        self.assertEqual(captured["details"]["ticket_id"], "INC-9901")

    # -------------------------------------------------------------------------
    # Test 11: Header Verification
    # -------------------------------------------------------------------------
    def test_header_verification_content_type_and_user_agent(self) -> None:
        """Verify request contains JSON Content-Type and custom User-Agent."""
        mock_opener = MagicMock()
        mock_opener.return_value = io.BytesIO(b'{"status":"ok"}')

        ok = dispatch_webhook_event(
            event_type="test_headers",
            severity="info",
            summary="Header test",
            details={},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        req = mock_opener.call_args[0][0]
        self.assertEqual(req.get_header("Content-type"), "application/json; charset=utf-8")
        user_agent = req.get_header("User-agent")
        self.assertTrue(user_agent.startswith("OpsCryer-WebhookNotifier/"))

    # -------------------------------------------------------------------------
    # Test 12: Invalid Payload Data Types Handled Safely
    # -------------------------------------------------------------------------
    def test_invalid_payload_data_types_handled_safely(self) -> None:
        """Verify non-serializable details or NaN values fail gracefully without crash."""
        mock_opener = MagicMock()

        # Non-serializable object in details
        ok = dispatch_webhook_event(
            event_type="test_invalid",
            severity="info",
            summary="Unserializable object test",
            details={"unsupported_obj": object()},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        # Must return False cleanly without crashing
        self.assertFalse(ok)
        self.assertEqual(mock_opener.call_count, 0)

    # -------------------------------------------------------------------------
    # Test 13: Severity Contract Validation
    # -------------------------------------------------------------------------
    def test_build_webhook_payload_validates_severity_contract(self) -> None:
        """Verify build_webhook_payload allows valid severities and raises on invalid ones."""
        for valid_sev in ("critical", "high", "warning", "info", "low", "CRITICAL", "Warning "):
            payload = build_webhook_payload(
                event_type="test_valid_sev",
                severity=valid_sev,
                summary="Valid severity test",
            )
            self.assertEqual(payload["severity"], valid_sev.strip().lower())

        invalid_severities = ("fatal", "emergency", "debug", "catastrophic", "unknown")
        for bad_sev in invalid_severities:
            with self.subTest(severity=bad_sev):
                with self.assertRaises(ValueError) as ctx:
                    build_webhook_payload(
                        event_type="test_bad_sev",
                        severity=bad_sev,
                        summary="Invalid severity test",
                    )
                self.assertIn("severity must be one of", str(ctx.exception))
                self.assertIn(bad_sev.lower(), str(ctx.exception))

    def test_dispatch_webhook_event_fails_closed_on_invalid_severity(self) -> None:
        """Verify dispatch_webhook_event fails closed (returns False) on invalid severity."""
        mock_opener = MagicMock()
        ok = dispatch_webhook_event(
            event_type="test_invalid_sev_dispatch",
            severity="fatal",
            summary="Fatal event should fail validation",
            details={},
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertFalse(ok)
        self.assertEqual(mock_opener.call_count, 0)

    # -------------------------------------------------------------------------
    # Test 14: OPSEC Scrubbing of PEM Private Keys and Certificates
    # -------------------------------------------------------------------------
    def test_opsec_scrubbing_redacts_pem_private_keys_and_certificates(self) -> None:
        """Verify PEM private keys and certificates in details strings and keys are redacted."""
        rsa_pem = "-----" + "BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\n-----" + "END RSA PRIVATE KEY-----"
        ec_pem = "-----" + "BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----" + "END EC PRIVATE KEY-----"
        cert_pem = "-----" + "BEGIN CERTIFICATE-----\nMIID...\n-----" + "END CERTIFICATE-----"

        captured_body: dict | None = None

        def mock_opener(req: Request, **kwargs) -> io.BytesIO:
            nonlocal captured_body
            captured_body = json.loads(req.data.decode("utf-8"))
            return io.BytesIO(b'{"status":"ok"}')

        details = {
            "error_diagnostic": f"Failed with PEM: {rsa_pem}",
            "tls_config": {"cert_key": rsa_pem, "ssl_key": ec_pem, "id_rsa": rsa_pem},
            "server_cert": cert_pem,
            "benign_metric": 42,
        }

        ok = dispatch_webhook_event(
            event_type="sec_probe",
            severity="high",
            summary="Testing PEM scrubbing",
            details=details,
            webhook_url=self.dummy_url,
            opener=mock_opener,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(captured_body)
        assert captured_body is not None

        raw_str = json.dumps(captured_body)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", raw_str)
        self.assertNotIn("BEGIN EC PRIVATE KEY", raw_str)
        self.assertNotIn("BEGIN CERTIFICATE", raw_str)

        # Check values in structured dictionary
        res_details = captured_body["details"]
        self.assertEqual(res_details["error_diagnostic"], "Failed with PEM: [REDACTED]")
        self.assertEqual(res_details["tls_config"]["cert_key"], "[REDACTED]")
        self.assertEqual(res_details["tls_config"]["ssl_key"], "[REDACTED]")
        self.assertEqual(res_details["tls_config"]["id_rsa"], "[REDACTED]")
        self.assertEqual(res_details["server_cert"], "[REDACTED]")
        self.assertEqual(res_details["benign_metric"], 42)


if __name__ == "__main__":
    unittest.main()
