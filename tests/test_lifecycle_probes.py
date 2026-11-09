# SPDX-License-Identifier: Apache-2.0
"""Unit and integration tests for Kubernetes lifecycle probes and structured logging."""

from __future__ import annotations

import http.client
import io
import json
import logging
import os
import socketserver
import threading
import unittest
from unittest.mock import patch

from opscryer_browser import (
    GATEWAY_VERSION,
    StructuredJsonFormatter,
    _build_frontend_handler,
    configure_gateway_logging,
    logger,
)


class TestLifecycleProbesAndLogging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handler_class = _build_frontend_handler()
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), cls.handler_class)
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server)

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.handler_class._readiness_override = None

    def request(self, method: str, path: str, body: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, str, Any]:
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        req_headers = dict(headers or {})
        try:
            conn.request(method, path, body=body, headers=req_headers)
            res = conn.getresponse()
            raw = res.read()
            ct = res.getheader("Content-Type", "")
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception:
                data = raw
            return res.status, ct, data
        finally:
            conn.close()

    # -----------------------------------------------------------------------
    # GET /healthz (Liveness) Tests
    # -----------------------------------------------------------------------

    def test_healthz_returns_200_and_expected_schema(self):
        status, ct, data = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("uptime_seconds", data)
        self.assertIsInstance(data["uptime_seconds"], (int, float))
        self.assertGreaterEqual(data["uptime_seconds"], 0.0)
        self.assertEqual(data.get("pid"), os.getpid())
        self.assertEqual(data.get("version"), GATEWAY_VERSION)

    def test_healthz_head_request(self):
        status, ct, _ = self.request("HEAD", "/healthz")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)

    def test_healthz_rejects_query_parameters_with_400(self):
        status, ct, data = self.request("GET", "/healthz?unexpected=true")
        self.assertEqual(status, 400)
        self.assertIn("application/json", ct)
        self.assertIn("error", data)
        self.assertEqual(data["error"], "Invalid query parameters")

    def test_healthz_rejects_post_method_with_405(self):
        status, ct, data = self.request("POST", "/healthz")
        self.assertEqual(status, 405)
        self.assertIn("application/json", ct)
        self.assertIn("error", data)

    # -----------------------------------------------------------------------
    # GET /readyz (Readiness) Tests
    # -----------------------------------------------------------------------

    def test_readyz_returns_200_when_all_subsystems_healthy(self):
        status, ct, data = self.request("GET", "/readyz")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("status"), "ready")
        self.assertTrue(data.get("graph_loaded"))
        self.assertTrue(data.get("airlock_ready"))
        self.assertTrue(data.get("config_loaded"))

    def test_readyz_head_request(self):
        status, ct, _ = self.request("HEAD", "/readyz")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)

    def test_readyz_rejects_query_parameters_with_400(self):
        status, ct, data = self.request("GET", "/readyz?format=json")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_readyz_rejects_post_method_with_405(self):
        status, ct, data = self.request("POST", "/readyz")
        self.assertEqual(status, 405)
        self.assertIn("application/json", ct)
        self.assertIn("error", data)

    def test_readyz_returns_503_when_readiness_override_disabled(self):
        self.handler_class._readiness_override = False
        status, ct, data = self.request("GET", "/readyz")
        self.assertEqual(status, 503)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("status"), "not_ready")
        self.assertIn("reason", data)

    def test_readyz_returns_503_when_graph_fails(self):
        with patch.object(self.handler_class, "_get_backend_engine", side_effect=RuntimeError("Graph engine crashed")):
            status, ct, data = self.request("GET", "/readyz")
            self.assertEqual(status, 503)
            self.assertEqual(data.get("status"), "not_ready")
            self.assertFalse(data.get("graph_loaded"))
            self.assertIn("graph engine unavailable", data.get("reason", ""))

    def test_readyz_returns_503_when_airlock_fails(self):
        with patch("security_airlock.evaluate_code_search_airlock", side_effect=Exception("Airlock failure")):
            status, ct, data = self.request("GET", "/readyz")
            self.assertEqual(status, 503)
            self.assertEqual(data.get("status"), "not_ready")
            self.assertFalse(data.get("airlock_ready"))
            self.assertIn("security airlock check failed", data.get("reason", ""))

    def test_readyz_returns_503_when_config_fails(self):
        with patch("opscryer_config.get_config_value", return_value=None):
            status, ct, data = self.request("GET", "/readyz")
            self.assertEqual(status, 503)
            self.assertEqual(data.get("status"), "not_ready")
            self.assertFalse(data.get("config_loaded"))

    # -----------------------------------------------------------------------
    # Structured Operational Logging Tests
    # -----------------------------------------------------------------------

    def test_structured_json_formatter_produces_valid_json(self):
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="opscryer.gateway",
            level=logging.INFO,
            pathname="opscryer_browser.py",
            lineno=100,
            msg="Request processed successfully",
            args=(),
            exc_info=None,
        )
        record.client_ip = "127.0.0.1"
        record.method = "GET"
        record.path = "/healthz"
        record.status_code = 200

        formatted = formatter.format(record)
        entry = json.loads(formatted)
        self.assertEqual(entry["level"], "INFO")
        self.assertEqual(entry["logger"], "opscryer.gateway")
        self.assertEqual(entry["message"], "Request processed successfully")
        self.assertEqual(entry["subsystem"], "gateway")
        self.assertEqual(entry["client_ip"], "127.0.0.1")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["path"], "/healthz")
        self.assertEqual(entry["status_code"], 200)
        self.assertIn("timestamp", entry)

    def test_structured_json_formatter_includes_exception_traceback(self):
        formatter = StructuredJsonFormatter()
        try:
            raise ValueError("Canary simulated failure")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="opscryer.gateway",
            level=logging.ERROR,
            pathname="opscryer_browser.py",
            lineno=120,
            msg="Exception trapped",
            args=(),
            exc_info=exc_info,
        )
        entry = json.loads(formatter.format(record))
        self.assertIn("exc_info", entry)
        self.assertIn("Canary simulated failure", entry["exc_info"])

    def test_gateway_logging_captures_http_requests(self):
        log_stream = io.StringIO()
        mem_handler = logging.StreamHandler(log_stream)
        mem_handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(mem_handler)
        self.addCleanup(logger.removeHandler, mem_handler)

        configure_gateway_logging(level="INFO")
        status, _, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)

        logs = log_stream.getvalue().strip().splitlines()
        self.assertGreaterEqual(len(logs), 1)
        found_healthz_log = False
        for line in logs:
            try:
                item = json.loads(line)
                if item.get("path") == "/healthz" and item.get("status_code") == 200:
                    found_healthz_log = True
                    break
            except Exception:
                continue
        self.assertTrue(found_healthz_log, f"Expected /healthz completion log in: {logs}")


if __name__ == "__main__":
    unittest.main()
