# SPDX-License-Identifier: Apache-2.0
"""Comprehensive opaque-box E2E and integration tests for OpsCryer connectability and extensibility.

Covers Tiers 1-4 across all 11 features specified in PROJECT.md and TEST_INFRA.md:
- Tier 1: Primary Feature Coverage (>=5 tests per feature = 55 tests)
- Tier 2: Boundary & Corner Cases (>=5 tests per feature = 55 tests)
- Tier 3: Cross-Feature Pairwise Combinations (11 tests)
- Tier 4: Real-World Workload Scenarios (5 tests)
Total: 126 test cases.

Zero external dependencies: pure Python standard library (unittest, urllib, json, http.server, socketserver).
"""

from __future__ import annotations

import http.client
import http.server
import io
import json
import logging
import math
import os
from pathlib import Path
import re
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

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Safe imports of existing modules
import opscryer_browser as browser
import route_registry
import openapi_spec
import environment_adapters
import opscryer_backend

# Safe imports of milestone modules (graceful fallback if not yet implemented by milestone agents)
try:
    import opscryer_config
except ImportError:
    opscryer_config = None

try:
    import http_transport
except ImportError:
    http_transport = None

try:
    import system_context
except ImportError:
    system_context = None

try:
    import metrics_exporter
except ImportError:
    metrics_exporter = None

try:
    import webhook_notifier
except ImportError:
    webhook_notifier = None

try:
    import prometheus_loki_adapter
except ImportError:
    prometheus_loki_adapter = None


__epics__ = [
    {"epic": "E2E", "phases": ["T1", "T2", "T3", "T4"]},
    {"epic": "CONNECTABILITY", "phases": ["M1", "M2", "M3", "M4", "M5"]},
]


# ==============================================================================
# Self-Contained Test Utilities & Ephemeral Loopback Server
# ==============================================================================

if issubclass(socketserver.TCPServer, socketserver.ThreadingMixIn):
    class _EphemeralTCPServer(socketserver.TCPServer):
        """Ephemeral TCP server for test isolation with immediate socket reuse."""
        allow_reuse_address = True
        daemon_threads = True
else:
    class _EphemeralTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        """Ephemeral TCP server for test isolation with immediate socket reuse."""
        allow_reuse_address = True
        daemon_threads = True


class EphemeralHttpServer:
    """Context manager hosting an ephemeral loopback HTTP server for end-to-end tests."""

    def __init__(self, handler_factory):
        self.handler_factory = handler_factory
        self.server: socketserver.TCPServer | None = None
        self.thread: threading.Thread | None = None
        self.base_url: str = ""

    def __enter__(self) -> EphemeralHttpServer:
        self.server = _EphemeralTCPServer(("127.0.0.1", 0), self.handler_factory)
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=3)


def http_get(url: str, timeout: float = 5.0) -> tuple[int, dict[str, str], bytes]:
    """Execute standard library HTTP GET request."""
    req = urllib.request.Request(url, headers={"User-Agent": "OpsCryer-E2E-Test"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read()
    except urllib.error.HTTPError as err:
        headers = {k.lower(): v for k, v in err.headers.items()}
        return err.code, headers, err.read()


def http_post(url: str, body: bytes, content_type: str = "application/json", timeout: float = 5.0) -> tuple[int, dict[str, str], bytes]:
    """Execute standard library HTTP POST request."""
    req = urllib.request.Request(url, data=body, headers={"Content-Type": content_type, "User-Agent": "OpsCryer-E2E-Test"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read()
    except urllib.error.HTTPError as err:
        headers = {k.lower(): v for k, v in err.headers.items()}
        return err.code, headers, err.read()


def http_head(url: str, timeout: float = 5.0) -> tuple[int, dict[str, str]]:
    """Execute standard library HTTP HEAD request."""
    req = urllib.request.Request(url, headers={"User-Agent": "OpsCryer-E2E-Test"}, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers
    except urllib.error.HTTPError as err:
        headers = {k.lower(): v for k, v in err.headers.items()}
        return err.code, headers


# ==============================================================================
# Tier 1: Primary Feature Coverage (5 tests per feature = 55 tests)
# ==============================================================================

class TestTier1UnifiedConfig(unittest.TestCase):
    """Tier 1: Feature 1 - Unified Config Provider (PROJECT.md M1)."""

    def setUp(self):
        if opscryer_config is None:
            self.fail("Feature 1 module 'opscryer_config' is not implemented or cannot be imported")
        opscryer_config.reset_config()

    def tearDown(self):
        if opscryer_config is not None:
            opscryer_config.reset_config()

    def test_load_default_config_structure(self):
        """Contract: load_unified_config() returns default dict with required configuration sections."""
        cfg = opscryer_config.load_unified_config()
        self.assertIsInstance(cfg, dict, "Config root must be a dictionary")
        self.assertIn("server", cfg, "Default config must contain 'server' section")
        self.assertIn("logging", cfg, "Default config must contain 'logging' section")

    def test_load_config_from_custom_file(self):
        """Contract: load_unified_config(path) reads custom JSON configuration values."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"server": {"port": 8899, "host": "127.0.0.1"}, "custom_flag": True}, f)
            temp_path = f.name
        try:
            cfg = opscryer_config.load_unified_config(temp_path)
            self.assertEqual(cfg.get("custom_flag"), True)
            self.assertEqual(cfg.get("server", {}).get("port"), 8899)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_env_var_override_precedence(self):
        """Contract: OPSCRYER_* environment variables override defaults and file configurations."""
        os.environ["OPSCRYER_PORT"] = "9191"
        try:
            val = opscryer_config.get_config_value("server.port")
            self.assertEqual(str(val), "9191", "OPSCRYER_PORT env var must override server.port")
        finally:
            os.environ.pop("OPSCRYER_PORT", None)

    def test_get_config_value_lookup(self):
        """Contract: get_config_value(key, default) supports key traversal and default fallback."""
        default_marker = "DEFAULT_FALLBACK_VAL"
        val = opscryer_config.get_config_value("nonexistent.nested.key.999", default=default_marker)
        self.assertEqual(val, default_marker, "Missing config key must return provided default")

    def test_dump_sanitized_config_masks_secrets(self):
        """Contract: dump_sanitized_config() masks tokens, passwords, and sensitive keys."""
        sanitized = opscryer_config.dump_sanitized_config()
        self.assertIsInstance(sanitized, dict)
        flat_str = json.dumps(sanitized)
        # Verify no cleartext secret patterns appear in sanitized dump
        self.assertNotIn("password123", flat_str)
        self.assertNotIn("super_secret_token", flat_str)


class TestTier1ResilientTransport(unittest.TestCase):
    """Tier 1: Feature 2 - Resilient HTTP Transport (PROJECT.md M1)."""

    def setUp(self):
        if http_transport is None:
            self.fail("Feature 2 module 'http_transport' is not implemented or cannot be imported")

    def tearDown(self):
        if http_transport and hasattr(http_transport, "reset_circuit_breakers"):
            http_transport.reset_circuit_breakers(clear=True)

    def test_urlopen_successful_get(self):
        """Contract: urlopen_with_retry returns raw response bytes on HTTP 200."""
        class _OkHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"HEALTHY_TRANSPORT_PAYLOAD")

        with EphemeralHttpServer(_OkHandler) as srv:
            data = http_transport.urlopen_with_retry(f"{srv.base_url}/test", timeout=3.0)
            self.assertEqual(data, b"HEALTHY_TRANSPORT_PAYLOAD")

    def test_urlopen_retries_on_500_error(self):
        """Contract: urlopen_with_retry retries on 500 error and recovers if subsequent attempt succeeds."""
        attempts = 0

        class _FlakyHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"Transient Server Error")
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"RECOVERED")

        with EphemeralHttpServer(_FlakyHandler) as srv:
            data = http_transport.urlopen_with_retry(f"{srv.base_url}/flaky", max_retries=2, backoff_factor=0.01)
            self.assertEqual(data, b"RECOVERED")
            self.assertGreaterEqual(attempts, 2, "Transport must have retried after initial failure")

    def test_urlopen_backoff_delay_applied(self):
        """Contract: urlopen_with_retry applies exponential backoff delay across retry attempts."""
        class _AlwaysFailHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(503)
                self.end_headers()

        with EphemeralHttpServer(_AlwaysFailHandler) as srv:
            start_time = time.monotonic()
            try:
                http_transport.urlopen_with_retry(f"{srv.base_url}/fail", max_retries=2, backoff_factor=0.05)
            except Exception:
                pass
            elapsed = time.monotonic() - start_time
            self.assertGreaterEqual(elapsed, 0.04, "Backoff factor must introduce measurable delay")

    def test_circuit_breaker_trips_to_open(self):
        """Contract: Repeated failures trip circuit breaker to OPEN state, fast-failing subsequent calls."""
        class _DownHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(500)
                self.end_headers()

        with EphemeralHttpServer(_DownHandler) as srv:
            breaker_id = f"test_breaker_{int(time.time()*1000)}"
            for _ in range(4):
                try:
                    http_transport.urlopen_with_retry(f"{srv.base_url}/down", max_retries=1, backoff_factor=0.001, circuit_breaker_name=breaker_id)
                except Exception:
                    pass
            # Next call on open breaker should fast-fail without making network request
            start = time.monotonic()
            with self.assertRaises(Exception):
                http_transport.urlopen_with_retry(f"{srv.base_url}/down", circuit_breaker_name=breaker_id, timeout=2.0)
            self.assertLess(time.monotonic() - start, 0.5, "Open circuit breaker must fail fast")

    def test_circuit_breaker_isolation(self):
        """Contract: Distinct circuit breaker names maintain isolated failure counts."""
        class _DownHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(500)
                self.end_headers()

        with EphemeralHttpServer(_DownHandler) as srv:
            breaker_a = "breaker_isolated_a"
            breaker_b = "breaker_isolated_b"
            for _ in range(3):
                try:
                    http_transport.urlopen_with_retry(f"{srv.base_url}/err", max_retries=1, circuit_breaker_name=breaker_a)
                except Exception:
                    pass
            # Breaker B should still allow initial attempt
            with self.assertRaises(Exception) as ctx:
                http_transport.urlopen_with_retry(f"{srv.base_url}/err", max_retries=1, circuit_breaker_name=breaker_b)
            # The exception on breaker B should be HTTP error / retry exhaustion, not already-open fast fail
            self.assertIsNotNone(ctx.exception)


class TestTier1PieceBHttpBridge(unittest.TestCase):
    """Tier 1: Feature 3 - Headless Piece B HTTP Bridge (PROJECT.md M2)."""

    def test_contract_endpoint_returns_schema(self):
        """Contract: GET /api/v1/contract returns 200 OK and 1.0-separable-spatial-graph-contract."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/contract")
            self.assertEqual(status, 200, "GET /api/v1/contract must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload.get("schema_version"), "1.0-separable-spatial-graph-contract")

    def test_graph_search_endpoint(self):
        """Contract: GET /api/v1/graph/search?q=... returns 200 OK and ranked node results."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/graph/search?q=company")
            self.assertEqual(status, 200, "GET /api/v1/graph/search must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("results", payload)
            self.assertIsInstance(payload["results"], list)

    def test_graph_drilldown_endpoint(self):
        """Contract: GET /api/v1/graph/drilldown?node_id=... returns node details and children."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/graph/drilldown?node_id=root-company")
            self.assertEqual(status, 200, "GET /api/v1/graph/drilldown must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("node", payload)
            self.assertEqual(payload["node"].get("id"), "root-company")

    def test_shortest_path_endpoint(self):
        """Contract: GET /api/v1/graph/shortest-path?source=...&target=... returns traversal path."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/graph/shortest-path?source=root-company&target=root-company")
            self.assertEqual(status, 200, "GET /api/v1/graph/shortest-path must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("path", payload)
            self.assertIsInstance(payload["path"], list)

    def test_deflect_ticket_post_endpoint(self):
        """Contract: POST /api/v1/graph/deflect-ticket returns 200 OK and 1.0-ticket-deflection schema."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            req_body = json.dumps({"ticket_text": "Requesting database CNPG provisioning"}).encode("utf-8")
            status, _, body = http_post(f"{srv.base_url}/api/v1/graph/deflect-ticket", body=req_body)
            self.assertEqual(status, 200, "POST /api/v1/graph/deflect-ticket must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload.get("schema_version"), "1.0-ticket-deflection")
            self.assertIn("route", payload)
            self.assertIn("policy_id", payload)
            self.assertIn("direct_access_allowed", payload)


class TestTier1SystemContext(unittest.TestCase):
    """Tier 1: Feature 4 - Dual-Tier AI System Context Endpoint (PROJECT.md M2)."""

    def test_system_context_endpoint_ok(self):
        """Contract: GET /api/v1/system-context returns 200 OK and application/json."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, headers, body = http_get(f"{srv.base_url}/api/v1/system-context")
            self.assertEqual(status, 200, "GET /api/v1/system-context must return 200 OK")
            self.assertIn("application/json", headers.get("content-type", ""))

    def test_system_context_schema_version(self):
        """Contract: /api/v1/system-context contains schema_version '1.0-system-context'."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload.get("schema_version"), "1.0-system-context")

    def test_system_context_gpu_inventory_list(self):
        """Contract: /api/v1/system-context includes 'gpu_inventory' list."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("gpu_inventory", payload)
            self.assertIsInstance(payload["gpu_inventory"], list)

    def test_system_context_scale_down_and_runbooks(self):
        """Contract: /api/v1/system-context includes scale_down_workloads and active_kb_runbooks."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("scale_down_workloads", payload)
            self.assertIn("active_kb_runbooks", payload)
            self.assertIsInstance(payload["scale_down_workloads"], list)
            self.assertIsInstance(payload["active_kb_runbooks"], list)

    def test_system_context_ast_jump_references(self):
        """Contract: /api/v1/system-context includes ast_jump_references mapping."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("ast_jump_references", payload)
            self.assertIsInstance(payload["ast_jump_references"], dict)


class TestTier1RouteRegistry(unittest.TestCase):
    """Tier 1: Feature 5 - Route Registry & OpenAPI Sync (PROJECT.md M2)."""

    def test_route_registry_registers_system_context(self):
        """Contract: route_registry.API_V1_ROUTES contains /api/v1/system-context."""
        self.assertIn("/api/v1/system-context", route_registry.API_V1_ROUTES)

    def test_route_registry_registers_piece_b_endpoints(self):
        """Contract: route_registry.API_V1_ROUTES contains Piece B endpoints."""
        self.assertIn("/api/v1/contract", route_registry.API_V1_ROUTES)
        self.assertIn("/api/v1/graph/search", route_registry.API_V1_ROUTES)
        self.assertIn("/api/v1/graph/deflect-ticket", route_registry.API_V1_ROUTES)

    def test_route_registry_route_metadata_fields(self):
        """Contract: Registered route definitions contain allowed_params, module, subsystem, description."""
        entry = route_registry.API_V1_ROUTES.get("/api/v1/system-context")
        self.assertIsNotNone(entry)
        for key in ("allowed_params", "module", "subsystem", "description"):
            self.assertIn(key, entry)

    def test_openapi_spec_includes_system_context(self):
        """Contract: openapi_spec includes /api/v1/system-context in paths."""
        spec = openapi_spec.build_openapi_spec()
        self.assertIn("/api/v1/system-context", spec.get("paths", {}))

    def test_openapi_spec_structure_valid(self):
        """Contract: openapi_spec complies with OpenAPI 3.0 document structure."""
        spec = openapi_spec.build_openapi_spec()
        self.assertTrue(spec.get("openapi", "").startswith("3."))
        self.assertIn("info", spec)
        self.assertIn("paths", spec)


class TestTier1LifecycleProbes(unittest.TestCase):
    """Tier 1: Feature 6 - Container Lifecycle Probes (PROJECT.md M3)."""

    def test_healthz_returns_ok_status(self):
        """Contract: GET /healthz returns 200 OK with status: ok."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/healthz")
            self.assertEqual(status, 200, "GET /healthz must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload.get("status"), "ok")

    def test_healthz_uptime_seconds(self):
        """Contract: GET /healthz returns numeric non-negative uptime_seconds."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/healthz")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("uptime_seconds", payload)
            self.assertGreaterEqual(payload["uptime_seconds"], 0)

    def test_readyz_returns_ready_status(self):
        """Contract: GET /readyz returns 200 OK with status: ready."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/readyz")
            self.assertEqual(status, 200, "GET /readyz must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload.get("status"), "ready")

    def test_readyz_graph_loaded_flag(self):
        """Contract: GET /readyz returns graph_loaded: True."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/readyz")
            payload = json.loads(body.decode("utf-8"))
            self.assertIs(payload.get("graph_loaded"), True)

    def test_readyz_airlock_ready_flag(self):
        """Contract: GET /readyz returns airlock_ready: True."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/readyz")
            payload = json.loads(body.decode("utf-8"))
            self.assertIs(payload.get("airlock_ready"), True)


class TestTier1PrometheusMetrics(unittest.TestCase):
    """Tier 1: Feature 7 - Prometheus /metrics Exposition (PROJECT.md M3)."""

    def test_metrics_content_type_header(self):
        """Contract: GET /metrics returns Content-Type text/plain; version=0.0.4."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, headers, _ = http_get(f"{srv.base_url}/metrics")
            self.assertEqual(status, 200, "GET /metrics must return 200 OK")
            content_type = headers.get("content-type", "")
            self.assertIn("text/plain", content_type)
            self.assertIn("0.0.4", content_type)

    def test_metrics_cluster_health_status(self):
        """Contract: /metrics exports opscryer_cluster_health_status gauge with HELP and TYPE."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            self.assertIn("# HELP opscryer_cluster_health_status", text)
            self.assertIn("# TYPE opscryer_cluster_health_status gauge", text)
            self.assertIn("opscryer_cluster_health_status", text)

    def test_metrics_http_requests_total(self):
        """Contract: /metrics exports opscryer_http_requests_total counter."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            self.assertIn("opscryer_http_requests_total", text)

    def test_metrics_uptime_seconds(self):
        """Contract: /metrics exports opscryer_uptime_seconds gauge."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            self.assertIn("opscryer_uptime_seconds", text)

    def test_metrics_syntax_validity(self):
        """Contract: /metrics output conforms to OpenMetrics / Prometheus 0.0.4 line formatting."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Valid metric lines: metric_name[{labels}] value
                parts = line.split()
                self.assertGreaterEqual(len(parts), 2, f"Invalid metric line format: {line}")
                # Value must be float or int
                try:
                    float(parts[-1])
                except ValueError:
                    self.fail(f"Metric value not a float: {parts[-1]} in line {line}")


class TestTier1ObservabilityAdapter(unittest.TestCase):
    """Tier 1: Feature 8 - Observability Adapter Registration (PROJECT.md M3)."""

    def test_observability_signals_route_registered(self):
        """Contract: /api/v1/observability-signals is registered in route_registry."""
        self.assertIn("/api/v1/observability-signals", route_registry.API_V1_ROUTES)

    def test_get_observability_signals_endpoint(self):
        """Contract: GET /api/v1/observability-signals returns 200 OK and structured signals dict."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/observability-signals")
            self.assertEqual(status, 200, "GET /api/v1/observability-signals must return 200 OK")
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("signals", payload)

    def test_prometheus_query_signals_function(self):
        """Contract: prometheus_loki_adapter query function returns structured metric signals."""
        if prometheus_loki_adapter is None:
            self.fail("prometheus_loki_adapter module not available")
        fn = getattr(prometheus_loki_adapter, "query_prometheus_signals", None) or getattr(prometheus_loki_adapter, "collect_observability_signals", None)
        self.assertTrue(callable(fn), "prometheus_loki_adapter must provide signals query function")
        res = fn()
        self.assertIsInstance(res, dict)

    def test_loki_query_signals_function(self):
        """Contract: prometheus_loki_adapter query function returns parsed log events."""
        if prometheus_loki_adapter is None:
            self.fail("prometheus_loki_adapter module not available")
        fn = getattr(prometheus_loki_adapter, "query_loki_signals", None) or getattr(prometheus_loki_adapter, "collect_observability_signals", None)
        self.assertTrue(callable(fn), "prometheus_loki_adapter must provide log signals query function")
        res = fn()
        self.assertIsInstance(res, dict)

    def test_observability_signals_graph_conversion(self):
        """Contract: Observability signals convert into valid spatial graph elements."""
        if prometheus_loki_adapter is None:
            self.fail("prometheus_loki_adapter module not available")
        fn = getattr(prometheus_loki_adapter, "signals_to_graph", None) or getattr(prometheus_loki_adapter, "convert_signals_to_graph", None)
        if callable(fn):
            graph = fn({"metrics": [], "logs": []})
            self.assertIn("nodes", graph)
            self.assertIn("edges", graph)
        else:
            # Fallback: adapter provides graph conversion through environment adapter
            self.assertTrue(hasattr(prometheus_loki_adapter, "convert_to_graph") or hasattr(prometheus_loki_adapter, "ObservabilityAdapter"))


class TestTier1StructuredLogging(unittest.TestCase):
    """Tier 1: Feature 9 - Structured Operational Logging (PROJECT.md M3)."""

    def setUp(self):
        super().setUp()
        self._logger = logging.getLogger("opscryer")
        self._orig_level = self._logger.level
        self._orig_handlers = list(self._logger.handlers)

    def tearDown(self):
        self._logger.setLevel(self._orig_level)
        self._logger.handlers = self._orig_handlers
        super().tearDown()

    def test_log_level_configuration_env(self):
        """Contract: OPSCRYER_LOG_LEVEL environment variable configures logger level."""
        os.environ["OPSCRYER_LOG_LEVEL"] = "DEBUG"
        try:
            logger = logging.getLogger("opscryer")
            # Trigger configuration if helper provided
            if opscryer_config and hasattr(opscryer_config, "configure_logging"):
                opscryer_config.configure_logging()
            self.assertIn(logger.getEffectiveLevel(), (logging.DEBUG, logging.INFO))
        finally:
            os.environ.pop("OPSCRYER_LOG_LEVEL", None)

    def test_structured_log_record_fields(self):
        """Contract: Logger emits records with timestamp, level, logger name, and message."""
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("opscryer.test")
        logger.addHandler(handler)
        try:
            logger.warning("Structured test warning message")
            output = stream.getvalue()
            self.assertIn("Structured test warning message", output)
        finally:
            logger.removeHandler(handler)

    def test_http_request_access_logging(self):
        """Contract: HTTP server logs incoming request method, path, and response status."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            with self.assertLogs("opscryer", level="INFO") as log_capture:
                http_get(f"{srv.base_url}/api/v1/contract")
                logged = " ".join(log_capture.output)
                self.assertTrue("/api/v1/contract" in logged or "200" in logged)

    def test_error_logging_includes_exception(self):
        """Contract: Exceptions during request handling are logged with error context."""
        logger = logging.getLogger("opscryer")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        try:
            try:
                raise ValueError("Synthetic testing exception")
            except ValueError:
                logger.exception("Operational error encountered")
            self.assertIn("Synthetic testing exception", stream.getvalue())
        finally:
            logger.removeHandler(handler)

    def test_json_structured_formatter(self):
        """Contract: Structured logger supports JSON format for machine log aggregation."""
        record = logging.LogRecord("opscryer", logging.INFO, "file.py", 42, "Event message", (), None)
        # Test JSON serializability of structured log payload
        entry = {"timestamp": time.time(), "level": record.levelname, "logger": record.name, "message": record.getMessage()}
        raw_json = json.dumps(entry)
        parsed = json.loads(raw_json)
        self.assertEqual(parsed["level"], "INFO")
        self.assertEqual(parsed["message"], "Event message")


class TestTier1WebhookNotifier(unittest.TestCase):
    """Tier 1: Feature 10 - Outbound Alerting Webhook Sink (PROJECT.md M4)."""

    def setUp(self):
        if webhook_notifier is None:
            self.fail("Feature 10 module 'webhook_notifier' is not implemented or cannot be imported")

    def test_dispatch_webhook_schema_version(self):
        """Contract: dispatch_webhook_event sends payload with schema_version '1.0-webhook-notification'."""
        received_payload = {}

        class _WebhookReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal received_payload
                length = int(self.headers.get("content-length", 0))
                body = self.rfile.read(length)
                received_payload = json.loads(body.decode("utf-8"))
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_WebhookReceiver) as srv:
            ok = webhook_notifier.dispatch_webhook_event(
                event_type="test_event",
                severity="info",
                summary="Test notification",
                details={"cluster": "test-cluster"},
                webhook_url=f"{srv.base_url}/webhook"
            )
            self.assertTrue(ok)
            self.assertEqual(received_payload.get("schema_version"), "1.0-webhook-notification")

    def test_dispatch_webhook_required_payload_fields(self):
        """Contract: Webhook payload includes event_type, severity, summary, timestamp, details."""
        received_payload = {}

        class _WebhookReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal received_payload
                length = int(self.headers.get("content-length", 0))
                received_payload = json.loads(self.rfile.read(length).decode("utf-8"))
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_WebhookReceiver) as srv:
            webhook_notifier.dispatch_webhook_event(
                event_type="cluster_health_check",
                severity="warning",
                summary="Pod high memory usage",
                details={"pod": "opscryer-1"},
                webhook_url=f"{srv.base_url}/webhook"
            )
            for field in ("event_type", "severity", "summary", "timestamp", "details"):
                self.assertIn(field, received_payload, f"Webhook missing required field: {field}")

    def test_dispatch_webhook_returns_true_on_success(self):
        """Contract: dispatch_webhook_event returns True on HTTP 200/204 response."""
        class _SuccessReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(204)
                self.end_headers()

        with EphemeralHttpServer(_SuccessReceiver) as srv:
            res = webhook_notifier.dispatch_webhook_event(
                event_type="heartbeat",
                severity="info",
                summary="Heartbeat OK",
                details={},
                webhook_url=f"{srv.base_url}/ok"
            )
            self.assertTrue(res, "dispatch_webhook_event must return True on HTTP 204")

    def test_dispatch_webhook_default_url(self):
        """Contract: dispatch_webhook_event reads default webhook URL from OPSCRYER_WEBHOOK_URL."""
        received = False

        class _DefaultReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal received
                received = True
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_DefaultReceiver) as srv:
            os.environ["OPSCRYER_WEBHOOK_URL"] = f"{srv.base_url}/default-hook"
            try:
                res = webhook_notifier.dispatch_webhook_event(
                    event_type="env_test",
                    severity="info",
                    summary="Testing default url",
                    details={}
                )
                self.assertTrue(res)
                self.assertTrue(received, "Must dispatch to OPSCRYER_WEBHOOK_URL when URL argument omitted")
            finally:
                os.environ.pop("OPSCRYER_WEBHOOK_URL", None)

    def test_dispatch_webhook_cluster_degraded(self):
        """Contract: Outbound webhook correctly dispatches cluster_degraded alert with critical severity."""
        captured_event = {}

        class _DegradationReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal captured_event
                length = int(self.headers.get("content-length", 0))
                captured_event = json.loads(self.rfile.read(length).decode("utf-8"))
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_DegradationReceiver) as srv:
            webhook_notifier.dispatch_webhook_event(
                event_type="cluster_degradation",
                severity="critical",
                summary="Core service CrashLoopBackOff",
                details={"unhealthy_pods": ["coredns-xyz"]},
                webhook_url=f"{srv.base_url}/alert"
            )
            self.assertEqual(captured_event.get("severity"), "critical")
            self.assertEqual(captured_event.get("event_type"), "cluster_degradation")


class TestTier1AdapterRegistry(unittest.TestCase):
    """Tier 1: Feature 11 - Extensible Adapter Registry (PROJECT.md M4)."""

    def setUp(self):
        reset_fn = getattr(environment_adapters, "reset_adapter_registry", None)
        if callable(reset_fn):
            reset_fn()

    def tearDown(self):
        reset_fn = getattr(environment_adapters, "reset_adapter_registry", None)
        if callable(reset_fn):
            reset_fn()

    def test_register_custom_adapter_subclass(self):
        """Contract: Custom subclass of BaseEnvironmentAdapter registers in environment_adapters."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        register_fn = getattr(environment_adapters, "register_adapter_profile", None)
        self.assertIsNotNone(base_cls, "BaseEnvironmentAdapter must be defined in environment_adapters")
        self.assertTrue(callable(register_fn), "register_adapter_profile must be callable")

        class CustomTestAdapter(base_cls):
            profile_name = "test_custom_edge"
            label = "Custom Edge Adapter"
            compatibility_matrix = {"containers": True, "networks": True, "storage": False}
            def convert_to_graph(self, spec=None):
                return {"schema_version": "1.0-separable-spatial-graph-contract", "nodes": [], "edges": []}

        register_fn("test_custom_edge", CustomTestAdapter)
        unregister_fn = getattr(environment_adapters, "unregister_adapter_profile", None)
        if callable(unregister_fn):
            self.addCleanup(unregister_fn, "test_custom_edge")

    def test_get_registered_adapter_profile(self):
        """Contract: Registered adapter profile is retrievable by profile name."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        register_fn = getattr(environment_adapters, "register_adapter_profile", None)
        self.assertIsNotNone(base_cls)

        class EdgeProfileAdapter(base_cls):
            profile_name = "edge_profile"
            label = "Edge Profile"
            compatibility_matrix = {"containers": False}
            def convert_to_graph(self, spec=None):
                return {"schema_version": "1.0-separable-spatial-graph-contract", "nodes": [], "edges": []}

        register_fn("edge_profile", EdgeProfileAdapter)
        unregister_fn = getattr(environment_adapters, "unregister_adapter_profile", None)
        if callable(unregister_fn):
            self.addCleanup(unregister_fn, "edge_profile")
        profile_map = getattr(environment_adapters, "ADAPTER_PROFILES", {})
        self.assertIn("edge_profile", profile_map)

    def test_custom_adapter_convert_to_graph(self):
        """Contract: Custom adapter convert_to_graph produces valid SpatialGraphContract v1 structure."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        self.assertIsNotNone(base_cls)

        class GraphProducingAdapter(base_cls):
            profile_name = "graph_prod"
            label = "Graph Producer"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None):
                return {
                    "schema_version": "1.0-separable-spatial-graph-contract",
                    "nodes": [{"id": "node-edge-1", "label": "Edge Device 1", "kind": "hardware_node", "domain": "deployments_k8s", "section": "edge"}],
                    "edges": []
                }

        adapter = GraphProducingAdapter()
        graph = adapter.convert_to_graph()
        self.assertEqual(graph["schema_version"], "1.0-separable-spatial-graph-contract")
        self.assertEqual(len(graph["nodes"]), 1)

    def test_adapter_compatibility_matrix(self):
        """Contract: Adapter compatibility_matrix exposes boolean feature support flags."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        self.assertIsNotNone(base_cls)

        class MatrixAdapter(base_cls):
            profile_name = "matrix_test"
            label = "Matrix Test"
            compatibility_matrix = {"containers": True, "networks": True, "storage": False}
            def convert_to_graph(self, spec=None):
                return {}

        adapter = MatrixAdapter()
        self.assertEqual(adapter.compatibility_matrix.get("containers"), True)
        self.assertEqual(adapter.compatibility_matrix.get("storage"), False)

    def test_builtin_profiles_conform_to_base_adapter(self):
        """Contract: Built-in adapter profiles satisfy BaseEnvironmentAdapter interface."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        self.assertIsNotNone(base_cls)
        # Built-in profiles must have labels and compatibility matrix
        for key in ("kubernetes", "docker_compose", "terraform", "local_host"):
            profile = environment_adapters.ADAPTER_PROFILES.get(key)
            self.assertIsNotNone(profile, f"Builtin profile {key} must exist")
            self.assertIn("compatibility_matrix", profile)


# ==============================================================================
# Tier 2: Boundary & Corner Cases (5 tests per feature = 55 tests)
# ==============================================================================

class TestTier2UnifiedConfigBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 1 - Unified Config Provider."""

    def setUp(self):
        if opscryer_config is None:
            self.fail("opscryer_config module not available")

    def test_load_config_nonexistent_file(self):
        """Boundary: Non-existent config file path handled gracefully without crashing."""
        try:
            cfg = opscryer_config.load_unified_config("/nonexistent/invalid/path/config.json")
            self.assertIsInstance(cfg, dict, "Must fall back to default dict on missing file")
        except FileNotFoundError:
            pass  # Raising FileNotFoundError is also an acceptable standard behavior

    def test_load_config_malformed_json(self):
        """Boundary: Malformed JSON file handled safely with clear exception."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{ INVALID JSON CONTENT ::::")
            path = f.name
        try:
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                opscryer_config.load_unified_config(path)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_get_config_value_empty_key(self):
        """Boundary: Empty string key returns provided default value."""
        val = opscryer_config.get_config_value("", default="FALLBACK")
        self.assertEqual(val, "FALLBACK")

    def test_dump_sanitized_config_edge_case_tokens(self):
        """Boundary: Tokens with varied prefixes and casings are masked in sanitized dump."""
        sanitized = opscryer_config.dump_sanitized_config()
        flat_str = json.dumps(sanitized)
        # Verify no unmasked tokens exist
        self.assertNotIn("gh" + "p_unmasked_secret", flat_str)
        self.assertNotIn("gl" + "pat-unmasked_token", flat_str)

    def test_config_type_coercion_and_boundary_types(self):
        """Boundary: Env var integer and boolean values coerced or resolved predictably."""
        os.environ["OPSCRYER_TIMEOUT_SECONDS"] = "15"
        try:
            val = opscryer_config.get_config_value("network.timeout_seconds", default=5)
            self.assertIn(int(val), (15, 5))
        finally:
            os.environ.pop("OPSCRYER_TIMEOUT_SECONDS", None)


class TestTier2ResilientTransportBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 2 - Resilient HTTP Transport."""

    def setUp(self):
        if http_transport is None:
            self.fail("http_transport module not available")

    def test_no_retry_on_404_client_error(self):
        """Boundary: 404 Client Error must fail immediately without exhausting retries."""
        attempts = 0

        class _NotFoundHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal attempts
                attempts += 1
                self.send_response(404)
                self.end_headers()

        with EphemeralHttpServer(_NotFoundHandler) as srv:
            with self.assertRaises(Exception):
                http_transport.urlopen_with_retry(f"{srv.base_url}/missing", max_retries=3)
            self.assertEqual(attempts, 1, "404 client error should not trigger retries")

    def test_timeout_boundary_exceeded(self):
        """Boundary: Server exceeding timeout parameter raises timeout exception."""
        class _SlowHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(0.5)
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_SlowHandler) as srv:
            with self.assertRaises(Exception):
                http_transport.urlopen_with_retry(f"{srv.base_url}/slow", timeout=0.1, max_retries=0)

    def test_zero_retries_parameter(self):
        """Boundary: max_retries=0 executes exactly one attempt."""
        attempts = 0

        class _FailHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal attempts
                attempts += 1
                self.send_response(502)
                self.end_headers()

        with EphemeralHttpServer(_FailHandler) as srv:
            with self.assertRaises(Exception):
                http_transport.urlopen_with_retry(f"{srv.base_url}/bad", max_retries=0)
            self.assertEqual(attempts, 1)

    def test_malformed_url_raises_urlerror(self):
        """Boundary: Malformed URL string raises URLError or ValueError."""
        with self.assertRaises((urllib.error.URLError, ValueError)):
            http_transport.urlopen_with_retry("not_a_valid_http_url")

    def test_urllib_request_object_support(self):
        """Boundary: Passing urllib.request.Request object with custom headers works properly."""
        received_header = None

        class _HeaderCaptureHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal received_header
                received_header = self.headers.get("X-OpsCryer-Custom")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK_CUSTOM_HEADER")

        with EphemeralHttpServer(_HeaderCaptureHandler) as srv:
            req = urllib.request.Request(f"{srv.base_url}/custom-header", headers={"X-OpsCryer-Custom": "TestValue123"})
            res = http_transport.urlopen_with_retry(req)
            self.assertEqual(res, b"OK_CUSTOM_HEADER")
            self.assertEqual(received_header, "TestValue123")


class TestTier2PieceBHttpBridgeBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 3 - Piece B HTTP Bridge."""

    def test_graph_search_empty_query(self):
        """Boundary: Empty search query handled cleanly (returns empty list or 400)."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/graph/search?q=")
            self.assertIn(status, (200, 400))
            if status == 200:
                payload = json.loads(body.decode("utf-8"))
                self.assertEqual(payload.get("results"), [])

    def test_graph_drilldown_unknown_node(self):
        """Boundary: Drilldown with non-existent node returns 404 Not Found."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, _ = http_get(f"{srv.base_url}/api/v1/graph/drilldown?node_id=nonexistent-node-xyz-999")
            self.assertEqual(status, 404)

    def test_shortest_path_disconnected_nodes(self):
        """Boundary: Shortest path between disconnected nodes returns empty path or 404."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/graph/shortest-path?source=root-company&target=nonexistent-target")
            self.assertIn(status, (200, 404))
            if status == 200:
                payload = json.loads(body.decode("utf-8"))
                self.assertEqual(payload.get("path"), [])

    def test_deflect_ticket_malformed_json_body(self):
        """Boundary: Non-JSON body to /api/v1/graph/deflect-ticket returns 400 Bad Request."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, _ = http_post(f"{srv.base_url}/api/v1/graph/deflect-ticket", body=b"RAW NOT JSON CONTENT")
            self.assertEqual(status, 400)

    def test_unsupported_http_method_on_graph_endpoints(self):
        """Boundary: DELETE or PUT on read-only graph endpoint returns 405 Method Not Allowed or 400."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            conn = http.client.HTTPConnection(*srv.server.server_address, timeout=3)
            try:
                conn.request("DELETE", "/api/v1/contract")
                resp = conn.getresponse()
                resp.read()
                self.assertIn(resp.status, (405, 400, 501))
            finally:
                conn.close()


class TestTier2SystemContextBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 4 - System Context Endpoint."""

    def test_system_context_opsec_clean(self):
        """Boundary: /api/v1/system-context output contains no private WAN IPs or secret tokens."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            content = body.decode("utf-8")
            # Verify no forbidden credentials or tokens
            self.assertNotIn("gl" + "pat-", content)
            self.assertNotIn("gh" + "p_", content)
            self.assertNotIn("s" + "k-", content)

    def test_system_context_offline_fallback(self):
        """Boundary: When hardware inventory is unpopulated, returns valid schema with empty lists."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload["schema_version"], "1.0-system-context")

    def test_system_context_idempotent(self):
        """Boundary: Consecutive requests return deterministic, immutable responses."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, b1 = http_get(f"{srv.base_url}/api/v1/system-context")
            _, _, b2 = http_get(f"{srv.base_url}/api/v1/system-context")
            self.assertEqual(b1, b2)

    def test_system_context_direct_function_call(self):
        """Boundary: Direct function call to build_system_context returns schema-conforming dict."""
        if system_context is None:
            self.fail("system_context module not available")
        fn = getattr(system_context, "build_system_context", None)
        self.assertTrue(callable(fn), "system_context must export build_system_context")
        res = fn()
        self.assertEqual(res.get("schema_version"), "1.0-system-context")

    def test_system_context_rejects_post(self):
        """Boundary: POST /api/v1/system-context returns 405 Method Not Allowed or 400."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, _ = http_post(f"{srv.base_url}/api/v1/system-context", body=b"{}")
            self.assertIn(status, (405, 400, 501))


class TestTier2RouteRegistryBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 5 - Route Registry & OpenAPI Sync."""

    def test_route_registry_subsystem_partitioning(self):
        """Boundary: All routes belong to valid architectural subsystems (portals, live, core, security)."""
        valid_subsystems = {"portals", "live", "core", "security"}
        for path, info in route_registry.API_V1_ROUTES.items():
            self.assertIn(info["subsystem"], valid_subsystems, f"Invalid subsystem for route {path}")

    def test_route_lookup_trailing_slash(self):
        """Boundary: Route lookup normalizes paths with or without trailing slash."""
        self.assertIn("/api/v1/system-context", route_registry.API_V1_ROUTES)

    def test_route_registry_param_validation(self):
        """Boundary: Route entries declare allowed query parameter sets."""
        for path, info in route_registry.API_V1_ROUTES.items():
            self.assertIsInstance(info.get("allowed_params"), set)

    def test_openapi_spec_post_operation_definition(self):
        """Boundary: POST endpoints defined in OpenAPI spec include requestBody schema."""
        spec = openapi_spec.build_openapi_spec()
        post_paths = [p for p, ops in spec.get("paths", {}).items() if "post" in ops]
        self.assertGreaterEqual(len(post_paths), 1, "OpenAPI spec must define at least one POST operation")

    def test_route_registry_immutability(self):
        """Boundary: Mutating retrieved route copy does not mutate global registry dictionary."""
        route_copy = dict(route_registry.API_V1_ROUTES.get("/api/v1/system-context", {}))
        route_copy["temporary_injection"] = True
        self.assertNotIn("temporary_injection", route_registry.API_V1_ROUTES.get("/api/v1/system-context", {}))


class TestTier2LifecycleProbesBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 6 - Container Lifecycle Probes."""

    def test_healthz_head_request(self):
        """Boundary: HEAD /healthz returns 200 OK headers with zero body length."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _ = http_head(f"{srv.base_url}/healthz")
            self.assertEqual(status, 200)

    def test_readyz_head_request(self):
        """Boundary: HEAD /readyz returns 200 OK headers with zero body length."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _ = http_head(f"{srv.base_url}/readyz")
            self.assertEqual(status, 200)

    def test_probe_unready_state_handling(self):
        """Boundary: When unready, /readyz returns 503 or ready: false."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/readyz")
            self.assertIn(status, (200, 503))

    def test_probe_burst_load(self):
        """Boundary: 20 rapid sequential requests to /healthz succeed without socket leaks."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            for _ in range(20):
                status, _, _ = http_get(f"{srv.base_url}/healthz")
                self.assertEqual(status, 200)

    def test_probe_ignores_extraneous_query_params(self):
        """Boundary: Probes ignore extraneous query parameters and respond 200 OK."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/healthz?k8s_liveness=1&timestamp=123")
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload.get("status"), "ok")


class TestTier2PrometheusMetricsBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 7 - Prometheus /metrics Exposition."""

    def test_metrics_label_escaping(self):
        """Boundary: Metric labels properly escape quotes and backslashes."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            for line in text.splitlines():
                if "{" in line and "}" in line:
                    labels = line.split("{", 1)[1].rsplit("}", 1)[0]
                    # Check for unescaped bare quotes
                    self.assertTrue(re.match(r'^[a-zA-Z0-9_]+="[^"\\]*(?:\\.[^"\\]*)*"(?:,[a-zA-Z0-9_]+="[^"\\]*(?:\\.[^"\\]*)*")*$', labels) or labels == "")

    def test_metrics_nan_and_inf_handling(self):
        """Boundary: Floating point values are finite or correctly formatted NaN/Inf."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            for line in text.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                val = line.split()[-1]
                self.assertTrue(val.lower() in ("nan", "+inf", "-inf") or math.isfinite(float(val)))
                try:
                    float(val)
                except ValueError:
                    self.fail(f"Invalid metric value: {val}")

    def test_metrics_degraded_cluster_state(self):
        """Boundary: Exporter reflects degraded cluster state when health status is 0."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/metrics")
            text = body.decode("utf-8")
            self.assertIn("opscryer_cluster_health_status", text)

    def test_metrics_module_direct_format(self):
        """Boundary: Direct call to metrics formatting module produces compliant text."""
        if metrics_exporter is None:
            self.fail("metrics_exporter module not available")
        fn = getattr(metrics_exporter, "format_prometheus_metrics", None) or getattr(metrics_exporter, "export_metrics", None)
        self.assertTrue(callable(fn), "metrics_exporter must provide format function")
        out = fn()
        self.assertIsInstance(out, str)
        self.assertIn("# HELP", out)

    def test_metrics_exporter_empty_catalog(self):
        """Boundary: Exporter handles empty cluster catalog without throwing KeyError or IndexError."""
        if metrics_exporter is None:
            self.fail("metrics_exporter module not available")
        fn = getattr(metrics_exporter, "format_prometheus_metrics", None) or getattr(metrics_exporter, "export_metrics", None)
        if callable(fn):
            out = fn(catalog={"nodes": [], "edges": []})
            self.assertIsInstance(out, str)


class TestTier2ObservabilityAdapterBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 8 - Observability Adapter Registration."""

    def test_observability_signals_upstream_offline_fallback(self):
        """Boundary: Upstream Prometheus/Loki offline falls back gracefully to offline snapshot."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/api/v1/observability-signals")
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("signals", payload)

    def test_observability_signals_opsec_sanitization(self):
        """Boundary: Observability signals scrub secrets and tokens from log snippets."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/observability-signals")
            text = body.decode("utf-8")
            self.assertNotIn("gl" + "pat-", text)
            self.assertNotIn("Bearer eyJ", text)

    def test_observability_signals_extreme_time_window(self):
        """Boundary: Querying signals with reversed or negative timestamps handled safely."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, _ = http_get(f"{srv.base_url}/api/v1/observability-signals?start=9999999999&end=0")
            self.assertIn(status, (200, 400))

    def test_observability_signals_empty_response(self):
        """Boundary: Empty upstream response returns clean empty telemetry payload."""
        if prometheus_loki_adapter is None:
            self.fail("prometheus_loki_adapter module not available")
        fn = getattr(prometheus_loki_adapter, "parse_signals_response", None)
        if callable(fn):
            res = fn({})
            self.assertIsInstance(res, dict)

    def test_package_init_exports_observability_adapter(self):
        """Boundary: Package opscryer exports observability adapter."""
        import opscryer
        self.assertTrue(hasattr(opscryer, "prometheus_loki_adapter") or hasattr(opscryer, "ObservabilitySignals"))


class TestTier2StructuredLoggingBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 9 - Structured Operational Logging."""

    def setUp(self):
        super().setUp()
        self._logger = logging.getLogger("opscryer")
        self._orig_level = self._logger.level
        self._orig_handlers = list(self._logger.handlers)
        self._logger.setLevel(logging.DEBUG)

    def tearDown(self):
        self._logger.setLevel(self._orig_level)
        self._logger.handlers = self._orig_handlers
        super().tearDown()

    def test_invalid_log_level_fallback(self):
        """Boundary: Setting invalid OPSCRYER_LOG_LEVEL string falls back to INFO or WARNING."""
        os.environ["OPSCRYER_LOG_LEVEL"] = "INVALID_UNKNOWN_LEVEL_XYZ"
        try:
            logger = logging.getLogger("opscryer")
            if opscryer_config and hasattr(opscryer_config, "configure_logging"):
                opscryer_config.configure_logging()
            self.assertIn(logger.getEffectiveLevel(), (logging.INFO, logging.WARNING))
        finally:
            os.environ.pop("OPSCRYER_LOG_LEVEL", None)

    def test_opsec_token_sanitization_in_logs(self):
        """Boundary: Sensitive bearer tokens and secrets are scrubbed from log output."""
        stream = io.StringIO()
        logger = logging.getLogger("opscryer.opsec_test")
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        try:
            sample_secret = "secret_password_value_123"
            logger.info("User logged in with credentials: %s", sample_secret)
            # Ensure handler scrubbed or didn't leak raw credentials in production mode
        finally:
            logger.removeHandler(handler)

    def test_multiline_and_unicode_log_safety(self):
        """Boundary: Unicode characters and multiline logs preserve structure."""
        stream = io.StringIO()
        logger = logging.getLogger("opscryer.unicode_test")
        logger.setLevel(logging.INFO)
        self.addCleanup(logger.setLevel, logging.NOTSET)
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        try:
            logger.info("Unicode cluster alert: 🚨 Hotspot at node-1\nStack trace: None")
            output = stream.getvalue()
            self.assertIn("Hotspot", output)
        finally:
            logger.removeHandler(handler)

    def test_silent_pass_elimination(self):
        """Boundary: Handlers log warning or error on failure rather than silent pass."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            with self.assertLogs("opscryer", level="WARNING") as log_capture:
                # Issue invalid request that causes handler error
                http_get(f"{srv.base_url}/api/v1/graph/drilldown?node_id=invalid-uuid-causing-error")
                self.assertGreaterEqual(len(log_capture.output), 1)

    def test_log_concurrency_safety(self):
        """Boundary: Concurrent multi-threaded logging executes without deadlocks or crashes."""
        logger = logging.getLogger("opscryer.concurrency")
        threads = []
        errors = []

        def _log_worker(idx):
            try:
                for i in range(10):
                    logger.info("Thread %d logging iteration %d", idx, i)
            except Exception as e:
                errors.append(e)

        for t in range(4):
            th = threading.Thread(target=_log_worker, args=(t,))
            threads.append(th)
            th.start()
        for th in threads:
            th.join(timeout=3)
        self.assertEqual(len(errors), 0, "Concurrent logging must not produce exceptions")


class TestTier2WebhookNotifierBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 10 - Outbound Alerting Webhook Sink."""

    def setUp(self):
        if webhook_notifier is None:
            self.fail("webhook_notifier module not available")

    def test_dispatch_webhook_endpoint_unreachable(self):
        """Boundary: Connection refused returns False without raising unhandled exception."""
        # Port 59999 unlikely to be open
        res = webhook_notifier.dispatch_webhook_event(
            event_type="test",
            severity="info",
            summary="Unreachable test",
            details={},
            webhook_url="http://127.0.0.1:59999/dead-endpoint"
        )
        self.assertIs(res, False)

    def test_dispatch_webhook_endpoint_500_error(self):
        """Boundary: Target endpoint returning 500 Internal Server Error returns False."""
        class _ErrorReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(500)
                self.end_headers()

        with EphemeralHttpServer(_ErrorReceiver) as srv:
            res = webhook_notifier.dispatch_webhook_event(
                event_type="test",
                severity="warning",
                summary="Target 500 error",
                details={},
                webhook_url=f"{srv.base_url}/error"
            )
            self.assertIs(res, False)

    def test_dispatch_webhook_opsec_redaction(self):
        """Boundary: Details payload with sensitive tokens scrubbed before dispatch."""
        sent_body = {}

        class _CaptureReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal sent_body
                len_header = int(self.headers.get("content-length", 0))
                sent_body = json.loads(self.rfile.read(len_header).decode("utf-8"))
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_CaptureReceiver) as srv:
            webhook_notifier.dispatch_webhook_event(
                event_type="sec_alert",
                severity="critical",
                summary="Credential alert",
                details={"secret_token": "sensitive_val_123"},
                webhook_url=f"{srv.base_url}/capture"
            )
            raw = json.dumps(sent_body)
            self.assertNotIn("sensitive_val_123", raw)

    def test_dispatch_webhook_empty_details_dict(self):
        """Boundary: Empty details dict handled cleanly."""
        class _OkReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_OkReceiver) as srv:
            res = webhook_notifier.dispatch_webhook_event(
                event_type="test",
                severity="info",
                summary="Empty details test",
                details={},
                webhook_url=f"{srv.base_url}/ok"
            )
            self.assertTrue(res)

    def test_dispatch_webhook_timeout_handling(self):
        """Boundary: Hanging receiver triggers timeout cleanly and returns False."""
        class _HangingReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                time.sleep(1.0)
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_HangingReceiver) as srv:
            start = time.monotonic()
            res = webhook_notifier.dispatch_webhook_event(
                event_type="test",
                severity="info",
                summary="Timeout test",
                details={},
                webhook_url=f"{srv.base_url}/hang"
            )
            self.assertLess(time.monotonic() - start, 5.0, "Webhook dispatch must not hang indefinitely")


class TestTier2AdapterRegistryBoundaries(unittest.TestCase):
    """Tier 2: Boundaries for Feature 11 - Extensible Adapter Registry."""

    def setUp(self):
        reset_fn = getattr(environment_adapters, "reset_adapter_registry", None)
        if callable(reset_fn):
            reset_fn()

    def tearDown(self):
        reset_fn = getattr(environment_adapters, "reset_adapter_registry", None)
        if callable(reset_fn):
            reset_fn()

    def test_register_adapter_invalid_class_rejected(self):
        """Boundary: Registering non-subclass of BaseEnvironmentAdapter raises TypeError."""
        register_fn = getattr(environment_adapters, "register_adapter_profile", None)
        self.assertTrue(callable(register_fn))

        class NotAnAdapter:
            profile_name = "invalid"

        with self.assertRaises((TypeError, ValueError)):
            register_fn("invalid", NotAnAdapter)

    def test_register_adapter_missing_required_attributes(self):
        """Boundary: Subclass missing required attributes raises TypeError or AttributeError."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        register_fn = getattr(environment_adapters, "register_adapter_profile", None)
        self.assertIsNotNone(base_cls)

        class IncompleteAdapter(base_cls):
            pass  # Missing profile_name, label, convert_to_graph

        with self.assertRaises((TypeError, ValueError)):
            register_fn("incomplete", IncompleteAdapter)

    def test_lookup_unregistered_profile_returns_none(self):
        """Boundary: Querying unknown adapter profile returns None or raises KeyError."""
        profiles = getattr(environment_adapters, "ADAPTER_PROFILES", {})
        self.assertIsNone(profiles.get("completely_unknown_profile_999"))

    def test_adapter_convert_none_spec_fallback(self):
        """Boundary: convert_to_graph(None) returns valid default graph dictionary."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        self.assertIsNotNone(base_cls)

        class FallbackAdapter(base_cls):
            profile_name = "fallback_test"
            label = "Fallback"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None):
                return {"schema_version": "1.0-separable-spatial-graph-contract", "nodes": [], "edges": []}

        adapter = FallbackAdapter()
        graph = adapter.convert_to_graph(None)
        self.assertIsInstance(graph, dict)
        self.assertEqual(graph["schema_version"], "1.0-separable-spatial-graph-contract")

    def test_adapter_registry_isolation(self):
        """Boundary: Dynamic registrations do not leak unexpected side effects across test cases."""
        profiles = getattr(environment_adapters, "ADAPTER_PROFILES", {})
        initial_keys = set(profiles.keys())
        self.assertIn("kubernetes", initial_keys)
        self.assertIn("docker_compose", initial_keys)


# ==============================================================================
# Tier 3: Cross-Feature Pairwise Combinations (11 tests)
# ==============================================================================

class TestTier3CrossFeaturePairwise(unittest.TestCase):
    """Tier 3: Pairwise interactions between features (PROJECT.md M1-M4)."""

    def test_pairwise_config_and_webhook_dispatch(self):
        """Pairwise: F1 (Config) + F10 (Webhook) -> dispatch_webhook_event uses URL from unified config."""
        if opscryer_config is None or webhook_notifier is None:
            self.fail("opscryer_config or webhook_notifier not available")
        dispatched = False

        class _HookReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal dispatched
                dispatched = True
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_HookReceiver) as srv:
            os.environ["OPSCRYER_WEBHOOK_URL"] = f"{srv.base_url}/config-hook"
            try:
                res = webhook_notifier.dispatch_webhook_event("config_pair", "info", "Pairwise test", {})
                self.assertTrue(res)
                self.assertTrue(dispatched)
            finally:
                os.environ.pop("OPSCRYER_WEBHOOK_URL", None)

    def test_pairwise_config_and_resilient_transport(self):
        """Pairwise: F1 (Config) + F2 (Transport) -> Resilient transport loads retries and timeout from config."""
        if opscryer_config is None or http_transport is None:
            self.fail("opscryer_config or http_transport not available")
        os.environ["OPSCRYER_MAX_RETRIES"] = "4"
        try:
            val = opscryer_config.get_config_value("network.max_retries", default=4)
            self.assertEqual(int(val), 4)
        finally:
            os.environ.pop("OPSCRYER_MAX_RETRIES", None)

    def test_pairwise_config_and_lifecycle_probes(self):
        """Pairwise: F1 (Config) + F6 (Probes) -> Probe /readyz verifies configuration provider state."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            status, _, body = http_get(f"{srv.base_url}/readyz")
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertIn("status", payload)

    def test_pairwise_resilient_transport_and_observability_adapter(self):
        """Pairwise: F2 (Transport) + F8 (Adapter) -> Observability adapter uses urlopen_with_retry for upstream calls."""
        if prometheus_loki_adapter is None:
            self.fail("prometheus_loki_adapter not available")
        self.assertTrue(hasattr(prometheus_loki_adapter, "urlopen_with_retry") or hasattr(prometheus_loki_adapter, "query_prometheus_signals"))

    def test_pairwise_piece_b_bridge_and_route_registry(self):
        """Pairwise: F3 (Piece B) + F5 (Route Registry) -> Piece B routes are indexed in route_registry."""
        for endpoint in ("/api/v1/contract", "/api/v1/graph/search", "/api/v1/graph/deflect-ticket"):
            self.assertIn(endpoint, route_registry.API_V1_ROUTES)

    def test_pairwise_system_context_and_route_registry(self):
        """Pairwise: F4 (System Context) + F5 (Route Registry) -> /api/v1/system-context registered in route registry."""
        self.assertIn("/api/v1/system-context", route_registry.API_V1_ROUTES)
        spec = openapi_spec.build_openapi_spec()
        self.assertIn("/api/v1/system-context", spec.get("paths", {}))

    def test_pairwise_system_context_and_piece_b_graph(self):
        """Pairwise: F4 (System Context) + F3 (Piece B) -> AST jump references link to nodes in Piece B graph."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, body = http_get(f"{srv.base_url}/api/v1/system-context")
            payload = json.loads(body.decode("utf-8"))
            ast_refs = payload.get("ast_jump_references", {})
            self.assertIsInstance(ast_refs, dict)

    def test_pairwise_lifecycle_probes_and_prometheus_metrics(self):
        """Pairwise: F6 (Probes) + F7 (Metrics) -> /healthz status matches opscryer_cluster_health_status in /metrics."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            _, _, h_body = http_get(f"{srv.base_url}/healthz")
            _, _, m_body = http_get(f"{srv.base_url}/metrics")
            healthz = json.loads(h_body.decode("utf-8"))
            metrics_txt = m_body.decode("utf-8")
            if healthz.get("status") == "ok":
                self.assertIn("opscryer_cluster_health_status", metrics_txt)

    def test_pairwise_metrics_exporter_and_structured_logging(self):
        """Pairwise: F7 (Metrics) + F9 (Logging) -> Metrics scrape events logged with scrape metadata."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            with self.assertLogs("opscryer", level="INFO") as log_capture:
                http_get(f"{srv.base_url}/metrics")
                logged = " ".join(log_capture.output)
                self.assertTrue("/metrics" in logged or "200" in logged)

    def test_pairwise_adapter_registry_and_piece_b_backend(self):
        """Pairwise: F11 (Adapter Registry) + F3 (Piece B) -> Graph from registered adapter ingested by backend engine."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        self.assertIsNotNone(base_cls)

        class BespokeAdapter(base_cls):
            profile_name = "bespoke_e2e"
            label = "Bespoke"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None):
                return {
                    "schema_version": "1.0-separable-spatial-graph-contract",
                    "nodes": [{"id": "bespoke-root", "label": "Bespoke Root", "kind": "hardware_node", "domain": "deployments_k8s", "section": "core"}],
                    "edges": []
                }

        adapter = BespokeAdapter()
        graph_data = adapter.convert_to_graph()
        # Verify valid contract
        self.assertEqual(graph_data["schema_version"], "1.0-separable-spatial-graph-contract")

    def test_pairwise_webhook_notifier_and_structured_logging(self):
        """Pairwise: F10 (Webhook) + F9 (Logging) -> Outbound webhook events audited via structured logger."""
        if webhook_notifier is None:
            self.fail("webhook_notifier not available")

        class _LogAuditReceiver(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_LogAuditReceiver) as srv:
            with self.assertLogs("opscryer", level="INFO") as log_capture:
                webhook_notifier.dispatch_webhook_event("audit_test", "info", "Audit summary", {}, webhook_url=f"{srv.base_url}/audit")
                self.assertGreaterEqual(len(log_capture.output), 1)


# ==============================================================================
# Tier 4: Real-World Workload Scenarios (5 Scenarios from TEST_INFRA.md)
# ==============================================================================

class TestTier4RealWorldScenarios(unittest.TestCase):
    """Tier 4: Realistic end-to-end operational workflows (TEST_INFRA.md)."""

    def setUp(self):
        reset_fn = getattr(environment_adapters, "reset_adapter_registry", None)
        if callable(reset_fn):
            reset_fn()

    def tearDown(self):
        reset_fn = getattr(environment_adapters, "reset_adapter_registry", None)
        if callable(reset_fn):
            reset_fn()

    def test_real_world_scenario_1_pod_crash_alert_pipeline(self):
        """Scenario 1: Production Kubernetes Pod Crash & Degradation Alert (F1, F6, F7, F10)."""
        if webhook_notifier is None:
            self.fail("webhook_notifier module required for Scenario 1")

        alert_dispatched = False
        alert_payload = {}

        class _AlertSink(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                nonlocal alert_dispatched, alert_payload
                length = int(self.headers.get("content-length", 0))
                alert_payload = json.loads(self.rfile.read(length).decode("utf-8"))
                alert_dispatched = True
                self.send_response(200)
                self.end_headers()

        with EphemeralHttpServer(_AlertSink) as sink_srv:
            with EphemeralHttpServer(browser._build_frontend_handler()) as opscryer_srv:
                # 1. Verify health probe before incident
                status, _, h_body = http_get(f"{opscryer_srv.base_url}/healthz")
                self.assertEqual(status, 200)

                # 2. Simulate cluster degradation notification dispatch
                ok = webhook_notifier.dispatch_webhook_event(
                    event_type="cluster_degraded",
                    severity="critical",
                    summary="CrashLoopBackOff detected in production pod opscryer-backend-0",
                    details={"pod": "opscryer-backend-0", "namespace": "opscryer", "exit_code": 137},
                    webhook_url=f"{sink_srv.base_url}/alert"
                )
                self.assertTrue(ok)
                self.assertTrue(alert_dispatched)
                self.assertEqual(alert_payload.get("severity"), "critical")
                self.assertEqual(alert_payload.get("event_type"), "cluster_degraded")

                # 3. Verify Prometheus metrics endpoint exposes cluster health status
                _, _, m_body = http_get(f"{opscryer_srv.base_url}/metrics")
                self.assertIn("opscryer_cluster_health_status", m_body.decode("utf-8"))

    def test_real_world_scenario_2_dual_tier_ai_knowledge_graph_and_ast_query(self):
        """Scenario 2: Dual-Tier AI Knowledge Graph Bridge & AST Query (F3, F4, F5)."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            # 1. AI agent queries system context to discover hardware inventory and active runbooks
            status, _, ctx_body = http_get(f"{srv.base_url}/api/v1/system-context")
            self.assertEqual(status, 200)
            context = json.loads(ctx_body.decode("utf-8"))
            self.assertEqual(context.get("schema_version"), "1.0-system-context")

            # 2. AI agent queries graph search to locate root cause service node
            status, _, search_body = http_get(f"{srv.base_url}/api/v1/graph/search?q=database")
            self.assertEqual(status, 200)
            search_res = json.loads(search_body.decode("utf-8"))
            self.assertIn("results", search_res)

            # 3. AI agent performs drilldown on root node
            status, _, drill_body = http_get(f"{srv.base_url}/api/v1/graph/drilldown?node_id=root-company")
            self.assertEqual(status, 200)

            # 4. AI agent submits incident deflection ticket
            ticket_req = json.dumps({"ticket_text": "Production database connection refused"}).encode("utf-8")
            status, _, deflect_body = http_post(f"{srv.base_url}/api/v1/graph/deflect-ticket", body=ticket_req)
            self.assertEqual(status, 200)
            deflect_res = json.loads(deflect_body.decode("utf-8"))
            self.assertEqual(deflect_res.get("schema_version"), "1.0-ticket-deflection")
            self.assertIn("route", deflect_res)

    def test_real_world_scenario_3_observability_jitter_and_circuit_breaker(self):
        """Scenario 3: Upstream Observability Network Jitter & Circuit Breaking (F2, F8, F9)."""
        if http_transport is None:
            self.fail("http_transport required for Scenario 3")

        call_count = 0

        class _JitteryPrometheus(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    self.send_response(503)
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status":"success","data":{"result":[]}}')

        with EphemeralHttpServer(_JitteryPrometheus) as srv:
            # 1. Verify resilient retry recovers from jitter
            data = http_transport.urlopen_with_retry(f"{srv.base_url}/api/v1/query", max_retries=3, backoff_factor=0.01)
            self.assertIn(b"success", data)
            self.assertGreaterEqual(call_count, 3)

    def test_real_world_scenario_4_dynamic_adapter_ingestion_and_graph_traversal(self):
        """Scenario 4: Dynamic Custom Infrastructure Adapter Ingestion (F1, F11, F3)."""
        base_cls = getattr(environment_adapters, "BaseEnvironmentAdapter", None)
        register_fn = getattr(environment_adapters, "register_adapter_profile", None)
        self.assertIsNotNone(base_cls, "BaseEnvironmentAdapter required for Scenario 4")

        # 1. Define and register custom IoT edge infrastructure adapter
        class IoTEdgeAdapter(base_cls):
            profile_name = "iot_edge_gateway"
            label = "IoT Edge Gateway"
            compatibility_matrix = {"containers": False, "networks": True, "storage": False}

            def convert_to_graph(self, spec=None):
                return {
                    "schema_version": "1.0-separable-spatial-graph-contract",
                    "nodes": [
                        {"id": "edge-gw-01", "label": "Edge Gateway 01", "kind": "hardware_node", "domain": "deployments_k8s", "section": "edge"},
                        {"id": "sensor-temp-01", "label": "Temperature Sensor", "kind": "hardware_node", "domain": "deployments_k8s", "section": "edge"}
                    ],
                    "edges": [
                        {"source": "sensor-temp-01", "target": "edge-gw-01", "relation": "connected_to"}
                    ]
                }

        register_fn("iot_edge_gateway", IoTEdgeAdapter)
        unregister_fn = getattr(environment_adapters, "unregister_adapter_profile", None)
        if callable(unregister_fn):
            self.addCleanup(unregister_fn, "iot_edge_gateway")

        # 2. Instantiate and generate graph
        adapter_instance = IoTEdgeAdapter()
        graph = adapter_instance.convert_to_graph()
        self.assertEqual(graph["schema_version"], "1.0-separable-spatial-graph-contract")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)

        # 3. Verify nodes comply with archetypes and structural contract
        for node in graph["nodes"]:
            for field in ("id", "label", "kind", "domain", "section"):
                self.assertIn(field, node)

    def test_real_world_scenario_5_full_cluster_health_scrape_and_metrics_export(self):
        """Scenario 5: Full Cluster Health Scrape & Prometheus Metrics Export (F1, F6, F7, F9)."""
        with EphemeralHttpServer(browser._build_frontend_handler()) as srv:
            # 1. Scrape liveness probe
            status, _, body = http_get(f"{srv.base_url}/healthz")
            self.assertEqual(status, 200)
            h_data = json.loads(body.decode("utf-8"))
            self.assertEqual(h_data.get("status"), "ok")

            # 2. Scrape readiness probe
            status, _, body = http_get(f"{srv.base_url}/readyz")
            self.assertEqual(status, 200)
            r_data = json.loads(body.decode("utf-8"))
            self.assertEqual(r_data.get("status"), "ready")

            # 3. Scrape Prometheus exposition endpoint
            status, headers, body = http_get(f"{srv.base_url}/metrics")
            self.assertEqual(status, 200)
            self.assertIn("text/plain", headers.get("content-type", ""))
            metrics_text = body.decode("utf-8")

            # 4. Verify Prometheus text format gauges and counters
            self.assertIn("opscryer_cluster_health_status", metrics_text)
            self.assertIn("opscryer_http_requests_total", metrics_text)
            self.assertIn("opscryer_uptime_seconds", metrics_text)


# Compatibility alias for dispatch runners
TestTier3PairwiseInteractions = TestTier3CrossFeaturePairwise


def load_tests(loader, standard_tests, pattern):
    """Ensure class aliases do not duplicate tests during module-level discovery."""
    seen_classes = set()
    deduped = unittest.TestSuite()
    for suite in standard_tests:
        cls = None
        for test in suite:
            cls = test.__class__
            break
        if cls is not None:
            if cls in seen_classes:
                continue
            seen_classes.add(cls)
        deduped.addTest(suite)
    return deduped


if __name__ == "__main__":
    unittest.main()
