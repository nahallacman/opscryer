# SPDX-License-Identifier: Apache-2.0
"""Behavioral Phase 3 security hardening tests for OpsCryer HTTP gateway & Hydrogen bridge."""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

OPSCRYER_ROOT = Path(__file__).resolve().parent.parent
if str(OPSCRYER_ROOT) not in sys.path:
    sys.path.insert(0, str(OPSCRYER_ROOT))

import live_metrics_poller
import model_tier_copilot
from opscryer.bridge import hydrogen_cast
import opscryer_browser as browser
import opscryer_suite_hub
import route_registry


class OpsCryerGatewaySecurityTests(unittest.TestCase):
    """Verify SEC-01 HTTP headers/Host/POST guards, 500 redaction, and ARCH-01 SSE caps."""

    def setUp(self) -> None:
        self.server = browser._ReusableTCPServer(("127.0.0.1", 0), browser._build_frontend_handler())
        self.address = self.server.server_address
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection(*self.address, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            raw = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, raw
        finally:
            conn.close()

    def test_security_headers_present_on_get_head_and_post(self) -> None:
        post_body = b'{"ticket_title":"deploy 3-tier scaffold"}'
        for method, path, body, hdrs in (
            ("GET", "/healthz", None, None),
            ("HEAD", "/healthz", None, None),
            (
                "POST",
                "/api/v1/graph/deflect-ticket",
                post_body,
                {"Content-Type": "application/json", "Content-Length": str(len(post_body))},
            ),
        ):
            status, resp_headers, _ = self._request(method, path, body=body, headers=hdrs)
            self.assertEqual(status, 200)
            self.assertEqual(resp_headers.get("x-content-type-options"), "nosniff")
            self.assertEqual(resp_headers.get("x-frame-options"), "DENY")
            self.assertEqual(resp_headers.get("referrer-policy"), "no-referrer")

    def test_dns_rebinding_host_rejected_across_methods(self) -> None:
        for method, path, body in (
            ("GET", "/healthz", None),
            ("HEAD", "/healthz", None),
            ("POST", "/api/v1/actions/dry-run", b"{}"),
        ):
            status, _, _ = self._request(
                method,
                path,
                body=body,
                headers={"Host": "rebind.attacker.example:8088", "Content-Type": "application/json"},
            )
            self.assertEqual(status, 403)

    def test_cross_site_post_and_invalid_content_type_blocked(self) -> None:
        payload = b'{"action_type":"restart_node","target":"node-1"}'
        status_origin, _, _ = self._request(
            "POST",
            "/api/v1/actions/dry-run",
            body=payload,
            headers={
                "Origin": "https://evil.attacker.example",
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
            },
        )
        self.assertEqual(status_origin, 403)

        status_fetch, _, _ = self._request(
            "POST",
            "/api/v1/actions/dry-run",
            body=payload,
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
            },
        )
        self.assertEqual(status_fetch, 403)

        status_ct, _, _ = self._request(
            "POST",
            "/api/v1/actions/dry-run",
            body=payload,
            headers={
                "Origin": f"http://127.0.0.1:{self.address[1]}",
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "text/plain",
                "Content-Length": str(len(payload)),
            },
        )
        self.assertEqual(status_ct, 415)

    def test_post_500_error_redacts_internal_exception_details(self) -> None:
        payload = b"{}"
        with patch.object(
            self.server.RequestHandlerClass,
            "_get_backend_engine",
            side_effect=RuntimeError("sensitive C:/internal/secret trace detail"),
        ):
            status, _, raw = self._request(
                "POST",
                "/api/v1/graph/deflect-ticket",
                body=payload,
                headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
            )
        self.assertEqual(status, 500)
        parsed = json.loads(raw.decode("utf-8"))
        self.assertEqual(parsed, {"error": "Internal server error"})
        self.assertNotIn("sensitive", raw.decode("utf-8"))

    def test_sse_stream_concurrency_cap_returns_503_and_releases_slot(self) -> None:
        started = threading.Event()
        release = threading.Event()
        results: dict[str, tuple[int, bytes]] = {}

        def _controlled_stream(**kwargs):
            started.set()
            yield "id: 1\nevent: heartbeat\ndata: {\"seq\": 1}\n\n"
            release.wait(timeout=3)

        def _hold_stream_one() -> None:
            status, _, raw = self._request("GET", "/api/v1/events/stream?max_events=1")
            results["first"] = (status, raw)

        with (
            patch.object(browser, "MAX_CONCURRENT_SSE_STREAMS", 1),
            patch("event_stream.stream_events_generator", side_effect=_controlled_stream),
        ):
            t1 = threading.Thread(target=_hold_stream_one, daemon=True)
            t1.start()
            self.assertTrue(started.wait(timeout=3))

            status_second, _, raw_second = self._request("GET", "/api/v1/events/stream?max_events=1")
            self.assertEqual(status_second, 503)
            self.assertIn("concurrent event streams", raw_second.decode("utf-8"))

            release.set()
            t1.join(timeout=3)
            self.assertEqual(results["first"][0], 200)

            status_third, _, _ = self._request("GET", "/api/v1/events/stream?max_events=1")
            self.assertEqual(status_third, 200)


class OpsCryerHydrogenCastSecurityTests(unittest.TestCase):
    """Verify SEC-03 path containment and SEC-05 provider/SSRF scrubbing."""

    def test_cast_metadata_and_listing_scrub_unapproved_providers(self) -> None:
        meta = model_tier_copilot.build_predumped_hydrogen_cast_metadata()
        self.assertEqual(
            meta["supported_providers"],
            ["ollama", "openai_compatible", "gemini", "deterministic_cutoff"],
        )

        scrubbed = hydrogen_cast._scrub_public_cast_models_listing(
            {
                "default_tier": "custom_vendor_tier",
                "supported_providers": ["ollama", "unapproved_vendor", "gemini"],
                "fallback_chain": ["custom_vendor_tier", "hydrogen", "zero_token_cutoff"],
                "tiers": [
                    {"tier_id": "custom_vendor_tier", "provider": "unapproved_vendor"},
                    {"tier_id": "hydrogen", "provider": "ollama"},
                    {"tier_id": "zero_token_cutoff", "provider": "deterministic_cutoff"},
                ],
            }
        )
        self.assertEqual(scrubbed["supported_providers"], ["ollama", "gemini"])
        self.assertEqual([t["tier_id"] for t in scrubbed["tiers"]], ["hydrogen", "zero_token_cutoff"])
        self.assertEqual(scrubbed["fallback_chain"], ["hydrogen", "zero_token_cutoff"])
        self.assertEqual(scrubbed["default_tier"], "hydrogen")

    def test_hydrogen_cast_blocks_ssrf_imds_and_disallowed_provider_or_traversal(self) -> None:
        for bad_endpoint in (
            "http://169.254.169.254/latest/meta-data/",
            "http://[fe80::1]:8080/v1",
            "https://evil.attacker.example/v1/chat",
            "http://user:pass@127.0.0.1:11434/api/generate",
        ):
            status, payload = hydrogen_cast.handle_hydrogen_cast_request(
                {"target": "deploy/app", "provider": "ollama", "endpoint_url": bad_endpoint}
            )
            self.assertEqual(status, 400)
            self.assertEqual(payload["error"], "invalid_cast_model_config")

        status_prov, payload_prov = hydrogen_cast.handle_hydrogen_cast_request(
            {"target": "deploy/app", "provider": "unapproved_vendor"}
        )
        self.assertEqual(status_prov, 400)
        self.assertEqual(payload_prov["error"], "invalid_cast_model_config")

        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"
            root.mkdir()
            (Path(tmp) / "secret.json").write_text('{"skill_id":"leak"}\n', encoding="utf-8")
            (root / "bundle-manifest.json").write_text(
                json.dumps({"skills": [{"id": "deploy-k8s", "context_anchor_path": "../../secret.json"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                hydrogen_cast._stdlib_cast_fallback(target="deploy/app", bundle_dir=root)

    def test_allowed_host_suffixes_env_extends_gateway_and_cast_hosts(self) -> None:
        self.assertFalse(browser._is_permitted_gateway_host("ops.corp.example:8088"))
        with self.assertRaises(ValueError):
            hydrogen_cast._validate_public_cast_endpoint_url("http://ollama.corp.example:11434/api/generate")

        with patch.dict(os.environ, {"OPSCRYER_ALLOWED_HOST_SUFFIXES": ".corp.example, internal.mesh"}, clear=False):
            self.assertTrue(browser._is_permitted_gateway_host("ops.corp.example:8088"))
            self.assertTrue(browser._is_permitted_gateway_host("internal.mesh:8088"))
            self.assertFalse(browser._is_permitted_gateway_host("rebind.attacker.example:8088"))
            self.assertEqual(
                hydrogen_cast._validate_public_cast_endpoint_url("http://ollama.corp.example:11434/api/generate"),
                "http://ollama.corp.example:11434/api/generate",
            )

    def test_p1_gateway_host_frame_ancestors_cast_catalog_and_brain_home(self) -> None:
        # 1. Gateway Host guard blocks public IPs and empty hosts, allows loopback/RFC1918 and overrides.
        self.assertFalse(browser._is_permitted_gateway_host(""))
        self.assertFalse(browser._is_permitted_gateway_host("198.51.100.5:8088"))
        public_ip = ".".join(("93", "184", "216", "34"))
        self.assertFalse(browser._is_permitted_gateway_host(f"{public_ip}:8088"))
        self.assertTrue(browser._is_permitted_gateway_host("127.0.0.1:8088"))
        self.assertTrue(browser._is_permitted_gateway_host("10.0.0.5:8088"))
        self.assertTrue(browser._is_permitted_gateway_host("172.20.1.10:8088"))
        self.assertTrue(browser._is_permitted_gateway_host("[::1]:8088"))
        with patch.dict(os.environ, {"OPSCRYER_ALLOWED_HOSTS": "198.51.100.5"}, clear=False):
            self.assertTrue(browser._is_permitted_gateway_host("198.51.100.5:8088"))

        # 2. OPSCRYER_FRAME_ANCESTORS configures CSP frame-ancestors; invalid tokens fall back to DENY.
        server = browser._ReusableTCPServer(("127.0.0.1", 0), browser._build_frontend_handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def _get_headers(path: str) -> dict[str, str]:
                conn = http.client.HTTPConnection(*server.server_address, timeout=5)
                try:
                    conn.request("GET", path)
                    resp = conn.getresponse()
                    resp.read()
                    return {k.lower(): v for k, v in resp.getheaders()}
                finally:
                    conn.close()

            with patch.dict(os.environ, {"OPSCRYER_FRAME_ANCESTORS": "http://localhost:3001"}, clear=False):
                hdrs = _get_headers("/healthz")
                self.assertEqual(hdrs.get("content-security-policy"), "frame-ancestors http://localhost:3001")
                self.assertNotIn("x-frame-options", hdrs)

            with patch.dict(os.environ, {"OPSCRYER_FRAME_ANCESTORS": "javascript:alert(1)"}, clear=False):
                hdrs_bad = _get_headers("/healthz")
                self.assertEqual(hdrs_bad.get("x-frame-options"), "DENY")
                self.assertNotIn("content-security-policy", hdrs_bad)

            # 3. POST /api/v1/cast/hydrogen passes live catalog so existing catalog nodes resolve.
            cat_body = json.dumps({"target": "team-demo-platform"}).encode("utf-8")
            conn = http.client.HTTPConnection(*server.server_address, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/api/v1/cast/hydrogen",
                    body=cat_body,
                    headers={"Content-Type": "application/json", "Content-Length": str(len(cat_body))},
                )
                resp = conn.getresponse()
                raw = resp.read()
                self.assertEqual(resp.status, 200)
                parsed = json.loads(raw.decode("utf-8"))
                self.assertTrue(parsed["catalog_context"]["matched"])
            finally:
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        # 4. BRAIN_HOME and BRAIN_DATA_DIR discovery work cleanly across ecosystem & bridge paths.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "brain-home"
            custom_data = root / "custom-data"
            home.mkdir()
            custom_data.mkdir()
            (home / "config.json").write_text(json.dumps({"data_dir": str(custom_data)}), encoding="utf-8")
            clean_env = {
                k: v
                for k, v in os.environ.items()
                if k not in {"OPSCRYER_BRAIN_ROOT", "BRAIN_DATA_DIR", "MESHWORKS_PREDUMP_DIR"}
            }
            with patch.dict(os.environ, {**clean_env, "BRAIN_HOME": str(home)}, clear=True):
                paths = browser._resolve_ecosystem_paths()
                self.assertEqual(paths["meshworks_graph"], custom_data / "knowledge-graph.json")
                self.assertEqual(hydrogen_cast._default_predump_dir(), custom_data / "predumped_bundle")

            direct_data = root / "direct-data"
            with patch.dict(os.environ, {**clean_env, "BRAIN_DATA_DIR": str(direct_data)}, clear=True):
                paths_direct = browser._resolve_ecosystem_paths()
                self.assertEqual(paths_direct["state"], direct_data / "skill_watch_state.json")
                self.assertEqual(hydrogen_cast._default_predump_dir(), direct_data / "predumped_bundle")

        # 5. _stdlib_cast_fallback sets non-null model inside ollama_generate_payload.
        with TemporaryDirectory() as tmp:
            fallback_env = hydrogen_cast._stdlib_cast_fallback(target="deploy/app", bundle_dir=Path(tmp))
            self.assertEqual(fallback_env["ollama_generate_payload"]["model"], "nemotron-mini:4b")

    def test_p2_bounded_server_metrics_lock_execution_modes_and_repo_hygiene(self) -> None:
        # 1. Bounded HTTP workers and request socket timeouts (exempting SSE streams).
        self.assertEqual(browser.REQUEST_SOCKET_TIMEOUT_S, 15.0)
        self.assertEqual(browser.MAX_CONCURRENT_HTTP_WORKERS, 64)
        srv = browser._ReusableTCPServer(("127.0.0.1", 0), browser._build_frontend_handler())
        try:
            self.assertIsInstance(srv._worker_semaphore, threading.BoundedSemaphore)
            for _ in range(browser.MAX_CONCURRENT_HTTP_WORKERS):
                self.assertTrue(srv._worker_semaphore.acquire(blocking=False))
            rejected: list[object] = []
            dummy_req = object()
            with patch.object(srv, "shutdown_request", side_effect=rejected.append):
                srv.process_request(dummy_req, ("127.0.0.1", 12345))
            self.assertEqual(rejected, [dummy_req])
            for _ in range(browser.MAX_CONCURRENT_HTTP_WORKERS):
                srv._worker_semaphore.release()
        finally:
            srv.server_close()

        recorded_timeouts: list[float | None] = []

        class _TrackingSocket:
            def __init__(self, real_sock: object) -> None:
                self._sock = real_sock

            def settimeout(self, value: float | None) -> None:
                recorded_timeouts.append(value)
                self._sock.settimeout(value)

            def __getattr__(self, name: str) -> object:
                return getattr(self._sock, name)

        stream_server = browser._ReusableTCPServer(("127.0.0.1", 0), browser._build_frontend_handler())
        orig_get_request = stream_server.get_request

        def _wrapped_get_request() -> tuple[object, object]:
            sock, addr = orig_get_request()
            return _TrackingSocket(sock), addr

        stream_server.get_request = _wrapped_get_request  # type: ignore[method-assign]
        t = threading.Thread(target=stream_server.serve_forever, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection(*stream_server.server_address, timeout=5)
            try:
                conn.request("GET", "/healthz")
                self.assertEqual(conn.getresponse().status, 200)
            finally:
                conn.close()

            conn = http.client.HTTPConnection(*stream_server.server_address, timeout=5)
            try:
                conn.request("GET", "/api/v1/events/stream?max_events=1")
                resp = conn.getresponse()
                resp.read()
                self.assertEqual(resp.status, 200)
            finally:
                conn.close()
        finally:
            stream_server.shutdown()
            stream_server.server_close()
            t.join(timeout=5)
        self.assertIn(browser.REQUEST_SOCKET_TIMEOUT_S, recorded_timeouts)
        self.assertIn(None, recorded_timeouts)

        # 2. Thread-safe live metrics cache under concurrent poll & clear operations.
        self.assertIsNotNone(live_metrics_poller._METRICS_CACHE_LOCK)
        live_metrics_poller.clear_live_metrics_cache()

        def _poll_or_clear(idx: int) -> str:
            if idx % 5 == 0:
                live_metrics_poller.clear_live_metrics_cache()
                return "cleared"
            data = live_metrics_poller.poll_live_cluster_metrics(allow_kubectl=False, ttl_seconds=60)
            self.assertEqual(data["schema_version"], "1.0-live-metrics-stream")
            self.assertFalse(data["live_kubectl_active"])
            return str(data["telemetry_mode"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(_poll_or_clear, range(30)))
        self.assertEqual(len(outcomes), 30)
        self.assertTrue(all(bool(item) for item in outcomes))

        # 3. Honest execution_mode annotations across route registry and Suite Hub.
        valid_modes = {"live_io", "snapshot_derived", "simulated"}
        for route in (*route_registry.HTML_PORTAL_ROUTES, *route_registry.API_V1_ROUTES.values()):
            self.assertIn(route["execution_mode"], valid_modes)
        summary = route_registry.build_route_registry_summary()
        by_mode = summary["by_execution_mode"]
        self.assertEqual(sum(v["html_routes"] for v in by_mode.values()), len(route_registry.HTML_PORTAL_ROUTES))
        self.assertEqual(sum(v["api_routes"] for v in by_mode.values()), len(route_registry.API_V1_ROUTES))

        hub_catalog = opscryer_suite_hub.build_suite_application_catalog()
        for entry in (*hub_catalog["applications"], *hub_catalog["compatibility_and_live_extensions"]):
            self.assertIn(entry["execution_mode"], valid_modes)
        hub_html = opscryer_suite_hub.render_suite_hub_html()
        self.assertIn("app.execution_mode", hub_html)

        # 4. Repo hygiene: agent debris removed, manifest renamed, YAML scrubbed, packaging present.
        for deleted_rel in (
            ".scratch/codex_burn_live_telemetry.json",
            ".scratch/codex_burn_run.log",
            "Dockerfile.codex-sandbox",
            "CODEX_OVERNIGHT_SWARM_TASKS.md",
        ):
            self.assertFalse((OPSCRYER_ROOT / deleted_rel).exists(), msg=f"Unexpected leftover file: {deleted_rel}")
        self.assertTrue((OPSCRYER_ROOT / "EPIC_SCOPE_MANIFEST.md").is_file())
        self.assertTrue((OPSCRYER_ROOT / "MANIFEST.in").is_file())

        yaml_text = (OPSCRYER_ROOT / "settled_production_systems.yaml").read_text(encoding="utf-8")
        for forbidden in (
            "subagent-flash38-kg-01",
            "kv/data/homelab/",
            "unseal-openbao.ps1",
            "swarm_dispatch.py",
            "gitlab_ops.py",
            "check_line_endings.py",
        ):
            self.assertNotIn(forbidden, yaml_text)

        # 5. Backstage plugin exports resolveSafeOpscryerUrl, has tests, and avoids MUI v5 sx props.
        tsx_path = OPSCRYER_ROOT / "plugins/opscryer/src/components/OpsCryerBrowserComponent/OpsCryerBrowserComponent.tsx"
        test_tsx_path = OPSCRYER_ROOT / "plugins/opscryer/src/components/OpsCryerBrowserComponent/OpsCryerBrowserComponent.test.tsx"
        tsx_text = tsx_path.read_text(encoding="utf-8")
        self.assertIn("export function resolveSafeOpscryerUrl(", tsx_text)
        self.assertNotIn("sx={{", tsx_text)
        self.assertTrue(test_tsx_path.is_file())


if __name__ == "__main__":
    unittest.main()
