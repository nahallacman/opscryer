# SPDX-License-Identifier: Apache-2.0
"""Unit tests for OpsCryer Browser live Central Brain KG proxy, timeout config, CSP, and HUD."""

from __future__ import annotations

import http.server
import json
import os
import threading
from typing import Any
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

import opscryer_browser


class _MockBrainHandler(http.server.BaseHTTPRequestHandler):
    """Hermetic mock Central Brain API server on 127.0.0.1."""

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/healthz":
            self._send_json(200, {"status": "ok", "uptime_seconds": 42.0, "service": "brain-api", "version": "0.3.1"})
        elif parsed.path == "/api/v1/scopes":
            self._send_json(
                200,
                {
                    "enabled": True,
                    "scopes": [
                        {"id": "org-platform", "label": "Platform Engineering"},
                        {"id": "dept-devx", "label": "Developer Experience"},
                    ],
                },
            )
        elif parsed.path == "/api/v1/opscryer/graph":
            scope = query.get("scope", ["org-platform"])[0]
            if scope == "org-platform":
                self._send_json(
                    200,
                    {
                        "schema_version": "1.0-separable-spatial-graph-contract",
                        "scope_id": "org-platform",
                        "root_node_id": "org-platform",
                        "ai_invoked": False,
                        "ecosystem_revision": "rev-platform-001",
                        "nodes": [
                            {
                                "id": "org-platform",
                                "label": "Platform Engineering",
                                "kind": "company_root",
                                "drilldown_children": [],
                            }
                        ],
                        "edges": [],
                        "rts_currencies": [],
                    },
                )
            elif scope == "dept-devx":
                self._send_json(
                    200,
                    {
                        "schema_version": "1.0-separable-spatial-graph-contract",
                        "scope_id": "dept-devx",
                        "root_node_id": "dept-devx",
                        "ai_invoked": False,
                        "ecosystem_revision": "rev-devx-002",
                        "nodes": [
                            {
                                "id": "dept-devx",
                                "label": "Developer Experience",
                                "kind": "company_team",
                                "drilldown_children": [],
                            }
                        ],
                        "edges": [],
                        "rts_currencies": [],
                    },
                )
            else:
                self._send_json(404, {"error": f"Unknown scope: {scope}"})
        else:
            self._send_json(404, {"error": f"Not found: {parsed.path}"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length)
        body = json.loads(raw_body.decode("utf-8")) if raw_body else {}

        if parsed.path == "/api/v1/telemetry/refresh":
            self._send_json(200, {"status": "ok", "action": "refresh"})
        elif parsed.path == "/api/v1/graph/dynamic-event":
            self._send_json(200, {"status": "ok", "action": "dynamic_event", "received": body})
        else:
            self._send_json(404, {"error": f"Not found: {parsed.path}"})

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class TestLiveBrainProxy(unittest.TestCase):
    """Test OpsCryer live Brain proxy routes, timeout config, CSP headers, and HUD controls."""

    brain_server: http.server.HTTPServer
    brain_thread: threading.Thread
    brain_url: str
    opscryer_server: http.server.HTTPServer
    opscryer_thread: threading.Thread
    opscryer_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.brain_server = http.server.HTTPServer(("127.0.0.1", 0), _MockBrainHandler)
        cls.brain_url = f"http://127.0.0.1:{cls.brain_server.server_address[1]}"
        cls.brain_thread = threading.Thread(target=cls.brain_server.serve_forever, daemon=True)
        cls.brain_thread.start()

        os.environ["OPSCRYER_BRAIN_API_URL"] = cls.brain_url
        handler_cls = opscryer_browser._build_frontend_handler()
        cls.opscryer_server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        cls.opscryer_url = f"http://127.0.0.1:{cls.opscryer_server.server_address[1]}"
        cls.opscryer_thread = threading.Thread(target=cls.opscryer_server.serve_forever, daemon=True)
        cls.opscryer_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.opscryer_server.shutdown()
        cls.opscryer_server.server_close()
        cls.brain_server.shutdown()
        cls.brain_server.server_close()
        os.environ.pop("OPSCRYER_BRAIN_API_URL", None)

    def test_brain_timeout_configuration_and_bounds(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPSCRYER_BRAIN_TIMEOUT", None)
            self.assertEqual(opscryer_browser._get_brain_proxy_timeout(), 15.0)
        with mock.patch.dict(os.environ, {"OPSCRYER_BRAIN_TIMEOUT": "22.5"}, clear=False):
            self.assertEqual(opscryer_browser._get_brain_proxy_timeout(), 22.5)
        with mock.patch.dict(os.environ, {"OPSCRYER_BRAIN_TIMEOUT": "0.1"}, clear=False):
            self.assertEqual(opscryer_browser._get_brain_proxy_timeout(), 1.0)
        with mock.patch.dict(os.environ, {"OPSCRYER_BRAIN_TIMEOUT": "999"}, clear=False):
            self.assertEqual(opscryer_browser._get_brain_proxy_timeout(), 60.0)
        with mock.patch.dict(os.environ, {"OPSCRYER_BRAIN_TIMEOUT": "not-a-number"}, clear=False):
            self.assertEqual(opscryer_browser._get_brain_proxy_timeout(), 15.0)

    def test_brain_scopes_and_status_proxy(self) -> None:
        req = urllib.request.Request(f"{self.opscryer_url}/api/v1/brain/scopes", headers={"Host": "localhost"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data["enabled"])
            self.assertEqual([s["id"] for s in data["scopes"]], ["org-platform", "dept-devx"])

        st_req = urllib.request.Request(f"{self.opscryer_url}/api/v1/brain/status", headers={"Host": "localhost"})
        with urllib.request.urlopen(st_req, timeout=5.0) as resp:
            st = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(st["enabled"])
            self.assertEqual(st["brain_api_url"], self.brain_url)
            self.assertEqual(st["status"], "ok")

    def test_graph_catalog_scope_routing_and_validation(self) -> None:
        for scope_id in ("org-platform", "dept-devx"):
            req = urllib.request.Request(
                f"{self.opscryer_url}/api/v1/graph/catalog?scope={scope_id}",
                headers={"Host": "localhost"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["scope_id"], scope_id)
                self.assertEqual(data["root_node_id"], scope_id)
                self.assertFalse(data["ai_invoked"])

        with self.assertRaises(urllib.error.HTTPError) as missing_ctx:
            urllib.request.urlopen(
                urllib.request.Request(
                    f"{self.opscryer_url}/api/v1/graph/catalog?scope=nonexistent",
                    headers={"Host": "localhost"},
                ),
                timeout=5.0,
            )
        self.assertEqual(missing_ctx.exception.code, 404)

        with self.assertRaises(urllib.error.HTTPError) as invalid_ctx:
            urllib.request.urlopen(
                urllib.request.Request(
                    f"{self.opscryer_url}/api/v1/graph/catalog?scope=bad%20scope%21",
                    headers={"Host": "localhost"},
                ),
                timeout=5.0,
            )
        self.assertEqual(invalid_ctx.exception.code, 400)

    def test_brain_refresh_and_dynamic_event_posts(self) -> None:
        refresh_req = urllib.request.Request(
            f"{self.opscryer_url}/api/v1/brain/refresh",
            data=b"{}",
            headers={"Host": "localhost", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(refresh_req, timeout=5.0) as resp:
            self.assertEqual(json.loads(resp.read().decode("utf-8"))["action"], "refresh")

        event_req = urllib.request.Request(
            f"{self.opscryer_url}/api/v1/brain/dynamic-event",
            data=json.dumps({"kind": "pipeline_pulse", "service": "api-gateway"}).encode("utf-8"),
            headers={"Host": "localhost", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(event_req, timeout=5.0) as resp:
            out = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(out["received"]["kind"], "pipeline_pulse")

    def test_readyz_and_standalone_fallback_when_brain_url_unset(self) -> None:
        with urllib.request.urlopen(
            urllib.request.Request(f"{self.opscryer_url}/readyz", headers={"Host": "localhost"}),
            timeout=5.0,
        ) as resp:
            ready = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(ready["status"], "ready")
            self.assertTrue(ready["brain_api_connected"])
            self.assertFalse(ready["ai_invoked"])

        with mock.patch.dict(os.environ, {"OPSCRYER_BRAIN_API_URL": ""}, clear=False):
            with urllib.request.urlopen(
                urllib.request.Request(f"{self.opscryer_url}/api/v1/brain/scopes", headers={"Host": "localhost"}),
                timeout=5.0,
            ) as resp:
                scopes_off = json.loads(resp.read().decode("utf-8"))
                self.assertFalse(scopes_off["enabled"])
                self.assertEqual(scopes_off["scopes"], [])

            with urllib.request.urlopen(
                urllib.request.Request(f"{self.opscryer_url}/api/v1/graph/catalog", headers={"Host": "localhost"}),
                timeout=5.0,
            ) as resp:
                cat = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(cat["schema_version"], "1.0-separable-spatial-graph-contract")
                self.assertGreater(len(cat["nodes"]), 0)

    def test_csp_frame_ancestors_allowed_hosts_and_hud_elements(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "OPSCRYER_FRAME_ANCESTORS": "https://backstage.cluster.example.org http://localhost:3000",
                "OPSCRYER_ALLOWED_HOSTS": "opscryer.cluster.example.org",
            },
            clear=False,
        ):
            req = urllib.request.Request(
                f"{self.opscryer_url}/healthz",
                headers={"Host": "opscryer.cluster.example.org"},
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self.assertEqual(resp.status, 200)
                csp = resp.headers.get("Content-Security-Policy", "")
                self.assertIn("frame-ancestors", csp)
                self.assertIn("https://backstage.cluster.example.org", csp)
                self.assertIsNone(resp.headers.get("X-Frame-Options"))

        html = opscryer_browser.render_standalone_browser_html()
        for elem_id in (
            "brain-scope-select",
            "brain-sync-btn",
            "brain-pulse-btn",
            "brain-reset-btn",
            "root_node_id",
            "root-company",
        ):
            self.assertIn(elem_id, html)


if __name__ == "__main__":
    unittest.main()
