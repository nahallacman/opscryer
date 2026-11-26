# SPDX-License-Identifier: Apache-2.0
"""Unit, HTTP API, SSRF, and Node.js tests for the Central Workspace Layout & Panel Configurator."""

from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import opscryer_browser as browser
import world_map_engine
from workspace_layout import (
    LAYOUT_PANELS,
    LAYOUT_PRESETS,
    PANEL_IDS,
    WORKSPACE_LAYOUT_SCHEMA_VERSION,
    build_workspace_config_payload,
    build_workspace_layout_js,
    parse_enabled_plugins_env,
    resolve_default_loadout_config,
    sanitize_nav_links_env,
)


class WorkspaceLayoutPythonTests(unittest.TestCase):
    """Verify presets, org-default loadout inheritance, opt-in plugins, nav link sanitization, and SSRF protection."""

    def test_presets_cover_all_declared_panel_ids(self) -> None:
        self.assertEqual(len(LAYOUT_PANELS), 15)
        for preset_id in ("focused", "full", "iframe", "minimal", "triage"):
            self.assertIn(preset_id, LAYOUT_PRESETS)
            self.assertEqual(set(LAYOUT_PRESETS[preset_id]["panels"].keys()), PANEL_IDS)
        # Focused default preset minimizes top chrome while keeping layer ribbon + box inspector active
        self.assertFalse(LAYOUT_PRESETS["focused"]["panels"]["portal_nav"])
        self.assertFalse(LAYOUT_PRESETS["focused"]["panels"]["currencies_bar"])
        self.assertFalse(LAYOUT_PRESETS["focused"]["panels"]["command_card"])
        self.assertTrue(LAYOUT_PRESETS["focused"]["panels"]["layer_ribbon"])
        self.assertTrue(LAYOUT_PRESETS["focused"]["panels"]["unit_console"])
        # Iframe preset hides heavy top navigation & currencies rows by default
        self.assertFalse(LAYOUT_PRESETS["iframe"]["panels"]["portal_nav"])
        self.assertFalse(LAYOUT_PRESETS["iframe"]["panels"]["currencies_bar"])
        self.assertFalse(LAYOUT_PRESETS["iframe"]["panels"]["fast_finder"])
        self.assertFalse(LAYOUT_PRESETS["iframe"]["panels"]["command_card"])
        # Minimal preset hides all chrome rows and bottom console
        self.assertTrue(all(not v for v in LAYOUT_PRESETS["minimal"]["panels"].values()))

    def test_org_default_loadout_config_and_opt_in_plugins(self) -> None:
        # Built-in default is clean focused loadout with nanoswarm plugin disabled
        base_def = resolve_default_loadout_config(env={})
        self.assertEqual(base_def["preset"], "focused")
        self.assertEqual(parse_enabled_plugins_env(""), [])

        # Deployment operator can switch org default via env JSON for all uncustomized users
        override_json = json.dumps({"preset": "focused", "panels": {"minimap": True, "fast_finder": True}})
        org_def = resolve_default_loadout_config(env={"OPSCRYER_DEFAULT_LAYOUT_JSON": override_json})
        self.assertTrue(org_def["panels"]["minimap"])
        self.assertTrue(org_def["panels"]["fast_finder"])
        self.assertFalse(org_def["panels"]["portal_nav"])
        self.assertNotEqual(org_def["version_hash"], base_def["version_hash"])

        # Opt-in plugin parsing enables nanoswarm only when explicitly requested
        self.assertEqual(parse_enabled_plugins_env("nanoswarm, custom"), ["nanoswarm", "custom"])
        cfg = build_workspace_config_payload(default_loadout=org_def, enabled_plugins=["nanoswarm"])
        self.assertFalse(cfg["ask_brain_default_open"])
        self.assertTrue(cfg["integrations"]["nanoswarm_plugin_enabled"])
        self.assertEqual(cfg["default_loadout"]["version_hash"], org_def["version_hash"])

    def test_sanitize_nav_links_blocks_xss_and_credentials(self) -> None:
        raw = json.dumps(
            [
                {"label": "Git Portal", "href": "https://git.example.org/org/repo"},
                {"label": "Local Launchpad", "href": "/mrs"},
                {"label": "Bad JS", "href": "javascript:alert(1)"},
                {"label": "Bad Data", "href": "data:text/html,<h1>x</h1>"},
                {"label": "Bad Protocol Relative", "href": "//evil.example.com"},
                {"label": "Bad Creds", "href": "https://user:pass@example.org/"},
            ]
        )
        safe = sanitize_nav_links_env(raw)
        self.assertEqual(
            safe,
            [
                {"label": "Git Portal", "href": "https://git.example.org/org/repo"},
                {"label": "Local Launchpad", "href": "/mrs"},
            ],
        )

    def test_rendered_html_includes_accessible_config_dialog_on_browser_and_world_map(self) -> None:
        for label, html in (
            ("browser", browser.render_standalone_browser_html()),
            ("world_map", world_map_engine.render_world_map_html()),
        ):
            with self.subTest(page=label):
                self.assertIn('id="workspace-layout-fab"', html)
                self.assertIn('<dialog id="workspace-layout-dialog" closedby="any"', html)
                self.assertIn("dialog[open]#workspace-layout-dialog", html)
                self.assertNotIn('role="dialog"', html)
                self.assertNotIn("aria-modal", html)
        browser_html = browser.render_standalone_browser_html()
        self.assertIn('id="ask-brain-fab"', browser_html)
        self.assertIn('id="ask-brain-drawer" data-open="false"', browser_html)

    def test_swarm_api_url_blocks_imds_and_public_hosts(self) -> None:
        with patch.dict(os.environ, {"OPSCRYER_SWARM_API_URL": "http://169.254.169.254/latest"}, clear=False):
            self.assertEqual(browser._get_swarm_api_url(), "")
        with patch.dict(os.environ, {"OPSCRYER_SWARM_API_URL": "https://evil.example.com"}, clear=False):
            self.assertEqual(browser._get_swarm_api_url(), "")
        with patch.dict(os.environ, {"OPSCRYER_SWARM_API_URL": "http://swarm-memory.dev-envs.svc.cluster.local:8090"}, clear=False):
            self.assertEqual(browser._get_swarm_api_url(), "http://swarm-memory.dev-envs.svc.cluster.local:8090")


class WorkspaceLayoutHTTPTests(unittest.TestCase):
    """Loopback HTTP verification for /api/v1/workspace/config and /api/v1/swarm/c2-summary."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), browser._build_frontend_handler())
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server)

    @classmethod
    def stop_server(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def _get_json(self, path: str):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()

    def test_workspace_config_and_standalone_swarm_summary(self) -> None:
        st, cfg = self._get_json("/api/v1/workspace/config")
        self.assertEqual(st, 200)
        self.assertEqual(cfg["schema_version"], WORKSPACE_LAYOUT_SCHEMA_VERSION)
        self.assertIn("iframe", cfg["presets"])
        self.assertIn("integrations", cfg)

        st2, c2 = self._get_json("/api/v1/swarm/c2-summary")
        self.assertEqual(st2, 200)
        self.assertFalse(c2["enabled"])
        self.assertEqual(c2["status"], "standalone")


class WorkspaceLayoutNodeTests(unittest.TestCase):
    """Execute OpsCryerWorkspaceLayout JS in Node.js to verify iframe detection, toggles, reflow, and embed URLs."""

    def test_nodejs_presets_iframe_auto_and_panel_toggles(self) -> None:
        layout_js = build_workspace_layout_js()
        harness = r"""
const assert = require('assert');
const store = {};
const attrs = {};
const footerEl = { style: {} };
const fabEl = { textContent: '' };
globalThis.window = {
  location: { search: '', href: 'https://opscryer.example.org/' },
  localStorage: {
    getItem: k => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; }
  }
};
globalThis.document = {
  body: { setAttribute: (k, v) => { attrs[k] = v; } },
  getElementById: id => (id === 'rts-bottom-perimeter-console' ? footerEl : (id === 'workspace-layout-fab' ? fabEl : null)),
  addEventListener: () => {}
};
""" + layout_js + r"""
const wl = globalThis.window.OpsCryerWorkspaceLayout;
assert.ok(wl, 'OpsCryerWorkspaceLayout attached');

/* 1. Auto-iframe preset reduces chrome without explicit URL params */
const iframeResolved = wl.resolveInitialLayout('', true, null);
assert.strictEqual(iframeResolved.preset, 'iframe');
assert.strictEqual(iframeResolved.panels.portal_nav, false);
assert.strictEqual(iframeResolved.panels.currencies_bar, false);
assert.strictEqual(iframeResolved.panels.command_card, false);
assert.strictEqual(iframeResolved.panels.minimap, true);

/* 2. URL ?hide= and ?show= and ?view=world_map overrides + spatial projection shortcuts work deterministically */
const customResolved = wl.resolveInitialLayout('?preset=full&hide=portal_nav,command_card&show=swarm_c2&view=world_map', false, null);
assert.strictEqual(customResolved.preset, 'custom');
assert.strictEqual(customResolved.panels.portal_nav, false);
assert.strictEqual(customResolved.panels.command_card, false);
assert.strictEqual(customResolved.panels.swarm_c2, true);
assert.strictEqual(customResolved.initialView, 'world_map');
assert.strictEqual(customResolved.initialProjection, null);

const spatial2d = wl.resolveInitialLayout('?view=spatial_2d', false, null);
assert.strictEqual(spatial2d.initialView, 'world_map');
assert.strictEqual(spatial2d.initialProjection, 'flat_2d');

const spatial3d = wl.resolveInitialLayout('?view=spatial_3d', false, null);
assert.strictEqual(spatial3d.initialView, 'world_map');
assert.strictEqual(spatial3d.initialProjection, 'orbit_3d');

const projQuery = wl.resolveInitialLayout('?proj=2.5d', false, null);
assert.strictEqual(projQuery.initialProjection, 'iso_25d');

/* 3. Clean focused default minimizes chrome, inherits org default for uncustomized users, and preserves user overrides */
let activeView = 'boxes';
const ctrl = wl.createWorkspaceLayoutController({
  footerId: 'rts-bottom-perimeter-console',
  pageMode: 'browser',
  search: '',
  inIframe: false,
  getActiveView: () => activeView,
  setActiveView: v => { activeView = v; }
});
assert.strictEqual(attrs['data-panel-portal-nav'], 'off');
assert.strictEqual(attrs['data-panel-layer-ribbon'], 'on');
assert.strictEqual(attrs['data-panel-unit-console'], 'on');
assert.strictEqual(attrs['data-plugin-nanoswarm'], 'off');
assert.strictEqual(footerEl.style.gridTemplateColumns, '1fr');

/* Uncustomized user automatically inherits an updated deployment/org default loadout */
ctrl.applyRuntimeDefaultLayout({ preset: 'org_default', panels: { minimap: true, fast_finder: true } }, ['nanoswarm']);
assert.strictEqual(attrs['data-panel-minimap'], 'on');
assert.strictEqual(attrs['data-panel-fast-finder'], 'on');
assert.strictEqual(attrs['data-plugin-nanoswarm'], 'on');
assert.strictEqual(footerEl.style.gridTemplateColumns, '240px 1fr');

/* Once a user customizes their layout, subsequent org default updates never overwrite their choices */
ctrl.applyPreset('full');
assert.strictEqual(attrs['data-panel-portal-nav'], 'on');
assert.strictEqual(footerEl.style.gridTemplateColumns, '240px 1fr 295px');
ctrl.applyRuntimeDefaultLayout({ preset: 'minimal', panels: {} }, []);
assert.strictEqual(attrs['data-panel-portal-nav'], 'on');

ctrl.togglePanel('command_card', false);
assert.strictEqual(attrs['data-panel-command-card'], 'off');
assert.strictEqual(footerEl.style.gridTemplateColumns, '240px 1fr');

ctrl.togglePanel('minimap', false);
assert.strictEqual(footerEl.style.gridTemplateColumns, '1fr');

/* Hiding all 3 bottom sub-panels collapses the entire bottom console cleanly */
ctrl.togglePanel('unit_console', false);
assert.strictEqual(attrs['data-panel-bottom-console'], 'off');

/* Reset snaps back to the active org default and clears user customization */
ctrl.applyRuntimeDefaultLayout({ preset: 'focused', panels: { layer_ribbon: true, bottom_console: true, unit_console: true } }, []);
ctrl.resetToDefault();
assert.strictEqual(attrs['data-panel-unit-console'], 'on');
assert.strictEqual(ctrl.getState().customized, false);

/* Shareable embed URL captures custom hidden panels and active view */
ctrl.applyPreset('full');
ctrl.togglePanel('command_card', false);
activeView = 'world_map';
const embedUrl = ctrl.buildEmbedUrl('https://opscryer.example.org/', activeView);
assert.ok(embedUrl.includes('hide='), 'Embed URL encodes hidden panels');
assert.ok(embedUrl.includes('view=world_map'), 'Embed URL preserves active view');

/* Minimal preset hides everything */
ctrl.applyPreset('minimal');
assert.strictEqual(attrs['data-panel-portal-nav'], 'off');
assert.strictEqual(attrs['data-panel-layer-ribbon'], 'off');
assert.strictEqual(attrs['data-panel-bottom-console'], 'off');

/* Initial projection hook fires when URL specifies ?view=spatial_3d */
let capturedProj = null;
wl.createWorkspaceLayoutController({
  footerId: 'rts-bottom-perimeter-console',
  pageMode: 'browser',
  search: '?view=spatial_3d',
  inIframe: false,
  setActiveView: v => { activeView = v; },
  setInitialProjection: p => { capturedProj = p; }
});
assert.strictEqual(capturedProj, 'orbit_3d');
console.log('NODE_WORKSPACE_LAYOUT_OK');
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "workspace_layout_harness.js"
            js_file.write_text(harness, encoding="utf-8", newline="\n")
            proc = subprocess.run(
                ["node", str(js_file)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertIn("NODE_WORKSPACE_LAYOUT_OK", proc.stdout)


class UserDelegatedAuthTests(unittest.TestCase):
    """Verify per-user delegated auth header sanitization, proxy forwarding, and browser Sign-In UI."""

    def test_extract_brain_delegated_headers_whitelist_and_bounds(self) -> None:
        clean = browser._extract_brain_delegated_headers(
            {
                "x-brain-delegated-tokens": '{"gitlab_direct":"tok-alice"}',
                "X-Brain-Delegated-Provider": "gitlab_direct",
                "X-Evil-Header": "must-drop",
                "Authorization": "Bearer hijack",
                "Cookie": "session=hijack",
            }
        )
        self.assertEqual(
            clean,
            {
                "X-Brain-Delegated-Tokens": '{"gitlab_direct":"tok-alice"}',
                "X-Brain-Delegated-Provider": "gitlab_direct",
            },
        )
        # Reject header injection (CR/LF/NUL) and oversized (>4096 bytes) payloads
        rejected = browser._extract_brain_delegated_headers(
            {
                "X-Brain-Delegated-Token": "abc\r\nX-Injected: 1",
                "X-Brain-Delegated-Provider": "bad\x00prov",
                "X-Brain-Delegated-Tokens": "x" * 5000,
            }
        )
        self.assertEqual(rejected, {})

    def test_proxy_forwards_delegated_headers_per_request_without_cross_user_leak(self) -> None:
        recorded_headers: list[dict[str, str | None]] = []

        class _MockBrainHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                delegated = self.headers.get("X-Brain-Delegated-Tokens")
                recorded_headers.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "delegated": delegated,
                    }
                )
                is_alice = delegated is not None and "alice-tok" in delegated
                if self.path.startswith("/api/v1/ask"):
                    payload = {
                        "user_scoped": is_alice,
                        "answer": "alice private match" if is_alice else "sign in needed",
                        "quick_links": [],
                        "matches": [],
                        "auth_required_sources": []
                        if is_alice
                        else [
                            {
                                "plugin": "gitlab_direct",
                                "provider": "gitlab",
                                "login_url": "https://gitlab.example.org/users/sign_in",
                            }
                        ],
                    }
                else:
                    payload = {
                        "user_scoped": is_alice,
                        "nodes": (
                            [{"id": "proj-alice-private", "label": "Alice App", "drilldown_children": []}]
                            if is_alice
                            else []
                        ),
                        "edges": [],
                        "auth_required_sources": []
                        if is_alice
                        else [
                            {
                                "plugin": "gitlab_direct",
                                "provider": "gitlab",
                                "login_url": "https://gitlab.example.org/users/sign_in",
                            }
                        ],
                    }
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        brain_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockBrainHandler)
        threading.Thread(target=brain_srv.serve_forever, daemon=True).start()
        brain_url = f"http://127.0.0.1:{brain_srv.server_address[1]}"

        front_srv = ThreadingHTTPServer(("127.0.0.1", 0), browser._build_frontend_handler())
        threading.Thread(target=front_srv.serve_forever, daemon=True).start()
        try:
            with patch.dict(os.environ, {"OPSCRYER_BRAIN_API_TOKEN": "srv-secret"}, clear=False):
                with patch.object(browser, "_get_brain_api_url", return_value=brain_url):
                    # 1. Direct _proxy_brain_json_request preserves Authorization and sends extra delegated header.
                    st_dir, body_dir = browser._proxy_brain_json_request(
                        brain_url,
                        "/api/v1/opscryer/graph?live=0",
                        extra_headers={
                            "X-Brain-Delegated-Tokens": '{"gitlab_direct":"alice-tok"}',
                            "Authorization": "Bearer cannot-override",
                        },
                    )
                    self.assertEqual(st_dir, 200)
                    self.assertTrue(body_dir["user_scoped"])
                    self.assertEqual(recorded_headers[-1]["auth"], "Bearer srv-secret")
                    self.assertEqual(recorded_headers[-1]["delegated"], '{"gitlab_direct":"alice-tok"}')

                    # 2. HTTP proxy on /api/v1/graph/catalog & /api/v1/live-cluster-ask isolates per request.
                    host, port = front_srv.server_address
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                    try:
                        conn.request(
                            "GET",
                            "/api/v1/graph/catalog",
                            headers={"X-Brain-Delegated-Tokens": '{"gitlab_direct":"alice-tok"}'},
                        )
                        r1 = json.loads(conn.getresponse().read().decode("utf-8"))
                        self.assertTrue(r1["user_scoped"])
                        self.assertEqual([n["id"] for n in r1["nodes"]], ["proj-alice-private"])

                        # Subsequent anonymous caller receives NO delegated headers and NO Alice nodes.
                        conn.request("GET", "/api/v1/graph/catalog")
                        r2 = json.loads(conn.getresponse().read().decode("utf-8"))
                        self.assertFalse(r2["user_scoped"])
                        self.assertEqual(r2["nodes"], [])
                        self.assertEqual(len(r2["auth_required_sources"]), 1)
                        self.assertIsNone(recorded_headers[-1]["delegated"])

                        conn.request(
                            "GET",
                            "/api/v1/live-cluster-ask?q=alice",
                            headers={"X-Brain-Delegated-Tokens": '{"gitlab_direct":"alice-tok"}'},
                        )
                        r3 = json.loads(conn.getresponse().read().decode("utf-8"))
                        self.assertTrue(r3["user_scoped"])
                        self.assertEqual(r3["answer"], "alice private match")
                    finally:
                        conn.close()
        finally:
            front_srv.shutdown()
            front_srv.server_close()
            brain_srv.shutdown()
            brain_srv.server_close()

    def test_generated_index_html_has_delegated_signin_ui_and_valid_js(self) -> None:
        index_html = (_PKG_DIR / "index.html").read_text(encoding="utf-8")
        rendered_html = browser.render_standalone_browser_html()
        for label, html in (("index.html", index_html), ("rendered", rendered_html)):
            with self.subTest(source=label):
                self.assertIn('id="brain-auth-banner"', html)
                self.assertIn('id="brain-auth-dialog"', html)
                self.assertIn("opscryer.brain.delegatedTokens.v1", html)
                self.assertIn("buildBrainAuthHeaders", html)
                self.assertIn("opscryer:setDelegatedToken", html)
                self.assertIn("openBrainAuthDialog", html)
                self.assertIn("submitBrainAuthDialog", html)
                self.assertIn("clearBrainDelegatedAuth", html)

        scripts = re.findall(r"<script[^>]*>(.*?)</script>", rendered_html, flags=re.DOTALL | re.IGNORECASE)
        self.assertGreaterEqual(len(scripts), 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            for idx, js in enumerate(scripts):
                if not js.strip():
                    continue
                js_path = Path(tmpdir) / f"script_{idx}.js"
                js_path.write_text(js, encoding="utf-8", newline="\n")
                proc = subprocess.run(
                    ["node", "--check", str(js_path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
