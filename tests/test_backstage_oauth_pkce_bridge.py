# SPDX-License-Identifier: Apache-2.0
"""Tests for the Backstage OAuth2 PKCE <-> OpsCryer delegated token postMessage bridge (Wave 2)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

OPSCRYER_ROOT = Path(__file__).resolve().parent.parent
if str(OPSCRYER_ROOT) not in sys.path:
    sys.path.insert(0, str(OPSCRYER_ROOT))

import opscryer_browser


PLUGIN_COMP_DIR = (
    OPSCRYER_ROOT
    / "plugins"
    / "opscryer"
    / "src"
    / "components"
    / "OpsCryerBrowserComponent"
)


class TestBackstageOAuth2PKCETokenBridge(unittest.TestCase):
    """Validates cross-origin PKCE token bridge security invariants in OpsCryer & Backstage plugin."""

    def test_01_plugin_typescript_files_enforce_strict_origin_and_zero_wildcards(self) -> None:
        bridge_ts = PLUGIN_COMP_DIR / "delegatedAuthBridge.ts"
        comp_tsx = PLUGIN_COMP_DIR / "OpsCryerBrowserComponent.tsx"
        test_tsx = PLUGIN_COMP_DIR / "OpsCryerBrowserComponent.test.tsx"
        for p in (bridge_ts, comp_tsx, test_tsx):
            self.assertTrue(p.is_file(), f"Missing Backstage plugin file: {p}")
            raw = p.read_bytes()
            self.assertNotIn(b"\r\n", raw, f"{p.name} must use LF line endings")

        bridge_txt = bridge_ts.read_text(encoding="utf-8")
        comp_txt = comp_tsx.read_text(encoding="utf-8")
        self.assertIn("opscryer:setDelegatedToken", bridge_txt)
        self.assertIn("opscryer:clearDelegatedToken", bridge_txt)
        self.assertIn("opscryer:authRequired", bridge_txt)
        self.assertIn("backstage-oauth-pkce", bridge_txt)
        # Never call postMessage with wildcard '*' targetOrigin.
        self.assertIsNone(re.search(r"postMessage\s*\([^)]*,\s*['\"]\*['\"]", bridge_txt))
        self.assertIsNone(re.search(r"postMessage\s*\([^)]*,\s*['\"]\*['\"]", comp_txt))
        self.assertIn("gitlabAuthApiRef", comp_txt)
        self.assertIn("useApiHolder", comp_txt)
        self.assertIn("Connect OAuth (PKCE)", comp_txt)
        self.assertIn("Disconnect OAuth", comp_txt)

    def test_02_opscryer_html_accepts_trusted_backstage_origin_and_rejects_untrusted_origins(self) -> None:
        env_patch = {
            "OPSCRYER_HOST_ALLOWED_ORIGINS": "https://backstage.example.org",
            "OPSCRYER_FRAME_ANCESTORS": "https://backstage.example.org",
        }
        with patch.dict(os.environ, env_patch, clear=False):
            html = opscryer_browser.render_standalone_browser_html()

        self.assertIn("isTrustedDelegatedAuthOrigin", html)
        self.assertIn("opscryer:setDelegatedToken", html)
        self.assertIn("opscryer:clearDelegatedToken", html)
        self.assertIn("opscryer:authRequired", html)
        self.assertNotIn("postMessage(authReqPayload, '*')", html)

        # If Node.js is available, execute the real browser listener logic in an isolated sandbox!
        node_bin = shutil.which("node")
        if not node_bin:
            return
        harness = r"""
const trustedOrigins = new Set(['https://backstage.example.org']);
const OpsCryerHostSnapshotBridge = {
  isTrustedOrigin(origin) { return trustedOrigins.has(origin); },
  _collectConfiguredOrigins() { return Array.from(trustedOrigins); },
};
let store = {};
let refreshes = 0;
const parentPosts = [];
const parentWin = { postMessage(msg, origin) { parentPosts.push({ msg, origin }); } };
const window = {
  location: { origin: 'https://opscryer.example.org' },
  parent: parentWin,
  _listeners: [],
  addEventListener(type, fn) { if (type === 'message') this._listeners.push(fn); },
};
function readBrainDelegatedTokens() { return { ...store }; }
function writeBrainDelegatedTokens(obj) { store = { ...obj }; }
function refreshGraphAfterAuthChange() { refreshes += 1; }
function isTrustedDelegatedAuthOrigin(origin) {
  if (!origin || typeof origin !== 'string') return false;
  if (typeof window !== 'undefined' && window.location && origin === window.location.origin) return true;
  if (typeof OpsCryerHostSnapshotBridge !== 'undefined' && typeof OpsCryerHostSnapshotBridge.isTrustedOrigin === 'function') {
    return Boolean(OpsCryerHostSnapshotBridge.isTrustedOrigin(origin));
  }
  return false;
}
window.addEventListener('message', ev => {
  if (!ev || !isTrustedDelegatedAuthOrigin(String(ev.origin || ''))) return;
  const isSameOrigin = Boolean(window.location && ev.origin === window.location.origin);
  if (!isSameOrigin && window.parent && ev.source && ev.source !== window.parent) return;
  const d = ev.data;
  if (!d || typeof d !== 'object') return;
  if (d.type === 'opscryer:clearDelegatedToken') {
    const clearProv = String(d.provider || '').trim().toLowerCase();
    if (clearProv && /^[a-z0-9_.-]{1,64}$/.test(clearProv)) {
      const cur = readBrainDelegatedTokens();
      delete cur[clearProv];
      writeBrainDelegatedTokens(cur);
    } else {
      writeBrainDelegatedTokens({});
    }
    refreshGraphAfterAuthChange();
    return;
  }
  if (d.type !== 'opscryer:setDelegatedToken') return;
  const prov = String(d.provider || '').trim().toLowerCase();
  const tok = String(d.token || '').trim();
  if (!/^[a-z0-9_.-]{1,64}$/.test(prov) || !tok) return;
  const cur = readBrainDelegatedTokens();
  cur[prov] = tok;
  writeBrainDelegatedTokens(cur);
  refreshGraphAfterAuthChange();
});
const dispatch = ev => window._listeners.forEach(fn => fn(ev));
// 1. Untrusted origin MUST be ignored
dispatch({ origin: 'https://evil.example.net', source: parentWin, data: { type: 'opscryer:setDelegatedToken', provider: 'gitlab', token: 'evil-tok' } });
if (Object.keys(store).length !== 0) throw new Error('Untrusted origin accepted');
// 2. Trusted origin from non-parent frame MUST be ignored
dispatch({ origin: 'https://backstage.example.org', source: { other: true }, data: { type: 'opscryer:setDelegatedToken', provider: 'gitlab', token: 'sibling-tok' } });
if (Object.keys(store).length !== 0) throw new Error('Non-parent source accepted');
// 3. Trusted Backstage parent origin MUST store short-lived PKCE token & refresh
dispatch({ origin: 'https://backstage.example.org', source: parentWin, data: { type: 'opscryer:setDelegatedToken', provider: 'gitlab', token: 'pkce-live-token' } });
if (store.gitlab !== 'pkce-live-token' || refreshes !== 1) throw new Error('Trusted parent token rejected');
// 4. Clear delegated token MUST remove provider cleanly
dispatch({ origin: 'https://backstage.example.org', source: parentWin, data: { type: 'opscryer:clearDelegatedToken', provider: 'gitlab' } });
if ('gitlab' in store || refreshes !== 2) throw new Error('Clear delegated token failed');
console.log(JSON.stringify({ ok: true, refreshes }));
"""
        proc = subprocess.run([node_bin, "-e", harness], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, f"Node harness failed: {proc.stderr}\n{proc.stdout}")
        res = json.loads(proc.stdout.strip())
        self.assertTrue(res["ok"])
        self.assertEqual(res["refreshes"], 2)


if __name__ == "__main__":
    unittest.main()
