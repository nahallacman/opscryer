# SPDX-License-Identifier: Apache-2.0
"""Unit tests for OpsCryer opt-in Knowledge Graph Sources proxy, validation, and HUD panel."""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from typing import Any
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import opscryer_browser  # noqa: E402


class _MockSourcesBrainHandler(http.server.BaseHTTPRequestHandler):
    """Hermetic mock Central Brain API server exposing /api/v1/graph/sources and /api/v1/opscryer/graph."""

    recorded_requests: list[tuple[str, str]] = []
    fail_sources_status: int | None = None

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        type(self).recorded_requests.append((parsed.path, parsed.query))

        if parsed.path == "/healthz":
            self._send_json(200, {"status": "ok", "service": "brain-api"})
            return

        if parsed.path == "/api/v1/scopes":
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
            return

        if parsed.path == "/api/v1/graph/sources":
            if type(self).fail_sources_status is not None:
                self._send_json(type(self).fail_sources_status, {"error": "Upstream Brain failure"})
                return
            refreshed = query.get("refresh", ["0"])[0] == "1"
            self._send_json(
                200,
                {
                    "refreshed": refreshed,
                    "sources": [
                        {
                            "id": "org-platform",
                            "label": "Organization Primary Graph",
                            "description": "Primary operational topology",
                            "default_enabled": True,
                            "kind": "primary",
                            "node_count": 120,
                            "edge_count": 240,
                        },
                        {
                            "id": "ai-foundations",
                            "label": "AI Engineering & Grounded Concepts",
                            "description": "Curated AI engineering knowledge graph",
                            "default_enabled": False,
                            "kind": "external",
                            "source_repo": "org/ai-engineering-knowledge",
                            "sync_source": "gitlab-live",
                            "commit_sha": "abc123456789",
                            "node_count": 46,
                            "edge_count": 103,
                            "docs_url": "/docs/default/component/ai-engineering-knowledge",
                        },
                        {
                            "id": "custom-kb",
                            "label": "Platform Architecture Standards",
                            "description": "Cached architecture guidelines",
                            "default_enabled": False,
                            "kind": "external",
                            "source_repo": "org/platform-kb",
                            "sync_source": "stale-cache",
                            "commit_sha": "def987654321",
                            "node_count": 19,
                            "edge_count": 31,
                            "docs_url": "https://docs.example.org/platform-kb",
                        },
                    ],
                },
            )
            return

        if parsed.path == "/api/v1/opscryer/graph":
            scope = query.get("scope", ["org-platform"])[0]
            raw_sources = query.get("sources", [""])[0]
            selected = [s for s in raw_sources.split(",") if s] if raw_sources else []

            nodes: list[dict[str, Any]] = [
                {
                    "id": scope,
                    "label": f"Scope {scope}",
                    "kind": "company_root",
                    "domain": "company_org",
                    "summary": "Primary scope root",
                    "drilldown_children": [],
                }
            ]
            edges: list[dict[str, str]] = []
            if "ai-foundations" in selected:
                nodes[0]["drilldown_children"].append("kb-ai-attention")
                nodes.append(
                    {
                        "id": "kb-ai-attention",
                        "label": "Attention Is All You Need",
                        "kind": "knowledge_concept",
                        "domain": "ai_foundations",
                        "summary": "Transformer self-attention foundations.",
                        "canonical_url": "https://arxiv.org/abs/1706.03762",
                        "control_plane_urls": [
                            {
                                "label": "TechDocs",
                                "url": "/docs/default/component/ai-engineering-knowledge/attention",
                                "system": "techdocs",
                            },
                            {
                                "label": "GitLab Source",
                                "url": "https://gitlab.example.org/org/ai-engineering-knowledge",
                                "system": "gitlab",
                            },
                        ],
                        "drilldown_children": [],
                    }
                )
                edges.append({"source": scope, "target": "kb-ai-attention", "relation": "references"})
            if "custom-kb" in selected:
                nodes[0]["drilldown_children"].append("kb-custom-adr")
                nodes.append(
                    {
                        "id": "kb-custom-adr",
                        "label": "Zero-Trust ADR",
                        "kind": "knowledge_article",
                        "domain": "architecture",
                        "summary": "Platform zero-trust reference.",
                        "canonical_url": "https://docs.example.org/platform-kb/adr-01",
                        "control_plane_urls": [],
                        "drilldown_children": [],
                    }
                )
                edges.append({"source": scope, "target": "kb-custom-adr", "relation": "references"})

            self._send_json(
                200,
                {
                    "schema_version": "1.0-separable-spatial-graph-contract",
                    "scope_id": scope,
                    "root_node_id": scope,
                    "ai_invoked": False,
                    "ecosystem_revision": "rev-kg-001",
                    "active_sources": selected,
                    "nodes": nodes,
                    "edges": edges,
                    "rts_currencies": [],
                },
            )
            return

        self._send_json(404, {"error": f"Not found: {parsed.path}"})

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class TestGraphSourcesPanel(unittest.TestCase):
    """Test /api/v1/graph/sources proxy, /api/v1/graph/catalog?sources validation, and index.html HUD."""

    brain_server: http.server.HTTPServer
    brain_thread: threading.Thread
    brain_url: str
    opscryer_server: http.server.HTTPServer
    opscryer_thread: threading.Thread
    opscryer_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.brain_server = http.server.HTTPServer(("127.0.0.1", 0), _MockSourcesBrainHandler)
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

    def setUp(self) -> None:
        _MockSourcesBrainHandler.recorded_requests.clear()
        _MockSourcesBrainHandler.fail_sources_status = None

    def _get_json(self, path: str) -> tuple[int, dict[str, Any]]:
        req = urllib.request.Request(f"{self.opscryer_url}{path}", headers={"Host": "localhost"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_graph_sources_proxy_success_and_refresh_forwarding(self) -> None:
        status, data = self._get_json("/api/v1/graph/sources")
        self.assertEqual(status, 200)
        self.assertTrue(data["brain_connected"])
        self.assertFalse(data["refreshed"])
        source_ids = [s["id"] for s in data["sources"]]
        self.assertEqual(source_ids, ["org-platform", "ai-foundations", "custom-kb"])
        ai_src = data["sources"][1]
        self.assertFalse(ai_src["default_enabled"])
        self.assertEqual(ai_src["kind"], "external")
        self.assertEqual(ai_src["node_count"], 46)
        self.assertEqual(ai_src["sync_source"], "gitlab-live")
        self.assertEqual(ai_src["docs_url"], "/docs/default/component/ai-engineering-knowledge")

        # Forward ?refresh=1 cleanly to Brain
        status_r, data_r = self._get_json("/api/v1/graph/sources?refresh=1")
        self.assertEqual(status_r, 200)
        self.assertTrue(data_r["brain_connected"])
        self.assertTrue(data_r["refreshed"])
        self.assertIn(("/api/v1/graph/sources", "refresh=1"), _MockSourcesBrainHandler.recorded_requests)

        # Reject invalid refresh values fail-closed with 400
        for bad_qs in ("?refresh=true", "?refresh=2", "?refresh=1&unknown=1"):
            with self.subTest(bad_qs=bad_qs):
                with self.assertRaises(urllib.error.HTTPError) as err_ctx:
                    self._get_json(f"/api/v1/graph/sources{bad_qs}")
                self.assertEqual(err_ctx.exception.code, 400)
                err_ctx.exception.close()

    def test_graph_sources_fail_closed_when_brain_unset_or_unreachable(self) -> None:
        # 1. OPSCRYER_BRAIN_API_URL unset -> graceful 200 fail-closed
        with mock.patch.dict(os.environ, {"OPSCRYER_BRAIN_API_URL": ""}, clear=False):
            status, data = self._get_json("/api/v1/graph/sources")
            self.assertEqual(status, 200)
            self.assertEqual(data["sources"], [])
            self.assertFalse(data["brain_connected"])
            self.assertIn("error", data)

        # 2. Upstream Brain HTTP error -> graceful 200 fail-closed
        _MockSourcesBrainHandler.fail_sources_status = 502
        status_err, data_err = self._get_json("/api/v1/graph/sources")
        self.assertEqual(status_err, 200)
        self.assertEqual(data_err["sources"], [])
        self.assertFalse(data_err["brain_connected"])
        self.assertIn("error", data_err)
        _MockSourcesBrainHandler.fail_sources_status = None

        # 3. Unreachable Brain socket -> graceful 200 fail-closed
        with mock.patch.dict(
            os.environ,
            {"OPSCRYER_BRAIN_API_URL": "http://127.0.0.1:1", "OPSCRYER_BRAIN_TIMEOUT": "1"},
            clear=False,
        ):
            status_down, data_down = self._get_json("/api/v1/graph/sources")
            self.assertEqual(status_down, 200)
            self.assertEqual(data_down["sources"], [])
            self.assertFalse(data_down["brain_connected"])
            self.assertIn("error", data_down)

    def test_graph_catalog_validates_and_forwards_sources_to_brain(self) -> None:
        # Omitted sources -> strictly 0 external opt-in nodes
        status_base, base_cat = self._get_json("/api/v1/graph/catalog?scope=org-platform")
        self.assertEqual(status_base, 200)
        self.assertEqual(base_cat["active_sources"], [])
        self.assertEqual([n["id"] for n in base_cat["nodes"]], ["org-platform"])
        last_path, last_qs = _MockSourcesBrainHandler.recorded_requests[-1]
        self.assertEqual(last_path, "/api/v1/opscryer/graph")
        self.assertNotIn("sources=", last_qs)

        # Multiple valid opt-in sources forwarded cleanly
        status_ext, ext_cat = self._get_json(
            "/api/v1/graph/catalog?scope=org-platform&sources=ai-foundations,custom-kb"
        )
        self.assertEqual(status_ext, 200)
        self.assertEqual(ext_cat["active_sources"], ["ai-foundations", "custom-kb"])
        node_ids = {n["id"] for n in ext_cat["nodes"]}
        self.assertEqual(node_ids, {"org-platform", "kb-ai-attention", "kb-custom-adr"})
        last_path, last_qs = _MockSourcesBrainHandler.recorded_requests[-1]
        self.assertEqual(last_path, "/api/v1/opscryer/graph")
        parsed_qs = urllib.parse.parse_qs(last_qs)
        self.assertEqual(parsed_qs["scope"], ["org-platform"])
        self.assertEqual(parsed_qs["sources"], ["ai-foundations,custom-kb"])

        # Deduplicates repeated identical source IDs cleanly
        status_dedup, dedup_cat = self._get_json(
            "/api/v1/graph/catalog?scope=org-platform&sources=ai-foundations,ai-foundations"
        )
        self.assertEqual(status_dedup, 200)
        self.assertEqual(dedup_cat["active_sources"], ["ai-foundations"])

    def test_graph_catalog_rejects_malformed_and_injection_sources(self) -> None:
        malformed_queries = (
            "sources=",
            "sources=ai-foundations,",
            "sources=,ai-foundations",
            "sources=ai-foundations,,custom-kb",
            "sources=AI-Foundations",
            "sources=-leading-dash",
            "sources=_leading_underscore",
            "sources=../etc/passwd",
            "sources=ai-foundations;rm",
            "sources=ai-foundations%26admin=1",
            "sources=bad%20source",
            "sources=ai.foundations",
            f"sources={'a' * 65}",
            "sources=" + ",".join(f"src-{i}" for i in range(33)),
            "sources=ai-foundations&sources=custom-kb",
        )
        for qs in malformed_queries:
            with self.subTest(qs=qs):
                _MockSourcesBrainHandler.recorded_requests.clear()
                with self.assertRaises(urllib.error.HTTPError) as err_ctx:
                    self._get_json(f"/api/v1/graph/catalog?scope=org-platform&{qs}")
                self.assertEqual(err_ctx.exception.code, 400)
                err_ctx.exception.close()
                # Fail closed: malformed input must never be proxied upstream to Brain
                self.assertEqual(_MockSourcesBrainHandler.recorded_requests, [])

    def test_index_html_contains_knowledge_sources_panel_and_matches_renderer(self) -> None:
        rendered = opscryer_browser.render_standalone_browser_html()
        disk_html = (REPO_ROOT / "index.html").read_text(encoding="utf-8")
        self.assertEqual(rendered, disk_html)
        for token in (
            'id="kg-sources-panel"',
            'id="kg-sources-list"',
            'id="kg-sources-refresh-btn"',
            "Knowledge Sources",
            "/api/v1/graph/sources",
            "sources=",
            "default_enabled",
            "Primary Source",
            "canonical_url",
            "control_plane_urls",
            "Docs ↗",
        ):
            self.assertIn(token, disk_html)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required to execute shipped browser JavaScript")
    def test_index_html_js_knowledge_sources_panel_toggle_and_inspector(self) -> None:
        html = (REPO_ROOT / "index.html").read_text(encoding="utf-8")
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]

        harness = r"""
const assert = require('node:assert/strict');
class Element {
  constructor(tag) {
    this.tagName = String(tag || 'div').toUpperCase();
    this.children = [];
    this.style = {display: 'none'};
    this.textContent = '';
    this.innerHTML = '';
    this.listeners = {};
    this.dataset = {};
    this.attributes = {};
    this.checked = false;
    this.value = '';
    this.href = '';
    this.title = '';
    this._classes = new Set();
    this.classList = {
      toggle: (name, force) => {
        const next = force === undefined ? !this._classes.has(name) : Boolean(force);
        if (next) this._classes.add(name);
        else this._classes.delete(name);
        return next;
      },
      contains: name => this._classes.has(name),
      add: name => this._classes.add(name),
      remove: name => this._classes.delete(name),
    };
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k]; }
  removeAttribute(k) { delete this.attributes[k]; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
}
const elements = new Map();
global.document = {
  listeners: {},
  referrer: '',
  body: new Element('body'),
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element('div'));
    return elements.get(id);
  },
  createElement(tag) { return new Element(tag); },
  addEventListener(type, callback) { this.listeners[type] = callback; },
  querySelector() { return null; },
  querySelectorAll() { return []; },
};
const openedUrls = [];
const fetchCalls = [];
let mockSourcesPayload = {
  brain_connected: true,
  sources: [
    {id: 'org-platform', label: 'Primary Org', default_enabled: true, kind: 'primary', node_count: 100},
    {
      id: 'ai-foundations',
      label: 'AI Engineering & Grounded Concepts',
      description: 'AI concepts',
      default_enabled: false,
      kind: 'external',
      source_repo: 'org/ai-engineering-knowledge',
      sync_source: 'gitlab-live',
      commit_sha: '1234567890abcdef',
      node_count: 46,
      edge_count: 103,
      docs_url: '/docs/default/component/ai-engineering-knowledge',
    },
    {
      id: 'custom-kb',
      label: 'Platform KB <script>alert(1)</script>',
      default_enabled: false,
      kind: 'external',
      source_repo: 'org/platform-kb',
      sync_source: 'stale-cache',
      node_count: 12,
      docs_url: 'javascript:alert(1)',
    },
  ],
};
global.fetch = async (url) => {
  const s = String(url);
  fetchCalls.push(s);
  if (s.includes('/api/v1/brain/scopes')) {
    return {
      ok: true,
      status: 200,
      json: async () => ({enabled: true, scopes: [{id: 'org-platform', label: 'Platform Engineering'}]}),
    };
  }
  if (s.includes('/api/v1/graph/sources')) {
    return {ok: true, status: 200, json: async () => mockSourcesPayload};
  }
  if (s.includes('/api/v1/graph/catalog')) {
    const parsed = new URL(s, 'http://localhost:8088');
    const scope = parsed.searchParams.get('scope') || 'org-platform';
    const sourcesParam = parsed.searchParams.get('sources') || '';
    const active = sourcesParam ? sourcesParam.split(',') : [];
    const nodes = [{
      id: scope,
      label: 'Org Root',
      kind: 'company_root',
      domain: 'company_org',
      summary: 'Root node',
      drilldown_children: active.includes('ai-foundations') ? ['kb-ai-01'] : [],
    }];
    if (active.includes('ai-foundations')) {
      nodes.push({
        id: 'kb-ai-01',
        label: 'Transformer Architecture <img src=x onerror=alert(1)>',
        kind: 'knowledge_concept',
        domain: 'ai_foundations',
        summary: 'Attention foundations',
        canonical_url: 'https://arxiv.org/abs/1706.03762',
        control_plane_urls: [
          {label: 'TechDocs', url: '/docs/default/component/ai-engineering-knowledge/transformers', system: 'techdocs'},
          {label: 'Evil XSS', url: 'javascript:alert(1)', system: 'xss'},
        ],
        drilldown_children: [],
      });
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        schema_version: '1.0-separable-spatial-graph-contract',
        scope_id: scope,
        root_node_id: scope,
        ai_invoked: false,
        ecosystem_revision: 'rev-1',
        nodes,
        edges: [],
        rts_currencies: [],
      }),
    };
  }
  return {ok: false, status: 404, json: async () => ({error: 'not found'})};
};
global.setInterval = () => 1;
global.clearInterval = () => {};
global.window = {
  location: {
    origin: 'http://localhost:8088',
    hostname: 'localhost',
    search: '?scope=org-platform&hostOrigin=https%3A%2F%2Fbackstage.example.org',
  },
  open(url) { openedUrls.push(url); },
  addEventListener() {},
  dispatchEvent() { return true; },
};
"""
        assertions = r"""
(async () => {
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));

  const adapter = window.SpatialGraphAdapter;
  assert.equal(adapter.currentScope, 'org-platform');

  // 1. Panel visible with ONLY the 2 external toggleable sources (primary excluded)
  const panel = $('kg-sources-panel');
  assert.equal(panel.style.display, 'flex');
  const rows = $('kg-sources-list').children;
  assert.equal(rows.length, 2);

  // 2. Opt-in sources MUST default to UNCHECKED and initial catalog request MUST omit sources=
  assert.deepEqual(adapter.selectedSources, []);
  const firstCb = rows[0].children[0].children[0];
  assert.equal(firstCb.checked, false);
  const secondCb = rows[1].children[0].children[0];
  assert.equal(secondCb.checked, false);
  const initialCatalogUrl = fetchCalls.find(u => u.includes('/api/v1/graph/catalog'));
  assert.ok(initialCatalogUrl, 'Initial catalog fetch must occur');
  assert.equal(initialCatalogUrl.includes('sources='), false, 'Initial fetch must omit sources= when none checked');

  // 3. Row metadata: label, node count, sync status, tooltip with source_repo, Backstage-resolved Docs link, XSS blocked
  assert.equal(rows[0].children[0].children[1].textContent, 'AI Engineering & Grounded Concepts');
  assert.equal(rows[0].children[1].textContent, '46 nodes');
  assert.equal(rows[0].children[2].textContent, 'gitlab-live');
  assert.ok(rows[0].title.includes('org/ai-engineering-knowledge'));
  assert.equal(rows[0].children[3].textContent, 'Docs ↗');
  assert.equal(
    rows[0].children[3].href,
    'https://backstage.example.org/docs/default/component/ai-engineering-knowledge'
  );
  // Malicious javascript: docs_url on second source must be rejected (no <a> appended)
  assert.equal(rows[1].children.length, 3);

  // 4. Checking ai-foundations updates selectedSources and re-fetches catalog with scope + sources
  fetchCalls.length = 0;
  firstCb.checked = true;
  await firstCb.listeners.change();
  assert.deepEqual(adapter.selectedSources, ['ai-foundations']);
  assert.equal(adapter.currentScope, 'org-platform');
  const checkedCatalogUrl = fetchCalls.find(u => u.includes('/api/v1/graph/catalog'));
  assert.equal(checkedCatalogUrl, '/api/v1/graph/catalog?scope=org-platform&sources=ai-foundations');
  assert.ok(adapter.getNode('kb-ai-01'), 'External knowledge node must be overlaid in graph');

  // 5. Clicking external node displays Primary Source (canonical_url) and TechDocs control_plane_url safely (blocks javascript:)
  adapter.inspectObjectInOuterFrame('kb-ai-01');
  const linkButtons = $('browser-focal-links').children;
  const labels = linkButtons.map(b => b.children[0].children[0].textContent);
  assert.ok(labels.includes('↗ Primary Source'), 'Expected Primary Source button in inspector');
  assert.ok(labels.some(l => l.includes('TechDocs')), 'Expected TechDocs button in inspector');
  assert.equal(labels.some(l => l.includes('Evil XSS')), false, 'javascript: URL must be blocked fail-closed');
  // Clicking TechDocs button opens resolved Backstage URL (not /tactical-deck dock)
  const docsBtn = linkButtons.find(b => b.children[0].children[0].textContent.includes('TechDocs'));
  docsBtn.listeners.click();
  assert.equal(
    openedUrls[openedUrls.length - 1],
    'https://backstage.example.org/docs/default/component/ai-engineering-knowledge/transformers'
  );

  // 6. Refresh button calls /api/v1/graph/sources?refresh=1 and preserves checked state
  fetchCalls.length = 0;
  await $('kg-sources-refresh-btn').onclick();
  assert.ok(fetchCalls.includes('/api/v1/graph/sources?refresh=1'));
  assert.deepEqual(adapter.selectedSources, ['ai-foundations']);

  // 7. Unchecking ai-foundations omits sources= on catalog re-fetch
  fetchCalls.length = 0;
  const refreshedCb = $('kg-sources-list').children[0].children[0].children[0];
  refreshedCb.checked = false;
  await refreshedCb.listeners.change();
  assert.deepEqual(adapter.selectedSources, []);
  const uncheckedCatalogUrl = fetchCalls.find(u => u.includes('/api/v1/graph/catalog'));
  assert.equal(uncheckedCatalogUrl, '/api/v1/graph/catalog?scope=org-platform');
  assert.equal(adapter.getNode('kb-ai-01'), null);

  // 8. Disconnected / empty external sources hides panel cleanly with zero errors
  mockSourcesPayload = {sources: [], brain_connected: false, error: 'offline'};
  await adapter.refreshSources();
  assert.equal($('kg-sources-panel').style.display, 'none');
  assert.equal($('kg-sources-list').children.length, 0);
})().catch(err => {
  console.error(err);
  process.exit(1);
});
"""
        proc = subprocess.run(
            ["node", "-"],
            input=harness + "\n" + script + "\n" + assertions,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"Node.js browser harness failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
