# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit, HTTP, Full-Truth, and Node.js tests for 7-Level Breakdown, 3-View Canvas, and Truth Mode."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import shutil
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

import graph_layers
import opscryer_browser as browser
import world_map_engine


class GraphLevelsPythonTests(unittest.TestCase):
    """Verify 7-level classification, selection breakdown, tactical status, and workspace truth harvesting."""

    def test_seven_canonical_levels_order_and_classification(self) -> None:
        self.assertEqual(
            graph_layers.GRAPH_LEVEL_IDS,
            ("project", "feature", "dependency", "requirement", "test", "deployment", "contract"),
        )
        samples = [
            ({"id": "proj-opscryer", "kind": "engineering_project", "label": "OpsCryer"}, "project"),
            ({"id": "feat-world-map", "kind": "feature", "label": "2.5D World Map"}, "feature"),
            ({"id": "dep-k8s-svc", "kind": "kubernetes_service", "label": "Valkey Service"}, "dependency"),
            ({"id": "req-042", "kind": "requirement", "label": "REQ-042 Zero Fake Data"}, "requirement"),
            ({"id": "test-smoke", "kind": "test_suite", "label": "test_opscryer_public_smoke.py"}, "test"),
            ({"id": "deploy-prod", "kind": "kubernetes_deployment", "label": "opscryer-prod"}, "deployment"),
            ({"id": "contract-openapi", "kind": "contract", "label": "OpenAPI 3.1 Spec"}, "contract"),
            # Explicit graph_level override takes precedence over kind heuristics
            ({"id": "custom-1", "kind": "engineering_project", "graph_level": "include/dependency"}, "dependency"),
        ]
        for node, expected in samples:
            with self.subTest(node=node["id"]):
                self.assertEqual(graph_layers.classify_node_graph_level(node), expected)

    def test_selection_breakdown_single_and_multi_unit_rts_squad(self) -> None:
        catalog = {
            "nodes": [
                {"id": "proj-a", "label": "Project A", "kind": "engineering_project", "drilldown_children": ["feat-1", "dep-1"]},
                {"id": "feat-1", "label": "Feature 1", "kind": "feature", "drilldown_children": ["req-1", "test-1"]},
                {"id": "dep-1", "label": "Dep Lib", "kind": "dependency", "drilldown_children": []},
                {"id": "req-1", "label": "REQ-1", "kind": "requirement", "drilldown_children": []},
                {"id": "test-1", "label": "test_feat_1.py", "kind": "test_suite", "drilldown_children": [], "test_results": {"passed": 12, "failed": 0, "errors": 0}},
                {"id": "test-unrun", "label": "test_unrun.py", "kind": "test_suite", "drilldown_children": []},
                {"id": "deploy-1", "label": "deploy/prod", "kind": "kubernetes_deployment", "drilldown_children": [], "status": "degraded"},
                {"id": "contract-1", "label": "OpenAPI Contract", "kind": "contract", "drilldown_children": [], "mls_redacted": True},
            ],
            "edges": [
                {"source": "feat-1", "target": "deploy-1", "relation": "deployed_by"},
                {"source": "feat-1", "target": "test-unrun", "relation": "verified_by"},
                {"source": "proj-a", "target": "contract-1", "relation": "exposes_contract"},
            ],
        }
        # Selecting proj-a + feat-1 as an RTS squad surfaces all 7 levels in direct + 1-hop neighborhood
        res = graph_layers.analyze_selection_graph_levels(catalog, selected_ids=["proj-a", "feat-1"])
        self.assertEqual(res["total_nodes"], 8)
        self.assertEqual(res["selected_ids"], ["proj-a", "feat-1"])
        for lid in graph_layers.GRAPH_LEVEL_IDS:
            expected_count = 2 if lid == "test" else 1
            self.assertEqual(res["selection_breakdown"][lid]["count"], expected_count, msg=f"Expected {expected_count} in {lid}")
        # Critical invariant: 0 errors with 0 executed tests MUST map to UNVERIFIED_NOT_RUN (blue), never green!
        tv = res["selection_breakdown"]["test"]["test_verification"]
        self.assertEqual(tv["suites_verified_pass"], 1)
        self.assertEqual(tv["suites_unverified_not_run"], 1)
        self.assertEqual(tv["suites_failed"], 0)
        self.assertEqual(tv["tests_passed"], 12)
        self.assertEqual(tv["tests_executed"], 12)
        self.assertEqual(res["tactical_status_counts"]["blue"], 1)
        self.assertEqual(res["tactical_status_counts"]["orange"], 1)
        self.assertEqual(res["tactical_status_counts"]["purple"], 1)
        self.assertEqual(res["tactical_status_counts"]["green"], 5)

    def test_golden_path_gates_record_positive_pass_counts_distinguishing_unrun_from_passed(self) -> None:
        import golden_path_gates

        report = golden_path_gates.run_six_gate_prepush_audit(_PKG_DIR)
        self.assertTrue(report["passed"])
        self.assertIn("summary", report)
        self.assertEqual(report["summary"]["gates_verified_pass"], 6)
        self.assertGreater(report["summary"]["total_items_checked"], 50)
        self.assertEqual(report["summary"]["total_items_passed"], report["summary"]["total_items_checked"])
        for name, gate in report["gates"].items():
            with self.subTest(gate=name):
                self.assertEqual(gate["status"], "verified_pass")
                self.assertGreater(gate["checked"], 0)
                self.assertEqual(gate["passed_count"], gate["checked"])

        cli_rep = golden_path_gates.verify_public_cli_entrypoints(_PKG_DIR)
        self.assertEqual(cli_rep["checked_count"], 7)
        self.assertEqual(cli_rep["passed_count"], 7)
        self.assertEqual(cli_rep["failed_count"], 0)

    def test_harvest_workspace_truth_graph_covers_all_seven_levels_without_fakes(self) -> None:
        catalog = graph_layers.harvest_workspace_truth_graph(_PKG_DIR, project_name="opscryer")
        self.assertTrue(catalog["truth_mode"])
        self.assertFalse(catalog["example"])
        self.assertEqual(catalog["source"], "workspace_truth_harvest")
        summary = catalog["graph_levels_summary"]
        for lid in ("project", "feature", "dependency", "requirement", "test", "contract"):
            self.assertGreater(summary[lid]["count"], 0, msg=f"Expected real {lid} nodes from opscryer repo")
        # Must never fabricate Acme Cloud Systems demo entities
        labels = " ".join(str(n.get("label") or "") for n in catalog["nodes"])
        self.assertNotIn("Acme Cloud Systems", labels)
        self.assertNotIn("nodealpha01", labels)

    def test_world_map_graph_layers_mode_creates_seven_level_territories(self) -> None:
        catalog = graph_layers.harvest_workspace_truth_graph(_PKG_DIR, project_name="opscryer")
        layout = world_map_engine.build_world_map_layout(catalog, mode="graph_layers")
        self.assertEqual(layout["mode"], "graph_layers")
        self.assertGreaterEqual(len(layout["territories"]), 6)
        self.assertTrue(all("graph_level" in n for n in layout["nodes"]))
        self.assertTrue(all("tactical_status" in n for n in layout["nodes"]))


class GraphLevelsAndTruthHTTPTests(unittest.TestCase):
    """Verify /api/v1/graph/levels, graph_layers World Map layout, and Full-Truth server behavior."""

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

    def test_api_graph_levels_and_world_map_graph_layers(self) -> None:
        st, data = self._get_json("/api/v1/graph/levels?node_ids=root-company")
        self.assertEqual(st, 200)
        self.assertEqual(data["schema_version"], graph_layers.GRAPH_LAYERS_SCHEMA_VERSION)
        self.assertEqual(len(data["levels"]), 7)
        self.assertIn("selection_breakdown", data)
        self.assertIn("global_breakdown", data)

        st2, wm = self._get_json("/api/v1/world-map/layout?mode=graph_layers")
        self.assertEqual(st2, 200)
        self.assertEqual(wm["mode"], "graph_layers")
        self.assertGreater(wm["node_count"], 0)

    def test_truth_mode_never_leaks_synthetic_acme_or_offline_nodes(self) -> None:
        with patch.dict(
            os.environ,
            {"OPSCRYER_TRUTH_MODE": "1", "OPSCRYER_BRAIN_API_URL": "", "OPSCRYER_TRUTH_WORKSPACE": ""},
            clear=False,
        ):
            st, cat = self._get_json("/api/v1/graph/catalog")
            self.assertEqual(st, 200)
            self.assertTrue(cat.get("truth_mode"))
            self.assertFalse(cat.get("example"))
            node_ids = {str(n.get("id")) for n in cat.get("nodes", [])}
            self.assertNotIn("root-company", node_ids)
            self.assertNotIn("team-demo-platform", node_ids)
            self.assertNotIn("k8s/Node//nodealpha01", node_ids)

        with patch.dict(
            os.environ,
            {"OPSCRYER_TRUTH_MODE": "1", "OPSCRYER_BRAIN_API_URL": "", "OPSCRYER_TRUTH_WORKSPACE": str(_PKG_DIR)},
            clear=False,
        ):
            st2, cat2 = self._get_json("/api/v1/graph/catalog")
            self.assertEqual(st2, 200)
            self.assertEqual(cat2.get("source"), "workspace_truth_harvest")
            self.assertGreater(len(cat2.get("nodes", [])), 20)


class UnifiedThreeViewNodeTests(unittest.TestCase):
    """Run rendered OpsCryer JS in Node.js to verify 3 views, 7-level RTS stats, and zero fake currencies."""

    @unittest.skipUnless(shutil.which("node"), "Node.js is required")
    def test_three_canvas_views_and_middle_rts_seven_level_stats(self) -> None:
        html = browser.render_standalone_browser_html()
        self.assertIn('id="inline-local-links-stage"', html)
        self.assertIn('id="rts-selection-level-stats"', html)
        self.assertIn('id="graph-level-breakdown-bar"', html)
        self.assertIn('id="tactical-6color-ribbon"', html)
        self.assertNotIn("0 failing (Synced)", html)
        self.assertNotIn("2-Stage Ready", html)
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]

        harness = r"""
const assert = require('node:assert/strict');
class Element {
  constructor() {
    this.children = [];
    this.style = {};
    this.textContent = '';
    this.listeners = {};
    this.dataset = {};
    this._classes = new Set();
    this.classList = {
      toggle: (name, force) => {
        const next = force === undefined ? !this._classes.has(name) : Boolean(force);
        if (next) this._classes.add(name); else this._classes.delete(name);
        return next;
      },
      contains: name => this._classes.has(name),
      add: name => this._classes.add(name),
      remove: name => this._classes.delete(name),
    };
  }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...c) { this.children = c; }
  addEventListener(t, cb) { this.listeners[t] = cb; }
  setAttribute() {}
}
const elements = new Map();
global.document = {
  body: new Element(),
  listeners: {},
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  },
  createElement() { return new Element(); },
  addEventListener(t, cb) { this.listeners[t] = cb; }
};
global.window = {location: {search: ''}};
"""
        assertions = r"""
(async () => {
  await new Promise(resolve => setImmediate(resolve));
  const stats = $('rts-selection-level-stats');
  assert.equal(stats.children.length, 7, 'Middle RTS console must render all 7 level stats');
  const labels = stats.children.map(c => c.textContent);
  assert.ok(labels.some(t => t.includes('Project:')));
  assert.ok(labels.some(t => t.includes('Feature:')));
  assert.ok(labels.some(t => t.includes('Include/Dep:')));
  assert.ok(labels.some(t => t.includes('Requirement:')));
  assert.ok(labels.some(t => t.includes('Test:')));
  assert.ok(labels.some(t => t.includes('Deployment:')));
  assert.ok(labels.some(t => t.includes('Contract:')));

  assert.equal(window.setWorkspaceCanvasView('local_links'), 'local_links');
  assert.equal($('inline-local-links-stage').style.display, 'block');
  assert.equal($('browser-children-list').style.display, 'none');
  assert.ok($('local-links-right-col').children.length > 0);

  assert.equal(window.setWorkspaceCanvasView('world_map'), 'world_map');
  assert.equal($('inline-world-map-stage').style.display, 'flex');
  assert.equal($('inline-local-links-stage').style.display, 'none');

  assert.equal(window.setWorkspaceCanvasView('boxes'), 'boxes');
  assert.equal($('browser-children-list').style.display, '');
  assert.equal($('inline-world-map-stage').style.display, 'none');
})().catch(err => { console.error(err); process.exitCode = 1; });
"""
        with tempfile.TemporaryDirectory() as td:
            js_file = Path(td) / "test_three_views.js"
            js_file.write_text(harness + "\n" + script + "\n" + assertions, encoding="utf-8", newline="\n")
            res = subprocess.run([shutil.which("node"), str(js_file)], capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 0, msg=res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
