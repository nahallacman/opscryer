# SPDX-License-Identifier: Apache-2.0
"""Unit, HTTP API, and Node.js reactive store tests for the 3-Tool Self-Dogfood Dataset
and Unidirectional Normalized DFS-Bitmask Dataset Tree Sidebar.
"""

from __future__ import annotations

import http.client
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

from dataset_tree_store import (
    DATASET_TREE_SCHEMA_VERSION,
    DOGFOOD_DATASET_ID,
    build_dataset_tree_store_js,
    build_dogfood_three_tool_dataset,
    build_normalized_dataset_tree,
    evaluate_dogfood_self_understanding,
    is_dogfood_dataset_default_enabled,
)
from graph_layers import GRAPH_LEVEL_IDS
import opscryer_browser as browser


class DatasetTreeStorePythonTests(unittest.TestCase):
    """Verify real 3-tool dogfood dataset, self-eval positive passes, and DFS interval invariants."""

    def test_dogfood_three_tool_dataset_contains_all_three_repos_seven_levels_and_contracts(self) -> None:
        ds = build_dogfood_three_tool_dataset()
        self.assertEqual(ds["dataset_id"], DOGFOOD_DATASET_ID)
        self.assertIs(ds["truth_mode"], True)
        self.assertIs(ds["example"], False)
        self.assertIs(ds["configurable_toggle"], True)
        self.assertGreater(ds["node_count"], 20)
        self.assertGreater(ds["edge_count"], 20)

        repos = {n.get("repo_id") for n in ds["nodes"]}
        self.assertTrue({"opscryer", "brain", "meshworks"}.issubset(repos))
        for lid in GRAPH_LEVEL_IDS:
            self.assertGreater(ds["graph_levels_summary"][lid]["count"], 0, f"missing level {lid}")

        rels = {e["relation"] for e in ds["edges"]}
        self.assertTrue(
            {"queries_spatial_graph_contract", "consumes_predump_bundle", "delegates_hydrogen_cast"}.issubset(rels)
        )
        all_labels = " ".join(str(n.get("label") or "") for n in ds["nodes"])
        self.assertNotIn("Acme Cloud Systems", all_labels)
        self.assertNotIn("Jordan Vance", all_labels)
        self.assertNotIn("Elena Rostova", all_labels)

    def test_dogfood_fallback_manifests_when_sibling_repos_absent(self) -> None:
        missing = Path(tempfile.gettempdir()) / "opscryer_nonexistent_sibling_repo_xyz"
        ds = build_dogfood_three_tool_dataset(workspace_roots={"brain": missing, "meshworks": missing})
        self.assertEqual(ds["repo_origins"]["brain"], "verified_manifest")
        self.assertEqual(ds["repo_origins"]["meshworks"], "verified_manifest")
        ev = evaluate_dogfood_self_understanding(ds)
        self.assertTrue(ev["passed"], ev)
        self.assertEqual(ev["status"], "verified_pass")
        self.assertEqual(ev["checks_executed"], 5)
        self.assertEqual(ev["checks_passed"], 5)
        self.assertEqual(ev["checks_failed"], 0)

    def test_dogfood_self_understanding_eval_records_positive_pass_counts(self) -> None:
        ds = build_dogfood_three_tool_dataset()
        ev = evaluate_dogfood_self_understanding(ds)
        self.assertTrue(ev["passed"], ev)
        self.assertEqual(ev["status"], "verified_pass")
        self.assertEqual(ev["checks_executed"], 5)
        self.assertEqual(ev["checks_passed"], 5)
        self.assertEqual(ev["checks_failed"], 0)
        tv = ds["test_verification"]
        self.assertGreater(tv["suites_total"], 0)
        self.assertEqual(tv["suites_verified_pass"], 0)
        self.assertGreater(tv["suites_unverified_not_run"], 0)

    def test_normalized_dataset_tree_dfs_intervals_contiguous_and_monotonic(self) -> None:
        ds = build_dogfood_three_tool_dataset()
        tree = ds["dataset_tree"]
        self.assertEqual(tree["schema_version"], DATASET_TREE_SCHEMA_VERSION)
        total = tree["total_leaves"]
        self.assertEqual(total, len(tree["leaf_graph_ids"]))
        self.assertEqual(total, len(tree["initial_mask"]))
        by_id = {n["id"]: n for n in tree["tree_nodes"]}

        leaf_positions: list[int] = []
        for tn in tree["tree_nodes"]:
            self.assertGreaterEqual(tn["dfs_in"], 0)
            self.assertLessEqual(tn["dfs_in"], tn["dfs_out"])
            self.assertLessEqual(tn["dfs_out"], total)
            self.assertEqual(tn["leaf_count"], tn["dfs_out"] - tn["dfs_in"])
            if tn["node_kind"] == "leaf":
                self.assertEqual(tn["leaf_count"], 1)
                leaf_positions.append(tn["dfs_in"])
            else:
                cursor = tn["dfs_in"]
                for cid in tn["children_ids"]:
                    child = by_id[cid]
                    self.assertEqual(child["parent_id"], tn["id"])
                    self.assertEqual(child["dfs_in"], cursor)
                    cursor = child["dfs_out"]
                self.assertEqual(cursor, tn["dfs_out"])

        self.assertEqual(sorted(leaf_positions), list(range(total)))

    def test_dogfood_default_env_flag_is_configurable(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPSCRYER_ENABLE_DOGFOOD_DATASET", None)
            self.assertFalse(is_dogfood_dataset_default_enabled())
        with patch.dict(os.environ, {"OPSCRYER_ENABLE_DOGFOOD_DATASET": "1"}, clear=False):
            self.assertTrue(is_dogfood_dataset_default_enabled())


class DatasetTreeStoreHTTPTests(unittest.TestCase):
    """Loopback HTTP verification for /api/v1/datasets/dogfood and /api/v1/datasets/tree."""

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

    def _get_json(self, path: str) -> tuple[int, dict]:
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=15)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()

    def test_dogfood_endpoint_and_self_eval_flag(self) -> None:
        st, body = self._get_json("/api/v1/datasets/dogfood")
        self.assertEqual(st, 200)
        self.assertEqual(body["dataset_id"], DOGFOOD_DATASET_ID)
        self.assertNotIn("self_eval", body)

        st2, body2 = self._get_json("/api/v1/datasets/dogfood?eval=1")
        self.assertEqual(st2, 200)
        self.assertEqual(body2["self_eval"]["status"], "verified_pass")
        self.assertEqual(body2["self_eval"]["checks_passed"], 5)
        self.assertEqual(body2["self_eval"]["checks_executed"], 5)

        st_bad, _ = self._get_json("/api/v1/datasets/dogfood?eval=invalid")
        self.assertEqual(st_bad, 400)

    def test_dataset_tree_endpoint_and_workspace_config_flag(self) -> None:
        st, body = self._get_json("/api/v1/datasets/tree")
        self.assertEqual(st, 200)
        self.assertIs(body["dogfood_included"], False)
        self.assertEqual(len(body["root_ids"]), 1)

        st2, body2 = self._get_json("/api/v1/datasets/tree?include_dogfood=1")
        self.assertEqual(st2, 200)
        self.assertIs(body2["dogfood_included"], True)
        self.assertEqual(len(body2["root_ids"]), 2)
        self.assertIn(f"ds:{DOGFOOD_DATASET_ID}", body2["root_ids"])

        st_bad, _ = self._get_json("/api/v1/datasets/tree?include_dogfood=9")
        self.assertEqual(st_bad, 400)

        st_cfg, cfg = self._get_json("/api/v1/workspace/config")
        self.assertEqual(st_cfg, 200)
        panel_ids = {p["id"] for p in cfg["panels"]}
        self.assertIn("dataset_sidebar", panel_ids)
        self.assertIn("dogfood_dataset_default", cfg["integrations"])


class DatasetTreeStoreNodeJSTests(unittest.TestCase):
    """Node.js verification of DFS bitmask toggles, tri-state selectors, scale speed, and UI wiring."""

    def test_normalized_store_bitmask_tristate_and_scale_performance(self) -> None:
        dogfood = build_dogfood_three_tool_dataset()
        js_code = build_dataset_tree_store_js()
        runner = (
            "const assert = require('assert');\n"
            f"const dogfood = {json.dumps(dogfood)};\n"
            f"{js_code}\n"
            "const store = globalThis.OpsCryerDatasetStore.createDatasetTreeStore([\n"
            "  {dataset_id: dogfood.dataset_id, label: dogfood.dataset_label, enabled: true, nodes: dogfood.nodes}\n"
            "]);\n"
            "const dsTid = 'ds:' + dogfood.dataset_id;\n"
            "const brainTid = dsTid + ':repo:brain';\n"
            "assert.strictEqual(store.getTriState(dsTid), 'true');\n"
            "assert.strictEqual(store.getTriState(brainTid), 'true');\n"
            "let events = 0;\n"
            "store.subscribe(() => { events++; });\n"
            "store.toggleTreeNode(brainTid);\n"
            "assert.strictEqual(store.getTriState(brainTid), 'false');\n"
            "assert.strictEqual(store.getTriState(dsTid), 'mixed');\n"
            "assert.ok(events >= 1);\n"
            "const activeIds = store.getActiveGraphNodeIds();\n"
            "assert.ok(!activeIds.has(dogfood.repo_root_ids.brain));\n"
            "assert.ok(activeIds.has(dogfood.repo_root_ids.opscryer));\n"
            "assert.ok(activeIds.has(dogfood.repo_root_ids.meshworks));\n"
            "store.toggleTreeNode(dsTid, true);\n"
            "assert.strictEqual(store.getTriState(brainTid), 'true');\n"
            "assert.strictEqual(store.getTriState(dsTid), 'true');\n"
            "store.setSearchQuery(dogfood.repo_root_ids.meshworks);\n"
            "const rows = store.getVisibleRows();\n"
            "assert.ok(rows.some(r => r.node.id === dsTid + ':repo:meshworks'));\n"
            "assert.ok(!rows.some(r => r.node.id === dsTid + ':repo:brain'));\n"
            "assert.ok(!rows.some(r => r.node.id === dsTid + ':repo:opscryer'));\n"
            "const bigNodes = [];\n"
            "for (let i = 0; i < 2500; i++) {\n"
            "  bigNodes.push({id: 'n-' + i, label: 'Node ' + i, repo_id: 'repo_' + (i % 5), graph_level: 'feature'});\n"
            "}\n"
            "const bigStore = globalThis.OpsCryerDatasetStore.createDatasetTreeStore([{dataset_id: 'big', label: 'Big', enabled: true, nodes: bigNodes}]);\n"
            "const t0 = Date.now();\n"
            "bigStore.toggleTreeNode('ds:big:repo:repo_0');\n"
            "const dt = Date.now() - t0;\n"
            "assert.strictEqual(bigStore.getSnapshot().includedLeaves, 2000);\n"
            "assert.strictEqual(bigStore.getTriState('ds:big'), 'mixed');\n"
            "assert.ok(dt < 100, 'Expected fast bitmask toggle, got ' + dt + 'ms');\n"
            "console.log(JSON.stringify({ok: true, toggle_ms: dt, total_dogfood_leaves: store.getSnapshot().totalLeaves}));\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as tf:
            tf.write(runner)
            temp_path = Path(tf.name)
        try:
            proc = subprocess.run(["node", str(temp_path)], capture_output=True, text=True, timeout=20, check=False)
        finally:
            temp_path.unlink(missing_ok=True)
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}\nstdout={proc.stdout}")
        res = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertTrue(res["ok"])
        self.assertGreater(res["total_dogfood_leaves"], 20)

    def test_rendered_browser_sidebar_end_to_end_live_filtering_and_aria(self) -> None:
        html = browser.render_standalone_browser_html()
        dogfood = build_dogfood_three_tool_dataset()
        script_match = re.search(r"<script>(.*?)</script>", html, flags=re.DOTALL)
        self.assertIsNotNone(script_match)
        embedded_script = script_match.group(1)

        harness = (
            "const assert = require('assert');\n"
            "const elements = new Map();\n"
            "function makeEl(tag, id) {\n"
            "  const el = {\n"
            "    tagName: String(tag || 'DIV').toUpperCase(),\n"
            "    id: id || '',\n"
            "    textContent: '',\n"
            "    value: '',\n"
            "    checked: false,\n"
            "    indeterminate: false,\n"
            "    style: {},\n"
            "    attrs: {},\n"
            "    children: [],\n"
            "    listeners: {},\n"
            "    classList: { _s: new Set(), toggle(c, v){ if(v===undefined){this._s.has(c)?this._s.delete(c):this._s.add(c);} else {v?this._s.add(c):this._s.delete(c);} }, add(c){this._s.add(c);}, remove(c){this._s.delete(c);}, contains(c){return this._s.has(c);} },\n"
            "    setAttribute(k, v) { this.attrs[k] = String(v); },\n"
            "    getAttribute(k) { return this.attrs[k] !== undefined ? this.attrs[k] : null; },\n"
            "    appendChild(c) { this.children.push(c); return c; },\n"
            "    replaceChildren(...args) { this.children = args; },\n"
            "    addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },\n"
            "    querySelectorAll() { return []; },\n"
            "    getBoundingClientRect() { return {left:0,top:0,right:100,bottom:30,width:100,height:30}; }\n"
            "  };\n"
            "  return el;\n"
            "}\n"
            "const body = makeEl('body', 'body');\n"
            "global.document = {\n"
            "  body: body,\n"
            "  documentElement: makeEl('html', 'html'),\n"
            "  getElementById(id) { if (!elements.has(id)) elements.set(id, makeEl('div', id)); return elements.get(id); },\n"
            "  createElement(tag) { return makeEl(tag, ''); },\n"
            "  createElementNS(_ns, tag) { return makeEl(tag, ''); },\n"
            "  querySelectorAll() { return []; },\n"
            "  addEventListener() {}\n"
            "};\n"
            "global.window = global;\n"
            "global.window.location = {search: '', href: 'http://localhost:8088/', hostname: ''};\n"
            "global.localStorage = { _m: {}, getItem(k){return this._m[k]||null;}, setItem(k,v){this._m[k]=String(v);}, removeItem(k){delete this._m[k];} };\n"
            f"const dogfoodPayload = {json.dumps(dogfood)};\n"
            f"{embedded_script}\n"
            "(async () => {\n"
            "  await new Promise(r => setTimeout(r, 25));\n"
            "  assert.ok(window.datasetTreeStore, 'datasetTreeStore should initialize');\n"
            "  const opened = window.toggleDatasetSidebar(true);\n"
            "  assert.strictEqual(opened, true);\n"
            "  assert.strictEqual(document.body.getAttribute('data-panel-dataset-sidebar'), 'on');\n"
            "  await window.toggleDogfoodDataset(true, dogfoodPayload);\n"
            "  assert.ok(window.SpatialGraphAdapter.getNode(dogfoodPayload.repo_root_ids.brain), 'brain root should merge when dogfood enabled');\n"
            "  assert.ok(window.SpatialGraphAdapter.getNode(dogfoodPayload.repo_root_ids.meshworks), 'meshworks root should merge when dogfood enabled');\n"
            "  const brainTid = 'ds:' + dogfoodPayload.dataset_id + ':repo:brain';\n"
            "  window.datasetTreeStore.toggleTreeNode(brainTid, false);\n"
            "  assert.strictEqual(window.datasetTreeStore.getTriState(brainTid), 'false');\n"
            "  assert.strictEqual(window.datasetTreeStore.getTriState('ds:' + dogfoodPayload.dataset_id), 'mixed');\n"
            "  assert.ok(!window.SpatialGraphAdapter.getNode(dogfoodPayload.repo_root_ids.brain), 'unchecking brain branch must filter brain nodes live');\n"
            "  assert.ok(window.SpatialGraphAdapter.getNode(dogfoodPayload.repo_root_ids.opscryer), 'opscryer nodes must remain visible');\n"
            "  const treeEl = document.getElementById('dataset-tree-list');\n"
            "  assert.ok(treeEl.children.length > 0, 'sidebar tree rows must render');\n"
            "  const dsRow = treeEl.children.find(r => r.getAttribute('data-tree-id') === 'ds:' + dogfoodPayload.dataset_id);\n"
            "  assert.ok(dsRow, 'dogfood dataset row should render in sidebar');\n"
            "  assert.strictEqual(dsRow.getAttribute('role'), 'treeitem');\n"
            "  assert.strictEqual(dsRow.getAttribute('aria-checked'), 'mixed');\n"
            "  dsRow.listeners.keydown[0]({key: ' ', preventDefault(){}});\n"
            "  assert.strictEqual(window.datasetTreeStore.getTriState('ds:' + dogfoodPayload.dataset_id), 'true');\n"
            "  assert.ok(window.SpatialGraphAdapter.getNode(dogfoodPayload.repo_root_ids.brain), 're-checking via Space key must restore brain nodes');\n"
            "  console.log(JSON.stringify({ok: true, tree_rows: treeEl.children.length}));\n"
            "})().catch(err => { console.error(err); process.exit(1); });\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as tf:
            tf.write(harness)
            temp_path = Path(tf.name)
        try:
            proc = subprocess.run(["node", str(temp_path)], capture_output=True, text=True, timeout=25, check=False)
        finally:
            temp_path.unlink(missing_ok=True)
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}\nstdout={proc.stdout}")
        res = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertTrue(res["ok"])
        self.assertGreater(res["tree_rows"], 3)


if __name__ == "__main__":
    unittest.main()
