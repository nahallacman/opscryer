# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit, HTTP API, security, and Node.js canvas engine tests for the 2D / 2.5D / 3D Spatial Map."""

from __future__ import annotations

import http.client
import json
import math
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import opscryer_browser as browser
from scale_benchmark import generate_synthetic_enterprise_graph
from unit_archetypes import (
    BUILTIN_UNIT_TYPES,
    delete_custom_unit_type,
    list_unit_types,
    reset_custom_unit_types,
    resolve_node_unit_type,
    sanitize_custom_svg,
    upsert_custom_unit_type,
)
from world_map_engine import (
    WORLD_MAP_MODES,
    WORLD_MAP_SCHEMA_VERSION,
    build_world_map_engine_js,
    build_world_map_layout,
    render_world_map_html,
)


class UnitArchetypesTests(unittest.TestCase):
    """Tests for dynamic Unit Types, resolution priority, and SVG XSS sanitization."""

    def tearDown(self) -> None:
        reset_custom_unit_types()

    def test_builtin_archetypes_present_and_resolution_deterministic(self) -> None:
        self.assertGreaterEqual(len(BUILTIN_UNIT_TYPES), 10)
        ut = list_unit_types()
        self.assertEqual(resolve_node_unit_type({"id": "root-company", "kind": "company_root"}, ut), "citadel_root")
        self.assertEqual(resolve_node_unit_type({"id": "swarm-nanobot", "kind": "ai_agent_unit"}, ut), "ai_construct")
        self.assertEqual(
            resolve_node_unit_type({"id": "n-1", "kind": "entity", "resource_kind": "Pod"}, ut),
            "k8s_pod",
        )
        # Explicit node override takes top precedence
        self.assertEqual(
            resolve_node_unit_type(
                {"id": "n-1", "kind": "entity", "resource_kind": "Pod"},
                ut,
                node_overrides={"n-1": "compute_reactor"},
            ),
            "compute_reactor",
        )

    def test_custom_unit_type_lifecycle_and_safe_svg_primitives(self) -> None:
        safe_svg = (
            '<svg viewBox="0 0 64 64" width="64" height="64">'
            '<g><path d="M32 6 L56 52 L8 52 Z" fill="#38BDF8" stroke="#F8FAFC" stroke-width="2"/>'
            '<circle cx="32" cy="36" r="6" fill="gold"/></g></svg>'
        )
        parsed = sanitize_custom_svg(safe_svg)
        self.assertEqual(parsed["view_box"], [0.0, 0.0, 64.0, 64.0])
        self.assertEqual(parsed["element_count"], 2)
        self.assertEqual(parsed["primitives"][0]["tag"], "path")
        self.assertEqual(parsed["primitives"][1]["tag"], "circle")

        saved = upsert_custom_unit_type(
            {
                "type_id": "custom_striker",
                "display_name": "Striker Beacon",
                "color_primary": "#38bdf8",
                "color_accent": "#f59e0b",
                "formation": "orbital",
                "z_elevation": 70,
                "match_kinds": ["custom_sensor"],
                "custom_svg": safe_svg,
            }
        )
        self.assertFalse(saved["builtin"])
        self.assertEqual(saved["color_primary"], "#38BDF8")
        self.assertIn("svg_spec", saved)

        all_types = list_unit_types()
        self.assertIn("custom_striker", all_types)
        self.assertEqual(
            resolve_node_unit_type({"id": "x-1", "kind": "custom_sensor"}, all_types),
            "custom_striker",
        )
        self.assertTrue(delete_custom_unit_type("custom_striker"))
        self.assertNotIn("custom_striker", list_unit_types())

    def test_svg_sanitizer_rejects_xss_and_entity_injection(self) -> None:
        malicious_payloads = [
            '<svg><script>alert(1)</script><circle cx="10" cy="10" r="5"/></svg>',
            '<svg><circle cx="10" cy="10" r="5" onload="alert(1)"/></svg>',
            '<svg><foreignObject width="64" height="64"><div>x</div></foreignObject></svg>',
            '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><circle cx="10" cy="10" r="5"/></svg>',
            '<svg><a href="javascript:alert(1)"><circle cx="10" cy="10" r="5"/></a></svg>',
            '<svg><rect x="0" y="0" width="10" height="10" fill="url(#bad)"/></svg>',
            '<svg><rect x="0" y="0" width="10" height="10" style="fill:red"/></svg>',
            '<svg><image href="data:image/png;base64,AAA"/></svg>',
        ]
        for bad_svg in malicious_payloads:
            with self.subTest(bad_svg=bad_svg[:48]):
                with self.assertRaises(ValueError):
                    sanitize_custom_svg(bad_svg)


class WorldMapEngineLayoutTests(unittest.TestCase):
    """Tests for 2.5D/3D World Map layout clustering, scale budget, and modern dialog/CVA HTML."""

    def tearDown(self) -> None:
        reset_custom_unit_types()

    def test_all_three_layout_modes_and_1500_node_performance_budget(self) -> None:
        graph_1500 = generate_synthetic_enterprise_graph(1500)
        for mode in WORLD_MAP_MODES:
            with self.subTest(mode=mode):
                t0 = time.perf_counter()
                layout = build_world_map_layout(graph_1500, mode=mode, scope="test-1500")
                elapsed_s = time.perf_counter() - t0
                self.assertEqual(layout["schema_version"], WORLD_MAP_SCHEMA_VERSION)
                self.assertEqual(layout["mode"], mode)
                self.assertEqual(layout["node_count"], 1500)
                self.assertGreater(layout["edge_count"], 0)
                self.assertLess(elapsed_s, 1.5)
                self.assertTrue(layout["territories"])
                for node in layout["nodes"]:
                    self.assertTrue(math.isfinite(node["wx"]))
                    self.assertTrue(math.isfinite(node["wy"]))
                    self.assertTrue(math.isfinite(node["wz"]))
                for edge in layout["edges"][:50]:
                    self.assertIsInstance(edge, list)
                    self.assertGreaterEqual(edge[0], 0)
                    self.assertLess(edge[1], 1500)

    def test_world_map_html_and_inline_browser_follow_modern_web_guidance(self) -> None:
        wm_html = render_world_map_html()
        self.assertIn('<dialog id="wm-unit-forge-dialog" closedby="any"', wm_html)
        self.assertNotIn('role="dialog"', wm_html)
        self.assertNotIn('aria-modal', wm_html)
        self.assertIn("dialog[open]#wm-unit-forge-dialog", wm_html)
        self.assertIn("content-visibility: auto", wm_html)
        self.assertIn("contentvisibilityautostatechange", wm_html)

        main_html = browser.render_standalone_browser_html()
        self.assertIn('id="inline-world-map-stage"', main_html)
        self.assertIn('id="inline-wm-minimap"', main_html)
        self.assertIn('id="wm-inline-forge-dialog"', main_html)
        self.assertIn("content-visibility: auto", main_html)
        self.assertNotIn('role="dialog"', main_html)
        self.assertNotIn('aria-modal', main_html)

    def test_builtin_unit_types_have_vector_svg_specs_and_professional_labels(self) -> None:
        forbidden = ("war" + "craft", "wc3", "command citadel", "engineering garrison", "warp nexus", "unit forge")
        ut = list_unit_types()
        for type_id, spec in ut.items():
            if not spec.get("builtin"):
                continue
            svg_spec = spec.get("svg_spec") or {}
            primitives = svg_spec.get("primitives") or []
            self.assertGreaterEqual(len(primitives), 2, msg=f"{type_id} missing multi-primitive svg_spec")
            self.assertEqual(svg_spec.get("view_box"), [0.0, 0.0, 64.0, 64.0], msg=type_id)
            disp = str(spec.get("display_name") or "").lower()
            for term in forbidden:
                self.assertNotIn(term, disp, msg=f"{type_id} display_name leaked {term!r}")
        self.assertEqual(resolve_node_unit_type({"id": "sys-root", "unit_type": "system_root"}, ut), "citadel_root")
        self.assertEqual(resolve_node_unit_type({"id": "team-1", "unit_type": "engineering_team"}, ut), "guild_team")

    def test_projection_modes_2d_25d_3d_rendered_without_fantasy_lore(self) -> None:
        wm_html = render_world_map_html()
        main_html = browser.render_standalone_browser_html()
        for label, html in (("world_map", wm_html), ("standalone_browser", main_html)):
            with self.subTest(surface=label):
                self.assertIn("2D Schematic", html)
                self.assertIn("2.5D Elevation", html)
                self.assertIn("3D Volumetric", html)
                self.assertIn("Node Studio", html)
                self.assertIn('popover="hint"', html)
                lowered = html.lower()
                for forbidden in (
                    "war" + "craft",
                    "wc3",
                    "command citadel",
                    "engineering garrison",
                    "k8s warp nexus",
                    "unit forge",
                    "terran command",
                    "protoss nexus",
                    "civ hex strategy",
                ):
                    self.assertNotIn(forbidden, lowered, msg=f"{label} still contains {forbidden!r}")
        self.assertIn('id="wm-proj-toolbar"', wm_html)
        self.assertIn('id="wm-proj-relevance"', wm_html)
        self.assertIn('id="nav-quick-proj-bar"', main_html)
        self.assertIn('id="inline-wm-proj-toolbar"', main_html)
        self.assertIn('id="inline-wm-proj-relevance"', main_html)


class WorldMapHTTPTests(unittest.TestCase):
    """Real loopback HTTP tests for /world-map and /api/v1/world-map/* endpoints."""

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

    def tearDown(self) -> None:
        reset_custom_unit_types()

    def _request(self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, resp.getheader("Content-Type"), raw
        finally:
            conn.close()

    def test_world_map_routes_get_post_and_security(self) -> None:
        status, ctype, raw = self._request("GET", "/world-map")
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "text/html; charset=utf-8")
        self.assertIn(b"OpsCryer Spatial Topology", raw)

        status_q, _, _ = self._request("GET", "/world-map?unexpected=1")
        self.assertEqual(status_q, 400)

        st_l, _, raw_l = self._request("GET", "/api/v1/world-map/layout?mode=cloud_3d&nodes=200")
        self.assertEqual(st_l, 200)
        lay = json.loads(raw_l)
        self.assertEqual(lay["mode"], "cloud_3d")
        self.assertEqual(lay["node_count"], 200)

        st_bad, _, _ = self._request("GET", "/api/v1/world-map/layout?mode=invalid_mode")
        self.assertEqual(st_bad, 400)

        st_ut, _, raw_ut = self._request("GET", "/api/v1/world-map/unit-types")
        self.assertEqual(st_ut, 200)
        self.assertGreaterEqual(len(json.loads(raw_ut)), 10)

        good_payload = json.dumps(
            {
                "type_id": "custom_bastion",
                "display_name": "Custom Bastion",
                "color_primary": "#22C55E",
                "color_accent": "#F59E0B",
                "custom_svg": '<svg viewBox="0 0 64 64"><rect x="12" y="12" width="40" height="40" fill="#22C55E"/></svg>',
            }
        ).encode("utf-8")

        # Cross-origin POST rejected by CSRF guard
        st_csrf, _, _ = self._request(
            "POST",
            "/api/v1/world-map/unit-types",
            body=good_payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(good_payload)),
                "Origin": "https://evil.example.com",
            },
        )
        self.assertEqual(st_csrf, 403)

        # Malicious SVG rejected with 400
        xss_payload = json.dumps(
            {
                "type_id": "bad_svg_unit",
                "display_name": "Bad Unit",
                "custom_svg": '<svg><script>alert(1)</script><circle cx="8" cy="8" r="4"/></svg>',
            }
        ).encode("utf-8")
        st_xss, _, _ = self._request(
            "POST",
            "/api/v1/world-map/unit-types",
            body=xss_payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(xss_payload)),
                "Sec-Fetch-Site": "same-origin",
            },
        )
        self.assertEqual(st_xss, 400)

        # Valid same-origin POST registers custom type and reflects in subsequent GET
        st_ok, _, raw_ok = self._request(
            "POST",
            "/api/v1/world-map/unit-types",
            body=good_payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(good_payload)),
                "Sec-Fetch-Site": "same-origin",
            },
        )
        self.assertEqual(st_ok, 200)
        self.assertTrue(json.loads(raw_ok)["ok"])
        _, _, raw_after = self._request("GET", "/api/v1/world-map/unit-types")
        self.assertIn("custom_bastion", json.loads(raw_after))


class WorldMapNodeEngineTests(unittest.TestCase):
    """Execute the World Map JS engine directly in Node.js to verify 2.5D frustum & RTS controls."""

    def test_nodejs_perspective_trapezoid_and_rts_selection_semantics(self) -> None:
        engine_js = build_world_map_engine_js()
        test_harness = r"""
const assert = require('assert');
const global = globalThis;
const window = globalThis;
window.localStorage = { getItem: () => null, setItem: () => {} };
""" + engine_js + r"""
const api = window.OpsCryerWorldMap;
assert.ok(api, 'OpsCryerWorldMap global attached');

const cam = {targetX: 0, targetY: 0, targetZ: 0, distance: 900, pitchDeg: 52, yawRad: 0, fovDeg: 44};
const pNear = api.projectPoint(0, -100, 0, cam, 1000, 600);
const pFar = api.projectPoint(0, 100, 0, cam, 1000, 600);
assert.strictEqual(pNear.behind, false);
assert.strictEqual(pFar.behind, false);
assert.ok(pNear.scale > pFar.scale, '2.5D foreshortening scale should decrease with depth');

const trap = api.computeCameraTrapezoid(cam, 1000, 600, 0);
assert.strictEqual(trap.length, 4);
trap.forEach(pt => {
  assert.ok(Number.isFinite(pt.wx) && Number.isFinite(pt.wy));
});
const topWidth = Math.hypot(trap[1].wx - trap[0].wx, trap[1].wy - trap[0].wy);
const botWidth = Math.hypot(trap[2].wx - trap[3].wx, trap[2].wy - trap[3].wy);
assert.ok(topWidth > botWidth, 'Tilted 2.5D camera frustum top ground edge must exceed bottom edge (trapezoid)');

const catalog = {
  nodes: [
    {id: 'root-company', label: 'System Root', kind: 'company_root', drilldown_children: ['t1', 't2', 'a1']},
    {id: 't1', label: 'Team Alpha', kind: 'company_team', drilldown_children: []},
    {id: 't2', label: 'Team Beta', kind: 'company_team', drilldown_children: []},
    {id: 'a1', label: 'Bot One', kind: 'ai_agent_unit', drilldown_children: []}
  ],
  edges: []
};
const ctrl = api.createWorldMapController({ids: {}, getCurrentCatalog: () => catalog});
ctrl.setCatalog(catalog, false);
const st = ctrl.getState();
const rootIdx = st.idToIndex.get('root-company');
const t1Idx = st.idToIndex.get('t1');
const t2Idx = st.idToIndex.get('t2');
const a1Idx = st.idToIndex.get('a1');

/* Place all units near projected center so viewport selection tests are deterministic */
st.spatialDirty = false;
st.drawOrder = [rootIdx, t1Idx, t2Idx, a1Idx];
st.sx[rootIdx] = 500; st.sy[rootIdx] = 300;
st.sx[t1Idx] = 200; st.sy[t1Idx] = 200;
st.sx[t2Idx] = 240; st.sy[t2Idx] = 200;
st.sx[a1Idx] = 350; st.sy[a1Idx] = 300;
/* Force t2 off-screen in drawOrder to distinguish Ctrl+Click (visible) vs Alt+Click (global) */
st.drawOrder = [rootIdx, t1Idx, a1Idx];

ctrl.selectClick(t1Idx, {});
assert.deepStrictEqual(st.selectedIds, ['t1']);

/* Shift+Click toggles unit membership */
ctrl.selectClick(a1Idx, {shiftKey: true});
assert.deepStrictEqual(new Set(st.selectedIds), new Set(['t1', 'a1']));
ctrl.selectClick(a1Idx, {shiftKey: true});
assert.deepStrictEqual(st.selectedIds, ['t1']);

/* Alt+Click selects all same unit_type across entire map (t1 + t2) */
ctrl.selectClick(t1Idx, {altKey: true});
assert.deepStrictEqual(new Set(st.selectedIds), new Set(['t1', 't2']));

/* Ctrl+Click selects visible same unit_type in drawOrder only (t1) */
ctrl.selectClick(t1Idx, {ctrlKey: true});
assert.deepStrictEqual(st.selectedIds, ['t1']);

/* Marquee rectangle selects enclosed visible units, highest priority unit_type first */
ctrl.selectMarquee(0, 0, 1000, 600, {});
assert.deepStrictEqual(new Set(st.selectedIds), new Set(['root-company', 't1', 'a1']));
const prevSub = st.activeSubgroupType;
const nextSub = ctrl.cycleSubgroup(false);
assert.ok(nextSub && nextSub !== prevSub, 'Tab cycles active subgroup');
const backSub = ctrl.cycleSubgroup(true);
assert.strictEqual(backSub, prevSub, 'Shift+Tab cycles subgroup back');

/* RTS Control groups: Ctrl+1 save, clear selection, 1 recall, Shift+2 merge, Alt+3 steal */
ctrl.handleControlGroupKey(1, {ctrlKey: true});
ctrl.selectClick(-1, {});
assert.deepStrictEqual(st.selectedIds, []);
ctrl.handleControlGroupKey(1, {});
assert.deepStrictEqual(new Set(st.selectedIds), new Set(['root-company', 't1', 'a1']));

ctrl.selectClick(t2Idx, {});
ctrl.handleControlGroupKey(2, {ctrlKey: true});
ctrl.selectClick(a1Idx, {});
ctrl.handleControlGroupKey(2, {shiftKey: true});
assert.deepStrictEqual(new Set(st.controlGroups[2]), new Set(['t2', 'a1']));

/* Alt+3 assigns selection exclusively to group 3, removing stolen units from groups 1 and 2 */
ctrl.handleControlGroupKey(3, {altKey: true});
assert.deepStrictEqual(st.controlGroups[3], ['a1']);
assert.strictEqual(st.controlGroups[1].includes('a1'), false);
assert.strictEqual(st.controlGroups[2].includes('a1'), false);

/* Double-tap control group 1 recenters camera on group units */
st.camera.goalX = -9999; st.camera.goalY = -9999;
ctrl.handleControlGroupKey(1, {});
ctrl.handleControlGroupKey(1, {});
assert.notStrictEqual(st.camera.goalX, -9999);

/* Verify 2D / 2.5D / 3D projections share dataset & transform Z elevation smoothly */
assert.strictEqual(api.normalizeProjectionId('top_2d'), 'flat_2d');
assert.strictEqual(api.normalizeProjectionId('2d'), 'flat_2d');
assert.strictEqual(api.normalizeProjectionId('wc3_25d'), 'iso_25d');
assert.strictEqual(api.normalizeProjectionId('2.5d'), 'iso_25d');
assert.strictEqual(api.normalizeProjectionId('cloud_3d'), 'orbit_3d');
assert.strictEqual(api.normalizeProjectionId('3d'), 'orbit_3d');

const preCount = st.nodes.length;
const preSel = st.selectedIds.slice();
ctrl.setProjection('flat_2d');
assert.strictEqual(st.projectionMode, 'flat_2d');
assert.strictEqual(st.camera.goalPitch, 89.2);
for (let i = 0; i < st.nodes.length; i++) {
  assert.strictEqual(st.wz[i], 0, '2D Schematic projection flattens Z plane to 0');
}
ctrl.setProjection('iso_25d');
assert.strictEqual(st.projectionMode, 'iso_25d');
assert.strictEqual(st.camera.goalPitch, 54);
assert.ok(st.wz[rootIdx] > 0, '2.5D Elevation restores architectural tier height');

ctrl.setProjection('orbit_3d');
assert.strictEqual(st.projectionMode, 'orbit_3d');
assert.strictEqual(st.camera.goalPitch, 34);
assert.strictEqual(st.nodes.length, preCount, 'Projection swap must preserve same loaded dataset');
assert.deepStrictEqual(st.selectedIds, preSel, 'Projection swap must preserve active selection');

assert.throws(() => api.sanitizeClientSvg('<svg><script>alert(1)</script></svg>'));
console.log('NODE_WORLD_MAP_OK');
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "world_map_harness.js"
            js_file.write_text(test_harness, encoding="utf-8", newline="\n")
            proc = subprocess.run(
                ["node", str(js_file)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
        self.assertIn("NODE_WORLD_MAP_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
