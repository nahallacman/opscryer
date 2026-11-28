# SPDX-License-Identifier: Apache-2.0
"""Tests for the Standalone 2D World Map split from the 2.5D/3D spatial engine."""

from __future__ import annotations

import ast
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import urlopen

OPSCRYER_ROOT = Path(__file__).resolve().parents[1]
if str(OPSCRYER_ROOT) not in sys.path:
    sys.path.insert(0, str(OPSCRYER_ROOT))

import opscryer_browser
from world_map_2d_standalone import (
    WORLD_MAP_2D_MODES,
    WORLD_MAP_2D_SCHEMA_VERSION,
    build_2d_world_map_layout,
    render_2d_world_map_html,
)


_SAMPLE_CATALOG = {
    "nodes": [
        {"id": "root-org", "label": "Enterprise Root", "kind": "company_root", "domain": "org", "status": "nominal"},
        {"id": "svc-api", "label": "API Gateway", "kind": "service", "domain": "platform", "status": "nominal"},
        {"id": "db-pg", "label": "Orders DB", "kind": "database", "domain": "data", "status": "warning"},
        {"id": "node-gpu", "label": "GPU Worker 01", "kind": "gpu", "domain": "compute", "status": "critical"},
    ],
    "edges": [
        {"source": "root-org", "target": "svc-api", "relation": "owns"},
        {"source": "svc-api", "target": "db-pg", "relation": "depends_on"},
        {"source": "svc-api", "target": "node-gpu", "relation": "schedules_on"},
    ],
}


class Standalone2DWorldMapTests(unittest.TestCase):
    def test_decoupled_from_world_map_engine(self) -> None:
        src = (OPSCRYER_ROOT / "world_map_2d_standalone.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertNotIn("world_map_engine", imported)

    def test_all_three_2d_layout_modes_and_pure_orthographic_coordinates(self) -> None:
        for mode in WORLD_MAP_2D_MODES:
            layout = build_2d_world_map_layout(_SAMPLE_CATALOG, mode=mode, scope="ops")
            self.assertEqual(layout["schema_version"], WORLD_MAP_2D_SCHEMA_VERSION)
            self.assertEqual(layout["engine"], "standalone_2d_orthographic")
            self.assertEqual(layout["mode"], mode)
            self.assertEqual(layout["summary"]["node_count"], 4)
            self.assertEqual(layout["summary"]["edge_count"], 3)
            self.assertGreaterEqual(layout["summary"]["region_count"], 1)
            self.assertEqual(layout["spatial_3d_route"], "/world-map")
            for item in layout["nodes"]:
                self.assertIn("x", item)
                self.assertIn("y", item)
                self.assertNotIn("z", item)

        with self.assertRaises(ValueError):
            build_2d_world_map_layout(_SAMPLE_CATALOG, mode="iso_25d")

    def test_rendered_html_zero_xss_accessibility_and_dark_mode_tokens(self) -> None:
        evil_catalog = {
            "nodes": [
                {
                    "id": "n-xss",
                    "label": "</script><img src=x onerror=alert(1)>",
                    "kind": "service",
                    "domain": "sec",
                    "status": "nominal",
                }
            ],
            "edges": [],
        }
        html = render_2d_world_map_html(catalog=evil_catalog)
        self.assertIn('<meta name="color-scheme" content="light dark">', html)
        self.assertIn("color-scheme: light dark;", html)
        self.assertIn("light-dark(", html)
        self.assertIn('href="/world-map"', html)
        self.assertIn('role="img"', html)
        self.assertIn("<caption>Accessible tabular view of 2D World Map nodes</caption>", html)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("document.write", html)
        self.assertNotIn("</script><img", html)

    def test_http_routes_and_mls_fail_closed_filtering(self) -> None:
        import tempfile

        mls_catalog = {
            "schema_version": "1.0-separable-spatial-graph-contract",
            "source": "standalone_2d_test_fixture",
            "root_node_id": "pub-svc",
            "generated_at": "2026-11-26T20:00:00Z",
            "nodes": [
                {
                    "id": "pub-svc",
                    "label": "Public Service",
                    "kind": "company_root",
                    "domain": "company_org",
                    "section": "section_1_company",
                    "level_index": 0,
                    "summary": "Public root service",
                    "primary_url": "https://opscryer.example.test/",
                    "drilldown_children": ["sec-vault"],
                },
                {
                    "id": "sec-vault",
                    "label": "Restricted Secret Node",
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "section_3_resources",
                    "level_index": 1,
                    "summary": "Restricted enclave vault",
                    "primary_url": "https://enclave.example.test/vault",
                    "drilldown_children": [],
                    "mls": {"classification_rank": 30, "compartments": ["project:blackbox"], "visibility": "OPAQUE"},
                },
            ],
            "edges": [{"source": "pub-svc", "target": "sec-vault", "relation": "depends_on"}],
        }

        with tempfile.TemporaryDirectory() as tmp:
            graph_path = Path(tmp) / "catalog_2d.json"
            with open(graph_path, "w", encoding="utf-8", newline="") as fh:
                fh.write(json.dumps(mls_catalog, indent=2))

            env_patch = {
                opscryer_browser.EXTERNAL_GRAPH_FILE_ENV: str(graph_path),
                "OPSCRYER_BRAIN_API_URL": "",
                "OPSCRYER_ECOSYSTEM_OVERLAY": "0",
                "OPSCRYER_VIEWER_RANK": "10",
                "OPSCRYER_VIEWER_COMPARTMENTS": "",
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                handler_cls = opscryer_browser._build_frontend_handler("")
                server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
                port = server.server_address[1]
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with urlopen(f"http://127.0.0.1:{port}/map-2d", timeout=5) as resp:
                        self.assertEqual(resp.status, 200)
                        body = resp.read().decode("utf-8")
                        self.assertIn("Standalone 2D World Map", body)
                        self.assertIn("/world-map", body)
                        self.assertNotIn("Restricted Secret Node", body)
                        self.assertIn("Public Service", body)

                    with urlopen(f"http://127.0.0.1:{port}/api/v1/world-map-2d/layout?mode=layer_bands", timeout=5) as resp:
                        self.assertEqual(resp.status, 200)
                        payload = json.loads(resp.read().decode("utf-8"))
                        node_ids = [n["id"] for n in payload["nodes"]]
                        self.assertEqual(node_ids, ["pub-svc"])
                        self.assertEqual(payload["edges"], [])
                        self.assertEqual(payload["mode"], "layer_bands")

                    with self.assertRaises(HTTPError) as ctx:
                        urlopen(f"http://127.0.0.1:{port}/api/v1/world-map-2d/layout?mode=bogus", timeout=5)
                    self.assertEqual(ctx.exception.code, 400)
                finally:
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    unittest.main()
