# SPDX-License-Identifier: Apache-2.0
"""Verify external Knowledge Graph isolation, tool-repo fail-closed guards, and HTTP hot-reload."""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import opscryer_backend  # noqa: E402
import opscryer_browser  # noqa: E402


class _LoopbackHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _build_external_catalog(root_label: str, child_id: str, child_label: str) -> dict:
    nodes = [
        {
            "id": "ext-root",
            "label": root_label,
            "kind": "company_root",
            "domain": "company_org",
            "summary": "External mounted Knowledge Graph root node.",
            "primary_url": "https://portal.example.invalid/root",
            "drilldown_children": [child_id],
        },
        {
            "id": child_id,
            "label": child_label,
            "kind": "engineering_project",
            "domain": "deployments_k8s",
            "summary": "External service node stored outside OpsCryer repo.",
            "primary_url": "https://portal.example.invalid/service",
            "drilldown_children": [],
        },
    ]
    edges = [{"source": "ext-root", "target": child_id, "relation": "contains"}]
    return {
        "schema_version": opscryer_backend.CONTRACT_VERSION,
        "piece_role": "EXTERNAL_MOUNTED_KNOWLEDGE_GRAPH",
        "backend_coupled": False,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "rts_currencies": [
            {
                "currency_id": "nodes",
                "icon": "N",
                "label": "External Nodes",
                "display_value": f"{len(nodes)} External",
                "supply_kind": "supply_cap",
                "hex_color": "#22C55E",
                "dropdown_items": [],
            }
        ],
    }


def _http_get_json(url: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


class ExternalGraphIsolationTests(unittest.TestCase):
    """Ensure OpsCryer mounts external graph files cleanly and blocks in-repo graph mutations/paths."""

    def test_in_repo_graph_paths_fail_closed(self) -> None:
        in_repo_sample = REPO_ROOT / "sample-graph-data.json"
        nested_in_repo = REPO_ROOT / "data" / "company-knowledge-graph.json"

        for candidate in (in_repo_sample, nested_in_repo):
            with self.subTest(candidate=candidate):
                with patch.dict(os.environ, {"OPSCRYER_GRAPH_FILE": str(candidate)}):
                    with self.assertRaises(ValueError) as browser_err:
                        opscryer_browser.resolve_external_graph_path()
                    self.assertIn("TOOL_REPO_GRAPH_PATH_BLOCKED", str(browser_err.exception))

                    with self.assertRaises(ValueError) as backend_err:
                        opscryer_backend.KnowledgeGraphBackendEngine()
                    self.assertIn("TOOL_REPO_GRAPH_PATH_BLOCKED", str(backend_err.exception))

        with patch("sys.stderr"):
            with self.assertRaises(SystemExit) as cli_exit:
                opscryer_browser.main(["--graph-file", str(in_repo_sample), "--demo-json"])
            self.assertNotEqual(cli_exit.exception.code, 0)

    def test_external_graph_file_serves_and_hot_reloads_over_http(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ext_path = Path(tmp) / "company-knowledge-graph.json"
            doc_v1 = _build_external_catalog("External Graph V1", "ext-svc-v1", "Billing API V1")
            ext_path.write_text(json.dumps(doc_v1), encoding="utf-8", newline="\n")

            env_updates = {
                "OPSCRYER_GRAPH_FILE": str(ext_path),
                "OPSCRYER_ECOSYSTEM_OVERLAY": "0",
                "OPSCRYER_OFFLINE_ONLY": "1",
            }
            with patch.dict(os.environ, env_updates):
                engine = opscryer_backend.KnowledgeGraphBackendEngine()
                self.assertEqual(engine.catalog()["node_count"], 2)
                self.assertIn("ext-svc-v1", {n["id"] for n in engine.catalog()["nodes"]})

                handler_cls = opscryer_browser._build_frontend_handler()
                server = _LoopbackHTTPServer(("127.0.0.1", 0), handler_cls)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    base = f"http://127.0.0.1:{server.server_address[1]}"

                    status, cat1 = _http_get_json(f"{base}/api/v1/graph/catalog")
                    self.assertEqual(status, 200)
                    node_ids_v1 = {n["id"] for n in cat1["nodes"]}
                    self.assertEqual(node_ids_v1, {"ext-root", "ext-svc-v1"})
                    self.assertNotIn("root-company", node_ids_v1)

                    status_dd, dd1 = _http_get_json(f"{base}/api/v1/graph/drilldown?node_id=ext-root")
                    self.assertEqual(status_dd, 200)
                    self.assertEqual(dd1["node"]["label"], "External Graph V1")
                    self.assertEqual([c["id"] for c in dd1["children"]], ["ext-svc-v1"])

                    # Modify external file and advance mtime_ns deterministically to verify live hot-reload.
                    prev_mtime_ns = ext_path.stat().st_mtime_ns
                    doc_v2 = _build_external_catalog("External Graph V2", "ext-svc-v2", "Billing API V2")
                    ext_path.write_text(json.dumps(doc_v2), encoding="utf-8", newline="\n")
                    next_ns = max(prev_mtime_ns + 10_000_000, ext_path.stat().st_mtime_ns + 10_000_000)
                    os.utime(ext_path, ns=(next_ns, next_ns))

                    status2, cat2 = _http_get_json(f"{base}/api/v1/graph/catalog")
                    self.assertEqual(status2, 200)
                    node_ids_v2 = {n["id"] for n in cat2["nodes"]}
                    self.assertEqual(node_ids_v2, {"ext-root", "ext-svc-v2"})

                    status_dd2, dd2 = _http_get_json(f"{base}/api/v1/graph/drilldown?node_id=ext-root")
                    self.assertEqual(status_dd2, 200)
                    self.assertEqual(dd2["node"]["label"], "External Graph V2")
                    self.assertEqual([c["id"] for c in dd2["children"]], ["ext-svc-v2"])
                finally:
                    server.shutdown()
                    server.server_close()

    def test_container_and_gitignore_external_mount_guards(self) -> None:
        dockerfile_text = (REPO_ROOT / "Dockerfile.opscryer").read_text(encoding="utf-8")
        self.assertIn("RUN mkdir -p /data", dockerfile_text)
        self.assertIn("OPSCRYER_GRAPH_FILE=/data/knowledge-graph.json", dockerfile_text)
        self.assertIn("COPY *.py ./", dockerfile_text)

        gitignore_text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in ("*company*graph*.json", "curated-graph.json", "knowledge-graph.json"):
            self.assertIn(pattern, gitignore_text)


if __name__ == "__main__":
    unittest.main()
