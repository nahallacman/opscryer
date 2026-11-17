# SPDX-License-Identifier: Apache-2.0
"""Tests for bridge/opscryer_bridge.py spatial contract and catalog helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest import mock
import urllib.request

from bridge.opscryer_bridge import (
    CONTRACT_VERSION,
    build_spatial_contract_from_ecosystem,
    build_spatial_graph_catalog,
    overlay_ecosystem_onto_catalog,
)
from opscryer_backend import validate_spatial_graph_contract
import opscryer_browser as browser


class TestOpsCryerBridge(unittest.TestCase):
    def test_build_spatial_graph_catalog_backwards_compatible(self) -> None:
        catalog = build_spatial_graph_catalog(
            tasks=[{"id": "t1"}],
            mrs=[{"iid": 42}],
            projects=[{"name": "demo"}],
        )
        self.assertEqual(catalog["tasks"], [{"id": "t1"}])
        self.assertEqual(catalog["merge_requests"], [{"iid": 42}])
        self.assertEqual(catalog["projects"], [{"name": "demo"}])
        self.assertIn("generated_at", catalog)

    def test_build_spatial_contract_from_ecosystem_validates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest_path = root / "skills-manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "skills": [
                            {
                                "id": "deploy-k8s",
                                "name": "deploy-k8s",
                                "description": "Deploy workloads",
                                "source": "personal",
                                "category": "platform",
                                "version": "2.0.0",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            state_path = root / "skill_watch_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "sources": {
                            "company": {
                                "project_path": "skills/company-skills",
                                "web_url": "https://example.org/skills/company",
                                "last_seen_sha": "abc12345",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            contract = build_spatial_contract_from_ecosystem(
                brain_manifest_path=manifest_path,
                brain_state_path=state_path,
                meshworks_graph={
                    "nodes": {
                        "k8s-rollout": {
                            "label": "K8s Rollout",
                            "kind": "kubernetes_deployment",
                            "domain": "deployments_k8s",
                            "summary": "Rollout monitor",
                        }
                    },
                    "edges": [],
                },
                triage_records=[{"query": "deploy k8s", "playbook": "k8s-deploy-rollout"}],
            )
        self.assertEqual(contract["schema_version"], CONTRACT_VERSION)
        errors = validate_spatial_graph_contract(contract)
        self.assertEqual(errors, [], f"Contract validation failed: {errors}")
        node_ids = {n["id"] for n in contract["nodes"]}
        self.assertIn("skill-deploy-k8s", node_ids)
        self.assertIn("watch-company", node_ids)
        self.assertIn("mesh-k8s-rollout", node_ids)
        self.assertIn("playbook-k8s-deploy-rollout", node_ids)

    def test_overlay_ecosystem_onto_catalog_preserves_contract_and_tracks_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest_path = root / "skills-manifest.json"
            data_dir = root / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            state_path = data_dir / "skill_watch_state.json"
            alerts_path = data_dir / "skill_watch_alerts.json"
            mesh_path = data_dir / "knowledge-graph.json"

            manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "skills": [
                            {
                                "id": "deploy-k8s",
                                "name": "deploy-k8s",
                                "description": "Deploy workloads",
                                "source": "company",
                                "category": "platform",
                                "version": "1.0.0",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            state_path.write_text(
                json.dumps(
                    {
                        "sources": {
                            "personal": {
                                "mode": "local",
                                "project_path": "example-repos/personal-skills",
                                "web_url": "file:///workspace/brain/example-repos/personal-skills",
                                "last_seen_sha": "sha11111111",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            alerts_path.write_text(
                json.dumps(
                    {
                        "alerts": [
                            {
                                "source": "personal",
                                "old_sha": "sha00000000",
                                "new_sha": "sha11111111",
                                "commit_message": "Updated personal skill deploy-k8s",
                                "changed_skills": ["deploy-k8s"],
                                "acknowledged": False,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            mesh_path.write_text(
                json.dumps(
                    {
                        "graph_revision": "rev111111111",
                        "nodes": {
                            "system:brain": {"label": "Brain", "kind": "system", "domain": "company_org"},
                            "tier:personal": {"label": "Personal Tier", "kind": "tier", "domain": "company_org"},
                            "skill:deploy-k8s": {"label": "deploy-k8s", "kind": "skill", "domain": "deployments_k8s"},
                        },
                        "edges": [
                            {"source": "system:brain", "target": "tier:personal", "relation": "contains_tier"},
                            {"source": "tier:personal", "target": "skill:deploy-k8s", "relation": "owns_skill"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            base_catalog = browser.build_standalone_demo_dataset()
            merged_v1 = overlay_ecosystem_onto_catalog(
                base_catalog,
                brain_manifest_path=manifest_path,
                brain_state_path=state_path,
                brain_alerts_path=alerts_path,
                meshworks_graph_path=mesh_path,
            )
            self.assertEqual(validate_spatial_graph_contract(merged_v1), [])
            self.assertIs(merged_v1["ecosystem_overlay_active"], True)
            ids_v1 = {n["id"] for n in merged_v1["nodes"]}
            self.assertTrue({"brain-skills-hub", "meshworks-coordinator", "skill-deploy-k8s", "watch-personal"}.issubset(ids_v1))
            self.assertIn("alert-0-personal-sha11111", ids_v1)
            self.assertNotIn("mesh-skill-deploy-k8s", ids_v1)

            manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "skills": [
                            {
                                "id": "deploy-k8s",
                                "name": "deploy-k8s",
                                "description": "Deploy workloads",
                                "source": "personal",
                                "category": "platform",
                                "version": "2.0.0",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            merged_v2 = overlay_ecosystem_onto_catalog(
                base_catalog,
                brain_manifest_path=manifest_path,
                brain_state_path=state_path,
                brain_alerts_path=alerts_path,
                meshworks_graph_path=mesh_path,
            )
            self.assertEqual(validate_spatial_graph_contract(merged_v2), [])
            self.assertNotEqual(merged_v1["ecosystem_revision"], merged_v2["ecosystem_revision"])

    def test_frontend_handler_ecosystem_overlay_env_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest_path = root / "skills-manifest.json"
            data_dir = root / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            state_path = data_dir / "skill_watch_state.json"
            alerts_path = data_dir / "skill_watch_alerts.json"
            mesh_path = data_dir / "knowledge-graph.json"

            manifest_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "skills": [
                            {
                                "id": "deploy-k8s",
                                "name": "deploy-k8s",
                                "description": "Deploy workloads",
                                "source": "company",
                                "category": "platform",
                                "version": "1.0.0",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            state_path.write_text(json.dumps({"sources": {}}), encoding="utf-8")
            alerts_path.write_text(json.dumps({"alerts": []}), encoding="utf-8")
            mesh_path.write_text(json.dumps({"graph_revision": "m1", "nodes": {}, "edges": []}), encoding="utf-8")

            handler_cls = browser._build_frontend_handler()
            with socketserver.TCPServer(("127.0.0.1", 0), handler_cls) as server:
                port = server.server_address[1]
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with mock.patch.dict(
                        os.environ,
                        {"OPSCRYER_ECOSYSTEM_OVERLAY": "0", "OPSCRYER_BRAIN_ROOT": str(root)},
                        clear=False,
                    ):
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/catalog") as resp:
                            default_cat = json.loads(resp.read().decode("utf-8"))
                        self.assertNotIn("ecosystem_overlay_active", default_cat)
                        self.assertNotIn("brain-skills-hub", {n["id"] for n in default_cat["nodes"]})
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/search?q=canary") as resp:
                            default_search = json.loads(resp.read().decode("utf-8"))
                        self.assertEqual(default_search["result_count"], 0)

                    with mock.patch.dict(
                        os.environ,
                        {"OPSCRYER_ECOSYSTEM_OVERLAY": "1", "OPSCRYER_BRAIN_ROOT": str(root)},
                        clear=False,
                    ):
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/catalog") as resp:
                            cat1 = json.loads(resp.read().decode("utf-8"))
                        self.assertIs(cat1["ecosystem_overlay_active"], True)
                        self.assertIn("brain-skills-hub", {n["id"] for n in cat1["nodes"]})

                        manifest_path.write_text(
                            json.dumps(
                                {
                                    "version": 1,
                                    "skills": [
                                        {
                                            "id": "live-watch-canary",
                                            "name": "live-watch-canary",
                                            "description": "Canary live skill watcher verification",
                                            "source": "personal",
                                            "category": "tooling",
                                            "version": "1.0.99",
                                        }
                                    ],
                                }
                            ),
                            encoding="utf-8",
                        )
                        cur_stat = manifest_path.stat()
                        os.utime(manifest_path, ns=(cur_stat.st_atime_ns, cur_stat.st_mtime_ns + 5_000_000))

                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/catalog") as resp:
                            cat2 = json.loads(resp.read().decode("utf-8"))
                        self.assertNotEqual(cat1["ecosystem_revision"], cat2["ecosystem_revision"])
                        self.assertIn("skill-live-watch-canary", {n["id"] for n in cat2["nodes"]})

                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/search?q=canary") as resp:
                            search2 = json.loads(resp.read().decode("utf-8"))
                        self.assertGreaterEqual(search2["result_count"], 1)
                        self.assertEqual(search2["results"][0]["id"], "skill-live-watch-canary")
                finally:
                    server.shutdown()

    def test_unified_backend_alignment_and_concurrent_sse(self):
        import tempfile
        from pathlib import Path
        import opscryer_browser as browser

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            data_dir = root / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            (data_dir / "skills-manifest.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "skills": [
                            {
                                "id": "deploy-k8s",
                                "name": "deploy-k8s",
                                "description": "Check pod health and Kubernetes rollout status.",
                                "source": "company",
                                "category": "platform",
                                "version": "1.2.0",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (data_dir / "skill_watch_state.json").write_text(
                json.dumps({"sources": {}}),
                encoding="utf-8",
            )
            (data_dir / "skill_watch_alerts.json").write_text(
                json.dumps({"alerts": []}),
                encoding="utf-8",
            )
            (data_dir / "knowledge-graph.json").write_text(
                json.dumps(
                    {
                        "graph_revision": "rev-test-001",
                        "nodes": {
                            "system:brain": {
                                "label": "Central Brain Skill Registry",
                                "kind": "system",
                                "domain": "company_org",
                            }
                        },
                        "edges": [],
                    }
                ),
                encoding="utf-8",
            )

            handler_cls = browser._build_frontend_handler()
            with socketserver.TCPServer(("127.0.0.1", 0), handler_cls) as server:
                port = server.server_address[1]
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                sse_resp = None
                try:
                    with mock.patch.dict(
                        os.environ,
                        {"OPSCRYER_ECOSYSTEM_OVERLAY": "1", "OPSCRYER_BRAIN_ROOT": str(root)},
                        clear=False,
                    ):
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/catalog", timeout=5) as resp:
                            catalog = json.loads(resp.read().decode("utf-8"))
                        by_id = {n["id"]: n for n in catalog["nodes"]}
                        self.assertIs(catalog["ecosystem_overlay_active"], True)
                        self.assertIn("cluster-home", by_id)
                        self.assertIn("root-company", by_id)
                        self.assertIn("brain-skills-hub", by_id)
                        self.assertIn("skill-deploy-k8s", by_id["brain-skills-hub"]["drilldown_children"])

                        for endpoint in (
                            "/api/v1/graph/drilldown?node_id=cluster-home",
                            "/api/v1/graph/drilldown?node_id=root-company",
                            "/api/v1/graph/drilldown?node_id=brain-skills-hub",
                        ):
                            with urllib.request.urlopen(f"http://127.0.0.1:{port}{endpoint}", timeout=5) as resp:
                                payload = json.loads(resp.read().decode("utf-8"))
                                self.assertIn("node", payload)

                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/search?q=ollama", timeout=5) as resp:
                            search = json.loads(resp.read().decode("utf-8"))
                            self.assertGreaterEqual(search["result_count"], 1)

                        # Keep an open SSE stream while issuing concurrent requests to prove non-blocking concurrency.
                        sse_resp = urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/api/v1/events/stream",
                            timeout=5,
                        )
                        first_line = sse_resp.readline()
                        self.assertTrue(first_line)

                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as resp:
                            self.assertEqual(resp.status, 200)
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/graph/catalog", timeout=3) as resp:
                            concurrent_cat = json.loads(resp.read().decode("utf-8"))
                            self.assertIn("cluster-home", {n["id"] for n in concurrent_cat["nodes"]})
                finally:
                    if sse_resp is not None:
                        try:
                            sse_resp.close()
                        except OSError:
                            pass
                    server.shutdown()


if __name__ == "__main__":
    unittest.main()
