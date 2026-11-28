# SPDX-License-Identifier: Apache-2.0
"""End-to-end OpsCryer High-Security MLS Confinement & Gateway Leak-Matrix Tests (Wave 1A).

Verifies that OpsCryer's bridge (`opscryer_bridge.py`) and live HTTP gateway
(`opscryer_browser.py` `/api/v1/graph/catalog` and `/api/v1/events/stream`) enforce
fail-closed `(rank, compartments)` dominance across all MLS carrier shapes (`mls`,
`classification`, `mls_label`, top-level), malformed classifications, spoofed
`level_index=0` roots, lateral high-rank attacks, and SSE event streams.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen

OPSCRYER_ROOT = Path(__file__).resolve().parent.parent
if str(OPSCRYER_ROOT) not in sys.path:
    sys.path.insert(0, str(OPSCRYER_ROOT))

from opscryer.bridge.opscryer_bridge import filter_spatial_catalog_by_clearance
import opscryer_browser


CANARY_TOKEN = "OPSCRYER_CANARY_HIGH_SIDE_8842"
CANARY_COMPARTMENT = "sec:high-side-canary"


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text.replace("\r\n", "\n"))


class TestOpsCryerMLSHighSecurityE2E(unittest.TestCase):
    """Proves high-risk MLS nodes and SSE events cannot leak through OpsCryer gateway."""

    def _build_canary_catalog(self) -> dict:
        return {
            "schema_version": "1.0-separable-spatial-graph-contract",
            "source": "mls_canary_fixture",
            "root_node_id": "root-company",
            "generated_at": "2026-11-25T20:00:00Z",
            "nodes": [
                {
                    "id": "root-company",
                    "label": "Public Organization Root",
                    "kind": "company_root",
                    "domain": "company_org",
                    "section": "section_1_company",
                    "level_index": 0,
                    "summary": "Public overview",
                    "primary_url": "https://opscryer.example.test/",
                    "drilldown_children": [
                        "svc-public-web",
                        "canary-mls-carrier",
                        "canary-classification-carrier",
                        "canary-mls-label-carrier",
                        "canary-spoofed-root",
                        "canary-malformed-carrier",
                        "canary-stub-node",
                    ],
                },
                {
                    "id": "svc-public-web",
                    "label": "Public Web Service",
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "section_3_resources",
                    "level_index": 1,
                    "summary": "Safe public service",
                    "primary_url": "https://opscryer.example.test/svc",
                    "drilldown_children": [],
                },
                {
                    "id": "canary-mls-carrier",
                    "label": f"Secret MLS Node {CANARY_TOKEN}",
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "section_3_resources",
                    "level_index": 1,
                    "summary": f"High-side details {CANARY_TOKEN}",
                    "primary_url": "https://enclave.example.test/mls",
                    "drilldown_children": [],
                    "mls": {"classification_rank": 40, "compartments": [CANARY_COMPARTMENT], "visibility": "OPAQUE"},
                },
                {
                    "id": "canary-classification-carrier",
                    "label": f"Secret Classification Node {CANARY_TOKEN}",
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "section_3_resources",
                    "level_index": 1,
                    "summary": f"Classification carrier {CANARY_TOKEN}",
                    "primary_url": "https://enclave.example.test/cls",
                    "drilldown_children": [],
                    "classification": {"rank": 40, "compartments": [CANARY_COMPARTMENT]},
                },
                {
                    "id": "canary-mls-label-carrier",
                    "label": f"Secret MLS Label Node {CANARY_TOKEN}",
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "section_3_resources",
                    "level_index": 1,
                    "summary": f"MLS label carrier {CANARY_TOKEN}",
                    "primary_url": "https://enclave.example.test/lbl",
                    "drilldown_children": [],
                    "mls_label": {"rank": 40, "compartments": [CANARY_COMPARTMENT]},
                },
                {
                    "id": "canary-spoofed-root",
                    "label": f"Spoofed Level-0 Root {CANARY_TOKEN}",
                    "kind": "company_root",
                    "domain": "company_org",
                    "section": "section_1_company",
                    "level_index": 0,
                    "summary": f"Attempted root bypass {CANARY_TOKEN}",
                    "primary_url": "https://enclave.example.test/root",
                    "drilldown_children": [],
                    "classification": {"rank": 40, "compartments": [CANARY_COMPARTMENT]},
                },
                {
                    "id": "canary-malformed-carrier",
                    "label": f"Corrupt Classification {CANARY_TOKEN}",
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "section_3_resources",
                    "level_index": 1,
                    "summary": f"Must fail closed {CANARY_TOKEN}",
                    "primary_url": "https://enclave.example.test/bad",
                    "drilldown_children": [],
                    "mls": {"rank": "corrupt-rank", "compartments": "not-a-list"},
                },
                {
                    "id": "canary-stub-node",
                    "label": f"Stub Title {CANARY_TOKEN}",
                    "kind": "operational_process",
                    "domain": "processes_workflows",
                    "section": "section_2_processes",
                    "level_index": 2,
                    "summary": f"Stub Secret Body {CANARY_TOKEN}",
                    "primary_url": "https://enclave.example.test/stub",
                    "drilldown_children": [],
                    "steps": [f"classified step {CANARY_TOKEN}"],
                    "mls": {"classification_rank": 40, "compartments": [CANARY_COMPARTMENT], "visibility": "STUB"},
                },
            ],
            "edges": [
                {"source": "root-company", "target": "svc-public-web", "relation": "contains"},
                {"source": "root-company", "target": "canary-mls-carrier", "relation": "contains"},
                {"source": "root-company", "target": "canary-stub-node", "relation": "contains"},
            ],
        }

    def test_01_bridge_filter_blocks_all_carriers_spoofed_roots_malformed_and_lateral(self) -> None:
        catalog = self._build_canary_catalog()

        # Unprivileged viewer (rank 0) and lateral high-rank viewer (rank 60, wrong compartment) both fail closed!
        for v_rank, v_comps in ((0, []), (60, ["sec:other-compartment"])):
            filtered = filter_spatial_catalog_by_clearance(
                catalog, viewer_rank=v_rank, viewer_compartments=v_comps, system_high=False
            )
            serialized = json.dumps(filtered)
            self.assertNotIn(CANARY_TOKEN, serialized)
            self.assertNotIn("canary-mls-carrier", serialized)
            self.assertNotIn("canary-classification-carrier", serialized)
            self.assertNotIn("canary-mls-label-carrier", serialized)
            self.assertNotIn("canary-spoofed-root", serialized)
            self.assertNotIn("canary-malformed-carrier", serialized)
            # STUB node survives only as a clean redacted placeholder with zero canary text or steps.
            stub = next(n for n in filtered["nodes"] if n["id"] == "canary-stub-node")
            self.assertEqual(stub["label"], "[REDACTED Rank 40 - Request Lease]")
            self.assertNotIn("steps", stub)
            self.assertEqual(filtered["security_posture"]["stripped_opaque_count"], 5)
            self.assertEqual(filtered["security_posture"]["redacted_stub_count"], 1)

        # Authorized viewer (rank 40 + exact compartment) sees valid rank=40 nodes, while malformed STILL fails closed!
        auth_view = filter_spatial_catalog_by_clearance(
            catalog, viewer_rank=40, viewer_compartments=[CANARY_COMPARTMENT], system_high=False
        )
        auth_ids = {n["id"] for n in auth_view["nodes"]}
        self.assertIn("canary-mls-carrier", auth_ids)
        self.assertIn("canary-classification-carrier", auth_ids)
        self.assertIn("canary-spoofed-root", auth_ids)
        self.assertNotIn("canary-malformed-carrier", auth_ids)

    def test_02_gateway_http_catalog_filters_mounted_external_high_side_graph_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            graph_path = Path(tmp) / "high_side_catalog.json"
            _write_lf(graph_path, json.dumps(self._build_canary_catalog(), indent=2))

            env_patch = {
                opscryer_browser.EXTERNAL_GRAPH_FILE_ENV: str(graph_path),
                "OPSCRYER_BRAIN_API_URL": "",
                "OPSCRYER_VIEWER_RANK": "0",
                "OPSCRYER_VIEWER_COMPARTMENTS": "",
            }
            with patch.dict(os.environ, env_patch, clear=False):
                from http.server import ThreadingHTTPServer

                handler_cls = opscryer_browser._build_frontend_handler("")
                server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
                port = server.server_address[1]
                t = threading.Thread(target=server.serve_forever, daemon=True)
                t.start()
                try:
                    with urlopen(f"http://127.0.0.1:{port}/api/v1/graph/catalog", timeout=5) as resp:
                        raw = resp.read().decode("utf-8")
                        doc = json.loads(raw)

                    self.assertNotIn(CANARY_TOKEN, raw)
                    self.assertNotIn("canary-mls-carrier", raw)
                    self.assertNotIn("canary-spoofed-root", raw)
                    self.assertNotIn("canary-malformed-carrier", raw)
                    ids = {n["id"] for n in doc["nodes"]}
                    self.assertIn("root-company", ids)
                    self.assertIn("svc-public-web", ids)
                    root_node = next(n for n in doc["nodes"] if n["id"] == "root-company")
                    self.assertNotIn("canary-mls-carrier", root_node["drilldown_children"])
                    self.assertEqual(doc["security_posture"]["stripped_opaque_count"], 5)
                finally:
                    server.shutdown()
                    server.server_close()
                    t.join(timeout=2)

    def test_03_gateway_sse_mls_chunk_filter_suppresses_high_side_and_lateral_events(self) -> None:
        public_chunk = (
            "id: 1\nevent: graph\n"
            'data: {"seq_id": 1, "topic": "graph", "data": {"node_id": "svc-public"}}\n\n'
        )
        high_chunk = (
            "id: 2\nevent: security\n"
            f'data: {{"seq_id": 2, "topic": "security", "data": {{"secret": "{CANARY_TOKEN}", '
            f'"classification": {{"rank": 40, "compartments": ["{CANARY_COMPARTMENT}"]}}}}}}\n\n'
        )
        malformed_chunk = (
            "id: 3\nevent: security\n"
            f'data: {{"seq_id": 3, "topic": "security", "data": {{"mls": "corrupt", "secret": "{CANARY_TOKEN}"}}}}\n\n'
        )

        self.assertTrue(opscryer_browser._is_sse_chunk_permitted_by_mls(public_chunk, 0, []))
        self.assertFalse(opscryer_browser._is_sse_chunk_permitted_by_mls(high_chunk, 0, []))
        self.assertFalse(opscryer_browser._is_sse_chunk_permitted_by_mls(high_chunk, 60, ["sec:other"]))
        self.assertTrue(opscryer_browser._is_sse_chunk_permitted_by_mls(high_chunk, 40, [CANARY_COMPARTMENT]))
        self.assertFalse(opscryer_browser._is_sse_chunk_permitted_by_mls(malformed_chunk, 100, [CANARY_COMPARTMENT]))


if __name__ == "__main__":
    unittest.main()
