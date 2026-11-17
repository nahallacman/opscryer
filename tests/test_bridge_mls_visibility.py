# SPDX-License-Identifier: Apache-2.0
"""Tests for OpsCryer bridge MLS visibility filtering and project overlay scrubbing."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from opscryer.bridge import (
    build_spatial_contract_from_ecosystem,
    filter_spatial_catalog_by_clearance,
    overlay_ecosystem_onto_catalog,
)
from opscryer_backend import bm25_search_nodes, validate_spatial_graph_contract


class BridgeMlsVisibilityTests(unittest.TestCase):
    def test_default_contract_invariance_and_valid_schema(self) -> None:
        catalog = build_spatial_contract_from_ecosystem()
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        self.assertNotIn("security_posture", catalog)

    def test_opaque_project_overlay_invisible_at_l0_and_lateral_compartments(self) -> None:
        overlays = [
            {
                "project_id": "alpha-core",
                "classification_rank": 30,
                "compartments": ["project:alpha-core"],
                "visibility": "OPAQUE",
                "summary": "Restricted alpha project slot",
                "steps": ["secret_alpha_runbook_keyword"],
                "skills": [
                    {
                        "id": "alpha-failover",
                        "name": "Alpha Failover",
                        "description": "Private failover steps",
                    }
                ],
            }
        ]
        # Default L0 view strips OPAQUE project node and child skill cleanly.
        l0_view = build_spatial_contract_from_ecosystem(project_overlays=overlays)
        self.assertEqual(validate_spatial_graph_contract(l0_view), [])
        l0_ids = {n["id"] for n in l0_view["nodes"]}
        self.assertNotIn("project-alpha-core", l0_ids)
        self.assertNotIn("pskill-alpha-core-alpha-failover", l0_ids)
        self.assertEqual(l0_view["security_posture"]["stripped_opaque_count"], 2)
        self.assertEqual(bm25_search_nodes(l0_view["nodes"], "alpha"), [])

        # Higher rank without matching compartment still sees zero OPAQUE nodes.
        lateral_view = build_spatial_contract_from_ecosystem(
            project_overlays=overlays,
            viewer_rank=60,
            viewer_compartments=["group:payments"],
        )
        self.assertEqual(validate_spatial_graph_contract(lateral_view), [])
        lateral_ids = {n["id"] for n in lateral_view["nodes"]}
        self.assertNotIn("project-alpha-core", lateral_ids)
        self.assertEqual(lateral_view["security_posture"]["stripped_opaque_count"], 2)

        # Dominated `(rank, compartments)` view reveals both project and child skill.
        authorized_view = build_spatial_contract_from_ecosystem(
            project_overlays=overlays,
            viewer_rank=30,
            viewer_compartments=["project:alpha-core"],
        )
        self.assertEqual(validate_spatial_graph_contract(authorized_view), [])
        auth_ids = {n["id"] for n in authorized_view["nodes"]}
        self.assertIn("project-alpha-core", auth_ids)
        self.assertIn("pskill-alpha-core-alpha-failover", auth_ids)
        self.assertEqual(authorized_view["security_posture"]["stripped_opaque_count"], 0)

        # System-High mode bypasses filtering and stamps posture metadata.
        syshigh_view = build_spatial_contract_from_ecosystem(
            project_overlays=overlays,
            viewer_rank=100,
            system_high=True,
        )
        self.assertEqual(validate_spatial_graph_contract(syshigh_view), [])
        self.assertTrue(syshigh_view["security_posture"]["system_high"])
        self.assertIn("project-alpha-core", {n["id"] for n in syshigh_view["nodes"]})

    def test_stub_scrubs_searchable_fields_and_keeps_valid_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "skills-manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "skills": [
                            {
                                "id": "restricted-rotate",
                                "name": "Rotate Enclave Certs",
                                "category": "platform",
                                "description": "Contains ultrasecretstubterm inside description",
                                "classification_rank": 40,
                                "compartments": ["group:secops"],
                                "visibility": "STUB",
                                "steps": ["ultrasecretstubterm step one"],
                                "workloads": ["ultrasecretstubterm-pod"],
                                "specs": "ultrasecretstubterm-spec",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            stub_view = build_spatial_contract_from_ecosystem(
                brain_manifest_path=manifest_path,
                viewer_rank=10,
                viewer_compartments=[],
            )
            self.assertEqual(validate_spatial_graph_contract(stub_view), [])
            self.assertEqual(stub_view["security_posture"]["redacted_stub_count"], 1)
            by_id = {n["id"]: n for n in stub_view["nodes"]}
            stub_node = by_id["skill-restricted-rotate"]
            self.assertEqual(stub_node["label"], "[REDACTED Rank 40 - Request Lease]")
            self.assertEqual(stub_node["summary"], "[REDACTED Rank 40 - Request Lease]")
            self.assertTrue(stub_node["redacted"])
            for scrubbed_field in ("steps", "workloads", "specs"):
                self.assertNotIn(scrubbed_field, stub_node)
            # Search index must return zero matches for scrubbed sensitive words.
            self.assertEqual(bm25_search_nodes(stub_view["nodes"], "ultrasecretstubterm"), [])

            # Direct filter_spatial_catalog_by_clearance works idempotently too.
            refiltered = filter_spatial_catalog_by_clearance(stub_view, viewer_rank=10)
            self.assertEqual(validate_spatial_graph_contract(refiltered), [])

    def test_overlay_ecosystem_onto_catalog_forwards_mls_filter(self) -> None:
        base_catalog = build_spatial_contract_from_ecosystem()
        overlays = [
            {
                "project_id": "vault-edge",
                "classification_rank": 50,
                "compartments": ["project:vault-edge"],
                "visibility": "OPAQUE",
            }
        ]
        blocked = overlay_ecosystem_onto_catalog(
            base_catalog,
            project_overlays=overlays,
            viewer_rank=20,
            viewer_compartments=[],
        )
        self.assertEqual(validate_spatial_graph_contract(blocked), [])
        self.assertNotIn("project-vault-edge", {n["id"] for n in blocked["nodes"]})

        allowed = overlay_ecosystem_onto_catalog(
            base_catalog,
            project_overlays=overlays,
            viewer_rank=50,
            viewer_compartments=["project:vault-edge"],
        )
        self.assertEqual(validate_spatial_graph_contract(allowed), [])
        self.assertIn("project-vault-edge", {n["id"] for n in allowed["nodes"]})


if __name__ == "__main__":
    unittest.main()
