# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the offline System-2 to System-1 Jev Decision Tree validator."""

from __future__ import annotations

from copy import deepcopy
import unittest

from jev_tree_author import dry_run_jev_tree_samples, validate_authored_jev_tree
from knowledge_base import CONCIERGE_JEV_TREE


class JevTreeAuthorTests(unittest.TestCase):
    def test_concierge_jev_tree_passes_validation_and_dry_run_samples(self) -> None:
        errors = validate_authored_jev_tree(CONCIERGE_JEV_TREE)
        self.assertEqual(errors, [])
        report = dry_run_jev_tree_samples()
        self.assertTrue(report["tree_valid"])
        self.assertTrue(report["all_samples_matched"])

    def test_cycle_and_unreachable_node_and_missing_anchor_are_detected(self) -> None:
        cyclic = deepcopy(CONCIERGE_JEV_TREE)
        cyclic["nodes"]["node-check-game-servers"]["false_branch"] = "node-check-scaffolding"
        errors = validate_authored_jev_tree(cyclic)
        self.assertTrue(any("cycle detected" in err for err in errors))

        orphan = deepcopy(CONCIERGE_JEV_TREE)
        orphan["nodes"]["leaf-orphan"] = {
            "node_id": "leaf-orphan",
            "kind": "leaf",
            "policy_id": "policy-orphan",
            "direct_access_allowed": False,
            "required_it_tickets": ["IT-ORPHAN-01"],
            "anchor_node_id": "kb-ops-009",
        }
        orphan_errors = validate_authored_jev_tree(orphan)
        self.assertTrue(any("unreachable nodes" in err for err in orphan_errors))

        catalog_errors = validate_authored_jev_tree(
            CONCIERGE_JEV_TREE,
            catalog={"nodes": [{"id": "only-one-node"}]},
        )
        self.assertTrue(any("unknown catalog anchor" in err for err in catalog_errors))


if __name__ == "__main__":
    unittest.main()
