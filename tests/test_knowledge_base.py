# SPDX-License-Identifier: Apache-2.0
"""Unit tests for canonical knowledge_base module and live/fixture K8s catalog overlay."""

from copy import deepcopy
import unittest

import cluster_harvester as cluster
import knowledge_base as kb
from opscryer_backend import validate_spatial_graph_contract
import ticket_chat_portal as portal


class KnowledgeBaseTests(unittest.TestCase):
    def test_canonical_exports_match_portal_and_harvester(self):
        self.assertEqual(len(kb.KNOWLEDGE_BASE_ARTICLES), 9)
        self.assertEqual(len(kb.KB_CLUSTER_RUNBOOKS), 9)
        self.assertIs(portal.KNOWLEDGE_BASE_ARTICLES, kb.KNOWLEDGE_BASE_ARTICLES)
        self.assertIs(portal.CONCIERGE_JEV_TREE, kb.CONCIERGE_JEV_TREE)
        self.assertIs(portal.POLICY_TO_ARTICLE_ID, kb.POLICY_TO_ARTICLE_ID)
        self.assertIs(cluster.KB_CLUSTER_RUNBOOKS, kb.KB_CLUSTER_RUNBOOKS)

    def test_fixture_harvest_overlays_matching_namespace_runbooks_and_validates(self):
        fixture_snapshot = {
            "items": [
                {"kind": "Namespace", "metadata": {"name": "cnpg-system"}},
                {"kind": "Pod", "metadata": {"name": "postgres-ha-1", "namespace": "cnpg-system"}},
            ]
        }
        catalog = cluster.build_live_cluster_spatial_catalog(fixture_snapshot)
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        by_id = {n["id"]: n for n in catalog["nodes"]}
        self.assertIn("k8s/Namespace//cnpg-system", by_id)
        self.assertIn("kb-db-001", by_id)
        self.assertIn("kb-db-001", by_id["k8s/Namespace//cnpg-system"]["drilldown_children"])
        self.assertIn(
            {"source": "k8s/Namespace//cnpg-system", "target": "kb-db-001", "relation": "contains_runbook"},
            catalog["edges"],
        )
        counted = deepcopy(catalog)
        counted["node_count"] = 1
        counted["edge_count"] = 1
        kb.overlay_knowledge_base_runbooks(counted)
        self.assertEqual(counted["node_count"], len(counted["nodes"]))
        self.assertEqual(counted["edge_count"], len(counted["edges"]))
        self.assertEqual(validate_spatial_graph_contract(counted), [])

    def test_overlay_is_idempotent_on_repeated_calls(self):
        catalog = cluster.build_live_cluster_spatial_catalog()
        before = deepcopy(catalog)
        kb.overlay_knowledge_base_runbooks(catalog)
        kb.overlay_knowledge_base(catalog)
        self.assertEqual(catalog, before)
        self.assertEqual(validate_spatial_graph_contract(catalog), [])


if __name__ == "__main__":
    unittest.main()
