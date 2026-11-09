# SPDX-License-Identifier: Apache-2.0
"""Disclosure boundaries, graph integrity and person/ticket joins."""

from copy import deepcopy
from ipaddress import IPv4Address
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import dogfood_graph as graph
from opscryer_backend import validate_spatial_graph_contract


class DogfoodGraphTests(unittest.TestCase):
    def setUp(self):
        self.catalog = graph.build_dogfood_zoom_catalog()

    def query(self, level, node_id=graph.ROOT_ID):
        return graph.query_node_at_progressive_zoom(node_id, level, self.catalog)

    def test_catalog_contract_references_and_all_nine_epics(self):
        self.assertEqual(validate_spatial_graph_contract(self.catalog), [])
        self.assertEqual(len([n for n in self.catalog["nodes"] if n["kind"] == "epic"]), 9)
        by_id = {n["id"]: n for n in self.catalog["nodes"]}
        for node in by_id.values():
            for child in node["drilldown_children"]:
                self.assertGreaterEqual(by_id[child]["zoom_level"], node["zoom_level"])
        for ticket in self.catalog["tickets"]:
            self.assertEqual(by_id[ticket["assignee_id"]]["kind"], "person")
            self.assertEqual(by_id[ticket["feature_id"]]["kind"], "feature")
        json.dumps(self.catalog, allow_nan=False)

    def test_l0_only_root_and_seven_aggregate_currencies(self):
        result = self.query(0)
        self.assertEqual([n["id"] for n in result["nodes"]], [graph.ROOT_ID])
        self.assertIn("Root Citadel", result["node"]["label"])
        self.assertEqual(result["node"]["drilldown_children"], [])
        self.assertEqual(result["node"]["encapsulated_child_count"], 1)
        self.assertEqual(result["edges"], [])
        self.assertEqual({c["currency_id"] for c in result["rts_currencies"]},
                         {"nodes", "cpu_load", "ram_load", "network_load",
                          "build_supply", "renovate_failures", "open_mrs"})

    def test_l1_teams_units_epics_and_l2_projects_walkthroughs(self):
        l1 = self.query(1)
        self.assertTrue({"company_team", "ai_agent_unit", "epic"}.issubset(
            {n["kind"] for n in l1["nodes"]}))
        self.assertEqual(len([n for n in l1["nodes"] if n["kind"] == "epic"]), 9)
        self.assertNotIn("walkthroughs", json.dumps(l1))
        projects = [n for n in self.query(2)["nodes"] if n["kind"] == "engineering_project"]
        self.assertEqual(len(projects), 9)
        self.assertTrue(all(n["walkthroughs"] for n in projects))

    def test_l3_feature_verification_and_l4_deep_runbooks(self):
        features = [n for n in self.query(3)["nodes"] if n["kind"] == "feature"]
        self.assertEqual(len(features), 9)
        for feature in features:
            self.assertIn("python -m unittest discover -s tests -v",
                          feature["automated_test_commands"])
            for field in ("manual_steps", "merge_requests", "ci_pipelines"):
                self.assertTrue(feature[field])
            self.assertEqual(feature["ci_pipelines"][0]["status"], "not_run")
        runbooks = [n for n in self.query(4)["nodes"] if n["zoom_level"] == 4]
        self.assertEqual(len(runbooks), 9)
        for runbook in runbooks:
            self.assertTrue(runbook["cli_commands"])
            self.assertEqual({p["predicate_id"] for p in runbook["jev_predicates"]},
                             {"is_project_scaffolding", "is_credential_access"})
            self.assertEqual(runbook["on_uncertain"], "human_escalation")

    def test_hidden_details_absent_from_entire_serialized_response(self):
        feature_fields = ("automated_test_commands", "manual_steps", "merge_requests", "ci_pipelines")
        for level in range(5):
            result = self.query(level)
            serialized = json.dumps(result)
            for field in feature_fields if level < 3 else ():
                self.assertNotIn(field, serialized)
            if level < 4:
                for marker in ("cli_commands", "jev_predicates", "runbook-", "human_escalation"):
                    self.assertNotIn(marker, serialized)
            self.assertNotIn("tickets", result)
            ids = {n["id"] for n in result["nodes"]}
            for node in result["nodes"]:
                self.assertLessEqual(node["zoom_level"], level)
                self.assertTrue(set(node["drilldown_children"]).issubset(ids))
            for edge in result["edges"]:
                self.assertTrue({edge["source"], edge["target"]}.issubset(ids))

    def test_direct_deep_lookup_does_not_bypass_zoom(self):
        for level in range(4):
            result = self.query(level, "runbook-1")
            self.assertTrue(result["encapsulated"])
            self.assertIsNone(result["node"])
            self.assertEqual(result["nodes"], [])
        self.assertTrue(self.query(4, "runbook-1")["node"]["cli_commands"])
        subtree = self.query(4, "project-2")
        self.assertEqual({n["id"] for n in subtree["nodes"]},
                         {"project-2", "feature-2", "runbook-2"})
        self.assertNotIn("rts_currencies", subtree)

    def test_zoom_back_out_is_stateless_and_results_are_detached(self):
        before = deepcopy(self.catalog)
        self.query(4)["nodes"][0]["label"] = "changed"
        self.query(0)["rts_currencies"].clear()
        self.query(3, "feature-1")["node"]["manual_steps"].clear()
        self.assertEqual(self.catalog, before)
        self.assertEqual(self.query(0), graph.query_node_at_progressive_zoom())
        self.catalog["nodes"].clear()
        self.assertTrue(graph.build_dogfood_zoom_catalog()["nodes"])

    def test_invalid_zoom_and_node_inputs(self):
        for level in (-1, 5, True, False, 1.0, "L2", None):
            with self.subTest(level=level), self.assertRaises(ValueError):
                self.query(level)
        for node_id in (None, [], ""):
            with self.assertRaises(ValueError):
                self.query(0, node_id)
        with self.assertRaises(KeyError):
            self.query(4, "missing")

    def test_person_lookup_matches_exact_identity_and_only_open_assigned_work(self):
        self.catalog["tickets"] += [
            {"id": "blocked", "assignee_id": "person-demo-maintainer", "status": "blocked"},
            {"id": "other", "assignee_id": "someone-else", "status": "open"},
            {"id": "done", "assignee_id": "person-demo-maintainer", "status": "resolved"},
        ]
        for identity in ("person-demo-maintainer", " Demo Maintainer ", "DEMO-MAINTAINER"):
            result = graph.lookup_person_and_open_tickets(identity, self.catalog)
            self.assertEqual(result["person"]["id"], "person-demo-maintainer")
            self.assertEqual({t["id"] for t in result["open_tickets"]},
                             {"DOGFOOD-1", "DOGFOOD-2", "blocked"})
        result["person"]["label"] = "changed"
        result["open_tickets"][0]["status"] = "closed"
        self.assertEqual(self.catalog["tickets"][0]["status"], "open")
        for identity in ("missing", "Demo", "unit-dogfood"):
            self.assertEqual(graph.lookup_person_and_open_tickets(identity, self.catalog),
                             {"person": None, "open_tickets": []})

    def test_person_lookup_rejects_bad_or_ambiguous_identity(self):
        for identity in (None, 1, "", "  "):
            with self.assertRaises(ValueError):
                graph.lookup_person_and_open_tickets(identity)
        duplicate = deepcopy(next(n for n in self.catalog["nodes"] if n["kind"] == "person"))
        duplicate["id"] = "person-other"
        self.catalog["nodes"].append(duplicate)
        with self.assertRaises(ValueError):
            graph.lookup_person_and_open_tickets("Demo Maintainer", self.catalog)
        self.assertEqual(graph.lookup_person_and_open_tickets(
            "person-other", self.catalog)["open_tickets"], [])


class LiveDogfoodSummaryTests(unittest.TestCase):
    def setUp(self):
        from cluster_harvester import build_live_cluster_spatial_catalog
        self.catalog = build_live_cluster_spatial_catalog()

    def test_all_epics_reference_shipped_modules_and_test_suites(self):
        result = graph.build_live_verified_dogfood_summary(self.catalog)
        self.assertEqual(list(result), [f"EPIC-{i}" for i in range(1, 10)])
        root = Path(graph.__file__).parent
        for entry in result.values():
            self.assertTrue(entry["title"])
            self.assertTrue(entry["shipped_modules"])
            for module in entry["shipped_modules"]:
                self.assertTrue((root / module).is_file(), module)
            command = entry["verification_commands"][0]
            self.assertTrue(command.startswith("python -m unittest "))
            for suite in command.split()[3:-1]:
                self.assertTrue((root / (suite.replace(".", "/") + ".py")).is_file(), suite)
        self.assertIn("openbao_kms_provenance.py", result["EPIC-5"]["shipped_modules"])
        self.assertIn("ticket_chat_portal.py", result["EPIC-8"]["shipped_modules"])
        self.assertEqual(json.loads(json.dumps(result, allow_nan=False)), result)

    def test_snapshot_evidence_is_grounded_scoped_and_not_a_live_check(self):
        result = graph.build_live_verified_dogfood_summary(self.catalog)
        by_id = {node["id"]: node for node in self.catalog["nodes"]}
        for entry in result.values():
            evidence = entry["live_evidence"]
            self.assertEqual(evidence["source"], "offline_fallback")
            self.assertTrue(evidence["example"])
            self.assertFalse(evidence["live_connections"])
            self.assertEqual(evidence["available"], bool(evidence["cited_node_ids"]))
            counts = {}
            for node_id in evidence["cited_node_ids"]:
                node = by_id[node_id]
                if evidence["namespaces"] is not None:
                    self.assertIn(node["namespace"], evidence["namespaces"])
                kind = node["resource_kind"]
                counts[kind] = counts.get(kind, 0) + 1
            self.assertEqual(evidence["resource_counts"], counts)
        self.assertTrue(result["EPIC-6"]["live_evidence"]["available"])
        self.assertEqual(result["EPIC-1"]["live_evidence"]["cluster_health"]["node_counts"]["total"], 3)

    def test_empty_catalog_has_no_invented_evidence(self):
        result = graph.build_live_verified_dogfood_summary({"nodes": []})
        for entry in result.values():
            evidence = entry["live_evidence"]
            self.assertFalse(evidence["available"])
            self.assertEqual(evidence["cited_node_ids"], [])
            self.assertEqual(evidence["resource_counts"], {})
            self.assertEqual(evidence["source"], "provided_catalog")

    def test_default_reads_bundled_snapshot_without_collection(self):
        with patch("subprocess.run", side_effect=AssertionError("collection attempted")), \
                patch("socket.socket", side_effect=AssertionError("network attempted")):
            result = graph.build_live_verified_dogfood_summary()
        bundled = json.loads(Path(graph.__file__).with_name(
            "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        self.assertEqual(result, graph.build_live_verified_dogfood_summary(bundled))

    def test_detached_results_sanitization_staleness_and_legacy_compatibility(self):
        legacy = graph.build_dogfood_zoom_catalog()
        zoom = graph.query_node_at_progressive_zoom(zoom_level=4, catalog=legacy)
        tickets = graph.lookup_person_and_open_tickets("demo-maintainer", legacy)
        self.catalog.update(source="live_kubectl", example=False, stale=True)
        wan = str(IPv4Address(0x08080808))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        token = "gh" + "p_" + "privatecredential"
        self.catalog["source"] += " " + " ".join((wan, mac, token))
        before = deepcopy(self.catalog)
        result = graph.build_live_verified_dogfood_summary(self.catalog)
        evidence = result["EPIC-1"]["live_evidence"]
        self.assertIn("203.0.113.1", evidence["source"])
        self.assertIn("AA:BB:CC:XX:XX:XX", evidence["source"])
        for private in (wan, mac, token):
            self.assertNotIn(private, json.dumps(result))
        self.assertTrue(evidence["stale"])
        self.assertFalse(evidence["example"])
        evidence["cluster_health"]["node_counts"]["total"] = -1
        evidence["cited_node_ids"].clear()
        result["EPIC-1"]["shipped_modules"].clear()
        self.assertEqual(self.catalog, before)
        self.assertEqual(result["EPIC-3"]["live_evidence"]["cluster_health"]["node_counts"]["total"], 3)
        self.assertTrue(graph.build_live_verified_dogfood_summary(self.catalog)["EPIC-1"]["shipped_modules"])
        graph.build_live_verified_dogfood_summary(legacy)
        self.assertEqual(graph.build_dogfood_zoom_catalog(), legacy)
        self.assertEqual(graph.query_node_at_progressive_zoom(zoom_level=4, catalog=legacy), zoom)
        self.assertEqual(graph.lookup_person_and_open_tickets("demo-maintainer", legacy), tickets)

    def test_health_evidence_tracks_supplied_snapshot(self):
        node = next(n for n in self.catalog["nodes"] if n.get("resource_kind") == "Node")
        node["resource"]["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
        pod = next(n for n in self.catalog["nodes"] if n.get("resource_kind") == "Pod")
        pod["resource"]["status"]["phase"] = "Failed"
        health = graph.build_live_verified_dogfood_summary(
            self.catalog)["EPIC-5"]["live_evidence"]["cluster_health"]
        self.assertGreaterEqual(health["node_counts"]["not_ready"], 1)
        self.assertIn(pod["id"], health["failed_pods_by_namespace"][pod["namespace"]]["pod_ids"])

    def test_invalid_catalogs_fail_without_echoing_input(self):
        duplicate = {"id": "private diagnostic"}
        for catalog in (False, [], {}, {"nodes": [None]},
                        {"nodes": [duplicate, duplicate]},
                        {"nodes": [], "example": "private diagnostic"},
                        {"nodes": [], "stale": 1},
                        {"nodes": [{"id": "one", "resource": []}]}):
            with self.subTest(catalog=catalog), self.assertRaisesRegex(
                    ValueError, "^Invalid cluster catalog$"):
                graph.build_live_verified_dogfood_summary(catalog)


if __name__ == "__main__":
    unittest.main()
