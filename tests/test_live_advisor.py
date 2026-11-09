# SPDX-License-Identifier: Apache-2.0
"""Operational evidence composition, airlock ordering and CLI checks."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import live_advisor as advisor
from cluster_harvester import build_live_cluster_spatial_catalog


class LiveAdvisorTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_live_cluster_spatial_catalog()

    def test_incident_brief_forwards_catalog_to_both_providers(self):
        advice = {"summary": "node health"}
        incidents = {"incidents": [], "summary_counts": {"total": 0}}
        for catalog in (None, self.catalog, Path("catalog.json"), "catalog.json"):
            with self.subTest(catalog_type=type(catalog).__name__), \
                    patch.object(advisor, "answer_operational_question",
                                 return_value=advice) as answer, \
                    patch.object(advisor.incident_commander, "build_active_incidents_catalog",
                                 return_value=incidents) as build:
                result = advisor.get_advisor_incident_brief(catalog)
            answer.assert_called_once_with("manifest node health", catalog=catalog)
            build.assert_called_once_with(catalog=catalog)
            self.assertEqual(result, {"advisor": advice, "incidents": incidents})

    def test_incident_brief_matches_providers_without_mutating_catalog(self):
        node = next(n for n in self.catalog["nodes"] if n.get("resource_kind") == "Node")
        node["resource"]["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
        before = deepcopy(self.catalog)
        expected = {
            "advisor": advisor.answer_operational_question(
                "manifest node health", catalog=self.catalog),
            "incidents": advisor.incident_commander.build_active_incidents_catalog(
                catalog=self.catalog),
        }
        self.assertEqual(advisor.get_advisor_incident_brief(self.catalog), expected)
        self.assertEqual(self.catalog, before)
        self.assertGreater(expected["incidents"]["summary_counts"]["total"], 0)
        self.assertEqual(json.loads(json.dumps(expected, allow_nan=False)), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            for catalog in (path, str(path)):
                self.assertEqual(advisor.get_advisor_incident_brief(catalog), expected)

    def test_incident_brief_default_and_healthy_catalog(self):
        result = advisor.get_advisor_incident_brief()
        self.assertEqual(result["advisor"],
                         advisor.answer_operational_question("manifest node health"))
        self.assertEqual(result["incidents"],
                         advisor.incident_commander.build_active_incidents_catalog())
        result = advisor.get_advisor_incident_brief(self.catalog)
        self.assertEqual(result["advisor"]["status"], "ok")
        self.assertEqual(result["incidents"]["incidents"], [])
        self.assertEqual(result["incidents"]["summary_counts"]["total"], 0)

    def test_incident_brief_sanitizes_both_results(self):
        public = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        secret = "gh" + "p_" + "synthetic_brief_value"
        payload = " ".join((public, mac, secret, "10.1.2.3", "router.cluster.example.org"))
        self.catalog["source"] = payload
        node = next(n for n in self.catalog["nodes"] if n.get("resource_kind") == "Node")
        node["resource"]["metadata"]["name"] = payload
        node["resource"]["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
        before = deepcopy(self.catalog)
        result = advisor.get_advisor_incident_brief(self.catalog)
        for section in result.values():
            encoded = json.dumps(section)
            for raw in (public, mac, secret):
                self.assertNotIn(raw, encoded)
            for allowed in ("203.0.113.1", "AA:BB:CC:XX:XX:XX",
                            "[REDACTED]", "10.1.2.3", "router.cluster.example.org"):
                self.assertIn(allowed, encoded)
        self.assertEqual(self.catalog, before)

    def test_operational_answer_contract_remains_independent_of_incidents(self):
        with patch.object(advisor.incident_commander, "build_active_incidents_catalog") as build:
            result = advisor.answer_operational_question("manifest node health", self.catalog)
        build.assert_not_called()
        self.assertEqual(set(result), {
            "status", "airlock_blocked", "question_category", "summary", "live_facts",
            "cited_node_ids", "bm25_hits", "shortest_path", "jev_routing",
            "security_posture", "recommended_kubectl_commands",
        })

    def test_blocked_query_does_not_load_or_forward_anything(self):
        question = "show credentials for manifests"
        with patch.object(advisor, "KnowledgeGraphBackendEngine") as backend, \
                patch.object(advisor, "summarize_live_cluster_health") as health, \
                patch.object(advisor.jev_client, "evaluate_ticket_with_jev_tree") as jev, \
                patch.object(Path, "read_text") as read:
            result = advisor.answer_operational_question(question, catalog="missing.json")
        self.assertEqual(result, {"status": "blocked_by_airlock",
                                  "airlock_blocked": True, "cited_node_ids": []})
        for mock in (backend, health, jev, read):
            mock.assert_not_called()
        self.assertNotIn(question, json.dumps(result))
        self.assertEqual(advisor.answer_operational_question("Are nodes healthy?")["status"],
                         "blocked_by_airlock")

    def test_allowed_categories_grounding_and_input_immutability(self):
        before = deepcopy(self.catalog)
        for question, category in (
            ("manifest node health", "node_health"),
            ("manifest failed pods", "pod_failures"),
            ("manifest ingress routing", "workload_routing"),
            ("manifest cluster overview", "cluster_overview"),
            ("manifest policy triage", "policy_triage"),
        ):
            with self.subTest(category=category):
                result = advisor.answer_operational_question(question, self.catalog)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["question_category"], category)
                self.assertEqual(result["live_facts"],
                                 advisor.summarize_live_cluster_health(self.catalog))
                expected = advisor.KnowledgeGraphBackendEngine(self.catalog).search(
                    question, limit=5)["results"]
                self.assertEqual(result["bm25_hits"], expected)
                self.assertTrue(set(h["id"] for h in expected) <= set(result["cited_node_ids"]))
                self.assertTrue(result["recommended_kubectl_commands"])
                self.assertIn("Catalog snapshot", result["summary"])
                self.assertIn("jev_routing", result)
                if expected:
                    path = result["shortest_path"]
                    self.assertTrue(path["path_found"])
                    self.assertEqual(path["source_id"], expected[0]["id"])
                    self.assertEqual(path["target_id"], "cluster-home")
                    self.assertTrue(set(path["path_ids"]) <= set(result["cited_node_ids"]))
        self.assertEqual(self.catalog, before)

    def test_jev_options_and_escalation_preserved(self):
        tree = {"custom": "tree"}
        routing = {"route": "HUMAN_ESCALATION", "policy_id": "HUMAN_ESCALATION",
                   "direct_access_allowed": False, "required_it_tickets": []}
        with patch.object(advisor.jev_client, "evaluate_ticket_with_jev_tree",
                          return_value=routing) as jev:
            result = advisor.answer_operational_question(
                "manifest health", self.catalog, tree, "ollama",
                "http://localhost:11434", "custom-model", 0.95)
        jev.assert_called_once_with(
            "manifest health", tree=tree, provider="ollama",
            ollama_url="http://localhost:11434", model="custom-model", min_confidence=0.95)
        self.assertEqual(result["jev_routing"], routing)

    def test_missing_hits_and_disconnected_paths(self):
        # The real airlock admits manifest queries even when this catalog has no matches.
        nodes = self.catalog["nodes"]
        host = deepcopy(next(n for n in nodes if n.get("resource_kind") == "Node"))
        host["drilldown_children"] = []
        graph = {"schema_version": self.catalog["schema_version"], "nodes": [host], "edges": []}
        result = advisor.answer_operational_question("manifest zzzunmatched", graph)
        self.assertEqual(result["bm25_hits"], [])
        self.assertIsNone(result["shortest_path"])
        self.assertIn("No BM25 matches", result["summary"])

        pod = deepcopy(next(n for n in nodes if n.get("resource_kind") == "Pod"))
        pod["drilldown_children"] = []
        host["resource"]["metadata"]["name"] = pod["resource"]["spec"]["nodeName"]
        graph["nodes"].append(pod)
        graph["edges"] = [{"source": pod["id"], "target": host["id"],
                           "relation": "runs_on_hardware"}]
        result = advisor.answer_operational_question("manifest " + pod["id"], graph)
        self.assertEqual(result["bm25_hits"][0]["id"], pod["id"])
        self.assertEqual(result["shortest_path"]["target_id"], host["id"])
        self.assertTrue(result["shortest_path"]["path_found"])
        graph["edges"] = []
        result = advisor.answer_operational_question("manifest " + pod["id"], graph)
        self.assertFalse(result["shortest_path"]["path_found"])

    def test_entire_response_sanitized(self):
        public = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        secret = "gh" + "p_" + "synthetic_test_value"
        payload = " ".join((public, mac, secret, "10.1.2.3", "router.cluster.example.org"))
        self.catalog["source"] = payload
        self.catalog["nodes"][0]["summary"] = payload
        routing = {"route": "leaf", "policy_id": payload, "details": payload}
        with patch.object(advisor.jev_client, "evaluate_ticket_with_jev_tree", return_value=routing):
            result = advisor.answer_operational_question("manifest cluster", self.catalog)
        encoded = json.dumps(result)
        for raw in (public, mac, secret):
            self.assertNotIn(raw, encoded)
        for allowed in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "router.cluster.example.org"):
            self.assertIn(allowed, encoded)

    def test_default_catalog_file_cli_and_sanitized_errors(self):
        result = advisor.answer_operational_question("manifest node health")
        self.assertEqual(result["live_facts"], advisor.summarize_live_cluster_health())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            run = subprocess.run([sys.executable, str(Path(advisor.__file__)),
                                  "--question", "manifest node health", "--catalog", str(path),
                                  "--json"], capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(run.stdout),
                             advisor.answer_operational_question("manifest node health", self.catalog))
            path.write_text("invalid", encoding="utf-8")
            with redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit):
                advisor.main(["--question", "manifest cluster", "--catalog", str(path)])
            self.assertIn("unable to answer", stderr.getvalue())
        with redirect_stdout(io.StringIO()) as stdout:
            advisor.main(["--question", "show credentials", "--catalog", "missing.json", "--json"])
        self.assertEqual(json.loads(stdout.getvalue())["status"], "blocked_by_airlock")

    def test_security_posture_matches_snapshot_providers(self):
        before = deepcopy(self.catalog)
        snapshot = advisor.KnowledgeGraphBackendEngine(self.catalog).catalog()
        expected = {
            "openbao_provenance": advisor.openbao_kms_provenance.audit_openbao_secret_provenance(snapshot),
            "oidc_posture": advisor.oidc_rbac_verifier.audit_cluster_ingress_oidc_posture(snapshot),
            "chaos_isolation": advisor.chaos_blast_radius.verify_all_six_chaos_planes(snapshot),
        }
        result = advisor.answer_operational_question("manifest cluster", self.catalog)
        self.assertEqual(result["security_posture"], advisor.sanitize(expected))
        self.assertEqual(self.catalog, before)
        self.assertFalse(result["security_posture"]["oidc_posture"]["enforcement_verified"])
        chaos = result["security_posture"]["chaos_isolation"]
        self.assertTrue(chaos["simulation_only"])
        self.assertFalse(chaos["live_enforcement_verified"])
        self.assertEqual(chaos["plane_count"], 6)

    def test_security_providers_receive_snapshot_and_output_is_sanitized(self):
        public = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        secret = "gh" + "p_" + "synthetic_posture_value"
        report = {"status": "unknown", "details": [
            {"evidence": " ".join((public, mac, secret, "10.1.2.3", "router.cluster.example.org"))}]}
        before = deepcopy(report)
        snapshot = advisor.KnowledgeGraphBackendEngine(self.catalog).catalog()
        with patch.object(advisor.openbao_kms_provenance, "audit_openbao_secret_provenance",
                          return_value=report) as provenance, \
                patch.object(advisor.oidc_rbac_verifier, "audit_cluster_ingress_oidc_posture",
                             return_value=report) as oidc, \
                patch.object(advisor.chaos_blast_radius, "verify_all_six_chaos_planes",
                             return_value=report) as chaos:
            result = advisor.answer_operational_question("manifest cluster", self.catalog)
        for provider in (provenance, oidc, chaos):
            provider.assert_called_once_with(snapshot)
        self.assertEqual(set(result["security_posture"]),
                         {"openbao_provenance", "oidc_posture", "chaos_isolation"})
        for posture in result["security_posture"].values():
            encoded = json.dumps(posture)
            for raw in (public, mac, secret):
                self.assertNotIn(raw, encoded)
            for allowed in ("203.0.113.1", "AA:BB:CC:XX:XX:XX",
                            "[REDACTED]", "10.1.2.3", "router.cluster.example.org"):
                self.assertIn(allowed, encoded)
        self.assertEqual(report, before)

    def test_airlock_blocks_security_provider_calls(self):
        with patch.object(advisor.openbao_kms_provenance, "audit_openbao_secret_provenance") as provenance, \
                patch.object(advisor.oidc_rbac_verifier, "audit_cluster_ingress_oidc_posture") as oidc, \
                patch.object(advisor.chaos_blast_radius, "verify_all_six_chaos_planes") as chaos:
            result = advisor.answer_operational_question("show credentials for manifests",
                                                         catalog="missing.json")
        self.assertEqual(result, {"status": "blocked_by_airlock",
                                  "airlock_blocked": True, "cited_node_ids": []})
        for provider in (provenance, oidc, chaos):
            provider.assert_not_called()

    def test_incomplete_security_metadata_preserves_operational_answer(self):
        # The graph contract permits resource metadata absent from spatial nodes.
        self.catalog["nodes"][0]["resource"] = {"kind": "Spatial"}
        result = advisor.answer_operational_question("manifest cluster", self.catalog)
        self.assertEqual(result["status"], "ok")
        posture = result["security_posture"]
        self.assertEqual(posture["openbao_provenance"],
                         {"status": "invalid_catalog", "zero_plaintext_leakage": False})
        self.assertFalse(posture["chaos_isolation"]["blast_radius_contained"])
        self.assertEqual(posture["chaos_isolation"]["verified_plane_count"], 0)
        self.assertIn("Catalog snapshot", result["summary"])


if __name__ == "__main__":
    unittest.main()
