# SPDX-License-Identifier: Apache-2.0
"""Grounded offline fault propagation, containment and CLI checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

import chaos_blast_radius as chaos


def fixture():
    nodes = [{"id": "hardware", "resource": {
        "kind": "Node", "metadata": {"name": "fixture-hardware"}}}]
    edges = []
    for plane, namespaces in chaos.PLANE_NAMESPACES.items():
        ns = namespaces[0]
        nodes.append({"id": "namespace/" + plane, "resource": {
            "kind": "Namespace", "metadata": {"name": ns}}})
        for suffix in ("seed", "dependent"):
            identity = plane + "/" + suffix
            nodes.append({"id": identity, "resource": {"kind": "Pod",
                "metadata": {"name": suffix, "namespace": ns}}})
            edges.append({"source": identity, "target": "hardware",
                          "relation": "runs_on_hardware"})
        edges.append({"source": plane + "/seed", "target": plane + "/dependent",
                      "relation": "owns_workload"})
    edges.extend([
        {"source": "ai_gpu_plane/dependent", "target": "storage_plane/seed",
         "relation": "routes_to"},
        {"source": "ai_gpu_plane/seed", "target": "household_gaming_plane/seed",
         "relation": "routes_to"},
    ])
    return {"nodes": nodes, "edges": edges}


class ChaosTests(unittest.TestCase):
    def test_each_plane_propagates_locally_and_preserves_other_five(self):
        data = fixture()
        for plane in chaos.PLANES:
            with self.subTest(plane=plane):
                report = chaos.simulate_six_plane_chaos_fault(plane, data)
                self.assertTrue(report["blast_radius_contained"])
                self.assertEqual(len(report["injected_node_indexes"]), 1)
                self.assertEqual(len(report["affected_node_indexes"]), 2)
                self.assertEqual(report["escaped_node_indexes"], [])
                self.assertEqual(set(report["unaffected_planes"]), set(chaos.PLANES) - {plane})
                for indexes in report["unaffected_planes"].values():
                    self.assertEqual(len(indexes), 3)
                    self.assertTrue(set(indexes).isdisjoint(report["affected_node_indexes"]))
                self.assertEqual(report["shared_hardware_node_indexes"], [0])
                self.assertTrue(report["simulation_only"])
                self.assertFalse(report["live_enforcement_verified"])

    def test_cross_plane_and_unclassified_edges_are_blocked(self):
        data = fixture()
        data["nodes"].append({"id": "unknown", "resource": {"kind": "Service",
            "metadata": {"name": "unknown", "namespace": "unclassified"}}})
        data["edges"].append({"source": "unknown", "target": "ai_gpu_plane/seed",
                              "relation": "routes_to"})
        report = chaos.simulate_six_plane_chaos_fault("ai_gpu_plane", data)
        self.assertEqual(len(report["blocked_cross_plane_edges"]), 3)
        blocked_targets = {e["target_index"] for e in report["blocked_cross_plane_edges"]}
        self.assertIn(len(data["nodes"]) - 1, blocked_targets)
        self.assertTrue(blocked_targets.isdisjoint(report["affected_node_indexes"]))

    def test_disconnected_workload_is_not_affected_by_routing_fault(self):
        data = fixture()
        data["edges"] = [e for e in data["edges"] if e["relation"] != "owns_workload"]
        report = chaos.simulate_six_plane_chaos_fault("control_plane", data)
        self.assertEqual(report["affected_node_indexes"], report["injected_node_indexes"])

    def test_missing_evidence_cannot_pass_vacuously(self):
        for data in ({"nodes": []},
                     {"nodes": [n for n in fixture()["nodes"]
                                if n["resource"]["kind"] != "Pod"]},
                     {"nodes": [n for n in fixture()["nodes"]
                                if n["resource"]["kind"] != "Node"]},
                     {"nodes": [n for n in fixture()["nodes"]
                                if n["id"] != "namespace/storage_plane"]}):
            with self.subTest(data_size=len(data["nodes"])):
                report = chaos.verify_all_six_chaos_planes(data)
                self.assertFalse(report["blast_radius_contained"])
                self.assertEqual(report["verified_plane_count"], 0)

    def test_invalid_catalogs_fail_closed_without_echo(self):
        cases = [[], {}, {"nodes": [None]}, {"nodes": [{}]},
                 {"nodes": [{"id": "x", "resource": []}]},
                 {"nodes": [{"id": "x", "resource": {"kind": "Pod", "metadata": []}}]},
                 {"nodes": [], "edges": {}}, {"nodes": [], "edges": [None]},
                 {"nodes": [], "edges": [{"source": "private-value", "target": "x",
                                           "relation": "routes_to"}]},
                 {"nodes": [], "extra": float("nan")}, Path("missing-private-value.json")]
        duplicate = fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        cases.append(duplicate)
        conflicting = fixture()
        conflicting["nodes"][2]["namespace"] = "private-value"
        cases.append(conflicting)
        for data in cases:
            report = chaos.simulate_six_plane_chaos_fault("ai_gpu_plane", data)
            self.assertEqual(report["status"], "invalid_catalog")
            self.assertFalse(report["blast_radius_contained"])
            self.assertNotIn("private-value", json.dumps(report))
            all_report = chaos.verify_all_six_chaos_planes(data)
            self.assertEqual(all_report["verified_plane_count"], 0)

    def test_invalid_plane_is_rejected_without_echo(self):
        for plane in (None, [], {}, "unknown-private-value", "AI_GPU_PLANE"):
            with self.assertRaisesRegex(ValueError, "^Unsupported chaos plane$"):
                chaos.simulate_six_plane_chaos_fault(plane, fixture())

    def test_determinism_no_mutation_or_arbitrary_metadata_echo(self):
        data = fixture()
        data["nodes"][2]["resource"]["metadata"]["name"] = "private-value"
        data["nodes"][2]["resource"]["spec"] = {"private-field": "private-value"}
        before = deepcopy(data)
        first = chaos.verify_all_six_chaos_planes(data)
        self.assertEqual(first, chaos.verify_all_six_chaos_planes(data))
        self.assertEqual(data, before)
        self.assertNotIn("private-value", json.dumps(first))
        first["planes"]["control_plane"]["affected_node_indexes"].clear()
        self.assertTrue(chaos.verify_all_six_chaos_planes(data)["planes"]
                        ["control_plane"]["affected_node_indexes"])

    def test_bundled_catalog_all_six_planes_are_grounded(self):
        data = json.loads(chaos.DEFAULT_CATALOG.read_text(encoding="utf-8"))
        before = deepcopy(data)
        report = chaos.verify_all_six_chaos_planes(data)
        self.assertTrue(report["blast_radius_contained"])
        self.assertEqual(report["verified_plane_count"], 6)
        self.assertEqual(report, chaos.verify_all_six_chaos_planes())
        for plane, result in report["planes"].items():
            self.assertEqual(len(result["hardware_node_indexes"]), 3)
            self.assertTrue(result["observed_namespaces"])
            for index in result["affected_node_indexes"]:
                self.assertIn(data["nodes"][index]["resource"]["metadata"]["namespace"],
                              chaos.PLANE_NAMESPACES[plane])
        self.assertEqual(data, before)

    def test_path_and_cli_success_failure_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(fixture()), encoding="utf-8")
            self.assertEqual(chaos.verify_all_six_chaos_planes(path),
                             chaos.verify_all_six_chaos_planes(str(path)))
            for mode in (["--verify-all"], ["--plane", "ai_gpu_plane"]):
                stream = io.StringIO()
                with redirect_stdout(stream):
                    code = chaos.main(mode + ["--catalog", str(path), "--json"])
                self.assertEqual(code, 0)
                self.assertTrue(json.loads(stream.getvalue())["blast_radius_contained"])
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(chaos.main(mode + ["--catalog", str(path)]), 0)
            path.write_text("malformed-private-value", encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(chaos.main(["--verify-all", "--catalog", str(path), "--json"]), 1)
            self.assertNotIn("private-value", stream.getvalue())
        for args in ([], ["--plane", "unknown"], ["--plane", "storage_plane", "--verify-all"]):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                chaos.main(args)
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
