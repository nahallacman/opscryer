# SPDX-License-Identifier: Apache-2.0
"""Offline drain placement, disruption and input boundary checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import capacity_planner as planner
from golden_path_gates import _opsec_count

from capacity_planner import (
    audit_workload_resource_requests,
    estimate_cluster_power_and_gpu_headroom,
    simulate_node_drain,
)


def fixture():
    nodes = []
    for name, ready in (("nodebeta02", "True"), ("worker", "True"),
                        ("unready", "Unknown")):
        nodes.append({"id": name, "resource": {"kind": "Node",
            "metadata": {"name": name, "labels": {"kubernetes.io/hostname": name}},
            "status": {"conditions": [{"type": "Ready", "status": ready}],
                       "allocatable": {"cpu": "2", "memory": "2Gi", "pods": "10"}}}})
    return {"nodes": nodes, "edges": []}


def pod(name, host="nodebeta02", owner="ReplicaSet", cpu="500m"):
    return {"id": name, "resource": {"kind": "Pod", "metadata": {
        "name": name, "namespace": "test", "ownerReferences": [
            {"kind": owner, "name": "app"}]}, "spec": {
        "nodeName": host, "containers": [{"resources": {"requests": {
            "cpu": cpu, "memory": "128Mi"}}}]}, "status": {"phase": "Running"}}}


class NodeDrainTests(unittest.TestCase):
    def test_resident_requests_and_sequential_bin_packing(self):
        data = fixture()
        data["nodes"] += [pod("resident", "worker", cpu="1"),
                          pod("a", cpu="750m"), pod("b", cpu="750m")]
        original = deepcopy(data)
        result = simulate_node_drain(catalog=data)
        self.assertEqual(data, original)
        self.assertEqual(result["surviving_ready_nodes"], ["worker"])
        self.assertEqual(result["evicted_pod_count"], 2)
        self.assertEqual(result["reschedulable_count"], 1)
        self.assertEqual(result["at_risk_workloads"][0]["pod_id"], "b")
        self.assertTrue(result["simulation_only"])
        self.assertEqual(result, simulate_node_drain(catalog=data))

    def test_edges_deduplicate_placement_and_exclude_terminal_pods(self):
        data = fixture()
        active, terminal = pod("a"), pod("terminal")
        del active["resource"]["spec"]["nodeName"]
        terminal["resource"]["status"]["phase"] = "Succeeded"
        data["nodes"] += [active, terminal]
        edge = {"source": "a", "target": "nodebeta02", "relation": "runs_on_hardware"}
        data["edges"] = [edge, deepcopy(edge)]
        result = simulate_node_drain(catalog=data)
        self.assertEqual(result["evicted_pod_count"], 1)
        self.assertEqual(result["reschedulable_count"], 1)
        self.assertIn("single_replica_observed", result["at_risk_workloads"][0]["reasons"])

    def test_daemonset_stateful_and_pinned_workloads_are_at_risk(self):
        data = fixture()
        pinned = pod("pinned")
        pinned["resource"]["spec"]["nodeSelector"] = {
            "kubernetes.io/hostname": "nodebeta02"}
        data["nodes"] += [pod("daemon", owner="DaemonSet"),
                          pod("stateful", owner="StatefulSet"), pinned]
        result = simulate_node_drain(catalog=data)
        self.assertEqual(result["reschedulable_count"], 0)
        self.assertEqual(len(result["at_risk_workloads"]), 3)
        self.assertEqual(result["blast_radius_status"], "at_risk")

    def test_no_ready_survivor(self):
        data = fixture()
        data["nodes"][1]["resource"]["status"]["conditions"] = []
        data["nodes"].append(pod("a"))
        result = simulate_node_drain(catalog=data)
        self.assertEqual(result["surviving_ready_nodes"], [])
        self.assertEqual(result["reschedulable_count"], 0)

    def test_missing_capacity_is_provisional(self):
        data = fixture()
        del data["nodes"][1]["resource"]["status"]["allocatable"]
        data["nodes"].append(pod("a"))
        result = simulate_node_drain(catalog=data)
        self.assertEqual(result["reschedulable_count"], 1)
        self.assertIn("capacity_evidence_incomplete", result["at_risk_workloads"][0]["reasons"])

    def test_cordon_taints_and_extended_resources_block_placement(self):
        for constraint in ("cordon", "taint", "gpu", "memory", "init"):
            with self.subTest(constraint=constraint):
                data = fixture()
                workload = pod("a")
                worker = data["nodes"][1]["resource"]
                if constraint == "cordon":
                    worker["spec"] = {"unschedulable": True}
                elif constraint == "taint":
                    worker["spec"] = {"taints": [{"key": "dedicated", "effect": "NoSchedule"}]}
                elif constraint in ("gpu", "memory"):
                    requests = workload["resource"]["spec"]["containers"][0]["resources"]["requests"]
                    requests.update({"nvidia.com/gpu": "1"} if constraint == "gpu"
                                    else {"memory": "3Gi"})
                else:
                    workload["resource"]["spec"]["initContainers"] = [
                        {"resources": {"requests": {"cpu": "3", "memory": "128Mi"}}}]
                data["nodes"].append(workload)
                self.assertEqual(simulate_node_drain(catalog=data)["reschedulable_count"], 0)

    def test_replicated_workload_with_known_headroom_has_no_identified_disruption(self):
        data = fixture()
        data["nodes"] += [pod("a"), pod("b", host="worker")]
        result = simulate_node_drain(catalog=data)
        self.assertEqual(result["reschedulable_count"], 1)
        self.assertEqual(result["at_risk_workloads"], [])
        self.assertEqual(result["blast_radius_status"], "no_disruption_identified")

    def test_invalid_names_never_echo_input(self):
        for value in (None, 1, [], {}, "", "unknown-private-name", "bad/name", "x..y"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError) as caught:
                    simulate_node_drain(value, fixture())
                self.assertEqual(str(caught.exception), "Invalid or unknown hardware node")


class PowerAndGPUHeadroomTests(unittest.TestCase):
    def test_modes_keep_exclusive_vram_and_conservative_power_budget(self):
        for mode, allocation in (("hybrid_balanced", (16, 18)),
                                 ("ai_swarm", (34, 0)), ("gaming_lan", (0, 34))):
            with self.subTest(mode=mode):
                result = estimate_cluster_power_and_gpu_headroom(mode, fixture())
                self.assertEqual(result["workload_capacity_gb"],
                                 dict(zip(("ai_swarm", "gaming_lan"), allocation)))
                self.assertEqual(result["total_vram_gb"], 34)
                self.assertFalse(result["vram_pooled"])
                self.assertTrue(all(gpu["exclusive"] for gpu in result["gpus"]))
                self.assertTrue(all(gpu["free_vram_gb"] is None for gpu in result["gpus"]))
                budget = result["power_thermal_budget"]
                self.assertEqual(budget["gpu_power_budget_watts"], 900)
                self.assertAlmostEqual(budget["gpu_heat_output_btu_per_hour"], 3070.93)
                self.assertIsNone(budget["cluster_total_power_watts"])
                self.assertIsNone(budget["cooling_headroom_watts"])
                json.dumps(result, allow_nan=False)

    def test_snapshot_headroom_unknowns_and_readiness(self):
        data = fixture()
        data["nodes"][0]["metrics"] = {"cpu_percent": 25.25, "ram_percent": 100}
        data["nodes"][1]["metrics"] = {"cpu_percent": 125, "ram_percent": -1}
        data["nodes"][2]["metrics"] = {"cpu_percent": True, "ram_percent": float("nan")}
        result = estimate_cluster_power_and_gpu_headroom(catalog=data)
        nodes = {node["name"]: node for node in result["nodes"]}
        self.assertEqual(nodes["nodebeta02"]["cpu_headroom_percent"], 74.75)
        self.assertEqual(nodes["nodebeta02"]["ram_headroom_percent"], 0)
        self.assertEqual(nodes["worker"]["cpu_headroom_percent"], 0)
        self.assertIsNone(nodes["worker"]["ram_headroom_percent"])
        self.assertFalse(nodes["unready"]["ready"])
        self.assertIsNone(nodes["unready"]["cpu_headroom_percent"])
        self.assertIsNone(nodes["unready"]["ram_headroom_percent"])
        self.assertEqual(estimate_cluster_power_and_gpu_headroom(catalog={"nodes": []})
                         ["nodes"], [])

    def test_sanitized_deterministic_and_no_input_mutation(self):
        data = fixture()
        sensitive = "gh" + "p_" + "examplecredential"
        data["source"] = sensitive
        original = deepcopy(data)
        result = estimate_cluster_power_and_gpu_headroom(catalog=data)
        self.assertEqual(data, original)
        self.assertNotIn(sensitive, json.dumps(result))
        self.assertEqual(result["provenance"]["source"], "[REDACTED]")
        data["nodes"].reverse()
        self.assertEqual(result, estimate_cluster_power_and_gpu_headroom(catalog=data))
        result["gpus"][0]["vram_gb"] = 0
        self.assertEqual(estimate_cluster_power_and_gpu_headroom(catalog=data)
                         ["gpus"][0]["vram_gb"], 16)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            from_file = estimate_cluster_power_and_gpu_headroom(catalog=path)
        self.assertEqual(from_file["nodes"], result["nodes"])
        self.assertEqual(from_file["provenance"]["input_kind"], "json_file")

    def test_default_snapshot_and_invalid_inputs(self):
        self.assertEqual(estimate_cluster_power_and_gpu_headroom()["mode"], "hybrid_balanced")
        for mode in (None, True, [], {}, "unknown"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                estimate_cluster_power_and_gpu_headroom(mode, fixture())
        with self.assertRaises(ValueError):
            estimate_cluster_power_and_gpu_headroom(catalog={})


class ResourceAuditTests(unittest.TestCase):
    def test_container_coverage_and_deployment_templates(self):
        complete = {"requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "1", "memory": "128Mi"}}
        bounded = pod("bounded")
        bounded["resource"]["spec"]["containers"] = [{"resources": deepcopy(complete)}]
        partial = deepcopy(bounded)
        partial["id"] = "partial"
        partial["resource"]["spec"]["containers"].append({"resources": {
            "requests": {"cpu": "100m"}, "limits": complete["limits"]}})
        deployment = {"id": "deployment", "resource_kind": "Deployment", "resource": {
            "metadata": {"namespace": "apps"}, "spec": {"replicas": 3, "template": {
                "spec": {"containers": [{"resources": deepcopy(complete)}],
                         "initContainers": [{"resources": {"requests": complete["requests"]}}]}}}}}
        data = {"nodes": [bounded, partial, deployment, {"id": "service", "resource_kind": "Service"}]}
        original = deepcopy(data)
        result = audit_workload_resource_requests(data)
        self.assertEqual(data, original)
        self.assertEqual(result["workloads_inspected"], 3)
        self.assertEqual(result["fully_bounded_count"], 1)
        self.assertEqual(result["missing_requests_count"], 1)
        self.assertEqual(result["missing_limits_count"], 1)
        recommendations = result["right_sizing_recommendations"]
        self.assertEqual(recommendations[0]["missing_limits"],
                         ["initContainers[0].cpu", "initContainers[0].memory"])
        self.assertEqual(recommendations[1]["missing_requests"], ["containers[1].memory"])
        self.assertEqual(result["top_namespaces_by_pod_count"],
                         [{"namespace": "test", "pod_count": 2}])

    def test_ranking_ties_terminal_pods_and_order_independence(self):
        data = {"nodes": [pod("c"), pod("a"), pod("b")]}
        data["nodes"][0]["resource"]["metadata"]["namespace"] = "alpha"
        data["nodes"][0]["resource"]["status"]["phase"] = "Succeeded"
        data["nodes"][1]["resource"]["metadata"]["namespace"] = "beta"
        del data["nodes"][2]["resource"]["metadata"]["namespace"]
        result = audit_workload_resource_requests(data)
        self.assertEqual([row["namespace"] for row in result["top_namespaces_by_pod_count"]],
                         ["alpha", "beta", "default"])
        data["nodes"].reverse()
        self.assertEqual(result, audit_workload_resource_requests(data))

    def test_empty_missing_and_invalid_resource_declarations(self):
        empty = audit_workload_resource_requests({"nodes": []})
        self.assertEqual(empty["workloads_inspected"], 0)
        self.assertEqual(empty["right_sizing_recommendations"], [])
        for spec in ({}, {"containers": []}, {"containers": None},
                     {"containers": [{"resources": None}]},
                     {"containers": [{"resources": {"requests": {
                         "cpu": "invalid", "memory": -1}}}]}):
            with self.subTest(spec=spec):
                result = audit_workload_resource_requests({"nodes": [
                    {"id": "a", "resource_kind": "Pod", "resource": {"spec": spec}}]})
                self.assertEqual(result["fully_bounded_count"], 0)
                self.assertEqual(result["missing_requests_count"], 1)
                self.assertEqual(result["missing_limits_count"], 1)

    def test_recommendations_and_rankings_are_sanitized(self):
        sensitive = "gh" + "p_" + "examplecredential"
        workload = pod("a")
        workload["resource"]["metadata"].update(name=sensitive, namespace=sensitive)
        result = audit_workload_resource_requests({"nodes": [workload]})
        self.assertEqual(result["right_sizing_recommendations"][0]["name"], "[REDACTED]")
        self.assertEqual(result["top_namespaces_by_pod_count"][0]["namespace"], "[REDACTED]")


class CapacitySummaryTests(unittest.TestCase):
    def test_counts_quantities_provenance_and_unknown_assignments(self):
        data = fixture()
        data.update(source="synthetic.cluster.example.org", collected_at="2026-10-30T00:00:00Z")
        data["nodes"][0]["metrics"] = {"cpu_percent": 25, "ram_percent": -1,
                                      "cpu_used": "500m", "ram_used": "128Mi"}
        data["nodes"][0]["resource"]["status"]["capacity"] = {"cpu": "4", "memory": "4Gi"}
        data["nodes"] += [pod("a"), pod("b", "worker"), pod("c", "absent"), pod("d", "")]
        data["nodes"][-1]["resource"]["status"]["phase"] = "Succeeded"
        before = deepcopy(data)
        result = planner.summarize_cluster_capacity(data)
        self.assertEqual(result["node_counts"], {"total": 3, "ready": 2, "not_ready": 1})
        self.assertEqual(result["pod_counts"], {"total": 4, "assigned": 3, "unassigned": 1})
        self.assertEqual(result["pods_per_node"],
                         {"nodebeta02": 1, "worker": 1, "unready": 0, "absent": 1})
        self.assertEqual(result["pods_per_namespace"], {"test": 4})
        self.assertEqual(result["pods_by_phase"], {"Running": 3, "Succeeded": 1})
        self.assertEqual(result["unknown_assignment_nodes"], ["absent"])
        self.assertEqual(result["missing_hardware_nodes"], ["nodealpha01", "nodegamma03"])
        node = result["nodes"][0]
        self.assertEqual(node["capacity"], {"cpu": "4", "memory": "4Gi"})
        self.assertEqual(node["allocatable"], {"cpu": "2", "memory": "2Gi"})
        self.assertEqual(node["metrics"], {"cpu_percent": 25, "ram_percent": None,
                                          "cpu_used": "500m", "ram_used": "128Mi"})
        self.assertEqual(result["provenance"]["collected_at"], data["collected_at"])
        self.assertFalse(result["provenance"]["live_collection"])
        self.assertEqual(data, before)
        data["nodes"].reverse()
        self.assertEqual(result, planner.summarize_cluster_capacity(data))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            for value in (path, str(path)):
                loaded = planner.summarize_cluster_capacity(value)
                self.assertEqual(loaded["nodes"], result["nodes"])
                self.assertEqual(loaded["provenance"]["input_kind"], "json_file")

    def test_empty_unknown_metrics_and_invalid_catalogs(self):
        empty = planner.summarize_cluster_capacity({"nodes": []})
        self.assertEqual(empty["node_counts"], {"total": 0, "ready": 0, "not_ready": 0})
        self.assertEqual(empty["missing_hardware_nodes"], sorted(planner.HARDWARE_NODES))
        self.assertIsNone(empty["provenance"]["collected_at"])
        data = fixture()
        data["nodes"][0]["metrics"] = {"cpu_percent": True, "ram_percent": float("inf")}
        self.assertTrue(all(value is None for value in
                            planner.summarize_cluster_capacity(data)["nodes"][0]["metrics"].values()))
        duplicate = fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        for invalid in ({}, [], {"nodes": {}}, {"nodes": [{"id": ""}]}, duplicate):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                planner.summarize_cluster_capacity(invalid)

    def test_bundled_summary_and_drain_for_each_hardware_node(self):
        summary = planner.summarize_cluster_capacity()
        self.assertEqual({node["name"] for node in summary["nodes"]}, set(planner.HARDWARE_NODES))
        self.assertEqual(summary["missing_hardware_nodes"], [])
        self.assertGreater(summary["pod_counts"]["total"], 0)
        self.assertEqual(summary["provenance"]["snapshot_file"], "live-cluster-sanitized.json")
        for name in planner.HARDWARE_NODES:
            with self.subTest(node=name):
                result = planner.simulate_node_drain(name)
                self.assertEqual(result["target_node"], name)
                self.assertTrue(result["simulation_only"])
                self.assertEqual(result["surviving_ready_nodes"], sorted(
                    node["name"] for node in summary["nodes"] if node["ready"] and node["name"] != name))
                self.assertGreater(result["evicted_pod_count"], 0)
                self.assertLessEqual(result["reschedulable_count"], result["evicted_pod_count"])
                self.assertEqual(_opsec_count(json.dumps(result).encode()), 0)

    def test_each_hardware_node_evacuates_only_its_active_pods(self):
        data = {"nodes": [], "edges": []}
        for name in planner.HARDWARE_NODES:
            node = deepcopy(fixture()["nodes"][0])
            node["id"] = node["resource"]["metadata"]["name"] = name
            data["nodes"] += [node, pod("app-" + name, name)]
        before = deepcopy(data)
        for name in planner.HARDWARE_NODES:
            with self.subTest(node=name):
                result = planner.simulate_node_drain(name, data)
                self.assertEqual(result["evicted_pod_count"], 1)
                self.assertEqual(result["reschedulable_count"], 1)
                self.assertEqual(result["at_risk_workloads"], [])
                self.assertEqual(result["surviving_ready_nodes"], sorted(set(planner.HARDWARE_NODES) - {name}))
        self.assertEqual(data, before)


class CapacityHTMLTests(unittest.TestCase):
    def test_navigation_dom_safety_and_embedded_evidence(self):
        tags = []

        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                tags.append((tag, dict(attrs)))

        data = fixture()
        attack = '</script><img src=x onerror="alert(1)"> & evidence'
        data["source"] = attack
        html = planner.render_capacity_planner_html(data)
        Parser().feed(html)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertNotIn(attack, html)
        self.assertFalse(any(tag == "img" for tag, _ in tags))
        self.assertEqual(sum(tag == "script" for tag, _ in tags), 2)
        self.assertTrue({"/", "/chat", "/incidents", "/capacity"} <= {
            attrs.get("href") for tag, attrs in tags if tag == "a"})
        ids = [attrs["id"] for _, attrs in tags if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for identity in re.findall(r'getElementById\("([^"]+)"\)', html):
            self.assertIn(identity, ids)
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(unsafe, html)
        self.assertFalse(any("src" in attrs for tag, attrs in tags if tag == "script"))
        self.assertFalse(any(key.startswith("on") for _, attrs in tags for key in attrs))
        payload = re.search(r'<script id="capacity-data" type="application/json">(.*?)</script>',
                            html, re.DOTALL).group(1)
        self.assertFalse(any(character in payload for character in "<>&"))
        evidence = json.loads(payload)
        self.assertEqual(evidence["summary"]["source"], attack)
        self.assertEqual(evidence["audit"], planner.audit_workload_resource_requests(data))
        self.assertEqual(evidence["power"], planner.estimate_cluster_power_and_gpu_headroom(catalog=data))
        self.assertEqual(evidence["drains"], [planner.simulate_node_drain(node["name"], data)
                                             for node in evidence["summary"]["nodes"]])

    def test_empty_html_has_no_scenarios(self):
        html = planner.render_capacity_planner_html({"nodes": []})
        self.assertIn('"drains": []', html)
        self.assertIn("select.disabled = data.drains.length === 0", html)


class CapacityCLITests(unittest.TestCase):
    def invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = planner.main(argv)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(_opsec_count(stdout.getvalue().encode()), 0)
        return stdout.getvalue()

    def test_default_json_markdown_and_drain_flags_with_catalog(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            args = ["--catalog", str(path)]
            default = json.loads(self.invoke(args))
            self.assertEqual(default, json.loads(self.invoke(args + ["--json"])))
            self.assertEqual(set(default), {"summary", "audit", "power"})
            self.assertEqual(default["summary"]["nodes"], planner.summarize_cluster_capacity(data)["nodes"])
            drain = json.loads(self.invoke(args + ["--json", "--drain-node", "nodebeta02"]))
            self.assertEqual(drain, planner.simulate_node_drain(catalog=data))
            self.assertEqual(self.invoke(args + ["--markdown"]), planner.render_capacity_markdown(path))

    def test_serve_defaults_and_custom_port_bind_loopback(self):
        for options, port in (([], 8091), (["--port", "8123"], 8123)):
            with self.subTest(port=port), patch.object(planner, "ThreadingHTTPServer") as server:
                running = server.return_value.__enter__.return_value
                running.serve_forever.side_effect = KeyboardInterrupt
                self.assertIn(f"http://127.0.0.1:{port}", self.invoke(["--serve"] + options))
                self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                running.serve_forever.assert_called_once_with()
                server.return_value.__exit__.assert_called_once()

    def test_invalid_flags_and_node_fail_without_echoing_input(self):
        for argv in (["--json", "--markdown"], ["--json", "--serve"],
                     ["--markdown", "--drain-node", "nodebeta02"],
                     ["--port", "0"], ["--port", "65536"], ["--port", "private-invalid"],
                     ["--drain-node", "private-invalid"], ["--unknown", "private-invalid"]):
            with self.subTest(argv=argv):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                    planner.main(argv)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertNotIn("private-invalid", stderr.getvalue())
                self.assertEqual(_opsec_count(stderr.getvalue().encode()), 0)


class CapacityOPSECTests(unittest.TestCase):
    def test_synthetic_sensitive_evidence_is_sanitized_in_all_exports(self):
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        credentials = [prefix + "syntheticcredential" for prefix in
                       ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        data = fixture()
        evidence = " ".join([wan, mac, *credentials, "10.1.2.3", "172.20.1.2",
                             "172.16.1.2", "game.cluster.example.org"])
        data["source"] = evidence
        workload = pod("sensitive")
        workload["resource"]["metadata"]["name"] = evidence
        data["nodes"].append(workload)
        before = deepcopy(data)
        outputs = [json.dumps(planner.summarize_cluster_capacity(data)),
                   json.dumps(planner.audit_workload_resource_requests(data)),
                   json.dumps(planner.estimate_cluster_power_and_gpu_headroom(catalog=data)),
                   json.dumps(planner.simulate_node_drain(catalog=data)),
                   planner.render_capacity_planner_html(data), planner.render_capacity_markdown(data)]
        for index, output in enumerate(outputs):
            with self.subTest(export=index):
                self.assertEqual(_opsec_count(output.encode()), 0)
                # Markdown escapes punctuation; also scan its rendered text.
                if index == 5:
                    output = re.sub(r"\\([\W_])", r"\1", output)
                    self.assertEqual(_opsec_count(output.encode()), 0)
                self.assertTrue(all(raw not in output for raw in [wan, mac, *credentials]))
                for safe in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3",
                             "172.20.1.2", "172.16.1.2", "game.cluster.example.org"):
                    self.assertIn(safe, output)
        self.assertEqual(data, before)

    def test_bundled_exports_and_source_have_zero_opsec_violations(self):
        outputs = [json.dumps(planner.summarize_cluster_capacity()),
                   json.dumps(planner.audit_workload_resource_requests()),
                   json.dumps(planner.estimate_cluster_power_and_gpu_headroom()),
                   planner.render_capacity_planner_html(), planner.render_capacity_markdown()]
        for output in outputs:
            self.assertEqual(_opsec_count(output.encode()), 0)
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertNotIn(b"\r", source)
        self.assertEqual(_opsec_count(source), 0)


if __name__ == "__main__":
    unittest.main()
