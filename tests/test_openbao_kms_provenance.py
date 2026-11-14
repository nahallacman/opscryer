# SPDX-License-Identifier: Apache-2.0
"""Offline provenance, literal detection, placement and presentation checks."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_kms_provenance as engine
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo


def catalog(*resources):
    return {"nodes": [{"resource": resource} for resource in resources]}


def resource(kind, name, spec=None, namespace="iam"):
    return {"kind": kind, "metadata": {"name": name, "namespace": namespace},
            "spec": {} if spec is None else spec}


def healthy_cluster():
    resources = []
    for index, host in enumerate(engine.HARDWARE_NODES):
        node = resource("Node", host)
        node["status"] = {"conditions": [{"type": "Ready", "status": "True"}]}
        pod = resource("Pod", "openbao-" + str(index), {"nodeName": host})
        pod["metadata"]["ownerReferences"] = [{"kind": "StatefulSet", "name": "openbao"}]
        pod["status"] = {"phase": "Running",
                         "conditions": [{"type": "Ready", "status": "True"}]}
        resources.extend([node, pod])
    return catalog(*resources)


class ProvenanceTests(unittest.TestCase):
    def test_canonical_identity_digest_and_no_mutation(self):
        workload = resource("Deployment", "worker", {"template": {"spec": {
            "serviceAccountName": "worker-account", "containers": []}}})
        data = catalog(workload)
        before = deepcopy(data)
        report = engine.audit_openbao_secret_provenance(data)
        record = report["workloads"][0]
        canonical = json.dumps(record["identity"], sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(record["sha256"], hashlib.sha256(canonical.encode()).hexdigest())
        self.assertEqual(record["identity"]["service_account"], "worker-account")
        self.assertEqual(data, before)
        workload["metadata"]["annotations"] = {"arbitrary": "omitted"}
        workload["spec"]["replicas"] = 12
        self.assertEqual(engine.audit_openbao_secret_provenance(data)["workloads"],
                         report["workloads"])
        workload["metadata"]["name"] = "another-worker"
        self.assertNotEqual(engine.audit_openbao_secret_provenance(data)["workloads"],
                            report["workloads"])

    def test_order_independent_and_values_never_enter_digest_or_report(self):
        pod = resource("Pod", "worker", {"containers": [{"env": [
            {"name": "DATABASE_PASSWORD", "value": "synthetic-credential-one"}]}]})
        first = engine.audit_openbao_secret_provenance(catalog(pod))
        pod["spec"]["containers"][0]["env"][0]["value"] = "synthetic-credential-two"
        second = engine.audit_openbao_secret_provenance(catalog(pod))
        self.assertEqual(first, second)
        self.assertFalse(first["zero_plaintext_leakage"])
        self.assertNotIn("synthetic-credential", json.dumps(first))
        a, b = resource("Pod", "a"), resource("Job", "b")
        self.assertEqual(engine.audit_openbao_secret_provenance(catalog(a, b))["workloads"],
                         engine.audit_openbao_secret_provenance(catalog(b, a))["workloads"])

    def test_references_are_allowed_and_literals_are_detected_recursively(self):
        safe = resource("Pod", "worker", {"containers": [{"env": [
            {"name": "DATABASE_PASSWORD", "valueFrom": {"secretKeyRef": {
                "name": "database", "key": "password"}}}],
            "envFrom": [{"secretRef": {"name": "database"}}]}],
            "volumes": [{"secret": {"secretName": "database"}}],
            "imagePullSecrets": [{"name": "registry"}]})
        self.assertTrue(engine.audit_openbao_secret_provenance(catalog(safe))["zero_plaintext_leakage"])
        for spec in ({"nested": [{"password": "synthetic-value"}]},
                     {"secret": "synthetic-value"},
                     {"args": ["password=synthetic-value"]},
                     {"command": ["Bearer synthetic-value"]},
                     {"private_key": ["synthetic-value"]}):
            report = engine.audit_openbao_secret_provenance(catalog(resource("Pod", "worker", spec)))
            self.assertEqual(report["status"], "failed")
            self.assertNotIn("synthetic-value", json.dumps(report))

    def test_secret_payload_and_redacted_placeholders(self):
        secret = resource("Secret", "database")
        for key in ("data", "stringData"):
            secret[key] = {"arbitrary": "synthetic-value"}
            report = engine.audit_openbao_secret_provenance(catalog(secret))
            self.assertEqual(report["findings"][0]["code"], "embedded_secret_payload")
            self.assertNotIn("synthetic-value", json.dumps(report))
            secret[key] = "[REDACTED]"
        self.assertEqual(engine.audit_openbao_secret_provenance(catalog(secret))["findings"], [])
        pod = resource("Pod", "worker", {"password": "[REDACTED]", "env": [
            {"name": "PASSWORD", "value": "[REDACTED]"}]})
        self.assertEqual(engine.audit_openbao_secret_provenance(catalog(pod))["findings"], [])

    def test_empty_and_partial_catalog_coverage(self):
        self.assertEqual(engine.audit_openbao_secret_provenance(catalog())["status"], "unknown")
        report = engine.audit_openbao_secret_provenance(catalog(resource("Deployment", "worker")))
        self.assertIn("omitted", report["coverage"])
        self.assertEqual(report["digest_scope"], "sanitized_workload_identity_v1")

    def test_sanitization_boundary(self):
        address = ".".join(map(str, (8, 8, 8, 8)))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        pod = resource("Pod", address + " " + mac)
        for function in (engine.audit_openbao_secret_provenance, engine.verify_raft_kms_quorum):
            with patch.object(engine, "_sanitize", wraps=sanitize_live_home_telemetry_for_demo) as clean:
                report = function(catalog(pod))
                clean.assert_called()
            rendered = json.dumps(report)
            self.assertNotIn(address, rendered)
            self.assertNotIn(mac, rendered)

    def test_invalid_inputs_are_generic(self):
        for data in ([], {"nodes": "sensitive-marker"}, {"nodes": [False]},
                     catalog({"kind": "Pod", "metadata": {"name": "worker"}, "spec": []}),
                     catalog(resource("Pod", "worker", {1: "sensitive-marker"}))):
            for function in (engine.audit_openbao_secret_provenance, engine.verify_raft_kms_quorum):
                with self.assertRaisesRegex(ValueError, "^Unable to load a valid cluster catalog$"):
                    function(data)


class QuorumTests(unittest.TestCase):
    def test_healthy_distribution_is_only_an_availability_proxy(self):
        data = healthy_cluster()
        before = deepcopy(data)
        report = engine.verify_raft_kms_quorum(data)
        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["required_majority"], 2)
        self.assertEqual(report["available_members"], 3)
        self.assertTrue(report["distributed_across_hardware"])
        self.assertFalse(report["raft_quorum_verified"])
        self.assertFalse(report["kms_verified"])
        self.assertEqual(data, before)

    def test_member_and_node_failures(self):
        for count, expected in ((1, "degraded"), (2, "quorum_at_risk")):
            data = healthy_cluster()
            for index in range(count):
                data["nodes"][index * 2 + 1]["resource"]["status"]["conditions"][0]["status"] = "False"
            self.assertEqual(engine.verify_raft_kms_quorum(data)["status"], expected)
        data = healthy_cluster()
        data["nodes"][0]["resource"]["status"]["conditions"][0]["status"] = "Unknown"
        self.assertEqual(engine.verify_raft_kms_quorum(data)["available_members"], 2)

    def test_colocation_duplicates_missing_and_injector(self):
        data = healthy_cluster()
        for index in (1, 3, 5):
            data["nodes"][index]["resource"]["spec"]["nodeName"] = engine.HARDWARE_NODES[0]
        self.assertFalse(engine.verify_raft_kms_quorum(data)["distributed_across_hardware"])
        self.assertEqual(engine.verify_raft_kms_quorum(data)["status"], "degraded")
        for change in ("duplicate", "missing", "injector", "node_duplicate", "terminating"):
            data = healthy_cluster()
            if change == "duplicate":
                data["nodes"][3] = deepcopy(data["nodes"][1])
            elif change == "missing":
                data["nodes"] = data["nodes"][:2]
            elif change == "injector":
                data["nodes"][1]["resource"]["metadata"] = {"name": "openbao-agent-injector"}
            elif change == "node_duplicate":
                data["nodes"].append(deepcopy(data["nodes"][0]))
            else:
                data["nodes"][1]["resource"]["metadata"]["deletionTimestamp"] = "observed"
            report = engine.verify_raft_kms_quorum(data)
            self.assertNotEqual(report["status"], "healthy")
        self.assertFalse(engine.verify_raft_kms_quorum(catalog())["availability_majority"])

    def test_default_snapshot_and_cli_paths(self):
        self.assertGreater(engine.audit_openbao_secret_provenance()["resource_count"], 0)
        self.assertEqual(len(engine.verify_raft_kms_quorum()["hardware_nodes"]), 3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(healthy_cluster()), encoding="utf-8")
            for flags in (["--json"], []):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(engine.main(["--catalog", str(path)] + flags), 0)
                if flags:
                    self.assertEqual(json.loads(output.getvalue())["quorum"]["status"], "healthy")
                else:
                    self.assertIn("Raft KMS posture: healthy", output.getvalue())
            path.write_text("sensitive-marker", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(engine.main(["--catalog", str(path), "--json"]), 2)
            self.assertNotIn("sensitive-marker", output.getvalue())
            self.assertIn("error", json.loads(output.getvalue()))


if __name__ == "__main__":
    unittest.main()
