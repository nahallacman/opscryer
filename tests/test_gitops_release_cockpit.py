# SPDX-License-Identifier: Apache-2.0
"""Snapshot run classification, ownership, and read-only remediation contracts."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import gitops_release_cockpit as cockpit
from golden_path_gates import _opsec_count
from gitops_release_cockpit import (
    evaluate_release_readiness_scorecard, triage_ci_and_renovate_jobs,
)


def workload(kind, name, status=None, namespace="ci", **metadata):
    return {"id": f"{namespace}/{kind}/{name}", "resource_kind": kind,
            "namespace": namespace,
            "resource": {"kind": kind, "metadata": {"name": name, **metadata},
                         "status": status or {}}}


class ReleaseReadinessTests(unittest.TestCase):
    def setUp(self):
        self.gates = self.enterContext(patch(
            "gitops_release_cockpit.golden_path_gates.run_six_gate_prepush_audit",
            return_value={"passed": True, "gates": {}}))
        self.cli = self.enterContext(patch(
            "gitops_release_cockpit.golden_path_gates.verify_public_cli_entrypoints",
            return_value={"passed": True, "entrypoints": {}}))
        pod = workload("Pod", "gitlab-runner", namespace="gitlab")
        pod["resource"]["spec"] = {"containers": [{"name": "runner"}]}
        self.catalog = {"nodes": [pod]}

    def test_combines_audits_and_preserves_input(self):
        before = deepcopy(self.catalog)
        result = evaluate_release_readiness_scorecard(self.catalog)
        for key in ("release_ready", "gates_passed", "secret_provenance_clean",
                    "cli_entrypoints_ready"):
            self.assertIs(result[key], True)
        self.assertEqual(result["gitops_and_ci_posture"]["counts"]["gitlab_workloads"], 1)
        self.assertEqual(result["secret_provenance"]["observed_specs"], 1)
        self.assertTrue(result["scope_notices"])
        self.assertIn("Container security", " ".join(result["scope_notices"]))
        self.assertEqual(self.catalog, before)
        self.gates.assert_called_once_with()
        self.cli.assert_called_once_with()

    def test_each_failed_or_missing_local_check_blocks_readiness(self):
        for audit, key in ((self.gates, "gates_passed"),
                           (self.cli, "cli_entrypoints_ready")):
            for report in ({"passed": False}, {}, {"passed": "true"}):
                with self.subTest(key=key, report=report):
                    audit.return_value = report
                    result = evaluate_release_readiness_scorecard(self.catalog)
                    self.assertIs(result["release_ready"], False)
                    self.assertIs(result[key], False)
            audit.return_value = {"passed": True}

    def test_secret_findings_and_unobserved_specs_block_readiness(self):
        for spec in (None, {"containers": [{"env": [
                {"name": "PASSWORD", "value": "test-sensitive-literal"}]}]}):
            with self.subTest(spec_present=spec is not None):
                resource = self.catalog["nodes"][0]["resource"]
                if spec is None:
                    resource.pop("spec")
                else:
                    resource["spec"] = spec
                result = evaluate_release_readiness_scorecard(self.catalog)
                self.assertFalse(result["release_ready"])
                self.assertFalse(result["secret_provenance_clean"])
                self.assertNotIn("test-sensitive-literal", json.dumps(result))

    def test_file_inputs_sanitization_and_invalid_catalogs(self):
        token = "gh" + "p_" + "testcredential"
        self.catalog["source"] = "token=" + token
        direct = evaluate_release_readiness_scorecard(self.catalog)
        self.assertNotIn(token, json.dumps(direct))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            for value in (path, str(path)):
                result = evaluate_release_readiness_scorecard(value)
                self.assertEqual(result["secret_provenance"], direct["secret_provenance"])
                self.assertEqual(result["gitops_and_ci_posture"]["provenance"]["input_kind"],
                                 "json_file")
                self.assertNotIn(token, json.dumps(result))
        for invalid in ({}, {"nodes": "invalid"}):
            with self.assertRaises(ValueError):
                evaluate_release_readiness_scorecard(invalid)


class JobTriageTests(unittest.TestCase):
    def triage(self, *nodes):
        return triage_ci_and_renovate_jobs({"nodes": list(nodes)})

    def test_job_conditions_override_retry_counters_and_owned_pods(self):
        job = workload("Job", "renovate-run", {"active": 1, "failed": 2,
                       "conditions": [{"type": "Complete", "status": "True"}]}, uid="job-1")
        pods = [workload("Pod", f"attempt-{index}", {"phase": phase},
                         ownerReferences=[{"kind": "Job", "uid": "job-1"}])
                for index, phase in enumerate(("Failed", "Failed", "Succeeded"))]
        result = self.triage(job, *pods)
        self.assertEqual(result["counts"]["runs"], 1)
        self.assertEqual(result["counts"]["succeeded"], 1)
        self.assertEqual(result["counts"]["owned_pods"], 3)
        self.assertEqual(result["runs"][0]["owned_pods_by_state"], {"failed": 2, "succeeded": 1})
        self.assertEqual(result["runs"][0]["category"], "renovate")

    def test_active_retries_partial_completions_and_unknown_status(self):
        active = workload("Job", "ci-runner-retry", {"failed": 3})
        partial = workload("Job", "partial", {"succeeded": 1})
        partial["resource"]["spec"] = {"completions": 2}
        failure = workload("Job", "failed", {"succeeded": 1,
                           "conditions": [{"type": "Failed", "status": "True"}]})
        unknown = workload("Job", "unknown", {"conditions": [{"type": "Failed", "status": "False"}]})
        result = self.triage(active, partial, failure, unknown)
        self.assertEqual({run["name"]: run["state"] for run in result["runs"]},
                         {"ci-runner-retry": "active", "partial": "active",
                          "failed": "failed", "unknown": "unknown"})

    def test_namespace_uid_and_name_ownership_and_missing_owner(self):
        job = workload("Job", "renovate", uid="current")
        pods = [
            workload("Pod", "renovate-by-name", {"phase": "Failed"},
                     ownerReferences=[{"kind": "Job", "name": "renovate"}]),
            workload("Pod", "renovate-stale", {"phase": "Failed"},
                     ownerReferences=[{"kind": "Job", "name": "renovate", "uid": "old"}]),
            workload("Pod", "renovate-other", {"phase": "Failed"}, namespace="other",
                     ownerReferences=[{"kind": "Job", "uid": "current"}]),
            workload("Pod", "renovate-observer", {"phase": "Succeeded"},
                     ownerReferences=[{"kind": "Job", "uid": "current", "controller": False}]),
        ]
        result = self.triage(job, *pods)
        self.assertEqual(result["counts"]["runs"], 4)
        self.assertEqual(result["counts"]["owned_pods"], 1)
        self.assertEqual(result["counts"]["failed"], 2)

    def test_cronjobs_are_schedules_and_category_inherits_from_owner(self):
        cron = workload("CronJob", "renovate", uid="cron")
        cron["resource"]["spec"] = {"schedule": "0 * * * *", "suspend": True}
        job = workload("Job", "scheduled-run", {"active": 1},
                       ownerReferences=[{"kind": "CronJob", "uid": "cron"}])
        result = self.triage(cron, job)
        self.assertEqual(result["counts"]["runs"], 1)
        self.assertEqual(result["counts"]["cronjobs"], 1)
        self.assertEqual(result["cronjobs"][0]["state"], "suspended")
        self.assertEqual(result["runs"][0]["category"], "renovate")
        self.assertEqual(result["cronjobs"][0]["observed_job_ids"], [job["id"]])

    def test_standalone_runner_phases_exporter_exclusion_and_read_only_commands(self):
        pods = [workload("Pod", f"runner-{index}", {"phase": phase}) for index, phase in
                enumerate(("Failed", "Succeeded", "Running", "Pending", "Unknown"))]
        pods.extend([workload("Pod", "renovate-exporter", {"phase": "Failed"},
                              labels={"app": "renovate"}),
                     workload("Pod", "web", {"phase": "Failed"})])
        result = self.triage(*pods)
        self.assertEqual(result["counts"], {"runs": 5, "terminal": 2, "succeeded": 1,
                         "active": 2, "failed": 1, "unknown": 1, "cronjobs": 0, "owned_pods": 0})
        for run in result["runs"]:
            self.assertTrue(run["remediation_steps"])
            self.assertTrue(run["commands"])
            for command in run["commands"]:
                self.assertIn(command.split()[1], {"get", "describe", "logs"})
        failed = next(run for run in result["runs"] if run["state"] == "failed")
        self.assertIn("python golden_path_gates.py", " ".join(failed["remediation_steps"]))

    def test_deterministic_fresh_results_paths_sanitization_and_command_safety(self):
        pod = workload("Pod", "runner-unsafe;echo", {"phase": "Failed"})
        catalog = {"nodes": [pod, workload("Job", "build", {"active": 1})],
                   "source": "token=" + "gh" + "p_" + "example"}
        before = deepcopy(catalog)
        result = triage_ci_and_renovate_jobs(catalog)
        self.assertEqual(catalog, before)
        self.assertNotIn("example", result["source"])
        unsafe = next(run for run in result["runs"] if run["kind"] == "Pod")
        self.assertEqual(unsafe["commands"], [])
        catalog["nodes"].reverse()
        self.assertEqual(result, triage_ci_and_renovate_jobs(catalog))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            loaded = triage_ci_and_renovate_jobs(path)
        self.assertEqual(result["runs"], loaded["runs"])
        self.assertEqual(loaded["provenance"]["input_kind"], "json_file")
        result["runs"].clear()
        self.assertEqual(len(triage_ci_and_renovate_jobs(catalog)["runs"]), 2)

    def test_empty_and_bundled_snapshot(self):
        self.assertEqual(self.triage()["counts"]["runs"], 0)
        result = triage_ci_and_renovate_jobs()
        self.assertEqual(result["counts"]["runs"], len(result["runs"]))
        self.assertFalse(result["provenance"]["live_collection"])


EXPORTERS = (cockpit.summarize_gitops_and_ci_posture,
             cockpit.triage_ci_and_renovate_jobs,
             cockpit.evaluate_release_readiness_scorecard,
             cockpit.render_release_evidence_markdown,
             cockpit.render_gitops_cockpit_html)


def release_fixture():
    pod = workload("Pod", "gitlab-runner", {"phase": "Running",
                   "conditions": [{"type": "Ready", "status": "True"}]},
                   namespace="gitlab")
    pod["resource"]["spec"] = {"containers": [{"name": "runner"}]}
    return {"source": "synthetic-offline", "example": True, "nodes": [pod,
        workload("Job", "renovate", {"conditions": [
            {"type": "Failed", "status": "True"}]}, namespace="devops-tools")],
        "edges": [], "errors": ["Snapshot collection incomplete"]}


class LocalAuditTests(unittest.TestCase):
    """Keep local audit outcomes deterministic while exercising real snapshot APIs."""

    def setUp(self):
        self.gates = self.enterContext(patch.object(
            cockpit.golden_path_gates, "run_six_gate_prepush_audit", return_value={
                "passed": True, "gates": {f"gate-{index}": {
                    "passed": True, "violations": 0, "errors": []}
                    for index in range(1, 7)}}))
        self.cli = self.enterContext(patch.object(
            cockpit.golden_path_gates, "verify_public_cli_entrypoints",
            return_value={"passed": True, "entrypoints": {}}))


class PostureTests(unittest.TestCase):
    def test_inventory_runner_activity_and_ready_subset(self):
        data = release_fixture()
        data["nodes"].extend([
            workload("Pod", "gitlab-runner-unready", {"phase": "Running"}, namespace="gitlab"),
            workload("Pod", "gitlab-runner-deleting", {"phase": "Running"},
                     namespace="gitlab", deletionTimestamp="2026-01-01T00:00:00Z"),
            workload("Pod", "gitlab-runner-done", {"phase": "Succeeded"}, namespace="gitlab"),
            workload("Deployment", "gitlab-runner", namespace="gitlab"),
            workload("StatefulSet", "controller", namespace="argocd"),
            workload("DaemonSet", "registry", namespace="harbor"),
            workload("CronJob", "e2e", namespace="e2e-testing"),
            workload("Service", "gitlab-runner", namespace="gitlab"),
            workload("Pod", "gitlab-runner-outside", {"phase": "Running"}, namespace="other")])
        report = cockpit.summarize_gitops_and_ci_posture(data)
        self.assertEqual(report["counts"], {"workloads": 9, "argocd_workloads": 1,
                         "gitlab_workloads": 5, "active_runners": 2})
        self.assertEqual(report["runner_counts"],
                         {"pods": 4, "active": 2, "ready": 1, "deployments": 1})
        self.assertEqual(report["namespaces"]["gitlab"]["pods_by_phase"],
                         {"Running": 3, "Succeeded": 1})
        self.assertFalse(report["provenance"]["live_collection"])
        self.assertIn("not verified", report["notice"])

    def test_empty_namespaces_and_metadata_fallback(self):
        report = cockpit.summarize_gitops_and_ci_posture({"nodes": []})
        self.assertEqual(tuple(report["namespaces"]), cockpit.NAMESPACES)
        self.assertEqual(report["counts"]["workloads"], 0)
        for entry in report["namespaces"].values():
            self.assertEqual(entry["workload_count"], 0)
            self.assertEqual(entry["workloads"], [])
        pod = release_fixture()["nodes"][0]
        pod.pop("namespace")
        pod.pop("resource_kind")
        pod["resource"]["metadata"]["namespace"] = "gitlab"
        report = cockpit.summarize_gitops_and_ci_posture({"nodes": [pod]})
        self.assertEqual(report["counts"]["active_runners"], 1)


class RenderingTests(LocalAuditTests):
    def test_markdown_contains_results_counts_scope_and_collection_errors(self):
        markdown = cockpit.render_release_evidence_markdown(release_fixture())
        self.assertTrue(markdown.startswith("# Pre-merge Release Readiness Evidence\n"))
        for heading in ("Release readiness scorecard", "Six-gate audit",
                        "GitOps and CI summary", "CI and Renovate job summary",
                        "Evidence scope", "Snapshot collection errors"):
            self.assertIn("## " + heading, markdown)
        self.assertIn("| Six Golden Path gates | PASS |", markdown)
        self.assertIn("| renovate | 1 | 0 | 1 | 0 | 0 | 0 |", markdown)
        self.assertIn("Total runs: 2; terminal: 1;", markdown)
        self.assertIn("not production deployment approval", markdown)
        self.gates.return_value["passed"] = False
        self.assertIn("| Six Golden Path gates | FAIL |",
                      cockpit.render_release_evidence_markdown(release_fixture()))

    def test_markdown_escapes_untrusted_source_and_errors(self):
        data = release_fixture()
        data["source"] = "<script>alert(1)</script> | [link](bad)\n# injected"
        markdown = cockpit.render_release_evidence_markdown(data)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("\n# injected", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn(r"\| \[link\]\(bad\)", markdown)

    def test_html_json_roundtrip_and_safe_dom_updates(self):
        data = release_fixture()
        attack = '</script><img src=x onerror="alert(1)">&'
        data["source"] = attack
        html = cockpit.render_gitops_cockpit_html(data)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        HTMLParser().feed(html)
        self.assertNotIn(attack, html)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("document.write", html)
        self.assertNotRegex(html, r'<script\b[^>]*\bsrc=')
        self.assertIn("element.textContent = text", html)
        payload = re.search(r'<script id="gitops-data" type="application/json">(.*?)</script>',
                            html, re.S)[1]
        self.assertNotIn("<", payload)
        report = json.loads(payload)
        self.assertEqual(report["scorecard"]["gitops_and_ci_posture"]["source"], attack)
        self.assertEqual(report["triage"], cockpit.triage_ci_and_renovate_jobs(data))
        self.assertEqual(len(report["scorecard"]["golden_path_gates"]["gates"]), 6)
        for route in ("/", "/chat", "/incidents", "/capacity", "/network", "/gitops"):
            self.assertIn('href="' + route + '"', html)


class CatalogAndOpsecTests(LocalAuditTests):
    def test_invalid_catalogs_rejected_by_all_exports(self):
        duplicate = release_fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        for export in EXPORTERS:
            for index, data in enumerate(([], {}, {"nodes": {}}, {"nodes": [None]},
                                          {"nodes": [{"id": ""}]}, duplicate)):
                with self.subTest(export=export.__name__, case=index):
                    with self.assertRaises(ValueError):
                        export(data)

    def test_file_inputs_determinism_and_immutability(self):
        data = release_fixture()
        before = deepcopy(data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            for export in EXPORTERS:
                with self.subTest(export=export.__name__):
                    direct = export(data)
                    self.assertEqual(direct, export(data))
                    self.assertEqual(export(path), export(str(path)))
                    self.assertEqual(data, before)
            path.write_text("{invalid", encoding="utf-8")
            for export in EXPORTERS:
                with self.assertRaises(ValueError):
                    export(path)
                with self.assertRaises(OSError):
                    export(path.with_name("missing.json"))

    def test_sensitive_telemetry_scrubbed_in_every_export(self):
        # Assemble synthetic markers at runtime so source and logs stay public-safe.
        wan = ".".join(map(str, (93, 184, 216, 34)))
        mac = ":".join(("AA", "BB", "CC", "12", "34", "56"))
        tokens = [prefix + "syntheticcredential" for prefix in
                  ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        allowed = ("10.2.3.4", "172.20.2.3", "172.20.1.2", "gitlab.cluster.example.org")
        data = release_fixture()
        data["source"] = " ".join([wan, mac, *tokens, *allowed])
        data["errors"] = [data["source"]]
        for export in EXPORTERS:
            with self.subTest(export=export.__name__):
                result = export(data)
                text = result if isinstance(result, str) else json.dumps(result)
                self.assertEqual(_opsec_count(text.encode("utf-8")), 0)
                self.assertFalse(any(marker in text for marker in (wan, mac, *tokens)))
                self.assertIn("203.0.113.1", text)
                self.assertIn("AA:BB:CC:XX:XX:XX", text)
                for marker in allowed:
                    self.assertIn(marker, text)

    def test_bundled_snapshot_and_test_source_have_zero_opsec_violations(self):
        for export in EXPORTERS:
            with self.subTest(export=export.__name__):
                result = export()
                text = result if isinstance(result, str) else json.dumps(result)
                self.assertEqual(_opsec_count(text.encode("utf-8")), 0)
        self.assertEqual(_opsec_count(Path(__file__).read_bytes()), 0)


class CliTests(LocalAuditTests):
    def test_default_json_and_markdown_with_catalog(self):
        data = release_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            for flags in ([], ["--json"], ["--markdown"]):
                with self.subTest(flags=flags), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cockpit.main([*flags, "--catalog", str(path)]), 0)
                    text = output.getvalue()
                    self.assertEqual(_opsec_count(text.encode("utf-8")), 0)
                    if flags == ["--markdown"]:
                        self.assertEqual(text, cockpit.render_release_evidence_markdown(data))
                    else:
                        report = json.loads(text)
                        self.assertEqual(set(report), {"scorecard", "triage"})
                        self.assertTrue(report["scorecard"]["release_ready"])
                        self.assertEqual(report["triage"]["counts"]["failed"], 1)

    def test_serve_uses_loopback_default_and_custom_port(self):
        for flags, port in (([], 8093), (["--port", "18093"], 18093)):
            with self.subTest(port=port), patch.object(cockpit, "ThreadingHTTPServer") as server, \
                    redirect_stdout(io.StringIO()):
                instance = server.return_value.__enter__.return_value
                instance.serve_forever.side_effect = KeyboardInterrupt
                self.assertEqual(cockpit.main(["--serve", *flags]), 0)
                self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                instance.serve_forever.assert_called_once_with()
                server.return_value.__exit__.assert_called_once()

    def test_invalid_flags_ports_and_catalogs_use_fixed_errors(self):
        cases = (["--json", "--markdown"], ["--serve", "--json"],
                 ["--port", "0"], ["--port", "65536"], ["--port", "private-input"],
                 ["--unknown-private-input"], ["--j"],
                 ["--catalog", "missing-private-input.json"])
        for flags in cases:
            with self.subTest(flag=flags[0]):
                self.assert_cli_error(flags)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for content in ("{invalid", "{}", '{"nodes": "private-input"}'):
                path.write_text(content, encoding="utf-8")
                self.assert_cli_error(["--catalog", str(path)])

    def assert_cli_error(self, flags):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
            cockpit.main(flags)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Invalid GitOps cockpit arguments", errors.getvalue())
        self.assertNotIn("private-input", errors.getvalue())
        self.assertEqual(_opsec_count(errors.getvalue().encode("utf-8")), 0)

    def test_help_lists_supported_flags(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            cockpit.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        for flag in ("--json", "--markdown", "--serve", "--catalog", "--port"):
            self.assertIn(flag, output.getvalue())


if __name__ == "__main__":
    unittest.main()
