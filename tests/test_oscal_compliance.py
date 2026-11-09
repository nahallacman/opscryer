# SPDX-License-Identifier: Apache-2.0
"""Verify OSCAL structure, traceable evidence and fail-closed HUD semantics."""

from copy import deepcopy
from contextlib import ExitStack
from datetime import datetime
import importlib
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile
from uuid import UUID

from oscal_compliance import (
    CATALOG_SOURCE, build_oscal_hud_posture_report,
    export_oscal_component_definition,
    evaluate_live_oscal_posture,
    main, render_oscal_markdown_summary,
)


CONTROL_IDS = {"AC-2", "AC-6", "AU-6", "CM-2", "CM-8", "IR-4", "RA-5", "SC-7", "SI-2"}
COLORS = {"GREEN", "YELLOW", "RED", "ORANGE", "PURPLE", "BLUE"}


class OscalComplianceTests(unittest.TestCase):
    def test_markdown_defaults_include_nine_unassessed_controls_and_notice(self):
        with patch("oscal_compliance.evaluate_live_oscal_posture") as live:
            markdown = render_oscal_markdown_summary()
        live.assert_not_called()
        self.assertIn("# NIST SP 800-53 Rev. 5\n", markdown)
        self.assertIn("| Control ID | Title | Status | Color | Scope | Coverage Gap |", markdown)
        rows = [line for line in markdown.splitlines() if line.startswith("| ")]
        self.assertEqual(len(rows), 11)
        self.assertEqual({row.split(" | ")[0][2:] for row in rows[2:]}, CONTROL_IDS)
        self.assertEqual(markdown.count("| not_assessed | BLUE |"), 9)
        self.assertIn(build_oscal_hud_posture_report()["notice"], markdown)
        self.assertIn("not NIST or FedRAMP certification", markdown)

    def test_markdown_preserves_all_statuses_scope_gaps_and_input(self):
        report = build_oscal_hud_posture_report(dict(zip(
            sorted(CONTROL_IDS),
            ("passed", "partial", "failed", "pending", "manual_review", "not_assessed"))))
        before = deepcopy(report)
        with patch("oscal_compliance.build_oscal_hud_posture_report") as builder:
            markdown = render_oscal_markdown_summary(report)
        builder.assert_not_called()
        for control in report["controls"]:
            self.assertIn("| " + " | ".join(control[field] for field in (
                "control_id", "title", "status", "color", "description", "coverage_gap")) + " |",
                markdown)
        self.assertEqual(report, before)
        self.assertEqual(render_oscal_markdown_summary(report), markdown)

    def test_markdown_escapes_table_delimiters_and_multiline_cells(self):
        report = build_oscal_hud_posture_report()
        report["controls"][0]["description"] = "Scope | detail\r\nnext <tag> & more"
        markdown = render_oscal_markdown_summary(report)
        self.assertIn("Scope \\| detail<br>next &lt;tag&gt; &amp; more", markdown)
        self.assertEqual(len([line for line in markdown.splitlines() if line.startswith("| ")]), 11)

    def test_markdown_cli_uses_default_report(self):
        with patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(main(["--markdown"]), 0)
        self.assertEqual(output.getvalue(), render_oscal_markdown_summary())

    def test_default_posture_is_unassessed_with_traceable_evidence(self):
        report = build_oscal_hud_posture_report()
        self.assertEqual({c["control_id"] for c in report["controls"]}, CONTROL_IDS)
        self.assertEqual(report["summary"]["total"], 9)
        self.assertEqual(report["summary"]["counts"],
                         {color: 9 if color == "BLUE" else 0 for color in COLORS})
        self.assertEqual(report["summary"]["color"], "BLUE")
        for control in report["controls"]:
            self.assertEqual(control["status"], "not_assessed")
            self.assertTrue(control["coverage_gap"])
            for evidence in control["evidence_links"]:
                module, class_name, method = evidence["test_id"].rsplit(".", 2)
                test_class = getattr(importlib.import_module(module), class_name)
                self.assertTrue(issubclass(test_class, unittest.TestCase))
                self.assertTrue(callable(getattr(test_class, method)))
                path = Path(__file__).resolve().parents[1] / evidence["href"].split("#")[0]
                self.assertTrue(path.is_file())
                self.assertEqual(evidence["command"],
                                 "python -m unittest " + evidence["test_id"] + " -v")
                self.assertEqual(evidence["kind"], "automated-test-reference")
        json.dumps(report, allow_nan=False)

    def test_all_six_statuses_and_color_aliases(self):
        expected = {"passed": "GREEN", "partial": "YELLOW", "failed": "RED",
                    "pending": "ORANGE", "manual_review": "PURPLE", "not_assessed": "BLUE"}
        for status, color in expected.items():
            for value in (status, status.upper(), color, color.lower()):
                with self.subTest(status=status, value=value):
                    report = build_oscal_hud_posture_report({"ac-2": value})
                    control = report["controls"][0]
                    self.assertEqual((control["status"], control["color"]), (status, color))
                    self.assertEqual(sum(report["summary"]["counts"].values()), 9)

    def test_summary_precedence_and_missing_assessments(self):
        statuses = {identifier: "passed" for identifier in CONTROL_IDS}
        self.assertEqual(build_oscal_hud_posture_report(statuses)["summary"]["color"], "GREEN")
        for status, color in (("not_assessed", "BLUE"), ("partial", "YELLOW"),
                              ("manual_review", "PURPLE"), ("pending", "ORANGE"),
                              ("failed", "RED")):
            statuses["AC-2"] = status
            self.assertEqual(build_oscal_hud_posture_report(statuses)["summary"]["color"], color)
        del statuses["AC-2"]
        self.assertEqual(build_oscal_hud_posture_report(statuses)["summary"]["color"], "BLUE")
        statuses.update({"AC-2": "failed", "SC-7": "pending"})
        self.assertEqual(build_oscal_hud_posture_report(statuses)["summary"]["color"], "RED")

    def test_invalid_input_never_echoes_values(self):
        marker = "sensitive-input-marker"
        for invalid in ([], True, marker, {marker: "passed"}, {"AC-2": marker},
                        {"AC-2": None}, {"AC-2": True}, {None: "passed"},
                        {"AC-2": "passed", "ac-2": "failed"}):
            for function in (build_oscal_hud_posture_report, export_oscal_component_definition):
                with self.subTest(function=function.__name__, input_type=type(invalid).__name__):
                    with self.assertRaises(ValueError) as error:
                        function(invalid)
                    self.assertNotIn(marker, str(error.exception))

    def test_component_definition_structure_and_hud_agree(self):
        statuses = {"AC-2": "manual_review", "AC-6": "passed", "SC-7": "failed"}
        document = export_oscal_component_definition(statuses)
        self.assertEqual(set(document), {"component-definition"})
        root = document["component-definition"]
        self.assertEqual(root["metadata"]["oscal-version"], "1.1.3")
        self.assertIsNotNone(datetime.fromisoformat(root["metadata"]["last-modified"]).tzinfo)
        self.assertIn("not executed", root["metadata"]["remarks"])
        component, = root["components"]
        self.assertEqual(component["type"], "software")
        implementation, = component["control-implementations"]
        self.assertEqual(implementation["source"], CATALOG_SOURCE)
        requirements = implementation["implemented-requirements"]
        self.assertEqual({r["control-id"] for r in requirements}, {i.lower() for i in CONTROL_IDS})
        identifiers = [root["uuid"], component["uuid"], implementation["uuid"]]
        identifiers.extend(r["uuid"] for r in requirements)
        self.assertEqual(len(set(identifiers)), 12)
        self.assertTrue(all(UUID(identifier).version == 4 for identifier in identifiers))
        report = build_oscal_hud_posture_report(statuses)
        for requirement, control in zip(requirements, report["controls"]):
            self.assertIn(control["description"], requirement["description"])
            self.assertIn(control["coverage_gap"], requirement["description"])
            props = {p["name"]: p["value"] for p in requirement["props"]}
            self.assertEqual(props["hud-color"], control["color"])
            self.assertEqual(props["assessment-status"], control["status"])
            self.assertTrue(all(p["ns"].startswith("https://") for p in requirement["props"]))
            self.assertEqual(requirement["links"][0]["href"], control["evidence_links"][0]["href"])
        self.assertEqual(json.loads(json.dumps(document, allow_nan=False)), document)

    def test_calls_do_not_mutate_inputs_or_share_results(self):
        statuses = {"AC-2": "passed"}
        original = deepcopy(statuses)
        report = build_oscal_hud_posture_report(statuses)
        report["controls"][0]["evidence_links"].clear()
        report["status_mapping"]["passed"] = "RED"
        report["summary"]["counts"]["GREEN"] = 99
        fresh = build_oscal_hud_posture_report(statuses)
        self.assertTrue(fresh["controls"][0]["evidence_links"])
        self.assertEqual(fresh["status_mapping"]["passed"], "GREEN")
        self.assertEqual(fresh["summary"]["counts"]["GREEN"], 1)
        first = export_oscal_component_definition(statuses)
        second = export_oscal_component_definition(statuses)
        self.assertNotEqual(first["component-definition"]["uuid"], second["component-definition"]["uuid"])
        first["component-definition"]["components"].clear()
        self.assertTrue(second["component-definition"]["components"])
        self.assertEqual(statuses, original)


class LiveOscalPostureTests(unittest.TestCase):
    def setUp(self):
        self.context = {"runAsNonRoot": True, "runAsUser": 10000,
                        "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
        self.catalog = {"nodes": [{"id": "worker", "resource": {
            "kind": "Pod", "metadata": {"name": "worker"},
            "spec": {"containers": [{"securityContext": self.context}]}}}], "edges": []}
        stack = self.enterContext(ExitStack())
        outcomes = {
            "audit_cluster_ingress_oidc_posture": {
                "status": "configured_observed_fields", "ingress_count": 1},
            "audit_openbao_secret_provenance": {
                "findings": [], "zero_plaintext_leakage": True, "workloads": [{}]},
            "verify_raft_kms_quorum": {"availability_majority": True},
            "verify_all_six_chaos_planes": {"blast_radius_contained": True},
            "run_six_gate_prepush_audit": {"passed": True},
        }
        self.providers = {name: stack.enter_context(patch("oscal_compliance." + name,
                                                        return_value=value))
                          for name, value in outcomes.items()}
        self.airlock = stack.enter_context(patch("oscal_compliance.evaluate_code_search_airlock"))
        self.airlock.side_effect = lambda query, catalog: (
            {"airlock_blocked": True, "status_code": 403} if query == "find passwords"
            else {"status_code": 200, "results": [{}]})

    def statuses(self, report):
        return {c["control_id"]: c["status"] for c in report["controls"]}

    def test_markdown_renders_live_statuses_and_live_non_certification_notice(self):
        report = evaluate_live_oscal_posture(self.catalog)
        before = deepcopy(report)
        with patch("oscal_compliance.evaluate_live_oscal_posture") as live:
            markdown = render_oscal_markdown_summary(report)
        live.assert_not_called()
        self.assertEqual(markdown.count("| partial | YELLOW |"), 9)
        self.assertIn(report["notice"], markdown)
        self.assertIn("live enforcement and full control coverage remain unverified", markdown)
        self.assertIn("not NIST or FedRAMP certification", markdown)
        self.assertEqual(report, before)

    def test_all_nine_controls_have_derived_evidence_and_defaults_stay_blue(self):
        before = deepcopy(self.catalog)
        with patch("oscal_compliance.build_oscal_hud_posture_report",
                   wraps=build_oscal_hud_posture_report) as builder:
            report = evaluate_live_oscal_posture(self.catalog)
        expected = {identifier: "partial" for identifier in CONTROL_IDS}
        builder.assert_called_once_with(expected)
        self.assertEqual(self.statuses(report), expected)
        self.assertEqual(report["summary"]["counts"]["YELLOW"], 9)
        self.assertTrue(all(c["live_evidence"] for c in report["controls"]))
        self.assertIn("live enforcement", report["notice"])
        self.assertEqual(self.catalog, before)
        json.dumps(report, allow_nan=False)
        for name, provider in self.providers.items():
            if name == "run_six_gate_prepush_audit":
                provider.assert_called_once_with()
            else:
                provider.assert_called_once_with(self.catalog)
            provider.reset_mock()
        default = build_oscal_hud_posture_report()
        self.assertEqual(default["summary"]["counts"]["BLUE"], 9)
        self.assertTrue(all("live_evidence" not in c for c in default["controls"]))
        for provider in self.providers.values():
            provider.assert_not_called()

    def test_container_failure_and_provenance_findings_fail_dependent_controls(self):
        self.context["allowPrivilegeEscalation"] = True
        self.providers["audit_openbao_secret_provenance"].return_value["findings"] = [{}]
        statuses = self.statuses(evaluate_live_oscal_posture(self.catalog))
        for identifier in ("AC-6", "CM-2", "CM-8"):
            self.assertEqual(statuses[identifier], "failed")
        self.assertEqual(statuses["AC-2"], "partial")

    def test_pod_identity_settings_are_inherited_but_nested_context_cannot_bypass_policy(self):
        spec = self.catalog["nodes"][0]["resource"]["spec"]
        spec["securityContext"] = {key: self.context.pop(key)
                                   for key in ("runAsUser", "runAsNonRoot")}
        self.assertEqual(self.statuses(evaluate_live_oscal_posture(self.catalog))["CM-2"], "partial")
        self.context["securityContext"] = {
            **spec["securityContext"], "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]}}
        self.context["allowPrivilegeEscalation"] = True
        self.assertEqual(self.statuses(evaluate_live_oscal_posture(self.catalog))["CM-2"], "failed")

    def test_missing_observations_are_pending_and_gate_failures_are_red(self):
        self.catalog["nodes"] = []
        self.providers["audit_cluster_ingress_oidc_posture"].return_value = {"status": "unknown"}
        self.providers["verify_raft_kms_quorum"].return_value = {"availability_majority": False}
        self.providers["verify_all_six_chaos_planes"].return_value = {
            "blast_radius_contained": False, "planes": {"plane": {"status": "insufficient_evidence"}}}
        self.providers["audit_openbao_secret_provenance"].return_value = {
            "findings": [], "zero_plaintext_leakage": False, "workloads": []}
        self.providers["run_six_gate_prepush_audit"].return_value = {"passed": False}
        statuses = self.statuses(evaluate_live_oscal_posture(self.catalog))
        for identifier in ("AC-2", "AC-6", "CM-2", "CM-8", "IR-4", "SC-7"):
            self.assertEqual(statuses[identifier], "pending")
        for identifier in ("AU-6", "SI-2"):
            self.assertEqual(statuses[identifier], "failed")

    def test_provider_errors_are_isolated_and_never_reflected(self):
        for name, provider in self.providers.items():
            with self.subTest(provider=name):
                provider.side_effect = RuntimeError("sensitive-input-marker")
                report = evaluate_live_oscal_posture(self.catalog)
                self.assertEqual(report["summary"]["color"], "RED")
                self.assertNotIn("sensitive-input-marker", json.dumps(report))
                self.assertTrue(any(s == "partial" for s in self.statuses(report).values()))
                provider.side_effect = None

    def test_invalid_catalogs_fail_closed_without_echo(self):
        for catalog in ([], {"nodes": ["sensitive-input-marker"]}, {"nodes": None},
                        "missing-sensitive-input-marker.json"):
            report = evaluate_live_oscal_posture(catalog)
            self.assertEqual(set(self.statuses(report).values()), {"failed"})
            self.assertNotIn("sensitive-input-marker", json.dumps(report))
        for provider in self.providers.values():
            provider.assert_not_called()

    def test_path_and_default_load_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            self.assertEqual(self.statuses(evaluate_live_oscal_posture(path)),
                             {identifier: "partial" for identifier in CONTROL_IDS})
        with patch("oscal_compliance.Path.read_text", return_value=json.dumps(self.catalog)) as read:
            report = evaluate_live_oscal_posture()
        read.assert_called_once_with(encoding="utf-8")
        self.assertEqual(report["summary"]["counts"]["YELLOW"], 9)

    def test_init_and_ephemeral_containers_and_controller_templates_are_checked(self):
        resource = self.catalog["nodes"][0]["resource"]
        for kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"):
            for field in ("initContainers", "ephemeralContainers"):
                with self.subTest(kind=kind, field=field):
                    spec = {"containers": [{"securityContext": deepcopy(self.context)}], field: [{}]}
                    resource["kind"] = kind
                    if kind != "Pod":
                        spec = {"template": {"spec": spec}}
                    if kind == "CronJob":
                        spec = {"jobTemplate": {"spec": spec}}
                    resource["spec"] = spec
                    statuses = self.statuses(evaluate_live_oscal_posture(self.catalog))
                    self.assertEqual(statuses["CM-2"], "failed")

    def test_real_providers_accept_empty_snapshot_without_claiming_compliance(self):
        # Retain only the repository-audit mock; exercise actual snapshot APIs.
        for name in self.providers:
            if name != "run_six_gate_prepush_audit":
                self.providers[name].side_effect = getattr(importlib.import_module({
                    "audit_cluster_ingress_oidc_posture": "oidc_rbac_verifier",
                    "audit_openbao_secret_provenance": "openbao_kms_provenance",
                    "verify_raft_kms_quorum": "openbao_kms_provenance",
                    "verify_all_six_chaos_planes": "chaos_blast_radius",
                }[name]), name)
        from security_airlock import evaluate_code_search_airlock
        self.airlock.side_effect = evaluate_code_search_airlock
        statuses = self.statuses(evaluate_live_oscal_posture({"nodes": [], "edges": []}))
        self.assertTrue(all(statuses[i] == "pending" for i in CONTROL_IDS - {"AU-6", "SI-2", "RA-5"}))
        # An empty snapshot lacks the spatial contract needed by code search.
        self.assertEqual(statuses["RA-5"], "failed")


if __name__ == "__main__":
    unittest.main()
