# SPDX-License-Identifier: Apache-2.0
"""Executive snapshot synthesis, safe exports, and offline CLI contracts."""

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

import executive_command_center as executive
from golden_path_gates import _opsec_count
from opscryer_backend import CONTRACT_VERSION


EXPORTERS = (executive.build_executive_posture_dossier,
             executive.build_platform_risk_register,
             executive.render_executive_brief_markdown,
             executive.render_executive_command_center_html)


def fixture():
    nodes = []
    for name, ready in (("worker-ready", "True"), ("worker-down", "False")):
        nodes.append({"id": name, "resource": {"kind": "Node",
            "metadata": {"name": name}, "status": {"conditions": [
                {"type": "Ready", "status": ready}]}}})
    nodes.append({"id": "failed-pod", "resource": {"kind": "Pod",
        "metadata": {"name": "failed-pod", "namespace": "test"},
        "spec": {"nodeName": "worker-down", "containers": [{"name": "app"}]},
        "status": {"phase": "Failed"}}})
    for node in nodes:
        node.update(label=node["id"], kind="kubernetes_" + node["resource"]["kind"].lower(),
                    resource_kind=node["resource"]["kind"], domain="deployments_k8s",
                    summary="Synthetic snapshot", primary_url="https://ops.cluster.example.org",
                    drilldown_children=[])
    return {"schema_version": CONTRACT_VERSION, "nodes": nodes, "edges": []}


class ExecutiveTests(unittest.TestCase):
    def setUp(self):
        report = {"passed": True, "gates": {}}
        self.gates = self.enterContext(patch.object(
            executive, "run_six_gate_prepush_audit", return_value=report))
        self.enterContext(patch("oscal_compliance.run_six_gate_prepush_audit",
                                return_value=report))

    def test_dossier_combines_real_providers_without_mutating_catalog(self):
        catalog = fixture()
        before = deepcopy(catalog)
        dossier = executive.build_executive_posture_dossier(catalog)
        self.assertEqual(dossier["node_counts"], {"total": 2, "ready": 1, "not_ready": 1})
        self.assertEqual(dossier["incident_counts"]["total"], 2)
        self.assertEqual(dossier["incident_counts"],
                         executive.incident_commander.build_active_incidents_catalog(catalog)["summary_counts"])
        for key, provider in (("oscal_posture", executive.evaluate_live_oscal_posture),
                              ("chaos_containment", executive.verify_all_six_chaos_planes),
                              ("openbao_provenance", executive.audit_openbao_secret_provenance),
                              ("raft_kms_quorum", executive.verify_raft_kms_quorum),
                              ("oidc_posture", executive.audit_cluster_ingress_oidc_posture)):
            self.assertEqual(dossier[key], provider(catalog))
        self.assertEqual(dossier["oscal_posture"]["summary"]["total"], 9)
        self.assertEqual(dossier["chaos_containment"]["plane_count"], 6)
        self.assertFalse(dossier["live_enforcement_verified"])
        self.assertIn("not NIST or FedRAMP certification", dossier["notice"])
        self.assertEqual(len(dossier["scope_notices"]), 2)
        self.assertEqual(catalog, before)

    def test_risks_remain_open_when_local_gates_pass_or_fail(self):
        for passed, status in ((True, "passed_local_checks"), (False, "failed_local_checks")):
            with self.subTest(passed=passed):
                self.gates.return_value = {"passed": passed, "gates": {}}
                register = executive.build_platform_risk_register(fixture())
                self.assertEqual(register["risk_count"], 6)
                self.assertEqual(register["open_risk_count"], 6)
                self.assertFalse(register["live_enforcement_verified"])
                risks = {risk["risk_id"]: risk for risk in register["risks"]}
                self.assertEqual(set(risks), {f"PR-{index:02}" for index in range(1, 7)})
                self.assertEqual(risks["PR-05"]["observed_status"], status)
                self.assertEqual(risks["PR-04"]["observed_status"], "degraded")
                self.assertEqual(len(risks["PR-06"]["remaining_live_evidence_required"]), 9)
                for risk in risks.values():
                    self.assertEqual(risk["status"], "open")
                    self.assertFalse(risk["live_enforcement_verified"])
                    self.assertTrue(risk["observed_evidence"])
                    self.assertTrue(risk["remaining_live_evidence_required"])

    def test_missing_kubernetes_observations_do_not_establish_readiness(self):
        catalog = {"schema_version": CONTRACT_VERSION, "nodes": [{
            "id": "root", "label": "Root", "kind": "company_root", "domain": "company_org",
            "summary": "No Kubernetes observations", "primary_url": "https://ops.cluster.example.org",
            "drilldown_children": []}], "edges": []}
        dossier = executive.build_executive_posture_dossier(catalog)
        self.assertEqual(dossier["node_counts"], {"total": 0, "ready": 0, "not_ready": 0})
        self.assertEqual(dossier["incident_counts"]["total"], 0)
        register = executive.build_platform_risk_register(catalog)
        self.assertEqual(register["risks"][3]["observed_status"], "unknown")
        self.assertEqual(register["open_risk_count"], 6)

    def test_file_inputs_default_determinism_and_immutability(self):
        catalog = fixture()
        before = deepcopy(catalog)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with patch.object(executive, "DEFAULT_CATALOG_PATH", path):
                for export in EXPORTERS:
                    with self.subTest(export=export.__name__):
                        expected = export(catalog)
                        for value in (path, str(path), None):
                            self.assertEqual(export(value), expected)
                        self.assertEqual(export(catalog), expected)
        self.assertEqual(catalog, before)

    def test_invalid_catalogs_fail_closed(self):
        duplicate = fixture()
        duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
        invalids = ([], {}, {"nodes": {}}, {"nodes": [None]},
                    {"schema_version": CONTRACT_VERSION, "nodes": [], "edges": []},
                    {"nodes": [{"id": ""}]}, duplicate)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{invalid", encoding="utf-8")
            for export in EXPORTERS:
                for index, value in enumerate((*invalids, path, path.with_name("missing.json"))):
                    with self.subTest(export=export.__name__, case=index):
                        with self.assertRaises(ValueError):
                            export(value)

    def test_provider_failures_propagate(self):
        for provider in ("evaluate_live_oscal_posture", "verify_all_six_chaos_planes",
                         "audit_openbao_secret_provenance", "verify_raft_kms_quorum",
                         "audit_cluster_ingress_oidc_posture"):
            with patch.object(executive, provider, side_effect=RuntimeError("unavailable")):
                for export in EXPORTERS:
                    with self.subTest(provider=provider, export=export.__name__):
                        with self.assertRaisesRegex(RuntimeError, "unavailable"):
                            export(fixture())

    def test_markdown_has_counts_controls_risks_and_scope(self):
        markdown = executive.render_executive_brief_markdown(fixture())
        self.assertTrue(markdown.startswith("# Executive Brief\n"))
        self.assertTrue(markdown.endswith("\n"))
        for heading in ("Key performance indicators", "Governance indicators",
                        "OSCAL control statuses", "Platform risk register",
                        "Evidence scope and non-certification notice"):
            self.assertIn("## " + heading, markdown)
        for row in ("| Nodes Ready / observed | 1 / 2 |", "| Active snapshot incidents | 2 |",
                    "| OSCAL controls mapped | 9 |", "| Open platform risks | 6 |",
                    "| Live enforcement verified | No |"):
            self.assertIn(row, markdown)
        for index in range(1, 7):
            self.assertIn(f"| PR-{index:02} |", markdown)
        self.assertIn("All risks remain open pending operational evidence", markdown)

    def test_renderers_escape_untrusted_evidence(self):
        dossier = executive.build_executive_posture_dossier(fixture())
        attack = '</script><img src=x onerror="alert(1)"> & | [link](bad)\n# injected'
        dossier["notice"] = attack
        with patch.object(executive, "build_executive_posture_dossier", return_value=dossier):
            markdown = executive.render_executive_brief_markdown(fixture())
            html = executive.render_executive_command_center_html(fixture())
        self.assertNotIn("<img", markdown)
        self.assertNotIn("\n# injected", markdown)
        self.assertIn("&lt;img", markdown)
        self.assertIn(r"\| \[link\]\(bad\)", markdown)
        tags = []

        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                tags.append((tag, dict(attrs)))

        Parser().feed(html)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertNotIn(attack, html)
        self.assertFalse(any(tag == "img" for tag, _ in tags))
        self.assertEqual(sum(tag == "script" for tag, _ in tags), 2)
        self.assertFalse(any("src" in attrs for tag, attrs in tags if tag == "script"))
        self.assertFalse(any(key.startswith("on") for _, attrs in tags for key in attrs))
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(unsafe, html)
        self.assertIn("element.textContent = text", html)
        ids = [attrs["id"] for _, attrs in tags if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for identity in re.findall(r'getElementById\("([^"]+)"\)', html):
            self.assertIn(identity, ids)
        for route in ("/", "/chat", "/incidents", "/capacity", "/network", "/gitops", "/executive"):
            self.assertIn('href="' + route + '"', html)
        payload = re.search(r'<script id="executive-data" type="application/json">(.*?)</script>',
                            html, re.S).group(1)
        self.assertFalse(any(character in payload for character in "<>&"))
        evidence = json.loads(payload)
        self.assertEqual(evidence["dossier"]["notice"], attack)
        self.assertEqual(evidence["register"]["open_risk_count"], 6)

    def invoke(self, flags):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(executive.main(flags), 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(_opsec_count(output.getvalue().encode()), 0)
        return output.getvalue()

    def test_cli_default_json_markdown_and_catalog(self):
        catalog = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            flags = ["--catalog", str(path)]
            report = json.loads(self.invoke(flags))
            self.assertEqual(report, json.loads(self.invoke([*flags, "--json"])))
            self.assertEqual(report, {"dossier": executive.build_executive_posture_dossier(catalog),
                                      "register": executive.build_platform_risk_register(catalog)})
            self.assertEqual(self.invoke([*flags, "--markdown"]),
                             executive.render_executive_brief_markdown(catalog))

    def test_cli_serve_binds_loopback_and_closes_on_interrupt(self):
        for flags, port in (([], 8094), (["--port", "18094"], 18094)):
            with self.subTest(port=port), patch.object(executive, "ThreadingHTTPServer") as server:
                running = server.return_value.__enter__.return_value
                running.serve_forever.side_effect = KeyboardInterrupt
                self.assertIn(f"http://127.0.0.1:{port}", self.invoke(["--serve", *flags]))
                self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                running.serve_forever.assert_called_once_with()
                server.return_value.__exit__.assert_called_once()

    def assert_cli_error(self, flags):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
            executive.main(flags)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Invalid executive command center request", errors.getvalue())
        self.assertNotIn("private-input", errors.getvalue())
        self.assertEqual(_opsec_count(errors.getvalue().encode()), 0)

    def test_cli_invalid_flags_ports_and_catalogs_do_not_echo_input(self):
        for flags in (["--json", "--markdown"], ["--serve", "--json"],
                      ["--serve", "--markdown"], ["--port", "0"], ["--port", "65536"],
                      ["--port", "private-input"], ["--unknown-private-input"], ["--j"],
                      ["--catalog", "missing-private-input.json"]):
            with self.subTest(flags=flags):
                self.assert_cli_error(flags)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for content in ("{invalid", "{}", '{"nodes": "private-input"}'):
                path.write_text(content, encoding="utf-8")
                self.assert_cli_error(["--catalog", str(path)])

    def test_cli_help_lists_supported_flags(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            executive.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        for flag in ("--json", "--markdown", "--serve", "--catalog", "--port"):
            self.assertIn(flag, output.getvalue())

    def test_sensitive_provider_evidence_is_sanitized_by_all_exports(self):
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        credentials = [prefix + "syntheticcredential" for prefix in
                       ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        safe = ("10.1.2.3", "172.20.1.2", "172.16.1.2", "test.cluster.example.org")
        evidence = " ".join((wan, mac, *credentials, *safe))
        catalog = fixture()
        before = deepcopy(catalog)
        provenance = executive.audit_openbao_secret_provenance(catalog)
        provenance["test_evidence"] = evidence
        provenance["status"] = evidence
        with patch.object(executive, "audit_openbao_secret_provenance", return_value=provenance):
            for export in EXPORTERS:
                with self.subTest(export=export.__name__):
                    result = export(catalog)
                    text = result if isinstance(result, str) else json.dumps(result)
                    text = re.sub(r"\\([\W_])", r"\1", text)
                    self.assertEqual(_opsec_count(text.encode()), 0)
                    for raw in (wan, mac, *credentials):
                        self.assertNotIn(raw, text)
                    for value in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", *safe):
                        self.assertIn(value, text)
        self.assertEqual(catalog, before)

    def test_bundled_exports_and_test_source_have_zero_opsec_violations(self):
        for export in EXPORTERS:
            with self.subTest(export=export.__name__):
                result = export()
                text = result if isinstance(result, str) else json.dumps(result)
                self.assertEqual(_opsec_count(text.encode()), 0)
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertNotIn(b"\r", source)
        self.assertEqual(_opsec_count(source), 0)


if __name__ == "__main__":
    unittest.main()
