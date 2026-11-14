# SPDX-License-Identifier: Apache-2.0
"""WAVE-C3 deterministic boundary and fuzz regression tests; entirely offline."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

import chaos_blast_radius as chaos
import capacity_planner as capacity
import cluster_diff_engine as diff
import jev_client as jev
import jev_knowledge_explorer as knowledge
import live_advisor as advisor
import incident_commander as incidents
import network_topology_inspector as network
import gitops_release_cockpit as gitops
import executive_command_center as executive
import gameday_simulator as gameday
import game_observability_loop as games
import playbook_studio as playbooks
import model_tier_copilot as copilot
import opscryer_suite_hub as hub
import oidc_rbac_verifier as oidc
import openbao_kms_provenance as bao
import opscryer_backend as backend
import security_airlock as airlock
import storage_zfs_cockpit as storage
import secops_vulnerability_cockpit as secops
import ticket_chat_portal as portal
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize
from tests.test_opscryer_public_smoke import ROOT, opsec_findings, scan_public_files


def nested(value, depth):
    for _ in range(depth):
        value = {"child": [value]}
    return value


def secret_markers():
    # Assemble at runtime; neither sources nor test diagnostics expose tokens.
    return tuple(left + right for left, right in
                 (("gh", "o_"), ("gh", "p_"), ("gl", "pat-"), ("s", "k-")))


def fullwidth(text):
    return "".join(chr(ord(c) + 0xFEE0) if 33 <= ord(c) <= 126 else c for c in text)


class SuiteEdgeCaseHardeningTests(unittest.TestCase):
    """STAGE-112/142/152: cross-product input and disclosure regressions."""

    modules = (incidents, capacity, network, gitops, executive, hub,
               gameday, playbooks, copilot, games, knowledge, storage, secops)

    cockpit_modules = (knowledge, storage, secops)
    cockpit_exporters = (
        lambda value: knowledge.build_jev_knowledge_catalog(catalog=value),
        lambda value: knowledge.render_jev_knowledge_markdown(catalog=value),
        knowledge.render_jev_knowledge_html,
        storage.summarize_storage_topology,
        storage.render_storage_cockpit_markdown,
        storage.render_storage_cockpit_html,
        secops.build_secops_posture_catalog,
        secops.render_secops_cockpit_markdown,
        secops.render_secops_cockpit_html,
    )

    def setUp(self):
        self.catalog = {"schema_version": backend.CONTRACT_VERSION, "nodes": [{
            "id": "root", "label": "Root", "kind": "company_root",
            "domain": "company_org", "summary": "Offline boundary fixture",
            "primary_url": "https://ops.cluster.example.org", "drilldown_children": [],
        }], "edges": []}
        # Local repository gates are exercised separately, not once per fuzz case.
        self.enterContext(patch.object(gitops.golden_path_gates,
                                      "run_six_gate_prepush_audit",
                                      return_value={"passed": True, "gates": {}}))
        self.enterContext(patch.object(gitops.golden_path_gates,
                                      "verify_public_cli_entrypoints",
                                      return_value={"passed": True}))
        self.enterContext(patch.object(executive, "run_six_gate_prepush_audit",
                                      return_value={"passed": True, "gates": {}}))

    def exporters(self, destination):
        # Hub metadata intentionally ignores telemetry; bundle export validates it.
        return (
            incidents.build_active_incidents_catalog,
            lambda value: incidents.generate_incident_runbook(catalog=value),
            incidents.build_blameless_pir_markdown,
            capacity.summarize_cluster_capacity,
            capacity.audit_workload_resource_requests,
            lambda value: capacity.estimate_cluster_power_and_gpu_headroom(catalog=value),
            capacity.render_capacity_planner_html,
            network.trace_ingress_to_hardware_routes,
            network.build_namespace_exposure_matrix,
            network.detect_routing_anomalies,
            network.export_network_mermaid_diagram,
            gitops.summarize_gitops_and_ci_posture,
            gitops.triage_ci_and_renovate_jobs,
            gitops.evaluate_release_readiness_scorecard,
            executive.build_executive_posture_dossier,
            executive.build_platform_risk_register,
            lambda value: hub.export_full_suite_static_bundle(destination, value),
            lambda value: gameday.simulate_gameday_scenario(catalog=value),
            lambda value: gameday.render_gameday_markdown(catalog=value),
            gameday.render_gameday_simulator_html,
            playbooks.build_playbook_studio_catalog,
            playbooks.render_playbook_studio_markdown,
            playbooks.render_playbook_studio_html,
            lambda value: copilot.build_dual_tier_context_pack(catalog=value),
            lambda value: copilot.run_dual_tier_model_comparison(catalog=value),
            copilot.build_model_copilot_benchmark_matrix,
            copilot.render_model_copilot_markdown,
            copilot.render_model_copilot_html,
            games.inspect_game_server_fleet,
            lambda value: games.trace_game_debugging_loop(catalog=value),
            lambda value: games.render_game_debug_markdown(catalog=value),
            games.render_game_debug_html,
        ) + self.cockpit_exporters

    def assert_cli_rejected(self, module, flags, marker=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                module.main(flags)
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error:", stderr.getvalue())
        if marker is not None:
            markers = (marker,) if isinstance(marker, str) else marker
            for value in markers:
                self.assertFalse(value in stderr.getvalue(), "CLI echoed untrusted input")
        findings = opsec_findings(stderr.getvalue().encode("utf-8"))
        self.assertFalse(any(findings.values()), "CLI exposed prohibited telemetry")

    def test_suite_cli_port_rejection_boundaries(self):
        for module in self.modules:
            for port in ("-1", "0", "65536", str(2 ** 256), "NaN", "Infinity", "1.5"):
                with self.subTest(module=module.__name__, port=port):
                    self.assert_cli_rejected(module, ["--port", port])

    def test_suite_cli_accepts_endpoint_ports_without_opening_sockets(self):
        for module in self.modules:
            for port in (1, 65535):
                owner = hub.socketserver if module is hub else module
                server_name = "TCPServer" if module is hub else "ThreadingHTTPServer"
                with self.subTest(module=module.__name__, port=port), \
                        patch.object(owner, server_name) as server, \
                        redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    server.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
                    flags = ["--serve", "--port", str(port)]
                    if module is hub:
                        self.assertEqual(module.main(flags), 0)
                    else:
                        with tempfile.TemporaryDirectory() as directory:
                            path = Path(directory) / "catalog.json"
                            path.write_text(json.dumps(self.catalog), encoding="utf-8")
                            self.assertEqual(module.main([*flags, "--catalog", str(path)]), 0)
                    self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))

    def test_suite_cli_diagnostics_never_echo_sensitive_arguments(self):
        markers = ["private-boundary-input", "\x00private-boundary-input"]
        markers.extend(prefix + "synthetic112" for prefix in secret_markers())
        for module in self.modules:
            for index, marker in enumerate(markers):
                for option, flags in enumerate((["--" + marker], ["--port", marker])):
                    with self.subTest(module=module.__name__, marker=index, option=option):
                        self.assert_cli_rejected(module, flags, marker)

    def test_suite_malformed_catalog_objects_fail_without_input_echo(self):
        rng = random.Random(112)
        marker = "private-catalog-boundary-input"
        invalids = [False, 0, [], {}, {"nodes": {}}, {"nodes": [None]},
                    {"nodes": [{"id": ""}]}]
        for _ in range(20):
            invalids.append({"nodes": rng.choice((False, 1, marker, {})),
                             "untrusted": marker})
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "bundle"
            for export_index, export in enumerate(self.exporters(destination)):
                for index, value in enumerate(invalids):
                    with self.subTest(export=export_index, case=index):
                        with self.assertRaises(ValueError) as raised:
                            export(value)
                        self.assertFalse(marker in str(raised.exception), "catalog input echoed")
                        self.assertFalse(destination.exists(), "invalid input wrote bundle files")

    def test_game_cli_flag_rejection_boundaries_without_input_echo(self):
        for flags in (["--json", "--markdown"], ["--json", "--serve"],
                      ["--markdown", "--serve"], ["--game"], ["--catalog"],
                      ["--port"], ["--gam", "minecraft"], ["--game", ""]):
            with self.subTest(flags=flags):
                self.assert_cli_rejected(games, flags)
        markers = ["private-game-boundary-input", "\x00private-game-boundary-input"]
        markers.extend(prefix + "synthetic152" for prefix in secret_markers())
        for index, marker in enumerate(markers):
            with self.subTest(marker=index):
                self.assert_cli_rejected(games, ["--game", marker], marker)

    def test_cockpit_cli_flag_rejection_boundaries_without_input_echo(self):
        for module in self.cockpit_modules:
            for flags in (["--json", "--markdown"], ["--json", "--serve"],
                          ["--markdown", "--serve"], ["--catalog"], ["--port"],
                          ["--jso"], ["--markdow"], ["--serv"],
                          ["--catalo", "private-catalog-boundary-input"],
                          ["--por", "private-port-boundary-input"]):
                with self.subTest(module=module.__name__, flags=flags):
                    self.assert_cli_rejected(module, flags, "private-")
        for flags in (["--query"], ["--quer", "private-query-boundary-input"],
                      ["--query", ""], ["--query", " \t"]):
            with self.subTest(flags=flags):
                self.assert_cli_rejected(knowledge, flags, "private-query-boundary-input")
        markers = ["\x00private-query-boundary-input", "private-query-boundary-input\n"]
        markers.extend("\x00" + prefix + "synthetic112" for prefix in secret_markers())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            for index, marker in enumerate(markers):
                for mode in ("--json", "--markdown", "--serve"):
                    with self.subTest(marker=index, mode=mode), \
                            patch.object(knowledge, "ThreadingHTTPServer") as server:
                        self.assert_cli_rejected(knowledge,
                            [mode, "--query", marker, "--catalog", str(path)],
                            marker.strip("\x00\n"))
                        server.assert_not_called()

    def test_suite_malformed_catalog_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-catalog-input.json"
            destination = Path(directory) / "bundle"
            for raw in (b"", b"{", b'{"nodes":}', b"[]", b"null", b"\xff",
                        b'{"nodes":"private-catalog-boundary-input"}'):
                path.write_bytes(raw)
                for index, export in enumerate(self.exporters(destination)):
                    with self.subTest(export=index, case=raw.hex()):
                        with self.assertRaises(ValueError) as raised:
                            export(path)
                        for marker in (path.name, "private-catalog-boundary-input"):
                            self.assertFalse(marker in str(raised.exception),
                                             "catalog input echoed")
                        self.assertFalse(destination.exists())

    def test_new_suite_cli_catalog_errors_never_echo_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-catalog-boundary-input.json"
            for raw in ('{"nodes":"private-catalog-boundary-input"}',
                        '{"nodes":', "null"):
                path.write_text(raw, encoding="utf-8")
                for module in (gameday, playbooks, copilot, games) + self.cockpit_modules:
                    for mode in ("--json", "--markdown"):
                        with self.subTest(module=module.__name__, mode=mode, raw=raw):
                            self.assert_cli_rejected(
                                module, [mode, "--catalog", str(path)],
                                (path.name, "private-catalog-boundary-input"))

    def test_new_suite_rejects_nonfinite_values_before_redaction(self):
        exports = (
            lambda value: gameday.simulate_gameday_scenario(catalog=value),
            playbooks.build_playbook_studio_catalog,
            lambda value: copilot.build_dual_tier_context_pack(catalog=value),
            games.inspect_game_server_fleet,
            lambda value: games.trace_game_debugging_loop(catalog=value),
            lambda value: games.render_game_debug_markdown(catalog=value),
            games.render_game_debug_html,
        ) + self.cockpit_exporters
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-catalog-boundary-input.json"
            for number in (float("nan"), float("inf"), -float("inf")):
                catalog = deepcopy(self.catalog)
                catalog["password"] = {"private-numeric-input": number}
                path.write_text(json.dumps(catalog), encoding="utf-8")
                for index, export in enumerate(exports):
                    for value in (catalog, path):
                        with self.subTest(export=index, number=str(number), file=value is path):
                            with self.assertRaises(ValueError) as raised:
                                export(value)
                            for marker in (path.name, "private-numeric-input"):
                                self.assertFalse(marker in str(raised.exception),
                                                 "catalog input echoed")
                for module in (gameday, playbooks, copilot, games) + self.cockpit_modules:
                    for mode in ("--json", "--markdown"):
                        with self.subTest(module=module.__name__, number=str(number), mode=mode):
                            self.assert_cli_rejected(
                                module, [mode, "--catalog", str(path)],
                                (path.name, "private-numeric-input"))

    def test_suite_nonfinite_catalogs_are_rejected_before_public_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            destination = Path(directory) / "bundle"
            for number in (float("nan"), float("inf"), -float("inf")):
                catalog = deepcopy(self.catalog)
                catalog["untrusted_numeric_evidence"] = number
                path.write_text(json.dumps(catalog), encoding="utf-8")
                # Capacity ignores unrelated evidence in summaries, while its
                # numeric metric contract is tested separately below.
                for index, export in enumerate(self.exporters(destination)):
                    if index in (3, 4, 5, 6, 11, 12):
                        # Inventory-only views may discard unrelated numeric
                        # fields, but must still return finite public evidence.
                        result = export(catalog)
                        json.dumps(result, allow_nan=False)
                        continue
                    for value in (catalog, path):
                        with self.subTest(export=index, number=str(number), file=value is path):
                            with self.assertRaises(ValueError):
                                export(value)
                            self.assertFalse(destination.exists())

    def test_gitops_null_catalog_file_is_rejected_without_default_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text("null", encoding="utf-8")
            for export in (gitops.summarize_gitops_and_ci_posture,
                           gitops.triage_ci_and_renovate_jobs,
                           gitops.evaluate_release_readiness_scorecard):
                with self.subTest(export=export.__name__):
                    with self.assertRaises(ValueError):
                        export(path)

    def test_bundle_null_catalog_file_is_rejected_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text("null", encoding="utf-8")
            destination = Path(directory) / "bundle"
            with self.assertRaisesRegex(ValueError, "^Invalid suite bundle catalog$"):
                hub.export_full_suite_static_bundle(destination, path)
            self.assertFalse(destination.exists())

    def test_capacity_metrics_reject_nonfinite_negative_and_boolean_values(self):
        for value in (float("nan"), float("inf"), -float("inf"), -1, True, "NaN"):
            catalog = deepcopy(self.catalog)
            node = catalog["nodes"][0]
            node["resource"] = {"kind": "Node", "metadata": {"name": "worker"}}
            node["metrics"] = {"cpu_percent": value, "ram_percent": value}
            with self.subTest(case=str(value)):
                result = capacity.summarize_cluster_capacity(catalog)
                self.assertIsNone(result["nodes"][0]["metrics"]["cpu_percent"])
                self.assertIsNone(result["nodes"][0]["metrics"]["ram_percent"])
                json.dumps(result, allow_nan=False)

    def test_incident_hotspot_thresholds_and_scaled_zero_boundaries(self):
        for cpu, ram, expected in ((79.999, 74.999, 0), (80, 0, 1),
                                   (0, 75, 1), (80, 75, 1)):
            catalog = deepcopy(self.catalog)
            node = catalog["nodes"][0]
            node["resource_kind"] = "Node"
            node["resource"] = {"kind": "Node", "status": {
                "conditions": [{"type": "Ready", "status": "True"}]}}
            node["metrics"] = {"cpu_percent": cpu, "ram_percent": ram}
            with self.subTest(cpu=cpu, ram=ram):
                counts = incidents.build_active_incidents_catalog(catalog)["summary_counts"]
                self.assertEqual(counts["total"], expected)
                self.assertEqual(counts["by_category"]["node_hotspot"], expected)
        for desired, ready, severity in ((0, 0, None), (1, 0, "SEV-2"),
                                          (2, 1, "SEV-3"), (1, 1, None)):
            catalog = deepcopy(self.catalog)
            catalog["nodes"][0]["resource"] = {"kind": "Deployment",
                "spec": {"replicas": desired}, "status": {"readyReplicas": ready}}
            with self.subTest(desired=desired, ready=ready):
                records = incidents.build_active_incidents_catalog(catalog)["incidents"]
                self.assertEqual([item["severity"] for item in records],
                                 [] if severity is None else [severity])

    def test_unknown_incident_and_drain_identifiers_have_fixed_errors(self):
        for value in ("", "\x00", "private-input", False, [], {}, 2 ** 256):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "^Unknown incident ID$"):
                    incidents.generate_incident_runbook(value, self.catalog)
                with self.assertRaisesRegex(ValueError, "^Invalid or unknown hardware node$"):
                    capacity.simulate_node_drain(value, self.catalog)

    def test_suite_hub_metadata_ignores_malformed_and_nonfinite_telemetry(self):
        expected = hub.build_suite_application_catalog()
        for value in (None, False, [], {"nodes": [None]},
                      {"private-input": float("nan")}, object()):
            with self.subTest(type=type(value).__name__):
                result = hub.build_suite_application_catalog(value)
                self.assertEqual(result, expected)
                result["applications"].clear()
                self.assertEqual(hub.build_suite_application_catalog(value), expected)


class EdgeCaseHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / "live-cluster-sanitized.json").read_text(
            encoding="utf-8"))
        cls.engine = backend.KnowledgeGraphBackendEngine()

    def assert_clean(self, value):
        findings = opsec_findings(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        self.assertFalse(any(findings.values()), "output contains prohibited telemetry")

    def test_sanitizer_scalar_boundaries_and_unsupported_types(self):
        for value in (None, False, True, 0, -1, 2 ** 256, -0.0, "", "\x00",
                      "café 中文 🛰 e\u0301", "10.0.0.1", "172.20.0.1",
                      "172.16.0.1", "router.cluster.example.org"):
            with self.subTest(type=type(value).__name__):
                self.assertEqual(sanitize(value), value)
                self.assertEqual(sanitize(sanitize(value)), value)
        for value in (set(), object(), b"bytes", {1: "value"}):
            with self.subTest(type=type(value).__name__), self.assertRaises(TypeError):
                sanitize(value)

    def test_sanitizer_seeded_nested_fuzz_is_pure_and_idempotent(self):
        rng = random.Random(39)
        wan = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        leaves = [None, False, 0, -1, "", "中文 🛰", "e\u0301", wan, mac]
        leaves.extend(marker + "synthetic39" for marker in secret_markers())

        def generate(depth):
            if depth == 0 or rng.randrange(3) == 0:
                return rng.choice(leaves)
            items = [generate(depth - 1) for _ in range(rng.randrange(5))]
            return rng.choice((items, tuple(items),
                               {"field" + str(i): v for i, v in enumerate(items)}))

        for index in range(100):
            with self.subTest(case=index):
                payload = generate(5)
                before = deepcopy(payload)
                clean = sanitize(payload)
                self.assertEqual(payload, before)
                self.assertEqual(sanitize(clean), clean)
                self.assert_clean(clean)

    def test_sanitizer_deep_nesting_and_redacted_key_collisions(self):
        payload = nested({"password": "synthetic", "text": "中文"}, 64)
        before = deepcopy(payload)
        clean = sanitize(payload)
        self.assertEqual(clean, sanitize(clean))
        self.assertEqual(payload, before)
        cursor = clean
        for _ in range(64):
            cursor = cursor["child"][0]
        self.assertEqual(cursor, {"password": "[REDACTED]", "text": "中文"})
        keys = [marker + "synthetic" for marker in secret_markers()[:2]]
        with self.assertRaisesRegex(ValueError, "collide"):
            sanitize(dict.fromkeys(keys, "value"))

    def test_jev_probability_boundaries(self):
        for probability, expected in ((0.799999, jev.HUMAN_ESCALATION),
                                      (0.80, "true_branch"), (1, "true_branch"),
                                      (1.000001, jev.HUMAN_ESCALATION),
                                      (True, jev.HUMAN_ESCALATION),
                                      (float("nan"), jev.HUMAN_ESCALATION),
                                      (float("inf"), jev.HUMAN_ESCALATION),
                                      (-1, jev.HUMAN_ESCALATION)):
            with self.subTest(probability=probability):
                result = {"predicate_id": "边界", "evaluated_value": True,
                          "calibrated_probability": probability}
                self.assertEqual(jev.predicate_route(result, "边界"), expected)
        for threshold in (None, True, -1, float("nan"), float("inf"), 2 ** 256):
            self.assertEqual(jev.predicate_route({}, "边界", threshold), jev.HUMAN_ESCALATION)

    def test_jev_malformed_json_and_excessive_nesting_escalate(self):
        cases = ("", "{", '{"x":}', "[]", "null", "true", "NaN", "Infinity",
                 '{"predicate_id":"p","predicate_id":"p","evaluated_value":true,'
                 '"calibrated_probability":1}', b"\xff", '{"x":"\\uZZZZ"}',
                 "[" * (sys.getrecursionlimit() + 100) + "0" +
                 "]" * (sys.getrecursionlimit() + 100))
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                self.assertEqual(jev.predicate_route(raw, "p"), jev.HUMAN_ESCALATION)

    def test_backend_api_malformed_json_and_limit_boundaries(self):
        for body in ("", "{", "null", "[]", "true", '{"ticket_title":}',
                     '{"ticket_title":"hello","min_confidence":NaN}', b"\xff"):
            status, result = self.engine.handle_api_request(
                "/api/v1/graph/deflect-ticket", method="POST", body=body)
            self.assertEqual(status, 400)
            self.assertEqual(result, {"error": "invalid request parameters or body"})
        for limit in (0, -1, 101, True, 1.5, "1e2", "", ["1", "2"]):
            status, _ = self.engine.handle_api_request(
                "/api/v1/graph/search", {"q": "manifest", "limit": limit})
            self.assertEqual(status, 400)
        for limit in (1, 100):
            status, result = self.engine.handle_api_request(
                "/api/v1/graph/search", {"q": "manifest", "limit": limit})
            self.assertEqual(status, 200)
            self.assertLessEqual(result["result_count"], limit)

    def test_unicode_search_and_routing_are_repeatable(self):
        for text in ("", "\x00", "中文 🛰", "café e\u0301", "manifest 中文", "ＳＥＣＲＥＴ"):
            with self.subTest(text=text):
                self.assertEqual(self.engine.search(text), self.engine.search(text))
                first = jev.evaluate_ticket_with_jev_tree(text)
                self.assertEqual(first, jev.evaluate_ticket_with_jev_tree(text))
                self.assertIn(first["route"], ("leaf", jev.HUMAN_ESCALATION))
        nodes = [{"id": "中文", "label": "中文 café"}]
        self.assertEqual(backend.bm25_search_nodes(nodes, "中文")[0]["id"], "中文")

    def test_airlock_prefix_variations_block_before_catalog_access(self):
        for marker_index, marker in enumerate(secret_markers()):
            for variant_index, variant in enumerate((marker, marker.upper(), fullwidth(marker))):
                with self.subTest(marker=marker_index, variant=variant_index):
                    query = "manifest 中文 " + variant + "synthetic39"
                    with patch.object(airlock, "KnowledgeGraphBackendEngine") as engine:
                        result = airlock.evaluate_code_search_airlock(query, catalog=object())
                    engine.assert_not_called()
                    self.assertEqual(result["reason"], "secret_hunting_blocked")
                    self.assertEqual(result["results"], [])
                    self.assertTrue(query not in json.dumps(result), "blocked query echoed")
                    self.assert_clean(result)

    def test_advisor_and_portal_airlock_precedes_loading(self):
        query = "manifest " + fullwidth(secret_markers()[0]) + "synthetic39"
        with patch.object(Path, "read_text", side_effect=AssertionError("catalog accessed")):
            advice = advisor.answer_operational_question(query, catalog="missing.json")
            chat = portal.ask_concierge_chat(query, catalog="missing.json")
        for result in (advice, chat):
            self.assertTrue(result["airlock_blocked"])
            self.assertEqual(result["status"], "blocked_by_airlock")
            self.assert_clean(result)

    def test_empty_and_wrong_type_message_boundaries(self):
        for value in (None, False, 0, [], {}, "", " \t\n"):
            self.assertTrue(airlock.evaluate_code_search_airlock(value)["airlock_blocked"])
            self.assertTrue(advisor.answer_operational_question(value)["airlock_blocked"])
            with self.assertRaisesRegex(ValueError, "Message must be a nonempty string"):
                portal.ask_concierge_chat(value)
        for persona in (None, [], "", "SRE", "中文"):
            with self.assertRaisesRegex(ValueError, "Unsupported persona"):
                portal.ask_concierge_chat("manifest", persona=persona)

    def test_container_uid_boundary_excludes_boolean(self):
        context = {"runAsNonRoot": True, "allowPrivilegeEscalation": False,
                   "capabilities": {"drop": ["ALL"]}}
        for uid, compliant in ((9999, False), (10000, True), (10001, True),
                               (True, False), (10000.0, False), ("10000", False)):
            self.assertEqual(airlock.audit_container_security_context(
                {**context, "runAsUser": uid})["compliant"], compliant)

    def test_catalog_loaders_reject_malformed_json_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            for raw in ("{", '{"nodes":}', "[]", "{}", '{"nodes":[null]}'):
                path.write_text(raw, encoding="utf-8")
                for audit in (bao.audit_openbao_secret_provenance, bao.verify_raft_kms_quorum):
                    with self.assertRaisesRegex(ValueError, "^Unable to load a valid cluster catalog$"):
                        audit(path)
                self.assertEqual(oidc.audit_cluster_ingress_oidc_posture(path)["status"],
                                 "invalid_catalog")
                self.assertEqual(chaos.verify_all_six_chaos_planes(path)["verified_plane_count"], 0)
                with self.assertRaises(ValueError):
                    advisor.answer_operational_question("manifest 中文", path)
                with self.assertRaises(ValueError):
                    portal.ask_concierge_chat("manifest 中文", catalog=path)
                with patch.object(diff, "DEFAULT_CATALOG_PATH", path), self.assertRaises(ValueError):
                    diff.summarize_live_cluster_health()

    def test_excessive_catalog_nesting_fails_closed(self):
        # C JSON encoders can have a separate recursion budget from Python code.
        depth = max(10000, sys.getrecursionlimit() * 10)
        catalog = {"nodes": [], "extra": nested("中文", depth)}
        for audit in (bao.audit_openbao_secret_provenance, bao.verify_raft_kms_quorum):
            with self.assertRaises(ValueError):
                audit(catalog)
        self.assertEqual(oidc.audit_cluster_ingress_oidc_posture(catalog)["status"], "invalid_catalog")
        self.assertEqual(chaos.verify_all_six_chaos_planes(catalog)["verified_plane_count"], 0)
        self.assertTrue(backend.validate_spatial_graph_contract(catalog))

    def test_oidc_expiry_and_unicode_route_boundaries(self):
        claims = {"signature_verified": True, "iss": oidc.TRUSTED_ISSUER,
                  "aud": oidc.TRUSTED_AUDIENCE, "sub": "用户 🛰",
                  "groups": ["platform-admins"], "exp": 1001, "iat": 999, "nbf": 1000}
        with patch.object(oidc.time, "time", return_value=1000):
            self.assertTrue(oidc.evaluate_oidc_rbac_access(claims, "/admin", {"nodes": []})["allowed"])
            for expiry in (999, 1000, True, "1001", float("nan"), float("inf")):
                self.assertFalse(oidc.evaluate_oidc_rbac_access(
                    {**claims, "exp": expiry}, "/admin", {"nodes": []})["allowed"])
            for route in ("/admin/", "/Admin", "/ａｄｍｉｎ", "/admin\x00", "/%61dmin",
                          "/admin?x=1", "/admin/../admin", "中文"):
                self.assertFalse(oidc.evaluate_oidc_rbac_access(claims, route, {"nodes": []})["allowed"])

    def test_provenance_unicode_digest_and_nested_literal_detection(self):
        resource = {"kind": "Pod", "metadata": {"name": "用户-🛰", "namespace": "iam"},
                    "spec": {"extension": nested("benign", 32)}}
        catalog = {"nodes": [{"id": "pod", "resource": resource}]}
        first = bao.audit_openbao_secret_provenance(catalog)
        workload = first["workloads"][0]
        encoded = json.dumps(workload["identity"], sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        self.assertEqual(workload["sha256"], hashlib.sha256(encoded).hexdigest())
        resource["spec"]["extension"] = nested(secret_markers()[0] + "synthetic39", 32)
        second = bao.audit_openbao_secret_provenance(catalog)
        self.assertEqual(first["workloads"], second["workloads"])
        self.assertFalse(second["zero_plaintext_leakage"])
        self.assertEqual(second["findings"], [{"resource_index": 0, "code": "embedded_sensitive_literal"}])
        self.assert_clean(second)

    def test_repeat_calls_do_not_mutate_catalog_or_share_results(self):
        catalog = deepcopy(self.catalog)
        before = deepcopy(catalog)
        operations = (
            lambda: sanitize(catalog),
            lambda: diff.summarize_live_cluster_health(catalog),
            lambda: bao.audit_openbao_secret_provenance(catalog),
            lambda: bao.verify_raft_kms_quorum(catalog),
            lambda: oidc.audit_cluster_ingress_oidc_posture(catalog),
            lambda: chaos.verify_all_six_chaos_planes(catalog),
            lambda: advisor.answer_operational_question("manifest 中文 cluster overview", catalog),
            lambda: portal.ask_concierge_chat("manifest 中文 cluster overview", catalog=catalog),
            lambda: airlock.evaluate_code_search_airlock("manifest 中文"),
            lambda: jev.evaluate_ticket_with_jev_tree("manifest 中文"),
            lambda: self.engine.catalog(),
        )
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                first = operation()
                expected = deepcopy(first)
                self.assertEqual(first, operation())
                first.clear()
                self.assertEqual(expected, operation())
                self.assertEqual(catalog, before)
                self.assert_clean(expected)
        self.assertEqual(diff.compute_catalog_diff(catalog, catalog), {
            "added_node_ids": [], "removed_node_ids": [],
            "status_transitions": [], "metrics_deltas": {}})

    def test_public_tree_stays_opsec_clean(self):
        self.assertFalse(any(scan_public_files(ROOT).values()), "public tree has OPSEC findings")


if __name__ == "__main__":
    unittest.main()
