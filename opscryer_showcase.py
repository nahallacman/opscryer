# SPDX-License-Identifier: Apache-2.0
"""Two-act public demo and master verifier using only the Python standard library.

Verification covers shipped public contracts and simulations, not deployed
infrastructure or certification. EPIC-5 includes offline cluster contracts.
No live telemetry is collected. Test diagnostics and raw inputs are never emitted.
"""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
from ipaddress import IPv4Address
import json
from pathlib import Path
import sys
import unittest

import dogfood_graph
import cluster_harvester
import cluster_diff_engine
import chaos_blast_radius
from golden_path_gates import _opsec_count
import live_advisor
import live_currencies
import live_gitops_signals
import oidc_rbac_verifier
import openbao_kms_provenance
import oscal_compliance
import opscryer_backend
import opscryer_browser
import telemetry_sanitizer
import ticket_chat_portal


EPIC_TESTS = {
    "EPIC-1": ("tests.test_opscryer_public_smoke", "tests.test_two_act_browser",
               "tests.test_demo_rehearsal", "tests.test_opscryer_suite_hub"),
    "EPIC-2": ("tests.test_jev_client", "tests.test_playbook_studio",
               "tests.test_jev_knowledge_explorer"),
    "EPIC-3": ("tests.test_opscryer_backend", "tests.test_model_tier_copilot"),
    "EPIC-4": ("tests.test_security_airlock", "tests.test_secops_vulnerability_cockpit"),
    "EPIC-5": ("tests.test_dogfood_graph", "tests.test_cluster_harvester",
               "tests.test_live_poller", "tests.test_cluster_diff_engine",
               "tests.test_live_advisor", "tests.test_live_currencies",
               "tests.test_live_watch_daemon", "tests.test_openbao_kms_provenance",
               "tests.test_oidc_rbac_verifier", "tests.test_chaos_blast_radius",
               "tests.test_live_gitops_signals", "tests.test_live_ollama_probe",
               "tests.test_live_e2e_runner", "tests.test_network_topology_inspector"),
    "EPIC-6": ("tests.test_golden_path_gates", "tests.test_gitops_release_cockpit"),
    "EPIC-7": ("tests.test_noc_golden_signals", "tests.test_incident_commander",
               "tests.test_gameday_simulator", "tests.test_storage_zfs_cockpit"),
    "EPIC-8": ("tests.test_gpu_and_household_triage", "tests.test_ticket_chat_portal",
               "tests.test_chat_walkthrough", "tests.test_capacity_planner",
               "tests.test_game_observability_loop"),
    "EPIC-9": ("tests.test_oscal_compliance", "tests.test_telemetry_sanitizer",
               "tests.test_edge_case_hardening", "tests.test_executive_command_center"),
}
NOTICE = (
    "Public contracts and simulations only; no deployment or compliance certification. "
    "EPIC-5 verifies its planned graph walkthrough and offline cluster contracts; "
    "OpenBao provenance, OIDC posture and six-plane chaos are snapshot audits and simulations; "
    "live enforcement remains unverified. "
    "Act 2 checks synthetic telemetry and the bundled sanitized cluster catalog "
    "without live network collection, including snapshot health, enriched currencies "
    "and deterministic grounded operational advice."
)


def _check(condition):
    if not condition:
        raise ValueError("Verification check failed")


def _verify_wave_b6_catalog(catalog):
    """Exercise portal and posture contracts using one explicit offline snapshot."""
    node_ids = {node["id"] for node in catalog["nodes"]}
    chat = ticket_chat_portal.ask_concierge_chat("manifest node health", catalog=catalog)
    _check(chat["status"] == "ok" and chat["airlock_blocked"] is False)
    _check(chat["ticket_card"] and chat["suggested_next_steps"])
    _check(chat["live_cluster_facts"]["source"] == catalog["source"])
    _check(chat["cited_node_ids"] and set(chat["cited_node_ids"]) <= node_ids)
    chaos = chaos_blast_radius.verify_all_six_chaos_planes(catalog=catalog)
    _check(chaos["status"] == "contained" and chaos["blast_radius_contained"] is True)
    _check(chaos["verified_plane_count"] == chaos["plane_count"] == 6)
    _check(set(chaos["planes"]) == set(chaos_blast_radius.PLANES))
    for evidence in (chaos, *chaos["planes"].values()):
        _check(evidence["simulation_only"] is True
               and evidence["live_enforcement_verified"] is False)
        _check(evidence["blast_radius_contained"] is True)
    provenance = openbao_kms_provenance.audit_openbao_secret_provenance(catalog=catalog)
    _check(provenance["algorithm"] == "SHA-256" and provenance["workloads"])
    _check(provenance["status"] == "passed_observed_fields"
           and provenance["zero_plaintext_leakage"] is True and not provenance["findings"])
    _check(all(len(item["sha256"]) == 64
               and all(char in "0123456789abcdef" for char in item["sha256"])
               for item in provenance["workloads"]))
    oidc = oidc_rbac_verifier.audit_cluster_ingress_oidc_posture(catalog=catalog)
    # Missing runtime observations are valid unknown posture, never enforcement.
    _check(oidc["status"] in ("unknown", "configured_observed_fields")
           and oidc["enforcement_verified"] is False)
    _check(oidc["ingress_count"] == len(oidc["ingresses"]) > 0
           and 0 <= oidc["configured_count"] <= oidc["ingress_count"])
    currencies = live_gitops_signals.enrich_all_seven_live_currencies(catalog=catalog)
    _check([item["currency_id"] for item in currencies] == [
        "nodes", "cpu_load", "ram_load", "network_load", "build_supply",
        "renovate_failures", "open_mrs"])
    _check(all(item["target_id"] in node_ids for currency in currencies
               for item in currency["dropdown_items"]))
    posture = oscal_compliance.evaluate_live_oscal_posture(catalog=catalog)
    _check({control["control_id"] for control in posture["controls"]} == {
        "AC-2", "AC-6", "AU-6", "CM-2", "CM-8", "IR-4", "RA-5", "SC-7", "SI-2"})
    _check(posture["summary"]["total"] == len(posture["controls"]) == 9)
    _check(all(control["status"] in ("partial", "pending", "failed")
               and control["live_evidence"] for control in posture["controls"]))
    for evidence in (chat, chaos, provenance, oidc, currencies, posture):
        _check(telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(evidence) == evidence)
        _check(_opsec_count(json.dumps(evidence, ensure_ascii=False,
                                      allow_nan=False).encode("utf-8")) == 0)


def _verify_cluster_catalogs():
    """Check generated and shipped catalogs without collecting or emitting data."""
    content = Path(__file__).with_name("live-cluster-sanitized.json").read_bytes()
    _check(_opsec_count(content) == 0)
    bundled = json.loads(content)
    generated = cluster_harvester.build_live_cluster_spatial_catalog()
    for catalog in (generated, bundled):
        _check(not opscryer_backend.validate_spatial_graph_contract(catalog))
        _check(catalog["root_id"] == cluster_harvester.ROOT_ID)
        _check(catalog["source"] in ("offline_fallback", "live_" + "kubectl"))
        _check(type(catalog["example"]) is bool
               and catalog["example"] == (catalog["source"] == "offline_fallback"))
        _check(telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(catalog) == catalog)
        # Scan decoded data too: JSON escapes must not conceal forbidden values.
        _check(_opsec_count(json.dumps(catalog, ensure_ascii=False,
                                      allow_nan=False).encode("utf-8")) == 0)
    _check(generated["source"] == "offline_fallback" and generated["example"] is True)
    # Pass the verified snapshot explicitly: no polling, default-file fallback,
    # or model service is needed to exercise the continuous live contracts.
    health = cluster_diff_engine.summarize_live_cluster_health(bundled)
    currencies = live_currencies.build_enriched_live_currencies(bundled)
    answer = live_advisor.answer_operational_question(
        "manifest node health", catalog=bundled, provider="deterministic")
    for counts_key, kind in (("node_counts", "Node"), ("pod_counts", "Pod"),
                             ("deployment_counts", "Deployment")):
        counts = health[counts_key]
        _check(counts["total"] == sum(
            node.get("resource_kind", node.get("resource", {}).get("kind")) == kind
            for node in bundled["nodes"]))
        _check(all(type(value) is int and value >= 0 for value in counts.values()))
        _check(counts["total"] == sum(value for key, value in counts.items()
                                     if key != "total"))
    _check(health["source"] == bundled["source"]
           and health["example"] == bundled["example"])
    _check([currency["currency_id"] for currency in currencies] == [
        "nodes", "cpu_load", "ram_load", "network_load", "build_supply",
        "renovate_failures", "open_mrs"])
    node_ids = {node["id"] for node in bundled["nodes"]}
    _check(all(item["target_id"] in node_ids for currency in currencies
               for item in currency["dropdown_items"]))
    _check(answer["status"] == "ok" and answer["airlock_blocked"] is False)
    _check(answer["question_category"] == "node_health" and answer["live_facts"] == health)
    _check(answer["cited_node_ids"] and set(answer["cited_node_ids"]) <= node_ids)
    _check(answer["bm25_hits"] and all(hit["id"] in answer["cited_node_ids"]
                                      for hit in answer["bm25_hits"]))
    _check(answer["shortest_path"]["path_found"] is True
           and set(answer["shortest_path"]["path_ids"]) <= set(answer["cited_node_ids"]))
    _check(answer["jev_routing"]["route"] and answer["recommended_kubectl_commands"])
    for evidence in (health, currencies, answer):
        _check(telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(evidence) == evidence)
        _check(_opsec_count(json.dumps(evidence, ensure_ascii=False,
                                      allow_nan=False).encode("utf-8")) == 0)
    _verify_wave_b6_catalog(bundled)
    return {"generated_contract": True, "bundled_contract": True,
            "opsec_clean": True, "artifact": "live-cluster-sanitized.json"}


def verify_act(act):
    """Exercise one complete local demo flow; return only safe evidence."""
    # Dependencies may print diagnostics containing unsanitized inputs. Keep
    # those streams private just as the Epic test runner does.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return _verify_act(act)


def _verify_act(act):
    """Run the selected flow inside the public verifier's output boundary."""
    if type(act) is not int or act not in (1, 2):
        raise ValueError("act must be an integer of 1 or 2")
    mode = ("OFFLINE_PUBLIC_STANDALONE" if act == 1 else
            "SANITIZED_LIVE_HOME_NETWORK")
    result = {"act": act, "mode": mode, "passed": False,
              "live_connections": False, "data_source": "synthetic"}
    try:
        status = opscryer_browser.build_two_act_browser_status(act)
        _check(status["mode"] == mode and status["live_connections"] is False)
        if act == 1:
            catalog = opscryer_browser.build_standalone_demo_dataset()
            engine = opscryer_backend.KnowledgeGraphBackendEngine(catalog)
            _check(not opscryer_backend.validate_spatial_graph_contract(engine.catalog()))
            hits = engine.search("pipeline")["results"]
            _check(hits and engine.shortest_path("root-company", hits[0]["id"])["path_found"])
            ticket = engine.deflect_ticket("scaffold a new project")
            _check(ticket["anchor_node_id"] in {node["id"] for node in catalog["nodes"]})
            _check("<html" in opscryer_browser.render_standalone_browser_html().lower())
            for level in range(5):
                zoom = dogfood_graph.query_node_at_progressive_zoom(zoom_level=level)
                _check(zoom["nodes"] and all(n["zoom_level"] <= level for n in zoom["nodes"]))
            result["checks"] = ["browser", "graph_contract", "bm25", "rooted_path",
                                "ticket_anchor", "progressive_zoom_L0_L4"]
        else:
            # Construct synthetic sensitive-looking values only in memory.
            raw = {"wan": str(IPv4Address(0x08080808)),
                   "mac": ":".join(("AA", "BB", "CC", "DD", "EE", "FF")),
                   "lan": ["10.20.3.2", "172.20.1.2", "172.16.0.2"],
                   "hostname": "gpu.cluster.example.org",
                   "nested": [{"password": "synthetic-demo-value"}]}
            clean = telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(raw)
            expected = {"wan": "203.0.113.1", "mac": "AA:BB:CC:XX:XX:XX",
                        "lan": raw["lan"], "hostname": "gpu.cluster.example.org",
                        "nested": [{"password": "[REDACTED]"}]}
            _check(clean == expected)
            _check(raw["wan"] != clean["wan"] and raw["mac"] != clean["mac"])
            _check(telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(clean) == clean)
            # Send only sanitized data through the shared graph exchange boundary.
            catalog = opscryer_browser.build_standalone_demo_dataset()
            catalog["nodes"][0]["telemetry"] = clean
            engine = opscryer_backend.KnowledgeGraphBackendEngine(catalog)
            _check(engine.drilldown("root-company")["node"]["telemetry"] == expected)
            result["cluster"] = _verify_cluster_catalogs()
            result["telemetry"] = expected
            result["checks"] = ["wan_scrub", "mac_mask", "lan_and_hostname_preserved",
                                "nested_credentials", "idempotence", "graph_exchange",
                                "cluster_harvester_contract", "bundled_cluster_contract",
                                "cluster_opsec_clean", "summarize_live_cluster_health",
                                "build_enriched_live_currencies", "answer_operational_question",
                                "ask_concierge_chat", "verify_all_six_chaos_planes",
                                "audit_openbao_secret_provenance",
                                "audit_cluster_ingress_oidc_posture",
                                "enrich_all_seven_live_currencies", "evaluate_live_oscal_posture"]
        result["passed"] = True
    except Exception:
        result["error"] = "Act verification failed; raw diagnostics withheld"
    return result


def _run_epic(epic_id, modules):
    """Run explicit suites (never recursive discovery of the master verifier)."""
    record = {"epic_id": epic_id, "passed": False, "tests_run": 0,
              "failures": 0, "errors": 0, "skipped": 0,
              "scope": "public_contracts_and_simulations"}
    if epic_id == "EPIC-5":
        record["scope"] = "planned_graph_walkthrough_and_offline_cluster_contracts"
    try:
        # Suppress arbitrary test output, exception messages and sensitive values.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromNames(modules)
            outcome = unittest.TestResult()
            suite.run(outcome)
            if epic_id == "EPIC-5":
                _verify_cluster_catalogs()
                zoom = dogfood_graph.query_node_at_progressive_zoom("epic-5", 4)
                _check(zoom["node"]["status"] == "planned")
                _check({"project-5", "feature-5", "runbook-5"}
                       <= {node["id"] for node in zoom["nodes"]})
            record.update(tests_run=outcome.testsRun, failures=len(outcome.failures),
                          errors=len(outcome.errors), skipped=len(outcome.skipped))
            record["passed"] = (outcome.wasSuccessful() and outcome.testsRun > 0
                                and not outcome.skipped and not outcome.expectedFailures
                                and not outcome.unexpectedSuccesses and not loader.errors)
    except Exception:
        record["errors"] += 1
    return record


def verify_all_epics():
    """Execute public verification for each Epic and both demonstration acts."""
    epics = [_run_epic(epic, modules) for epic, modules in EPIC_TESTS.items()]
    acts = [verify_act(1), verify_act(2)]
    verified = sum(epic["passed"] for epic in epics)
    return {"schema_version": "1.0", "passed": verified == 9 and all(a["passed"] for a in acts),
            "epics_verified": verified, "epics": epics, "acts": acts, "notice": NOTICE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--act", type=int, choices=(1, 2), help="Verify one demonstration act")
    parser.add_argument("--verify-all-epics", action="store_true",
                        help="Run all nine public Epic suites and both acts (default)")
    parser.add_argument("--json", action="store_true", help="Emit the structured JSON scorecard")
    args = parser.parse_args(argv)
    if args.verify_all_epics or args.act is None:
        scorecard = verify_all_epics()
    else:
        act = verify_act(args.act)
        scorecard = {"schema_version": "1.0", "passed": act["passed"],
                     "epics_verified": 0, "epics": [], "acts": [act], "notice": NOTICE}
    if args.json:
        print(json.dumps(scorecard, indent=2, allow_nan=False))
    else:
        print("OpsCryer showcase: " + ("PASS" if scorecard["passed"] else "FAIL"))
        print(f"Epics verified: {scorecard['epics_verified']}/9")
        for act in scorecard["acts"]:
            print(f"Act {act['act']}: {act['mode']} - " + ("PASS" if act["passed"] else "FAIL"))
        print(NOTICE)
    return 0 if scorecard["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
