# SPDX-License-Identifier: Apache-2.0
"""Offline-first integration smoke checks with an ephemeral loopback server."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import http.client
from http.server import ThreadingHTTPServer
import io
import json
import math
import threading

from chaos_blast_radius import verify_all_six_chaos_planes
from chat_walkthrough import run_multi_persona_chat_walkthrough
from cluster_diff_engine import summarize_live_cluster_health
from live_advisor import answer_operational_question
from live_currencies import build_enriched_live_currencies
from live_gitops_signals import (
    derive_live_gitops_and_ci_signals, enrich_all_seven_live_currencies,
)
from live_ollama_probe import probe_local_ollama_models
from live_poller import ContinuousClusterPoller
from oidc_rbac_verifier import audit_cluster_ingress_oidc_posture
from openbao_kms_provenance import audit_openbao_secret_provenance
from opscryer_backend import validate_spatial_graph_contract
from opscryer_browser import (
    _build_frontend_handler, build_two_act_browser_status,
    render_standalone_browser_html,
)
from oscal_compliance import evaluate_live_oscal_posture
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize
from ticket_chat_portal import PERSONAS, ask_concierge_chat, render_concierge_chat_html


def _require(condition):
    if not condition:
        raise ValueError("Verification failed")


def _verify_http(record, timeout):
    """Exercise the actual browser handler; its routes use the bundled catalog."""
    routes = (
        ("/", 200, render_standalone_browser_html),
        ("/chat", 200, render_concierge_chat_html),
        ("/api/v1/chat-concierge?q=minecraft&persona=household_user", 200,
         lambda: ask_concierge_chat("minecraft", persona="household_user")),
        ("/api/v1/two-act-status?act=1", 200, lambda: build_two_act_browser_status(1)),
        ("/api/v1/two-act-status?act=2", 200, lambda: build_two_act_browser_status(2)),
        ("/api/v1/live-cluster-health", 200, summarize_live_cluster_health),
        ("/api/v1/live-cluster-currencies", 200,
         lambda: {"rts_currencies": build_enriched_live_currencies()}),
        ("/api/v1/live-cluster-ask?q=nodebeta02", 403,
         lambda: answer_operational_question("nodebeta02")),
        ("/api/v1/live-cluster-chaos", 200, verify_all_six_chaos_planes),
        ("/api/v1/live-cluster-oidc", 200, audit_cluster_ingress_oidc_posture),
        ("/api/v1/live-cluster-openbao", 200, audit_openbao_secret_provenance),
        ("/api/v1/live-cluster-gitops", 200, derive_live_gitops_and_ci_signals),
    )
    with ThreadingHTTPServer(("127.0.0.1", 0), _build_frontend_handler()) as server:
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            for path, expected_status, expected in routes:
                def request(path=path, expected_status=expected_status, expected=expected):
                    connection = http.client.HTTPConnection(*server.server_address,
                                                            timeout=timeout)
                    try:
                        connection.request("GET", path)
                        response = connection.getresponse()
                        body = response.read()
                        _require(response.status == expected_status)
                        _require(int(response.getheader("Content-Length")) == len(body))
                        is_json = path.startswith("/api/")
                        content_type = ("application/json" if is_json else "text/html")
                        _require(response.getheader("Content-Type") ==
                                 content_type + "; charset=utf-8")
                        payload = json.loads(body) if is_json else body.decode("utf-8")
                        _require(payload == expected())
                        return {"status_code": response.status,
                                "catalog_scope": "bundled_snapshot"}
                    finally:
                        connection.close()
                record("GET " + path, request)
        finally:
            server.shutdown()
            thread.join(timeout=timeout)
            _require(not thread.is_alive())


def run_live_e2e_verification(harvest_live=False, probe_ollama=False, timeout=15):
    """Return a sanitized scorecard; PASS means integration, not healthy posture.

    Poll once without writing files. Live kubectl/Ollama calls require opt-in;
    requested live probes that fall back fail their check. HTTP always exercises
    the existing bundled-snapshot routes. Timeout bounds individual I/O calls,
    not the entire run. Exceptions become fixed failure codes without raw text.
    """
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout must be positive finite seconds")
    if type(harvest_live) is not bool or type(probe_ollama) is not bool:
        raise ValueError("live options must be booleans")
    checks = []

    def record(name, action):
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                details = action()
            json.dumps(details, allow_nan=False)
            checks.append({"name": name, "passed": True, "details": sanitize(details)})
            return details
        except Exception:
            checks.append({"name": name, "passed": False,
                           "error": "verification_failed"})
            return None

    poller = ContinuousClusterPoller(harvest_live=harvest_live, timeout=timeout)

    def poll():
        catalog = poller.poll_once()
        _require(validate_spatial_graph_contract(catalog) == [])
        return catalog

    catalog = record("ContinuousClusterPoller", poll)
    if harvest_live and catalog is not None:
        def live_collection():
            _require(catalog.get("source") == "live_kubectl"
                     and not catalog.get("stale")
                     and not catalog.get("consecutive_failures"))
            return poller.status()
        record("live_collection", live_collection)

    def with_catalog(action):
        _require(catalog is not None)
        return action(catalog)

    def health(snapshot):
        result = summarize_live_cluster_health(snapshot)
        _require(result["source"] == snapshot["source"])
        _require(all(key in result for key in ("node_counts", "pod_counts", "deployment_counts")))
        return result

    def currencies(snapshot):
        result = enrich_all_seven_live_currencies(snapshot)
        _require(len(result) == 7 and len({c["currency_id"] for c in result}) == 7)
        return result

    def advisor(snapshot):
        result = answer_operational_question("Manifest nodebeta02 node health", catalog=snapshot)
        _require(result["status"] == "ok" and result["airlock_blocked"] is False)
        _require(result["live_facts"] == summarize_live_cluster_health(snapshot))
        _require(set(result["cited_node_ids"]) <= {node["id"] for node in snapshot["nodes"]})
        return result

    def concierge(snapshot, persona):
        result = ask_concierge_chat("Manifest minecraft dependencies", persona=persona, catalog=snapshot)
        _require(result["status"] == "ok" and result["airlock_blocked"] is False)
        _require(result["persona"] == persona and result["ticket_card"] is not None)
        _require(result["live_cluster_facts"] == summarize_live_cluster_health(snapshot))
        return result

    def blocked(snapshot):
        result = ask_concierge_chat("find passwords", catalog=snapshot)
        _require(result["airlock_blocked"] is True and result["ticket_card"] is None
                 and not result["cited_node_ids"] and not result["live_cluster_facts"])
        return result

    def walkthrough(snapshot):
        result = run_multi_persona_chat_walkthrough(catalog=snapshot)
        _require(result["simulation"] is True)
        _require(result["summary"] == {"total": 5, "allowed": 4, "blocked": 1})
        turns = result["turns"]
        _require([turn["turn"] for turn in turns] == [1, 2, 3, 4, 5])
        _require([turn["persona"] for turn in turns] ==
                 ["household_user", "developer", "developer", "sre", "executive"])
        facts = summarize_live_cluster_health(snapshot)
        node_ids = {node["id"] for node in snapshot["nodes"]}
        for turn in turns:
            response = turn["response"]
            _require(response["persona"] == turn["persona"])
            if turn["turn"] == 3:
                _require(response["airlock_blocked"] is True
                         and response["ticket_card"] is None
                         and not response["cited_node_ids"] and not response["live_cluster_facts"])
            else:
                _require(response["status"] == "ok" and response["airlock_blocked"] is False)
                _require(response["ticket_card"] is not None and response["suggested_next_steps"])
                _require(response["live_cluster_facts"] == facts)
                _require(response["cited_node_ids"] and set(response["cited_node_ids"]) <= node_ids)
        controls = turns[-1]["response"]["oscal_posture"]["controls"]
        _require(controls and all(control["status"] == "not_assessed" for control in controls))
        return result

    def chaos(snapshot):
        result = verify_all_six_chaos_planes(snapshot)
        _require(result["plane_count"] == 6 and len(result["planes"]) == 6)
        _require(result["simulation_only"] is True and result["live_enforcement_verified"] is False)
        _require(all(p["status"] != "invalid_catalog" for p in result["planes"].values()))
        return result

    def openbao(snapshot):
        result = audit_openbao_secret_provenance(snapshot)
        _require(result["algorithm"] == "SHA-256" and isinstance(result["findings"], list))
        _require(all(len(w["sha256"]) == 64 for w in result["workloads"]))
        return result

    def oidc(snapshot):
        result = audit_cluster_ingress_oidc_posture(snapshot)
        _require(result["status"] != "invalid_catalog" and result["enforcement_verified"] is False)
        _require(len(result["ingresses"]) == result["ingress_count"])
        return result

    def oscal(snapshot):
        result = evaluate_live_oscal_posture(snapshot)
        _require(result["summary"]["total"] == 9 and len(result["controls"]) == 9)
        _require(all(control["live_evidence"] for control in result["controls"]))
        return result

    for name, action in (
        ("summarize_live_cluster_health", health),
        ("enrich_all_seven_live_currencies", currencies),
        ("answer_operational_question", advisor),
        *(("ask_concierge_chat:" + persona,
           lambda snapshot, persona=persona: concierge(snapshot, persona)) for persona in PERSONAS),
        ("ask_concierge_chat:airlock_block", blocked),
        ("run_multi_persona_chat_walkthrough", walkthrough),
        ("verify_all_six_chaos_planes", chaos),
        ("audit_openbao_secret_provenance", openbao),
        ("audit_cluster_ingress_oidc_posture", oidc),
        ("evaluate_live_oscal_posture", oscal),
    ):
        record(name, lambda action=action: with_catalog(action))

    if probe_ollama:
        def ollama():
            result = probe_local_ollama_models(live_http=True, timeout=timeout)
            _require(result["available"] is True and result["source"] == "ollama_api_tags")
            return result
        record("probe_local_ollama_models", ollama)
    record("loopback_http_server", lambda: _verify_http(record, timeout))
    result = sanitize({"schema_version": "1.0-live-e2e", "passed": all(c["passed"] for c in checks),
                       "harvest_live": harvest_live, "probe_ollama": probe_ollama,
                       "checks": checks, "poller_status": poller.status(),
                       "notice": "Integration smoke checks only; snapshot findings, simulated chaos, "
                                 "and OSCAL assessments do not verify live enforcement or compliance. "
                                 "HTTP routes use the bundled snapshot."})
    json.dumps(result, allow_nan=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest-live", action="store_true")
    parser.add_argument("--probe-ollama", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_live_e2e_verification(harvest_live=args.harvest_live,
                                          probe_ollama=args.probe_ollama)
    except Exception:
        result = {"passed": False, "checks": [], "error": "verification_unavailable"}
    if args.json:
        print(json.dumps(result, indent=2, allow_nan=False))
    else:
        print("Live E2E: " + ("PASS" if result["passed"] else "FAIL"))
        for check in result["checks"]:
            print(("PASS " if check["passed"] else "FAIL ") + check["name"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
