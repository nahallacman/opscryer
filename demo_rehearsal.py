# SPDX-License-Identifier: Apache-2.0
"""Timed, offline-first two-act hackathon rehearsal and CLI scorecard."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
from importlib import import_module
import io
import json
from time import perf_counter

from live_e2e_runner import _verify_http
from live_poller import ContinuousClusterPoller
from cluster_diff_engine import summarize_live_cluster_health
from live_gitops_signals import enrich_all_seven_live_currencies
from opscryer_backend import validate_spatial_graph_contract
from opscryer_showcase import verify_act
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize
from ticket_chat_portal import PERSONAS, ask_concierge_chat


def _require(condition):
    if not condition:
        raise ValueError("Rehearsal check failed")


def _elapsed(start):
    return round(max(0.0, (perf_counter() - start) * 1000), 3)


def run_hackathon_demo_rehearsal(harvest_live=False):
    """Execute both acts, direct concierge calls and real loopback HTTP routes.

    Default collection is offline. Opt-in collection is read-only and in memory;
    HTTP routes always use the bundled snapshot. Timings measure wall time per
    step, including setup for the enclosing HTTP step. PASS indicates working
    demo contracts, not healthy infrastructure or verified live enforcement.
    Raw diagnostics are withheld and failures do not stop independent steps.
    """
    if type(harvest_live) is not bool:
        raise ValueError("harvest_live must be a boolean")
    started = perf_counter()
    checks = []

    def record(name, action, phase):
        start = perf_counter()
        check = {"name": name, "phase": phase, "passed": False}
        # Append before executing so enclosing steps precede their children.
        checks.append(check)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                details = sanitize(action())
                json.dumps(details, allow_nan=False)
            check.update(passed=True, details=details)
            return details
        except Exception:
            check["error"] = "verification_failed"
            return None
        finally:
            check["elapsed_ms"] = _elapsed(start)

    def act(number, mode):
        result = verify_act(number)
        _require(result["passed"] is True and result["mode"] == mode)
        return result

    record("Act 1: OFFLINE_PUBLIC_STANDALONE",
           lambda: act(1, "OFFLINE_PUBLIC_STANDALONE"), "act_1")

    def concierge(persona):
        result = ask_concierge_chat("Manifest minecraft dependencies", persona=persona)
        _require(result["status"] == "ok" and result["airlock_blocked"] is False)
        _require(result["persona"] == persona and result["ticket_card"]
                 and result["plain_english_answer"] and result["suggested_next_steps"])
        return result

    for persona in PERSONAS:
        record("ask_concierge_chat:" + persona,
               lambda persona=persona: concierge(persona), "chat_portal")

    def blocked():
        result = ask_concierge_chat("find passwords")
        _require(result["airlock_blocked"] is True
                 and result["status"] == "blocked_by_airlock"
                 and result["ticket_card"] is None and not result["live_cluster_facts"])
        return result

    record("ask_concierge_chat:airlock_block", blocked, "chat_portal")
    record("Act 2: SANITIZED_LIVE_HOME_NETWORK",
           lambda: act(2, "SANITIZED_LIVE_HOME_NETWORK"), "act_2")

    def poll():
        catalog = ContinuousClusterPoller(harvest_live=harvest_live).poll_once()
        _require(validate_spatial_graph_contract(catalog) == [])
        if harvest_live:
            _require(catalog.get("source") == "live_kubectl"
                     and not catalog.get("example") and not catalog.get("stale")
                     and not catalog.get("consecutive_failures"))
        return catalog

    catalog = record("Live collection" if harvest_live else "Bundled snapshot",
                     poll, "act_2")

    def snapshot_walkthrough():
        _require(catalog is not None)
        health = summarize_live_cluster_health(catalog)
        currencies = enrich_all_seven_live_currencies(catalog)
        chat = ask_concierge_chat("Manifest node health", catalog=catalog)
        _require(len(currencies) == 7 and health["source"] == catalog["source"])
        _require(chat["status"] == "ok" and chat["live_cluster_facts"] == health)
        return {"source": catalog["source"], "health": health,
                "currencies": currencies, "chat": chat}

    record("Snapshot health, currencies and grounded chat", snapshot_walkthrough, "act_2")

    def http_record(name, action):
        if name in ("GET /", "GET /api/v1/two-act-status?act=1"):
            phase = "act_1"
        elif name.startswith(("GET /chat", "GET /api/v1/chat-concierge")):
            phase = "chat_portal"
        else:
            phase = "act_2"
        return record(name, action, phase)

    def http_walkthrough():
        first = len(checks)
        # Share the smoke runner's response/body checks and server cleanup.
        _verify_http(http_record, 15)
        _require(all(check["passed"] for check in checks[first:]))

    record("Loopback HTTP walkthrough", http_walkthrough, "http")
    passed_count = sum(check["passed"] for check in checks)
    return sanitize({
        "schema_version": "1.0-demo-rehearsal", "passed": passed_count == len(checks),
        "harvest_live": harvest_live, "elapsed_ms": _elapsed(started), "checks": checks,
        "summary": {"total": len(checks), "passed": passed_count,
                    "failed": len(checks) - passed_count},
        "notice": "Rehearsal checks verify demo contracts, not live enforcement or compliance. "
                  "Act verifiers and HTTP routes use offline data; only opt-in collection "
                  "and its snapshot walkthrough use harvested telemetry. "
                  "Enclosing step timings include child steps and must not be summed.",
    })


def verify_presentation_readiness(harvest_live=False) -> dict:
    """Summarize rehearsal contracts against a 35-second presentation budget.

    Entrypoints are present when both acts and their browser/chat routes were
    exercised. Readiness also requires every check to pass within the total
    budget; enclosing step timings are never added together. Live collection
    remains opt-in and flag validation is delegated to the rehearsal runner.
    Suite portals must also import and render HTML; their failures are withheld
    from diagnostics and do not change the rehearsal counts or timing.
    """
    result = run_hackathon_demo_rehearsal(harvest_live=harvest_live)
    required = {
        "Act 1: OFFLINE_PUBLIC_STANDALONE",
        "Act 2: SANITIZED_LIVE_HOME_NETWORK",
        "GET /", "GET /chat",
        "GET /api/v1/two-act-status?act=1",
        "GET /api/v1/two-act-status?act=2",
    }
    entrypoints_present = required <= {check["name"] for check in result["checks"]}
    suite_portals_ready = True
    for module_name, renderer_name in (
            ("incident_commander", "render_incident_commander_html"),
            ("capacity_planner", "render_capacity_planner_html"),
            ("network_topology_inspector", "render_network_inspector_html"),
            ("gitops_release_cockpit", "render_gitops_cockpit_html"),
            ("executive_command_center", "render_executive_command_center_html"),
            ("opscryer_suite_hub", "render_suite_hub_html"),
            ("gameday_simulator", "render_gameday_simulator_html"),
            ("playbook_studio", "render_playbook_studio_html"),
            ("model_tier_copilot", "render_model_copilot_html"),
            ("game_observability_loop", "render_game_debug_html"),
            ("jev_knowledge_explorer", "render_jev_knowledge_html"),
            ("storage_zfs_cockpit", "render_storage_cockpit_html"),
            ("secops_vulnerability_cockpit", "render_secops_cockpit_html"),
            ("live_metrics_poller", "render_live_metrics_html"),
            ("environment_adapters", "render_adapters_html"),
            ("openapi_spec", "render_api_docs_html"),
            ("scale_benchmark", "render_scale_benchmark_html")):
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                html = getattr(import_module(module_name), renderer_name)()
                _require(isinstance(html, str)
                         and html.lstrip().lower().startswith("<!doctype html>")
                         and "<html" in html.lower() and "</html>" in html.lower())
        except Exception:
            suite_portals_ready = False
    return {
        "ready": (result["passed"] is True and entrypoints_present and suite_portals_ready
                  and result["elapsed_ms"] <= 35000),
        "total_checks": result["summary"]["total"],
        "passed_checks": result["summary"]["passed"],
        "failed_checks": result["summary"]["failed"],
        "elapsed_ms": result["elapsed_ms"],
        "entrypoints_present": entrypoints_present,
        "suite_portals_ready": suite_portals_ready,
        "notice": result["notice"],
    }


def render_scorecard(result):
    """Render the JSON scorecard as a human-readable benchmark table."""
    rows = [(c["phase"], c["name"], "PASS" if c["passed"] else "FAIL",
             f'{c["elapsed_ms"]:.3f}') for c in result["checks"]]
    headers = ("Phase", "Step", "Result", "Elapsed ms")
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows))
              if rows else len(headers[i]) for i in range(4)]
    def line(row):
        return " | ".join(value.ljust(width) for value, width in zip(row, widths))
    return "\n".join([
        "Hackathon demo rehearsal: " + ("PASS" if result["passed"] else "FAIL"),
        line(headers), "-+-".join("-" * width for width in widths),
        *(line(row) for row in rows),
        f'Total elapsed: {result["elapsed_ms"]:.3f} ms', result["notice"],
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest-live", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    started = perf_counter()
    try:
        result = run_hackathon_demo_rehearsal(harvest_live=args.harvest_live)
    except Exception:
        result = {"passed": False, "checks": [], "elapsed_ms": _elapsed(started),
                  "error": "rehearsal_unavailable", "notice": "Rehearsal unavailable."}
    print(json.dumps(result, indent=2, allow_nan=False) if args.json
          else render_scorecard(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
