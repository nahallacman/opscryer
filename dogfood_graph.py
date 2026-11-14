# SPDX-License-Identifier: Apache-2.0
"""Synthetic OpsCryer self-dogfood graph with five disclosure levels.

``build_dogfood_zoom_catalog`` returns the complete storage catalog, including
deep details. Use ``query_node_at_progressive_zoom`` for presentation: its
subtree contains only nodes and fields visible at the requested absolute level.
This is a presentation boundary, not an authorization mechanism.
All people, tickets, MR records, CI records and resource readings are examples.
"""

from copy import deepcopy


CONTRACT_VERSION = "1.0-separable-spatial-graph-contract"
ROOT_ID = "root-company"
_TEST_COMMAND = "python -m unittest discover -s tests -v"
_EPICS = (
    ("Spatial Information Tree & RTS Browser", "Zoom from the Citadel through each box and back."),
    ("System-1 Jev Ticket Deflection", "Compare scaffolding, credential and unclassified ticket routes."),
    ("Headless Knowledge Graph & BM25", "Inspect a catalog, then compare search and shortest-path results."),
    ("Argus Container Factory & Code Search", "Review the planned container isolation and code-search boundary."),
    ("OpenBao Identity & Chaos Isolation", "Review the planned identity and six-plane isolation walkthrough."),
    ("GitLab Golden Path Ticket Concierge", "Review the planned pipeline gates and ticket concierge walkthrough."),
    ("Pi NOC Kiosk & Grafana Cockpit", "Review the planned kiosk navigation and dashboard walkthrough."),
    ("GPU Workload Switcher & Household Portal", "Review the planned GPU allocation and household ticket walkthrough."),
    ("Apache Public Release & OSCAL Export", "Review the planned release attribution and compliance export walkthrough."),
)


def build_dogfood_zoom_catalog():
    """Return a fresh JSON-compatible SpatialGraphContract v1 storage catalog.

    L0: Citadel and seven aggregate currencies; L1: teams, units, people, epics;
    L2: projects and walkthroughs; L3: feature verification, MRs and pipelines;
    L4: runbook CLI commands and supported Jev predicates. Planned epics are
    explicitly identified; example CI states do not claim successful execution.
    """
    nodes, edges = [], []

    def add(node_id, label, kind, level, parent=None, **details):
        node = {"id": node_id, "label": label, "kind": kind,
                "domain": "company_org", "summary": label,
                "primary_url": "https://example.org/opscryer/" + node_id,
                "zoom_level": level, "drilldown_children": [], **details}
        nodes.append(node)
        if parent is not None:
            parent["drilldown_children"].append(node_id)
            edges.append({"source": parent["id"], "target": node_id,
                          "relation": "contains"})
        return node

    root = add(ROOT_ID, "OpsCryer Root Citadel", "company_root", 0)
    team = add("team-platform", "OpsCryer Platform Team", "company_team", 1, root)
    add("unit-dogfood", "Dogfood AI Unit", "ai_agent_unit", 1, team,
        handle="dogfood-agent", telemetry={"state": "EXAMPLE", "routing": "local"})
    add("person-demo-maintainer", "Demo Maintainer", "person", 1, team,
        handle="demo-maintainer", team_id=team["id"])
    for number, (title, walkthrough) in enumerate(_EPICS, 1):
        epic = add(f"epic-{number}", f"EPIC-{number}: {title}", "epic", 1, team,
                   status="implemented" if number <= 3 else "planned")
        project = add(f"project-{number}", title, "engineering_project", 2, epic,
                      walkthroughs=[walkthrough])
        feature = add(f"feature-{number}", title + " verification", "feature", 3, project,
                      automated_test_commands=[_TEST_COMMAND],
                      manual_steps=[walkthrough, "Record observed behavior and any failing checks."],
                      merge_requests=[{"id": f"MR-DEMO-{number}", "status": "example",
                                       "url": f"https://example.org/opscryer/merge_requests/{number}"}],
                      ci_pipelines=[{"id": f"CI-DEMO-{number}", "status": "not_run",
                                     "example": True, "command": _TEST_COMMAND}])
        commands = [_TEST_COMMAND]
        if number == 1:
            commands = ["python opscryer_browser.py --serve --port 8088"]
        elif number == 2:
            commands = [
                'python -c "from jev_client import evaluate_ticket_with_jev_tree; '
                "print(evaluate_ticket_with_jev_tree('scaffold a new project'))\""
            ]
        elif number == 3:
            commands = [
                'python -c "from opscryer_backend import KnowledgeGraphBackendEngine; '
                'print(KnowledgeGraphBackendEngine().catalog())"'
            ]
        add(f"runbook-{number}", title + " deep runbook", "operational_process", 4, feature,
            cli_commands=commands,
            jev_predicates=[{"predicate_id": "is_project_scaffolding", "min_confidence": 0.80},
                            {"predicate_id": "is_credential_access", "min_confidence": 0.80}],
            on_uncertain="human_escalation")

    currencies = [
        {"currency_id": key, "label": label, "display_value": value,
         "supply_kind": kind, "dropdown_items": []}
        for key, label, value, kind in (
            ("nodes", "Nodes", "3/3 Ready (example)", "supply_cap"),
            ("cpu_load", "CPU Load", "24% (example)", "currency_rate"),
            ("ram_load", "RAM Load", "54% (example)", "currency_rate"),
            ("network_load", "Net Load %", "11% (example)", "currency_rate"),
            ("build_supply", "Build Supply", "4/5 Slots (example)", "food_supply"),
            ("renovate_failures", "Renovate", "0 Fail (example)", "upkeep_alert"),
            ("open_mrs", "Open MRs", "9 (example)", "production_queue"),
        )
    ]
    return {"schema_version": CONTRACT_VERSION, "root_id": ROOT_ID, "example": True,
            "nodes": nodes, "edges": edges, "rts_currencies": currencies,
            "tickets": [
                {"id": "DOGFOOD-1", "title": "Verify progressive disclosure",
                 "assignee_id": "person-demo-maintainer", "status": "open",
                 "feature_id": "feature-1"},
                {"id": "DOGFOOD-2", "title": "Check Jev confidence boundary",
                 "assignee_id": "person-demo-maintainer", "status": "in_progress",
                 "feature_id": "feature-2"},
                {"id": "DOGFOOD-3", "title": "Inspect graph contract",
                 "assignee_id": "person-demo-maintainer", "status": "closed",
                 "feature_id": "feature-3"},
            ]}


def _zoom(level):
    if type(level) is not int or not 0 <= level <= 4:
        raise ValueError("zoom_level must be an integer from 0 to 4")


def query_node_at_progressive_zoom(node_id=ROOT_ID, zoom_level=0, catalog=None):
    """Return a detached visible subtree rooted at ``node_id``.

    Levels are cumulative, absolute L0-L4 integers (booleans are rejected).
    Unknown IDs raise KeyError. A known node above the requested level returns
    ``encapsulated=True`` and no node payload. Hidden child IDs and edges are
    omitted; ``encapsulated_child_count`` indicates further boxes to explore.
    Only the root response includes aggregate currencies. No ticket store or
    other full-catalog metadata is included in a presentation response.
    """
    _zoom(zoom_level)
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("node_id must be a nonempty string")
    catalog = build_dogfood_zoom_catalog() if catalog is None else catalog
    by_id = {node["id"]: node for node in catalog["nodes"]}
    if node_id not in by_id:
        raise KeyError("Unknown dogfood node")
    result = {"zoom_level": zoom_level, "node": None, "nodes": [], "edges": [],
              "encapsulated": by_id[node_id]["zoom_level"] > zoom_level}
    if result["encapsulated"]:
        return result

    seen = set()

    def visit(current_id):
        if current_id in seen:
            return
        seen.add(current_id)
        source = by_id[current_id]
        visible = [child for child in source["drilldown_children"]
                   if by_id[child]["zoom_level"] <= zoom_level]
        # Field allowlists ensure deep payloads cannot leak through ancestors.
        fields = ["id", "label", "kind", "domain", "summary", "primary_url", "zoom_level"]
        if zoom_level >= 1:
            fields += ["status", "handle", "team_id", "telemetry"]
        if zoom_level >= 2:
            fields += ["walkthroughs"]
        if zoom_level >= 3:
            fields += ["automated_test_commands", "manual_steps", "merge_requests", "ci_pipelines"]
        if zoom_level >= 4:
            fields += ["cli_commands", "jev_predicates", "on_uncertain"]
        node = {key: deepcopy(source[key]) for key in fields if key in source}
        node["drilldown_children"] = visible
        node["encapsulated_child_count"] = len(source["drilldown_children"]) - len(visible)
        result["nodes"].append(node)
        for child in visible:
            visit(child)

    visit(node_id)
    result["node"] = deepcopy(result["nodes"][0])
    result["edges"] = deepcopy([edge for edge in catalog["edges"]
                                if edge["source"] in seen and edge["target"] in seen])
    if node_id == catalog["root_id"]:
        result["rts_currencies"] = deepcopy(catalog["rts_currencies"])
    return result


def lookup_person_and_open_tickets(person, catalog=None):
    """Find an exact, case-insensitive person ID, label or handle and open work.

    Open statuses are open, in_progress, and blocked. Unknown people return
    ``person=None`` and an empty list; ambiguous names raise ValueError so work
    cannot accidentally be attributed to another person. Tickets join on ID.
    This explicit lookup is independent of the progressive presentation API.
    """
    if not isinstance(person, str) or not person.strip():
        raise ValueError("person must be a nonempty string")
    catalog = build_dogfood_zoom_catalog() if catalog is None else catalog
    query = person.strip().casefold()
    matches = [node for node in catalog["nodes"] if node["kind"] == "person"
               and any(query == node.get(field, "").casefold()
                       for field in ("id", "label", "handle"))]
    if len(matches) > 1:
        raise ValueError("Ambiguous person lookup; use a unique person ID")
    found = matches[0] if matches else None
    tickets = [ticket for ticket in catalog["tickets"] if found
               and ticket["assignee_id"] == found["id"]
               and ticket["status"] in {"open", "in_progress", "blocked"}]
    return deepcopy({"person": found, "open_tickets": tickets})


def build_live_verified_dogfood_summary(catalog=None):
    """Map EPIC-1..EPIC-9 to shipped code and sanitized snapshot evidence.

    ``catalog`` is a cluster catalog dict; None reads the bundled snapshot
    relative to this module. No collection, model calls, tests, or deployment
    checks run here. Evidence is resource inventory and observed health, not
    proof of application deployment, identity enforcement, chaos execution,
    GPU allocation, or compliance certification. Empty scopes are explicitly
    unavailable. Legacy synthetic graph APIs and planned statuses are unchanged.

    Results are fresh JSON-compatible dictionaries. Invalid catalogs raise
    ValueError without echoing their contents; inputs are never modified.
    """
    import json
    from pathlib import Path

    from cluster_diff_engine import summarize_live_cluster_health
    from live_currencies import build_enriched_live_currencies
    from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo

    if catalog is None:
        catalog = json.loads(Path(__file__).with_name(
            "live-cluster-sanitized.json").read_text(encoding="utf-8"))
    try:
        snapshot = sanitize_live_home_telemetry_for_demo(catalog)
        # Check identities after redaction too: two IDs must not collapse.
        build_enriched_live_currencies(snapshot)
        for node in snapshot["nodes"]:
            resource = node.get("resource", {})
            metadata = resource.get("metadata", {})
            kind = node.get("resource_kind", resource.get("kind"))
            namespace = node.get("namespace", metadata.get("namespace"))
            if (not isinstance(metadata, dict)
                    or kind is not None and not isinstance(kind, str)
                    or namespace is not None and not isinstance(namespace, str)):
                raise ValueError
        health = summarize_live_cluster_health(snapshot)
        if ("example" in snapshot and type(snapshot["example"]) is not bool
                or "stale" in snapshot and type(snapshot["stale"]) is not bool
                or "source" in snapshot and not isinstance(snapshot["source"], str)):
            raise ValueError
        json.dumps(snapshot, allow_nan=False)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError("Invalid cluster catalog") from None

    # None scopes cover the complete resource inventory. Other scopes are
    # namespace inventories supporting that Epic, not deployment assertions.
    scopes = (
        (("opscryer_browser.py", "dogfood_graph.py"), None,
         ("tests.test_opscryer_public_smoke", "tests.test_two_act_browser")),
        (("jev_client.py", "live_advisor.py"), {"ai-infra", "ai-sandbox"},
         ("tests.test_jev_client", "tests.test_live_advisor")),
        (("opscryer_backend.py",), None, ("tests.test_opscryer_backend",)),
        (("security_airlock.py",), {"security", "dev-envs", "ai-sandbox"},
         ("tests.test_security_airlock",)),
        (("cluster_harvester.py", "live_poller.py", "cluster_diff_engine.py",
          "live_advisor.py", "live_currencies.py", "live_watch_daemon.py",
          "openbao_kms_provenance.py", "oidc_rbac_verifier.py", "chaos_blast_radius.py"),
         {"security", "iam", "kube-system"},
         ("tests.test_cluster_harvester", "tests.test_live_poller",
          "tests.test_cluster_diff_engine", "tests.test_live_advisor",
          "tests.test_live_currencies", "tests.test_live_watch_daemon",
          "tests.test_openbao_kms_provenance", "tests.test_oidc_rbac_verifier",
          "tests.test_chaos_blast_radius", "tests.test_dogfood_graph")),
        (("golden_path_gates.py", "live_gitops_signals.py"),
         {"gitlab", "argocd", "devops-tools"},
         ("tests.test_golden_path_gates", "tests.test_live_gitops_signals")),
        (("noc_golden_signals.py", "live_currencies.py"), {"monitoring"},
         ("tests.test_noc_golden_signals", "tests.test_live_currencies")),
        (("gpu_and_household_triage.py", "live_ollama_probe.py", "ticket_chat_portal.py"),
         {"ai-infra", "ai-sandbox", "game-servers", "gaming", "media"},
         ("tests.test_gpu_and_household_triage", "tests.test_live_ollama_probe",
          "tests.test_ticket_chat_portal")),
        (("oscal_compliance.py", "telemetry_sanitizer.py"), None,
         ("tests.test_oscal_compliance", "tests.test_telemetry_sanitizer")),
    )
    result = {}
    for number, (modules, namespaces, suites) in enumerate(scopes, 1):
        counts, cited = {}, []
        for node in snapshot["nodes"]:
            resource = node.get("resource", {})
            kind = node.get("resource_kind", resource.get("kind"))
            namespace = node.get("namespace", resource.get("metadata", {}).get("namespace"))
            if kind and (namespaces is None or namespace in namespaces):
                counts[kind] = counts.get(kind, 0) + 1
                cited.append(node["id"])
        result[f"EPIC-{number}"] = {
            "title": _EPICS[number - 1][0],
            "shipped_modules": list(modules),
            "verification_commands": ["python -m unittest " + " ".join(suites) + " -v"],
            "live_evidence": {
                "scope": "snapshot_inventory_and_health",
                "source": snapshot.get("source", "provided_catalog"),
                "example": snapshot.get("example", False),
                "stale": snapshot.get("stale", False),
                "live_connections": False,
                "available": bool(cited),
                "namespaces": sorted(namespaces) if namespaces is not None else None,
                "resource_counts": dict(sorted(counts.items())),
                "cited_node_ids": sorted(cited),
                "cluster_health": deepcopy(health),
            },
        }
    return result
