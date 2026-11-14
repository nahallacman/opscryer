# SPDX-License-Identifier: Apache-2.0
"""Read-only game fleet observations from a sanitized cluster graph snapshot."""

import argparse
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

import capacity_planner
import gpu_and_household_triage
import incident_commander
import model_tier_copilot
from opscryer_backend import KnowledgeGraphBackendEngine, validate_spatial_graph_contract
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
GAME_PROFILES = ("minecraft", "satisfactory", "factorio", "palworld", "romm")
HARDWARE_NODES = ("nodealpha01", "nodebeta02", "nodegamma03")
OBSERVABILITY_LINKS = {
    "grafana_dashboard_url": "https://grafana.cluster.example.org/dashboards",
    "grafana_explore_url": "https://grafana.cluster.example.org/explore",
    "argocd_app_url": "https://argocd.cluster.example.org/applications",
    "gitlab_pipelines_url": "https://gitlab.cluster.example.org/platform/infra-gitops/-/pipelines",
    "runbookgate_actions_url": "https://runbookgate.cluster.example.org",
}
_INVALID_CATALOG = "Invalid game observability catalog"
_INVALID_REQUEST = "Invalid game observability request"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_INVALID_CATALOG)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(_INVALID_CATALOG)


def _snapshot(catalog):
    """Validate original and redacted identities, including opaque secret data."""
    try:
        if catalog is None:
            catalog = DEFAULT_CATALOG_PATH
        if isinstance(catalog, (str, Path)):
            catalog = json.loads(
                Path(catalog).read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if not isinstance(catalog, dict):
            raise ValueError(_INVALID_CATALOG)
        json.dumps(catalog, allow_nan=False)
        detached = deepcopy(catalog)
        if validate_spatial_graph_contract(detached):
            raise ValueError(_INVALID_CATALOG)
        snapshot = sanitize(detached)
        if validate_spatial_graph_contract(snapshot):
            raise ValueError(_INVALID_CATALOG)
        json.dumps(snapshot, allow_nan=False)
        return snapshot
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, OverflowError):
        raise ValueError(_INVALID_CATALOG) from None


def _matches_game(node, game):
    """Match entity identity and routing evidence, never descriptive prose.

    Token boundaries include Kubernetes suffixes but exclude names such as
    minecraftish. Namespace membership alone does not identify a game.
    """
    if (node["domain"] != "deployments_k8s"
            or node.get("resource_kind") == "Namespace"
            or node["kind"] == "kubernetes_namespace"):
        return False
    resource = node.get("resource", {})
    metadata = resource.get("metadata", {})
    spec = resource.get("spec", {})
    evidence = [node["id"].rsplit("/", 1)[-1], node["label"],
                metadata.get("name", ""), metadata.get("labels", {}),
                spec.get("selector", {}), spec.get("rules", []),
                spec.get("defaultBackend", {})]
    pattern = r"(?<![a-z0-9])" + re.escape(game) + r"(?![a-z0-9])"
    return any(re.search(pattern, value if isinstance(value, str) else
                         json.dumps(value), re.IGNORECASE) for value in evidence)


def _observed_hosts(matches, snapshot, capacity):
    """Follow workload graph links without crossing namespace/root containment."""
    nodes = {node["id"]: node for node in snapshot["nodes"]}
    adjacency = {node_id: set() for node_id in nodes}
    for edge in snapshot.get("edges", []):
        source, target = edge["source"], edge["target"]
        adjacency[source].add(target)
        adjacency[target].add(source)
    hosts = set()
    visited = set()
    pending = [node["id"] for node in matches]
    names_by_id = {node["node_id"]: node["name"] for node in capacity["nodes"]}
    while pending:
        node_id = pending.pop()
        if node_id in visited:
            continue
        visited.add(node_id)
        node = nodes[node_id]
        if node_id in names_by_id:
            hosts.add(names_by_id[node_id])
            continue  # Shared hardware does not connect unrelated workloads.
        if (node["domain"] != "deployments_k8s"
                or node["kind"] == "kubernetes_namespace"
                or node.get("resource_kind") == "Namespace"):
            continue
        resource = node.get("resource", {})
        if node.get("resource_kind", resource.get("kind")) == "Pod":
            host = resource.get("spec", {}).get("nodeName")
            if host:
                hosts.add(host)
        pending.extend(sorted(adjacency[node_id] - visited))
    return sorted(hosts)


def inspect_game_server_fleet(catalog=None) -> dict:
    """Inspect five game profiles without collection, commands or model calls.

    Accept None (the bundled snapshot), a Path/string filename, or a graph dict.
    Missing workloads and hardware are explicit; absence is not a live outage.
    Nominal hardware is a fleet inventory, not an assumed game placement.
    Actual hosting comes from pod nodeName and workload-to-hardware graph links.
    CPU/RAM and readiness describe snapshot time; unknown values remain None.
    """
    snapshot = _snapshot(catalog)
    return _inspect_game_server_fleet(snapshot)


def _inspect_game_server_fleet(snapshot, capacity=None, incidents=None):
    """Inspect an already validated snapshot, reusing operational summaries."""
    try:
        if capacity is None:
            capacity = capacity_planner.summarize_cluster_capacity(snapshot)
        if incidents is None:
            incidents = incident_commander.build_active_incidents_catalog(snapshot)
        by_name = {node["name"]: node for node in capacity["nodes"]}

        def hardware(name):
            observed = by_name.get(name)
            node_id = observed["node_id"] if observed else None
            return {
                "name": name, "present_in_snapshot": observed is not None,
                "node_id": node_id,
                "ready": observed["ready"] if observed else None,
                "readiness": observed["readiness"] if observed else "Unknown",
                "ready_condition": observed["ready_condition"] if observed else None,
                "metrics": deepcopy(observed["metrics"]) if observed else {
                    "cpu_percent": None, "ram_percent": None,
                    "cpu_used": None, "ram_used": None},
                "incidents": [item for item in incidents["incidents"] if node_id
                              and (item["affected_node_id"] == node_id
                                   or node_id in item["hardware_lineage_ids"])],
            }

        games = []
        for game in GAME_PROFILES:
            matches = sorted((node for node in snapshot["nodes"]
                              if _matches_game(node, game)), key=lambda node: node["id"])
            matched_ids = {node["id"] for node in matches}
            host_names = _observed_hosts(matches, snapshot, capacity)
            host_ids = {by_name[name]["node_id"] for name in host_names if name in by_name}
            games.append({
                "game": game, "present_in_snapshot": bool(matches),
                "snapshot_status": "present" if matches else "not_present_in_snapshot",
                "matched_node_ids": sorted(matched_ids), "matched_nodes": matches,
                "observed_hosting_nodes": [hardware(name) for name in host_names],
                "incidents": [item for item in incidents["incidents"] if
                              item["affected_node_id"] in matched_ids | host_ids
                              or host_ids.intersection(item["hardware_lineage_ids"])],
                "observability_links": dict(OBSERVABILITY_LINKS),
            })
        return sanitize({
            "schema_version": 1, "read_only": True,
            "telemetry_source": ("live_kubectl" if snapshot.get("source") == "live_kubectl"
                                 else "offline_fallback"),
            "notice": "Snapshot observations only; no live collection. Missing workloads "
                      "are not confirmed outages. Nominal hardware inventory does not "
                      "establish game placement or root cause.",
            "source": snapshot.get("source", "provided_catalog"),
            "collected_at": snapshot.get("collected_at"),
            "games": games, "nominal_hardware_nodes": list(HARDWARE_NODES),
            "hardware_nodes": [hardware(name) for name in HARDWARE_NODES],
            "cluster_capacity": capacity, "active_incidents": incidents,
            "gpu_workload_plan": gpu_and_household_triage.allocate_gpu_workload_profile(
                "hybrid_balanced"),
            "observability_links": dict(OBSERVABILITY_LINKS),
        })
    except (ValueError, TypeError, KeyError, AttributeError,
            RecursionError, OverflowError):
        raise ValueError(_INVALID_CATALOG) from None


def trace_game_debugging_loop(game='minecraft', catalog=None) -> dict:
    """Build a five-step offline operator runbook; never execute recovery actions.

    Graph observations describe snapshot time, not live health or root cause.
    The deterministic copilot preserves its policy airlock, including denials.
    """
    if not isinstance(game, str) or game not in GAME_PROFILES:
        raise ValueError('Unknown game server profile')
    snapshot = _snapshot(catalog)
    return _trace_game_debugging_loop(game, snapshot, {})


def _trace_game_debugging_loop(game, snapshot, context):
    """Reuse snapshot analysis within one export, never across requests."""
    try:
        symptom = (f"{game} server tick lag or server down: are all players affected, "
                   "does the .cluster.example.org hostname resolve, and is client FPS low?")
        shared = context.setdefault("shared", [snapshot])
        comparison = model_tier_copilot.run_dual_tier_model_comparison(
            f"Manifest {game} game server pods and hosting node readiness: what should we do?",
            snapshot, provider="deterministic", _shared=shared)
        if "fleet" in context:
            engine, nodes, fleet = context["engine"], context["nodes"], context["fleet"]
        elif len(shared) > 1:
            _, engine, nodes, incidents, capacity, _, _ = shared[1]
            fleet = _inspect_game_server_fleet(snapshot, capacity, incidents)
        else:
            engine = KnowledgeGraphBackendEngine(snapshot)
            nodes = {node["id"]: node for node in snapshot["nodes"]}
            fleet = _inspect_game_server_fleet(snapshot)
        context.update(engine=engine, nodes=nodes, fleet=fleet)
        server = next(entry for entry in fleet["games"] if entry["game"] == game)

        # Only observed hosting nodes are targets; containment is not hosting proof.
        lineage = []
        hosting_lineage = []
        hardware_ids = sorted(node["id"] for node in nodes.values()
                              if node["domain"] == "hardware_topology")
        for source in server["matched_node_ids"]:
            paths = []
            for host in server["observed_hosting_nodes"]:
                if not host["node_id"]:
                    continue
                path = engine.shortest_path(source, host["node_id"])
                if path["path_found"] and not any(
                        node["kind"] in {"company_root", "kubernetes_namespace"}
                        for node in path["path_nodes"]):
                    paths.append(path)
            if paths:
                hosting_lineage.append(min(paths, key=lambda path: (path["hop_count"], path["path_ids"])))
            physical_paths = [engine.shortest_path(source, target) for target in hardware_ids]
            physical_paths = [path for path in physical_paths if path["path_found"]
                              and not any(node["kind"] in {"company_root", "kubernetes_namespace"}
                                          for node in path["path_nodes"])
                              and any(host["node_id"] in path["path_ids"]
                                      for host in server["observed_hosting_nodes"])]
            if physical_paths:
                lineage.append(min(physical_paths,
                                   key=lambda path: (path["hop_count"], path["path_ids"])))

        # Use JSON string escaping for exact PromQL/Loki label values. Catalog
        # identities remain data, even when they contain quotes or backslashes.
        pods = sorted({(node.get("resource", {}).get("metadata", {}).get("namespace"),
                        node.get("resource", {}).get("metadata", {}).get("name"))
                       for node in server["matched_nodes"]
                       if node.get("resource_kind", node.get("resource", {}).get("kind")) == "Pod"
                       and isinstance(node.get("resource", {}).get("metadata", {}).get("namespace"), str)
                       and isinstance(node.get("resource", {}).get("metadata", {}).get("name"), str)})
        queries = []
        for namespace, pod in pods or [("NAMESPACE", "POD")]:
            labels = f'namespace={json.dumps(namespace)},pod={json.dumps(pod)}'
            selector = "{" + labels + "}"
            for title, query in (
                    ("Container restarts over 15 minutes",
                     f"increase(kube_pod_container_status_restarts_total{selector}[15m])"),
                    ("CPU throttled periods ratio",
                     f"rate(container_cpu_cfs_throttled_periods_total{selector}[5m]) / "
                     f"rate(container_cpu_cfs_periods_total{selector}[5m])"),
                    ("Memory working set bytes (compare with configured limits)",
                     f"container_memory_working_set_bytes{selector}")):
                queries.append({"title": title, "language": "PromQL", "query": query,
                                "template": not bool(pods),
                                "url": OBSERVABILITY_LINKS["grafana_explore_url"]})
            queries.append({"title": "Server tick lag and memory failure logs", "language": "Loki",
                            "template": not bool(pods),
                            "query": selector + ' |~ "(?i)(tick|lag|can.t keep up|oom|out of memory)"',
                            "url": OBSERVABILITY_LINKS["grafana_explore_url"]})
        for host in server["observed_hosting_nodes"] or [{"name": "NODE"}]:
            queries.append({"title": "Hosting node 15-minute load", "language": "PromQL",
                            "template": not bool(server["observed_hosting_nodes"]),
                            "query": 'node_load15{nodename=' + json.dumps(host["name"]) + '}',
                            "url": OBSERVABILITY_LINKS["grafana_explore_url"]})
        return sanitize({
            "schema_version": "1.0", "read_only": True, "game": game,
            "telemetry_source": fleet["telemetry_source"],
            "server_entry": server, "observability_links": dict(OBSERVABILITY_LINKS),
            "notice": fleet["notice"],
            "debugging_steps": [
                {"step": 1, "id": "symptom_and_triage", "player_symptom": symptom,
                 "triage": gpu_and_household_triage.triage_household_game_ticket(symptom)},
                {"step": 2, "id": "knowledge_graph_lineage", "hardware_lineage": lineage,
                 "hosting_node_lineage": hosting_lineage,
                 "hosting_nodes": server["observed_hosting_nodes"], "active_incidents": server["incidents"],
                 "cited_node_ids": sorted({identity for path in lineage for identity in path["path_ids"]}),
                 "missing_evidence": [] if lineage else [
                     "No workload-to-host path is established in this snapshot; confirm pod placement."]},
                {"step": 3, "id": "cross_tool_observability",
                 "observability_links": dict(OBSERVABILITY_LINKS), "queries": queries,
                 "operator_pivots": [
                     "Use OpsCryer graph IDs, host metrics and incidents to choose the affected pod and host.",
                     "Open Grafana dashboards for trends, then Explore for these PromQL/Loki queries "
                     "over the symptom time window; confirm exporter labels and Loki ingestion labels first.",
                     "If placement is missing, replace NAMESPACE/POD/NODE templates only after confirming inventory.",
                     "Open ArgoCD applications to inspect sync/health and compare desired state with the pod.",
                     "Open GitLab pipelines to correlate deployment times and failed jobs with symptom onset.",
                     "Open RunbookGate to review available runbooks; recovery execution requires an approved ticket.",
                 ]},
                {"step": 4, "id": "dual_tier_ai_what_to_do", "model_comparison": comparison},
                {"step": 5, "id": "recovery_verification", "checklist": [
                    "Grafana dashboards show stable tick time, CPU throttling, memory and restart rates "
                    "over the same before/after window; Explore logs show no recurring tick lag or OOM.",
                    "Read-only kubectl get pods --all-namespaces -o wide confirms intended pods Ready "
                    "and replicas available; kubectl get nodes confirms hosting nodes Ready.",
                    f"From the household LAN, use nslookup {game}.cluster.example.org (confirm the configured "
                    "game hostname first); verify split-horizon resolution and player connectivity.",
                    "Confirm recovery with affected players and attach before/after evidence to the Jev IT ticket.",
                ]},
            ],
        })
    except (ValueError, TypeError, KeyError, AttributeError, IndexError,
            RecursionError, OverflowError):
        raise ValueError(_INVALID_CATALOG) from None


def render_game_debug_markdown(game='minecraft', catalog=None) -> str:
    """Export sanitized snapshot evidence as escaped, single-line tables."""
    if not isinstance(game, str) or game not in GAME_PROFILES:
        raise ValueError('Unknown game server profile')
    context = {}
    trace = sanitize(_trace_game_debugging_loop(game, _snapshot(catalog), context))
    fleet = sanitize(context["fleet"])

    def text(value):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, allow_nan=False)
        value = sanitize('Unavailable' if value is None else str(value))
        value = ''.join(char for char in ' '.join(value.split()) if char.isprintable())
        return re.sub(r'([\\`*_{}\[\]()#+.!|>~$-])', r'\\\1', escape(value, quote=True))

    def row(values):
        return '| ' + ' | '.join(text(value) for value in values) + ' |'

    lines = ['# Live Game Server & Cross-Tool Observability Debugging Loop', '',
             text(trace['notice']), '', 'Selected game: ' + text(game), '',
             'Read-only offline demonstration; no model inference or operational actions.', '',
             '## Fleet Status', '',
             '| Game | Snapshot status | Hosting nodes / readiness / metrics | Active incidents |',
             '| --- | --- | --- | --- |']
    for entry in fleet['games']:
        lines.append(row([entry['game'], entry['snapshot_status'],
                          entry['observed_hosting_nodes'], entry['incidents']]))
    lines.extend(['', '## External Observability Deep-Links', '',
                  '| Tool | URL |', '| --- | --- |'])
    for tool, url in OBSERVABILITY_LINKS.items():
        # URLs come only from the fixed, trusted tool inventory.
        lines.append('| ' + text(tool) + ' | [Open tool](' + url + ') |')
    lines.extend(['', '## PromQL & Loki Queries', '',
                  '| Check | Language | Query | Template requiring confirmed inventory |',
                  '| --- | --- | --- | --- |'])
    for query in trace['debugging_steps'][2]['queries']:
        lines.append(row([query['title'], query['language'], query['query'], query['template']]))
    lines.extend(['', '## 5-Step Debugging Loop', '',
                  '| Step | Evidence and operator checks |', '| --- | --- |'])
    for step in trace['debugging_steps']:
        evidence = {key: value for key, value in step.items()
                    if key not in {'step', 'id', 'model_comparison'}}
        if 'model_comparison' in step:
            comparison = step['model_comparison']
            evidence = {key: comparison.get(key) for key in
                        ('status', 'airlock_blocked', 'reason', 'evaluation_scope')}
        lines.append(row([str(step['step']) + '. ' + step['id'], evidence]))
    comparison = trace['debugging_steps'][3]['model_comparison']
    lines.extend(['', '## Dual-Tier Low-Power vs. High-Power AI "What To Do" Guidance', '',
                  'Low-Power: 0.5B-3B, < 400 estimated context-pack tokens when available.', '',
                  text(comparison.get('reason', comparison['evaluation_scope'])), '',
                  '| Guidance | Low-Power | High-Power |', '| --- | --- | --- |'])
    for field, label in (
            ('status', 'Status'), ('model', 'Model'), ('tier_role', 'Role'),
            ('context_pack_estimated_tokens', 'Estimated context-pack tokens'),
            ('synthesis', 'Grounded response'), ('what_to_do', 'What To Do'),
            ('diagnostic_commands', 'Read-only diagnostics'), ('required_ticket', 'Jev ticket'),
            ('verification_criteria', 'Verification criteria'),
            ('escalation_policy', 'Escalation policy'), ('cited_node_ids', 'Cited graph IDs')):
        lines.append(row([label] + [comparison['tiers'][tier].get(field)
                                    for tier in ('low_power', 'high_power')]))
    return '\n'.join(lines) + '\n'


def render_game_debug_html(catalog=None) -> str:
    """Render a self-contained, text-only interactive snapshot debugging UI."""
    snapshot = _snapshot(catalog)
    context = {}
    traces = [_trace_game_debugging_loop(game, snapshot, context) for game in GAME_PROFILES]
    data = sanitize({'fleet': context["fleet"], 'traces': traces})
    evidence = (json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
                .replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e'))
    return '''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Live Game Server &amp; Cross-Tool Observability Debugging Loop</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#090e1a;color:#e5ecf8}
*{box-sizing:border-box}body{margin:0}main,nav{max-width:1440px;margin:auto;padding:24px}
nav{display:flex;flex-wrap:wrap;gap:12px 22px;border-bottom:1px solid #34445c}
a{color:#a9c9ff;text-underline-offset:4px}nav a[aria-current]{color:white;font-weight:700}
h1{font-size:clamp(2rem,4vw,3rem)}h2{font-size:1.4rem}h3{font-size:1.1rem}
p,li,pre{line-height:1.6;overflow-wrap:anywhere}pre{white-space:pre-wrap}
.muted{color:#a8b7ce}section{margin-top:28px}
.card{background:#121c2d;border:1px solid #34445c;border-top:3px solid #80daca;
border-radius:16px;padding:20px;min-width:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:16px}
#game-ai-guidance{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
#game-selector-buttons{display:flex;flex-wrap:wrap;gap:10px}
button{font:inherit;color:inherit;background:#1b2940;border:1px solid #536987;
border-radius:10px;padding:12px;cursor:pointer}button:hover{border-color:#a9c9ff}
button[aria-pressed="true"]{background:#29446b;border-color:#80daca}
button:focus-visible,a:focus-visible{outline:3px solid #80daca;outline-offset:4px}
@media(max-width:700px){main,nav{padding:16px}#game-ai-guidance{grid-template-columns:1fr}}
</style></head><body>
<nav aria-label="Main navigation"><a href="/">Home</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/executive">Executive</a><a href="/hub">Suite Hub</a>
<a href="/simulator">Simulator</a><a href="/playbooks">Playbooks</a>
<a href="/models">Models</a><a href="/games" aria-current="page">Games</a><a href='/metrics-live'>Live Metrics</a></nav>
<main><header><p class="muted">READ-ONLY / OFFLINE SNAPSHOT</p>
<h1>Live Game Server &amp; Cross-Tool Observability Debugging Loop</h1>
<p>No model inference, commands or ticket submissions are performed.</p>
<p id="game-notice" class="muted"></p></header>
<p>Snapshot telemetry_source: <strong id="telemetry-source">''' + escape(data["fleet"]["telemetry_source"]) + '''</strong></p>
<section aria-label="Live Metrics Stream">
<h2>Live Metrics Stream</h2>
<button id="live-refresh" type="button">Refresh Live Metrics</button>
<p id="live-refresh-status" role="status" aria-live="polite">Live metrics have not been refreshed.</p>
<pre id="live-metrics-output" hidden></pre>
</section>
<section aria-labelledby="fleet-title"><h2 id="fleet-title">Fleet Status</h2>
<div id="game-fleet-grid" class="grid"></div></section>
<section aria-labelledby="links-title"><h2 id="links-title">External Observability Deep-Links</h2>
<div id="game-observability-links" class="grid">
<a class="card" href="https://grafana.cluster.example.org/dashboards">Grafana dashboards: health and trends</a>
<a class="card" href="https://grafana.cluster.example.org/explore">Grafana Explore: PromQL and Loki</a>
<a class="card" href="https://argocd.cluster.example.org/applications">ArgoCD: sync and health</a>
<a class="card" href="https://gitlab.cluster.example.org/platform/infra-gitops/-/pipelines">GitLab: deployment pipelines</a>
<a class="card" href="https://runbookgate.cluster.example.org">RunbookGate: review recovery runbooks</a></div></section>
<section aria-labelledby="selector-title"><h2 id="selector-title">Select Game</h2>
<div id="game-selector-buttons" role="group" aria-label="Select game"></div>
<p id="game-status" role="status" aria-live="polite"></p></section>
<section aria-labelledby="steps-title"><h2 id="steps-title">5-Step Debugging Loop</h2>
<div id="game-debug-steps" class="grid"></div></section>
<section aria-labelledby="queries-title"><h2 id="queries-title">PromQL &amp; Loki Queries</h2>
<p>Confirm inventory and exporter labels before replacing query templates.</p>
<div id="game-promql-panel" class="grid"></div></section>
<section aria-labelledby="ai-title"><h2 id="ai-title">Dual-Tier AI: What To Do</h2>
<p id="game-ai-status"></p><div id="game-ai-guidance"></div></section>
<noscript><p>Enable JavaScript to select games and inspect snapshot evidence.</p></noscript>
</main><script id="game-debug-data" type="application/json">''' + evidence + '''</script>
<script>

(() => {
  const button = document.getElementById("live-refresh");
  const status = document.getElementById("live-refresh-status");
  const output = document.getElementById("live-metrics-output");
  button.addEventListener("click", async () => {
    button.disabled = true;
    status.textContent = "Refreshing live metrics...";
    try {
      const response = await fetch("/api/v1/live-metrics?live=1", {cache: "no-store"});
      if (!response.ok) throw new Error("Metrics unavailable");
      const metrics = await response.json();
      if (typeof metrics.live_kubectl_active !== "boolean") throw new Error("Invalid metrics");
      const source = metrics.live_kubectl_active ? "live_kubectl" : "offline_fallback";
      output.textContent = JSON.stringify(metrics.node_metrics || [], null, 2);
      output.hidden = false;
      status.textContent = "Live metrics telemetry_source: " + source +
        ". Refreshed at " + new Date().toLocaleTimeString() + ". Portal evidence remains a snapshot.";
    } catch (error) {
      status.textContent = "Live metrics refresh failed; any previously displayed metrics may be stale. Open Live Metrics in the integrated portal to retry.";
    } finally {
      button.disabled = false;
    }
  });
})();
"use strict";
(() => {
  const data = JSON.parse(document.getElementById("game-debug-data").textContent);
  function display(value) {
    if (value === null || value === undefined) return "Unavailable";
    return typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
  }
  function add(parent, tag, value) {
    const element = document.createElement(tag);
    if (arguments.length > 2) element.textContent = display(value);
    parent.appendChild(element);
    return element;
  }
  function card(parent, title) {
    const element = add(parent, "article");
    element.className = "card";
    add(element, "h3", title);
    return element;
  }
  function details(parent, label, value) {
    add(parent, "h4", label);
    if (Array.isArray(value)) {
      const list = add(parent, "ul");
      value.forEach(item => add(list, "li", item));
      if (!value.length) add(parent, "p", "None provided");
    } else {
      add(parent, typeof value === "object" && value !== null ? "pre" : "p", value);
    }
  }
  document.getElementById("game-notice").textContent = data.fleet.notice;
  const fleet = document.getElementById("game-fleet-grid");
  data.fleet.games.forEach(entry => {
    const element = card(fleet, entry.game);
    details(element, "Snapshot status", entry.snapshot_status);
    details(element, "Hosting nodes / readiness / CPU / RAM", entry.observed_hosting_nodes);
    details(element, "Active incidents", entry.incidents);
  });
  const buttons = document.getElementById("game-selector-buttons");
  function select(trace) {
    Array.from(buttons.children).forEach(button => {
      button.setAttribute("aria-pressed", String(button.dataset.game === trace.game));
    });
    document.getElementById("game-status").textContent = trace.game + " / " + trace.server_entry.snapshot_status;
    const steps = document.getElementById("game-debug-steps");
    steps.textContent = "";
    trace.debugging_steps.forEach(step => {
      const element = card(steps, step.step + ". " + step.id.replace(/_/g, " "));
      Object.entries(step).forEach(([key, value]) => {
        if (["step", "id", "queries", "model_comparison"].includes(key)) return;
        details(element, key.replace(/_/g, " "), value);
      });
      if (step.model_comparison) {
        details(element, "AI status", step.model_comparison.status);
        details(element, "Scope", step.model_comparison.evaluation_scope);
      }
    });
    const queries = document.getElementById("game-promql-panel");
    queries.textContent = "";
    trace.debugging_steps[2].queries.forEach(query => {
      const element = card(queries, query.language + ": " + query.title);
      add(element, "pre", query.query);
      add(element, "p", query.template ? "Template: confirm inventory first" : "Snapshot labels: confirm current inventory");
      const link = add(element, "a", "Open Grafana Explore");
      link.href = "https://grafana.cluster.example.org/explore";
    });
    const comparison = trace.debugging_steps[3].model_comparison;
    document.getElementById("game-ai-status").textContent = comparison.status + " / " +
      (comparison.reason || comparison.evaluation_scope);
    const guidance = document.getElementById("game-ai-guidance");
    guidance.textContent = "";
    [["low_power", "Low-Power: 0.5B-3B / < 400 estimated pack tokens"],
     ["high_power", "High-Power: architectural guidance"]].forEach(([key, title]) => {
      const element = card(guidance, title);
      const tier = comparison.tiers[key];
      if (comparison.airlock_blocked) add(element, "p", comparison.reason);
      [["status", "Status"], ["model", "Model"],
       ["context_pack_estimated_tokens", "Estimated context-pack tokens"],
       ["synthesis", "Grounded response"], ["what_to_do", "What To Do"],
       ["diagnostic_commands", "Read-only diagnostics"], ["required_ticket", "Jev ticket"],
       ["verification_criteria", "Verification criteria"], ["escalation_policy", "Escalation policy"],
       ["cited_node_ids", "Cited graph IDs"]].forEach(([field, label]) => details(element, label, tier[field]));
    });
  }
  data.traces.forEach(trace => {
    const button = add(buttons, "button", trace.game);
    button.type = "button";
    button.dataset.game = trace.game;
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", () => select(trace));
  });
  if (data.traces.length) select(data.traces[0]);
})();
</script></body></html>
'''


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(_INVALID_REQUEST)


def _build_game_debug_handler(catalog=None):
    """Serve offline game runbooks without logging or echoing request input."""
    class GameDebugRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send(self, status, body, content_type):
            body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            self._send(code, '{"error":"Invalid HTTP request"}', "application/json")

        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.path not in {"/", "/games", "/api/v1/game-debug-loop",
                                    "/games/debug.md"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                if re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                    raise ValueError(_INVALID_REQUEST)
                query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True,
                                 max_num_fields=1, errors="strict")
                if set(query) - {"game"}:
                    raise ValueError(_INVALID_REQUEST)
                game = query.get("game", ["minecraft"])[0]
                if game not in GAME_PROFILES:
                    raise ValueError(_INVALID_REQUEST)
                if url.path in {"/", "/games"}:
                    if url.query:
                        raise ValueError(_INVALID_REQUEST)
                    body = render_game_debug_html(catalog)
                    content_type = "text/html"
                elif url.path == "/games/debug.md":
                    body = render_game_debug_markdown(game, catalog)
                    content_type = "text/markdown"
                else:
                    body = json.dumps(trace_game_debugging_loop(game, catalog),
                                      indent=2, allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError, KeyError):
                self._send(400, json.dumps({"error": _INVALID_REQUEST}), "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Game observability unavailable"}',
                           "application/json")
                return
            self._send(200, body, content_type)

    return GameDebugRequestHandler


def main(argv=None) -> int:
    """Export an offline game runbook or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="game_observability_loop", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--game", metavar="GAME", default="minecraft")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or args.game not in GAME_PROFILES:
        parser.error(_INVALID_REQUEST)
    try:
        catalog = _snapshot(args.catalog)
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_game_debug_handler(catalog)) as server:
                print(f"Game observability: http://127.0.0.1:{args.port}/games", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_game_debug_markdown(args.game, catalog), end="")
        else:
            print(json.dumps(trace_game_debugging_loop(args.game, catalog),
                             indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.error(_INVALID_REQUEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
