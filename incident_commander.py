# SPDX-License-Identifier: Apache-2.0
"""Deterministic incident triage from an offline cluster graph snapshot."""

import argparse
from collections import Counter
from hashlib import sha256
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from cluster_diff_engine import summarize_live_cluster_health
import jev_client
from opscryer_backend import KnowledgeGraphBackendEngine
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
SEVERITIES = ("SEV-1", "SEV-2", "SEV-3", "SEV-4")
CATEGORIES = ("node_not_ready", "node_hotspot", "pod_failed", "pod_pending",
              "pod_crash_loop", "deployment_degraded")


def _load_catalog(catalog):
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if not isinstance(catalog, dict):
        raise ValueError("catalog must be a graph object or JSON file path")
    # Validate after redaction so colliding graph identities fail closed.
    return KnowledgeGraphBackendEngine(sanitize(catalog)).catalog()


def _lineage(engine, snapshot, source_id, hardware_ids=None, root_ids=None):
    """Prefer hosting paths; containment through a namespace is not hosting."""
    paths = []
    if hardware_ids is None:
        hardware_ids = [node["id"] for node in sorted(
            snapshot["nodes"], key=lambda node: node["id"])
            if node["domain"] == "hardware_topology"]
    for target_id in hardware_ids:
        path = engine.shortest_path(source_id, target_id)
        if path["path_found"] and not any(
                node["kind"] in {"company_root", "kubernetes_namespace"}
                for node in path["path_nodes"]):
            paths.append(path)
    if paths:
        return min(paths, key=lambda path: (path["hop_count"], path["path_ids"]))["path_ids"]
    if root_ids is None:
        roots = {node["id"] for node in snapshot["nodes"]
                 if node["kind"] == "company_root"}
        if isinstance(snapshot.get("root_id"), str):
            roots.add(snapshot["root_id"])
        root_ids = sorted(roots)
    for root_id in root_ids:
        path = engine.shortest_path(source_id, root_id)
        if path["path_found"]:
            paths.append(path)
    return (min(paths, key=lambda path: (path["hop_count"], path["path_ids"]))["path_ids"]
            if paths else [])


def build_active_incidents_catalog(catalog=None) -> dict:
    """Accept a graph dict, JSON path, or the bundled sanitized snapshot.

    Snapshot priority policy: NotReady nodes are SEV-1; failed/crashing pods
    and deployments with no ready replicas are SEV-2; partially ready
    deployments and node hotspots are SEV-3; pending pods are SEV-4.
    Hotspots use the health helper's CPU >= 80% or RAM >= 75% thresholds.
    A crashing pod produces one incident even if its phase is Failed/Pending.
    IDs derive from category and graph identity, independent of input order.
    Lineage contains the complete shortest path to hardware, or the root as
    a containment fallback; an empty list means no reachable anchor.
    No collection, paging, commands, or input mutation occurs here.
    """
    # Validate before canonicalizing so malformed catalogs fail with the
    # backend's fixed diagnostics. Canonical graph order also breaks BFS ties.
    snapshot = _load_catalog(catalog)
    snapshot["nodes"].sort(key=lambda node: node["id"])
    for node in snapshot["nodes"]:
        node["drilldown_children"].sort()
    snapshot["edges"] = sorted(snapshot.get("edges", []), key=lambda edge: (
        edge["source"], edge["target"], edge["relation"]))
    engine = KnowledgeGraphBackendEngine(snapshot)
    snapshot = engine.catalog()
    facts = summarize_live_cluster_health(snapshot)
    hotspots = {node["node_id"] for node in facts["node_hotspots"]}
    hardware_ids = [node["id"] for node in snapshot["nodes"]
                    if node["domain"] == "hardware_topology"]
    roots = {node["id"] for node in snapshot["nodes"]
             if node["kind"] == "company_root"}
    if isinstance(snapshot.get("root_id"), str):
        roots.add(snapshot["root_id"])
    root_ids = sorted(roots)
    incidents = []
    lineage_by_node = {}

    def add(node, severity, category, namespace, summary):
        identity = json.dumps([category, node["id"]], ensure_ascii=True)
        if node["id"] not in lineage_by_node:
            lineage_by_node[node["id"]] = _lineage(
                engine, snapshot, node["id"], hardware_ids, root_ids)
        incidents.append({
            "incident_id": "INC-" + sha256(identity.encode("utf-8")).hexdigest()[:20],
            "severity": severity, "category": category,
            "affected_node_id": node["id"], "namespace": namespace,
            "summary": summary,
            "hardware_lineage_ids": list(lineage_by_node[node["id"]]),
        })

    for node in sorted(snapshot["nodes"], key=lambda item: item["id"]):
        resource = node.get("resource", {})
        kind = node.get("resource_kind", resource.get("kind"))
        metadata = resource.get("metadata", {})
        status = resource.get("status", {})
        name = metadata.get("name", node["label"])
        namespace = metadata.get("namespace", node.get("namespace") or "default")
        if kind == "Node":
            ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                        for condition in status.get("conditions", []))
            if not ready:
                add(node, "SEV-1", "node_not_ready", "",
                    f"Node {name} is NotReady in the snapshot.")
            if node["id"] in hotspots:
                add(node, "SEV-3", "node_hotspot", "",
                    f"Node {name} meets the CPU or RAM hotspot threshold in the snapshot.")
        elif kind == "Pod":
            containers = [container for field in (
                "containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses")
                for container in status.get(field, [])]
            crashing = any(container.get("state", {}).get("waiting", {}).get("reason")
                           == "CrashLoopBackOff" for container in containers)
            phase = status.get("phase")
            if crashing:
                add(node, "SEV-2", "pod_crash_loop", namespace,
                    f"Pod {namespace}/{name} has a CrashLoopBackOff container in the snapshot.")
            elif phase in {"Failed", "Pending"}:
                add(node, "SEV-2" if phase == "Failed" else "SEV-4",
                    "pod_" + phase.lower(), namespace,
                    f"Pod {namespace}/{name} is {phase} in the snapshot.")
        elif kind == "Deployment":
            desired = resource.get("spec", {}).get("replicas", 1)
            ready = status.get("readyReplicas", 0)
            if desired > 0 and ready < desired:
                add(node, "SEV-2" if ready == 0 else "SEV-3", "deployment_degraded", namespace,
                    f"Deployment {namespace}/{name} has {ready}/{desired} ready replicas in the snapshot.")

    incidents.sort(key=lambda incident: (incident["severity"], incident["category"],
                                         incident["affected_node_id"], incident["incident_id"]))
    severity_counts = Counter(incident["severity"] for incident in incidents)
    category_counts = Counter(incident["category"] for incident in incidents)
    return sanitize({
        "telemetry_source": ("live_kubectl" if snapshot.get("source") == "live_kubectl"
                             else "offline_fallback"),
        "incidents": incidents,
        "summary_counts": {
            "total": len(incidents),
            "by_severity": {severity: severity_counts[severity] for severity in SEVERITIES},
            "by_category": {category: category_counts[category] for category in CATEGORIES},
        },
        "notice": "Offline snapshot triage, not live paging. Observations do not establish root cause.",
    })


def _build_runbook_for_incident(incident, nodes_by_id):
    commands = []
    checklist = ["No active incidents in the snapshot; continue routine monitoring."]
    policy_text = "Review offline cluster health; no active incidents."
    if incident is not None:
        node = nodes_by_id[incident["affected_node_id"]]
        metadata = node.get("resource", {}).get("metadata", {})
        name = metadata.get("name", node["label"])

        def safe_name(value):
            # An allowlist prevents shell metacharacters and option injection.
            return (isinstance(value, str) and len(value) <= 253
                    and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value))

        category = incident["category"]
        is_node = category.startswith("node_")
        resource = ("nodes" if is_node else "deployments"
                    if category == "deployment_degraded" else "pods")
        namespace = incident["namespace"]
        scope = "" if is_node else (
            " --namespace " + namespace if safe_name(namespace) else " --all-namespaces")
        # A named lookup across all namespaces is unsupported by kubectl.
        target = " " + name if safe_name(name) and "--all-namespaces" not in scope else ""
        commands = [
            "kubectl get " + resource + target + scope + " -o wide",
            "kubectl describe " + resource + target + scope,
            "kubectl get events" + (" --all-namespaces" if is_node else scope)
            + " --sort-by=.metadata.creationTimestamp",
        ]
        if category == "deployment_degraded" and target:
            commands.append("kubectl rollout history deployment" + target + scope)
        checklist = [
            "Confirm snapshot observations against current read-only diagnostics and assess impact.",
            "Review hardware lineage and dependent workloads before proposing containment.",
            "Identify the last known healthy GitOps revision and review the rollback diff.",
            "Review rollback prerequisites, capacity, data compatibility and recovery criteria.",
            "Obtain incident commander approval and required Jev IT tickets before any change.",
            "After an approved recovery, verify readiness and record evidence for incident review.",
        ]
        policy_text = "Review incident containment and rollback: " + incident["summary"]
    return sanitize({
        "incident": incident,
        "diagnostic_commands": commands,
        "containment_checklist": checklist,
        "jev_decision": jev_client.explain_jev_decision_path(
            policy_text, provider="deterministic"),
        "simulation_only": True,
    })


def generate_incident_runbook(incident_id=None, catalog=None) -> dict:
    """Return offline triage commands, rollback review and Jev breadcrumbs.

    With no ID, select the catalog's first (highest-severity) incident. An
    empty catalog produces an idle runbook with no diagnostic commands.
    Commands are suggestions only; resource identifiers must be Kubernetes
    DNS names before interpolation, otherwise use a collection-level query.
    """
    snapshot = _load_catalog(catalog)
    incidents = build_active_incidents_catalog(snapshot)["incidents"]
    incident = next((item for item in incidents
                     if incident_id is None or item["incident_id"] == incident_id), None)
    if incident_id is not None and incident is None:
        raise ValueError("Unknown incident ID")
    nodes_by_id = {node["id"]: node for node in snapshot["nodes"]}
    return _build_runbook_for_incident(incident, nodes_by_id)


def build_blameless_pir_markdown(catalog=None) -> str:
    """Export snapshot observations and suggested runbooks, without execution.

    Accept the same catalog inputs as build_active_incidents_catalog. Sanitize
    before Markdown escaping so redaction cannot be bypassed by formatting.
    No timestamps, impact estimates or root-cause claims are inferred.
    """
    snapshot = _load_catalog(catalog)
    active = sanitize(build_active_incidents_catalog(snapshot))
    nodes_by_id = {node["id"]: node for node in snapshot["nodes"]}

    def text(value):
        # Keep untrusted text on one line and disable HTML/Markdown structure,
        # including table delimiters, links and inline code fences.
        value = escape(" ".join(str(sanitize(value)).split()), quote=False)
        return re.sub(r"([\\`*_{}\[\]()#+!|~])", r"\\\1", value)

    counts = active["summary_counts"]
    lines = [
        "# Blameless Post-Incident Review (PIR)",
        "",
        "> Observations come from a sanitized cluster snapshot. This offline report",
        "> does not establish current service health, customer impact, or root cause.",
        "",
        "This review focuses on system conditions and learning, without assigning blame.",
        "Incident timing, duration, confirmed impact, recovery and contributing factors",
        "remain unconfirmed until responders supply evidence.",
        "",
        "## Incident summary",
        "",
        "Total snapshot incidents: " + text(counts["total"]) + ". " + "; ".join(
            text(severity) + ": " + text(counts["by_severity"][severity])
            for severity in SEVERITIES) + ".",
        "",
        "| Incident | Severity | Category | Affected resource | Namespace | Observation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for incident in active["incidents"]:
        lines.append("| " + " | ".join(text(incident[key]) or "(cluster-wide)"
                                     for key in (
                                         "incident_id", "severity", "category",
                                         "affected_node_id", "namespace", "summary")) + " |")
    if not active["incidents"]:
        lines.extend(["", "No active incidents were identified in the sanitized snapshot."])

    for incident in active["incidents"]:
        runbook = _build_runbook_for_incident(incident, nodes_by_id)
        lines.extend([
            "", "## " + text(incident["incident_id"]), "",
            "Observed condition: " + text(incident["summary"]), "",
            "Hardware lineage (resource to anchor; may fall back to containment): "
            + (" → ".join(text(node_id) for node_id in incident["hardware_lineage_ids"])
               or "No reachable anchor in the snapshot."),
            "", "### Diagnostic runbook", "",
            "Suggested read-only commands; no commands have been executed by this report.",
            "",
        ])
        # Commands use the runbook generator's Kubernetes-name allowlist. An
        # indented code block preserves shell syntax without fence injection.
        for command in runbook["diagnostic_commands"]:
            lines.extend("    " + line for line in sanitize(command).splitlines())
        lines.extend(["", "### Containment and rollback review", ""])
        lines.extend("- [ ] " + text(item) for item in runbook["containment_checklist"])
        decision = runbook["jev_decision"]
        lines.extend(["", "### Jev policy breadcrumbs", "",
                      text(decision["plain_english_why"]), ""])
        for breadcrumb in decision["breadcrumbs"]:
            lines.append("- " + text(breadcrumb["node_id"]) + ": "
                         + text(breadcrumb["branch"]) + " (provider-reported confidence: "
                         + text(breadcrumb["confidence"]) + ").")
        if not decision["breadcrumbs"]:
            lines.append("No completed policy predicates were recorded.")
        lines.extend([
            "", "### Learning and follow-up", "",
            "- [ ] Record confirmed impact, timeline and recovery evidence.",
            "- [ ] Validate contributing system conditions before stating a root cause.",
            "- [ ] Agree preventive actions, owners, due dates and verification criteria.",
        ])
    return sanitize("\n".join(lines) + "\n")


def render_incident_commander_html(catalog=None) -> str:
    """Render offline triage and read-only runbooks without network dependencies."""
    active = build_active_incidents_catalog(catalog)
    evidence = escape(json.dumps(active, indent=2, allow_nan=False))
    runbooks = {}
    if active.get("incidents"):
        snapshot = _load_catalog(catalog)
        nodes_by_id = {node["id"]: node for node in snapshot["nodes"]}
        runbooks = {incident["incident_id"]: _build_runbook_for_incident(incident, nodes_by_id)
                    for incident in active["incidents"]}
    runbook_evidence = escape(json.dumps(runbooks, indent=2, allow_nan=False))
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident Commander</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#090e1a;color:#e5ecf8}
*{box-sizing:border-box}body{margin:0}main,nav{max-width:1440px;margin:auto;padding:24px}
nav{display:flex;gap:10px 22px;flex-wrap:wrap;border-bottom:1px solid #263247}
a{color:#a9c9ff;text-underline-offset:4px}nav a{text-decoration:none}
nav a[aria-current]{color:#fff;font-weight:700}h1{font-size:clamp(2rem,4vw,3rem);margin:8px 0}
h2{font-size:1.2rem;margin:0 0 18px}h3{font-size:1rem}p{line-height:1.6}
.eyebrow{color:#80daca;text-transform:uppercase;letter-spacing:.15em;font-size:.75rem}
.muted{color:#a8b7ce}.intro{display:flex;justify-content:space-between;align-items:center;gap:20px}
.pill{display:inline-block;border:1px solid #34445c;border-radius:30px;padding:6px 12px;font-size:.8rem}
#incident-kpi-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:26px 0}
.kpi,.panel{background:#121c2d;border:1px solid #2a3850;border-radius:18px;padding:22px}
.kpi{border-top:3px solid var(--accent,#80daca)}.kpi strong{display:block;font-size:2.2rem;margin-top:8px}
.sev-1{--accent:#ff8a9b}.sev-2{--accent:#ffc080}.sev-3{--accent:#f6df8b}.sev-4{--accent:#91baff}
.badge{color:var(--accent,#d2def0);font-size:.8rem;font-weight:700}
.workspace{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:20px;align-items:start}
#incident-severity-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
button{font:inherit;color:inherit;background:#1b2940;border:1px solid #3b4e6b;border-radius:10px;
padding:9px 14px;cursor:pointer}button:hover{border-color:#a9c9ff}
button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #80daca;outline-offset:4px}
button[aria-pressed="true"]{background:#29446b;border-color:#a9c9ff}
#incidents-grid{display:grid;gap:12px}.incident{background:#0d1626;border:1px solid #2a3850;
border-left:3px solid var(--accent);border-radius:12px;padding:18px;overflow-wrap:anywhere}
.incident h3{margin:10px 0}.incident p{margin:8px 0}.incident button{margin-top:8px}
#runbook-panel{position:sticky;top:20px;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#090f1c;border:1px solid #263247;
border-radius:10px;padding:16px;line-height:1.6}li{line-height:1.6;margin-bottom:10px}
details{margin-top:22px}summary{cursor:pointer;color:#a9c9ff}footer{margin-top:24px}
@media(max-width:950px){.workspace{grid-template-columns:1fr}#runbook-panel{position:static}}
@media(max-width:600px){main,nav{padding:18px}.intro{display:block}
#incident-kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.kpi:first-child{grid-column:1/-1}}
</style></head>
<body>
<nav><a href="/">Home</a><a href="/chat">Chat</a>
<a href="/incidents" aria-current="page">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/executive">Executive</a><a href="/hub">Suite Hub</a>
<a href="/incidents/pir.md">PIR Markdown</a><a href='/metrics-live'>Live Metrics</a></nav>
<main><header class="intro"><div><span class="eyebrow">Operations / Snapshot triage</span>
<h1>Incident Commander</h1><p class="muted" id="incident-notice">Offline snapshot triage, not live paging.</p>
</div><span class="pill">Read-only / Simulation</span></header>
<p>Snapshot telemetry_source: <strong id="telemetry-source">""" + escape(active.get("telemetry_source", "offline_fallback")) + """</strong></p>
<section aria-label="Live Metrics Stream">
<h2>Live Metrics Stream</h2>
<button id="live-refresh" type="button">Refresh Live Metrics</button>
<p id="live-refresh-status" role="status" aria-live="polite">Live metrics have not been refreshed.</p>
<pre id="live-metrics-output" hidden></pre>
</section>
<section id="incident-kpi-grid" aria-label="Incident severity summary"></section>
<div class="workspace"><section class="panel" aria-labelledby="incidents-heading">
<h2 id="incidents-heading">Active incidents</h2>
<div id="incident-severity-filters" role="group" aria-label="Filter incidents by severity">
<button type="button" data-severity="All" aria-pressed="true">All</button>
<button type="button" data-severity="SEV-1" aria-pressed="false">SEV-1</button>
<button type="button" data-severity="SEV-2" aria-pressed="false">SEV-2</button>
<button type="button" data-severity="SEV-3" aria-pressed="false">SEV-3</button>
<button type="button" data-severity="SEV-4" aria-pressed="false">SEV-4</button></div>
<p id="incident-result-count" class="muted" role="status"></p><div id="incidents-grid"></div>
</section><aside class="panel" id="runbook-panel" aria-labelledby="runbook-heading">
<h2 id="runbook-heading">Selected incident runbook</h2>
<div id="runbook-content" aria-live="polite"><p>Select an incident to review its runbook.</p></div>
</aside></div>
<noscript><p>Enable JavaScript for incident filters and runbooks. Snapshot evidence is available below.</p></noscript>
<details><summary>Inspect sanitized snapshot evidence</summary>
<pre id="incident-evidence-json">""" + evidence + """</pre></details>
<pre id="incident-runbooks-json" hidden>""" + runbook_evidence + """</pre>
<footer class="muted">Diagnostics are suggestions only. No commands are executed by this dashboard.</footer>
</main>
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
(() => {
  'use strict';
  const evidence = JSON.parse(document.getElementById('incident-evidence-json').textContent);
  const runbooks = JSON.parse(document.getElementById('incident-runbooks-json').textContent);
  const incidents = evidence.incidents || [];
  const grid = document.getElementById('incidents-grid');
  const kpis = document.getElementById('incident-kpi-grid');
  const filters = document.getElementById('incident-severity-filters');
  const content = document.getElementById('runbook-content');
  const resultCount = document.getElementById('incident-result-count');
  let severity = 'All';
  let selectedId = null;
  function add(parent, tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    parent.appendChild(element);
    return element;
  }
  function severityClass(value) { return value.toLowerCase(); }
  document.getElementById('incident-notice').textContent = evidence.notice || 'Offline snapshot triage, not live paging.';
  ['All', 'SEV-1', 'SEV-2', 'SEV-3', 'SEV-4'].forEach(value => {
    const card = add(kpis, 'article', undefined, 'kpi ' + severityClass(value));
    add(card, 'span', value === 'All' ? 'Total incidents' : value, 'badge');
    const count = value === 'All' ? incidents.length : incidents.filter(item => item.severity === value).length;
    add(card, 'strong', String(count));
    add(card, 'span', 'Snapshot observations', 'muted');
  });
  function list(title, items, commands) {
    add(content, 'h3', title);
    if (!items.length) { add(content, 'p', 'None recorded in this snapshot.', 'muted'); return; }
    const container = add(content, commands ? 'div' : 'ol');
    items.forEach(item => add(container, commands ? 'pre' : 'li', item));
  }
  function showRunbook(incident) {
    content.textContent = '';
    if (!incident) {
      add(content, 'p', 'No active incidents match this filter. Continue routine monitoring.', 'muted');
      return;
    }
    const runbook = runbooks[incident.incident_id];
    add(content, 'span', incident.severity, 'badge ' + severityClass(incident.severity));
    add(content, 'h3', incident.incident_id);
    add(content, 'p', incident.summary);
    add(content, 'h3', 'Hardware lineage');
    add(content, 'p', incident.hardware_lineage_ids.join(' → ') || 'No reachable anchor in the snapshot.');
    if (!runbook) { add(content, 'p', 'No runbook recorded.'); return; }
    list('Read-only diagnostics', runbook.diagnostic_commands, true);
    list('Containment and rollback review', runbook.containment_checklist, false);
    add(content, 'h3', 'Jev policy decision');
    add(content, 'p', runbook.jev_decision.plain_english_why);
    list('Policy breadcrumbs', runbook.jev_decision.breadcrumbs.map(item =>
      item.node_id + ': ' + item.branch + ' (provider-reported confidence: ' + item.confidence + ')'), false);
  }
  function render() {
    const visible = incidents.filter(item => severity === 'All' || item.severity === severity);
    if (!visible.some(item => item.incident_id === selectedId)) {
      selectedId = visible.length ? visible[0].incident_id : null;
    }
    grid.textContent = '';
    resultCount.textContent = visible.length + ' of ' + incidents.length + ' incidents shown';
    if (!visible.length) add(grid, 'p', 'No active incidents match this filter.', 'muted');
    visible.forEach(incident => {
      const card = add(grid, 'article', undefined, 'incident ' + severityClass(incident.severity));
      add(card, 'span', incident.severity + ' / ' + incident.category.replace(/_/g, ' '), 'badge');
      add(card, 'h3', incident.affected_node_id);
      add(card, 'p', incident.summary);
      add(card, 'p', 'Namespace: ' + (incident.namespace || 'Cluster-wide'), 'muted');
      add(card, 'small', incident.incident_id, 'muted');
      const action = add(card, 'button', 'Review runbook');
      action.type = 'button';
      action.setAttribute('aria-label', 'Review runbook for ' + incident.incident_id);
      action.setAttribute('aria-controls', 'runbook-panel');
      action.setAttribute('aria-pressed', String(incident.incident_id === selectedId));
      action.addEventListener('click', () => {
        selectedId = incident.incident_id;
        grid.querySelectorAll('button').forEach(button => button.setAttribute('aria-pressed', 'false'));
        action.setAttribute('aria-pressed', 'true');
        showRunbook(incident);
      });
    });
    showRunbook(visible.find(item => item.incident_id === selectedId));
  }
  filters.querySelectorAll('button').forEach(button => {
    button.addEventListener('click', () => {
      severity = button.dataset.severity;
      filters.querySelectorAll('button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
      render();
    });
  });
  render();
})();
</script></body></html>"""


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse diagnostics can include unknown options and invalid values.
        super().error("Invalid incident commander arguments")


def _build_incident_handler(catalog):
    """Bind a validated snapshot; never log request targets or exceptions."""
    class IncidentRequestHandler(BaseHTTPRequestHandler):
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
            # BaseHTTPRequestHandler can otherwise echo an invalid method.
            self._send(code, '{"error":"Invalid HTTP request"}', "application/json")

        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.path not in {"/", "/incidents", "/api/v1/incident-commander",
                                    "/incidents/pir.md"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                query = parse_qs(url.query, keep_blank_values=True, max_num_fields=2)
                if set(query) - {"incident_id"} or any(len(values) != 1 for values in query.values()):
                    raise ValueError("Invalid query")
                incident_id = query.get("incident_id", [None])[0]
                if url.path == "/incidents/pir.md":
                    if query:
                        raise ValueError("Invalid query")
                    body = build_blameless_pir_markdown(catalog)
                    content_type = "text/markdown"
                elif url.path in {"/", "/incidents"} and incident_id is None:
                    body = render_incident_commander_html(catalog)
                    content_type = "text/html"
                else:
                    result = (generate_incident_runbook(incident_id, catalog)
                              if incident_id is not None else build_active_incidents_catalog(catalog))
                    body = json.dumps(result, indent=2, allow_nan=False)
                    content_type = "application/json"
                    if url.path in {"/", "/incidents"}:
                        body = ('<!DOCTYPE html><html lang="en"><meta charset="utf-8">'
                                '<title>Incident Commander</title>'
                                '<style>body{background:#111827;color:#e5e7eb;font-family:system-ui;'
                                'margin:2rem}a{color:#93c5fd}pre{white-space:pre-wrap}</style>'
                                '<nav><a href="/">Home</a> | <a href="/chat">Chat</a> | '
                                '<a href="/incidents">Incidents</a></nav>'
                                '<h1>Incident Commander</h1><a href="/incidents/pir.md">PIR Markdown</a>'
                                '<pre>' + escape(body) + '</pre></html>')
                        content_type = "text/html"
            except (ValueError, TypeError, KeyError):
                self._send(400, '{"error":"Invalid incident request"}', "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Incident commander unavailable"}', "application/json")
                return
            self._send(200, body, content_type)

    return IncidentRequestHandler


def main(argv=None) -> int:
    """Export offline incident evidence or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="incident_commander", description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--serve", action="store_true")
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--incident-id", metavar="ID")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or (args.incident_id is not None
                                      and (args.markdown or args.serve)):
        parser.error("Invalid option combination")
    try:
        catalog = _load_catalog(args.catalog)
        if args.serve:
            handler = _build_incident_handler(catalog)
            with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
                print(f"Incident commander: http://127.0.0.1:{args.port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(build_blameless_pir_markdown(catalog), end="")
        else:
            result = (generate_incident_runbook(args.incident_id, catalog)
                      if args.incident_id is not None else build_active_incidents_catalog(catalog))
            print(json.dumps(result, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete incident request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
