# SPDX-License-Identifier: Apache-2.0
"""Offline capacity and workload distribution from sanitized cluster snapshots."""

import argparse
from collections import Counter
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

import gpu_and_household_triage
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
HARDWARE_NODES = ("nodealpha01", "nodebeta02", "nodegamma03")


def _load_catalog(catalog):
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
        raise ValueError("catalog must contain a nodes array")
    snapshot = sanitize(catalog)
    identities = set()
    for node in snapshot["nodes"]:
        if (not isinstance(node, dict) or not isinstance(node.get("id"), str)
                or not node["id"] or node["id"] in identities):
            raise ValueError("catalog requires unique nonempty node IDs after sanitization")
        identities.add(node["id"])
    return snapshot


def _metric(value):
    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
        return value
    return None


def _quantity(value):
    # Preserve Kubernetes quantity units; missing capacity cannot be inferred
    # from rounded utilization percentages.
    if isinstance(value, str) and value.strip():
        return value
    return _metric(value)


def summarize_cluster_capacity(catalog=None) -> dict:
    """Summarize a graph dict, JSON path, or the bundled sanitized snapshot.

    All Node resources are included; missing expected hardware is listed rather
    than invented. Unknown/missing Ready conditions count as not_ready, with
    their original condition retained. Metrics use CPU/RAM percentages and
    Kubernetes usage quantities; capacity/allocatable preserve source units.
    Missing or invalid metrics are None, never zero or estimates.

    Pod counts include every phase (including terminal pods), using spec.nodeName
    for assignment. Unscheduled pods and assignments to absent nodes remain
    visible. Results are deterministic, sanitized, and do not mutate input or
    collect telemetry. No snapshot timestamp is fabricated.
    """
    default_snapshot = catalog is None
    from_file = default_snapshot or isinstance(catalog, (str, Path))
    snapshot = _load_catalog(catalog)
    nodes = []
    node_names = set()
    by_node = Counter()
    by_namespace = Counter()
    phases = Counter()
    unassigned = 0
    for item in sorted(snapshot["nodes"], key=lambda node: node["id"]):
        resource = item.get("resource", {})
        kind = item.get("resource_kind", resource.get("kind"))
        metadata = resource.get("metadata", {})
        if kind == "Pod":
            namespace = metadata.get("namespace") or item.get("namespace") or "default"
            name = resource.get("spec", {}).get("nodeName")
            if name:
                by_node[name] += 1
            else:
                unassigned += 1
            by_namespace[namespace] += 1
            phases[resource.get("status", {}).get("phase") or "Unknown"] += 1
        elif kind == "Node":
            name = metadata.get("name") or item.get("label") or item["id"]
            if not isinstance(name, str) or name in node_names:
                raise ValueError("hardware node names must be unique nonempty strings")
            node_names.add(name)
            status = resource.get("status", {})
            ready_condition = next((condition.get("status")
                                    for condition in status.get("conditions", [])
                                    if condition.get("type") == "Ready"), None)
            metrics = item.get("metrics", {})
            nodes.append({
                "node_id": item["id"], "name": name,
                "ready": ready_condition == "True",
                "readiness": "Ready" if ready_condition == "True" else "NotReady",
                "ready_condition": ready_condition,
                "metrics": {
                    "cpu_percent": _metric(metrics.get("cpu_percent")),
                    "ram_percent": _metric(metrics.get("ram_percent")),
                    "cpu_used": _quantity(metrics.get("cpu_used")),
                    "ram_used": _quantity(metrics.get("ram_used")),
                },
                "capacity": {key: _quantity(status.get("capacity", {}).get(key))
                             for key in ("cpu", "memory")},
                "allocatable": {key: _quantity(status.get("allocatable", {}).get(key))
                                for key in ("cpu", "memory")},
            })
    nodes.sort(key=lambda node: node["name"])
    for node in nodes:
        node["pod_count"] = by_node[node["name"]]
        by_node.setdefault(node["name"], 0)
    ready = sum(node["ready"] for node in nodes)
    return sanitize({
        "telemetry_source": ("live_kubectl" if snapshot.get("source") == "live_kubectl"
                             else "offline_fallback"),
        "source": snapshot.get("source", "provided_catalog"),
        "example": snapshot.get("example", False),
        "provenance": {
            "mode": "offline_snapshot", "live_collection": False,
            "input_kind": "json_file" if from_file else "provided_catalog",
            "snapshot_file": DEFAULT_CATALOG_PATH.name if default_snapshot else None,
            "source": snapshot.get("source", "provided_catalog"),
            "example": snapshot.get("example", False),
            "collected_at": snapshot.get("collected_at"),
            "errors": snapshot.get("errors", []),
        },
        "notice": "Snapshot observations only; missing metrics/capacity are unknown. "
                  "Pod counts include all phases and do not measure resource requests.",
        "expected_hardware_nodes": list(HARDWARE_NODES),
        "missing_hardware_nodes": sorted(set(HARDWARE_NODES) - node_names),
        "node_counts": {"total": len(nodes), "ready": ready,
                        "not_ready": len(nodes) - ready},
        "nodes": nodes,
        "pod_counts": {"total": sum(by_namespace.values()),
                       "assigned": sum(by_node.values()), "unassigned": unassigned},
        "pods_per_node": dict(sorted(by_node.items())),
        "pods_per_namespace": dict(sorted(by_namespace.items())),
        "pods_by_phase": dict(sorted(phases.items())),
        "unknown_assignment_nodes": sorted(set(by_node) - node_names),
    })


def estimate_cluster_power_and_gpu_headroom(mode='hybrid_balanced', catalog=None) -> dict:
    """Combine nominal GPU allocations with observed cluster utilization.

    GPU watts are fixed planning assumptions for simultaneous full load in all
    modes, not measured draw or vendor specifications. Heat assumes electrical
    input becomes heat (3.412142 BTU/h per watt). Node CPU/RAM headroom is the
    unused percentage of snapshot utilization, not schedulable requests or a
    workload admission guarantee. Unknown metrics remain None. GPU placement,
    free VRAM, host power, cooling capacity and PSU/circuit limits are unknown.
    """
    plan = gpu_and_household_triage.build_three_gpu_workload_plan(mode)
    summary = summarize_cluster_capacity(catalog)
    assumed_watts = {"gpu-0": 360, "gpu-1": 320, "gpu-2": 220}
    gpus = [dict(gpu, modeled_power_budget_watts=assumed_watts[gpu["id"]],
                 free_vram_gb=None) for gpu in plan["gpus"]]
    gpu_watts = sum(gpu["modeled_power_budget_watts"] for gpu in gpus)
    nodes = []
    for node in summary["nodes"]:
        headroom = {}
        for resource in ("cpu", "ram"):
            used = node["metrics"][resource + "_percent"]
            headroom[resource + "_headroom_percent"] = (
                None if used is None else round(max(0, 100 - used), 2))
        nodes.append(dict(node, **headroom))
    return sanitize({
        "simulation_only": True, "mode": plan["mode"],
        "gpu_workload_plan": plan, "gpus": gpus,
        "total_vram_gb": plan["total_vram_gb"],
        "workload_capacity_gb": plan["workload_capacity_gb"],
        "vram_pooled": plan["vram_pooled"],
        "power_thermal_budget": {
            "basis": "Assumed simultaneous full GPU load, independent of workload mode.",
            "gpu_power_budget_watts": gpu_watts,
            "gpu_heat_output_btu_per_hour": round(gpu_watts * 3.412142, 2),
            "cluster_total_power_watts": None,
            "cooling_headroom_watts": None,
            "notice": "GPU-only planning budget; excludes hosts and PSU losses. "
                      "No measured temperatures, cooling, PSU or circuit limits available.",
        },
        "nodes": nodes, "node_counts": summary["node_counts"],
        "missing_hardware_nodes": summary["missing_hardware_nodes"],
        "provenance": summary["provenance"],
        "notice": "VRAM is nominal exclusive allocation, not measured free memory. "
                  "GPU-to-node placement is unknown. CPU/RAM headroom uses snapshot "
                  "utilization, including NotReady nodes; it is not schedulable capacity.",
    })


def audit_workload_resource_requests(catalog=None) -> dict:
    """Audit explicit CPU/memory coverage in Pod and Deployment specs.

    Each observed object counts once, including terminal Pods and zero-replica
    Deployments; Deployment templates are not multiplied by replicas. Regular
    and init containers must all declare valid nonnegative CPU/memory requests
    and limits to be fully bounded. Missing/invalid declarations count as gaps;
    no admission defaults or runtime usage are inferred. Missing request and
    limit counts can overlap. Namespace ranks count Pods only, across all phases.
    """
    snapshot = _load_catalog(catalog)
    namespaces = Counter()
    inspected = bounded = missing_requests = missing_limits = 0
    recommendations = []

    def mapping(value):
        return value if isinstance(value, dict) else {}

    for item in sorted(snapshot["nodes"], key=lambda node: node["id"]):
        resource = mapping(item.get("resource"))
        kind = item.get("resource_kind", resource.get("kind"))
        if kind not in ("Pod", "Deployment"):
            continue
        inspected += 1
        metadata = mapping(resource.get("metadata"))
        namespace = metadata.get("namespace") or item.get("namespace") or "default"
        spec = mapping(resource.get("spec"))
        if kind == "Pod":
            namespaces[namespace] += 1
        else:
            spec = mapping(mapping(spec.get("template")).get("spec"))
        gaps = {"requests": [], "limits": []}
        containers = spec.get("containers")
        if not isinstance(containers, list) or not containers:
            for entries in gaps.values():
                entries.append("containers: CPU/memory coverage unavailable")
        for group in ("containers", "initContainers"):
            entries = spec.get(group, [])
            if not isinstance(entries, list):
                for missing in gaps.values():
                    missing.append(group + ": CPU/memory coverage unavailable")
                continue
            for index, container in enumerate(entries):
                container = mapping(container)
                resources = mapping(container.get("resources"))
                for category, missing in gaps.items():
                    declarations = mapping(resources.get(category))
                    for key in ("cpu", "memory"):
                        if _drain_quantity(declarations.get(key)) is None:
                            missing.append(f"{group}[{index}].{key}")
        requests_gap, limits_gap = bool(gaps["requests"]), bool(gaps["limits"])
        missing_requests += requests_gap
        missing_limits += limits_gap
        bounded += not (requests_gap or limits_gap)
        if requests_gap or limits_gap:
            recommendations.append({
                "workload_id": item["id"], "kind": kind,
                "namespace": namespace,
                "name": metadata.get("name") or item.get("label") or item["id"],
                "missing_requests": gaps["requests"], "missing_limits": gaps["limits"],
                "recommendation": "Review container usage history and set explicit CPU/memory "
                                  "requests and limits for the identified gaps. Update the "
                                  "owning workload template before rollout.",
            })
    return sanitize({
        "workloads_inspected": inspected, "fully_bounded_count": bounded,
        "missing_requests_count": missing_requests, "missing_limits_count": missing_limits,
        "top_namespaces_by_pod_count": [
            {"namespace": namespace, "pod_count": count}
            for namespace, count in sorted(namespaces.items(), key=lambda row: (-row[1], row[0]))
        ],
        "right_sizing_recommendations": recommendations,
    })


def _drain_quantity(value):
    """Parse nonnegative Kubernetes resource quantities into base units."""
    if type(value) in (int, float):
        return _metric(value)
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(\d+(?:\.\d*)?|\.\d+)([eE][+-]?\d+|[numkKMGTEP]|[KMGTPE]i)?", value)
    if not match:
        return None
    suffix = match[2] or ""
    powers = {"": 1, "n": 1e-9, "u": 1e-6, "m": 1e-3,
              "k": 1e3, "K": 1e3}
    powers.update({unit: 1000 ** index for index, unit in enumerate("MGTPE", 2)})
    powers.update({unit + "i": 1024 ** index
                   for index, unit in enumerate("KMGTPE", 1)})
    try:
        factor = powers[suffix] if suffix in powers else 10 ** int(suffix[1:])
        return _metric(float(match[1]) * factor)
    except (OverflowError, ValueError):
        return None


def _drain_requests(spec):
    """Effective requests, including init containers, sidecars and pod overhead."""
    total, init_peak, sidecars = Counter(), Counter(), Counter()
    unknown = not bool(spec.get("containers"))
    for container in spec.get("containers", []):
        requests = container.get("resources", {}).get("requests", {})
        unknown |= not all(key in requests for key in ("cpu", "memory"))
        for key, value in requests.items():
            amount = _drain_quantity(value)
            unknown |= amount is None
            total[key] += amount or 0
    for container in spec.get("initContainers", []):
        requests = container.get("resources", {}).get("requests", {})
        unknown |= not all(key in requests for key in ("cpu", "memory"))
        current = Counter()
        for key, value in requests.items():
            amount = _drain_quantity(value)
            unknown |= amount is None
            current[key] = amount or 0
        if container.get("restartPolicy") == "Always":
            sidecars.update(current)
            current = Counter(sidecars)
        else:
            current.update(sidecars)
        for key, amount in current.items():
            init_peak[key] = max(init_peak[key], amount)
    total.update(sidecars)
    for key, amount in init_peak.items():
        total[key] = max(total[key], amount)
    for key, value in spec.get("overhead", {}).items():
        amount = _drain_quantity(value)
        unknown |= amount is None
        total[key] += amount or 0
    return total, unknown


def simulate_node_drain(node_name='nodebeta02', catalog=None) -> dict:
    """Simulate node loss without changing the snapshot or contacting Kubernetes.

    First-fit placement uses observed requests and allocatable resources. Missing
    data makes placement provisional. nodeName is an observed assignment, not
    proof of a permanent pin. DaemonSets, stateful/local-storage workloads and
    unevaluated affinity constraints conservatively require operator review.
    Terminal pods are excluded. Single-replica workloads may be placeable while
    still facing an availability interruption. This is not a full scheduler or
    a PodDisruptionBudget/volume-topology check.
    """
    if (not isinstance(node_name, str) or len(node_name) > 253
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", node_name) is None
            or any(not part or len(part) > 63 or part.startswith("-")
                   or part.endswith("-") for part in node_name.split("."))):
        raise ValueError("Invalid or unknown hardware node")
    snapshot = _load_catalog(catalog)
    summary = summarize_cluster_capacity(snapshot)
    hardware = {node["name"]: node for node in summary["nodes"]}
    if node_name not in hardware:
        raise ValueError("Invalid or unknown hardware node")
    items = {item["id"]: item for item in snapshot["nodes"]}
    node_ids = {node["node_id"]: name for name, node in hardware.items()}
    placements = {}
    for edge in snapshot.get("edges", []):
        if edge.get("relation") == "runs_on_hardware" and edge.get("target") in node_ids:
            placements.setdefault(edge.get("source"), set()).add(node_ids[edge["target"]])
    survivors = sorted(name for name, node in hardware.items()
                       if name != node_name and node["ready"])
    available, node_specs, node_labels = {}, {}, {}
    unknown_capacity = set()
    for name in survivors:
        node = hardware[name]
        resource = items[node["node_id"]].get("resource", {})
        node_specs[name] = resource.get("spec", {})
        node_labels[name] = resource.get("metadata", {}).get("labels", {})
        available[name] = {key: _drain_quantity(value) for key, value in
                           resource.get("status", {}).get("allocatable", {}).items()}
        if any(available[name].get(key) is None for key in ("cpu", "memory")):
            unknown_capacity.add(name)
    pods, owner_counts = [], Counter()
    for item in sorted(snapshot["nodes"], key=lambda item: item["id"]):
        resource = item.get("resource", {})
        if (item.get("resource_kind", resource.get("kind")) != "Pod"
                or resource.get("status", {}).get("phase") in ("Succeeded", "Failed")):
            continue
        spec, metadata = resource.get("spec", {}), resource.get("metadata", {})
        hosts = set(placements.get(item["id"], ()))
        if spec.get("nodeName"):
            hosts.add(spec["nodeName"])
        owners = [owner for owner in metadata.get("ownerReferences", [])
                  if owner.get("controller") is not False]
        owner = owners[0] if owners else {}
        namespace = metadata.get("namespace") or item.get("namespace") or "default"
        owner_key = (namespace, owner.get("kind"), owner.get("name"))
        owner_counts[owner_key] += 1
        requests, unknown = _drain_requests(spec)
        pods.append((item, spec, metadata, hosts, owner, owner_key, requests, unknown))
        # Charge resident requests once, even when placement has duplicate edges.
        for host in hosts & set(survivors):
            if unknown:
                unknown_capacity.add(host)
            for key, amount in dict(requests, pods=1).items():
                if available[host].get(key) is not None:
                    available[host][key] -= amount
    risks, evicted, reschedulable = [], 0, 0
    for item, spec, metadata, hosts, owner, owner_key, requests, unknown in pods:
        if node_name not in hosts:
            continue
        evicted += 1
        reasons, blockers = [], []
        if len(hosts) > 1:
            blockers.append("conflicting_placement")
        if owner.get("kind") == "DaemonSet":
            blockers.append("daemonset_node_local")
        if (owner.get("kind") == "StatefulSet" or
                "statefulset.kubernetes.io/pod-name" in metadata.get("labels", {})):
            blockers.append("stateful_workload")
        if any(any(key in volume for key in ("hostPath", "local", "persistentVolumeClaim"))
               for volume in spec.get("volumes", [])):
            blockers.append("storage_requires_review")
        if spec.get("affinity") or spec.get("topologySpreadConstraints"):
            blockers.append("scheduling_constraints_require_review")
        if not owner or "kubernetes.io/config.mirror" in metadata.get("annotations", {}):
            blockers.append("unmanaged_or_static_pod")
        if owner and owner.get("kind") != "DaemonSet" and owner_counts[owner_key] == 1:
            reasons.append("single_replica_observed")
        candidates = []
        for host in survivors:
            if node_specs[host].get("unschedulable"):
                continue
            if any(node_labels[host].get(key) != value
                   for key, value in spec.get("nodeSelector", {}).items()):
                continue
            taints = node_specs[host].get("taints", [])
            if any(taint.get("effect") in ("NoSchedule", "NoExecute") and not any(
                    (not tol.get("effect") or tol["effect"] == taint.get("effect"))
                    and (tol.get("key") == taint.get("key") or
                         (tol.get("operator") == "Exists" and not tol.get("key")))
                    and (tol.get("operator") == "Exists" or
                         tol.get("value", "") == taint.get("value", ""))
                    for tol in spec.get("tolerations", [])) for taint in taints):
                continue
            needed = dict(requests, pods=1)
            if all((available[host].get(key) is None and key in ("cpu", "memory", "pods"))
                   or (available[host].get(key) is not None and available[host][key] >= amount)
                   for key, amount in needed.items()):
                candidates.append(host)
        if not candidates:
            blockers.append("no_eligible_remaining_capacity")
        if not blockers:
            reschedulable += 1
            chosen = candidates[0]
            for key, amount in dict(requests, pods=1).items():
                if available[chosen].get(key) is not None:
                    available[chosen][key] -= amount
            if unknown or chosen in unknown_capacity:
                reasons.append("capacity_evidence_incomplete")
        reasons = blockers + reasons
        if reasons:
            risks.append({"pod_id": item["id"], "namespace": owner_key[0],
                          "name": metadata.get("name") or item.get("label") or item["id"],
                          "owner_kind": owner.get("kind"), "reasons": reasons,
                          "reschedulable": not bool(blockers)})
    return sanitize({
        "simulation_only": True, "target_node": node_name,
        "surviving_ready_nodes": survivors, "evicted_pod_count": evicted,
        "reschedulable_count": reschedulable, "at_risk_workloads": risks,
        "blast_radius_status": "at_risk" if risks else "no_disruption_identified",
        "notice": "Offline first-fit simulation; evicted count includes active DaemonSet/static "
                  "pods affected by node loss. Placement is provisional when capacity evidence "
                  "is incomplete. PDBs and full scheduler/volume constraints are not evaluated.",
    })


def render_capacity_planner_html(catalog=None) -> str:
    """Render an offline snapshot with interactive, read-only drain scenarios."""
    snapshot = _load_catalog(catalog)
    summary = summarize_cluster_capacity(snapshot)
    evidence = {
        "summary": summary,
        "audit": audit_workload_resource_requests(snapshot),
        "power": estimate_cluster_power_and_gpu_headroom(catalog=snapshot),
        "drains": [simulate_node_drain(node["name"], snapshot)
                   for node in summary["nodes"]],
    }
    # JSON inside a script element must not contain HTML parser delimiters,
    # even though all subsequent DOM writes use textContent.
    payload = (json.dumps(sanitize(evidence), allow_nan=False)
               .replace("&", "\\u0026").replace("<", "\\u003c")
               .replace(">", "\\u003e"))
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>OpsCryer Capacity Planner</title>
<style>
:root{color-scheme:dark}body{background:#111827;color:#e5e7eb;
font-family:system-ui,sans-serif;max-width:1100px;margin:auto;padding:1.5rem;
line-height:1.6}nav{display:flex;gap:1.2rem;flex-wrap:wrap}a{color:#93c5fd}
section{background:#1f2937;border:1px solid #4b5563;border-radius:.7rem;
padding:1.2rem;margin-top:1.5rem}h1,h2{line-height:1.25}li{margin:.6rem 0}
select{background:#111827;color:#e5e7eb;border:1px solid #9ca3af;
border-radius:.3rem;padding:.6rem;max-width:100%;font:inherit}
:focus-visible{outline:3px solid #93c5fd;outline-offset:3px}
pre{white-space:pre-wrap;overflow-wrap:anywhere}li,p{overflow-wrap:anywhere}
</style>
</head>
<body>
<nav aria-label="Main navigation"><a href="/">Home</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity" aria-current="page">Capacity</a><a href='/metrics-live'>Live Metrics</a></nav>
<main>
<h1>Capacity &amp; N-1 Drain Simulator</h1>
<p>Offline snapshot planning. Selecting a node simulates its loss without changing the cluster.</p>
<p>Snapshot telemetry_source: <strong id="telemetry-source">''' + escape(summary["telemetry_source"]) + '''</strong></p>
<section aria-label="Live Metrics Stream">
<h2>Live Metrics Stream</h2>
<button id="live-refresh" type="button">Refresh Live Metrics</button>
<p id="live-refresh-status" role="status" aria-live="polite">Live metrics have not been refreshed.</p>
<pre id="live-metrics-output" hidden></pre>
</section>
<noscript>Enable JavaScript to view the embedded capacity snapshot and drain scenarios.</noscript>
<section aria-labelledby="summary-heading">
<h2 id="summary-heading">Cluster capacity</h2><div id="capacity-summary"></div>
</section>
<section aria-labelledby="drain-heading">
<h2 id="drain-heading">N-1 drain simulation</h2>
<label for="drain-node-select">Node to drain</label>
<select id="drain-node-select"></select>
<div id="drain-result" role="status" aria-live="polite"></div>
</section>
<section aria-labelledby="sizing-heading">
<h2 id="sizing-heading">Right-sizing recommendations</h2>
<p id="resource-audit-summary"></p><ul id="right-sizing-list"></ul>
</section>
<section aria-labelledby="power-heading">
<h2 id="power-heading">GPU power and headroom assumptions</h2><div id="power-summary"></div>
</section>
</main>
<script id="capacity-data" type="application/json">''' + payload + '''</script>
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
  if (typeof window !== "undefined" && window.location && /^https?:$/i.test(window.location.protocol)) {
    button.click();
  }
})();
"use strict";
const data = JSON.parse(document.getElementById("capacity-data").textContent);
function add(parent, tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    parent.appendChild(element);
    return element;
}
function known(value) { return value == null ? "unknown" : String(value); }
const summary = data.summary;
const panel = document.getElementById("capacity-summary");
add(panel, "p", summary.node_counts.ready + " / " + summary.node_counts.total +
    " nodes Ready; " + summary.pod_counts.total + " pods; " +
    summary.pod_counts.unassigned + " unassigned.");
add(panel, "p", "Source: " + known(summary.provenance.source) +
    "; collected: " + known(summary.provenance.collected_at));
add(panel, "p", summary.notice);
if (summary.missing_hardware_nodes.length) {
    add(panel, "p", "Missing expected nodes: " + summary.missing_hardware_nodes.join(", "));
}
const nodes = add(panel, "ul", "");
for (const node of summary.nodes) {
    add(nodes, "li", node.name + " — " + node.readiness + "; pods: " + node.pod_count +
        "; CPU usage (%): " + known(node.metrics.cpu_percent) +
        "; RAM usage (%): " + known(node.metrics.ram_percent) +
        "; CPU capacity / allocatable: " + known(node.capacity.cpu) + " / " +
        known(node.allocatable.cpu) + "; memory capacity / allocatable: " +
        known(node.capacity.memory) + " / " + known(node.allocatable.memory));
}
const select = document.getElementById("drain-node-select");
for (const scenario of data.drains) {
    const option = add(select, "option", scenario.target_node);
    option.value = scenario.target_node;
}
function renderDrain() {
    const result = document.getElementById("drain-result");
    result.textContent = "";
    const scenario = data.drains.find(item => item.target_node === select.value);
    if (!scenario) {
        add(result, "p", "No hardware nodes available in this snapshot.");
        return;
    }
    add(result, "p", "Simulation only — " + scenario.target_node + ": " +
        scenario.evicted_pod_count + " affected pods; " + scenario.reschedulable_count +
        " provisionally reschedulable; status: " + scenario.blast_radius_status);
    add(result, "p", "Surviving Ready nodes: " +
        (scenario.surviving_ready_nodes.join(", ") || "none"));
    add(result, "p", scenario.notice);
    const risks = add(result, "ul", "");
    for (const risk of scenario.at_risk_workloads) {
        add(risks, "li", risk.namespace + "/" + risk.name + ": " + risk.reasons.join(", "));
    }
    if (!scenario.at_risk_workloads.length) {
        add(result, "p", "No disruption identified by this limited simulation.");
    }
}
select.disabled = data.drains.length === 0;
select.addEventListener("change", renderDrain);
renderDrain();
const audit = data.audit;
document.getElementById("resource-audit-summary").textContent =
    audit.workloads_inspected + " workloads inspected; " + audit.fully_bounded_count +
    " fully bounded; " + audit.missing_requests_count + " missing requests; " +
    audit.missing_limits_count + " missing limits.";
const recommendations = document.getElementById("right-sizing-list");
for (const row of audit.right_sizing_recommendations) {
    add(recommendations, "li", row.kind + " " + row.namespace + "/" + row.name +
        ": " + row.recommendation + " Missing requests: " +
        (row.missing_requests.join(", ") || "none") + "; missing limits: " +
        (row.missing_limits.join(", ") || "none"));
}
if (!audit.right_sizing_recommendations.length) {
    add(recommendations, "li", "No resource declaration gaps found in inspected workloads.");
}
const power = document.getElementById("power-summary");
add(power, "p", data.power.notice);
add(power, "p", "Mode: " + known(data.power.mode) + " — Total VRAM: " +
    known(data.power.total_vram_gb) + " GB (AI Swarm: " +
    known((data.power.workload_capacity_gb || {}).ai_swarm) + " GB; Gaming LAN: " +
    known((data.power.workload_capacity_gb || {}).gaming_lan) + " GB); GPU Power Budget: " +
    known(data.power.power_thermal_budget.gpu_power_budget_watts) + " W (" +
    known(data.power.power_thermal_budget.gpu_heat_output_btu_per_hour) + " BTU/h).");
const gpuList = add(power, "ul", "");
for (const gpu of (data.power.gpus || [])) {
    add(gpuList, "li", gpu.id + " (" + gpu.tier + "): " + gpu.vram_gb +
        " GB VRAM — assigned workload: " + gpu.assigned_workload +
        "; modeled power budget: " + gpu.modeled_power_budget_watts + " W");
}
for (const n of (data.power.nodes || [])) {
    add(gpuList, "li", n.name + " (" + n.readiness + "): CPU headroom " +
        known(n.cpu_headroom_percent) + "%; RAM headroom " + known(n.ram_headroom_percent) + "%");
}
add(power, "pre", JSON.stringify(data.power.power_thermal_budget, null, 2));
</script>
</body>
</html>'''


def render_capacity_markdown(catalog=None) -> str:
    """Export sanitized capacity, resource audit and offline drain evidence."""
    snapshot = _load_catalog(catalog)
    summary = summarize_cluster_capacity(snapshot)
    audit = audit_workload_resource_requests(snapshot)
    power = estimate_cluster_power_and_gpu_headroom(catalog=snapshot)

    def text(value):
        if value is None:
            return "unknown"
        value = escape(str(value), quote=True)
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", " ".join(value.split()))

    lines = ["# OpsCryer Capacity Planner", "", "## Cluster capacity", "",
             f"Ready nodes: {summary['node_counts']['ready']} / {summary['node_counts']['total']}",
             f"Pods: {summary['pod_counts']['total']}; unassigned: {summary['pod_counts']['unassigned']}",
             "Source: " + text(summary['provenance']['source']),
             "Collected: " + text(summary['provenance']['collected_at']), "",
             summary['notice'], "",
             "| Node | Readiness | Pods | CPU usage (%) | RAM usage (%) | CPU capacity / allocatable | Memory capacity / allocatable |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for node in summary['nodes']:
        cells = [node['name'], node['readiness'], node['pod_count'],
                 node['metrics']['cpu_percent'], node['metrics']['ram_percent']]
        cells = [text(value) for value in cells]
        for key in ('cpu', 'memory'):
            cells.append(text(node['capacity'][key]) + " / " + text(node['allocatable'][key]))
        lines.append("| " + " | ".join(cells) + " |")
    if summary['missing_hardware_nodes']:
        lines.extend(["", "Missing expected nodes: " + ", ".join(
            text(name) for name in summary['missing_hardware_nodes'])])
    lines.extend(["", "## Resource requests and limits", "",
                  f"Workloads inspected: {audit['workloads_inspected']}; "
                  f"fully bounded: {audit['fully_bounded_count']}; "
                  f"missing requests: {audit['missing_requests_count']}; "
                  f"missing limits: {audit['missing_limits_count']}", ""])
    for row in audit['right_sizing_recommendations']:
        lines.append("- " + text(row['kind']) + " " + text(row['namespace']) + "/" +
                     text(row['name']) + ": " + text(row['recommendation']) +
                     " Missing requests: " + text(", ".join(row['missing_requests']) or "none") +
                     "; missing limits: " + text(", ".join(row['missing_limits']) or "none"))
    if not audit['right_sizing_recommendations']:
        lines.append("No resource declaration gaps found in inspected workloads.")
    lines.extend(["", "### Namespaces by pod count", ""])
    for row in audit['top_namespaces_by_pod_count']:
        lines.append("- " + text(row['namespace']) + ": " + str(row['pod_count']))
    lines.extend(["", "## N-1 drain simulations", ""])
    for node in summary['nodes']:
        drain = simulate_node_drain(node['name'], snapshot)
        lines.extend(["### " + text(drain['target_node']), "",
                      f"Affected pods: {drain['evicted_pod_count']}; "
                      f"provisionally reschedulable: {drain['reschedulable_count']}",
                      "Status: " + text(drain['blast_radius_status']),
                      "Surviving Ready nodes: " + text(", ".join(drain['surviving_ready_nodes']) or "none"),
                      "", drain['notice'], ""])
        for risk in drain['at_risk_workloads']:
            lines.append("- " + text(risk['namespace']) + "/" + text(risk['name']) +
                         ": " + text(", ".join(risk['reasons'])))
        if not drain['at_risk_workloads']:
            lines.append("No disruption identified by this limited simulation.")
        lines.append("")
    budget = power['power_thermal_budget']
    lines.extend(["## GPU power and headroom assumptions", "", power['notice'], "",
                  budget['basis'], "",
                  f"GPU power budget: {budget['gpu_power_budget_watts']} W; "
                  f"heat output: {budget['gpu_heat_output_btu_per_hour']} BTU/h.",
                  "Cluster total power: unknown; cooling headroom: unknown.", "", budget['notice']])
    return sanitize("\n".join(lines) + "\n")


def _capacity_report(catalog, drain_node=None):
    if drain_node is not None:
        return simulate_node_drain(drain_node, catalog)
    return {"summary": summarize_cluster_capacity(catalog),
            "audit": audit_workload_resource_requests(catalog),
            "power": estimate_cluster_power_and_gpu_headroom(catalog=catalog)}


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid capacity planner arguments")


def _build_capacity_handler(catalog, drain_node=None):
    """Serve a validated snapshot without logging request targets or errors."""
    class CapacityRequestHandler(BaseHTTPRequestHandler):
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
                if url.path not in {"/", "/capacity", "/api/v1/capacity-planner", "/capacity/report.md"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                query = parse_qs(url.query, keep_blank_values=True, max_num_fields=1)
                if set(query) - {"drain_node"}:
                    raise ValueError("Invalid query")
                target = query.get("drain_node", [drain_node])[0]
                if url.path == "/api/v1/capacity-planner":
                    body = json.dumps(_capacity_report(catalog, target), indent=2, allow_nan=False)
                    content_type = "application/json"
                else:
                    if query:
                        raise ValueError("Invalid query")
                    if url.path == "/capacity/report.md":
                        body, content_type = render_capacity_markdown(catalog), "text/markdown"
                    else:
                        body, content_type = render_capacity_planner_html(catalog), "text/html"
            except (ValueError, TypeError, KeyError):
                self._send(400, '{"error":"Invalid capacity request"}', "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Capacity planner unavailable"}', "application/json")
                return
            self._send(200, body, content_type)

    return CapacityRequestHandler


def main(argv=None) -> int:
    """Export offline capacity evidence or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="capacity_planner", description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--drain-node", metavar="NODE")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or (args.markdown and args.drain_node is not None):
        parser.error("Invalid option combination")
    try:
        catalog = _load_catalog(args.catalog)
        if args.drain_node is not None:
            simulate_node_drain(args.drain_node, catalog)
        if args.serve:
            handler = _build_capacity_handler(catalog, args.drain_node)
            with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
                print(f"Capacity planner: http://127.0.0.1:{args.port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_capacity_markdown(catalog), end="")
        else:
            print(json.dumps(_capacity_report(catalog, args.drain_node), indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete capacity request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
