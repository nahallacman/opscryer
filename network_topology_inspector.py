# SPDX-License-Identifier: Apache-2.0
"""Offline, sanitized Ingress-to-hardware observations from cluster snapshots."""

import argparse
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import oidc_rbac_verifier
import chaos_blast_radius
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
WORKLOAD_KINDS = frozenset(("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
                            "Job", "CronJob"))


def _load_catalog(catalog):
    try:
        if catalog is None or isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(DEFAULT_CATALOG_PATH if catalog is None else catalog)
                                 .read_text(encoding="utf-8"))
        if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
            raise ValueError
        json.dumps(catalog, allow_nan=False)
        snapshot = sanitize(catalog)
        identities = set()
        for node in snapshot["nodes"]:
            if (not isinstance(node, dict) or not isinstance(node.get("id"), str)
                    or not node["id"] or node["id"] in identities):
                raise ValueError
            identities.add(node["id"])
            resource = node.get("resource", {})
            if not isinstance(resource, dict):
                raise ValueError
            for field in ("metadata", "spec", "status"):
                if not isinstance(resource.get(field, {}), dict):
                    raise ValueError
        edges = snapshot.get("edges", [])
        if not isinstance(edges, list):
            raise ValueError
        for edge in edges:
            if (not isinstance(edge, dict) or edge.get("source") not in identities
                    or edge.get("target") not in identities
                    or not isinstance(edge.get("relation"), str)):
                raise ValueError
        return snapshot
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError("Invalid cluster catalog") from None


def _resource(node):
    return node.get("resource", {})


def _kind(node):
    return _resource(node).get("kind", node.get("resource_kind"))


def _name(node):
    return _resource(node).get("metadata", {}).get("name") or node.get("label") or node["id"]


def _namespace(node):
    return (_resource(node).get("metadata", {}).get("namespace")
            or node.get("namespace") or "default")


def _ref(node):
    return {"node_id": node["id"], "name": _name(node), "kind": _kind(node)}


def detect_routing_anomalies(catalog=None) -> dict:
    """Return deterministic offline findings and suggested read-only commands.

    Services are backed by same-namespace routing links or matching pod/workload
    template labels, including workload ownership chains. Absent backing objects
    are snapshot gaps, including for ExternalName and manually managed services.
    Explicit unhealthy pod/controller state and unready/empty endpoint records
    establish degraded endpoint observations; absent health fields stay unknown.
    Missing forward-auth annotations never prove anonymous runtime access.
    Accept the bundled snapshot, a JSON path or a graph dict without mutation.
    """
    try:
        snapshot = _load_catalog(catalog)
        snapshot["nodes"].sort(key=lambda node: node["id"])
        nodes = {node["id"]: node for node in snapshot["nodes"]}
        posture = oidc_rbac_verifier.audit_cluster_ingress_oidc_posture(snapshot)
        if posture["status"] == "invalid_catalog":
            raise ValueError
        identities = set()
        for node in nodes.values():
            identity = (_kind(node), _namespace(node), _name(node))
            if identity in identities:
                raise ValueError
            identities.add(identity)
        outgoing = defaultdict(set)
        for edge in snapshot.get("edges", []):
            outgoing[edge["source"], edge["relation"]].add(edge["target"])
        by_identity = {(_kind(n), _namespace(n), _name(n)): n["id"]
                       for n in nodes.values()}
        for node in nodes.values():
            for owner in _resource(node).get("metadata", {}).get("ownerReferences", []):
                parent = by_identity.get((owner.get("kind"), _namespace(node), owner.get("name")))
                if parent:
                    outgoing[parent, "owns_workload"].add(node["id"])

        # Service selectors only match pods/workloads in the same namespace.
        # Extract labels once instead of rescanning the whole graph per service.
        candidates_by_namespace = defaultdict(list)
        for candidate in nodes.values():
            kind = _kind(candidate)
            if kind not in WORKLOAD_KINDS | {"Pod"}:
                continue
            resource = _resource(candidate)
            labels = (resource.get("metadata", {}).get("labels", {}) if kind == "Pod"
                      else resource.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}))
            candidates_by_namespace[_namespace(candidate)].append((candidate["id"], labels))

        def commands(namespace, resource, name=None):
            def safe(value):
                return (isinstance(value, str) and len(value) <= 253
                        and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value))

            scope = (" --namespace " + namespace if safe(namespace)
                     else " --all-namespaces")
            target = " " + name if safe(namespace) and safe(name) else ""
            return ["kubectl get " + resource + target + scope + " -o wide",
                    "kubectl describe " + resource + target + scope]

        findings, degraded = [], defaultdict(set)
        for service in nodes.values():
            if _kind(service) != "Service":
                continue
            namespace = _namespace(service)
            selector = _resource(service).get("spec", {}).get("selector", {})
            if not isinstance(selector, dict):
                raise ValueError
            backing = set(outgoing[service["id"], "routes_to"])
            if selector:
                for candidate_id, labels in candidates_by_namespace[namespace]:
                    if all(labels.get(key) == value for key, value in selector.items()):
                        backing.add(candidate_id)
            backing = {key for key in backing if _namespace(nodes[key]) == namespace
                       and _kind(nodes[key]) in WORKLOAD_KINDS | {"Pod"}}
            pending = list(backing)
            while pending:
                current = pending.pop()
                for child in outgoing[current, "owns_workload"]:
                    if (child not in backing and _namespace(nodes[child]) == namespace
                            and _kind(nodes[child]) in WORKLOAD_KINDS | {"Pod"}):
                        backing.add(child)
                        pending.append(child)
            if not backing:
                findings.append({
                    "category": "orphan_service", "namespace": namespace,
                    "resource": _ref(service),
                    "summary": "No backing pod or workload observed in the snapshot.",
                    "inspection_commands": commands(namespace, "services", _name(service))
                    + commands(namespace, "pods"),
                })
            for key in sorted(backing):
                node = nodes[key]
                resource = _resource(node)
                status = resource.get("status", {})
                unhealthy = False
                if _kind(node) == "Pod":
                    unhealthy = (status.get("phase") in {"Failed", "Pending", "Unknown"}
                                 or any(c.get("type") == "Ready" and c.get("status") in {"False", "Unknown"}
                                        for c in status.get("conditions", []))
                                 or any(c.get("ready") is False
                                        for c in status.get("containerStatuses", [])))
                elif _kind(node) in {"Deployment", "StatefulSet", "ReplicaSet", "DaemonSet"}:
                    desired = (status.get("desiredNumberScheduled") if _kind(node) == "DaemonSet"
                               else resource.get("spec", {}).get("replicas", 1))
                    ready = status.get("numberReady" if _kind(node) == "DaemonSet" else "readyReplicas")
                    if desired is not None and (ready is not None or status):
                        unhealthy = desired > 0 and (ready or 0) < desired
                if unhealthy:
                    degraded[namespace].add(key)

        ingress_index = 0
        for node in nodes.values():
            kind, namespace = _kind(node), _namespace(node)
            resource = _resource(node)
            if kind == "Ingress":
                observation = posture["ingresses"][ingress_index]
                ingress_index += 1
                auth_findings = sorted(code for code in observation["findings"]
                                       if code.startswith("authentik_"))
                if auth_findings:
                    findings.append({
                        "category": "ingress_oidc_unverified", "namespace": namespace,
                        "resource": _ref(node), "evidence": auth_findings,
                        "enforcement_verified": False,
                        "summary": "Expected OIDC forward-auth annotations are missing or unverified.",
                        "inspection_commands": commands(namespace, "ingresses", _name(node)),
                    })
            elif kind == "Endpoints":
                subsets = resource.get("subsets", [])
                if (not any(subset.get("addresses") for subset in subsets)
                        or any(subset.get("notReadyAddresses") for subset in subsets)):
                    degraded[namespace].add(node["id"])
            elif kind == "EndpointSlice":
                endpoints = resource.get("endpoints", [])
                if not endpoints or any(e.get("conditions", {}).get("ready") is False
                                        for e in endpoints):
                    degraded[namespace].add(node["id"])
        for namespace in sorted(degraded):
            findings.append({
                "category": "degraded_endpoints", "namespace": namespace,
                "resources": [_ref(nodes[key]) for key in sorted(degraded[namespace])],
                "summary": "Unhealthy backends or empty/unready endpoint records observed in this namespace.",
                "inspection_commands": commands(namespace, "pods")
                + commands(namespace, "endpoints") + commands(namespace, "endpointslices"),
            })
        findings.sort(key=lambda item: (item["category"], item["namespace"],
                                        item.get("resource", {}).get("node_id", "")))
        categories = ("orphan_service", "ingress_oidc_unverified", "degraded_endpoints")
        return sanitize({
            "source": snapshot.get("source", "provided_catalog"),
            "provenance": {"mode": "offline_snapshot", "live_collection": False,
                           "collected_at": snapshot.get("collected_at")},
            "notice": "Snapshot observations only; missing backing objects can reflect incomplete "
                      "collection or externally managed services. Missing OIDC metadata does not "
                      "prove anonymous access. Commands are read-only suggestions, never executed.",
            "finding_count": len(findings), "findings": findings,
            "summary_counts": {category: sum(f["category"] == category for f in findings)
                               for category in categories},
        })
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, RecursionError):
        raise ValueError("Invalid cluster catalog") from None


def build_namespace_exposure_matrix(catalog=None) -> dict:
    """Combine namespace exposure, OIDC observations and offline chaos planes.

    Accept the bundled snapshot, a JSON path or a graph dict without mutation.
    Namespace declarations and resource namespace fields establish observations;
    ingress/service resources without a namespace belong to default. Unmapped
    namespaces never inherit a plane. Barriers are model assumptions, including
    when the chaos simulation has insufficient evidence, not observed controls.
    Malformed catalogs raise a fixed ValueError without reflecting input.
    """
    try:
        snapshot = _load_catalog(catalog)
        posture = oidc_rbac_verifier.audit_cluster_ingress_oidc_posture(snapshot)
        if posture["status"] == "invalid_catalog":
            raise ValueError
        chaos = chaos_blast_radius.verify_all_six_chaos_planes(snapshot)
        if any(report["status"] == "invalid_catalog"
               for report in chaos["planes"].values()):
            raise ValueError
        namespace_planes = {namespace: plane
                            for plane, names in chaos_blast_radius.PLANE_NAMESPACES.items()
                            for namespace in names}
        rows = {}
        ingress_index = 0
        for node in snapshot["nodes"]:
            kind = _kind(node)
            metadata = _resource(node).get("metadata", {})
            namespace = (_name(node) if kind == "Namespace" else
                         metadata.get("namespace") or node.get("namespace"))
            if namespace in (None, "") and kind in {"Ingress", "Service"}:
                namespace = "default"
            if namespace in (None, ""):
                continue
            if not isinstance(namespace, str) or not namespace:
                raise ValueError
            if namespace not in rows:
                plane = namespace_planes.get(namespace)
                rows[namespace] = {
                    "namespace": namespace, "chaos_isolation_plane": plane,
                    "ingress_count": 0, "service_count": 0,
                    "cross_plane_barrier_status": "assumed" if plane else "unmapped",
                    "chaos_simulation_status": (chaos["planes"][plane]["status"]
                                                if plane else "unmapped"),
                    "simulation_only": True, "live_enforcement_verified": False,
                    "oidc_posture": {"status": "no_ingresses_observed",
                                     "configured_count": 0, "unknown_count": 0,
                                     "enforcement_verified": False, "ingresses": []},
                }
            row = rows[namespace]
            if kind == "Service":
                row["service_count"] += 1
            elif kind == "Ingress":
                observation = posture["ingresses"][ingress_index]
                ingress_index += 1
                row["ingress_count"] += 1
                oidc = row["oidc_posture"]
                oidc["ingresses"].append(observation)
                oidc["configured_count"] += observation["status"] == "configured_observed_fields"
                oidc["unknown_count"] += observation["status"] == "unknown"
                oidc["status"] = ("unknown" if oidc["unknown_count"] else
                                  "configured_observed_fields")
        if ingress_index != posture["ingress_count"]:
            raise ValueError
        return sanitize({
            "source": snapshot.get("source", "provided_catalog"),
            "provenance": {"mode": "offline_snapshot", "live_collection": False,
                           "collected_at": snapshot.get("collected_at")},
            "notice": "Offline snapshot and chaos model only. Cross-plane barriers are "
                      "assumed, not verified network policies or dedicated hardware isolation. "
                      "OIDC metadata does not verify runtime authentication enforcement; "
                      "missing configuration is unknown evidence, not proof of anonymous access.",
            "simulation_only": True, "live_enforcement_verified": False,
            "namespace_count": len(rows), "ingress_count": ingress_index,
            "service_count": sum(row["service_count"] for row in rows.values()),
            "namespaces": [rows[name] for name in sorted(rows)],
            "oidc_posture": posture, "chaos_planes": chaos,
        })
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, RecursionError):
        raise ValueError("Invalid cluster catalog") from None


def trace_ingress_to_hardware_routes(catalog=None) -> dict:
    """Trace every Ingress, including cluster.example.org hosts, without live collection.

    Accept a graph dict, JSON path, or the bundled snapshot. Directed routes_to,
    owns_workload and runs_on_hardware edges supply observed links; Kubernetes
    backend names, selectors, ownerReferences and nodeName supplement them.
    Namespace containment alone never implies a service backend. Missing services,
    pods, owners and hardware remain explicit rather than creating inferred paths.
    OIDC metadata observations do not establish runtime authentication enforcement.
    Results are deterministic, detached, sanitized and leave the input untouched.
    Invalid catalogs raise a fixed ValueError without exposing their contents.
    """
    try:
        return _trace_routes(_load_catalog(catalog))
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise ValueError("Invalid cluster catalog") from None


def export_network_mermaid_diagram(catalog=None) -> str:
    """Export observed cluster.example.org ingress -> namespace -> hardware topology.

    Accept the same catalogs as trace_ingress_to_hardware_routes. Namespace
    links aggregate observed hardware across their ingress routes; missing
    hardware never creates an inferred node. Generated IDs and quoted,
    entity-escaped labels keep catalog text out of Mermaid syntax.
    """
    report = trace_ingress_to_hardware_routes(catalog)
    labels, edges = {}, set()
    for route in report["routes"]:
        hosts = [host for host in route["hosts"]
                 if host.lower().endswith(".cluster.example.org")]
        if not hosts:
            continue
        namespace = ("namespace", route["namespace"])
        labels[namespace] = "Namespace: " + route["namespace"]
        for host in hosts:
            ingress = ("ingress", route["ingress"]["node_id"], host)
            labels[ingress] = "Ingress: " + host + " (" + route["ingress"]["name"] + ")"
            edges.add((ingress, namespace))
        for service in route["services"]:
            for pod in service["pods"]:
                for hardware in pod["hardware_nodes"]:
                    node = ("hardware", hardware["node_id"])
                    labels[node] = "Hardware: " + hardware["name"]
                    edges.add((namespace, node))

    def quote_label(label):
        # Mermaid uses #decimal; entities, rather than JSON backslash escapes.
        label = sanitize(label)
        return "".join(
            " " if character.isspace() else character
            if character.isascii() and (character.isalnum() or character in " ._-:/")
            else "#" + str(ord(character)) + ";"
            for character in label)

    identities = {key: "n" + str(index) for index, key in enumerate(sorted(labels))}
    lines = ["flowchart LR"]
    for key in sorted(labels):
        lines.append('    ' + identities[key] + '["' + quote_label(labels[key]) + '"]')
    for source, target in sorted(edges):
        lines.append("    " + identities[source] + " --> " + identities[target])
    return "\n".join(lines) + "\n"


def render_network_inspector_html(catalog=None) -> str:
    """Return an offline Network & OIDC Route Inspector with safe DOM updates."""
    snapshot = _load_catalog(catalog)
    evidence = {
        "routes": trace_ingress_to_hardware_routes(snapshot),
        "exposure": build_namespace_exposure_matrix(snapshot),
        "mermaid": export_network_mermaid_diagram(snapshot),
    }
    # Escape HTML parser delimiters before placing JSON in a script data block.
    payload = (json.dumps(sanitize(evidence), allow_nan=False)
               .replace("&", "\\u0026").replace("<", "\\u003c")
               .replace(">", "\\u003e"))
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>OpsCryer | Network &amp; OIDC Route Inspector</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif;
    background: #0b1220; color: #e2e8f0; }
body { max-width: 1440px; margin: auto; padding: 24px; }
nav { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 32px; }
a { color: #7dd3fc; } a[aria-current] { font-weight: bold; }
h1, h2 { color: #f8fafc; } p { line-height: 1.6; }
section { background: #111c30; border: 1px solid #334155;
    border-radius: 12px; padding: 20px; margin: 24px 0; }
.table-scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; text-align: left; }
caption { text-align: left; padding-bottom: 16px; color: #cbd5e1; }
th, td { border-bottom: 1px solid #334155; padding: 12px;
    vertical-align: top; white-space: pre-line; overflow-wrap: anywhere; }
th { color: #7dd3fc; } pre { overflow: auto; padding: 16px;
    background: #0b1220; border-radius: 8px; }
.notice { color: #cbd5e1; }
</style>
</head>
<body>
<nav aria-label="Main navigation">
<a href="/">Overview</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network" aria-current="page">Network</a>
</nav>
<main>
<h1>Network &amp; OIDC Route Inspector</h1>
<p id="network-summary"></p>
<p class="notice">Offline snapshot observations only. Runtime connectivity and OIDC
authentication enforcement are unverified. Missing metadata is unknown evidence.
Cross-plane barriers are model assumptions, not verified network policies.</p>
<noscript>Enable JavaScript to view the embedded snapshot reports.</noscript>
<section aria-labelledby="routes-heading">
<h2 id="routes-heading">Ingress routes</h2>
<div class="table-scroll"><table>
<caption>Observed ingress to service, pod and hardware lineage</caption>
<thead><tr><th scope="col">Namespace / ingress</th><th scope="col">Hosts</th>
<th scope="col">Services / pods / hardware</th><th scope="col">OIDC metadata</th>
</tr></thead><tbody id="network-routes-list"></tbody>
</table></div></section>
<section aria-labelledby="exposure-heading">
<h2 id="exposure-heading">Namespace exposure matrix</h2>
<div class="table-scroll"><table>
<caption>Snapshot exposure and modeled isolation; enforcement is unverified</caption>
<thead><tr><th scope="col">Namespace</th><th scope="col">Ingresses / services</th>
<th scope="col">OIDC metadata</th><th scope="col">Isolation plane</th>
<th scope="col">Barrier / simulation</th></tr></thead>
<tbody id="exposure-matrix"></tbody></table></div></section>
<section aria-labelledby="mermaid-heading">
<h2 id="mermaid-heading">Mermaid preview</h2>
<p>Mermaid source for observed cluster.example.org ingress, namespace and hardware links.</p>
<pre><code id="mermaid-diagram-code"></code></pre>
</section>
</main>
<script id="network-data" type="application/json">''' + payload + r'''</script>
<script>
"use strict";
const data = JSON.parse(document.getElementById("network-data").textContent);
function row(target, values) {
    const tr = document.createElement("tr");
    for (const value of values) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
    }
    target.appendChild(tr);
}
document.getElementById("network-summary").textContent =
    data.routes.ingress_count + " ingress routes across " +
    data.exposure.namespace_count + " namespaces. Source: " + data.routes.source;
const routes = document.getElementById("network-routes-list");
for (const route of data.routes.routes) {
    const lineage = [];
    for (const service of route.services) {
        lineage.push("Service: " + service.name);
        if (!service.pods.length) lineage.push("  Pods: not observed");
        for (const pod of service.pods) {
            const hardware = pod.hardware_nodes.map(node => node.name).join(", ");
            lineage.push("  Pod: " + pod.name + " -> " + (hardware || "hardware not observed"));
        }
    }
    for (const name of route.missing_services) lineage.push("Missing service: " + name);
    row(routes, [route.namespace + " / " + route.ingress.name,
        route.hosts.join("\n") || "No host observed",
        lineage.join("\n") || "No service observed", route.oidc_posture.status]);
}
if (!data.routes.routes.length) row(routes, ["No ingress routes observed."]);
const matrix = document.getElementById("exposure-matrix");
for (const item of data.exposure.namespaces) {
    row(matrix, [item.namespace, item.ingress_count + " / " + item.service_count,
        item.oidc_posture.status, item.chaos_isolation_plane || "unmapped",
        item.cross_plane_barrier_status + " / " + item.chaos_simulation_status]);
}
if (!data.exposure.namespaces.length) row(matrix, ["No namespace exposure observed."]);
document.getElementById("mermaid-diagram-code").textContent = data.mermaid;
</script>
</body>
</html>'''


def _trace_routes(snapshot):
    posture = oidc_rbac_verifier.audit_cluster_ingress_oidc_posture(snapshot)
    if posture["status"] == "invalid_catalog":
        raise ValueError("Invalid cluster ingress catalog")
    nodes = {node["id"]: node for node in snapshot["nodes"]}
    by_identity = {}
    outgoing, owners = defaultdict(set), defaultdict(set)
    for node in nodes.values():
        key = (_kind(node), _namespace(node), _name(node))
        if key in by_identity:
            raise ValueError("Duplicate cluster resource identity")
        by_identity[key] = node["id"]
    for edge in snapshot.get("edges", []):
        outgoing[edge["source"], edge["relation"]].add(edge["target"])
        if edge["relation"] == "owns_workload":
            owners[edge["target"]].add(edge["source"])
    for node in nodes.values():
        for owner in _resource(node).get("metadata", {}).get("ownerReferences", []):
            owner_id = by_identity.get((owner.get("kind"), _namespace(node), owner.get("name")))
            if owner_id:
                owners[node["id"]].add(owner_id)

    def linked(node_id, relation, kinds, namespace=None):
        return {target for target in outgoing[node_id, relation]
                if _kind(nodes[target]) in kinds
                and (namespace is None or _namespace(nodes[target]) == namespace)}

    def workload_refs(node_id, namespace):
        found, pending, seen = set(), [node_id], set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            for owner_id in owners[current]:
                owner = nodes[owner_id]
                if _namespace(owner) == namespace and _kind(owner) in WORKLOAD_KINDS:
                    found.add(owner_id)
                    pending.append(owner_id)
        return [_ref(nodes[key]) for key in sorted(found)]

    routes = []
    ingresses = [node for node in snapshot["nodes"] if _kind(node) == "Ingress"]
    if len(ingresses) != posture["ingress_count"]:
        raise ValueError("Invalid cluster ingress catalog")
    for index, ingress in enumerate(ingresses):
        namespace = _namespace(ingress)
        spec = _resource(ingress).get("spec", {})
        hosts, backends = [], []
        for rule in spec.get("rules", []):
            if isinstance(rule.get("host"), str):
                hosts.append(rule["host"])
            backends.extend(path.get("backend", {})
                            for path in rule.get("http", {}).get("paths", []))
        if "defaultBackend" in spec:
            backends.append(spec["defaultBackend"])
        service_ids = linked(ingress["id"], "routes_to", {"Service"}, namespace)
        missing = set()
        for backend in backends:
            name = backend.get("service", {}).get("name") or backend.get("serviceName")
            if not name:
                continue
            service_id = by_identity.get(("Service", namespace, name))
            if service_id:
                service_ids.add(service_id)
            else:
                missing.add(name)
        services = []
        for service_id in sorted(service_ids):
            service = nodes[service_id]
            pod_ids = linked(service_id, "routes_to", {"Pod"}, namespace)
            workload_ids = linked(service_id, "routes_to", WORKLOAD_KINDS, namespace)
            selector = _resource(service).get("spec", {}).get("selector", {})
            if selector:
                for pod_id, pod in nodes.items():
                    if _kind(pod) == "Pod" and _namespace(pod) == namespace:
                        labels = _resource(pod).get("metadata", {}).get("labels", {})
                        if all(labels.get(key) == value for key, value in selector.items()):
                            pod_ids.add(pod_id)
            # Follow workload ownership only in the forward direction to pods.
            pending, seen = list(workload_ids), set()
            while pending:
                current = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                pod_ids.update(linked(current, "owns_workload", {"Pod"}, namespace))
                pending.extend(linked(current, "owns_workload", WORKLOAD_KINDS, namespace) - seen)
                for child_id, parent_ids in owners.items():
                    if current in parent_ids and _namespace(nodes[child_id]) == namespace:
                        if _kind(nodes[child_id]) == "Pod":
                            pod_ids.add(child_id)
                        elif _kind(nodes[child_id]) in WORKLOAD_KINDS:
                            pending.append(child_id)
            pods = []
            for pod_id in sorted(pod_ids):
                pod = nodes[pod_id]
                hardware = linked(pod_id, "runs_on_hardware", {"Node"})
                assigned = _resource(pod).get("spec", {}).get("nodeName")
                hardware_id = by_identity.get(("Node", "default", assigned))
                if hardware_id:
                    hardware.add(hardware_id)
                workloads = workload_refs(pod_id, namespace)
                workload_ids.update(item["node_id"] for item in workloads)
                pods.append({**_ref(pod), "phase": _resource(pod).get("status", {}).get("phase"),
                             "workloads": workloads, "assigned_node_name": assigned,
                             "hardware_nodes": [_ref(nodes[key]) for key in sorted(hardware)],
                             "hardware_observed": bool(hardware)})
            services.append({**_ref(service), "pods": pods,
                             "workloads": [_ref(nodes[key]) for key in sorted(workload_ids)],
                             "pods_observed": bool(pods)})
        namespace_id = by_identity.get(("Namespace", "default", namespace))
        routes.append({"ingress": _ref(ingress), "namespace": namespace,
                       "namespace_node_id": namespace_id, "hosts": sorted(set(hosts)),
                       "services": services, "missing_services": sorted(missing),
                       "oidc_posture": posture["ingresses"][index]})
    routes.sort(key=lambda route: route["ingress"]["node_id"])
    return sanitize({
        "source": snapshot.get("source", "provided_catalog"),
        "provenance": {"mode": "offline_snapshot", "live_collection": False,
                       "collected_at": snapshot.get("collected_at")},
        "notice": "Snapshot links describe observed topology, not verified connectivity. "
                  "Missing OIDC configuration is unknown evidence; runtime enforcement is unverified.",
        "ingress_count": len(routes), "routes": routes, "oidc_posture": posture,
    })


def _network_report(catalog):
    return {"routes": trace_ingress_to_hardware_routes(catalog),
            "exposure": build_namespace_exposure_matrix(catalog),
            "anomalies": detect_routing_anomalies(catalog),
            "mermaid": export_network_mermaid_diagram(catalog)}


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid network inspector arguments")


def _build_network_handler(catalog):
    """Serve offline evidence without logging untrusted request contents."""
    # Build all representations before starting the server to validate the snapshot.
    responses = {
        "/": (render_network_inspector_html(catalog), "text/html"),
        "/api/v1/network-inspector": (
            json.dumps(_network_report(catalog), indent=2, allow_nan=False),
            "application/json"),
        "/network/topology.mmd": (export_network_mermaid_diagram(catalog), "text/plain"),
    }
    responses["/network"] = responses["/"]

    class NetworkRequestHandler(BaseHTTPRequestHandler):
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
                if url.query:
                    self._send(400, '{"error":"Invalid network request"}', "application/json")
                    return
                response = responses.get(url.path)
            except ValueError:
                self._send(400, '{"error":"Invalid network request"}', "application/json")
                return
            if response is None:
                self._send(404, '{"error":"Not found"}', "application/json")
                return
            self._send(200, *response)

    return NetworkRequestHandler


def main(argv=None) -> int:
    """Export sanitized network evidence or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="network_topology_inspector",
                                 description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--mermaid", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8092)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    try:
        catalog = _load_catalog(args.catalog)
        if args.serve:
            handler = _build_network_handler(catalog)
            with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
                print(f"Network inspector: http://127.0.0.1:{args.port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.mermaid:
            print(export_network_mermaid_diagram(catalog), end="")
        else:
            print(json.dumps(_network_report(catalog), indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete network request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
