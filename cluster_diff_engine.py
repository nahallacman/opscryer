# SPDX-License-Identifier: Apache-2.0
"""Deterministic health facts and state changes from sanitized cluster catalogs."""

import argparse
import json
import math
from pathlib import Path

from cluster_harvester import build_live_cluster_spatial_catalog
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")


def _catalog(catalog):
    if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
        raise ValueError("catalog must contain a nodes array")
    # Validate identities before sanitization so redaction cannot merge nodes.
    identities = set()
    for node in catalog["nodes"]:
        if (not isinstance(node, dict) or not isinstance(node.get("id"), str)
                or not node["id"] or node["id"] in identities):
            raise ValueError("catalog requires unique nonempty node IDs")
        identities.add(node["id"])
    return catalog


def _resource(node):
    return node.get("resource", {})


def _kind(node):
    return node.get("resource_kind", _resource(node).get("kind"))


def _status(node):
    resource = _resource(node)
    status = resource.get("status", {})
    if _kind(node) == "Node":
        ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in status.get("conditions", []))
        return "Ready" if ready else "NotReady"
    if _kind(node) == "Pod":
        return status.get("phase", "Unknown")
    if _kind(node) == "Deployment":
        desired = resource.get("spec", {}).get("replicas", 1)
        if desired == 0:
            return "scaled_zero"
        return "ready" if status.get("readyReplicas", 0) >= desired else "degraded"
    return resource.get("status", node.get("status"))


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def summarize_live_cluster_health(catalog=None):
    """Return fresh health facts without collecting live data or mutating input.

    Ready/not-ready lists contain node names; failed pods use graph IDs.
    Hotspots contain node_id, name and available finite CPU/RAM percentages.
    Each ingress host maps to a sorted list of {service, namespace} targets,
    retaining different backends across paths and ingress resources. Deployment
    categories are exclusive; omitted desired replicas default to Kubernetes' 1.
    An absent default file uses the offline builder; unreadable/invalid files fail.
    """
    if catalog is None:
        if DEFAULT_CATALOG_PATH.is_file():
            catalog = json.loads(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        else:
            catalog = build_live_cluster_spatial_catalog()
    catalog = _catalog(catalog)
    result = {
        "source": catalog.get("source", "provided_catalog"),
        "example": catalog.get("example", False),
        "node_counts": {"total": 0, "ready": 0, "not_ready": 0},
        "ready_nodes": [], "not_ready_nodes": [],
        "pod_counts": dict.fromkeys(
            ("total", "running", "succeeded", "failed", "pending", "other"), 0),
        "failed_pods_by_namespace": {},
        "deployment_counts": dict.fromkeys(("total", "ready", "scaled_zero", "degraded"), 0),
        "node_hotspots": [], "ingress_hosts": {},
    }
    for node in sorted(catalog["nodes"], key=lambda n: n["id"]):
        resource = _resource(node)
        metadata = resource.get("metadata", {})
        namespace = metadata.get("namespace", node.get("namespace", "default"))
        kind = _kind(node)
        if kind == "Node":
            category = "ready" if _status(node) == "Ready" else "not_ready"
            result["node_counts"]["total"] += 1
            result["node_counts"][category] += 1
            name = metadata.get("name", node.get("label", node["id"]))
            result[category + "_nodes"].append(name)
            metrics = {k: v for k, v in node.get("metrics", {}).items()
                       if k in {"cpu_percent", "ram_percent"} and _number(v)}
            if metrics.get("cpu_percent", -1) >= 80 or metrics.get("ram_percent", -1) >= 75:
                result["node_hotspots"].append({"node_id": node["id"], "name": name, **metrics})
        elif kind == "Pod":
            category = {"Running": "running", "Succeeded": "succeeded",
                        "Failed": "failed", "Pending": "pending"}.get(_status(node), "other")
            result["pod_counts"]["total"] += 1
            result["pod_counts"][category] += 1
            if category == "failed":
                group = result["failed_pods_by_namespace"].setdefault(
                    namespace, {"count": 0, "pod_ids": []})
                group["count"] += 1
                group["pod_ids"].append(node["id"])
        elif kind == "Deployment":
            result["deployment_counts"]["total"] += 1
            result["deployment_counts"][_status(node)] += 1
        elif kind == "Ingress":
            spec = resource.get("spec", {})
            for rule in spec.get("rules", []):
                host = rule.get("host", "")
                if not isinstance(host, str) or not host.lower().endswith(".cluster.example.org"):
                    continue
                paths = rule.get("http", {}).get("paths", [])
                backends = [p.get("backend", {}) for p in paths]
                if not backends:
                    backends = [spec.get("defaultBackend", {})]
                for backend in backends:
                    service = backend.get("service", {}).get("name", backend.get("serviceName"))
                    if not service:
                        continue
                    target = {"service": service, "namespace": namespace}
                    targets = result["ingress_hosts"].setdefault(host.lower(), [])
                    if target not in targets:
                        targets.append(target)
    for key in ("ready_nodes", "not_ready_nodes"):
        result[key].sort()
    result["ingress_hosts"] = {
        host: sorted(targets, key=lambda t: (t["namespace"], t["service"]))
        for host, targets in sorted(result["ingress_hosts"].items())}
    return sanitize(result)


def compute_catalog_diff(previous_catalog, current_catalog):
    """Compare all graph IDs, returning sorted additions/removals and changes.

    status_transitions is a list of {node_id, previous_status, current_status}.
    Node readiness, pod phase and deployment health use the summary semantics;
    other resources compare their full status. metrics_deltas maps shared IDs
    to changed shared finite numeric metrics as {previous, current, delta}.
    Missing metrics, booleans and nonnumeric readings do not imply zero usage.
    """
    previous = {n["id"]: n for n in _catalog(previous_catalog)["nodes"]}
    current = {n["id"]: n for n in _catalog(current_catalog)["nodes"]}
    result = {"added_node_ids": sorted(current.keys() - previous.keys()),
              "removed_node_ids": sorted(previous.keys() - current.keys()),
              "status_transitions": [], "metrics_deltas": {}}
    for node_id in sorted(previous.keys() & current.keys()):
        before, after = previous[node_id], current[node_id]
        old_status, new_status = _status(before), _status(after)
        if old_status != new_status:
            result["status_transitions"].append({"node_id": node_id,
                "previous_status": old_status, "current_status": new_status})
        old_metrics, new_metrics = before.get("metrics", {}), after.get("metrics", {})
        changes = {}
        for metric in sorted(old_metrics.keys() & new_metrics.keys()):
            old, new = old_metrics[metric], new_metrics[metric]
            if _number(old) and _number(new) and old != new and _number(new - old):
                changes[metric] = {"previous": old, "current": new, "delta": new - old}
        if changes:
            result["metrics_deltas"][node_id] = changes
    return sanitize(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true", help="Print the full health summary as JSON")
    args = parser.parse_args(argv)
    try:
        catalog = (json.loads(args.catalog.read_text(encoding="utf-8"))
                   if args.catalog is not None else None)
        summary = summarize_live_cluster_health(catalog)
        encoded = json.dumps(summary, indent=2, allow_nan=False)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        parser.error("unable to load a valid cluster catalog")
    if args.json:
        print(encoded)
    else:
        print(f"Cluster health ({summary['source']}, example={summary['example']})")
        for key in ("node_counts", "pod_counts", "deployment_counts"):
            print(f"{key}: " + ", ".join(f"{k}={v}" for k, v in summary[key].items()))
        print("NotReady nodes: " + (", ".join(summary["not_ready_nodes"]) or "none"))
        for hotspot in summary["node_hotspots"]:
            print("Hotspot: " + json.dumps(hotspot, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
