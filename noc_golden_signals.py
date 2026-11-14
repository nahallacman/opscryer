# SPDX-License-Identifier: Apache-2.0
"""Example NOC queries and a deterministic, offline kiosk button replay."""

import json
from pathlib import Path

from cluster_diff_engine import summarize_live_cluster_health
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")


def evaluate_four_golden_signals(health, routing_resources) -> dict:
    """Describe snapshot proxies without inventing HTTP metrics or capacity.

    Saturation is the fraction of nodes unavailable by readiness, not measured
    resource utilization. Failed/pending pod counts are workload indicators,
    not HTTP errors. Routing inventory establishes surface, not traffic volume.
    """
    nodes, pods = health["node_counts"], health["pod_counts"]
    return {
        "latency": {
            "available": False, "value": None, "unit": "seconds",
            "notice": "Offline snapshot: request latency is not measured; live duration metrics are required.",
        },
        "traffic": {
            "ingress_count": sum(r["kind"] == "Ingress" for r in routing_resources),
            "service_count": sum(r["kind"] == "Service" for r in routing_resources),
            "ingress_host_count": len(health["ingress_hosts"]),
            "request_rate": None,
            "notice": "Snapshot routing surface only; request rate and bandwidth are not measured.",
        },
        "errors": {
            "failed_pods": pods["failed"], "pending_pods": pods["pending"],
            "affected_pods": pods["failed"] + pods["pending"],
            "notice": "Snapshot workload indicators; pending pods are not necessarily failures or HTTP errors.",
        },
        "saturation": {
            "total_nodes": nodes["total"], "ready_nodes": nodes["ready"],
            "not_ready_nodes": nodes["not_ready"],
            "unready_node_ratio": (nodes["not_ready"] / nodes["total"]
                                   if nodes["total"] else None),
            "notice": "Snapshot node readiness proxy; CPU, memory and queue saturation are not inferred.",
        },
    }


def correlate_noc_signals_with_live_catalog(catalog=None) -> dict:
    """Return deterministic, sanitized observations from a graph dict or path.

    None reads the bundled sanitized snapshot, without network collection or
    synthetic fallback. Invalid input raises a fixed ValueError without paths
    or raw catalog diagnostics. Input and returned containers are independent.
    """
    try:
        if catalog is None:
            catalog = DEFAULT_CATALOG_PATH
        if isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
        health = summarize_live_cluster_health(catalog)
        routes = []
        pending = {}
        for node in sorted(catalog["nodes"], key=lambda n: n["id"]):
            resource = node.get("resource", {})
            kind = node.get("resource_kind", resource.get("kind"))
            metadata = resource.get("metadata", {})
            namespace = metadata.get("namespace", node.get("namespace", "default"))
            if kind in {"Ingress", "Service"}:
                routes.append({"node_id": node["id"], "kind": kind,
                               "namespace": namespace,
                               "name": metadata.get("name", node.get("label", node["id"]))})
            elif kind == "Pod" and resource.get("status", {}).get("phase") == "Pending":
                group = pending.setdefault(namespace, {"count": 0, "pod_ids": []})
                group["count"] += 1
                group["pod_ids"].append(node["id"])
        health["pending_pods_by_namespace"] = dict(sorted(pending.items()))
        health["routing_resources"] = routes
        result = sanitize({
            "schema_version": 1, "source": health["source"],
            "example": health["example"], "mode": "offline_snapshot",
            "signals": evaluate_four_golden_signals(health, routes),
            "observations": health,
        })
        json.dumps(result, allow_nan=False)
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ValueError("Unable to load valid cluster catalog") from None


def build_noc_golden_signals_catalog():
    """Return a fresh JSON-compatible catalog for four example cluster nodes.

    HTTP exporters must expose request counters and duration sum/count in
    seconds, node exporters memory gauges in bytes, and DCGM framebuffer
    gauges in MiB. Instances use the conventional exporter ports below.
    Each query aggregates to one unlabeled sample for its selected node,
    allowing ``or on() vector(0)`` to fill missing data independently per node.
    Denominator floors also prevent 0/0 on idle or zero-capacity exporters.
    Missing-data zeros are presentation defaults, not evidence of node health.
    No live telemetry is fetched by this function.
    """
    signals = [
        {"id": "latency", "title": "Mean HTTP latency", "unit": "seconds"},
        {"id": "traffic", "title": "HTTP request rate", "unit": "requests/second"},
        {"id": "errors", "title": "HTTP 5xx fraction", "unit": "ratio"},
        {"id": "saturation", "title": "Memory utilization", "unit": "ratio"},
        {"id": "gpu_vram", "title": "GPU framebuffer utilization", "unit": "ratio"},
    ]
    nodes = []
    for subnet in (3, 4):
        for host in (11, 12):
            address = f"10.20.{subnet}.{host}"
            http = f'instance="{address}:8000"'
            memory = f'instance="{address}:9100"'
            gpu = f'instance="{address}:9400"'
            requests = f'sum(rate(http_requests_total{{{http}}}[5m]))'
            durations = f'sum(rate(http_request_duration_seconds_sum{{{http}}}[5m]))'
            observations = f'sum(rate(http_request_duration_seconds_count{{{http}}}[5m]))'
            errors = f'sum(rate(http_requests_total{{{http},status=~"5.."}}[5m]))'
            total = f'sum(node_memory_MemTotal_bytes{{{memory}}})'
            available = f'sum(node_memory_MemAvailable_bytes{{{memory}}})'
            used = f'sum(DCGM_FI_DEV_FB_USED{{{gpu}}})'
            free = f'sum(DCGM_FI_DEV_FB_FREE{{{gpu}}})'
            expressions = {
                "latency": f"{durations} / clamp_min({observations}, 1e-9)",
                "traffic": requests,
                "errors": f"{errors} / clamp_min({requests}, 1e-9)",
                "saturation": f"({total} - {available}) / clamp_min({total}, 1)",
                "gpu_vram": f"{used} / clamp_min(({used} + {free}), 1)",
            }
            nodes.append({
                "id": f"cluster-{subnet}-node-{host}", "address": address,
                "cluster": f"10.20.{subnet}.0/24",
                "queries": {key: f"({value}) or on() vector(0)"
                            for key, value in expressions.items()},
            })

    all_nodes = [node["id"] for node in nodes]
    all_signals = [signal["id"] for signal in signals]
    views = [{"id": 1, "title": "Cluster overview", "node_ids": all_nodes[:],
              "signal_ids": all_signals[:]}]
    for signal in signals:
        views.append({"id": len(views) + 1, "title": signal["title"],
                      "node_ids": all_nodes[:], "signal_ids": [signal["id"]]})
    for subnet in (3, 4):
        views.append({"id": len(views) + 1, "title": f"Cluster 10.20.{subnet}.0/24",
                      "node_ids": [n["id"] for n in nodes
                                   if n["cluster"] == f"10.20.{subnet}.0/24"],
                      "signal_ids": all_signals[:]})
    views.append({"id": 9, "title": "Compute capacity", "node_ids": all_nodes[:],
                  "signal_ids": ["saturation", "gpu_vram"]})
    return {"schema_version": 1, "example": True, "signals": signals,
            "nodes": nodes, "views": views, "missing_data_value": 0,
            "missing_data_note": "Zero is a display fallback, not a health check."}


def simulate_kiosk_view_cycler(total_views=9, button_presses=50):
    """Replay presses starting at view 1; history includes the initial view.

    Positive integer view counts and nonnegative integer press counts are
    required (booleans are rejected). Every press executes one modulo step;
    there are no locks, I/O, timers, retries or waits. Runtime and history size
    are O(button_presses). ``wrap_count`` counts every N -> 1 transition,
    including 1 -> 1 when only one view exists.
    """
    if type(total_views) is not int or total_views < 1:
        raise ValueError("total_views must be a positive integer")
    if type(button_presses) is not int or button_presses < 0:
        raise ValueError("button_presses must be a nonnegative integer")
    current_view, wrap_count = 1, 0
    history = [current_view]
    for _ in range(button_presses):
        wrap_count += int(current_view == total_views)
        current_view = current_view % total_views + 1
        history.append(current_view)
    return {"total_views": total_views, "button_presses": button_presses,
            "history": history, "current_view": current_view,
            "wrap_count": wrap_count}
