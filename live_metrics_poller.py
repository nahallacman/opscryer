# SPDX-License-Identifier: Apache-2.0
"""Sanitized live metrics and the Live Cluster Metrics & Telemetry Stream portal."""

from collections import Counter, defaultdict
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import ipaddress
import json
import os
import re
import ssl
import threading
import time
from urllib.error import URLError
from urllib.parse import parse_qs, urlencode, urlsplit
import urllib.request

import cluster_diff_engine
import cluster_harvester
from live_currencies import build_enriched_live_currencies
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


_METRICS_CACHE = {}
_METRICS_CACHE_LOCK = threading.Lock()


def clear_live_metrics_cache() -> None:
    """Discard cached responses without collecting telemetry."""
    with _METRICS_CACHE_LOCK:
        _METRICS_CACHE.clear()


def poll_live_cluster_metrics(allow_kubectl: bool = False, ttl_seconds: int = 10,
                              catalog: dict | None = None) -> dict:
    """Build an independent metrics response; live collection is explicitly opt-in."""
    if (type(allow_kubectl) is not bool or type(ttl_seconds) is not int
            or not 0 <= ttl_seconds <= 3600):
        raise ValueError("Invalid live metrics parameters")
    key = (allow_kubectl, ttl_seconds)
    with _METRICS_CACHE_LOCK:
        cached = _METRICS_CACHE.get(key) if catalog is None else None
    if cached and time.monotonic() - cached[0] < ttl_seconds:
        return deepcopy(cached[1])
    mode = "SNAPSHOT_CACHE"
    active = catalog
    if active is None and allow_kubectl:
        try:
            snapshot = cluster_harvester.harvest_live_k8s_cluster(timeout=6)
            candidate = cluster_harvester.build_live_cluster_spatial_catalog(snapshot)
            if candidate.get("source") == "live_kubectl":
                active = candidate
                mode = "LIVE_KUBECTL"
            else:
                mode = "SNAPSHOT_FALLBACK"
        except (OSError, ValueError, TypeError, RuntimeError):
            mode = "SNAPSHOT_FALLBACK"
    if active is None:
        path = cluster_diff_engine.DEFAULT_CATALOG_PATH
        active = (json.loads(path.read_text(encoding="utf-8")) if path.is_file()
                  else cluster_harvester.build_live_cluster_spatial_catalog())
    health = cluster_diff_engine.summarize_live_cluster_health(active)
    active = sanitize(active)
    namespaces = defaultdict(Counter)
    pods_by_node = defaultdict(Counter)
    nodes = []
    for item in active["nodes"]:
        resource = item.get("resource", {})
        kind = item.get("resource_kind", resource.get("kind"))
        metadata = resource.get("metadata", {})
        status = resource.get("status", {})
        if kind == "Pod":
            phase = status.get("phase", "Unknown").lower()
            namespace = metadata.get("namespace", item.get("namespace", "default"))
            namespaces[namespace][phase] += 1
            pods_by_node[resource.get("spec", {}).get("nodeName")][phase] += 1
        elif kind == "Node":
            name = metadata.get("name") or item.get("label") or item["id"]
            metrics = item.get("metrics", {})
            nodes.append({
                "node_id": item["id"], "name": name,
                "ready": any(c.get("type") == "Ready" and c.get("status") == "True"
                             for c in status.get("conditions", [])),
                **{key: metrics.get(key) for key in
                   ("cpu_percent", "ram_percent", "cpu_used", "ram_used")},
            })
    for node in nodes:
        counts = pods_by_node[node["name"]]
        node.update(running_pod_count=counts["running"], failed_pod_count=counts["failed"])
    pressure = [{"namespace": name, "running_pods": counts["running"],
                 "failed_pods": counts["failed"], "pending_pods": counts["pending"]}
                for name, counts in namespaces.items()]
    pressure.sort(key=lambda row: (-row["failed_pods"], -row["running_pods"], row["namespace"]))
    live = mode == "LIVE_KUBECTL"
    result = sanitize({
        "schema_version": "1.0-live-metrics-stream", "telemetry_mode": mode,
        "live_kubectl_active": live, "ttl_seconds": ttl_seconds,
        "freshness_label": ("LIVE (real-time kubectl poll)" if live
                            else "CACHED SNAPSHOT (offline-safe)"),
        "health": health, "rts_currencies": build_enriched_live_currencies(active),
        "node_metrics": sorted(nodes, key=lambda node: node["name"]),
        "namespace_pressure": pressure[:8],
    })
    if catalog is None:
        with _METRICS_CACHE_LOCK:
            _METRICS_CACHE[key] = (time.monotonic(), deepcopy(result))
    return result


def render_live_metrics_markdown(allow_kubectl: bool = False,
                                catalog: dict | None = None,
                                ttl_seconds: int = 10) -> str:
    """Render a sanitized report, escaping telemetry used in Markdown cells."""
    metrics = sanitize(poll_live_cluster_metrics(
        allow_kubectl=allow_kubectl, catalog=catalog, ttl_seconds=ttl_seconds))

    def text(value):
        value = "Unavailable" if value is None else str(value)
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1",
                      escape(" ".join(value.split()), quote=True))

    lines = ["# Live Cluster Metrics & Telemetry Stream", "",
             "Telemetry mode: **" + metrics["telemetry_mode"] + "**", "",
             text(metrics["freshness_label"]), ""]

    def table(title, headers, rows):
        lines.extend(["## " + title, "", "| " + " | ".join(headers) + " |",
                      "| " + " | ".join("---" for _ in headers) + " |"])
        lines.extend("| " + " | ".join(text(cell) for cell in row) + " |" for row in rows)
        lines.append("")

    table("Per-node telemetry",
          ["Node", "Ready", "CPU (%)", "RAM (%)", "CPU used", "RAM used", "Running pods", "Failed pods"],
          ([n.get(key) for key in ("name", "ready", "cpu_percent", "ram_percent", "cpu_used",
                                  "ram_used", "running_pod_count", "failed_pod_count")]
           for n in metrics["node_metrics"]))
    table("Live RTS currencies", ["Currency", "Value", "Available"],
          ([c.get("label"), c.get("display_value"), c.get("available", False)]
           for c in metrics["rts_currencies"]))
    table("Namespace workload pressure", ["Namespace", "Running pods", "Failed pods", "Pending pods"],
          ([n.get(key) for key in ("namespace", "running_pods", "failed_pods", "pending_pods")]
           for n in metrics["namespace_pressure"]))
    return "\n".join(lines)


def render_live_metrics_html() -> str:
    """Return a standalone portal; API values are inserted only as DOM text."""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpsCryer — Live Cluster Metrics &amp; Telemetry Stream</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#080f1b;color:#e2e8f0}
body{max-width:1200px;margin:auto;padding:24px}nav,.controls{display:flex;flex-wrap:wrap;gap:16px;align-items:center}
a{color:#67e8f9}h1{color:#a5f3fc}h2{margin-top:32px}button{background:#155e75;color:white;border:1px solid #22d3ee;padding:12px;border-radius:6px;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}.badge{display:inline-block;background:#164e63;padding:8px;border-radius:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}
.card{background:#111e30;border:1px solid #334155;border-radius:8px;padding:16px;overflow-wrap:anywhere}
.value{font-size:1.6rem;color:#86efac}progress{display:block;width:100%;height:18px;accent-color:#22d3ee;margin:8px 0 16px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:12px;border-bottom:1px solid #334155}
.table-scroll{overflow-x:auto}#status{min-height:1.5em;color:#cbd5e1}input{accent-color:#22d3ee}
</style>
</head>
<body>
<nav aria-label="Portals">
<a href="/">Cluster</a><a href="/hub">Hub</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a><a href="/games">Games</a>
<a href="/kb">Knowledge Base</a><a href="/storage">Storage</a><a href="/secops">SecOps</a>
<a href="/metrics-live" aria-current="page">Live Metrics</a>
</nav>
<h1>Live Cluster Metrics &amp; Telemetry Stream</h1>
<p id="mode" class="badge">Loading telemetry…</p>
<div class="controls">
<button id="poll" type="button">🔴 Poll Live Cluster Now (live=1)</button>
<label><input id="auto-poll" type="checkbox"> ⏱️ Auto-Poll Every 10s</label>
</div>
<p id="status" role="status" aria-live="polite">Loading cached snapshot…</p>
<main>
<section aria-labelledby="nodes-heading"><h2 id="nodes-heading">Per-node CPU / RAM / Pod telemetry</h2><div id="nodes" class="grid"></div></section>
<section aria-labelledby="currencies-heading"><h2 id="currencies-heading">7 Live RTS Currencies</h2><div id="currencies" class="grid"></div></section>
<section aria-labelledby="pressure-heading"><h2 id="pressure-heading">Namespace workload pressure</h2>
<div class="table-scroll"><table><thead><tr><th scope="col">Namespace</th><th scope="col">Running pods</th><th scope="col">Failed pods</th><th scope="col">Pending pods</th></tr></thead><tbody id="pressure"></tbody></table></div>
</section>
</main>
<script>
'use strict';
const byId = id => document.getElementById(id);
const known = value => value === null || value === undefined ? 'Unavailable' : String(value);
function add(parent, tag, value, className) {
  const element = document.createElement(tag);
  if (value !== undefined) element.textContent = known(value);
  if (className) element.className = className;
  parent.appendChild(element);
  return element;
}
function usage(card, label, value) {
  const valid = typeof value === 'number' && Number.isFinite(value);
  add(card, 'p', label + ': ' + (valid ? value + '%' : 'Unavailable'));
  const bar = add(card, 'progress');
  bar.max = 100;
  bar.value = valid ? Math.min(100, Math.max(0, value)) : 0;
  bar.setAttribute('aria-label', label + ': ' + (valid ? value + '%' : 'Unavailable'));
}
function render(data) {
  byId('mode').textContent = known(data.telemetry_mode);
  const nodes = byId('nodes'); nodes.replaceChildren();
  for (const node of data.node_metrics) {
    const card = add(nodes, 'article', undefined, 'card');
    add(card, 'h3', node.name);
    add(card, 'p', node.ready ? 'Ready' : 'NotReady');
    usage(card, 'CPU', node.cpu_percent); usage(card, 'RAM', node.ram_percent);
    add(card, 'p', 'CPU used: ' + known(node.cpu_used) + ' / RAM used: ' + known(node.ram_used));
    add(card, 'p', 'Pods: ' + known(node.running_pod_count) + ' running / ' + known(node.failed_pod_count) + ' failed');
  }
  if (!data.node_metrics.length) add(nodes, 'p', 'No node telemetry available.');
  const currencies = byId('currencies'); currencies.replaceChildren();
  for (const currency of data.rts_currencies) {
    const card = add(currencies, 'article', undefined, 'card');
    add(card, 'h3', currency.label);
    add(card, 'p', currency.display_value, 'value');
    add(card, 'p', currency.available === false ? 'Unavailable' : 'Available');
  }
  const pressure = byId('pressure'); pressure.replaceChildren();
  for (const namespace of data.namespace_pressure) {
    const row = add(pressure, 'tr');
    for (const key of ['namespace', 'running_pods', 'failed_pods', 'pending_pods']) add(row, 'td', namespace[key]);
  }
  if (!data.namespace_pressure.length) {
    const cell = add(add(pressure, 'tr'), 'td', 'No namespace workload telemetry available.'); cell.colSpan = 4;
  }
  byId('status').textContent = known(data.freshness_label) + ' · Updated ' + new Date().toLocaleTimeString();
}
let inFlight = false;
let timer = null;
async function refresh(live = false) {
  if (inFlight) return;
  inFlight = true; byId('poll').disabled = true;
  byId('status').textContent = live ? 'Polling live cluster…' : 'Loading cached snapshot…';
  try {
    const response = await fetch(live ? '/api/v1/live-metrics?live=1' : '/api/v1/live-metrics', {cache: 'no-store'});
    if (!response.ok) throw new Error('metrics unavailable');
    render(await response.json());
  } catch (_) {
    byId('status').textContent = 'Telemetry refresh failed. Previously displayed metrics may be stale. Try polling again.';
  } finally {
    inFlight = false; byId('poll').disabled = false;
  }
}
byId('poll').addEventListener('click', () => refresh(true));
byId('auto-poll').addEventListener('change', event => {
  if (timer !== null) clearInterval(timer);
  timer = null;
  if (event.target.checked) {
    refresh(true);
    timer = setInterval(() => refresh(true), 10000);
  }
});
window.addEventListener('pagehide', () => { if (timer !== null) clearInterval(timer); });
refresh();
</script>
</body>
</html>'''


UNAVAILABLE_NO_EXPORTER = "UNAVAILABLE_NO_EXPORTER"


class _PromNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Outbound redirects are disabled for Prometheus telemetry probes")


def _validate_prometheus_url(raw_url: str | None) -> str:
    """Validate optional Prometheus URL against non-http(s) schemes and cloud IMDS/link-local SSRF."""
    candidate = str(raw_url or "").strip().rstrip("/")
    if not candidate:
        return ""
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Prometheus URL must use http or https with an explicit host")
    if parsed.username or parsed.password:
        raise ValueError("Prometheus URL must not embed credentials")
    host = parsed.hostname.strip().lower()
    if host in {"metadata.google.internal", "metadata", "169.254.169.254", "0.0.0.0", "::"}:
        raise ValueError("Prometheus URL targets a blocked metadata or unspecified address")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            raise ValueError("Prometheus URL targets a blocked link-local or multicast IP")
    except ValueError as exc:
        if "blocked" in str(exc):
            raise
    return candidate


def _query_prometheus_instant(
    base_url: str,
    expr: str,
    *,
    timeout_s: float = 2.0,
    headers: dict[str, str] | None = None,
) -> list[dict]:
    """Run a bounded no-redirect Prometheus instant query; return [] when unreachable."""
    safe_base = _validate_prometheus_url(base_url)
    if not safe_base:
        return []
    q_url = f"{safe_base}/api/v1/query?{urlencode({'query': expr})}"
    req = urllib.request.Request(q_url, headers={"Accept": "application/json", **(headers or {})})
    ca_file = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE") or ""
    ctx = ssl.create_default_context(cafile=ca_file) if (ca_file and os.path.isfile(ca_file)) else ssl.create_default_context()
    opener = urllib.request.build_opener(_PromNoRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            if getattr(resp, "status", 200) != 200:
                return []
            payload = json.loads(resp.read(2_097_152).decode("utf-8", errors="replace"))
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    res = (payload.get("data") or {}).get("result") if isinstance(payload.get("data"), dict) else None
    return [item for item in res if isinstance(item, dict)] if isinstance(res, list) else []


def _to_finite_float(value) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        val = float(value)
    except (TypeError, ValueError):
        return None
    return round(val, 1) if val == val and abs(val) != float("inf") else None


def poll_live_nodes_hardware_metrics(
    *,
    allow_kubectl: bool = False,
    prometheus_url: str | None = None,
    brain_catalog: dict | None = None,
    ttl_seconds: int = 10,
    catalog: dict | None = None,
    prom_query_fn=None,
) -> dict:
    """Assemble live per-node CPU/RAM/GPU hardware metrics with honest UNAVAILABLE_NO_EXPORTER states.

    Never fabricates zero or synthetic telemetry when a CPU, RAM, or GPU exporter is absent.
    """
    if (
        type(allow_kubectl) is not bool
        or type(ttl_seconds) is not int
        or not 0 <= ttl_seconds <= 3600
    ):
        raise ValueError("Invalid live node hardware metrics parameters")

    eff_prom = _validate_prometheus_url(
        prometheus_url if prometheus_url is not None else os.environ.get("OPSCRYER_PROMETHEUS_URL", "")
    )
    nodes_by_name: dict[str, dict] = {}
    source_parts: list[str] = []

    # 1. Seed nodes from Brain live catalog (physical_hardware / k8s-node-* nodes) when provided.
    if isinstance(brain_catalog, dict) and isinstance(brain_catalog.get("nodes"), list):
        brain_hits = 0
        for item in brain_catalog["nodes"]:
            if not isinstance(item, dict):
                continue
            nid = str(item.get("id") or "")
            kind = str(item.get("kind") or "")
            r_kind = str(item.get("resource_kind") or "")
            if not (kind == "physical_hardware" or r_kind == "Node" or nid.startswith("k8s-node-")):
                continue
            raw_label = str(item.get("label") or nid).strip()
            name = raw_label[len("Node:"):].strip() if raw_label.startswith("Node:") else raw_label
            if not name:
                continue
            m = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}
            entry = nodes_by_name.setdefault(
                name,
                {
                    "node_id": nid or f"k8s-node-{name}",
                    "name": name,
                    "ready": True,
                    "internal_ip": None,
                    "cpu_percent": None,
                    "ram_percent": None,
                    "gpu_percent": None,
                    "gpu_vram_used_mib": None,
                    "gpu_vram_total_mib": None,
                    "gpu_vram_percent": None,
                    "gpu_temp_c": None,
                    "cpu_used": None,
                    "ram_used": None,
                    "running_pod_count": 0,
                    "failed_pod_count": 0,
                    "telemetry_sources": [],
                },
            )
            if "ready" in m and isinstance(m["ready"], bool):
                entry["ready"] = m["ready"]
            if m.get("internal_ip"):
                entry["internal_ip"] = str(m["internal_ip"])
            cpu_val = _to_finite_float(m.get("cpu_pct") if "cpu_pct" in m else m.get("cpu_percent"))
            ram_val = _to_finite_float(m.get("mem_pct") if "mem_pct" in m else m.get("ram_percent"))
            gpu_val = _to_finite_float(m.get("gpu_util_pct") if "gpu_util_pct" in m else m.get("gpu_percent"))
            vram_u = _to_finite_float(m.get("gpu_vram_used_mib"))
            vram_t = _to_finite_float(m.get("gpu_vram_total_mib"))
            vram_p = _to_finite_float(m.get("gpu_vram_pct") if "gpu_vram_pct" in m else m.get("gpu_vram_percent"))
            temp_c = _to_finite_float(m.get("gpu_temp_c"))
            if cpu_val is not None:
                entry["cpu_percent"] = cpu_val
            if ram_val is not None:
                entry["ram_percent"] = ram_val
            if gpu_val is not None:
                entry["gpu_percent"] = gpu_val
            if vram_u is not None:
                entry["gpu_vram_used_mib"] = vram_u
            if vram_t is not None:
                entry["gpu_vram_total_mib"] = vram_t
            if vram_p is not None:
                entry["gpu_vram_percent"] = vram_p
            if temp_c is not None:
                entry["gpu_temp_c"] = temp_c
            if "brain_harvester" not in entry["telemetry_sources"]:
                entry["telemetry_sources"].append("brain_harvester")
            brain_hits += 1
        if brain_hits > 0:
            source_parts.append("brain_harvester")

    # 2. Seed/merge local K8s cluster metrics snapshot or live kubectl poll when no Brain nodes were passed (or catalog given).
    if not nodes_by_name or catalog is not None or allow_kubectl:
        base_metrics = poll_live_cluster_metrics(
            allow_kubectl=allow_kubectl,
            ttl_seconds=ttl_seconds,
            catalog=catalog,
        )
        source_parts.append(str(base_metrics.get("telemetry_mode") or "SNAPSHOT_CACHE").lower())
        for n in base_metrics.get("node_metrics") or []:
            name = str(n.get("name") or "").strip()
            if not name:
                continue
            entry = nodes_by_name.setdefault(
                name,
                {
                    "node_id": str(n.get("node_id") or f"k8s-node-{name}"),
                    "name": name,
                    "ready": bool(n.get("ready", False)),
                    "internal_ip": None,
                    "cpu_percent": None,
                    "ram_percent": None,
                    "gpu_percent": None,
                    "gpu_vram_used_mib": None,
                    "gpu_vram_total_mib": None,
                    "gpu_vram_percent": None,
                    "gpu_temp_c": None,
                    "cpu_used": None,
                    "ram_used": None,
                    "running_pod_count": 0,
                    "failed_pod_count": 0,
                    "telemetry_sources": [],
                },
            )
            entry["ready"] = bool(n.get("ready", entry["ready"]))
            if entry["cpu_percent"] is None:
                entry["cpu_percent"] = _to_finite_float(n.get("cpu_percent"))
            if entry["ram_percent"] is None:
                entry["ram_percent"] = _to_finite_float(n.get("ram_percent"))
            if n.get("cpu_used") is not None:
                entry["cpu_used"] = n["cpu_used"]
            if n.get("ram_used") is not None:
                entry["ram_used"] = n["ram_used"]
            entry["running_pod_count"] = int(n.get("running_pod_count") or 0)
            entry["failed_pod_count"] = int(n.get("failed_pod_count") or 0)
            src_tag = "live_kubectl" if base_metrics.get("live_kubectl_active") else "k8s_snapshot"
            if src_tag not in entry["telemetry_sources"]:
                entry["telemetry_sources"].append(src_tag)

    # 3. Optional live Prometheus overlay (CPU, RAM, DCGM/nvidia-smi GPU) when OPSCRYER_PROMETHEUS_URL is configured.
    if eff_prom:
        q_fn = prom_query_fn or _query_prometheus_instant
        ip_to_name = {
            str(e["internal_ip"]): name
            for name, e in nodes_by_name.items()
            if e.get("internal_ip")
        }

        def _prom_node_name(metric: dict) -> str:
            for key in ("exported_node", "node", "nodename", "Hostname", "hostname"):
                val = str(metric.get(key) or "").strip()
                if val:
                    return val
            inst = str(metric.get("instance") or "").strip().split(":", 1)[0]
            return ip_to_name.get(inst, inst or "host")

        prom_queries = (
            ("cpu_percent", '100 - (avg by (instance,node) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
            ("ram_percent", "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100"),
            ("gpu_percent", "avg by (Hostname,exported_node,node,instance) (DCGM_FI_DEV_GPU_UTIL)"),
            ("gpu_vram_used_mib", "sum by (Hostname,exported_node,node,instance) (DCGM_FI_DEV_FB_USED)"),
            ("gpu_vram_free_mib", "sum by (Hostname,exported_node,node,instance) (DCGM_FI_DEV_FB_FREE)"),
            ("gpu_temp_c", "max by (Hostname,exported_node,node,instance) (DCGM_FI_DEV_GPU_TEMP)"),
        )
        prom_hits = 0
        vram_free_by_node: dict[str, float] = {}
        for field_name, expr in prom_queries:
            for item in q_fn(eff_prom, expr):
                metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
                val = item.get("value")
                if not (isinstance(val, list) and len(val) >= 2):
                    continue
                parsed_v = _to_finite_float(val[1])
                if parsed_v is None:
                    continue
                n_name = _prom_node_name(metric)
                entry = nodes_by_name.setdefault(
                    n_name,
                    {
                        "node_id": f"k8s-node-{n_name}",
                        "name": n_name,
                        "ready": True,
                        "internal_ip": None,
                        "cpu_percent": None,
                        "ram_percent": None,
                        "gpu_percent": None,
                        "gpu_vram_used_mib": None,
                        "gpu_vram_total_mib": None,
                        "gpu_vram_percent": None,
                        "gpu_temp_c": None,
                        "cpu_used": None,
                        "ram_used": None,
                        "running_pod_count": 0,
                        "failed_pod_count": 0,
                        "telemetry_sources": [],
                    },
                )
                if field_name == "gpu_vram_free_mib":
                    vram_free_by_node[n_name] = parsed_v
                else:
                    entry[field_name] = parsed_v
                if "prometheus" not in entry["telemetry_sources"]:
                    entry["telemetry_sources"].append("prometheus")
                prom_hits += 1
        for n_name, free_mib in vram_free_by_node.items():
            entry = nodes_by_name.get(n_name)
            if entry and entry.get("gpu_vram_used_mib") is not None:
                total = round(float(entry["gpu_vram_used_mib"]) + free_mib, 1)
                entry["gpu_vram_total_mib"] = total
                if total > 0:
                    entry["gpu_vram_percent"] = round((float(entry["gpu_vram_used_mib"]) / total) * 100.0, 1)
        if prom_hits > 0:
            source_parts.append("prometheus")

    # 4. Finalize per-node explicit exporter statuses (ZERO fabricated zeros!).
    finalized: list[dict] = []
    cpu_ok = ram_ok = gpu_ok = unavailable_all = 0
    for name in sorted(nodes_by_name.keys()):
        e = nodes_by_name[name]
        if e["gpu_vram_percent"] is None and e["gpu_vram_used_mib"] is not None and e["gpu_vram_total_mib"]:
            e["gpu_vram_percent"] = round((float(e["gpu_vram_used_mib"]) / float(e["gpu_vram_total_mib"])) * 100.0, 1)

        cpu_status = "OK" if e["cpu_percent"] is not None else UNAVAILABLE_NO_EXPORTER
        ram_status = "OK" if e["ram_percent"] is not None else UNAVAILABLE_NO_EXPORTER
        gpu_status = (
            "OK"
            if any(e[k] is not None for k in ("gpu_percent", "gpu_vram_percent", "gpu_vram_used_mib", "gpu_temp_c"))
            else UNAVAILABLE_NO_EXPORTER
        )
        if cpu_status == "OK":
            cpu_ok += 1
        if ram_status == "OK":
            ram_ok += 1
        if gpu_status == "OK":
            gpu_ok += 1
        ok_cnt = sum(1 for s in (cpu_status, ram_status, gpu_status) if s == "OK")
        if ok_cnt == 3:
            exporter_status = "COMPLETE"
        elif ok_cnt > 0:
            exporter_status = "PARTIAL_EXPORTERS"
        else:
            exporter_status = UNAVAILABLE_NO_EXPORTER
            unavailable_all += 1

        e["cpu_status"] = cpu_status
        e["ram_status"] = ram_status
        e["gpu_status"] = gpu_status
        e["exporter_status"] = exporter_status
        finalized.append(e)

    return sanitize(
        {
            "schema_version": "1.0-live-nodes-hardware-metrics",
            "honest_zero_fabrication": True,
            "telemetry_sources": list(dict.fromkeys(source_parts)) or ["offline_empty"],
            "prometheus_configured": bool(eff_prom),
            "exporter_summary": {
                "total_nodes": len(finalized),
                "cpu_reporting": cpu_ok,
                "ram_reporting": ram_ok,
                "gpu_reporting": gpu_ok,
                "unavailable_nodes": unavailable_all,
            },
            "nodes": finalized,
        }
    )


def render_nodes_hardware_html() -> str:
    """Render the dedicated /nodes Hardware Metrics portal with honest UNAVAILABLE_NO_EXPORTER states."""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpsCryer — Live /nodes Hardware Telemetry</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#080f1b;color:#e2e8f0}
body{max-width:1240px;margin:auto;padding:24px}nav,.controls{display:flex;flex-wrap:wrap;gap:14px;align-items:center}
a{color:#67e8f9}h1{color:#a5f3fc}button{background:#155e75;color:#fff;border:1px solid #22d3ee;padding:10px 14px;border-radius:6px;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px;margin-top:16px}
.card{background:#111e30;border:1px solid #334155;border-radius:10px;padding:16px;overflow-wrap:anywhere}
.pill{display:inline-block;font-size:.76rem;padding:3px 8px;border-radius:999px;border:1px solid #334155;margin-right:6px}
.pill-ok{background:#064e3b;border-color:#10b981;color:#a7f3d0}
.pill-unavail{background:#451a03;border-color:#f59e0b;color:#fde68a}
.metric-row{margin:10px 0}.metric-label{display:flex;justify-content:space-between;font-size:.9rem}
progress{display:block;width:100%;height:14px;accent-color:#22d3ee;margin-top:4px}
#status{color:#cbd5e1;min-height:1.4em}
</style>
</head>
<body>
<nav aria-label="Portals">
<a href="/">Cluster</a><a href="/hub">Hub</a><a href="/nodes" aria-current="page">Nodes Hardware</a>
<a href="/metrics-live">Live Metrics</a><a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
</nav>
<h1>Live /nodes Hardware Telemetry (CPU / RAM / GPU)</h1>
<p id="summary" class="pill">Loading node hardware exporters…</p>
<div class="controls">
<button id="poll" type="button">🔴 Poll Live Hardware Now</button>
<label><input id="auto-poll" type="checkbox"> ⏱️ Auto-Poll Every 10s</label>
</div>
<p id="status" role="status" aria-live="polite">Querying /api/v1/nodes/hardware-metrics…</p>
<main><div id="nodes-grid" class="grid"></div></main>
<script>
'use strict';
const byId = id => document.getElementById(id);
function add(parent, tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = String(text);
  if (cls) el.className = cls;
  parent.appendChild(el);
  return el;
}
function addMetricRow(card, label, value, status, suffix) {
  const row = add(card, 'div', undefined, 'metric-row');
  const head = add(row, 'div', undefined, 'metric-label');
  add(head, 'span', label);
  const available = status === 'OK' && typeof value === 'number' && Number.isFinite(value);
  if (available) {
    add(head, 'span', value + (suffix || '%'), 'pill pill-ok');
    if (!suffix || suffix === '%') {
      const bar = add(row, 'progress');
      bar.max = 100;
      bar.value = Math.min(100, Math.max(0, value));
      bar.setAttribute('aria-label', label + ': ' + value + '%');
    }
  } else {
    add(head, 'span', status || 'UNAVAILABLE_NO_EXPORTER', 'pill pill-unavail');
  }
}
function render(data) {
  const s = data.exporter_summary || {};
  byId('summary').textContent = 'Nodes: ' + (s.total_nodes || 0) + ' · CPU OK: ' + (s.cpu_reporting || 0) +
    ' · RAM OK: ' + (s.ram_reporting || 0) + ' · GPU OK: ' + (s.gpu_reporting || 0) +
    ' · Unavailable: ' + (s.unavailable_nodes || 0);
  const grid = byId('nodes-grid');
  grid.replaceChildren();
  for (const node of (data.nodes || [])) {
    const card = add(grid, 'article', undefined, 'card');
    add(card, 'h2', node.name || node.node_id);
    add(card, 'span', node.ready ? 'Ready' : 'NotReady', node.ready ? 'pill pill-ok' : 'pill pill-unavail');
    add(card, 'span', node.exporter_status || 'UNAVAILABLE_NO_EXPORTER',
      node.exporter_status === 'COMPLETE' ? 'pill pill-ok' : 'pill pill-unavail');
    addMetricRow(card, 'CPU Utilization', node.cpu_percent, node.cpu_status, '%');
    addMetricRow(card, 'RAM Utilization', node.ram_percent, node.ram_status, '%');
    addMetricRow(card, 'GPU Utilization', node.gpu_percent, node.gpu_status, '%');
    if (node.gpu_status === 'OK') {
      if (typeof node.gpu_vram_percent === 'number') {
        addMetricRow(card, 'GPU VRAM', node.gpu_vram_percent, 'OK', '%');
      }
      if (typeof node.gpu_temp_c === 'number') {
        addMetricRow(card, 'GPU Temp', node.gpu_temp_c, 'OK', ' °C');
      }
    }
    add(card, 'p', 'Pods: ' + (node.running_pod_count || 0) + ' running / ' + (node.failed_pod_count || 0) + ' failed');
  }
  if (!(data.nodes || []).length) add(grid, 'p', 'No cluster nodes discovered yet.');
  byId('status').textContent = 'Sources: ' + ((data.telemetry_sources || []).join(', ') || 'none') +
    ' · Zero fabricated metrics · Updated ' + new Date().toLocaleTimeString();
}
let busy = false, timer = null;
async function refresh(live) {
  if (busy) return;
  busy = true; byId('poll').disabled = true;
  try {
    const res = await fetch(live ? '/api/v1/nodes/hardware-metrics?live=1' : '/api/v1/nodes/hardware-metrics', {cache: 'no-store'});
    if (!res.ok) throw new Error('failed');
    render(await res.json());
  } catch (_) {
    byId('status').textContent = 'Hardware telemetry refresh failed; no fake values substituted.';
  } finally {
    busy = false; byId('poll').disabled = false;
  }
}
byId('poll').addEventListener('click', () => refresh(true));
byId('auto-poll').addEventListener('change', ev => {
  if (timer !== null) clearInterval(timer);
  timer = ev.target.checked ? setInterval(() => refresh(true), 10000) : null;
  if (ev.target.checked) refresh(true);
});
window.addEventListener('pagehide', () => { if (timer !== null) clearInterval(timer); });
refresh(false);
</script>
</body>
</html>'''


_INVALID_REQUEST = "Invalid live metrics request"
ALLOWED_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


def validate_loopback_host_header(host_header: str | None) -> bool:
    """Allow only loopback Host headers to prevent DNS-rebinding triggers of live=1."""
    if host_header is None:
        return True
    if not isinstance(host_header, str) or not host_header.strip():
        return False
    raw = host_header.strip().lower()
    if raw.startswith("["):
        host = raw.split("]", 1)[0] + "]" if "]" in raw else raw
    else:
        host = raw.split(":", 1)[0]
    return host in ALLOWED_LOOPBACK_HOSTS


def _build_live_metrics_handler(ttl_seconds: int = 10):
    """Build a read-only handler with explicit live collection opt-in."""
    class LiveMetricsHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send(self, status, body, content_type):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def send_error(self, code, message=None, explain=None):
            self._send(code, json.dumps({"error": _INVALID_REQUEST}), "application/json")

        def do_GET(self):
            try:
                if not validate_loopback_host_header(self.headers.get("Host")):
                    raise ValueError(_INVALID_REQUEST)
                url = urlsplit(self.path)
                html_route = url.path in {"/", "/metrics-live"}
                if not html_route and url.path not in {
                        "/metrics-live/report.md", "/api/v1/live-metrics"}:
                    self._send(404, '{"error": "Not found"}', "application/json")
                    return
                if (html_route and url.query) or re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                    raise ValueError(_INVALID_REQUEST)
                query = parse_qs(url.query, keep_blank_values=True,
                                 strict_parsing=True, errors="strict")
                if (set(query) - {"live"} or any(len(v) != 1 for v in query.values())
                        or query.get("live", ["0"])[0] not in {"0", "1"}):
                    raise ValueError(_INVALID_REQUEST)
                live = query.get("live", ["0"])[0] == "1"
                if html_route:
                    body, content_type = render_live_metrics_html(), "text/html"
                elif url.path == "/metrics-live/report.md":
                    body = render_live_metrics_markdown(allow_kubectl=live,
                                                        ttl_seconds=ttl_seconds)
                    content_type = "text/markdown"
                else:
                    body = json.dumps(poll_live_cluster_metrics(
                        allow_kubectl=live, ttl_seconds=ttl_seconds), allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError):
                self._send(400, json.dumps({"error": _INVALID_REQUEST}), "application/json")
                return
            self._send(200, body, content_type)

    return LiveMetricsHandler


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(_INVALID_REQUEST)


def main(argv=None) -> int:
    """Export sanitized metrics or serve the portal on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="live_metrics_poller", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--ttl", type=int, default=10)
    parser.add_argument("--port", type=int, default=8104)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 0 <= args.ttl <= 3600:
        parser.error(_INVALID_REQUEST)
    try:
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_live_metrics_handler(args.ttl)) as server:
                print(f"Live metrics: http://127.0.0.1:{args.port}/metrics-live", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_live_metrics_markdown(allow_kubectl=args.live, ttl_seconds=args.ttl))
        else:
            print(json.dumps(poll_live_cluster_metrics(
                allow_kubectl=args.live, ttl_seconds=args.ttl), indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error(_INVALID_REQUEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
