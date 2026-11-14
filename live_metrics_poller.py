# SPDX-License-Identifier: Apache-2.0
"""Sanitized live metrics and the Live Cluster Metrics & Telemetry Stream portal."""

from collections import Counter, defaultdict
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

import cluster_diff_engine
import cluster_harvester
from live_currencies import build_enriched_live_currencies
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


_METRICS_CACHE = {}


def clear_live_metrics_cache() -> None:
    """Discard cached responses without collecting telemetry."""
    _METRICS_CACHE.clear()


def poll_live_cluster_metrics(allow_kubectl: bool = False, ttl_seconds: int = 10,
                              catalog: dict | None = None) -> dict:
    """Build an independent metrics response; live collection is explicitly opt-in."""
    if (type(allow_kubectl) is not bool or type(ttl_seconds) is not int
            or not 0 <= ttl_seconds <= 3600):
        raise ValueError("Invalid live metrics parameters")
    key = (allow_kubectl, ttl_seconds)
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
