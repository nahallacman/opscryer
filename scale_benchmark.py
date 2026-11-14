# SPDX-License-Identifier: Apache-2.0
"""Deterministic enterprise topology and local, stdlib-only scale benchmarks.

Run ``python scale_benchmark.py --json --nodes 1500`` for JSON telemetry.
Structural metrics are repeatable; wall-clock timings depend on the machine.
These synthetic workloads measure local graph operations, not live services.
"""

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import perf_counter
from urllib.parse import parse_qs, urlsplit

from opscryer_backend import (
    CONTRACT_VERSION,
    KnowledgeGraphBackendEngine,
    validate_spatial_graph_contract,
)


def generate_synthetic_enterprise_graph(node_count: int = 500) -> dict:
    """Build a fresh, connected L0-L4 SpatialGraphContract v1 catalog.

    Each node has one containment parent at the preceding level. Explicit
    same-level workflow and scheduling edges connect domains without creating
    shortcuts past hierarchy levels. No randomness or live telemetry is used.
    """
    if type(node_count) is not int or not 10 <= node_count <= 5000:
        raise ValueError("node_count must be an integer between 10 and 5000")

    counts = [1, max(1, node_count // 100), max(2, node_count // 10),
              max(2, node_count // 5)]
    counts.append(node_count - sum(counts))
    nodes, edges, levels = [], [], []
    archetypes = (
        (("company_root", "company_org", "Citadel"),),
        (("company_team", "company_org", "Team"),),
        (("engineering_project", "company_org", "Project"),
         ("operational_process", "processes_workflows", "Runbook")),
        (("k8s_namespace", "deployments_k8s", "K8s Namespace"),
         ("k8s_deployment", "deployments_k8s", "Deployment")),
        (("k8s_pod", "deployments_k8s", "Pod"),
         ("hardware_node", "hardware_topology", "Hardware Node")),
    )
    for level, count in enumerate(counts):
        layer = []
        for index in range(count):
            kind, domain, label = archetypes[level][index % len(archetypes[level])]
            node_id = f"{kind}-{index:04d}"
            if level == 0:
                node_id = "root-company"
            # Keep the backend's deterministic Jev policy anchors resolvable.
            elif level == 2 and index == 0 and count < 4:
                node_id = "proc-demo-secret-policy"
            elif level == 2 and index in (1, 3):
                node_id = "proc-demo-cicd" if index == 1 else "proc-demo-secret-policy"
            elif level == 3 and index == 1:
                node_id = "deploy-demo-k8s"
            node = {
                "id": node_id, "label": f"Synthetic Enterprise {label} {index:04d}",
                "kind": kind, "domain": domain,
                "summary": f"Synthetic enterprise {label.lower()} for platform operations",
                "primary_url": f"https://example.org/enterprise/{node_id}",
                "zoom_level": level, "level_index": level,
                "drilldown_children": [],
            }
            nodes.append(node)
            layer.append(node)
            if level:
                parent = levels[level - 1][index % len(levels[level - 1])]
                parent["drilldown_children"].append(node_id)
                edges.append({"source": parent["id"], "target": node_id,
                              "relation": "contains"})
        levels.append(layer)

    for layer, relation in ((levels[2], "documented_by"), (levels[4], "scheduled_on")):
        for index in range(0, len(layer) - 1, 2):
            edges.append({"source": layer[index]["id"],
                          "target": layer[index + 1]["id"], "relation": relation})

    currencies = [
        {"currency_id": key, "label": label, "display_value": value,
         "supply_kind": supply, "dropdown_items": []}
        for key, label, value, supply in (
            ("nodes", "Nodes", str(counts[4] // 2), "supply_cap"),
            ("cpu_load", "CPU Load", "24% (synthetic)", "currency_rate"),
            ("ram_load", "RAM Load", "54% (synthetic)", "currency_rate"),
            ("network_load", "Net Load %", "11% (synthetic)", "currency_rate"),
            ("build_supply", "Build Supply", "4/5 Slots (synthetic)", "food_supply"),
            ("renovate_failures", "Renovate", "0 Fail (synthetic)", "upkeep_alert"),
            ("open_mrs", "Open MRs", "9 (synthetic)", "production_queue"),
        )
    ]
    return {"schema_version": CONTRACT_VERSION, "root_id": "root-company",
            "synthetic": True, "node_count": len(nodes), "edge_count": len(edges),
            "nodes": nodes, "edges": edges, "rts_currencies": currencies}


def run_scalability_benchmark_suite(sizes: tuple[int, ...] = (100, 500, 1500)) -> dict:
    """Return ordered ``results``, with ten operations of each type per size.

    ``shortest_path_hops`` is the maximum across ten paths (always four).
    ``search_hit_count`` totals hits across ten queries (search limit 10).
    ``index_ms`` includes engine validation and index setup,
    excluding graph generation. The realtime tier requires every operation's
    mean latency (search, BFS and Jev) to be strictly below 10 ms; the other
    tier is a label for remaining measurements, not a latency guarantee.
    """
    results = []
    queries = ("enterprise", "platform", "project", "runbook", "namespace",
               "deployment", "pod", "hardware", "operations", "synthetic")
    tickets = ("Scaffold a new project", "Database access credentials", "Find a runbook")
    for size in sizes:
        graph = generate_synthetic_enterprise_graph(size)
        errors = validate_spatial_graph_contract(graph)
        if errors:
            raise ValueError("synthetic graph failed contract validation")
        started = perf_counter()
        engine = KnowledgeGraphBackendEngine(graph)
        index_ms = (perf_counter() - started) * 1000

        hits = 0
        started = perf_counter()
        for query in queries:
            response = engine.search(query, limit=10)
            if response["result_count"] == 0:
                raise RuntimeError("benchmark search returned no hits")
            hits += response["result_count"]
        avg_search_ms = (perf_counter() - started) * 1000 / 10

        leaves = [node for node in graph["nodes"] if node["zoom_level"] == 4]
        targets = [leaves[index * (len(leaves) - 1) // 9]["id"] for index in range(10)]
        hops = 0
        started = perf_counter()
        for target in targets:
            path = engine.shortest_path(graph["root_id"], target)
            if not path["path_found"] or path["hop_count"] != 4:
                raise RuntimeError("benchmark leaf is not four hops from the root")
            hops = max(hops, path["hop_count"])
        avg_bfs_ms = (perf_counter() - started) * 1000 / 10

        started = perf_counter()
        for index in range(10):
            decision = engine.deflect_ticket(tickets[index % len(tickets)])
            if decision["policy_id"] is None or decision["traversal_steps"][-1]["kind"] != "leaf":
                raise RuntimeError("benchmark Jev evaluation did not reach a policy leaf")
        avg_jev_ms = (perf_counter() - started) * 1000 / 10
        results.append({
            "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]),
            "max_depth": max(node["zoom_level"] for node in graph["nodes"]),
            "shortest_path_hops": hops, "search_hit_count": hits, "contract_valid": True,
            "index_ms": index_ms, "avg_search_ms": avg_search_ms,
            "avg_bfs_ms": avg_bfs_ms, "avg_jev_ms": avg_jev_ms,
            "scalability_tier": ("SUB_10MS_REALTIME"
                                 if max(avg_search_ms, avg_bfs_ms, avg_jev_ms) < 10
                                 else "INTERACTIVE_READY"),
        })
    return {"iterations_per_operation": 10, "results": results}


def render_scale_benchmark_markdown(sizes=(100, 500, 1500)) -> str:
    """Render measured local latencies as a portable Markdown table."""
    report = run_scalability_benchmark_suite(sizes)
    lines = ["# OpsCryer Graph Scalability & Performance Benchmark", "",
             "Synthetic workloads; local wall-clock timings vary by machine. "
             "Each operation latency is the mean of 10 iterations.", "",
             "| Nodes | Edges | Index (ms) | Search (ms) | BFS (ms) | Jev (ms) | Tier |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in report["results"]:
        lines.append(
            f"| {row['node_count']} | {row['edge_count']} | {row['index_ms']:.3f} | "
            f"{row['avg_search_ms']:.3f} | {row['avg_bfs_ms']:.3f} | "
            f"{row['avg_jev_ms']:.3f} | {row['scalability_tier']} |")
    return "\n".join(lines) + "\n"


def render_scale_benchmark_html() -> str:
    """Render a same-origin benchmark UI and self-contained browser exports."""
    from opscryer_browser import render_standalone_browser_html

    documents = {
        str(size): render_standalone_browser_html(
            dataset=generate_synthetic_enterprise_graph(size))
        for size in (100, 500, 1500, 3000)
    }
    return r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpsCryer ??? Graph Scalability & Performance Benchmark</title>
<style>
body{font:16px system-ui;background:#101827;color:#e5edf8;max-width:1000px;margin:40px auto;padding:20px}
a{color:#81d4fa}button,select{font:inherit;padding:10px;margin:8px;border-radius:6px}
#cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
article{background:#203047;padding:20px;border-radius:10px}strong{display:block;font-size:24px}
</style></head><body>
<nav><a href="/">Spatial RTS Browser</a></nav>
<h1>Graph Scalability &amp; Performance Benchmark</h1>
<p>Synthetic enterprise graphs, measured locally. Search, BFS traversal and Jev policy
latencies are means of 10 operations; index latency measures one initialization.
These measurements exclude network requests and browser rendering.</p>
<label for="nodes">Graph size</label><select id="nodes">
<option value="100">100 nodes</option><option value="500" selected>500 nodes</option>
<option value="1500">1500 nodes</option><option value="3000">3000 nodes</option></select>
<button id="run">Run benchmark</button>
<button id="export">Export synthetic graph into Spatial RTS Browser</button>
<p id="status" role="status" aria-live="polite"></p>
<section id="cards" aria-label="Latency comparison cards"></section>
<p>The export downloads a standalone HTML browser containing the selected graph.
Open the file locally to explore its L0–L4 hierarchy.</p>
<script>
const exportDocuments = __EXPORT_DOCUMENTS__;
const nodes = document.getElementById('nodes');
const status = document.getElementById('status');
let requestNumber = 0;
async function runBenchmark() {
  const currentRequest = ++requestNumber;
  status.textContent = 'Benchmark running…';
  document.getElementById('cards').replaceChildren();
  try {
    const response = await fetch('/api/v1/scale-benchmark?nodes=' + nodes.value);
    if (!response.ok) throw new Error('Benchmark unavailable');
    const report = await response.json();
    if (currentRequest !== requestNumber) return;
    const row = report.results[0];
    for (const [label, key] of [['Index', 'index_ms'], ['Search', 'avg_search_ms'],
                              ['BFS traversal', 'avg_bfs_ms'], ['Jev policy', 'avg_jev_ms']]) {
      const card = document.createElement('article');
      const heading = document.createElement('h2'); heading.textContent = label;
      const value = document.createElement('strong'); value.textContent = row[key].toFixed(3) + ' ms';
      card.append(heading, value); document.getElementById('cards').append(card);
    }
    status.textContent = row.node_count + ' nodes · ' + row.edge_count + ' edges · ' + row.scalability_tier;
  } catch (_) {
    if (currentRequest === requestNumber) status.textContent = 'Benchmark unavailable. Try again.';
  }
}
document.getElementById('run').addEventListener('click', runBenchmark);
nodes.addEventListener('change', runBenchmark);
document.getElementById('export').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([exportDocuments[nodes.value]], {type:'text/html;charset=utf-8'}));
  const link = document.createElement('a'); link.href = url;
  link.download = 'opscryer-synthetic-' + nodes.value + '-nodes.html';
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
runBenchmark();
</script></body></html>'''.replace(
        "__EXPORT_DOCUMENTS__", json.dumps(documents, ensure_ascii=True).replace("</", "<\\/"))


_INVALID_REQUEST = "Invalid scale benchmark request"


def _parse_scale_nodes(value):
    """Accept decimal integer node counts without reflecting rejected input."""
    if not re.fullmatch(r"[0-9]+", value) or not 10 <= int(value) <= 5000:
        raise ValueError(_INVALID_REQUEST)
    return int(value)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(_INVALID_REQUEST)


def _build_scale_handler():
    """Build a loopback dashboard/API handler that never logs request input."""
    class ScaleRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send(self, status, body, content_type):
            body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            self._send(code, json.dumps({"error": _INVALID_REQUEST}), "application/json")

        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.path not in {"/", "/scale", "/api/v1/scale-benchmark"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                if re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                    raise ValueError(_INVALID_REQUEST)
                query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True,
                                 max_num_fields=1, errors="strict")
                if set(query) - {"nodes"}:
                    raise ValueError(_INVALID_REQUEST)
                if url.path in {"/", "/scale"}:
                    if url.query:
                        raise ValueError(_INVALID_REQUEST)
                    body, content_type = render_scale_benchmark_html(), "text/html"
                else:
                    sizes = ((_parse_scale_nodes(query["nodes"][0]),)
                             if "nodes" in query else (100, 500, 1500))
                    body = json.dumps(run_scalability_benchmark_suite(sizes), allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError):
                self._send(400, json.dumps({"error": _INVALID_REQUEST}), "application/json")
                return
            self._send(200, body, content_type)

    return ScaleRequestHandler


def main(argv=None):
    """Export measured results or serve the dashboard on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="scale_benchmark", description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--nodes", type=_parse_scale_nodes, default=500)
    parser.add_argument("--sizes", nargs="+", type=_parse_scale_nodes,
                        help="Legacy multi-size JSON/Markdown export")
    parser.add_argument("--port", type=int, default=8107)
    options = parser.parse_args(argv)
    if not 1 <= options.port <= 65535:
        parser.error(_INVALID_REQUEST)
    try:
        sizes = tuple(options.sizes) if options.sizes else (options.nodes,)
        if options.serve:
            with ThreadingHTTPServer(("127.0.0.1", options.port), _build_scale_handler()) as server:
                print(f"Scale benchmark: http://127.0.0.1:{options.port}/scale", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif options.markdown:
            print(render_scale_benchmark_markdown(sizes), end="")
        else:
            print(json.dumps(run_scalability_benchmark_suite(sizes), indent=2, allow_nan=False))
    except (ValueError, TypeError, OSError):
        parser.error(_INVALID_REQUEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
