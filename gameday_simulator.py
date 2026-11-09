# SPDX-License-Identifier: Apache-2.0
"""Deterministic, simulation-only game-day exercises on offline snapshots."""

import argparse
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

import capacity_planner
import incident_commander
import network_topology_inspector
from opscryer_backend import KnowledgeGraphBackendEngine

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")


def list_gameday_scenarios() -> dict:
    """Return a fresh sanitized catalog of offline what-if exercises."""
    return sanitize({
        "schema_version": "1.0",
        "simulation_only": True,
        "scenarios": [
            {
                "scenario_id": "node_down_nodebeta02",
                "title": "Hardware Node Drain / Outage: nodebeta02",
                "category": "hardware",
                "target_node_id": "k8s/Node//nodebeta02",
                "description": (
                    "Model nodebeta02 becoming unavailable and assess workload "
                    "disruption and remaining cluster capacity."
                ),
            },
            {
                "scenario_id": "gitlab_runner_crashloop",
                "title": "CI/CD Workload CrashLoopBackOff",
                "category": "workload",
                "target_node_id": "k8s/Deployment/gitlab/gitlab-gitlab-runner",
                "description": (
                    "Model a GitLab runner entering CrashLoopBackOff and assess "
                    "CI/CD workload availability."
                ),
            },
            {
                "scenario_id": "ingress_oidc_bypass",
                "title": "Unauthenticated Public Ingress Drift",
                "category": "network",
                "target_node_id": "k8s/Ingress/gitlab/gitlab-ingress",
                "description": (
                    "Model missing OIDC authentication on a public ingress and "
                    "assess exposure and incident escalation."
                ),
            },
            {
                "scenario_id": "gpu_thermal_hotspot",
                "title": "GPU / Compute Node Hotspot Saturation",
                "category": "capacity",
                "target_node_id": "k8s/Node//nodegamma03",
                "description": (
                    "Model GPU thermal pressure and compute saturation on "
                    "nodegamma03 and assess workload headroom."
                ),
            },
            {
                "scenario_id": "combined_multi_plane_stress",
                "title": "Multi-Plane Cascading Stress Test",
                "category": "multi_plane",
                "target_node_id": "k8s/Node//nodebeta02",
                "description": (
                    "Combine node outage, runner crash loops, ingress "
                    "authentication drift, and GPU pressure to assess cascading "
                    "effects across operational planes."
                ),
            },
        ],
    })


def _simulation_metrics(snapshot):
    """Use component observations, including executive dashboard readiness KPIs."""
    incidents = incident_commander.build_active_incidents_catalog(snapshot)
    capacity = capacity_planner.summarize_cluster_capacity(snapshot)
    routing = network_topology_inspector.detect_routing_anomalies(snapshot)
    return {
        "incident_counts": incidents["summary_counts"],
        "node_counts": capacity["node_counts"],
        "pod_counts": capacity["pod_counts"],
        "node_metrics": {node["node_id"]: {
            key: node["metrics"][key] for key in ("cpu_percent", "ram_percent")
        } for node in capacity["nodes"]},
        "routing_anomaly_counts": {
            "total": routing["finding_count"], **routing["summary_counts"],
        },
    }


def _metric_delta(before, after):
    """Subtract observed numeric metrics; unknown observations stay unknown."""
    if isinstance(before, dict) and isinstance(after, dict):
        return {key: _metric_delta(before.get(key), after.get(key))
                for key in sorted(before.keys() | after.keys())}
    if type(before) in (int, float) and type(after) in (int, float):
        return after - before
    return None


def _prepare_gameday_baseline(catalog):
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    # A file containing null must not trigger the backend's default catalog.
    if not isinstance(catalog, dict):
        raise ValueError("Invalid gameday catalog")
    # Check before redaction too: credential fields can hide invalid numbers.
    json.dumps(catalog, allow_nan=False)
    snapshot = KnowledgeGraphBackendEngine(sanitize(deepcopy(catalog))).catalog()
    baseline = _simulation_metrics(snapshot)
    return snapshot, baseline


def simulate_gameday_scenario(scenario_id="node_down_nodebeta02", catalog=None,
                              _prepared=None) -> dict:
    """Compare an offline snapshot with a detached synthetic fault snapshot.

    Accept a graph dict, JSON path, or None for the bundled snapshot. No live
    collection or writes occur. Deltas are simulated minus baseline; missing
    utilization stays unknown. Already degraded targets may yield zero deltas.
    """
    scenarios = {item["scenario_id"]: item
                 for item in list_gameday_scenarios()["scenarios"]}
    if not isinstance(scenario_id, str) or scenario_id not in scenarios:
        raise ValueError("Unknown gameday scenario")
    try:
        snapshot, baseline = (
            _prepare_gameday_baseline(catalog) if _prepared is None else _prepared
        )
        simulated_snapshot = deepcopy(snapshot)

        def target(kind, name, namespace=""):
            identity = f"k8s/{kind}/{namespace}/{name}"
            for node in simulated_snapshot["nodes"]:
                resource = node.get("resource", {})
                metadata = resource.get("metadata", {})
                if (node["id"] == identity or (
                        node.get("resource_kind", resource.get("kind")) == kind
                        and metadata.get("name", node["label"]) == name
                        and (metadata.get("namespace") or node.get("namespace") or "")
                        == namespace)):
                    return node
            node = {
                "id": identity, "label": name,
                "kind": "kubernetes_" + kind.lower(),
                "domain": "deployments_k8s", "summary": "Synthetic game-day target",
                "primary_url": "https://kubernetes.cluster.example.org",
                "drilldown_children": [], "resource_kind": kind,
                "namespace": namespace,
                "resource": {"kind": kind, "metadata": {"name": name}},
            }
            if namespace:
                node["resource"]["metadata"]["namespace"] = namespace
            simulated_snapshot["nodes"].append(node)
            return node

        combined = scenario_id == "combined_multi_plane_stress"
        if combined or scenario_id == "node_down_nodebeta02":
            node = target("Node", "nodebeta02")
            status = node["resource"].setdefault("status", {})
            conditions = status.setdefault("conditions", [])
            conditions[:] = [c for c in conditions if c.get("type") != "Ready"]
            conditions.append({"type": "Ready", "status": "False"})
        if combined or scenario_id == "gitlab_runner_crashloop":
            deployment = target("Deployment", "gitlab-gitlab-runner", "gitlab")
            resource = deployment["resource"]
            spec = resource.setdefault("spec", {})
            spec["replicas"] = max(1, spec.get("replicas", 1))
            resource.setdefault("status", {})["readyReplicas"] = 0
            pod = target("Pod", "gitlab-gitlab-runner-gameday", "gitlab")
            pod["resource"].setdefault("metadata", {})["ownerReferences"] = [
                {"kind": "Deployment", "name": "gitlab-gitlab-runner"}]
            pod["resource"].setdefault("status", {}).update({
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "False"}],
                "containerStatuses": [{"name": "runner", "ready": False,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}}}],
            })
        if combined or scenario_id == "ingress_oidc_bypass":
            ingress = target("Ingress", "gitlab-gameday-oidc-bypass", "gitlab")
            ingress["resource"]["metadata"]["annotations"] = {}
            ingress["resource"]["spec"] = {
                "rules": [{"host": "gameday.cluster.example.org", "http": {"paths": [{
                    "path": "/", "pathType": "Prefix", "backend": {
                        "service": {"name": "gitlab-webservice-default",
                                    "port": {"number": 8080}}},
                }]}}],
            }
        if combined or scenario_id == "gpu_thermal_hotspot":
            target("Node", "nodegamma03").setdefault("metrics", {}).update({
                "cpu_percent": 92, "ram_percent": 88,
            })
        if "node_count" in simulated_snapshot:
            simulated_snapshot["node_count"] = len(simulated_snapshot["nodes"])
        simulated_snapshot = KnowledgeGraphBackendEngine(simulated_snapshot).catalog()
        simulated = _simulation_metrics(simulated_snapshot)
        result = sanitize({
            "schema_version": "1.0", "scenario_id": scenario_id,
            "simulation_only": True, "live_cluster_modified": False,
            "baseline": baseline, "simulated": simulated,
            "delta": _metric_delta(baseline, simulated),
            "notice": "Offline synthetic faults only; deltas are simulated minus baseline. "
                      "Missing metrics remain unknown. Synthetic targets are added when absent. "
                      "OIDC findings describe missing evidence, not verified anonymous access. "
                      "CPU/RAM pressure does not establish GPU temperature.",
        })
        json.dumps(result, allow_nan=False)
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError,
            OverflowError, RecursionError):
        raise ValueError("Invalid gameday catalog") from None


def render_gameday_markdown(scenario_id="node_down_nodebeta02", catalog=None) -> str:
    """Render sanitized offline evidence and a tabletop-only containment review."""
    report = simulate_gameday_scenario(scenario_id, catalog=catalog)
    scenario = next(item for item in list_gameday_scenarios()["scenarios"]
                    if item["scenario_id"] == report["scenario_id"])

    def text(value):
        # Redact before escaping so markup cannot interfere with OPSEC patterns.
        value = sanitize("unknown" if value is None else str(value))
        value = " ".join(value.split())
        value = "".join(char for char in value if char.isprintable())
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~$-])", r"\\\1",
                      escape(value, quote=True))

    def row(values):
        return "| " + " | ".join(text(value) for value in values) + " |"

    def leaves(values, path=()):
        for key, value in values.items():
            current = path + (key,)
            if isinstance(value, dict):
                yield from leaves(value, current)
            else:
                yield current, value

    def at_path(values, path):
        for key in path:
            if not isinstance(values, dict):
                return None
            values = values.get(key)
        return values

    lines = [
        "# Game-Day Simulation Report", "",
        "> Simulation only: offline synthetic faults for a tabletop exercise. "
        "No live cluster changes or containment actions are performed.", "",
        text(report["notice"]), "",
        "## Scenario Summary", "",
        "- Scenario ID: " + text(report["scenario_id"]),
        "- Title: " + text(scenario["title"]),
        "- Category: " + text(scenario["category"]),
        "- Target: " + text(scenario["target_node_id"]),
        "- Description: " + text(scenario["description"]), "",
        "## Baseline vs. Simulated KPI Delta", "",
        "Delta is simulated minus baseline. Unknown observations remain unknown.", "",
        "| KPI | Baseline | Simulated | Delta |",
        "| --- | --- | --- | --- |",
    ]
    for path, delta in leaves(report["delta"]):
        lines.append(row((" / ".join(path), at_path(report["baseline"], path),
                          at_path(report["simulated"], path), delta)))

    lines.extend([
        "", "## Newly Triggered Incidents", "",
        "Positive net incident count increases by severity are shown below. "
        "Aggregate counts do not identify individual newly triggered incidents.", "",
        "| Severity | Baseline | Simulated | Net increase |",
        "| --- | --- | --- | --- |",
    ])
    increases = 0
    for severity, delta in report["delta"]["incident_counts"].items():
        if severity != "total" and type(delta) in (int, float) and delta > 0:
            lines.append(row((severity, report["baseline"]["incident_counts"][severity],
                              report["simulated"]["incident_counts"][severity], delta)))
            increases += 1
    if not increases:
        lines.append("| No net incident count increases observed | — | — | 0 |")

    lines.extend([
        "", "## Tabletop Containment Checklist", "",
        "- [ ] Confirm the scenario assumptions and missing evidence with exercise participants.",
        "- [ ] Review the affected target: " + text(scenario["target_node_id"]),
        "- [ ] Trace dependent workloads and review capacity and routing KPI deltas.",
        "- [ ] Assign an incident owner and document proposed containment and rollback steps.",
        "- [ ] Review authorization and change controls before any separate live response.",
        "- [ ] Define recovery checks for node readiness, workload health, capacity, and authentication.",
        "- [ ] Record exercise findings, evidence gaps, and follow-up tickets.", "",
    ])
    return "\n".join(lines)


def render_gameday_simulator_html(catalog=None) -> str:
    """Render all offline exercises with sanitized evidence and safe DOM updates."""
    scenarios = list_gameday_scenarios()["scenarios"]
    try:
        prepared = _prepare_gameday_baseline(catalog)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError,
            OverflowError, RecursionError):
        raise ValueError("Invalid gameday catalog") from None
    payload = sanitize({
        "simulation_only": True,
        "scenarios": scenarios,
        "simulations": [simulate_gameday_scenario(item["scenario_id"], catalog=catalog,
                                                  _prepared=prepared)
                        for item in scenarios],
    })
    evidence = (json.dumps(payload, allow_nan=False)
                .replace("&", "\\u0026").replace("<", "\\u003c")
                .replace(">", "\\u003e"))
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Game-Day Simulator</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#090e1a;color:#e5ecf8}
*{box-sizing:border-box}body{margin:0}main,nav{max-width:1440px;margin:auto;padding:24px}
nav{display:flex;flex-wrap:wrap;gap:12px 22px;border-bottom:1px solid #2a3850}
a{color:#a9c9ff;text-underline-offset:4px}nav a[aria-current]{color:#fff;font-weight:700}
h1{font-size:clamp(2rem,4vw,3rem)}h2{font-size:1.3rem}h3{font-size:1rem}
p,li{line-height:1.6}.muted{color:#a8b7ce}.eyebrow{color:#80daca;letter-spacing:.12em}
.panel,.kpi{background:#121c2d;border:1px solid #2a3850;border-radius:16px;padding:22px}
.panel{margin-top:22px}#gameday-scenario-buttons{display:flex;flex-wrap:wrap;gap:10px}
button{font:inherit;color:inherit;background:#1b2940;border:1px solid #536987;
border-radius:10px;padding:12px;cursor:pointer}button:hover{border-color:#a9c9ff}
button[aria-pressed="true"]{background:#29446b;border-color:#80daca}
button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #80daca;outline-offset:4px}
#gameday-kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.kpi{border-top:3px solid #80daca}.kpi strong{display:block;font-size:1.5rem}
.table-scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}
th,td{padding:12px;border-bottom:1px solid #34445c;overflow-wrap:anywhere}
caption{text-align:left;color:#a8b7ce;padding:12px}ul{list-style:none;padding:0}
li{margin:12px 0}input{margin-right:12px}label{cursor:pointer}
@media(max-width:600px){main,nav{padding:16px}.panel,.kpi{padding:16px}}
</style></head>
<body>
<nav aria-label="Main navigation"><a href="/">Home</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/executive">Executive</a><a href="/hub">Suite Hub</a>
<a href="/simulator" aria-current="page">Simulator</a></nav>
<main><header><p class="eyebrow">OFFLINE / TABLETOP EXERCISE</p>
<h1>Game-Day Simulator</h1>
<p>Simulation only. Explore synthetic faults and cascading impact without changing the live cluster.</p>
</header>
<section class="panel" aria-labelledby="gameday-selector-title">
<h2 id="gameday-selector-title">Choose a scenario</h2>
<div id="gameday-scenario-buttons" role="group" aria-label="Scenarios"></div>
</section>
<section class="panel" aria-labelledby="gameday-scenario-title">
<h2 id="gameday-scenario-title">Scenario details</h2>
<p id="gameday-description"></p><p id="gameday-target" class="muted"></p>
<p id="gameday-notice" class="muted"></p>
<p id="gameday-status" role="status" aria-live="polite"></p>
</section>
<section class="panel" aria-labelledby="gameday-kpi-title">
<h2 id="gameday-kpi-title">Baseline vs. Simulated KPI Delta</h2>
<p class="muted">Delta = simulated minus baseline. Missing observations remain unknown.</p>
<div id="gameday-kpi-grid"></div>
</section>
<section class="panel" aria-labelledby="gameday-impact-title">
<h2 id="gameday-impact-title">Cascading Impact</h2><div class="table-scroll">
<table id="gameday-delta-table"><caption>Observed metrics across incident, capacity and routing planes</caption>
<thead><tr><th scope="col">Metric / plane</th><th scope="col">Baseline</th>
<th scope="col">Simulated</th><th scope="col">Delta</th></tr></thead>
<tbody id="gameday-delta-rows"></tbody></table></div></section>
<section class="panel" aria-labelledby="gameday-runbook-title">
<h2 id="gameday-runbook-title">Tabletop Runbook</h2>
<p class="muted">Checks record this exercise locally in memory. Switching scenarios resets the checklist.</p>
<ul id="gameday-runbook"></ul></section>
<noscript><p>Enable JavaScript to select scenarios and review offline simulation evidence.</p></noscript>
</main>
<script id="gameday-data" type="application/json">""" + evidence + """</script>
<script>
"use strict";
(() => {
  const data = JSON.parse(document.getElementById("gameday-data").textContent);
  const buttons = document.getElementById("gameday-scenario-buttons");
  const grid = document.getElementById("gameday-kpi-grid");
  const rows = document.getElementById("gameday-delta-rows");
  const runbook = document.getElementById("gameday-runbook");
  function add(parent, tag, value) {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = String(value);
    parent.appendChild(element);
    return element;
  }
  function atPath(object, path) {
    return path.reduce((value, key) => value == null ? null : value[key], object);
  }
  function display(value, delta = false) {
    if (value == null) return "unknown";
    return (delta && value > 0 ? "+" : "") + String(value);
  }
  function select(index) {
    const scenario = data.scenarios[index];
    const report = data.simulations[index];
    Array.from(buttons.children).forEach((button, position) => {
      button.setAttribute("aria-pressed", String(position === index));
    });
    document.getElementById("gameday-scenario-title").textContent = scenario.title;
    document.getElementById("gameday-description").textContent = scenario.description;
    document.getElementById("gameday-target").textContent = "Target: " + scenario.target_node_id;
    document.getElementById("gameday-notice").textContent = report.notice;
    document.getElementById("gameday-status").textContent = "Selected: " + scenario.title;
    grid.textContent = "";
    const kpis = [
      ["Incidents", ["incident_counts", "total"]],
      ["SEV-1 incidents", ["incident_counts", "by_severity", "SEV-1"]],
      ["Ready nodes", ["node_counts", "ready"]],
      ["Not-ready nodes", ["node_counts", "not_ready"]],
      ["Pods", ["pod_counts", "total"]],
      ["Routing anomalies", ["routing_anomaly_counts", "total"]]
    ];
    kpis.forEach(([title, path]) => {
      const card = add(grid, "article");
      card.className = "kpi";
      add(card, "h3", title);
      add(card, "p", "Baseline: " + display(atPath(report.baseline, path)));
      add(card, "p", "Simulated: " + display(atPath(report.simulated, path)));
      add(card, "strong", "Delta: " + display(atPath(report.delta, path), true));
    });
    rows.textContent = "";
    function metrics(values, path = []) {
      Object.entries(values).forEach(([key, value]) => {
        const current = path.concat(key);
        if (value !== null && typeof value === "object") {
          metrics(value, current);
        } else {
          const row = add(rows, "tr");
          const heading = add(row, "th", current.join(" / "));
          heading.scope = "row";
          add(row, "td", display(atPath(report.baseline, current)));
          add(row, "td", display(atPath(report.simulated, current)));
          add(row, "td", display(value, true));
        }
      });
    }
    metrics(report.delta);
    runbook.textContent = "";
    [
      "Confirm scenario assumptions and missing evidence with participants.",
      "Review the affected target: " + scenario.target_node_id,
      "Trace dependent workloads and review capacity and routing KPI deltas.",
      "Assign an incident owner and document proposed containment and rollback steps.",
      "Review authorization and change controls before any separate live response.",
      "Define recovery checks for readiness, workload health, capacity and authentication.",
      "Record exercise findings, evidence gaps and follow-up tickets."
    ].forEach(step => {
      const label = add(add(runbook, "li"), "label");
      const check = add(label, "input");
      check.type = "checkbox";
      add(label, "span", step);
    });
  }
  data.scenarios.forEach((scenario, index) => {
    const button = add(buttons, "button", scenario.title);
    button.type = "button";
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", () => select(index));
  });
  select(0);
})();
</script></body></html>
"""


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid gameday simulator request")


def _build_gameday_handler(catalog=None):
    """Serve offline simulations without logging or echoing request input."""
    class GamedayRequestHandler(BaseHTTPRequestHandler):
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
                if url.path not in {"/", "/simulator", "/api/v1/gameday-simulator",
                                    "/simulator/report.md"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True,
                                 max_num_fields=1, errors="strict")
                if set(query) - {"scenario"}:
                    raise ValueError("Invalid query")
                scenario = query.get("scenario", ["node_down_nodebeta02"])[0]
                if url.path in {"/", "/simulator"}:
                    if query:
                        raise ValueError("Invalid query")
                    body = render_gameday_simulator_html(catalog)
                    content_type = "text/html"
                elif url.path == "/simulator/report.md":
                    body = render_gameday_markdown(scenario, catalog)
                    content_type = "text/markdown"
                else:
                    body = json.dumps(simulate_gameday_scenario(scenario, catalog),
                                      indent=2, allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError, KeyError):
                self._send(400, '{"error":"Invalid gameday simulator request"}',
                           "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Gameday simulator unavailable"}',
                           "application/json")
                return
            self._send(200, body, content_type)

    return GamedayRequestHandler


def main(argv=None) -> int:
    """Export an offline simulation or serve the simulator on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="gameday_simulator", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--scenario", metavar="ID", default="node_down_nodebeta02")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8096)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    try:
        catalog = json.loads((args.catalog or DEFAULT_CATALOG_PATH).read_text(encoding="utf-8"))
        if not isinstance(catalog, dict):
            raise ValueError("Invalid gameday catalog")
        result = simulate_gameday_scenario(args.scenario, catalog)
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_gameday_handler(catalog)) as server:
                print(f"Gameday simulator: http://127.0.0.1:{args.port}/simulator", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_gameday_markdown(args.scenario, catalog), end="")
        else:
            print(json.dumps(result, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.error("Unable to complete request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
