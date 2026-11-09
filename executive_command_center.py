# SPDX-License-Identifier: Apache-2.0
"""Executive governance evidence from local policy and offline snapshots."""

import argparse
import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
from urllib.parse import urlsplit

import capacity_planner
from golden_path_gates import run_six_gate_prepush_audit
from chaos_blast_radius import verify_all_six_chaos_planes
import incident_commander
from oidc_rbac_verifier import audit_cluster_ingress_oidc_posture
from openbao_kms_provenance import (
    audit_openbao_secret_provenance, verify_raft_kms_quorum,
)
from oscal_compliance import evaluate_live_oscal_posture
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")


def render_executive_command_center_html(catalog=None) -> str:
    """Render a standalone dashboard from sanitized, bundled snapshot evidence.

    Embed JSON safely across the HTML parser boundary. All dynamic content is
    inserted as text nodes; no network requests or live operations are needed.
    Provider failures propagate rather than displaying an empty healthy report.
    """
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        try:
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ValueError("Unable to load executive snapshot") from None
    dossier = build_executive_posture_dossier(catalog)
    evidence = {
        "dossier": dossier,
        "register": build_platform_risk_register(catalog, _dossier=dossier),
    }
    # Escape script delimiters even though the embedded script is inert JSON.
    payload = (json.dumps(sanitize(evidence), allow_nan=False)
               .replace("&", "\\u0026").replace("<", "\\u003c")
               .replace(">", "\\u003e"))
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>OpsCryer | Executive CISO &amp; Platform Governance</title>
<style>
:root { color-scheme: dark; background: #0b1220; color: #e2e8f0;
    font-family: system-ui, sans-serif; }
body { max-width: 1400px; margin: auto; padding: 24px; line-height: 1.6; }
nav { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 28px; }
a { color: #7dd3fc; } a[aria-current] { font-weight: bold; }
section { margin: 28px 0; }
.grid { display: grid; gap: 16px;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); }
article { background: #111c30; border: 1px solid #334155;
    border-radius: 12px; padding: 20px; }
article h3 { margin-top: 0; }
.table-scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; text-align: left; }
caption { text-align: left; padding-bottom: 12px; }
th, td { padding: 12px; border-bottom: 1px solid #334155; vertical-align: top;
    white-space: pre-line; overflow-wrap: anywhere; }
th { color: #7dd3fc; }
p, li { overflow-wrap: anywhere; }
:focus-visible { outline: 3px solid #7dd3fc; outline-offset: 3px; }
</style>
</head>
<body>
<nav aria-label="Main navigation">
<a href="/">Overview</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/executive" aria-current="page">Executive</a>
</nav>
<main>
<h1>Executive CISO &amp; Platform Governance Command Center</h1>
<p>Read-only snapshot evidence and local checks captured when this page was generated.</p>
<p id="executive-notice"></p><p id="executive-kpis"></p>
<noscript>Enable JavaScript to view the embedded posture, risks and security summaries.</noscript>
<section aria-labelledby="oscal-heading">
<h2 id="oscal-heading">OSCAL 9-control posture</h2>
<p id="oscal-summary"></p>
<div id="oscal-posture-grid" class="grid"></div>
</section>
<section aria-labelledby="security-heading">
<h2 id="security-heading">Chaos containment and OpenBao quorum</h2>
<div id="security-planes-summary" class="grid"></div>
</section>
<section aria-labelledby="risk-heading">
<h2 id="risk-heading">Platform risk register</h2>
<p id="risk-notice"></p>
<div class="table-scroll"><table id="platform-risk-register">
<caption>Open risks and required operational evidence</caption>
<thead><tr><th scope="col">Risk / domain</th><th scope="col">Status</th>
<th scope="col">Observed status</th><th scope="col">Required operational evidence</th></tr></thead>
<tbody id="platform-risk-rows"></tbody>
</table></div>
</section>
<section aria-labelledby="scope-heading">
<h2 id="scope-heading">Evidence scope</h2><ul id="executive-scope-notices"></ul>
</section>
</main>
<script id="executive-data" type="application/json">''' + payload + r'''</script>
<script>
"use strict";
const data = JSON.parse(document.getElementById("executive-data").textContent);
const dossier = data.dossier;
function add(parent, tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    parent.appendChild(element);
    return element;
}
document.getElementById("executive-notice").textContent = dossier.notice;
document.getElementById("executive-kpis").textContent =
    "Nodes Ready: " + dossier.node_counts.ready + "/" + dossier.node_counts.total +
    "; active snapshot incidents: " + dossier.incident_counts.total +
    "; open platform risks: " + data.register.open_risk_count + ".";
const oscal = dossier.oscal_posture;
document.getElementById("oscal-summary").textContent = oscal.framework +
    " | " + oscal.summary.total + " controls | Overall posture: " + oscal.summary.color;
const grid = document.getElementById("oscal-posture-grid");
for (const control of oscal.controls) {
    const card = add(grid, "article", "");
    add(card, "h3", control.control_id + " | " + control.title);
    add(card, "p", "Status: " + control.status + " | " + control.color);
    add(card, "p", "Evidence gap: " + control.coverage_gap);
}
const security = document.getElementById("security-planes-summary");
const chaos = dossier.chaos_containment;
const chaosCard = add(security, "article", "");
add(chaosCard, "h3", "Six-plane chaos containment");
add(chaosCard, "p", "Simulation status: " + chaos.status + "; contained planes: " +
    chaos.verified_plane_count + "/" + chaos.plane_count);
const planes = add(chaosCard, "ul", "");
for (const [name, plane] of Object.entries(chaos.planes)) {
    add(planes, "li", name + ": " + plane.status);
}
add(chaosCard, "p", "Simulation only; live enforcement is unverified.");
const quorum = dossier.raft_kms_quorum;
const quorumCard = add(security, "article", "");
add(quorumCard, "h3", "OpenBao Raft / KMS quorum");
add(quorumCard, "p", "Snapshot status: " + quorum.status + "; available members: " +
    quorum.available_members + "/" + quorum.expected_members +
    "; required majority: " + quorum.required_majority);
add(quorumCard, "p", quorum.coverage);
for (const [label, key] of [["Secret provenance", "openbao_provenance"],
    ["Ingress OIDC posture", "oidc_posture"]]) {
    const card = add(security, "article", "");
    add(card, "h3", label);
    add(card, "p", "Observed status: " + dossier[key].status);
}
document.getElementById("risk-notice").textContent = data.register.notice;
const rows = document.getElementById("platform-risk-rows");
for (const risk of data.register.risks) {
    const row = add(rows, "tr", "");
    for (const value of [risk.risk_id + " | " + risk.domain, risk.status,
        risk.observed_status, risk.remaining_live_evidence_required.join("\n")]) {
        add(row, "td", value);
    }
}
const scope = document.getElementById("executive-scope-notices");
for (const notice of [...dossier.scope_notices, oscal.notice, data.register.notice]) {
    add(scope, "li", notice);
}
</script>
</body>
</html>'''


def render_executive_brief_markdown(catalog=None) -> str:
    """Render a concise executive brief from sanitized, offline evidence.

    Accept the dossier's catalog inputs and resolve files once so both reports
    share a snapshot. Provider failures propagate. Escape dynamic Markdown and
    HTML after sanitization, without modifying the caller's catalog.
    """
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        try:
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ValueError("Unable to load executive snapshot") from None
    dossier = build_executive_posture_dossier(catalog)
    register = build_platform_risk_register(catalog, _dossier=dossier)
    oscal = dossier["oscal_posture"]
    nodes = dossier["node_counts"]
    incidents = dossier["incident_counts"]

    def text(value):
        value = escape(" ".join(str(sanitize(value)).split()), quote=False)
        return re.sub(r"([\\`*_{}\[\]()#+!|~])", r"\\\1", value)

    def row(*values):
        return "| " + " | ".join(text(value) for value in values) + " |"

    lines = [
        "# Executive Brief", "",
        text(dossier["notice"]), "",
        "## Key performance indicators", "",
        "| KPI | Snapshot / local result |",
        "| --- | --- |",
        row("Nodes Ready / observed", f"{nodes['ready']} / {nodes['total']}"),
        row("Nodes not Ready", nodes["not_ready"]),
        row("Active snapshot incidents", incidents["total"]),
    ]
    for severity, count in incidents["by_severity"].items():
        lines.append(row(severity + " incidents", count))
    lines.extend([
        row("OSCAL posture", oscal["summary"]["color"]),
        row("OSCAL controls mapped", oscal["summary"]["total"]),
        row("Open platform risks", register["open_risk_count"]),
        row("Live enforcement verified", "No"),
        "", "## Governance indicators", "",
        "| Domain | Observed status |", "| --- | --- |",
    ])
    for label, key in (
            ("Six-plane chaos containment", "chaos_containment"),
            ("OpenBao secret provenance", "openbao_provenance"),
            ("Raft / KMS quorum", "raft_kms_quorum"),
            ("Ingress OIDC posture", "oidc_posture")):
        lines.append(row(label, dossier[key]["status"]))
    lines.extend([
        "", "## OSCAL control statuses", "", text(oscal["framework"]), "",
        "| Control | Title | Status | Color | Evidence gap |",
        "| --- | --- | --- | --- | --- |",
    ])
    for control in oscal["controls"]:
        lines.append(row(*(control[key] for key in (
            "control_id", "title", "status", "color", "coverage_gap"))))
    lines.extend([
        "", "## Platform risk register", "",
        "All risks remain open pending operational evidence; local passes do "
        "not close live evidence gaps.", "",
        "| Risk | Domain | Status | Observed status | Required operational evidence |",
        "| --- | --- | --- | --- | --- |",
    ])
    for risk in register["risks"]:
        lines.append(row(risk["risk_id"], risk["domain"], risk["status"],
                         risk["observed_status"],
                         " ".join(risk["remaining_live_evidence_required"])))
    lines.extend(["", "## Evidence scope and non-certification notice", ""])
    lines.extend("- " + text(notice) for notice in (
        *dossier["scope_notices"], oscal["notice"], register["notice"]))
    return "\n".join(lines) + "\n"


def build_platform_risk_register(catalog=None, _dossier=None) -> dict:
    """Contrast snapshot/local controls with outstanding operational evidence.

    Accept the same inputs as the executive dossier. Provider errors propagate;
    missing observations never establish control effectiveness. This runs local
    repository gates, but performs no live collection or fault injection. All
    risks remain open pending operational evidence, even when local checks pass.
    The complete return value passes through the telemetry sanitizer.
    """
    dossier = _dossier if _dossier is not None else build_executive_posture_dossier(catalog)
    gates = run_six_gate_prepush_audit()
    provenance = dossier["openbao_provenance"]
    quorum = dossier["raft_kms_quorum"]
    oidc = dossier["oidc_posture"]
    chaos = dossier["chaos_containment"]
    nodes = dossier["node_counts"]
    oscal = dossier["oscal_posture"]

    def risk(identifier, domain, status, observations, required):
        return {
            "risk_id": identifier, "domain": domain,
            "status": "open", "observed_status": status,
            "observed_evidence": observations,
            "remaining_live_evidence_required": required,
            "live_enforcement_verified": False,
        }

    risks = [
        risk("PR-01", "Secret Provenance", provenance["status"], {
            "provenance": provenance, "raft_kms_quorum": quorum,
        }, [
            "Verify live OpenBao Raft membership, leader and voting quorum; "
            "exercise KMS seal/unseal and recovery.",
            "Collect redacted secret issuance, rotation, revocation and audit "
            "records linking workloads to OpenBao; identity hashes alone do "
            "not prove secret origin or absence of plaintext.",
        ]),
        risk("PR-02", "Ingress OIDC Coverage", oidc["status"], oidc, [
            "Test each live ingress for unauthenticated rejection and valid "
            "OIDC login, issuer, audience, signature and expiry validation.",
            "Capture group authorization allow/deny results, TLS validation "
            "and bypass checks for direct backend routes.",
        ]),
        risk("PR-03", "Six-Plane Chaos Containment", chaos["status"], chaos, [
            "Run authorized fault exercises across all six planes and record "
            "observed blast radius, isolation, recovery time and service impact.",
            "Validate network policy enforcement and shared hardware, control, "
            "identity and storage failure dependencies outside the simulation.",
        ]),
        risk("PR-04", "Node Readiness & Capacity",
             "unknown" if not nodes["total"] else (
                 "degraded" if nodes["not_ready"] else "ready_observed_nodes"), {
                 "node_counts": nodes, "incident_counts": dossier["incident_counts"],
                 "coverage": "Snapshot Ready conditions only; these counts "
                             "do not establish schedulable capacity or headroom.",
             }, [
                 "Collect fresh node readiness, pressure conditions, allocatable "
                 "CPU/memory, workload requests/limits and utilization history.",
                 "Validate peak-load headroom and N-1 drain/recovery with "
                 "scheduling, disruption budget and storage constraints.",
             ]),
        risk("PR-05", "CI/CD Golden Path Gates",
             "passed_local_checks" if gates["passed"] else "failed_local_checks",
             gates, [
                 "Capture CI execution records for the exact release revision "
                 "and verify branch protections enforce all required gates.",
                 "Collect artifact provenance, vulnerability scans, deployment "
                 "approval, reconciliation and rollback verification records.",
             ]),
        risk("PR-06", "NIST 800-53 Evidence Gaps", oscal["summary"]["color"], {
            "framework": oscal["framework"], "summary": oscal["summary"],
            "controls": [{"control_id": control["control_id"],
                          "status": control["status"],
                          "coverage_gap": control["coverage_gap"]}
                         for control in oscal["controls"]],
        }, [control["control_id"] + ": " + control["coverage_gap"]
            for control in oscal["controls"]]),
    ]
    return sanitize({
        "notice": "Snapshot observations, simulations and local repository "
                  "checks only; operational evidence remains outstanding. "
                  "This register is not NIST or FedRAMP certification.",
        "live_enforcement_verified": False,
        "risk_count": len(risks), "open_risk_count": len(risks),
        "risks": risks,
    })


def build_executive_posture_dossier(catalog=None) -> dict:
    """Combine component evidence without claiming certification or enforcement.

    Accept a graph dict, JSON path, or None for the bundled sanitized snapshot.
    File inputs are read once so all providers observe the same snapshot. Local
    repository policy checks run through the OSCAL evaluator; no collection,
    credential retrieval, fault injection, or cluster changes occur. Provider
    errors propagate rather than being replaced with reassuring empty counts.
    Returned evidence is sanitized without mutating the caller's catalog.
    """
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        try:
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ValueError("Unable to load executive snapshot") from None
    if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
        raise ValueError("Executive snapshot must contain a nodes array")

    # Audit original fields before redaction so sensitive literals still count
    # as findings; each provider limits its own evidence output.
    oscal = evaluate_live_oscal_posture(catalog)
    chaos = verify_all_six_chaos_planes(catalog)
    provenance = audit_openbao_secret_provenance(catalog)
    quorum = verify_raft_kms_quorum(catalog)
    oidc = audit_cluster_ingress_oidc_posture(catalog)
    incidents = incident_commander.build_active_incidents_catalog(catalog)
    capacity = capacity_planner.summarize_cluster_capacity(catalog)
    return sanitize({
        "notice": "Local policy and snapshot observations only; this dossier is not "
                  "NIST or FedRAMP certification and does not establish live enforcement.",
        "live_enforcement_verified": False,
        "oscal_posture": oscal,
        "chaos_containment": chaos,
        "openbao_provenance": provenance,
        "raft_kms_quorum": quorum,
        "oidc_posture": oidc,
        "incident_counts": incidents["summary_counts"],
        "node_counts": capacity["node_counts"],
        "scope_notices": [incidents["notice"], capacity["notice"]],
    })


def _executive_report(catalog):
    return {"dossier": build_executive_posture_dossier(catalog),
            "register": build_platform_risk_register(catalog)}


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid executive command center request")


def _build_executive_handler(catalog):
    """Prepare offline responses without logging request contents."""
    responses = {
        "/": (render_executive_command_center_html(catalog), "text/html"),
        "/api/v1/executive-summary": (
            json.dumps(_executive_report(catalog), indent=2, allow_nan=False),
            "application/json"),
        "/executive/brief.md": (
            render_executive_brief_markdown(catalog), "text/markdown"),
    }
    responses["/executive"] = responses["/"]

    class ExecutiveRequestHandler(BaseHTTPRequestHandler):
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
                    self._send(400, '{"error":"Invalid executive request"}', "application/json")
                    return
                response = responses.get(url.path)
            except ValueError:
                self._send(400, '{"error":"Invalid executive request"}', "application/json")
                return
            if response is None:
                self._send(404, '{"error":"Not found"}', "application/json")
                return
            self._send(200, *response)

    return ExecutiveRequestHandler


def main(argv=None) -> int:
    """Export executive evidence or serve the dashboard on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="executive_command_center",
                                 description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8094)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    try:
        catalog = json.loads((args.catalog or DEFAULT_CATALOG_PATH).read_text(encoding="utf-8"))
        if args.serve:
            handler = _build_executive_handler(catalog)
            with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
                print(f"Executive command center: http://127.0.0.1:{args.port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_executive_brief_markdown(catalog), end="")
        else:
            print(json.dumps(_executive_report(catalog), indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete executive request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
