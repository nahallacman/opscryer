# SPDX-License-Identifier: Apache-2.0
"""Read-only GitOps and CI posture from sanitized cluster snapshots."""

import argparse
from collections import Counter
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import golden_path_gates
import openbao_kms_provenance
from live_gitops_signals import derive_live_gitops_and_ci_signals
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
NAMESPACES = ("argocd", "gitlab", "harbor", "devops-tools", "e2e-testing")
_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
_RUNNER = re.compile(r"gitlab[-_ .]*runner", re.IGNORECASE)
_CI = re.compile(r"(?:gitlab[-_ .]*runner|github[-_ .]*runner|actions[-_ .]*runner|"
                 r"ci[-_ .]*runner|runner[-_ .]|jenkins)", re.IGNORECASE)


def render_gitops_cockpit_html(catalog=None) -> str:
    """Return a self-contained, sanitized cockpit for local snapshot evidence."""
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if catalog is None:
        raise ValueError("Invalid GitOps catalog")
    evidence = {
        "scorecard": evaluate_release_readiness_scorecard(catalog),
        "triage": triage_ci_and_renovate_jobs(catalog),
    }
    # Script data still passes through the HTML parser before JSON.parse.
    payload = (json.dumps(sanitize(evidence), allow_nan=False)
               .replace("&", "\\u0026").replace("<", "\\u003c")
               .replace(">", "\\u003e"))
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>OpsCryer | GitOps &amp; CI/CD Release Cockpit</title>
<style>
:root { color-scheme: dark; background: #0b1220; color: #e2e8f0;
    font-family: system-ui, sans-serif; }
body { max-width: 1400px; margin: auto; padding: 24px; line-height: 1.6; }
nav { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 28px; }
a { color: #7dd3fc; } a[aria-current] { font-weight: bold; }
section, #release-readiness-banner { background: #111c30; border: 1px solid #334155;
    border-radius: 12px; padding: 20px; margin: 24px 0; }
#golden-path-gates-strip { display: grid; gap: 12px; padding: 0; list-style: none;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); }
#golden-path-gates-strip li { background: #0b1220; padding: 16px; border-radius: 8px; }
.pass { color: #86efac; } .fail { color: #fda4af; }
.table-scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; text-align: left; }
caption { text-align: left; padding-bottom: 12px; }
th, td { border-bottom: 1px solid #334155; padding: 12px; vertical-align: top;
    white-space: pre-line; overflow-wrap: anywhere; }
th { color: #7dd3fc; } p, li { overflow-wrap: anywhere; }
:focus-visible { outline: 3px solid #7dd3fc; outline-offset: 3px; }
</style>
</head>
<body>
<nav aria-label="Main navigation">
<a href="/">Overview</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops" aria-current="page">GitOps</a>
</nav>
<main>
<h1>GitOps &amp; CI/CD Release Cockpit</h1>
<p>Read-only snapshot evidence and local repository checks captured when this page was generated.</p>
<div id="release-readiness-banner" role="status" aria-live="polite">
Release readiness has not been displayed. Enable JavaScript to view the embedded evidence.
</div>
<noscript>Enable JavaScript to view the gate results and job triage reports.</noscript>
<section aria-labelledby="gates-heading">
<h2 id="gates-heading">6-Gate Golden Path status</h2>
<ul id="golden-path-gates-strip" aria-label="Six local pre-push gate results"></ul>
</section>
<section aria-labelledby="posture-heading">
<h2 id="posture-heading">GitOps and CI inventory</h2>
<p id="gitops-summary"></p><p id="gitops-provenance"></p><p id="gitops-notice"></p>
</section>
<section aria-labelledby="jobs-heading">
<h2 id="jobs-heading">Renovate / CI job triage</h2>
<p id="triage-notice"></p>
<div class="table-scroll"><table>
<caption>Observed runs and separate CronJob schedules; commands are read-only reference text</caption>
<thead><tr><th scope="col">Namespace / workload</th><th scope="col">Category</th>
<th scope="col">State</th><th scope="col">Remediation guidance</th>
<th scope="col">Inspection commands</th></tr></thead>
<tbody id="renovate-jobs-list"></tbody>
</table></div></section>
<section aria-labelledby="scope-heading">
<h2 id="scope-heading">Release evidence scope</h2><ul id="release-scope-notices"></ul>
</section>
</main>
<script id="gitops-data" type="application/json">''' + payload + r'''</script>
<script>
"use strict";
const data = JSON.parse(document.getElementById("gitops-data").textContent);
function add(parent, tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    parent.appendChild(element);
    return element;
}
function result(value) { return value === true ? "PASS" : "FAIL"; }
const scorecard = data.scorecard;
const banner = document.getElementById("release-readiness-banner");
banner.textContent = (scorecard.release_ready === true ?
    "READY for local pre-merge review" : "BLOCKED: local release checks require attention") +
    ". Six gates: " + result(scorecard.gates_passed) +
    "; secret provenance: " + result(scorecard.secret_provenance_clean) +
    "; CLI entrypoints: " + result(scorecard.cli_entrypoints_ready) +
    ". Local checks only; production deployment approval and live health are unverified.";
banner.className = scorecard.release_ready === true ? "pass" : "fail";
const strip = document.getElementById("golden-path-gates-strip");
for (const [name, label] of [
    ["crlf", "LF line endings"], ["opsec", "OPSEC sanitization"],
    ["spdx", "SPDX licensing"], ["graph_contract", "Graph contract"],
    ["commit_subject", "Commit subject"], ["epic_locks", "Epic file locks"]]) {
    const gate = scorecard.golden_path_gates.gates[name];
    const item = add(strip, "li", label + ": " + (gate ? result(gate.passed) : "UNKNOWN") +
        (gate ? "\nViolations: " + gate.violations + "; errors: " + gate.errors : ""));
    item.className = gate && gate.passed === true ? "pass" : "fail";
}
const posture = scorecard.gitops_and_ci_posture;
document.getElementById("gitops-summary").textContent =
    posture.counts.workloads + " workload inventory objects; " +
    posture.runner_counts.active + " active GitLab runner pods; " +
    posture.runner_counts.ready + " ready active runner pods.";
document.getElementById("gitops-provenance").textContent =
    "Source: " + posture.source + "; collected: " +
    (posture.provenance.collected_at || "not recorded") +
    "; example snapshot: " + (posture.example ? "yes" : "no");
document.getElementById("gitops-notice").textContent = posture.notice;
document.getElementById("triage-notice").textContent = data.triage.notice;
const jobs = document.getElementById("renovate-jobs-list");
for (const job of [...data.triage.runs, ...data.triage.cronjobs]) {
    const tr = add(jobs, "tr", "");
    for (const value of [job.namespace + " / " + (job.kind || "CronJob") + "/" + job.name,
        job.category, job.state + (job.schedule ? "\nSchedule: " + job.schedule : ""),
        job.remediation_steps.join("\n"), job.commands.join("\n") || "No safe command available"]) {
        add(tr, "td", value);
    }
}
if (!jobs.children.length) {
    const cell = add(add(jobs, "tr", ""), "td", "No CI or Renovate runs or job schedules observed.");
    cell.colSpan = 5;
}
const scope = document.getElementById("release-scope-notices");
for (const notice of scorecard.scope_notices) add(scope, "li", notice);
for (const error of posture.provenance.errors) add(scope, "li", "Snapshot collection error: " + error);
</script>
</body>
</html>'''


def render_release_evidence_markdown(catalog=None) -> str:
    """Export a sanitized pre-merge dossier from local checks and a snapshot.

    Accept the same inputs as the scorecard. Resolve file inputs once so all
    snapshot summaries share evidence. Sanitize before escaping untrusted text
    for Markdown; retain scope notices without implying deployment approval.
    """
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if catalog is None:
        raise ValueError("Invalid GitOps catalog")
    scorecard = sanitize(evaluate_release_readiness_scorecard(catalog))
    triage = sanitize(triage_ci_and_renovate_jobs(catalog))
    posture = scorecard["gitops_and_ci_posture"]

    def text(value):
        value = escape(" ".join(str(sanitize(value)).split()), quote=False)
        return re.sub(r"([\\`*_{}\[\]()#+!|~])", r"\\\1", value)

    def result(value):
        return "PASS" if value is True else "FAIL"

    def row(*values):
        return "| " + " | ".join(text(value) for value in values) + " |"

    lines = [
        "# Pre-merge Release Readiness Evidence", "",
        "## Release readiness scorecard", "",
        "| Check | Result |", "| --- | --- |",
    ]
    for label, key in (
            ("Release ready (local checks only)", "release_ready"),
            ("Six Golden Path gates", "gates_passed"),
            ("Secret provenance clean", "secret_provenance_clean"),
            ("CLI entrypoints ready", "cli_entrypoints_ready")):
        lines.append(row(label, result(scorecard[key])))
    lines.extend([
        "", "## Six-gate audit", "",
        "| Gate | Result | Violations | Errors |", "| --- | --- | --- | --- |",
    ])
    for name, gate in scorecard["golden_path_gates"]["gates"].items():
        lines.append(row(name, result(gate["passed"]), gate["violations"], gate["errors"]))
    lines.extend([
        "", "## GitOps and CI summary", "",
        "Source: " + text(posture["source"]), "",
        "Collected at: " + text(posture["provenance"]["collected_at"] or "Not recorded"), "",
        "Example snapshot: " + ("Yes" if posture["example"] else "No"), "",
        text(posture["notice"]), "",
        "Total workload inventory objects: " + text(posture["counts"]["workloads"]), "",
        "| Namespace | Workloads | Pods | Deployments | Jobs | CronJobs |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for namespace, entry in posture["namespaces"].items():
        kinds = entry["workloads_by_kind"]
        lines.append(row(namespace, entry["workload_count"],
                         *(kinds[kind] for kind in ("Pod", "Deployment", "Job", "CronJob"))))
    runners = posture["runner_counts"]
    lines.extend([
        "", "GitLab runner pods: " + text(runners["pods"])
        + "; active: " + text(runners["active"])
        + "; ready active subset: " + text(runners["ready"])
        + "; deployments: " + text(runners["deployments"]) + ".",
        "", "## CI and Renovate job summary", "", text(triage["notice"]), "",
        "| Category | Runs | Succeeded | Failed | Active | Unknown | CronJobs |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for category in ("ci", "renovate", "other"):
        runs = [run for run in triage["runs"] if run["category"] == category]
        states = Counter(run["state"] for run in runs)
        schedules = sum(cron["category"] == category for cron in triage["cronjobs"])
        lines.append(row(category, len(runs), *(states[state] for state in
                         ("succeeded", "failed", "active", "unknown")), schedules))
    lines.extend([
        "", "Total runs: " + text(triage["counts"]["runs"])
        + "; terminal: " + text(triage["counts"]["terminal"])
        + "; owned Pods (not additional runs): " + text(triage["counts"]["owned_pods"]) + ".",
        "", "## Evidence scope", "",
    ])
    lines.extend("- " + text(notice) for notice in scorecard["scope_notices"])
    errors = posture["provenance"]["errors"]
    if errors:
        lines.extend(["", "### Snapshot collection errors", ""])
        lines.extend("- " + text(error) for error in errors)
    return "\n".join(lines) + "\n"


def evaluate_release_readiness_scorecard(catalog=None) -> dict:
    """Combine local checks and snapshot evidence into a scoped scorecard.

    Readiness requires all three audit flags to be explicitly True. Inventory
    is supporting context, not an additional health attestation. Provenance is
    audited before sanitizing the combined report so literals remain detectable.
    Invalid catalogs propagate the underlying validation errors.
    """
    # Resolve files once so posture and provenance inspect the same snapshot.
    default_snapshot = catalog is None
    from_file = default_snapshot or isinstance(catalog, (str, Path))
    if default_snapshot:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if catalog is None:
        raise ValueError("Invalid GitOps catalog")
    provenance = openbao_kms_provenance.audit_openbao_secret_provenance(catalog)
    posture = summarize_gitops_and_ci_posture(catalog)
    posture["provenance"].update(
        input_kind="json_file" if from_file else "provided_catalog",
        snapshot_file=DEFAULT_CATALOG_PATH.name if default_snapshot else None)
    gates = golden_path_gates.run_six_gate_prepush_audit()
    entrypoints = golden_path_gates.verify_public_cli_entrypoints()
    gates_passed = gates.get("passed") is True
    secret_clean = provenance.get("zero_plaintext_leakage") is True
    cli_ready = entrypoints.get("passed") is True
    return sanitize({
        "release_ready": gates_passed and secret_clean and cli_ready,
        "gates_passed": gates_passed,
        "secret_provenance_clean": secret_clean,
        "cli_entrypoints_ready": cli_ready,
        "golden_path_gates": gates,
        "secret_provenance": provenance,
        "cli_entrypoints": entrypoints,
        "gitops_and_ci_posture": posture,
        "scope_notices": [
            "Release readiness covers local repository checks and observed snapshot fields only; "
            "it is not production deployment approval or live release verification.",
            "The six gates inspect the current working tree and HEAD commit; CLI checks "
            "verify callable main functions without executing CLI commands.",
            "Secret provenance covers recognized literals in observed fields only; missing "
            "specs and arbitrary literals cannot be verified. No secrets are retrieved; "
            "live OpenBao Raft membership and KMS/seal health are not verified.",
            "GitOps and CI posture is snapshot inventory only; runner registration, pipeline "
            "success, reconciliation, and current workload health are not verified.",
            "Container security contexts, image vulnerabilities, signatures, and runtime "
            "security are not assessed by these checks.",
        ],
    })


def triage_ci_and_renovate_jobs(catalog=None) -> dict:
    """Classify snapshot runs without counting a Job's owned Pods again.

    All Jobs and CronJobs are inspected, plus standalone Renovate/CI runner
    Pods. CronJobs are schedules, not completed runs. True Job conditions take
    precedence over counters; failed attempts alone do not prove Job failure.
    Ownership is namespace-scoped and UID-first (name fallback only without a
    UID). Missing owners leave Pods visible. No commands are executed and no
    historical throughput, registration, or release readiness is inferred.
    """
    default_snapshot = catalog is None
    from_file = default_snapshot or isinstance(catalog, (str, Path))
    if default_snapshot:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if catalog is None:
        raise ValueError("Invalid GitOps catalog")
    # Keep catalog validation consistent with the existing posture API.
    derive_live_gitops_and_ci_signals(catalog)
    snapshot = sanitize(catalog)

    def kind(node):
        return node.get("resource_kind", node.get("resource", {}).get("kind"))

    def meta(node):
        return node.get("resource", {}).get("metadata", {})

    def namespace(node):
        return node.get("namespace", meta(node).get("namespace")) or "default"

    def name(node):
        return meta(node).get("name") or node.get("label") or node["id"]

    nodes = sorted(snapshot["nodes"], key=lambda node: node["id"])
    jobs = [node for node in nodes if kind(node) == "Job"]
    crons = [node for node in nodes if kind(node) == "CronJob"]
    controllers = jobs + crons
    by_uid = {(namespace(node), kind(node), meta(node)["uid"]): node
              for node in controllers if meta(node).get("uid")}
    by_name = {(namespace(node), kind(node), name(node)): node for node in controllers}

    def owner(node, owner_kind):
        for ref in meta(node).get("ownerReferences", []):
            if ref.get("kind") != owner_kind or ref.get("controller") is False:
                continue
            key = (namespace(node), owner_kind)
            found = (by_uid.get(key + (ref["uid"],)) if ref.get("uid") else
                     by_name.get(key + (ref.get("name"),)))
            if found is not None:
                return found
        return None

    children = {node["id"]: [] for node in jobs}
    standalone = []
    for node in nodes:
        if kind(node) == "Pod":
            parent = owner(node, "Job")
            if parent is not None:
                children[parent["id"]].append(node)
            else:
                standalone.append(node)

    def category(group):
        values = []
        for node in group:
            values.extend([name(node), node.get("label", ""),
                           *meta(node).get("labels", {}).values()])
        exporter = any(re.search(r"renovate[-_ .]*exporter", str(value), re.I)
                       for value in values)
        if not exporter and any(re.search(r"\brenovate\b", str(value), re.I) for value in values):
            return "renovate"
        if any(_CI.search(str(value)) for value in values):
            return "ci"
        return "other"

    def number(status, key):
        value = status.get(key, 0)
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0

    def classify(node):
        status = node.get("resource", {}).get("status", {})
        if kind(node) == "Pod":
            phase = status.get("phase", "Unknown")
            return {"Succeeded": "succeeded", "Failed": "failed",
                    "Running": "active", "Pending": "active"}.get(phase, "unknown")
        conditions = {condition.get("type") for condition in status.get("conditions", [])
                      if condition.get("status") == "True"}
        if "Failed" in conditions:
            return "failed"
        if "Complete" in conditions:
            return "succeeded"
        if "FailureTarget" in conditions:
            return "active"  # Termination can still be in progress.
        if number(status, "active"):
            return "active"
        completions = node.get("resource", {}).get("spec", {}).get("completions", 1)
        if (isinstance(completions, int) and not isinstance(completions, bool)
                and completions > 0 and number(status, "succeeded") >= completions):
            return "succeeded"
        if status.get("startTime") or number(status, "failed") or number(status, "succeeded"):
            return "active"
        return "unknown"

    def commands(node):
        ns, resource_name = namespace(node), name(node)
        # Only literal Kubernetes identifiers can enter copyable shell commands.
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value)
                   for value in (ns, resource_name)):
            return []
        target = f"{kind(node).lower()}/{resource_name}"
        result = [f"kubectl get {target} -n {ns} -o wide",
                  f"kubectl describe {target} -n {ns}"]
        if kind(node) in {"Pod", "Job"}:
            result.append(f"kubectl logs {target} -n {ns} --all-containers=true --tail=100")
        return result

    guidance = {
        "failed": ["Inspect status, events, and bounded logs with the read-only commands.",
                   "Review the CI pipeline or Renovate configuration in Git; check referenced "
                   "credentials and image availability without exporting secret values.",
                   "Propose the smallest configuration fix through the Golden Path merge request; "
                   "run python golden_path_gates.py before merge.",
                   "After the approved GitOps reconciliation, inspect the next run for success."],
        "active": ["Inspect progress and failed attempts; confirm retries and scheduling in events.",
                   "If blocked, propose a Git configuration fix through the Golden Path and run "
                   "python golden_path_gates.py before merge."],
        "succeeded": ["Retain terminal run evidence for Golden Path review; no remediation indicated."],
        "unknown": ["Collect missing status with the read-only commands before deciding remediation."]}
    runs = []
    for node in jobs + standalone:
        pods = children.get(node["id"], [])
        cron = owner(node, "CronJob") if kind(node) == "Job" else None
        workload_type = category([node, *pods] + ([cron] if cron is not None else []))
        if kind(node) == "Pod" and workload_type == "other":
            continue
        state = classify(node)
        pod_states = Counter(classify(pod) for pod in pods)
        if state == "unknown" and pod_states["active"]:
            state = "active"
        runs.append({
            "node_id": node["id"], "namespace": namespace(node), "kind": kind(node),
            "name": name(node), "category": workload_type, "state": state,
            "terminal": state in {"succeeded", "failed"},
            "deleting": bool(meta(node).get("deletionTimestamp")),
            "cronjob_id": cron["id"] if cron is not None else None,
            "owned_pod_ids": [pod["id"] for pod in pods],
            "owned_pods_by_state": dict(sorted(pod_states.items())),
            "failed_attempts": number(node.get("resource", {}).get("status", {}), "failed")
                               if kind(node) == "Job" else int(state == "failed"),
            "remediation_steps": guidance[state][:], "commands": commands(node),
        })
    runs.sort(key=lambda run: run["node_id"])
    schedules = []
    for cron in crons:
        resource = cron.get("resource", {})
        schedules.append({
            "node_id": cron["id"], "namespace": namespace(cron), "name": name(cron),
            "category": category([cron]), "state": "suspended" if
            resource.get("spec", {}).get("suspend", False) else "scheduled",
            "schedule": resource.get("spec", {}).get("schedule"),
            "active_references": len(resource.get("status", {}).get("active", [])),
            "observed_job_ids": [run["node_id"] for run in runs
                                 if run["cronjob_id"] == cron["id"]],
            "commands": commands(cron),
            "remediation_steps": ["Inspect schedule, suspension, and child Job evidence; "
                                  "a schedule alone does not establish a run result."],
        })
    counts = Counter(run["state"] for run in runs)
    return sanitize({
        "source": snapshot.get("source", "provided_catalog"),
        "example": snapshot.get("example", False),
        "provenance": {"mode": "offline_snapshot", "live_collection": False,
                       "input_kind": "json_file" if from_file else "provided_catalog",
                       "snapshot_file": DEFAULT_CATALOG_PATH.name if default_snapshot else None,
                       "collected_at": snapshot.get("collected_at"),
                       "errors": snapshot.get("errors", [])},
        "notice": "Snapshot only. Job conditions govern run results; failed attempts may retry. "
                  "Owned Pods are evidence, not additional runs. CronJobs are separate schedules. "
                  "Missing status is unknown; no live checks or commands were executed.",
        "counts": {"runs": len(runs), "terminal": counts["succeeded"] + counts["failed"],
                   **{state: counts[state] for state in ("succeeded", "active", "failed", "unknown")},
                   "cronjobs": len(crons),
                   "owned_pods": sum(len(pods) for pods in children.values())},
        "runs": runs, "cronjobs": schedules,
    })


def summarize_gitops_and_ci_posture(catalog=None) -> dict:
    """Summarize the bundled snapshot, a JSON path, or a catalog dictionary.

    Workload counts are Kubernetes inventory objects, including terminal pods;
    pods and their controllers are counted separately by kind. Active runners
    are matching Running pods without a deletion timestamp, not registered CI
    runners, execution slots, or throughput. Readiness is reported separately.
    Missing namespaces remain explicit zero-observation entries. Inputs are
    validated by the existing signal builder, sanitized, and never modified.
    No network calls or current timestamps are used.
    """
    default_snapshot = catalog is None
    from_file = default_snapshot or isinstance(catalog, (str, Path))
    if default_snapshot:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if catalog is None:
        raise ValueError("Invalid GitOps catalog")
    signals = derive_live_gitops_and_ci_signals(catalog)
    snapshot = sanitize(catalog)
    namespaces = {}
    runner_counts = Counter({"pods": 0, "active": 0, "ready": 0, "deployments": 0})
    for namespace in NAMESPACES:
        workloads = []
        kinds = Counter()
        phases = Counter()
        for node in sorted(snapshot["nodes"], key=lambda item: item["id"]):
            resource = node.get("resource", {})
            metadata = resource.get("metadata", {})
            if node.get("namespace", metadata.get("namespace")) != namespace:
                continue
            kind = node.get("resource_kind", resource.get("kind"))
            if kind not in _WORKLOAD_KINDS:
                continue
            status = resource.get("status", {})
            phase = status.get("phase") or "Unknown" if kind == "Pod" else None
            deleting = bool(metadata.get("deletionTimestamp"))
            ready = kind == "Pod" and any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in status.get("conditions", []))
            values = [node.get("label", ""), metadata.get("name", "")]
            values.extend(metadata.get("labels", {}).values())
            runner = kind in {"Pod", "Deployment"} and any(
                _RUNNER.search(str(value)) for value in values)
            active_runner = runner and kind == "Pod" and phase == "Running" and not deleting
            if runner:
                runner_counts["pods" if kind == "Pod" else "deployments"] += 1
                runner_counts["active"] += int(active_runner)
                runner_counts["ready"] += int(active_runner and ready)
            kinds[kind] += 1
            if kind == "Pod":
                phases[phase] += 1
            workloads.append({
                "node_id": node["id"], "kind": kind,
                "name": metadata.get("name") or node.get("label") or node["id"],
                "phase": phase, "ready": ready if kind == "Pod" else None,
                "deleting": deleting, "runner": runner, "active_runner": active_runner,
            })
        namespaces[namespace] = {
            "workload_count": len(workloads),
            "workloads_by_kind": {kind: kinds[kind] for kind in sorted(_WORKLOAD_KINDS)},
            "pods_by_phase": dict(sorted(phases.items())), "workloads": workloads,
        }
    return sanitize({
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
        "notice": "Snapshot inventory only; absent workloads are not proof of absence. "
                  "Active runners are Running, non-deleting GitLab runner pods; ready is "
                  "the Ready subset. Controllers and pods are separate inventory objects. "
                  "CI slots, registration, throughput, and release readiness are not verified.",
        "counts": {
            "workloads": sum(entry["workload_count"] for entry in namespaces.values()),
            "argocd_workloads": namespaces["argocd"]["workload_count"],
            "gitlab_workloads": namespaces["gitlab"]["workload_count"],
            "active_runners": runner_counts["active"],
        },
        "runner_counts": dict(runner_counts),
        "namespaces": namespaces,
        "signals": signals,
    })


def _gitops_report(catalog):
    return {"scorecard": evaluate_release_readiness_scorecard(catalog),
            "triage": triage_ci_and_renovate_jobs(catalog)}


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid GitOps cockpit arguments")


def _build_gitops_handler(catalog):
    """Validate and serve offline evidence without logging request contents."""
    responses = {
        "/": (render_gitops_cockpit_html(catalog), "text/html"),
        "/api/v1/gitops-cockpit": (
            json.dumps(_gitops_report(catalog), indent=2, allow_nan=False),
            "application/json"),
        "/gitops/evidence.md": (render_release_evidence_markdown(catalog), "text/markdown"),
    }
    responses["/gitops"] = responses["/"]

    class GitOpsRequestHandler(BaseHTTPRequestHandler):
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
                    self._send(400, '{"error":"Invalid GitOps request"}', "application/json")
                    return
                response = responses.get(url.path)
            except ValueError:
                self._send(400, '{"error":"Invalid GitOps request"}', "application/json")
                return
            if response is None:
                self._send(404, '{"error":"Not found"}', "application/json")
                return
            self._send(200, *response)

    return GitOpsRequestHandler


def main(argv=None) -> int:
    """Export sanitized release evidence or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="gitops_release_cockpit",
                                 description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8093)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    try:
        catalog = json.loads((args.catalog or DEFAULT_CATALOG_PATH).read_text(encoding="utf-8"))
        if catalog is None:
            raise ValueError("Invalid GitOps catalog")
        if args.serve:
            handler = _build_gitops_handler(catalog)
            with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
                print(f"GitOps cockpit: http://127.0.0.1:{args.port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_release_evidence_markdown(catalog), end="")
        else:
            print(json.dumps(_gitops_report(catalog), indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete GitOps request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
