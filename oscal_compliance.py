# SPDX-License-Identifier: Apache-2.0
"""NIST SP 800-53 Rev. 5 mappings, opt-in evidence assessment and OSCAL export.

Test links identify supporting automated checks, not execution results or a
certification. Callers supply assessment statuses; omitted controls are BLUE.
Live assessment is opt-in and covers local policy and snapshot observations only.
"""

import argparse
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from uuid import uuid4

from chaos_blast_radius import verify_all_six_chaos_planes
from golden_path_gates import run_six_gate_prepush_audit
from oidc_rbac_verifier import audit_cluster_ingress_oidc_posture
from openbao_kms_provenance import (
    audit_openbao_secret_provenance, verify_raft_kms_quorum,
)
from security_airlock import audit_container_security_context, evaluate_code_search_airlock


OSCAL_VERSION = "1.1.3"
CATALOG_SOURCE = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
_NS = "https://opscryer.org/ns/compliance"
_STATUS_COLORS = {
    "passed": "GREEN", "partial": "YELLOW", "failed": "RED",
    "pending": "ORANGE", "manual_review": "PURPLE", "not_assessed": "BLUE",
}
_NOTICE = (
    "Supporting test references only; tests are not executed by this exporter. "
    "Statuses are caller assertions, not NIST or FedRAMP certification."
)
# Control, title, implementation scope, remaining coverage, unittest identifier.
_CONTROLS = (
    ("AC-2", "Account Management", "Graph identity and open-ticket ownership lookup.",
     "Account provisioning, review and deprovisioning require external IAM evidence.",
     "tests.test_dogfood_graph.DogfoodGraphTests."
     "test_person_lookup_matches_exact_identity_and_only_open_assigned_work"),
    ("AC-6", "Least Privilege", "Argus rejects privileged container contexts.",
     "Workload checks do not establish organization-wide least privilege.",
     "tests.test_security_airlock.ContainerSecurityTests."
     "test_each_setting_fails_independently_including_wrong_types"),
    ("AU-6", "Audit Record Review, Analysis, and Reporting",
     "Pre-push audit aggregates six policy gate results.",
     "Operational audit log review and retention require additional evidence.",
     "tests.test_golden_path_gates.TestSixGateAudit.test_clean_checkout_passes_all_six_gates"),
    ("CM-2", "Baseline Configuration", "Container security context policy defines a baseline.",
     "An approved system baseline and change history remain external.",
     "tests.test_security_airlock.ContainerSecurityTests."
     "test_valid_context_and_wrapped_container_are_not_mutated"),
    ("CM-8", "System Component Inventory", "Spatial graph validates inventory references.",
     "Graph validity does not prove live inventory completeness or freshness.",
     "tests.test_opscryer_backend.SpatialContractTests.test_shared_sample_and_custom_kinds_are_valid"),
    ("IR-4", "Incident Handling", "Decision routing escalates uncertain tickets to humans.",
     "Incident containment, recovery and exercises require operational evidence.",
     "tests.test_jev_client.TestJevTree."
     "test_escalation_stops_before_leaf_and_preserves_prior_steps"),
    ("RA-5", "Vulnerability Monitoring and Scanning",
     "Airlock supports manifest and dependency blast-radius discovery.",
     "No vulnerability scanner is implemented here; scan results remain external.",
     "tests.test_security_airlock.CodeSearchAirlockTests."
     "test_manifest_and_dependency_queries_have_real_rooted_paths"),
    ("SC-7", "Boundary Protection", "Code-search airlock denies secret-hunting queries.",
     "Application query gating does not establish network boundary protection.",
     "tests.test_security_airlock.CodeSearchAirlockTests."
     "test_secret_searches_block_before_catalog_access_and_never_echo_input"),
    ("SI-2", "Flaw Remediation", "Release gates detect local policy violations.",
     "Patch installation, remediation deadlines and verification remain external.",
     "tests.test_golden_path_gates.TestSixGateAudit.test_missing_git_and_missing_files_fail_closed"),
)


def build_oscal_hud_posture_report(control_statuses=None):
    """Return a fresh JSON-compatible nine-control posture report.

    ``control_statuses`` is an optional dict keyed by control ID (case
    insensitive). Values are passed, partial, failed, pending, manual_review,
    or not_assessed, mapping to GREEN, YELLOW, RED, ORANGE, PURPLE, BLUE.
    Color names are also accepted. Missing controls are not_assessed. Unknown
    IDs, duplicate normalized IDs and invalid statuses raise ValueError without
    echoing input. This function performs no I/O and never runs tests.
    """
    if control_statuses is None:
        control_statuses = {}
    if not isinstance(control_statuses, dict):
        raise ValueError("control_statuses must be a dictionary")
    known = {control[0] for control in _CONTROLS}
    statuses = {}
    colors = {color.lower(): status for status, color in _STATUS_COLORS.items()}
    for identifier, status in control_statuses.items():
        if (not isinstance(identifier, str) or identifier.upper() not in known
                or identifier.upper() in statuses or not isinstance(status, str)):
            raise ValueError("Invalid control or status")
        status = colors.get(status.lower(), status.lower())
        if status not in _STATUS_COLORS:
            raise ValueError("Invalid control or status")
        statuses[identifier.upper()] = status
    controls = []
    counts = {color: 0 for color in _STATUS_COLORS.values()}
    for identifier, title, description, gap, test_id in _CONTROLS:
        status = statuses.get(identifier, "not_assessed")
        color = _STATUS_COLORS[status]
        counts[color] += 1
        module, test_class, method = test_id.rsplit(".", 2)
        controls.append({
            "control_id": identifier, "title": title, "status": status,
            "color": color, "description": description, "coverage_gap": gap,
            "evidence_links": [{
                "href": module.replace(".", "/") + ".py#" + method,
                "test_id": test_id,
                "command": "python -m unittest " + test_id + " -v",
                "kind": "automated-test-reference",
            }],
        })
    # Operational urgency order; BLUE takes precedence over GREEN so missing
    # assessments cannot disappear in an otherwise passing summary.
    overall = next(color for color in
                   ("RED", "ORANGE", "PURPLE", "YELLOW", "BLUE", "GREEN") if counts[color])
    return {"framework": "NIST SP 800-53 Rev. 5", "notice": _NOTICE,
            "status_mapping": dict(_STATUS_COLORS), "controls": controls,
            "summary": {"total": len(controls), "counts": counts, "color": overall}}


def _container_posture(catalog):
    """Audit observed regular, init and ephemeral containers, without values."""
    checked, missing, failed = 0, False, False
    for node in catalog["nodes"]:
        resource = node.get("resource")
        if resource is None:
            continue
        kind = resource.get("kind")
        if kind not in {"Pod", "Deployment", "StatefulSet", "DaemonSet",
                        "ReplicaSet", "Job", "CronJob"}:
            continue
        spec = resource.get("spec")
        if kind == "CronJob" and isinstance(spec, dict):
            spec = spec.get("jobTemplate", {}).get("spec")
        if kind != "Pod" and isinstance(spec, dict):
            spec = spec.get("template", {}).get("spec")
        if not isinstance(spec, dict):
            missing = True
            continue
        containers = spec.get("containers")
        if not isinstance(containers, list) or not containers:
            missing = True
        for field in ("containers", "initContainers", "ephemeralContainers"):
            items = spec.get(field, [])
            if not isinstance(items, list):
                failed = True
                continue
            for container in items:
                checked += 1
                context = container.get("securityContext", {}) if isinstance(container, dict) else None
                inherited = spec.get("securityContext", {})
                if not isinstance(context, dict) or not isinstance(inherited, dict):
                    failed = True
                    continue
                # Only runAsUser/runAsNonRoot can be inherited from pod policy.
                effective = {key: inherited[key] for key in ("runAsUser", "runAsNonRoot")
                             if key in inherited}
                effective.update(context)
                if audit_container_security_context({"securityContext": effective}).get("compliant") is not True:
                    failed = True
    return {"status": "failed" if failed else (
        "partial" if checked and not missing else "pending")}


def evaluate_live_oscal_posture(catalog=None):
    """Assess nine controls using current local checks and a single snapshot.

    Accept a graph dict or JSON path; None reads live-cluster-sanitized.json.
    This opt-in API reads files and runs the read-only six-gate repository audit,
    never tests, network requests, fault injection or credential retrieval.
    Positive observations are partial coverage, never full control compliance.
    Missing observations are pending; unavailable/broken checks fail closed.
    Only fixed check names and derived statuses enter the returned report.
    """
    statuses = {}
    evidence = {identifier: [] for identifier, *_ in _CONTROLS}

    def record(identifiers, source, status):
        for identifier in identifiers:
            evidence[identifier].append({"source": source, "status": status})
        return status

    def check(identifiers, source, action, assess):
        try:
            status = assess(action())
        except Exception:
            # Provider errors must neither expose catalog values nor turn GREEN.
            status = "failed"
        return record(identifiers, source, status)

    def combine(identifier):
        observed = {item["status"] for item in evidence[identifier]}
        return next(status for status in ("failed", "pending", "partial") if status in observed)

    try:
        if catalog is None or isinstance(catalog, (str, Path)):
            path = Path(__file__).with_name("live-cluster-sanitized.json") if catalog is None else Path(catalog)
            catalog = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list)
                or any(not isinstance(node, dict) for node in catalog["nodes"])):
            raise ValueError
        json.dumps(catalog, allow_nan=False)
    except (OSError, ValueError, TypeError, RecursionError):
        for identifier in evidence:
            record((identifier,), "catalog", "failed")
    else:
        check(("AC-2", "SC-7"), "oidc_rbac_verifier.audit_cluster_ingress_oidc_posture",
              lambda: audit_cluster_ingress_oidc_posture(catalog),
              lambda r: "failed" if r["status"] == "invalid_catalog" else (
                  "partial" if r["status"] == "configured_observed_fields" and r["ingress_count"] > 0
                  else "pending"))
        check(("AC-6", "CM-2"), "security_airlock.audit_container_security_context",
              lambda: _container_posture(catalog), lambda r: r["status"])
        check(("AC-6", "CM-8"), "openbao_kms_provenance.audit_openbao_secret_provenance",
              lambda: audit_openbao_secret_provenance(catalog),
              lambda r: "failed" if r["findings"] else (
                  "partial" if r["zero_plaintext_leakage"] is True and r["workloads"] else "pending"))
        check(("IR-4",), "openbao_kms_provenance.verify_raft_kms_quorum",
              lambda: verify_raft_kms_quorum(catalog),
              lambda r: "partial" if r["availability_majority"] is True else "pending")
        check(("IR-4", "SC-7"), "chaos_blast_radius.verify_all_six_chaos_planes",
              lambda: verify_all_six_chaos_planes(catalog),
              lambda r: "partial" if r["blast_radius_contained"] is True else (
                  "failed" if any(p["status"] == "invalid_catalog" for p in r["planes"].values())
                  else "pending"))
        check(("SC-7",), "security_airlock.evaluate_code_search_airlock",
              lambda: evaluate_code_search_airlock("find passwords", catalog),
              lambda r: "partial" if r["airlock_blocked"] is True and r["status_code"] == 403
              else "failed")
        check(("RA-5",), "security_airlock.evaluate_code_search_airlock",
              lambda: evaluate_code_search_airlock("manifest dependency blast radius", catalog),
              lambda r: "partial" if r["status_code"] == 200 and r["results"] else "pending")
        check(("AU-6", "SI-2"), "golden_path_gates.run_six_gate_prepush_audit",
              run_six_gate_prepush_audit, lambda r: "partial" if r["passed"] is True else "failed")
    statuses.update((identifier, combine(identifier)) for identifier in evidence)
    report = build_oscal_hud_posture_report(statuses)
    report["notice"] = (
        "Local policy and catalog snapshot assessment only; live enforcement and full "
        "control coverage remain unverified. Test references are not execution results. "
        "This assessment is not NIST or FedRAMP certification."
    )
    for control in report["controls"]:
        control["live_evidence"] = evidence[control["control_id"]]
    return report


def render_oscal_markdown_summary(report=None) -> str:
    """Render a HUD or live posture report without running assessments.

    Omitted reports use the unassessed HUD defaults. Preserve the supplied
    report's scope, coverage gaps and non-certification notice without mutation.
    """
    if report is None:
        report = build_oscal_hud_posture_report()

    def cell(value):
        return (escape(str(value), quote=False).replace("\\", "\\\\")
                .replace("|", "\\|").replace("\r\n", "\n")
                .replace("\r", "\n").replace("\n", "<br>"))

    lines = [
        "# " + cell(report["framework"]),
        "",
        "| Control ID | Title | Status | Color | Scope | Coverage Gap |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    fields = ("control_id", "title", "status", "color", "description", "coverage_gap")
    for control in report["controls"]:
        lines.append("| " + " | ".join(cell(control[field]) for field in fields) + " |")
    lines.extend(["", report["notice"], ""])
    return "\n".join(lines)


def export_oscal_component_definition(control_statuses=None):
    """Return an OSCAL 1.1.3 component-definition dict for JSON serialization.

    Accepts the same status mapping as build_oscal_hud_posture_report. Each
    export gets new UUIDs and a UTC last-modified timestamp. Custom posture
    properties use an application namespace; evidence links point at repository
    test sources and include runnable unittest commands. No files are written.
    Model reference: https://pages.nist.gov/OSCAL-Reference/models/v1.1.3/
    component-definition/json-reference/
    """
    report = build_oscal_hud_posture_report(control_statuses)
    requirements = []
    for control in report["controls"]:
        evidence = control["evidence_links"][0]
        requirements.append({
            "uuid": str(uuid4()), "control-id": control["control_id"].lower(),
            "description": control["description"] + " " + control["coverage_gap"],
            "props": [
                {"name": "assessment-status", "ns": _NS, "value": control["status"]},
                {"name": "hud-color", "ns": _NS, "value": control["color"]},
                {"name": "automated-test-command", "ns": _NS, "value": evidence["command"]},
            ],
            "links": [{"href": evidence["href"], "rel": "evidence",
                       "text": evidence["test_id"]}],
            "remarks": _NOTICE,
        })
    return {"component-definition": {
        "uuid": str(uuid4()),
        "metadata": {"title": "OpsCryer NIST SP 800-53 Rev. 5 Control Mapping",
                     "last-modified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                     "version": "1.0.0", "oscal-version": OSCAL_VERSION,
                     "remarks": _NOTICE},
        "components": [{
            "uuid": str(uuid4()), "type": "software", "title": "OpsCryer",
            "description": "OpsCryer local policy, graph and ticket-routing support.",
            "control-implementations": [{
                "uuid": str(uuid4()), "source": CATALOG_SOURCE,
                "description": "Partial supporting mappings to nine NIST SP 800-53 Rev. 5 controls.",
                "implemented-requirements": requirements,
            }],
        }],
    }}


def main(argv=None):
    """Print the default unassessed posture as JSON or Markdown."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--markdown", action="store_true", help="Export a Markdown control table")
    args = parser.parse_args(argv)
    report = build_oscal_hud_posture_report()
    print(render_oscal_markdown_summary(report) if args.markdown
          else json.dumps(report, indent=2), end="\n" if not args.markdown else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
