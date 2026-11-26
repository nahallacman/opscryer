#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""7-Level Knowledge Graph Breakdown, RTS Selection Stats, Tactical Status & Truth Harvester.

Canonical 7 architectural levels:
  1. project     — Repositories, services, applications, and top-level systems
  2. feature     — Capabilities, UI portals, operational skills, and workflows
  3. dependency  — Includes, libraries, packages, Helm charts, services, hardware
  4. requirement — Requirements (REQ-*), ADRs, policies, security controls, runbooks
  5. test        — Unit/integration/E2E tests, CI gates, verifiers, benchmarks
  6. deployment  — Kubernetes namespaces, deployments, pods, ingresses, environments
  7. contract    — OpenAPI specs, JSON schemas, CRDs, API routes, RBAC/OIDC interfaces

Zero backend imports: safe for Piece A standalone browser and Full-Truth live deployments.
"""

from __future__ import annotations

import argparse
import ast
from collections import deque
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

GRAPH_LAYERS_SCHEMA_VERSION = "1.0-graph-levels-breakdown"

GRAPH_LEVELS: tuple[dict[str, Any], ...] = (
    {
        "id": "project",
        "label": "Project",
        "short_label": "Project",
        "icon": "📦",
        "color": "#38BDF8",
        "z_elevation": 120,
        "description": "Repositories, services, applications, and owning project boundaries.",
    },
    {
        "id": "feature",
        "label": "Feature",
        "short_label": "Feature",
        "icon": "✨",
        "color": "#A855F7",
        "z_elevation": 98,
        "description": "Capabilities, interactive portals, workflows, skills, and autonomous units.",
    },
    {
        "id": "dependency",
        "label": "Include / Dependency",
        "short_label": "Include/Dep",
        "icon": "🔗",
        "color": "#F59E0B",
        "z_elevation": 78,
        "description": "Includes, shared libraries, packages, Helm charts, services, and backing compute.",
    },
    {
        "id": "requirement",
        "label": "Requirement",
        "short_label": "Requirement",
        "icon": "📋",
        "color": "#14B8A6",
        "z_elevation": 60,
        "description": "Requirements (REQ-*), ADRs, compliance policies, controls, and runbook specs.",
    },
    {
        "id": "test",
        "label": "Test",
        "short_label": "Test",
        "icon": "🧪",
        "color": "#22C55E",
        "z_elevation": 42,
        "description": "Automated unit/integration/E2E suites, CI gates, benchmarks, and verifiers.",
    },
    {
        "id": "deployment",
        "label": "Deployment",
        "short_label": "Deployment",
        "icon": "🚀",
        "color": "#06B6D4",
        "z_elevation": 24,
        "description": "Kubernetes namespaces, deployments, pods, ingresses, ArgoCD apps, and environments.",
    },
    {
        "id": "contract",
        "label": "Contract",
        "short_label": "Contract",
        "icon": "📜",
        "color": "#E879F9",
        "z_elevation": 8,
        "description": "OpenAPI specs, JSON schemas, CRDs, route registries, and API/RBAC contracts.",
    },
)

GRAPH_LEVEL_IDS: tuple[str, ...] = tuple(item["id"] for item in GRAPH_LEVELS)
GRAPH_LEVEL_MAP: dict[str, dict[str, Any]] = {item["id"]: item for item in GRAPH_LEVELS}

_LEVEL_ALIASES: dict[str, str] = {
    "project": "project",
    "projects": "project",
    "repo": "project",
    "repository": "project",
    "system": "project",
    "feature": "feature",
    "features": "feature",
    "capability": "feature",
    "include": "dependency",
    "includes": "dependency",
    "dependency": "dependency",
    "dependencies": "dependency",
    "include/dependency": "dependency",
    "include_dependency": "dependency",
    "dep": "dependency",
    "library": "dependency",
    "package": "dependency",
    "requirement": "requirement",
    "requirements": "requirement",
    "req": "requirement",
    "policy": "requirement",
    "adr": "requirement",
    "test": "test",
    "tests": "test",
    "verification": "test",
    "deployment": "deployment",
    "deployments": "deployment",
    "deploy": "deployment",
    "runtime": "deployment",
    "contract": "contract",
    "contracts": "contract",
    "schema": "contract",
    "interface": "contract",
    "api": "contract",
}

TACTICAL_STATUSES: tuple[dict[str, str], ...] = (
    {"id": "red", "label": "Critical / Error", "color": "#EF4444", "hotkey": "1"},
    {"id": "orange", "label": "Unseen / Degraded", "color": "#F97316", "hotkey": "2"},
    {"id": "blue", "label": "Pending / Stalled", "color": "#38BDF8", "hotkey": "3"},
    {"id": "purple", "label": "MLS / Locked", "color": "#A855F7", "hotkey": "4"},
    {"id": "yellow", "label": "Warning / Watch", "color": "#F59E0B", "hotkey": "5"},
    {"id": "green", "label": "Nominal / Ready", "color": "#22C55E", "hotkey": "6"},
)


def _normalize_level_alias(raw: Any) -> str | None:
    text = str(raw or "").strip().lower()
    if not text:
        return None
    return _LEVEL_ALIASES.get(text)


def classify_node_graph_level(node: Mapping[str, Any]) -> str:
    """Deterministically classify any spatial graph node into one of the 7 canonical levels."""
    if not isinstance(node, Mapping):
        return "feature"

    for explicit_key in ("graph_level", "architecture_level", "kg_level"):
        mapped = _normalize_level_alias(node.get(explicit_key))
        if mapped:
            return mapped

    nid = str(node.get("id") or "").lower()
    kind = str(node.get("kind") or "").lower()
    rkind = str(
        node.get("resource_kind")
        or (node.get("resource", {}).get("kind") if isinstance(node.get("resource"), Mapping) else "")
        or ""
    ).lower()
    domain = str(node.get("domain") or "").lower()
    section = str(node.get("section") or "").lower()
    label = str(node.get("label") or "").lower()
    tags_raw = node.get("tags")
    tags = " ".join(str(t).lower() for t in tags_raw) if isinstance(tags_raw, (list, tuple, set)) else ""
    combined = f"{nid} {kind} {rkind} {domain} {section} {label} {tags}"

    # 7. Contract — OpenAPI, schemas, CRDs, interfaces, route registries
    if (
        kind in {"contract", "api_contract", "openapi", "schema", "crd", "interface", "sla_contract"}
        or nid.startswith(("contract-", "api-", "schema-", "crd-", "openapi-"))
        or any(tok in combined for tok in ("openapi", "contract", "json schema", "spatialgraphcontract", "route_registry", "crd ", "interface spec"))
    ):
        return "contract"

    # 5. Test — test suites, benchmarks, verification gates, evals
    if (
        kind in {"test", "test_suite", "ci_gate", "benchmark", "verification", "eval_suite"}
        or nid.startswith(("test-", "tests/", "gate-", "eval-", "bench-"))
        or any(tok in combined for tok in ("pytest", "unittest", "test_", "e2e", "smoke test", "benchmark", "calibration eval", "verifier", "ci gate"))
    ):
        return "test"

    # 4. Requirement — REQ-*, ADRs, compliance policies, runbooks, KB articles
    if (
        kind in {"requirement", "adr", "policy", "compliance_control", "knowledge_article", "security_policy"}
        or nid.startswith(("req-", "adr-", "kb-", "policy-", "oscal-", "nist-"))
        or any(tok in combined for tok in ("requirement", "req-", "adr-", "runbook", "policy", "nist", "oscal", "compliance", "zero-trust", "secops"))
    ):
        return "requirement"

    # 6. Deployment — K8s namespaces/deployments/pods/ingresses, ArgoCD apps, live environments
    if (
        kind in {"deployment", "kubernetes_deployment", "kubernetes_namespace", "kubernetes_pod", "kubernetes_ingress", "environment", "argocd_app"}
        or rkind in {"deployment", "namespace", "pod", "ingress", "statefulset", "daemonset", "application"}
        or nid.startswith(("deploy-", "k8s/deployment/", "k8s/namespace/", "k8s/pod/", "k8s/ingress/", "env-", "argocd-"))
        or "deployments_k8s" in domain
    ):
        return "deployment"

    # 3. Include / Dependency — libraries, includes, packages, Helm charts, K8s services, hardware nodes
    if (
        kind in {"dependency", "include", "library", "package", "helm_chart", "kubernetes_service", "physical_hardware", "storage_volume", "database"}
        or rkind in {"service", "node", "persistentvolumeclaim", "configmap"}
        or nid.startswith(("dep-", "inc-", "lib-", "pkg-", "chart-", "hw-", "k8s/service/", "k8s/node/", "res-"))
        or "hardware_topology" in domain
        or any(tok in combined for tok in ("dependency", "include ", "helm chart", "container registry", "harbor", "storage", "openzfs", "postgres", "valkey"))
    ):
        return "dependency"

    # 1. Project — repositories, projects, systems, org roots, teams owning projects
    if (
        kind in {"project", "engineering_project", "backstage_component", "repository", "company_root", "company_team", "system"}
        or nid.startswith(("proj-", "project-", "repo-", "root-", "cluster-", "org-", "pillar-", "dept-", "team-"))
    ):
        return "project"

    # 2. Feature — capabilities, UI portals, skills, workflows, autonomous AI units
    return "feature"


def summarize_test_verification(node: Mapping[str, Any]) -> dict[str, Any]:
    """Return explicit pass/fail/error/executed counts so 0 errors with 0 run is never conflated with passing."""
    if not isinstance(node, Mapping):
        return {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "executed": 0, "verification_state": "UNVERIFIED_NOT_RUN"}

    raw_tr = node.get("test_results") if isinstance(node.get("test_results"), Mapping) else {}
    def _nonneg_int(val: Any) -> int:
        if isinstance(val, bool):
            return 0
        try:
            n = int(val)
            return n if n >= 0 else 0
        except (TypeError, ValueError):
            return 0

    passed = _nonneg_int(raw_tr.get("passed", node.get("tests_passed", 0)))
    failed = _nonneg_int(raw_tr.get("failed", node.get("tests_failed", 0)))
    errors = _nonneg_int(raw_tr.get("errors", node.get("tests_errors", 0)))
    skipped = _nonneg_int(raw_tr.get("skipped", node.get("tests_skipped", 0)))
    executed = passed + failed + errors

    if failed > 0 or errors > 0:
        state = "FAILED"
    elif executed > 0 and passed > 0:
        state = "VERIFIED_PASS"
    else:
        state = "UNVERIFIED_NOT_RUN"

    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "executed": executed,
        "verification_state": state,
    }


def classify_tactical_status(node: Mapping[str, Any]) -> str:
    """Classify real node operational status into the 6-color tactical HUD palette (zero fabrication).

    Test nodes with 0 executed tests (even when failed=0 and errors=0) map to 'blue'
    (Pending / Unverified), never 'green', unless explicit positive pass evidence exists.
    """
    if not isinstance(node, Mapping):
        return "blue"

    # Purple: MLS-redacted, opaqued, or restricted classification rank
    if (
        node.get("mls_redacted")
        or node.get("opaqued")
        or node.get("locked")
        or (isinstance(node.get("classification_rank"), int) and node["classification_rank"] >= 20)
    ):
        return "purple"

    severity = str(node.get("severity") or node.get("status") or "").strip().lower()
    bh_state = ""
    telem = node.get("rts_ai_unit_telemetry")
    if isinstance(telem, Mapping):
        bh = telem.get("behavioral_health")
        if isinstance(bh, Mapping):
            bh_state = str(bh.get("state") or "").strip().lower()

    # Enforce explicit positive pass evidence on test nodes or nodes carrying test_results
    has_test_results = isinstance(node.get("test_results"), Mapping) or any(
        k in node for k in ("tests_passed", "tests_failed", "tests_errors")
    )
    if has_test_results or classify_node_graph_level(node) == "test":
        tv = summarize_test_verification(node)
        if tv["verification_state"] == "FAILED":
            return "red"
        if tv["verification_state"] == "VERIFIED_PASS":
            return "green"
        if severity in {"critical", "error", "failed", "down"}:
            return "red"
        if severity in {"degraded", "novel", "anomaly", "high"}:
            return "orange"
        return "blue"

    # Red: critical / failed / error / alert
    if (
        node.get("alert") is True
        or severity in {"critical", "error", "failed", "down", "crashloopbackoff", "unhealthy"}
        or bh_state in {"critical", "alert", "failed"}
    ):
        return "red"

    # Orange: novel / degraded / unseen anomaly
    if severity in {"degraded", "novel", "anomaly", "high"} or bh_state in {"degraded"}:
        return "orange"

    # Blue: pending / stalled / progressing / offline / unavailable / unverified
    if severity in {"pending", "stalled", "progressing", "offline", "unavailable", "unknown", "cached", "unverified", "not_run"}:
        return "blue"

    # Yellow: warning / watch / high CPU threshold
    metrics = node.get("metrics")
    cpu_pct = None
    if isinstance(metrics, Mapping):
        raw_cpu = metrics.get("cpu_pct", metrics.get("cpu_percent"))
        if isinstance(raw_cpu, (int, float)) and not isinstance(raw_cpu, bool):
            cpu_pct = float(raw_cpu)
    if severity in {"warn", "warning", "medium"} or (cpu_pct is not None and cpu_pct >= 70.0):
        return "yellow"

    return "green"


def _build_adjacency(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    """Return (outbound_map, inbound_map, children_map) for valid node IDs."""
    valid_ids = {str(n["id"]) for n in nodes if isinstance(n, Mapping) and n.get("id")}
    outbound: dict[str, set[str]] = {nid: set() for nid in valid_ids}
    inbound: dict[str, set[str]] = {nid: set() for nid in valid_ids}
    children_map: dict[str, set[str]] = {nid: set() for nid in valid_ids}

    for n in nodes:
        if not isinstance(n, Mapping) or not n.get("id"):
            continue
        uid = str(n["id"])
        for cid in n.get("drilldown_children") or ():
            sc = str(cid or "")
            if sc in valid_ids and sc != uid:
                children_map[uid].add(sc)
                outbound[uid].add(sc)
                inbound[sc].add(uid)

    for e in edges:
        if not isinstance(e, Mapping):
            continue
        u = str(e.get("source") or "")
        v = str(e.get("target") or "")
        if u in valid_ids and v in valid_ids and u != v:
            outbound[u].add(v)
            inbound[v].add(u)

    return outbound, inbound, children_map


def analyze_selection_graph_levels(
    catalog: Mapping[str, Any],
    selected_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Compute graph-wide and selection-scoped 7-level breakdowns plus tactical status counts."""
    raw_nodes = [
        dict(n)
        for n in (catalog.get("nodes") or ())
        if isinstance(n, Mapping) and n.get("id")
    ]
    raw_edges = [dict(e) for e in (catalog.get("edges") or ()) if isinstance(e, Mapping)]
    by_id: dict[str, dict[str, Any]] = {str(n["id"]): n for n in raw_nodes}
    outbound, inbound, _ = _build_adjacency(raw_nodes, raw_edges)

    node_levels: dict[str, str] = {}
    global_buckets: dict[str, list[str]] = {lvl: [] for lvl in GRAPH_LEVEL_IDS}
    tactical_counts: dict[str, int] = {item["id"]: 0 for item in TACTICAL_STATUSES}

    for n in raw_nodes:
        nid = str(n["id"])
        lvl = classify_node_graph_level(n)
        node_levels[nid] = lvl
        global_buckets[lvl].append(nid)
        st = classify_tactical_status(n)
        tactical_counts[st] = tactical_counts.get(st, 0) + 1

    eff_selected = [str(sid) for sid in (selected_ids or ()) if str(sid) in by_id]
    eff_selected = list(dict.fromkeys(eff_selected))
    direct_set = set(eff_selected)

    linked_set: set[str] = set()
    for sid in eff_selected:
        for nb in outbound.get(sid, ()):
            if nb not in direct_set:
                linked_set.add(nb)
        for nb in inbound.get(sid, ()):
            if nb not in direct_set:
                linked_set.add(nb)

    def _aggregate_test_verification(ids: Sequence[str]) -> dict[str, int]:
        suites_pass = suites_fail = suites_unrun = 0
        tests_passed = tests_failed = tests_errors = tests_executed = 0
        for nid in ids:
            n = by_id.get(nid)
            if not n:
                continue
            tv = summarize_test_verification(n)
            tests_passed += tv["passed"]
            tests_failed += tv["failed"]
            tests_errors += tv["errors"]
            tests_executed += tv["executed"]
            if tv["verification_state"] == "VERIFIED_PASS":
                suites_pass += 1
            elif tv["verification_state"] == "FAILED":
                suites_fail += 1
            else:
                suites_unrun += 1
        return {
            "suites_total": len(ids),
            "suites_verified_pass": suites_pass,
            "suites_failed": suites_fail,
            "suites_unverified_not_run": suites_unrun,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "tests_errors": tests_errors,
            "tests_executed": tests_executed,
        }

    scope_ids = list(dict.fromkeys([*eff_selected, *sorted(linked_set)]))
    selection_breakdown: dict[str, dict[str, Any]] = {}
    for lvl_meta in GRAPH_LEVELS:
        lid = lvl_meta["id"]
        direct_in_lvl = [nid for nid in eff_selected if node_levels.get(nid) == lid]
        linked_in_lvl = [nid for nid in sorted(linked_set) if node_levels.get(nid) == lid]
        all_in_lvl = [*direct_in_lvl, *linked_in_lvl]
        entry: dict[str, Any] = {
            "level": lid,
            "label": lvl_meta["label"],
            "short_label": lvl_meta["short_label"],
            "icon": lvl_meta["icon"],
            "color": lvl_meta["color"],
            "count": len(all_in_lvl),
            "direct_count": len(direct_in_lvl),
            "linked_count": len(linked_in_lvl),
            "node_ids": all_in_lvl,
        }
        if lid == "test":
            entry["test_verification"] = _aggregate_test_verification(all_in_lvl)
        selection_breakdown[lid] = entry

    global_breakdown: dict[str, dict[str, Any]] = {}
    for lvl_meta in GRAPH_LEVELS:
        lid = lvl_meta["id"]
        ids = global_buckets[lid]
        g_entry: dict[str, Any] = {
            "level": lid,
            "label": lvl_meta["label"],
            "short_label": lvl_meta["short_label"],
            "icon": lvl_meta["icon"],
            "color": lvl_meta["color"],
            "count": len(ids),
            "node_ids": ids,
        }
        if lid == "test":
            g_entry["test_verification"] = _aggregate_test_verification(ids)
        global_breakdown[lid] = g_entry

    return {
        "schema_version": GRAPH_LAYERS_SCHEMA_VERSION,
        "levels": [dict(item) for item in GRAPH_LEVELS],
        "total_nodes": len(raw_nodes),
        "selected_ids": eff_selected,
        "linked_neighbor_count": len(linked_set),
        "scope_node_count": len(scope_ids),
        "global_breakdown": global_breakdown,
        "selection_breakdown": selection_breakdown,
        "test_verification": selection_breakdown["test"]["test_verification"] if eff_selected else global_breakdown["test"]["test_verification"],
        "tactical_status_counts": tactical_counts,
        "node_levels": node_levels,
    }


def _safe_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def harvest_workspace_truth_graph(
    workspace_root: Path,
    *,
    project_name: str | None = None,
    max_files: int = 300,
) -> dict[str, Any]:
    """Harvest a 100% real 7-level SpatialGraphContract v1 catalog from a local workspace repository.

    Inspects actual project manifests, Python/TS modules, real imports/dependencies, ADRs/docs/skills,
    test files, Dockerfiles/K8s manifests, and OpenAPI/contract modules with zero fabricated nodes.
    """
    root = Path(workspace_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Workspace root not found: {root}")

    resolved_name = (project_name or root.name).strip() or "workspace"
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", resolved_name.lower()).strip("-") or "workspace"
    root_id = f"proj-{slug}"

    nodes: list[dict[str, Any]] = []
    node_by_id: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add_node(node: dict[str, Any]) -> dict[str, Any]:
        nid = str(node["id"])
        if nid in node_by_id:
            return node_by_id[nid]
        node.setdefault("drilldown_children", [])
        node.setdefault("control_plane_urls", [])
        node_by_id[nid] = node
        nodes.append(node)
        return node

    def add_edge(src: str, dst: str, relation: str, *, attach_child: bool = True) -> None:
        if src == dst or src not in node_by_id or dst not in node_by_id:
            return
        key = (src, dst, relation)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": src, "target": dst, "relation": relation})
        if attach_child:
            ch = node_by_id[src]["drilldown_children"]
            if dst not in ch:
                ch.append(dst)

    add_node(
        {
            "id": root_id,
            "label": f"Project: {resolved_name}",
            "kind": "engineering_project",
            "graph_level": "project",
            "domain": "company_org",
            "section": "section_project",
            "level_index": 0,
            "summary": f"Live workspace repository harvested from {root.name} across all 7 architectural levels.",
            "primary_url": f"/{slug}",
            "status": "nominal",
        }
    )

    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "scratch",
    }
    collected_files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs and not d.startswith(".tox"))
        for fname in sorted(filenames):
            collected_files.append(Path(dirpath) / fname)
            if len(collected_files) >= max_files:
                break
        if len(collected_files) >= max_files:
            break

    py_modules_by_stem: dict[str, str] = {}
    feature_ids: list[str] = []
    test_ids: list[str] = []

    for fpath in collected_files:
        rel = _safe_rel(fpath, root)
        lower_rel = rel.lower()
        name = fpath.name
        lower_name = name.lower()

        # 7. Contracts (OpenAPI, route_registry, JSON schemas, CRDs)
        if (
            lower_name in {"openapi_spec.py", "route_registry.py", "openapi.json", "openapi.yaml"}
            or lower_name.endswith((".schema.json", "-schema.json"))
            or "contract" in lower_name
        ):
            cid = f"contract-{re.sub(r'[^a-z0-9]+', '-', lower_rel).strip('-')}"
            add_node(
                {
                    "id": cid,
                    "label": f"Contract: {rel}",
                    "kind": "contract",
                    "graph_level": "contract",
                    "domain": "contracts",
                    "section": "section_contract",
                    "level_index": 1,
                    "summary": f"Repository interface / schema contract defined at {rel}.",
                    "primary_url": "/docs" if "openapi" in lower_name else "/api/v1/openapi.json",
                    "source_path": rel,
                    "status": "nominal",
                }
            )
            add_edge(root_id, cid, "exposes_contract")
            if fpath.suffix == ".py":
                py_modules_by_stem[fpath.stem] = cid
            continue

        # 5. Tests (tests/test_*.py, *.test.ts, *.test.tsx)
        if (
            lower_rel.startswith("tests/")
            and (lower_name.startswith("test_") or lower_name.endswith(("_test.py", ".test.ts", ".test.tsx")))
        ) or lower_name.endswith((".test.ts", ".test.tsx")):
            tid = f"test-{re.sub(r'[^a-z0-9]+', '-', lower_rel).strip('-')}"
            add_node(
                {
                    "id": tid,
                    "label": f"Test: {rel}",
                    "kind": "test_suite",
                    "graph_level": "test",
                    "domain": "verification",
                    "section": "section_test",
                    "level_index": 2,
                    "summary": f"Automated verification suite located at {rel} (static file discovery; not yet executed).",
                    "primary_url": f"/tests/{name}",
                    "source_path": rel,
                    "status": "unverified",
                    "test_results": {
                        "passed": 0,
                        "failed": 0,
                        "errors": 0,
                        "skipped": 0,
                        "executed": 0,
                        "verification_state": "UNVERIFIED_NOT_RUN",
                    },
                }
            )
            add_edge(root_id, tid, "verified_by")
            test_ids.append(tid)
            continue

        # 6. Deployments (Dockerfile*, kustomization.yaml, Helm values, K8s manifests)
        if (
            lower_name.startswith("dockerfile")
            or lower_name in {"kustomization.yaml", "deployment.yaml", "ingress.yaml", "httproute.yaml", "chart.yaml"}
            or lower_rel.startswith(("apps/", "gitops/", "deploy/", "k8s/", "containers/"))
            and lower_name.endswith((".yaml", ".yml"))
        ):
            did = f"deploy-{re.sub(r'[^a-z0-9]+', '-', lower_rel).strip('-')}"
            add_node(
                {
                    "id": did,
                    "label": f"Deployment: {rel}",
                    "kind": "kubernetes_deployment",
                    "graph_level": "deployment",
                    "domain": "deployments_k8s",
                    "section": "section_deployment",
                    "level_index": 2,
                    "summary": f"Container or GitOps deployment manifest at {rel}.",
                    "primary_url": "/gitops",
                    "source_path": rel,
                    "status": "nominal",
                }
            )
            add_edge(root_id, did, "deployed_by")
            continue

        # 4. Requirements (ADRs, SKILL.md, SECURITY.md, requirements/docs markdown)
        if (
            lower_name in {"security.md", "epic_scope_manifest.md", "agents.md", "skill.md"}
            or lower_rel.startswith(("docs/", ".ai/knowledge/", ".ai/design/", ".ai/plans/", ".ai/skills/"))
            and lower_name.endswith(".md")
        ):
            rid = f"req-{re.sub(r'[^a-z0-9]+', '-', lower_rel).strip('-')}"
            add_node(
                {
                    "id": rid,
                    "label": f"Requirement: {rel}",
                    "kind": "requirement",
                    "graph_level": "requirement",
                    "domain": "requirements",
                    "section": "section_requirement",
                    "level_index": 1,
                    "summary": f"Architecture specification, policy, or skill doc at {rel}.",
                    "primary_url": "/kb",
                    "source_path": rel,
                    "status": "nominal",
                }
            )
            add_edge(root_id, rid, "satisfies_requirement")
            continue

        # 3. Dependencies (pyproject.toml, requirements*.txt, package.json, Chart.lock)
        if lower_name in {"pyproject.toml", "requirements.txt", "package.json", "chart.lock"}:
            dep_id = f"dep-{re.sub(r'[^a-z0-9]+', '-', lower_rel).strip('-')}"
            add_node(
                {
                    "id": dep_id,
                    "label": f"Dependency Manifest: {rel}",
                    "kind": "dependency",
                    "graph_level": "dependency",
                    "domain": "dependencies",
                    "section": "section_dependency",
                    "level_index": 1,
                    "summary": f"Declared runtime & package dependencies in {rel}.",
                    "primary_url": "/adapters",
                    "source_path": rel,
                    "status": "nominal",
                }
            )
            add_edge(root_id, dep_id, "depends_on")
            continue

        # 2. Features (Python/TypeScript source modules at top level or src/engine)
        if fpath.suffix in {".py", ".ts", ".tsx"} and not lower_name.startswith("__"):
            fid = f"feat-{re.sub(r'[^a-z0-9]+', '-', lower_rel).strip('-')}"
            add_node(
                {
                    "id": fid,
                    "label": f"Feature: {rel}",
                    "kind": "feature",
                    "graph_level": "feature",
                    "domain": "features",
                    "section": "section_feature",
                    "level_index": 1,
                    "summary": f"Implementation module at {rel}.",
                    "primary_url": f"/{fpath.stem}",
                    "source_path": rel,
                    "status": "nominal",
                }
            )
            add_edge(root_id, fid, "has_feature")
            feature_ids.append(fid)
            if fpath.suffix == ".py":
                py_modules_by_stem[fpath.stem] = fid

    # Wire real Python local import edges (include/dependency) and test->feature edges via stdlib AST.
    for nid in [*feature_ids, *test_ids]:
        nobj = node_by_id.get(nid)
        if not nobj:
            continue
        rel = str(nobj.get("source_path") or "")
        if not rel.endswith(".py"):
            continue
        fpath = root / rel
        try:
            tree = ast.parse(fpath.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        imported_stems: set[str] = set()
        for stmt in ast.walk(tree):
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    imported_stems.add(alias.name.split(".", 1)[0])
            elif isinstance(stmt, ast.ImportFrom) and stmt.module:
                imported_stems.add(stmt.module.split(".", 1)[0])
        for stem in sorted(imported_stems):
            target_id = py_modules_by_stem.get(stem)
            if target_id and target_id != nid:
                rel_name = "tests_module" if nid.startswith("test-") else "imports_include"
                add_edge(nid, target_id, rel_name, attach_child=False)

    analysis = analyze_selection_graph_levels({"nodes": nodes, "edges": edges}, [root_id])
    counts = analysis["global_breakdown"]
    currencies = [
        {
            "currency_id": "nodes",
            "icon": "📦",
            "label": "Truth Nodes",
            "display_value": f"{len(nodes)} Real",
            "supply_kind": "supply_cap",
            "hex_color": "#22C55E",
            "available": True,
            "dropdown_items": [
                {
                    "label": f"{GRAPH_LEVEL_MAP[lid]['icon']} {GRAPH_LEVEL_MAP[lid]['label']}",
                    "value": f"{counts[lid]['count']} nodes",
                    "target_id": counts[lid]["node_ids"][0] if counts[lid]["node_ids"] else root_id,
                }
                for lid in GRAPH_LEVEL_IDS
            ],
        },
        {
            "currency_id": "cpu_load",
            "icon": "⚡",
            "label": "CPU Load",
            "display_value": "Unavailable",
            "supply_kind": "currency_rate",
            "hex_color": "#94A3B8",
            "available": False,
            "dropdown_items": [],
        },
        {
            "currency_id": "ram_load",
            "icon": "🧠",
            "label": "RAM Load",
            "display_value": "Unavailable",
            "supply_kind": "currency_rate",
            "hex_color": "#94A3B8",
            "available": False,
            "dropdown_items": [],
        },
        {
            "currency_id": "network_load",
            "icon": "📜",
            "label": "Contracts",
            "display_value": f"{counts['contract']['count']} Verified",
            "supply_kind": "currency_rate",
            "hex_color": "#E879F9" if counts["contract"]["count"] else "#94A3B8",
            "available": bool(counts["contract"]["count"]),
            "dropdown_items": [
                {"label": node_by_id[cid]["label"], "value": "contract", "target_id": cid}
                for cid in counts["contract"]["node_ids"][:6]
            ],
        },
        {
            "currency_id": "build_supply",
            "icon": "🧪",
            "label": "Test Suites",
            "display_value": f"{counts['test']['count']} Suites",
            "supply_kind": "food_supply",
            "hex_color": "#22C55E" if counts["test"]["count"] else "#94A3B8",
            "available": bool(counts["test"]["count"]),
            "dropdown_items": [
                {"label": node_by_id[tid]["label"], "value": "test", "target_id": tid}
                for tid in counts["test"]["node_ids"][:6]
            ],
        },
        {
            "currency_id": "renovate_failures",
            "icon": "🚀",
            "label": "Deployments",
            "display_value": f"{counts['deployment']['count']} Manifests",
            "supply_kind": "upkeep_alert",
            "hex_color": "#06B6D4" if counts["deployment"]["count"] else "#94A3B8",
            "available": bool(counts["deployment"]["count"]),
            "dropdown_items": [
                {"label": node_by_id[did]["label"], "value": "deployment", "target_id": did}
                for did in counts["deployment"]["node_ids"][:6]
            ],
        },
        {
            "currency_id": "open_mrs",
            "icon": "🔗",
            "label": "Dependencies",
            "display_value": f"{counts['dependency']['count']} Manifests",
            "supply_kind": "production_queue",
            "hex_color": "#F59E0B" if counts["dependency"]["count"] else "#94A3B8",
            "available": bool(counts["dependency"]["count"]),
            "dropdown_items": [
                {"label": node_by_id[did]["label"], "value": "dependency", "target_id": did}
                for did in counts["dependency"]["node_ids"][:6]
            ],
        },
    ]

    return {
        "schema_version": "1.0-separable-spatial-graph-contract",
        "source": "workspace_truth_harvest",
        "example": False,
        "truth_mode": True,
        "root_node_id": root_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "rts_currencies": currencies,
        "graph_levels_summary": analysis["global_breakdown"],
    }


def build_graph_layers_js() -> str:
    """Return zero-dependency client-side 7-Level Breakdown & Local-Links JS engine (zero // comments)."""
    levels_json = json.dumps([dict(x) for x in GRAPH_LEVELS], ensure_ascii=True, separators=(",", ":"))
    statuses_json = json.dumps([dict(x) for x in TACTICAL_STATUSES], ensure_ascii=True, separators=(",", ":"))
    aliases_json = json.dumps(_LEVEL_ALIASES, ensure_ascii=True, separators=(",", ":"))
    template = r"""
(function(globalScope) {
  const GRAPH_LEVELS = __GRAPH_LEVELS__;
  const TACTICAL_STATUSES = __TACTICAL_STATUSES__;
  const LEVEL_ALIASES = __LEVEL_ALIASES__;
  const LEVEL_MAP = {};
  GRAPH_LEVELS.forEach(item => { LEVEL_MAP[item.id] = item; });

  function classifyNodeGraphLevel(node) {
    if (!node || typeof node !== 'object') return 'feature';
    const explicit = [node.graph_level, node.architecture_level, node.kg_level];
    for (let i = 0; i < explicit.length; i++) {
      const k = String(explicit[i] || '').trim().toLowerCase();
      if (k && LEVEL_ALIASES[k]) return LEVEL_ALIASES[k];
    }
    const nid = String(node.id || '').toLowerCase();
    const kind = String(node.kind || '').toLowerCase();
    const rkind = String(node.resource_kind || (node.resource && node.resource.kind) || '').toLowerCase();
    const domain = String(node.domain || '').toLowerCase();
    const section = String(node.section || '').toLowerCase();
    const label = String(node.label || '').toLowerCase();
    const tags = Array.isArray(node.tags) ? node.tags.map(t => String(t).toLowerCase()).join(' ') : '';
    const hay = nid + ' ' + kind + ' ' + rkind + ' ' + domain + ' ' + section + ' ' + label + ' ' + tags;

    if (
      kind === 'contract' || kind === 'api_contract' || kind === 'openapi' || kind === 'schema' || kind === 'crd' || kind === 'interface' || kind === 'sla_contract'
      || nid.indexOf('contract-') === 0 || nid.indexOf('api-') === 0 || nid.indexOf('schema-') === 0 || nid.indexOf('crd-') === 0 || nid.indexOf('openapi-') === 0
      || hay.indexOf('openapi') >= 0 || hay.indexOf('contract') >= 0 || hay.indexOf('json schema') >= 0 || hay.indexOf('spatialgraphcontract') >= 0 || hay.indexOf('route_registry') >= 0
    ) return 'contract';

    if (
      kind === 'test' || kind === 'test_suite' || kind === 'ci_gate' || kind === 'benchmark' || kind === 'verification' || kind === 'eval_suite'
      || nid.indexOf('test-') === 0 || nid.indexOf('tests/') === 0 || nid.indexOf('gate-') === 0 || nid.indexOf('eval-') === 0 || nid.indexOf('bench-') === 0
      || hay.indexOf('pytest') >= 0 || hay.indexOf('unittest') >= 0 || hay.indexOf('test_') >= 0 || hay.indexOf('e2e') >= 0 || hay.indexOf('benchmark') >= 0 || hay.indexOf('verifier') >= 0
    ) return 'test';

    if (
      kind === 'requirement' || kind === 'adr' || kind === 'policy' || kind === 'compliance_control' || kind === 'knowledge_article' || kind === 'security_policy'
      || nid.indexOf('req-') === 0 || nid.indexOf('adr-') === 0 || nid.indexOf('kb-') === 0 || nid.indexOf('policy-') === 0 || nid.indexOf('oscal-') === 0 || nid.indexOf('nist-') === 0
      || hay.indexOf('requirement') >= 0 || hay.indexOf('req-') >= 0 || hay.indexOf('adr-') >= 0 || hay.indexOf('runbook') >= 0 || hay.indexOf('policy') >= 0 || hay.indexOf('nist') >= 0 || hay.indexOf('oscal') >= 0 || hay.indexOf('compliance') >= 0 || hay.indexOf('zero-trust') >= 0
    ) return 'requirement';

    if (
      kind === 'deployment' || kind === 'kubernetes_deployment' || kind === 'kubernetes_namespace' || kind === 'kubernetes_pod' || kind === 'kubernetes_ingress' || kind === 'environment' || kind === 'argocd_app'
      || rkind === 'deployment' || rkind === 'namespace' || rkind === 'pod' || rkind === 'ingress' || rkind === 'statefulset' || rkind === 'daemonset' || rkind === 'application'
      || nid.indexOf('deploy-') === 0 || nid.indexOf('k8s/deployment/') === 0 || nid.indexOf('k8s/namespace/') === 0 || nid.indexOf('k8s/pod/') === 0 || nid.indexOf('k8s/ingress/') === 0 || nid.indexOf('env-') === 0 || nid.indexOf('argocd-') === 0
      || domain.indexOf('deployments_k8s') >= 0
    ) return 'deployment';

    if (
      kind === 'dependency' || kind === 'include' || kind === 'library' || kind === 'package' || kind === 'helm_chart' || kind === 'kubernetes_service' || kind === 'physical_hardware' || kind === 'storage_volume' || kind === 'database'
      || rkind === 'service' || rkind === 'node' || rkind === 'persistentvolumeclaim' || rkind === 'configmap'
      || nid.indexOf('dep-') === 0 || nid.indexOf('inc-') === 0 || nid.indexOf('lib-') === 0 || nid.indexOf('pkg-') === 0 || nid.indexOf('chart-') === 0 || nid.indexOf('hw-') === 0 || nid.indexOf('k8s/service/') === 0 || nid.indexOf('k8s/node/') === 0 || nid.indexOf('res-') === 0
      || domain.indexOf('hardware_topology') >= 0
      || hay.indexOf('dependency') >= 0 || hay.indexOf('helm chart') >= 0 || hay.indexOf('container registry') >= 0 || hay.indexOf('harbor') >= 0 || hay.indexOf('storage') >= 0 || hay.indexOf('openzfs') >= 0 || hay.indexOf('postgres') >= 0
    ) return 'dependency';

    if (
      kind === 'project' || kind === 'engineering_project' || kind === 'backstage_component' || kind === 'repository' || kind === 'company_root' || kind === 'company_team' || kind === 'system'
      || nid.indexOf('proj-') === 0 || nid.indexOf('project-') === 0 || nid.indexOf('repo-') === 0 || nid.indexOf('root-') === 0 || nid.indexOf('cluster-') === 0 || nid.indexOf('org-') === 0 || nid.indexOf('pillar-') === 0 || nid.indexOf('dept-') === 0 || nid.indexOf('team-') === 0
    ) return 'project';

    return 'feature';
  }

  function summarizeTestVerification(node) {
    if (!node || typeof node !== 'object') return {passed: 0, failed: 0, errors: 0, skipped: 0, executed: 0, verification_state: 'UNVERIFIED_NOT_RUN'};
    const tr = (node.test_results && typeof node.test_results === 'object') ? node.test_results : {};
    const toInt = v => (typeof v === 'number' && isFinite(v) && v >= 0) ? Math.floor(v) : 0;
    const passed = toInt(tr.passed !== undefined ? tr.passed : node.tests_passed);
    const failed = toInt(tr.failed !== undefined ? tr.failed : node.tests_failed);
    const errors = toInt(tr.errors !== undefined ? tr.errors : node.tests_errors);
    const skipped = toInt(tr.skipped !== undefined ? tr.skipped : node.tests_skipped);
    const executed = passed + failed + errors;
    let state = 'UNVERIFIED_NOT_RUN';
    if (failed > 0 || errors > 0) state = 'FAILED';
    else if (executed > 0 && passed > 0) state = 'VERIFIED_PASS';
    return {passed: passed, failed: failed, errors: errors, skipped: skipped, executed: executed, verification_state: state};
  }

  function classifyTacticalStatus(node) {
    if (!node || typeof node !== 'object') return 'blue';
    if (node.mls_redacted || node.opaqued || node.locked || (typeof node.classification_rank === 'number' && node.classification_rank >= 20)) return 'purple';
    const sev = String(node.severity || node.status || '').trim().toLowerCase();
    const bh = node.rts_ai_unit_telemetry && node.rts_ai_unit_telemetry.behavioral_health ? String(node.rts_ai_unit_telemetry.behavioral_health.state || '').trim().toLowerCase() : '';
    const hasTr = Boolean((node.test_results && typeof node.test_results === 'object') || node.tests_passed !== undefined || node.tests_failed !== undefined || node.tests_errors !== undefined);
    if (hasTr || classifyNodeGraphLevel(node) === 'test') {
      const tv = summarizeTestVerification(node);
      if (tv.verification_state === 'FAILED') return 'red';
      if (tv.verification_state === 'VERIFIED_PASS') return 'green';
      if (sev === 'critical' || sev === 'error' || sev === 'failed' || sev === 'down') return 'red';
      if (sev === 'degraded' || sev === 'novel' || sev === 'anomaly' || sev === 'high') return 'orange';
      return 'blue';
    }
    if (node.alert === true || sev === 'critical' || sev === 'error' || sev === 'failed' || sev === 'down' || sev === 'crashloopbackoff' || sev === 'unhealthy' || bh === 'critical' || bh === 'alert' || bh === 'failed') return 'red';
    if (sev === 'degraded' || sev === 'novel' || sev === 'anomaly' || sev === 'high' || bh === 'degraded') return 'orange';
    if (sev === 'pending' || sev === 'stalled' || sev === 'progressing' || sev === 'offline' || sev === 'unavailable' || sev === 'unknown' || sev === 'cached' || sev === 'unverified' || sev === 'not_run') return 'blue';
    const m = node.metrics;
    const cpu = m && typeof (m.cpu_pct !== undefined ? m.cpu_pct : m.cpu_percent) === 'number' ? Number(m.cpu_pct !== undefined ? m.cpu_pct : m.cpu_percent) : null;
    if (sev === 'warn' || sev === 'warning' || sev === 'medium' || (cpu !== null && cpu >= 70)) return 'yellow';
    return 'green';
  }

  function analyzeSelectionLevels(catalog, selectedIds) {
    const nodes = (catalog && Array.isArray(catalog.nodes)) ? catalog.nodes : [];
    const edges = (catalog && Array.isArray(catalog.edges)) ? catalog.edges : [];
    const byId = new Map();
    const outbound = new Map();
    const inbound = new Map();
    const nodeLevels = {};
    const globalBuckets = {};
    const tacticalCounts = {red: 0, orange: 0, blue: 0, purple: 0, yellow: 0, green: 0};

    GRAPH_LEVELS.forEach(l => { globalBuckets[l.id] = []; });
    nodes.forEach(n => {
      if (!n || !n.id) return;
      const id = String(n.id);
      byId.set(id, n);
      outbound.set(id, new Set());
      inbound.set(id, new Set());
      const lvl = classifyNodeGraphLevel(n);
      nodeLevels[id] = lvl;
      globalBuckets[lvl].push(id);
      const st = classifyTacticalStatus(n);
      tacticalCounts[st] = (tacticalCounts[st] || 0) + 1;
    });

    nodes.forEach(n => {
      if (!n || !n.id) return;
      const u = String(n.id);
      (n.drilldown_children || []).forEach(c => {
        const v = String(c || '');
        if (byId.has(v) && u !== v) {
          outbound.get(u).add(v);
          inbound.get(v).add(u);
        }
      });
    });

    edges.forEach(e => {
      if (!e) return;
      const u = String(Array.isArray(e) ? ((nodes[e[0]] && nodes[e[0]].id) || '') : (e.source || ''));
      const v = String(Array.isArray(e) ? ((nodes[e[1]] && nodes[e[1]].id) || '') : (e.target || ''));
      if (byId.has(u) && byId.has(v) && u !== v) {
        outbound.get(u).add(v);
        inbound.get(v).add(u);
      }
    });

    const effSel = [];
    const directSet = new Set();
    (selectedIds || []).forEach(rawId => {
      const id = String(rawId || '');
      if (byId.has(id) && !directSet.has(id)) {
        directSet.add(id);
        effSel.push(id);
      }
    });

    const linkedSet = new Set();
    effSel.forEach(sid => {
      (outbound.get(sid) || []).forEach(nb => { if (!directSet.has(nb)) linkedSet.add(nb); });
      (inbound.get(sid) || []).forEach(nb => { if (!directSet.has(nb)) linkedSet.add(nb); });
    });

    const aggTests = ids => {
      let sp = 0, sf = 0, su = 0, tp = 0, tf = 0, te = 0, tx = 0;
      (ids || []).forEach(id => {
        const n = byId.get(id);
        if (!n) return;
        const tv = summarizeTestVerification(n);
        tp += tv.passed; tf += tv.failed; te += tv.errors; tx += tv.executed;
        if (tv.verification_state === 'VERIFIED_PASS') sp++;
        else if (tv.verification_state === 'FAILED') sf++;
        else su++;
      });
      return {suites_total: (ids || []).length, suites_verified_pass: sp, suites_failed: sf, suites_unverified_not_run: su, tests_passed: tp, tests_failed: tf, tests_errors: te, tests_executed: tx};
    };

    const sortedLinked = Array.from(linkedSet).sort();
    const globalBreakdown = {};
    const selectionBreakdown = {};
    GRAPH_LEVELS.forEach(meta => {
      const lid = meta.id;
      const gEntry = {level: lid, label: meta.label, short_label: meta.short_label, icon: meta.icon, color: meta.color, count: globalBuckets[lid].length, node_ids: globalBuckets[lid].slice()};
      if (lid === 'test') gEntry.test_verification = aggTests(globalBuckets[lid]);
      globalBreakdown[lid] = gEntry;
      const dIds = effSel.filter(id => nodeLevels[id] === lid);
      const lIds = sortedLinked.filter(id => nodeLevels[id] === lid);
      const allIds = dIds.concat(lIds);
      const sEntry = {level: lid, label: meta.label, short_label: meta.short_label, icon: meta.icon, color: meta.color, count: allIds.length, direct_count: dIds.length, linked_count: lIds.length, node_ids: allIds};
      if (lid === 'test') sEntry.test_verification = aggTests(allIds);
      selectionBreakdown[lid] = sEntry;
    });

    return {
      total_nodes: nodes.length,
      selected_ids: effSel,
      linked_neighbor_count: sortedLinked.length,
      global_breakdown: globalBreakdown,
      selection_breakdown: selectionBreakdown,
      test_verification: effSel.length ? selectionBreakdown.test.test_verification : globalBreakdown.test.test_verification,
      tactical_status_counts: tacticalCounts,
      node_levels: nodeLevels
    };
  }

  function renderLevelStatChips(containerEl, breakdownMap, activeLevel, onLevelClick) {
    if (!containerEl || typeof containerEl.replaceChildren !== 'function') return;
    const chips = [];
    GRAPH_LEVELS.forEach(meta => {
      const entry = (breakdownMap && breakdownMap[meta.id]) || {count: 0, node_ids: []};
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'kg-level-stat-pill' + (activeLevel === meta.id ? ' active' : '') + (entry.count === 0 ? ' empty' : '');
      btn.style.borderColor = entry.count > 0 ? meta.color : '#334155';
      let extra = '';
      if (meta.id === 'test' && entry.count > 0 && entry.test_verification) {
        const tv = entry.test_verification;
        if (tv.tests_executed > 0) {
          extra = ' (✓' + tv.tests_passed + (tv.tests_failed + tv.tests_errors > 0 ? (' ✗' + (tv.tests_failed + tv.tests_errors)) : '') + (tv.suites_unverified_not_run > 0 ? (' ?' + tv.suites_unverified_not_run + ' unrun') : '') + ')';
        } else {
          extra = ' (0 run)';
          btn.style.borderColor = '#38BDF8';
        }
      }
      if (btn.setAttribute) {
        btn.setAttribute('data-graph-level', meta.id);
        btn.setAttribute('title', meta.label + ': ' + entry.count + ' linked/selected item(s)' + extra);
      }
      btn.textContent = meta.icon + ' ' + meta.short_label + ': ' + String(entry.count) + extra;
      btn.addEventListener('click', () => {
        if (typeof onLevelClick === 'function') onLevelClick(meta.id, entry.node_ids || []);
      });
      chips.push(btn);
    });
    containerEl.replaceChildren(...chips);
  }

  globalScope.OpsCryerGraphLayers = {
    GRAPH_LEVELS: GRAPH_LEVELS,
    LEVEL_MAP: LEVEL_MAP,
    TACTICAL_STATUSES: TACTICAL_STATUSES,
    classifyNodeGraphLevel: classifyNodeGraphLevel,
    summarizeTestVerification: summarizeTestVerification,
    classifyTacticalStatus: classifyTacticalStatus,
    analyzeSelectionLevels: analyzeSelectionLevels,
    renderLevelStatChips: renderLevelStatChips
  };
})(typeof window !== 'undefined' ? window : globalThis);
""".strip()
    return (
        template.replace("__GRAPH_LEVELS__", levels_json.replace("</", "<\\/"))
        .replace("__TACTICAL_STATUSES__", statuses_json.replace("</", "<\\/"))
        .replace("__LEVEL_ALIASES__", aliases_json.replace("</", "<\\/"))
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpsCryer 7-Level Knowledge Graph Classifier & Workspace Truth Harvester")
    parser.add_argument("--harvest-repo", type=Path, default=None, help="Harvest a real 7-level truth graph from a repository directory")
    parser.add_argument("--project-name", default=None, help="Override project root name for --harvest-repo")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args(argv)
    if args.harvest_repo is not None:
        payload = harvest_workspace_truth_graph(args.harvest_repo, project_name=args.project_name)
    else:
        payload = {
            "schema_version": GRAPH_LAYERS_SCHEMA_VERSION,
            "levels": [dict(item) for item in GRAPH_LEVELS],
            "tactical_statuses": [dict(item) for item in TACTICAL_STATUSES],
        }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
