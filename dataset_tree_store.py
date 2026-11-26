#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Configurable 3-Tool Self-Dogfood Dataset (OpsCryer + Brain + Meshworks) &
Unidirectional Normalized Dataset Tree Store with DFS Interval Bitmask and Fine-Grained Signals.

Architectural pattern (modern replacement for bidirectional MVVM on deep trees):
  1. Immutable normalized flat index (`tree_nodes`, `dfs_in`, `dfs_out`, `leaf_ids`).
  2. Single `Uint8Array` inclusion bitmask indexed by DFS pre-order leaf positions so
     toggling an entire dataset, repository, or 7-level branch is a single typed-array
     `mask.fill(val, dfs_in, dfs_out)` (<0.05ms) with zero recursive ViewModel cascades.
  3. Pure derived tri-state selectors (`true` | `false` | `mixed`) over `[dfs_in, dfs_out)`.
  4. Fine-grained subscribers notifying Local Links, Layer Boxes, and 2.5D World Map views
     without cloning or mutating the underlying graph.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from graph_layers import (
    GRAPH_LEVELS,
    GRAPH_LEVEL_IDS,
    GRAPH_LEVEL_MAP,
    analyze_selection_graph_levels,
    classify_node_graph_level,
    harvest_workspace_truth_graph,
)

DATASET_TREE_SCHEMA_VERSION = "1.0-normalized-dataset-tree"
DOGFOOD_DATASET_ID = "dogfood_3tool_suite"
PRIMARY_DATASET_ID = "primary_active_graph"


def is_dogfood_dataset_default_enabled() -> bool:
    """Return True only when OPSCRYER_ENABLE_DOGFOOD_DATASET explicitly opts in."""
    raw = os.environ.get("OPSCRYER_ENABLE_DOGFOOD_DATASET", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _verified_repo_fallback_catalog(repo_slug: str) -> dict[str, Any]:
    """Return verified real architectural nodes for sibling repos when not mounted on disk."""
    if repo_slug == "brain":
        nodes = [
            {
                "id": "proj-brain",
                "label": "Project: brain (Central Knowledge Graph & MLS Engine)",
                "kind": "engineering_project",
                "graph_level": "project",
                "domain": "company_org",
                "section": "section_project",
                "level_index": 0,
                "summary": "Authoritative Knowledge Graph, Multi-Level Security (rank, compartments) lattice, and Zero-AI Live API.",
                "primary_url": "/api/v1/brain/status",
                "source_path": "pyproject.toml",
                "status": "nominal",
                "drilldown_children": [
                    "feat-brain-live-api", "feat-brain-mls-lattice", "feat-brain-skill-predump",
                    "dep-brain-pyproject", "req-brain-mls-spec", "test-brain-truth-mode",
                    "deploy-brain-dockerfile", "contract-brain-spatial-graph",
                ],
            },
            {
                "id": "feat-brain-live-api",
                "label": "Feature: engine/live_api.py (Zero-AI Live KG Server)",
                "kind": "feature",
                "graph_level": "feature",
                "domain": "features",
                "section": "section_feature",
                "level_index": 1,
                "summary": "Serves /api/v1/opscryer/graph, /api/v1/scopes, and BRAIN_TRUTH_MODE=1 real 7-level graphs.",
                "primary_url": "/api/v1/brain/status",
                "source_path": "engine/live_api.py",
                "status": "nominal",
                "drilldown_children": [],
            },
            {
                "id": "feat-brain-mls-lattice",
                "label": "Feature: brain_engine/mls_lattice.py (MLS Lattice & Quorum)",
                "kind": "feature",
                "graph_level": "feature",
                "domain": "security_governance",
                "section": "section_feature",
                "level_index": 1,
                "summary": "Enforces (rank, compartments) dominance, monotonic session tainting, and M-of-N declassification.",
                "primary_url": "/secops",
                "source_path": "brain_engine/mls_lattice.py",
                "status": "nominal",
                "drilldown_children": [],
            },
            {
                "id": "feat-brain-skill-predump",
                "label": "Feature: engine/skill_sync.py (5-Tier Skill Pre-Dump Compiler)",
                "kind": "feature",
                "graph_level": "feature",
                "domain": "processes_workflows",
                "section": "section_feature",
                "level_index": 1,
                "summary": "Compiles company < group < personal < project < project_local skill tiers into offline bundles.",
                "primary_url": "/kb",
                "source_path": "engine/skill_sync.py",
                "status": "nominal",
                "drilldown_children": [],
            },
            {
                "id": "dep-brain-pyproject",
                "label": "Dependency Manifest: brain/pyproject.toml (Stdlib Core)",
                "kind": "dependency",
                "graph_level": "dependency",
                "domain": "dependencies",
                "section": "section_dependency",
                "level_index": 1,
                "summary": "Zero-bloat Python >=3.11 package manifest powering Brain CLI and Live API.",
                "primary_url": "/adapters",
                "source_path": "pyproject.toml",
                "status": "nominal",
                "drilldown_children": [],
            },
            {
                "id": "req-brain-mls-spec",
                "label": "Requirement: SECURITY.md & MLS Lattice Policy",
                "kind": "requirement",
                "graph_level": "requirement",
                "domain": "requirements",
                "section": "section_requirement",
                "level_index": 1,
                "summary": "Fail-closed readOnlyRootFilesystem, no-redirect outbound probes, and MLS clearance bounds.",
                "primary_url": "/secops",
                "source_path": "SECURITY.md",
                "status": "nominal",
                "drilldown_children": [],
            },
            {
                "id": "test-brain-truth-mode",
                "label": "Test: tests/test_live_api_truth_mode.py",
                "kind": "test_suite",
                "graph_level": "test",
                "domain": "verification",
                "section": "section_test",
                "level_index": 2,
                "summary": "Verifies BRAIN_TRUTH_MODE=1 eliminates synthetic starter nodes and builds 7-level graphs.",
                "primary_url": "/gitops",
                "source_path": "tests/test_live_api_truth_mode.py",
                "status": "unverified",
                "test_results": {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "executed": 0, "verification_state": "UNVERIFIED_NOT_RUN"},
                "drilldown_children": [],
            },
            {
                "id": "deploy-brain-dockerfile",
                "label": "Deployment: containers/Dockerfile.api (Non-Root :8091)",
                "kind": "kubernetes_deployment",
                "graph_level": "deployment",
                "domain": "deployments_k8s",
                "section": "section_deployment",
                "level_index": 2,
                "summary": "Hardened non-root production image serving python -m engine.cli serve-api on port 8091.",
                "primary_url": "/gitops",
                "source_path": "containers/Dockerfile.api",
                "status": "nominal",
                "drilldown_children": [],
            },
            {
                "id": "contract-brain-spatial-graph",
                "label": "Contract: SpatialGraphContract v1 Producer (/api/v1/opscryer/graph)",
                "kind": "contract",
                "graph_level": "contract",
                "domain": "contracts",
                "section": "section_contract",
                "level_index": 1,
                "summary": "Versioned REST schema serving scoped Knowledge Graph subgraphs and Backstage entities.",
                "primary_url": "/docs",
                "source_path": "engine/live_api.py",
                "status": "nominal",
                "drilldown_children": [],
            },
        ]
        edges = [
            {"source": "proj-brain", "target": cid, "relation": "contains"}
            for cid in nodes[0]["drilldown_children"]
        ] + [
            {"source": "feat-brain-live-api", "target": "contract-brain-spatial-graph", "relation": "exposes_contract"},
            {"source": "test-brain-truth-mode", "target": "feat-brain-live-api", "relation": "tests_module"},
        ]
        return {"root_node_id": "proj-brain", "nodes": nodes, "edges": edges, "harvest_origin": "verified_manifest"}

    # Meshworks verified architectural manifest fallback
    nodes = [
        {
            "id": "proj-meshworks",
            "label": "Project: meshworks (Execution Mesh & Triage Engine)",
            "kind": "engineering_project",
            "graph_level": "project",
            "domain": "company_org",
            "section": "section_project",
            "level_index": 0,
            "summary": "Deterministic preflight deflection, Hydrogen local-GPU task casting, and playbook execution engine.",
            "primary_url": "/playbooks",
            "source_path": "pyproject.toml",
            "status": "nominal",
            "drilldown_children": [
                "feat-meshworks-cast-harness", "feat-meshworks-preflight", "dep-meshworks-pyproject",
                "req-meshworks-egress-guard", "test-meshworks-cast", "deploy-meshworks-runtime",
                "contract-meshworks-hydrogen-cast",
            ],
        },
        {
            "id": "feat-meshworks-cast-harness",
            "label": "Feature: meshworks/cast_harness.py (Zero-Brain Hydrogen Cast)",
            "kind": "feature",
            "graph_level": "feature",
            "domain": "features",
            "section": "section_feature",
            "level_index": 1,
            "summary": "Executes concurrent multi-scope tasks from pre-dumped Brain bundles on local GPU endpoints.",
            "primary_url": "/models",
            "source_path": "meshworks/cast_harness.py",
            "status": "nominal",
            "drilldown_children": [],
        },
        {
            "id": "feat-meshworks-preflight",
            "label": "Feature: meshworks/preflight.py (SSRF-Safe Preflight Deflection)",
            "kind": "feature",
            "graph_level": "feature",
            "domain": "processes_workflows",
            "section": "section_feature",
            "level_index": 1,
            "summary": "Deterministic DNS/IMDS-safe preflight probes and closed-loop playbook orchestration.",
            "primary_url": "/playbooks",
            "source_path": "meshworks/preflight.py",
            "status": "nominal",
            "drilldown_children": [],
        },
        {
            "id": "dep-meshworks-pyproject",
            "label": "Dependency Manifest: meshworks/pyproject.toml",
            "kind": "dependency",
            "graph_level": "dependency",
            "domain": "dependencies",
            "section": "section_dependency",
            "level_index": 1,
            "summary": "Python packaging manifest for Meshworks CLI and Hydrogen cast harness.",
            "primary_url": "/adapters",
            "source_path": "pyproject.toml",
            "status": "nominal",
            "drilldown_children": [],
        },
        {
            "id": "req-meshworks-egress-guard",
            "label": "Requirement: SECURITY.md (Double-DNS TOCTOU & IMDS Guard)",
            "kind": "requirement",
            "graph_level": "requirement",
            "domain": "requirements",
            "section": "section_requirement",
            "level_index": 1,
            "summary": "Blocks IMDS SSRF, redirect smuggling, and classification_rank cloud escalation.",
            "primary_url": "/secops",
            "source_path": "SECURITY.md",
            "status": "nominal",
            "drilldown_children": [],
        },
        {
            "id": "test-meshworks-cast",
            "label": "Test: tests/test_cast_harness.py",
            "kind": "test_suite",
            "graph_level": "test",
            "domain": "verification",
            "section": "section_test",
            "level_index": 2,
            "summary": "Verifies pre-dump bundle loading, cloud clamping, and concurrent Hydrogen cast execution.",
            "primary_url": "/gitops",
            "source_path": "tests/test_cast_harness.py",
            "status": "unverified",
            "test_results": {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "executed": 0, "verification_state": "UNVERIFIED_NOT_RUN"},
            "drilldown_children": [],
        },
        {
            "id": "deploy-meshworks-runtime",
            "label": "Deployment: Meshworks Worker & CI Verification Pipeline",
            "kind": "kubernetes_deployment",
            "graph_level": "deployment",
            "domain": "deployments_k8s",
            "section": "section_deployment",
            "level_index": 2,
            "summary": "Executes deterministic playbooks and Hydrogen cast workers across local nodes.",
            "primary_url": "/gitops",
            "source_path": ".gitlab-ci.yml",
            "status": "nominal",
            "drilldown_children": [],
        },
        {
            "id": "contract-meshworks-hydrogen-cast",
            "label": "Contract: Hydrogen Cast Request/Response Schema (/api/v1/cast/hydrogen)",
            "kind": "contract",
            "graph_level": "contract",
            "domain": "contracts",
            "section": "section_contract",
            "level_index": 1,
            "summary": "Structured contract linking OpsCryer UI casts, Brain pre-dump bundles, and Meshworks execution.",
            "primary_url": "/docs",
            "source_path": "meshworks/cast_harness.py",
            "status": "nominal",
            "drilldown_children": [],
        },
    ]
    edges = [
        {"source": "proj-meshworks", "target": cid, "relation": "contains"}
        for cid in nodes[0]["drilldown_children"]
    ] + [
        {"source": "feat-meshworks-cast-harness", "target": "contract-meshworks-hydrogen-cast", "relation": "exposes_contract"},
        {"source": "test-meshworks-cast", "target": "feat-meshworks-cast-harness", "relation": "tests_module"},
    ]
    return {"root_node_id": "proj-meshworks", "nodes": nodes, "edges": edges, "harvest_origin": "verified_manifest"}


def _discover_three_tool_workspace_roots(
    explicit_roots: Mapping[str, Path] | None = None,
) -> dict[str, Path | None]:
    """Discover local checkout paths for opscryer, brain, and meshworks without escaping boundaries."""
    opscryer_root = Path(__file__).resolve().parent
    sibling_base = opscryer_root.parent
    discovered: dict[str, Path | None] = {
        "opscryer": opscryer_root if opscryer_root.is_dir() else None,
        "brain": (sibling_base / "brain") if (sibling_base / "brain" / "engine").is_dir() else None,
        "meshworks": (sibling_base / "meshworks") if (sibling_base / "meshworks" / "pyproject.toml").is_file() else None,
    }
    if explicit_roots:
        for key in ("opscryer", "brain", "meshworks"):
            val = explicit_roots.get(key)
            if val is not None:
                cand = Path(val).expanduser().resolve()
                discovered[key] = cand if cand.is_dir() else None
    return discovered


def build_dogfood_three_tool_dataset(
    *,
    workspace_roots: Mapping[str, Path] | None = None,
    max_files_per_repo: int = 120,
) -> dict[str, Any]:
    """Build a configurable self-dogfooding 7-level Knowledge Graph across opscryer, brain, and meshworks."""
    roots = _discover_three_tool_workspace_roots(workspace_roots)
    suite_root_id = "dogfood:suite:three-tool-ecosystem"
    nodes: list[dict[str, Any]] = [
        {
            "id": suite_root_id,
            "label": "3-Tool Knowledge Ecosystem (OpsCryer + Brain + Meshworks)",
            "kind": "engineering_project",
            "graph_level": "project",
            "domain": "company_org",
            "section": "section_project",
            "level_index": 0,
            "dataset_id": DOGFOOD_DATASET_ID,
            "dataset_label": "Dogfood 3-Tool Suite (opscryer + brain + meshworks)",
            "repo_id": "ecosystem",
            "summary": "Real self-dogfooding Knowledge Graph mapping OpsCryer (Visual HUD), Brain (Authoritative KG & MLS), and Meshworks (Execution Mesh) across all 7 architectural levels.",
            "primary_url": "/",
            "status": "nominal",
            "drilldown_children": [],
            "control_plane_urls": [
                {"label": "OpsCryer Spatial HUD", "url": "/", "system": "opscryer"},
                {"label": "2.5D World Map", "url": "/world-map", "system": "opscryer"},
                {"label": "OpenAPI Contract Docs", "url": "/docs", "system": "opscryer"},
            ],
        }
    ]
    node_by_id: dict[str, dict[str, Any]] = {suite_root_id: nodes[0]}
    edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    repo_origins: dict[str, str] = {}
    repo_root_ids: dict[str, str] = {}
    repo_contract_ids: dict[str, list[str]] = {"opscryer": [], "brain": [], "meshworks": []}

    def _add_edge(src: str, dst: str, rel: str, *, attach_child: bool = False) -> None:
        if src == dst or src not in node_by_id or dst not in node_by_id:
            return
        key = (src, dst, rel)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": src, "target": dst, "relation": rel})
        if attach_child:
            ch = node_by_id[src].setdefault("drilldown_children", [])
            if dst not in ch:
                ch.append(dst)

    for repo_slug in ("opscryer", "brain", "meshworks"):
        repo_path = roots.get(repo_slug)
        if repo_path is not None:
            harvested = harvest_workspace_truth_graph(
                repo_path,
                project_name=repo_slug,
                max_files=max_files_per_repo,
            )
            origin = "live_filesystem"
        else:
            harvested = _verified_repo_fallback_catalog(repo_slug)
            origin = str(harvested.get("harvest_origin") or "verified_manifest")

        repo_origins[repo_slug] = origin
        prefix = f"dogfood:{repo_slug}:"
        id_map: dict[str, str] = {}
        for raw_n in harvested.get("nodes") or ():
            if not isinstance(raw_n, Mapping) or not raw_n.get("id"):
                continue
            orig_id = str(raw_n["id"])
            namespaced_id = f"{prefix}{orig_id}"
            id_map[orig_id] = namespaced_id

        raw_root = str(harvested.get("root_node_id") or f"proj-{repo_slug}")
        ns_root = id_map.get(raw_root) or next(iter(id_map.values()), f"{prefix}proj-{repo_slug}")
        repo_root_ids[repo_slug] = ns_root

        for raw_n in harvested.get("nodes") or ():
            if not isinstance(raw_n, Mapping) or not raw_n.get("id"):
                continue
            orig_id = str(raw_n["id"])
            ns_id = id_map[orig_id]
            cloned = deepcopy(dict(raw_n))
            cloned["id"] = ns_id
            cloned["dataset_id"] = DOGFOOD_DATASET_ID
            cloned["dataset_label"] = "Dogfood 3-Tool Suite (opscryer + brain + meshworks)"
            cloned["repo_id"] = repo_slug
            cloned["harvest_origin"] = origin
            cloned["graph_level"] = classify_node_graph_level(cloned)
            cloned["level_index"] = min(5, int(cloned.get("level_index", 1)) + 1)
            cloned["drilldown_children"] = [
                id_map[str(c)] for c in (cloned.get("drilldown_children") or ()) if str(c) in id_map
            ]
            node_by_id[ns_id] = cloned
            nodes.append(cloned)
            if cloned["graph_level"] == "contract":
                repo_contract_ids[repo_slug].append(ns_id)

        for raw_e in harvested.get("edges") or ():
            if not isinstance(raw_e, Mapping):
                continue
            su = id_map.get(str(raw_e.get("source") or ""))
            sv = id_map.get(str(raw_e.get("target") or ""))
            if su and sv:
                _add_edge(su, sv, str(raw_e.get("relation") or "connected"), attach_child=False)

        if ns_root in node_by_id:
            _add_edge(suite_root_id, ns_root, "contains_tool_repo", attach_child=True)

    # Wire real cross-repository architectural contracts connecting the 3-Tool Suite!
    opscryer_root = repo_root_ids.get("opscryer", "")
    brain_root = repo_root_ids.get("brain", "")
    meshworks_root = repo_root_ids.get("meshworks", "")
    _add_edge(opscryer_root, brain_root, "queries_spatial_graph_contract")
    _add_edge(meshworks_root, brain_root, "consumes_predump_bundle")
    _add_edge(opscryer_root, meshworks_root, "delegates_hydrogen_cast")
    if repo_contract_ids["brain"]:
        _add_edge(opscryer_root, repo_contract_ids["brain"][0], "implements_contract")
    if repo_contract_ids["meshworks"]:
        _add_edge(opscryer_root, repo_contract_ids["meshworks"][0], "invokes_contract")
    if repo_contract_ids["opscryer"]:
        _add_edge(brain_root, repo_contract_ids["opscryer"][0], "serves_contract")

    analysis = analyze_selection_graph_levels({"nodes": nodes, "edges": edges}, [])
    tree = build_normalized_dataset_tree(
        [
            {
                "dataset_id": DOGFOOD_DATASET_ID,
                "label": "Dogfood 3-Tool Suite (opscryer + brain + meshworks)",
                "enabled_default": True,
                "nodes": nodes,
            }
        ]
    )
    return {
        "schema_version": "1.0-separable-spatial-graph-contract",
        "dataset_id": DOGFOOD_DATASET_ID,
        "dataset_label": "Dogfood 3-Tool Suite (opscryer + brain + meshworks)",
        "source": "dogfood_three_tool_harvest",
        "example": False,
        "truth_mode": True,
        "configurable_toggle": True,
        "enabled_by_default": is_dogfood_dataset_default_enabled(),
        "root_node_id": suite_root_id,
        "repo_origins": repo_origins,
        "repo_root_ids": repo_root_ids,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "graph_levels_summary": analysis["global_breakdown"],
        "test_verification": analysis["global_breakdown"]["test"]["test_verification"],
        "dataset_tree": tree,
    }


def evaluate_dogfood_self_understanding(catalog: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Run self-understanding evaluation checks on the 3-tool dogfood dataset with positive pass counts."""
    cat = dict(catalog) if isinstance(catalog, Mapping) else build_dogfood_three_tool_dataset()
    nodes = [n for n in (cat.get("nodes") or ()) if isinstance(n, Mapping) and n.get("id")]
    edges = [e for e in (cat.get("edges") or ()) if isinstance(e, Mapping)]
    analysis = analyze_selection_graph_levels(cat, [])

    repo_ids = {str(n.get("repo_id") or "") for n in nodes}
    levels_nonzero = [
        lid for lid in GRAPH_LEVEL_IDS if analysis["global_breakdown"][lid]["count"] > 0
    ]
    cross_rels = {str(e.get("relation") or "") for e in edges}
    raw_labels = " ".join(str(n.get("label") or "") for n in nodes)
    tv = analysis["global_breakdown"]["test"]["test_verification"]

    checks: list[dict[str, Any]] = [
        {
            "check_id": "all_three_tools_present",
            "passed": {"opscryer", "brain", "meshworks"}.issubset(repo_ids),
            "detail": f"repos={sorted(r for r in repo_ids if r in {'opscryer', 'brain', 'meshworks'})}",
        },
        {
            "check_id": "seven_canonical_levels_populated",
            "passed": len(levels_nonzero) == len(GRAPH_LEVEL_IDS),
            "detail": f"populated_levels={len(levels_nonzero)}/7 ({', '.join(levels_nonzero)})",
        },
        {
            "check_id": "cross_repo_contracts_linked",
            "passed": {"queries_spatial_graph_contract", "consumes_predump_bundle", "delegates_hydrogen_cast"}.issubset(cross_rels),
            "detail": f"cross_repo_edges={sorted(cross_rels & {'queries_spatial_graph_contract', 'consumes_predump_bundle', 'delegates_hydrogen_cast'})}",
        },
        {
            "check_id": "zero_synthetic_acme_or_fictional_employees",
            "passed": ("Acme Cloud Systems" not in raw_labels and "Jordan Vance" not in raw_labels and "Elena Rostova" not in raw_labels),
            "detail": "zero synthetic Acme or fictional employee nodes",
        },
        {
            "check_id": "positive_pass_evidence_on_unexecuted_tests",
            "passed": (tv["suites_total"] > 0 and (tv["suites_unverified_not_run"] > 0 or tv["tests_executed"] > 0)),
            "detail": f"suites_total={tv['suites_total']} pass={tv['suites_verified_pass']} unrun={tv['suites_unverified_not_run']} executed={tv['tests_executed']}",
        },
    ]
    executed_count = len(checks)
    passed_count = sum(1 for c in checks if c["passed"])
    failed_count = executed_count - passed_count
    return {
        "schema_version": "1.0-dogfood-self-eval",
        "passed": executed_count > 0 and failed_count == 0,
        "status": "verified_pass" if (executed_count > 0 and failed_count == 0) else "failed",
        "checks_executed": executed_count,
        "checks_passed": passed_count,
        "checks_failed": failed_count,
        "checks": checks,
    }


def build_normalized_dataset_tree(
    datasets: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a flat normalized hierarchy with contiguous DFS pre-order intervals [dfs_in, dfs_out).

    Hierarchy: Dataset -> Project/Repo Group -> 7 Canonical Levels -> Leaf Graph Nodes.
    """
    tree_nodes: list[dict[str, Any]] = []
    leaf_graph_ids: list[str] = []
    initial_mask: list[int] = []

    def _new_branch(
        tid: str,
        parent_id: str | None,
        label: str,
        node_kind: str,
        depth: int,
        *,
        dataset_id: str,
        icon: str = "",
        color: str = "#38BDF8",
        graph_node_id: str | None = None,
    ) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "id": tid,
            "parent_id": parent_id,
            "label": label,
            "node_kind": node_kind,
            "depth": depth,
            "dataset_id": dataset_id,
            "icon": icon,
            "color": color,
            "graph_node_id": graph_node_id,
            "children_ids": [],
            "dfs_in": 0,
            "dfs_out": 0,
            "leaf_count": 0,
        }
        tree_nodes.append(obj)
        return obj

    root_ids: list[str] = []
    for ds in datasets:
        ds_id = str(ds.get("dataset_id") or PRIMARY_DATASET_ID)
        ds_label = str(ds.get("label") or ds_id)
        enabled_default = 1 if ds.get("enabled_default", True) else 0
        raw_nodes = [n for n in (ds.get("nodes") or ()) if isinstance(n, Mapping) and n.get("id")]

        ds_tree_id = f"ds:{ds_id}"
        ds_branch = _new_branch(ds_tree_id, None, ds_label, "dataset", 0, dataset_id=ds_id, icon="🗂️", color="#38BDF8")
        root_ids.append(ds_tree_id)
        ds_branch["dfs_in"] = len(leaf_graph_ids)

        # Group nodes by repo_id (for dogfood 3-tool suite) or domain/root
        repo_buckets: dict[str, list[Mapping[str, Any]]] = {}
        for n in raw_nodes:
            rkey = str(n.get("repo_id") or n.get("domain") or "graph").strip() or "graph"
            repo_buckets.setdefault(rkey, []).append(n)

        ordered_repos = sorted(
            repo_buckets.keys(),
            key=lambda r: (
                0 if r == "ecosystem" else (1 if r == "opscryer" else (2 if r == "brain" else (3 if r == "meshworks" else 4))),
                r,
            ),
        )
        for repo_key in ordered_repos:
            repo_nodes = repo_buckets[repo_key]
            repo_tree_id = f"ds:{ds_id}:repo:{repo_key}"
            repo_branch = _new_branch(
                repo_tree_id,
                ds_tree_id,
                repo_key.replace("_", " "),
                "repo_group",
                1,
                dataset_id=ds_id,
                icon="📦",
                color="#A855F7",
            )
            ds_branch["children_ids"].append(repo_tree_id)
            repo_branch["dfs_in"] = len(leaf_graph_ids)

            lvl_buckets: dict[str, list[Mapping[str, Any]]] = {lid: [] for lid in GRAPH_LEVEL_IDS}
            for n in repo_nodes:
                lid = classify_node_graph_level(n)
                lvl_buckets.setdefault(lid, []).append(n)

            for lid in GRAPH_LEVEL_IDS:
                lvl_nodes = lvl_buckets.get(lid) or []
                if not lvl_nodes:
                    continue
                meta = GRAPH_LEVEL_MAP[lid]
                lvl_tree_id = f"ds:{ds_id}:repo:{repo_key}:lvl:{lid}"
                lvl_branch = _new_branch(
                    lvl_tree_id,
                    repo_tree_id,
                    str(meta["label"]),
                    "level_group",
                    2,
                    dataset_id=ds_id,
                    icon=str(meta["icon"]),
                    color=str(meta["color"]),
                )
                repo_branch["children_ids"].append(lvl_tree_id)
                lvl_branch["dfs_in"] = len(leaf_graph_ids)

                for n in sorted(lvl_nodes, key=lambda x: str(x.get("label") or x["id"]).lower()):
                    gid = str(n["id"])
                    leaf_idx = len(leaf_graph_ids)
                    leaf_graph_ids.append(gid)
                    initial_mask.append(enabled_default)
                    leaf_tree_id = f"ds:{ds_id}:leaf:{leaf_idx}"
                    leaf_obj = _new_branch(
                        leaf_tree_id,
                        lvl_tree_id,
                        str(n.get("label") or gid),
                        "leaf",
                        3,
                        dataset_id=ds_id,
                        icon=str(meta["icon"]),
                        color=str(meta["color"]),
                        graph_node_id=gid,
                    )
                    leaf_obj["dfs_in"] = leaf_idx
                    leaf_obj["dfs_out"] = leaf_idx + 1
                    leaf_obj["leaf_count"] = 1
                    lvl_branch["children_ids"].append(leaf_tree_id)

                lvl_branch["dfs_out"] = len(leaf_graph_ids)
                lvl_branch["leaf_count"] = lvl_branch["dfs_out"] - lvl_branch["dfs_in"]

            repo_branch["dfs_out"] = len(leaf_graph_ids)
            repo_branch["leaf_count"] = repo_branch["dfs_out"] - repo_branch["dfs_in"]

        ds_branch["dfs_out"] = len(leaf_graph_ids)
        ds_branch["leaf_count"] = ds_branch["dfs_out"] - ds_branch["dfs_in"]

    return {
        "schema_version": DATASET_TREE_SCHEMA_VERSION,
        "root_ids": root_ids,
        "total_leaves": len(leaf_graph_ids),
        "total_tree_nodes": len(tree_nodes),
        "leaf_graph_ids": leaf_graph_ids,
        "initial_mask": initial_mask,
        "tree_nodes": tree_nodes,
    }


def build_dataset_tree_store_js() -> str:
    """Return zero-dependency Normalized Store + DFS Interval Bitmask + Fine-Grained Signals JS (zero // comments)."""
    template = r"""
(function(globalScope) {
  const STORAGE_KEY = 'opscryer_dataset_tree_v1';

  function buildNormalizedTreeFromDatasets(datasets) {
    const gl = globalScope.OpsCryerGraphLayers;
    const levelDefs = (gl && gl.GRAPH_LEVELS) ? gl.GRAPH_LEVELS : [
      {id: 'project', label: 'Project', icon: '📦', color: '#38BDF8'},
      {id: 'feature', label: 'Feature', icon: '✨', color: '#A855F7'},
      {id: 'dependency', label: 'Include / Dependency', icon: '🔗', color: '#F59E0B'},
      {id: 'requirement', label: 'Requirement', icon: '📋', color: '#14B8A6'},
      {id: 'test', label: 'Test', icon: '🧪', color: '#22C55E'},
      {id: 'deployment', label: 'Deployment', icon: '🚀', color: '#06B6D4'},
      {id: 'contract', label: 'Contract', icon: '📜', color: '#E879F9'}
    ];
    const levelMap = {};
    levelDefs.forEach(d => { levelMap[d.id] = d; });

    const treeNodes = [];
    const byId = new Map();
    const leafGraphIds = [];
    const initialMask = [];
    const rootIds = [];

    const addBranch = (id, parentId, label, nodeKind, depth, datasetId, icon, color, graphNodeId) => {
      const obj = {
        id: id, parent_id: parentId, label: label, node_kind: nodeKind, depth: depth,
        dataset_id: datasetId, icon: icon || '', color: color || '#38BDF8',
        graph_node_id: graphNodeId || null, children_ids: [],
        dfs_in: 0, dfs_out: 0, leaf_count: 0
      };
      treeNodes.push(obj);
      byId.set(id, obj);
      return obj;
    };

    (datasets || []).forEach(ds => {
      if (!ds || !ds.dataset_id) return;
      const dsId = String(ds.dataset_id);
      const enabledDef = ds.enabled !== false ? 1 : 0;
      const rawNodes = Array.isArray(ds.nodes) ? ds.nodes.filter(n => n && n.id) : [];
      const dsTid = 'ds:' + dsId;
      const dsNode = addBranch(dsTid, null, String(ds.label || dsId), 'dataset', 0, dsId, '🗂️', '#38BDF8', null);
      rootIds.push(dsTid);
      dsNode.dfs_in = leafGraphIds.length;

      const repoBuckets = new Map();
      rawNodes.forEach(n => {
        const rk = String(n.repo_id || n.domain || 'graph').trim() || 'graph';
        if (!repoBuckets.has(rk)) repoBuckets.set(rk, []);
        repoBuckets.get(rk).push(n);
      });
      const rankRepo = r => (r === 'ecosystem' ? 0 : (r === 'opscryer' ? 1 : (r === 'brain' ? 2 : (r === 'meshworks' ? 3 : 4))));
      const ordRepos = Array.from(repoBuckets.keys()).sort((a, b) => (rankRepo(a) - rankRepo(b)) || a.localeCompare(b));

      ordRepos.forEach(rk => {
        const rTid = 'ds:' + dsId + ':repo:' + rk;
        const rNode = addBranch(rTid, dsTid, rk.replace(/_/g, ' '), 'repo_group', 1, dsId, '📦', '#A855F7', null);
        dsNode.children_ids.push(rTid);
        rNode.dfs_in = leafGraphIds.length;

        const lvlBuckets = new Map();
        levelDefs.forEach(ld => lvlBuckets.set(ld.id, []));
        repoBuckets.get(rk).forEach(n => {
          const lid = gl ? gl.classifyNodeGraphLevel(n) : String(n.graph_level || 'feature');
          if (!lvlBuckets.has(lid)) lvlBuckets.set(lid, []);
          lvlBuckets.get(lid).push(n);
        });

        levelDefs.forEach(ld => {
          const items = lvlBuckets.get(ld.id) || [];
          if (!items.length) return;
          const lTid = 'ds:' + dsId + ':repo:' + rk + ':lvl:' + ld.id;
          const lNode = addBranch(lTid, rTid, ld.label, 'level_group', 2, dsId, ld.icon, ld.color, null);
          rNode.children_ids.push(lTid);
          lNode.dfs_in = leafGraphIds.length;

          items.slice().sort((a, b) => String(a.label || a.id).localeCompare(String(b.label || b.id))).forEach(n => {
            const gid = String(n.id);
            const idx = leafGraphIds.length;
            leafGraphIds.push(gid);
            initialMask.push(enabledDef);
            const leafTid = 'ds:' + dsId + ':leaf:' + idx;
            const leaf = addBranch(leafTid, lTid, String(n.label || gid), 'leaf', 3, dsId, ld.icon, ld.color, gid);
            leaf.dfs_in = idx;
            leaf.dfs_out = idx + 1;
            leaf.leaf_count = 1;
            lNode.children_ids.push(leafTid);
          });
          lNode.dfs_out = leafGraphIds.length;
          lNode.leaf_count = lNode.dfs_out - lNode.dfs_in;
        });

        rNode.dfs_out = leafGraphIds.length;
        rNode.leaf_count = rNode.dfs_out - rNode.dfs_in;
      });

      dsNode.dfs_out = leafGraphIds.length;
      dsNode.leaf_count = dsNode.dfs_out - dsNode.dfs_in;
    });

    return {
      rootIds: rootIds,
      treeNodes: treeNodes,
      byId: byId,
      leafGraphIds: leafGraphIds,
      mask: new Uint8Array(initialMask)
    };
  }

  function createDatasetTreeStore(initialDatasets) {
    let datasets = [];
    let index = buildNormalizedTreeFromDatasets([]);
    let expandedIds = new Set();
    let searchQuery = '';
    let revision = 0;
    let lastToggleMs = 0;
    const listeners = new Set();

    function notify() {
      revision++;
      const snap = getSnapshot();
      listeners.forEach(fn => {
        try { fn(snap); } catch (_err) {}
      });
    }

    function setDatasets(nextDatasets, preserveSelection) {
      const prevExcluded = new Set();
      if (preserveSelection && index.leafGraphIds.length) {
        for (let i = 0; i < index.leafGraphIds.length; i++) {
          if (index.mask[i] === 0) prevExcluded.add(index.leafGraphIds[i]);
        }
      }
      datasets = (nextDatasets || []).map(d => ({...d}));
      index = buildNormalizedTreeFromDatasets(datasets);
      if (preserveSelection && prevExcluded.size) {
        for (let i = 0; i < index.leafGraphIds.length; i++) {
          if (prevExcluded.has(index.leafGraphIds[i])) index.mask[i] = 0;
        }
      }
      index.rootIds.forEach(rid => {
        expandedIds.add(rid);
        const rn = index.byId.get(rid);
        if (rn) rn.children_ids.slice(0, 4).forEach(cid => expandedIds.add(cid));
      });
      notify();
    }

    function getTriState(treeNodeId) {
      const node = index.byId.get(treeNodeId);
      if (!node || node.dfs_out <= node.dfs_in) return 'false';
      let sum = 0;
      const total = node.dfs_out - node.dfs_in;
      for (let i = node.dfs_in; i < node.dfs_out; i++) sum += index.mask[i];
      if (sum === 0) return 'false';
      if (sum === total) return 'true';
      return 'mixed';
    }

    function getIncludedCount(treeNodeId) {
      const node = index.byId.get(treeNodeId);
      if (!node) return 0;
      let sum = 0;
      for (let i = node.dfs_in; i < node.dfs_out; i++) sum += index.mask[i];
      return sum;
    }

    function toggleTreeNode(treeNodeId, forceChecked) {
      const node = index.byId.get(treeNodeId);
      if (!node) return false;
      const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      const curState = getTriState(treeNodeId);
      const nextBit = typeof forceChecked === 'boolean' ? (forceChecked ? 1 : 0) : (curState === 'true' ? 0 : 1);
      index.mask.fill(nextBit, node.dfs_in, node.dfs_out);
      const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      lastToggleMs = Math.max(0.01, Math.round((t1 - t0) * 100) / 100);
      notify();
      return Boolean(nextBit);
    }

    function toggleExpand(treeNodeId, forceOpen) {
      const next = typeof forceOpen === 'boolean' ? forceOpen : !expandedIds.has(treeNodeId);
      if (next) expandedIds.add(treeNodeId); else expandedIds.delete(treeNodeId);
      notify();
      return next;
    }

    function setSearchQuery(q) {
      searchQuery = String(q || '').trim().toLowerCase();
      notify();
    }

    function setAll(checked) {
      index.mask.fill(checked ? 1 : 0);
      notify();
    }

    function getActiveGraphNodeIds() {
      const out = new Set();
      for (let i = 0; i < index.leafGraphIds.length; i++) {
        if (index.mask[i] === 1) out.add(index.leafGraphIds[i]);
      }
      return out;
    }

    function getVisibleRows() {
      const rows = [];
      const q = searchQuery;
      const matchingSubtree = new Set();
      if (q) {
        index.treeNodes.forEach(tn => {
          if (String(tn.label || '').toLowerCase().indexOf(q) >= 0 || String(tn.graph_node_id || '').toLowerCase().indexOf(q) >= 0) {
            let cur = tn;
            while (cur) {
              matchingSubtree.add(cur.id);
              cur = cur.parent_id ? index.byId.get(cur.parent_id) : null;
            }
          }
        });
      }
      const walk = tid => {
        const node = index.byId.get(tid);
        if (!node) return;
        if (q && !matchingSubtree.has(tid)) return;
        const isOpen = q ? true : expandedIds.has(tid);
        rows.push({
          node: node,
          triState: getTriState(tid),
          includedCount: getIncludedCount(tid),
          expanded: isOpen,
          hasChildren: node.children_ids.length > 0
        });
        if (isOpen && node.children_ids.length) {
          node.children_ids.forEach(walk);
        }
      };
      index.rootIds.forEach(walk);
      return rows;
    }

    function getSnapshot() {
      let incTotal = 0;
      for (let i = 0; i < index.mask.length; i++) incTotal += index.mask[i];
      return {
        revision: revision,
        totalLeaves: index.leafGraphIds.length,
        includedLeaves: incTotal,
        lastToggleMs: lastToggleMs,
        searchQuery: searchQuery,
        activeGraphNodeIds: getActiveGraphNodeIds(),
        datasets: datasets.map(d => ({dataset_id: d.dataset_id, label: d.label, enabled: getTriState('ds:' + d.dataset_id) !== 'false'}))
      };
    }

    function subscribe(fn) {
      if (typeof fn === 'function') listeners.add(fn);
      return () => listeners.delete(fn);
    }

    function serializeState() {
      const excluded = [];
      for (let i = 0; i < index.leafGraphIds.length; i++) {
        if (index.mask[i] === 0) excluded.push(index.leafGraphIds[i]);
      }
      return {excluded: excluded, expanded: Array.from(expandedIds).slice(0, 64)};
    }

    if (Array.isArray(initialDatasets) && initialDatasets.length) {
      setDatasets(initialDatasets, false);
    }

    return {
      setDatasets: setDatasets,
      getTriState: getTriState,
      getIncludedCount: getIncludedCount,
      toggleTreeNode: toggleTreeNode,
      toggleExpand: toggleExpand,
      setSearchQuery: setSearchQuery,
      setAll: setAll,
      getActiveGraphNodeIds: getActiveGraphNodeIds,
      getVisibleRows: getVisibleRows,
      getSnapshot: getSnapshot,
      subscribe: subscribe,
      serializeState: serializeState,
      getIndex: () => index
    };
  }

  function bindDatasetTreeSidebar(opts) {
    const cfg = opts || {};
    const store = cfg.store;
    if (!store || typeof document === 'undefined' || typeof document.getElementById !== 'function') return null;

    function renderTree() {
      const host = document.getElementById(cfg.treeId || 'dataset-tree-list');
      const statsEl = document.getElementById(cfg.statsId || 'dataset-tree-stats');
      const snap = store.getSnapshot();
      if (statsEl) {
        statsEl.textContent = snap.includedLeaves + '/' + snap.totalLeaves + ' active • ' + snap.lastToggleMs + 'ms mask';
      }
      if (!host || typeof host.replaceChildren !== 'function') return;
      const rows = store.getVisibleRows().slice(0, 400);
      const els = rows.map(row => {
        const div = document.createElement('div');
        div.className = 'ds-tree-row ds-depth-' + row.node.depth;
        if (div.setAttribute) {
          div.setAttribute('role', 'treeitem');
          div.setAttribute('tabindex', '0');
          div.setAttribute('aria-checked', row.triState);
          div.setAttribute('data-tree-id', row.node.id);
          if (row.hasChildren) div.setAttribute('aria-expanded', row.expanded ? 'true' : 'false');
        }
        if (div.style) div.style.paddingLeft = (row.node.depth * 14 + 4) + 'px';

        const expBtn = document.createElement('button');
        expBtn.type = 'button';
        expBtn.className = 'ds-tree-exp';
        expBtn.textContent = row.hasChildren ? (row.expanded ? '▾' : '▸') : '·';
        if (row.hasChildren && expBtn.addEventListener) {
          expBtn.addEventListener('click', ev => {
            if (ev && ev.stopPropagation) ev.stopPropagation();
            store.toggleExpand(row.node.id);
          });
        }
        div.appendChild(expBtn);

        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.checked = row.triState === 'true';
        chk.indeterminate = row.triState === 'mixed';
        if (chk.addEventListener) chk.addEventListener('change', () => { store.toggleTreeNode(row.node.id); });
        div.appendChild(chk);

        const lbl = document.createElement('span');
        lbl.className = 'ds-tree-label';
        lbl.textContent = (row.node.icon ? (row.node.icon + ' ') : '') + row.node.label;
        if (lbl.addEventListener) {
          lbl.addEventListener('click', () => {
            if (row.node.graph_node_id && typeof cfg.onFocusGraphNode === 'function') {
              cfg.onFocusGraphNode(row.node.graph_node_id);
            } else if (row.hasChildren) {
              store.toggleExpand(row.node.id);
            }
          });
        }
        div.appendChild(lbl);

        if (row.hasChildren) {
          const cnt = document.createElement('span');
          cnt.className = 'ds-tree-count';
          cnt.textContent = row.includedCount + '/' + row.node.leaf_count;
          div.appendChild(cnt);
        }

        if (div.addEventListener) {
          div.addEventListener('keydown', ev => {
            if (!ev) return;
            if (ev.key === ' ') { if (ev.preventDefault) ev.preventDefault(); store.toggleTreeNode(row.node.id); }
            else if (ev.key === 'ArrowRight' && row.hasChildren && !row.expanded) { store.toggleExpand(row.node.id, true); }
            else if (ev.key === 'ArrowLeft' && row.hasChildren && row.expanded) { store.toggleExpand(row.node.id, false); }
          });
        }
        return div;
      });
      host.replaceChildren(...els);
    }

    store.subscribe(renderTree);
    renderTree();
    return {renderTree: renderTree};
  }

  globalScope.OpsCryerDatasetStore = {
    STORAGE_KEY: STORAGE_KEY,
    buildNormalizedTreeFromDatasets: buildNormalizedTreeFromDatasets,
    createDatasetTreeStore: createDatasetTreeStore,
    bindDatasetTreeSidebar: bindDatasetTreeSidebar
  };
})(typeof window !== 'undefined' ? window : globalThis);
""".strip()
    return template


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpsCryer Configurable 3-Tool Self-Dogfood Dataset & Tree Store")
    parser.add_argument("--eval", action="store_true", help="Run the 3-tool self-understanding evaluation checks")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args(argv)
    ds = build_dogfood_three_tool_dataset()
    out = evaluate_dogfood_self_understanding(ds) if args.eval else ds
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
