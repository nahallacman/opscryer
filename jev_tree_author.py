# SPDX-License-Identifier: Apache-2.0
"""Offline System-2 to System-1 Jev Decision Tree validator and branch compiler."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from typing import Any

from jev_client import SystemOneJevClient, evaluate_ticket_with_jev_tree
from knowledge_base import CONCIERGE_JEV_TREE


def validate_authored_jev_tree(
    tree: dict[str, Any],
    catalog: dict[str, Any] | None = None,
) -> list[str]:
    """Validate structural integrity, acyclicity, and optional catalog anchor existence."""
    if not isinstance(tree, dict):
        return ["tree must be a dict"]
    errors: list[str] = []
    if tree.get("schema_version") != "1.0-system-one-decision-tree":
        errors.append("unsupported schema_version")
    root_id = tree.get("root_node_id")
    nodes = tree.get("nodes")
    if not isinstance(nodes, dict) or not nodes:
        return errors + ["nodes must be a nonempty dict"]
    if not isinstance(root_id, str) or root_id not in nodes:
        errors.append("root_node_id missing from nodes")
        return errors

    catalog_ids = None
    if isinstance(catalog, dict) and isinstance(catalog.get("nodes"), list):
        catalog_ids = {n.get("id") for n in catalog["nodes"] if isinstance(n, dict)}

    for nid, node in nodes.items():
        if not isinstance(node, dict):
            errors.append(f"{nid} must be a dict")
            continue
        kind = node.get("kind")
        anchor = node.get("anchor_node_id")
        if not isinstance(anchor, str) or not anchor.strip():
            errors.append(f"{nid} requires anchor_node_id")
        elif catalog_ids is not None and anchor not in catalog_ids:
            errors.append(f"{nid} references unknown catalog anchor {anchor}")
        if kind == "decision":
            for branch in ("true_branch", "false_branch"):
                target = node.get(branch)
                if not isinstance(target, str) or target not in nodes:
                    errors.append(f"{nid}.{branch} references unknown node")
        elif kind == "leaf":
            if not isinstance(node.get("policy_id"), str) or not node["policy_id"].strip():
                errors.append(f"{nid} requires policy_id")
            if type(node.get("direct_access_allowed")) is not bool:
                errors.append(f"{nid} requires boolean direct_access_allowed")
        else:
            errors.append(f"{nid} has unsupported kind")

    # Verify acyclicity and reachability from root_node_id
    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(curr: str) -> None:
        if curr in visiting:
            errors.append(f"cycle detected at {curr}")
            return
        if curr in visited or curr not in nodes or not isinstance(nodes[curr], dict):
            return
        visiting.add(curr)
        node = nodes[curr]
        if node.get("kind") == "decision":
            for branch in ("true_branch", "false_branch"):
                nxt = node.get(branch)
                if isinstance(nxt, str):
                    dfs(nxt)
        visiting.remove(curr)
        visited.add(curr)

    dfs(root_id)
    unreachable = sorted(set(nodes) - visited)
    if unreachable:
        errors.append("unreachable nodes: " + ", ".join(unreachable))
    return errors


def dry_run_jev_tree_samples(
    tree: dict[str, Any] | None = None,
    sample_tickets: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Validate tree and run deterministic dry-run assertions over sample (ticket, expected_policy) pairs."""
    active_tree = deepcopy(tree if tree is not None else CONCIERGE_JEV_TREE)
    validation_errors = validate_authored_jev_tree(active_tree)
    samples = sample_tickets or [
        ("How 2 database connect to PostgreSQL?", "playbook-golden-path-database-cnpg"),
        ("Scaffold a new 3-tier microservice pipeline", "playbook-demo-golden-path-3tier"),
        ("Minecraft server lagging with high MSPT", "playbook-game-server-observability"),
    ]
    outcomes: list[dict[str, Any]] = []
    for title, expected_policy in samples:
        res = evaluate_ticket_with_jev_tree(title, active_tree, provider="deterministic")
        outcomes.append({
            "ticket_title": title,
            "expected_policy": expected_policy,
            "actual_policy": res.get("policy_id"),
            "matched": res.get("policy_id") == expected_policy,
        })
    return {
        "schema_version": "1.0-jev-tree-author-report",
        "tree_valid": len(validation_errors) == 0,
        "validation_errors": validation_errors,
        "node_count": len(active_tree.get("nodes", {})),
        "sample_outcomes": outcomes,
        "all_samples_matched": all(item["matched"] for item in outcomes) and not validation_errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = dry_run_jev_tree_samples()
    print(json.dumps(report, indent=2))
    return 0 if report["all_samples_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
