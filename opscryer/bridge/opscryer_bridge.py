# SPDX-License-Identifier: Apache-2.0
"""OpsCryer Bridge: translates brain and meshworks state into spatial graph catalogs."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


CONTRACT_VERSION = "1.0-separable-spatial-graph-contract"

_CATEGORY_TO_DOMAIN = {
    "platform": "deployments_k8s",
    "infrastructure": "deployments_k8s",
    "process": "processes_workflows",
    "tooling": "processes_workflows",
    "productivity": "company_org",
    "hardware": "hardware_topology",
}


def build_spatial_graph_catalog(
    tasks: Optional[List[Dict[str, Any]]] = None,
    mrs: Optional[List[Dict[str, Any]]] = None,
    projects: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate a lightweight bridge summary catalog dictionary."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tasks": tasks or [],
        "merge_requests": mrs or [],
        "projects": projects or [],
    }


def _load_json_safe(path: Optional[Path]) -> Any:
    if path is None or not Path(path).is_file():
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _safe_id(prefix: str, raw: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in str(raw)).strip("-")
    return f"{prefix}-{cleaned or 'item'}"


def _extract_node_mls(source: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract normalized MLS metadata from an entry or return None if unclassified."""
    if not isinstance(source, dict):
        return None
    raw_mls = source.get("mls") if isinstance(source.get("mls"), dict) else None
    has_top_level = any(
        k in source for k in ("classification_rank", "compartments", "visibility", "scope")
    )
    if raw_mls is None and not has_top_level:
        return None
    holder = raw_mls if raw_mls is not None else source
    rank = int(holder.get("classification_rank", source.get("classification_rank", 0)) or 0)
    raw_comps = holder.get("compartments", source.get("compartments")) or []
    comps = sorted({str(c).strip() for c in raw_comps if str(c).strip()})
    scope = str(holder.get("scope", source.get("scope", "")) or "").strip().lower()
    raw_vis = str(holder.get("visibility", source.get("visibility", "")) or "").strip().upper()
    if raw_vis in ("OPAQUE", "STUB", "FULL"):
        vis = raw_vis
    elif scope == "project" and rank > 0:
        vis = "OPAQUE"
    else:
        vis = "STUB"
    result: Dict[str, Any] = {
        "classification_rank": rank,
        "compartments": comps,
        "visibility": vis,
    }
    if scope:
        result["scope"] = scope
    return result


def filter_spatial_catalog_by_clearance(
    catalog: Dict[str, Any],
    viewer_rank: int = 0,
    viewer_compartments: Optional[List[str]] = None,
    system_high: bool = False,
) -> Dict[str, Any]:
    """Filter or scrub SpatialGraphContract nodes according to viewer `(rank, compartments)` dominance."""
    filtered = deepcopy(catalog) if isinstance(catalog, dict) else {}
    comp_set = frozenset(str(c).strip() for c in (viewer_compartments or []) if str(c).strip())
    v_rank = int(viewer_rank)

    raw_nodes = filtered.get("nodes") if isinstance(filtered.get("nodes"), list) else []
    raw_edges = filtered.get("edges") if isinstance(filtered.get("edges"), list) else []

    if system_high:
        # System-High host mode renders the full catalog while stamping output with MLS posture.
        kept_nodes = [deepcopy(n) for n in raw_nodes if isinstance(n, dict) and n.get("id")]
        valid_ids = {str(n["id"]) for n in kept_nodes}
        for node in kept_nodes:
            nid = str(node["id"])
            children = [
                str(cid) for cid in (node.get("drilldown_children") or [])
                if isinstance(cid, str) and cid and cid != nid and cid in valid_ids
            ]
            node["drilldown_children"] = list(dict.fromkeys(children))
        kept_edges = [
            deepcopy(e) for e in raw_edges
            if isinstance(e, dict) and str(e.get("source")) in valid_ids and str(e.get("target")) in valid_ids
        ]
        filtered["nodes"] = kept_nodes
        filtered["edges"] = kept_edges
        filtered["node_count"] = len(kept_nodes)
        filtered["edge_count"] = len(kept_edges)
        filtered["security_posture"] = {
            "system_high": True,
            "viewer_rank": v_rank,
            "viewer_compartments": sorted(comp_set),
            "stripped_opaque_count": 0,
            "redacted_stub_count": 0,
        }
        return filtered

    kept_nodes = []
    stripped_opaque_count = 0
    redacted_stub_count = 0

    for node in raw_nodes:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        nid = str(node["id"])
        is_root = nid in ("root-company", "cluster-home") or int(node.get("level_index", 1) or 0) == 0
        mls = _extract_node_mls(node)
        if is_root or mls is None:
            kept_nodes.append(deepcopy(node))
            continue

        node_rank = int(mls.get("classification_rank", 0))
        node_comps = frozenset(str(c).strip() for c in (mls.get("compartments") or []) if str(c).strip())
        dominated = v_rank >= node_rank and node_comps.issubset(comp_set)
        if dominated:
            kept_nodes.append(deepcopy(node))
            continue

        vis = str(mls.get("visibility") or "STUB").upper()
        scope = str(mls.get("scope") or "").lower()
        # Non-dominated project slots default to OPAQUE unless explicitly marked STUB.
        if scope == "project" and node_rank > 0 and vis != "STUB":
            vis = "OPAQUE"

        if vis == "OPAQUE":
            stripped_opaque_count += 1
            continue

        redacted_msg = f"[REDACTED Rank {node_rank} - Request Lease]"
        # Build a clean structural stub excluding searchable steps/workloads/specs fields.
        stub_node: Dict[str, Any] = {
            "id": nid,
            "label": redacted_msg,
            "kind": str(node.get("kind") or "operational_process"),
            "domain": str(node.get("domain") or "processes_workflows"),
            "section": str(node.get("section") or "section_2_processes"),
            "level_index": int(node.get("level_index", 2) or 2),
            "summary": redacted_msg,
            "primary_url": "http://127.0.0.1:8089/request-lease",
            "drilldown_children": [],
            "redacted": True,
            "mls": {
                "classification_rank": node_rank,
                "visibility": "STUB",
                "redacted": True,
            },
        }
        kept_nodes.append(stub_node)
        redacted_stub_count += 1

    surviving_ids = {str(n["id"]) for n in kept_nodes}
    for node in kept_nodes:
        nid = str(node["id"])
        # Filter children against surviving node IDs so OPAQUE removals leave zero dangling refs.
        children = [
            str(cid) for cid in (node.get("drilldown_children") or [])
            if isinstance(cid, str) and cid and cid != nid and cid in surviving_ids
        ]
        node["drilldown_children"] = list(dict.fromkeys(children))

    surviving_edges = [
        deepcopy(e) for e in raw_edges
        if isinstance(e, dict)
        and str(e.get("source")) in surviving_ids
        and str(e.get("target")) in surviving_ids
        and str(e.get("relation") or "").strip()
    ]
    filtered["nodes"] = kept_nodes
    filtered["edges"] = surviving_edges
    filtered["node_count"] = len(kept_nodes)
    filtered["edge_count"] = len(surviving_edges)
    filtered["security_posture"] = {
        "system_high": False,
        "viewer_rank": v_rank,
        "viewer_compartments": sorted(comp_set),
        "stripped_opaque_count": stripped_opaque_count,
        "redacted_stub_count": redacted_stub_count,
    }
    return filtered


def _map_meshworks_kind(raw_kind: str) -> str:
    kind_map = {
        "system": "company_team",
        "tier": "company_team",
        "watch_source": "knowledge_article",
        "watch_alert": "knowledge_article",
        "skill": "operational_process",
    }
    return kind_map.get(raw_kind, raw_kind or "kubernetes_deployment")


def _resolve_meshworks_node_id(raw_id: str) -> str:
    if raw_id == "system:brain":
        return "brain-skills-hub"
    if raw_id.startswith("skill:"):
        return _safe_id("skill", raw_id[len("skill:"):])
    if raw_id.startswith("watch:"):
        return _safe_id("watch", raw_id[len("watch:"):])
    if raw_id.startswith("alert:"):
        return _safe_id("alert", raw_id[len("alert:"):])
    return _safe_id("mesh", raw_id)


def build_spatial_contract_from_ecosystem(
    brain_manifest_path: Optional[Path] = None,
    brain_state_path: Optional[Path] = None,
    meshworks_graph: Optional[Dict[str, Any]] = None,
    triage_records: Optional[List[Dict[str, Any]]] = None,
    brain_alerts_path: Optional[Path] = None,
    meshworks_graph_path: Optional[Path] = None,
    project_overlays: Optional[List[Dict[str, Any]]] = None,
    viewer_rank: Optional[int] = None,
    viewer_compartments: Optional[List[str]] = None,
    system_high: bool = False,
) -> Dict[str, Any]:
    """Translate brain manifests/watcher state/alerts and meshworks graphs into ``SpatialGraphContract v1``."""
    manifest = _load_json_safe(brain_manifest_path) or {}
    watch_state = _load_json_safe(brain_state_path) or {}
    alerts_doc = _load_json_safe(brain_alerts_path) or {}
    if meshworks_graph is None and meshworks_graph_path is not None:
        loaded_mesh = _load_json_safe(meshworks_graph_path)
        if isinstance(loaded_mesh, dict):
            meshworks_graph = loaded_mesh

    root_children: List[str] = ["brain-skills-hub", "meshworks-coordinator"]
    nodes: List[Dict[str, Any]] = [
        {
            "id": "root-company",
            "label": "3-Tool Operations Ecosystem (OpsCryer + Brain + Meshworks)",
            "kind": "company_root",
            "domain": "company_org",
            "section": "z0_overview",
            "level_index": 0,
            "summary": "Unified spatial view connecting Brain skill sync, Meshworks workflow/triage, and OpsCryer visual cockpits.",
            "primary_url": "http://127.0.0.1:8088",
            "drilldown_children": root_children,
        },
        {
            "id": "brain-skills-hub",
            "label": "Brain Skill Sync & Source Watcher",
            "kind": "company_team",
            "domain": "company_org",
            "section": "section_1_company",
            "level_index": 1,
            "summary": "Multi-source three-tier skill synchronization (personal > group > company) and upstream watcher.",
            "primary_url": "http://127.0.0.1:8089",
            "drilldown_children": [],
        },
        {
            "id": "meshworks-coordinator",
            "label": "Meshworks Agent Triage & Knowledge Graph",
            "kind": "engineering_project",
            "domain": "processes_workflows",
            "section": "section_2_processes",
            "level_index": 1,
            "summary": "Natural-language playbook triage, agent workflow execution, graph slicing, and golf anti-speculation scoring.",
            "primary_url": "http://127.0.0.1:8089/api/knowledge-graph",
            "drilldown_children": [],
        },
    ]
    edges: List[Dict[str, str]] = [
        {"source": "root-company", "target": "brain-skills-hub", "relation": "contains_subsystem"},
        {"source": "root-company", "target": "meshworks-coordinator", "relation": "contains_subsystem"},
        {"source": "meshworks-coordinator", "target": "brain-skills-hub", "relation": "ingests_skills"},
    ]
    seen_ids = {n["id"] for n in nodes}
    by_id: Dict[str, Dict[str, Any]] = {n["id"]: n for n in nodes}
    seen_edges = {(e["source"], e["target"], e["relation"]) for e in edges}

    def add_edge(src: str, dst: str, rel: str) -> None:
        key = (src, dst, rel)
        # Only register edges once both endpoints exist and the triple is unseen.
        if src in seen_ids and dst in seen_ids and key not in seen_edges:
            seen_edges.add(key)
            edges.append({"source": src, "target": dst, "relation": rel})

    def add_child(parent_id: str, child_id: str) -> None:
        parent = by_id.get(parent_id)
        # Enforce non-self valid children to satisfy SpatialGraphContract uniqueness checks.
        if parent is not None and child_id != parent_id and child_id in seen_ids:
            if child_id not in parent["drilldown_children"]:
                parent["drilldown_children"].append(child_id)

    # Add Brain synced skills
    brain_children: List[str] = []
    for entry in manifest.get("skills", []) or []:
        if not isinstance(entry, dict):
            continue
        skill_id = str(entry.get("id") or entry.get("name") or "unknown")
        node_id = _safe_id("skill", skill_id)
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        category = str(entry.get("category") or "process").lower()
        domain = _CATEGORY_TO_DOMAIN.get(category, "processes_workflows")
        source_tier = str(entry.get("source") or "company")
        version = str(entry.get("version") or "1.0.0")
        node = {
            "id": node_id,
            "label": f"{entry.get('name', skill_id)} [{source_tier} v{version}]",
            "kind": "operational_process",
            "domain": domain,
            "section": "section_2_processes",
            "level_index": 2,
            "summary": str(entry.get("description") or f"Synced skill {skill_id} from tier {source_tier}"),
            "primary_url": f"http://127.0.0.1:8089/?skill={skill_id}",
            "drilldown_children": [],
        }
        entry_mls = _extract_node_mls(entry)
        if entry_mls is not None:
            node["mls"] = entry_mls
        for extra_field in ("steps", "workloads", "specs"):
            if extra_field in entry and entry[extra_field] is not None:
                node[extra_field] = deepcopy(entry[extra_field])
        nodes.append(node)
        by_id[node_id] = node
        brain_children.append(node_id)
        add_edge("brain-skills-hub", node_id, "provides_skill")
    nodes[1]["drilldown_children"] = brain_children

    # Add Brain watched source entries if present
    for src_name, src_info in sorted((watch_state.get("sources") or {}).items()):
        if not isinstance(src_info, dict):
            continue
        node_id = _safe_id("watch", src_name)
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        mode = str(src_info.get("mode") or "gitlab")
        node = {
            "id": node_id,
            "label": f"Watcher Source: {src_name} [{mode}]",
            "kind": "knowledge_article",
            "domain": "company_org",
            "section": "section_1_company",
            "level_index": 2,
            "summary": f"Tracks {src_info.get('project_path', src_name)} ({mode}; last_seen={src_info.get('last_seen_sha') or 'none'})",
            "primary_url": str(src_info.get("web_url") or "http://127.0.0.1:8089"),
            "drilldown_children": [],
        }
        nodes.append(node)
        by_id[node_id] = node
        add_child("brain-skills-hub", node_id)
        add_edge("brain-skills-hub", node_id, "watches_repo")

    # Add Brain skill-watch alerts linked from watch sources and brain hub to changed skills
    raw_alerts = alerts_doc.get("alerts") if isinstance(alerts_doc, dict) else []
    if isinstance(raw_alerts, list):
        total_alerts = len(raw_alerts)
        for idx, alert in enumerate(raw_alerts):
            if not isinstance(alert, dict):
                continue
            acknowledged = bool(alert.get("acknowledged"))
            # Retain all unacknowledged alerts and only the newest 5 acknowledged alerts to bound graph size.
            if acknowledged and idx < total_alerts - 5:
                continue
            src_name = str(alert.get("source") or "company")
            new_sha = str(alert.get("new_sha") or "")
            short_sha = new_sha[:8] or "unknown"
            alert_id = _safe_id("alert", f"{idx}-{src_name}-{short_sha}")
            if alert_id in seen_ids:
                continue
            seen_ids.add(alert_id)
            changed_skills = [str(s) for s in (alert.get("changed_skills") or []) if str(s)]
            child_skill_ids = [_safe_id("skill", s) for s in changed_skills if _safe_id("skill", s) in seen_ids]
            commit_msg = str(alert.get("commit_message") or "").splitlines()[0] if alert.get("commit_message") else ""
            status_tag = "ACK" if acknowledged else "LIVE"
            node = {
                "id": alert_id,
                "label": f"Watch Alert [{src_name} {short_sha}] ({status_tag})",
                "kind": "knowledge_article",
                "domain": "processes_workflows",
                "section": "section_2_processes",
                "level_index": 2,
                "summary": f"{commit_msg or 'Skill update detected'} | changed={','.join(changed_skills) or 'none'}",
                "primary_url": "http://127.0.0.1:8089",
                "drilldown_children": list(dict.fromkeys(child_skill_ids)),
            }
            nodes.append(node)
            by_id[alert_id] = node
            add_child("brain-skills-hub", alert_id)
            watch_node_id = _safe_id("watch", src_name)
            if watch_node_id in seen_ids:
                add_child(watch_node_id, alert_id)
                add_edge(watch_node_id, alert_id, "emitted_alert")
            else:
                add_edge("brain-skills-hub", alert_id, "emitted_alert")
            for snode_id in child_skill_ids:
                add_edge(alert_id, snode_id, "updated_skill")

    # Add Meshworks KnowledgeGraph nodes & edges if supplied (deduplicating Brain IDs)
    mesh_children: List[str] = []
    if isinstance(meshworks_graph, dict):
        raw_nodes = meshworks_graph.get("nodes") or {}
        if isinstance(raw_nodes, dict):
            for raw_id, attrs in raw_nodes.items():
                if not isinstance(attrs, dict):
                    continue
                raw_id_str = str(raw_id)
                node_id = _resolve_meshworks_node_id(raw_id_str)
                if node_id in seen_ids:
                    if raw_id_str.startswith("tier:") or raw_id_str.startswith("alert:"):
                        mesh_children.append(node_id)
                    continue
                seen_ids.add(node_id)
                domain = str(attrs.get("domain") or "deployments_k8s")
                if domain not in ("company_org", "processes_workflows", "deployments_k8s", "hardware_topology"):
                    domain = "processes_workflows"
                kind = _map_meshworks_kind(str(attrs.get("kind") or "kubernetes_deployment"))
                node = {
                    "id": node_id,
                    "label": str(attrs.get("label") or raw_id_str),
                    "kind": kind,
                    "domain": domain,
                    "section": "section_3_workloads",
                    "level_index": 2,
                    "summary": str(attrs.get("summary") or attrs.get("description") or f"Meshworks node {raw_id_str}"),
                    "primary_url": str(attrs.get("primary_url") or "http://127.0.0.1:8089"),
                    "drilldown_children": [],
                }
                attrs_mls = _extract_node_mls(attrs)
                if attrs_mls is not None:
                    node["mls"] = attrs_mls
                for extra_field in ("steps", "workloads", "specs"):
                    if extra_field in attrs and attrs[extra_field] is not None:
                        node[extra_field] = deepcopy(attrs[extra_field])
                nodes.append(node)
                by_id[node_id] = node
                mesh_children.append(node_id)
                add_edge("meshworks-coordinator", node_id, "manages_node")

        for edge in meshworks_graph.get("edges") or []:
            if not isinstance(edge, dict):
                continue
            src = _resolve_meshworks_node_id(str(edge.get("source", "")))
            dst = _resolve_meshworks_node_id(str(edge.get("target", "")))
            rel = str(edge.get("relation") or "linked_to")
            add_edge(src, dst, rel)
            # Propagate Meshworks structural edges into drilldown children without introducing reverse hub cycles.
            if src in seen_ids and dst in seen_ids and dst not in ("brain-skills-hub", "meshworks-coordinator", "root-company"):
                add_child(src, dst)

    for rec in triage_records or []:
        if not isinstance(rec, dict):
            continue
        pb_name = str(rec.get("playbook") or "triage")
        node_id = _safe_id("playbook", pb_name)
        if node_id not in seen_ids:
            seen_ids.add(node_id)
            node = {
                "id": node_id,
                "label": f"Playbook: {pb_name}",
                "kind": "operational_process",
                "domain": "processes_workflows",
                "section": "section_2_processes",
                "level_index": 2,
                "summary": str(rec.get("query") or f"Meshworks playbook {pb_name}"),
                "primary_url": "http://127.0.0.1:8089",
                "drilldown_children": [],
            }
            nodes.append(node)
            by_id[node_id] = node
            mesh_children.append(node_id)
            add_edge("meshworks-coordinator", node_id, "routes_to_playbook")

    for mc in dict.fromkeys(mesh_children):
        add_child("meshworks-coordinator", mc)

    if project_overlays:
        for proj in project_overlays:
            if not isinstance(proj, dict):
                continue
            pid = str(proj.get("project_id") or proj.get("id") or "project")
            pnode_id = _safe_id("project", pid)
            if pnode_id not in seen_ids:
                seen_ids.add(pnode_id)
                proj_rank = int(proj.get("classification_rank", 30) if proj.get("classification_rank") is not None else 30)
                proj_comps = sorted({
                    str(c).strip()
                    for c in (proj.get("compartments") or [f"project:{pid}"])
                    if str(c).strip()
                })
                proj_vis = str(proj.get("visibility") or "OPAQUE").strip().upper()
                if proj_vis not in ("OPAQUE", "STUB", "FULL"):
                    proj_vis = "OPAQUE"
                pnode: Dict[str, Any] = {
                    "id": pnode_id,
                    "label": str(proj.get("label") or f"Project Slot: {pid}"),
                    "kind": "engineering_project",
                    "domain": "processes_workflows",
                    "section": "section_2_processes",
                    "level_index": 2,
                    "summary": str(proj.get("summary") or f"Isolated .ai project slot {pid}"),
                    "primary_url": str(proj.get("primary_url") or "http://127.0.0.1:8089/api/project-slots"),
                    "drilldown_children": [],
                    "mls": {
                        "classification_rank": proj_rank,
                        "compartments": proj_comps,
                        "visibility": proj_vis,
                        "scope": "project",
                    },
                }
                for extra_field in ("steps", "workloads", "specs"):
                    if extra_field in proj and proj[extra_field] is not None:
                        pnode[extra_field] = deepcopy(proj[extra_field])
                nodes.append(pnode)
                by_id[pnode_id] = pnode
                add_child("brain-skills-hub", pnode_id)
                add_edge("brain-skills-hub", pnode_id, "contains_project")

                for pskill in proj.get("skills") or []:
                    if not isinstance(pskill, dict):
                        continue
                    sid = str(pskill.get("id") or pskill.get("name") or "skill")
                    ps_node_id = _safe_id("pskill", f"{pid}-{sid}")
                    if ps_node_id in seen_ids:
                        continue
                    seen_ids.add(ps_node_id)
                    sk_mls = _extract_node_mls(pskill) or {}
                    sk_rank = max(proj_rank, int(sk_mls.get("classification_rank", proj_rank)))
                    sk_comps = sorted(set(proj_comps) | set(sk_mls.get("compartments") or []))
                    sk_vis = str(sk_mls.get("visibility") or proj_vis).upper()
                    ps_node: Dict[str, Any] = {
                        "id": ps_node_id,
                        "label": str(pskill.get("label") or pskill.get("name") or sid),
                        "kind": "operational_process",
                        "domain": "processes_workflows",
                        "section": "section_2_processes",
                        "level_index": 3,
                        "summary": str(pskill.get("description") or f"Project skill {sid} in {pid}"),
                        "primary_url": str(pskill.get("primary_url") or f"http://127.0.0.1:8089/?project={pid}&skill={sid}"),
                        "drilldown_children": [],
                        "mls": {
                            "classification_rank": sk_rank,
                            "compartments": sk_comps,
                            "visibility": sk_vis,
                            "scope": "project",
                        },
                    }
                    for extra_field in ("steps", "workloads", "specs"):
                        if extra_field in pskill and pskill[extra_field] is not None:
                            ps_node[extra_field] = deepcopy(pskill[extra_field])
                    nodes.append(ps_node)
                    by_id[ps_node_id] = ps_node
                    add_child(pnode_id, ps_node_id)
                    add_edge(pnode_id, ps_node_id, "contains_project_skill")

    mesh_rev = meshworks_graph.get("graph_revision") if isinstance(meshworks_graph, dict) else None
    if mesh_rev:
        by_id["meshworks-coordinator"]["summary"] = (
            f"Live Meshworks KnowledgeGraph rev={mesh_rev} ({len(mesh_children)} direct nodes); playbook triage & slicing."
        )

    fingerprint_material = {
        "nodes": [{k: n.get(k) for k in ("id", "label", "kind", "domain", "summary", "drilldown_children")} for n in nodes],
        "edges": edges,
        "watch_sources": {k: v.get("last_seen_sha") for k, v in sorted((watch_state.get("sources") or {}).items()) if isinstance(v, dict)},
        "mesh_revision": mesh_rev or "",
    }
    ecosystem_revision = hashlib.sha256(
        json.dumps(fingerprint_material, sort_keys=True).encode("utf-8")
    ).hexdigest()[:12]

    contract = {
        "schema_version": CONTRACT_VERSION,
        "piece_role": "ECOSYSTEM_BRIDGE_SPATIAL_CATALOG",
        "backend_coupled": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ecosystem_revision": ecosystem_revision,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }
    # Apply MLS clearance filtering only when project overlays or explicit viewer credentials are requested.
    if (
        project_overlays is not None
        or viewer_rank is not None
        or viewer_compartments is not None
        or system_high
    ):
        return filter_spatial_catalog_by_clearance(
            contract,
            viewer_rank=0 if viewer_rank is None else int(viewer_rank),
            viewer_compartments=viewer_compartments,
            system_high=bool(system_high),
        )
    return contract


def overlay_ecosystem_onto_catalog(
    base_catalog: Dict[str, Any],
    brain_manifest_path: Optional[Path] = None,
    brain_state_path: Optional[Path] = None,
    brain_alerts_path: Optional[Path] = None,
    meshworks_graph_path: Optional[Path] = None,
    project_overlays: Optional[List[Dict[str, Any]]] = None,
    viewer_rank: Optional[int] = None,
    viewer_compartments: Optional[List[str]] = None,
    system_high: bool = False,
) -> Dict[str, Any]:
    """Overlay live Brain/Meshworks ecosystem nodes & edges onto an OpsCryer SpatialGraphContract v1 catalog."""
    merged = deepcopy(base_catalog) if isinstance(base_catalog, dict) else {}
    raw_base_nodes = merged.get("nodes") if isinstance(merged.get("nodes"), list) else []
    merged_nodes: List[Dict[str, Any]] = [deepcopy(n) for n in raw_base_nodes if isinstance(n, dict) and n.get("id")]
    raw_base_edges = merged.get("edges") if isinstance(merged.get("edges"), list) else []
    merged_edges: List[Dict[str, Any]] = [deepcopy(e) for e in raw_base_edges if isinstance(e, dict)]

    by_id: Dict[str, Dict[str, Any]] = {}
    for node in merged_nodes:
        nid = str(node["id"])
        children = node.get("drilldown_children")
        node["drilldown_children"] = list(children) if isinstance(children, list) else []
        by_id[nid] = node

    if "cluster-home" in by_id:
        root_id = "cluster-home"
    elif "root-company" in by_id:
        root_id = "root-company"
    elif merged_nodes:
        root_id = str(merged_nodes[0]["id"])
    else:
        root_id = "root-company"

    eco = build_spatial_contract_from_ecosystem(
        brain_manifest_path=brain_manifest_path,
        brain_state_path=brain_state_path,
        brain_alerts_path=brain_alerts_path,
        meshworks_graph_path=meshworks_graph_path,
        project_overlays=project_overlays,
        viewer_rank=viewer_rank,
        viewer_compartments=viewer_compartments,
        system_high=system_high,
    )

    for eco_node in eco.get("nodes", []):
        nid = str(eco_node.get("id") or "")
        if not nid:
            continue
        # Preserve the existing base catalog root (cluster-home or root-company) rather than overwriting it.
        if nid == "root-company" and root_id in by_id:
            continue
        if nid in by_id:
            existing = by_id[nid]
            existing["label"] = eco_node["label"]
            existing["summary"] = eco_node["summary"]
            existing["primary_url"] = eco_node["primary_url"]
            combined_children = list(eco_node.get("drilldown_children") or []) + list(existing.get("drilldown_children") or [])
            existing["drilldown_children"] = list(dict.fromkeys(combined_children))
        else:
            copied = deepcopy(eco_node)
            merged_nodes.append(copied)
            by_id[nid] = copied

    seen_edges = {(str(e.get("source")), str(e.get("target")), str(e.get("relation"))) for e in merged_edges}
    for edge in eco.get("edges", []):
        src = root_id if edge.get("source") == "root-company" else str(edge.get("source") or "")
        dst = root_id if edge.get("target") == "root-company" else str(edge.get("target") or "")
        rel = str(edge.get("relation") or "connected")
        key = (src, dst, rel)
        # Only add valid deduplicated edges between nodes present in the merged graph.
        if src in by_id and dst in by_id and key not in seen_edges:
            seen_edges.add(key)
            merged_edges.append({"source": src, "target": dst, "relation": rel})

    if root_id in by_id:
        root_node = by_id[root_id]
        front = [hub_id for hub_id in ("brain-skills-hub", "meshworks-coordinator") if hub_id in by_id]
        rest = [cid for cid in root_node.get("drilldown_children", []) if cid not in front]
        root_node["drilldown_children"] = front + rest

    valid_ids = set(by_id.keys())
    for node in merged_nodes:
        nid = str(node["id"])
        # Filter invalid or self-referential child links to keep SpatialGraphContract valid.
        filtered_children = [
            str(cid) for cid in (node.get("drilldown_children") or [])
            if isinstance(cid, str) and cid and cid != nid and cid in valid_ids
        ]
        node["drilldown_children"] = list(dict.fromkeys(filtered_children))

    merged["schema_version"] = merged.get("schema_version") or CONTRACT_VERSION
    merged["nodes"] = merged_nodes
    merged["edges"] = merged_edges
    merged["node_count"] = len(merged_nodes)
    merged["edge_count"] = len(merged_edges)
    merged["ecosystem_revision"] = eco["ecosystem_revision"]
    merged["ecosystem_overlay_active"] = True
    # Apply MLS filtering to the combined catalog (including base nodes) when requested.
    if (
        project_overlays is not None
        or viewer_rank is not None
        or viewer_compartments is not None
        or system_high
    ):
        return filter_spatial_catalog_by_clearance(
            merged,
            viewer_rank=0 if viewer_rank is None else int(viewer_rank),
            viewer_compartments=viewer_compartments,
            system_high=bool(system_high),
        )
    return merged


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="OpsCryer bridge")
    parser.add_argument("--catalog", action="store_true", help="Print lightweight bridge summary catalog")
    parser.add_argument(
        "--spatial-contract",
        action="store_true",
        help="Build and print validated SpatialGraphContract v1 payload from Brain/Meshworks state",
    )
    parser.add_argument("--brain-manifest", type=Path, default=None, help="Path to brain skills-manifest.json")
    parser.add_argument("--brain-state", type=Path, default=None, help="Path to brain skill_watch_state.json")
    parser.add_argument("--brain-alerts", type=Path, default=None, help="Path to brain skill_watch_alerts.json")
    parser.add_argument("--meshworks-graph", type=Path, default=None, help="Path to meshworks knowledge-graph.json")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON output file path")
    args = parser.parse_args(argv)

    if args.spatial_contract:
        payload = build_spatial_contract_from_ecosystem(
            brain_manifest_path=args.brain_manifest,
            brain_state_path=args.brain_state,
            brain_alerts_path=args.brain_alerts,
            meshworks_graph_path=args.meshworks_graph,
        )
    elif args.catalog:
        payload = build_spatial_graph_catalog()
    else:
        payload = build_spatial_contract_from_ecosystem(
            brain_manifest_path=args.brain_manifest,
            brain_state_path=args.brain_state,
            brain_alerts_path=args.brain_alerts,
            meshworks_graph_path=args.meshworks_graph,
        )

    encoded = json.dumps(payload, indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8", newline="\n")
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
