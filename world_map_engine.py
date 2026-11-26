# SPDX-License-Identifier: Apache-2.0
"""High-performance (>=60 FPS) 2D / 2.5D / 3D Spatial Knowledge Graph engine."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from html import escape
import json
import math
from typing import Any, Mapping

from graph_layers import (
    GRAPH_LEVELS,
    GRAPH_LEVEL_IDS,
    GRAPH_LEVEL_MAP,
    build_graph_layers_js,
    classify_node_graph_level,
    classify_tactical_status,
)
from unit_archetypes import (
    BUILTIN_UNIT_TYPES,
    UNIT_ARCHETYPES_SCHEMA_VERSION,
    list_unit_types,
    resolve_node_unit_type,
)

WORLD_MAP_SCHEMA_VERSION = "1.0-world-map-layout"
WORLD_MAP_MODES = ("unit_type", "domain_squads", "graph_layers", "cloud_3d")
PROJECTION_MODES = ("flat_2d", "iso_25d", "orbit_3d")
PROJECTION_GUIDE: dict[str, dict[str, Any]] = {
    "flat_2d": {
        "id": "flat_2d",
        "short": "2D Schematic",
        "title": "2D Orthographic Schematic",
        "pitch_deg": 89.2,
        "relevance": "Best for dense dependency auditing, layer alignment, and exact box selection with zero perspective foreshortening.",
    },
    "iso_25d": {
        "id": "iso_25d",
        "short": "2.5D Elevation",
        "title": "2.5D Architectural Elevation",
        "pitch_deg": 54.0,
        "relevance": "Best for reading vertical architecture tiers (Hardware -> Cluster -> Service -> Root) anchored cleanly onto ground sectors.",
    },
    "orbit_3d": {
        "id": "orbit_3d",
        "short": "3D Volumetric",
        "title": "3D Volumetric Cloud",
        "pitch_deg": 34.0,
        "relevance": "Best for untangling high-node-count hubs across full spherical Z-depth with free orbit (Right-Drag or Q/E).",
    },
}


def _compute_level_indices(nodes: list[dict[str, Any]], edge_pairs: list[tuple[str, str]]) -> dict[str, int]:
    """Compute breadth-first hierarchy depth from root nodes when explicit level_index is absent."""
    by_id = {str(n["id"]): n for n in nodes}
    levels: dict[str, int] = {}
    roots = [
        str(n["id"])
        for n in nodes
        if str(n.get("kind") or "").lower() == "company_root"
        or str(n.get("id") or "") in {"root-company", "cluster-home"}
    ]
    if not roots and nodes:
        roots = [str(nodes[0]["id"])]

    adj: dict[str, list[str]] = {nid: [] for nid in by_id}
    for u, v in edge_pairs:
        if u in adj and v in by_id:
            adj[u].append(v)
    for n in nodes:
        nid = str(n["id"])
        for cid in n.get("drilldown_children") or ():
            sc = str(cid)
            if sc in by_id:
                adj[nid].append(sc)

    queue: deque[tuple[str, int]] = deque()
    for r in roots:
        if r in by_id and r not in levels:
            levels[r] = 0
            queue.append((r, 0))
    while queue:
        curr, depth = queue.popleft()
        for nxt in adj.get(curr, ()):
            if nxt not in levels:
                levels[nxt] = min(6, depth + 1)
                queue.append((nxt, depth + 1))

    for n in nodes:
        nid = str(n["id"])
        explicit = n.get("level_index", n.get("zoom_level"))
        if isinstance(explicit, int) and not isinstance(explicit, bool):
            levels[nid] = max(0, min(6, explicit))
        else:
            levels.setdefault(nid, 2)
    return levels


def _pack_formation_offset(index: int, count: int, formation: str, spacing: float) -> tuple[float, float]:
    """Return local (dx, dy) formation offset within a unit-type or squad territory."""
    if count <= 1:
        return 0.0, 0.0
    if formation == "ring":
        ring_cap = 8
        ring = 0
        rem = index
        while rem >= ring_cap:
            rem -= ring_cap
            ring += 1
            ring_cap += 6
        angle = (2.0 * math.pi * rem) / max(1, min(ring_cap, count - (index - rem)))
        radius = (1.0 + ring * 0.95) * spacing
        return round(math.cos(angle) * radius, 2), round(math.sin(angle) * radius, 2)
    if formation == "orbital":
        golden = 2.399963229728653
        radius = spacing * 0.68 * math.sqrt(index + 1.0)
        theta = index * golden
        return round(math.cos(theta) * radius, 2), round(math.sin(theta) * radius * 0.78, 2)
    if formation == "hex":
        golden = 2.399963229728653
        cols = max(2, math.ceil(math.sqrt(count)))
        if count <= 6:
            angle = (2.0 * math.pi * index) / count
            rad = spacing * 0.92
            return round(math.cos(angle) * rad, 2), round(math.sin(angle) * rad, 2)
        if count <= 64:
            row = index // cols
            col = index % cols
            offset_x = (row % 2) * spacing * 0.5
            x = (col - (cols - 1) * 0.5) * spacing + offset_x
            y = (row - ((count - 1) // cols) * 0.5) * (spacing * 0.866)
            return round(x, 2), round(y, 2)
        rad = spacing * 0.62 * math.sqrt(index + 0.5)
        theta = index * golden
        return round(math.cos(theta) * rad, 2), round(math.sin(theta) * rad, 2)

    cols = max(1, math.ceil(math.sqrt(count)))
    rows = max(1, math.ceil(count / cols))
    row = index // cols
    col = index % cols
    x = (col - (cols - 1) * 0.5) * spacing
    y = (row - (rows - 1) * 0.5) * spacing
    return round(x, 2), round(y, 2)


def _extract_node_vital_and_flags(node: Mapping[str, Any]) -> tuple[int, str, bool]:
    """Derive normalized vital percentage, tactical status, and MLS lock state without side effects."""
    vital = 96
    status = "nominal"
    telem = node.get("rts_ai_unit_telemetry")
    if isinstance(telem, Mapping):
        bh = telem.get("behavioral_health")
        if isinstance(bh, Mapping) and bh.get("sla_utilization_pct") is not None:
            try:
                vital = max(10, min(100, int(round(100.0 - float(bh["sla_utilization_pct"]) * 0.4))))
            except (TypeError, ValueError):
                vital = 94
        state = str((bh or {}).get("state") or "").upper() if isinstance(bh, Mapping) else ""
        if state in {"DEGRADED", "ALERT", "CRITICAL"}:
            status = "alert"
            vital = min(vital, 58)

    metrics = node.get("metrics")
    if isinstance(metrics, Mapping) and metrics.get("cpu_pct") is not None:
        try:
            cpu = float(metrics["cpu_pct"])
            vital = max(15, min(100, int(round(100.0 - cpu * 0.6))))
            if cpu >= 85.0:
                status = "alert"
            elif cpu >= 70.0 and status == "nominal":
                status = "warn"
        except (TypeError, ValueError):
            pass

    if node.get("alert") or str(node.get("severity") or "").lower() in {"high", "critical"}:
        status = "alert"
        vital = min(vital, 52)

    mls_locked = bool(
        node.get("mls_redacted")
        or node.get("opaqued")
        or (isinstance(node.get("classification_rank"), int) and node["classification_rank"] >= 20)
    )
    return vital, status, mls_locked


def build_world_map_layout(
    catalog: Mapping[str, Any],
    *,
    mode: str = "unit_type",
    scope: str = "",
    unit_types: Mapping[str, Mapping[str, Any]] | None = None,
    node_overrides: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build deterministic 2.5D/3D World Map coordinates, unit territories, and compact graph arrays."""
    eff_mode = str(mode or "unit_type").strip().lower()
    if eff_mode not in WORLD_MAP_MODES:
        raise ValueError(f"Unsupported World Map layout mode '{eff_mode}'")

    eff_types = list_unit_types() if unit_types is None else deepcopy(dict(unit_types))
    raw_nodes = [
        dict(n)
        for n in (catalog.get("nodes") or ())
        if isinstance(n, Mapping) and n.get("id")
    ]
    id_to_idx: dict[str, int] = {}
    dedup_nodes: list[dict[str, Any]] = []
    for n in raw_nodes:
        nid = str(n["id"])
        if nid not in id_to_idx:
            id_to_idx[nid] = len(dedup_nodes)
            dedup_nodes.append(n)

    edge_pairs_raw: list[tuple[str, str, str]] = []
    seen_edges: set[tuple[str, str]] = set()
    for e in catalog.get("edges") or ():
        if not isinstance(e, Mapping):
            continue
        u = str(e.get("source") or "")
        v = str(e.get("target") or "")
        if u in id_to_idx and v in id_to_idx and u != v and (u, v) not in seen_edges:
            seen_edges.add((u, v))
            edge_pairs_raw.append((u, v, str(e.get("relation") or "connected")))
    for n in dedup_nodes:
        u = str(n["id"])
        for c in n.get("drilldown_children") or ():
            v = str(c or "")
            if v in id_to_idx and u != v and (u, v) not in seen_edges:
                seen_edges.add((u, v))
                edge_pairs_raw.append((u, v, "encapsulates"))

    levels = _compute_level_indices(dedup_nodes, [(u, v) for u, v, _ in edge_pairs_raw])

    unit_counts: dict[str, int] = {}
    node_unit_types: list[str] = []
    for n in dedup_nodes:
        ut = resolve_node_unit_type(n, eff_types, node_overrides=node_overrides)
        node_unit_types.append(ut)
        unit_counts[ut] = unit_counts.get(ut, 0) + 1

    positions: list[tuple[float, float, float]] = [(0.0, 0.0, 0.0)] * len(dedup_nodes)
    territories: list[dict[str, Any]] = []

    if dedup_nodes:
        if eff_mode == "unit_type":
            groups: dict[str, list[int]] = {}
            for idx, ut in enumerate(node_unit_types):
                groups.setdefault(ut, []).append(idx)

            ordered_types = sorted(
                groups.keys(),
                key=lambda tid: (-int(eff_types.get(tid, {}).get("priority", 50)), tid),
            )
            ring_types = [tid for tid in ordered_types if tid != "citadel_root"]
            center_types = ["citadel_root"] if "citadel_root" in groups else []

            spacing = 54.0
            for tid in center_types:
                members = groups[tid]
                spec = eff_types.get(tid, {})
                base_z = float(spec.get("z_elevation", 85))
                form = str(spec.get("formation") or "ring")
                rad = max(95.0, 38.0 * math.sqrt(len(members)) + 32.0)
                for local_idx, node_idx in enumerate(members):
                    dx, dy = _pack_formation_offset(local_idx, len(members), form, spacing)
                    lvl = levels.get(str(dedup_nodes[node_idx]["id"]), 0)
                    positions[node_idx] = (dx, dy, round(base_z + max(0, 4 - lvl) * 10.0, 2))
                territories.append(
                    {
                        "territory_id": f"terr-{tid}",
                        "label": str(spec.get("display_name") or tid),
                        "unit_type": tid,
                        "color": str(spec.get("color_primary") or "#38BDF8"),
                        "cx": 0.0,
                        "cy": 0.0,
                        "radius": round(rad, 1),
                        "count": len(members),
                    }
                )

            ring_r = 340.0 + min(320.0, math.sqrt(len(dedup_nodes)) * 12.0)
            total_ring = max(1, len(ring_types))
            for sector_idx, tid in enumerate(ring_types):
                members = groups[tid]
                spec = eff_types.get(tid, {})
                base_z = float(spec.get("z_elevation", 32))
                form = str(spec.get("formation") or "hex")
                rad = max(115.0, 42.0 * math.sqrt(len(members)) + 36.0)
                local_ring_r = ring_r + (sector_idx // 8) * 320.0 + max(0.0, (rad - 180.0) * 0.75)
                angle = -math.pi * 0.5 + (2.0 * math.pi * sector_idx) / total_ring
                cx = round(math.cos(angle) * local_ring_r, 2)
                cy = round(math.sin(angle) * local_ring_r, 2)
                for local_idx, node_idx in enumerate(members):
                    dx, dy = _pack_formation_offset(local_idx, len(members), form, spacing)
                    lvl = levels.get(str(dedup_nodes[node_idx]["id"]), 2)
                    positions[node_idx] = (
                        round(cx + dx, 2),
                        round(cy + dy, 2),
                        round(base_z + max(0, 4 - lvl) * 6.0, 2),
                    )
                territories.append(
                    {
                        "territory_id": f"terr-{tid}",
                        "label": str(spec.get("display_name") or tid),
                        "unit_type": tid,
                        "color": str(spec.get("color_primary") or "#38BDF8"),
                        "cx": cx,
                        "cy": cy,
                        "radius": round(rad, 1),
                        "count": len(members),
                    }
                )

        elif eff_mode == "domain_squads":
            dom_groups: dict[str, list[int]] = {}
            for idx, n in enumerate(dedup_nodes):
                dom = str(n.get("domain") or "company_org")
                dom_groups.setdefault(dom, []).append(idx)
            ordered_domains = sorted(dom_groups.keys(), key=lambda d: (-len(dom_groups[d]), d))
            ring_r = 310.0 + min(300.0, math.sqrt(len(dedup_nodes)) * 11.0)
            for d_idx, dom in enumerate(ordered_domains):
                members = sorted(
                    dom_groups[dom],
                    key=lambda ni: (
                        -int(eff_types.get(node_unit_types[ni], {}).get("priority", 50)),
                        node_unit_types[ni],
                        str(dedup_nodes[ni]["id"]),
                    ),
                )
                angle = -math.pi * 0.5 + (2.0 * math.pi * d_idx) / max(1, len(ordered_domains))
                rad = max(125.0, 44.0 * math.sqrt(len(members)) + 36.0)
                cx = round(math.cos(angle) * (ring_r if len(ordered_domains) > 1 else 0.0), 2)
                cy = round(math.sin(angle) * (ring_r if len(ordered_domains) > 1 else 0.0), 2)
                lead_ut = node_unit_types[members[0]]
                for local_idx, node_idx in enumerate(members):
                    ut = node_unit_types[node_idx]
                    spec = eff_types.get(ut, {})
                    dx, dy = _pack_formation_offset(local_idx, len(members), "hex", 52.0)
                    lvl = levels.get(str(dedup_nodes[node_idx]["id"]), 2)
                    positions[node_idx] = (
                        round(cx + dx, 2),
                        round(cy + dy, 2),
                        round(float(spec.get("z_elevation", 32)) + max(0, 4 - lvl) * 6.0, 2),
                    )
                territories.append(
                    {
                        "territory_id": f"terr-dom-{dom}",
                        "label": dom.replace("_", " ").title(),
                        "unit_type": lead_ut,
                        "color": str(eff_types.get(lead_ut, {}).get("color_primary") or "#38BDF8"),
                        "cx": cx,
                        "cy": cy,
                        "radius": round(rad, 1),
                        "count": len(members),
                    }
                )

        elif eff_mode == "graph_layers":
            lvl_groups: dict[str, list[int]] = {lid: [] for lid in GRAPH_LEVEL_IDS}
            for idx, n in enumerate(dedup_nodes):
                gl = classify_node_graph_level(n)
                lvl_groups.setdefault(gl, []).append(idx)
            active_levels = [lid for lid in GRAPH_LEVEL_IDS if lvl_groups.get(lid)]
            total_bands = max(1, len(active_levels))
            ring_r = 340.0 + min(300.0, math.sqrt(len(dedup_nodes)) * 11.0)
            for b_idx, lid in enumerate(active_levels):
                members = lvl_groups[lid]
                meta = GRAPH_LEVEL_MAP[lid]
                angle = -math.pi * 0.5 + (2.0 * math.pi * b_idx) / total_bands
                rad = max(125.0, 44.0 * math.sqrt(len(members)) + 36.0)
                cx = round(math.cos(angle) * (ring_r if total_bands > 1 else 0.0), 2)
                cy = round(math.sin(angle) * (ring_r if total_bands > 1 else 0.0), 2)
                base_z = float(meta["z_elevation"])
                lead_ut = node_unit_types[members[0]]
                for local_idx, node_idx in enumerate(members):
                    dx, dy = _pack_formation_offset(local_idx, len(members), "hex", 52.0)
                    positions[node_idx] = (round(cx + dx, 2), round(cy + dy, 2), base_z)
                territories.append(
                    {
                        "territory_id": f"terr-lvl-{lid}",
                        "label": f"{meta['icon']} {meta['label']}",
                        "graph_level": lid,
                        "unit_type": lead_ut,
                        "color": str(meta["color"]),
                        "cx": cx,
                        "cy": cy,
                        "radius": round(rad, 1),
                        "count": len(members),
                    }
                )

        else:
            # 3D orbital Fibonacci sphere organized into distinct Unit Type clusters.
            groups_3d: dict[str, list[int]] = {}
            for idx, ut in enumerate(node_unit_types):
                groups_3d.setdefault(ut, []).append(idx)
            ordered_3d = sorted(
                groups_3d.keys(),
                key=lambda tid: (-int(eff_types.get(tid, {}).get("priority", 50)), tid),
            )
            sphere_r = 360.0 + min(280.0, math.sqrt(len(dedup_nodes)) * 10.0)
            golden_angle = math.pi * (3.0 - math.sqrt(5.0))
            n_clusters = max(1, len(ordered_3d))
            for c_idx, tid in enumerate(ordered_3d):
                members = groups_3d[tid]
                spec = eff_types.get(tid, {})
                if tid == "citadel_root":
                    cx, cy, cz = 0.0, 0.0, 140.0
                else:
                    y_unit = 1.0 - (2.0 * (c_idx + 0.5)) / n_clusters
                    r_xy = math.sqrt(max(0.0, 1.0 - y_unit * y_unit))
                    theta = c_idx * golden_angle
                    cx = round(math.cos(theta) * r_xy * sphere_r, 2)
                    cy = round(math.sin(theta) * r_xy * sphere_r, 2)
                    cz = round(y_unit * sphere_r * 0.72 + 110.0, 2)
                for local_idx, node_idx in enumerate(members):
                    phi = local_idx * golden_angle
                    m_rad = 38.0 * math.sqrt(local_idx + 1.0)
                    mz = math.sin(local_idx * 1.15) * min(120.0, m_rad * 0.48)
                    positions[node_idx] = (
                        round(cx + math.cos(phi) * m_rad, 2),
                        round(cy + math.sin(phi) * m_rad, 2),
                        round(cz + mz, 2),
                    )
                territories.append(
                    {
                        "territory_id": f"terr-3d-{tid}",
                        "label": str(spec.get("display_name") or tid),
                        "unit_type": tid,
                        "color": str(spec.get("color_primary") or "#38BDF8"),
                        "cx": cx,
                        "cy": cy,
                        "radius": round(max(100.0, 40.0 * math.sqrt(len(members)) + 30.0), 1),
                        "count": len(members),
                    }
                )

    out_nodes: list[dict[str, Any]] = []
    min_x = min_y = min_z = 0.0
    max_x = max_y = max_z = 0.0
    for idx, n in enumerate(dedup_nodes):
        nid = str(n["id"])
        wx, wy, wz = positions[idx]
        if idx == 0:
            min_x = max_x = wx
            min_y = max_y = wy
            min_z = max_z = wz
        else:
            min_x, max_x = min(min_x, wx), max(max_x, wx)
            min_y, max_y = min(min_y, wy), max(max_y, wy)
            min_z, max_z = min(min_z, wz), max(max_z, wz)
        vital_pct, status, mls_locked = _extract_node_vital_and_flags(n)
        out_nodes.append(
            {
                "id": nid,
                "label": str(n.get("label") or nid),
                "kind": str(n.get("kind") or "entity"),
                "domain": str(n.get("domain") or "company_org"),
                "summary": str(n.get("summary") or ""),
                "primary_url": str(n.get("primary_url") or ""),
                "unit_type": node_unit_types[idx],
                "graph_level": classify_node_graph_level(n),
                "tactical_status": classify_tactical_status(n),
                "level_index": levels.get(nid, 2),
                "wx": wx,
                "wy": wy,
                "wz": wz,
                "vital_pct": vital_pct,
                "child_count": len(n.get("drilldown_children") or ()),
                "status": status,
                "mls_locked": mls_locked,
            }
        )

    compact_edges = [[id_to_idx[u], id_to_idx[v], rel] for u, v, rel in edge_pairs_raw]
    return {
        "schema_version": WORLD_MAP_SCHEMA_VERSION,
        "unit_types_schema_version": UNIT_ARCHETYPES_SCHEMA_VERSION,
        "mode": eff_mode,
        "scope": str(scope or ""),
        "node_count": len(out_nodes),
        "edge_count": len(compact_edges),
        "world_bounds": {
            "min_x": round(min_x - 160.0, 1),
            "max_x": round(max_x + 160.0, 1),
            "min_y": round(min_y - 160.0, 1),
            "max_y": round(max_y + 160.0, 1),
            "min_z": round(min_z, 1),
            "max_z": round(max_z + 80.0, 1),
        },
        "territories": territories,
        "unit_types": eff_types,
        "unit_counts": unit_counts,
        "nodes": out_nodes,
        "edges": compact_edges,
    }


def build_world_map_engine_js() -> str:
    """Return modular zero-dependency 2D/2.5D/3D Spatial Map Canvas JS engine (zero // comments)."""
    builtin_types_json = json.dumps(BUILTIN_UNIT_TYPES, ensure_ascii=True, separators=(",", ":"))
    projection_guide_json = json.dumps(PROJECTION_GUIDE, ensure_ascii=True, separators=(",", ":"))
    template = r"""
(function(globalScope) {
  const BUILTIN_UNIT_TYPES = __BUILTIN_UNIT_TYPES__;
  const PROJECTION_GUIDE = __PROJECTION_GUIDE__;
  const CUSTOM_TYPES_STORAGE_KEY = 'opscryer_custom_unit_types_v1';
  const OVERRIDES_STORAGE_KEY = 'opscryer_unit_type_overrides_v1';
  const SAFE_SVG_COLORS = new Set([
    'none', 'transparent', 'currentcolor', 'white', 'black', 'cyan', 'gold',
    'amber', 'red', 'green', 'blue', 'purple', 'teal', 'indigo', 'sky',
    'emerald', 'slate', 'gray', 'grey', 'orange', 'yellow', 'pink'
  ]);

  function normalizeProjectionId(raw) {
    const k = String(raw || '').trim().toLowerCase();
    if (k === 'flat_2d' || k === 'top_2d' || k === '2d' || k === 'ortho_2d') return 'flat_2d';
    if (k === 'orbit_3d' || k === 'cloud_3d' || k === '3d') return 'orbit_3d';
    return 'iso_25d';
  }
  const SAFE_SVG_TAGS = new Set([
    'svg', 'g', 'path', 'circle', 'rect', 'ellipse', 'line', 'polygon', 'polyline'
  ]);

  function clamp(v, lo, hi) {
    return v < lo ? lo : (v > hi ? hi : v);
  }

  function cloneJson(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function readStorageJson(key, fallback) {
    try {
      if (typeof localStorage === 'undefined') return fallback;
      const raw = localStorage.getItem(key);
      if (!raw) return fallback;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : fallback;
    } catch (_e) {
      return fallback;
    }
  }

  function writeStorageJson(key, val) {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(key, JSON.stringify(val));
      }
    } catch (_e) {}
  }

  function sanitizeClientSvg(rawSvg) {
    if (typeof rawSvg !== 'string' || !rawSvg.trim()) {
      throw new Error('SVG markup must be non-empty');
    }
    if (rawSvg.length > 16384) {
      throw new Error('SVG markup exceeds 16 KiB limit');
    }
    const low = rawSvg.toLowerCase();
    const blocked = ['<!', '<script', '<foreignobject', 'javascript:', 'vbscript:', 'data:', 'url(', '@import', 'expression('];
    for (let i = 0; i < blocked.length; i++) {
      if (low.indexOf(blocked[i]) !== -1) {
        throw new Error('SVG contains forbidden construct: ' + blocked[i]);
      }
    }
    const primitives = [];
    let viewBox = [0, 0, 64, 64];
    const vbMatch = rawSvg.match(/viewBox\s*=\s*["']([^"']+)["']/i);
    if (vbMatch) {
      const parts = vbMatch[1].trim().split(/[\s,]+/).map(Number);
      if (parts.length !== 4 || parts.some(x => !Number.isFinite(x)) || parts[2] <= 0 || parts[3] <= 0) {
        throw new Error('Invalid SVG viewBox');
      }
      viewBox = parts;
    }
    const tagRe = /<\s*(\/)?\s*([a-zA-Z0-9:_-]+)([^>]*)>/g;
    let m;
    let count = 0;
    while ((m = tagRe.exec(rawSvg)) !== null) {
      if (m[1]) continue;
      const tag = String(m[2] || '').split(':').pop().toLowerCase();
      if (!SAFE_SVG_TAGS.has(tag)) {
        throw new Error('Disallowed SVG tag <' + tag + '>');
      }
      count++;
      if (count > 64) throw new Error('Too many SVG elements (max 64)');
      const attrSrc = m[3] || '';
      if (/\bon[a-z]+\s*=|\bhref\s*=|\bxlink:href\s*=|\bstyle\s*=/i.test(attrSrc)) {
        throw new Error('Disallowed SVG event/href/style attribute');
      }
      if (tag === 'svg' || tag === 'g') continue;
      const attrs = {};
      const attrRe = /([a-zA-Z0-9:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
      let am;
      while ((am = attrRe.exec(attrSrc)) !== null) {
        const ak = am[1].toLowerCase();
        const av = am[2] !== undefined ? am[2] : (am[3] || '');
        attrs[ak] = av;
      }
      const checkColor = col => {
        if (!col) return undefined;
        const c = String(col).trim();
        if (/^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(c)) return c;
        if (SAFE_SVG_COLORS.has(c.toLowerCase())) return c.toLowerCase();
        throw new Error('Disallowed SVG color: ' + c.slice(0, 24));
      };
      const num = (k, def) => {
        const v = Number(attrs[k] !== undefined ? attrs[k] : def);
        if (!Number.isFinite(v)) throw new Error('Non-finite SVG numeric attribute ' + k);
        return v;
      };
      const base = {tag: tag};
      if (attrs.fill) base.fill = checkColor(attrs.fill);
      if (attrs.stroke) base.stroke = checkColor(attrs.stroke);
      if (attrs['stroke-width'] !== undefined) base.stroke_width = clamp(num('stroke-width', 1.5), 0, 64);
      if (attrs.opacity !== undefined) base.opacity = clamp(num('opacity', 1), 0, 1);
      if (tag === 'path') {
        const d = String(attrs.d || '').trim();
        if (!d || !/^[0-9eE.,+\-\sMmLlHhVvCcSsQqTtAaZz]{1,2048}$/.test(d)) {
          throw new Error('Invalid SVG path d geometry');
        }
        base.d = d;
      } else if (tag === 'circle') {
        base.cx = num('cx', 0); base.cy = num('cy', 0); base.r = Math.max(0.1, num('r', 1));
      } else if (tag === 'rect') {
        base.x = num('x', 0); base.y = num('y', 0);
        base.w = Math.max(0.1, num('width', 1)); base.h = Math.max(0.1, num('height', 1));
        base.rx = Math.max(0, num('rx', 0));
      } else if (tag === 'ellipse') {
        base.cx = num('cx', 0); base.cy = num('cy', 0);
        base.rx = Math.max(0.1, num('rx', 1)); base.ry = Math.max(0.1, num('ry', 1));
      } else if (tag === 'line') {
        base.x1 = num('x1', 0); base.y1 = num('y1', 0); base.x2 = num('x2', 0); base.y2 = num('y2', 0);
      } else if (tag === 'polygon' || tag === 'polyline') {
        const ptsRaw = String(attrs.points || '').trim();
        if (!ptsRaw || !/^[0-9eE.,+\-\s]{1,1024}$/.test(ptsRaw)) {
          throw new Error('Invalid SVG polygon/polyline points');
        }
        const pts = ptsRaw.split(/[\s,]+/).filter(Boolean).map(Number);
        if (pts.length < 4 || pts.length % 2 !== 0 || pts.some(x => !Number.isFinite(x))) {
          throw new Error('SVG points must have even finite numbers');
        }
        base.points = pts;
      }
      primitives.push(base);
    }
    if (!primitives.length) throw new Error('SVG must contain at least one geometry primitive');
    return {view_box: viewBox, primitives: primitives, element_count: primitives.length};
  }

  function resolveClientNodeUnitType(node, unitTypes, overrides) {
    const nid = String((node && node.id) || '');
    if (overrides && nid && overrides[nid] && unitTypes[overrides[nid]]) {
      return overrides[nid];
    }
    const exp = String((node && node.unit_type) || '').trim().toLowerCase();
    if (exp && unitTypes[exp]) return exp;
    const kind = String((node && node.kind) || '').trim().toLowerCase();
    const dom = String((node && node.domain) || '').trim().toLowerCase();
    const rkind = String((node && (node.resource_kind || (node.resource && node.resource.kind))) || '').trim().toLowerCase();
    const nidLow = nid.toLowerCase();
    let bestId = unitTypes.forge_project ? 'forge_project' : (Object.keys(unitTypes)[0] || 'citadel_root');
    let bestScore = -1;
    const keys = Object.keys(unitTypes);
    for (let i = 0; i < keys.length; i++) {
      const tid = keys[i];
      const spec = unitTypes[tid] || {};
      let sc = 0;
      const prefixes = spec.match_prefixes || [];
      for (let p = 0; p < prefixes.length; p++) {
        if (nidLow.indexOf(String(prefixes[p]).toLowerCase()) === 0) { sc += 5; break; }
      }
      const kinds = (spec.match_kinds || []).map(x => String(x).toLowerCase());
      if (kinds.indexOf(kind) !== -1 || (rkind && (kinds.indexOf('k8s_' + rkind) !== -1 || kinds.indexOf('kubernetes_' + rkind) !== -1))) {
        sc += 4;
      }
      const doms = (spec.match_domains || []).map(x => String(x).toLowerCase());
      if (doms.indexOf(dom) !== -1) sc += 1;
      if (sc <= 0) continue;
      const total = sc * 1000 + (spec.builtin ? 0 : 200) + (Number(spec.priority) || 50);
      if (total > bestScore) { bestScore = total; bestId = tid; }
    }
    return bestId;
  }

  function packFormation(idx, count, form, spacing) {
    if (count <= 1) return [0, 0];
    if (form === 'ring') {
      let cap = 8;
      let ring = 0;
      let rem = idx;
      while (rem >= cap) { rem -= cap; ring++; cap += 6; }
      const ang = (2 * Math.PI * rem) / Math.max(1, Math.min(cap, count - (idx - rem)));
      const rad = (1 + ring * 0.95) * spacing;
      return [Math.cos(ang) * rad, Math.sin(ang) * rad];
    }
    if (form === 'orbital') {
      const rad = spacing * 0.68 * Math.sqrt(idx + 1);
      const th = idx * 2.399963229728653;
      return [Math.cos(th) * rad, Math.sin(th) * rad * 0.78];
    }
    if (form === 'hex') {
      if (count <= 6) {
        const ang = (2 * Math.PI * idx) / count;
        return [Math.cos(ang) * spacing * 0.92, Math.sin(ang) * spacing * 0.92];
      }
      if (count <= 64) {
        const cols = Math.max(2, Math.ceil(Math.sqrt(count)));
        const row = Math.floor(idx / cols);
        const col = idx % cols;
        const ox = (row % 2) * spacing * 0.5;
        return [(col - (cols - 1) * 0.5) * spacing + ox, (row - Math.floor((count - 1) / cols) * 0.5) * spacing * 0.866];
      }
      const rad = spacing * 0.62 * Math.sqrt(idx + 0.5);
      const th = idx * 2.399963229728653;
      return [Math.cos(th) * rad, Math.sin(th) * rad];
    }
    const cols = Math.max(1, Math.ceil(Math.sqrt(count)));
    const rows = Math.max(1, Math.ceil(count / cols));
    const row = Math.floor(idx / cols);
    const col = idx % cols;
    return [(col - (cols - 1) * 0.5) * spacing, (row - (rows - 1) * 0.5) * spacing];
  }

  function buildClientWorldLayout(catalog, mode, unitTypes, nodeOverrides) {
    const effMode = (mode === 'domain_squads' || mode === 'graph_layers' || mode === 'cloud_3d') ? mode : 'unit_type';
    const glApi = globalScope.OpsCryerGraphLayers || null;
    const effTypes = unitTypes && Object.keys(unitTypes).length ? cloneJson(unitTypes) : cloneJson(BUILTIN_UNIT_TYPES);
    const rawNodes = ((catalog && catalog.nodes) || []).filter(n => n && n.id);
    const idToIdx = new Map();
    const nodes = [];
    for (let i = 0; i < rawNodes.length; i++) {
      const nid = String(rawNodes[i].id);
      if (!idToIdx.has(nid)) {
        idToIdx.set(nid, nodes.length);
        nodes.push(rawNodes[i]);
      }
    }
    const edgePairs = [];
    const seenEdge = new Set();
    const addEdge = (u, v, rel) => {
      if (u === v || !idToIdx.has(u) || !idToIdx.has(v)) return;
      const k = u + '->' + v;
      if (seenEdge.has(k)) return;
      seenEdge.add(k);
      edgePairs.push([idToIdx.get(u), idToIdx.get(v), rel || 'connected']);
    };
    ((catalog && catalog.edges) || []).forEach(e => {
      if (e) addEdge(String(e.source || ''), String(e.target || ''), String(e.relation || 'connected'));
    });
    for (let i = 0; i < nodes.length; i++) {
      const u = String(nodes[i].id);
      const ch = nodes[i].drilldown_children || [];
      for (let j = 0; j < ch.length; j++) addEdge(u, String(ch[j] || ''), 'encapsulates');
    }

    const nodeUnitTypes = nodes.map(n => resolveClientNodeUnitType(n, effTypes, nodeOverrides));
    const unitCounts = {};
    nodeUnitTypes.forEach(ut => { unitCounts[ut] = (unitCounts[ut] || 0) + 1; });

    const outNodes = nodes.map((n, i) => ({
      id: String(n.id),
      label: String(n.label || n.id),
      kind: String(n.kind || 'entity'),
      domain: String(n.domain || 'company_org'),
      summary: String(n.summary || ''),
      primary_url: String(n.primary_url || ''),
      unit_type: nodeUnitTypes[i],
      graph_level: glApi ? glApi.classifyNodeGraphLevel(n) : String(n.graph_level || 'feature'),
      tactical_status: glApi ? glApi.classifyTacticalStatus(n) : (n.alert ? 'red' : 'green'),
      level_index: typeof n.level_index === 'number' ? n.level_index : (typeof n.zoom_level === 'number' ? n.zoom_level : 2),
      wx: 0, wy: 0, wz: 0,
      vital_pct: 95,
      child_count: (n.drilldown_children || []).length,
      status: n.alert ? 'alert' : 'nominal',
      mls_locked: Boolean(n.mls_redacted || n.opaqued || (typeof n.classification_rank === 'number' && n.classification_rank >= 20))
    }));

    const territories = [];
    if (effMode === 'unit_type') {
      const groups = new Map();
      nodeUnitTypes.forEach((ut, i) => {
        if (!groups.has(ut)) groups.set(ut, []);
        groups.get(ut).push(i);
      });
      const ordered = Array.from(groups.keys()).sort((a, b) => ((effTypes[b]?.priority || 50) - (effTypes[a]?.priority || 50)) || a.localeCompare(b));
      const ringTypes = ordered.filter(t => t !== 'citadel_root');
      if (groups.has('citadel_root')) {
        const mems = groups.get('citadel_root');
        const sp = effTypes.citadel_root || {};
        mems.forEach((ni, li) => {
          const [dx, dy] = packFormation(li, mems.length, sp.formation || 'ring', 54);
          outNodes[ni].wx = dx; outNodes[ni].wy = dy;
          outNodes[ni].wz = (Number(sp.z_elevation) || 85) + Math.max(0, 4 - outNodes[ni].level_index) * 10;
        });
        territories.push({
          territory_id: 'terr-citadel_root', label: sp.display_name || 'System Root',
          unit_type: 'citadel_root', color: sp.color_primary || '#38BDF8', cx: 0, cy: 0,
          radius: Math.max(95, 38 * Math.sqrt(mems.length) + 32), count: mems.length
        });
      }
      const baseRing = 340 + Math.min(320, Math.sqrt(outNodes.length) * 12);
      ringTypes.forEach((tid, sIdx) => {
        const mems = groups.get(tid);
        const sp = effTypes[tid] || {};
        const rad = Math.max(115, 42 * Math.sqrt(mems.length) + 36);
        const r = baseRing + Math.floor(sIdx / 8) * 320 + Math.max(0, (rad - 180) * 0.75);
        const ang = -Math.PI * 0.5 + (2 * Math.PI * sIdx) / Math.max(1, ringTypes.length);
        const cx = Math.cos(ang) * r;
        const cy = Math.sin(ang) * r;
        mems.forEach((ni, li) => {
          const [dx, dy] = packFormation(li, mems.length, sp.formation || 'hex', 54);
          outNodes[ni].wx = cx + dx; outNodes[ni].wy = cy + dy;
          outNodes[ni].wz = (Number(sp.z_elevation) || 32) + Math.max(0, 4 - outNodes[ni].level_index) * 6;
        });
        territories.push({
          territory_id: 'terr-' + tid, label: sp.display_name || tid,
          unit_type: tid, color: sp.color_primary || '#38BDF8', cx: cx, cy: cy, radius: rad, count: mems.length
        });
      });
    } else if (effMode === 'domain_squads') {
      const doms = new Map();
      outNodes.forEach((n, i) => {
        if (!doms.has(n.domain)) doms.set(n.domain, []);
        doms.get(n.domain).push(i);
      });
      const ordDom = Array.from(doms.keys()).sort((a, b) => (doms.get(b).length - doms.get(a).length) || a.localeCompare(b));
      const baseRing = 310 + Math.min(300, Math.sqrt(outNodes.length) * 11);
      ordDom.forEach((dom, dIdx) => {
        const mems = doms.get(dom).slice().sort((a, b) => ((effTypes[outNodes[b].unit_type]?.priority || 50) - (effTypes[outNodes[a].unit_type]?.priority || 50)));
        const ang = -Math.PI * 0.5 + (2 * Math.PI * dIdx) / Math.max(1, ordDom.length);
        const r = ordDom.length > 1 ? baseRing : 0;
        const cx = Math.cos(ang) * r;
        const cy = Math.sin(ang) * r;
        const leadUt = outNodes[mems[0]].unit_type;
        mems.forEach((ni, li) => {
          const [dx, dy] = packFormation(li, mems.length, 'hex', 52);
          const sp = effTypes[outNodes[ni].unit_type] || {};
          outNodes[ni].wx = cx + dx; outNodes[ni].wy = cy + dy;
          outNodes[ni].wz = (Number(sp.z_elevation) || 32) + Math.max(0, 4 - outNodes[ni].level_index) * 6;
        });
        territories.push({
          territory_id: 'terr-dom-' + dom, label: dom.replace(/_/g, ' '),
          unit_type: leadUt, color: (effTypes[leadUt] && effTypes[leadUt].color_primary) || '#38BDF8',
          cx: cx, cy: cy, radius: Math.max(125, 44 * Math.sqrt(mems.length) + 36), count: mems.length
        });
      });
    } else if (effMode === 'graph_layers') {
      const levelDefs = (glApi && glApi.GRAPH_LEVELS) ? glApi.GRAPH_LEVELS : [
        {id: 'project', label: 'Project', icon: '📦', color: '#38BDF8', z_elevation: 120},
        {id: 'feature', label: 'Feature', icon: '✨', color: '#A855F7', z_elevation: 98},
        {id: 'dependency', label: 'Include / Dependency', icon: '🔗', color: '#F59E0B', z_elevation: 78},
        {id: 'requirement', label: 'Requirement', icon: '📋', color: '#14B8A6', z_elevation: 60},
        {id: 'test', label: 'Test', icon: '🧪', color: '#22C55E', z_elevation: 42},
        {id: 'deployment', label: 'Deployment', icon: '🚀', color: '#06B6D4', z_elevation: 24},
        {id: 'contract', label: 'Contract', icon: '📜', color: '#E879F9', z_elevation: 8}
      ];
      const byLvl = new Map();
      levelDefs.forEach(ld => byLvl.set(ld.id, []));
      outNodes.forEach((n, i) => {
        const lid = byLvl.has(n.graph_level) ? n.graph_level : 'feature';
        byLvl.get(lid).push(i);
      });
      const activeDefs = levelDefs.filter(ld => (byLvl.get(ld.id) || []).length > 0);
      const baseRing = 340 + Math.min(300, Math.sqrt(outNodes.length) * 11);
      activeDefs.forEach((ld, bIdx) => {
        const mems = byLvl.get(ld.id);
        const ang = -Math.PI * 0.5 + (2 * Math.PI * bIdx) / Math.max(1, activeDefs.length);
        const r = activeDefs.length > 1 ? baseRing : 0;
        const cx = Math.cos(ang) * r;
        const cy = Math.sin(ang) * r;
        const leadUt = outNodes[mems[0]].unit_type;
        mems.forEach((ni, li) => {
          const [dx, dy] = packFormation(li, mems.length, 'hex', 52);
          outNodes[ni].wx = cx + dx;
          outNodes[ni].wy = cy + dy;
          outNodes[ni].wz = Number(ld.z_elevation || 40);
        });
        territories.push({
          territory_id: 'terr-lvl-' + ld.id,
          label: ld.icon + ' ' + ld.label,
          graph_level: ld.id,
          unit_type: leadUt,
          color: ld.color || '#38BDF8',
          cx: cx, cy: cy,
          radius: Math.max(125, 44 * Math.sqrt(mems.length) + 36),
          count: mems.length
        });
      });
    } else {
      const groups = new Map();
      outNodes.forEach((n, i) => {
        if (!groups.has(n.unit_type)) groups.set(n.unit_type, []);
        groups.get(n.unit_type).push(i);
      });
      const ord = Array.from(groups.keys()).sort((a, b) => ((effTypes[b]?.priority || 50) - (effTypes[a]?.priority || 50)) || a.localeCompare(b));
      const sphereR = 360 + Math.min(280, Math.sqrt(outNodes.length) * 10);
      const golden = Math.PI * (3 - Math.sqrt(5));
      ord.forEach((tid, cIdx) => {
        const mems = groups.get(tid);
        const sp = effTypes[tid] || {};
        let cx = 0, cy = 0, cz = 140;
        if (tid !== 'citadel_root') {
          const yu = 1 - (2 * (cIdx + 0.5)) / Math.max(1, ord.length);
          const rxy = Math.sqrt(Math.max(0, 1 - yu * yu));
          const th = cIdx * golden;
          cx = Math.cos(th) * rxy * sphereR;
          cy = Math.sin(th) * rxy * sphereR;
          cz = yu * sphereR * 0.72 + 110;
        }
        mems.forEach((ni, li) => {
          const phi = li * golden;
          const mRad = 38 * Math.sqrt(li + 1);
          const mz = Math.sin(li * 1.15) * Math.min(120, mRad * 0.48);
          outNodes[ni].wx = cx + Math.cos(phi) * mRad;
          outNodes[ni].wy = cy + Math.sin(phi) * mRad;
          outNodes[ni].wz = cz + mz;
        });
        territories.push({
          territory_id: 'terr-3d-' + tid, label: sp.display_name || tid,
          unit_type: tid, color: sp.color_primary || '#38BDF8', cx: cx, cy: cy,
          radius: Math.max(100, 40 * Math.sqrt(mems.length) + 30), count: mems.length
        });
      });
    }

    let minX = 0, maxX = 0, minY = 0, maxY = 0, minZ = 0, maxZ = 80;
    outNodes.forEach((n, idx) => {
      if (idx === 0) {
        minX = maxX = n.wx; minY = maxY = n.wy; minZ = maxZ = n.wz;
      } else {
        if (n.wx < minX) minX = n.wx; if (n.wx > maxX) maxX = n.wx;
        if (n.wy < minY) minY = n.wy; if (n.wy > maxY) maxY = n.wy;
        if (n.wz < minZ) minZ = n.wz; if (n.wz > maxZ) maxZ = n.wz;
      }
    });
    return {
      schema_version: '1.0-world-map-layout',
      mode: effMode,
      node_count: outNodes.length,
      edge_count: edgePairs.length,
      world_bounds: {min_x: minX - 160, max_x: maxX + 160, min_y: minY - 160, max_y: maxY + 160, min_z: minZ, max_z: maxZ + 80},
      territories: territories,
      unit_types: effTypes,
      unit_counts: unitCounts,
      nodes: outNodes,
      edges: edgePairs
    };
  }

  function cameraBasis(cam) {
    const pitchRad = clamp(Number(cam.pitchDeg || 54), 18, 89.2) * Math.PI / 180;
    const yawRad = Number(cam.yawRad || 0);
    const cp = Math.cos(pitchRad), sp = Math.sin(pitchRad);
    const cy = Math.cos(yawRad), sy = Math.sin(yawRad);
    const fwd = [sy * cp, cy * cp, -sp];
    const right = [cy, -sy, 0];
    const up = [sy * sp, cy * sp, cp];
    const dist = Math.max(120, Number(cam.distance || 920));
    const tx = Number(cam.targetX || 0);
    const ty = Number(cam.targetY || 0);
    const tz = Number(cam.targetZ || 0);
    const pos = [tx - fwd[0] * dist, ty - fwd[1] * dist, tz - fwd[2] * dist];
    return {fwd: fwd, right: right, up: up, pos: pos, fovRad: clamp(Number(cam.fovDeg || 44), 25, 75) * Math.PI / 180};
  }

  function projectPoint(wx, wy, wz, cam, viewW, viewH, cachedBasis) {
    const b = cachedBasis || cameraBasis(cam);
    const w = Math.max(1, viewW || 1000), h = Math.max(1, viewH || 600);
    const focal = (h * 0.5) / Math.tan(b.fovRad * 0.5);
    const dx = wx - b.pos[0], dy = wy - b.pos[1], dz = wz - b.pos[2];
    const vx = dx * b.right[0] + dy * b.right[1] + dz * b.right[2];
    const vy = dx * b.up[0] + dy * b.up[1] + dz * b.up[2];
    const depth = dx * b.fwd[0] + dy * b.fwd[1] + dz * b.fwd[2];
    if (depth <= 16) return {sx: -9999, sy: -9999, scale: 0, depth: depth, behind: true};
    const scale = focal / depth;
    return {sx: w * 0.5 + vx * scale, sy: h * 0.5 - vy * scale, scale: scale, depth: depth, behind: false};
  }

  function unprojectGroundPoint(sx, sy, cam, viewW, viewH, groundZ, cachedBasis) {
    const b = cachedBasis || cameraBasis(cam);
    const w = Math.max(1, viewW || 1000), h = Math.max(1, viewH || 600);
    const focal = (h * 0.5) / Math.tan(b.fovRad * 0.5);
    const nx = (sx - w * 0.5) / focal;
    const ny = (h * 0.5 - sy) / focal;
    const rx = b.right[0] * nx + b.up[0] * ny + b.fwd[0];
    const ry = b.right[1] * nx + b.up[1] * ny + b.fwd[1];
    const rz = b.right[2] * nx + b.up[2] * ny + b.fwd[2];
    const gz = Number(groundZ || 0);
    if (rz > -0.025) {
      const cap = Math.max(600, Number(cam.distance || 900) * 3.5);
      const lenXy = Math.hypot(rx, ry) || 1;
      return {wx: b.pos[0] + (rx / lenXy) * cap, wy: b.pos[1] + (ry / lenXy) * cap, clamped: true};
    }
    const t = Math.min(Number(cam.distance || 900) * 4.5, Math.max(10, (gz - b.pos[2]) / rz));
    return {wx: b.pos[0] + rx * t, wy: b.pos[1] + ry * t, clamped: false};
  }

  function computeCameraTrapezoid(cam, viewW, viewH, groundZ) {
    const b = cameraBasis(cam);
    const w = Math.max(1, viewW || 1000), h = Math.max(1, viewH || 600);
    return [
      unprojectGroundPoint(0, 0, cam, w, h, groundZ, b),
      unprojectGroundPoint(w, 0, cam, w, h, groundZ, b),
      unprojectGroundPoint(w, h, cam, w, h, groundZ, b),
      unprojectGroundPoint(0, h, cam, w, h, groundZ, b)
    ];
  }

  function drawLayerPrimitive(ctx, lay) {
    const cx = Number(lay.cx != null ? lay.cx : 32), cy = Number(lay.cy != null ? lay.cy : 32);
    const r = Number(lay.r || 18);
    ctx.save();
    if (lay.opacity != null) ctx.globalAlpha = clamp(Number(lay.opacity), 0.05, 1);
    const sh = lay.shape;
    if (sh === 'path' && lay.d && typeof Path2D === 'function') {
      try {
        const p2 = new Path2D(lay.d);
        if (lay.fill && lay.fill !== 'none') { ctx.fillStyle = lay.fill; ctx.fill(p2); }
        if (lay.stroke && lay.stroke !== 'none') { ctx.strokeStyle = lay.stroke; ctx.lineWidth = Number(lay.stroke_width || 2); ctx.stroke(p2); }
      } catch (_e) {}
      ctx.restore();
      return;
    }
    ctx.beginPath();
    if (sh === 'circle' || sh === 'ring') {
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
    } else if (sh === 'hex') {
      for (let i = 0; i < 6; i++) {
        const a = Math.PI / 6 + i * (Math.PI / 3);
        const px = cx + Math.cos(a) * r, py = cy + Math.sin(a) * r;
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
    } else if (sh === 'diamond') {
      ctx.moveTo(cx, cy - r); ctx.lineTo(cx + r, cy); ctx.lineTo(cx, cy + r); ctx.lineTo(cx - r, cy); ctx.closePath();
    } else if (sh === 'triangle') {
      for (let i = 0; i < 3; i++) {
        const a = -Math.PI / 2 + i * (2 * Math.PI / 3);
        const px = cx + Math.cos(a) * r, py = cy + Math.sin(a) * r;
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
    } else if (sh === 'star') {
      for (let i = 0; i < 10; i++) {
        const a = -Math.PI / 2 + i * (Math.PI / 5);
        const sr = (i % 2 === 0) ? r : r * 0.45;
        const px = cx + Math.cos(a) * sr, py = cy + Math.sin(a) * sr;
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
    } else if (sh === 'shield') {
      ctx.moveTo(cx, cy - r);
      ctx.lineTo(cx + r * 0.85, cy - r * 0.55);
      ctx.lineTo(cx + r * 0.72, cy + r * 0.35);
      ctx.lineTo(cx, cy + r);
      ctx.lineTo(cx - r * 0.72, cy + r * 0.35);
      ctx.lineTo(cx - r * 0.85, cy - r * 0.55);
      ctx.closePath();
    } else if (sh === 'cross') {
      const arm = r * 0.85;
      ctx.moveTo(cx - arm, cy); ctx.lineTo(cx + arm, cy);
      ctx.moveTo(cx, cy - arm); ctx.lineTo(cx, cy + arm);
    } else if (sh === 'rect' || sh === 'pill') {
      const w = Number(lay.w || 34), h = Number(lay.h || 24);
      const x = cx - w * 0.5, y = cy - h * 0.5;
      if (sh === 'pill' && typeof ctx.roundRect === 'function') {
        ctx.roundRect(x, y, w, h, Math.min(h * 0.5, 10));
      } else {
        ctx.rect(x, y, w, h);
      }
    }
    if (sh !== 'ring' && sh !== 'cross' && lay.fill && lay.fill !== 'none') {
      ctx.fillStyle = lay.fill;
      ctx.fill();
    }
    if (lay.stroke && lay.stroke !== 'none') {
      ctx.strokeStyle = lay.stroke;
      ctx.lineWidth = Number(lay.stroke_width || 2.2);
      ctx.stroke();
    }
    ctx.restore();
  }

  function drawSvgPrimitive(ctx, prim) {
    ctx.save();
    if (prim.opacity != null) ctx.globalAlpha = clamp(Number(prim.opacity), 0.05, 1);
    const fill = (prim.fill && prim.fill !== 'none') ? prim.fill : null;
    const stroke = (prim.stroke && prim.stroke !== 'none') ? prim.stroke : null;
    const lw = Number(prim.stroke_width || 2);
    if (prim.tag === 'path' && prim.d && typeof Path2D === 'function') {
      try {
        const p = new Path2D(prim.d);
        if (fill) { ctx.fillStyle = fill; ctx.fill(p); }
        if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = lw; ctx.stroke(p); }
      } catch (_e) {}
      ctx.restore();
      return;
    }
    ctx.beginPath();
    if (prim.tag === 'circle') {
      ctx.arc(prim.cx, prim.cy, prim.r, 0, Math.PI * 2);
    } else if (prim.tag === 'ellipse' && typeof ctx.ellipse === 'function') {
      ctx.ellipse(prim.cx, prim.cy, prim.rx, prim.ry, 0, 0, Math.PI * 2);
    } else if (prim.tag === 'rect') {
      if (prim.rx > 0 && typeof ctx.roundRect === 'function') ctx.roundRect(prim.x, prim.y, prim.w, prim.h, prim.rx);
      else ctx.rect(prim.x, prim.y, prim.w, prim.h);
    } else if (prim.tag === 'line') {
      ctx.moveTo(prim.x1, prim.y1); ctx.lineTo(prim.x2, prim.y2);
    } else if ((prim.tag === 'polygon' || prim.tag === 'polyline') && Array.isArray(prim.points) && prim.points.length >= 4) {
      ctx.moveTo(prim.points[0], prim.points[1]);
      for (let i = 2; i < prim.points.length; i += 2) ctx.lineTo(prim.points[i], prim.points[i + 1]);
      if (prim.tag === 'polygon') ctx.closePath();
    }
    if (fill && prim.tag !== 'line' && prim.tag !== 'polyline') { ctx.fillStyle = fill; ctx.fill(); }
    if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = lw; ctx.stroke(); }
    ctx.restore();
  }

  function traceOctagonPlate(ctx, cx, cy, r, cut) {
    const k = Math.max(4, cut || (r * 0.34));
    ctx.beginPath();
    ctx.moveTo(cx - r + k, cy - r);
    ctx.lineTo(cx + r - k, cy - r);
    ctx.lineTo(cx + r, cy - r + k);
    ctx.lineTo(cx + r, cy + r - k);
    ctx.lineTo(cx + r - k, cy + r);
    ctx.lineTo(cx - r + k, cy + r);
    ctx.lineTo(cx - r, cy + r - k);
    ctx.lineTo(cx - r, cy - r + k);
    ctx.closePath();
  }

  function bakeUnitSprite(spec, pixelSize) {
    if (typeof document === 'undefined' || typeof document.createElement !== 'function') return null;
    const c = document.createElement('canvas');
    if (!c || typeof c.getContext !== 'function') return null;
    const dpr = (typeof window !== 'undefined' && Number(window.devicePixelRatio)) ? Math.min(2, window.devicePixelRatio) : 1;
    c.width = pixelSize * dpr;
    c.height = pixelSize * dpr;
    const ctx = c.getContext('2d');
    if (!ctx) return null;
    ctx.scale((pixelSize * dpr) / 64, (pixelSize * dpr) / 64);

    const primCol = (spec && spec.color_primary) || '#38BDF8';
    const accCol = (spec && spec.color_accent) || '#F59E0B';

    /* Ambient telemetry glow backdrop */
    if (typeof ctx.createRadialGradient === 'function') {
      try {
        const halo = ctx.createRadialGradient(32, 32, 8, 32, 32, 31);
        halo.addColorStop(0, primCol + '40');
        halo.addColorStop(0.65, primCol + '14');
        halo.addColorStop(1, 'rgba(2, 6, 23, 0)');
        ctx.fillStyle = halo;
        ctx.beginPath();
        ctx.arc(32, 32, 31, 0, Math.PI * 2);
        ctx.fill();
      } catch (_gErr) {}
    }

    /* Glassmorphic beveled architectural node housing */
    traceOctagonPlate(ctx, 32, 32, 27.5, 9);
    if (typeof ctx.createLinearGradient === 'function') {
      const plateBg = ctx.createLinearGradient(0, 5, 0, 59);
      plateBg.addColorStop(0, '#162540');
      plateBg.addColorStop(0.55, '#0A1326');
      plateBg.addColorStop(1, '#040914');
      ctx.fillStyle = plateBg;
    } else {
      ctx.fillStyle = 'rgba(11, 18, 34, 0.94)';
    }
    ctx.fill();
    ctx.strokeStyle = primCol;
    ctx.lineWidth = 1.9;
    ctx.stroke();

    /* Subtle top edge specular highlight */
    ctx.save();
    traceOctagonPlate(ctx, 32, 32, 25.2, 8);
    ctx.strokeStyle = 'rgba(248, 250, 252, 0.16)';
    ctx.lineWidth = 0.8;
    ctx.stroke();
    ctx.restore();

    if (spec && spec.svg_spec && Array.isArray(spec.svg_spec.primitives) && spec.svg_spec.primitives.length) {
      const vb = spec.svg_spec.view_box || [0, 0, 64, 64];
      const scale = Math.min(44 / Math.max(1, vb[2]), 44 / Math.max(1, vb[3]));
      ctx.save();
      ctx.translate(32 - vb[2] * scale * 0.5 - vb[0] * scale, 32 - vb[3] * scale * 0.5 - vb[1] * scale);
      ctx.scale(scale, scale);
      spec.svg_spec.primitives.forEach(p => drawSvgPrimitive(ctx, p));
      ctx.restore();
    } else if (spec && Array.isArray(spec.icon_layers) && spec.icon_layers.length) {
      spec.icon_layers.forEach(lay => drawLayerPrimitive(ctx, lay));
    } else {
      drawLayerPrimitive(ctx, {shape: 'hex', cx: 32, cy: 32, r: 21, fill: '#0F172A', stroke: primCol, stroke_width: 2.2});
      drawLayerPrimitive(ctx, {shape: 'diamond', cx: 32, cy: 32, r: 9, fill: accCol});
    }
    return c;
  }

  function createWorldMapController(opts) {
    const cfg = opts || {};
    const ids = cfg.ids || {};
    const getEl = k => (typeof document !== 'undefined' && ids[k]) ? document.getElementById(ids[k]) : null;

    const state = {
      layoutMode: 'unit_type',
      projectionMode: 'iso_25d',
      unitTypes: cloneJson(BUILTIN_UNIT_TYPES),
      customTypes: readStorageJson(CUSTOM_TYPES_STORAGE_KEY, {}),
      nodeOverrides: readStorageJson(OVERRIDES_STORAGE_KEY, {}),
      layout: null,
      nodes: [],
      edges: [],
      territories: [],
      idToIndex: new Map(),
      baseWx: new Float32Array(0),
      baseWy: new Float32Array(0),
      baseWz: new Float32Array(0),
      goalWx: new Float32Array(0),
      goalWy: new Float32Array(0),
      goalWz: new Float32Array(0),
      wx: new Float32Array(0),
      wy: new Float32Array(0),
      wz: new Float32Array(0),
      sx: new Float32Array(0),
      sy: new Float32Array(0),
      sScale: new Float32Array(0),
      sDepth: new Float32Array(0),
      selectedMask: new Uint8Array(0),
      groupMask: new Uint16Array(0),
      drawOrder: [],
      spatialHash: new Map(),
      spatialDirty: true,
      selectedIds: [],
      activeSubgroupType: null,
      hoveredIdx: -1,
      controlGroups: {1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: [], 8: [], 9: []},
      lastGroupTap: {num: 0, ts: 0},
      isolateSelected: false,
      levelFilter: null,
      statusFilter: null,
      altPeekHeld: false,
      overlays: {
        health_bar: true,
        child_count: true,
        alert_pulse: true,
        dependency_beam: true,
        mls_badge: true,
        labels: true
      },
      camera: {
        targetX: 0, targetY: 0, targetZ: 0, distance: 1200, pitchDeg: 54, yawRad: 0, fovDeg: 44,
        goalX: 0, goalY: 0, goalZ: 0, goalDist: 1200, goalPitch: 54, goalYaw: 0
      },
      viewW: 1100,
      viewH: 560,
      marquee: {active: false, x0: 0, y0: 0, x1: 0, y1: 0, shiftKey: false},
      orbitDrag: {active: false, lastX: 0, lastY: 0, button: 0},
      keysDown: new Set(),
      spritesHi: new Map(),
      spritesLo: new Map(),
      paused: false,
      rafId: 0,
      frameTimes: [],
      lastFrameTs: 0,
      measuredFps: 60,
      dirtyRender: true
    };

    Object.keys(state.customTypes).forEach(tid => { state.unitTypes[tid] = state.customTypes[tid]; });

    function rebuildSpriteAtlas(onlyTypeId) {
      const targetKeys = onlyTypeId ? [onlyTypeId] : Object.keys(state.unitTypes);
      targetKeys.forEach(tid => {
        const sp = state.unitTypes[tid];
        if (!sp) return;
        const hi = bakeUnitSprite(sp, 68);
        const lo = bakeUnitSprite(sp, 22);
        if (hi) state.spritesHi.set(tid, hi);
        if (lo) state.spritesLo.set(tid, lo);
      });
      state.dirtyRender = true;
    }

    function applyProjectionTargets(snapImmediate) {
      const n = state.nodes.length;
      if (!n) return;
      const effProj = normalizeProjectionId(state.projectionMode);
      const isCloud = state.layoutMode === 'cloud_3d';
      let sumZ = 0;
      const goldenAngle = Math.PI * (3 - Math.sqrt(5));
      for (let i = 0; i < n; i++) {
        const bx = state.baseWx[i];
        const by = state.baseWy[i];
        const bz = state.baseWz[i];
        let tx = bx, ty = by, tz = bz;
        if (effProj === 'flat_2d') {
          tz = 0;
        } else if (effProj === 'iso_25d') {
          tz = isCloud ? Math.max(10, Math.round((bz * 0.45) * 100) / 100) : bz;
        } else {
          if (isCloud) {
            tx = bx; ty = by; tz = bz;
          } else {
            const ang = i * goldenAngle;
            const ringScale = 0.88;
            const spiralZ = Math.sin(ang) * 96 + ((i % 7) - 3) * 18;
            tx = Math.round(bx * ringScale * 100) / 100;
            ty = Math.round(by * ringScale * 100) / 100;
            tz = Math.round((bz * 2.15 + spiralZ + 90) * 100) / 100;
          }
        }
        state.goalWx[i] = tx;
        state.goalWy[i] = ty;
        state.goalWz[i] = tz;
        sumZ += tz;
        if (snapImmediate) {
          state.wx[i] = tx;
          state.wy[i] = ty;
          state.wz[i] = tz;
        }
      }
      if (effProj === 'orbit_3d') {
        state.camera.goalZ = Math.round((sumZ / Math.max(1, n)) * 0.55);
      } else {
        state.camera.goalZ = 0;
      }
      state.spatialDirty = true;
      state.dirtyRender = true;
    }

    function fitCameraToWorld() {
      if (!state.layout || !state.layout.world_bounds) return;
      const b = state.layout.world_bounds;
      const span = Math.max(400, b.max_x - b.min_x, b.max_y - b.min_y);
      state.camera.goalX = (b.min_x + b.max_x) * 0.5;
      state.camera.goalY = (b.min_y + b.max_y) * 0.5;
      const effProj = normalizeProjectionId(state.projectionMode);
      state.camera.goalZ = (effProj === 'orbit_3d' || state.layoutMode === 'cloud_3d') ? ((b.min_z + b.max_z) * 0.45) : 0;
      state.camera.goalDist = clamp(span * 0.92, 320, 4200);
      state.camera.targetX = state.camera.goalX;
      state.camera.targetY = state.camera.goalY;
      state.camera.targetZ = state.camera.goalZ;
      state.camera.distance = state.camera.goalDist;
      state.dirtyRender = true;
      state.spatialDirty = true;
    }

    function applyLayout(layout) {
      state.layout = layout;
      state.nodes = layout.nodes || [];
      state.edges = layout.edges || [];
      state.territories = layout.territories || [];
      state.idToIndex = new Map();
      const n = state.nodes.length;
      state.baseWx = new Float32Array(n);
      state.baseWy = new Float32Array(n);
      state.baseWz = new Float32Array(n);
      state.goalWx = new Float32Array(n);
      state.goalWy = new Float32Array(n);
      state.goalWz = new Float32Array(n);
      state.wx = new Float32Array(n);
      state.wy = new Float32Array(n);
      state.wz = new Float32Array(n);
      state.sx = new Float32Array(n);
      state.sy = new Float32Array(n);
      state.sScale = new Float32Array(n);
      state.sDepth = new Float32Array(n);
      state.selectedMask = new Uint8Array(n);
      state.groupMask = new Uint16Array(n);
      state.drawOrder = new Array(n);
      for (let i = 0; i < n; i++) {
        const node = state.nodes[i];
        state.idToIndex.set(node.id, i);
        const bx = Number(node.wx || 0), by = Number(node.wy || 0), bz = Number(node.wz || 0);
        state.baseWx[i] = bx; state.baseWy[i] = by; state.baseWz[i] = bz;
        state.drawOrder[i] = i;
      }
      applyProjectionTargets(true);
      state.selectedIds = state.selectedIds.filter(id => state.idToIndex.has(id));
      syncMasksFromSelection();
      rebuildSpriteAtlas();
      fitCameraToWorld();
      renderSelectionHud();
      state.dirtyRender = true;
      state.spatialDirty = true;
    }

    function setCatalog(catalog, keepCamera) {
      const prevCam = keepCamera ? cloneJson(state.camera) : null;
      const layout = buildClientWorldLayout(catalog, state.layoutMode, state.unitTypes, state.nodeOverrides);
      applyLayout(layout);
      if (prevCam) Object.assign(state.camera, prevCam);
      state.dirtyRender = true;
      state.spatialDirty = true;
    }

    function syncMasksFromSelection() {
      state.selectedMask.fill(0);
      for (let i = 0; i < state.selectedIds.length; i++) {
        const idx = state.idToIndex.get(state.selectedIds[i]);
        if (idx !== undefined) state.selectedMask[idx] = 1;
      }
      state.groupMask.fill(0);
      for (let g = 1; g <= 9; g++) {
        const arr = state.controlGroups[g] || [];
        const bit = 1 << (g - 1);
        for (let k = 0; k < arr.length; k++) {
          const idx = state.idToIndex.get(arr[k]);
          if (idx !== undefined) state.groupMask[idx] |= bit;
        }
      }
      const typesPresent = new Set();
      state.selectedIds.forEach(id => {
        const idx = state.idToIndex.get(id);
        if (idx !== undefined) typesPresent.add(state.nodes[idx].unit_type);
      });
      if (!state.activeSubgroupType || !typesPresent.has(state.activeSubgroupType)) {
        state.activeSubgroupType = typesPresent.size ? Array.from(typesPresent)[0] : null;
      }
    }

    function notifySelection() {
      syncMasksFromSelection();
      renderSelectionHud();
      if (typeof cfg.onSelectionChange === 'function') {
        const primaryId = state.selectedIds[0] || (state.nodes[0] && state.nodes[0].id) || null;
        cfg.onSelectionChange(state.selectedIds.slice(), primaryId, state.activeSubgroupType);
      }
      state.dirtyRender = true;
    }

    function sortSelectionByUnitPriority(idSet) {
      return Array.from(idSet).sort((a, b) => {
        const ia = state.idToIndex.get(a), ib = state.idToIndex.get(b);
        const na = state.nodes[ia], nb = state.nodes[ib];
        const pa = (state.unitTypes[na?.unit_type]?.priority) || 50;
        const pb = (state.unitTypes[nb?.unit_type]?.priority) || 50;
        if (pb !== pa) return pb - pa;
        return String(a).localeCompare(String(b));
      });
    }

    function updateSpatialProjection() {
      const b = cameraBasis(state.camera);
      const n = state.nodes.length;
      const cellSize = 48;
      state.spatialHash.clear();
      const visible = [];
      for (let i = 0; i < n; i++) {
        const p = projectPoint(state.wx[i], state.wy[i], state.wz[i], state.camera, state.viewW, state.viewH, b);
        state.sx[i] = p.sx;
        state.sy[i] = p.sy;
        state.sScale[i] = p.scale;
        state.sDepth[i] = p.depth;
        if (!p.behind && p.sx >= -60 && p.sx <= state.viewW + 60 && p.sy >= -60 && p.sy <= state.viewH + 60) {
          visible.push(i);
          const gx = Math.floor(p.sx / cellSize), gy = Math.floor(p.sy / cellSize);
          const gk = gx + ',' + gy;
          if (!state.spatialHash.has(gk)) state.spatialHash.set(gk, []);
          state.spatialHash.get(gk).push(i);
        }
      }
      visible.sort((a, bb) => state.sDepth[bb] - state.sDepth[a]);
      state.drawOrder = visible;
      state.spatialDirty = false;
    }

    function pickUnitAt(px, py) {
      if (state.spatialDirty) updateSpatialProjection();
      const gx = Math.floor(px / 48), gy = Math.floor(py / 48);
      let bestIdx = -1;
      let bestDepth = Infinity;
      for (let ox = -1; ox <= 1; ox++) {
        for (let oy = -1; oy <= 1; oy++) {
          const bucket = state.spatialHash.get((gx + ox) + ',' + (gy + oy));
          if (!bucket) continue;
          for (let k = 0; k < bucket.length; k++) {
            const i = bucket[k];
            const sp = state.unitTypes[state.nodes[i].unit_type] || {};
            const rad = Math.max(10, Math.min(36, 26 * state.sScale[i] * (Number(sp.unit_scale) || 1)));
            const dx = px - state.sx[i], dy = py - state.sy[i];
            if (dx * dx + dy * dy <= rad * rad && state.sDepth[i] < bestDepth) {
              bestDepth = state.sDepth[i];
              bestIdx = i;
            }
          }
        }
      }
      return bestIdx;
    }

    function selectClick(idx, modifiers) {
      const mod = modifiers || {};
      if (idx < 0 || idx >= state.nodes.length) {
        if (!mod.shiftKey && !mod.ctrlKey) {
          state.selectedIds = [];
          notifySelection();
        }
        return state.selectedIds;
      }
      const clicked = state.nodes[idx];
      const clickedId = clicked.id;
      const targetType = clicked.unit_type;
      const next = new Set(mod.shiftKey ? state.selectedIds : []);

      if (mod.altKey) {
        for (let i = 0; i < state.nodes.length; i++) {
          if (state.nodes[i].unit_type === targetType) next.add(state.nodes[i].id);
        }
      } else if (mod.ctrlKey || mod.metaKey) {
        if (state.spatialDirty) updateSpatialProjection();
        const visibleSameType = [];
        for (let i = 0; i < state.drawOrder.length; i++) {
          const ni = state.drawOrder[i];
          if (state.nodes[ni].unit_type === targetType) visibleSameType.push(state.nodes[ni].id);
        }
        const allPresent = mod.shiftKey && visibleSameType.length > 0 && visibleSameType.every(id => next.has(id));
        visibleSameType.forEach(id => { if (allPresent) next.delete(id); else next.add(id); });
      } else if (mod.shiftKey) {
        if (next.has(clickedId)) next.delete(clickedId); else next.add(clickedId);
      } else {
        next.add(clickedId);
      }
      state.selectedIds = sortSelectionByUnitPriority(next);
      notifySelection();
      return state.selectedIds;
    }

    function selectMarquee(x0, y0, x1, y1, modifiers) {
      if (state.spatialDirty) updateSpatialProjection();
      const mod = modifiers || {};
      const minX = Math.min(x0, x1), maxX = Math.max(x0, x1);
      const minY = Math.min(y0, y1), maxY = Math.max(y0, y1);
      const next = new Set(mod.shiftKey ? state.selectedIds : []);
      for (let i = 0; i < state.drawOrder.length; i++) {
        const ni = state.drawOrder[i];
        const sx = state.sx[ni], sy = state.sy[ni];
        if (sx >= minX && sx <= maxX && sy >= minY && sy <= maxY) {
          const id = state.nodes[ni].id;
          if (mod.ctrlKey) next.delete(id); else next.add(id);
        }
      }
      state.selectedIds = sortSelectionByUnitPriority(next);
      notifySelection();
      return state.selectedIds;
    }

    function cycleSubgroup(reverse) {
      const types = [];
      state.selectedIds.forEach(id => {
        const idx = state.idToIndex.get(id);
        if (idx !== undefined) {
          const ut = state.nodes[idx].unit_type;
          if (types.indexOf(ut) === -1) types.push(ut);
        }
      });
      if (!types.length) return null;
      const cur = types.indexOf(state.activeSubgroupType);
      const nxt = reverse ? ((cur - 1 + types.length) % types.length) : ((cur + 1) % types.length);
      state.activeSubgroupType = types[nxt];
      renderSelectionHud();
      state.dirtyRender = true;
      return state.activeSubgroupType;
    }

    function centerOnIds(idsList) {
      if (!idsList || !idsList.length) { fitCameraToWorld(); return; }
      let sx = 0, sy = 0, sz = 0, cnt = 0;
      idsList.forEach(id => {
        const idx = state.idToIndex.get(id);
        if (idx !== undefined) { sx += state.wx[idx]; sy += state.wy[idx]; sz += state.wz[idx]; cnt++; }
      });
      if (!cnt) return;
      state.camera.goalX = sx / cnt;
      state.camera.goalY = sy / cnt;
      state.camera.goalZ = state.layoutMode === 'cloud_3d' ? (sz / cnt) : 0;
      state.dirtyRender = true;
    }

    function handleControlGroupKey(num, modifiers) {
      const n = Number(num);
      if (!(n >= 1 && n <= 9)) return;
      const mod = modifiers || {};
      if (mod.ctrlKey || mod.metaKey) {
        state.controlGroups[n] = state.selectedIds.slice();
      } else if (mod.altKey) {
        const selSet = new Set(state.selectedIds);
        for (let g = 1; g <= 9; g++) {
          if (g !== n) state.controlGroups[g] = (state.controlGroups[g] || []).filter(id => !selSet.has(id));
        }
        state.controlGroups[n] = state.selectedIds.slice();
      } else if (mod.shiftKey) {
        const merged = new Set([...(state.controlGroups[n] || []), ...state.selectedIds]);
        state.controlGroups[n] = sortSelectionByUnitPriority(merged);
      } else {
        const grp = (state.controlGroups[n] || []).filter(id => state.idToIndex.has(id));
        if (grp.length) {
          state.selectedIds = grp.slice();
          notifySelection();
          const t = Date.now();
          if (state.lastGroupTap.num === n && (t - state.lastGroupTap.ts) < 380) {
            centerOnIds(grp);
          }
          state.lastGroupTap = {num: n, ts: t};
        }
        return;
      }
      syncMasksFromSelection();
      renderSelectionHud();
      state.dirtyRender = true;
    }

    function renderSelectionHud() {
      const portraitEl = getEl('groupGrid');
      const groupTabsEl = getEl('groupTabs');
      const statusEl = getEl('statusLine');
      if (statusEl) {
        const activeSp = state.activeSubgroupType ? (state.unitTypes[state.activeSubgroupType]?.display_name || state.activeSubgroupType) : 'None';
        const pInfo = PROJECTION_GUIDE[normalizeProjectionId(state.projectionMode)] || PROJECTION_GUIDE.iso_25d;
        statusEl.textContent = state.selectedIds.length
          ? (pInfo.short + ' • Selected ' + state.selectedIds.length + ' node(s) • Active Type [Tab]: ' + activeSp)
          : (pInfo.short + ' • ' + state.nodes.length + ' nodes • Drag=Box Select • Ctrl+Click=Visible Type • Alt+Click=All Type • Ctrl+1..9=Group');
      }
      if (groupTabsEl && typeof groupTabsEl.replaceChildren === 'function') {
        const btns = [];
        for (let g = 1; g <= 9; g++) {
          const cnt = (state.controlGroups[g] || []).length;
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'wm-group-tab' + (cnt ? ' populated' : '');
          b.textContent = '[' + g + ']' + (cnt ? (' ' + cnt) : '');
          b.onclick = () => handleControlGroupKey(g, {});
          btns.push(b);
        }
        groupTabsEl.replaceChildren(...btns);
      }
      const levelStatsEl = getEl('levelStats');
      if (levelStatsEl && globalScope.OpsCryerGraphLayers) {
        const srcCatalog = (typeof cfg.getCurrentCatalog === 'function' && cfg.getCurrentCatalog()) || {nodes: state.nodes, edges: state.edges};
        const analysis = globalScope.OpsCryerGraphLayers.analyzeSelectionLevels(srcCatalog, state.selectedIds);
        const targetMap = state.selectedIds.length ? analysis.selection_breakdown : analysis.global_breakdown;
        globalScope.OpsCryerGraphLayers.renderLevelStatChips(levelStatsEl, targetMap, state.levelFilter, (lvlId, nodeIds) => {
          const valid = (nodeIds || []).filter(id => state.idToIndex.has(id));
          if (valid.length) {
            state.selectedIds = sortSelectionByUnitPriority(new Set(valid));
            notifySelection();
            centerOnIds(valid);
          } else {
            setLevelFilter(state.levelFilter === lvlId ? null : lvlId);
          }
        });
      }
      if (portraitEl && typeof portraitEl.replaceChildren === 'function') {
        const chips = [];
        const showIds = state.selectedIds.slice(0, 24);
        showIds.forEach(id => {
          const idx = state.idToIndex.get(id);
          if (idx === undefined) return;
          const n = state.nodes[idx];
          const sp = state.unitTypes[n.unit_type] || {};
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'wm-unit-chip' + (n.unit_type === state.activeSubgroupType ? ' active-subgroup' : '');
          btn.style.borderColor = sp.color_primary || '#38BDF8';
          btn.textContent = n.label.slice(0, 22);
          btn.onclick = ev => {
            if (ev && ev.shiftKey) {
              state.selectedIds = state.selectedIds.filter(x => x !== id);
              notifySelection();
            } else if (ev && (ev.ctrlKey || ev.metaKey)) {
              state.selectedIds = state.selectedIds.filter(x => {
                const xi = state.idToIndex.get(x);
                return xi !== undefined && state.nodes[xi].unit_type === n.unit_type;
              });
              notifySelection();
            } else {
              state.selectedIds = [id];
              notifySelection();
              centerOnIds([id]);
            }
          };
          chips.push(btn);
        });
        portraitEl.replaceChildren(...chips);
      }
    }

    function drawMainCanvas() {
      const canvas = getEl('canvas');
      if (!canvas || typeof canvas.getContext !== 'function') return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      const rect = (typeof canvas.getBoundingClientRect === 'function') ? canvas.getBoundingClientRect() : null;
      const cssW = Math.max(300, Math.round((rect && rect.width) || state.viewW || 1000));
      const cssH = Math.max(240, Math.round((rect && rect.height) || state.viewH || 540));
      const dpr = (typeof window !== 'undefined' && Number(window.devicePixelRatio)) ? Math.min(2, window.devicePixelRatio) : 1;
      if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
        canvas.width = Math.round(cssW * dpr);
        canvas.height = Math.round(cssH * dpr);
        state.spatialDirty = true;
      }
      state.viewW = cssW;
      state.viewH = cssH;

      const reducedMotion = (typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
      const effProj = normalizeProjectionId(state.projectionMode);
      const camLerp = reducedMotion ? 1.0 : 0.24;

      const camDiff = Math.abs(state.camera.goalX - state.camera.targetX)
        + Math.abs(state.camera.goalY - state.camera.targetY)
        + Math.abs(state.camera.goalZ - state.camera.targetZ)
        + Math.abs(state.camera.goalDist - state.camera.distance)
        + Math.abs(state.camera.goalPitch - state.camera.pitchDeg)
        + Math.abs(state.camera.goalYaw - state.camera.yawRad);
      if (camDiff > 0.05) {
        state.camera.targetX += (state.camera.goalX - state.camera.targetX) * camLerp;
        state.camera.targetY += (state.camera.goalY - state.camera.targetY) * camLerp;
        state.camera.targetZ += (state.camera.goalZ - state.camera.targetZ) * camLerp;
        state.camera.distance += (state.camera.goalDist - state.camera.distance) * camLerp;
        state.camera.pitchDeg += (state.camera.goalPitch - state.camera.pitchDeg) * camLerp;
        state.camera.yawRad += (state.camera.goalYaw - state.camera.yawRad) * camLerp;
        state.spatialDirty = true;
      }

      /* Smoothly animate world coordinates across 2D <-> 2.5D <-> 3D transitions */
      let nodeMoved = false;
      const nCount = state.nodes.length;
      for (let i = 0; i < nCount; i++) {
        const dx = state.goalWx[i] - state.wx[i];
        const dy = state.goalWy[i] - state.wy[i];
        const dz = state.goalWz[i] - state.wz[i];
        if (Math.abs(dx) > 0.2 || Math.abs(dy) > 0.2 || Math.abs(dz) > 0.2) {
          state.wx[i] += dx * camLerp;
          state.wy[i] += dy * camLerp;
          state.wz[i] += dz * camLerp;
          nodeMoved = true;
        }
      }
      if (nodeMoved) state.spatialDirty = true;

      if (state.keysDown.size) {
        const panStep = Math.max(8, state.camera.distance * 0.022);
        const cy = Math.cos(state.camera.yawRad), sy = Math.sin(state.camera.yawRad);
        if (state.keysDown.has('w') || state.keysDown.has('arrowup')) { state.camera.goalX += sy * panStep; state.camera.goalY += cy * panStep; }
        if (state.keysDown.has('s') || state.keysDown.has('arrowdown')) { state.camera.goalX -= sy * panStep; state.camera.goalY -= cy * panStep; }
        if (state.keysDown.has('a') || state.keysDown.has('arrowleft')) { state.camera.goalX -= cy * panStep; state.camera.goalY += sy * panStep; }
        if (state.keysDown.has('d') || state.keysDown.has('arrowright')) { state.camera.goalX += cy * panStep; state.camera.goalY -= sy * panStep; }
        if (state.keysDown.has('q')) state.camera.goalYaw -= 0.035;
        if (state.keysDown.has('e')) state.camera.goalYaw += 0.035;
        state.dirtyRender = true;
      }

      if (state.spatialDirty) updateSpatialProjection();

      ctx.save();
      ctx.scale(dpr, dpr);
      if (typeof ctx.createRadialGradient === 'function') {
        const bgGrad = ctx.createRadialGradient(cssW * 0.5, cssH * 0.44, 24, cssW * 0.5, cssH * 0.5, Math.max(cssW, cssH) * 0.72);
        bgGrad.addColorStop(0, '#0B1730');
        bgGrad.addColorStop(0.58, '#050C1B');
        bgGrad.addColorStop(1, '#02050D');
        ctx.fillStyle = bgGrad;
      } else {
        ctx.fillStyle = '#040813';
      }
      ctx.fillRect(0, 0, cssW, cssH);

      const basis = cameraBasis(state.camera);
      const trap = computeCameraTrapezoid(state.camera, cssW, cssH, 0);

      /* Coordinate space backdrop: dual-scale schematic grid (2D/2.5D) or volumetric rings (3D) */
      if (effProj === 'orbit_3d') {
        const midZ = state.camera.targetZ || 90;
        const radii = [240, 480, 740];
        ctx.save();
        radii.forEach((rad, rIdx) => {
          ctx.beginPath();
          for (let s = 0; s <= 40; s++) {
            const ang = (s / 40) * Math.PI * 2;
            const rp = projectPoint(Math.cos(ang) * rad, Math.sin(ang) * rad, midZ + (rIdx - 1) * 45, state.camera, cssW, cssH, basis);
            if (rp.behind) continue;
            if (s === 0) ctx.moveTo(rp.sx, rp.sy); else ctx.lineTo(rp.sx, rp.sy);
          }
          ctx.strokeStyle = rIdx === 1 ? 'rgba(56, 189, 248, 0.14)' : 'rgba(148, 163, 184, 0.08)';
          ctx.lineWidth = 1;
          ctx.stroke();
        });
        const zTop = projectPoint(0, 0, midZ + 220, state.camera, cssW, cssH, basis);
        const zBot = projectPoint(0, 0, midZ - 140, state.camera, cssW, cssH, basis);
        if (!zTop.behind && !zBot.behind) {
          ctx.beginPath();
          ctx.moveTo(zBot.sx, zBot.sy); ctx.lineTo(zTop.sx, zTop.sy);
          ctx.strokeStyle = 'rgba(245, 158, 11, 0.18)';
          ctx.lineWidth = 1;
          ctx.stroke();
        }
        ctx.restore();
      } else {
        const xs = trap.map(p => p.wx), ys = trap.map(p => p.wy);
        const gx0 = Math.floor(clamp(Math.min(...xs), -4000, 4000) / 160) * 160;
        const gx1 = Math.ceil(clamp(Math.max(...xs), -4000, 4000) / 160) * 160;
        const gy0 = Math.floor(clamp(Math.min(...ys), -4000, 4000) / 160) * 160;
        const gy1 = Math.ceil(clamp(Math.max(...ys), -4000, 4000) / 160) * 160;
        ctx.strokeStyle = effProj === 'flat_2d' ? 'rgba(56, 189, 248, 0.09)' : 'rgba(56, 189, 248, 0.06)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let gx = gx0; gx <= gx1 && (gx - gx0) <= 6400; gx += 160) {
          const p0 = projectPoint(gx, gy0, 0, state.camera, cssW, cssH, basis);
          const p1 = projectPoint(gx, gy1, 0, state.camera, cssW, cssH, basis);
          if (!p0.behind && !p1.behind) { ctx.moveTo(p0.sx, p0.sy); ctx.lineTo(p1.sx, p1.sy); }
        }
        for (let gy = gy0; gy <= gy1 && (gy - gy0) <= 6400; gy += 160) {
          const p0 = projectPoint(gx0, gy, 0, state.camera, cssW, cssH, basis);
          const p1 = projectPoint(gx1, gy, 0, state.camera, cssW, cssH, basis);
          if (!p0.behind && !p1.behind) { ctx.moveTo(p0.sx, p0.sy); ctx.lineTo(p1.sx, p1.sy); }
        }
        ctx.stroke();
      }

      /* Draw architectural sector rings and floating glass pills */
      const sectorZ = effProj === 'orbit_3d' ? (state.camera.targetZ * 0.45) : 0;
      for (let t = 0; t < state.territories.length; t++) {
        const terr = state.territories[t];
        const centerP = projectPoint(terr.cx, terr.cy, sectorZ, state.camera, cssW, cssH, basis);
        if (centerP.behind || centerP.sx < -240 || centerP.sx > cssW + 240 || centerP.sy < -240 || centerP.sy > cssH + 240) continue;
        ctx.save();
        ctx.beginPath();
        for (let s = 0; s <= 28; s++) {
          const ang = (s / 28) * Math.PI * 2;
          const rp = projectPoint(terr.cx + Math.cos(ang) * terr.radius, terr.cy + Math.sin(ang) * terr.radius, sectorZ, state.camera, cssW, cssH, basis);
          if (s === 0) ctx.moveTo(rp.sx, rp.sy); else ctx.lineTo(rp.sx, rp.sy);
        }
        if (typeof ctx.setLineDash === 'function') ctx.setLineDash(effProj === 'flat_2d' ? [8, 5] : [6, 4]);
        ctx.strokeStyle = terr.color || '#38BDF8';
        ctx.globalAlpha = effProj === 'orbit_3d' ? 0.16 : 0.34;
        ctx.lineWidth = 1.4;
        ctx.stroke();
        if (typeof ctx.setLineDash === 'function') ctx.setLineDash([]);
        ctx.fillStyle = terr.color || '#38BDF8';
        ctx.globalAlpha = effProj === 'orbit_3d' ? 0.025 : 0.045;
        ctx.fill();
        ctx.restore();

        const lblP = projectPoint(terr.cx, terr.cy - terr.radius * 0.82, sectorZ + 6, state.camera, cssW, cssH, basis);
        if (!lblP.behind) {
          const secTxt = String(terr.label || '') + ' (' + String(terr.count || 0) + ')';
          ctx.save();
          ctx.font = '700 10.5px Inter, system-ui, sans-serif';
          const tw = (typeof ctx.measureText === 'function' ? ctx.measureText(secTxt).width : secTxt.length * 6.2) + 18;
          const px0 = lblP.sx - tw * 0.5, py0 = lblP.sy - 10;
          ctx.fillStyle = 'rgba(7, 13, 27, 0.86)';
          ctx.strokeStyle = (terr.color || '#38BDF8') + '66';
          ctx.lineWidth = 1;
          ctx.beginPath();
          if (typeof ctx.roundRect === 'function') ctx.roundRect(px0, py0, tw, 17, 6); else ctx.rect(px0, py0, tw, 17);
          ctx.fill();
          ctx.stroke();
          ctx.fillStyle = terr.color || '#38BDF8';
          ctx.fillRect(px0 + 4, py0 + 3, 2.5, 11);
          ctx.fillStyle = '#E2E8F0';
          ctx.textAlign = 'center';
          ctx.fillText(secTxt, lblP.sx + 2, py0 + 12);
          ctx.restore();
        }
      }

      /* Draw curved Bezier dependency splines with directional cues and animated tracers */
      const nowMs = (typeof performance !== 'undefined' ? performance.now() : Date.now());
      const pulsePhase = 0.5 + 0.5 * Math.sin(nowMs * 0.006);
      const flowT = reducedMotion ? 0.5 : ((nowMs * 0.00055) % 1);
      if (state.overlays.dependency_beam && state.edges.length) {
        const hasSel = state.selectedIds.length > 0;
        const maxDrawEdges = 1400;
        const denseFastMode = state.edges.length > 750;
        ctx.save();
        for (let e = 0; e < state.edges.length && e < maxDrawEdges; e++) {
          const edge = state.edges[e];
          const u = edge[0], v = edge[1];
          const selRel = state.selectedMask[u] || state.selectedMask[v] || u === state.hoveredIdx || v === state.hoveredIdx;
          if (state.isolateSelected && hasSel && !selRel) continue;
          const ux = state.sx[u], uy = state.sy[u], vx = state.sx[v], vy = state.sy[v];
          if ((ux < -40 && vx < -40) || (ux > cssW + 40 && vx > cssW + 40) || (uy < -40 && vy < -40) || (uy > cssH + 40 && vy > cssH + 40)) continue;
          const dx = vx - ux, dy = vy - uy;
          const chord = Math.hypot(dx, dy);
          ctx.beginPath();
          ctx.moveTo(ux, uy);
          if (denseFastMode || chord < 14) {
            ctx.lineTo(vx, vy);
          } else {
            const bow = Math.min(38, chord * 0.14) * (e % 2 === 0 ? 1 : -1);
            const nx = -dy / chord, ny = dx / chord;
            const cxp = (ux + vx) * 0.5 + nx * bow;
            const cyp = (uy + vy) * 0.5 + ny * bow - (effProj !== 'flat_2d' ? Math.min(18, chord * 0.06) : 0);
            ctx.quadraticCurveTo(cxp, cyp, vx, vy);
            if (selRel) {
              ctx.strokeStyle = 'rgba(245, 158, 11, 0.84)';
              ctx.lineWidth = 1.9;
              ctx.stroke();
              /* Animated telemetry tracer dot along highlighted Bezier arc */
              const omt = 1 - flowT;
              const pxDot = omt * omt * ux + 2 * omt * flowT * cxp + flowT * flowT * vx;
              const pyDot = omt * omt * uy + 2 * omt * flowT * cyp + flowT * flowT * vy;
              ctx.beginPath();
              ctx.arc(pxDot, pyDot, 2.7, 0, Math.PI * 2);
              ctx.fillStyle = '#FEF08A';
              ctx.fill();
              continue;
            }
          }
          if (selRel) {
            ctx.strokeStyle = 'rgba(245, 158, 11, 0.84)';
            ctx.lineWidth = 1.8;
          } else {
            ctx.strokeStyle = (hasSel && state.isolateSelected) ? 'rgba(148, 163, 184, 0.05)' : 'rgba(56, 189, 248, 0.20)';
            ctx.lineWidth = 0.95;
          }
          ctx.stroke();
        }
        ctx.restore();
      }

      /* Draw visible nodes back-to-front using pre-baked glassmorphic vector plates */
      const hasSelAny = state.selectedIds.length > 0;
      for (let d = 0; d < state.drawOrder.length; d++) {
        const i = state.drawOrder[d];
        const node = state.nodes[i];
        const spec = state.unitTypes[node.unit_type] || {};
        const primCol = spec.color_primary || '#38BDF8';
        const px = state.sx[i], py = state.sy[i];
        const sc = state.sScale[i];
        const isSel = Boolean(state.selectedMask[i]);
        const isHov = (i === state.hoveredIdx);
        const unitPx = clamp(44 * sc * (Number(spec.unit_scale) || 1), 8, 72);
        const filterDimmed = Boolean((state.levelFilter && node.graph_level !== state.levelFilter) || (state.statusFilter && node.tactical_status !== state.statusFilter));
        const dimmed = (state.isolateSelected && hasSelAny && !isSel && !isHov) || filterDimmed;

        ctx.save();
        if (dimmed) ctx.globalAlpha = 0.22;

        /* Ground anchor pedestal ring + dashed elevation tether in 2.5D mode */
        if (effProj === 'iso_25d' && state.wz[i] > 4 && unitPx >= 11) {
          const gp = projectPoint(state.wx[i], state.wy[i], 0, state.camera, cssW, cssH, basis);
          if (!gp.behind) {
            ctx.save();
            if (typeof ctx.setLineDash === 'function') ctx.setLineDash([3, 3]);
            ctx.beginPath();
            ctx.moveTo(gp.sx, gp.sy);
            ctx.lineTo(px, py);
            ctx.strokeStyle = primCol + '55';
            ctx.lineWidth = 1.1;
            ctx.stroke();
            if (typeof ctx.setLineDash === 'function') ctx.setLineDash([]);
            ctx.beginPath();
            ctx.ellipse(gp.sx, gp.sy, unitPx * 0.34, unitPx * 0.16, 0, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(2, 6, 23, 0.45)';
            ctx.fill();
            ctx.strokeStyle = primCol + '4D';
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.restore();
          }
        }

        /* Precision tactical reticle selection halo */
        if (isSel || isHov) {
          const selCol = isSel ? (node.unit_type === state.activeSubgroupType ? '#22C55E' : '#38BDF8') : '#F59E0B';
          ctx.beginPath();
          ctx.arc(px, py, unitPx * 0.62, 0, Math.PI * 2);
          ctx.strokeStyle = selCol;
          ctx.lineWidth = isSel ? 2.2 : 1.5;
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(px, py, unitPx * 0.72, -0.4, 0.4);
          ctx.strokeStyle = selCol;
          ctx.lineWidth = 1.8;
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(px, py, unitPx * 0.72, Math.PI - 0.4, Math.PI + 0.4);
          ctx.stroke();
        }

        if (state.overlays.alert_pulse && node.status === 'alert') {
          ctx.beginPath();
          ctx.arc(px, py, unitPx * (0.64 + 0.14 * pulsePhase), 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(239, 68, 68, 0.88)';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        const sprite = unitPx >= 18 ? state.spritesHi.get(node.unit_type) : state.spritesLo.get(node.unit_type);
        if (sprite) {
          ctx.drawImage(sprite, px - unitPx * 0.5, py - unitPx * 0.5, unitPx, unitPx);
        } else {
          ctx.beginPath();
          ctx.arc(px, py, unitPx * 0.36, 0, Math.PI * 2);
          ctx.fillStyle = primCol;
          ctx.fill();
        }

        /* Crisp pill telemetry micro-overlays */
        const showMinor = isSel || isHov || state.altPeekHeld || unitPx >= 24;
        if (showMinor && state.overlays.health_bar) {
          const bw = Math.max(24, unitPx * 0.86);
          const bx = px - bw * 0.5, by = py - unitPx * 0.60 - 6;
          ctx.beginPath();
          if (typeof ctx.roundRect === 'function') ctx.roundRect(bx, by, bw, 4.5, 2.2); else ctx.rect(bx, by, bw, 4.5);
          ctx.fillStyle = 'rgba(2, 6, 23, 0.90)';
          ctx.fill();
          ctx.strokeStyle = 'rgba(148, 163, 184, 0.35)';
          ctx.lineWidth = 0.75;
          ctx.stroke();
          const fillW = Math.max(3, bw * clamp(node.vital_pct / 100, 0.05, 1));
          ctx.beginPath();
          if (typeof ctx.roundRect === 'function') ctx.roundRect(bx, by, fillW, 4.5, 2.2); else ctx.rect(bx, by, fillW, 4.5);
          ctx.fillStyle = node.vital_pct >= 75 ? '#22C55E' : (node.vital_pct >= 50 ? '#F59E0B' : '#EF4444');
          ctx.fill();
        }
        if (showMinor && state.overlays.child_count && node.child_count > 0 && unitPx >= 16) {
          const pillW = node.child_count >= 10 ? 22 : 18;
          const cx0 = px + unitPx * 0.24, cy0 = py + unitPx * 0.16;
          ctx.beginPath();
          if (typeof ctx.roundRect === 'function') ctx.roundRect(cx0, cy0, pillW, 13, 6); else ctx.rect(cx0, cy0, pillW, 13);
          ctx.fillStyle = 'rgba(7, 15, 32, 0.95)';
          ctx.fill();
          ctx.strokeStyle = '#38BDF8';
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.font = '700 8.5px Inter, system-ui, sans-serif';
          ctx.fillStyle = '#BAE6FD';
          ctx.textAlign = 'center';
          ctx.fillText('+' + node.child_count, cx0 + pillW * 0.5, cy0 + 9.5);
        }
        if (showMinor && state.overlays.mls_badge && node.mls_locked && unitPx >= 18) {
          ctx.font = '700 9px Inter, system-ui, sans-serif';
          ctx.fillStyle = '#C084FC';
          ctx.textAlign = 'center';
          ctx.fillText('LOCK', px - unitPx * 0.42, py - unitPx * 0.36);
        }
        if (state.groupMask[i]) {
          for (let g = 1; g <= 9; g++) {
            if (state.groupMask[i] & (1 << (g - 1))) {
              ctx.fillStyle = '#F59E0B';
              ctx.font = '800 9px Inter, system-ui, sans-serif';
              ctx.textAlign = 'center';
              ctx.fillText('[' + g + ']', px - unitPx * 0.42, py + unitPx * 0.48);
              break;
            }
          }
        }
        if (state.overlays.labels && (isSel || isHov || unitPx >= 32)) {
          const lblTxt = node.label.slice(0, 26);
          ctx.font = '600 10px Inter, system-ui, sans-serif';
          const lw = (typeof ctx.measureText === 'function' ? ctx.measureText(lblTxt).width : lblTxt.length * 5.8) + 12;
          const ly = py + unitPx * 0.54 + 2;
          ctx.beginPath();
          if (typeof ctx.roundRect === 'function') ctx.roundRect(px - lw * 0.5, ly, lw, 15, 5); else ctx.rect(px - lw * 0.5, ly, lw, 15);
          ctx.fillStyle = isSel ? 'rgba(15, 23, 42, 0.94)' : 'rgba(2, 6, 23, 0.84)';
          ctx.fill();
          ctx.strokeStyle = isSel ? 'rgba(56, 189, 248, 0.65)' : 'rgba(148, 163, 184, 0.25)';
          ctx.lineWidth = 0.85;
          ctx.stroke();
          ctx.textAlign = 'center';
          ctx.fillStyle = '#F8FAFC';
          ctx.fillText(lblTxt, px, ly + 10.8);
        }
        ctx.restore();
      }

      /* Marquee RTS selection rectangle */
      if (state.marquee.active) {
        const mx = Math.min(state.marquee.x0, state.marquee.x1);
        const my = Math.min(state.marquee.y0, state.marquee.y1);
        const mw = Math.abs(state.marquee.x1 - state.marquee.x0);
        const mh = Math.abs(state.marquee.y1 - state.marquee.y0);
        ctx.fillStyle = 'rgba(34, 197, 94, 0.14)';
        ctx.fillRect(mx, my, mw, mh);
        ctx.strokeStyle = '#22C55E';
        ctx.lineWidth = 1.6;
        ctx.strokeRect(mx, my, mw, mh);
      }
      ctx.restore();

      drawMinimapCanvas(trap);
    }

    function drawMinimapCanvas(trap) {
      const mini = getEl('minimap');
      if (!mini || typeof mini.getContext !== 'function' || !state.layout) return;
      const ctx = mini.getContext('2d');
      if (!ctx) return;
      const mw = mini.width || 220, mh = mini.height || 105;
      ctx.clearRect(0, 0, mw, mh);
      ctx.fillStyle = '#020617';
      ctx.fillRect(0, 0, mw, mh);

      const b = state.layout.world_bounds;
      const spanX = Math.max(100, b.max_x - b.min_x);
      const spanY = Math.max(100, b.max_y - b.min_y);
      const toMini = (wx, wy) => [
        ((wx - b.min_x) / spanX) * (mw - 12) + 6,
        (1 - (wy - b.min_y) / spanY) * (mh - 12) + 6
      ];

      for (let t = 0; t < state.territories.length; t++) {
        const terr = state.territories[t];
        const [tx, ty] = toMini(terr.cx, terr.cy);
        const tr = clamp((terr.radius / spanX) * (mw - 12), 4, 24);
        ctx.beginPath();
        ctx.arc(tx, ty, tr, 0, Math.PI * 2);
        ctx.strokeStyle = terr.color || '#38BDF8';
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      for (let i = 0; i < state.nodes.length; i++) {
        const [bx, by] = toMini(state.wx[i], state.wy[i]);
        const isSel = Boolean(state.selectedMask[i]);
        ctx.fillStyle = isSel ? '#22C55E' : ((state.unitTypes[state.nodes[i].unit_type]?.color_primary) || '#38BDF8');
        const sz = isSel ? 3 : 2;
        ctx.fillRect(bx - sz * 0.5, by - sz * 0.5, sz, sz);
      }

      if (Array.isArray(trap) && trap.length === 4) {
        ctx.beginPath();
        trap.forEach((pt, idx) => {
          const [fx, fy] = toMini(pt.wx, pt.wy);
          if (idx === 0) ctx.moveTo(fx, fy); else ctx.lineTo(fx, fy);
        });
        ctx.closePath();
        ctx.fillStyle = 'rgba(255, 255, 255, 0.08)';
        ctx.fill();
        ctx.strokeStyle = '#FACC15';
        ctx.lineWidth = 1.6;
        ctx.stroke();
      }
    }

    function panCameraToMinimapPoint(clientX, clientY) {
      const mini = getEl('minimap');
      if (!mini || !state.layout || typeof mini.getBoundingClientRect !== 'function') return;
      const r = mini.getBoundingClientRect();
      const nx = clamp((clientX - r.left - 6) / Math.max(1, r.width - 12), 0, 1);
      const ny = clamp((clientY - r.top - 6) / Math.max(1, r.height - 12), 0, 1);
      const b = state.layout.world_bounds;
      state.camera.goalX = b.min_x + nx * (b.max_x - b.min_x);
      state.camera.goalY = b.min_y + (1 - ny) * (b.max_y - b.min_y);
      state.dirtyRender = true;
    }

    function updateFpsMeter(nowTs) {
      if (state.lastFrameTs > 0) {
        const dt = nowTs - state.lastFrameTs;
        if (dt > 0 && dt < 500) {
          state.frameTimes.push(dt);
          if (state.frameTimes.length > 45) state.frameTimes.shift();
          const avgDt = state.frameTimes.reduce((a, b) => a + b, 0) / state.frameTimes.length;
          state.measuredFps = Math.min(120, Math.max(1, Math.round(1000 / Math.max(1, avgDt))));
          const fpsEl = getEl('fpsPill');
          if (fpsEl) fpsEl.textContent = '⚡ ' + state.measuredFps + ' FPS • ' + (Math.round(avgDt * 10) / 10) + 'ms frame • ' + state.nodes.length + ' units';
        }
      }
      state.lastFrameTs = nowTs;
    }

    function frameLoop(nowTs) {
      if (state.paused) { state.rafId = 0; return; }
      updateFpsMeter(nowTs);
      drawMainCanvas();
      if (typeof requestAnimationFrame === 'function') {
        state.rafId = requestAnimationFrame(frameLoop);
      }
    }

    function startLoop() {
      if (!state.paused && state.rafId) return;
      state.paused = false;
      state.lastFrameTs = 0;
      if (typeof requestAnimationFrame === 'function') {
        state.rafId = requestAnimationFrame(frameLoop);
      }
    }

    function stopLoop() {
      state.paused = true;
      if (state.rafId && typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(state.rafId);
        state.rafId = 0;
      }
    }

    function syncProjectionUi() {
      const effProj = normalizeProjectionId(state.projectionMode);
      const pInfo = PROJECTION_GUIDE[effProj] || PROJECTION_GUIDE.iso_25d;
      const selEl = getEl('projectionSelect');
      if (selEl && selEl.value !== effProj) selEl.value = effProj;
      const relEl = getEl('relevanceBanner');
      if (relEl) relEl.textContent = pInfo.title + ' — ' + pInfo.relevance;
      const tbEl = getEl('projectionToolbar');
      if (tbEl && typeof tbEl.querySelectorAll === 'function') {
        tbEl.querySelectorAll('button[data-proj]').forEach(btn => {
          const active = btn.getAttribute('data-proj') === effProj;
          btn.setAttribute('aria-pressed', active ? 'true' : 'false');
          btn.tabIndex = active ? 0 : -1;
        });
      }
    }

    function setMode(mode) {
      state.layoutMode = (mode === 'domain_squads' || mode === 'graph_layers' || mode === 'cloud_3d') ? mode : 'unit_type';
      if (state.layoutMode === 'cloud_3d' && state.projectionMode !== 'orbit_3d') {
        state.projectionMode = 'orbit_3d';
        state.camera.goalPitch = 34;
      }
      if (typeof cfg.getCurrentCatalog === 'function') {
        const cat = cfg.getCurrentCatalog();
        if (cat) setCatalog(cat, false);
      } else {
        applyProjectionTargets(typeof requestAnimationFrame !== 'function');
      }
      syncProjectionUi();
    }

    function setLevelFilter(lvl) {
      state.levelFilter = lvl ? String(lvl) : null;
      renderSelectionHud();
      state.dirtyRender = true;
    }

    function setStatusFilter(st) {
      state.statusFilter = st ? String(st) : null;
      state.dirtyRender = true;
    }

    function setProjection(proj) {
      const norm = normalizeProjectionId(proj);
      state.projectionMode = norm;
      if (norm === 'flat_2d') {
        state.camera.goalPitch = 89.2;
        state.camera.goalYaw = 0;
      } else if (norm === 'orbit_3d') {
        state.camera.goalPitch = 34;
      } else {
        state.camera.goalPitch = 54;
        state.camera.goalYaw = 0;
      }
      const snap = (typeof requestAnimationFrame !== 'function');
      applyProjectionTargets(snap);
      syncProjectionUi();
      renderSelectionHud();
      if (typeof cfg.onProjectionChange === 'function') cfg.onProjectionChange(norm, PROJECTION_GUIDE[norm]);
      state.dirtyRender = true;
      return norm;
    }

    function setOverlay(name, enabled) {
      if (name in state.overlays) {
        state.overlays[name] = Boolean(enabled);
        state.dirtyRender = true;
      }
    }

    function upsertUnitType(spec, assignSelected) {
      if (!spec || !spec.type_id) throw new Error('Invalid unit type specification');
      const cleaned = cloneJson(spec);
      if (cleaned.custom_svg && !cleaned.svg_spec) {
        cleaned.svg_spec = sanitizeClientSvg(cleaned.custom_svg);
      }
      state.unitTypes[cleaned.type_id] = cleaned;
      state.customTypes[cleaned.type_id] = cleaned;
      writeStorageJson(CUSTOM_TYPES_STORAGE_KEY, state.customTypes);
      if (assignSelected && state.selectedIds.length) {
        state.selectedIds.forEach(id => { state.nodeOverrides[id] = cleaned.type_id; });
        writeStorageJson(OVERRIDES_STORAGE_KEY, state.nodeOverrides);
      }
      rebuildSpriteAtlas(cleaned.type_id);
      if (typeof cfg.getCurrentCatalog === 'function' && cfg.getCurrentCatalog()) {
        setCatalog(cfg.getCurrentCatalog(), true);
      } else if (state.layout) {
        if (assignSelected && state.selectedIds.length) {
          state.selectedIds.forEach(id => {
            const idx = state.idToIndex.get(id);
            if (idx !== undefined) state.nodes[idx].unit_type = cleaned.type_id;
          });
        }
        renderSelectionHud();
      }
      return cleaned;
    }

    function assignSelectedUnitType(typeId) {
      if (!state.unitTypes[typeId] || !state.selectedIds.length) return 0;
      let changed = 0;
      state.selectedIds.forEach(id => {
        state.nodeOverrides[id] = typeId;
        const idx = state.idToIndex.get(id);
        if (idx !== undefined) { state.nodes[idx].unit_type = typeId; changed++; }
      });
      writeStorageJson(OVERRIDES_STORAGE_KEY, state.nodeOverrides);
      renderSelectionHud();
      state.dirtyRender = true;
      return changed;
    }

    function bindDomEvents() {
      const canvas = getEl('canvas');
      if (canvas && typeof canvas.addEventListener === 'function') {
        canvas.addEventListener('pointerdown', ev => {
          const rect = canvas.getBoundingClientRect ? canvas.getBoundingClientRect() : {left: 0, top: 0};
          const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
          if (ev.button === 1 || ev.button === 2 || (ev.button === 0 && ev.altKey && ev.shiftKey)) {
            state.orbitDrag = {active: true, lastX: ev.clientX, lastY: ev.clientY, button: ev.button};
            return;
          }
          if (ev.button === 0) {
            state.marquee = {active: true, x0: px, y0: py, x1: px, y1: py, shiftKey: Boolean(ev.shiftKey), ctrlKey: Boolean(ev.ctrlKey || ev.metaKey), altKey: Boolean(ev.altKey)};
          }
        });
        canvas.addEventListener('pointermove', ev => {
          const rect = canvas.getBoundingClientRect ? canvas.getBoundingClientRect() : {left: 0, top: 0};
          const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
          if (state.orbitDrag.active) {
            const dx = ev.clientX - state.orbitDrag.lastX, dy = ev.clientY - state.orbitDrag.lastY;
            state.orbitDrag.lastX = ev.clientX; state.orbitDrag.lastY = ev.clientY;
            if (ev.altKey) {
              state.camera.goalYaw += dx * 0.008;
              state.camera.goalPitch = clamp(state.camera.goalPitch + dy * 0.25, 18, 89);
            } else {
              const panSp = Math.max(0.8, state.camera.distance * 0.0014);
              const cy = Math.cos(state.camera.yawRad), sy = Math.sin(state.camera.yawRad);
              state.camera.goalX -= (dx * cy - dy * sy) * panSp;
              state.camera.goalY += (dx * sy + dy * cy) * panSp;
            }
            return;
          }
          if (state.marquee.active) {
            state.marquee.x1 = px; state.marquee.y1 = py;
            return;
          }
          state.hoveredIdx = pickUnitAt(px, py);
        });
        canvas.addEventListener('pointerup', ev => {
          if (state.orbitDrag.active) { state.orbitDrag.active = false; return; }
          if (!state.marquee.active) return;
          const rect = canvas.getBoundingClientRect ? canvas.getBoundingClientRect() : {left: 0, top: 0};
          const px = ev.clientX - rect.left, py = ev.clientY - rect.top;
          const dist = Math.hypot(px - state.marquee.x0, py - state.marquee.y0);
          state.marquee.active = false;
          if (dist < 6) {
            const hit = pickUnitAt(px, py);
            selectClick(hit, {shiftKey: ev.shiftKey, ctrlKey: ev.ctrlKey || ev.metaKey, altKey: ev.altKey});
          } else {
            selectMarquee(state.marquee.x0, state.marquee.y0, px, py, {shiftKey: ev.shiftKey, ctrlKey: ev.ctrlKey || ev.metaKey});
          }
        });
        canvas.addEventListener('dblclick', ev => {
          const rect = canvas.getBoundingClientRect ? canvas.getBoundingClientRect() : {left: 0, top: 0};
          const hit = pickUnitAt(ev.clientX - rect.left, ev.clientY - rect.top);
          if (hit >= 0) selectClick(hit, {ctrlKey: true});
        });
        canvas.addEventListener('wheel', ev => {
          if (ev.preventDefault) ev.preventDefault();
          const rect = canvas.getBoundingClientRect ? canvas.getBoundingClientRect() : {left: 0, top: 0, width: state.viewW, height: state.viewH};
          const factor = ev.deltaY > 0 ? 1.14 : 0.88;
          const before = unprojectGroundPoint(ev.clientX - rect.left, ev.clientY - rect.top, state.camera, rect.width || state.viewW, rect.height || state.viewH, 0);
          state.camera.goalDist = clamp(state.camera.goalDist * factor, 180, 4800);
          const nextCam = {...state.camera, distance: state.camera.goalDist};
          const after = unprojectGroundPoint(ev.clientX - rect.left, ev.clientY - rect.top, nextCam, rect.width || state.viewW, rect.height || state.viewH, 0);
          if (!before.clamped && !after.clamped) {
            state.camera.goalX += (before.wx - after.wx) * 0.45;
            state.camera.goalY += (before.wy - after.wy) * 0.45;
          }
        }, {passive: false});
        canvas.addEventListener('contextmenu', ev => { if (ev.preventDefault) ev.preventDefault(); });
      }

      const mini = getEl('minimap');
      if (mini && typeof mini.addEventListener === 'function') {
        let miniDrag = false;
        mini.addEventListener('pointerdown', ev => { miniDrag = true; panCameraToMinimapPoint(ev.clientX, ev.clientY); });
        mini.addEventListener('pointermove', ev => { if (miniDrag) panCameraToMinimapPoint(ev.clientX, ev.clientY); });
        if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
          window.addEventListener('pointerup', () => { miniDrag = false; state.orbitDrag.active = false; });
        }
      }

      const container = getEl('container');
      if (container && typeof container.addEventListener === 'function') {
        /* Pause background rAF loop when content-visibility skips rendering */
        container.addEventListener('contentvisibilityautostatechange', ev => {
          if (ev && ev.skipped) stopLoop(); else startLoop();
        });
        const cvSupported = typeof document !== 'undefined' && document.documentElement && document.documentElement.style && ('contentVisibility' in document.documentElement.style);
        if (!cvSupported && typeof IntersectionObserver === 'function') {
          const io = new IntersectionObserver(entries => {
            entries.forEach(en => { if (en.isIntersecting) startLoop(); else stopLoop(); });
          }, {rootMargin: '120px'});
          io.observe(container);
        }
      }
    }

    bindDomEvents();
    return {
      getState: () => state,
      setCatalog: setCatalog,
      applyLayout: applyLayout,
      setMode: setMode,
      setLevelFilter: setLevelFilter,
      setStatusFilter: setStatusFilter,
      setProjection: setProjection,
      syncProjectionUi: syncProjectionUi,
      setOverlay: setOverlay,
      selectClick: selectClick,
      selectMarquee: selectMarquee,
      cycleSubgroup: cycleSubgroup,
      handleControlGroupKey: handleControlGroupKey,
      centerOnIds: centerOnIds,
      fitCameraToWorld: fitCameraToWorld,
      upsertUnitType: upsertUnitType,
      assignSelectedUnitType: assignSelectedUnitType,
      startLoop: startLoop,
      stopLoop: stopLoop,
      renderFrame: drawMainCanvas
    };
  }

  function initForgeDialog(dialogId, getController, apiBase) {
    if (typeof document === 'undefined') return null;
    const dlg = document.getElementById(dialogId);
    if (!dlg) return null;

    if (typeof HTMLDialogElement !== 'undefined' && !('closedBy' in HTMLDialogElement.prototype) && typeof dlg.addEventListener === 'function') {
      const outside = (e) => {
        if (!dlg.getBoundingClientRect) return false;
        const r = dlg.getBoundingClientRect();
        return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
      };
      let pressedOutside = false;
      dlg.addEventListener('pointerdown', e => { pressedOutside = outside(e); });
      dlg.addEventListener('pointerup', e => { if (pressedOutside && outside(e) && dlg.close) dlg.close(); });
    }
    if (typeof dlg.addEventListener === 'function') {
      dlg.addEventListener('close', () => { dlg.returnValue = ''; });
    }

    let draftLayers = [
      {shape: 'hex', cx: 32, cy: 32, r: 24, fill: '#0F172A', stroke: '#38BDF8', stroke_width: 2.2},
      {shape: 'diamond', cx: 32, cy: 32, r: 11, fill: '#F59E0B', stroke: '#FEF3C7', stroke_width: 1.2}
    ];

    function renderForgePreview() {
      const prev = document.getElementById('wm-forge-preview-canvas');
      if (!prev || typeof prev.getContext !== 'function') return;
      const pCtx = prev.getContext('2d');
      if (!pCtx) return;
      pCtx.clearRect(0, 0, prev.width, prev.height);
      const spec = {
        color_primary: (document.getElementById('wm-forge-primary')?.value) || '#38BDF8',
        color_accent: (document.getElementById('wm-forge-accent')?.value) || '#F59E0B',
        icon_layers: draftLayers
      };
      const rawSvg = (document.getElementById('wm-forge-svg-input')?.value || '').trim();
      const errEl = document.getElementById('wm-forge-error');
      if (rawSvg) {
        try {
          spec.svg_spec = sanitizeClientSvg(rawSvg);
          if (errEl) errEl.textContent = 'SVG geometry validated (' + spec.svg_spec.element_count + ' primitives).';
        } catch (err) {
          if (errEl) errEl.textContent = 'SVG Rejected: ' + err.message;
        }
      } else if (errEl) {
        errEl.textContent = 'Layered Vector Studio ready (' + draftLayers.length + ' layers).';
      }
      const spCanvas = bakeUnitSprite(spec, 64);
      if (spCanvas) pCtx.drawImage(spCanvas, 0, 0, prev.width, prev.height);
    }

    function renderLayerList() {
      const host = document.getElementById('wm-forge-layer-list');
      if (!host || typeof host.replaceChildren !== 'function') return;
      const rows = draftLayers.map((lay, idx) => {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'wm-layer-pill';
        chip.textContent = (idx + 1) + '. ' + lay.shape + ' (r=' + (lay.r || lay.w || 20) + ') ✕';
        chip.onclick = () => {
          if (draftLayers.length > 1) { draftLayers.splice(idx, 1); renderLayerList(); renderForgePreview(); }
        };
        return chip;
      });
      host.replaceChildren(...rows);
    }

    function openForge(seedTypeId) {
      const ctrl = typeof getController === 'function' ? getController() : null;
      const existing = ctrl && seedTypeId && ctrl.getState().unitTypes[seedTypeId];
      const tidInput = document.getElementById('wm-forge-type-id');
      const nameInput = document.getElementById('wm-forge-display-name');
      const primInput = document.getElementById('wm-forge-primary');
      const accInput = document.getElementById('wm-forge-accent');
      const formSel = document.getElementById('wm-forge-formation');
      const zInput = document.getElementById('wm-forge-z-elev');
      const kindInput = document.getElementById('wm-forge-match-kinds');
      const svgInput = document.getElementById('wm-forge-svg-input');
      if (existing) {
        if (tidInput) tidInput.value = existing.builtin ? (existing.type_id + '_custom') : existing.type_id;
        if (nameInput) nameInput.value = existing.display_name + (existing.builtin ? ' Custom' : '');
        if (primInput) primInput.value = existing.color_primary || '#38BDF8';
        if (accInput) accInput.value = existing.color_accent || '#F59E0B';
        if (formSel) formSel.value = existing.formation || 'hex';
        if (zInput) zInput.value = String(existing.z_elevation || 40);
        if (kindInput) kindInput.value = (existing.match_kinds || []).join(',');
        draftLayers = cloneJson(existing.icon_layers || draftLayers);
      }
      if (svgInput && existing && existing.custom_svg) svgInput.value = existing.custom_svg;
      renderLayerList();
      renderForgePreview();
      if (typeof dlg.showModal === 'function') dlg.showModal();
    }

    function addLayerFromInputs() {
      const sh = (document.getElementById('wm-forge-layer-shape')?.value) || 'diamond';
      const r = clamp(Number(document.getElementById('wm-forge-layer-radius')?.value) || 14, 4, 30);
      const col = (document.getElementById('wm-forge-layer-color')?.value) || '#38BDF8';
      if (draftLayers.length >= 16) return;
      draftLayers.push({shape: sh, cx: 32, cy: 32, r: r, w: r * 2, h: r * 1.4, fill: sh === 'ring' || sh === 'cross' ? 'none' : col, stroke: '#F8FAFC', stroke_width: 1.8});
      renderLayerList();
      renderForgePreview();
    }

    async function saveForgeUnitType() {
      const typeId = String(document.getElementById('wm-forge-type-id')?.value || '').trim().toLowerCase();
      const displayName = String(document.getElementById('wm-forge-display-name')?.value || '').trim();
      const prim = String(document.getElementById('wm-forge-primary')?.value || '#38BDF8');
      const acc = String(document.getElementById('wm-forge-accent')?.value || '#F59E0B');
      const form = String(document.getElementById('wm-forge-formation')?.value || 'hex');
      const zElev = clamp(Number(document.getElementById('wm-forge-z-elev')?.value) || 40, 0, 200);
      const matchKinds = String(document.getElementById('wm-forge-match-kinds')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
      const assignSel = Boolean(document.getElementById('wm-forge-assign-selected')?.checked);
      const rawSvg = String(document.getElementById('wm-forge-svg-input')?.value || '').trim();
      const errEl = document.getElementById('wm-forge-error');

      if (!/^[a-z0-9][a-z0-9_-]{1,47}$/.test(typeId)) {
        if (errEl) errEl.textContent = 'Invalid type_id: use lowercase letters, numbers, -, _ (2..48 chars).';
        return false;
      }
      if (!displayName) {
        if (errEl) errEl.textContent = 'Display Name is required.';
        return false;
      }
      const payload = {
        type_id: typeId,
        display_name: displayName,
        category: 'custom',
        color_primary: prim,
        color_accent: acc,
        unit_scale: 1.1,
        z_elevation: zElev,
        formation: form,
        priority: 88,
        match_kinds: matchKinds,
        minor_overlays: ['health_bar', 'child_count', 'alert_pulse'],
        icon_layers: draftLayers
      };
      if (rawSvg) {
        try {
          payload.svg_spec = sanitizeClientSvg(rawSvg);
          payload.custom_svg = rawSvg;
        } catch (err) {
          if (errEl) errEl.textContent = 'SVG Rejected: ' + err.message;
          return false;
        }
      }
      if (typeof fetch === 'function' && typeof window !== 'undefined' && window.location && window.location.hostname) {
        try {
          const res = await fetch((apiBase || '') + '/api/v1/world-map/unit-types', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
          });
          if (!res.ok) {
            const errJson = await res.json().catch(() => ({}));
            if (errEl) errEl.textContent = 'Server validation failed: ' + (errJson.error || res.status);
            return false;
          }
          const saved = await res.json();
          if (saved && saved.unit_type) Object.assign(payload, saved.unit_type);
        } catch (_netErr) {}
      }
      const ctrl = typeof getController === 'function' ? getController() : null;
      if (ctrl) ctrl.upsertUnitType(payload, assignSel);
      if (typeof dlg.close === 'function') dlg.close('saved');
      return true;
    }

    return {openForge: openForge, renderForgePreview: renderForgePreview, addLayerFromInputs: addLayerFromInputs, saveForgeUnitType: saveForgeUnitType};
  }

  function bindProjectionToolbar(opts) {
    if (typeof document === 'undefined') return;
    const cfg = opts || {};
    const bar = cfg.toolbarId ? document.getElementById(cfg.toolbarId) : null;
    const sel = cfg.selectId ? document.getElementById(cfg.selectId) : null;
    const rel = cfg.relevanceId ? document.getElementById(cfg.relevanceId) : null;
    const guideTipId = cfg.guideTipId || '';
    const getCtrl = cfg.getController;

    function previewRelevance(projKey) {
      const info = PROJECTION_GUIDE[normalizeProjectionId(projKey)];
      if (rel && info) rel.textContent = info.title + ' — ' + info.relevance;
    }

    if (bar && typeof bar.querySelectorAll === 'function') {
      const btns = Array.from(bar.querySelectorAll('button[data-proj]'));
      btns.forEach(btn => {
        const p = typeof btn.getAttribute === 'function' ? btn.getAttribute('data-proj') : '';
        btn.onclick = () => {
          const ctrl = typeof getCtrl === 'function' ? getCtrl() : null;
          if (ctrl) ctrl.setProjection(p);
          if (sel) sel.value = normalizeProjectionId(p);
          previewRelevance(p);
        };
        if (typeof btn.addEventListener === 'function') {
          btn.addEventListener('pointerenter', () => previewRelevance(p));
          btn.addEventListener('focus', () => previewRelevance(p));
        }
      });
      if (typeof bar.addEventListener === 'function') {
        bar.addEventListener('pointerleave', () => {
          const ctrl = typeof getCtrl === 'function' ? getCtrl() : null;
          if (ctrl && typeof ctrl.syncProjectionUi === 'function') ctrl.syncProjectionUi();
        });
      }

      /* Native focusgroup roving tabindex fallback for Firefox/Safari */
      if (typeof HTMLElement !== 'undefined' && !('focusGroup' in HTMLElement.prototype) && btns.length && typeof bar.addEventListener === 'function') {
        btns.forEach((b, idx) => {
          const pressed = typeof b.getAttribute === 'function' && b.getAttribute('aria-pressed') === 'true';
          b.tabIndex = pressed ? 0 : (idx === 0 ? 0 : -1);
        });
        bar.addEventListener('focusin', ev => {
          if (btns.includes(ev.target)) btns.forEach(b => { b.tabIndex = (b === ev.target ? 0 : -1); });
        });
        bar.addEventListener('keydown', ev => {
          const cur = btns.indexOf(document.activeElement);
          if (cur === -1) return;
          const dir = (typeof getComputedStyle === 'function' && getComputedStyle(bar).direction === 'rtl') ? -1 : 1;
          let nxt = -1;
          if (ev.key === 'ArrowRight') nxt = (cur + dir + btns.length) % btns.length;
          else if (ev.key === 'ArrowLeft') nxt = (cur - dir + btns.length) % btns.length;
          else if (ev.key === 'Home') nxt = 0;
          else if (ev.key === 'End') nxt = btns.length - 1;
          if (nxt >= 0) {
            if (ev.preventDefault) ev.preventDefault();
            btns[nxt].focus();
            btns[nxt].click();
          }
        });
      }
    }

    if (sel) {
      sel.onchange = ev => {
        const ctrl = typeof getCtrl === 'function' ? getCtrl() : null;
        if (ctrl) ctrl.setProjection(ev.target.value);
        previewRelevance(ev.target.value);
      };
    }

    /* Wire accessible toggletip popover sync and hint->auto fallback */
    if (guideTipId && typeof document.getElementById === 'function') {
      const tip = document.getElementById(guideTipId);
      const trigger = typeof document.querySelector === 'function' ? document.querySelector('[popovertarget="' + guideTipId + '"]') : null;
      if (tip) {
        if (typeof document.createElement === 'function' && typeof tip.setAttribute === 'function') {
          const probe = document.createElement('div');
          try { probe.popover = 'hint'; } catch (_e) {}
          if (probe.popover !== 'hint') {
            tip.setAttribute('popover', 'auto');
          }
        }
        if (typeof tip.addEventListener === 'function') {
          tip.addEventListener('toggle', ev => {
            if (trigger && typeof trigger.setAttribute === 'function') {
              trigger.setAttribute('aria-expanded', (ev && ev.newState === 'open') ? 'true' : 'false');
            }
          });
        }
      }
    }
    const ctrl = typeof getCtrl === 'function' ? getCtrl() : null;
    if (ctrl && typeof ctrl.syncProjectionUi === 'function') ctrl.syncProjectionUi();
  }

  globalScope.OpsCryerWorldMap = {
    BUILTIN_UNIT_TYPES: BUILTIN_UNIT_TYPES,
    PROJECTION_GUIDE: PROJECTION_GUIDE,
    normalizeProjectionId: normalizeProjectionId,
    sanitizeClientSvg: sanitizeClientSvg,
    resolveClientNodeUnitType: resolveClientNodeUnitType,
    buildClientWorldLayout: buildClientWorldLayout,
    projectPoint: projectPoint,
    unprojectGroundPoint: unprojectGroundPoint,
    computeCameraTrapezoid: computeCameraTrapezoid,
    createWorldMapController: createWorldMapController,
    initForgeDialog: initForgeDialog,
    bindProjectionToolbar: bindProjectionToolbar
  };
})(typeof window !== 'undefined' ? window : globalThis);
""".strip()
    return (
        template.replace("__BUILTIN_UNIT_TYPES__", builtin_types_json.replace("</", "<\\/"))
        .replace("__PROJECTION_GUIDE__", projection_guide_json.replace("</", "<\\/"))
    )


def render_world_map_html(
    catalog: Mapping[str, Any] | None = None,
    default_api_base: str = "",
) -> str:
    """Render the standalone 2D / 2.5D / 3D Spatial Knowledge Graph HTML application."""
    if catalog is None:
        from opscryer_browser import build_standalone_demo_dataset

        eff_catalog = build_standalone_demo_dataset()
    else:
        eff_catalog = deepcopy(dict(catalog))

    layout = build_world_map_layout(eff_catalog, mode="unit_type")
    initial_json = json.dumps(
        {
            "catalog": eff_catalog,
            "layout": layout,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).replace("</", "<\\/")
    safe_api_base = json.dumps(str(default_api_base or "")).replace("</", "<\\/")
    graph_layers_js = build_graph_layers_js().replace("</", "<\\/")
    engine_js = build_world_map_engine_js().replace("</", "<\\/")
    from workspace_layout import (
        build_workspace_layout_css,
        build_workspace_layout_dialog_html,
        build_workspace_layout_js,
    )

    layout_css = build_workspace_layout_css()
    layout_dialog_html = build_workspace_layout_dialog_html(include_view_switcher=False)
    layout_js = build_workspace_layout_js().replace("</", "<\\/")

    html = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpsCryer Spatial Topology — 2D / 2.5D / 3D Knowledge Graph</title>
  <style>
    :root {
      --bg: #040813;
      --panel: #0B1222;
      --panel-elevated: #111C33;
      --border: #1E293B;
      --text: #F8FAFC;
      --muted: #94A3B8;
      --cyan: #38BDF8;
      --green: #22C55E;
      --purple: #A855F7;
      --amber: #F59E0B;
      --red: #EF4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      height: 100dvh;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    header.wm-topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
      padding: 0.45rem 0.9rem;
      background: linear-gradient(180deg, var(--panel-elevated) 0%, var(--panel) 100%);
      border-bottom: 1px solid var(--border);
    }
    .wm-row { display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; }
    button, select, input, textarea {
      background: #1E293B;
      color: var(--text);
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 0.28rem 0.52rem;
      font-size: 0.73rem;
      font-family: inherit;
    }
    button { cursor: pointer; font-weight: 700; border-color: var(--cyan); min-inline-size: 28px; min-block-size: 28px; }
    button:focus-visible, select:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
    @media (hover: hover) {
      button:hover { background: rgba(56, 189, 248, 0.2); }
    }
    @media (pointer: coarse) {
      .proj-seg-btn { min-block-size: 36px; min-inline-size: 44px; }
    }
    .proj-segmented-bar {
      display: inline-flex;
      align-items: center;
      gap: 2px;
      padding: 2px;
      border-radius: 8px;
      background: #060C19;
      border: 1px solid #26354D;
    }
    .proj-seg-btn {
      position: relative;
      border: 1px solid transparent;
      background: transparent;
      color: var(--muted);
      padding: 0.24rem 0.55rem;
      font-size: 0.71rem;
      border-radius: 6px;
    }
    .proj-seg-btn[aria-pressed="true"] {
      background: rgba(56, 189, 248, 0.2);
      border-color: var(--cyan);
      color: var(--text);
    }
    .proj-seg-btn[aria-pressed="true"]::after {
      content: "";
      position: absolute;
      inset: auto 4px 1px;
      border-block-end: 2px solid var(--amber);
    }
    @media (forced-colors: active) {
      .proj-seg-btn[aria-pressed="true"] {
        background: Highlight;
        color: HighlightText;
        border-color: ButtonText;
      }
    }
    .proj-relevance-strip {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
      padding: 0.26rem 0.9rem;
      background: rgba(7, 13, 27, 0.94);
      border-bottom: 1px solid #1E293B;
      font-size: 0.7rem;
      color: #CBD5E1;
    }
    #wm-proj-guide-tip {
      background: #0B1222;
      color: var(--text);
      border: 1px solid var(--cyan);
      border-radius: 8px;
      padding: 0.65rem 0.8rem;
      max-width: 410px;
      font-size: 0.72rem;
      line-height: 1.45;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.65);
    }
    @supports (position-area: block-end) {
      [popover].anchored-guide-tip {
        inset: auto;
        margin: 0.25rem 0 0 0;
        position-area: block-end span-inline-end;
        position-try-fallbacks: flip-block, flip-inline;
      }
    }
    @supports not (position-area: block-end) {
      [popover].anchored-guide-tip {
        position: fixed;
        inset: 4.2rem 1rem auto auto;
        margin: 0;
      }
    }
    @media (prefers-reduced-motion: no-preference) {
      .proj-seg-btn { transition: background-color 140ms ease, color 140ms ease; }
    }
    a.wm-nav-link {
      color: var(--cyan);
      text-decoration: none;
      font-size: 0.72rem;
      font-weight: 700;
      padding: 0.25rem 0.55rem;
      border-radius: 6px;
      border: 1px solid rgba(56, 189, 248, 0.35);
      background: #0F172A;
    }
    .wm-badge {
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.18rem 0.5rem;
      border-radius: 999px;
      border: 1px solid var(--amber);
      color: var(--amber);
      background: rgba(245, 158, 11, 0.12);
    }
    main#wm-stage-container {
      flex: 1;
      position: relative;
      min-height: 260px;
      content-visibility: auto;
      contain-intrinsic-size: auto none auto 520px;
      background: radial-gradient(circle at 50% 40%, #0B152A 0%, #03060F 80%);
    }
    canvas#wm-canvas { width: 100%; height: 100%; display: block; cursor: crosshair; }
    .wm-hud-strip {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.45rem;
      flex-wrap: wrap;
      padding: 0.32rem 0.9rem;
      background: rgba(11, 18, 34, 0.95);
      border-top: 1px solid var(--border);
      font-size: 0.71rem;
    }
    footer.wm-console {
      display: grid;
      grid-template-columns: 245px 1fr 290px;
      gap: 0.7rem;
      padding: 0.5rem 0.9rem;
      height: 158px;
      background: linear-gradient(180deg, #0D1527 0%, #050912 100%);
      border-top: 2px solid #334155;
      flex-shrink: 0;
    }
    .wm-box {
      background: #09101E;
      border: 1px solid #26354D;
      border-radius: 8px;
      padding: 0.4rem 0.6rem;
      display: flex;
      flex-direction: column;
      gap: 0.28rem;
      min-height: 0;
    }
    canvas#wm-minimap {
      width: 220px;
      height: 105px;
      border-radius: 6px;
      border: 1px solid #334155;
      cursor: pointer;
    }
    #wm-group-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 0.28rem;
      overflow-y: auto;
      align-content: flex-start;
    }
    .wm-unit-chip {
      font-size: 0.67rem;
      padding: 0.18rem 0.42rem;
      border-width: 1px;
      background: #0F172A;
    }
    .wm-unit-chip.active-subgroup {
      box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.45);
      background: rgba(34, 197, 94, 0.16);
    }
    .wm-group-tab { font-size: 0.66rem; padding: 0.15rem 0.38rem; border-color: #334155; }
    .wm-group-tab.populated { border-color: var(--amber); color: var(--amber); }
    .kg-level-stats-row { display: flex; flex-wrap: wrap; gap: 0.24rem; margin-bottom: 0.18rem; }
    .kg-level-stat-pill { font-size: 0.62rem; padding: 0.12rem 0.36rem; border-radius: 999px; background: #0F172A; border: 1px solid #334155; color: var(--text); font-weight: 700; cursor: pointer; }
    .kg-level-stat-pill.empty { opacity: 0.45; }
    .kg-level-stat-pill.active { box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.45); background: rgba(56, 189, 248, 0.18); }
    .wm-cmd-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.3rem; flex: 1; }
    .wm-layer-pill { font-size: 0.66rem; padding: 0.15rem 0.4rem; border-color: #475569; }
    dialog#wm-unit-forge-dialog {
      border: 1px solid var(--cyan);
      border-radius: 10px;
      background: #0B1222;
      color: var(--text);
      max-width: 640px;
      width: 92vw;
      padding: 1rem;
    }
    dialog[open]#wm-unit-forge-dialog {
      display: flex;
      flex-direction: column;
      gap: 0.55rem;
    }
    dialog:modal { overscroll-behavior: contain; }
    dialog::backdrop {
      background: rgba(2, 6, 23, 0.78);
      overflow: hidden;
      overscroll-behavior: contain;
    }
__WORKSPACE_LAYOUT_CSS__
  </style>
</head>
<body>
  <header class="wm-topbar">
    <div class="wm-row">
      <a class="wm-nav-link" href="/?view=local_links">🔗 Local Links</a>
      <a class="wm-nav-link" href="/?view=boxes">📦 Layer Boxes</a>
      <strong>🌐 OpsCryer Spatial Topology</strong>
      <span class="wm-badge" id="wm-fps-pill">⚡ 60 FPS</span>
    </div>
    <div class="wm-row">
      <select id="wm-layout-mode" aria-label="Spatial Grouping">
        <option value="unit_type">Group: By Node Type</option>
        <option value="graph_layers">Group: 7-Level Stack (Project → Contract)</option>
        <option value="domain_squads">Group: By Ecosystem Domain</option>
        <option value="cloud_3d">Group: Orbital Constellation</option>
      </select>
      <div id="wm-proj-toolbar" class="proj-segmented-bar" role="toolbar" focusgroup="toolbar wrap" aria-label="Spatial Projection Mode" aria-controls="wm-canvas">
        <div role="group" aria-label="Dimensions" style="display:inline-flex;gap:2px;">
          <button type="button" class="proj-seg-btn" data-proj="flat_2d" aria-pressed="false" title="Orthographic flat layout for schematic audits & exact box selection">2D Schematic</button>
          <button type="button" class="proj-seg-btn" data-proj="iso_25d" aria-pressed="true" title="Elevated architectural plane showing tier height anchored to ground sectors">2.5D Elevation</button>
          <button type="button" class="proj-seg-btn" data-proj="orbit_3d" aria-pressed="false" title="Spherical Z-depth cloud for dense hub exploration & multi-angle orbit">3D Volumetric</button>
        </div>
      </div>
      <select id="wm-projection-mode" aria-label="Projection Preset">
        <option value="iso_25d">Projection: 2.5D Elevation</option>
        <option value="flat_2d">Projection: 2D Schematic</option>
        <option value="orbit_3d">Projection: 3D Volumetric</option>
      </select>
      <button type="button" interestfor="wm-proj-guide-tip" popovertarget="wm-proj-guide-tip" popovertargetaction="show" aria-expanded="false" aria-label="Projection mode guide" style="border-color:var(--muted);color:var(--cyan);">? Guide</button>
      <div id="wm-proj-guide-tip" class="anchored-guide-tip" popover="hint" role="tooltip">
        <strong style="color:var(--amber);">When to use each projection (same dataset):</strong>
        <div style="margin-top:0.25rem;"><strong>2D Schematic:</strong> Best for flat dependency audits, alignment, and marquee selection with zero foreshortening.</div>
        <div><strong>2.5D Elevation:</strong> Best for separating vertical system tiers (Hardware → Cluster → Service → Root) above ground sectors.</div>
        <div><strong>3D Volumetric:</strong> Best for untangling high-node-count clusters across Z-depth with orbit rotation (Alt/Right-Drag or Q/E).</div>
      </div>
      <button type="button" id="wm-scale-600-btn">600 Nodes</button>
      <button type="button" id="wm-scale-1500-btn">1500 Nodes</button>
      <button type="button" id="wm-open-forge-btn" style="border-color:var(--amber);color:var(--amber);">🧩 Node Studio</button>
    </div>
  </header>

  <div class="proj-relevance-strip">
    <span id="wm-proj-relevance" role="status">2.5D Architectural Elevation — Best for reading vertical architecture tiers anchored cleanly onto ground sectors.</span>
    <span style="color:var(--muted);">Same active dataset across 2D, 2.5D &amp; 3D</span>
  </div>

  <main id="wm-stage-container">
    <canvas id="wm-canvas" aria-label="2D / 2.5D / 3D Spatial Knowledge Graph Canvas"></canvas>
  </main>

  <section class="wm-hud-strip" aria-label="Overlays and Selection Groups">
    <div class="wm-row">
      <span id="wm-status-line" style="color:var(--cyan);font-weight:700;">Ready</span>
      <span style="color:var(--muted);">| Hold [Alt] for metrics peek</span>
    </div>
    <div class="wm-row" id="wm-control-group-tabs"></div>
    <div class="wm-row">
      <label><input type="checkbox" id="wm-ov-health" checked="checked" /> Health</label>
      <label><input type="checkbox" id="wm-ov-children" checked="checked" /> Links Badge</label>
      <label><input type="checkbox" id="wm-ov-beams" checked="checked" /> Dependencies</label>
      <label><input type="checkbox" id="wm-ov-alerts" checked="checked" /> Alerts</label>
      <button type="button" id="wm-isolate-btn">Isolate Selection</button>
      <button type="button" id="wm-fit-btn">Fit View</button>
    </div>
  </section>

  <footer class="wm-console" id="wm-footer-console">
    <section class="wm-box" id="wm-minimap-box">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong style="font-size:0.68rem;color:var(--amber);">VIEWPORT MINIMAP</strong>
        <span style="font-size:0.63rem;color:var(--muted);">Click / Drag Pan</span>
      </div>
      <canvas id="wm-minimap" width="220" height="105"></canvas>
    </section>
    <section class="wm-box" id="wm-squad-box">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong style="font-size:0.68rem;color:var(--cyan);">ACTIVE SELECTION • 7-LEVEL BREAKDOWN &amp; NODES</strong>
        <span style="font-size:0.63rem;color:var(--muted);">[Tab] Cycle Type • Ctrl+1..9 Pin Group</span>
      </div>
      <div id="wm-selection-level-stats" class="kg-level-stats-row" aria-label="Selected Nodes 7-Level Breakdown"></div>
      <div id="wm-group-grid"></div>
    </section>
    <section class="wm-box" id="wm-cmd-box">
      <strong style="font-size:0.68rem;color:var(--amber);">QUICK ACTIONS</strong>
      <div class="wm-cmd-grid">
        <button type="button" id="wm-cmd-focus"><strong>[F] Focus</strong></button>
        <button type="button" id="wm-cmd-fit"><strong>[Space] Fit</strong></button>
        <button type="button" id="wm-cmd-sub"><strong>[Tab] Cycle</strong></button>
        <button type="button" id="wm-cmd-assign"><strong>🧩 Node Type</strong></button>
        <button type="button" id="wm-cmd-isolate"><strong>Isolate</strong></button>
        <button type="button" id="wm-cmd-open-url"><strong>↗ Open URL</strong></button>
      </div>
    </section>
  </footer>

  <dialog id="wm-unit-forge-dialog" closedby="any" aria-labelledby="wm-unit-forge-title">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h2 id="wm-unit-forge-title" style="margin:0;font-size:1rem;color:var(--amber);">🧩 Node Type &amp; Vector Icon Studio</h2>
      <form method="dialog"><button type="submit" value="cancel">✕ Close</button></form>
    </div>
    <div class="wm-row" style="gap:0.75rem;">
      <canvas id="wm-forge-preview-canvas" width="96" height="96" style="border:1px solid var(--cyan);border-radius:8px;background:#020617;"></canvas>
      <div style="flex:1;display:grid;grid-template-columns:1fr 1fr;gap:0.4rem;">
        <label>Type ID <input id="wm-forge-type-id" type="text" value="custom_squad_unit" autofocus="autofocus" /></label>
        <label>Display Name <input id="wm-forge-display-name" type="text" value="Custom Squad Unit" /></label>
        <label>Primary Hex <input id="wm-forge-primary" type="text" value="#38BDF8" /></label>
        <label>Accent Hex <input id="wm-forge-accent" type="text" value="#F59E0B" /></label>
        <label>Formation <select id="wm-forge-formation"><option value="hex">Hex</option><option value="ring">Ring</option><option value="grid">Grid</option><option value="orbital">Orbital</option></select></label>
        <label>Elevation Z <input id="wm-forge-z-elev" type="number" min="0" max="200" value="44" /></label>
      </div>
    </div>
    <label>Match Node Kinds (CSV) <input id="wm-forge-match-kinds" type="text" value="engineering_project" style="width:100%;" /></label>
    <div class="wm-row">
      <strong style="font-size:0.72rem;color:var(--cyan);">Vector Layers:</strong>
      <select id="wm-forge-layer-shape">
        <option value="hex">Hex</option><option value="shield">Shield</option><option value="star">Star</option>
        <option value="diamond">Diamond</option><option value="ring">Ring</option><option value="circle">Circle</option>
        <option value="triangle">Triangle</option><option value="cross">Cross</option><option value="pill">Pill</option>
      </select>
      <input id="wm-forge-layer-radius" type="number" min="4" max="30" value="14" style="width:62px;" />
      <input id="wm-forge-layer-color" type="text" value="#22C55E" style="width:82px;" />
      <button type="button" id="wm-forge-add-layer-btn">+ Add Layer</button>
    </div>
    <div id="wm-forge-layer-list" class="wm-row"></div>
    <label>Optional Custom SVG (Strictly Geometry-Sanitized)
      <textarea id="wm-forge-svg-input" rows="3" style="width:100%;" placeholder="<svg viewBox='0 0 64 64'><path d='M32 6 L58 54 L6 54 Z' fill='#38BDF8'/></svg>"></textarea>
    </label>
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <label><input type="checkbox" id="wm-forge-assign-selected" checked="checked" /> Assign to currently selected units</label>
      <button type="button" id="wm-forge-save-btn" style="border-color:var(--green);color:var(--green);">💾 Save &amp; Bake Sprite</button>
    </div>
    <div id="wm-forge-error" role="status" style="font-size:0.72rem;color:var(--amber);"></div>
  </dialog>
__WORKSPACE_LAYOUT_DIALOG__

  <script>
__GRAPH_LAYERS_JS__
__ENGINE_JS__
__WORKSPACE_LAYOUT_JS__
(function() {
  const BOOT = __INITIAL_JSON__;
  const API_BASE = __API_BASE__;
  let currentCatalog = BOOT.catalog;
  const ctrl = window.OpsCryerWorldMap.createWorldMapController({
    ids: {
      container: 'wm-stage-container',
      canvas: 'wm-canvas',
      minimap: 'wm-minimap',
      groupGrid: 'wm-group-grid',
      levelStats: 'wm-selection-level-stats',
      groupTabs: 'wm-control-group-tabs',
      statusLine: 'wm-status-line',
      fpsPill: 'wm-fps-pill',
      projectionToolbar: 'wm-proj-toolbar',
      projectionSelect: 'wm-projection-mode',
      relevanceBanner: 'wm-proj-relevance'
    },
    getCurrentCatalog: () => currentCatalog
  });
  ctrl.applyLayout(BOOT.layout);
  ctrl.startLoop();

  const forge = window.OpsCryerWorldMap.initForgeDialog('wm-unit-forge-dialog', () => ctrl, API_BASE);
  const byId = id => document.getElementById(id);
  const qsProj = (typeof window !== 'undefined' && window.location && window.location.search)
    ? (new URLSearchParams(window.location.search).get('proj') || new URLSearchParams(window.location.search).get('projection') || '')
    : '';
  if (qsProj) ctrl.setProjection(qsProj);
  if (window.OpsCryerWorldMap.bindProjectionToolbar) {
    window.OpsCryerWorldMap.bindProjectionToolbar({
      toolbarId: 'wm-proj-toolbar',
      selectId: 'wm-projection-mode',
      relevanceId: 'wm-proj-relevance',
      guideTipId: 'wm-proj-guide-tip',
      getController: () => ctrl
    });
  }

  if (byId('wm-layout-mode')) byId('wm-layout-mode').onchange = ev => ctrl.setMode(ev.target.value);
  if (byId('wm-scale-600-btn')) byId('wm-scale-600-btn').onclick = async () => {
    const r = await fetch((API_BASE || '') + '/api/v1/world-map/layout?mode=' + encodeURIComponent(ctrl.getState().layoutMode) + '&nodes=600');
    if (r.ok) { const lay = await r.json(); ctrl.applyLayout(lay); }
  };
  if (byId('wm-scale-1500-btn')) byId('wm-scale-1500-btn').onclick = async () => {
    const r = await fetch((API_BASE || '') + '/api/v1/world-map/layout?mode=' + encodeURIComponent(ctrl.getState().layoutMode) + '&nodes=1500');
    if (r.ok) { const lay = await r.json(); ctrl.applyLayout(lay); }
  };
  if (byId('wm-open-forge-btn') && forge) byId('wm-open-forge-btn').onclick = () => forge.openForge(ctrl.getState().activeSubgroupType);
  if (byId('wm-forge-add-layer-btn') && forge) byId('wm-forge-add-layer-btn').onclick = () => forge.addLayerFromInputs();
  if (byId('wm-forge-save-btn') && forge) byId('wm-forge-save-btn').onclick = () => forge.saveForgeUnitType();
  ['wm-forge-primary', 'wm-forge-accent', 'wm-forge-svg-input'].forEach(fid => {
    const el = byId(fid);
    if (el && forge) el.oninput = () => forge.renderForgePreview();
  });
  if (byId('wm-ov-health')) byId('wm-ov-health').onchange = ev => ctrl.setOverlay('health_bar', ev.target.checked);
  if (byId('wm-ov-children')) byId('wm-ov-children').onchange = ev => ctrl.setOverlay('child_count', ev.target.checked);
  if (byId('wm-ov-beams')) byId('wm-ov-beams').onchange = ev => ctrl.setOverlay('dependency_beam', ev.target.checked);
  if (byId('wm-ov-alerts')) byId('wm-ov-alerts').onchange = ev => ctrl.setOverlay('alert_pulse', ev.target.checked);
  const togIso = () => { const s = ctrl.getState(); s.isolateSelected = !s.isolateSelected; s.dirtyRender = true; };
  if (byId('wm-isolate-btn')) byId('wm-isolate-btn').onclick = togIso;
  if (byId('wm-cmd-isolate')) byId('wm-cmd-isolate').onclick = togIso;
  if (byId('wm-fit-btn')) byId('wm-fit-btn').onclick = () => ctrl.fitCameraToWorld();
  if (byId('wm-cmd-fit')) byId('wm-cmd-fit').onclick = () => ctrl.fitCameraToWorld();
  if (byId('wm-cmd-focus')) byId('wm-cmd-focus').onclick = () => ctrl.centerOnIds(ctrl.getState().selectedIds);
  if (byId('wm-cmd-sub')) byId('wm-cmd-sub').onclick = () => ctrl.cycleSubgroup(false);
  if (byId('wm-cmd-assign') && forge) byId('wm-cmd-assign').onclick = () => forge.openForge(ctrl.getState().activeSubgroupType);
  if (byId('wm-cmd-open-url')) byId('wm-cmd-open-url').onclick = () => {
    const st = ctrl.getState();
    const id = st.selectedIds[0];
    const idx = st.idToIndex.get(id);
    const u = idx !== undefined ? st.nodes[idx].primary_url : '';
    if (u && typeof window.open === 'function') window.open(u, '_blank', 'noopener,noreferrer');
  };

  if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
    document.addEventListener('keydown', ev => {
      const tag = (ev.target && ev.target.tagName) ? ev.target.tagName.toUpperCase() : '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      const st = ctrl.getState();
      if (ev.key === 'Alt') { st.altPeekHeld = true; return; }
      const kl = String(ev.key || '').toLowerCase();
      st.keysDown.add(kl);
      if (ev.key === 'Tab') { if (ev.preventDefault) ev.preventDefault(); ctrl.cycleSubgroup(Boolean(ev.shiftKey)); }
      else if (kl >= '1' && kl <= '9') { ctrl.handleControlGroupKey(Number(kl), ev); }
      else if (kl === 'f') { ctrl.centerOnIds(st.selectedIds); }
      else if (ev.key === ' ' || ev.key === 'Home') { if (ev.preventDefault) ev.preventDefault(); ctrl.fitCameraToWorld(); }
    });
    document.addEventListener('keyup', ev => {
      const st = ctrl.getState();
      if (ev.key === 'Alt') st.altPeekHeld = false;
      st.keysDown.delete(String(ev.key || '').toLowerCase());
    });
  }
  window.worldMapController = ctrl;
  if (window.OpsCryerWorkspaceLayout) {
    window.workspaceLayoutController = window.OpsCryerWorkspaceLayout.createWorkspaceLayoutController({
      footerId: 'wm-footer-console',
      pageMode: 'world_map'
    });
  }
})();
  </script>
</body>
</html>
"""
    rendered = (
        html.replace("__GRAPH_LAYERS_JS__", graph_layers_js)
        .replace("__ENGINE_JS__", engine_js)
        .replace("__WORKSPACE_LAYOUT_CSS__", layout_css)
        .replace("__WORKSPACE_LAYOUT_DIALOG__", layout_dialog_html)
        .replace("__WORKSPACE_LAYOUT_JS__", layout_js)
        .replace("__INITIAL_JSON__", initial_json)
        .replace("__API_BASE__", safe_api_base)
    )
    return rendered
