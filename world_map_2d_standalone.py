# SPDX-License-Identifier: Apache-2.0
"""Standalone orthographic 2D World Map engine decoupled from the 2.5D/3D spatial engine.

Provides a lightweight top-down 2D layout builder and accessible SVG/DOM viewer served at
``/map-2d`` and ``/api/v1/world-map-2d/layout`` with a 1-click link back to ``/world-map``
for 2.5D/3D isometric exploration.
"""

from __future__ import annotations

import json
import math
from typing import Any, Mapping


WORLD_MAP_2D_SCHEMA_VERSION = "1.0-world-map-2d-standalone"
WORLD_MAP_2D_MODES: tuple[str, ...] = ("domain_grid", "layer_bands", "radial_ring")

_DOMAIN_PALETTE: tuple[str, ...] = (
    "#0ea5e9",
    "#10b981",
    "#f59e0b",
    "#8b5cf6",
    "#ec4899",
    "#14b8a6",
    "#6366f1",
    "#f97316",
)


def _normalize_status(node: Mapping[str, Any]) -> str:
    raw = str(node.get("status") or node.get("health") or "nominal").strip().lower()
    if raw in {"critical", "error", "down", "unhealthy", "degraded_critical", "red"}:
        return "critical"
    if raw in {"warning", "warn", "degraded", "amber", "yellow"}:
        return "warning"
    if raw in {"unknown", "stale", "offline", "unverified"}:
        return "unknown"
    return "nominal"


def _extract_mls_badge(node: Mapping[str, Any]) -> str:
    for key in ("mls", "mls_label", "classification"):
        carrier = node.get(key)
        if isinstance(carrier, Mapping):
            rank = carrier.get("rank", carrier.get("classification_rank"))
            comps = carrier.get("compartments") or []
            if rank is not None or comps:
                comp_str = ",".join(str(c) for c in comps) if isinstance(comps, list) else str(comps)
                return f"R{rank}" + (f" [{comp_str}]" if comp_str else "")
    top_rank = node.get("classification_rank")
    if isinstance(top_rank, int) and not isinstance(top_rank, bool) and top_rank > 0:
        return f"R{top_rank}"
    return ""


def _infer_layer_band(node: Mapping[str, Any]) -> tuple[int, str]:
    explicit = node.get("level_index", node.get("zoom_level"))
    kind = str(node.get("kind") or node.get("type") or "service").strip().lower()
    if isinstance(explicit, int) and not isinstance(explicit, bool):
        clamped = max(0, min(4, explicit))
        labels = ("Executive / Root", "Platform & Control", "Core Services", "Workloads & Data", "Edge & Hardware")
        return clamped, labels[clamped]
    if kind in {"company_root", "root", "organization", "tier"}:
        return 0, "Executive / Root"
    if kind in {"cluster", "control_plane", "identity", "security", "gitops", "gateway"}:
        return 1, "Platform & Control"
    if kind in {"database", "storage", "queue", "cache", "nas"}:
        return 3, "Workloads & Data"
    if kind in {"node", "host", "gpu", "hardware", "device", "workstation"}:
        return 4, "Edge & Hardware"
    return 2, "Core Services"


def _build_domain_grid_layout(
    nodes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, float]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        dom = str(node.get("domain") or node.get("namespace") or node.get("kind") or "core").strip() or "core"
        grouped.setdefault(dom, []).append(node)

    domain_names = sorted(grouped.keys())
    grid_cols = max(1, math.ceil(math.sqrt(max(1, len(domain_names)))))
    cell_gap_x = 48.0
    cell_gap_y = 48.0
    node_step_x = 176.0
    node_step_y = 78.0
    pad_x = 28.0
    pad_top = 48.0
    pad_bottom = 26.0

    region_boxes: list[dict[str, Any]] = []
    positioned: list[dict[str, Any]] = []

    row_heights: dict[int, float] = {}
    col_widths: dict[int, float] = {}
    region_dims: dict[str, tuple[float, float, int]] = {}

    for idx, dom in enumerate(domain_names):
        members = sorted(grouped[dom], key=lambda item: str(item.get("id") or ""))
        inner_cols = max(1, min(3, math.ceil(math.sqrt(len(members)))))
        inner_rows = max(1, math.ceil(len(members) / inner_cols))
        width = pad_x * 2 + inner_cols * node_step_x
        height = pad_top + pad_bottom + inner_rows * node_step_y
        region_dims[dom] = (width, height, inner_cols)
        r_idx = idx // grid_cols
        c_idx = idx % grid_cols
        row_heights[r_idx] = max(row_heights.get(r_idx, 0.0), height)
        col_widths[c_idx] = max(col_widths.get(c_idx, 0.0), width)

    col_x: dict[int, float] = {}
    cursor_x = 40.0
    for c_idx in range(grid_cols):
        col_x[c_idx] = cursor_x
        cursor_x += col_widths.get(c_idx, 240.0) + cell_gap_x

    total_rows = max(1, math.ceil(len(domain_names) / grid_cols))
    row_y: dict[int, float] = {}
    cursor_y = 40.0
    for r_idx in range(total_rows):
        row_y[r_idx] = cursor_y
        cursor_y += row_heights.get(r_idx, 180.0) + cell_gap_y

    for idx, dom in enumerate(domain_names):
        r_idx = idx // grid_cols
        c_idx = idx % grid_cols
        rx = round(col_x[c_idx], 1)
        ry = round(row_y[r_idx], 1)
        rw, rh, inner_cols = region_dims[dom]
        accent = _DOMAIN_PALETTE[idx % len(_DOMAIN_PALETTE)]
        members = sorted(grouped[dom], key=lambda item: str(item.get("id") or ""))
        region_boxes.append(
            {
                "id": f"region:{dom}",
                "label": dom,
                "x": rx,
                "y": ry,
                "width": round(rw, 1),
                "height": round(rh, 1),
                "accent": accent,
                "node_count": len(members),
            }
        )
        for m_idx, node in enumerate(members):
            mr = m_idx // inner_cols
            mc = m_idx % inner_cols
            nx = round(rx + pad_x + (mc + 0.5) * node_step_x, 1)
            ny = round(ry + pad_top + (mr + 0.5) * node_step_y, 1)
            positioned.append(
                {
                    "id": str(node["id"]),
                    "label": str(node.get("label") or node["id"]),
                    "kind": str(node.get("kind") or "service"),
                    "domain": dom,
                    "status": _normalize_status(node),
                    "mls_badge": _extract_mls_badge(node),
                    "summary": str(node.get("summary") or ""),
                    "primary_url": str(node.get("primary_url") or ""),
                    "region_id": f"region:{dom}",
                    "x": nx,
                    "y": ny,
                    "accent": accent,
                }
            )

    bounds = {
        "width": round(max(920.0, cursor_x), 1),
        "height": round(max(560.0, cursor_y), 1),
    }
    return positioned, region_boxes, bounds


def _build_layer_bands_layout(
    nodes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, float]]:
    bands: dict[int, tuple[str, list[dict[str, Any]]]] = {}
    for node in nodes:
        b_idx, b_label = _infer_layer_band(node)
        if b_idx not in bands:
            bands[b_idx] = (b_label, [])
        bands[b_idx][1].append(node)

    band_keys = sorted(bands.keys())
    node_step_x = 188.0
    band_height = 112.0
    band_gap_y = 32.0
    max_cols = max((len(bands[k][1]) for k in band_keys), default=1)
    band_width = max(840.0, 80.0 + max_cols * node_step_x)

    region_boxes: list[dict[str, Any]] = []
    positioned: list[dict[str, Any]] = []
    cursor_y = 36.0

    for order_idx, b_idx in enumerate(band_keys):
        b_label, members = bands[b_idx]
        members = sorted(members, key=lambda item: str(item.get("id") or ""))
        accent = _DOMAIN_PALETTE[order_idx % len(_DOMAIN_PALETTE)]
        region_boxes.append(
            {
                "id": f"band:{b_idx}",
                "label": f"L{b_idx} · {b_label}",
                "x": 36.0,
                "y": round(cursor_y, 1),
                "width": round(band_width, 1),
                "height": round(band_height, 1),
                "accent": accent,
                "node_count": len(members),
            }
        )
        start_x = 36.0 + (band_width - len(members) * node_step_x) / 2.0 + node_step_x / 2.0
        for m_idx, node in enumerate(members):
            nx = round(start_x + m_idx * node_step_x, 1)
            ny = round(cursor_y + band_height * 0.60, 1)
            positioned.append(
                {
                    "id": str(node["id"]),
                    "label": str(node.get("label") or node["id"]),
                    "kind": str(node.get("kind") or "service"),
                    "domain": str(node.get("domain") or "core"),
                    "status": _normalize_status(node),
                    "mls_badge": _extract_mls_badge(node),
                    "summary": str(node.get("summary") or ""),
                    "primary_url": str(node.get("primary_url") or ""),
                    "region_id": f"band:{b_idx}",
                    "x": nx,
                    "y": ny,
                    "accent": accent,
                }
            )
        cursor_y += band_height + band_gap_y

    bounds = {
        "width": round(band_width + 72.0, 1),
        "height": round(max(560.0, cursor_y + 24.0), 1),
    }
    return positioned, region_boxes, bounds


def _build_radial_ring_layout(
    nodes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, float]]:
    ordered = sorted(nodes, key=lambda item: (_infer_layer_band(item)[0], str(item.get("id") or "")))
    cx, cy = 540.0, 360.0
    positioned: list[dict[str, Any]] = []
    region_boxes: list[dict[str, Any]] = []

    if not ordered:
        return positioned, region_boxes, {"width": 1080.0, "height": 720.0}

    ring_step = 155.0
    max_r = 180.0
    idx = 0
    ring = 0
    while idx < len(ordered):
        cap = 1 if ring == 0 else max(6, ring * 8)
        chunk = ordered[idx : idx + cap]
        radius = 0.0 if ring == 0 else ring * ring_step
        max_r = max(max_r, radius + 120.0)
        accent = _DOMAIN_PALETTE[ring % len(_DOMAIN_PALETTE)]
        region_boxes.append(
            {
                "id": f"ring:{ring}",
                "label": f"Ring {ring}",
                "x": round(cx - max(90.0, radius), 1),
                "y": round(cy - max(90.0, radius), 1),
                "width": round(max(180.0, radius * 2.0), 1),
                "height": round(max(180.0, radius * 2.0), 1),
                "accent": accent,
                "node_count": len(chunk),
            }
        )
        for j, node in enumerate(chunk):
            angle = (2.0 * math.pi * j) / max(1, len(chunk)) - math.pi / 2.0
            nx = round(cx + radius * math.cos(angle), 1)
            ny = round(cy + radius * math.sin(angle), 1)
            positioned.append(
                {
                    "id": str(node["id"]),
                    "label": str(node.get("label") or node["id"]),
                    "kind": str(node.get("kind") or "service"),
                    "domain": str(node.get("domain") or "core"),
                    "status": _normalize_status(node),
                    "mls_badge": _extract_mls_badge(node),
                    "summary": str(node.get("summary") or ""),
                    "primary_url": str(node.get("primary_url") or ""),
                    "region_id": f"ring:{ring}",
                    "x": nx,
                    "y": ny,
                    "accent": accent,
                }
            )
        idx += cap
        ring += 1

    shift_x = max(0.0, max_r - cx + 40.0)
    shift_y = max(0.0, max_r - cy + 40.0)
    if shift_x > 0.0 or shift_y > 0.0:
        for item in positioned:
            item["x"] = round(item["x"] + shift_x, 1)
            item["y"] = round(item["y"] + shift_y, 1)
        for box in region_boxes:
            box["x"] = round(box["x"] + shift_x, 1)
            box["y"] = round(box["y"] + shift_y, 1)

    bounds = {
        "width": round((cx + shift_x) * 2.0, 1),
        "height": round((cy + shift_y) * 2.0, 1),
    }
    return positioned, region_boxes, bounds


def build_2d_world_map_layout(
    catalog: Mapping[str, Any] | None,
    *,
    mode: str = "domain_grid",
    scope: str = "",
) -> dict[str, Any]:
    """Build a pure orthographic 2D World Map layout with zero 2.5D/3D projection coupling."""
    if mode not in WORLD_MAP_2D_MODES:
        raise ValueError(f"Unsupported 2D world map mode '{mode}'. Permitted: {', '.join(WORLD_MAP_2D_MODES)}")

    cat = catalog if isinstance(catalog, Mapping) else {}
    raw_nodes = [dict(n) for n in (cat.get("nodes") or []) if isinstance(n, Mapping) and n.get("id")]
    raw_edges = [dict(e) for e in (cat.get("edges") or []) if isinstance(e, Mapping)]

    if mode == "layer_bands":
        nodes_2d, regions, bounds = _build_layer_bands_layout(raw_nodes)
    elif mode == "radial_ring":
        nodes_2d, regions, bounds = _build_radial_ring_layout(raw_nodes)
    else:
        nodes_2d, regions, bounds = _build_domain_grid_layout(raw_nodes)

    node_ids = {n["id"] for n in nodes_2d}
    edges_2d = [
        {
            "source": str(e.get("source") or ""),
            "target": str(e.get("target") or ""),
            "relation": str(e.get("relation") or e.get("type") or "relates_to"),
        }
        for e in raw_edges
        # Include only edges whose endpoints both survived filtering and layout placement.
        if str(e.get("source") or "") in node_ids and str(e.get("target") or "") in node_ids
    ]

    status_counts = {"nominal": 0, "warning": 0, "critical": 0, "unknown": 0}
    for n in nodes_2d:
        status_counts[n["status"]] = status_counts.get(n["status"], 0) + 1

    result: dict[str, Any] = {
        "schema_version": WORLD_MAP_2D_SCHEMA_VERSION,
        "engine": "standalone_2d_orthographic",
        "mode": mode,
        "available_modes": list(WORLD_MAP_2D_MODES),
        "scope": str(scope or ""),
        "bounds": bounds,
        "summary": {
            "node_count": len(nodes_2d),
            "edge_count": len(edges_2d),
            "region_count": len(regions),
            "status_counts": status_counts,
        },
        "regions": regions,
        "nodes": nodes_2d,
        "edges": edges_2d,
        "spatial_3d_route": "/world-map",
    }
    if isinstance(cat.get("security_posture"), Mapping):
        result["security_posture"] = dict(cat["security_posture"])
    return result


def _safe_json_for_script_tag(data: Any) -> str:
    """Serialize JSON safely for inline ``<script type="application/json">`` blocks."""
    raw = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_2d_world_map_html(
    catalog: Mapping[str, Any] | None = None,
    *,
    mode: str = "domain_grid",
    default_api_base: str = "",
) -> str:
    """Render the standalone orthographic 2D World Map HTML page (zero innerHTML, accessible, light/dark)."""
    layout = build_2d_world_map_layout(catalog, mode=mode)
    bootstrap_json = _safe_json_for_script_tag(
        {
            "layout": layout,
            "apiBase": str(default_api_base or "").rstrip("/"),
        }
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Standalone 2D World Map | OpsCryer</title>
  <style>
    :root {{
      --bg-light: #f8fafc;
      --bg-dark: #0b1120;
      --surface-light: #ffffff;
      --surface-dark: #111827;
      --surface-alt-light: #f1f5f9;
      --surface-alt-dark: #1e293b;
      --border-light: #cbd5e1;
      --border-dark: #334155;
      --text-light: #0f172a;
      --text-dark: #f1f5f9;
      --muted-light: #475569;
      --muted-dark: #94a3b8;
      --accent-light: #0369a1;
      --accent-dark: #38bdf8;
      --focus-light: #be123c;
      --focus-dark: #fb7185;
      --scroll-thumb-light: #64748b;
      --scroll-thumb-dark: #64748b;
      --scroll-track-light: #e2e8f0;
      --scroll-track-dark: #0f172a;

      --bg: var(--bg-light);
      --surface: var(--surface-light);
      --surface-alt: var(--surface-alt-light);
      --border: var(--border-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --accent: var(--accent-light);
      --focus: var(--focus-light);
      --scroll-thumb: var(--scroll-thumb-light);
      --scroll-track: var(--scroll-track-light);

      color-scheme: light dark;
      scrollbar-color: var(--scroll-thumb) var(--scroll-track);
    }}

    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: var(--bg-dark);
        --surface: var(--surface-dark);
        --surface-alt: var(--surface-alt-dark);
        --border: var(--border-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --accent: var(--accent-dark);
        --focus: var(--focus-dark);
        --scroll-thumb: var(--scroll-thumb-dark);
        --scroll-track: var(--scroll-track-dark);
      }}
    }}

    @supports (color: light-dark(white, black)) {{
      :root {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --surface: light-dark(var(--surface-light), var(--surface-dark));
        --surface-alt: light-dark(var(--surface-alt-light), var(--surface-alt-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --accent: light-dark(var(--accent-light), var(--accent-dark));
        --focus: light-dark(var(--focus-light), var(--focus-dark));
        --scroll-thumb: light-dark(var(--scroll-thumb-light), var(--scroll-thumb-dark));
        --scroll-track: light-dark(var(--scroll-track-light), var(--scroll-track-dark));
      }}
    }}

    @supports not (scrollbar-color: auto) {{
      .scroller {{ scrollbar-width: auto; }}
      .scroller::-webkit-scrollbar {{ width: 10px; height: 10px; }}
      .scroller::-webkit-scrollbar-thumb {{ background: var(--scroll-thumb); }}
      .scroller::-webkit-scrollbar-track {{ background: var(--scroll-track); }}
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}

    .visually-hidden:where(:not(:focus-within, :active)) {{
      position: absolute !important;
      clip-path: inset(50%) !important;
      overflow: hidden !important;
      width: 1px !important;
      height: 1px !important;
      margin: -1px !important;
      padding: 0 !important;
      border: 0 !important;
      white-space: nowrap !important;
    }}

    .skip-link:focus {{
      position: fixed;
      top: 0.75rem;
      left: 0.75rem;
      z-index: 1000;
      padding: 0.6rem 1rem;
      background: var(--surface);
      color: var(--text);
      border: 2px solid var(--focus);
      border-radius: 6px;
    }}

    :where(a:any-link, button, input, select):focus-visible {{
      outline: 3px solid var(--focus);
      outline-offset: 3px;
    }}

    header {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.25rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }}

    .brand-block h1 {{
      margin: 0;
      font-size: 1.15rem;
      line-height: 1.3;
    }}
    .brand-block p {{
      margin: 0.15rem 0 0;
      font-size: 0.85rem;
      color: var(--muted);
    }}

    nav ul {{
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    .nav-link, .ctrl-btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.35rem;
      min-block-size: 36px;
      min-inline-size: 36px;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface-alt);
      color: var(--text);
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
    }}
    .nav-link.primary-switch {{
      border-color: var(--accent);
      color: var(--accent);
    }}

    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      align-items: flex-end;
      gap: 0.75rem;
      padding: 0.75rem 1.25rem;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
    }}
    .field-group {{
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }}
    .field-group label {{
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--muted);
    }}
    .field-group input, .field-group select {{
      min-block-size: 36px;
      padding: 0.35rem 0.65rem;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      color: var(--text);
      font-size: 0.875rem;
    }}

    .zoom-controls {{
      display: flex;
      align-items: center;
      gap: 0.4rem;
      margin-left: auto;
    }}

    main {{
      flex: 1;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 320px;
      gap: 1rem;
      padding: 1rem 1.25rem;
      min-height: 0;
    }}
    @media (max-width: 960px) {{
      main {{ grid-template-columns: 1fr; }}
    }}

    .canvas-card, aside.inspector-card, .table-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }}
    .canvas-stage {{
      position: relative;
      height: 62vh;
      min-height: 420px;
      background: var(--bg);
      cursor: grab;
      overflow: hidden;
    }}
    .canvas-stage:active {{ cursor: grabbing; }}
    #map2d-svg {{
      width: 100%;
      height: 100%;
      display: block;
    }}

    aside.inspector-card {{
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      max-height: 62vh;
      overflow: auto;
    }}
    aside.inspector-card h2 {{
      margin: 0;
      font-size: 1rem;
    }}
    .kv-list {{
      margin: 0;
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.35rem 0.75rem;
      font-size: 0.85rem;
    }}
    .kv-list dt {{ color: var(--muted); font-weight: 600; }}
    .kv-list dd {{ margin: 0; word-break: break-word; }}

    .table-section {{
      padding: 0 1.25rem 1.25rem;
    }}
    .table-card {{
      padding: 0.75rem 1rem;
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }}
    caption {{
      text-align: left;
      font-weight: 600;
      margin-bottom: 0.5rem;
      color: var(--muted);
    }}
    th, td {{
      text-align: left;
      padding: 0.45rem 0.6rem;
      border-bottom: 1px solid var(--border);
    }}
    .status-pill {{
      display: inline-block;
      padding: 0.15rem 0.45rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      border: 1px solid var(--border);
    }}
  </style>
</head>
<body>
  <header>
    <a href="#map-2d-heading" class="skip-link visually-hidden">Skip to 2D World Map</a>
    <div class="brand-block">
      <h1 id="map-2d-heading" tabindex="-1">Standalone 2D World Map</h1>
      <p>Pure orthographic top-down topology decoupled from the 2.5D/3D isometric engine.</p>
    </div>
    <nav aria-label="Map views">
      <ul>
        <li><a class="nav-link" href="/">Portal Home</a></li>
        <li><a class="nav-link primary-switch" href="/world-map">Switch to 2.5D / 3D Spatial View</a></li>
      </ul>
    </nav>
  </header>

  <section class="toolbar" aria-label="2D map controls">
    <div class="field-group">
      <label for="map2d-mode">Layout Mode</label>
      <select id="map2d-mode" name="mode">
        <option value="domain_grid">Domain Grid</option>
        <option value="layer_bands">Architecture Layer Bands</option>
        <option value="radial_ring">Concentric Radial Rings</option>
      </select>
    </div>
    <div class="field-group">
      <label for="map2d-search">Filter Nodes</label>
      <input id="map2d-search" type="search" autocomplete="off" placeholder="Service, domain, or status">
    </div>
    <div class="zoom-controls">
      <button type="button" class="ctrl-btn" id="btn-zoom-in" aria-label="Zoom in 2D map">+</button>
      <button type="button" class="ctrl-btn" id="btn-zoom-out" aria-label="Zoom out 2D map">-</button>
      <button type="button" class="ctrl-btn" id="btn-zoom-reset">Reset View</button>
    </div>
  </section>

  <main>
    <div class="canvas-card">
      <div class="canvas-stage" id="map2d-stage">
        <svg id="map2d-svg" role="img" aria-label="Standalone 2D orthographic topology map">
          <title>Standalone 2D World Map Topology</title>
        </svg>
      </div>
    </div>

    <aside class="inspector-card scroller" aria-label="Selected node details">
      <h2>Node Inspector</h2>
      <p id="map2d-status-live" aria-live="polite"></p>
      <dl class="kv-list" id="map2d-inspector-dl"></dl>
    </aside>
  </main>

  <section class="table-section">
    <div class="table-card scroller">
      <table>
        <caption>Accessible tabular view of 2D World Map nodes</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Label</th>
            <th scope="col">Domain</th>
            <th scope="col">Kind</th>
            <th scope="col">Status</th>
            <th scope="col">Coordinates (X, Y)</th>
          </tr>
        </thead>
        <tbody id="map2d-table-body"></tbody>
      </table>
    </div>
  </section>

  <script id="map2d-initial-data" type="application/json">{bootstrap_json}</script>
  <script>
    (function () {{
      "use strict";
      const SVG_NS = "http://www.w3.org/2000/svg";
      const bootEl = document.getElementById("map2d-initial-data");
      const boot = bootEl ? JSON.parse(bootEl.textContent || "{{}}") : {{}};
      let currentLayout = boot.layout || {{ bounds: {{ width: 960, height: 560 }}, regions: [], nodes: [], edges: [] }};
      const apiBase = String(boot.apiBase || "");

      const svg = document.getElementById("map2d-svg");
      const stage = document.getElementById("map2d-stage");
      const modeSelect = document.getElementById("map2d-mode");
      const searchInput = document.getElementById("map2d-search");
      const statusLive = document.getElementById("map2d-status-live");
      const inspectorDl = document.getElementById("map2d-inspector-dl");
      const tableBody = document.getElementById("map2d-table-body");

      let viewBox = {{ x: 0, y: 0, w: 960, h: 560 }};
      let dragging = false;
      let dragStart = {{ x: 0, y: 0, vx: 0, vy: 0 }};

      function clearChildren(el) {{
        while (el.firstChild) {{
          el.removeChild(el.firstChild);
        }}
      }}

      function svgEl(tag, attrs) {{
        const node = document.createElementNS(SVG_NS, tag);
        Object.keys(attrs || {{}}).forEach(function (k) {{
          node.setAttribute(k, String(attrs[k]));
        }});
        return node;
      }}

      function statusStroke(status) {{
        if (status === "critical") return "#ef4444";
        if (status === "warning") return "#f59e0b";
        if (status === "unknown") return "#64748b";
        return "#10b981";
      }}

      function applyViewBox() {{
        svg.setAttribute("viewBox", [viewBox.x, viewBox.y, viewBox.w, viewBox.h].join(" "));
      }}

      function resetView() {{
        const b = currentLayout.bounds || {{ width: 960, height: 560 }};
        viewBox = {{ x: 0, y: 0, w: Number(b.width) || 960, h: Number(b.height) || 560 }};
        applyViewBox();
      }}

      function renderInspector(node) {{
        clearChildren(inspectorDl);
        if (!node) {{
          const summary = currentLayout.summary || {{}};
          statusLive.textContent =
            "Showing " + (summary.node_count || 0) + " nodes and " + (summary.edge_count || 0) +
            " edges in " + (currentLayout.mode || "domain_grid") + " mode.";
          return;
        }}
        statusLive.textContent = "Selected node " + node.label + " (" + node.status + ").";
        const pairs = [
          ["ID", node.id],
          ["Label", node.label],
          ["Domain", node.domain],
          ["Kind", node.kind],
          ["Status", node.status],
          ["Position", node.x + ", " + node.y],
          ["MLS", node.mls_badge || "Unclassified"],
          ["Summary", node.summary || "No summary recorded"]
        ];
        pairs.forEach(function (pair) {{
          const dt = document.createElement("dt");
          dt.textContent = pair[0];
          const dd = document.createElement("dd");
          dd.textContent = String(pair[1]);
          inspectorDl.appendChild(dt);
          inspectorDl.appendChild(dd);
        }});
      }}

      function renderMap() {{
        const filterText = (searchInput.value || "").trim().toLowerCase();
        const nodes = (currentLayout.nodes || []).filter(function (n) {{
          if (!filterText) return true;
          const hay = [n.id, n.label, n.domain, n.kind, n.status].join(" ").toLowerCase();
          return hay.indexOf(filterText) >= 0;
        }});
        const byId = Object.create(null);
        nodes.forEach(function (n) {{ byId[n.id] = n; }});

        clearChildren(svg);
        const titleEl = svgEl("title", {{}});
        titleEl.textContent = "Standalone 2D World Map (" + nodes.length + " nodes)";
        svg.appendChild(titleEl);

        const regionsLayer = svgEl("g", {{ "data-layer": "regions" }});
        (currentLayout.regions || []).forEach(function (reg) {{
          regionsLayer.appendChild(svgEl("rect", {{
            x: reg.x, y: reg.y, width: reg.width, height: reg.height, rx: 10,
            fill: "none", stroke: reg.accent || "#38bdf8", "stroke-width": 1.5,
            "stroke-dasharray": "6 4", opacity: 0.7
          }}));
          const lbl = svgEl("text", {{
            x: reg.x + 12, y: reg.y + 22, fill: reg.accent || "#38bdf8",
            "font-size": 13, "font-weight": 700
          }});
          lbl.textContent = reg.label + " (" + reg.node_count + ")";
          regionsLayer.appendChild(lbl);
        }});
        svg.appendChild(regionsLayer);

        const edgesLayer = svgEl("g", {{ "data-layer": "edges" }});
        (currentLayout.edges || []).forEach(function (edge) {{
          const s = byId[edge.source];
          const t = byId[edge.target];
          if (!s || !t) return;
          edgesLayer.appendChild(svgEl("line", {{
            x1: s.x, y1: s.y, x2: t.x, y2: t.y,
            stroke: "#64748b", "stroke-width": 1.4, opacity: 0.65
          }}));
        }});
        svg.appendChild(edgesLayer);

        const nodesLayer = svgEl("g", {{ "data-layer": "nodes" }});
        nodes.forEach(function (n) {{
          const g = svgEl("g", {{
            transform: "translate(" + n.x + "," + n.y + ")",
            role: "button",
            tabindex: "0",
            "aria-label": n.label + ", " + n.domain + ", " + n.status
          }});
          g.appendChild(svgEl("rect", {{
            x: -74, y: -24, width: 148, height: 48, rx: 8,
            fill: "var(--surface)", stroke: statusStroke(n.status), "stroke-width": 2
          }}));
          const txt = svgEl("text", {{
            x: 0, y: -2, "text-anchor": "middle", fill: "var(--text)",
            "font-size": 12, "font-weight": 600
          }});
          txt.textContent = String(n.label).slice(0, 20);
          g.appendChild(txt);
          const sub = svgEl("text", {{
            x: 0, y: 14, "text-anchor": "middle", fill: "var(--muted)",
            "font-size": 10
          }});
          sub.textContent = n.kind + (n.mls_badge ? " · " + n.mls_badge : "");
          g.appendChild(sub);

          g.addEventListener("click", function () {{ renderInspector(n); }});
          g.addEventListener("keydown", function (ev) {{
            if (ev.key === "Enter") renderInspector(n);
            if (ev.key === " ") ev.preventDefault();
          }});
          g.addEventListener("keyup", function (ev) {{
            if (ev.key === " ") renderInspector(n);
          }});
          nodesLayer.appendChild(g);
        }});
        svg.appendChild(nodesLayer);

        clearChildren(tableBody);
        nodes.forEach(function (n) {{
          const tr = document.createElement("tr");
          [n.id, n.label, n.domain, n.kind, n.status, n.x + ", " + n.y].forEach(function (val) {{
            const td = document.createElement("td");
            td.textContent = String(val);
            tr.appendChild(td);
          }});
          tableBody.appendChild(tr);
        }});
        renderInspector(null);
      }}

      function zoomBy(factor) {{
        const cx = viewBox.x + viewBox.w / 2;
        const cy = viewBox.y + viewBox.h / 2;
        viewBox.w = Math.max(240, Math.min(6000, viewBox.w * factor));
        viewBox.h = Math.max(160, Math.min(4000, viewBox.h * factor));
        viewBox.x = cx - viewBox.w / 2;
        viewBox.y = cy - viewBox.h / 2;
        applyViewBox();
      }}

      stage.addEventListener("pointerdown", function (ev) {{
        if (ev.button !== 0) return;
        dragging = true;
        dragStart = {{ x: ev.clientX, y: ev.clientY, vx: viewBox.x, vy: viewBox.y }};
      }});
      window.addEventListener("pointermove", function (ev) {{
        if (!dragging) return;
        const rect = stage.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        const dx = ((ev.clientX - dragStart.x) / rect.width) * viewBox.w;
        const dy = ((ev.clientY - dragStart.y) / rect.height) * viewBox.h;
        viewBox.x = dragStart.vx - dx;
        viewBox.y = dragStart.vy - dy;
        applyViewBox();
      }});
      window.addEventListener("pointerup", function () {{ dragging = false; }});
      stage.addEventListener("wheel", function (ev) {{
        ev.preventDefault();
        zoomBy(ev.deltaY > 0 ? 1.12 : 0.89);
      }}, {{ passive: false }});

      document.getElementById("btn-zoom-in").addEventListener("click", function () {{ zoomBy(0.82); }});
      document.getElementById("btn-zoom-out").addEventListener("click", function () {{ zoomBy(1.22); }});
      document.getElementById("btn-zoom-reset").addEventListener("click", resetView);
      searchInput.addEventListener("input", renderMap);

      modeSelect.value = currentLayout.mode || "domain_grid";
      modeSelect.addEventListener("change", function () {{
        const nextMode = encodeURIComponent(modeSelect.value);
        fetch(apiBase + "/api/v1/world-map-2d/layout?mode=" + nextMode)
          .then(function (r) {{ if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }})
          .then(function (data) {{
            currentLayout = data;
            resetView();
            renderMap();
          }})
          .catch(function (err) {{
            statusLive.textContent = "Failed to switch 2D layout: " + err.message;
          }});
      }});

      resetView();
      renderMap();
    }})();
  </script>
</body>
</html>
"""
