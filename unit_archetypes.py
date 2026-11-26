# SPDX-License-Identifier: Apache-2.0
"""Dynamic Spatial Graph node archetypes, vector SVG schematics, and strict geometry sanitizer."""

from __future__ import annotations

from copy import deepcopy
import math
import re
import threading
from typing import Any, Mapping
import xml.etree.ElementTree as ET


UNIT_ARCHETYPES_SCHEMA_VERSION = "1.0-world-map-unit-types"
MAX_CUSTOM_UNIT_TYPES = 64
MAX_SVG_BYTES = 16384
MAX_SVG_ELEMENTS = 64
MAX_SVG_DEPTH = 6
MAX_ICON_LAYERS = 16

_VALID_TYPE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_VALID_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
_VALID_SVG_HEX_RE = re.compile(r"^#(?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$")
_VALID_PATH_D_RE = re.compile(r"^[0-9eE.,+\-\sMmLlHhVvCcSsQqTtAaZz]{1,2048}$")
_VALID_POINTS_RE = re.compile(r"^[0-9eE.,+\-\s]{1,1024}$")

_SAFE_SVG_TAGS = frozenset({"svg", "g", "path", "circle", "rect", "ellipse", "line", "polygon", "polyline"})
_SAFE_SVG_COLOR_NAMES = frozenset(
    {
        "none", "transparent", "currentcolor", "white", "black", "cyan", "gold",
        "amber", "red", "green", "blue", "purple", "teal", "indigo", "sky",
        "emerald", "slate", "gray", "grey", "orange", "yellow", "pink",
    }
)
_SAFE_ICON_SHAPES = frozenset({"hex", "circle", "ring", "diamond", "rect", "star", "shield", "triangle", "cross", "pill", "path"})
_VALID_FORMATIONS = frozenset({"ring", "grid", "hex", "orbital"})
_VALID_OVERLAYS = frozenset({"health_bar", "child_count", "alert_pulse", "dependency_beam", "mls_badge"})

_FORBIDDEN_SVG_SUBSTRINGS = (
    "<!",
    "<script",
    "<foreignobject",
    "javascript:",
    "vbscript:",
    "data:",
    "url(",
    "@import",
    "expression(",
)

_DEFAULT_OVERLAYS = ["health_bar", "child_count", "alert_pulse"]

BUILTIN_UNIT_TYPES: dict[str, dict[str, Any]] = {
    "citadel_root": {
        "type_id": "citadel_root",
        "display_name": "System Root",
        "category": "command",
        "color_primary": "#38BDF8",
        "color_accent": "#F59E0B",
        "unit_scale": 1.45,
        "z_elevation": 90,
        "formation": "ring",
        "priority": 100,
        "silhouette": "root_hub",
        "match_kinds": ["company_root"],
        "match_domains": [],
        "match_prefixes": ["root-", "cluster-home"],
        "minor_overlays": ["health_bar", "child_count", "alert_pulse", "dependency_beam"],
        "builtin": True,
        "icon_layers": [
            {"shape": "hex", "cx": 32, "cy": 32, "r": 27, "fill": "#0B1222", "stroke": "#38BDF8", "stroke_width": 2.8},
            {"shape": "ring", "cx": 32, "cy": 32, "r": 18, "stroke": "#F59E0B", "stroke_width": 2.0},
            {"shape": "diamond", "cx": 32, "cy": 32, "r": 9, "fill": "#F59E0B", "stroke": "#FEF3C7", "stroke_width": 1.2},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 3.5, "fill": "#0F172A"},
        ],
    },
    "guild_team": {
        "type_id": "guild_team",
        "display_name": "Engineering Team",
        "category": "org",
        "color_primary": "#60A5FA",
        "color_accent": "#93C5FD",
        "unit_scale": 1.2,
        "z_elevation": 65,
        "formation": "hex",
        "priority": 90,
        "silhouette": "team_mesh",
        "match_kinds": ["company_team", "team", "group", "department"],
        "match_domains": [],
        "match_prefixes": ["team-", "dept-", "pillar-"],
        "minor_overlays": list(_DEFAULT_OVERLAYS),
        "builtin": True,
        "icon_layers": [
            {"shape": "hex", "cx": 32, "cy": 32, "r": 24, "fill": "#0F1E3A", "stroke": "#60A5FA", "stroke_width": 2.4},
            {"shape": "triangle", "cx": 32, "cy": 33, "r": 13, "fill": "#1D4ED8", "stroke": "#93C5FD", "stroke_width": 1.6},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 4.2, "fill": "#F8FAFC"},
        ],
    },
    "ai_construct": {
        "type_id": "ai_construct",
        "display_name": "AI Agent Runtime",
        "category": "ai",
        "color_primary": "#22C55E",
        "color_accent": "#86EFAC",
        "unit_scale": 1.1,
        "z_elevation": 58,
        "formation": "orbital",
        "priority": 85,
        "silhouette": "agent_core",
        "match_kinds": ["ai_agent_unit"],
        "match_domains": ["ai_agents"],
        "match_prefixes": ["unit-", "swarm-"],
        "minor_overlays": ["health_bar", "child_count", "alert_pulse", "dependency_beam"],
        "builtin": True,
        "icon_layers": [
            {"shape": "ring", "cx": 32, "cy": 32, "r": 24, "stroke": "#22C55E", "stroke_width": 2.4},
            {"shape": "diamond", "cx": 32, "cy": 32, "r": 16, "fill": "#052E16", "stroke": "#86EFAC", "stroke_width": 2.0},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 6.5, "fill": "#22C55E"},
        ],
    },
    "forge_project": {
        "type_id": "forge_project",
        "display_name": "Project Repository",
        "category": "code",
        "color_primary": "#A855F7",
        "color_accent": "#D8B4FE",
        "unit_scale": 1.05,
        "z_elevation": 48,
        "formation": "grid",
        "priority": 80,
        "silhouette": "repo_module",
        "match_kinds": ["engineering_project", "backstage_component", "cli_tool"],
        "match_domains": ["company_org"],
        "match_prefixes": ["proj-", "tool-", "portal-"],
        "minor_overlays": list(_DEFAULT_OVERLAYS),
        "builtin": True,
        "icon_layers": [
            {"shape": "rect", "cx": 32, "cy": 32, "w": 40, "h": 34, "fill": "#1E1035", "stroke": "#A855F7", "stroke_width": 2.4},
            {"shape": "diamond", "cx": 32, "cy": 32, "r": 11, "fill": "#7E22CE", "stroke": "#D8B4FE", "stroke_width": 1.5},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 4, "fill": "#F3E8FF"},
        ],
    },
    "k8s_nexus": {
        "type_id": "k8s_nexus",
        "display_name": "Cluster Workload",
        "category": "cluster",
        "color_primary": "#06B6D4",
        "color_accent": "#67E8F9",
        "unit_scale": 1.05,
        "z_elevation": 30,
        "formation": "hex",
        "priority": 75,
        "silhouette": "cluster_hex",
        "match_kinds": [
            "kubernetes_deployment",
            "k8s_deployment",
            "k8s_namespace",
            "kubernetes_namespace",
            "service",
        ],
        "match_domains": ["deployments_k8s"],
        "match_prefixes": ["deploy-", "k8s/Deployment", "k8s/Namespace"],
        "minor_overlays": list(_DEFAULT_OVERLAYS),
        "builtin": True,
        "icon_layers": [
            {"shape": "hex", "cx": 32, "cy": 32, "r": 24, "fill": "#082F49", "stroke": "#06B6D4", "stroke_width": 2.4},
            {"shape": "ring", "cx": 32, "cy": 32, "r": 15, "stroke": "#67E8F9", "stroke_width": 2.0},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 6.5, "fill": "#22D3EE"},
        ],
    },
    "gateway_sentinel": {
        "type_id": "gateway_sentinel",
        "display_name": "Ingress Gateway",
        "category": "network",
        "color_primary": "#818CF8",
        "color_accent": "#C7D2FE",
        "unit_scale": 0.98,
        "z_elevation": 42,
        "formation": "ring",
        "priority": 72,
        "silhouette": "ingress_prism",
        "match_kinds": ["kubernetes_ingress", "kubernetes_service"],
        "match_domains": [],
        "match_prefixes": ["ing-", "svc-", "k8s/Ingress", "k8s/Service"],
        "minor_overlays": ["health_bar", "child_count", "dependency_beam"],
        "builtin": True,
        "icon_layers": [
            {"shape": "ring", "cx": 32, "cy": 32, "r": 23, "fill": "#1E1B4B", "stroke": "#818CF8", "stroke_width": 2.4},
            {"shape": "cross", "cx": 32, "cy": 32, "r": 15, "stroke": "#C7D2FE", "stroke_width": 2.2},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 5.5, "fill": "#A5B4FC"},
        ],
    },
    "codex_process": {
        "type_id": "codex_process",
        "display_name": "Operating Process",
        "category": "process",
        "color_primary": "#14B8A6",
        "color_accent": "#5EEAD4",
        "unit_scale": 0.95,
        "z_elevation": 38,
        "formation": "grid",
        "priority": 70,
        "silhouette": "workflow_dag",
        "match_kinds": ["operational_process"],
        "match_domains": ["processes_workflows", "security_governance"],
        "match_prefixes": ["proc-"],
        "minor_overlays": ["health_bar", "child_count", "mls_badge"],
        "builtin": True,
        "icon_layers": [
            {"shape": "pill", "cx": 32, "cy": 32, "w": 42, "h": 30, "fill": "#042F2E", "stroke": "#14B8A6", "stroke_width": 2.2},
            {"shape": "rect", "cx": 32, "cy": 28, "w": 22, "h": 4, "fill": "#5EEAD4"},
            {"shape": "rect", "cx": 32, "cy": 36, "w": 16, "h": 4, "fill": "#2DD4BF"},
        ],
    },
    "knowledge_tome": {
        "type_id": "knowledge_tome",
        "display_name": "Runbook & Spec",
        "category": "knowledge",
        "color_primary": "#0EA5E9",
        "color_accent": "#7DD3FC",
        "unit_scale": 0.92,
        "z_elevation": 34,
        "formation": "grid",
        "priority": 65,
        "silhouette": "spec_blueprint",
        "match_kinds": ["knowledge_article"],
        "match_domains": [],
        "match_prefixes": ["kb-"],
        "minor_overlays": ["health_bar", "child_count", "mls_badge"],
        "builtin": True,
        "icon_layers": [
            {"shape": "rect", "cx": 32, "cy": 32, "w": 36, "h": 42, "fill": "#0C4A6E", "stroke": "#0EA5E9", "stroke_width": 2.2},
            {"shape": "rect", "cx": 22, "cy": 32, "w": 4, "h": 32, "fill": "#7DD3FC"},
            {"shape": "diamond", "cx": 36, "cy": 32, "r": 7, "fill": "#38BDF8"},
        ],
    },
    "compute_reactor": {
        "type_id": "compute_reactor",
        "display_name": "Compute & GPU Node",
        "category": "hardware",
        "color_primary": "#F59E0B",
        "color_accent": "#FDE68A",
        "unit_scale": 1.1,
        "z_elevation": 12,
        "formation": "hex",
        "priority": 60,
        "silhouette": "compute_blade",
        "match_kinds": ["physical_hardware", "hardware_node"],
        "match_domains": ["hardware_topology"],
        "match_prefixes": ["hw-", "k8s/Node"],
        "minor_overlays": list(_DEFAULT_OVERLAYS),
        "builtin": True,
        "icon_layers": [
            {"shape": "hex", "cx": 32, "cy": 32, "r": 25, "fill": "#271705", "stroke": "#F59E0B", "stroke_width": 2.4},
            {"shape": "ring", "cx": 32, "cy": 32, "r": 16, "stroke": "#FDE68A", "stroke_width": 2.0},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 6.5, "fill": "#FBBF24"},
        ],
    },
    "k8s_pod": {
        "type_id": "k8s_pod",
        "display_name": "Workload Pod",
        "category": "cluster",
        "color_primary": "#10B981",
        "color_accent": "#6EE7B7",
        "unit_scale": 0.85,
        "z_elevation": 18,
        "formation": "grid",
        "priority": 55,
        "silhouette": "pod_container",
        "match_kinds": ["kubernetes_pod", "k8s_pod"],
        "match_domains": [],
        "match_prefixes": ["pod-", "k8s/Pod"],
        "minor_overlays": list(_DEFAULT_OVERLAYS),
        "builtin": True,
        "icon_layers": [
            {"shape": "hex", "cx": 32, "cy": 32, "r": 21, "fill": "#022C22", "stroke": "#10B981", "stroke_width": 2.2},
            {"shape": "circle", "cx": 32, "cy": 32, "r": 9, "fill": "#34D399", "stroke": "#A7F3D0", "stroke_width": 1.4},
        ],
    },
}

_CUSTOM_UNIT_TYPES_LOCK = threading.Lock()
_CUSTOM_UNIT_TYPES: dict[str, dict[str, Any]] = {}


def _strip_ns(tag: str) -> str:
    text = str(tag or "").strip()
    if "}" in text:
        text = text.rsplit("}", 1)[1]
    elif ":" in text:
        text = text.rsplit(":", 1)[1]
    return text.lower()


def _parse_finite_float(raw: Any, label: str, *, min_val: float | None = None, max_val: float | None = None) -> float:
    try:
        val = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric SVG/icon value for '{label}'") from exc
    if not math.isfinite(val):
        raise ValueError(f"Non-finite SVG/icon value for '{label}'")
    if min_val is not None and val < min_val:
        raise ValueError(f"Value for '{label}' below minimum {min_val}")
    if max_val is not None and val > max_val:
        raise ValueError(f"Value for '{label}' exceeds maximum {max_val}")
    return round(val, 3)


def _validate_color(raw: Any, *, default: str | None = None) -> str | None:
    if raw is None or raw == "":
        return default
    text = str(raw).strip()
    if _VALID_SVG_HEX_RE.match(text):
        return text.upper() if len(text) == 7 else text
    low = text.lower()
    if low in _SAFE_SVG_COLOR_NAMES:
        return low
    raise ValueError(f"Unsupported color specification: {text[:32]}")


def _validate_view_box(raw: Any) -> list[float]:
    if not raw:
        return [0.0, 0.0, 64.0, 64.0]
    parts = re.split(r"[\s,]+", str(raw).strip())
    if len(parts) != 4:
        raise ValueError("SVG viewBox must contain exactly 4 numbers")
    vx = _parse_finite_float(parts[0], "viewBox.x", min_val=-4096, max_val=4096)
    vy = _parse_finite_float(parts[1], "viewBox.y", min_val=-4096, max_val=4096)
    vw = _parse_finite_float(parts[2], "viewBox.width", min_val=1.0, max_val=4096)
    vh = _parse_finite_float(parts[3], "viewBox.height", min_val=1.0, max_val=4096)
    return [vx, vy, vw, vh]


def _validate_svg_points(raw: str) -> list[float]:
    text = str(raw or "").strip()
    if not text or not _VALID_POINTS_RE.match(text):
        raise ValueError("Invalid SVG polygon/polyline points attribute")
    nums = [
        _parse_finite_float(tok, "points", min_val=-4096, max_val=4096)
        for tok in re.split(r"[\s,]+", text)
        if tok
    ]
    if len(nums) < 4 or len(nums) % 2 != 0:
        raise ValueError("SVG points attribute must contain even coordinate pairs (>= 4 values)")
    return nums


def sanitize_custom_svg(raw_svg: str) -> dict[str, Any]:
    """Parse and sanitize custom SVG into pure geometric Canvas primitives (zero DOM HTML)."""
    if not isinstance(raw_svg, str) or not raw_svg.strip():
        raise ValueError("SVG markup must be a non-empty string")
    raw_bytes = raw_svg.encode("utf-8", errors="strict")
    if len(raw_bytes) > MAX_SVG_BYTES:
        raise ValueError(f"SVG markup exceeds {MAX_SVG_BYTES} byte limit")
    for ch in raw_svg:
        code = ord(ch)
        if (code < 32 and ch not in ("\t", "\n", "\r")) or code == 127:
            raise ValueError("SVG contains disallowed control characters")

    lowered = raw_svg.lower()
    for bad in _FORBIDDEN_SVG_SUBSTRINGS:
        if bad in lowered:
            raise ValueError(f"SVG contains forbidden construct: {bad}")

    try:
        root = ET.fromstring(raw_svg)
    except ET.ParseError as exc:
        raise ValueError("Malformed SVG XML markup") from exc

    if _strip_ns(root.tag) != "svg":
        raise ValueError("Root element of custom icon must be <svg>")

    view_box = _validate_view_box(root.attrib.get("viewBox"))
    primitives: list[dict[str, Any]] = []
    elem_count = 0

    def _walk(node: ET.Element, depth: int, inherited_style: dict[str, Any]) -> None:
        nonlocal elem_count
        if depth > MAX_SVG_DEPTH:
            raise ValueError(f"SVG nesting depth exceeds limit ({MAX_SVG_DEPTH})")
        tag = _strip_ns(node.tag)
        if tag not in _SAFE_SVG_TAGS:
            raise ValueError(f"Disallowed SVG element <{tag}>")

        elem_count += 1
        if elem_count > MAX_SVG_ELEMENTS:
            raise ValueError(f"SVG element count exceeds limit ({MAX_SVG_ELEMENTS})")

        for attr_key in node.attrib:
            local_attr = _strip_ns(attr_key)
            if (
                local_attr.startswith("on")
                or local_attr in {"href", "style", "filter", "clip-path", "mask", "xmlns"}
                and local_attr != "xmlns"
            ):
                raise ValueError(f"Disallowed SVG attribute '{local_attr}'")
            if ":" in attr_key and attr_key.lower().endswith(":href"):
                raise ValueError("Disallowed SVG xlink:href attribute")

        style = dict(inherited_style)
        if "fill" in node.attrib:
            style["fill"] = _validate_color(node.attrib["fill"], default="none")
        if "stroke" in node.attrib:
            style["stroke"] = _validate_color(node.attrib["stroke"], default="none")
        if "stroke-width" in node.attrib:
            style["stroke_width"] = _parse_finite_float(
                node.attrib["stroke-width"], "stroke-width", min_val=0.0, max_val=64.0
            )
        if "opacity" in node.attrib:
            style["opacity"] = _parse_finite_float(
                node.attrib["opacity"], "opacity", min_val=0.0, max_val=1.0
            )

        if tag == "path":
            d_val = str(node.attrib.get("d") or "").strip()
            if not d_val or not _VALID_PATH_D_RE.match(d_val):
                raise ValueError("Invalid or empty SVG <path d> geometry")
            primitives.append({"tag": "path", "d": d_val, **style})
        elif tag == "circle":
            primitives.append(
                {
                    "tag": "circle",
                    "cx": _parse_finite_float(node.attrib.get("cx", 0), "cx", min_val=-4096, max_val=4096),
                    "cy": _parse_finite_float(node.attrib.get("cy", 0), "cy", min_val=-4096, max_val=4096),
                    "r": _parse_finite_float(node.attrib.get("r", 1), "r", min_val=0.1, max_val=4096),
                    **style,
                }
            )
        elif tag == "rect":
            primitives.append(
                {
                    "tag": "rect",
                    "x": _parse_finite_float(node.attrib.get("x", 0), "x", min_val=-4096, max_val=4096),
                    "y": _parse_finite_float(node.attrib.get("y", 0), "y", min_val=-4096, max_val=4096),
                    "w": _parse_finite_float(node.attrib.get("width", 1), "width", min_val=0.1, max_val=4096),
                    "h": _parse_finite_float(node.attrib.get("height", 1), "height", min_val=0.1, max_val=4096),
                    "rx": _parse_finite_float(node.attrib.get("rx", 0), "rx", min_val=0.0, max_val=512),
                    **style,
                }
            )
        elif tag == "ellipse":
            primitives.append(
                {
                    "tag": "ellipse",
                    "cx": _parse_finite_float(node.attrib.get("cx", 0), "cx", min_val=-4096, max_val=4096),
                    "cy": _parse_finite_float(node.attrib.get("cy", 0), "cy", min_val=-4096, max_val=4096),
                    "rx": _parse_finite_float(node.attrib.get("rx", 1), "rx", min_val=0.1, max_val=4096),
                    "ry": _parse_finite_float(node.attrib.get("ry", 1), "ry", min_val=0.1, max_val=4096),
                    **style,
                }
            )
        elif tag == "line":
            primitives.append(
                {
                    "tag": "line",
                    "x1": _parse_finite_float(node.attrib.get("x1", 0), "x1", min_val=-4096, max_val=4096),
                    "y1": _parse_finite_float(node.attrib.get("y1", 0), "y1", min_val=-4096, max_val=4096),
                    "x2": _parse_finite_float(node.attrib.get("x2", 0), "x2", min_val=-4096, max_val=4096),
                    "y2": _parse_finite_float(node.attrib.get("y2", 0), "y2", min_val=-4096, max_val=4096),
                    **style,
                }
            )
        elif tag in {"polygon", "polyline"}:
            primitives.append(
                {
                    "tag": tag,
                    "points": _validate_svg_points(node.attrib.get("points", "")),
                    **style,
                }
            )

        for child in list(node):
            _walk(child, depth + 1, style)

    _walk(root, 0, {})
    if not primitives:
        raise ValueError("Custom SVG must contain at least one visible geometry primitive")
    return {
        "view_box": view_box,
        "primitives": primitives,
        "element_count": len(primitives),
    }


# Production-grade 64x64 technical vector schematics replacing placeholder geometric primitives
_BUILTIN_SVG_MARKUP: dict[str, str] = {
    "citadel_root": (
        '<svg viewBox="0 0 64 64">'
        '<circle cx="32" cy="32" r="22" fill="none" stroke="#38BDF8" stroke-width="2" opacity="0.55"/>'
        '<polygon points="32,8 52,20 52,44 32,56 12,44 12,20" fill="#0B162C" stroke="#38BDF8" stroke-width="2.4"/>'
        '<line x1="32" y1="8" x2="32" y2="21" stroke="#7DD3FC" stroke-width="2"/>'
        '<line x1="32" y1="43" x2="32" y2="56" stroke="#7DD3FC" stroke-width="2"/>'
        '<line x1="12" y1="32" x2="21" y2="32" stroke="#7DD3FC" stroke-width="2"/>'
        '<line x1="43" y1="32" x2="52" y2="32" stroke="#7DD3FC" stroke-width="2"/>'
        '<circle cx="32" cy="32" r="10" fill="#172554" stroke="#F59E0B" stroke-width="2.2"/>'
        '<circle cx="32" cy="32" r="4.5" fill="#FBBF24"/>'
        '</svg>'
    ),
    "guild_team": (
        '<svg viewBox="0 0 64 64">'
        '<line x1="32" y1="17" x2="17" y2="43" stroke="#60A5FA" stroke-width="2.2"/>'
        '<line x1="32" y1="17" x2="47" y2="43" stroke="#60A5FA" stroke-width="2.2"/>'
        '<line x1="17" y1="43" x2="47" y2="43" stroke="#60A5FA" stroke-width="2.2"/>'
        '<line x1="32" y1="17" x2="32" y2="34" stroke="#93C5FD" stroke-width="1.6"/>'
        '<line x1="17" y1="43" x2="32" y2="34" stroke="#93C5FD" stroke-width="1.6"/>'
        '<line x1="47" y1="43" x2="32" y2="34" stroke="#93C5FD" stroke-width="1.6"/>'
        '<circle cx="32" cy="17" r="6.5" fill="#1D4ED8" stroke="#93C5FD" stroke-width="2"/>'
        '<circle cx="17" cy="43" r="6.5" fill="#1D4ED8" stroke="#93C5FD" stroke-width="2"/>'
        '<circle cx="47" cy="43" r="6.5" fill="#1D4ED8" stroke="#93C5FD" stroke-width="2"/>'
        '<circle cx="32" cy="34" r="5" fill="#EFF6FF"/>'
        '</svg>'
    ),
    "ai_construct": (
        '<svg viewBox="0 0 64 64">'
        '<rect x="18" y="18" width="28" height="28" rx="5" fill="#052E16" stroke="#22C55E" stroke-width="2.4"/>'
        '<line x1="25" y1="10" x2="25" y2="18" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="32" y1="10" x2="32" y2="18" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="39" y1="10" x2="39" y2="18" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="25" y1="46" x2="25" y2="54" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="32" y1="46" x2="32" y2="54" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="39" y1="46" x2="39" y2="54" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="10" y1="26" x2="18" y2="26" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="10" y1="38" x2="18" y2="38" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="46" y1="26" x2="54" y2="26" stroke="#86EFAC" stroke-width="2"/>'
        '<line x1="46" y1="38" x2="54" y2="38" stroke="#86EFAC" stroke-width="2"/>'
        '<polygon points="32,22 42,32 32,42 22,32" fill="#16A34A" stroke="#BBF7D0" stroke-width="1.6"/>'
        '<circle cx="32" cy="32" r="3.5" fill="#ECFDF5"/>'
        '</svg>'
    ),
    "forge_project": (
        '<svg viewBox="0 0 64 64">'
        '<rect x="12" y="13" width="40" height="38" rx="6" fill="#1E1035" stroke="#A855F7" stroke-width="2.2"/>'
        '<line x1="23" y1="21" x2="23" y2="43" stroke="#E9D5FF" stroke-width="2.4"/>'
        '<path d="M23 36 C23 28 40 31 40 23" fill="none" stroke="#C084FC" stroke-width="2.4"/>'
        '<circle cx="23" cy="21" r="4" fill="#A855F7" stroke="#F3E8FF" stroke-width="1.5"/>'
        '<circle cx="23" cy="43" r="4" fill="#A855F7" stroke="#F3E8FF" stroke-width="1.5"/>'
        '<circle cx="40" cy="23" r="4" fill="#F59E0B" stroke="#FEF3C7" stroke-width="1.5"/>'
        '</svg>'
    ),
    "k8s_nexus": (
        '<svg viewBox="0 0 64 64">'
        '<polygon points="32,9 51,20 51,44 32,55 13,44 13,20" fill="#082F49" stroke="#06B6D4" stroke-width="2.4"/>'
        '<circle cx="32" cy="32" r="13" fill="none" stroke="#67E8F9" stroke-width="1.8" opacity="0.8"/>'
        '<line x1="32" y1="13" x2="32" y2="25" stroke="#A5F3FC" stroke-width="2"/>'
        '<line x1="32" y1="39" x2="32" y2="51" stroke="#A5F3FC" stroke-width="2"/>'
        '<line x1="15" y1="22" x2="26" y2="28" stroke="#A5F3FC" stroke-width="2"/>'
        '<line x1="38" y1="36" x2="49" y2="42" stroke="#A5F3FC" stroke-width="2"/>'
        '<line x1="49" y1="22" x2="38" y2="28" stroke="#A5F3FC" stroke-width="2"/>'
        '<line x1="26" y1="36" x2="15" y2="42" stroke="#A5F3FC" stroke-width="2"/>'
        '<circle cx="32" cy="32" r="5.5" fill="#22D3EE" stroke="#ECFEFF" stroke-width="1.4"/>'
        '</svg>'
    ),
    "gateway_sentinel": (
        '<svg viewBox="0 0 64 64">'
        '<polygon points="32,10 53,32 32,54 11,32" fill="#1E1B4B" stroke="#818CF8" stroke-width="2.3"/>'
        '<line x1="14" y1="32" x2="50" y2="32" stroke="#A5B4FC" stroke-width="2"/>'
        '<polyline points="24,23 33,32 24,41" fill="none" stroke="#E0E7FF" stroke-width="2.4"/>'
        '<polyline points="35,23 44,32 35,41" fill="none" stroke="#38BDF8" stroke-width="2.4"/>'
        '<circle cx="17" cy="32" r="3" fill="#22C55E"/>'
        '</svg>'
    ),
    "codex_process": (
        '<svg viewBox="0 0 64 64">'
        '<rect x="11" y="14" width="42" height="36" rx="6" fill="#042F2E" stroke="#14B8A6" stroke-width="2.2"/>'
        '<line x1="20" y1="32" x2="44" y2="32" stroke="#5EEAD4" stroke-width="2"/>'
        '<line x1="24" y1="32" x2="32" y2="22" stroke="#5EEAD4" stroke-width="1.6"/>'
        '<line x1="32" y1="22" x2="44" y2="32" stroke="#5EEAD4" stroke-width="1.6"/>'
        '<circle cx="20" cy="32" r="4.2" fill="#2DD4BF" stroke="#CCFBF1" stroke-width="1.4"/>'
        '<polygon points="32,17 37,22 32,27 27,22" fill="#F59E0B" stroke="#FEF3C7" stroke-width="1.2"/>'
        '<rect x="39" y="28" width="8" height="8" rx="2" fill="#14B8A6" stroke="#CCFBF1" stroke-width="1.4"/>'
        '</svg>'
    ),
    "knowledge_tome": (
        '<svg viewBox="0 0 64 64">'
        '<polygon points="15,11 41,11 49,19 49,53 15,53" fill="#0C4A6E" stroke="#0EA5E9" stroke-width="2.2"/>'
        '<polyline points="41,11 41,19 49,19" fill="none" stroke="#7DD3FC" stroke-width="2"/>'
        '<line x1="22" y1="26" x2="42" y2="26" stroke="#BAE6FD" stroke-width="2.2"/>'
        '<line x1="22" y1="34" x2="42" y2="34" stroke="#7DD3FC" stroke-width="2.2"/>'
        '<line x1="22" y1="42" x2="34" y2="42" stroke="#38BDF8" stroke-width="2.2"/>'
        '<circle cx="41" cy="43" r="4.5" fill="#22C55E" stroke="#DCFCE7" stroke-width="1.3"/>'
        '</svg>'
    ),
    "compute_reactor": (
        '<svg viewBox="0 0 64 64">'
        '<rect x="12" y="13" width="40" height="16" rx="4" fill="#271705" stroke="#F59E0B" stroke-width="2.2"/>'
        '<rect x="12" y="35" width="40" height="16" rx="4" fill="#271705" stroke="#F59E0B" stroke-width="2.2"/>'
        '<circle cx="19" cy="21" r="2.8" fill="#22C55E"/>'
        '<circle cx="19" cy="43" r="2.8" fill="#FBBF24"/>'
        '<line x1="26" y1="21" x2="45" y2="21" stroke="#FDE68A" stroke-width="2.2"/>'
        '<line x1="26" y1="43" x2="45" y2="43" stroke="#FDE68A" stroke-width="2.2"/>'
        '<line x1="32" y1="29" x2="32" y2="35" stroke="#F59E0B" stroke-width="2.2"/>'
        '</svg>'
    ),
    "k8s_pod": (
        '<svg viewBox="0 0 64 64">'
        '<polygon points="32,11 50,21 32,31 14,21" fill="#065F46" stroke="#6EE7B7" stroke-width="2"/>'
        '<polygon points="14,21 32,31 32,52 14,42" fill="#064E3B" stroke="#10B981" stroke-width="2"/>'
        '<polygon points="50,21 32,31 32,52 50,42" fill="#022C22" stroke="#34D399" stroke-width="2"/>'
        '<circle cx="32" cy="21" r="2.6" fill="#A7F3D0"/>'
        '</svg>'
    ),
}


def _populate_builtin_svg_specs() -> None:
    for tid, markup in _BUILTIN_SVG_MARKUP.items():
        if tid in BUILTIN_UNIT_TYPES:
            BUILTIN_UNIT_TYPES[tid]["svg_spec"] = sanitize_custom_svg(markup)


_populate_builtin_svg_specs()


def _validate_icon_layer(layer: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(layer, Mapping):
        raise ValueError("Each icon layer must be an object")
    shape = str(layer.get("shape") or "").strip().lower()
    if shape not in _SAFE_ICON_SHAPES:
        raise ValueError(f"Unsupported icon layer shape '{shape}'")
    out: dict[str, Any] = {
        "shape": shape,
        "cx": _parse_finite_float(layer.get("cx", 32), "cx", min_val=0, max_val=64),
        "cy": _parse_finite_float(layer.get("cy", 32), "cy", min_val=0, max_val=64),
    }
    if "r" in layer:
        out["r"] = _parse_finite_float(layer["r"], "r", min_val=1, max_val=32)
    if "w" in layer:
        out["w"] = _parse_finite_float(layer["w"], "w", min_val=1, max_val=64)
    if "h" in layer:
        out["h"] = _parse_finite_float(layer["h"], "h", min_val=1, max_val=64)
    if "fill" in layer and layer["fill"] is not None:
        out["fill"] = _validate_color(layer["fill"])
    if "stroke" in layer and layer["stroke"] is not None:
        out["stroke"] = _validate_color(layer["stroke"])
    if "stroke_width" in layer:
        out["stroke_width"] = _parse_finite_float(layer["stroke_width"], "stroke_width", min_val=0.2, max_val=10.0)
    if "opacity" in layer:
        out["opacity"] = _parse_finite_float(layer["opacity"], "opacity", min_val=0.05, max_val=1.0)
    if shape == "path":
        d_val = str(layer.get("d") or "").strip()
        if not d_val or not _VALID_PATH_D_RE.match(d_val):
            raise ValueError("Icon layer with shape='path' requires a valid SVG path 'd'")
        out["d"] = d_val
    return out


def _sanitize_str_list(raw: Any, *, field: str, max_items: int = 32, max_len: int = 64) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"'{field}' must be a list of strings")
    items: list[str] = []
    for entry in raw[:max_items]:
        text = str(entry or "").strip()
        if not text or len(text) > max_len or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise ValueError(f"Invalid item in '{field}'")
        if text not in items:
            items.append(text)
    return items


def validate_and_normalize_unit_type(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize a custom Unit Type definition for World Map rendering."""
    if not isinstance(payload, Mapping):
        raise ValueError("Unit type payload must be a JSON object")

    type_id = str(payload.get("type_id") or "").strip().lower()
    if not _VALID_TYPE_ID_RE.match(type_id):
        raise ValueError("type_id must match ^[a-z0-9][a-z0-9_-]{1,47}$")

    display_name = " ".join(str(payload.get("display_name") or "").split())
    if not display_name or len(display_name) > 64 or any(ord(c) < 32 or ord(c) == 127 for c in display_name):
        raise ValueError("display_name must be 1..64 printable characters")

    category = str(payload.get("category") or "custom").strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", category):
        raise ValueError("category must match ^[a-z0-9_-]{1,32}$")

    color_primary = str(payload.get("color_primary") or "#38BDF8").strip()
    color_accent = str(payload.get("color_accent") or "#F59E0B").strip()
    if not _VALID_HEX_COLOR_RE.match(color_primary) or not _VALID_HEX_COLOR_RE.match(color_accent):
        raise ValueError("color_primary and color_accent must be #RRGGBB hex colors")

    unit_scale = _parse_finite_float(payload.get("unit_scale", 1.0), "unit_scale", min_val=0.5, max_val=2.5)
    z_elevation = int(_parse_finite_float(payload.get("z_elevation", 36), "z_elevation", min_val=0, max_val=200))
    formation = str(payload.get("formation") or "hex").strip().lower()
    if formation not in _VALID_FORMATIONS:
        raise ValueError(f"formation must be one of {sorted(_VALID_FORMATIONS)}")
    priority = int(_parse_finite_float(payload.get("priority", 82), "priority", min_val=0, max_val=100))

    match_kinds = _sanitize_str_list(payload.get("match_kinds"), field="match_kinds")
    match_domains = _sanitize_str_list(payload.get("match_domains"), field="match_domains")
    match_prefixes = _sanitize_str_list(payload.get("match_prefixes"), field="match_prefixes")

    raw_overlays = payload.get("minor_overlays")
    if raw_overlays is None:
        minor_overlays = list(_DEFAULT_OVERLAYS)
    else:
        minor_overlays = _sanitize_str_list(raw_overlays, field="minor_overlays", max_items=8)
        for ov in minor_overlays:
            if ov not in _VALID_OVERLAYS:
                raise ValueError(f"Unsupported minor overlay '{ov}'")

    raw_layers = payload.get("icon_layers") or []
    if not isinstance(raw_layers, (list, tuple)):
        raise ValueError("icon_layers must be a list")
    if len(raw_layers) > MAX_ICON_LAYERS:
        raise ValueError(f"icon_layers exceeds {MAX_ICON_LAYERS} layer limit")
    icon_layers = [_validate_icon_layer(layer) for layer in raw_layers]

    svg_spec: dict[str, Any] | None = None
    raw_svg = payload.get("custom_svg")
    if raw_svg is not None and str(raw_svg).strip():
        svg_spec = sanitize_custom_svg(str(raw_svg))

    if not icon_layers and svg_spec is None:
        icon_layers = [
            {"shape": "hex", "cx": 32.0, "cy": 32.0, "r": 24.0, "fill": "#0F172A", "stroke": color_primary.upper(), "stroke_width": 2.6},
            {"shape": "diamond", "cx": 32.0, "cy": 32.0, "r": 12.0, "fill": color_accent.upper()},
        ]

    return {
        "type_id": type_id,
        "display_name": display_name,
        "category": category,
        "color_primary": color_primary.upper(),
        "color_accent": color_accent.upper(),
        "unit_scale": unit_scale,
        "z_elevation": z_elevation,
        "formation": formation,
        "priority": priority,
        "silhouette": str(payload.get("silhouette") or ("custom_svg" if svg_spec else "custom_layered")),
        "match_kinds": match_kinds,
        "match_domains": match_domains,
        "match_prefixes": match_prefixes,
        "minor_overlays": minor_overlays,
        "builtin": False,
        "icon_layers": icon_layers,
        **({"svg_spec": svg_spec} if svg_spec is not None else {}),
    }


def list_unit_types() -> dict[str, dict[str, Any]]:
    """Return a merged detached copy of built-in and registered custom Unit Types."""
    merged = deepcopy(BUILTIN_UNIT_TYPES)
    with _CUSTOM_UNIT_TYPES_LOCK:
        for tid, spec in _CUSTOM_UNIT_TYPES.items():
            merged[tid] = deepcopy(spec)
    return merged


def upsert_custom_unit_type(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and register or update a custom Unit Type in the session registry."""
    normalized = validate_and_normalize_unit_type(payload)
    tid = normalized["type_id"]
    with _CUSTOM_UNIT_TYPES_LOCK:
        if tid not in _CUSTOM_UNIT_TYPES and len(_CUSTOM_UNIT_TYPES) >= MAX_CUSTOM_UNIT_TYPES:
            raise ValueError(f"Custom unit type limit ({MAX_CUSTOM_UNIT_TYPES}) reached")
        _CUSTOM_UNIT_TYPES[tid] = deepcopy(normalized)
    return deepcopy(normalized)


def delete_custom_unit_type(type_id: str) -> bool:
    """Remove a custom Unit Type override (never removes built-in IDs if not overridden)."""
    cleaned = str(type_id or "").strip().lower()
    with _CUSTOM_UNIT_TYPES_LOCK:
        return _CUSTOM_UNIT_TYPES.pop(cleaned, None) is not None


def reset_custom_unit_types() -> None:
    """Clear all session custom Unit Types (primarily for test isolation)."""
    with _CUSTOM_UNIT_TYPES_LOCK:
        _CUSTOM_UNIT_TYPES.clear()


def resolve_node_unit_type(
    node: Mapping[str, Any],
    unit_types: Mapping[str, Mapping[str, Any]],
    node_overrides: Mapping[str, str] | None = None,
) -> str:
    """Deterministically resolve a Knowledge Graph node's World Map Unit Type."""
    nid = str(node.get("id") or "")
    if node_overrides and nid in node_overrides and node_overrides[nid] in unit_types:
        return str(node_overrides[nid])

    explicit_type = str(node.get("unit_type") or "").strip().lower()
    alias_map = {
        "system_root": "citadel_root",
        "team_unit": "guild_team",
        "project_repo": "forge_project",
        "cluster_workload": "k8s_nexus",
    }
    explicit_type = alias_map.get(explicit_type, explicit_type)
    if explicit_type and explicit_type in unit_types:
        return explicit_type

    kind = str(node.get("kind") or "").strip().lower()
    domain = str(node.get("domain") or "").strip().lower()
    rkind = str(node.get("resource_kind") or (node.get("resource") or {}).get("kind") or "").strip().lower()
    nid_low = nid.lower()

    best_id = "forge_project" if "forge_project" in unit_types else next(iter(unit_types), "citadel_root")
    best_score = -1

    for tid, spec in unit_types.items():
        score = 0
        kinds_low = {str(k).lower() for k in (spec.get("match_kinds") or ())}
        domains_low = {str(d).lower() for d in (spec.get("match_domains") or ())}
        prefixes_low = tuple(str(p).lower() for p in (spec.get("match_prefixes") or ()))

        if nid_low and any(nid_low.startswith(pref) for pref in prefixes_low):
            score += 5
        if kind in kinds_low or (rkind and f"k8s_{rkind}" in kinds_low) or (rkind and f"kubernetes_{rkind}" in kinds_low):
            score += 4
        if domain in domains_low:
            score += 1

        if score <= 0:
            continue
        is_custom = 1 if not spec.get("builtin", True) else 0
        total = score * 1000 + is_custom * 200 + int(spec.get("priority", 50))
        if total > best_score:
            best_score = total
            best_id = tid

    return best_id
