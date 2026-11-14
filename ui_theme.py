# SPDX-License-Identifier: Apache-2.0
"""Shared OpsCryer dark theme CSS, responsive layout helpers, and navigation partial."""

from __future__ import annotations

from html import escape
from typing import Any


SHARED_PORTAL_LINKS: tuple[tuple[str, str], ...] = (
    ("/", "Spatial Browser"),
    ("/hub", "Suite Hub"),
    ("/chat", "Concierge Chat"),
    ("/incidents", "Incidents"),
    ("/capacity", "Capacity"),
    ("/network", "Network"),
    ("/gitops", "GitOps"),
    ("/executive", "Executive"),
    ("/simulator", "Simulator"),
    ("/playbooks", "Playbooks"),
    ("/models", "Model Copilot"),
    ("/games", "Game Loop"),
    ("/kb", "Knowledge Base"),
    ("/jev-eval", "Jev Eval"),
    ("/storage", "Storage"),
    ("/secops", "SecOps"),
    ("/metrics-live", "Live Metrics"),
    ("/adapters", "Adapters"),
    ("/docs", "API Docs"),
    ("/scale", "Scale"),
    ("/tactical-deck", "Tactical Deck"),
)


def render_shared_portal_css() -> str:
    """Return the shared dark-theme CSS variables and responsive grid rules."""
    return (
        ":root{color-scheme:dark;--bg:#070d17;--panel:#0e1726;--panel-2:#142136;"
        "--border:#233554;--accent:#38bdf8;--accent-2:#a855f7;--ok:#22c55e;"
        "--warn:#f59e0b;--err:#ef4444;--text:#e2e8f0;--muted:#94a3b8;"
        "font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
        "*{box-sizing:border-box}"
        "body{margin:0;background:var(--bg);color:var(--text);line-height:1.5}"
        ".opscryer-shared-nav{display:flex;flex-wrap:wrap;gap:8px;padding:10px 18px;"
        "background:#0b1322;border-bottom:1px solid var(--border);align-items:center}"
        ".opscryer-shared-nav a{color:var(--accent);text-decoration:none;font-size:.82rem;"
        "padding:4px 8px;border-radius:6px;border:1px solid transparent}"
        ".opscryer-shared-nav a[aria-current='page']{background:var(--panel-2);"
        "border-color:var(--accent);color:#fff;font-weight:600}"
        "@media (max-width:1100px){.rts-bottom-console{grid-template-columns:1fr!important;"
        "height:auto!important}}"
    )


def render_shared_portal_nav(current_path: str = "/") -> str:
    """Render an accessible HTML <nav> bar highlighting current_path."""
    items: list[str] = []
    for href, label in SHARED_PORTAL_LINKS:
        safe_href = escape(href, quote=True)
        safe_label = escape(label)
        current_attr = ' aria-current="page"' if href == current_path else ""
        items.append(f'<a href="{safe_href}"{current_attr}>{safe_label}</a>')
    return '<nav class="opscryer-shared-nav" aria-label="OpsCryer Suite Portals">' + "".join(items) + "</nav>"


def get_ui_theme_manifest() -> dict[str, Any]:
    """Return metadata describing the shared theme and registered portal links."""
    return {
        "schema_version": "1.0-opscryer-ui-theme",
        "portal_count": len(SHARED_PORTAL_LINKS),
        "routes": [href for href, _ in SHARED_PORTAL_LINKS],
        "responsive_breakpoint_px": 1100,
    }
