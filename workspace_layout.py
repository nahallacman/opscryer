# SPDX-License-Identifier: Apache-2.0
"""Central Workspace Layout & Panel Configurator for OpsCryer (Desktop, Iframe, and Minimal modes)."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

WORKSPACE_LAYOUT_SCHEMA_VERSION = "1.0-workspace-layout"

LAYOUT_PANELS: tuple[dict[str, str], ...] = (
    {
        "id": "portal_nav",
        "label": "Portal Navigation Bar",
        "group": "top_rows",
        "description": "Top horizontal strip of all OpsCryer suite portals.",
    },
    {
        "id": "cluster_links",
        "label": "Cluster & External Jump Strip",
        "group": "top_rows",
        "description": "Quick-launch external service buttons inside the navigation bar.",
    },
    {
        "id": "currencies_bar",
        "label": "Currencies, Theme & Adapter Bar",
        "group": "top_rows",
        "description": "RTS resource currencies, theme selector, zoom density, and adapter sync controls.",
    },
    {
        "id": "fast_finder",
        "label": "Fast Ops & Knowledge Finder",
        "group": "top_rows",
        "description": "Quick category filters and search/question bar above the main stage.",
    },
    {
        "id": "layer_ribbon",
        "label": "Layer Breadcrumb & View Ribbon",
        "group": "top_rows",
        "description": "L0-L4 ancestor trail, Dive/Ascend buttons, and Layer Boxes / World Map switch.",
    },
    {
        "id": "connection_ribbon",
        "label": "Cross-Layer Connection Ribbon",
        "group": "top_rows",
        "description": "Inbound and outbound dependency jump chips for the active focal node.",
    },
    {
        "id": "level_breakdown",
        "label": "7-Level Graph Breakdown Bar",
        "group": "top_rows",
        "description": "Project, Feature, Include/Dependency, Requirement, Test, Deployment & Contract filter pills.",
    },
    {
        "id": "tactical_ribbon",
        "label": "6-Color Tactical Status Ribbon",
        "group": "top_rows",
        "description": "Real-signal status filter ribbon (Critical, Degraded, Pending, Locked, Warning, Nominal).",
    },
    {
        "id": "bottom_console",
        "label": "Entire Bottom RTS Console",
        "group": "bottom_console",
        "description": "Master switch for the bottom console footer (Minimap, Unit Inspector, Command Card).",
    },
    {
        "id": "minimap",
        "label": "Viewport / Spatial Minimap",
        "group": "bottom_console",
        "description": "Left bottom panel showing layer blips or 2D/2.5D/3D spatial camera minimap.",
    },
    {
        "id": "unit_console",
        "label": "Unit Portrait, Vitals & Squad Grid",
        "group": "bottom_console",
        "description": "Center bottom panel showing focal unit portrait, 6 stat slots, or selected squad chips.",
    },
    {
        "id": "command_card",
        "label": "Tactical Command Card (3x3)",
        "group": "bottom_console",
        "description": "Right bottom panel containing quick-action hotkey buttons.",
    },
    {
        "id": "world_map_hud",
        "label": "World Map Overlays & Control Groups",
        "group": "integrations",
        "description": "Minor layer overlay checkboxes and RTS 1..9 control group tabs.",
    },
    {
        "id": "swarm_c2",
        "label": "Swarm C2, RAMCache & Launchpad",
        "group": "integrations",
        "description": "Optional backend-connected Swarm DDR4 RAMCache, issue broker, and launchpad dock.",
    },
    {
        "id": "dataset_sidebar",
        "label": "Dataset Tree & Self-Dogfood Sidebar",
        "group": "integrations",
        "description": "Collapsible hierarchical tri-state checklist toggling active datasets, repos (opscryer/brain/meshworks), 7 levels, and leaves.",
    },
)

PANEL_IDS: frozenset[str] = frozenset(panel["id"] for panel in LAYOUT_PANELS)

LAYOUT_PRESETS: dict[str, dict[str, Any]] = {
    "focused": {
        "preset_id": "focused",
        "label": "Focused (Clean Default)",
        "description": "Uncluttered default view: spatial graph canvas, breadcrumb bar, and selected box inspector with clickable links and live metrics.",
        "panels": {
            "portal_nav": False,
            "cluster_links": False,
            "currencies_bar": False,
            "fast_finder": False,
            "layer_ribbon": True,
            "connection_ribbon": False,
            "level_breakdown": False,
            "tactical_ribbon": False,
            "bottom_console": True,
            "minimap": False,
            "unit_console": True,
            "command_card": False,
            "world_map_hud": False,
            "swarm_c2": False,
            "dataset_sidebar": False,
        },
    },
    "full": {
        "preset_id": "full",
        "label": "Full Command (Desktop)",
        "description": "All navigation rows, RTS currencies, main stage, and full 3-pane bottom console.",
        "panels": {
            "portal_nav": True,
            "cluster_links": True,
            "currencies_bar": True,
            "fast_finder": True,
            "layer_ribbon": True,
            "connection_ribbon": True,
            "level_breakdown": True,
            "tactical_ribbon": True,
            "bottom_console": True,
            "minimap": True,
            "unit_console": True,
            "command_card": True,
            "world_map_hud": True,
            "swarm_c2": False,
            "dataset_sidebar": False,
        },
    },
    "iframe": {
        "preset_id": "iframe",
        "label": "Iframe / Embed (Compact)",
        "description": "Auto-applied inside iframes (Backstage/Grafana): hides top chrome and 3x3 card for ~85% canvas.",
        "panels": {
            "portal_nav": False,
            "cluster_links": False,
            "currencies_bar": False,
            "fast_finder": False,
            "layer_ribbon": True,
            "connection_ribbon": False,
            "level_breakdown": False,
            "tactical_ribbon": False,
            "bottom_console": True,
            "minimap": True,
            "unit_console": True,
            "command_card": False,
            "world_map_hud": True,
            "swarm_c2": False,
            "dataset_sidebar": False,
        },
    },
    "minimal": {
        "preset_id": "minimal",
        "label": "Canvas Focus (Minimal)",
        "description": "Full-bleed canvas or layer boxes with only the floating Panels trigger visible.",
        "panels": {
            "portal_nav": False,
            "cluster_links": False,
            "currencies_bar": False,
            "fast_finder": False,
            "layer_ribbon": False,
            "connection_ribbon": False,
            "level_breakdown": False,
            "tactical_ribbon": False,
            "bottom_console": False,
            "minimap": False,
            "unit_console": False,
            "command_card": False,
            "world_map_hud": False,
            "swarm_c2": False,
            "dataset_sidebar": False,
        },
    },
    "triage": {
        "preset_id": "triage",
        "label": "Triage & Search",
        "description": "Fast Ops Finder, layer breadcrumbs, and focal unit inspector without minimap or command card.",
        "panels": {
            "portal_nav": False,
            "cluster_links": False,
            "currencies_bar": False,
            "fast_finder": True,
            "layer_ribbon": True,
            "connection_ribbon": True,
            "level_breakdown": True,
            "tactical_ribbon": True,
            "bottom_console": True,
            "minimap": False,
            "unit_console": True,
            "command_card": False,
            "world_map_hud": False,
            "swarm_c2": False,
            "dataset_sidebar": False,
        },
    },
}


def sanitize_nav_links_env(raw_json: str | None = None) -> list[dict[str, str]]:
    """Parse optional OPSCRYER_NAV_LINKS_JSON into safe http(s)/relative navigation links."""
    text = (os.environ.get("OPSCRYER_NAV_LINKS_JSON", "") if raw_json is None else str(raw_json)).strip()
    if not text or len(text) > 16384:
        return []
    try:
        parsed = json.loads(text)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    safe_links: list[dict[str, str]] = []
    for item in parsed[:16]:
        if not isinstance(item, dict):
            continue
        label = " ".join(str(item.get("label") or "").split())[:48]
        href = str(item.get("href") or "").strip()
        if not label or not href or any(ord(c) < 32 or ord(c) == 127 for c in href):
            continue
        if href.startswith("/") and not href.startswith("//"):
            safe_links.append({"label": label, "href": href})
            continue
        parts = urlsplit(href)
        # Allow only explicit http/https URLs with a hostname and no embedded credentials
        if parts.scheme.lower() in {"http", "https"} and parts.hostname and not parts.username and not parts.password:
            safe_links.append({"label": label, "href": href})
    return safe_links


def parse_enabled_plugins_env(raw: str | None = None) -> list[str]:
    """Parse optional OPSCRYER_PLUGINS CSV (e.g. 'nanoswarm') into normalized opt-in plugin names."""
    text = (os.environ.get("OPSCRYER_PLUGINS", "") if raw is None else str(raw)).strip()
    if not text:
        return []
    out: list[str] = []
    for part in text.split(","):
        slug = part.strip().lower()
        if slug and slug not in out and len(slug) <= 48:
            out.append(slug)
    return out


def resolve_default_loadout_config(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve the deployment-wide default UI loadout inherited by all uncustomized users."""
    eff_env = env if env is not None else os.environ
    preset_id = "focused"
    panels = deepcopy(LAYOUT_PRESETS["focused"]["panels"])
    source = "builtin_default"

    env_preset = str(eff_env.get("OPSCRYER_DEFAULT_PRESET") or "").strip().lower()
    if env_preset in LAYOUT_PRESETS:
        preset_id = env_preset
        panels = deepcopy(LAYOUT_PRESETS[env_preset]["panels"])
        source = "env_preset"

    raw_obj: dict[str, Any] | None = None
    inline_json = str(eff_env.get("OPSCRYER_DEFAULT_LAYOUT_JSON") or "").strip()
    layout_file = str(eff_env.get("OPSCRYER_DEFAULT_LAYOUT_FILE") or "").strip()
    if inline_json and len(inline_json) <= 16384:
        try:
            parsed = json.loads(inline_json)
            if isinstance(parsed, dict):
                raw_obj = parsed
                source = "env_json"
        except Exception:
            raw_obj = None
    elif layout_file:
        try:
            p = Path(layout_file)
            if p.is_file():
                parsed = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    raw_obj = parsed
                    source = "env_file"
        except Exception:
            raw_obj = None

    if raw_obj is not None:
        raw_preset = str(raw_obj.get("preset") or "").strip().lower()
        if raw_preset in LAYOUT_PRESETS:
            preset_id = raw_preset
            panels = deepcopy(LAYOUT_PRESETS[raw_preset]["panels"])
        raw_panels = raw_obj.get("panels")
        if isinstance(raw_panels, dict):
            changed = False
            for pid, enabled in raw_panels.items():
                if pid in PANEL_IDS:
                    panels[pid] = bool(enabled)
                    changed = True
            if changed and raw_preset not in LAYOUT_PRESETS:
                preset_id = "org_default"

    digest = hashlib.sha256(
        json.dumps({"preset": preset_id, "panels": panels}, sort_keys=True).encode("utf-8")
    ).hexdigest()[:10]
    return {
        "preset": preset_id,
        "panels": panels,
        "source": source,
        "version_hash": digest,
    }


def build_workspace_config_payload(
    *,
    brain_api_enabled: bool = False,
    swarm_c2_enabled: bool = False,
    telemetry_api_enabled: bool = False,
    dogfood_dataset_default: bool = False,
    nav_links: list[dict[str, str]] | None = None,
    enabled_plugins: list[str] | None = None,
    default_loadout: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return workspace layout panels, presets, deployment-wide default loadout, and opt-in plugins."""
    eff_default = deepcopy(default_loadout) if default_loadout is not None else resolve_default_loadout_config()
    eff_plugins = list(enabled_plugins) if enabled_plugins is not None else parse_enabled_plugins_env()
    return {
        "schema_version": WORKSPACE_LAYOUT_SCHEMA_VERSION,
        "default_desktop_preset": eff_default["preset"],
        "default_iframe_preset": "iframe",
        "default_loadout": eff_default,
        "enabled_plugins": eff_plugins,
        "ask_brain_default_open": False,
        "panels": [dict(p) for p in LAYOUT_PANELS],
        "presets": deepcopy(LAYOUT_PRESETS),
        "integrations": {
            "brain_api_enabled": bool(brain_api_enabled),
            "swarm_c2_enabled": bool(swarm_c2_enabled),
            "telemetry_api_enabled": bool(telemetry_api_enabled),
            "dogfood_dataset_default": bool(dogfood_dataset_default),
            "nanoswarm_plugin_enabled": "nanoswarm" in eff_plugins,
            "nav_links": list(nav_links) if nav_links is not None else sanitize_nav_links_env(),
        },
    }


def build_workspace_layout_css() -> str:
    """Return shared CSS for central panel visibility, smart footer reflow, floating trigger, and <dialog>."""
    return r"""
    body[data-panel-portal-nav="off"] nav.page-navigation,
    body[data-panel-portal-nav="off"] header.wm-topbar { display: none !important; }
    body[data-panel-cluster-links="off"] #top-cluster-service-strip { display: none !important; }
    body[data-panel-currencies-bar="off"] #rts-top-currencies-bar { display: none !important; }
    body[data-panel-fast-finder="off"] #fast-ops-finder-bar { display: none !important; }
    body[data-panel-layer-ribbon="off"] .layer-nav-ribbon { display: none !important; }
    body[data-panel-connection-ribbon="off"] #rts-connection-ribbon { display: none !important; }
    body[data-panel-level-breakdown="off"] #graph-level-breakdown-bar { display: none !important; }
    body[data-panel-tactical-ribbon="off"] #tactical-6color-ribbon { display: none !important; }
    body[data-panel-bottom-console="off"] footer#rts-bottom-perimeter-console,
    body[data-panel-bottom-console="off"] footer.wm-console { display: none !important; }
    body[data-panel-minimap="off"] #rts-minimap-box,
    body[data-panel-minimap="off"] #wm-minimap-box { display: none !important; }
    body[data-panel-unit-console="off"] #rts-unit-console,
    body[data-panel-unit-console="off"] #wm-squad-box { display: none !important; }
    body[data-panel-command-card="off"] #rts-command-card-3x3,
    body[data-panel-command-card="off"] #wm-cmd-box { display: none !important; }
    body[data-panel-world-map-hud="off"] .inline-wm-hud-strip,
    body[data-panel-world-map-hud="off"] #inline-wm-group-grid,
    body[data-panel-world-map-hud="off"] .wm-hud-strip { display: none !important; }
    body[data-panel-swarm-c2="off"] #opscryer-swarm-c2-panel { display: none !important; }
    body[data-panel-swarm-c2="on"] #opscryer-swarm-c2-panel { display: flex; }
    body[data-plugin-nanoswarm="off"] #nanomachine-swarm-hud,
    body[data-plugin-nanoswarm="off"] .nanoswarm-plugin-only { display: none !important; }
    body[data-panel-dataset-sidebar="off"] #dataset-tree-sidebar { display: none !important; }
    body[data-panel-dataset-sidebar="on"] #dataset-tree-sidebar { display: flex; }

    #opscryer-swarm-c2-panel {
      display: none;
      flex-direction: column;
      gap: 0.4rem;
      padding: 0.55rem 0.8rem;
      background: linear-gradient(180deg, rgba(17, 28, 51, 0.96) 0%, rgba(11, 18, 34, 0.96) 100%);
      border: 1px solid var(--cyan);
      border-left: 4px solid var(--green);
      border-radius: 8px;
      font-size: 0.73rem;
    }
    .swarm-c2-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
      gap: 0.45rem;
    }
    .swarm-c2-card {
      background: rgba(2, 6, 23, 0.72);
      border: 1px solid #1E293B;
      border-radius: 6px;
      padding: 0.35rem 0.5rem;
    }
    #workspace-layout-fab {
      position: fixed;
      right: 12px;
      bottom: 12px;
      z-index: 120;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.34rem 0.68rem;
      border-radius: 999px;
      border: 1px solid var(--amber);
      background: rgba(11, 18, 34, 0.92);
      color: var(--amber);
      font-size: 0.72rem;
      font-weight: 800;
      cursor: pointer;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.65);
    }
    #workspace-layout-fab:hover {
      background: rgba(245, 158, 11, 0.2);
    }
    dialog#workspace-layout-dialog {
      border: 1px solid var(--amber);
      border-radius: 12px;
      background: #0B1222;
      color: #F8FAFC;
      max-width: 620px;
      width: 92vw;
      padding: 1rem 1.15rem;
      box-shadow: 0 20px 55px rgba(0, 0, 0, 0.85);
    }
    dialog[open]#workspace-layout-dialog {
      display: flex;
      flex-direction: column;
      gap: 0.7rem;
    }
    dialog:modal { overscroll-behavior: contain; }
    dialog::backdrop {
      background: rgba(2, 6, 23, 0.78);
      overflow: hidden;
      overscroll-behavior: contain;
    }
    .wl-preset-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }
    .wl-preset-btn.active {
      background: rgba(56, 189, 248, 0.25);
      border-color: #38BDF8;
      color: #F8FAFC;
    }
    .wl-group-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(235px, 1fr));
      gap: 0.42rem;
    }
    .wl-toggle-item {
      display: flex;
      align-items: flex-start;
      gap: 0.45rem;
      padding: 0.38rem 0.5rem;
      background: #0F172A;
      border: 1px solid #1E293B;
      border-radius: 7px;
      font-size: 0.73rem;
      cursor: pointer;
    }
    .wl-toggle-item small {
      display: block;
      color: #94A3B8;
      font-size: 0.65rem;
      margin-top: 0.1rem;
    }
    .wl-section-title {
      font-size: 0.69rem;
      font-weight: 800;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: #38BDF8;
      margin: 0.15rem 0 0.2rem 0;
    }
    """.strip()


def build_workspace_layout_dialog_html(*, include_view_switcher: bool = True) -> str:
    """Return the floating Panels button and native <dialog closedby='any'> central config panel."""
    view_switch_html = ""
    if include_view_switcher:
        view_switch_html = """
    <div>
      <div class="wl-section-title">Workspace Canvas Mode</div>
      <div class="wl-preset-row">
        <button type="button" id="wl-view-locallinks-btn" data-wl-view="local_links">🔗 Local Links (Close-Up Graph)</button>
        <button type="button" id="wl-view-boxes-btn" data-wl-view="boxes">📦 Layer Boxes (Viewport Zoom)</button>
        <button type="button" id="wl-view-worldmap-btn" data-wl-view="world_map">🌐 Spatial Map (2D / 2.5D / 3D)</button>
      </div>
    </div>"""
    return f"""
  <button type="button" id="workspace-layout-fab" aria-label="Configure visible workspace panels and rows" title="Workspace Panels &amp; Layout Config (Shift+,)">⚙️ Panels</button>

  <dialog id="workspace-layout-dialog" closedby="any" aria-labelledby="workspace-layout-title">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
      <div>
        <h2 id="workspace-layout-title" style="margin:0;font-size:1rem;color:#F59E0B;">⚙️ Workspace Rows &amp; Panels Configurator</h2>
        <div id="wl-context-subtitle" style="font-size:0.7rem;color:#94A3B8;">Toggle rows and panels on/off for full-screen, split windows, or iframe embeds.</div>
      </div>
      <form method="dialog"><button type="submit" value="close" autofocus="autofocus">✕ Close</button></form>
    </div>
    <div>
      <div class="wl-section-title">Quick Presets</div>
      <div class="wl-preset-row" id="wl-preset-buttons"></div>
    </div>{view_switch_html}
    <div>
      <div class="wl-section-title">Top Rows &amp; Navigation</div>
      <div class="wl-group-grid" id="wl-group-top_rows"></div>
    </div>
    <div>
      <div class="wl-section-title">Bottom Console &amp; Sub-Panels</div>
      <div class="wl-group-grid" id="wl-group-bottom_console"></div>
    </div>
    <div>
      <div class="wl-section-title">Overlays &amp; Optional C2 Integrations</div>
      <div class="wl-group-grid" id="wl-group-integrations"></div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;border-top:1px solid #1E293B;padding-top:0.55rem;">
      <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
        <button type="button" id="wl-copy-embed-btn" style="border-color:#38BDF8;color:#38BDF8;">📋 Copy Embed URL</button>
        <button type="button" id="wl-reset-btn" style="border-color:#94A3B8;color:#94A3B8;">↺ Reset Default</button>
      </div>
      <span id="wl-status-msg" role="status" style="font-size:0.7rem;color:#22C55E;"></span>
    </div>
  </dialog>
""".strip()


def build_workspace_layout_js() -> str:
    """Return zero-dependency Workspace Layout Configurator JS engine (zero // comments)."""
    panels_json = json.dumps([dict(p) for p in LAYOUT_PANELS], ensure_ascii=True, separators=(",", ":"))
    presets_json = json.dumps(LAYOUT_PRESETS, ensure_ascii=True, separators=(",", ":"))
    template = r"""
(function(globalScope) {
  const LAYOUT_PANELS = __LAYOUT_PANELS__;
  const LAYOUT_PRESETS = __LAYOUT_PRESETS__;
  const STORAGE_KEY = 'opscryer_layout_config_v1';
  const VALID_PANEL_IDS = new Set(LAYOUT_PANELS.map(p => p.id));

  function cloneObj(v) {
    return JSON.parse(JSON.stringify(v));
  }

  function detectIframe() {
    try {
      return typeof window !== 'undefined' && window.self !== window.top;
    } catch (_err) {
      return true;
    }
  }

  function readSavedLayout() {
    try {
      if (typeof window === 'undefined' || !window.localStorage) return null;
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return (parsed && typeof parsed === 'object') ? parsed : null;
    } catch (_err) {
      return null;
    }
  }

  function writeSavedLayout(state) {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
          customized: true,
          preset: state.preset,
          panels: state.panels
        }));
      }
    } catch (_err) {}
  }

  function clearSavedLayout() {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.removeItem(STORAGE_KEY);
      }
    } catch (_err) {}
  }

  function normalizeOrgDefault(orgDefault) {
    const basePreset = (orgDefault && orgDefault.preset && LAYOUT_PRESETS[orgDefault.preset]) ? orgDefault.preset : 'focused';
    const basePanels = cloneObj(LAYOUT_PRESETS[basePreset].panels);
    let effPreset = basePreset;
    if (orgDefault && orgDefault.panels && typeof orgDefault.panels === 'object') {
      Object.keys(orgDefault.panels).forEach(pid => {
        if (VALID_PANEL_IDS.has(pid)) basePanels[pid] = Boolean(orgDefault.panels[pid]);
      });
      if (orgDefault.preset && !LAYOUT_PRESETS[orgDefault.preset]) effPreset = String(orgDefault.preset);
    }
    return {preset: effPreset, panels: basePanels};
  }

  function resolveInitialLayout(searchStr, inIframe, savedObj, orgDefault) {
    const params = new URLSearchParams(String(searchStr || ''));
    const embedFlag = params.get('embed') === '1' || params.get('embed') === 'true';
    const rawPreset = String(params.get('preset') || (embedFlag ? 'iframe' : '')).trim().toLowerCase();
    const resolvedOrg = normalizeOrgDefault(orgDefault);
    let presetId = resolvedOrg.preset;
    let panels = cloneObj(resolvedOrg.panels);
    let source = 'default';
    let customized = false;

    const hasUserSaved = Boolean(
      savedObj && savedObj.panels && typeof savedObj.panels === 'object' && savedObj.customized !== false
    );

    if (rawPreset && LAYOUT_PRESETS[rawPreset]) {
      presetId = rawPreset;
      panels = cloneObj(LAYOUT_PRESETS[rawPreset].panels);
      source = 'url_preset';
    } else if (hasUserSaved) {
      presetId = (savedObj.preset && LAYOUT_PRESETS[savedObj.preset]) ? savedObj.preset : 'custom';
      const base = LAYOUT_PRESETS[presetId] ? cloneObj(LAYOUT_PRESETS[presetId].panels) : cloneObj(resolvedOrg.panels);
      Object.keys(savedObj.panels).forEach(pid => {
        if (VALID_PANEL_IDS.has(pid)) base[pid] = Boolean(savedObj.panels[pid]);
      });
      panels = base;
      source = 'localStorage';
      customized = true;
    } else if (inIframe) {
      presetId = 'iframe';
      panels = cloneObj(LAYOUT_PRESETS.iframe.panels);
      source = 'iframe_auto';
    }

    const hideRaw = String(params.get('hide') || '').trim();
    if (hideRaw) {
      hideRaw.split(',').map(s => s.trim().toLowerCase()).forEach(pid => {
        if (VALID_PANEL_IDS.has(pid)) { panels[pid] = false; presetId = 'custom'; }
      });
    }
    const showRaw = String(params.get('show') || '').trim();
    if (showRaw) {
      showRaw.split(',').map(s => s.trim().toLowerCase()).forEach(pid => {
        if (VALID_PANEL_IDS.has(pid)) { panels[pid] = true; presetId = 'custom'; }
      });
    }
    const viewParam = String(params.get('view') || '').trim().toLowerCase();
    const initialView = (
      viewParam === 'world_map' || viewParam === 'world-map'
      || viewParam === 'spatial_2d' || viewParam === 'spatial_25d' || viewParam === 'spatial_3d'
    )
      ? 'world_map'
      : ((viewParam === 'local_links' || viewParam === 'local-links' || viewParam === 'links')
        ? 'local_links'
        : (viewParam === 'boxes' || viewParam === 'viewport' ? 'boxes' : null));
    const projParam = String(params.get('proj') || params.get('projection') || viewParam).trim().toLowerCase();
    const initialProjection = (projParam === '2d' || projParam === 'flat_2d' || projParam === 'top_2d' || projParam === 'spatial_2d')
      ? 'flat_2d'
      : ((projParam === '3d' || projParam === 'orbit_3d' || projParam === 'cloud_3d' || projParam === 'spatial_3d')
        ? 'orbit_3d'
        : ((projParam === '2.5d' || projParam === '25d' || projParam === 'iso_25d' || projParam === 'spatial_25d') ? 'iso_25d' : null));

    return {
      preset: presetId,
      panels: panels,
      inIframe: Boolean(inIframe),
      source: source,
      customized: customized,
      initialView: initialView,
      initialProjection: initialProjection
    };
  }

  function computeFooterGridColumns(panels, mode) {
    if (!panels.bottom_console) return '';
    const cols = [];
    const miniW = mode === 'world_map' ? '245px' : '240px';
    const cmdW = mode === 'world_map' ? '290px' : '295px';
    if (panels.minimap) cols.push(miniW);
    if (panels.unit_console) cols.push('1fr');
    if (panels.command_card) cols.push(cmdW);
    if (!cols.length) return '';
    if (cols.length === 1) return '1fr';
    return cols.join(' ');
  }

  function buildEmbedUrl(baseHref, state, activeView) {
    let originPath = String(baseHref || '/');
    try {
      const u = new URL(originPath, 'http://localhost');
      u.searchParams.delete('preset');
      u.searchParams.delete('hide');
      u.searchParams.delete('show');
      u.searchParams.delete('embed');
      u.searchParams.delete('view');
      if (state.preset && LAYOUT_PRESETS[state.preset]) {
        u.searchParams.set('preset', state.preset);
      } else {
        u.searchParams.set('preset', 'full');
        const hidden = [];
        const shownExtra = [];
        LAYOUT_PANELS.forEach(p => {
          const defVal = Boolean(LAYOUT_PRESETS.full.panels[p.id]);
          const curVal = Boolean(state.panels[p.id]);
          if (defVal && !curVal) hidden.push(p.id);
          if (!defVal && curVal) shownExtra.push(p.id);
        });
        if (hidden.length) u.searchParams.set('hide', hidden.join(','));
        if (shownExtra.length) u.searchParams.set('show', shownExtra.join(','));
      }
      if (activeView === 'world_map' || activeView === 'boxes' || activeView === 'local_links') {
        u.searchParams.set('view', activeView);
      }
      return originPath.startsWith('http://') || originPath.startsWith('https://')
        ? u.toString()
        : (u.pathname + u.search);
    } catch (_err) {
      return originPath;
    }
  }

  function createWorkspaceLayoutController(opts) {
    const cfg = opts || {};
    const footerId = cfg.footerId || 'rts-bottom-perimeter-console';
    const pageMode = cfg.pageMode || 'browser';
    const searchStr = cfg.search != null ? cfg.search : ((typeof window !== 'undefined' && window.location && window.location.search) || '');
    const inIframe = cfg.inIframe != null ? Boolean(cfg.inIframe) : detectIframe();
    let runtimeOrgDefault = normalizeOrgDefault(cfg.defaultLoadout || null);
    let enabledPlugins = Array.isArray(cfg.enabledPlugins) ? cfg.enabledPlugins.slice() : [];
    const state = resolveInitialLayout(searchStr, inIframe, cfg.ignoreStorage ? null : readSavedLayout(), runtimeOrgDefault);

    function applyToDom() {
      if (typeof document === 'undefined' || !document.body) return;
      const body = document.body;
      const effBottom = Boolean(state.panels.bottom_console) && (Boolean(state.panels.minimap) || Boolean(state.panels.unit_console) || Boolean(state.panels.command_card));
      LAYOUT_PANELS.forEach(p => {
        const attr = 'data-panel-' + p.id.replace(/_/g, '-');
        const on = (p.id === 'bottom_console') ? effBottom : Boolean(state.panels[p.id]);
        if (body.setAttribute) body.setAttribute(attr, on ? 'on' : 'off');
      });
      if (body.setAttribute) {
        body.setAttribute('data-plugin-nanoswarm', enabledPlugins.indexOf('nanoswarm') >= 0 ? 'on' : 'off');
      }
      const footerEl = document.getElementById ? document.getElementById(footerId) : null;
      if (footerEl && footerEl.style) {
        const cols = computeFooterGridColumns(state.panels, pageMode);
        if (cols) footerEl.style.gridTemplateColumns = cols;
      }
      const fab = document.getElementById ? document.getElementById('workspace-layout-fab') : null;
      if (fab) {
        const activeCount = LAYOUT_PANELS.filter(p => Boolean(state.panels[p.id])).length;
        const badgeName = LAYOUT_PRESETS[state.preset] ? state.preset : (state.preset || 'custom');
        fab.textContent = '⚙️ Panels (' + activeCount + '/' + LAYOUT_PANELS.length + ' • ' + badgeName + ')';
      }
      if (typeof cfg.onLayoutChange === 'function') {
        cfg.onLayoutChange(cloneObj(state));
      }
    }

    function syncDialogControls() {
      if (typeof document === 'undefined' || typeof document.getElementById !== 'function') return;
      const sub = document.getElementById('wl-context-subtitle');
      if (sub) {
        const presetLabel = LAYOUT_PRESETS[state.preset] ? LAYOUT_PRESETS[state.preset].label : (state.preset === 'org_default' ? 'Organization Default' : 'Custom');
        const modeTxt = state.customized ? 'Personal override (Reset restores Org Default)' : 'Inheriting Org Default loadout';
        sub.textContent = (state.inIframe ? 'Iframe embed • ' : 'Standalone • ') + presetLabel + ' • ' + modeTxt;
      }
      const presetHost = document.getElementById('wl-preset-buttons');
      if (presetHost && typeof presetHost.replaceChildren === 'function') {
        const btns = Object.keys(LAYOUT_PRESETS).map(pid => {
          const p = LAYOUT_PRESETS[pid];
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'wl-preset-btn' + (state.preset === pid ? ' active' : '');
          b.textContent = p.label;
          b.title = p.description;
          b.onclick = () => applyPreset(pid);
          return b;
        });
        presetHost.replaceChildren(...btns);
      }
      const nanoswarmOn = enabledPlugins.indexOf('nanoswarm') >= 0;
      ['top_rows', 'bottom_console', 'integrations'].forEach(grp => {
        const host = document.getElementById('wl-group-' + grp);
        if (!host || typeof host.replaceChildren !== 'function') return;
        const items = LAYOUT_PANELS.filter(p => p.group === grp && (p.id !== 'swarm_c2' || nanoswarmOn || state.panels.swarm_c2)).map(p => {
          const lbl = document.createElement('label');
          lbl.className = 'wl-toggle-item';
          const chk = document.createElement('input');
          chk.type = 'checkbox';
          chk.checked = Boolean(state.panels[p.id]);
          chk.onchange = () => togglePanel(p.id, chk.checked);
          const wrap = document.createElement('span');
          const strong = document.createElement('strong');
          strong.textContent = p.label;
          const desc = document.createElement('small');
          desc.textContent = p.description;
          wrap.appendChild(strong);
          wrap.appendChild(desc);
          lbl.appendChild(chk);
          lbl.appendChild(wrap);
          return lbl;
        });
        host.replaceChildren(...items);
      });
    }

    function applyPreset(presetId) {
      if (!LAYOUT_PRESETS[presetId]) return false;
      state.preset = presetId;
      state.panels = cloneObj(LAYOUT_PRESETS[presetId].panels);
      state.customized = true;
      state.source = 'localStorage';
      writeSavedLayout(state);
      applyToDom();
      syncDialogControls();
      return true;
    }

    function togglePanel(panelId, enabled) {
      if (!VALID_PANEL_IDS.has(panelId)) return false;
      const nextVal = typeof enabled === 'boolean' ? enabled : !state.panels[panelId];
      state.panels[panelId] = nextVal;
      if (panelId !== 'bottom_console' && (panelId === 'minimap' || panelId === 'unit_console' || panelId === 'command_card') && nextVal) {
        state.panels.bottom_console = true;
      }
      state.preset = 'custom';
      state.customized = true;
      state.source = 'localStorage';
      writeSavedLayout(state);
      applyToDom();
      syncDialogControls();
      return nextVal;
    }

    function applyRuntimeDefaultLayout(orgDefault, runtimePlugins) {
      if (Array.isArray(runtimePlugins)) {
        enabledPlugins = runtimePlugins.map(s => String(s || '').trim().toLowerCase()).filter(Boolean);
      }
      if (orgDefault && typeof orgDefault === 'object') {
        runtimeOrgDefault = normalizeOrgDefault(orgDefault);
        if (!state.customized && !state.inIframe && state.source === 'default') {
          state.preset = runtimeOrgDefault.preset;
          state.panels = cloneObj(runtimeOrgDefault.panels);
        }
      }
      applyToDom();
      syncDialogControls();
      return cloneObj(state);
    }

    function resetToDefault() {
      clearSavedLayout();
      state.customized = false;
      if (state.inIframe) {
        state.preset = 'iframe';
        state.panels = cloneObj(LAYOUT_PRESETS.iframe.panels);
        state.source = 'iframe_auto';
      } else {
        state.preset = runtimeOrgDefault.preset;
        state.panels = cloneObj(runtimeOrgDefault.panels);
        state.source = 'default';
      }
      applyToDom();
      syncDialogControls();
      return state.preset;
    }

    function bindDialog() {
      if (typeof document === 'undefined' || typeof document.getElementById !== 'function') return;
      const dlg = document.getElementById('workspace-layout-dialog');
      const fab = document.getElementById('workspace-layout-fab');
      if (fab && dlg && typeof dlg.showModal === 'function') {
        fab.onclick = () => {
          syncDialogControls();
          dlg.showModal();
        };
      }
      if (dlg && typeof HTMLDialogElement !== 'undefined' && !('closedBy' in HTMLDialogElement.prototype) && typeof dlg.addEventListener === 'function') {
        const outside = (e) => {
          if (!dlg.getBoundingClientRect) return false;
          const r = dlg.getBoundingClientRect();
          return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
        };
        let pressedOutside = false;
        dlg.addEventListener('pointerdown', e => { pressedOutside = outside(e); });
        dlg.addEventListener('pointerup', e => { if (pressedOutside && outside(e) && dlg.close) dlg.close(); });
      }
      if (dlg && typeof dlg.addEventListener === 'function') {
        dlg.addEventListener('close', () => { dlg.returnValue = ''; });
      }
      const resetBtn = document.getElementById('wl-reset-btn');
      if (resetBtn) {
        resetBtn.onclick = () => {
          resetToDefault();
          const stMsg = document.getElementById('wl-status-msg');
          if (stMsg) stMsg.textContent = 'Reset to ' + (state.inIframe ? 'Iframe' : 'Full Command') + ' default.';
        };
      }
      const copyBtn = document.getElementById('wl-copy-embed-btn');
      if (copyBtn) {
        copyBtn.onclick = async () => {
          const activeView = typeof cfg.getActiveView === 'function' ? cfg.getActiveView() : null;
          const href = (typeof window !== 'undefined' && window.location && window.location.href) ? window.location.href : '/';
          const url = buildEmbedUrl(href, state, activeView);
          const stMsg = document.getElementById('wl-status-msg');
          try {
            if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
              await navigator.clipboard.writeText(url);
              if (stMsg) stMsg.textContent = 'Copied embed URL to clipboard.';
              return;
            }
          } catch (_err) {}
          if (stMsg) stMsg.textContent = url;
        };
      }
      const localBtn = document.getElementById('wl-view-locallinks-btn');
      const boxBtn = document.getElementById('wl-view-boxes-btn');
      const wmBtn = document.getElementById('wl-view-worldmap-btn');
      if (localBtn && typeof cfg.setActiveView === 'function') {
        localBtn.onclick = () => { cfg.setActiveView('local_links'); };
      }
      if (boxBtn && typeof cfg.setActiveView === 'function') {
        boxBtn.onclick = () => { cfg.setActiveView('boxes'); };
      }
      if (wmBtn && typeof cfg.setActiveView === 'function') {
        wmBtn.onclick = () => { cfg.setActiveView('world_map'); };
      }
      if (cfg.bindKeydown !== false && typeof document.addEventListener === 'function') {
        document.addEventListener('keydown', handleKeydown);
      }
    }

    function handleKeydown(ev) {
      if (typeof document === 'undefined' || typeof document.getElementById !== 'function') return false;
      const tgt = ev && ev.target;
      const tag = tgt && tgt.tagName ? String(tgt.tagName).toUpperCase() : '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return false;
      if (ev && ev.shiftKey && (ev.key === '<' || ev.key === ',' || ev.code === 'Comma')) {
        const dlg = document.getElementById('workspace-layout-dialog');
        if (dlg && typeof dlg.showModal === 'function' && !dlg.open) {
          if (ev.preventDefault) ev.preventDefault();
          syncDialogControls();
          dlg.showModal();
          return true;
        }
      }
      return false;
    }

    applyToDom();
    bindDialog();
    if (state.initialView && typeof cfg.setActiveView === 'function') {
      cfg.setActiveView(state.initialView);
    }
    if (state.initialProjection && typeof cfg.setInitialProjection === 'function') {
      cfg.setInitialProjection(state.initialProjection);
    }

    return {
      getState: () => cloneObj(state),
      applyPreset: applyPreset,
      togglePanel: togglePanel,
      applyRuntimeDefaultLayout: applyRuntimeDefaultLayout,
      resetToDefault: resetToDefault,
      buildEmbedUrl: (baseHref, activeView) => buildEmbedUrl(baseHref, state, activeView),
      applyToDom: applyToDom,
      syncDialogControls: syncDialogControls,
      handleKeydown: handleKeydown
    };
  }

  globalScope.OpsCryerWorkspaceLayout = {
    LAYOUT_PANELS: LAYOUT_PANELS,
    LAYOUT_PRESETS: LAYOUT_PRESETS,
    resolveInitialLayout: resolveInitialLayout,
    computeFooterGridColumns: computeFooterGridColumns,
    buildEmbedUrl: buildEmbedUrl,
    createWorkspaceLayoutController: createWorkspaceLayoutController
  };
})(typeof window !== 'undefined' ? window : globalThis);
""".strip()
    return (
        template.replace("__LAYOUT_PANELS__", panels_json.replace("</", "<\\/"))
        .replace("__LAYOUT_PRESETS__", presets_json.replace("</", "<\\/"))
    )
