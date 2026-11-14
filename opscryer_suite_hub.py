# SPDX-License-Identifier: Apache-2.0
"""Sanitized entrypoint catalog for the OpsCryer application suite."""

import argparse
import json
from html import escape
import os
from pathlib import Path
import re
import stat
import socketserver
import tempfile

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


def _validate_bundle_destination(output_dir, filenames):
    """Reject ambiguous paths, links (including junctions), and special files."""
    try:
        raw = os.fspath(output_dir)
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError
        path = Path(raw)
        if ".." in path.parts or path == Path("."):
            raise ValueError
        path = path.absolute()
        if path == Path(path.anchor) or str(path.anchor).startswith("\\\\"):
            raise ValueError
        # Windows device names, alternate data streams, and trailing dots/spaces
        # can alias a different filesystem object than the caller requested.
        for part in path.parts[1:]:
            if (":" in part or part.endswith((".", " "))
                    or Path(part).is_reserved()):
                raise ValueError
        for candidate in (*reversed(path.parents), path,
                          *(path / name for name in filenames)):
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400):
                raise ValueError
            if candidate == path or candidate in path.parents:
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError
        return path
    except (OSError, TypeError, ValueError):
        raise ValueError("Unsafe suite bundle output directory") from None


def export_full_suite_static_bundle(output_dir, catalog=None) -> dict:
    """Export eight offline HTML snapshots and the suite catalog using UTF-8/LF.

    Accept the same graph dictionary or JSON path as the application builders.
    Navigation works with file URLs and static hosting, without API requests.
    Existing regular output files are replaced; links and special files fail
    closed. The manifest contains fixed basenames, never caller filesystem paths.
    """
    filenames = ("index.html", "chat.html", "incidents.html", "capacity.html",
                 "network.html", "gitops.html", "executive.html", "hub.html",
                 "suite-catalog.json")
    destination = _validate_bundle_destination(output_dir, filenames)

    from capacity_planner import render_capacity_planner_html
    from executive_command_center import render_executive_command_center_html
    from gitops_release_cockpit import render_gitops_cockpit_html
    from incident_commander import DEFAULT_CATALOG_PATH, render_incident_commander_html
    from network_topology_inspector import render_network_inspector_html
    from ticket_chat_portal import QUICK_REPLIES, ask_concierge_chat

    try:
        snapshot = catalog
        if snapshot is None or isinstance(snapshot, (str, Path)):
            snapshot = json.loads(Path(DEFAULT_CATALOG_PATH if snapshot is None
                                       else snapshot).read_text(encoding="utf-8"))
        if snapshot is None:
            raise ValueError("Invalid suite bundle catalog")
        snapshot = sanitize(snapshot)
        suite = build_suite_application_catalog(snapshot)
        routes = {app["route"]: name for app, name in
                  zip(suite["applications"], filenames)}
        navigation = '<nav aria-label="Suite applications">' + " | ".join(
            '<a href="' + routes[app["route"]] + '">' + escape(app["title"]) + '</a>'
            for app in suite["applications"]) + '</nav>'

        def snapshot_page(title, evidence):
            payload = escape(json.dumps(sanitize(evidence), indent=2, allow_nan=False))
            return ('<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width, initial-scale=1">'
                    '<title>' + escape(title) + '</title><style>'
                    'body{background:#0b1220;color:#e2e8f0;font-family:system-ui;'
                    'margin:2rem}a{color:#7dd3fc}nav{line-height:2}'
                    'pre{white-space:pre-wrap;overflow-wrap:anywhere}'
                    '</style></head><body>' + navigation + '<main><h1>'
                    + escape(title) + '</h1><p>Offline snapshot evidence. '
                    'No live checks or actions are performed.</p><pre>' + payload
                    + '</pre></main></body></html>\n')

        pages = {
            "index.html": snapshot_page("OpsCryer Spatial Browser Snapshot", snapshot),
            "chat.html": snapshot_page("Ticket Concierge Chat Snapshot", [
                {"question": question, "response": ask_concierge_chat(
                    question, catalog=snapshot)} for question in QUICK_REPLIES]),
            "incidents.html": render_incident_commander_html(snapshot),
            "capacity.html": render_capacity_planner_html(snapshot),
            "network.html": render_network_inspector_html(snapshot),
            "gitops.html": render_gitops_cockpit_html(snapshot),
            "executive.html": render_executive_command_center_html(snapshot),
            "hub.html": snapshot_page("OpsCryer Application Suite Hub", suite),
        }
        # Use bundle-only navigation in renderer-owned markup. Server routes
        # such as live metrics and Markdown reports have no offline artifact.
        for name in ("incidents.html", "capacity.html", "network.html", "gitops.html",
                     "executive.html"):
            pages[name] = re.sub(r'<nav\b[^>]*>.*?</nav>', lambda match: navigation,
                                 pages[name], count=1, flags=re.DOTALL)
        # Retain local filters and simulations, but omit live-only controls
        # and their isolated refresh function from the offline snapshots.
        for name in ("incidents.html", "capacity.html"):
            pages[name] = re.sub(
                r'<section aria-label="Live Metrics Stream">.*?</section>', '',
                pages[name], count=1, flags=re.DOTALL)
            pages[name] = re.sub(
                r'\(\(\) => \{\n  const button = document\.getElementById\("live-refresh"\);'
                r'.*?\n\}\)\(\);\n', '', pages[name], count=1, flags=re.DOTALL)
        pages["suite-catalog.json"] = json.dumps(suite, indent=2, allow_nan=False) + "\n"
    except (OSError, TypeError, ValueError, KeyError):
        raise ValueError("Invalid suite bundle catalog") from None

    try:
        destination.mkdir(parents=True, exist_ok=True)
        _validate_bundle_destination(destination, filenames)
        for name in filenames:
            # Replace instead of truncating an existing file, and never follow a
            # destination symlink when opening it. Tempfiles stay on this volume.
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                                 dir=destination, delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(pages[name].replace("\r\n", "\n").replace("\r", "\n"))
                _validate_bundle_destination(destination, filenames)
                os.replace(temporary, destination / name)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    except (OSError, ValueError):
        raise ValueError("Unable to write suite bundle safely") from None
    return sanitize({"schema_version": "1.0", "file_count": len(filenames),
                     "files": list(filenames)})


def build_suite_application_catalog(catalog=None) -> dict:
    """Return fresh metadata for core applications and server-only extensions.

    ``catalog`` is accepted for compatibility with the suite's snapshot builders.
    Application entrypoints are fixed and independent of snapshot contents, so
    no caller telemetry is copied into the index. ``ready`` identifies catalog
    entries; it is not a runtime health check or evidence that a route is mounted.
    Extensions are discoverable separately from the eight core applications so
    the portable bundle retains its nine-file offline contract.
    """
    applications = [
        {
            "app_id": "spatial_browser",
            "title": "Spatial Information Tree & RTS/TBS Browser",
            "route": "/",
            "api_route": "/api/v1/dogfood-zoom",
            "cli_module": "opscryer_browser",
            "target_audience": "Platform engineers and operators",
            "epic_id": "EPIC-1",
            "ready": True,
        },
        {
            "app_id": "ticket_chat_portal",
            "title": "Ticket Concierge Chat Portal",
            "route": "/chat",
            "api_route": "/api/v1/chat-concierge",
            "cli_module": "ticket_chat_portal",
            "target_audience": "Household users and support teams",
            "epic_id": "EPIC-8",
            "ready": True,
        },
        {
            "app_id": "incident_commander",
            "title": "Incident Commander & Blameless PIR",
            "route": "/incidents",
            "api_route": "/api/v1/incident-commander",
            "cli_module": "incident_commander",
            "target_audience": "On-call engineers and incident commanders",
            "epic_id": "EPIC-7",
            "ready": True,
        },
        {
            "app_id": "capacity_planner",
            "title": "Cluster Capacity & GPU Workload Planner",
            "route": "/capacity",
            "api_route": "/api/v1/capacity-planner",
            "cli_module": "capacity_planner",
            "target_audience": "Capacity planners and GPU workload operators",
            "epic_id": "EPIC-8",
            "ready": True,
        },
        {
            "app_id": "network_topology_inspector",
            "title": "Network & OIDC Route Inspector",
            "route": "/network",
            "api_route": "/api/v1/network-inspector",
            "cli_module": "network_topology_inspector",
            "target_audience": "Network engineers and identity administrators",
            "epic_id": "EPIC-5",
            "ready": True,
        },
        {
            "app_id": "gitops_release_cockpit",
            "title": "GitOps & CI/CD Release Cockpit",
            "route": "/gitops",
            "api_route": "/api/v1/gitops-cockpit",
            "cli_module": "gitops_release_cockpit",
            "target_audience": "Release managers and DevOps engineers",
            "epic_id": "EPIC-6",
            "ready": True,
        },
        {
            "app_id": "executive_command_center",
            "title": "Executive CISO & Platform Governance Command Center",
            "route": "/executive",
            "api_route": "/api/v1/executive-summary",
            "cli_module": "executive_command_center",
            "target_audience": "Executives, CISOs and governance teams",
            "epic_id": "EPIC-9",
            "ready": True,
        },
        {
            "app_id": "opscryer_suite_hub",
            "title": "OpsCryer Application Suite Hub",
            "route": "/hub",
            "api_route": "/api/v1/suite-catalog",
            "cli_module": "opscryer_suite_hub",
            "target_audience": "All OpsCryer users",
            "epic_id": "EPIC-1",
            "ready": True,
        },
    ]
    return sanitize({
        "schema_version": "1.0",
        "application_count": len(applications),
        "applications": applications,
        "compatibility_and_live_extensions": [
            {"route": "/metrics-live", "title": "Live Metrics",
             "api_route": "/api/v1/live-metrics"},
            {"route": "/adapters", "title": "Environment Adapters",
             "api_route": "/api/v1/environment-adapters"},
            {"route": "/docs", "title": "API Documentation",
             "api_route": "/api/v1/openapi.json"},
        ],
    })


def render_suite_hub_html() -> str:
    """Return a standalone launchpad with same-origin API reachability checks."""
    applications = json.dumps(build_suite_application_catalog()["applications"])
    applications = (applications.replace("&", "\\u0026")
                    .replace("<", "\\u003c").replace(">", "\\u003e"))
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>OpsCryer Application Suite Launchpad</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif;
  background: #0b1220; color: #e2e8f0; }
body { max-width: 1200px; margin: auto; padding: 24px;
  background: radial-gradient(ellipse at top right, #173454, transparent 65%); }
nav { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 32px; }
a { color: #7dd3fc; text-underline-offset: 4px; }
a:focus-visible, button:focus-visible { outline: 3px solid #fbbf24; outline-offset: 4px; }
h1 { font-size: clamp(1.8rem, 4vw, 2.8rem); }
p { line-height: 1.6; }
#suite-apps-grid { display: grid; gap: 20px;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); }
.card { background: linear-gradient(145deg, #192b43, #101b2d);
  border: 1px solid #334155; border-radius: 20px;
  padding: 24px; overflow-wrap: anywhere; display: flex; flex-direction: column;
  box-shadow: 0 12px 30px #0003; }
.card[hidden] { display: none; }
.card:hover, .card:focus-within { border-color: #7dd3fc; }
.card h2 { margin-top: 0; font-size: 1.2rem; }
.card code { display: block; background: #0b1220; padding: 12px;
  border-radius: 8px; white-space: pre-wrap; }
.card .api-path { font-size: .85rem; color: #94a3b8; margin-top: auto; }
.badge { align-self: flex-start; border: 1px solid #456687; color: #bae6fd;
  border-radius: 999px; padding: 4px 10px; font-size: .8rem; margin-bottom: 16px; }
#suite-filter-bar { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 28px; }
#suite-filter-bar button { border-radius: 999px; border-color: #475569; }
#suite-filter-bar button[aria-pressed="true"] { background: #bae6fd; color: #0b1220;
  border-color: #bae6fd; }
#suite-filter-count, .latency { color: #94a3b8; font-size: .9rem; }
.latency { margin-bottom: 0; }
.status { color: #cbd5e1; }
.status[data-state="available"] { color: #86efac; }
.status[data-state="unavailable"] { color: #fda4af; }
button { background: #1e3a5f; color: #e2e8f0; border: 1px solid #7dd3fc;
  border-radius: 6px; padding: 10px 16px; cursor: pointer; }
button:disabled { opacity: .6; cursor: wait; }
</style>
</head>
<body>
<nav aria-label="Suite applications">
<a href="/">Spatial Browser</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/games">Game Observability</a><a href="/kb">Knowledge Explorer</a>
<a href="/metrics-live">Live Metrics</a><a href="/adapters">Environment Adapters</a>
<a href="/docs">API Documentation</a>
<a href="/executive">Executive</a><a href="/hub" aria-current="page">Suite Hub</a>
</nav>
<main>
<h1>OpsCryer Application Suite Launchpad</h1>
<p>Open an application and check its API availability from this browser.
Availability indicates an HTTP response, not cluster health or verified enforcement.</p>
<button id="refresh-status" type="button">Refresh API status</button>
<p id="suite-status" role="status" aria-live="polite">Waiting to check APIs.</p>
<section id="suite-filter-bar" aria-label="Filter applications by domain">
<button type="button" id="filter-all" aria-pressed="true" aria-controls="suite-apps-grid">All Portals</button>
<button type="button" id="filter-ops" aria-pressed="false" aria-controls="suite-apps-grid">Operations &amp; Triage</button>
<button type="button" id="filter-arch" aria-pressed="false" aria-controls="suite-apps-grid">Architecture &amp; Network</button>
<button type="button" id="filter-gov" aria-pressed="false" aria-controls="suite-apps-grid">Governance &amp; Release</button>
</section>
<p id="suite-filter-count" role="status" aria-live="polite">Showing all 8 portals.</p>
<section id="suite-apps-grid" aria-label="Applications and live API status"></section>
<noscript>Enable JavaScript for application cards and live API status. Use the navigation links above to open applications.</noscript>
</main>
<script>
'use strict';
const applications = ''' + applications + r''';
const grid = document.getElementById('suite-apps-grid');
const refresh = document.getElementById('refresh-status');
const summary = document.getElementById('suite-status');
const filterCount = document.getElementById('suite-filter-count');
const filters = [
  {button: document.getElementById('filter-all'), domain: 'all'},
  {button: document.getElementById('filter-ops'), domain: 'ops'},
  {button: document.getElementById('filter-arch'), domain: 'arch'},
  {button: document.getElementById('filter-gov'), domain: 'gov'}
];
const domainEpics = {
  ops: ['EPIC-7', 'EPIC-8'],
  arch: ['EPIC-1', 'EPIC-5'],
  gov: ['EPIC-6', 'EPIC-9']
};
const checks = applications.map(app => {
  const card = document.createElement('article');
  card.className = 'card';
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.textContent = app.epic_id;
  card.appendChild(badge);
  const heading = document.createElement('h2');
  const link = document.createElement('a');
  link.href = app.route;
  link.textContent = app.title;
  heading.appendChild(link);
  card.appendChild(heading);
  const audience = document.createElement('p');
  audience.textContent = app.target_audience;
  card.appendChild(audience);
  const command = document.createElement('code');
  command.textContent = 'python ' + app.cli_module + '.py --json';
  card.appendChild(command);
  const api = document.createElement('p');
  api.className = 'api-path';
  api.textContent = 'API: ' + app.api_route;
  card.appendChild(api);
  const status = document.createElement('p');
  status.className = 'status';
  status.textContent = 'API: Not checked';
  card.appendChild(status);
  const latency = document.createElement('p');
  latency.className = 'latency';
  latency.textContent = 'Check latency: Not measured';
  card.appendChild(latency);
  grid.appendChild(card);
  return {app, card, status, latency};
});
function filterApplications(domain) {
  let visible = 0;
  checks.forEach(({app, card}) => {
    card.hidden = domain !== 'all' && !domainEpics[domain].includes(app.epic_id);
    if (!card.hidden) visible += 1;
  });
  filters.forEach(filter => {
    filter.button.setAttribute('aria-pressed', String(filter.domain === domain));
  });
  filterCount.textContent = 'Showing ' + visible + ' of ' + checks.length + ' portals.';
}
filters.forEach(({button, domain}) => {
  button.addEventListener('click', () => filterApplications(domain));
});
filterApplications('all');
async function updateStatus() {
  if (refresh.disabled) return;
  refresh.disabled = true;
  summary.textContent = 'Checking APIs...';
  let available = 0;
  await Promise.all(checks.map(async ({app, status, latency}) => {
    status.textContent = 'API: Checking...';
    status.dataset.state = 'checking';
    latency.textContent = 'Check latency: Measuring...';
    const started = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const probeUrl = app.api_route === '/api/v1/chat-concierge'
        ? app.api_route + '?q=manifest%20cluster'
        : app.api_route;
      const response = await fetch(probeUrl, {
        signal: controller.signal, cache: 'no-store', redirect: 'error',
        mode: 'same-origin', headers: {'Accept': 'application/json'}
      });
      status.textContent = response.ok ? 'API: Available' : 'API: HTTP ' + response.status;
      status.dataset.state = response.ok ? 'available' : 'unavailable';
      if (response.ok) available += 1;
      if (response.body) await response.body.cancel();
    } catch (error) {
      status.textContent = controller.signal.aborted ? 'API: Timed out' : 'API: Unreachable';
      status.dataset.state = 'unavailable';
    } finally {
      clearTimeout(timeout);
      latency.textContent = 'Check latency: ' + Math.round(performance.now() - started) + ' ms';
    }
  }));
  summary.textContent = available + ' of ' + checks.length +
    ' APIs available. Checked ' + new Date().toLocaleTimeString() +
    '. Refreshes every 60 seconds.';
  refresh.disabled = false;
}
refresh.addEventListener('click', updateStatus);
updateStatus();
setInterval(updateStatus, 60000);
</script>
</body>
</html>
'''


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid suite hub request")


def main(argv=None) -> int:
    """Print the catalog, export offline pages, or serve the suite on loopback."""
    parser = _SafeArgumentParser(prog="opscryer_suite_hub",
                                 description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true", help="Print the suite catalog")
    mode.add_argument("--export-suite-bundle", metavar="DIRECTORY",
                      help="Export the portable suite and print its manifest")
    mode.add_argument("--serve", action="store_true", help="Serve the application suite locally")
    parser.add_argument("--port", type=int, default=8095,
                        help="Port for --serve (default: 8095)")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    try:
        if args.serve:
            from opscryer_browser import _build_frontend_handler

            with socketserver.TCPServer(("127.0.0.1", args.port),
                                        _build_frontend_handler()) as server:
                print(f"Suite hub: http://127.0.0.1:{args.port}/hub", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        else:
            payload = (export_full_suite_static_bundle(args.export_suite_bundle)
                       if args.export_suite_bundle is not None
                       else build_suite_application_catalog())
            print(json.dumps(payload, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete suite hub request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
