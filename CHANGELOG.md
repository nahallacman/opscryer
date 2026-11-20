<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to OpsCryer are documented in this file.

## [1.2.1] - 2026-11-20

### Security
- Enforced fail-closed authentication on staged Action Cards, hardened harvester security-context boundaries, gateway `Host` and CSP `frame-ancestors` checks, and webhook SSRF protections.
- Exported `resolveSafeOpscryerUrl()` in `OpsCryerBrowserComponent.tsx` (MUI v4 compatible) to restrict embedded URLs to `http:`/`https:`, backed by `OpsCryerBrowserComponent.test.tsx`.

### Fixed
- Bounded `_ReusableTCPServer` (`MAX_CONCURRENT_HTTP_WORKERS = 64`), applied `15.0s` per-socket request timeouts in `_FrontendHandler.setup()` (cleared for `/api/v1/events/stream` SSE), and synchronized `live_metrics_poller.py` cache access with `_METRICS_CACHE_LOCK`.
- Restored consistent `BRAIN_HOME` and `BRAIN_DATA_DIR` discovery across gateway and bridge modules.

### Changed
- Tagged all 21 HTML and 63 API routes in `route_registry.py` and Suite Hub cards in `opscryer_suite_hub.py` with explicit `execution_mode` labels (`live_io`, `snapshot_derived`, `simulated`) and `by_execution_mode` summary counts.
- Removed stale scratch/container artifacts, renamed `EPIC_SCOPE_MANIFEST.md`, scrubbed environment-specific examples in `settled_production_systems.yaml`, added `MANIFEST.in`, and installed `setuptools>=61` in `.github/workflows/ci.yml` for Python 3.12 packaging smoke checks.

## [1.2.0] - 2026-11-18

### Added
- External Knowledge Graph file mounting (`OPSCRYER_GRAPH_FILE`, `--graph-file`, `/data` read-only volume mount) with HTTP `mtime` auto-reload and fail-closed `TOOL_REPO_GRAPH_PATH_BLOCKED` guard on in-repo paths.
- Six-gate pre-push CI audit (`golden_path_gates.py`) enforcing zero CRLF line endings, SPDX headers, OPSEC hygiene, `SpatialGraphContract v1` / demo dataset integrity, and lowercase Conventional Commits.
- GitHub Actions CI workflow (`.github/workflows/ci.yml`), `CHANGELOG.md`, and `SECURITY.md`.
