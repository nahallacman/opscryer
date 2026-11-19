<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to OpsCryer are documented in this file.

## [1.2.0] - 2026-11-18

### Added
- External Knowledge Graph file mounting (`OPSCRYER_GRAPH_FILE`, `--graph-file`, `/data` read-only volume mount) with HTTP `mtime` auto-reload and fail-closed `TOOL_REPO_GRAPH_PATH_BLOCKED` guard on in-repo paths.
- Six-gate pre-push CI audit (`golden_path_gates.py`) enforcing zero CRLF line endings, SPDX headers, OPSEC hygiene, `SpatialGraphContract v1` / demo dataset integrity, and lowercase Conventional Commits.
- GitHub Actions CI workflow (`.github/workflows/ci.yml`), `CHANGELOG.md`, and `SECURITY.md`.
