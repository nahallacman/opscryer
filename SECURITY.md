<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security Policy

## Reporting a Vulnerability

Please report security issues responsibly through a private repository advisory or direct maintainer contact rather than opening public unredacted issues with live credentials, internal topology, or exploit payloads.

## Security Architecture Highlights

- **Tool-Repository Data Separation**: Operational Knowledge Graph payloads are loaded strictly from external mounts (`OPSCRYER_GRAPH_FILE` / `--graph-file`), blocking in-repo writes via `TOOL_REPO_GRAPH_PATH_BLOCKED` and enforcing checked-in sample contract checks in CI.
- **Read-Only Discovery & Airlock Bounds**: The browser and server enforce `Origin`/`Sec-Fetch-Site` validation, strict payload sizing, HTML escaping at the render boundary, zero unauthenticated C2 mutation endpoints, and six automated OPSEC/SPDX/CRLF pre-push gates (`golden_path_gates.py`).
