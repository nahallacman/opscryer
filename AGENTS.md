# OpsCryer Autonomous Agent & Verification Rules

## 1. License & Attribution
- Every source file MUST retain `# SPDX-License-Identifier: Apache-2.0` under the single `Apache License, Version 2.0` (`LICENSE`).

## 2. Strict Public Release OPSEC & Synthetic-Only Telemetry Rules
- **Zero Private Homelab Data:** NEVER commit live `kubectl` cluster dumps, private homelab hostnames, internal `.local` / private DNS domains, or personal handles/emails into the public repository.
- **Synthetic Example Topology Only:** All bundled catalogs (`live-cluster-sanitized.json` and `sample-graph-data.json`) MUST use synthetic offline fallback data (`"source": "offline_fallback"`, `"example": true`) with generic `cluster.example.org` domains and generic RFC 1918 test addresses (`10.20.x.x`, `172.20.x.x`).
- **External Public WAN IPv4 Addresses:** NEVER commit or display real external WAN IPs; always scrub to `203.0.113.1`.
- **MAC Addresses:** NEVER display full 6-octet hardware MAC addresses; always mask the trailing 3 octets (`AA:BB:CC:XX:XX:XX`).
- **Secrets & Tokens:** NEVER commit API keys, personal access tokens, or `.env` files.

## 3. 1-Epic-Per-Agent Disjoint File Locks & Verification
- Each agent worker is assigned strictly 1 Epic and may only modify files within that Epic's `locked_scopes`.
- Every change must pass `python -m unittest discover -s tests -v` before committing.
