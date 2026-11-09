# OpsCryer Autonomous Agent, 3-Tool Architecture & Low-Power AI Entrypoint Rules

## 0. Fast Entrypoint for Lower-Powered / Small-Context AI Models (Start Here!)
If you are an AI assistant with a smaller context window or running on a work machine, **do NOT read all 20+ repository files or 2,000-line UI modules**. Instead, use the unified `<350`-token abstraction module [`opscryer_abstraction.py`](opscryer_abstraction.py):

```bash
# 1. Print the <350-token JSON mental model & 3-Tool Architecture API map
python opscryer_abstraction.py --ai-brief

# 2. Run the plug-in demo (Knowledge Graph + Jev Decision Tree + Multi-Agent RAMCache hot-swap)
python opscryer_abstraction.py --demo-plugin-and-ramcache

# 3. Spin up the Herdr Brain + Gemini 3.8 Flash sub-agent zero-guessing test
python opscryer_abstraction.py --herdr-brain-test

# 4. Run the 4-epoch progressive Knowledge Graph training curriculum over settled systems
python opscryer_abstraction.py --train-graph-over-time
```

## 1. 3-Tool Interoperable Architecture (`OpsCryer`, `The Brain`, `The Swarm`)
- **Tool 1 — `OpsCryer` (`:8090`)**: Read-only visual spatial topology discovery, NOC HUD, and optional/modular Support Ticket Triage UI.
- **Tool 2 — `The Brain` (`:8091`)**: Authoritative Knowledge Graph, deterministic `Jev` diagnostic engine (`System 1` zero-AI hot path), Pluggable Metric Extension System (`MetricPluginRegistry` binding `plugin://<plugin_id>/<metric_key>` live signals to graph nodes), and Closed-Loop `PlaybookExecutionEngine`.
- **Tool 3 — `The Swarm` (`:8094`)**: Authenticated persistent multi-agent development environment and AI Fallback / Playbook-Rework pipeline (`SwarmAIGraphAndPlaybookPipeline`) invoked only when an issue is uncovered by the deterministic decision graph (`UNCOVERED_BY_DECISION_GRAPH`) or when a playbook flags `NEEDS_REWORK` (`PLAYBOOK_RAN_BUT_METRIC_STILL_DEGRADED`, `PLAYBOOK_DRIFT_DETECTED`, or `PLAYBOOK_FLAPPING_ROOT_CAUSE_UNFIXED`).

## 2. License & Attribution
- Every source file MUST retain `# SPDX-License-Identifier: Apache-2.0` under the single `Apache License, Version 2.0` (`LICENSE`).

## 3. Strict Public Release OPSEC & Synthetic-Only Telemetry Rules
- **Zero Private Homelab Data:** NEVER commit live `kubectl` cluster dumps, private homelab hostnames, internal `.local` / private DNS domains, or personal handles/emails into the public repository.
- **Synthetic Example Topology Only:** All bundled catalogs (`live-cluster-sanitized.json` and `sample-graph-data.json`) MUST use synthetic offline fallback data (`"source": "offline_fallback"`, `"example": true`) with generic `cluster.example.org` domains and generic RFC 1918 test addresses (`10.20.x.x`, `172.20.x.x`).
- **External Public WAN IPv4 Addresses:** NEVER commit or display real external WAN IPs; always scrub to `203.0.113.1`.
- **MAC Addresses:** NEVER display full 6-octet hardware MAC addresses; always mask the trailing 3 octets (`AA:BB:CC:XX:XX:XX`).
- **Secrets & Tokens:** NEVER commit API keys, personal access tokens, or `.env` files.

## 4. 1-Epic-Per-Agent Disjoint File Locks & Verification
- Each agent worker is assigned strictly 1 Epic and may only modify files within that Epic's `locked_scopes`.
- Every change must pass `python -m unittest discover -s tests -v` before committing.
