# GEMINI.md — OpsCryer Context & Lazy Skill Index (Gemini CLI)

This repository implements **OpsCryer**, the Visual & Gateway Plane of the 3-Tool Operations & Knowledge Suite (`OpsCryer`, `Central Brain`, `Meshworks`), including clean repo-native `.ai/` architecture, roadmap, and skills.

## 1. Execution & Hygiene Rules
- **Line Endings & Commits**: Preserve `LF` (`\n`) line endings (`newline='\n'` in Python) and use lowercase Conventional Commit subjects `<= 100` characters.
- **Deterministic First**: Inspect live telemetry, graph levels (`graph_layers.py`), and Central Brain `/api/v1/ask` deterministically before escalating to model inference.
- **SPDX & OPSEC**: Every Python file requires `# SPDX-License-Identifier: Apache-2.0`. Keep internal hostnames, cluster IPs, credentials, and external Knowledge Graphs out of this tool repo (`python scripts/ci_verify.py`).

## 2. The 3-Tool Architecture
1. **OpsCryer (`opscryer_browser.py` + `opscryer_backend.py`)**: 3-view spatial Knowledge Graph browser (`Local Links`, `Layer Boxes`, `2D/2.5D/3D`), 7-level taxonomy, minimal default loadout (`workspace_layout.py`), and Brain HTTP/auth proxy.
2. **Central Brain (`brain_engine`)**: Authoritative Knowledge Graph core, swappable `HarvesterPlugin` pipeline, `.ai/` compiler, MLS lattice, and `GET/POST /api/v1/ask`.
3. **Meshworks (`meshworks`)**: Pure-stdlib agent execution and training plane consuming pre-dumped `<=400`-token cast bundles from Brain.

## 3. Repository `.ai/` Index (Lazy-Load Only What You Need)
| Artifact | Path | When to Load |
| :--- | :--- | :--- |
| Architecture Design | `.ai/design/architecture.md` | Understand OpsCryer views, Full-Truth mode, and user-delegated auth proxy. |
| Active Roadmap | `.ai/plans/roadmap.md` | Check shipped foundations vs. queued Stage 2 workstreams. |
| UI & Layout Skill | `.ai/skills/opscryer_ui_and_layout_development/SKILL.md` | Edit browser HTML/JS/CSS, regenerate `index.html`, or modify layout presets/auth dialogs. |
| CI & OPSEC Skill | `.ai/skills/opscryer_verification_and_opsec/SKILL.md` | Run `scripts/ci_verify.py` or audit SPDX, CRLF, OPSEC, and `golden_path_gates.py`. |
