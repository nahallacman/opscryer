<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpsCryer Agent Rules & 3-Tool Architecture

1. **Read Design & Roadmap First**: Review `.ai/design/architecture.md`, `.ai/plans/roadmap.md`, and `.ai/skills/` before modifying gateway routes, spatial views, or layout presets.
2. **3-Tool Interoperable Architecture**:
   - **OpsCryer**: Visual Knowledge Graph, 3-view spatial canvas (`Local Links` / `Layer Boxes` / `2D/2.5D/3D`), minimal default UI (`focused`), and Brain HTTP gateway/auth proxy.
   - **Central Brain**: Authoritative Knowledge Graph core, swappable `HarvesterPlugin` pipeline, 4-scope `.ai/` compiler, MLS lattice, and `GET/POST /api/v1/ask`.
   - **Meshworks**: Pure-stdlib AI agent execution and training plane consuming pre-dumped `<=400`-token cast bundles from Brain.
3. **Public OPSEC & Tool-vs-Data Separation**: Never commit internal cluster hostnames, RFC 1918 lab ranges outside `10.20.x.x` / `172.20.x.x` test fixtures, personal handles, API tokens, or external `knowledge-graph.json` / `curated-graph.json` files. Use `cluster.example.org` and `203.0.113.1` placeholders cleanly.
4. **SPDX, LF Endings & JS Compaction**: Every `.py` file requires `# SPDX-License-Identifier: Apache-2.0`. All files must use LF (`\n`). Inside `opscryer_browser.py` embedded `<script>`, never use `//` comments; regenerate `index.html` and run `node --check`.
5. **Commit & Verify**: Commit with a `<=100`-character lowercase Conventional Commit first, then run `python scripts/ci_verify.py` and confirm zero failures across all unit tests, `.ai/` hygiene checks, `7/7` CLI checks, `6/6` `golden_path_gates.py` gates, and showcase checks.
