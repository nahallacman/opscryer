---
name: opscryer_verification_and_opsec
description: "CI verification, six-gate golden_path_gates audit, SPDX headers, Conventional Commits, and strict tool-vs-data OPSEC rules for this repository."
---
# OpsCryer Verification, CI Gates & Public OPSEC

## 1. Six Pre-Push Gates (`golden_path_gates.py`)
- Every tracked and untracked public file must pass `run_six_gate_prepush_audit`:
  1. `crlf`: zero `\r\n` bytes across tracked files.
  2. `opsec`: zero non-documentation global IPv4s, hardware MACs, API token prefixes, `.env` secrets, or `curated-graph.json` / `knowledge-graph.json` payloads.
  3. `spdx`: every `.py` file must start with `# SPDX-License-Identifier: Apache-2.0` (line 1, or line 2 after `#!`).
  4. `graph_contract`: `sample-graph-data.json` remains valid `SpatialGraphContract` demo data (`PIECE_A_FRONTEND_SPATIAL_BROWSER_DEMO_DATASET`).
  5. `commit_subject`: HEAD commit subject must be single-line lowercase Conventional Commit `<= 100` characters (commit first before running `scripts/ci_verify.py`).
  6. `epic_locks`: `EPIC_SCOPE_MANIFEST.md` maintains pairwise-disjoint locks across `EPIC-1..9`.

## 2. Positive Pass Evidence & `.ai/` Hygiene
- Never conflate `0` errors with `0` executed checks; report explicit `checked`/`passed_count`/`status` counters everywhere.
- Keep `.ai/design/`, `.ai/plans/`, `.ai/skills/`, and `.agents/` generic with valid YAML frontmatter and `.ai/local/` gitignored (`scripts/ci_verify.py` verifies `verify_ai_project_hygiene`).
- Run `python scripts/ci_verify.py` after committing and push review branches only to `gitlab`.
