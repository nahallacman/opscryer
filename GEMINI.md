# GEMINI.md — OpsCryer 3-Tool Suite & Lazy Skill Index (Gemini CLI)

This repository includes the **OpsCryer 3-Tool Operations & Knowledge Suite** and a library of
portable engineering skills designed for **Gemini CLI (`gemini`)**.

## 1. Gemini CLI Execution Rules (Token & Prompt Conservation)
- **Direct CLI Execution**: Run standard direct commands (`git status`, `git diff`, `kubectl get`, `python ...`)
  that match the prefix allowlist in `.gemini/settings.json` (`tools.allowed`). Never wrap arguments in
  `(Get-Content ...)` or `$(cat ...)` subshells.
- **Line Endings & Commits**: Preserve `LF` (`\n`) line endings (`newline='\n'` in Python) and use
  lowercase Conventional Commit subjects (`feat: ...`, `fix: ...`).
- **Deterministic Brain First**: Before spending LLM tokens diagnosing known infrastructure or ticket
  issues, check **The Brain** (`python opscryer_abstraction.py --ai-brief` or `/opscryer:diagnose`).

## 2. The 3-Tool Architecture
1. **OpsCryer (`opscryer_browser.py`)**: Fast visual spatial cockpits & support ticket deflection HUD.
2. **The Brain (`opscryer_abstraction.py` -> `MetricPluginRegistry` + `evaluate_jev_with_live_plugins`)**:
   Authoritative Knowledge Graph, deterministic System One Jev decision tree, and live telemetry plugins (`0` AI tokens on match).
3. **The Swarm (`opscryer_abstraction.py` -> `PlaybookExecutionEngine` + `SwarmAIGraphAndPlaybookPipeline`)**:
   Executes deterministic playbooks, detects drift/flapping (`NEEDS_REWORK`), and stages 6-gate validated playbook reworks or graph expansions on fallback.

## 3. Lazy-Loaded Skill Routing Table (`.ai/skills/`)
To conserve context window tokens, **do not** read all skill files upfront. When your task matches one of
the domains below, read its `SKILL.md` file (or run `/skill:use <skill_name>`):

| Skill Name | Path | When to Load |
| :--- | :--- | :--- |
| `gemini_cli_execution_protocol` | `.ai/skills/gemini_cli_execution_protocol/SKILL.md` | Native Gemini CLI command execution, prefix allowlisting (.gemini/settings.json), custom TOML slash commands, and lazy skill loading. |
| `opscryer_three_tool_suite` | `.ai/skills/opscryer_three_tool_suite/SKILL.md` | Operating guide for the decoupled 3-Tool Operations & Knowledge Suite (OpsCryer Visual Cockpits, The Brain / Jev Graph + MetricPluginRegistry, and The Swarm PlaybookExecutionEngine & SwarmAIGraphAndPlaybookPipeline). |
