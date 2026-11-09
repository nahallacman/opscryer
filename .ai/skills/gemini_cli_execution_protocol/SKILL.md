---
name: gemini_cli_execution_protocol
description: Native Gemini CLI command execution, prefix allowlisting (.gemini/settings.json), custom TOML slash commands, and lazy skill loading.
---

# Gemini CLI Execution & Prefix Allowlist Protocol (`gemini_cli_execution_protocol`)

This workspace is configured for **Gemini CLI (`gemini`)**. Follow these execution rules to avoid unnecessary confirmation prompts and conserve tokens:

## 1. Use Direct CLI Commands (Never Subshell Indirection)
- Gemini CLI matches allowed commands by **prefix** in `.gemini/settings.json` (`tools.allowed`).
- **Always run direct commands** such as:
  - `git status --short --branch`
  - `git diff`
  - `git log -n 5 --oneline`
  - `kubectl get pods -A`
  - `kubectl describe pod <name> -n <ns>`
  - `python opscryer_abstraction.py --ai-brief`
- **Never** wrap arguments in `$(cat ...)` or `(Get-Content ...)`, as Gemini CLI's shell parser flags subshell expansion for manual confirmation.

## 2. Native Gemini CLI Slash Commands (`.gemini/commands/`)
- `/opscryer:brief` — Injects the compact (<350-token) 3-Tool Suite architecture & Jev digest.
- `/opscryer:diagnose <symptom>` — Runs deterministic **Brain + MetricPluginRegistry** evaluation (`0` AI tokens on graph match).
- `/opscryer:rework <query>` — Runs **Swarm** `SwarmAIGraphAndPlaybookPipeline` to stage a 6-gate validated graph expansion or playbook rework.
- `/skill:use <skill_name>` — Loads `.ai/skills/<skill_name>/SKILL.md` into context on demand.

## 3. Lazy Skill Loading
- Check the **Skill Routing Table** in `GEMINI.md` and read only the specific `.ai/skills/<skill_name>/SKILL.md` needed for the current task.
