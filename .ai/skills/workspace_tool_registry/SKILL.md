---
name: workspace_tool_registry
description: Workspace Tool Registry Usage & Maintenance
---

# AI SKILL: Workspace Tool Registry Usage & Maintenance

**Purpose:** Standard Operating Procedure (SOP) for how AI agents must interact with the `WORKSPACE_TOOL_REGISTRY.md`. This skill governs the "Ingestion of New Skills/Tools" to ensure agents build upon existing automation rather than reinventing the wheel.

## 1. Tool Discovery Before Implementation
- **Rule:** Before an AI agent attempts to write a new PowerShell script, Python automation script, or custom bash script for a specific workspace task (e.g., cleaning up databases, migrating users, restarting deployments), the agent **MUST** check `WORKSPACE_TOOL_REGISTRY.md`.
- **Action:** If an existing tool is cataloged that performs the requested task, the agent must execute that tool according to its documented flags instead of writing new code.

## 2. Ingesting New Skills & Tools
When an AI agent creates a brand new utility script, ChatOps command, or generalized workflow automation that has value beyond a single one-off task, the agent is formally "Ingesting a New Skill" into the workspace.
- **Rule:** The agent **MUST** formally register the new tool in `WORKSPACE_TOOL_REGISTRY.md`.
- **Action:** Append a new row to the registry detailing the `Tool Name`, `Path / Context`, `Purpose`, and `Usage / Invocation Flags`.
- **Requirement:** Keep the entries dense and accurate. If the script uses an `<ai_context>` comment block for detailed API documentation, mention that in the registry so future agents know to read the file directly for parameters.

## 3. Separation of Concerns
- **Intent Dictionary (`AI_INTENT_DICTIONARY.md`):** Strictly for translating conversational user *intent* (like "Run dry run") into universal execution modes (like `--dry-run`). Do **not** list specific scripts here.
- **Tool Registry (`WORKSPACE_TOOL_REGISTRY.md`):** Strictly for discovering specific, concrete files and scripts that accomplish a domain-specific goal (e.g., `manage-test-users.ps1`).
