---
name: dictionary_maintenance
description: Dictionary Maintenance
---

# AI SKILL: Dictionary Maintenance
**Purpose:** Standard Operating Procedure (SOP) for AI agents updating the `AI_INTENT_DICTIONARY.md` file.

## 1. Strict Token Efficiency
The primary value of the Intent Dictionary is that it can be loaded into an agent's context window instantly without wasting compute tokens.
- **Rule:** Do **NOT** convert the dictionary into verbose paragraphs or bulleted lists. 
- **Rule:** All additions must be strictly appended to the existing Markdown Table format. Keep descriptions dense and punchy.

## 2. Semantic Grouping (Avoid Duplication)
Before adding a brand new row to the dictionary, analyze whether the user's new verbal intent is simply a synonym for an existing execution mode.
- **Rule:** If the user creates a new phrase like *"Just go ahead"* or *"Make the changes"*, do not create a new row. Simply inject the new phrase into the `User Verbal Intent` column of the existing **Phase 2: Execution** row.

## 3. Tool-Agnostic Mappings
The dictionary is designed to enforce repeatability across the entire repository.
- **Rule:** Never map verbal intents to specific scripts (e.g., do not write mappings for `gitlab-migration.ps1`). 
- **Migration Rule:** If an agent discovers a specific script hardcoded into the Intent Dictionary, they must **NOT** just delete it. They must migrate the tool into the `WORKSPACE_TOOL_REGISTRY.md` so that the cluster knowledge is not lost.
- **Rule (Evaluation Before Intake):** Do not automatically insert every discovered script or tool into the Tool Registry or formalize it as an AI Skill. Evaluate carefully whether it is meant for **reuse and automation** versus a **one-off scratch script**. One-off scripts must not be permanently registered.
- **Rule:** Intents must only be mapped to **universal execution patterns** (e.g., `--dry-run`, `--auto-confirm`, or `CI/CD Mode`).

## 4. Required Syntax
When creating a brand new row for a new execution mode, use the following Markdown table syntax:
```markdown
| *"Verbal Phrase 1", "Verbal Phrase 2"* | **Execution Mode** (`--flag`) | Dense enforcement rule. |
```

## 5. Human-In-The-Loop Review & Engineering Decisions Log (EDL)
Agents must not blindly append new entries into the dictionary without explicit human approval.
- **Rule (Batching):** If an agent needs to propose a new entry AND notices that existing entries seem bloated or errant, it must bundle both the new proposal and the audit request into a **single, unified prompt**. Do not spam the user with excessive messages.
- **Rule (Context Harvesting):** If an agent suggests that an entry is errant, but the user explicitly overrides the agent and chooses to keep the entry, the agent must ask the user *why* they are keeping it. 
- **Rule (Documentation):** Once the user provides their reasoning, the agent must document the context in the `ENGINEERING_DECISIONS_LOG.md` file. 
- **Rule (Silence):** Before flagging any entry as errant or questioning an established pattern, agents **must** check `ENGINEERING_DECISIONS_LOG.md`. If the architectural decision is already explained there, the agent must silently respect the user's intent and never prompt them about it again.
