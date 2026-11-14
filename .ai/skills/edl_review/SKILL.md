---
name: edl_review
description: Engineering Decisions Log (EDL) Review
---

# AI SKILL: Engineering Decisions Log (EDL) Review
**Purpose:** Standard Operating Procedure (SOP) for AI agents to audit, evaluate, and safely deprecate stale entries in the `ENGINEERING_DECISIONS_LOG.md` without destroying historical context.

## 1. When to Perform a Review
Agents should initiate an EDL review in the following scenarios:
- **Explicit Request:** When the user explicitly asks to "review the EDL", "evaluate architectural decisions", or "audit the decision log".
- **Major Upgrades:** During major architectural shifts, tool migrations, or Kubernetes version upgrades where past technical constraints may no longer apply.

## 2. Evaluation Criteria
During the review, the agent must systematically evaluate each entry against the current state of the repository:
- **Context Validity:** Does the original "Context" or constraint still exist? For example, if a decision was made as a workaround for a bug in an old version of a tool (e.g., a TLS bug in `Invoke-RestMethod`), and the environment has since been upgraded, the decision is likely stale.
- **Consequences Audit:** Are the documented "Consequences" still acceptable? Are the trade-offs now causing cascading failures or friction in newer systems?

## 3. Human-In-The-Loop Deprecation
The EDL is a historical ledger. Decisions must never be erased from history.
- **Rule (No Silent Deletion):** Agents must **never** silently delete or alter an active EDL entry.
- **Rule (Propose Deprecation):** If an agent determines an entry is stale, it must present its evaluation to the user, explaining exactly *why* the context has changed, and propose deprecating the decision.
- **Rule (Historical Preservation):** If the user approves the deprecation, the agent must **NOT** delete the entry. Instead, it must update the entry by injecting a `> [!WARNING] STATUS: DEPRECATED` alert at the top of the specific log entry, along with a timestamp and a brief explanation of why the architectural choice was retired.
