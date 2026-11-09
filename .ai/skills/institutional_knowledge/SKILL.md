---
name: "institutional_knowledge"
description: Instructions and operating protocol for reading and capturing developer preferences, workstation environment quirks, operational disaster recovery runbooks, and architectural decisions in .ai/knowledge/.
---

# Institutional Knowledge & Memory Architecture (`.ai/knowledge/`)

**Purpose:** This skill establishes the standard protocol for navigating, retrieving, and recording institutional knowledge across the `infra-gitops` ecosystem. It prevents knowledge loss across AI sessions and guarantees that developer preferences, hardware quirks, and operational runbooks are permanently saved.

---

## 1. Directory Structure & Taxonomy

Knowledge is organized under `.ai/knowledge/`:

* **`workflow/` (`collaboration_and_dev_process.md`, `user_feedback_ledger.md`, `ui_ux_and_visualization_standards.md`):**
  * Human-in-the-loop review boundaries (AI pushes branches; only humans create MRs; 1-Click Launchpad on `https://opscryer.cluster.example.org/mrs`).
  * Anti-Junk MR Quality Bar & Zero Notification Fatigue: 5-point Gold-Tier quality gate so every second of human review is spent on real, tested work—unlocking direct 1-click approval.
  * Compaction-Proof User Feedback Ledger (`user_feedback_ledger.md`): Permanent record of all user directives, UX corrections, and architectural pivots so zero context is ever lost to conversation compaction.
  * Ergonomics: Give copy-pasteable commands to the user; do not perform stealth execution behind their back.
  * Git workflow: Rebase-only (`git rebase origin/main`), lowercase conventional commits (`feat: ...`), inline documentation in `PersonalProjectDocumentation/` (no submodule commit hash updates), no ad-hoc scripts in repo root (Rule 11).
  * UI/UX & Visualization Guidance: Familiar interactions, flowing live diagrams with client-side graphics stability, 6-color semantic vocabulary (`Red`=Error, `Yellow`=Warn, `Green`=Clean, `Blue`=Stalled, `Orange`=Novel DB Error, `Purple`=Locked Resource), video-game HUD simplicity over heavy animations, lower technical detail pane, and golfed-down menu depths (`<= 1-2` clicks).
* **`environment/` (`workstation_and_network.md`):**
  * Workstation architecture (Windows 11, PowerShell, MSYS2/DevkitPro bash).
  * Critical MSYS2 `$HOME` local expansion trap on remote `scp`/`ssh`.
  * Physical network layout, NetFilter gateway, VLAN 30 static server IP allocations.
* **`operations/` (`cluster_disaster_recovery.md`):**
  * Cluster disaster recovery runbooks: Linux swap persistence, kubeadm 365-day certificate renewals, OpenZFS CSI storage DNS deadlock, headless node recovery after GPU removal, OpenBao/Vault unsealing, Calico BGP peering.
* **`decisions/` (Architecture Decision Records - ADRs):**
  * Historical decisions explaining *why* technical paths were chosen (e.g. `ADR-001-static-server-allocations.md`).
* **`code/` (`application_gotchas.md`):**
  * Runtime gotchas: Node.js self-signed CA rejection, Java PKIX keystores, Python SSL contexts, CRLF/LF line endings, StatefulSet headless services.

---

## 2. Operating Protocol for AI Agents

1. **Before Executing Commands:**
   * Review `workflow/collaboration_and_dev_process.md`, `workflow/user_feedback_ledger.md`, and `environment/workstation_and_network.md`.
2. **Immediate Compaction-Proof User Feedback Capture:**
   * Whenever the user provides workflow feedback, UX preferences, or architectural directives during a session, immediately persist them to `workflow/user_feedback_ledger.md` and the relevant `.ai/skills/*/SKILL.md` so context window compaction never loses user guidance.
3. **When Solving Non-Trivial Problems:**
   * Any non-obvious bug fix, environment workaround, or design decision MUST be documented in `.ai/knowledge/`.
4. **Pre-Handoff Verification:**
   * Before handing off or providing a GitLab Compare Link, verify that your git diff includes your notes in `.ai/knowledge/` so the MR Bot scorecard reports `✅ PASS`.

