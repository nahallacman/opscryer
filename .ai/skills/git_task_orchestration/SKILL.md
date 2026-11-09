---
name: git_task_orchestration
description: Standard operating procedure for autonomous and multi-node agent task checkout, branch management, commit auto-tagging, secret scanning, and Merge Request traceability using the git-task CLI.
---

# AI Skill: Multi-Node Git-Task Orchestration & Traceability

## Context
When AI agents or multi-node swarm workers operate autonomously across repositories, they must maintain 100% requirements-to-code traceability. This skill defines how agents discover, claim, execute, and tag tasks using the `git task` toolchain, ensuring that every commit and Merge Request maps directly from high-level Roadmap Epics to low-level code diffs and vulnerability fixes.

---

## 🛠️ The `git-task` Command Suite

The repository provides `git task` (backed by `scripts/dev/git_task.py`) with native Git integration:

| Command | Purpose | Agent Usage |
| :--- | :--- | :--- |
| `git task list` | Query open GitLab issues & roadmap epics | Used by agents to find unassigned tickets and prioritize by severity. |
| `git task checkout <ID>` | Claim task & switch to standardized branch | Creates `fix/issue-<ID>-<slug>` or `feature/issue-<ID>-<slug>` and sets `.git/ACTIVE_TASK.json`. |
| `git task status` | Inspect current active task & risk | Reads `.git/ACTIVE_TASK.json` to verify context. |
| `git task mr [--dry-run]` | Push branch & generate traceable MR | Automatically populates MR title, description, labels, and Roadmap Epic references. |
| `git task clear` | Reset active task context | Cleans up local state upon completion. |

---

## 🤖 Multi-Node Agent Execution Protocol

### Step 1: Task Discovery & Triage
1. Agent checks available tasks:
   ```bash
   git task list
   ```
2. Priority sorting:
   - `CRITICAL` / `HIGH` Security Triage issues (`[SEC-TRIAGE]`) MUST be claimed first.
   - Standard Roadmap Phases (`Phase X`) are claimed in sequence.

### Step 2: Task Claim & Branch Checkout
1. Agent checks out the issue:
   ```bash
   git task checkout 176
   ```
2. Verification:
   - Confirm branch creation: `git branch --show-current` -> `fix/issue-176-cve-2026-25681`
   - Confirm local state: `git task status`

### Step 3: Implementation & Local Validation
1. Execute the necessary code changes or dependency bumps.
2. Run local tests:
   ```bash
   pytest
   ```
3. Run local secret scanning (Epic 3D Gate):
   ```bash
   gitleaks protect --staged --verbose --config .gitleaks.toml
   ```

### Step 4: Commit Hygiene & Auto-Tagging
1. The repository's `prepare-commit-msg` hook automatically reads `.git/ACTIVE_TASK.json` and appends:
   `Refs #<ID> [Epic <X>]`
2. **Commit Length Rule**: Keep the commit header strictly under **100 characters** to pass `conventional-commit-lint`:
   ```bash
   git commit -m "fix(security): bump dependency to resolve #176"
   ```

### Step 5: Merge Request Generation & CI Verification
1. Push and open the Merge Request:
   ```bash
   git task mr
   ```
2. The MR will be opened with:
   - Roadmap Epic link
   - Resolves Issue reference (`#<ID>`)
   - Risk level and checklist
   - Proper labels (`~governance`, `~epic-X`, `~in-review`)
3. Monitor pipeline execution until green.

### Step 6: Multi-Node Swarm Notification
When operating as part of an autonomous multi-node swarm, agents should dispatch status updates to the Notification Arbitrator:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"agent_id": "NodeAgent-01", "task_type": "TaskComplete", "status": "success", "reason": "Resolved Issue #176 with MR !338", "mr_url": "https://gitlab.cluster.example.org/platform/infra-gitops/-/merge_requests/338"}' \
  -k https://notifications.cluster.example.org/webhooks/agent
```

### Step 7: Traceability Matrix Refresh
After merging, update the living matrix:
```bash
python scripts/ci/generate_traceability_matrix.py
```
This guarantees `PersonalProjectDocumentation/Traceability_Matrix.md` remains 100% up to date.
