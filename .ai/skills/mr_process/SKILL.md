---
name: mr_process
description: Mr Process
---

# AI Skill: Test-Driven MR Validation & Feedback Loop

## Context
AI Agents modifying code must rigorously ensure that the CI pipelines and local tests pass. This skill unifies the MR Pipeline Discipline and the Test-Driven MR verification rules into a single robust feedback loop that the AI must follow autonomously.

## The Protocol

Whenever instructed to "make an MR", "write new tests", or push code, the AI Agent MUST automatically enforce the following loop:

### 1. Local Validation
- The agent must execute the relevant local testing suites (e.g., PyTest for E2E, or `npm run lint` for JS).
- If the tests fail, the AI must parse the local output, fix the failures, and re-run the tests.
- DO NOT commit new tests or open an MR if the local environment is throwing 500/503 errors (e.g. Docker Desktop down).

### 2. Conflict Resolution & Commit Linting (Pre-Push)
- The pipeline utilizes `commitlint` which strictly enforces the Conventional Commits specification (`feat:`, `fix:`, `chore:`, etc.).
- **NEVER** use `git merge origin/main` to bring in upstream changes, as the resulting merge commit will likely fail `commitlint` and clutter the history.
- **ALWAYS** use `git rebase origin/main` to maintain a linear history.
- If previous commits on your branch violate the Conventional Commits spec, you MUST use `git rebase -i` (or equivalent resetting/rewording) to reword the failing commits before pushing.

### 3. Push & Branch Creation
- Once local tests pass and your commits are conventionally formatted, the agent must commit the code.
- **CRITICAL RULE**: AI agents MUST NOT create or open Merge Requests themselves. AI agents are restricted to pushing branches to the remote repository:
  `git push --force-with-lease origin <branch_name>`
- After pushing, the AI must provide the human user with a GitLab **Compare Link** (e.g. `http://gitlab.cluster.example.org/platform/infra-gitops/-/compare/main...<branch_name>`).
- Only humans are allowed to click the compare link, review the code, and officially open the Merge Request. If they don't like it, they will give feedback to the AI.

> [!WARNING]
> **Antigravity "Automatic Merge" is Broken for Updates**
> Do NOT rely on the Antigravity desktop app's built-in "automatic merge" or update functionality to resolve upstream drift. It frequently fails or creates messy merge commits that break the pipeline. The agent MUST always manually run `git fetch` and `git rebase origin/main`, resolve conflicts via the terminal, and `git push --force-with-lease`.

### 4. Pipeline Monitoring
- The GitLab CI will automatically execute the Golden Path pipelines (which run SAST, DAST, Secret Scanning, and PyTest).
- The `AI-GrillMe MR Bot` CI component will parse the results and post a summary directly to the MR.
- The AI Agent must run `python scripts/devops/gitlab_ops.py mr notes <mr_iid>` (and `mr view <mr_iid>`) to fetch the bot's report and pipeline status.
  - *Note: the agent may need to wait or poll a few times for the pipeline to finish and the bot to comment.*

### 4. Autonomous Feedback Loop
- If the bot reports `[PIPELINE STATUS: FAILED]`, the AI agent must read the attached pipeline logs from the comment, identify the broken tests or linting errors, fix the code locally, and push the branch again.
- The AI must repeat Step 3 until `[PIPELINE STATUS: SUCCESS]` is achieved.

### 5. Circuit Breaker (The "Hopper" Alert)
- If the AI agent attempts to fix the pipeline failures but gets stuck in a loop (failing more than 3 consecutive MR pipeline runs), it MUST trigger the Notification Arbitrator's Agent webhook to summon the user.
- The agent should run a curl command (or Python requests equivalent):
```bash
curl -X POST -H "Content-Type: application/json" -d '{"agent_id": "MR_Agent", "task_type": "Pipeline Loop", "status": "stuck", "reason": "Failed 3 times fixing test_xyz", "mr_url": "http://gitlab.cluster.example.org/..."}' -k https://notifications.cluster.example.org/webhooks/agent
```
- Upon triggering the circuit breaker, the AI must STOP and wait for the user to reply and help debug the issue.

### 6. Hopper Task Completion
- Once the pipeline passes and the work is complete, the agent can optionally dispatch a "success" webhook to the same `/webhooks/agent` endpoint, alerting the user that the task from the hopper is ready for manual review.

### 7. Observability Staging & Ephemeral Dashboard Previews (Epic 47)
- Whenever an MR modifies Grafana dashboards in `grafana/`, CI automatically executes `generate-dashboard-preview` and `capture-visual-diff`.
- **Git-Scoped Previews**: Previews are strictly scoped to dashboards touched in the MR branch.
- **Genuine 1080p Live Capture**: Headless Chromium leverages Grafana's read-only anonymous viewer mode to capture genuine 1920x1080 screenshots of the production baseline vs ephemeral MR preview (`prev-<mr_iid>-<uid>`).
- **Automated Embedding**: `publish-mr-report` uploads both 1080p screenshots to the GitLab project uploads and embeds them under prominent sections in both the MR description and discussion comments.


### 7. User MR Handoff & Persistence (CRITICAL)
- When the AI agent determines the branch is ready, it MUST provide the human user with the direct **Compare Link** (and register it on `https://opscryer.cluster.example.org/mrs` for 1-Click Human MR Creation).
- **Persistence Rules**: Once the human opens the MR, the pipeline is allowed to write to persistence (e.g., sandbox or dev deployments). However, an MR pipeline MUST NEVER promote to production.
- Only a **MERGE** to the default branch (e.g., `main`) is allowed to promote deployments to the production environment.
- After the human opens the MR, the AI can then poll the MR pipeline using `gitlab_ops.py`.

### 8. High-Signal MR Quality Bar & Zero Notification Fatigue (`mr_quality_and_compaction_guard`)
- **Quality Over Junk:** High-quality, tested, conflict-free MRs are strictly favored over low-effort, untested, or conflicted "junk" branches that waste human review time and must be closed. Every second a human reviews code must be spent on real, verified work.
- **5-Point Gold-Tier Gate (Prerequisite for 1-Click Approval):**
  1. Local unit tests and `tests/test_k8s_manifests.py` pass 100%.
  2. Branch is rebased cleanly on `origin/main` (`0` merge conflicts).
  3. Disjoint file-scope lock (no collision with other open Swarm MRs).
  4. Lowercase Conventional Commit subject (`feat(scope): ... (refs #ID)`), `LF` line endings, zero leaked tokens.
  5. Institutional knowledge note captured in `.ai/knowledge/` or `.ai/skills/` so the MR Bot audit reports `PASSED`.
- **Clean GitLab-Native MR Comments:** Never emit raw GitHub `[!WARNING]`/`[!TIP]` alert syntax, un-prefixed blockquote lines, or `file:///` links inside GitLab MR comments or descriptions. See the `mr_quality_and_compaction_guard` skill for full details.

