---
name: gitlab-workflow
description: >-
  Standard operating procedures and CLI automation for GitLab DevOps operations:
  tracking and viewing Merge Requests, inspecting CI pipelines and failed job logs,
  listing and creating Tasks and Epics, and managing git branches without ad-hoc scripts.
---

# GitLab Workflow & DevOps Automation Skill

This skill standardizes all interactions with `gitlab.cluster.example.org` using the unified DevOps CLI tool [`scripts/devops/gitlab_ops.py`](file:///<workspace>/scripts/devops/gitlab_ops.py).

---

## 1. Quick Reference Commands

| Task | Command |
| :--- | :--- |
| **List Open MRs** | `python scripts/devops/gitlab_ops.py mr list` |
| **View MR Details & Pipeline** | `python scripts/devops/gitlab_ops.py mr view <MR_IID>` |
| **View MR Changed Files** | `python scripts/devops/gitlab_ops.py mr diff <MR_IID>` |
| **View MR Notes & Comments** | `python scripts/devops/gitlab_ops.py mr notes <MR_IID> [--limit 10]` |
| **Create New MR** | `python scripts/devops/gitlab_ops.py mr create --source <branch> --title <title> --desc <desc> [--desc-file <path>]` |
| **Update Existing MR** | `python scripts/devops/gitlab_ops.py mr update <MR_IID> [--title <title>] [--desc <desc>] [--desc-file <path>]` |
| **List Recent Pipelines** | `python scripts/devops/gitlab_ops.py pipeline list [--ref <branch>] [--limit 10]` |
| **View Pipeline Jobs** | `python scripts/devops/gitlab_ops.py pipeline view <PIPELINE_ID>` |
| **Watch Pipeline** | `python scripts/devops/gitlab_ops.py pipeline watch <PIPELINE_ID>` |
| **Inspect Failed Job Log** | `python scripts/devops/gitlab_ops.py pipeline trace <JOB_ID> [--tail 100]` |
| **Retry Failed Job** | `python scripts/devops/gitlab_ops.py pipeline retry <JOB_ID>` |
| **Download Job Artifact** | `python scripts/devops/gitlab_ops.py artifact download <JOB_ID> <path> [--output <dest>]` |
| **List Open Tasks / Work Items** | `python scripts/devops/gitlab_ops.py task list [--label <label>]` |
| **View Task Details** | `python scripts/devops/gitlab_ops.py task view <TASK_IID>` |
| **Create New Task** | `python scripts/devops/gitlab_ops.py task create --title <title> --desc <desc> [--labels <l1,l2>] [--epic-id <id>]` |
| **Close Task / Work Item** | `python scripts/devops/gitlab_ops.py task close <TASK_IID> [--comment <note>]` |
| **List Epics** | `python scripts/devops/gitlab_ops.py epic list` |
| **Create New Epic** | `python scripts/devops/gitlab_ops.py epic create --title <title> --desc <desc>` |
| **List PATs** | `python scripts/devops/gitlab_ops.py token list [--user-id <id>] [--state active]` |
| **Verify PAT String** | `python scripts/devops/gitlab_ops.py token verify <TOKEN_STRING>` |
| **Create PAT for User** | `python scripts/devops/gitlab_ops.py token create --user-id <id> --name <name> [--scopes api,read_repository,write_repository]` |
| **Rotate PAT** | `python scripts/devops/gitlab_ops.py token rotate <TOKEN_ID> [--expires-at YYYY-MM-DD]` |
| **Revoke PAT** | `python scripts/devops/gitlab_ops.py token revoke <TOKEN_ID>` |

---

## 2. Standard Workflow Guidelines

### 🔒 Strict Merge Rules
* **NEVER Auto-Merge:** The AI agent must **NEVER** merge or auto-merge any Merge Request under any circumstances. All MRs must remain strictly in open state for user manual review and manual merge.

### 📝 Commit & Traceability Standards (Epic 3G: Requirements -> Code)
All commits and Merge Requests MUST maintain 100% requirements-to-code traceability enforced by `scripts/ci/validate_traceability.py` during CI:

1. **Conventional Commit Header:**
   - Maximum length: $\le 100$ characters, all lowercase subject.
   - Must include issue or phase reference: `feat(scope): short description (Refs #<id>)` or `(Phase <X>)`
2. **Commit Body:**
   - Line length: $\le 100$ characters.
   - Include issue/epic references: `Refs #<id>, Phase <X>`
3. **Merge Request Description Template:**
   MR descriptions must contain the standardized Traceability Block linking to Master Roadmap and active GitLab Issues:
   ```markdown
   ## 🎯 Traceability & Requirements Mapping
   - **Master Roadmap:** `Phase <X>: <Phase Title>` (Epic <Y>)
   - **Resolves Issue:** #<ID> ([View Issue](https://gitlab.cluster.example.org/platform/infra-gitops/-/work_items/<ID>))
   - **Risk Classification:** **<Normal/HIGH/CRITICAL>**

   ## 📝 Description of Changes
   <Summary of changes>

   ### 🔍 Verification & Audit Checklist
   - [x] Pre-commit hooks & Secret scanning validated (Gitleaks)
   - [x] Conventional commit format verified
   - [x] Traceability metadata mapped to Roadmap and GitLab Issue
   ```

### 🚨 Traceability Audit Remediation
If a pipeline fails on the `traceability-audit` job with:
```text
[!] ERROR: Traceability policy violation!
No GitLab Issue (e.g., '#176' or 'Refs #176') or Roadmap Epic reference found.
```
**Remediation Steps:**
1. Identify the associated Roadmap Phase and GitLab Issue (using `python scripts/devops/gitlab_ops.py task list` or `PersonalProjectDocumentation/Master_Roadmap.md`).
2. Update the MR description on GitLab using `gitlab_ops.py`:
   ```bash
   python scripts/devops/gitlab_ops.py mr update <MR_IID> --desc-file <path_to_desc.md>
   ```
3. Retry the failed `traceability-audit` job:
   ```bash
   python scripts/devops/gitlab_ops.py pipeline retry <JOB_ID>
   ```

### 🗺️ Traceability Matrix Refresh (Post-Merge)
Whenever a Merge Request is merged to `main`, run the dynamic generator to keep the living matrix up to date:
```bash
python scripts/ci/generate_traceability_matrix.py
```
This updates `PersonalProjectDocumentation/Traceability_Matrix.md`.

### 🚀 CI Pipeline Debugging Procedure
When an MR pipeline fails:
1. Run `python scripts/devops/gitlab_ops.py mr view <MR_IID>` to identify which job failed.
2. Run `python scripts/devops/gitlab_ops.py pipeline trace <JOB_ID> --tail 50` to inspect the exact failure message.
3. Fix the issue on the branch, commit, push, and monitor until all required jobs are green.
