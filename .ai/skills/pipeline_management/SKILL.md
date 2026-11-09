---
name: pipeline_management
description: Rules for handling stale, failed, or missing pipelines on Merge Requests.
---

# Pipeline Management Skill

This skill defines the autonomous behavior required when an AI agent encounters a missing, failed, stale, or timed-out pipeline on a GitLab Merge Request. 

## Triggers
This skill must be invoked if:
- A pipeline fails after another MR is merged into `main`.
- A pipeline is "stale" (e.g., the MR is behind `main` and requires a rebase or a new pipeline run).
- A pipeline times out.
- A pipeline is missing entirely because of configuration errors preventing GitLab from processing it.

## Required Actions

1. **Do NOT blindly run the pipeline**: If the pipeline has a configuration error or requires manual intervention, do NOT attempt to brute-force run it via API unless you are actively debugging a specific issue.
2. **Inspect Pipeline & MR Status via `gitlab_ops.py`**: Use the pre-approved DevOps CLI runner:
   - **Command**: `python scripts/devops/gitlab_ops.py mr view <mr_iid>` and `python scripts/devops/gitlab_ops.py pipeline trace <job_id>`
   - To retry a transient failure: `python scripts/devops/gitlab_ops.py pipeline retry <job_id>`
3. **Notify in Chat**: If human intervention is required on the MR, inform the human directly in the chat UI with a clickable link to the MR/pipeline.
