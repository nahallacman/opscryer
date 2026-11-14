---
name: e2e_cleanup
description: E2E Workspace Cleanup
---

# AI SKILL: E2E Workspace Cleanup

**Purpose:** Provide a standardized procedure for AI agents to idempotently clean up abandoned GitLab workspaces, users, and projects that are left behind if an End-to-End (E2E) test crashes or is interrupted before its automatic teardown phase.

## Context
Our E2E test suite (`<workspace>\tests\e2e-golden-path\e2e\test_e2e_live.py`) dynamically provisions isolated GitLab groups, projects, and users to test CI pipelines, webhooks, and security flares. These entities are strictly prefixed with `e2e-` or `nofail-user-`. 

If the test crashes (e.g. `AssertionError`), the `tearDown()` block might not execute, leaving "ghost" projects polluting the GitLab instance.

## Execution Requirements
Whenever an agent observes an E2E test failure, or the user specifically asks to "clean up test workspaces", the agent **must** run the idempotency script.

### The Script
**Path:** `<workspace>\scripts\cleanup_e2e_workspaces.ps1`

**Parameters:**
- Uses the `GITLAB_TOKEN` environment variable. (Ensure this is set to an admin PAT).

**Behavior:**
1. Queries the `/api/v4/groups` endpoint for any group matching `^e2e-` and deletes it.
2. Queries the `/api/v4/users` endpoint for any user matching `^e2e-` or `^nofail-user-` and performs a `hard_delete`.

### Example Invocation
```powershell
$env:GITLAB_TOKEN="<admin_token>"
.\cleanup_e2e_workspaces.ps1
```

## AI Agent Rules
- **Do NOT** attempt to manually delete projects one by one using API calls via `curl` or python. Always use this centralized script to ensure the regex patterns are strictly followed and we don't accidentally delete production groups.
- If the user asks why the GitLab instance is sluggish or full of weird `e2e-*` projects, immediately propose running this skill.
