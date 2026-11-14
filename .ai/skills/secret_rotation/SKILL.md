---
name: secret_rotation
description: Incident Response & Secret Rotation
---

# AI SKILL: Incident Response & Secret Rotation

**Core Directive:** This document governs how AI Agents respond to Critical Security Incidents where secrets (API Keys, Passwords, Private Keys) have been inadvertently leaked or compromised.

## 1. The Incident Pipeline
When the Golden Path `secret-scanner` component detects a leaked credential during CI execution, it will automatically:
1. **Fire a Flare:** Alert the human administrator via `ntfy.sh`.
2. **Crash the Pipeline:** Instantly terminate the CI job (`exit 1`) to prevent further deployment.
3. **Execute Auto-Revocation:** Automatically attempt to revoke the exact token exposed by calling upstream APIs (e.g., GitLab token revocation API).

## 2. Agent Auto-Revocation Extensibility
The current `secret-scanner` component natively supports auto-revoking GitLab Personal Access Tokens (`glpat-`). If an Agent detects that another provider is frequently being leaked (e.g., AWS, Tailscale, Cloudflare), they are tasked with extending the auto-revocation bash script.

### Rules for Extending Auto-Revocation:
- **Do NOT depend on external Python libraries:** The component runs in `zricethezav/gitleaks:latest` which is built on Alpine Linux. You have access to `curl`, `jq`, and `bash`.
- **Verify the Auth Payload:** The revoked secret MUST be sent over a secure HTTPS payload natively supporting the upstream provider's revocation endpoint. Do NOT log the secret.
- **Fail Gracefully:** If the auto-revocation fails (e.g., 401 Unauthorized because the token lacks self-revocation scope), the script must catch the HTTP error code and inform the human administrator via the `ntfy.sh` flare without breaking the core pipeline failure exit code.

## 3. Human Operator Cleanup
If an Agent is tasked by a human operator to clean up a leaked secret from Git history, they must:
1. Use `git filter-repo` or BFG Repo-Cleaner to completely obliterate the secret from the branch history.
2. Force push the rewritten history.
3. Validate that the Golden Path `secret-scanner` passes on the next CI run.
