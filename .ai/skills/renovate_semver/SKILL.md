---
name: renovate_semver
description: Renovate & Semantic Versioning Rules
---

# Renovate & Semantic Versioning Rules

## 1. Branching & MR Strategy
- **Target Branch**: All Renovate Merge Requests (MRs) must target `main`.
- **Grouping**: Renovate should group updates into a single rolling MR to reduce pipeline spam. 
  - *Agent Note*: Ensure Major updates are excluded from the auto-merging group, as a pending Major update will block the automatic merging of safe Patch/Minor updates.

## 2. Auto-Merge Policy
- **Patch & Minor Updates**: MUST be configured to auto-merge automatically once the CI/CD pipeline (tests) passes.
- **Major Updates**: MUST NOT auto-merge. These require manual review and approval by the user.

## 3. Handling Vulnerable Images
- **Do Not Delete**: If a security scanner flags an image as vulnerable (a "bad" image), do **NOT** delete the image artifact or tag from the container registry (e.g., Harbor). 
- **Track & Replace**: Track the vulnerable image (e.g., in DefectDojo or via an Epic) so there is a historical record.
- **Strict SemVer Usage**: Always use strict semantic versioning tags (e.g., `v1.2.3`) for all deployments. **Never** use mutable tags like `latest`. This ensures that bad images are isolated to their specific version and don't create conflicts.
- **Conflict Resolution**: If a vulnerability forces an update and there are conflicts, continuously increment the semantic version number (bump to the next patch/minor) or investigate the root cause.

## 4. Commit Formatting
- **Conventional Commits**: Renovate and developers must use strict Conventional Commits (e.g., `chore(deps): update dependency...`, `fix: ...`, `feat: ...`).
- Semantic versioning bumps should be automatically driven by these prefixes.

## 5. Scheduling
- **Continuous**: Renovate should run continuously as new versions are released, updating its rolling MRs in real-time.

## 6. Troubleshooting Internal TLS (Node.js)
- **Concept**: Renovate is built on Node.js, which strictly rejects internal Certificate Authorities (like `netfilter-ca`) used by `gitlab.cluster.example.org`. This causes Renovate to fail silently or throw an ambiguous `Authentication failure` because the TLS handshake is rejected before the token is even sent.
- **Current Workaround**: Until Phase 2L is complete, any project running Node.js in CI/CD against internal endpoints must use a `before_script` to dynamically download the public certificate via `openssl` and map it to `NODE_EXTRA_CA_CERTS`.
- **Future Resolution**: Refer to `Architecture/GitLabCI_TLS_Architecture.md`. Once the GitLab Runner is updated to mount the CA globally, agents must remove the `NODE_EXTRA_CA_CERTS` workaround from all CI pipelines.

## 7. SLA & Ticket Bot Rules
- **Monitoring Bot:** A custom Ticket Bot actively monitors all open Renovate MRs across the repositories.
- **SLA Thresholds:** The default SLA for completing a Renovate MR is 14 days. Critical security updates have a stricter SLA of 3 days.
- **Justifications:** If an MR is deliberately left open past its SLA, developers or AI agents MUST write a comment containing the exact keyword `Justification:` explaining the delay, or the MR will trigger "Neglected" alerts.
- **Closed MRs:** If an update is known to be breaking or unwanted, the MR MUST be closed, as the Ticket Bot inherently respects closed MRs as permanently rejected updates.

## 8. NuGet `NU1605` Transitive Floor Lockstep (`ASP.NET Core OpenAPI`)
- **Rule:** In `renovate.json`, `Microsoft.OpenApi` (`< 2.0.0`) and `Swashbuckle.AspNetCore` (`< 7.0.0`) MUST be grouped under `"groupName": "ASP.NET Core OpenAPI (net8.0)"`, and `dependency-mapper/backend/DependencyMapper.Backend.csproj` MUST maintain `Microsoft.OpenApi >= 1.6.31` whenever `Microsoft.AspNetCore.OpenApi >= 8.0.32` is installed.
- **Reasoning:** Prevents Kaniko `dotnet restore` failures (`error NU1605: Detected package downgrade: Microsoft.OpenApi from 1.6.31 to 1.6.22`) when Renovate bumps `Microsoft.AspNetCore.OpenApi` patch releases.
