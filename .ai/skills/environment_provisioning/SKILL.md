---
name: environment_provisioning
description: Rules and Target Architectures for Ephemeral and Static Environments
---

# AI SKILL: Environment Provisioning

**Core Directive:** This skill governs how AI Agents design, scaffold, and deploy Kubernetes namespaces and environments for the applications they build. It enforces strict separation between testing (Ephemeral) and production (Static) workloads.

## 1. Dual-Environment Architecture

You must strictly adhere to the following environment classification when designing Helm charts, Kustomize overlays, or GitLab CI/CD deploy jobs:

### A. Ephemeral Environments (MR Validation)
- **Purpose:** Used strictly for running End-to-End (E2E) test suites dynamically during a Merge Request (MR).
- **Naming Convention:** `pr-<mr_id>-<app_name>` (e.g., `pr-123-frontend`).
- **Lifecycle:** 
  1. The CI pipeline spins up this namespace automatically.
  2. The application and its mocked dependencies (e.g., databases) are deployed into it.
  3. The automated E2E tests are executed against the active pods.
  4. The namespace is **destroyed** at the end of the pipeline, regardless of test pass/fail status.
- **Rule:** Never deploy an Ephemeral environment manually. It must be strictly managed by the CI/CD pipeline lifecycle (e.g., using GitLab Review Apps).

### B. Static Environments (Persistent Releases)
- **Purpose:** Used for persistent, human-facing, and production workloads.
- **Naming Convention:** `staging`, `test`, and `prod`.
- **Lifecycle:**
  1. Once an MR is merged and a Semantic Release tag (e.g., `v1.0.0`) is cut, the artifact is pushed to the registry.
  2. ArgoCD (or the Golden Path deployment pipeline) detects the new tag and syncs it to the `staging` namespace.
  3. After synthetic checks pass in staging, it is promoted to `prod`.
- **Rule:** AI Agents are strictly forbidden from deploying directly to `prod`. All modifications to persistent environments must be executed via GitOps commits to the cluster repository.

## 2. CI/CD Integration Mandates
When modifying the Golden Path templates (e.g., `template-frontend`, `template-backend`), you must ensure that:
1. The `test` stage actively deploys the Ephemeral Environment.
2. The `deploy` stage is restricted to Semantic Release tags and targets the Static Environments.

## 3. Renovate E2E Testing
Renovate Bot creates MRs to update dependencies. Because Ephemeral Environments are tied to the MR lifecycle, Renovate PRs **will natively trigger full E2E environment testing** before human approval is required. Never bypass or disable Ephemeral Environment E2E testing for Renovate branches.
