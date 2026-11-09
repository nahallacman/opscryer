---
name: golden_path_architecture
description: CI/CD Architecture Rules, Golden Paths, Component Development, Semantic Release, and Tagging
---

# Golden Path CI/CD Architecture

This document defines the strict CI/CD architecture for the `infra-gitops` environment. You must adhere to this architecture when provisioning new services, modifying pipelines, or building components.

## Architecture Tiers

The CI/CD ecosystem is divided into three distinct tiers. **Do not create monolithic pipelines.**

### 1. Atomic CI Components
Single-purpose, independent CI capabilities that perform exactly one job (e.g., `scan-sast-semgrep`, `semantic-release`, `build-docker`).
- **Location**: Standalone top-level repositories (e.g., `/scan-sast-semgrep/`).
- **Structure**: Must contain a `templates/template.yml` defining the GitLab CI component inputs and job.

### 2. Golden Path Facades
Meta-components that bundle Atomic CI Components into a cohesive pipeline for a specific deployment type (e.g., `golden-path-backend`, `golden-path-frontend`, `golden-path-cicd-component`).
- **Location**: Standalone top-level repositories.
- **Rule**: Golden Paths **MUST NEVER** define raw CI script execution logic. They must exclusively `include` Atomic CI Components via the `gitlab.cluster.example.org/devops/components/...` path.

### 3. Project Scaffolding Templates
Boilerplate repositories that developers clone to start new projects.
- **Location**: `/golden-path-templates/`
- **Rule**: The `.gitlab-ci.yml` in a scaffolding template MUST only include exactly one Golden Path Facade.

## The Self-Releasing Mechanism (Semantic Release)

All CI Components (both Atomic and Golden Paths) use a centralized mechanism for versioning and publishing.

- Every Atomic Component and Golden Path repository **MUST** have a `.gitlab-ci.yml` in its root directory.
- This root `.gitlab-ci.yml` **MUST ONLY** contain the following inclusion:

```yaml
include:
  - component: $CI_SERVER_FQDN/devops/components/golden-path-cicd-component/template@main
```

By including `golden-path-cicd-component`, the component automatically inherits:
1. Validation (`validate-aicac`)
2. Secret Scanning (`scan-secrets-trufflehog`)
3. Semantic Versioning (`semantic-release`)

## Workflow for Ushering Changes (Tagging & Merging)

When you modify an Atomic Component or a Golden Path:
1. **Never use auto-merge**: The user must review all MRs manually.
2. **Commitlint Strictness**: Commit messages MUST comply with Conventional Commits (e.g., `feat: ...`, `fix: ...`, `chore: ...`). The header must be < 100 chars, and the subject must be lowercase.
3. **Semantic Release Process**:
   - When a branch is merged into `main`, the `semantic-release` job in the `golden-path-cicd-component` pipeline will automatically analyze the commit messages.
   - It will automatically generate a Semantic Version tag (e.g., `v1.0.1`) and push it to the component's repository.
   - Renovate Bot will detect this new tag and automatically open MRs across the ecosystem to bump downstream projects to the new version.

**Do not manually tag CI component releases.** The system is entirely automated via Conventional Commits.
