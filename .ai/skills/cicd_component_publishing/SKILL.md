---
name: cicd_component_publishing
description: CI/CD Component Tagging & Publishing Rules
---

# AI SKILL: CI/CD Component Publishing

**Core Directive:** This document governs how AI Agents handle releases for CI/CD components or any template-based module that relies on Semantic Versioning tags to trigger a deployment.

## 1. The Automated Semantic Release Pipeline
CI/CD Components (like those scaffolded with `template-ci-component`) utilize `release-it` to automatically cut releases, generate changelogs, and bump semantic versions.
- Merging to `main` **automatically** triggers the `semantic-release` pipeline job.
- You do NOT need to push tags manually. The CI pipeline will analyze the commit history, mathematically determine the next SemVer tag, and push it to the repository itself!

## 2. Mandatory Conventional Commits
Because human/AI intervention is removed from the tagging process, the CI pipeline relies 100% on **Conventional Commits** to understand what version to bump.

- **Rule 1:** NEVER ask the Human Reviewer for a manual tag.
- **Rule 2:** Every Merge Request you create MUST use a strict Conventional Commit prefix in the title.
  - `feat: xyz` -> Triggers a Minor version bump (`v1.0.0` -> `v1.1.0`)
  - `fix: xyz` -> Triggers a Patch version bump (`v1.0.0` -> `v1.0.1`)
  - `feat!: xyz` (or `BREAKING CHANGE:`) -> Triggers a Major version bump (`v1.0.0` -> `v2.0.0`)
- **Rule 3:** Do NOT use arbitrary prefixes like `update:`, `changed:`, or `wip:`. If you fail to use `feat:` or `fix:`, the `release-it` engine will completely ignore the MR and will NOT cut a new release!

## 3. Handling Validation Failures
If the `semantic-release` pipeline fails (e.g., due to a syntax error or a failing `validate-aicac` step):
- Do NOT attempt to manually force a tag.
- You MUST fix the underlying code, push the new commit via an MR, and allow the pipeline to run again.
