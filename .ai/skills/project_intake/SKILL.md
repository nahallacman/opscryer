---
name: project_intake
description: Project Intake & GitOps Governance
---

# AI SKILL: Project Intake & GitOps Governance

**Core Directive:** This document governs how AI Agents onboard new software projects, repositories, or services into the HomeLab Golden Path CI/CD ecosystem. Failure to adhere to these rules will result in the pipeline triggering hard blocks and instantly rejecting your merge request.

## 1. Zero-Test Hard Gate
Every repository integrated into the CI/CD catalog MUST have testing frameworks initialized. The pipeline physically cannot proceed without them.
- **Rule:** Before opening an MR, you must verify at least one test file exists (e.g., `test_*.py`, `*.spec.js`).
- **Action:** If the repository is completely legacy and has no tests, you MUST scaffold a bare minimum `test_sanity.py` (or equivalent) containing an `assert True` or basic structural validation check. 
- **Consequence:** If you fail to do this, the `test-intake-reporter` component will crash the pipeline with a "GOLDEN PATH COMPLIANCE ERROR: ZERO TESTS FOUND" error.

## 2. Test Intake Delta Reporting
When adding new features or E2E validation tests to a repository, the CI pipeline will dynamically generate a Markdown report of every test you added.
- **Rule:** The Human Reviewer will use the `/golden-path-sandbox` ChatOps command to test your specific functions before they approve the merge.
- **Action:** Ensure your tests are hermetic and can run successfully in isolated sandbox environments. Do not hardcode production URLs or secrets.

## 3. Strict Semantic Versioning Enforcement
The Golden Path CI uses a centralized `component-release.yml` catalog script to cut releases automatically. Renovate Bot relies heavily on these tags.
- **Rule:** All tags and releases MUST follow the strict format: `vX.Y.Z` (e.g., `v1.2.3`).
- **Action:** Never use arbitrary naming conventions like `v.bad.release`, `latest`, or `test-tag`. 
- **Consequence:** Pushing a non-compliant tag will cause the CI pipeline to `exit 1` with a massive red banner, blocking the release to prevent Renovate Bot breakages.

## 4. Secret Scanning & Leak Prevention
Every repository MUST be shielded against accidental credential leaks using both local and remote scanning architectures.
- **Rule:** You MUST include the `secret-scanner` component in the `.gitlab-ci.yml` pipeline.
- **Rule:** You MUST scaffold a `.pre-commit-config.yaml` file utilizing the `gitleaks` hook to physically block secrets from being staged locally.
- **Consequence:** If a secret is pushed, the `secret-scanner` will trigger a Flare to `ntfy.sh` and attempt to automatically revoke the token (e.g., calling GitLab API for `glpat-` tokens). 

## 5. Pipeline Construction (Catalog Components)
When scaffolding a new `.gitlab-ci.yml` file for an incoming project, you must NOT write raw pipeline jobs. You MUST inherit from the `components-repo`.
- **Rule:** Use the `include: component:` syntax pointing to the `gitlab.cluster.example.org/devops/components/gitlab-ci-components` catalog.
- **Example Usage:**
  ```yaml
  include:
    - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/test-intake-reporter@main
      inputs:
        stage: test
        
    - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/secret-scanner@main
      inputs:
        stage: test
  ```
- **Self-Testing Rule:** If you are modifying the `components-repo` itself, you must use `@$CI_COMMIT_SHA` to ensure the MR tests the modified component instead of the `main` branch.

## 6. Artifact Traceability
Every GitLab Release is automatically injected with the CI Pipeline ID and the exact commit SHA that validated it.
- **Rule:** When modifying logic, always trace your MRs and PRs back to the specific Roadmap Epic/Phase (Epic -> Issue -> PR). Never commit code without a tracking ID.


## 7. Dynamic Scaffolding & Overloading
When scaffolding a brand new project during intake, you do not need to rigidly follow a strict pre-determined template. 
- **Rule:** You MUST dynamically compose the project template (src, tests, docs, etc.) as you go, ensuring it is reasonably structured for the specific language/framework.
- **Rule:** The template architecture MUST be designed to be reasonable for overloading (e.g., using environment variables, clean class hierarchies, or modular entrypoints) to allow future expansion without rewriting core logic.

## 8. Open-Source Sovereignty & License Auditing
Before ingesting any new third-party dependency, Helm chart, or container image into the cluster, a strict license audit is mandatory.
- **Rule:** You MUST evaluate the software for restrictive licenses (e.g., BSL, SSPL) or heavy corporate vendor lock-in risks.
- **Action:** Prioritize MIT, Apache 2.0, or GPL licensed software to ensure long-term sovereignty of the homelab.
- **Consequence:** If a BSL/SSPL or highly restrictive license is detected, you MUST pause the intake and prompt the Human Reviewer for an explicit override before proceeding.
