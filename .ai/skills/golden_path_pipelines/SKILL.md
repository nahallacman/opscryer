---
name: golden_path_pipelines
description: Golden Path CI/CD Pipeline Generation
---

# AI Skill: Golden Path CI/CD Pipeline Generation

## Overview
This skill instructs AI agents on how to autonomously construct standard, secure, and compliant `.gitlab-ci.yml` pipelines for newly ingested applications using the centralized `gitlab-ci-components` catalog.

## The Catalog Address
All internal CI/CD components must be sourced from:
`gitlab.cluster.example.org/devops/components/gitlab-ci-components/<COMPONENT_NAME>@main`

## Available Components
1. **lint-test-js**: Runs ESLint and Jest.
   - `inputs: src_dir` (default: ".")
2. **lint-test-python**: Runs flake8 and pytest.
   - `inputs: src_dir` (default: ".")
3. **build-docker**: Builds and pushes Docker images to the internal registry.
   - `inputs: image_name`, `dockerfile_path`, `context_dir`, `stage`
4. **deploy-gitops**: Pushes updated tags to the ArgoCD manifests.
   - `inputs: environment`, `manifest_path`
5. **utility-run**: Generic script execution wrapper.

## SOP: Generating a Pipeline
When tasked with onboarding a new repository, follow these strict steps to compose the pipeline:

1. **Analyze the Architecture:** Determine if the project is a single-frontend, single-backend, or complex full-stack application.
2. **Consult the Golden Path Templates:** Review `<workspace>\golden-path-templates` to find the exact architecture match. Do not invent custom stages unless the architecture fundamentally deviates from the templates.
3. **Assemble the `include` Block:** 
   - Define all pipeline stages in the exact following order: `test`, `build`, `deploy`. If it's a full-stack, split the build stages (e.g., `build-backend`, `build-frontend`).
   - Use the `- component:` syntax for every step. Do not write raw `script:` blocks in the `.gitlab-ci.yml` unless invoking `utility-run`.
4. **Strict Secrets Policy:** Never inject secrets directly into the pipeline variables. Rely on the `deploy-gitops` component to handle secure syncing via External-Secrets.

## Example: Full-Stack Complex Pipeline
```yaml
include:
  - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/lint-test-python@main
    inputs:
      src_dir: "backend"
  - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/lint-test-js@main
    inputs:
      src_dir: "frontend"
  - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/build-docker@main
    inputs:
      image_name: "fullstack-backend"
      dockerfile_path: "backend/Dockerfile"
      context_dir: "backend"
      stage: "build-backend"
  - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/build-docker@main
    inputs:
      image_name: "fullstack-frontend"
      dockerfile_path: "frontend/Dockerfile"
      context_dir: "frontend"
      stage: "build-frontend"
  - component: gitlab.cluster.example.org/devops/components/gitlab-ci-components/deploy-gitops@main
    inputs:
      environment: "staging"
      manifest_path: "k8s/overlays/staging"

stages:
  - test
  - build-backend
  - build-frontend
  - deploy
```

## Execution Hard-Rails
- **NEVER** modify the component logic inside `devops/components`. Only consume them via inputs.
- **NEVER** use `latest` tags for the `component-release` or downstream Docker images unless explicitly developing in the `sandbox` environment.
