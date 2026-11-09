---
name: kubernetes_manifest_standards
description: Kubernetes Manifest Standards & GitOps Guidelines
---

# Kubernetes Manifest Standards & GitOps Guidelines

This document serves as the absolute source of truth for generating or modifying Kubernetes YAML manifests in this repository. All AI agents MUST strictly adhere to these rules. Failure to do so will result in CI pipeline failures and a broken GitOps deployment loop.

## 1. The `default` Namespace is BANNED
Under no circumstances should any application, secret, configmap, or custom resource be deployed into the `default` namespace. 
- **Rule:** Do not use `namespace: default` in any manifest.
- **Why:** Deploying to the `default` namespace creates "cluster orphans" and violates our strict logical separation of applications, making RBAC and NetworkPolicies impossible to enforce cleanly.

## 2. Explicit Namespaces are REQUIRED
Every namespace-scoped resource (Deployment, Service, Ingress, Secret, PVC, ConfigMap, etc.) MUST explicitly declare a `namespace:` field in its metadata.
- **Rule:** Never omit the `namespace:` field, assuming it will automatically deploy correctly.
- **Exception:** Cluster-scoped resources (e.g., `ClusterRole`, `ClusterRoleBinding`, `ClusterIssuer`, `Namespace`, `CustomResourceDefinition`) do not require a namespace field.

## 3. Namespace Grouping
When creating new applications, logically group them into descriptive namespaces. Examples (not exhaustive):
- `media`: Media stack applications (Jellyfin, Sonarr, etc.)
- `iam`: Identity and Access Management (Keycloak, LLDAP, Authentik)
- `security`: Security dashboards, auditing, and vault/secret management
- `monitoring`: Prometheus, Grafana, Alertmanager
- `cals-aggregator`: Data aggregation and specialized pipelines
- `sandbox`: Experimental or temporary bot deployments

*(Note: Granular access control is managed via RBAC later on, so keep the namespaces generic and logically grouped.)*

## 4. AI Self-Check Mandate (CRITICAL)
Before you commit any changes to Kubernetes YAML files, you **MUST** run the mechanical validation script to check your own work.
- **Command:** `python tests/test_k8s_manifests.py`
- **Action:** If the script fails, you must read the error output and fix the offending YAML files. Do not commit failing code. Do not ask the user for permission to fix your own mistakes. Just fix them.

## 5. Legacy Exceptions
We have an established `k8s_manifest_exceptions.txt` list used by the test script for legacy files that have not yet been assimilated into proper namespaces. 
- **Rule:** You are NOT allowed to add new files to the exception list. You must write compliant YAML.

## 6. Grafana Dashboard Standards (Jsonnet & Grafonnet)
- **Monolithic YAML Banned:** Do not write raw monolithic YAML or JSON for Grafana dashboards.
- **Jsonnet Native:** All Grafana dashboards MUST be written as modular `.libsonnet` / `.jsonnet` components using the official `grafonnet` library.
- **ArgoCD Compilation:** Place dashboard code in `grafana/dashboards/` and rely on ArgoCD's native Jsonnet directory plugin (with `dashboards/vendor` added to the `JPATH`) to compile the ConfigMaps automatically on the server.
