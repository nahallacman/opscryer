#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Canonical single source of truth for OpsCryer Knowledge Base articles, Jev decision tree, and K8s graph overlays."""

from __future__ import annotations

from typing import Any


KNOWLEDGE_BASE_ARTICLES: tuple[dict[str, Any], ...] = (
    {
        "article_id": "KB-DB-001",
        "title": "Deploying a PostgreSQL Database on the Golden Path (CloudNativePG + OpenBao ExternalSecret)",
        "category": "Database & Secret Provisioning",
        "pattern": r"\b(databases?|postgres(?:ql)?|cnpg|sql|schema|db)\b",
        "summary": (
            "Deploy PostgreSQL in infra-gitops by declaring a CloudNativePG Cluster resource "
            "backed by OpenZFS ZFS storage (openzfs-iscsi-csi) and injecting credentials "
            "automatically from OpenBao via an ExternalSecret with Reloader auto-rotation."
        ),
        "steps": [
            "Open ticket IT-PLAT-GP-01 (Golden Path database provisioning) and IT-SEC-DB-01 (OpenBao secret path registration).",
            "Create a postgresql.cnpg.io/v1 Cluster manifest with instances: 2 and storageClass: openzfs-iscsi-csi.",
            "Create an external-secrets.io/v1beta1 ExternalSecret pointing to secret/data/<namespace>/<app>-db in OpenBao.",
            "Annotate your application Deployment with reloader.stakater.com/auto: \"true\" and deploy via the Golden Path deploy-gitops@main component.",
        ],
        "reference_snippet": (
            "apiVersion: postgresql.cnpg.io/v1\n"
            "kind: Cluster\n"
            "metadata:\n"
            "  name: app-postgres-cluster\n"
            "spec:\n"
            "  instances: 2\n"
            "  storage:\n"
            "    size: 20Gi\n"
            "    storageClass: openzfs-iscsi-csi"
        ),
        "focused_citations": [
            "k8s/Deployment/cnpg-system/cnpg-cloudnative-pg",
            "k8s/Deployment/kube-system/external-secrets",
            "k8s/Deployment/iam/openbao-agent-injector",
            "k8s/Deployment/storage-system/zfs-nfs-driver-democratic-csi-controller",
        ],
    },
    {
        "article_id": "KB-GP-002",
        "title": "Scaffolding a 3-Tier Application & Golden Path CI/CD Pipeline",
        "category": "CI/CD & Project Intake",
        "pattern": r"\b(scaffold(?:ing)?|3-tier|pipelines?|gitlab-ci|golden[\s_-]*path)\b",
        "summary": (
            "All downstream repositories use modular Golden Path CI/CD components "
            "(lint-test, secret-scanner, build-docker, deploy-gitops) with ephemeral MR review environments."
        ),
        "steps": [
            "Request ticket IT-DEMO-GP-01 / IT-PLAT-GP-01 for Golden Path repository intake.",
            "Include gitlab.cluster.example.org/devops/components/golden-path/pipeline@main in .gitlab-ci.yml (never raw script blocks).",
            "Push a feature branch and use the GitLab compare link for human MR review.",
        ],
        "reference_snippet": (
            "include:\n"
            "  - component: gitlab.cluster.example.org/devops/components/golden-path/pipeline@main\n"
            "    inputs:\n"
            "      app_name: my-three-tier-app"
        ),
        "focused_citations": [
            "k8s/Deployment/gitlab/gitlab",
            "k8s/Deployment/gitlab/gitlab-gitlab-runner",
            "k8s/Deployment/argocd/argocd-server",
            "k8s/Deployment/harbor/harbor-core",
        ],
    },
    {
        "article_id": "KB-GAME-003",
        "title": "Homelab Game Server Pod Triage & Cross-Tool Grafana Debugging (Minecraft / Factorio / Satisfactory)",
        "category": "Game Servers & Observability",
        "pattern": r"\b(minecraft|factorio|satisfactory|palworld|game\s+server|pods?\s+are\s+down|tick\s+lag)\b",
        "summary": (
            "Isolate game server disruptions across Layer 1 (game-servers namespace pods), "
            "Layer 2 (.cluster.example.org LAN DNS), and Layer 3 (client GPU/APU), then pivot to Grafana and RunbookGate."
        ),
        "steps": [
            "Check game-servers Deployment and Pod readiness (minecraft-survival, minecraft-creative, factorio, satisfactory).",
            "Open https://grafana.cluster.example.org/dashboards and /games to inspect server tick time, container restarts, and host load.",
            "Verify OpenZFS ZFS NFS persistent volume health before running an approved RunbookGate restart runbook.",
        ],
        "reference_snippet": (
            "kubectl get pods -n game-servers -o wide\n"
            "kubectl describe pod -n game-servers -l app=minecraft-survival"
        ),
        "focused_citations": [
            "k8s/Deployment/game-servers/minecraft-survival",
            "k8s/Deployment/game-servers/factorio",
            "k8s/Deployment/game-servers/satisfactory",
            "k8s/Deployment/monitoring/kube-prometheus-stack-grafana",
        ],
    },
    {
        "article_id": "KB-DNS-004",
        "title": "Split-Horizon .cluster.example.org LAN DNS & Ingress Routing Runbook",
        "category": "Network & Ingress",
        "pattern": r"\.cluster\.example\.org\b|\b(dns|nxdomain|split[\s_-]*horizon|hostname|ingress)\b",
        "summary": (
            "Internal .cluster.example.org records resolve via split-horizon DNS on NetFilter (10.20.3.1) "
            "to the NGINX Ingress controller VIP (172.20.1.210) with Authentik OIDC forward-auth."
        ),
        "steps": [
            "Compare direct RFC 1918 LAN IP reachability against the .cluster.example.org hostname.",
            "Verify CoreDNS and ingress-nginx-controller pods are Ready and check TLS certificates in cert-manager.",
        ],
        "reference_snippet": (
            "nslookup game.cluster.example.org 10.20.3.1\n"
            "kubectl get ingress,svc -A"
        ),
        "focused_citations": [
            "k8s/Deployment/ingress-nginx/ingress-nginx-controller",
            "k8s/Deployment/kube-system/coredns",
            "k8s/Deployment/cert-manager/cert-manager",
            "k8s/Deployment/iam/authentik-server",
        ],
    },
    {
        "article_id": "KB-GPU-005",
        "title": "4-GPU Workload Switchboard (RTX 3080 / RTX 3070 Ti / 2x GTX 1080 Ti) & Client FPS Triage",
        "category": "GPU & Compute Capacity",
        "pattern": r"\b(gpus?|fps|vram|bc[\s_-]*250|thermals?|stutter)\b",
        "summary": (
            "Each GPU is assigned exclusively to AI swarm or LAN gaming with zero cross-node VRAM pooling "
            "(verified 4-GPU inventory: 1x RTX 3080 10GB, 1x RTX 3070 Ti 8GB, 2x GTX 1080 Ti 11GB each = 40 GB VRAM)."
        ),
        "steps": [
            "Compare frame times on a second client to isolate local GPU/APU-200 APU thermal throttling from server lag.",
            "Check competing Ollama GPU worker reservations in ai-infra before switching the GPU profile.",
        ],
        "reference_snippet": (
            "kubectl get pods -n ai-infra -o wide\n"
            "kubectl get pods -n gaming -o wide"
        ),
        "focused_citations": [
            "k8s/Deployment/ai-infra/ollama-gpu-worker",
            "k8s/Deployment/ai-infra/ollama-desktop-gpu-worker",
            "k8s/Deployment/gaming/steam-headless",
            "k8s/Node//nodegamma03",
        ],
    },
    {
        "article_id": "KB-STOR-007",
        "title": "Provisioning Persistent Storage on OpenZFS ZFS (NFS & iSCSI Democratic-CSI)",
        "category": "Storage & Persistence",
        "pattern": r"\b(storage|pvc|openzfs|zfs|nfs|iscsi|volumes?|seaweedfs|s3)\b",
        "summary": (
            "Stateful workloads bind PersistentVolumeClaims through democratic-csi against "
            "OpenZFS ZFS datasets (openzfs-iscsi-csi for block databases, zfs-nfs for shared media/game worlds)."
        ),
        "steps": [
            "Select openzfs-iscsi-csi for RWO block workloads (PostgreSQL/CNPG) or zfs-nfs for shared RWX directories.",
            "Declare a PersistentVolumeClaim in your Golden Path Helm/Kustomize manifest and verify Bound status.",
            "For S3 object storage, request a bucket path on SeaweedFS (storage namespace) via OpenBao ExternalSecret.",
        ],
        "reference_snippet": (
            "apiVersion: v1\n"
            "kind: PersistentVolumeClaim\n"
            "metadata:\n"
            "  name: app-data-pvc\n"
            "spec:\n"
            "  accessModes: [ReadWriteOnce]\n"
            "  storageClassName: openzfs-iscsi-csi\n"
            "  resources:\n"
            "    requests:\n"
            "      storage: 20Gi"
        ),
        "focused_citations": [
            "k8s/Deployment/storage-system/zfs-nfs-driver-democratic-csi-controller",
            "k8s/Deployment/storage/seaweedfs-master",
            "k8s/Deployment/storage/seaweedfs-volume",
            "k8s/Deployment/cnpg-system/cnpg-cloudnative-pg",
        ],
    },
    {
        "article_id": "KB-IAM-008",
        "title": "Authentik SSO / OIDC Forward-Auth & Zero-Knowledge Secret Injection (OpenBao)",
        "category": "Identity, SSO & Security",
        "pattern": r"\b(sso|oidc|authentik|oauth|login|rbac|openbao|external[\s_-]*secrets?)\b",
        "summary": (
            "All browser portals behind .cluster.example.org use Authentik OIDC or NGINX forward-auth outposts, "
            "while runtime secrets are injected from OpenBao via ExternalSecrets with zero plaintext in Git."
        ),
        "steps": [
            "Register an OAuth2/OIDC Provider and Application in Authentik (iam namespace) and bind group RBAC.",
            "Add nginx.ingress.kubernetes.io/auth-url annotations for forward-auth or configure native OIDC client ID via ExternalSecret.",
            "Verify pod security context compliance (runAsNonRoot: true, readOnlyRootFilesystem: true, drop: [ALL]).",
        ],
        "reference_snippet": (
            "apiVersion: external-secrets.io/v1beta1\n"
            "kind: ExternalSecret\n"
            "metadata:\n"
            "  name: app-oidc-secret\n"
            "spec:\n"
            "  secretStoreRef:\n"
            "    name: openbao-backend\n"
            "    kind: ClusterSecretStore"
        ),
        "focused_citations": [
            "k8s/Deployment/iam/authentik-server",
            "k8s/Deployment/iam/authentik-worker",
            "k8s/Deployment/iam/openbao-agent-injector",
            "k8s/Deployment/kube-system/external-secrets",
        ],
    },
    {
        "article_id": "KB-GITOPS-009",
        "title": "ArgoCD GitOps Sync, Renovate SemVer & Human-Gated Merge Request Promotion",
        "category": "GitOps & Release Engineering",
        "pattern": r"\b(argocd|gitops|sync|renovate|releases?|merge\s+requests?|rollout)\b",
        "summary": (
            "ArgoCD continuously reconciles Kubernetes manifests from GitLab after human MR approval; "
            "AI agents push feature branches and compare links but never auto-merge."
        ),
        "steps": [
            "Push changes on a feature branch with lowercase Conventional Commits and pass the 6-gate CI pipeline.",
            "Open the GitLab compare link for human review and merge to main.",
            "Verify ArgoCD Application sync status at https://argocd.cluster.example.org and monitor pod rollout.",
        ],
        "reference_snippet": (
            "kubectl get applications -n argocd\n"
            "kubectl rollout status deployment/<app-name> -n <namespace>"
        ),
        "focused_citations": [
            "k8s/Deployment/argocd/argocd-server",
            "k8s/Deployment/argocd/argocd-repo-server",
            "k8s/Deployment/gitlab/gitlab",
            "k8s/Deployment/harbor/harbor-core",
        ],
    },
    {
        "article_id": "KB-OPS-006",
        "title": "Cluster Node Health, nodebeta02 NotReady & Failed Runner Pod Triage",
        "category": "Cluster Operations & SRE",
        "pattern": r".*",
        "summary": (
            "Correlate Kubernetes node readiness (nodealpha01, nodegamma03, nodebeta02) "
            "with failed GitLab runner job pods and N-1 drain headroom."
        ),
        "steps": [
            "Inspect NotReady node conditions on nodebeta02 and review N-1 drain simulation in /capacity.",
            "Review failed concurrent runner pods in the gitlab namespace and check active SEV incidents in /incidents.",
        ],
        "reference_snippet": (
            "kubectl get nodes -o wide\n"
            "kubectl get pods -n gitlab --field-selector=status.phase=Failed"
        ),
        "focused_citations": [
            "k8s/Node//nodebeta02",
            "k8s/Node//nodegamma03",
            "k8s/Node//nodealpha01",
            "k8s/Deployment/gitlab/gitlab-gitlab-runner",
        ],
    },
)


CONCIERGE_JEV_TREE: dict[str, Any] = {
    "schema_version": "1.0-system-one-decision-tree",
    "root_node_id": "node-check-database",
    "default_min_confidence": 0.80,
    "nodes": {
        "node-check-database": {
            "node_id": "node-check-database", "kind": "decision",
            "predicate_id": "is_database_provisioning",
            "true_branch": "leaf-kb-db-001", "false_branch": "node-check-scaffolding",
            "anchor_node_id": "proc-demo-secret-policy",
        },
        "node-check-scaffolding": {
            "node_id": "node-check-scaffolding", "kind": "decision",
            "predicate_id": "is_project_scaffolding",
            "true_branch": "leaf-kb-gp-002", "false_branch": "node-check-storage",
            "anchor_node_id": "proc-demo-cicd",
        },
        "node-check-storage": {
            "node_id": "node-check-storage", "kind": "decision",
            "predicate_id": "is_storage_provisioning",
            "true_branch": "leaf-kb-stor-007", "false_branch": "node-check-sso",
            "anchor_node_id": "deploy-demo-k8s",
        },
        "node-check-sso": {
            "node_id": "node-check-sso", "kind": "decision",
            "predicate_id": "is_sso_identity",
            "true_branch": "leaf-kb-iam-008", "false_branch": "node-check-game-servers",
            "anchor_node_id": "proc-demo-secret-policy",
        },
        "node-check-game-servers": {
            "node_id": "node-check-game-servers", "kind": "decision",
            "predicate_id": "is_game_server_issue",
            "true_branch": "leaf-kb-game-003", "false_branch": "node-check-dns-ingress",
            "anchor_node_id": "deploy-demo-k8s",
        },
        "node-check-dns-ingress": {
            "node_id": "node-check-dns-ingress", "kind": "decision",
            "predicate_id": "is_dns_or_ingress_issue",
            "true_branch": "leaf-kb-dns-004", "false_branch": "node-check-gpu-fps",
            "anchor_node_id": "deploy-demo-k8s",
        },
        "node-check-gpu-fps": {
            "node_id": "node-check-gpu-fps", "kind": "decision",
            "predicate_id": "is_gpu_or_fps_issue",
            "true_branch": "leaf-kb-gpu-005", "false_branch": "leaf-kb-ops-006",
            "anchor_node_id": "hw-demo-gpu-node",
        },
        "leaf-kb-db-001": {
            "node_id": "leaf-kb-db-001", "kind": "leaf",
            "policy_id": "playbook-golden-path-database-cnpg",
            "direct_access_allowed": True, "required_it_tickets": ["IT-PLAT-GP-01", "IT-SEC-DB-01"],
            "anchor_node_id": "proc-demo-secret-policy",
        },
        "leaf-kb-gp-002": {
            "node_id": "leaf-kb-gp-002", "kind": "leaf",
            "policy_id": "playbook-demo-golden-path-3tier",
            "direct_access_allowed": True, "required_it_tickets": ["IT-DEMO-GP-01"],
            "anchor_node_id": "proc-demo-cicd",
        },
        "leaf-kb-stor-007": {
            "node_id": "leaf-kb-stor-007", "kind": "leaf",
            "policy_id": "playbook-storage-openzfs-csi",
            "direct_access_allowed": True, "required_it_tickets": ["IT-STOR-CSI-01"],
            "anchor_node_id": "deploy-demo-k8s",
        },
        "leaf-kb-iam-008": {
            "node_id": "leaf-kb-iam-008", "kind": "leaf",
            "policy_id": "playbook-identity-authentik-oidc",
            "direct_access_allowed": True, "required_it_tickets": ["IT-IAM-OIDC-01"],
            "anchor_node_id": "proc-demo-secret-policy",
        },
        "leaf-kb-game-003": {
            "node_id": "leaf-kb-game-003", "kind": "leaf",
            "policy_id": "playbook-game-server-observability",
            "direct_access_allowed": True, "required_it_tickets": ["IT-GAME-OPS-01"],
            "anchor_node_id": "deploy-demo-k8s",
        },
        "leaf-kb-dns-004": {
            "node_id": "leaf-kb-dns-004", "kind": "leaf",
            "policy_id": "playbook-lan-dns-ingress",
            "direct_access_allowed": True, "required_it_tickets": ["IT-NET-DNS-01"],
            "anchor_node_id": "deploy-demo-k8s",
        },
        "leaf-kb-gpu-005": {
            "node_id": "leaf-kb-gpu-005", "kind": "leaf",
            "policy_id": "playbook-gpu-workload-switchboard",
            "direct_access_allowed": True, "required_it_tickets": ["IT-GPU-OPS-01"],
            "anchor_node_id": "hw-demo-gpu-node",
        },
        "leaf-kb-ops-006": {
            "node_id": "leaf-kb-ops-006", "kind": "leaf",
            "policy_id": "policy-demo-standard-guidance",
            "direct_access_allowed": True, "required_it_tickets": ["IT-DEMO-OPS-01"],
            "anchor_node_id": "deploy-demo-k8s",
        },
    },
}


POLICY_TO_ARTICLE_ID: dict[str, str] = {
    "playbook-golden-path-database-cnpg": "KB-DB-001",
    "playbook-demo-golden-path-3tier": "KB-GP-002",
    "playbook-storage-openzfs-csi": "KB-STOR-007",
    "playbook-identity-authentik-oidc": "KB-IAM-008",
    "playbook-game-server-observability": "KB-GAME-003",
    "playbook-lan-dns-ingress": "KB-DNS-004",
    "playbook-gpu-workload-switchboard": "KB-GPU-005",
    "policy-demo-standard-guidance": "KB-OPS-006",
}


KB_CLUSTER_RUNBOOKS: tuple[tuple[Any, ...], ...] = (
    ("kb-db-001", "KB-DB-001: How 2 Database — Deploy PostgreSQL via CloudNativePG & OpenBao",
     "How 2 database / how to deploy a database: provision a PostgreSQL HA cluster via CloudNativePG (postgresql.cnpg.io/v1) on OpenZFS ZFS storage and inject credentials from OpenBao via ExternalSecret.",
     ("k8s/Namespace//cnpg-system", "k8s/Namespace//iam"),
     ("k8s/Deployment/cnpg-system/cnpg-cloudnative-pg", "k8s/Deployment/kube-system/external-secrets", "k8s/Deployment/iam/openbao-agent-injector")),
    ("kb-gp-002", "KB-GP-002: How 2 Spin Up a 3-Tier Golden Path Project",
     "How 2 new project / CI/CD pipeline: scaffold a 3-tier application using GitLab CI/CD Golden Path components and ArgoCD GitOps sync.",
     ("k8s/Namespace//gitlab",),
     ("k8s/Deployment/gitlab/gitlab", "k8s/Deployment/argocd/argocd-server")),
    ("kb-game-003", "KB-GAME-003: How 2 Debug Game Servers (Minecraft / Factorio / Satisfactory)",
     "How 2 game server debugging: isolate Pod readiness (Layer 1), .cluster.example.org LAN DNS (Layer 2), and client GPU/APU (Layer 3) with Grafana and RunbookGate.",
     ("k8s/Namespace//game-servers", "k8s/Namespace//monitoring", "k8s/Namespace//runbookgate"),
     ("k8s/Deployment/monitoring/kube-prometheus-stack-grafana", "k8s/Deployment/runbookgate/runbookgate", "k8s/Deployment/game-servers/minecraft")),
    ("kb-dns-004", "KB-DNS-004: How 2 Fix .cluster.example.org LAN DNS & NGINX Ingress",
     "How 2 DNS / ingress: verify NGINX Ingress controller routing, TLS certificates, and AdGuard/Unbound split-horizon DNS for *.cluster.example.org.",
     ("k8s/Namespace//ingress-nginx",),
     ("k8s/Deployment/ingress-nginx/ingress-nginx-controller",)),
    ("kb-gpu-005", "KB-GPU-005: How 2 Debug GPU / APU & Local LLM Inference",
     "How 2 GPU / FPS / Ollama: inspect hardware GPU/APU utilization across nodegamma03, nodebeta02, and nodealpha01.",
     ("k8s/Namespace//ai-infra",),
     ("k8s/Deployment/ai-infra/ollama-gpu-worker", "k8s/Deployment/ai-infra/ollama")),
    ("kb-ops-006", "KB-OPS-006: How 2 Triage Cluster Health, Node Hotspots & Failed Pods",
     "How 2 cluster health: inspect node readiness, CPU/RAM hotspots, failed GitLab runner pods, and degraded deployments.",
     ("k8s/Namespace//monitoring",),
     ("k8s/Deployment/monitoring/kube-prometheus-stack-grafana",)),
    ("kb-stor-007", "KB-STOR-007: How 2 Storage — OpenZFS ZFS, Democratic-CSI & SeaweedFS",
     "How 2 storage / PVC: provision PersistentVolumeClaims via democratic-csi (zfs-nfs RWX or openzfs-iscsi-csi RWO) and SeaweedFS S3 buckets.",
     ("k8s/Namespace//democratic-csi", "k8s/Namespace//seaweedfs", "k8s/Namespace//storage-system"),
     ("k8s/Deployment/democratic-csi/zfs-nfs-driver-democratic-csi-controller", "k8s/Deployment/democratic-csi/openzfs-iscsi-csi-driver-democratic-csi-controller")),
    ("kb-iam-008", "KB-IAM-008: How 2 Auth / SSO — Authentik OIDC & OpenBao ExternalSecrets",
     "How 2 auth / SSO / OIDC: protect *.cluster.example.org ingresses with Authentik OAuth2/OIDC providers and OpenBao ExternalSecret credentials.",
     ("k8s/Namespace//iam",),
     ("k8s/Deployment/iam/authentik-server", "k8s/Deployment/iam/openbao-agent-injector")),
    ("kb-gitops-009", "KB-GITOPS-009: How 2 GitOps — ArgoCD Sync & Drift Recovery",
     "How 2 GitOps / ArgoCD: resolve OutOfSync or Degraded ArgoCD applications and verify Renovate dependency updates.",
     ("k8s/Namespace//argocd",),
     ("k8s/Deployment/argocd/argocd-server", "k8s/Deployment/argocd/argocd-ApplicationSet-controller")),
)


def overlay_knowledge_base_runbooks(catalog: dict[str, Any]) -> dict[str, Any]:
    """Attach KB-* operational process nodes under their owning namespaces in-place."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
        return catalog
    by_id = {n["id"]: n for n in catalog["nodes"] if isinstance(n, dict) and "id" in n}
    edges = catalog.setdefault("edges", [])
    edge_set = {(e.get("source"), e.get("target"), e.get("relation")) for e in edges}
    article_by_id = {a["article_id"].lower(): a for a in KNOWLEDGE_BASE_ARTICLES}
    for kb_id, label, summary, group_ids, target_ids in KB_CLUSTER_RUNBOOKS:
        present_groups = [gid for gid in group_ids if gid in by_id]
        present_targets = [tid for tid in target_ids if tid in by_id]
        if not present_groups:
            continue
        if kb_id not in by_id:
            article = article_by_id.get(kb_id, {})
            kb_node: dict[str, Any] = {
                "id": kb_id,
                "label": label,
                "kind": "operational_process",
                "domain": "processes_workflows",
                "summary": summary,
                "primary_url": "https://gitlab.cluster.example.org/platform/infra-gitops",
                "drilldown_children": list(present_targets),
            }
            if article.get("steps"):
                kb_node["steps"] = list(article["steps"])
            catalog["nodes"].append(kb_node)
            by_id[kb_id] = kb_node
        for gid in present_groups:
            grp = by_id[gid]
            if kb_id not in grp.setdefault("drilldown_children", []):
                grp["drilldown_children"].append(kb_id)
            ek = (gid, kb_id, "contains_runbook")
            if ek not in edge_set:
                edges.append({"source": gid, "target": kb_id, "relation": "contains_runbook"})
                edge_set.add(ek)
        for tid in present_targets:
            ek = (kb_id, tid, "governs_workload")
            if ek not in edge_set:
                edges.append({"source": kb_id, "target": tid, "relation": "governs_workload"})
                edge_set.add(ek)
    if "node_count" in catalog:
        catalog["node_count"] = len(catalog["nodes"])
    if "edge_count" in catalog:
        catalog["edge_count"] = len(catalog["edges"])
    return catalog


overlay_knowledge_base = overlay_knowledge_base_runbooks


__all__ = [
    "CONCIERGE_JEV_TREE",
    "KB_CLUSTER_RUNBOOKS",
    "KNOWLEDGE_BASE_ARTICLES",
    "POLICY_TO_ARTICLE_ID",
    "overlay_knowledge_base",
    "overlay_knowledge_base_runbooks",
]
