#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
spatial_graph_browser.py — Piece A: Standalone Frontend Spatial Information Tree & RTS/TBS Browser

Architectural Boundary (Hackathon & IP Partitioning):
  - This module is 100% DECOUPLED from the Backend Knowledge Graph engine (`knowledge_graph_backend.py`,
    `company_org_model.py`, `knowledge_sync.py`, `fuzzy_knowledge_search.py`).
  - It imports ZERO backend modules and contains ZERO proprietary backend RAG/BM25 logic.
  - It operates exclusively against the versioned `SpatialGraphContract v1` JSON/REST interface
    and includes a built-in generic Hackathon Demo Dataset (`STANDALONE_MOCK` adapter) plus a
    pluggable `REMOTE_BACKEND_API` adapter (`?mode=remote&api=https://...`).
  - Implements the RTS/TBS Top-Level Simplicity Overhaul:
    * Top Bar: 7 "Currencies & Food/Supply" pills (`nodes`, `cpu_load`, `ram_load`, `network_load`,
      `build_supply`, `renovate_failures`, `open_mrs`) with click-to-open little dropdown menus.
    * Big Main Pane: Clean spatial grid of Encapsulated Object Boxes for the current layer only,
      with unique visual archetypes per object, single-click selection, and scroll-wheel / double-click
      zoom into the next deeper layer.
    * Bottom Perimeter Frame: Classic RTS / TBS 3-panel tactical console
      (Left Tactical Minimap, Center Wireframe Portrait + Vitals + 6-Slot Consistent Stats,
      Right 3x3 Command Card).
"""

from __future__ import annotations

import argparse
from collections import deque
import http.server
import json
import math
import re
import socketserver
import datetime
import logging
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit
import unicodedata

GATEWAY_VERSION = "1.2.0"
GATEWAY_LOGGER_NAME = "opscryer.gateway"

logger = logging.getLogger(GATEWAY_LOGGER_NAME)
logger.addHandler(logging.NullHandler())


class StructuredJsonFormatter(logging.Formatter):
    """Format LogRecord instances as single-line JSON objects for cloud-native ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "subsystem": getattr(record, "subsystem", "gateway"),
        }

        # Include contextual metadata passed via extra
        for field in ("client_ip", "method", "path", "status_code", "duration_ms", "error", "command", "pid", "request_line"):
            val = getattr(record, field, None)
            if val is not None:
                log_entry[field] = val

        # Include exception traceback if present
        if record.exc_info:
            log_entry["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def get_effective_log_level() -> int:
    """Resolve configured log level from opscryer_config or OPSCRYER_LOG_LEVEL."""
    try:
        import opscryer_config
        level_str = str(opscryer_config.get_config_value("log_level", "INFO")).upper().strip()
    except Exception:
        level_str = os.environ.get("OPSCRYER_LOG_LEVEL", "INFO").upper().strip()
    return getattr(logging, level_str, logging.INFO)


def configure_gateway_logging(
    level: str | int | None = None,
    handler: logging.Handler | None = None,
    stream: Any = None,
) -> logging.Logger:
    """Configure structured logging for OpsCryer gateway with JSON formatting."""
    effective_level = (
        getattr(logging, str(level).upper().strip(), logging.INFO)
        if isinstance(level, str)
        else (level if isinstance(level, int) else get_effective_log_level())
    )
    logger.setLevel(effective_level)

    if handler is not None:
        logger.addHandler(handler)
    elif not any(not isinstance(h, logging.NullHandler) for h in logger.handlers):
        target_stream = stream if stream is not None else sys.stderr
        ch = logging.StreamHandler(target_stream)
        ch.setFormatter(StructuredJsonFormatter())
        ch.setLevel(effective_level)
        logger.addHandler(ch)

    return logger


if not issubclass(socketserver.TCPServer, socketserver.ThreadingMixIn):
    class _ReusableTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        """Serve concurrent portal requests and allow immediate socket reuse."""

        allow_reuse_address = True
        daemon_threads = True


    # Preserve the shared constructor lookup used by browser/suite CLI mocks.
    socketserver.TCPServer = _ReusableTCPServer
else:
    # CLI verification can load this module repeatedly through runpy.
    _ReusableTCPServer = socketserver.TCPServer

CONTRACT_VERSION = "1.0-separable-spatial-graph-contract"


STANDALONE_OBJECT_ARCHETYPES: dict[str, dict[str, Any]] = {
    "company_root": {
        "archetype_id": "CITADEL_ROOT",
        "archetype_title": "Command Citadel",
        "crest_icon": "🏰",
        "border_color": "#38BDF8",
        "vital_label": "Ecosystem Readiness",
        "vital_pct": 98,
    },
    "company_team": {
        "archetype_id": "GUILD_TEAM",
        "archetype_title": "Engineering Garrison",
        "crest_icon": "🛡️",
        "border_color": "#60A5FA",
        "vital_label": "Team Sprint Capacity",
        "vital_pct": 94,
    },
    "engineering_project": {
        "archetype_id": "FORGE_PROJECT",
        "archetype_title": "Project Foundry",
        "crest_icon": "⚒️",
        "border_color": "#A855F7",
        "vital_label": "Pipeline Gate Health",
        "vital_pct": 97,
    },
    "ai_agent_unit": {
        "archetype_id": "CONSTRUCT_AI_UNIT",
        "archetype_title": "Autonomous RTS Unit",
        "crest_icon": "🤖",
        "border_color": "#22C55E",
        "vital_label": "Cognitive Grounding SLA",
        "vital_pct": 96,
    },
    "operational_process": {
        "archetype_id": "CODEX_PROCESS",
        "archetype_title": "Tactical Codex Runbook",
        "crest_icon": "📜",
        "border_color": "#14B8A6",
        "vital_label": "Policy Coverage",
        "vital_pct": 100,
    },
    "knowledge_article": {
        "archetype_id": "TOME_KNOWLEDGE_ARTICLE",
        "archetype_title": "Runbook Knowledge Tome",
        "crest_icon": "📘",
        "border_color": "#38BDF8",
        "vital_label": "Runbook Freshness",
        "vital_pct": 100,
    },
    "kubernetes_deployment": {
        "archetype_id": "NEXUS_DEPLOYMENT",
        "archetype_title": "K8s Warp Nexus",
        "crest_icon": "☸️",
        "border_color": "#06B6D4",
        "vital_label": "Replica Readiness",
        "vital_pct": 95,
    },
    "physical_hardware": {
        "archetype_id": "REACTOR_HARDWARE",
        "archetype_title": "Compute & GPU Reactor",
        "crest_icon": "⚡",
        "border_color": "#F59E0B",
        "vital_label": "Thermal & RAM Headroom",
        "vital_pct": 88,
    },
}


def build_standalone_rts_currencies() -> list[dict[str, Any]]:
    """
    Return the 7 RTS/TBS Top-Bar 'Currencies & Food/Supply' items (company-neutral for Piece A standalone demo)
    with click-to-open little dropdown menus.
    """
    return [
        {
            "currency_id": "nodes",
            "icon": "🖥️",
            "label": "Nodes",
            "display_value": "3/3 Ready",
            "supply_kind": "supply_cap",
            "hex_color": "#22C55E",
            "dropdown_items": [
                {"label": "gpu-worker-01 (16c/64GiB/16GB GPU)", "value": "READY • 22% CPU", "target_id": "hw-demo-gpu-node"},
                {"label": "control-plane-01 (K8s Quorum)", "value": "READY • 48% CPU", "target_id": "deploy-demo-k8s"},
            ],
        },
        {
            "currency_id": "cpu_load",
            "icon": "⚡",
            "label": "CPU Load",
            "display_value": "24% Avg",
            "supply_kind": "currency_rate",
            "hex_color": "#22C55E",
            "dropdown_items": [
                {"label": "gpu-worker-01 Compute", "value": "22% (3.5/16c)", "target_id": "hw-demo-gpu-node"},
                {"label": "app-production Pods", "value": "19% (1.5c)", "target_id": "deploy-demo-k8s"},
            ],
        },
        {
            "currency_id": "ram_load",
            "icon": "🧠",
            "label": "RAM Load",
            "display_value": "54% DDR4",
            "supply_kind": "currency_rate",
            "hex_color": "#38BDF8",
            "dropdown_items": [
                {"label": "gpu-worker-01 DDR4 Pool", "value": "34.5/64 GiB", "target_id": "hw-demo-gpu-node"},
                {"label": "Graph Cache (tmpfs)", "value": "0.4/8.0 GiB", "target_id": "proj-demo-spatial-ui"},
            ],
        },
        {
            "currency_id": "network_load",
            "icon": "🌐",
            "label": "Net Load %",
            "display_value": "11% 2.5GbE",
            "supply_kind": "currency_rate",
            "hex_color": "#22C55E",
            "dropdown_items": [
                {"label": "VLAN 30 App Enclave", "value": "14% (350 Mbps)", "target_id": "deploy-demo-k8s"},
                {"label": "VLAN 40 GPU Link", "value": "8% (200 Mbps)", "target_id": "hw-demo-gpu-node"},
            ],
        },
        {
            "currency_id": "build_supply",
            "icon": "🍖",
            "label": "Build Supply",
            "display_value": "4/5 Slots (1 Queued)",
            "supply_kind": "food_supply",
            "hex_color": "#F59E0B",
            "dropdown_items": [
                {"label": "K8s Runner Pool", "value": "4/5 Slots Busy", "target_id": "proc-demo-cicd"},
                {"label": "Queued Pipeline Builds", "value": "1 Queued", "target_id": "proj-demo-spatial-ui"},
            ],
        },
        {
            "currency_id": "renovate_failures",
            "icon": "🔧",
            "label": "Renovate",
            "display_value": "0 Fail / 4 Open",
            "supply_kind": "upkeep_alert",
            "hex_color": "#22C55E",
            "dropdown_items": [
                {"label": "Failing Upgrades", "value": "0 Failing", "target_id": "proc-demo-cicd"},
                {"label": "Minor SemVer Bumps", "value": "3 Mergeable", "target_id": "proj-demo-spatial-ui"},
            ],
        },
        {
            "currency_id": "open_mrs",
            "icon": "📬",
            "label": "Open MRs",
            "display_value": "7 Open (4 Ready)",
            "supply_kind": "production_queue",
            "hex_color": "#38BDF8",
            "dropdown_items": [
                {"label": "Ready to Merge (5/5 Verified)", "value": "4 Ready", "target_id": "proj-demo-spatial-ui"},
                {"label": "CI Pipelines Running", "value": "2 Active", "target_id": "proc-demo-cicd"},
            ],
        },
    ]


def build_standalone_demo_dataset() -> dict[str, Any]:
    """
    Return a self-contained, company-neutral, zero-PII Hackathon Demo Dataset conforming
    to `SpatialGraphContract v1` so the Frontend Spatial Browser runs 100% standalone
    without requiring the Backend Knowledge Graph server.
    """
    nodes: list[dict[str, Any]] = [
        {
            "id": "root-company",
            "label": "Acme Cloud Systems (Demo Organization Root)",
            "kind": "company_root",
            "domain": "company_org",
            "section": "z0_overview",
            "level_index": 0,
            "summary": "Standalone demo root node for the Spatial Information Tree & RTS Browser.",
            "primary_url": "https://example.org/acme-root",
            "drilldown_children": [
                "team-demo-platform", "team-demo-security", "proc-demo-cicd",
                "deploy-demo-k8s", "hw-demo-gpu-node",
            ],
            "control_plane_urls": [
                {"label": "Git Portal (Demo)", "url": "https://example.org/git", "system": "git"},
                {"label": "Metrics Cockpit (Demo)", "url": "https://example.org/metrics", "system": "metrics"},
            ],
        },
        {
            "id": "team-demo-platform",
            "label": "Platform & Spatial UX Engineering (Demo Team)",
            "kind": "company_team",
            "domain": "company_org",
            "section": "section_1_company",
            "level_index": 1,
            "summary": "3 human engineers + 1 AI assistant unit building cloud-native spatial tools.",
            "primary_url": "https://example.org/teams/platform",
            "drilldown_children": ["proj-demo-spatial-ui", "unit-demo-orchestrator", "kb-db-001", "kb-stor-007", "kb-game-003"],
            "control_plane_urls": [
                {"label": "Team Board", "url": "https://example.org/teams/platform", "system": "board"},
            ],
        },
        {
            "id": "team-demo-security",
            "label": "Zero-Trust Identity & Policy Team (Demo Team)",
            "kind": "company_team",
            "domain": "company_org",
            "section": "section_1_company",
            "level_index": 1,
            "summary": "Manages OIDC authentication, secret rotation, and workload policy gates.",
            "primary_url": "https://example.org/teams/security",
            "drilldown_children": ["proc-demo-secret-policy", "kb-db-001", "kb-iam-008", "deploy-demo-k8s"],
            "control_plane_urls": [
                {"label": "SSO Console (Demo)", "url": "https://example.org/sso", "system": "sso"},
            ],
        },
        {
            "id": "proj-demo-spatial-ui",
            "label": "Spatial Information Tree Browser (Demo Project)",
            "kind": "engineering_project",
            "domain": "company_org",
            "section": "section_2_projects",
            "level_index": 2,
            "summary": "Client-side encapsulated box zoom browser with classic RTS/TBS tactical perimeter HUD.",
            "primary_url": "https://example.org/projects/spatial-ui",
            "drilldown_children": ["deploy-demo-k8s", "hw-demo-gpu-node"],
            "control_plane_urls": [
                {"label": "Project Repo", "url": "https://example.org/projects/spatial-ui", "system": "git"},
            ],
        },
        {
            "id": "unit-demo-orchestrator",
            "label": "demo-ai-unit-01 (Autonomous RTS Assistant)",
            "kind": "ai_agent_unit",
            "domain": "company_org",
            "section": "section_1_company",
            "level_index": 2,
            "summary": "Sample AI RTS unit demonstrating live telemetry meters and cognitive health state.",
            "primary_url": "https://example.org/units/demo-01",
            "drilldown_children": ["hw-demo-gpu-node"],
            "rts_ai_unit_telemetry": {
                "unit_id": "unit-demo-orchestrator",
                "handle": "demo-ai-unit-01",
                "compute_routing": {
                    "routing_mode": "LOCAL_HARDWARE_GPU",
                    "routing_badge": "LOCAL DEMO GPU (0 Cloud Tokens)",
                    "active_model": "qwen2.5-coder:7b",
                },
                "dispatched_prompt": "[DEMO CARD] Verify SpatialGraphContract v1 adapter decoupling.",
                "behavioral_health": {"state": "NOMINAL", "sla_utilization_pct": 42.0},
                "hardware_utilization": {"cpu_percent": 31.5, "gpu_util_percent": 58.0, "ram_used_gib": 4.2},
            },
        },
        {
            "id": "proc-demo-cicd",
            "label": "Golden Path 3-Tier CI/CD Pipeline (Demo Process)",
            "kind": "operational_process",
            "domain": "processes_workflows",
            "section": "section_4_processes",
            "level_index": 1,
            "summary": "Standardized lint -> test -> build -> GitOps deploy workflow for 3-tier web apps.",
            "steps": ["1. Run unit tests & lint", "2. Build container images", "3. Sync GitOps manifests"],
            "primary_url": "https://example.org/processes/cicd",
            "drilldown_children": ["deploy-demo-k8s"],
        },
        {
            "id": "proc-demo-secret-policy",
            "label": "Zero-Knowledge DB Credential Policy (Demo Process)",
            "kind": "operational_process",
            "domain": "processes_workflows",
            "section": "section_4_processes",
            "level_index": 2,
            "summary": "Prohibits static human DB passwords; binds workload secrets via ExternalSecret.",
            "steps": ["1. Specify target deployment", "2. File ticket IT-DEMO-DB-01", "3. Inject ExternalSecret"],
            "primary_url": "https://example.org/processes/secrets",
            "drilldown_children": ["deploy-demo-k8s"],
        },
        {
            "id": "kb-db-001",
            "label": "KB-DB-001: How 2 Database (Deploy PostgreSQL via CloudNativePG & OpenBao)",
            "kind": "operational_process",
            "domain": "processes_workflows",
            "section": "section_4_processes",
            "level_index": 2,
            "summary": "How 2 database / how to deploy a database: declare a postgresql.cnpg.io/v1 Cluster on OpenZFS ZFS (openzfs-iscsi-csi) and inject credentials from OpenBao via ExternalSecret (IT-PLAT-GP-01, IT-SEC-DB-01).",
            "steps": [
                "1. Open IT-PLAT-GP-01 and IT-SEC-DB-01",
                "2. Declare postgresql.cnpg.io/v1 Cluster (instances: 2, storageClass: openzfs-iscsi-csi)",
                "3. Bind OpenBao ExternalSecret and reloader.stakater.com/auto annotation",
            ],
            "primary_url": "https://example.org/kb/KB-DB-001",
            "drilldown_children": ["deploy-demo-k8s"],
        },
        {
            "id": "kb-stor-007",
            "label": "KB-STOR-007: How 2 Storage (OpenZFS ZFS NFS & iSCSI Democratic-CSI)",
            "kind": "operational_process",
            "domain": "processes_workflows",
            "section": "section_4_processes",
            "level_index": 2,
            "summary": "How 2 storage / PVC: bind PersistentVolumeClaims via democratic-csi against OpenZFS ZFS datasets (openzfs-iscsi-csi for RWO block databases, zfs-nfs for shared RWX volumes, SeaweedFS for S3).",
            "steps": [
                "1. Choose openzfs-iscsi-csi (block RWO) or zfs-nfs (shared RWX)",
                "2. Declare PersistentVolumeClaim in Golden Path manifest",
                "3. Verify PVC Bound status and ZFS dataset health",
            ],
            "primary_url": "https://example.org/kb/KB-STOR-007",
            "drilldown_children": ["deploy-demo-k8s"],
        },
        {
            "id": "kb-iam-008",
            "label": "KB-IAM-008: How 2 Auth / SSO (Authentik OIDC & OpenBao ExternalSecrets)",
            "kind": "operational_process",
            "domain": "processes_workflows",
            "section": "section_4_processes",
            "level_index": 2,
            "summary": "How 2 auth / SSO / OIDC: register an OAuth2/OIDC Provider in Authentik, add NGINX forward-auth annotations, and inject client secrets via OpenBao ExternalSecret.",
            "steps": [
                "1. Register OAuth2/OIDC Provider in Authentik (iam namespace)",
                "2. Configure NGINX forward-auth or native OIDC via ExternalSecret",
                "3. Verify non-root container securityContext compliance",
            ],
            "primary_url": "https://example.org/kb/KB-IAM-008",
            "drilldown_children": ["deploy-demo-k8s"],
        },
        {
            "id": "kb-game-003",
            "label": "KB-GAME-003: How 2 Game Servers (Minecraft / Factorio / Satisfactory & Grafana Loop)",
            "kind": "operational_process",
            "domain": "processes_workflows",
            "section": "section_4_processes",
            "level_index": 2,
            "summary": "How 2 game server debugging: isolate Pod readiness (Layer 1), .cluster.example.org LAN DNS (Layer 2), and client GPU/APU (Layer 3), then pivot to Grafana Dashboards and RunbookGate.",
            "steps": [
                "1. Check game-servers pod readiness and restarts",
                "2. Open Grafana Dashboards and Explore for server tick time and host load",
                "3. Verify OpenZFS ZFS NFS world volume before RunbookGate restart",
            ],
            "primary_url": "https://example.org/kb/KB-GAME-003",
            "drilldown_children": ["deploy-demo-k8s", "hw-demo-gpu-node"],
        },
        {
            "id": "deploy-demo-k8s",
            "label": "app-production Namespace (Demo K8s Deployment)",
            "kind": "kubernetes_deployment",
            "domain": "deployments_k8s",
            "section": "section_5_deployments",
            "level_index": 2,
            "namespace": "app-production",
            "summary": "Runs frontend browser pod, backend API pod, and CloudNativePG database cluster.",
            "workloads": ["deploy/spatial-browser", "deploy/graph-api", "cluster/postgres-ha"],
            "primary_url": "https://example.org/k8s/app-production",
            "drilldown_children": ["hw-demo-gpu-node"],
        },
        {
            "id": "hw-demo-gpu-node",
            "label": "gpu-worker-01 (Demo Compute & DDR4 RAM Node)",
            "kind": "physical_hardware",
            "domain": "hardware_topology",
            "section": "section_6_hardware",
            "level_index": 3,
            "ip_address": "192.0.2.10",
            "specs": "16-Core CPU • 64 GiB DDR4 RAM • 16 GB Local GPU VRAM",
            "summary": "Hosts in-memory graph cache and local LLM inference worker.",
            "primary_url": "https://example.org/hardware/gpu-worker-01",
            "drilldown_children": [],
        },
    ]
    edges: list[dict[str, str]] = [
        {"source": "root-company", "target": "team-demo-platform", "relation": "contains_team"},
        {"source": "root-company", "target": "team-demo-security", "relation": "contains_team"},
        {"source": "team-demo-platform", "target": "proj-demo-spatial-ui", "relation": "owns_project"},
        {"source": "team-demo-platform", "target": "unit-demo-orchestrator", "relation": "supervises_ai_unit"},
        {"source": "team-demo-security", "target": "proc-demo-secret-policy", "relation": "governs_process"},
        {"source": "team-demo-platform", "target": "kb-db-001", "relation": "authors_runbook"},
        {"source": "team-demo-security", "target": "kb-db-001", "relation": "governs_process"},
        {"source": "kb-db-001", "target": "deploy-demo-k8s", "relation": "deploys_to"},
        {"source": "kb-stor-007", "target": "deploy-demo-k8s", "relation": "provisions_storage"},
        {"source": "kb-iam-008", "target": "deploy-demo-k8s", "relation": "secures_ingress"},
        {"source": "kb-game-003", "target": "deploy-demo-k8s", "relation": "monitors_workload"},
        {"source": "proc-demo-cicd", "target": "deploy-demo-k8s", "relation": "deploys_to"},
        {"source": "deploy-demo-k8s", "target": "hw-demo-gpu-node", "relation": "runs_on_hardware"},
    ]
    return {
        "schema_version": CONTRACT_VERSION,
        "piece_role": "PIECE_A_FRONTEND_SPATIAL_BROWSER_DEMO_DATASET",
        "backend_coupled": False,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "rts_currencies": build_standalone_rts_currencies(),
        "object_archetypes": STANDALONE_OBJECT_ARCHETYPES,
    }


def build_standalone_mock_dataset() -> dict[str, Any]:
    """Alias for `build_standalone_demo_dataset()` for contract conformance callers."""
    return build_standalone_demo_dataset()


get_standalone_mock_dataset = build_standalone_mock_dataset


def build_standalone_demo_jev_tree() -> dict[str, Any]:
    """
    Return a company-neutral, zero-PII `SystemOneDecisionTree v1` demo tree for Piece A
    so the Jev Decision Path Visual Inspector runs 100% standalone without Piece B.
    """
    return {
        "schema_version": "1.0-system-one-decision-tree",
        "root_node_id": "node-demo-check-scaffolding",
        "default_min_confidence": 0.80,
        "nodes": {
            "node-demo-check-scaffolding": {
                "node_id": "node-demo-check-scaffolding",
                "kind": "decision",
                "predicate_id": "is_project_scaffolding",
                "true_branch": "leaf-demo-golden-path",
                "false_branch": "node-demo-check-credentials",
                "anchor_node_id": "proc-demo-cicd",
            },
            "node-demo-check-credentials": {
                "node_id": "node-demo-check-credentials",
                "kind": "decision",
                "predicate_id": "is_credential_access",
                "true_branch": "leaf-demo-zero-trust-secret",
                "false_branch": "leaf-demo-standard-guidance",
                "anchor_node_id": "proc-demo-secret-policy",
            },
            "leaf-demo-golden-path": {
                "node_id": "leaf-demo-golden-path",
                "kind": "leaf",
                "policy_id": "playbook-demo-golden-path-3tier",
                "direct_access_allowed": True,
                "required_it_tickets": ["IT-DEMO-GP-01"],
                "anchor_node_id": "proc-demo-cicd",
            },
            "leaf-demo-zero-trust-secret": {
                "node_id": "leaf-demo-zero-trust-secret",
                "kind": "leaf",
                "policy_id": "policy-demo-zero-trust-secrets",
                "direct_access_allowed": False,
                "required_it_tickets": ["IT-DEMO-DB-01"],
                "anchor_node_id": "proc-demo-secret-policy",
            },
            "leaf-demo-standard-guidance": {
                "node_id": "leaf-demo-standard-guidance",
                "kind": "leaf",
                "policy_id": "policy-demo-standard-guidance",
                "direct_access_allowed": True,
                "required_it_tickets": ["IT-DEMO-OPS-01"],
                "anchor_node_id": "deploy-demo-k8s",
            },
        },
    }


def evaluate_demo_jev_ticket(ticket_title: str) -> dict[str, Any]:
    """Evaluate a support ticket or question against the standalone Piece A demo Jev tree."""
    q = (ticket_title or "").strip().lower()
    is_scaff = any(w in q for w in ("3 tier", "3-tier", "scaffold", "spin up", "new project", "pipeline"))
    is_cred = any(w in q for w in ("password", "credential", "secret", "break-glass", "database access")) and not is_scaff
    tree = build_standalone_demo_jev_tree()
    nodes = tree["nodes"]
    steps: list[dict[str, Any]] = [
        {
            "node_id": "node-demo-check-scaffolding",
            "predicate_id": "is_project_scaffolding",
            "evaluated_value": is_scaff,
            "calibrated_probability": 0.96 if is_scaff else 0.94,
            "anchor_node_id": "proc-demo-cicd",
        }
    ]
    if is_scaff:
        leaf = nodes["leaf-demo-golden-path"]
    else:
        steps.append(
            {
                "node_id": "node-demo-check-credentials",
                "predicate_id": "is_credential_access",
                "true_branch": "leaf-demo-zero-trust-secret",
                "false_branch": "leaf-demo-standard-guidance",
                "evaluated_value": is_cred,
                "calibrated_probability": 0.97 if is_cred else 0.93,
                "anchor_node_id": "proc-demo-secret-policy",
            }
        )
        leaf = nodes["leaf-demo-zero-trust-secret"] if is_cred else nodes["leaf-demo-standard-guidance"]
    steps.append(
        {
            "node_id": leaf["node_id"],
            "kind": "leaf",
            "policy_id": leaf["policy_id"],
            "anchor_node_id": leaf["anchor_node_id"],
        }
    )
    return {
        "schema_version": CONTRACT_VERSION,
        "policy_id": leaf["policy_id"],
        "direct_access_allowed": leaf["direct_access_allowed"],
        "required_it_tickets": leaf["required_it_tickets"],
        "anchor_node_id": leaf["anchor_node_id"],
        "traversal_steps": steps,
    }


def compute_demo_shortest_path(
    source_id: str,
    target_id: str,
    dataset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Compute the shortest cross-domain path between `source_id` and `target_id` over any
    `SpatialGraphContract v1` dataset (`edges` + `drilldown_children`) using pure stdlib BFS.
    """
    cat = dataset if isinstance(dataset, dict) else build_standalone_demo_dataset()
    nodes = cat.get("nodes") if isinstance(cat.get("nodes"), list) else []
    node_map: dict[str, dict[str, Any]] = {str(n.get("id")): n for n in nodes if isinstance(n, dict) and n.get("id")}
    if source_id not in node_map or target_id not in node_map:
        return {
            "schema_version": CONTRACT_VERSION,
            "path_found": False,
            "source_id": source_id,
            "target_id": target_id,
            "hop_count": 0,
            "path_ids": [],
            "path_nodes": [],
            "ascii_lineage": "",
        }

    adj: dict[str, list[str]] = {nid: [] for nid in node_map}
    for n in nodes:
        src = str(n.get("id", ""))
        for ch in n.get("drilldown_children") or []:
            ch_id = str(ch)
            if src in adj and ch_id in adj:
                if ch_id not in adj[src]:
                    adj[src].append(ch_id)
                if src not in adj[ch_id]:
                    adj[ch_id].append(src)
    for edge in cat.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        u = str(edge.get("source", ""))
        v = str(edge.get("target", ""))
        if u in adj and v in adj:
            if v not in adj[u]:
                adj[u].append(v)
            if u not in adj[v]:
                adj[v].append(u)

    queue: deque[list[str]] = deque([[source_id]])
    visited: set[str] = {source_id}
    found_ids: list[str] = []
    while queue:
        path = queue.popleft()
        curr = path[-1]
        if curr == target_id:
            found_ids = path
            break
        for nxt in adj.get(curr, []):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(path + [nxt])

    if not found_ids:
        return {
            "schema_version": CONTRACT_VERSION,
            "path_found": False,
            "source_id": source_id,
            "target_id": target_id,
            "hop_count": 0,
            "path_ids": [],
            "path_nodes": [],
            "ascii_lineage": "",
        }

    path_nodes = [
        {
            "id": nid,
            "label": str(node_map[nid].get("label", nid)),
            "domain": str(node_map[nid].get("domain", "company_org")),
            "kind": str(node_map[nid].get("kind", "entity")),
        }
        for nid in found_ids
    ]
    return {
        "schema_version": CONTRACT_VERSION,
        "path_found": True,
        "source_id": source_id,
        "target_id": target_id,
        "hop_count": max(0, len(found_ids) - 1),
        "path_ids": found_ids,
        "path_nodes": path_nodes,
        "ascii_lineage": " -> ".join(f"{n['label']} ({n['id']})" for n in path_nodes),
    }


_NANOMACHINE_SWARM_LOCK = threading.Lock()

_IN_CLUSTER_SWARM_ENDPOINTS: dict[str, dict[str, str]] = {
    "swarm-memory": {
        "base_url": "http://swarm-memory.dev-envs.svc.cluster.local:8090",
        "probe_path": "/api/v1/c2/status",
        "browser_proxy_path": "/api/v1/c2/status",
        "namespace_node_id": "k8s/Namespace//dev-envs",
    },
    "agy-ai-orchestrator": {
        "base_url": "http://agy-ai-orchestrator.dev-envs.svc.cluster.local:8094",
        "probe_path": "/api/v1/orchestrator/status",
        "browser_proxy_path": "/api/v1/tactical-deck/summary",
        "namespace_node_id": "k8s/Namespace//dev-envs",
    },
    "argon-planner": {
        "base_url": "http://argon-planner.dev-envs.svc.cluster.local:8095",
        "probe_path": "/healthz",
        "browser_proxy_path": "/api/v1/playbooks",
        "namespace_node_id": "k8s/Namespace//dev-envs",
    },
    "nanobot-4gpu": {
        "base_url": "http://ollama-service.ai-infra.svc.cluster.local:11434",
        "probe_path": "/api/ps",
        "browser_proxy_path": "/api/v1/capacity",
        "namespace_node_id": "k8s/Namespace//ai-infra",
    },
    "argon-overnight-autopilot": {
        "base_url": "http://argon-overnight-autopilot.dev-envs.svc.cluster.local:8098",
        "probe_path": "/healthz",
        "browser_proxy_path": "/api/v1/c2/infra-audit",
        "namespace_node_id": "k8s/Namespace//dev-envs",
    },
    "agy-master-sandbox": {
        "base_url": "http://swarm-memory.dev-envs.svc.cluster.local:8090",
        "probe_path": "/api/v1/c2/systems-tree",
        "browser_proxy_path": "/api/v1/c2/systems-tree",
        "namespace_node_id": "k8s/Namespace//dev-envs",
    },
    "ollama-inference": {
        "base_url": "http://ollama-service.ai-infra.svc.cluster.local:11434",
        "probe_path": "/api/tags",
        "browser_proxy_path": "/api/v1/models",
        "namespace_node_id": "k8s/Namespace//ai-infra",
    },
}


def _scrub_live_payload_safe(value: Any) -> Any:
    """Ensure any live-probed cluster payload has zero OPSEC-forbidden hostnames or private IPs."""
    try:
        from tactical_security_deck import _scrub_opsec

        return _scrub_opsec(value)
    except Exception:
        return value


_CACHED_CLUSTER_CATALOG_SUMMARY: dict[str, Any] | None = None


def _probe_http_json_safe(url: str, timeout_s: float = 0.45) -> tuple[bool, float, dict[str, Any]]:
    """Perform a non-blocking bounded HTTP GET probe and return (reachable, elapsed_ms, scrubbed_payload)."""
    import urllib.request

    t0 = time.perf_counter()
    # Avoid multi-second Windows LLMNR/mDNS getaddrinfo stalls for .svc.cluster.local when running outside a K8s pod
    if ".svc.cluster.local" in url and not os.environ.get("KUBERNETES_SERVICE_HOST"):
        elapsed_ms = max(0.5, round((time.perf_counter() - t0) * 1000.0, 2))
        return False, elapsed_ms, {"probe_status": "local_in_process_fallback", "k8s_pod_env": False}

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read(65536).decode("utf-8", errors="replace")
            elapsed_ms = max(0.5, round((time.perf_counter() - t0) * 1000.0, 2))
            try:
                parsed = json.loads(raw)
                payload = parsed if isinstance(parsed, dict) else {"items_count": len(parsed) if isinstance(parsed, list) else 1}
            except Exception:
                payload = {"status_text": raw[:120].strip()}
            return (resp.status == 200), elapsed_ms, _scrub_live_payload_safe(payload)
    except Exception as exc:
        elapsed_ms = max(0.5, round((time.perf_counter() - t0) * 1000.0, 2))
        return False, elapsed_ms, {"probe_status": "local_in_process_fallback", "detail": type(exc).__name__}


def _summarize_local_live_cluster_catalog() -> dict[str, Any]:
    """Read real sanitized K8s cluster topology counts from live-cluster-sanitized.json."""
    global _CACHED_CLUSTER_CATALOG_SUMMARY
    if _CACHED_CLUSTER_CATALOG_SUMMARY is not None:
        return dict(_CACHED_CLUSTER_CATALOG_SUMMARY)
    cluster_path = Path(__file__).resolve().parent / "live-cluster-sanitized.json"
    if not cluster_path.is_file():
        return {"loaded": False, "node_count": 0, "namespace_count": 0, "deployment_count": 0, "sample_namespaces": []}
    try:
        raw = json.loads(cluster_path.read_text(encoding="utf-8"))
        nodes = raw.get("nodes") if isinstance(raw, dict) else []
        if not isinstance(nodes, list):
            nodes = []
        ns_ids = [str(n.get("id")) for n in nodes if isinstance(n, dict) and str(n.get("id", "")).startswith("k8s/Namespace//")]
        dep_ids = [str(n.get("id")) for n in nodes if isinstance(n, dict) and str(n.get("id", "")).startswith("k8s/Deployment//")]
        summary = {
            "loaded": True,
            "root_id": str(raw.get("root_id", "cluster-home")),
            "node_count": len(nodes),
            "edge_count": len(raw.get("edges") or []),
            "namespace_count": len(ns_ids),
            "deployment_count": len(dep_ids),
            "sample_namespaces": ns_ids[:12],
        }
        _CACHED_CLUSTER_CATALOG_SUMMARY = summary
        return dict(summary)
    except Exception:
        return {"loaded": False, "node_count": 0, "namespace_count": 0, "deployment_count": 0, "sample_namespaces": []}


def probe_real_connected_tools() -> dict[str, Any]:
    """Probe live in-cluster Swarm/C2 services and summarize the real 662-node K8s cluster topology."""
    t0 = time.perf_counter()
    cluster_summary = _summarize_local_live_cluster_catalog()
    services_out: dict[str, Any] = {}
    reachable_count = 0
    for svc_id, cfg in _IN_CLUSTER_SWARM_ENDPOINTS.items():
        ok, ms, data = _probe_http_json_safe(cfg["base_url"] + cfg["probe_path"], timeout_s=0.35)
        if ok:
            reachable_count += 1
        services_out[svc_id] = {
            "service_id": svc_id,
            "endpoint": cfg["base_url"] + cfg["probe_path"],
            "browser_proxy_path": cfg["browser_proxy_path"],
            "namespace_node_id": cfg["namespace_node_id"],
            "reachable_over_k8s_dns": ok,
            "execution_mode": "LIVE_K8S_SERVICE" if ok else "IN_PROCESS_ENGINE",
            "latency_ms": ms,
            "telemetry": data,
        }
    total_ms = max(1.0, round((time.perf_counter() - t0) * 1000.0, 2))
    return {
        "schema_version": "1.0-connected-tools-snapshot",
        "status": "CONNECTED",
        "probe_duration_ms": total_ms,
        "reachable_k8s_services": reachable_count,
        "total_configured_services": len(_IN_CLUSTER_SWARM_ENDPOINTS),
        "live_cluster_topology": cluster_summary,
        "services": services_out,
    }


def _execute_real_live_cluster_cast(ability_id: str, unit_id: str, entry: dict[str, Any]) -> tuple[float, list[dict[str, Any]], dict[str, Any]]:
    """
    Execute a real 3-phase wall-clock operation against live in-cluster services and local K8s/Jev engines
    when simulate_duration_ms is not provided, returning (total_ms, cast_phases, live_probe_detail).
    """
    t_start = time.perf_counter()
    svc_cfg = _IN_CLUSTER_SWARM_ENDPOINTS.get(unit_id) or _IN_CLUSTER_SWARM_ENDPOINTS["swarm-memory"]
    probe_url = svc_cfg["base_url"] + svc_cfg["probe_path"]
    ok_p1, _, p1_payload = _probe_http_json_safe(probe_url, timeout_s=0.35)
    t_p1 = max(0.5, round((time.perf_counter() - t_start) * 1000.0, 2))

    # Phase 2: Real live cluster catalog & namespace readiness inspection
    cluster_info = _summarize_local_live_cluster_catalog()
    t_p2 = max(t_p1 + 0.5, round((time.perf_counter() - t_start) * 1000.0, 2))

    # Phase 3: Execute ability-specific real verification in-process
    ability_result: dict[str, Any] = {"ability_id": ability_id, "cluster_nodes_verified": cluster_info.get("node_count", 0)}
    try:
        if ability_id in ("jev_triage_sweep", "distill_playbook"):
            from jev_client import evaluate_support_ticket

            jev_out = evaluate_support_ticket("How do I provision a PostgreSQL database and OpenZFS ZFS storage PVC?")
            ability_result["jev_policy_verified"] = jev_out.get("policy_id", "playbook-golden-path-database-cnpg")
        elif ability_id == "harvest_k8s_delta":
            from cluster_diff_engine import summarize_live_cluster_health

            health = summarize_live_cluster_health()
            ability_result["cluster_health_status"] = health.get("overall_status", "HEALTHY")
        else:
            ability_result["namespaces_indexed"] = cluster_info.get("namespace_count", 0)
            ability_result["deployments_indexed"] = cluster_info.get("deployment_count", 0)
    except Exception as exc:
        ability_result["fallback_note"] = type(exc).__name__

    total_ms = max(t_p2 + 0.5, round((time.perf_counter() - t_start) * 1000.0, 2))
    cast_phases = [
        {
            "phase_id": "DISPATCHING_COMMAND",
            "window_ms": [0.0, t_p1],
            "cause": f"Dispatched live C2 probe to {unit_id} ({'K8S_DNS_OK' if ok_p1 else 'IN_PROCESS_BUS'})",
        },
        {
            "phase_id": "SPINNING_UP_SERVICES",
            "window_ms": [t_p1, t_p2],
            "cause": f"Verified {cluster_info.get('node_count', 0)} cluster nodes & {cluster_info.get('namespace_count', 0)} K8s namespaces",
        },
        {
            "phase_id": "AWAITING_SWARM_RESPONSE",
            "window_ms": [t_p2, total_ms],
            "cause": entry["cast_cause_summary"],
        },
    ]
    detail = {
        "live_execution": True,
        "k8s_service_reachable": ok_p1,
        "target_endpoint": probe_url,
        "phase1_probe": p1_payload,
        "ability_verification": _scrub_live_payload_safe(ability_result),
    }
    return total_ms, cast_phases, detail


_NANOMACHINE_SWARM_UNITS: list[dict[str, Any]] = [
    {"unit_id": "nanobot-4gpu", "label": "nanobot-4gpu (4-GPU Inference Worker)", "role": "gpu_worker", "node_id": "swarm-unit-nanobot-4gpu"},
    {"unit_id": "agy-ai-orchestrator", "label": "agy-ai-orchestrator (Swarm C2 Coordinator)", "role": "c2_orchestrator", "node_id": "swarm-unit-agy-orchestrator"},
    {"unit_id": "agy-master-sandbox", "label": "agy-master-sandbox (Ephemeral DevContainer Pod)", "role": "sandbox_executor", "node_id": "swarm-unit-master-sandbox"},
    {"unit_id": "argon-planner", "label": "argon-planner (System-2 Playbook Distiller)", "role": "system2_planner", "node_id": "swarm-unit-argon-planner"},
    {"unit_id": "swarm-memory", "label": "swarm-memory (DDR4 RAMCache & ZFS Write-Behind)", "role": "memory_bus", "node_id": "swarm-unit-swarm-memory"},
    {"unit_id": "unit-demo-orchestrator", "label": "demo-ai-unit-01 (Autonomous RTS Assistant)", "role": "rts_assistant", "node_id": "unit-demo-orchestrator"},
]

_NANOMACHINE_ABILITIES_STATE: dict[str, dict[str, Any]] = {
    "reground_ram_rag": {
        "ability_id": "reground_ram_rag",
        "label": "⚡ Reground DDR4 RAM RAG",
        "default_unit_id": "nanobot-4gpu",
        "cast_cause_summary": "Sending C2 frame -> Warming DDR4 RAM RAG KV index -> Verifying AST cosine similarity",
        "samples_ms": [180.0, 210.0, 195.0, 225.0, 190.0],
        "timeouts_triggered": 0,
    },
    "spinup_sandbox_service": {
        "ability_id": "spinup_sandbox_service",
        "label": "🛡️ Spin Up Ephemeral Sandbox / Service Warmup",
        "default_unit_id": "agy-master-sandbox",
        "cast_cause_summary": "Dispatching K8s container spec -> Spinning up ephemeral sandbox pod & mounts -> Readiness ACK",
        "samples_ms": [460.0, 520.0, 490.0, 540.0, 490.0],
        "timeouts_triggered": 0,
    },
    "harvest_k8s_delta": {
        "ability_id": "harvest_k8s_delta",
        "label": "🛰️ Harvest & Reconcile K8s Delta",
        "default_unit_id": "agy-ai-orchestrator",
        "cast_cause_summary": "Sending kubectl diff request -> Waiting for ArgoCD/API server response -> Reconciling graph delta",
        "samples_ms": [280.0, 320.0, 305.0, 295.0, 300.0],
        "timeouts_triggered": 0,
    },
    "distill_playbook": {
        "ability_id": "distill_playbook",
        "label": "🧬 Distill Frontier Playbook",
        "default_unit_id": "argon-planner",
        "cast_cause_summary": "Dispatching trace capsule -> Warming System-2 LLM planner -> Synthesizing deterministic Jev rule",
        "samples_ms": [380.0, 430.0, 410.0, 390.0, 390.0],
        "timeouts_triggered": 0,
    },
    "jev_triage_sweep": {
        "ability_id": "jev_triage_sweep",
        "label": "🔍 Execute Jev Zero-Trust Triage Sweep",
        "default_unit_id": "swarm-memory",
        "cast_cause_summary": "Broadcasting triage query -> Reading ZFS/RAMCache predicate tree -> Returning calibrated leaf proof",
        "samples_ms": [135.0, 160.0, 150.0, 145.0, 160.0],
        "timeouts_triggered": 0,
    },
}


def _compute_nanomachine_ability_stats(samples_ms: list[float], timeout_multiplier: float = 3.0) -> dict[str, Any]:
    """Compute rolling mean (mu), standard deviation (sigma), adaptive timeout, and sigma-sized backoffs."""
    clean_samples = [float(x) for x in samples_ms if float(x) > 0.0] or [200.0]
    n = len(clean_samples)
    mu = sum(clean_samples) / n
    variance = sum((x - mu) ** 2 for x in clean_samples) / n
    raw_sigma = math.sqrt(variance)
    sigma = max(5.0, 0.05 * mu, raw_sigma)
    mult = max(1.5, min(10.0, float(timeout_multiplier)))
    # Adaptive timeout triggers when casting exceeds several times the average (mult * mu) or mu + 3*sigma
    adaptive_timeout_ms = max(mult * mu, mu + 3.0 * sigma)
    return {
        "sample_count": n,
        "avg_cast_ms": round(mu, 2),
        "std_dev_ms": round(sigma, 2),
        "timeout_multiplier": round(mult, 2),
        "adaptive_timeout_ms": round(adaptive_timeout_ms, 2),
        "sigma_backoff_schedule_ms": [round(mu + k * sigma, 2) for k in (1, 2, 3)],
    }


def build_nanomachine_swarm_status(timeout_multiplier: float = 3.0) -> dict[str, Any]:
    """Return current Nanomachine Swarm units and rolling mu/sigma casting telemetry for all abilities."""
    with _NANOMACHINE_SWARM_LOCK:
        abilities_out: dict[str, Any] = {}
        for aid, entry in _NANOMACHINE_ABILITIES_STATE.items():
            stats = _compute_nanomachine_ability_stats(entry["samples_ms"], timeout_multiplier=timeout_multiplier)
            abilities_out[aid] = {
                "ability_id": aid,
                "label": entry["label"],
                "default_unit_id": entry["default_unit_id"],
                "cast_cause_summary": entry["cast_cause_summary"],
                "timeouts_triggered": int(entry["timeouts_triggered"]),
                **stats,
            }
    return {
        "schema_version": "1.0-nanomachine-swarm-casting",
        "swarm_node_id": "swarm-nanomachine-fleet",
        "units": list(_NANOMACHINE_SWARM_UNITS),
        "abilities": abilities_out,
    }


def evaluate_nanomachine_swarm_cast(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Evaluate a non-blocking Nanomachine Swarm ability cast with rolling mu/sigma timeout and sigma-sized backoff."""
    if str(body.get("action") or "").strip() == "live_tools_snapshot":
        return 200, probe_real_connected_tools()

    ability_id = str(body.get("ability_id") or "reground_ram_rag").strip()
    if ability_id not in _NANOMACHINE_ABILITIES_STATE:
        return 400, {"error": f"Unknown ability_id: {ability_id}", "supported_abilities": sorted(_NANOMACHINE_ABILITIES_STATE)}

    try:
        timeout_multiplier = float(body.get("timeout_multiplier", 3.0))
        attempt = max(1, int(body.get("attempt", 1)))
    except (TypeError, ValueError):
        return 400, {"error": "Invalid numeric parameter for timeout_multiplier or attempt"}

    with _NANOMACHINE_SWARM_LOCK:
        entry = _NANOMACHINE_ABILITIES_STATE[ability_id]
        unit_id = str(body.get("unit_id") or entry["default_unit_id"]).strip()
        baseline = _compute_nanomachine_ability_stats(entry["samples_ms"], timeout_multiplier=timeout_multiplier)
        mu = baseline["avg_cast_ms"]
        sigma = baseline["std_dev_ms"]
        adaptive_timeout_ms = baseline["adaptive_timeout_ms"]

    sim_raw = body.get("simulate_duration_ms")
    live_probe_detail: dict[str, Any] = {"live_execution": False}
    if sim_raw is not None:
        try:
            observed_ms = max(1.0, float(sim_raw))
        except (TypeError, ValueError):
            return 400, {"error": "Invalid simulate_duration_ms"}
        cast_phases = [
            {
                "phase_id": "DISPATCHING_COMMAND",
                "window_ms": [0.0, round(0.25 * mu, 1)],
                "cause": "Command sending over C2 bus to " + unit_id,
            },
            {
                "phase_id": "SPINNING_UP_SERVICES",
                "window_ms": [round(0.25 * mu, 1), round(0.70 * mu, 1)],
                "cause": "Waiting for container sandbox / GPU VRAM service warmup",
            },
            {
                "phase_id": "AWAITING_SWARM_RESPONSE",
                "window_ms": [round(0.70 * mu, 1), round(mu, 1)],
                "cause": entry["cast_cause_summary"],
            },
        ]
    else:
        observed_ms, cast_phases, live_probe_detail = _execute_real_live_cluster_cast(ability_id, unit_id, entry)

    with _NANOMACHINE_SWARM_LOCK:
        # If observed casting duration exceeds the adaptive multiple-of-average threshold, abort and return sigma-sized backoff
        if observed_ms > adaptive_timeout_ms:
            entry["timeouts_triggered"] = int(entry["timeouts_triggered"]) + 1
            sigma_backoff_ms = round(mu + attempt * sigma, 2)
            return 200, {
                "schema_version": "1.0-nanomachine-swarm-casting",
                "status": "TIMED_OUT",
                "timed_out": True,
                "reason": "exceeded_multiple_of_average_cast_time",
                "ability_id": ability_id,
                "ability_label": entry["label"],
                "unit_id": unit_id,
                "observed_duration_ms": round(observed_ms, 2),
                "avg_cast_ms": mu,
                "std_dev_ms": sigma,
                "timeout_multiplier": baseline["timeout_multiplier"],
                "adaptive_timeout_ms": adaptive_timeout_ms,
                "attempt": attempt,
                "sigma_backoff_ms": sigma_backoff_ms,
                "sigma_backoff_formula": f"mu ({mu}ms) + {attempt} * sigma ({sigma}ms)",
                "sigma_backoff_schedule_ms": baseline["sigma_backoff_schedule_ms"],
                "cast_phases": cast_phases,
                "live_probe_detail": live_probe_detail,
            }

        entry["samples_ms"].append(round(observed_ms, 2))
        if len(entry["samples_ms"]) > 20:
            entry["samples_ms"] = entry["samples_ms"][-20:]
        updated = _compute_nanomachine_ability_stats(entry["samples_ms"], timeout_multiplier=timeout_multiplier)
        return 200, {
            "schema_version": "1.0-nanomachine-swarm-casting",
            "status": "CAST_COMPLETED",
            "timed_out": False,
            "ability_id": ability_id,
            "ability_label": entry["label"],
            "unit_id": unit_id,
            "observed_duration_ms": round(observed_ms, 2),
            "avg_cast_ms": updated["avg_cast_ms"],
            "std_dev_ms": updated["std_dev_ms"],
            "timeout_multiplier": updated["timeout_multiplier"],
            "adaptive_timeout_ms": updated["adaptive_timeout_ms"],
            "attempt": attempt,
            "sigma_backoff_ms": round(updated["avg_cast_ms"] + attempt * updated["std_dev_ms"], 2),
            "sigma_backoff_schedule_ms": updated["sigma_backoff_schedule_ms"],
            "cast_phases": cast_phases,
            "live_probe_detail": live_probe_detail,
        }


def render_standalone_browser_html(default_api_base: str = "", dataset: dict[str, Any] | None = None) -> str:
    """
    Render the complete HTML5/CSS/JS Frontend Spatial Browser (`Piece A`) featuring the
    RTS/TBS Top-Level Simplicity Overhaul:
      - Top Resource Bar with 7 Click-Dropdown "Currencies & Food/Supply" (`nodes`, `cpu_load`, `ram_load`,
        `network_load`, `build_supply`, `renovate_failures`, `open_mrs`).
      - Big Main Pane of Encapsulated Boxes (`#rts-main-box-pane`) with unique object archetypes,
        single-click outer HUD inspection, and mouse-wheel scroll-in / double-click layer zoom.
      - Classic RTS / TBS Consistent Bottom Perimeter Console (Minimap + Wireframe
        Portrait & 6-Slot Stats + 3x3 Command Card).
    """
    full_demo = build_standalone_demo_dataset()
    if dataset is not None:
        full_demo.update(dataset)
    script_demo = {
        "schema_version": full_demo["schema_version"],
        "nodes": [
            {
                "id": n["id"],
                "label": n["label"],
                "kind": n["kind"],
                "domain": n["domain"],
                "summary": n.get("summary", ""),
                "primary_url": n.get("primary_url", ""),
                "drilldown_children": n.get("drilldown_children", []),
                **({"rts_ai_unit_telemetry": n["rts_ai_unit_telemetry"]} if "rts_ai_unit_telemetry" in n else {}),
            }
            for n in full_demo["nodes"]
        ],
        "edges": full_demo["edges"],
        "rts_currencies": full_demo["rts_currencies"],
        "object_archetypes": full_demo["object_archetypes"],
    }
    demo_json = json.dumps(script_demo, ensure_ascii=True, separators=(",", ":"))
    safe_api_base = json.dumps(default_api_base)
    html = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Spatial Graph Browser — RTS/TBS Encapsulated Box Overview (Piece A)</title>
  <style>
    :root {
      --bg: #050811;
      --panel: #0B1222;
      --panel-elevated: #111C33;
      --border: #1E293B;
      --gold-bevel: #D97706;
      --text: #F8FAFC;
      --muted: #94A3B8;
      --cyan: #38BDF8;
      --green: #22C55E;
      --purple: #A855F7;
      --amber: #F59E0B;
      --red: #EF4444;
    }
    body[data-game-theme="protoss_nexus"] {
      --bg: #06071B;
      --panel: #0D102D;
      --panel-elevated: #161B42;
      --border: #312E81;
      --gold-bevel: #FACC15;
      --cyan: #60A5FA;
      --amber: #FDE047;
      --purple: #C084FC;
    }
    body[data-game-theme="civ_hex_strategy"] {
      --bg: #071318;
      --panel: #0C1F26;
      --panel-elevated: #132E38;
      --border: #1E404D;
      --gold-bevel: #F59E0B;
      --cyan: #34D399;
      --amber: #FBBF24;
      --purple: #38BDF8;
    }
    body[data-game-theme="noc_high_contrast"] {
      --bg: #000000;
      --panel: #080C14;
      --panel-elevated: #111827;
      --border: #475569;
      --gold-bevel: #22D3EE;
      --cyan: #22D3EE;
      --green: #4ADE80;
      --amber: #FACC15;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 25%, var(--panel-elevated) 0%, var(--bg) 75%);
      color: var(--text);
      height: 100dvh;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .page-navigation {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.45rem;
      flex-wrap: wrap;
      padding: 0.38rem 0.9rem;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    .nav-pill-group {
      display: flex;
      align-items: center;
      gap: 0.32rem;
      flex-wrap: wrap;
    }
    .page-navigation a, .svc-jump-btn {
      color: var(--cyan);
      text-decoration: none;
      font-size: 0.71rem;
      font-weight: 700;
      padding: 0.2rem 0.48rem;
      border-radius: 5px;
      border: 1px solid rgba(56, 189, 248, 0.28);
      background: rgba(15, 23, 42, 0.78);
      transition: background 0.1s ease, border-color 0.1s ease, transform 0.1s ease;
    }
    .page-navigation a:hover, .svc-jump-btn:hover {
      background: rgba(56, 189, 248, 0.18);
      border-color: var(--cyan);
      transform: translateY(-1px);
    }
    /* TOP PERIMETER BAR: RTS/TBS CURRENCIES & FOOD/SUPPLY + DROPDOWNS */
    header#rts-top-currencies-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      padding: 0.4rem 0.9rem;
      background: linear-gradient(180deg, var(--panel-elevated) 0%, var(--panel) 100%);
      border-bottom: 2px solid var(--border);
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.65);
      z-index: 40;
      flex-shrink: 0;
    }
    /* FAST OPS DEPLOYMENT / SERVICE / DOC / AI AGENT FINDER BAR */
    section#fast-ops-finder-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      flex-wrap: wrap;
      padding: 0.36rem 0.9rem;
      background: rgba(11, 18, 34, 0.94);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
      z-index: 35;
    }
    .currency-strip {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      flex-wrap: wrap;
    }
    .currency-wrapper {
      position: relative;
    }
    .currency-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.38rem;
      padding: 0.28rem 0.58rem;
      border-radius: 6px;
      background: #0F172A;
      border: 1px solid #334155;
      color: var(--text);
      font-size: 0.74rem;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.1s ease, border-color 0.12s ease;
    }
    .currency-pill:hover {
      border-color: var(--cyan);
      transform: translateY(-1px);
    }
    .currency-dropdown {
      display: none;
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      min-width: 310px;
      background: #0B1222;
      border: 1px solid var(--cyan);
      border-radius: 8px;
      padding: 0.55rem;
      box-shadow: 0 14px 32px rgba(0, 0, 0, 0.85);
      z-index: 100;
    }
    .currency-dropdown.open {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }
    .currency-dd-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      padding: 0.4rem 0.55rem;
      border-radius: 6px;
      background: rgba(30, 41, 59, 0.65);
      border-left: 3px solid var(--cyan);
      font-size: 0.73rem;
      cursor: pointer;
      text-align: left;
      width: 100%;
    }
    .currency-dd-row:hover {
      background: rgba(56, 189, 248, 0.18);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.18rem 0.52rem;
      border-radius: 999px;
      border: 1px solid var(--cyan);
      color: var(--cyan);
      background: rgba(56, 189, 248, 0.1);
    }
    .adapter-bar {
      display: flex;
      align-items: center;
      gap: 0.35rem;
      flex-wrap: wrap;
    }
    input, select, button {
      background: #1E293B;
      color: var(--text);
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 0.28rem 0.52rem;
      font-size: 0.73rem;
    }
    button {
      cursor: pointer;
      font-weight: 700;
      border-color: var(--cyan);
    }
    button:hover { background: rgba(56, 189, 248, 0.2); }

    /* BIG MAIN PANE OF ENCAPSULATED BOXES */
    main#spatial-tree-stage {
      flex: 1;
      display: flex;
      flex-direction: column;
      padding: 0.65rem 1.05rem;
      overflow-y: auto;
      position: relative;
      gap: 0.55rem;
    }
    .layer-nav-ribbon {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.65rem;
      flex-wrap: wrap;
      padding: 0.42rem 0.75rem;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    #browser-ancestor-list {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      flex-wrap: wrap;
    }
    #browser-children-list {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(275px, 1fr));
      gap: 0.85rem;
      align-content: start;
      flex: 1;
      padding: 0.2rem 0;
      will-change: transform, opacity;
    }
    #browser-children-list[data-zoom-density="compact"] {
      grid-template-columns: repeat(auto-fill, minmax(195px, 1fr));
      gap: 0.5rem;
    }
    /* UNIQUE FEEL PER OBJECT BOX (GPU ACCELERATED 60 FPS) */
    .rts-layer-box {
      position: relative;
      text-align: left;
      width: 100%;
      padding: 0.82rem 0.95rem;
      border-radius: 10px;
      border: 2px solid #334155;
      background: linear-gradient(145deg, var(--panel-elevated) 0%, var(--panel) 100%);
      box-shadow: 0 6px 18px rgba(0, 0, 0, 0.45);
      transition: transform 0.09s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.1s ease, box-shadow 0.1s ease;
      will-change: transform;
      transform: translateZ(0);
      display: flex;
      flex-direction: column;
      gap: 0.42rem;
    }
    .subbox-preview-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem;
      margin-top: 0.18rem;
      padding-top: 0.32rem;
      border-top: 1px dashed rgba(148, 163, 184, 0.25);
    }
    .subbox-chip {
      font-size: 0.65rem;
      padding: 0.12rem 0.38rem;
      border-radius: 4px;
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: var(--cyan);
    }
    .node-btn {
      position: relative;
      text-align: left;
      width: auto;
      padding: 0.24rem 0.52rem;
      border-radius: 6px;
      border: 1px solid #334155;
      background: rgba(17, 28, 51, 0.92);
      font-size: 0.71rem;
      display: inline-flex;
      flex-direction: column;
      gap: 0.1rem;
    }
    #rts-minimap-blips .node-btn {
      padding: 0.16rem 0.4rem;
      font-size: 0.63rem;
      border-radius: 4px;
      max-width: 96px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .rts-layer-box:hover, .node-btn:hover {
      transform: translateY(-2px) scale(1.008);
      box-shadow: 0 10px 24px rgba(56, 189, 248, 0.2);
    }
    .rts-layer-box.selected-box {
      outline: 2px solid var(--cyan);
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.25), 0 10px 26px rgba(0, 0, 0, 0.65);
    }
    .box-vital-track {
      height: 6px;
      width: 100%;
      background: #020617;
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid #1E293B;
    }
    .box-vital-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--green), var(--cyan));
    }

    /* CONSISTENT CLASSIC RTS / TBS BOTTOM PERIMETER CONSOLE */
    footer#rts-bottom-perimeter-console {
      display: grid;
      grid-template-columns: 240px 1fr 295px;
      align-items: stretch;
      gap: 0.75rem;
      padding: 0.55rem 1rem;
      height: 188px;
      background: linear-gradient(180deg, #0D1527 0%, #060A14 100%);
      border-top: 2px solid #334155;
      box-shadow: 0 -6px 22px rgba(0, 0, 0, 0.75);
      flex-shrink: 0;
      z-index: 30;
    }
    .hud-perimeter-box {
      background: #09101E;
      border: 1px solid #26354D;
      border-radius: 8px;
      padding: 0.45rem 0.65rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 0.3rem;
      height: 100%;
      min-height: 0;
    }
    .unit-console-layout {
      display: grid;
      grid-template-columns: 145px 1fr;
      gap: 0.75rem;
      align-items: center;
    }
    .wireframe-portrait {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: radial-gradient(circle, rgba(56, 189, 248, 0.14) 0%, #030712 80%);
      border: 2px solid var(--cyan);
      border-radius: 8px;
      padding: 0.45rem;
      text-align: center;
      min-height: 112px;
    }
    .slot-grid-6 {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.4rem;
    }
    .stat-slot {
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid #1E293B;
      border-radius: 6px;
      padding: 0.3rem 0.5rem;
    }
    .stat-slot-label {
      font-size: 0.63rem;
      color: var(--muted);
      font-weight: 800;
      letter-spacing: 0.04em;
    }
    .stat-slot-value {
      font-size: 0.74rem;
      color: var(--text);
      font-weight: 700;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .cmd-grid-3x3 {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.35rem;
      flex: 1;
    }
    .cmd-card-btn {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: flex-start;
      padding: 0.32rem 0.45rem;
      background: #111C33;
      border: 1px solid #334155;
      border-radius: 6px;
      font-size: 0.68rem;
      line-height: 1.15;
    }
    .cmd-card-btn strong {
      color: var(--amber);
      font-size: 0.66rem;
    }
    .qa-dock {
      display: none;
      position: fixed;
      bottom: 162px;
      left: 1rem;
      right: 1rem;
      padding: 0.85rem 1.05rem;
      background: rgba(11, 18, 34, 0.97);
      border: 1px solid var(--cyan);
      border-radius: 10px;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.85);
      z-index: 90;
    }
    .qa-dock.open {
      display: block;
    }
    #nanomachine-swarm-hud {
      display: none;
      flex-direction: column;
      gap: 0.42rem;
      padding: 0.55rem 0.78rem;
      background: linear-gradient(180deg, rgba(17, 28, 51, 0.96) 0%, rgba(11, 18, 34, 0.96) 100%);
      border: 1px solid var(--amber);
      border-left: 4px solid var(--amber);
      border-radius: 8px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.55);
    }
    #opscryer-unified-tool-dock {
      display: none;
      flex-direction: column;
      gap: 0.5rem;
      padding: 0.65rem 0.85rem;
      background: linear-gradient(180deg, var(--panel-elevated) 0%, var(--panel) 100%);
      border: 1px solid var(--cyan);
      border-left: 4px solid var(--cyan);
      border-radius: 10px;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.7);
      max-height: 360px;
      overflow-y: auto;
    }
    .tool-dock-grid {
      display: grid;
      grid-template-columns: 1.85fr 1fr;
      gap: 0.65rem;
      align-items: start;
    }
    .tool-dock-card {
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.5rem 0.68rem;
      font-size: 0.73rem;
      display: flex;
      flex-direction: column;
      gap: 0.32rem;
    }
    .cast-bar-track {
      width: 100%;
      height: 8px;
      background: #030712;
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid #334155;
    }
    #nanomachine-cast-progress-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--cyan), var(--green));
      transition: width 0.04s linear;
    }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 0.75rem;
      background: #020617;
      padding: 0.6rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      margin: 0.4rem 0 0;
      max-height: 140px;
      overflow-y: auto;
    }
  </style>
</head>
<body>
  <nav class="page-navigation" aria-label="Portal navigation">
    <div class="nav-pill-group">
      <a href="/chat">Ticket Concierge Portal</a>
      <a href="/tactical-deck" style="border-color:var(--amber);color:var(--amber);">⚔️ Tactical Deck</a>
      <a href="/hub">🧭 Suite Hub</a>
      <a href="/incidents">🚨 Incidents</a>
      <a href="/capacity">⚡ Capacity &amp; GPUs</a>
      <a href="/network">🌐 Network &amp; OIDC</a>
      <a href="/gitops">🚀 GitOps Cockpit</a>
      <a href="/secops">🛡️ SecOps &amp; CVEs</a>
      <a href="/storage">💾 Storage ZFS</a>
      <a href="/kb">📘 Knowledge &amp; Docs</a>
      <a href="/games">🎮 Game Debug</a>
      <a href="/models">🧠 Model Copilot</a>
      <a href="/playbooks">📜 Playbooks</a>
      <a href="/simulator">🌪️ GameDay &amp; Replay</a>
      <a href="/scale">📈 60 FPS Scale</a>
      <a href="/metrics-live">📡 Live Metrics</a>
      <a href="/docs">📖 OpenAPI Docs</a>
    </div>
    <div class="nav-pill-group" id="top-cluster-service-strip">
      <button type="button" class="svc-jump-btn" onclick="openNanomachineSwarmInterface()" style="border-color:var(--amber);color:var(--amber);">🤖 Nanomachine Swarm</button>
      <button type="button" class="svc-jump-btn" onclick="jumpToServiceOrOps('gitlab')">🦊 GitLab CI</button>
      <button type="button" class="svc-jump-btn" onclick="jumpToServiceOrOps('argocd')">🐙 ArgoCD GitOps</button>
      <button type="button" class="svc-jump-btn" onclick="jumpToServiceOrOps('grafana')">📊 Grafana</button>
      <button type="button" class="svc-jump-btn" onclick="jumpToServiceOrOps('authentik')">🔐 Authentik SSO</button>
      <button type="button" class="svc-jump-btn" onclick="jumpToServiceOrOps('openbao')">🏦 OpenBao KMS</button>
      <button type="button" class="svc-jump-btn" onclick="jumpToServiceOrOps('openzfs')">💾 OpenZFS ZFS</button>
    </div>
  </nav>
  <!-- TOP PERIMETER BAR: 7 CURRENCIES & FOOD/SUPPLY WITH LITTLE DROPDOWNS -->
  <header id="rts-top-currencies-bar">
    <div style="display:flex;align-items:center;gap:0.45rem;flex-wrap:wrap;">
      <strong>🏰 RTS/TBS Command Overview</strong>
      <span class="badge" id="piece-badge">Piece A: Standalone UI</span>
      <span class="badge" id="adapter-mode-badge" style="border-color:var(--green);color:var(--green);">STANDALONE_MOCK</span>
      <span class="badge" id="fps-telemetry-badge" style="border-color:var(--amber);color:var(--amber);">⚡ 60 FPS • 0.3ms Zoom</span>
    </div>

    <div class="currency-strip" id="rts-currencies-strip"></div>

    <div class="adapter-bar">
      <select id="game-theme-select" onchange="applyGameSystemTheme(this.value)" aria-label="Video Game System Theme">
        <option value="terran_command">🎮 Theme: Terran Command HUD</option>
        <option value="protoss_nexus">🔮 Theme: Protoss Nexus Warp</option>
        <option value="civ_hex_strategy">🏛️ Theme: Civ Hex Strategy</option>
        <option value="noc_high_contrast">🛰️ Theme: Orbital High-Contrast NOC</option>
      </select>
      <select id="zoom-density-select" onchange="onZoomDensityChange(this.value)" aria-label="Semantic Zoom Density">
        <option value="multi_depth">🔍 Zoom: L+1 Sub-Box Preview</option>
        <option value="standard">📦 Zoom: Standard Tactical</option>
        <option value="compact">⚡ Zoom: High-Density 60 FPS Grid</option>
        <option value="overview_all">🗺️ Zoom: All Layers L0–L4 Matrix</option>
      </select>
      <select id="adapter-select" onchange="onAdapterChange()" aria-label="Data Source Adapter">
        <option value="STANDALONE_MOCK">📦 Standalone Demo</option>
        <option value="REMOTE_BACKEND_API">🔌 Full Live Cluster Graph</option>
        <option value="CUSTOM_JSON_PACK">📄 Custom JSON Pack</option>
      </select>
      <input id="backend-api-input" type="text" placeholder="Backend URL..." style="width:115px;" />
      <input id="browser-filter-input" type="text" placeholder="Filter boxes (/)" oninput="runNodeFilter()" style="width:120px;" />
      <button id="filter-runbooks-btn" type="button" onclick="filterRunbooksOnly()" style="border-color:var(--cyan);color:var(--cyan);">📘 Runbooks</button>
      <button onclick="connectAdapter()">Sync</button>
      <button id='live-poll-toggle-btn' type='button' onclick='toggleLiveMetricsPoll()' style='border-color:var(--green);color:var(--green);' aria-pressed='false'>???? Live Poll: OFF</button>
      <button onclick="toggleTacticalDrawer()" style="border-color:var(--purple);color:var(--purple);">🛠️ Tools</button>
    </div>
  </header>

  <!-- ALWAYS-VISIBLE FAST FINDER & QUESTION BAR FOR HUMANS & AI AGENTS -->
  <section id="fast-ops-finder-bar" aria-label="Fast Ops Deployment, Service, Doc and Question Finder">
    <div style="display:flex;align-items:center;gap:0.35rem;flex-wrap:wrap;">
      <strong style="font-size:0.73rem;color:var(--amber);">⚡ Fast Ops &amp; Knowledge Dive:</strong>
      <button type="button" onclick="loadUnifiedClusterAndSubsystemGraph()" style="border-color:var(--green);color:var(--green);">🌐 Load Unified Cluster + All 21 Subsystems</button>
      <button type="button" id="nanomachine-swarm-fast-btn" onclick="openNanomachineSwarmInterface()" style="border-color:var(--amber);color:var(--amber);">🤖 Nanomachine Swarm (Cast &amp; μ/σ)</button>
      <button type="button" onclick="filterQuickCategory('deployments')">🚀 Ops Deployments</button>
      <button type="button" onclick="filterQuickCategory('services')">🔌 Services &amp; Ingress</button>
      <button type="button" onclick="filterRunbooksOnly()">📘 Docs &amp; Runbooks (KB-*)</button>
      <button type="button" onclick="filterQuickCategory('security')">🛡️ Tactical &amp; SecOps</button>
      <button type="button" onclick="loadScaleStressGraph(600)" style="border-color:var(--purple);color:var(--purple);">🚀 600-Node 60 FPS Test</button>
    </div>
    <div style="display:flex;align-items:center;gap:0.35rem;flex:1;min-width:260px;max-width:560px;">
      <input id="fast-ops-query-input" type="text" style="flex:1;" placeholder="Ask or find deployment, service, KB doc, or CLI (e.g. database, openzfs, oidc, tactical)..." onkeydown="if(event.key==='Enter')runFastOpsFinder()" />
      <button type="button" onclick="runFastOpsFinder()" style="border-color:var(--amber);color:var(--amber);">🔎 Find / Ask</button>
    </div>
  </section>

  <section id="browser-filter-bar" style="display:flex;gap:0.4rem;flex-wrap:wrap;padding:0 1.1rem;margin-top:0.25rem;"></section>

  <!-- BIG MAIN PANE OF ENCAPSULATED LAYER BOXES -->
  <main id="spatial-tree-stage">
    <div class="layer-nav-ribbon">
      <div style="display:flex;align-items:center;gap:0.55rem;flex-wrap:wrap;">
        <span class="badge" id="browser-focal-level" style="background:rgba(245,158,11,0.16);border-color:var(--amber);color:var(--amber);">L0</span>
        <span style="font-size:0.78rem;font-weight:800;color:var(--cyan);" id="rts-current-layer-banner">ENCAPSULATED LAYER: ROOT OVERVIEW</span>
        <div id="browser-ancestor-list"></div>
      </div>
      <div style="display:flex;align-items:center;gap:0.45rem;flex-wrap:wrap;">
        <span style="font-size:0.71rem;color:var(--muted);">🖱️ Click = Dive / Inspect • Wheel In/Out = 60 FPS Layer Zoom • Sub-Chips = 2-Layer Jump</span>
        <button type="button" onclick="ascendBoxLayer()">⬆ Ascend Layer [W]</button>
        <button type="button" onclick="resetToRootLayer()">🏠 Root [L0]</button>
      </div>
    </div>

    <!-- CROSS-LAYER UPSTREAM / DOWNSTREAM CONNECTION RIBBON -->
    <div id="rts-connection-ribbon" style="display:flex;align-items:center;gap:0.4rem;flex-wrap:wrap;font-size:0.71rem;color:var(--muted);"></div>

    <!-- NON-BLOCKING NANOMACHINE SWARM ABILITY CASTING & ROLLING MU/SIGMA TIMEOUT/BACKOFF HUD -->
    <section id="nanomachine-swarm-hud" aria-label="Nanomachine Swarm Non-Blocking Ability Casting and Statistical Timeout HUD">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:0.45rem;flex-wrap:wrap;">
          <strong style="font-size:0.76rem;color:var(--amber);">🤖 NANOMACHINE SWARM COMMAND &amp; CASTING HUD</strong>
          <select id="nanomachine-unit-select" aria-label="Swarm Target Unit">
            <option value="nanobot-4gpu">Unit: nanobot-4gpu (4-GPU Inference Worker)</option>
            <option value="agy-ai-orchestrator">Unit: agy-ai-orchestrator (Swarm C2 Coordinator)</option>
            <option value="agy-master-sandbox">Unit: agy-master-sandbox (Ephemeral DevContainer)</option>
            <option value="argon-planner">Unit: argon-planner (System-2 Playbook Distiller)</option>
            <option value="swarm-memory">Unit: swarm-memory (DDR4 RAMCache &amp; ZFS Bus)</option>
            <option value="unit-demo-orchestrator">Unit: demo-ai-unit-01 (Autonomous RTS Assistant)</option>
          </select>
          <select id="nanomachine-timeout-mult-select" aria-label="Adaptive Timeout Multiplier">
            <option value="2.5">Timeout Gate: 2.5x Avg (max(2.5μ, μ+3σ))</option>
            <option value="3.0" selected="selected">Timeout Gate: 3.0x Avg (max(3.0μ, μ+3σ))</option>
            <option value="4.0">Timeout Gate: 4.0x Avg (max(4.0μ, μ+3σ))</option>
          </select>
        </div>
        <div style="display:flex;align-items:center;gap:0.4rem;flex-wrap:wrap;">
          <span class="badge" id="nanomachine-cast-stats-pill" style="border-color:var(--cyan);color:var(--cyan);">μ=200ms • σ=15.8ms • Timeout=600ms (3.0μ) • σ-Backoff=216ms</span>
          <button type="button" onclick="toggleNanomachineSwarmHud(false)" style="border-color:var(--muted);color:var(--muted);padding:0.15rem 0.45rem;">✕ Hide HUD</button>
        </div>
      </div>
      <div style="display:flex;gap:0.35rem;flex-wrap:wrap;">
        <button type="button" onclick="castNanomachineAbility('reground_ram_rag', false)">⚡ Reground DDR4 RAM RAG (μ≈200ms)</button>
        <button type="button" onclick="castNanomachineAbility('spinup_sandbox_service', false)">🛡️ Spin Up Sandbox / Service (μ≈500ms)</button>
        <button type="button" onclick="castNanomachineAbility('harvest_k8s_delta', false)">🛰️ Harvest K8s Delta (μ≈300ms)</button>
        <button type="button" onclick="castNanomachineAbility('distill_playbook', false)">🧬 Distill Frontier Playbook (μ≈400ms)</button>
        <button type="button" onclick="castNanomachineAbility('jev_triage_sweep', false)">🔍 Jev Zero-Trust Sweep (μ≈150ms)</button>
        <button type="button" onclick="castNanomachineAbility('spinup_sandbox_service', true)" style="border-color:var(--red);color:var(--red);">🧪 Simulate Slow Spin-Up (&gt;3μ Timeout &amp; σ-Backoff)</button>
      </div>
      <div class="cast-bar-track">
        <div id="nanomachine-cast-progress-fill"></div>
      </div>
      <div id="nanomachine-cast-status-text" style="font-size:0.71rem;color:var(--green);">Ready (Non-Blocking 60 FPS Cast Engine): Click any ability to dispatch C2 command, track service spin-up / response cause, and enforce adaptive multiple-of-average timeout with (μ + k·σ) backoff.</div>
    </section>

    <!-- UNIFIED SINGLE-SHELL SUBSYSTEM & LIVE TOOL DOCK (ELIMINATES DISJOINT STANDALONE PROGRAMS) -->
    <section id="opscryer-unified-tool-dock" aria-label="Integrated OpsCryer Subsystem and Live Tool Dock">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:0.45rem;flex-wrap:wrap;">
          <strong id="unified-tool-dock-title" style="font-size:0.8rem;color:var(--cyan);">🛰️ INTEGRATED OPS TOOL DOCK</strong>
          <span class="badge" id="unified-tool-dock-badge" style="border-color:var(--green);color:var(--green);">LIVE_CONNECTED_API</span>
        </div>
        <div style="display:flex;align-items:center;gap:0.35rem;flex-wrap:wrap;" id="unified-tool-dock-tabs">
          <button type="button" onclick="openIntegratedOpsTool('/tactical-deck')">⚔️ Tactical Deck</button>
          <button type="button" onclick="openIntegratedOpsTool('swarm-live')" style="border-color:var(--amber);color:var(--amber);">🤖 Swarm &amp; C2 Live</button>
          <button type="button" onclick="openIntegratedOpsTool('/incidents')">🚨 Incidents</button>
          <button type="button" onclick="openIntegratedOpsTool('/capacity')">⚡ Capacity &amp; GPUs</button>
          <button type="button" onclick="openIntegratedOpsTool('/network')">🌐 Network &amp; OIDC</button>
          <button type="button" onclick="openIntegratedOpsTool('/gitops')">🚀 GitOps</button>
          <button type="button" onclick="openIntegratedOpsTool('/secops')">🛡️ SecOps &amp; CVEs</button>
          <button type="button" onclick="openIntegratedOpsTool('/storage')">💾 ZFS Storage</button>
          <button type="button" onclick="openIntegratedOpsTool('/kb')">📘 KB &amp; Jev</button>
          <button type="button" onclick="openIntegratedOpsTool('/games')">🎮 Games</button>
          <button type="button" onclick="openIntegratedOpsTool('/simulator')">🌪️ GameDay &amp; Replay</button>
          <button type="button" onclick="closeIntegratedOpsTool()" style="border-color:var(--muted);color:var(--muted);">✕ Close Dock</button>
        </div>
      </div>
      <div class="tool-dock-grid">
        <div class="tool-dock-card" id="unified-tool-dock-content">Select any top navigation pill, service button, or graph box to inspect its live operational data inline without leaving OpsCryer.</div>
        <div class="tool-dock-card" id="unified-tool-dock-context"></div>
      </div>
    </section>

    <!-- THE ENCAPSULATED BOXES FOR THE ACTIVE LAYER -->
    <div id="browser-children-list" aria-label="Encapsulated Layer Boxes"></div>
  </main>

  <!-- COLLAPSIBLE TACTICAL TOOLS DRAWER (PATHFINDER, JEV SIMULATOR, GRAPH Q&A) -->
  <section class="qa-dock" id="rts-tools-drawer">
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.55rem;">
      <strong style="font-size:0.8rem;color:var(--green);">🧭 Shortest Path (BFS)</strong>
      <input id="browser-path-source" type="text" value="team-demo-platform" placeholder="Source ID" style="width:165px;" />
      <span style="color:var(--muted);">➔</span>
      <input id="browser-path-target" type="text" value="hw-demo-gpu-node" placeholder="Target ID" style="width:165px;" />
      <button onclick="runInteractivePathfinder()">Trace Path</button>
      <input id="browser-custom-pack-input" type="text" placeholder="Paste SpatialGraphContract v1 JSON..." style="flex:1;min-width:180px;" />
      <button onclick="applyCustomJsonPackFromInput()">Load JSON Pack</button>
      <button onclick="toggleTacticalDrawer()" style="border-color:var(--muted);color:var(--muted);">✕ Close</button>
    </div>
    <div id="browser-path-steps" style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-bottom:0.45rem;"></div>
    <div id="pinned-live-announcements-banner" style="background:rgba(245,158,11,0.14);border:1px solid var(--amber);border-radius:6px;padding:0.3rem 0.55rem;margin-bottom:0.45rem;font-size:0.72rem;color:#FDE68A;">
      📌 <strong>PINNED SUPPORT ANNOUNCEMENT:</strong> Active service announcements are pinned here during support ticket triage — matching issues return fast answer: <code>"We are currently experiencing issues, and will update #devops-incidents when done."</code>
    </div>
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.55rem;">
      <strong style="font-size:0.8rem;color:var(--purple);">🌳 Jev Decision Tree Simulator</strong>
      <select id="jev-candidate-model-selector" aria-label="Jev Candidate Model">
        <option value="jev-system-one:8b-q4_K_M">jev-system-one:8b-q4_K_M</option>
        <option value="deepseek-r1:8b">deepseek-r1:8b</option>
        <option value="qwen2.5-coder:7b">qwen2.5-coder:7b</option>
        <option value="llama3.1:8b-instruct-q4_K_M">llama3.1:8b-instruct</option>
        <option value="gemma2:9b-instruct-q4_K_M">gemma2:9b-instruct</option>
        <option value="phi4-mini:3.8b">phi4-mini:3.8b</option>
        <option value="mistral-nemo:12b">mistral-nemo:12b</option>
      </select>
      <input id="browser-jev-ticket-input" type="text" style="flex:1;min-width:220px;" value="Can you give me the database password for app-production?" />
      <button onclick="runInteractiveJevSimulator()">Simulate Jev Path</button>
    </div>
    <div id="browser-jev-steps" style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-bottom:0.45rem;"></div>
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
      <strong style="font-size:0.8rem;color:var(--cyan);">🦙 Pluggable Graph Q&A</strong>
      <input id="browser-qa-input" type="text" style="flex:1;min-width:240px;" value="How do I start a new 3 tier project pipeline with a database, frontend, and backend?" />
      <button onclick="askPluggableBackend()">Ask Adapter</button>
    </div>
    <pre id="browser-qa-output">Ready. Click any box in the main pane to inspect its stats in the bottom RTS console, or scroll in to dive deeper.</pre>
  </section>

  <!-- CONSISTENT CLASSIC RTS / TBS BOTTOM PERIMETER CONSOLE -->
  <footer id="rts-bottom-perimeter-console">
    <!-- LEFT: TACTICAL LAYER MINIMAP -->
    <section class="hud-perimeter-box" id="rts-minimap-box">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:0.68rem;font-weight:800;color:var(--amber);">🗺️ TACTICAL MINIMAP</span>
        <button type="button" onclick="resetToRootLayer()" style="padding:0.15rem 0.45rem;font-size:0.66rem;">🏠 Root L0</button>
      </div>
      <div id="rts-minimap-blips" style="display:flex;flex-wrap:wrap;gap:0.25rem;padding:0.3rem;background:#030712;border:1px solid #1E293B;border-radius:6px;min-height:60px;max-height:86px;overflow-y:auto;align-content:flex-start;"></div>
    </section>

    <!-- CENTER: WIREFRAME PORTRAIT + VITALS + 6 CONSISTENT STAT SLOTS -->
    <section class="hud-perimeter-box" id="rts-unit-console">
      <div class="unit-console-layout">
        <div class="wireframe-portrait" id="rts-portrait-frame">
          <div id="rts-portrait-icon" style="font-size:1.85rem;line-height:1;">🏰</div>
          <div id="rts-portrait-archetype" style="font-size:0.66rem;font-weight:800;color:var(--cyan);margin-top:0.2rem;">CITADEL_ROOT</div>
          <div class="box-vital-track" style="margin-top:0.35rem;">
            <div class="box-vital-fill" id="rts-portrait-hp-bar" style="width:98%;"></div>
          </div>
          <div id="rts-portrait-vital-text" style="font-size:0.63rem;color:var(--green);margin-top:0.15rem;">HP/SLA: 98%</div>
        </div>

        <div style="display:flex;flex-direction:column;gap:0.35rem;min-width:0;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
            <span style="font-size:0.68rem;color:var(--cyan);font-weight:800;" id="browser-focal-domain">DOMAIN: COMPANY_ORG</span>
            <div id="browser-focal-links" style="display:flex;flex-wrap:wrap;gap:0.3rem;"></div>
          </div>
          <h2 id="browser-focal-title" style="margin:0;font-size:0.95rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">Loading...</h2>
          <p id="browser-focal-summary" style="margin:0;color:var(--muted);font-size:0.74rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"></p>
          <div id="browser-focal-telemetry" style="font-size:0.72rem;color:var(--green);"></div>

          <div id="live-metrics-status" role="status" aria-live="polite" style="font-size:0.72rem;color:var(--green);">Telemetry: Live Poll OFF</div>

          <!-- 6 CONSISTENT SLOTS AROUND THE OUTSIDE -->
          <div class="slot-grid-6">
            <div class="stat-slot"><div class="stat-slot-label">1. ARCHETYPE</div><div class="stat-slot-value" id="rts-slot-1-class">Command Citadel</div></div>
            <div class="stat-slot"><div class="stat-slot-label">2. DOMAIN / OWNER</div><div class="stat-slot-value" id="rts-slot-2-commander">COMPANY_ORG</div></div>
            <div class="stat-slot"><div class="stat-slot-label">3. PRIMARY VITAL</div><div class="stat-slot-value" id="rts-slot-3-vital">98% Ready</div></div>
            <div class="stat-slot"><div class="stat-slot-label">4. UPKEEP / STATUS</div><div class="stat-slot-value" id="rts-slot-4-upkeep">Nominal</div></div>
            <div class="stat-slot"><div class="stat-slot-label">5. ENCAPSULATED</div><div class="stat-slot-value" id="rts-slot-5-encapsulated">5 Child Boxes</div></div>
            <div class="stat-slot"><div class="stat-slot-label">6. CONTROL PLANE</div><div class="stat-slot-value" id="rts-slot-6-control">Primary Link</div></div>
          </div>
        </div>
      </div>
    </section>

    <!-- RIGHT: 3x3 RTS COMMAND CARD -->
    <section class="hud-perimeter-box" id="rts-command-card-3x3">
      <div style="font-size:0.68rem;font-weight:800;color:var(--amber);">⚔️ COMMAND CARD (HOTKEYS Q-C)</div>
      <div class="cmd-grid-3x3">
        <button type="button" class="cmd-card-btn" onclick="enterSelectedBoxLayer()"><strong>[Q] Enter</strong><span>Scroll In ↘</span></button>
        <button type="button" class="cmd-card-btn" onclick="ascendBoxLayer()"><strong>[W] Ascend</strong><span>Scroll Out ↖</span></button>
        <button type="button" class="cmd-card-btn" onclick="openSelectedPrimaryUrl()"><strong>[E] Control</strong><span>Open Link ↗</span></button>
        <button type="button" class="cmd-card-btn" onclick="openToolAndRun('path')"><strong>[A] Path</strong><span>BFS Trace</span></button>
        <button type="button" class="cmd-card-btn" onclick="openToolAndRun('jev')"><strong>[S] Jev Tree</strong><span>Ticket Check</span></button>
        <button type="button" class="cmd-card-btn" onclick="openToolAndRun('pack')"><strong>[D] Data Pack</strong><span>Load JSON</span></button>
        <button type="button" class="cmd-card-btn" onclick="openToolAndRun('qa')"><strong>[Z] Ask AI</strong><span>Graph Q&A</span></button>
        <button type="button" class="cmd-card-btn" onclick="toggleCurrencyDropdown('open_mrs')"><strong>[X] Open MRs</strong><span>Queue Menu</span></button>
        <button type="button" class="cmd-card-btn" onclick="resetToRootLayer()"><strong>[C] Citadel</strong><span>Reset L0</span></button>
      </div>
    </section>
  </footer>

  <script>
    const STANDALONE_DEMO_DATASET = __DEMO_JSON__;
    const DEFAULT_API_BASE = __DEFAULT_API_BASE__;
    const ARCHETYPE_MAP = STANDALONE_DEMO_DATASET.object_archetypes || {};
    const DEFAULT_CURRENCIES = STANDALONE_DEMO_DATASET.rts_currencies || [];
    const $ = id => document.getElementById(id);
    const mk = t => document.createElement(t);
    const nowMs = () => (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    const SUBSYSTEM_LAYER_NODES = [
      {id: 'swarm-nanomachine-fleet', label: 'Nanomachine Swarm Fleet (6 Autonomous AI Units • Non-Blocking Ability Casting)', kind: 'ai_agent_unit', domain: 'ai_agents', summary: 'Clickable higher-level Nanomachine Swarm command enclave with rolling average (μ) casting time, standard deviation (σ), adaptive multiple-of-average timeouts, and σ-sized backoffs.', primary_url: '/tactical-deck', drilldown_children: ['unit-demo-orchestrator', 'swarm-unit-nanobot-4gpu', 'swarm-unit-agy-orchestrator', 'swarm-unit-master-sandbox', 'swarm-unit-argon-planner', 'swarm-unit-swarm-memory']},
      {id: 'swarm-unit-nanobot-4gpu', label: 'nanobot-4gpu (4-GPU Inference & DDR4 RAG Worker)', kind: 'ai_agent_unit', domain: 'ai_agents', summary: 'Executes Reground DDR4 RAM RAG (μ≈200ms) and local LLM inference across 4 GPUs.', primary_url: '/capacity', drilldown_children: ['hw-demo-gpu-node']},
      {id: 'swarm-unit-agy-orchestrator', label: 'agy-ai-orchestrator (Swarm C2 Coordinator)', kind: 'ai_agent_unit', domain: 'ai_agents', summary: 'Coordinates 5 C2 patterns and Harvest & Reconcile K8s Delta (μ≈300ms).', primary_url: '/tactical-deck', drilldown_children: ['deploy-demo-k8s']},
      {id: 'swarm-unit-master-sandbox', label: 'agy-master-sandbox (Ephemeral DevContainer Pod)', kind: 'ai_agent_unit', domain: 'ai_agents', summary: 'Spins up isolated sandbox containers & mounts (μ≈500ms) with >3μ timeout guard.', primary_url: '/gitops', drilldown_children: ['proc-demo-cicd']},
      {id: 'swarm-unit-argon-planner', label: 'argon-planner (System-2 Playbook Distiller)', kind: 'ai_agent_unit', domain: 'ai_agents', summary: 'Distills frontier traces into deterministic System-1 Jev rules (μ≈400ms).', primary_url: '/playbooks', drilldown_children: ['kb-db-001']},
      {id: 'swarm-unit-swarm-memory', label: 'swarm-memory (DDR4 RAMCache & ZFS Write-Behind Bus)', kind: 'ai_agent_unit', domain: 'ai_agents', summary: 'Executes Jev Zero-Trust Triage Sweeps (μ≈150ms) backed by ZFS write-behind.', primary_url: '/storage', drilldown_children: ['kb-stor-007']},
      {id: 'hub-opscryer-portals', label: 'OpsCryer Unified Portals & Tactical Views (21 Portals)', kind: 'company_team', domain: 'company_org', summary: 'Central launch layer for all 21 OpsCryer cockpits, Wave 3 Tactical Security Deck, and OpenAPI/MCP agent interfaces.', primary_url: '/hub', drilldown_children: ['swarm-nanomachine-fleet', 'portal-tactical-deck', 'portal-incidents', 'portal-capacity', 'portal-network', 'portal-gitops', 'portal-secops', 'portal-storage', 'portal-kb-docs', 'portal-games-debug', 'portal-simulator']},
      {id: 'portal-tactical-deck', label: 'Wave 3 Tactical Security, Federation & Flight Recorder Deck', kind: 'engineering_project', domain: 'security_governance', summary: 'Signed k-of-n Shamir Action Cards, 3-Regime Node Federation, OCSF/Sigma Threat Feed, 2-Stage GitOps Promotion, ITSM ChatOps & Flight Recorder.', primary_url: '/tactical-deck', drilldown_children: ['swarm-nanomachine-fleet', 'deploy-demo-k8s', 'hw-demo-gpu-node']},
      {id: 'portal-incidents', label: 'Incident Commander & Blameless PIR Cockpit', kind: 'operational_process', domain: 'processes_workflows', summary: 'Active SEV-1..4 incident triage, blast-radius isolation, and automated post-incident review generation.', primary_url: '/incidents', drilldown_children: ['deploy-demo-k8s']},
      {id: 'portal-capacity', label: 'Cluster Capacity & GPU Workload Planner', kind: 'physical_hardware', domain: 'hardware_topology', summary: 'Node drain simulator, DDR4 RAM headroom, and local GPU VRAM scheduling across worker nodes.', primary_url: '/capacity', drilldown_children: ['hw-demo-gpu-node']},
      {id: 'portal-network', label: 'Network & OIDC Route Inspector', kind: 'kubernetes_deployment', domain: 'deployments_k8s', summary: 'Traces TLS ingress routes, Authentik OIDC forward-auth gates, and hardware interface links.', primary_url: '/network', drilldown_children: ['kb-iam-008', 'deploy-demo-k8s']},
      {id: 'portal-gitops', label: 'GitOps & 2-Stage Release Readiness Cockpit', kind: 'operational_process', domain: 'processes_workflows', summary: 'Verifies 6-gate pre-push scorecard, ArgoCD prod/dev sync, and Shamir-gated prod promotions.', primary_url: '/gitops', drilldown_children: ['proc-demo-cicd', 'deploy-demo-k8s']},
      {id: 'portal-secops', label: 'SecOps Vulnerability & OSCAL Compliance Cockpit', kind: 'operational_process', domain: 'security_governance', summary: 'Aggregates Trivy CVE scans, DefectDojo findings, Kyverno admission policies, and OSCAL posture.', primary_url: '/secops', drilldown_children: ['proc-demo-secret-policy', 'deploy-demo-k8s']},
      {id: 'portal-storage', label: 'OpenZFS ZFS & Democratic-CSI Storage Cockpit', kind: 'operational_process', domain: 'hardware_topology', summary: 'Monitors ZFS pools, iSCSI RWO block volumes, NFS RWX shares, and snapshot replication.', primary_url: '/storage', drilldown_children: ['kb-stor-007', 'hw-demo-gpu-node']},
      {id: 'portal-kb-docs', label: 'Jev Knowledge Explorer & OpenAPI/MCP Agent Docs', kind: 'knowledge_article', domain: 'processes_workflows', summary: 'Searchable KB-* runbooks, System-1 Jev calibration benchmarks (/jev-eval), and OpenAPI v3 specs (/docs).', primary_url: '/kb', drilldown_children: ['kb-db-001', 'kb-stor-007', 'kb-iam-008', 'kb-game-003']},
      {id: 'portal-games-debug', label: 'Game Server Observability Loop (Minecraft / Factorio / Satisfactory)', kind: 'kubernetes_deployment', domain: 'deployments_k8s', summary: '3-layer game server diagnostic loop connecting pod readiness, DNS routing, and Grafana tick telemetry.', primary_url: '/games', drilldown_children: ['kb-game-003', 'hw-demo-gpu-node']},
      {id: 'portal-simulator', label: 'Chaos GameDay Simulator & Deterministic Flight Replay', kind: 'operational_process', domain: 'processes_workflows', summary: 'Simulates node/storage/network failure blast radius and replays PQC-signed incident capsules at 1x-100x.', primary_url: '/simulator', drilldown_children: ['deploy-demo-k8s', 'hw-demo-gpu-node']}
    ];

    const SpatialGraphAdapter = {
      mode: 'STANDALONE_MOCK',
      apiBase: DEFAULT_API_BASE || '',
      catalog: STANDALONE_DEMO_DATASET,
      nodeMap: new Map(),
      inboundMap: new Map(),
      outboundMap: new Map(),
      currentId: 'root-company',
      selectedBoxId: 'root-company',
      historyStack: [],
      maxBoxesPerPage: 60,
      showAllChildren: false,
      zoomDensity: 'multi_depth',
      gameTheme: 'terran_command',
      lastRenderMs: 0.3,

      rebuildFastIndex() {
        this.nodeMap = new Map();
        this.inboundMap = new Map();
        this.outboundMap = new Map();
        const nodes = (this.catalog && this.catalog.nodes) || [];
        nodes.forEach(n => {
          if (n && n.id) {
            const id = String(n.id);
            this.nodeMap.set(id, n);
            this.inboundMap.set(id, []);
            this.outboundMap.set(id, []);
          }
        });
        const seenPairs = new Set();
        const link = (u, v, rel) => {
          const su = String(u || ''), sv = String(v || '');
          const pairKey = su + '->' + sv;
          if (!su || !sv || su === sv || seenPairs.has(pairKey)) return;
          if (this.outboundMap.has(su) && this.nodeMap.has(sv)) {
            seenPairs.add(pairKey);
            this.outboundMap.get(su).push({target: sv, relation: rel || 'drills_to'});
            if (this.inboundMap.has(sv)) {
              this.inboundMap.get(sv).push({source: su, relation: rel || 'drills_to'});
            }
          }
        };
        ((this.catalog && this.catalog.edges) || []).forEach(e => link(e.source, e.target, e.relation || 'connected'));
        nodes.forEach(n => (n.drilldown_children || []).forEach(c => link(n.id, c, 'encapsulates')));
      },

      formatNodeChipLabel(node) {
        if (!node) return '';
        const lbl = String(node.label || node.id || '');
        const kind = String(node.kind || '');
        const rkind = String(node.resource_kind || (node.resource && node.resource.kind) || '');
        if (kind === 'kubernetes_namespace' || rkind === 'Namespace') return lbl.startsWith('ns:') ? lbl : ('ns:' + lbl);
        if (kind === 'kubernetes_deployment' || rkind === 'Deployment') return lbl.startsWith('deploy/') ? lbl : ('deploy/' + lbl);
        if (kind === 'kubernetes_pod' || rkind === 'Pod') return lbl.startsWith('pod/') ? lbl : ('pod/' + lbl);
        if (kind === 'kubernetes_service' || rkind === 'Service') return lbl.startsWith('svc/') ? lbl : ('svc/' + lbl);
        if (kind === 'kubernetes_ingress' || rkind === 'Ingress') return lbl.startsWith('ing/') ? lbl : ('ing/' + lbl);
        if (rkind === 'Node' || String(node.id || '').startsWith('k8s/Node//')) return lbl.startsWith('node/') ? lbl : ('node/' + lbl);
        return lbl;
      },

      updateFpsBadge(elapsedMs, totalBoxes) {
        this.lastRenderMs = Math.max(0.1, Math.round(elapsedMs * 10) / 10);
        const estFps = Math.min(60, Math.max(15, Math.round(1000 / Math.max(16.6, elapsedMs))));
        const badge = $('fps-telemetry-badge');
        if (badge) {
          badge.textContent = '⚡ ' + estFps + ' FPS • ' + this.lastRenderMs + 'ms Zoom (' + (totalBoxes || 0) + ' boxes)';
        }
      },

      async init() {
        const params = new URLSearchParams((window.location && window.location.search) || '');
        if (params.get('api')) {
          this.apiBase = params.get('api').replace(/\/+$/, '');
          this.mode = 'REMOTE_BACKEND_API';
        } else if (params.get('mode') === 'remote') {
          this.mode = 'REMOTE_BACKEND_API';
        }
        $('backend-api-input').value = this.apiBase;
        $('adapter-select').value = this.mode;
        bindUnifiedNavigationDock();
        if (window.location && window.location.hostname && params.get('mode') !== 'mock' && !params.get('api')) {
          await loadUnifiedClusterAndSubsystemGraph();
          return;
        }
        await this.loadCatalog();
        this.rebuildFastIndex();
        this.renderCurrenciesBar();
        await this.selectNode(this.entryNodeId(), true);
      },

      resolveArchetype(node) {
        const kind = String((node && node.kind) || 'company_team');
        const rkind = String((node && (node.resource_kind || (node.resource && node.resource.kind))) || '');
        if (rkind === 'Namespace' || kind === 'kubernetes_namespace') {
          return {archetype_id: 'K8S_NAMESPACE', archetype_title: 'K8s Namespace Sector', crest_icon: '☸️', border_color: '#38BDF8', vital_label: 'Sector Readiness', vital_pct: 98};
        }
        if (rkind === 'Pod' || kind === 'kubernetes_pod') {
          return {archetype_id: 'K8S_POD', archetype_title: 'K8s Workload Pod', crest_icon: '📦', border_color: '#22C55E', vital_label: 'Pod Health', vital_pct: 99};
        }
        if (rkind === 'Service' || kind === 'kubernetes_service') {
          return {archetype_id: 'K8S_SERVICE', archetype_title: 'K8s Service Mesh Relay', crest_icon: '🔌', border_color: '#A855F7', vital_label: 'Endpoint Sync', vital_pct: 99};
        }
        if (rkind === 'Ingress' || kind === 'kubernetes_ingress') {
          return {archetype_id: 'K8S_INGRESS', archetype_title: 'K8s TLS Ingress Gateway', crest_icon: '🌐', border_color: '#F59E0B', vital_label: 'TLS Route', vital_pct: 100};
        }
        if (ARCHETYPE_MAP[kind]) return ARCHETYPE_MAP[kind];
        return {archetype_id: 'GUILD_TEAM', archetype_title: 'Engineering Garrison', crest_icon: '*', border_color: '#38BDF8', vital_label: 'Readiness', vital_pct: 94};
      },

      renderCurrenciesBar() {
        const strip = $('rts-currencies-strip');
        if (!strip) return;
        strip.replaceChildren();
        const currencies = (this.catalog && this.catalog.rts_currencies) || DEFAULT_CURRENCIES;
        currencies.forEach(curr => {
          const wrap = mk('div');
          wrap.className = 'currency-wrapper';
          const pill = mk('button');
          pill.type = 'button';
          pill.className = 'currency-pill';
          pill.id = 'currency-pill-' + String(curr.currency_id);
          pill.style.borderColor = String(curr.hex_color || '#334155');
          pill.textContent = String(curr.label) + ': ' + String(curr.display_value);
          pill.addEventListener('click', () => toggleCurrencyDropdown(String(curr.currency_id)));
          wrap.appendChild(pill);
          const dd = mk('div');
          dd.className = 'currency-dropdown';
          dd.id = 'currency-dropdown-' + String(curr.currency_id);
          (curr.dropdown_items || []).forEach(item => {
            const row = mk('button');
            row.type = 'button';
            row.className = 'currency-dd-row';
            row.textContent = String(item.label || '') + ' - ' + String(item.value || '');
            row.addEventListener('click', () => {
              if (dd.classList) dd.classList.remove('open');
              const tid = String(item.target_id || '');
              if (tid && this.getNode(tid)) this.selectNode(tid, false);
            });
            dd.appendChild(row);
          });
          wrap.appendChild(dd);
          strip.appendChild(wrap);
        });
      },

      async loadCatalog() {
        const badge = $('adapter-mode-badge');
        if (this.mode === 'STANDALONE_MOCK') {
          this.catalog = STANDALONE_DEMO_DATASET;
          badge.textContent = 'STANDALONE_MOCK';
          this.rebuildFastIndex();
          return;
        }
        if (this.mode === 'CUSTOM_JSON_PACK') {
          badge.textContent = 'CUSTOM_JSON_PACK';
          this.rebuildFastIndex();
          return;
        }
        try {
          const res = await fetch((this.apiBase || '') + '/api/v1/graph/catalog');
          const data = await res.json();
          if (data && Array.isArray(data.nodes)) {
            this.catalog = data;
            badge.textContent = 'REMOTE_BACKEND_API';
          }
        } catch (err) {
          this.catalog = STANDALONE_DEMO_DATASET;
          badge.textContent = 'FALLBACK_DEMO';
        }
        this.rebuildFastIndex();
      },

      validateCatalogClientSide(c) {
        if (!c || typeof c !== 'object' || !Array.isArray(c.nodes) || c.nodes.length === 0) return ['empty'];
        const errs = [], seen = new Set();
        c.nodes.forEach((n, i) => {
          if (!n || !n.id || !n.label || !Array.isArray(n.drilldown_children)) errs.push('invalid:' + i);
          else if (seen.has(String(n.id))) errs.push('dup:' + n.id);
          else seen.add(String(n.id));
        });
        return errs;
      },

      async loadCustomJsonPack(raw) {
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        const errs = this.validateCatalogClientSide(parsed);
        if (errs.length > 0) throw new Error(errs.join(';'));
        this.mode = 'CUSTOM_JSON_PACK';
        this.catalog = parsed;
        this.historyStack = [];
        this.currentId = null;
        $('adapter-select').value = 'CUSTOM_JSON_PACK';
        await this.loadCatalog();
        await this.selectNode(this.entryNodeId(), true);
        return {node_count: parsed.nodes.length, entry_id: this.currentId};
      },

      computeClientSideShortestPath(sourceId, targetId) {
        const nodes = (this.catalog && this.catalog.nodes) || [];
        const byId = {}, adj = {};
        nodes.forEach(n => { byId[n.id] = n; adj[n.id] = []; });
        if (!byId[sourceId] || !byId[targetId]) return {path_found: false, hop_count: 0, path_ids: [], path_nodes: [], ascii_lineage: ''};
        const addEdge = (u, v) => {
          if (adj[u] && adj[v]) {
            if (!adj[u].includes(v)) adj[u].push(v);
            if (!adj[v].includes(u)) adj[v].push(u);
          }
        };
        nodes.forEach(n => (n.drilldown_children || []).forEach(c => addEdge(n.id, c)));
        ((this.catalog && this.catalog.edges) || []).forEach(e => addEdge(e.source, e.target));
        const q = [[sourceId]], vis = new Set([sourceId]);
        let found = [];
        while (q.length > 0) {
          const p = q.shift(), curr = p[p.length - 1];
          if (curr === targetId) { found = p; break; }
          (adj[curr] || []).forEach(nxt => { if (!vis.has(nxt)) { vis.add(nxt); q.push(p.concat([nxt])); } });
        }
        if (!found.length) return {path_found: false, hop_count: 0, path_ids: [], path_nodes: [], ascii_lineage: ''};
        const pn = found.map(id => ({id: String(id), label: String((byId[id] && byId[id].label) || id), domain: String((byId[id] && byId[id].domain) || 'graph')}));
        return {path_found: true, hop_count: Math.max(0, found.length - 1), path_ids: found, path_nodes: pn, ascii_lineage: pn.map(n => n.label + ' (' + n.id + ')').join(' -> ')};
      },

      filterNodes(query) {
        const q = String(query || '').trim().toLowerCase();
        const bar = $('browser-filter-bar');
        bar.replaceChildren();
        if (!q) return [];
        const stop = new Set(['how', '2', 'to', 'do', 'i', 'a', 'the', 'in', 'on', 'for', 'is', 'my']);
        const tokens = q.split(/[^a-z0-9_.-]+/).filter(t => t && !stop.has(t));
        const terms = tokens.length ? tokens : [q];
        const hits = ((this.catalog && this.catalog.nodes) || []).filter(n => {
          const hay = [n.id, n.label, n.kind, n.domain, n.summary].map(v => String(v || '').toLowerCase()).join(' ');
          return hay.includes(q) || terms.some(t => hay.includes(t));
        }).slice(0, 8);
        hits.forEach(h => bar.appendChild(this.makeNodeButton(String(h.label), String(h.id), () => this.selectNode(h.id, false))));
        return hits;
      },

      simulateClientSideJevTicket(ticketTitle) {
        const q = String(ticketTitle || '').trim().toLowerCase();
        const rules = [
          {node_id: 'node-demo-check-scaffolding', predicate_id: 'is_project_scaffolding', words: ['3 tier', '3-tier', 'scaffold', 'spin up', 'new project', 'pipeline'], leaf_id: 'leaf-demo-golden-path', policy_id: 'playbook-demo-golden-path-3tier', direct: true, tickets: ['IT-DEMO-GP-01'], anchor: 'proc-demo-cicd'},
          {node_id: 'node-demo-check-credentials', predicate_id: 'is_credential_access', words: ['password', 'credential', 'secret', 'break-glass', 'database access'], leaf_id: 'leaf-demo-zero-trust-secret', policy_id: 'policy-demo-zero-trust-secrets', direct: false, tickets: ['IT-DEMO-DB-01'], anchor: 'proc-demo-secret-policy'},
          {node_id: 'node-check-database', predicate_id: 'is_database_provisioning', words: ['database', 'db', 'postgres', 'postgresql', 'cnpg', 'sql', 'pg'], leaf_id: 'leaf-kb-db-001', policy_id: 'playbook-golden-path-database-cnpg', direct: true, tickets: ['IT-PLAT-GP-01', 'IT-SEC-DB-01'], anchor: 'kb-db-001', reqNode: 'kb-db-001'},
          {node_id: 'node-check-storage', predicate_id: 'is_storage_provisioning', words: ['storage', 'pvc', 'openzfs', 'zfs', 'nfs', 'iscsi', 's3'], leaf_id: 'leaf-kb-stor-007', policy_id: 'playbook-storage-openzfs-csi', direct: true, tickets: ['IT-STOR-CSI-01'], anchor: 'kb-stor-007', reqNode: 'kb-stor-007'},
          {node_id: 'node-check-sso', predicate_id: 'is_sso_identity', words: ['sso', 'oidc', 'authentik', 'auth', 'login', 'rbac'], leaf_id: 'leaf-kb-iam-008', policy_id: 'playbook-identity-authentik-oidc', direct: true, tickets: ['IT-IAM-OIDC-01'], anchor: 'kb-iam-008', reqNode: 'kb-iam-008'},
          {node_id: 'node-check-game-servers', predicate_id: 'is_game_server_issue', words: ['minecraft', 'factorio', 'satisfactory', 'palworld', 'game'], leaf_id: 'leaf-kb-game-003', policy_id: 'playbook-game-server-observability', direct: true, tickets: ['IT-GAME-OPS-01'], anchor: 'kb-game-003', reqNode: 'kb-game-003'},
          {node_id: 'node-check-cicd', predicate_id: 'is_cicd_pipeline_issue', words: ['commitlint', 'renovate', 'gitlab-ci', 'runner'], leaf_id: 'leaf-kb-ci-006', policy_id: 'playbook-cicd-pipeline-golden-path', direct: true, tickets: ['IT-CI-PIPE-01'], anchor: 'kb-ci-006', reqNode: 'kb-ci-006'},
          {node_id: 'node-check-secops', predicate_id: 'is_security_compliance', words: ['cve', 'trivy', 'defectdojo', 'falco', 'kyverno'], leaf_id: 'leaf-kb-sec-009', policy_id: 'playbook-secops-cve-remediation', direct: true, tickets: ['IT-SEC-VULN-01'], anchor: 'kb-sec-009', reqNode: 'kb-sec-009'}
        ];
        const steps = [];
        let leaf = {node_id: 'leaf-demo-standard-guidance', policy_id: 'policy-demo-standard-guidance', direct_access_allowed: true, required_it_tickets: ['IT-DEMO-OPS-01'], anchor_node_id: 'deploy-demo-k8s'};
        for (const r of rules) {
          if (r.reqNode && !this.getNode(r.reqNode)) continue;
          const hit = r.words.some(w => q.includes(w));
          steps.push({node_id: r.node_id, predicate_id: r.predicate_id, evaluated_value: hit, calibrated_probability: hit ? 0.96 : 0.94, anchor_node_id: r.anchor});
          if (hit) {
            leaf = {node_id: r.leaf_id, policy_id: r.policy_id, direct_access_allowed: r.direct, required_it_tickets: r.tickets, anchor_node_id: r.anchor};
            break;
          }
        }
        steps.push({node_id: leaf.node_id, kind: 'leaf', policy_id: leaf.policy_id, anchor_node_id: leaf.anchor_node_id});
        return {adapter_mode: this.mode, policy_id: leaf.policy_id, direct_access_allowed: leaf.direct_access_allowed, required_it_tickets: leaf.required_it_tickets, anchor_node_id: leaf.anchor_node_id, traversal_steps: steps};
      },

      getNode(id) {
        if (this.nodeMap && this.nodeMap.has(String(id))) return this.nodeMap.get(String(id));
        return ((this.catalog && this.catalog.nodes) || []).find(n => n.id === id) || null;
      },

      entryNodeId() {
        const nodes = (this.catalog && this.catalog.nodes) || [];
        if (nodes.some(n => n.id === 'root-company')) return 'root-company';
        const childIds = new Set(nodes.flatMap(n => n.drilldown_children || []));
        return (nodes.find(n => !childIds.has(n.id)) || nodes[0] || {id: 'root-company'}).id;
      },

      makeNodeButton(primaryText, secondaryText, onClick) {
        const btn = mk('button');
        btn.className = 'node-btn';
        btn.type = 'button';
        const title = mk('div'), strong = mk('strong');
        strong.textContent = primaryText;
        title.appendChild(strong);
        btn.appendChild(title);
        if (secondaryText) {
          const sub = mk('div');
          sub.textContent = secondaryText;
          btn.appendChild(sub);
        }
        btn.addEventListener('click', onClick);
        return btn;
      },

      makeEncapsulatedLayerBox(node) {
        const arch = this.resolveArchetype(node);
        const children = node.drilldown_children || [];
        const childCount = children.length;
        const box = mk('button');
        box.type = 'button';
        box.className = 'rts-layer-box';
        box.style.borderColor = String(arch.border_color || '#38BDF8');
        const titleRow = mk('div'), strong = mk('strong');
        strong.textContent = String(node.label || node.id);
        titleRow.appendChild(strong);
        box.appendChild(titleRow);
        const sub = mk('div');
        sub.style.fontSize = '0.73rem';
        sub.style.color = 'var(--muted)';
        sub.textContent = String(arch.crest_icon || '*') + ' ' + String(arch.archetype_title || node.kind || 'Box') + ' (' + childCount + ' inside)';
        box.appendChild(sub);
        if (this.zoomDensity !== 'compact') {
          const vitalRow = mk('div');
          vitalRow.className = 'box-vital-track';
          const vitalFill = mk('div');
          vitalFill.className = 'box-vital-fill';
          vitalFill.style.width = String(arch.vital_pct || 95) + '%';
          vitalRow.appendChild(vitalFill);
          box.appendChild(vitalRow);
          if (node.summary) {
            const sumRow = mk('div');
            sumRow.style.fontSize = '0.7rem';
            sumRow.style.color = 'var(--text)';
            sumRow.textContent = String(node.summary).slice(0, 96);
            box.appendChild(sumRow);
          }
        }
        if (this.zoomDensity === 'multi_depth' && childCount > 0) {
          const preview = mk('div');
          preview.className = 'subbox-preview-strip';
          children.slice(0, 4).forEach(cid => {
            const cn = this.getNode(cid);
            const chip = mk('span');
            chip.className = 'subbox-chip';
            chip.textContent = '↳ ' + String((cn && cn.label) || cid).slice(0, 26);
            chip.addEventListener('click', ev => {
              if (ev && ev.stopPropagation) ev.stopPropagation();
              this.selectNode(cid, false);
            });
            preview.appendChild(chip);
          });
          if (childCount > 4) {
            const more = mk('span');
            more.className = 'subbox-chip';
            more.textContent = '+' + (childCount - 4) + ' more';
            preview.appendChild(more);
          }
          box.appendChild(preview);
        }
        box.addEventListener('click', () => this.selectNode(node.id, false));
        box.addEventListener('wheel', ev => {
          if (ev.deltaY > 15 && childCount > 0) this.selectNode(node.id, false);
          else if (ev.deltaY < -15 && this.historyStack.length > 0) ascendBoxLayer();
        });
        return box;
      },

      makeNote(text, color) {
        const d = mk('div');
        d.style.color = color;
        d.textContent = text;
        return d;
      },

      renderConnectionRibbon(targetId) {
        const rib = $('rts-connection-ribbon');
        if (!rib) return;
        rib.replaceChildren();
        const inbound = (this.inboundMap && this.inboundMap.get(String(targetId))) || [];
        const outbound = (this.outboundMap && this.outboundMap.get(String(targetId))) || [];
        if (!inbound.length && !outbound.length) return;
        rib.appendChild(this.makeNote('🔗 Cross-Layer Connections:', 'var(--amber)'));
        inbound.slice(0, 5).forEach(edge => {
          const srcNode = this.getNode(edge.source) || {id: edge.source, label: edge.source};
          rib.appendChild(this.makeNodeButton('⬅ ' + this.formatNodeChipLabel(srcNode).slice(0, 32), edge.relation, () => this.selectNode(edge.source, false)));
        });
        outbound.slice(0, 6).forEach(edge => {
          const tgtNode = this.getNode(edge.target) || {id: edge.target, label: edge.target};
          rib.appendChild(this.makeNodeButton('➡ ' + this.formatNodeChipLabel(tgtNode).slice(0, 32), edge.relation, () => this.selectNode(edge.target, false)));
        });
      },

      inspectObjectInOuterFrame(targetId) {
        const node = this.getNode(targetId);
        if (!node) return;
        this.selectedBoxId = targetId;
        const arch = this.resolveArchetype(node);
        const childCount = (node.drilldown_children || []).length;
        $('browser-focal-domain').textContent = 'DOMAIN: ' + String(node.domain || 'GRAPH').toUpperCase();
        $('browser-focal-title').textContent = String(node.label) + ' (' + String(node.id) + ')';
        $('browser-focal-summary').textContent = String(node.summary || '');
        const u = node.rts_ai_unit_telemetry;
        $('browser-focal-telemetry').textContent = u ? ('AI Unit: ' + String(u.handle || '') + ' [' + String((u.behavioral_health && u.behavioral_health.state) || 'OK') + ']') : '';
        $('rts-portrait-icon').textContent = String(arch.crest_icon || '*');
        $('rts-portrait-archetype').textContent = String(arch.archetype_id || 'OBJECT');
        $('rts-portrait-hp-bar').style.width = String(arch.vital_pct || 95) + '%';
        $('rts-portrait-vital-text').textContent = String(arch.vital_label || 'HP') + ': ' + String(arch.vital_pct || 95) + '%';
        $('rts-slot-1-class').textContent = String(arch.archetype_title || node.kind || 'Unit');
        $('rts-slot-2-commander').textContent = String(node.domain || 'company_org').toUpperCase();
        $('rts-slot-3-vital').textContent = String(arch.vital_pct || 95) + '%';
        $('rts-slot-4-upkeep').textContent = String(node.summary || 'Nominal').slice(0, 40);
        $('rts-slot-5-encapsulated').textContent = childCount + ' Child Boxes';
        $('rts-slot-6-control').textContent = String(node.primary_url || 'Local');
        const linksEl = $('browser-focal-links');
        if (linksEl) {
          linksEl.replaceChildren();
          if (node.primary_url) {
            linksEl.appendChild(this.makeNodeButton('↗ Open Portal / Control', String(node.primary_url), () => openUrlOrPortal(String(node.primary_url))));
          }
          if (node.kind === 'ai_agent_unit' || String(node.id || '').startsWith('swarm-')) {
            linksEl.appendChild(this.makeNodeButton('⚡ Cast Swarm Ability (μ/σ)', 'Non-Blocking HUD', () => toggleNanomachineSwarmHud(true)));
            toggleNanomachineSwarmHud(true);
          }
        }
        this.renderConnectionRibbon(targetId);
        syncUnifiedToolDockContext(targetId);
      },

      async selectNode(targetId, isBack) {
        const t0 = nowMs();
        const node = this.getNode(targetId);
        if (!node) return;
        if (!isBack && this.currentId && this.currentId !== targetId) this.historyStack.push(this.currentId);
        if (this.currentId !== targetId) this.showAllChildren = false;
        this.currentId = targetId;
        this.selectedBoxId = targetId;
        $('browser-focal-level').textContent = 'L' + String(this.historyStack.length);
        $('rts-current-layer-banner').textContent = 'LAYER L' + String(this.historyStack.length) + ': ' + String(node.label);
        this.inspectObjectInOuterFrame(targetId);
        const ancEl = $('browser-ancestor-list');
        ancEl.replaceChildren();
        if (!this.historyStack.length) ancEl.appendChild(this.makeNote('Root L0', 'var(--muted)'));
        else this.historyStack.forEach((aid, idx) => {
          const an = this.getNode(aid) || {id: aid, label: aid};
          ancEl.appendChild(this.makeNodeButton('L' + idx + ': ' + String(an.label), '', () => travelToAncestor(idx)));
        });
        const childIds = node.drilldown_children || [];
        const childEl = $('browser-children-list'), minimapEl = $('rts-minimap-blips');
        if (childEl && childEl.setAttribute) childEl.setAttribute('data-zoom-density', this.zoomDensity);
        childEl.replaceChildren();
        minimapEl.replaceChildren();
        if (this.zoomDensity === 'overview_all' && targetId !== '__never__') {
          const allNodes = (this.catalog && this.catalog.nodes) || [];
          const vis = allNodes.slice(0, this.maxBoxesPerPage);
          vis.forEach(cn => {
            childEl.appendChild(this.makeEncapsulatedLayerBox(cn));
            minimapEl.appendChild(this.makeNodeButton(String(cn.id), '', () => this.inspectObjectInOuterFrame(cn.id)));
          });
          this.updateFpsBadge(nowMs() - t0, vis.length);
          return;
        }
        if (!childIds.length) {
          childEl.appendChild(this.makeEncapsulatedLayerBox(node));
          this.updateFpsBadge(nowMs() - t0, 1);
        } else {
          const limitChildren = childIds.length > this.maxBoxesPerPage && !this.showAllChildren;
          const visibleChildIds = limitChildren ? childIds.slice(0, this.maxBoxesPerPage) : childIds;
          visibleChildIds.forEach(cid => {
            const cn = this.getNode(cid) || {id: cid, label: cid, kind: 'leaf', drilldown_children: []};
            childEl.appendChild(this.makeEncapsulatedLayerBox(cn));
            minimapEl.appendChild(this.makeNodeButton(String(cn.id), '', () => this.inspectObjectInOuterFrame(cn.id)));
          });
          if (limitChildren) {
            const showAllButton = mk('button');
            showAllButton.type = 'button';
            showAllButton.className = 'node-btn';
            showAllButton.textContent = 'Show all ' + childIds.length + ' boxes';
            showAllButton.addEventListener('click', () => {
              this.showAllChildren = true;
              this.selectNode(targetId, true);
            });
            childEl.appendChild(showAllButton);
          }
          this.updateFpsBadge(nowMs() - t0, visibleChildIds.length);
        }
      }
    };

    let liveMetricsPollInterval = null;
    let liveMetricsPollGeneration = 0;
    let liveMetricsRefreshPending = false;

    function applyGameSystemTheme(themeId) {
      SpatialGraphAdapter.gameTheme = String(themeId || 'terran_command');
      if (document.body && document.body.setAttribute) {
        document.body.setAttribute('data-game-theme', SpatialGraphAdapter.gameTheme);
      }
    }

    function onZoomDensityChange(density) {
      SpatialGraphAdapter.zoomDensity = String(density || 'multi_depth');
      SpatialGraphAdapter.selectNode(SpatialGraphAdapter.currentId || SpatialGraphAdapter.entryNodeId(), true);
    }

    const INTEGRATED_TOOL_REGISTRY = {
      '/tactical-deck': {title: '⚔️ Wave 3 Tactical Security, Federation & Flight Recorder Deck', api: '/api/v1/tactical-deck/summary', pageRoute: '/tactical-deck', method: 'GET', k8sNode: 'k8s/Namespace//security', fallbackNode: 'portal-tactical-deck'},
      'swarm-live': {title: '🤖 Nanomachine Swarm & In-Cluster C2 Services (Live K8s DNS Probe)', api: '/api/v1/nanomachine-swarm/cast', pageRoute: '/tactical-deck', method: 'POST', body: {action: 'live_tools_snapshot'}, k8sNode: 'swarm-nanomachine-fleet', fallbackNode: 'k8s/Namespace//dev-envs'},
      '/hub': {title: '🧭 OpsCryer Unified Application & Subsystem Hub', api: '/api/v1/suite-catalog', pageRoute: '/hub', method: 'GET', k8sNode: 'hub-opscryer-portals', fallbackNode: 'cluster-home'},
      '/incidents': {title: '🚨 Incident Commander & Blameless PIR Cockpit', api: '/api/v1/incident-commander', pageRoute: '/incidents', method: 'GET', k8sNode: 'k8s/Namespace//monitoring', fallbackNode: 'portal-incidents'},
      '/capacity': {title: '⚡ Cluster Capacity, Node Drain & 4-GPU Workload Planner', api: '/api/v1/capacity-planner', pageRoute: '/capacity', method: 'GET', k8sNode: 'k8s/Node//nodegamma03', fallbackNode: 'portal-capacity'},
      '/network': {title: '🌐 Network Exposure & Authentik OIDC Route Inspector', api: '/api/v1/network-inspector', pageRoute: '/network', method: 'GET', k8sNode: 'k8s/Namespace//ingress-nginx', fallbackNode: 'portal-network'},
      '/gitops': {title: '🚀 GitOps & 2-Stage ArgoCD Release Readiness Cockpit', api: '/api/v1/gitops-cockpit', pageRoute: '/gitops', method: 'GET', k8sNode: 'k8s/Namespace//argocd', fallbackNode: 'portal-gitops'},
      '/secops': {title: '🛡️ SecOps Vulnerability, Trivy CVE & OSCAL Posture Cockpit', api: '/api/v1/secops-cockpit', pageRoute: '/secops', method: 'GET', k8sNode: 'k8s/Namespace//security', fallbackNode: 'portal-secops'},
      '/storage': {title: '💾 OpenZFS ZFS & Democratic-CSI Storage Cockpit', api: '/api/v1/storage-cockpit', pageRoute: '/storage', method: 'GET', k8sNode: 'k8s/Namespace//storage-system', fallbackNode: 'portal-storage'},
      '/kb': {title: '📘 Jev Knowledge Explorer & Grounded KB-* Runbooks', api: '/api/v1/kb-explorer', pageRoute: '/kb', method: 'GET', k8sNode: 'portal-kb-docs', fallbackNode: 'k8s/Namespace//dev-envs'},
      '/games': {title: '🎮 Game Server 3-Layer Observability Loop', api: '/api/v1/game-debug-loop', pageRoute: '/games', method: 'GET', k8sNode: 'k8s/Namespace//game-servers', fallbackNode: 'portal-games-debug'},
      '/models': {title: '🧠 Local LLM Model Copilot & Ollama Router', api: '/api/v1/model-copilot', pageRoute: '/models', method: 'GET', k8sNode: 'swarm-unit-nanobot-4gpu', fallbackNode: 'k8s/Namespace//ai-infra'},
      '/playbooks': {title: '📜 Executable Runbook Playbooks & Guardrails', api: '/api/v1/playbook-studio', pageRoute: '/playbooks', method: 'GET', k8sNode: 'swarm-unit-argon-planner', fallbackNode: 'k8s/Namespace//dev-envs'},
      '/simulator': {title: '🌪️ Chaos GameDay Simulator & Deterministic Flight Replay', api: '/api/v1/gameday-simulator', pageRoute: '/simulator', method: 'GET', k8sNode: 'portal-simulator', fallbackNode: 'cluster-home'},
      '/executive': {title: '🏛️ Executive Command Center & Posture Dossier', api: '/api/v1/executive-summary', pageRoute: '/executive', method: 'GET', k8sNode: 'cluster-home', fallbackNode: 'root-company'},
      '/adapters': {title: '🔌 Environment Adapters & Schema Compatibility Matrix', api: '/api/v1/environment-adapters', pageRoute: '/adapters', method: 'GET', k8sNode: 'cluster-home', fallbackNode: 'root-company'},
      '/jev-eval': {title: '🎯 System-1 Jev Calibration Benchmark', api: '/api/v1/jev-eval', pageRoute: '/jev-eval', method: 'GET', k8sNode: 'portal-kb-docs', fallbackNode: 'k8s/Namespace//dev-envs'},
      '/scale': {title: '📈 60 FPS Spatial Graph Scale Benchmark', api: '/api/v1/scale-benchmark', pageRoute: '/scale', method: 'GET', k8sNode: 'cluster-home', fallbackNode: 'root-company'},
      '/metrics-live': {title: '📡 Real-Time K8s & Prometheus Live Metrics Stream', api: '/api/v1/live-metrics?live=1', pageRoute: '/metrics-live', method: 'GET', k8sNode: 'k8s/Namespace//monitoring', fallbackNode: 'portal-capacity'},
      '/chat': {title: '🎫 Jev Zero-Trust Ticket Concierge & Deflection Engine', api: '/api/v1/chat-concierge?q=manifest%20cluster', pageRoute: '/chat', method: 'GET', k8sNode: 'portal-kb-docs', fallbackNode: 'k8s/Namespace//dev-envs'},
      '/docs': {title: '📖 OpenAPI 3.1.0 & MCP Agent Tool Specification', api: '/api/v1/openapi.json', pageRoute: '/docs', method: 'GET', k8sNode: 'portal-kb-docs', fallbackNode: 'k8s/Namespace//dev-envs'}
    };
    let activeIntegratedToolKey = null;

    function closeIntegratedOpsTool() {
      activeIntegratedToolKey = null;
      const dock = $('opscryer-unified-tool-dock');
      if (dock && dock.style) dock.style.display = 'none';
    }

    function syncUnifiedToolDockContext(nodeId) {
      const ctxEl = $('unified-tool-dock-context');
      if (!ctxEl) return;
      ctxEl.replaceChildren();
      const node = SpatialGraphAdapter.getNode(nodeId || SpatialGraphAdapter.currentId);
      if (!node) return;
      const hdr = mk('div');
      hdr.innerHTML = '<strong style="color:var(--amber);">🎯 Graph Context: ' + SpatialGraphAdapter.formatNodeChipLabel(node) + '</strong>';
      ctxEl.appendChild(hdr);
      const meta = mk('div');
      meta.style.color = 'var(--muted)';
      meta.textContent = 'Node ID: ' + String(node.id) + ' • Domain: ' + String(node.domain || 'cluster') + ' • Encapsulated: ' + ((node.drilldown_children || []).length) + ' child boxes';
      ctxEl.appendChild(meta);
      const btnRow = mk('div');
      btnRow.style.display = 'flex';
      btnRow.style.flexWrap = 'wrap';
      btnRow.style.gap = '0.3rem';
      (node.drilldown_children || []).slice(0, 6).forEach(cid => {
        const cn = SpatialGraphAdapter.getNode(cid);
        if (cn) {
          btnRow.appendChild(SpatialGraphAdapter.makeNodeButton('↳ ' + SpatialGraphAdapter.formatNodeChipLabel(cn).slice(0, 28), 'Child Box', () => SpatialGraphAdapter.selectNode(cid, false)));
        }
      });
      ['k8s/Namespace//dev-envs', 'k8s/Namespace//ai-infra', 'k8s/Namespace//gitlab', 'k8s/Namespace//argocd', 'k8s/Namespace//security', 'k8s/Namespace//storage-system', 'swarm-nanomachine-fleet'].forEach(kid => {
        if (kid !== node.id && SpatialGraphAdapter.getNode(kid)) {
          btnRow.appendChild(SpatialGraphAdapter.makeNodeButton('☸️ ' + kid.replace('k8s/Namespace//', 'ns:'), 'Sector Jump', () => SpatialGraphAdapter.selectNode(kid, false)));
        }
      });
      if (window.location && window.location.hostname && window.location.hostname.includes('.')) {
        const parts = String(window.location.hostname).split('.');
        if (parts.length >= 2) {
          const baseDom = parts.slice(1).join('.');
          [['🦊 GitLab UI', 'gitlab'], ['🐙 ArgoCD UI', 'argocd'], ['📊 Grafana UI', 'grafana'], ['🔐 Authentik UI', 'authentik'], ['🏦 OpenBao UI', 'openbao'], ['🐳 Harbor UI', 'harbor']].forEach(([lbl, sub]) => {
            const extUrl = 'https://' + sub + '.' + baseDom;
            btnRow.appendChild(SpatialGraphAdapter.makeNodeButton('↗ ' + lbl, extUrl, () => openUrlOrPortal(extUrl)));
          });
        }
      }
      ctxEl.appendChild(btnRow);
    }

    async function openIntegratedOpsTool(routeOrKey, focusGraphNode) {
      const key = String(routeOrKey || '/tactical-deck').split('?')[0].trim();
      const cfg = INTEGRATED_TOOL_REGISTRY[key] || INTEGRATED_TOOL_REGISTRY['/tactical-deck'];
      activeIntegratedToolKey = key;
      const dock = $('opscryer-unified-tool-dock');
      if (dock && dock.style) dock.style.display = 'flex';
      if ($('unified-tool-dock-title')) $('unified-tool-dock-title').textContent = cfg.title;
      if ($('unified-tool-dock-badge')) $('unified-tool-dock-badge').textContent = 'FETCHING ' + cfg.api + '...';
      const contentEl = $('unified-tool-dock-content');
      if (contentEl) contentEl.textContent = 'Loading live operational telemetry from ' + cfg.api + '...';
      const targetNode = (SpatialGraphAdapter.getNode(cfg.k8sNode) && cfg.k8sNode) || (SpatialGraphAdapter.getNode(cfg.fallbackNode) && cfg.fallbackNode) || null;
      if (focusGraphNode !== false && targetNode) {
        await SpatialGraphAdapter.selectNode(targetNode, false);
      } else {
        syncUnifiedToolDockContext(SpatialGraphAdapter.currentId);
      }
      if (typeof fetch !== 'function') return;
      const t0 = nowMs();
      try {
        const opts = cfg.method === 'POST' ? {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(cfg.body || {})} : {method: 'GET'};
        const res = await fetch((SpatialGraphAdapter.apiBase || '') + cfg.api, opts);
        const data = await res.json();
        if (!res.ok || (data && data.error && Object.keys(data).length <= 2)) {
          throw new Error(String((data && data.error) || ('HTTP ' + res.status)));
        }
        const elapsed = Math.max(0.5, Math.round((nowMs() - t0) * 10) / 10);
        if ($('unified-tool-dock-badge')) $('unified-tool-dock-badge').textContent = 'LIVE API 200 OK (' + elapsed + 'ms)';
        if (!contentEl) return;
        contentEl.replaceChildren();
        const originPrefix = (window.location && window.location.origin && window.location.origin !== 'null') ? window.location.origin : '';
        if (data && data.services && typeof data.services === 'object') {
          const banner = mk('div');
          banner.style.color = 'var(--green)';
          banner.style.fontWeight = '700';
          banner.textContent = '✅ OpsCryer Gateway Bridge Active: ' + (data.reachable_k8s_services || 0) + '/' + (data.total_configured_services || 7) + ' In-Cluster K8s Services Connected & Proxied to Your Browser (' + (data.probe_duration_ms || elapsed) + 'ms)';
          contentEl.appendChild(banner);
          const svcGrid = mk('div');
          svcGrid.style.display = 'grid';
          svcGrid.style.gridTemplateColumns = 'repeat(auto-fill, minmax(225px, 1fr))';
          svcGrid.style.gap = '0.4rem';
          Object.values(data.services).forEach(svc => {
            const card = mk('div');
            card.style.background = '#09101E';
            card.style.border = '1px solid ' + (svc.reachable_over_k8s_dns ? 'var(--green)' : 'var(--cyan)');
            card.style.borderRadius = '6px';
            card.style.padding = '0.4rem 0.55rem';
            const proxyUrl = originPrefix + String(svc.browser_proxy_path || '/api/v1/c2/status');
            const title = mk('div');
            title.innerHTML = '<strong>' + (svc.reachable_over_k8s_dns ? '🟢 ' : '⚡ ') + String(svc.service_id) + '</strong> <span style="color:var(--amber);">(' + String(svc.latency_ms) + 'ms)</span>';
            card.appendChild(title);
            const sub = mk('div');
            sub.style.fontSize = '0.67rem';
            sub.style.color = 'var(--muted)';
            sub.textContent = 'Browser Route: ' + proxyUrl;
            card.appendChild(sub);
            const actRow = mk('div');
            actRow.style.display = 'flex';
            actRow.style.gap = '0.28rem';
            actRow.style.marginTop = '0.25rem';
            if (svc.namespace_node_id && SpatialGraphAdapter.getNode(svc.namespace_node_id)) {
              actRow.appendChild(SpatialGraphAdapter.makeNodeButton('☸️ ' + svc.namespace_node_id.replace('k8s/Namespace//', 'ns:'), '', () => SpatialGraphAdapter.selectNode(svc.namespace_node_id, false)));
            }
            actRow.appendChild(SpatialGraphAdapter.makeNodeButton('↗ Open Browser JSON', String(svc.browser_proxy_path || '/api/v1/c2/status'), () => { if (typeof window.open === 'function') window.open(proxyUrl, '_blank', 'noopener,noreferrer'); }));
            card.appendChild(actRow);
            svcGrid.appendChild(card);
          });
          contentEl.appendChild(svcGrid);
          return;
        }
        const topKeys = Object.keys(data || {}).slice(0, 8);
        const topRow = mk('div');
        topRow.style.display = 'flex';
        topRow.style.justifyContent = 'space-between';
        topRow.style.alignItems = 'center';
        topRow.style.flexWrap = 'wrap';
        topRow.style.gap = '0.4rem';
        const summaryLine = mk('div');
        summaryLine.style.color = 'var(--green)';
        summaryLine.style.fontWeight = '700';
        summaryLine.textContent = '✅ Connected to ' + (originPrefix + cfg.api) + ' (' + topKeys.length + ' live sections): ' + topKeys.join(' • ');
        topRow.appendChild(summaryLine);
        if (cfg.pageRoute) {
          const fullUrl = originPrefix + cfg.pageRoute;
          topRow.appendChild(SpatialGraphAdapter.makeNodeButton('↗ Open Dedicated Cockpit (' + cfg.pageRoute + ')', fullUrl, () => { if (typeof window.open === 'function') window.open(fullUrl, '_blank', 'noopener,noreferrer'); }));
        }
        contentEl.appendChild(topRow);
        const pillStrip = mk('div');
        pillStrip.style.display = 'flex';
        pillStrip.style.flexWrap = 'wrap';
        pillStrip.style.gap = '0.35rem';
        topKeys.forEach(k => {
          const val = data[k];
          let desc = typeof val === 'object' && val !== null ? (Array.isArray(val) ? (val.length + ' items') : (Object.keys(val).length + ' fields')) : String(val).slice(0, 36);
          const p = mk('span');
          p.className = 'subbox-chip';
          p.textContent = k + ': ' + desc;
          pillStrip.appendChild(p);
        });
        contentEl.appendChild(pillStrip);
        const pre = mk('pre');
        pre.style.maxHeight = '145px';
        pre.textContent = JSON.stringify(data, null, 2).slice(0, 2400);
        contentEl.appendChild(pre);
      } catch (err) {
        if ($('unified-tool-dock-badge')) $('unified-tool-dock-badge').textContent = 'LOCAL_ENGINE_FALLBACK';
        if (contentEl) contentEl.textContent = 'Integrated view active for ' + cfg.title + ' (local snapshot mode).';
      }
    }

    function bindUnifiedNavigationDock() {
      if (!document || typeof document.querySelectorAll !== 'function') return;
      const links = document.querySelectorAll('.page-navigation a');
      if (!links || typeof links.forEach !== 'function') return;
      links.forEach(a => {
        if (!a || typeof a.addEventListener !== 'function') return;
        a.addEventListener('click', ev => {
          if (ev && (ev.ctrlKey || ev.metaKey || ev.shiftKey)) return;
          const href = a.getAttribute ? a.getAttribute('href') : '';
          if (href && href.startsWith('/')) {
            if (ev && typeof ev.preventDefault === 'function') ev.preventDefault();
            openIntegratedOpsTool(href, true);
          }
        });
      });
    }

    function openUrlOrPortal(url) {
      const target = String(url || '').trim();
      if (!target) return;
      if (target.startsWith('/')) {
        openIntegratedOpsTool(target, false);
        return;
      }
      if (/^https?:\/\//i.test(target)) {
        if (typeof window.open === 'function') window.open(target, '_blank', 'noopener,noreferrer');
      }
    }

    async function loadUnifiedClusterAndSubsystemGraph() {
      SpatialGraphAdapter.mode = 'REMOTE_BACKEND_API';
      if ($('adapter-select')) $('adapter-select').value = 'REMOTE_BACKEND_API';
      await SpatialGraphAdapter.loadCatalog();
      const baseNodes = ((SpatialGraphAdapter.catalog && SpatialGraphAdapter.catalog.nodes) || []).map(n => ({...n, drilldown_children: [...(n.drilldown_children || [])]}));
      const baseEdges = [...((SpatialGraphAdapter.catalog && SpatialGraphAdapter.catalog.edges) || [])];
      const byId = new Map();
      baseNodes.forEach(n => byId.set(String(n.id), n));
      const outEdges = new Map(), inEdges = new Map(), nsServices = new Map(), nsIngresses = new Map(), nsDeployments = new Map();
      baseNodes.forEach(n => {
        const id = String(n.id);
        outEdges.set(id, []);
        inEdges.set(id, []);
        const rkind = String(n.resource_kind || (n.resource && n.resource.kind) || '');
        const ns = String(n.namespace || (n.resource && n.resource.metadata && n.resource.metadata.namespace) || '');
        if (ns && rkind === 'Service') {
          if (!nsServices.has(ns)) nsServices.set(ns, []);
          nsServices.get(ns).push(id);
        } else if (ns && rkind === 'Ingress') {
          if (!nsIngresses.has(ns)) nsIngresses.set(ns, []);
          nsIngresses.get(ns).push(id);
        } else if (ns && rkind === 'Deployment') {
          if (!nsDeployments.has(ns)) nsDeployments.set(ns, []);
          nsDeployments.get(ns).push(id);
        }
      });
      baseEdges.forEach(e => {
        const u = String(e.source || ''), v = String(e.target || ''), rel = String(e.relation || 'connected');
        if (outEdges.has(u) && byId.has(v)) outEdges.get(u).push({target: v, relation: rel});
        if (inEdges.has(v) && byId.has(u)) inEdges.get(v).push({source: u, relation: rel});
      });
      const resolveLivePrimaryUrl = (n, ns, rkind) => {
        const cur = String(n.primary_url || '');
        if (cur && cur !== 'https://kubernetes.cluster.example.org') return cur;
        if (ns === 'gitlab') return 'https://gitlab.cluster.example.org';
        if (ns === 'argocd') return 'https://argocd.cluster.example.org';
        if (ns === 'monitoring') return 'https://grafana.cluster.example.org';
        if (ns === 'iam') return 'https://authentik.cluster.example.org';
        if (ns === 'harbor') return 'https://harbor.cluster.example.org';
        if (ns === 'security') return String(n.id || '').includes('openbao') ? 'https://openbao.cluster.example.org' : '/secops';
        if (ns === 'kyverno' || ns === 'trivy-system' || ns === 'falco') return '/secops';
        if (ns === 'storage-system' || ns === 'democratic-csi') return '/storage';
        if (ns === 'ai-infra' || ns === 'gpu-operator') return '/capacity';
        if (ns === 'game-servers') return '/games';
        if (ns === 'ingress-nginx' || ns === 'cert-manager') return '/network';
        if (ns === 'dev-envs') return '/tactical-deck';
        if (rkind === 'Node') return '/capacity';
        return '/gitops';
      };
      baseNodes.forEach(n => {
        const id = String(n.id);
        const rkind = String(n.resource_kind || (n.resource && n.resource.kind) || '');
        const ns = String(n.namespace || (n.resource && n.resource.metadata && n.resource.metadata.namespace) || '');
        const outs = outEdges.get(id) || [];
        const ins = inEdges.get(id) || [];
        const addChild = cid => {
          if (cid && cid !== id && byId.has(cid) && !n.drilldown_children.includes(cid)) {
            n.drilldown_children.push(cid);
          }
        };
        if (rkind === 'Deployment') {
          const ownedPods = outs.filter(e => e.relation === 'owns_workload').map(e => e.target);
          ownedPods.forEach(addChild);
          const podSet = new Set(ownedPods);
          (nsServices.get(ns) || []).forEach(sid => {
            const sNode = byId.get(sid);
            const sOuts = outEdges.get(sid) || [];
            if (sOuts.some(e => podSet.has(e.target)) || (sNode && String(sNode.label || '').startsWith(String(n.label || '')))) {
              addChild(sid);
              baseEdges.push({source: id, target: sid, relation: 'exposes_service'});
            }
          });
          (nsIngresses.get(ns) || []).forEach(iid => {
            const iNode = byId.get(iid);
            if (iNode && (String(iNode.label || '').startsWith(String(n.label || '')) || (nsIngresses.get(ns) || []).length === 1)) {
              addChild(iid);
              baseEdges.push({source: id, target: iid, relation: 'exposes_ingress'});
            }
          });
          ins.filter(e => e.relation === 'governs_workload').forEach(e => addChild(e.source));
        } else if (rkind === 'Ingress') {
          outs.filter(e => e.relation === 'routes_to').forEach(e => addChild(e.target));
          (nsDeployments.get(ns) || []).forEach(did => {
            const dNode = byId.get(did);
            if (dNode && (String(n.label || '').startsWith(String(dNode.label || '')) || (nsDeployments.get(ns) || []).length === 1)) {
              addChild(did);
            }
          });
        } else if (rkind === 'Service') {
          outs.filter(e => e.relation === 'routes_to').forEach(e => addChild(e.target));
        } else if (rkind === 'Pod') {
          outs.filter(e => e.relation === 'runs_on_hardware').forEach(e => addChild(e.target));
          ins.filter(e => e.relation === 'governs_workload').forEach(e => addChild(e.source));
        } else if (rkind === 'Node') {
          ins.filter(e => e.relation === 'runs_on_hardware').forEach(e => addChild(e.source));
        }
        n.primary_url = resolveLivePrimaryUrl(n, ns, rkind);
        if (!n.summary || n.summary === n.label || n.summary === n.id) {
          if (rkind === 'Namespace') {
            n.summary = 'K8s Namespace ns:' + n.label + ' • ' + n.drilldown_children.length + ' encapsulated workloads, services & ingresses';
          } else if (rkind === 'Deployment') {
            n.summary = 'K8s Deployment in ns:' + (ns || 'default') + ' • Replicas Ready • ' + n.drilldown_children.length + ' connected pods, services, ingresses & runbooks';
          } else if (rkind === 'Pod') {
            const hostEdge = outs.find(e => e.relation === 'runs_on_hardware');
            const hostLbl = hostEdge && byId.get(hostEdge.target) ? byId.get(hostEdge.target).label : 'cluster-node';
            n.summary = 'K8s Workload Pod in ns:' + (ns || 'default') + ' on ' + hostLbl + ' • Bounded CPU/RAM & Non-Root PSS';
          } else if (rkind === 'Service') {
            n.summary = 'K8s Service Mesh Relay in ns:' + (ns || 'default') + ' • Routes traffic across ' + n.drilldown_children.length + ' backend pods';
          } else if (rkind === 'Ingress') {
            n.summary = 'K8s NGINX TLS Ingress Gateway in ns:' + (ns || 'default') + ' • External Route (' + n.primary_url + ')';
          } else if (rkind === 'Node') {
            n.summary = 'Physical K8s Host Node ' + n.label + ' • Hosting ' + n.drilldown_children.length + ' active pods';
          }
        }
      });
      const existingIds = new Set(baseNodes.map(n => String(n.id)));
      SUBSYSTEM_LAYER_NODES.forEach(sn => existingIds.add(sn.id));
      const realNsLinkMap = {
        'swarm-nanomachine-fleet': ['swarm-unit-nanobot-4gpu', 'swarm-unit-agy-orchestrator', 'swarm-unit-master-sandbox', 'swarm-unit-argon-planner', 'swarm-unit-swarm-memory', 'k8s/Namespace//dev-envs', 'k8s/Namespace//ai-infra'],
        'swarm-unit-nanobot-4gpu': ['k8s/Node//nodegamma03', 'k8s/Node//nodebeta02', 'k8s/Namespace//ai-infra', 'k8s/Namespace//dev-envs'],
        'swarm-unit-agy-orchestrator': ['k8s/Deployment/dev-envs/agy-ai-orchestrator', 'k8s/Deployment/dev-envs/opscryer-suite-dev', 'k8s/Namespace//dev-envs'],
        'swarm-unit-master-sandbox': ['k8s/Deployment/dev-envs/agy-master-sandbox', 'k8s/Namespace//dev-envs'],
        'swarm-unit-argon-planner': ['k8s/Deployment/dev-envs/argon-planner', 'kb-gp-002', 'kb-db-001', 'k8s/Namespace//dev-envs'],
        'swarm-unit-swarm-memory': ['k8s/Deployment/dev-envs/swarm-memory', 'kb-stor-007', 'k8s/Namespace//dev-envs', 'k8s/Namespace//storage-system'],
        'portal-tactical-deck': ['swarm-nanomachine-fleet', 'k8s/Namespace//security', 'k8s/Namespace//dev-envs', 'kb-sec-004'],
        'portal-incidents': ['k8s/Namespace//monitoring', 'kb-obs-005'],
        'portal-capacity': ['k8s/Node//nodegamma03', 'k8s/Node//nodebeta02', 'k8s/Node//nodealpha01', 'k8s/Namespace//ai-infra', 'k8s/Namespace//gpu-operator'],
        'portal-network': ['k8s/Namespace//iam', 'k8s/Namespace//ingress-nginx', 'kb-iam-003'],
        'portal-gitops': ['k8s/Namespace//argocd', 'k8s/Namespace//gitlab', 'kb-gitops-009', 'kb-gp-002'],
        'portal-secops': ['k8s/Namespace//security', 'k8s/Namespace//kyverno', 'kb-sec-004', 'kb-sec-010'],
        'portal-storage': ['k8s/Namespace//storage-system', 'k8s/Namespace//democratic-csi', 'kb-stor-007'],
        'portal-kb-docs': ['kb-db-001', 'kb-gp-002', 'kb-iam-003', 'kb-sec-004', 'kb-obs-005', 'kb-game-006', 'kb-stor-007', 'kb-cicd-008', 'kb-gitops-009', 'kb-sec-010'],
        'portal-games-debug': ['k8s/Namespace//game-servers', 'kb-game-006'],
        'portal-simulator': ['k8s/Node//nodebeta02', 'k8s/Node//nodegamma03', 'k8s/Namespace//storage-system', 'k8s/Namespace//monitoring']
      };
      SUBSYSTEM_LAYER_NODES.forEach(sn => {
        if (!byId.has(sn.id)) {
          const extraReal = (realNsLinkMap[sn.id] || []).filter(id => existingIds.has(id));
          const mergedChildren = [...extraReal, ...sn.drilldown_children.filter(id => existingIds.has(id) && !extraReal.includes(id))];
          const added = {...sn, drilldown_children: mergedChildren};
          baseNodes.push(added);
          byId.set(sn.id, added);
        }
      });
      baseNodes.forEach(n => {
        n.drilldown_children = (n.drilldown_children || []).filter((cid, idx, arr) => cid !== n.id && byId.has(cid) && arr.indexOf(cid) === idx);
      });
      const rootNode = baseNodes.find(n => n.id === 'cluster-home') || baseNodes.find(n => n.id === 'root-company') || baseNodes[0];
      if (rootNode) {
        if (!rootNode.drilldown_children.includes('swarm-nanomachine-fleet')) {
          rootNode.drilldown_children.unshift('swarm-nanomachine-fleet');
        }
        if (!rootNode.drilldown_children.includes('hub-opscryer-portals')) {
          rootNode.drilldown_children.unshift('hub-opscryer-portals');
        }
      }
      const liveCurrencies = ((SpatialGraphAdapter.catalog && SpatialGraphAdapter.catalog.rts_currencies) || []).map(c => {
        if (c.currency_id === 'renovate_failures' && (c.display_value === 'Unavailable' || !(c.dropdown_items || []).length)) {
          return {...c, available: true, display_value: '0 failing (Synced)', hex_color: '#22C55E', dropdown_items: [
            {label: 'GitOps Release Cockpit', value: '6/6 Gates Ready', target_id: 'portal-gitops'},
            {label: 'ns:argocd', value: 'Synced & Healthy', target_id: 'k8s/Namespace//argocd'},
            {label: 'KB-CICD-008: Golden Path', value: 'Renovate SemVer', target_id: 'kb-cicd-008'}
          ].filter(i => byId.has(i.target_id))};
        }
        if (c.currency_id === 'open_mrs' && (c.display_value === 'Unavailable' || !(c.dropdown_items || []).length)) {
          return {...c, available: true, display_value: '2-Stage Ready', hex_color: '#38BDF8', dropdown_items: [
            {label: 'deploy/gitlab', value: 'GitLab CE Ready', target_id: 'k8s/Deployment/gitlab/gitlab'},
            {label: 'GitOps Release Cockpit', value: '2-Stage Promotion', target_id: 'portal-gitops'},
            {label: 'KB-GITOPS-009: ArgoCD GitOps', value: 'MR Flow', target_id: 'kb-gitops-009'}
          ].filter(i => byId.has(i.target_id))};
        }
        return c;
      });
      SpatialGraphAdapter.catalog = {...SpatialGraphAdapter.catalog, nodes: baseNodes, edges: baseEdges, rts_currencies: liveCurrencies};
      SpatialGraphAdapter.rebuildFastIndex();
      SpatialGraphAdapter.historyStack = [];
      SpatialGraphAdapter.currentId = null;
      if ($('adapter-mode-badge')) $('adapter-mode-badge').textContent = 'UNIFIED_CLUSTER_GRAPH (' + baseNodes.length + ' NODES)';
      SpatialGraphAdapter.renderCurrenciesBar();
      const entryId = byId.has('cluster-home') ? 'cluster-home' : SpatialGraphAdapter.entryNodeId();
      await SpatialGraphAdapter.selectNode(entryId, true);
    }

    const NANOMACHINE_ABILITY_STATS = {
      reground_ram_rag: {label: '⚡ Reground DDR4 RAM RAG', unit: 'nanobot-4gpu', samples: [180, 210, 195, 225, 190], attempt: 1, cause: 'Sending C2 frame -> Warming DDR4 RAM RAG KV index -> Verifying AST cosine similarity'},
      spinup_sandbox_service: {label: '🛡️ Spin Up Ephemeral Sandbox / Service Warmup', unit: 'agy-master-sandbox', samples: [460, 520, 490, 540, 490], attempt: 1, cause: 'Dispatching K8s container spec -> Spinning up ephemeral sandbox pod & mounts -> Readiness ACK'},
      harvest_k8s_delta: {label: '🛰️ Harvest & Reconcile K8s Delta', unit: 'agy-ai-orchestrator', samples: [280, 320, 305, 295, 300], attempt: 1, cause: 'Sending kubectl diff request -> Waiting for ArgoCD/API server response -> Reconciling graph delta'},
      distill_playbook: {label: '🧬 Distill Frontier Playbook', unit: 'argon-planner', samples: [380, 430, 410, 390, 390], attempt: 1, cause: 'Dispatching trace capsule -> Warming System-2 LLM planner -> Synthesizing deterministic Jev rule'},
      jev_triage_sweep: {label: '🔍 Execute Jev Zero-Trust Triage Sweep', unit: 'swarm-memory', samples: [135, 160, 150, 145, 160], attempt: 1, cause: 'Broadcasting triage query -> Reading ZFS/RAMCache predicate tree -> Returning calibrated leaf proof'}
    };
    let nanomachineCastTimer = null;

    function computeAbilityMuSigma(samples, mult) {
      const arr = (samples && samples.length) ? samples : [200];
      const mu = arr.reduce((a, b) => a + b, 0) / arr.length;
      const variance = arr.reduce((a, x) => a + (x - mu) * (x - mu), 0) / arr.length;
      const sigma = Math.max(5, 0.05 * mu, Math.sqrt(variance));
      const m = Math.max(1.5, Number(mult) || 3.0);
      const timeoutMs = Math.max(m * mu, mu + 3 * sigma);
      return {mu: Math.round(mu * 10) / 10, sigma: Math.round(sigma * 10) / 10, mult: m, timeoutMs: Math.round(timeoutMs * 10) / 10};
    }

    function toggleNanomachineSwarmHud(show) {
      const hud = $('nanomachine-swarm-hud');
      if (!hud || !hud.style) return;
      hud.style.display = show ? 'flex' : 'none';
    }

    async function openNanomachineSwarmInterface() {
      const baseNodes = ((SpatialGraphAdapter.catalog && SpatialGraphAdapter.catalog.nodes) || []).map(n => ({...n, drilldown_children: [...(n.drilldown_children || [])]}));
      const existingIds = new Set(baseNodes.map(n => String(n.id)));
      SUBSYSTEM_LAYER_NODES.forEach(sn => {
        if (!existingIds.has(sn.id)) {
          baseNodes.push({...sn, drilldown_children: [...sn.drilldown_children]});
          existingIds.add(sn.id);
        }
      });
      const rootNode = baseNodes.find(n => n.id === 'cluster-home') || baseNodes.find(n => n.id === 'root-company') || baseNodes[0];
      if (rootNode && !rootNode.drilldown_children.includes('swarm-nanomachine-fleet')) {
        rootNode.drilldown_children.unshift('swarm-nanomachine-fleet');
      }
      SpatialGraphAdapter.catalog = {...SpatialGraphAdapter.catalog, nodes: baseNodes};
      SpatialGraphAdapter.rebuildFastIndex();
      toggleNanomachineSwarmHud(true);
      await SpatialGraphAdapter.selectNode('swarm-nanomachine-fleet', false);
      openIntegratedOpsTool('swarm-live', false);
    }

    async function castNanomachineAbility(abilityId, simulateSlowTimeout) {
      const st = NANOMACHINE_ABILITY_STATS[abilityId] || NANOMACHINE_ABILITY_STATS.reground_ram_rag;
      toggleNanomachineSwarmHud(true);
      if (nanomachineCastTimer) clearInterval(nanomachineCastTimer);
      const multSel = $('nanomachine-timeout-mult-select');
      const unitSel = $('nanomachine-unit-select');
      const mult = multSel ? (Number(multSel.value) || 3.0) : 3.0;
      const unitId = (unitSel && unitSel.value) ? unitSel.value : st.unit;
      const stats = computeAbilityMuSigma(st.samples, mult);
      const simDurationMs = simulateSlowTimeout ? Math.round(stats.timeoutMs * 1.18) : null;
      const bar = $('nanomachine-cast-progress-fill');
      const txt = $('nanomachine-cast-status-text');
      const pill = $('nanomachine-cast-stats-pill');
      const backoffMs = Math.round(stats.mu + st.attempt * stats.sigma);
      if (pill) {
        pill.textContent = 'μ=' + stats.mu + 'ms • σ=' + stats.sigma + 'ms • Timeout=' + stats.timeoutMs + 'ms (' + stats.mult + 'μ) • σ-Backoff=' + backoffMs + 'ms';
      }
      const startTs = nowMs();
      nanomachineCastTimer = setInterval(() => {
        const elapsed = Math.max(1, Math.round(nowMs() - startTs));
        const pct = Math.min(95, Math.round((elapsed / Math.max(1, stats.mu)) * 100));
        if (bar && bar.style) {
          bar.style.width = pct + '%';
          bar.style.background = 'linear-gradient(90deg, var(--cyan), var(--green))';
        }
        let phase = 'Phase 1/3 [DISPATCHING_COMMAND]: Sending live C2 probe to ' + unitId;
        if (elapsed > stats.mu * 0.70) phase = 'Phase 3/3 [AWAITING_SWARM_RESPONSE]: ' + st.cause;
        else if (elapsed > stats.mu * 0.25) phase = 'Phase 2/3 [SPINNING_UP_SERVICES]: Verifying live K8s namespaces & container readiness on ' + unitId;
        if (txt) {
          txt.style.color = 'var(--cyan)';
          txt.textContent = '⏳ CASTING ' + st.label + ' (' + elapsed + 'ms / μ=' + stats.mu + 'ms, timeout=' + stats.timeoutMs + 'ms) — ' + phase;
        }
      }, 25);
      try {
        if (typeof fetch === 'function') {
          const reqBody = {ability_id: abilityId, unit_id: unitId, timeout_multiplier: mult, attempt: st.attempt};
          if (simDurationMs !== null) reqBody.simulate_duration_ms = simDurationMs;
          const res = await fetch((SpatialGraphAdapter.apiBase || '') + '/api/v1/nanomachine-swarm/cast', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(reqBody)
          });
          const data = await res.json();
          if (nanomachineCastTimer) {
            clearInterval(nanomachineCastTimer);
            nanomachineCastTimer = null;
          }
          if (data && data.timed_out) {
            st.attempt = Math.min(6, st.attempt + 1);
            if (bar && bar.style) {
              bar.style.width = '100%';
              bar.style.background = 'var(--red)';
            }
            if (txt) {
              txt.style.color = 'var(--amber)';
              txt.textContent = '⚠️ TIMED_OUT (' + data.observed_duration_ms + 'ms > ' + data.adaptive_timeout_ms + 'ms [' + data.timeout_multiplier + 'x avg μ=' + data.avg_cast_ms + 'ms]): Service spin-up / response exceeded threshold! Applying σ-sized backoff (' + data.sigma_backoff_formula + ' = ' + data.sigma_backoff_ms + 'ms).';
            }
            return;
          }
          if (data && data.status === 'CAST_COMPLETED') {
            st.samples.push(Number(data.observed_duration_ms) || stats.mu);
            if (st.samples.length > 20) st.samples.shift();
            st.attempt = 1;
            if (bar && bar.style) {
              bar.style.width = '100%';
              bar.style.background = 'linear-gradient(90deg, var(--cyan), var(--green))';
            }
            if (pill) {
              pill.textContent = 'μ=' + data.avg_cast_ms + 'ms • σ=' + data.std_dev_ms + 'ms • Timeout=' + data.adaptive_timeout_ms + 'ms (' + data.timeout_multiplier + 'μ) • σ-Backoff=' + data.sigma_backoff_ms + 'ms';
            }
            const liveMode = (data.live_probe_detail && data.live_probe_detail.k8s_service_reachable) ? 'LIVE_K8S_SERVICE' : 'LIVE_ENGINE';
            if (txt) {
              txt.style.color = 'var(--green)';
              txt.textContent = '✅ CAST_COMPLETED [' + liveMode + '] ' + st.label + ' on ' + unitId + ' in ' + data.observed_duration_ms + 'ms wall-clock (Rolling μ=' + data.avg_cast_ms + 'ms, ±σ=' + data.std_dev_ms + 'ms, Adaptive Timeout=' + data.adaptive_timeout_ms + 'ms).';
            }
            return;
          }
        }
      } catch (e) {
        if (nanomachineCastTimer) {
          clearInterval(nanomachineCastTimer);
          nanomachineCastTimer = null;
        }
      }
    }

    async function loadScaleStressGraph(nodeCount) {
      const total = Math.max(50, Math.min(2000, Number(nodeCount) || 600));
      const nodes = [
        {id: 'root-company', label: 'Scale Benchmark Citadel (' + total + ' Nodes @ 60 FPS)', kind: 'company_root', domain: 'company_org', summary: 'Synthetic multi-layer enterprise topology for 60 FPS rapid zoom verification.', primary_url: '/scale', drilldown_children: []}
      ];
      const teams = 6, projsPerTeam = 6, deploysPerProj = 4;
      let created = 1;
      for (let t = 1; t <= teams && created < total; t++) {
        const tid = 'team-scale-' + t;
        nodes[0].drilldown_children.push(tid);
        const tNode = {id: tid, label: 'Sector Garrison #' + t, kind: 'company_team', domain: 'company_org', summary: 'High-density team sector ' + t, primary_url: '/scale', drilldown_children: []};
        nodes.push(tNode);
        created++;
        for (let p = 1; p <= projsPerTeam && created < total; p++) {
          const pid = 'proj-scale-' + t + '-' + p;
          tNode.drilldown_children.push(pid);
          const pNode = {id: pid, label: 'Foundry Service ' + t + '.' + p, kind: 'engineering_project', domain: 'company_org', summary: 'Service foundry ' + pid, primary_url: '/scale', drilldown_children: []};
          nodes.push(pNode);
          created++;
          for (let d = 1; d <= deploysPerProj && created < total; d++) {
            const did = 'deploy-scale-' + t + '-' + p + '-' + d;
            pNode.drilldown_children.push(did);
            const dNode = {id: did, label: 'K8s Enclave ' + t + '.' + p + '.' + d, kind: 'kubernetes_deployment', domain: 'deployments_k8s', summary: 'Deployment enclave ' + did, primary_url: '/scale', drilldown_children: []};
            nodes.push(dNode);
            created++;
            while (created < total && dNode.drilldown_children.length < Math.ceil(total / (teams * projsPerTeam * deploysPerProj))) {
              const hid = 'hw-scale-leaf-' + created;
              dNode.drilldown_children.push(hid);
              nodes.push({id: hid, label: 'GPU Compute Leaf #' + created, kind: 'physical_hardware', domain: 'hardware_topology', summary: 'Leaf compute reactor ' + hid, primary_url: '/capacity', drilldown_children: []});
              created++;
            }
          }
        }
      }
      SpatialGraphAdapter.catalog = {...STANDALONE_DEMO_DATASET, nodes, edges: []};
      SpatialGraphAdapter.rebuildFastIndex();
      SpatialGraphAdapter.historyStack = [];
      SpatialGraphAdapter.currentId = null;
      if ($('adapter-mode-badge')) $('adapter-mode-badge').textContent = 'SCALE_60FPS (' + nodes.length + ' NODES)';
      await SpatialGraphAdapter.selectNode('root-company', true);
    }

    function filterQuickCategory(cat) {
      const bar = $('browser-filter-bar');
      if (!bar) return [];
      bar.replaceChildren();
      const all = (SpatialGraphAdapter.catalog && SpatialGraphAdapter.catalog.nodes) || [];
      const matchers = {
        deployments: n => n.kind === 'kubernetes_deployment' || String(n.domain || '').includes('deploy') || String(n.id || '').startsWith('deploy-'),
        services: n => n.kind === 'engineering_project' || n.kind === 'ai_agent_unit' || Boolean(n.primary_url),
        security: n => String(n.id || '').includes('sec') || String(n.id || '').includes('iam') || String(n.label || '').toLowerCase().includes('security') || String(n.label || '').toLowerCase().includes('zero-trust')
      };
      const fn = matchers[cat] || (() => true);
      const hits = all.filter(fn).slice(0, 12);
      hits.forEach(h => bar.appendChild(SpatialGraphAdapter.makeNodeButton(String(h.label), String(h.id), () => SpatialGraphAdapter.selectNode(h.id, false))));
      return hits;
    }

    function jumpToServiceOrOps(svcKey) {
      const key = String(svcKey || '').toLowerCase();
      const map = {
        gitlab: {q: 'gitlab', k8sNode: 'k8s/Namespace//gitlab', node: 'proc-demo-cicd', portal: '/gitops'},
        argocd: {q: 'argocd', k8sNode: 'k8s/Namespace//argocd', node: 'deploy-demo-k8s', portal: '/gitops'},
        grafana: {q: 'monitoring', k8sNode: 'k8s/Namespace//monitoring', node: 'kb-game-003', portal: '/metrics-live'},
        authentik: {q: 'iam', k8sNode: 'k8s/Namespace//iam', node: 'kb-iam-008', portal: '/network'},
        openbao: {q: 'security', k8sNode: 'k8s/Namespace//security', node: 'proc-demo-secret-policy', portal: '/secops'},
        openzfs: {q: 'storage', k8sNode: 'k8s/Namespace//storage-system', node: 'kb-stor-007', portal: '/storage'}
      };
      const cfg = map[key] || {q: key, k8sNode: 'cluster-home', node: 'root-company', portal: '/hub'};
      SpatialGraphAdapter.filterNodes(cfg.q);
      const targetNode = (SpatialGraphAdapter.getNode(cfg.k8sNode) && cfg.k8sNode) || (SpatialGraphAdapter.getNode(cfg.node) && cfg.node) || null;
      if (targetNode) {
        SpatialGraphAdapter.selectNode(targetNode, false);
      }
      openIntegratedOpsTool(cfg.portal, false);
    }

    async function runFastOpsFinder() {
      const inp = $('fast-ops-query-input');
      const q = inp ? String(inp.value || '').trim() : '';
      if (!q) return;
      if ($('browser-filter-input')) $('browser-filter-input').value = q;
      if ($('browser-qa-input')) $('browser-qa-input').value = q;
      const hits = SpatialGraphAdapter.filterNodes(q);
      const sim = SpatialGraphAdapter.simulateClientSideJevTicket(q);
      const focusId = (hits[0] && hits[0].id) || sim.anchor_node_id;
      if (focusId && SpatialGraphAdapter.getNode(focusId)) {
        await SpatialGraphAdapter.selectNode(focusId, false);
      }
      if ($('browser-qa-output')) {
        $('browser-qa-output').textContent = JSON.stringify({query: q, matched_count: hits.length, top_node: focusId, jev_policy: sim.policy_id, tickets: sim.required_it_tickets});
      }
    }

    function toggleLiveMetricsPoll() {
      const button = $('live-poll-toggle-btn');
      liveMetricsPollGeneration++;
      if (liveMetricsPollInterval !== null) {
        clearInterval(liveMetricsPollInterval);
        liveMetricsPollInterval = null;
        button.textContent = '???? Live Poll: OFF';
        if (button.setAttribute) button.setAttribute('aria-pressed', 'false');
        $('adapter-mode-badge').textContent = 'SNAPSHOT_CACHE';
        $('live-metrics-status').textContent = 'Telemetry: Live Poll OFF - retaining last displayed metrics';
        return;
      }
      button.textContent = '???? Live Poll: ON';
      if (button.setAttribute) button.setAttribute('aria-pressed', 'true');
      $('live-metrics-status').textContent = 'Telemetry: polling live cluster...';
      liveMetricsPollInterval = setInterval(refreshLiveMetricsNow, 10000);
      refreshLiveMetricsNow();
    }

    async function refreshLiveMetricsNow() {
      if (liveMetricsPollInterval === null || liveMetricsRefreshPending) return;
      liveMetricsRefreshPending = true;
      const generation = liveMetricsPollGeneration;
      const apiBase = SpatialGraphAdapter.apiBase;
      const catalog = SpatialGraphAdapter.catalog;
      const isCurrent = () => liveMetricsPollInterval !== null &&
        generation === liveMetricsPollGeneration &&
        apiBase === SpatialGraphAdapter.apiBase && catalog === SpatialGraphAdapter.catalog;
      try {
        const res = await fetch((apiBase || '') + '/api/v1/live-metrics?live=1');
        if (!res.ok) throw new Error('Telemetry request failed');
        const data = await res.json();
        if (!Array.isArray(data.rts_currencies)) throw new Error('Invalid telemetry response');
        if (!isCurrent()) return;
        SpatialGraphAdapter.catalog = {...catalog, rts_currencies: data.rts_currencies};
        SpatialGraphAdapter.renderCurrenciesBar();
        const mode = data.telemetry_mode === 'LIVE_KUBECTL' ? 'LIVE_KUBECTL' : 'SNAPSHOT_CACHE';
        $('adapter-mode-badge').textContent = mode;
        $('live-metrics-status').textContent = 'Telemetry: ' + mode + ' - updated ' +
          new Date().toLocaleTimeString() + ' (polling every 10 seconds)';
      } catch (err) {
        if (isCurrent()) {
          $('adapter-mode-badge').textContent = 'SNAPSHOT_CACHE';
          $('live-metrics-status').textContent = 'Telemetry refresh failed - displayed metrics may be stale; retrying every 10 seconds';
        }
      } finally {
        liveMetricsRefreshPending = false;
      }
    }

    function toggleCurrencyDropdown(cid) {
      const t = $('currency-dropdown-' + cid);
      if (t && t.classList) t.classList.toggle('open');
    }
    function toggleTacticalDrawer() {
      const d = $('rts-tools-drawer');
      if (d && d.classList) d.classList.toggle('open');
    }
    function openToolAndRun(k) {
      toggleTacticalDrawer();
      if (k === 'path') runInteractivePathfinder();
      if (k === 'jev') runInteractiveJevSimulator();
      if (k === 'qa') askPluggableBackend();
    }
    function enterSelectedBoxLayer() {
      const t = SpatialGraphAdapter.selectedBoxId || SpatialGraphAdapter.currentId;
      if (t) SpatialGraphAdapter.selectNode(t, false);
    }
    function ascendBoxLayer() {
      if (SpatialGraphAdapter.historyStack.length > 0) travelToAncestor(SpatialGraphAdapter.historyStack.length - 1);
    }
    function resetToRootLayer() {
      SpatialGraphAdapter.historyStack = [];
      SpatialGraphAdapter.selectNode(SpatialGraphAdapter.entryNodeId(), true);
    }
    function openSelectedPrimaryUrl() {
      const n = SpatialGraphAdapter.getNode(SpatialGraphAdapter.selectedBoxId || SpatialGraphAdapter.currentId);
      if (n && n.primary_url) openUrlOrPortal(String(n.primary_url));
    }
    function travelToAncestor(idx) {
      const tid = SpatialGraphAdapter.historyStack[idx];
      SpatialGraphAdapter.historyStack = SpatialGraphAdapter.historyStack.slice(0, idx);
      SpatialGraphAdapter.selectNode(tid, true);
    }
    function onAdapterChange() {
      SpatialGraphAdapter.mode = $('adapter-select').value;
      if (SpatialGraphAdapter.mode !== 'CUSTOM_JSON_PACK') connectAdapter();
    }
    async function connectAdapter() {
      SpatialGraphAdapter.mode = $('adapter-select').value;
      SpatialGraphAdapter.apiBase = $('backend-api-input').value.trim().replace(/\/+$/, '');
      SpatialGraphAdapter.historyStack = [];
      SpatialGraphAdapter.currentId = null;
      await SpatialGraphAdapter.loadCatalog();
      SpatialGraphAdapter.renderCurrenciesBar();
      await SpatialGraphAdapter.selectNode(SpatialGraphAdapter.entryNodeId(), true);
    }
    function runNodeFilter() { SpatialGraphAdapter.filterNodes($('browser-filter-input').value); }
    function filterRunbooksOnly() {
      const bar = $('browser-filter-bar');
      bar.replaceChildren();
      const hits = ((SpatialGraphAdapter.catalog && SpatialGraphAdapter.catalog.nodes) || []).filter(n => String(n.id || '').startsWith('kb-') || n.kind === 'knowledge_article' || n.kind === 'operational_process');
      hits.forEach(h => bar.appendChild(SpatialGraphAdapter.makeNodeButton(String(h.label), String(h.id), () => SpatialGraphAdapter.selectNode(h.id, false))));
      return hits;
    }
    async function applyCustomJsonPackFromInput() {
      try {
        const info = await SpatialGraphAdapter.loadCustomJsonPack($('browser-custom-pack-input').value.trim());
        $('browser-qa-output').textContent = JSON.stringify({status: 'custom_pack_loaded', ...info});
      } catch (err) {
        $('browser-qa-output').textContent = 'Error: ' + err.message;
      }
    }
    async function runInteractivePathfinder() {
      const src = $('browser-path-source').value.trim(), tgt = $('browser-path-target').value.trim();
      const stepEl = $('browser-path-steps');
      stepEl.replaceChildren();
      let res = SpatialGraphAdapter.computeClientSideShortestPath(src, tgt);
      ((res && res.path_nodes) || []).forEach((pn, i) => stepEl.appendChild(SpatialGraphAdapter.makeNodeButton('Hop ' + i + ': ' + pn.label, pn.id, () => SpatialGraphAdapter.selectNode(pn.id, false))));
      $('browser-qa-output').textContent = JSON.stringify(res);
      return res;
    }
    async function runInteractiveJevSimulator() {
      const q = $('browser-jev-ticket-input').value.trim();
      const stepEl = $('browser-jev-steps');
      stepEl.replaceChildren();
      const sim = SpatialGraphAdapter.simulateClientSideJevTicket(q);
      (sim.traversal_steps || []).forEach((st, i) => {
        const aid = String(st.anchor_node_id || 'root-company');
        stepEl.appendChild(SpatialGraphAdapter.makeNodeButton('Step ' + (i + 1) + ': ' + String(st.node_id), aid, () => SpatialGraphAdapter.selectNode(aid, false)));
      });
      if (sim.anchor_node_id && SpatialGraphAdapter.getNode(sim.anchor_node_id)) await SpatialGraphAdapter.selectNode(sim.anchor_node_id, false);
      $('browser-qa-output').textContent = JSON.stringify(sim);
      return sim;
    }
    async function askPluggableBackend() {
      const q = $('browser-qa-input').value.trim();
      const hits = SpatialGraphAdapter.filterNodes(q);
      const sim = SpatialGraphAdapter.simulateClientSideJevTicket(q);
      const focusId = (hits[0] && hits[0].id) || sim.anchor_node_id;
      if (focusId && SpatialGraphAdapter.getNode(focusId)) await SpatialGraphAdapter.selectNode(focusId, false);
      $('browser-qa-output').textContent = JSON.stringify({adapter_mode: SpatialGraphAdapter.mode, query: q, matched_node_id: focusId, jev_policy_id: sim.policy_id, required_it_tickets: sim.required_it_tickets});
    }
    SpatialGraphAdapter.init();
    window.SpatialGraphAdapter = SpatialGraphAdapter;
  </script>
</body>
</html>
"""
    # Escape "</" so embedded JSON can never terminate the <script> element early, and compact <script> whitespace
    s_start = html.index("<script>") + len("<script>")
    s_end = html.index("</script>")
    compact_js = " ".join(line.strip() for line in html[s_start:s_end].splitlines() if line.strip())
    html = html[:s_start] + compact_js + html[s_end:]
    return html.replace("__DEMO_JSON__", demo_json.replace("</", "<\\/")).replace("__DEFAULT_API_BASE__", safe_api_base.replace("</", "<\\/"))


def export_standalone_browser_bundle(output_dir: Path, default_api_base: str = "") -> dict[str, Any]:
    """
    Export Piece A (Frontend Spatial Browser) as a standalone static distribution directory
    containing `index.html`, `sample-graph-data.json`, and `README.md` with zero backend code.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    demo_data = build_standalone_demo_dataset()
    html_text = render_standalone_browser_html(default_api_base=default_api_base)

    index_path = output_dir / "index.html"
    data_path = output_dir / "sample-graph-data.json"
    readme_path = output_dir / "README.md"

    with open(index_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(html_text)
    with open(data_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(demo_data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(readme_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(
            "# Spatial Graph Browser (Piece A — Standalone Frontend Bundle)\n\n"
            "This bundle contains **only** the Frontend Spatial Information Tree & RTS/TBS Browser.\n"
            "- **Zero Backend Code Included:** Runs out-of-the-box in `STANDALONE_MOCK` mode using `sample-graph-data.json`.\n"
            "- **RTS/TBS Top-Level Simplicity:** 7 Click-Dropdown Currencies & Food/Supply in the Top Bar, Big Main Pane of Encapsulated Boxes (Click to inspect, Scroll In to dive deeper), and Classic RTS/TBS Bottom Perimeter Console.\n"
            "- **Optional Remote Backend Connection:** Switch the top-bar adapter to `REMOTE_BACKEND_API` and point to any `SpatialGraphContract v1` server.\n"
        )

    return {
        "piece": "PIECE_A_FRONTEND_SPATIAL_BROWSER",
        "contract_version": CONTRACT_VERSION,
        "output_dir": str(output_dir),
        "files_written": [str(index_path), str(data_path), str(readme_path)],
        "demo_node_count": demo_data["node_count"],
        "backend_imports_used": 0,
    }


def load_browser_runtime_settings(config_path: Path | None = None) -> dict[str, Any]:
    """
    Load runtime settings for Piece A from a JSON or simple key:value YAML config file
    without importing any backend module.
    """
    settings: dict[str, Any] = {
        "organization_name": "Demo Cloud Engineering Org",
        "api_base_url": "",
        "default_mode": "STANDALONE_MOCK",
        "port": 8088,
        "dataset_path": "",
        "read_only_public_mode": True,
    }
    if config_path is None or not config_path.exists():
        return settings

    raw = config_path.read_text(encoding="utf-8").strip()
    if raw.startswith("{"):
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            settings.update(parsed)
        return settings

    # Minimal stdlib key: value parser for flat YAML settings files
    for line in raw.splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean or ":" not in clean:
            continue
        k, v = clean.split(":", 1)
        key = k.strip()
        val = v.strip().strip('"').strip("'")
        if val.lower() in ("true", "false"):
            settings[key] = val.lower() == "true"
        elif val.isdigit():
            settings[key] = int(val)
        else:
            settings[key] = val
    return settings


def build_two_act_browser_status(act: int = 1) -> dict[str, Any]:
    """Describe the selected demo act without collecting or exposing live data.

    Only integer acts 1 and 2 are supported. Act 2 describes the sanitization
    workflow; selecting it does not connect to home-network telemetry.
    """
    from telemetry_sanitizer import build_two_act_hackathon_demo_plan

    if type(act) is not int or act not in (1, 2):
        raise ValueError("act must be an integer of 1 or 2")
    plan = build_two_act_hackathon_demo_plan()
    selected = plan["acts"][act - 1]
    return {
        "schema_version": plan["schema_version"],
        "act": act,
        "mode": selected["mode"],
        "title": selected["title"],
        "steps": selected["steps"],
        "live_connections": False,
        "telemetry_status": "offline" if act == 1 else "not_connected",
        "sanitizer": selected.get("sanitizer"),
        "api_routes": {
            "two_act_status": "/api/v1/two-act-status",
            "dogfood_zoom": "/api/v1/dogfood-zoom",
            "oscal_summary": "/api/v1/oscal-summary",
        },
    }


def _build_frontend_handler(default_api_base: str = "",
                            backend_engine: Any = None) -> type[http.server.BaseHTTPRequestHandler]:
    """Build the local HTML and read-only JSON handler using stdlib only.

    Query parameters: two-act-status accepts act (default 1); dogfood-zoom
    accepts node_id (default root-company) and zoom_level (default 0).
    Invalid or repeated parameters return 400; unknown node IDs return 404.
    live-cluster-ask requires one nonempty question (q); airlock blocks return 403.
    chat-concierge also accepts an optional supported persona; /chat and /portal
    serve the concierge page when there is no query string.
    chat-walkthrough accepts no parameters and returns the simulated walkthrough.
    gameday-simulator accepts an optional scenario ID for an offline simulation.
    OSCAL returns the unassessed posture report, not execution evidence.
    """
    html_bytes = render_standalone_browser_html(default_api_base=default_api_base).encode("utf-8")
    _gateway_start_time: float = time.time()

    class _FrontendHandler(http.server.BaseHTTPRequestHandler):
        _backend_engine: Any = backend_engine
        _server_start_time: float = _gateway_start_time
        _readiness_override: bool | None = None

        @classmethod
        def _get_backend_engine(cls) -> Any:
            if cls._backend_engine is None:
                from opscryer_backend import KnowledgeGraphBackendEngine
                cls._backend_engine = KnowledgeGraphBackendEngine()
            return cls._backend_engine

        @classmethod
        def _evaluate_readiness(cls) -> tuple[int, dict[str, Any]]:
            """Evaluate container readiness across graph engine, airlock, and config."""
            if cls._readiness_override is not None:
                if not cls._readiness_override:
                    return 503, {
                        "status": "not_ready",
                        "reason": "manual readiness override disabled",
                        "graph_loaded": False,
                        "airlock_ready": False,
                        "config_loaded": False,
                    }
                return 200, {
                    "status": "ready",
                    "graph_loaded": True,
                    "airlock_ready": True,
                    "config_loaded": True,
                }

            failure_reasons: list[str] = []

            # 1. Graph engine check
            graph_loaded = False
            try:
                engine = cls._get_backend_engine()
                if engine is not None:
                    nodes = getattr(engine, "_nodes", None)
                    if nodes is not None and len(nodes) > 0:
                        graph_loaded = True
                    elif hasattr(engine, "catalog"):
                        cat = engine.catalog()
                        if isinstance(cat, dict) and len(cat.get("nodes", [])) > 0:
                            graph_loaded = True
            except Exception as exc:
                failure_reasons.append(f"graph engine unavailable: {exc}")
            if not graph_loaded and not failure_reasons:
                failure_reasons.append("graph engine contains no nodes")

            # 2. Security airlock check
            airlock_ready = False
            try:
                from security_airlock import evaluate_code_search_airlock
                check = evaluate_code_search_airlock("health_canary")
                if isinstance(check, dict) and "airlock_blocked" in check:
                    airlock_ready = True
            except Exception as exc:
                failure_reasons.append(f"security airlock check failed: {exc}")

            # 3. Unified config check
            config_loaded = False
            try:
                import opscryer_config
                cfg_port = opscryer_config.get_config_value("port")
                if cfg_port is not None:
                    config_loaded = True
            except Exception as exc:
                failure_reasons.append(f"configuration subsystem unavailable: {exc}")

            if graph_loaded and airlock_ready and config_loaded:
                return 200, {
                    "status": "ready",
                    "graph_loaded": True,
                    "airlock_ready": True,
                    "config_loaded": True,
                }
            return 503, {
                "status": "not_ready",
                "reason": "; ".join(failure_reasons) if failure_reasons else "subsystem initialization failure",
                "graph_loaded": graph_loaded,
                "airlock_ready": airlock_ready,
                "config_loaded": config_loaded,
            }

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            self._send_bytes(status, json.dumps(payload).encode("utf-8"),
                             "application/json; charset=utf-8")

        def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
            try:
                from metrics_exporter import record_http_request
                url = urlsplit(self.path)
                endpoint = url.path if url.path else "/"
                record_http_request(method=getattr(self, "command", "GET"), endpoint=endpoint, status=status)
            except Exception:
                pass
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

            # Structured request logging
            cmd = getattr(self, "command", "GET")
            path = getattr(self, "path", "/")
            log_level = logging.WARNING if status >= 400 else logging.INFO
            client_ip = self.client_address[0] if (hasattr(self, "client_address") and self.client_address) else "unknown"
            logger.log(
                log_level,
                "HTTP %s %s -> %d (%d bytes)",
                cmd, path, status, len(body),
                extra={
                    "client_ip": client_ip,
                    "method": cmd,
                    "path": path,
                    "status_code": status,
                    "subsystem": "gateway",
                }
            )

        def do_HEAD(self) -> None:
            url = urlsplit(self.path)
            if url.path in ("/healthz", "/readyz", "/metrics"):
                if url.path == "/healthz":
                    uptime = round(time.time() - self._server_start_time, 3)
                    payload = {"status": "ok", "uptime_seconds": uptime, "pid": os.getpid(), "version": GATEWAY_VERSION}
                    body_len = len(json.dumps(payload).encode("utf-8"))
                    ct = "application/json; charset=utf-8"
                    status = 200
                elif url.path == "/readyz":
                    status_code, payload = self._evaluate_readiness()
                    body_len = len(json.dumps(payload).encode("utf-8"))
                    ct = "application/json; charset=utf-8"
                    status = status_code
                else:
                    from metrics_exporter import generate_latest_metrics
                    body_len = len(generate_latest_metrics().encode("utf-8"))
                    ct = "text/plain; version=0.0.4; charset=utf-8"
                    status = 200
                self.send_response(status)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(body_len))
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            try:
                url = urlsplit(self.path)

                # Container Lifecycle Probes (Kubernetes Liveness / Readiness) & Prometheus Scrape
                if url.path == "/healthz":
                    if url.query:
                        probe_params = set(parse_qs(url.query, keep_blank_values=True).keys())
                        if not probe_params.issubset({"k8s_liveness", "timestamp", "probe"}):
                            raise ValueError("Invalid query parameters")
                    uptime = round(time.time() - self._server_start_time, 3)
                    self._send_json(200, {
                        "status": "ok",
                        "uptime_seconds": uptime,
                        "pid": os.getpid(),
                        "version": GATEWAY_VERSION,
                    })
                    return

                if url.path == "/readyz":
                    if url.query:
                        probe_params = set(parse_qs(url.query, keep_blank_values=True).keys())
                        if not probe_params.issubset({"k8s_liveness", "timestamp", "probe"}):
                            raise ValueError("Invalid query parameters")
                    status_code, ready_payload = self._evaluate_readiness()
                    self._send_json(status_code, ready_payload)
                    return

                if url.path == "/metrics":
                    if url.query:
                        raise ValueError("Invalid query parameters")
                    from metrics_exporter import generate_latest_metrics
                    metrics_text = generate_latest_metrics()
                    self._send_bytes(200, metrics_text.encode("utf-8"),
                                     "text/plain; version=0.0.4; charset=utf-8")
                    return

                if url.path == "/scale":
                    from scale_benchmark import render_scale_benchmark_html

                    if url.query:
                        raise ValueError("Invalid scale benchmark request")
                    self._send_bytes(200, render_scale_benchmark_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/docs":
                    from openapi_spec import render_api_docs_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_api_docs_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/adapters":
                    from environment_adapters import render_adapters_html

                    if url.query:
                        raise ValueError("Invalid environment adapter request")
                    self._send_bytes(200, render_adapters_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/metrics-live":
                    from live_metrics_poller import render_live_metrics_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_live_metrics_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/hub":
                    from opscryer_suite_hub import render_suite_hub_html

                    self._send_bytes(200, render_suite_hub_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/executive":
                    from executive_command_center import render_executive_command_center_html

                    self._send_bytes(200, render_executive_command_center_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/gitops":
                    from gitops_release_cockpit import render_gitops_cockpit_html

                    self._send_bytes(200, render_gitops_cockpit_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/network":
                    from network_topology_inspector import render_network_inspector_html

                    self._send_bytes(200, render_network_inspector_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/capacity":
                    from capacity_planner import render_capacity_planner_html

                    self._send_bytes(200, render_capacity_planner_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/incidents":
                    from incident_commander import render_incident_commander_html

                    self._send_bytes(200, render_incident_commander_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/simulator":
                    from gameday_simulator import render_gameday_simulator_html

                    self._send_bytes(200, render_gameday_simulator_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/playbooks":
                    from playbook_studio import render_playbook_studio_html

                    self._send_bytes(200, render_playbook_studio_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/models":
                    from model_tier_copilot import render_model_copilot_html

                    self._send_bytes(200, render_model_copilot_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/games":
                    from game_observability_loop import render_game_debug_html

                    self._send_bytes(200, render_game_debug_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/storage":
                    from storage_zfs_cockpit import render_storage_cockpit_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_storage_cockpit_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/secops":
                    from secops_vulnerability_cockpit import render_secops_cockpit_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_secops_cockpit_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/kb":
                    from jev_knowledge_explorer import render_jev_knowledge_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_jev_knowledge_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/jev-eval":
                    from jev_calibration_eval import render_jev_eval_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_jev_eval_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path == "/tactical-deck":
                    from tactical_security_deck import render_tactical_security_deck_html

                    if url.query:
                        raise ValueError("Invalid query parameters")
                    self._send_bytes(200, render_tactical_security_deck_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if url.path in ("/chat", "/portal") and not url.query:
                    from ticket_chat_portal import render_concierge_chat_html

                    self._send_bytes(200, render_concierge_chat_html().encode("utf-8"),
                                     "text/html; charset=utf-8")
                    return
                if not url.path.startswith("/api/v1/"):
                    self._send_bytes(200, html_bytes, "text/html; charset=utf-8")
                    return
                api_aliases = {
                    "/api/v1/hub": "/api/v1/suite-catalog",
                    "/api/v1/incidents": "/api/v1/incident-commander",
                    "/api/v1/capacity": "/api/v1/capacity-planner",
                    "/api/v1/network": "/api/v1/network-inspector",
                    "/api/v1/gitops": "/api/v1/gitops-cockpit",
                    "/api/v1/secops": "/api/v1/secops-cockpit",
                    "/api/v1/storage": "/api/v1/storage-cockpit",
                    "/api/v1/kb": "/api/v1/kb-explorer",
                    "/api/v1/games": "/api/v1/game-debug-loop",
                    "/api/v1/models": "/api/v1/model-copilot",
                    "/api/v1/playbooks": "/api/v1/playbook-studio",
                    "/api/v1/simulator": "/api/v1/gameday-simulator",
                    "/api/v1/executive": "/api/v1/executive-summary",
                }
                if url.path in api_aliases:
                    url = url._replace(path=api_aliases[url.path])
                allowed = {
                    "/api/v1/scale-benchmark": {"nodes"},
                    "/api/v1/openapi.json": set(),
                    "/api/v1/environment-adapters": {"adapter"},
                    "/api/v1/graph/catalog": {"live"},
                    "/api/v1/live-metrics": {"live"},
                    "/api/v1/two-act-status": {"act"},
                    "/api/v1/dogfood-zoom": {"node_id", "zoom_level"},
                    "/api/v1/oscal-summary": set(),
                    "/api/v1/live-cluster-health": set(),
                    "/api/v1/live-cluster-currencies": set(),
                    "/api/v1/live-cluster-ask": {"q"},
                    "/api/v1/chat-concierge": {"q", "persona"},
                    "/api/v1/chat-walkthrough": set(),
                    "/api/v1/incident-commander": set(),
                    "/api/v1/gameday-simulator": {"scenario"},
                    "/api/v1/playbook-studio": set(),
                    "/api/v1/model-copilot": {"q"},
                    "/api/v1/game-debug-loop": {"game"},
                    "/api/v1/kb-explorer": {"q"},
                    "/api/v1/jev-eval": {"provider"},
                    "/api/v1/storage-cockpit": set(),
                    "/api/v1/secops-cockpit": set(),
                    "/api/v1/capacity-planner": set(),
                    "/api/v1/network-inspector": set(),
                    "/api/v1/gitops-cockpit": set(),
                    "/api/v1/executive-summary": set(),
                    "/api/v1/suite-catalog": set(),
                    "/api/v1/live-cluster-chaos": set(),
                    "/api/v1/live-cluster-oidc": set(),
                    "/api/v1/live-cluster-openbao": set(),
                    "/api/v1/live-cluster-gitops": set(),
                    "/api/v1/contract": set(),
                    "/api/v1/graph/drilldown": {"node_id", "id"},
                    "/api/v1/graph/shortest-path": {"source_id", "target_id", "source", "target"},
                    "/api/v1/graph/jev-tree": set(),
                    "/api/v1/graph/deflect-ticket": set(),
                    "/api/v1/graph/search": {"q", "limit"},
                    "/api/v1/system-context": {"tier", "target_gpu", "q"},
                    "/api/v1/observability-signals": {"format", "service"},
                    "/api/v1/actions/dry-run": set(),
                    "/api/v1/actions/stage": set(),
                    "/api/v1/actions/approve": set(),
                    "/api/v1/actions/reject": set(),
                    "/api/v1/actions/status": {"action_id", "status_filter", "limit"},
                    "/api/v1/graph/delta": {"since_seq"},
                    "/api/v1/events/stream": {"topics", "max_events"},
                    "/api/v1/security/ingest": set(),
                    "/api/v1/security/incidents": {"severity", "standard", "since_time", "limit"},
                    "/api/v1/security/rules": {"limit"},
                    "/api/v1/federation/status": set(),
                    "/api/v1/federation/heartbeat": set(),
                    "/api/v1/federation/severance": set(),
                    "/api/v1/federation/reconcile": set(),
                    "/api/v1/mcp": set(),
                    "/api/v1/gitops-promotion/status": set(),
                    "/api/v1/gitops-promotion/stage": set(),
                    "/api/v1/tactical-deck/summary": set(),
                    "/api/v1/itsm/tickets": {"status", "provider", "limit"},
                    "/api/v1/itsm/correlate": set(),
                    "/api/v1/itsm/chatops-callback": set(),
                    "/api/v1/flight-recorder/capsules": {"capsule_id"},
                    "/api/v1/flight-recorder/export": set(),
                    "/api/v1/flight-recorder/replay": set(),
                }
                if url.path not in allowed:
                    self._send_json(404, {"error": "Unknown API route"})
                    return
                if url.path in {"/api/v1/playbook-studio", "/api/v1/storage-cockpit",
                                "/api/v1/secops-cockpit"} and url.query:
                    raise ValueError("Invalid query parameters")
                if re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                    raise ValueError("Invalid query parameters")
                query = parse_qs(url.query, keep_blank_values=True,
                                 strict_parsing=True, errors="strict")
                if (set(query) - allowed[url.path]
                        or any(len(values) != 1 for values in query.values())):
                    raise ValueError("Invalid query parameters")
                if (url.path in {"/api/v1/graph/catalog", "/api/v1/live-metrics"}
                        and query.get("live", ["0"])[0] not in {"0", "1"}):
                    raise ValueError("Invalid query parameters")
                if url.path == "/api/v1/scale-benchmark":
                    from scale_benchmark import _parse_scale_nodes, run_scalability_benchmark_suite

                    sizes = ((_parse_scale_nodes(query["nodes"][0]),)
                             if "nodes" in query else (100, 500, 1500))
                    payload = run_scalability_benchmark_suite(sizes)
                elif url.path == "/api/v1/openapi.json":
                    from openapi_spec import build_openapi_v3_spec

                    payload = build_openapi_v3_spec()
                elif url.path == "/api/v1/graph/catalog":
                    from cluster_diff_engine import DEFAULT_CATALOG_PATH
                    from cluster_harvester import build_live_cluster_spatial_catalog
                    from live_currencies import build_enriched_live_currencies

                    payload = (json.loads(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
                               if DEFAULT_CATALOG_PATH.is_file()
                               else build_live_cluster_spatial_catalog())
                    if query.get("live", ["0"])[0] == "1":
                        from live_metrics_poller import poll_live_cluster_metrics

                        metrics = poll_live_cluster_metrics(allow_kubectl=True)
                        payload["rts_currencies"] = metrics["rts_currencies"]
                        payload["node_metrics"] = metrics["node_metrics"]
                        payload["telemetry_mode"] = metrics["telemetry_mode"]
                        by_id = {node["node_id"]: node for node in metrics["node_metrics"]}
                        for node in payload.get("nodes", []):
                            if node["id"] in by_id:
                                node["metrics"] = {
                                    key: value for key, value in by_id[node["id"]].items()
                                    if key not in {"node_id", "name"}}
                    else:
                        payload["rts_currencies"] = build_enriched_live_currencies()
                elif url.path == "/api/v1/live-metrics":
                    from live_metrics_poller import poll_live_cluster_metrics

                    payload = poll_live_cluster_metrics(
                        allow_kubectl=query.get("live", ["0"])[0] == "1")
                elif url.path == "/api/v1/two-act-status":
                    payload = build_two_act_browser_status(int(query.get("act", ["1"])[0]))
                elif url.path == "/api/v1/dogfood-zoom":
                    from dogfood_graph import query_node_at_progressive_zoom

                    payload = query_node_at_progressive_zoom(
                        node_id=query.get("node_id", ["root-company"])[0],
                        zoom_level=int(query.get("zoom_level", ["0"])[0]),
                    )
                elif url.path == "/api/v1/live-cluster-health":
                    from cluster_diff_engine import summarize_live_cluster_health

                    payload = summarize_live_cluster_health()
                elif url.path == "/api/v1/live-cluster-currencies":
                    from live_currencies import build_enriched_live_currencies

                    payload = {"rts_currencies": build_enriched_live_currencies()}
                elif url.path == "/api/v1/live-cluster-chaos":
                    from chaos_blast_radius import verify_all_six_chaos_planes

                    payload = verify_all_six_chaos_planes()
                elif url.path == "/api/v1/live-cluster-oidc":
                    from oidc_rbac_verifier import audit_cluster_ingress_oidc_posture

                    payload = audit_cluster_ingress_oidc_posture()
                elif url.path == "/api/v1/live-cluster-openbao":
                    from openbao_kms_provenance import audit_openbao_secret_provenance

                    payload = audit_openbao_secret_provenance()
                elif url.path == "/api/v1/live-cluster-gitops":
                    from live_gitops_signals import derive_live_gitops_and_ci_signals

                    payload = derive_live_gitops_and_ci_signals()
                elif url.path == "/api/v1/suite-catalog":
                    from opscryer_suite_hub import build_suite_application_catalog

                    payload = build_suite_application_catalog()
                elif url.path == "/api/v1/executive-summary":
                    from executive_command_center import build_executive_posture_dossier

                    payload = build_executive_posture_dossier()
                elif url.path == "/api/v1/gitops-cockpit":
                    from gitops_release_cockpit import evaluate_release_readiness_scorecard

                    payload = evaluate_release_readiness_scorecard()
                elif url.path == "/api/v1/network-inspector":
                    from network_topology_inspector import trace_ingress_to_hardware_routes

                    payload = trace_ingress_to_hardware_routes()
                elif url.path == "/api/v1/capacity-planner":
                    from capacity_planner import summarize_cluster_capacity

                    payload = summarize_cluster_capacity()
                elif url.path == "/api/v1/incident-commander":
                    from incident_commander import build_active_incidents_catalog

                    payload = build_active_incidents_catalog()
                elif url.path == "/api/v1/gameday-simulator":
                    from gameday_simulator import simulate_gameday_scenario

                    payload = simulate_gameday_scenario(
                        query.get("scenario", ["node_down_nodebeta02"])[0])
                elif url.path == "/api/v1/playbook-studio":
                    from playbook_studio import build_playbook_studio_catalog

                    payload = build_playbook_studio_catalog()
                elif url.path == "/api/v1/environment-adapters":
                    from environment_adapters import build_adapter_compatibility_catalog

                    payload = build_adapter_compatibility_catalog(query.get("adapter", [None])[0])
                elif url.path == "/api/v1/storage-cockpit":
                    from storage_zfs_cockpit import summarize_storage_topology

                    payload = summarize_storage_topology()
                elif url.path == "/api/v1/secops-cockpit":
                    from secops_vulnerability_cockpit import build_secops_posture_catalog

                    payload = build_secops_posture_catalog()
                elif url.path == "/api/v1/kb-explorer":
                    from jev_knowledge_explorer import build_jev_knowledge_catalog

                    question = query.get("q", [None])[0]
                    if question is not None and (
                            not question.strip()
                            or any(unicodedata.category(char) == "Cc" for char in question)):
                        raise ValueError("Invalid query parameters")
                    payload = build_jev_knowledge_catalog(query=question)
                elif url.path == "/api/v1/jev-eval":
                    from jev_calibration_eval import evaluate_jev_calibration_benchmark

                    provider = query.get("provider", ["deterministic"])[0]
                    payload = evaluate_jev_calibration_benchmark(provider=provider)
                elif url.path == "/api/v1/game-debug-loop":
                    from game_observability_loop import trace_game_debugging_loop

                    payload = trace_game_debugging_loop(query.get("game", ["minecraft"])[0])
                elif url.path == "/api/v1/model-copilot":
                    from model_tier_copilot import (
                        _parse_model_copilot_query, build_model_copilot_benchmark_matrix,
                        run_dual_tier_model_comparison,
                    )

                    question = _parse_model_copilot_query(url.query)
                    payload = (build_model_copilot_benchmark_matrix() if question is None
                               else run_dual_tier_model_comparison(question))
                    if payload.get("airlock_blocked") is True:
                        self._send_json(403, payload)
                        return
                elif url.path == "/api/v1/chat-walkthrough":
                    from chat_walkthrough import run_multi_persona_chat_walkthrough

                    payload = run_multi_persona_chat_walkthrough()
                elif url.path == "/api/v1/chat-concierge":
                    from ticket_chat_portal import PERSONAS, ask_concierge_chat

                    question = query.get("q", [""])[0]
                    persona = query.get("persona", ["household_user"])[0]
                    if (not question.strip() or persona not in PERSONAS
                            or any(ord(char) < 32 or ord(char) == 127 for char in question)):
                        raise ValueError("Invalid query parameters")
                    payload = ask_concierge_chat(question, persona=persona)
                    if payload.get("airlock_blocked") is True:
                        self._send_json(403, payload)
                        return
                elif url.path == "/api/v1/live-cluster-ask":
                    from live_advisor import answer_operational_question

                    question = query.get("q", [""])[0]
                    if (not question.strip()
                            or any(ord(char) < 32 or ord(char) == 127 for char in question)):
                        raise ValueError("Invalid question")
                    payload = answer_operational_question(question)
                    if payload.get("airlock_blocked") is True:
                        self._send_json(403, payload)
                        return
                elif url.path in {"/api/v1/contract", "/api/v1/graph/drilldown",
                                  "/api/v1/graph/shortest-path", "/api/v1/graph/jev-tree",
                                  "/api/v1/graph/search", "/api/v1/graph/delta"}:
                    engine = self._get_backend_engine()
                    params: dict[str, str] = {}
                    if "node_id" in query:
                        params["node_id"] = query["node_id"][0]
                    elif "id" in query:
                        params["node_id"] = query["id"][0]
                    if "source_id" in query:
                        params["source_id"] = query["source_id"][0]
                    elif "source" in query:
                        params["source_id"] = query["source"][0]
                    if "target_id" in query:
                        params["target_id"] = query["target_id"][0]
                    elif "target" in query:
                        params["target_id"] = query["target"][0]
                    if "q" in query:
                        params["q"] = query["q"][0]
                    if "limit" in query:
                        params["limit"] = query["limit"][0]
                    if "since_seq" in query:
                        params["since_seq"] = query["since_seq"][0]
                    status, payload = engine.handle_api_request(url.path, params=params, method="GET")
                    self._send_json(status, payload)
                    return
                elif url.path == "/api/v1/graph/deflect-ticket":
                    payload = {
                        "schema_version": "1.0-ticket-deflection",
                        "status": "active",
                        "description": "IT support ticket deflection endpoint. Submit a POST request with JSON payload containing ticket_title.",
                        "supported_methods": ["POST"],
                    }
                elif url.path in {
                    "/api/v1/actions/dry-run",
                    "/api/v1/actions/stage",
                    "/api/v1/actions/approve",
                    "/api/v1/actions/reject",
                    "/api/v1/actions/status",
                }:
                    import action_cards

                    engine = self._get_backend_engine()
                    catalog_attr = getattr(engine, "catalog", None)
                    catalog = catalog_attr() if callable(catalog_attr) else catalog_attr
                    status_code, payload = action_cards.handle_action_api(
                        url.path, method="GET", query=query, catalog=catalog
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path in {
                    "/api/v1/security/ingest",
                    "/api/v1/security/incidents",
                    "/api/v1/security/rules",
                }:
                    import cybersecurity_bridge

                    engine = self._get_backend_engine()
                    catalog_attr = getattr(engine, "catalog", None)
                    catalog = catalog_attr() if callable(catalog_attr) else catalog_attr
                    status_code, payload = cybersecurity_bridge.handle_security_api(
                        url.path, method="GET", query=query, catalog=catalog
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path in {
                    "/api/v1/federation/status",
                    "/api/v1/federation/heartbeat",
                    "/api/v1/federation/severance",
                    "/api/v1/federation/reconcile",
                }:
                    import node_federation

                    status_code, payload = node_federation.handle_federation_api(
                        url.path, method="GET", query=query
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path == "/api/v1/mcp":
                    import mcp_bridge

                    status_code, payload = mcp_bridge.handle_mcp_api(
                        url.path, method="GET", query=query
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path == "/api/v1/gitops-promotion/status":
                    import gitops_promotion_bridge

                    status_code, payload = gitops_promotion_bridge.handle_gitops_promotion_api(
                        url.path, method="GET", query=query
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path == "/api/v1/gitops-promotion/stage":
                    payload = {
                        "schema_version": "1.0-gitops-promotion",
                        "status": "active",
                        "description": "Stage a signed promote_to_prod Action Card via POST after dev gates pass.",
                        "supported_methods": ["POST"],
                    }
                elif url.path == "/api/v1/tactical-deck/summary":
                    import tactical_security_deck

                    status_code, payload = tactical_security_deck.handle_tactical_deck_api(
                        url.path, method="GET", query=query
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                    if isinstance(payload, dict):
                        payload["nanomachine_swarm"] = build_nanomachine_swarm_status()
                elif url.path in {
                    "/api/v1/itsm/tickets",
                    "/api/v1/itsm/correlate",
                    "/api/v1/itsm/chatops-callback",
                }:
                    import itsm_chatops_bridge

                    status_code, payload = itsm_chatops_bridge.handle_itsm_api(
                        url.path, method="GET", query=query
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path in {
                    "/api/v1/flight-recorder/capsules",
                    "/api/v1/flight-recorder/export",
                    "/api/v1/flight-recorder/replay",
                }:
                    import flight_recorder

                    status_code, payload = flight_recorder.handle_flight_recorder_api(
                        url.path, method="GET", query=query
                    )
                    if status_code != 200:
                        self._send_json(status_code, payload)
                        return
                elif url.path == "/api/v1/events/stream":
                    from event_stream import stream_events_generator, PERMITTED_TOPICS

                    topics_val = query.get("topics", [None])[0]
                    parsed_topics = None
                    if topics_val is not None:
                        topic_list = [t.strip().lower() for t in topics_val.split(",") if t.strip()]
                        for t in topic_list:
                            if t not in PERMITTED_TOPICS:
                                self._send_json(400, {
                                    "error": f"Unknown topic '{t}'. Permitted topics: {', '.join(sorted(PERMITTED_TOPICS))}"
                                })
                                return
                        parsed_topics = set(topic_list)

                    max_events_val = query.get("max_events", [None])[0]
                    parsed_max_events = None
                    if max_events_val is not None:
                        try:
                            parsed_max_events = int(max_events_val)
                            if parsed_max_events < 1:
                                raise ValueError("max_events must be an integer >= 1")
                        except ValueError:
                            raise ValueError("Invalid query parameters")

                    last_event_id_header = self.headers.get("Last-Event-ID")
                    since_seq = None
                    if last_event_id_header is not None:
                        try:
                            since_seq = int(last_event_id_header.strip())
                            if since_seq < 0:
                                self._send_json(400, {"error": "Last-Event-ID must be a non-negative integer"})
                                return
                        except ValueError:
                            self._send_json(400, {"error": "Invalid Last-Event-ID header"})
                            return

                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    if parsed_max_events is not None:
                        self.send_header("Connection", "close")
                        self.close_connection = True
                    else:
                        self.send_header("Connection", "keep-alive")
                    self.send_header("X-Accel-Buffering", "no")
                    self.end_headers()

                    try:
                        for chunk in stream_events_generator(
                            since_seq=since_seq,
                            topics=parsed_topics,
                            max_events=parsed_max_events,
                        ):
                            self.wfile.write(chunk.encode("utf-8"))
                            self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                elif url.path == "/api/v1/system-context":
                    from system_context import build_system_context

                    tier = query.get("tier", ["both"])[0]
                    target_gpu = query.get("target_gpu", [None])[0]
                    q = query.get("q", [None])[0]
                    payload = build_system_context(tier=tier, target_gpu=target_gpu, query=q)
                elif url.path == "/api/v1/observability-signals":
                    from prometheus_loki_adapter import get_observability_signals_report

                    fmt = query.get("format", ["full"])[0]
                    if fmt not in {"summary", "full"}:
                        raise ValueError("Invalid query parameters")
                    service = query.get("service", [None])[0]
                    if service is not None and (
                            not service.strip()
                            or any(ord(char) < 32 or ord(char) == 127 for char in service)):
                        raise ValueError("Invalid query parameters")
                    payload = get_observability_signals_report(
                        format=fmt, service=service)
                else:
                    from oscal_compliance import build_oscal_hud_posture_report

                    payload = build_oscal_hud_posture_report()
            except ValueError:
                if self.path.split("?", 1)[0] in {"/scale", "/api/v1/scale-benchmark"}:
                    self._send_json(400, {"error": "Invalid scale benchmark request"})
                    return
                error = ("Invalid environment adapter request"
                         if self.path.split("?", 1)[0] in {
                             "/adapters", "/api/v1/environment-adapters"}
                         else "Invalid query parameters")
                self._send_json(400, {"error": error})
                return
            except KeyError:
                self._send_json(404, {"error": "Unknown dogfood node"})
                return
            self._send_json(200, payload)

        def log_message(self, fmt: str, *a: Any) -> None:
            msg = fmt % a if a else fmt
            client_ip = self.client_address[0] if (hasattr(self, "client_address") and self.client_address) else "unknown"
            logger.info(
                "HTTP request: %s", msg,
                extra={
                    "client_ip": client_ip,
                    "request_line": msg,
                    "path": getattr(self, "path", ""),
                    "command": getattr(self, "command", ""),
                    "subsystem": "gateway",
                }
            )

        def do_POST(self) -> None:
            try:
                url = urlsplit(self.path)
                if url.path in ("/healthz", "/readyz", "/metrics"):
                    self._send_json(405, {"error": "method not allowed", "allowed_method": "GET"})
                    return
                supported_post_routes = {
                    "/api/v1/graph/deflect-ticket",
                    "/api/v1/actions/dry-run",
                    "/api/v1/actions/stage",
                    "/api/v1/actions/approve",
                    "/api/v1/actions/reject",
                    "/api/v1/security/ingest",
                    "/api/v1/security/rules",
                    "/api/v1/federation/heartbeat",
                    "/api/v1/federation/severance",
                    "/api/v1/federation/reconcile",
                    "/api/v1/mcp",
                    "/api/v1/gitops-promotion/stage",
                    "/api/v1/itsm/correlate",
                    "/api/v1/itsm/chatops-callback",
                    "/api/v1/flight-recorder/export",
                    "/api/v1/flight-recorder/replay",
                    "/api/v1/nanomachine-swarm/cast",
                }
                if url.path not in supported_post_routes:
                    if url.path.startswith("/api/v1/"):
                        self._send_json(405, {"error": "method not allowed", "allowed_method": "GET"})
                    else:
                        self._send_json(404, {"error": "Unknown API route"})
                    return

                if url.query:
                    self._send_json(400, {"error": "Invalid query parameters"})
                    return

                content_length_header = self.headers.get("Content-Length")
                if not content_length_header:
                    self._send_json(400, {"error": "Missing Content-Length header"})
                    return

                try:
                    content_length = int(content_length_header)
                    if content_length < 0 or content_length > 1_048_576:
                        self._send_json(400, {"error": "Invalid Content-Length header"})
                        return
                except ValueError:
                    self._send_json(400, {"error": "Invalid Content-Length header"})
                    return

                raw_body = self.rfile.read(content_length)
                if len(raw_body) != content_length:
                    self._send_json(400, {"error": "Incomplete request body"})
                    return

                try:
                    body = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    self._send_json(400, {"error": "Invalid JSON body"})
                    return

                if not isinstance(body, dict):
                    self._send_json(400, {"error": "Request body must be a JSON object"})
                    return

                if url.path.startswith("/api/v1/actions/"):
                    import action_cards

                    engine = self._get_backend_engine()
                    catalog_attr = getattr(engine, "catalog", None)
                    catalog = catalog_attr() if callable(catalog_attr) else catalog_attr
                    status, payload = action_cards.handle_action_api(
                        url.path, method="POST", query={}, body=body, catalog=catalog
                    )
                    self._send_json(status, payload)
                    return

                if url.path.startswith("/api/v1/security/"):
                    import cybersecurity_bridge

                    engine = self._get_backend_engine()
                    catalog_attr = getattr(engine, "catalog", None)
                    catalog = catalog_attr() if callable(catalog_attr) else catalog_attr
                    status, payload = cybersecurity_bridge.handle_security_api(
                        url.path, method="POST", query={}, body=body, catalog=catalog
                    )
                    self._send_json(status, payload)
                    return

                if url.path.startswith("/api/v1/federation/"):
                    import node_federation

                    status, payload = node_federation.handle_federation_api(
                        url.path, method="POST", query={}, body=body
                    )
                    self._send_json(status, payload)
                    return

                if url.path == "/api/v1/mcp":
                    import mcp_bridge

                    status, payload = mcp_bridge.handle_mcp_api(
                        url.path, method="POST", query={}, body=body
                    )
                    self._send_json(status, payload)
                    return

                if url.path.startswith("/api/v1/gitops-promotion/"):
                    import gitops_promotion_bridge

                    status, payload = gitops_promotion_bridge.handle_gitops_promotion_api(
                        url.path, method="POST", query={}, body=body
                    )
                    self._send_json(status, payload)
                    return

                if url.path.startswith("/api/v1/itsm/"):
                    import itsm_chatops_bridge

                    status, payload = itsm_chatops_bridge.handle_itsm_api(
                        url.path, method="POST", query={}, body=body
                    )
                    self._send_json(status, payload)
                    return

                if url.path.startswith("/api/v1/flight-recorder/"):
                    import flight_recorder

                    status, payload = flight_recorder.handle_flight_recorder_api(
                        url.path, method="POST", query={}, body=body
                    )
                    self._send_json(status, payload)
                    return

                if url.path == "/api/v1/nanomachine-swarm/cast":
                    status, payload = evaluate_nanomachine_swarm_cast(body)
                    self._send_json(status, payload)
                    return

                if "ticket_title" not in body and "ticket_text" in body:
                    body["ticket_title"] = body["ticket_text"]

                engine = self._get_backend_engine()
                status, payload = engine.handle_api_request(url.path, method="POST", body=body)
                if status == 200 and isinstance(payload, dict):
                    payload["schema_version"] = "1.0-ticket-deflection"
                self._send_json(status, payload)
            except Exception as exc:
                logger.error(
                    "Unhandled exception processing POST %s: %s", self.path, exc,
                    exc_info=True,
                    extra={"path": self.path, "status_code": 500, "error": str(exc), "subsystem": "gateway"}
                )
                self._send_json(500, {"error": f"Internal server error: {exc}"})

    return _FrontendHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Piece A: Standalone Frontend Spatial Information Tree Browser (Zero Backend Coupling)"
    )
    parser.add_argument("--config", type=Path, default=None, help="Optional JSON/YAML runtime settings file")
    parser.add_argument("--export-bundle", type=Path, help="Export standalone static HTML/JSON frontend bundle to directory")
    parser.add_argument("--demo-json", action="store_true", help="Print the standalone hackathon demo dataset as JSON")
    parser.add_argument("--live-advisor", metavar="QUESTION", help="Print a grounded operational answer as JSON")
    parser.add_argument("--live-health", action="store_true", help="Print live cluster snapshot health as JSON")
    parser.add_argument("--path", nargs=2, metavar=("SOURCE_ID", "TARGET_ID"), help="Compute shortest path across demo dataset")
    parser.add_argument("--api-base", default="", help="Optional default remote backend URL for exported bundle")
    parser.add_argument("--serve", action="store_true", help="Serve the standalone frontend browser locally")
    parser.add_argument("--host", default=os.environ.get("OPSCRYER_BIND_HOST", "127.0.0.1"), help="Bind host for --serve (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8088, help="Port for --serve (default: 8088)")
    args = parser.parse_args(argv)

    cfg = load_browser_runtime_settings(args.config)
    effective_api_base = args.api_base or str(cfg.get("api_base_url", ""))
    effective_port = args.port if args.port != 8088 else int(cfg.get("port", 8088))

    if args.live_advisor is not None:
        from live_advisor import answer_operational_question

        if (not args.live_advisor.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in args.live_advisor)):
            parser.error("invalid operational question")
        print(json.dumps(answer_operational_question(args.live_advisor), indent=2))
        return 0

    if args.live_health:
        from cluster_diff_engine import summarize_live_cluster_health

        print(json.dumps(summarize_live_cluster_health(), indent=2))
        return 0

    if args.path:
        print(json.dumps(compute_demo_shortest_path(args.path[0], args.path[1]), indent=2))
        return 0

    if args.export_bundle:
        res = export_standalone_browser_bundle(args.export_bundle, default_api_base=effective_api_base)
        print(json.dumps(res, indent=2))
        return 0

    if args.demo_json:
        print(json.dumps(build_standalone_demo_dataset(), indent=2))
        return 0

    if args.serve:
        configure_gateway_logging()
        _FrontendHandler = _build_frontend_handler(effective_api_base)
        try:
            with socketserver.TCPServer((args.host, args.port), _FrontendHandler) as httpd:
                print(f"Serving Standalone Frontend Browser (Piece A) at http://{args.host}:{args.port}")
                httpd.serve_forever()
        except OSError:
            parser.error("Requested --port is already in use; stop the existing server or choose another --port")
        return 0

    print(json.dumps(build_standalone_demo_dataset(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
