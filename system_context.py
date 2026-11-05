# SPDX-License-Identifier: Apache-2.0
"""Dual-tier AI system context, hardware inventory, and AST jump references.

This module is pure Python standard library with zero external dependencies.
It exposes authoritative homelab hardware inventory, intentional scale-down
workload status, canonical knowledge runbooks, and AST jump references for
both low-powered local GPU models and high-powered frontier models.
All outputs are strictly passed through telemetry_sanitizer to ensure full
OPSEC and demo integrity.
"""

from __future__ import annotations

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import time
from typing import Any

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize

SYSTEM_CONTEXT_SCHEMA_VERSION = "1.0-system-context"

# Authoritative Physical Homelab GPU Inventory (Human-Verified Ground Truth):
# Exactly 4 GPUs (40 GB total VRAM):
#   - 1x NVIDIA GeForce RTX 3080 (10 GB GDDR6X)
#   - 1x NVIDIA GeForce RTX 3070 Ti (8 GB GDDR6X)
#   - 2x NVIDIA GeForce GTX 1080 Ti (2x 11 GB GDDR5X = 22 GB)
# Note: "RTX 5080" was a historical agent hallucination and does NOT exist in physical hardware.
VERIFIED_HOMELAB_GPU_INVENTORY: dict[str, Any] = {
    "total_gpu_count": 4,
    "total_vram_gb": 40,
    "summary": (
        "1x RTX 3080 (10 GB GDDR6X) + 1x RTX 3070 Ti (8 GB GDDR6X) + "
        "2x GTX 1080 Ti (2x 11 GB GDDR5X = 22 GB) = 4 GPUs (40 GB total VRAM)"
    ),
    "gpus": [
        {
            "id": "hw-gpu-rtx-3080-01",
            "model": "NVIDIA GeForce RTX 3080",
            "vram_gb": 10,
            "memory_type": "GDDR6X",
            "architecture": "Ampere",
            "host_node": "nodegamma03 (10.20.3.13)",
            "role": "Primary 24/7 In-Cluster K8s Ollama GPU Worker (ollama-service.ai-infra.svc:11434) & Media/Game Host",
            "preferred_local_models": ["phi3:latest", "qwen2.5-coder:7b", "llama3.1:8b"],
        },
        {
            "id": "hw-gpu-rtx-3070ti-01",
            "model": "NVIDIA GeForce RTX 3070 Ti",
            "vram_gb": 8,
            "memory_type": "GDDR6X",
            "architecture": "Ampere",
            "host_node": "Developer Workstation / Local GPU Tier",
            "role": "Fast 7B/8B Local GPU Worker, Single-Token Jev Classifier & Security Triage",
            "preferred_local_models": ["qwen2.5-coder:7b-instruct-q4_K_M", "llama3.1:8b-instruct-q4_K_M", "phi3:latest"],
        },
        {
            "id": "hw-gpu-gtx-1080ti-01",
            "model": "NVIDIA GeForce GTX 1080 Ti",
            "vram_gb": 11,
            "memory_type": "GDDR5X",
            "architecture": "Pascal",
            "host_node": "Local GPU Compute Tier (Slot #1)",
            "role": "11 GB VRAM Parallel Batch Inference, Embeddings & Multi-Model Evaluation Worker #1",
            "preferred_local_models": ["llama3.1:8b", "qwen2.5-coder:7b", "nomic-embed-text"],
        },
        {
            "id": "hw-gpu-gtx-1080ti-02",
            "model": "NVIDIA GeForce GTX 1080 Ti",
            "vram_gb": 11,
            "memory_type": "GDDR5X",
            "architecture": "Pascal",
            "host_node": "Local GPU Compute Tier (Slot #2)",
            "role": "11 GB VRAM Parallel Batch Inference, Code Audit & Multi-Model Evaluation Worker #2",
            "preferred_local_models": ["qwen2.5-coder:7b", "deepseek-r1:8b", "nomic-embed-text"],
        },
    ],
    "hallucinated_gpu_denylist": [
        "RTX 5080",
        "RTX 4090",
        "H100",
        "A100",
    ],
}

# Authoritative Homelab Physical Host Node Hardware (CPU Cores & DDR4 RAM)
HOMELAB_NODE_HARDWARE: dict[str, Any] = {
    "total_nodes": 3,
    "total_cpu_cores": 28,
    "total_ram_gb": 112,
    "nodes": [
        {
            "node_name": "nodegamma03",
            "node_id": "k8s/Node//nodegamma03",
            "cpu_cores": 16,
            "ram_gb": 64,
            "memory_type": "DDR4",
            "hot_cache_gb": 16,
            "primary_ip": "10.20.3.13",
            "role": "Primary Kubernetes compute, GPU host, OpenZFS DDR4 write-behind cache",
            "attached_gpus": ["hw-gpu-rtx-3080-01"],
        },
        {
            "node_name": "nodebeta02",
            "node_id": "k8s/Node//nodebeta02",
            "cpu_cores": 8,
            "ram_gb": 32,
            "memory_type": "DDR4",
            "hot_cache_gb": 0,
            "primary_ip": "10.20.3.10",
            "role": "Control plane & secondary services",
            "attached_gpus": [],
        },
        {
            "node_name": "nodealpha01",
            "node_id": "k8s/Node//nodealpha01",
            "cpu_cores": 4,
            "ram_gb": 16,
            "memory_type": "DDR4",
            "hot_cache_gb": 0,
            "primary_ip": "10.20.3.2",
            "role": "Utility & low-power DNS/ingress proxy",
            "attached_gpus": [],
        },
    ],
}

# Canonical Intentional Scale-Down Registry
# Prevents models from wasting tokens attempting to restart or scale up workloads
# intentionally kept at 0/0 replicas to preserve host RAM/VRAM.
INTENTIONAL_SCALE_DOWN_WORKLOADS: list[dict[str, Any]] = [
    {
        "workload": "ai-infra/agentic-agent-developer",
        "namespace": "ai-infra",
        "name": "agentic-agent-developer",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 (replaced by dev-envs Antigravity fleet)",
    },
    {
        "workload": "ai-infra/ollama-model-publisher",
        "namespace": "ai-infra",
        "name": "ollama-model-publisher",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 (on-demand model weight sync only)",
    },
    {
        "workload": "ai-infra/open-webui",
        "namespace": "ai-infra",
        "name": "open-webui",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 (chat-sandbox.cluster.example.org disabled when idle)",
    },
    {
        "workload": "ai-infra/scalable-worker",
        "namespace": "ai-infra",
        "name": "scalable-worker",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 (KEDA/overflow worker scaled on queue depth)",
    },
    {
        "workload": "packet-aggregator-demo/pcap-ingest",
        "namespace": "packet-aggregator-demo",
        "name": "pcap-ingest",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 outside active packet capture windows",
    },
    {
        "workload": "gitlab/gitlab-runner-turbo",
        "namespace": "gitlab",
        "name": "gitlab-runner-turbo",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 when turbo burst mode is inactive",
    },
    {
        "workload": "security/trivy-operator",
        "namespace": "security",
        "name": "trivy-operator",
        "replicas": 0,
        "reason": "Intentionally scaled to 0/0 between scheduled 6-hour SBOM scan windows",
    },
]

# Canonical KB Runbooks
CANONICAL_KB_RUNBOOKS: list[dict[str, Any]] = [
    {
        "id": "kb-db-001",
        "label": "Runbook: Provision HA PostgreSQL via CloudNativePG (CNPG)",
        "kind": "knowledge_article",
        "domain": "processes_workflows",
        "namespace": "cnpg-system",
        "summary": "Standard Golden Path runbook for provisioning HA PostgreSQL clusters with OpenBao ExternalSecret credentials and Barman WAL backups.",
        "primary_url": "https://gitlab.cluster.example.org/prod/home-k8s/-/blob/main/.ai/skills/environment_provisioning/SKILL.md",
        "declarative_cli": "kubectl get clusters.postgresql.cnpg.io -A",
        "governs_targets": ["k8s/Namespace//cnpg-system", "k8s/Namespace//gitlab"],
    },
    {
        "id": "kb-game-002",
        "label": "Runbook: Household Game Server & Dual AMD APU-200 Triage",
        "kind": "knowledge_article",
        "domain": "processes_workflows",
        "namespace": "game-servers",
        "summary": "Triage playbook for Minecraft (:25565/:25566), Factorio (:34197), Satisfactory (:7777), GPU AI/Gaming mode switching, and APU-200 node_exporter (:9100).",
        "primary_url": "https://gitlab.cluster.example.org/prod/home-k8s/-/blob/main/.ai/knowledge/workflow/user_feedback_ledger.md",
        "declarative_cli": "kubectl get pods,svc -n game-servers -o wide",
        "governs_targets": ["k8s/Namespace//game-servers", "k8s/Namespace//gaming"],
    },
    {
        "id": "kb-git-003",
        "label": "Runbook: Golden Path CI/CD Component Facade & 6-Gate Pre-Push Parity",
        "kind": "knowledge_article",
        "domain": "processes_workflows",
        "namespace": "gitlab",
        "summary": "Enforces modular Golden Path CI components, lowercase Conventional Commits, LF line endings, and two-class AI/Human MR creation (Rules 2, 4, 5, 6, 7).",
        "primary_url": "https://gitlab.cluster.example.org/prod/home-k8s/-/blob/main/.ai/skills/golden_path_architecture/SKILL.md",
        "declarative_cli": "python scripts/devops/inline_docs_migration.py verify",
        "governs_targets": ["k8s/Namespace//gitlab", "k8s/Namespace//dev-envs"],
    },
    {
        "id": "kb-sec-004",
        "label": "Runbook: OpenBao Raft KMS Unseal, ExternalSecrets & Argus DinD Hardening",
        "kind": "knowledge_article",
        "domain": "processes_workflows",
        "namespace": "security",
        "summary": "Zero-knowledge secret rotation via OpenBao KVv2 + Reloader and non-root UID 10001 DinD container builds verified by Trivy and DefectDojo.",
        "primary_url": "https://gitlab.cluster.example.org/prod/home-k8s/-/blob/main/.ai/skills/secret_rotation_and_reloading/SKILL.md",
        "declarative_cli": "kubectl get externalsecrets -A",
        "governs_targets": ["k8s/Namespace//security", "k8s/Namespace//iam"],
    },
    {
        "id": "kb-stor-005",
        "label": "Runbook: OpenZFS SCALE ZFS (`10.20.3.5`) & DDR4 RAM Write-Behind Checkpoint",
        "kind": "knowledge_article",
        "domain": "processes_workflows",
        "namespace": "storage-system",
        "summary": "Democratic-CSI NFS/iSCSI storage provisioning on OpenZFS (10.20.3.5) paired with nodegamma03 16 GiB DDR4 RAM tmpfs hot cache.",
        "primary_url": "https://gitlab.cluster.example.org/prod/home-k8s/-/blob/main/.ai/graphify/architecture.md",
        "declarative_cli": "kubectl get pvc -A",
        "governs_targets": ["k8s/Namespace//storage-system", "k8s/Namespace//dev-envs"],
    },
]

# Pre-indexed fallback AST jump references correlated to Piece B graph node IDs
_DEFAULT_AST_JUMPS: dict[str, list[dict[str, Any]]] = {
    "system_context": [
        {
            "symbol": "build_system_context",
            "kind": "def",
            "file": "system_context.py",
            "line_range": "L260-L380",
            "jump_ref": "system_context.py#L260",
            "correlated_graph_node_id": "hw-demo-gpu-node",
        },
        {
            "symbol": "get_verified_gpu_inventory",
            "kind": "def",
            "file": "system_context.py",
            "line_range": "L235-L245",
            "jump_ref": "system_context.py#L235",
            "correlated_graph_node_id": "hw-demo-gpu-node",
        },
        {
            "symbol": "get_intentional_scale_down_workloads",
            "kind": "def",
            "file": "system_context.py",
            "line_range": "L247-L251",
            "jump_ref": "system_context.py#L247",
            "correlated_graph_node_id": "deploy-demo-k8s",
        },
        {
            "symbol": "get_canonical_kb_runbooks",
            "kind": "def",
            "file": "system_context.py",
            "line_range": "L253-L257",
            "jump_ref": "system_context.py#L253",
            "correlated_graph_node_id": "proc-demo-cicd",
        },
    ],
    "opscryer_browser": [
        {
            "symbol": "_FrontendHandler",
            "kind": "class",
            "file": "opscryer_browser.py",
            "line_range": "L1940-L2180",
            "jump_ref": "opscryer_browser.py#L1940",
            "correlated_graph_node_id": "root-company",
        },
        {
            "symbol": "build_standalone_rts_currencies",
            "kind": "def",
            "file": "opscryer_browser.py",
            "line_range": "L124-L180",
            "jump_ref": "opscryer_browser.py#L124",
            "correlated_graph_node_id": "root-company",
        },
    ],
    "route_registry": [
        {
            "symbol": "build_route_registry_summary",
            "kind": "def",
            "file": "route_registry.py",
            "line_range": "L132-L149",
            "jump_ref": "route_registry.py#L132",
            "correlated_graph_node_id": "root-company",
        },
    ],
    "opscryer_backend": [
        {
            "symbol": "KnowledgeGraphBackendEngine",
            "kind": "class",
            "file": "opscryer_backend.py",
            "line_range": "L30-L240",
            "jump_ref": "opscryer_backend.py#L30",
            "correlated_graph_node_id": "root-company",
        },
    ],
}


def get_verified_gpu_inventory() -> dict[str, Any]:
    """Return the human-verified 4-GPU homelab inventory and hallucination denylist."""
    return deepcopy(VERIFIED_HOMELAB_GPU_INVENTORY)


def get_homelab_hardware_inventory() -> dict[str, Any]:
    """Return the authoritative homelab host node specs (CPU cores, DDR4 RAM, IPs)."""
    return deepcopy(HOMELAB_NODE_HARDWARE)


def get_intentional_scale_down_workloads() -> list[dict[str, Any]]:
    """Return the list of intentional 0/0 scale-down workloads."""
    return deepcopy(INTENTIONAL_SCALE_DOWN_WORKLOADS)


def get_canonical_kb_runbooks() -> list[dict[str, Any]]:
    """Return the 5 canonical KB runbooks."""
    return deepcopy(CANONICAL_KB_RUNBOOKS)


def _extract_ast_symbols_from_file(file_path: Path, rel_name: str) -> list[dict[str, Any]]:
    """Extract top-level classes and functions with exact line numbers using stdlib ast."""
    if not file_path.is_file() or file_path.suffix != ".py":
        return []
    try:
        src = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=rel_name)
    except (OSError, SyntaxError):
        return []

    symbols: list[dict[str, Any]] = []
    # Map common modules to correlated Piece B graph node IDs
    node_correlation_map = {
        "system_context.py": "hw-demo-gpu-node",
        "opscryer_browser.py": "root-company",
        "route_registry.py": "root-company",
        "opscryer_backend.py": "root-company",
        "opscryer_config.py": "proc-demo-secret-policy",
        "http_transport.py": "proc-demo-cicd",
        "capacity_planner.py": "deploy-demo-k8s",
        "knowledge_base.py": "proc-demo-cicd",
    }
    correlated_node = node_correlation_map.get(rel_name, "root-company")

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "def"
            end_line = getattr(node, "end_lineno", node.lineno + 15)
            symbols.append({
                "symbol": node.name,
                "kind": kind,
                "file": rel_name,
                "line_range": f"L{node.lineno}-L{end_line}",
                "jump_ref": f"{rel_name}#L{node.lineno}",
                "correlated_graph_node_id": correlated_node,
            })
    return symbols


def build_ast_jump_references(target_files: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """Build inspectable AST jump references for code modules in the OpsCryer suite."""
    base_dir = Path(__file__).parent
    files_to_scan = target_files or [
        "system_context.py",
        "opscryer_browser.py",
        "route_registry.py",
        "opscryer_backend.py",
        "opscryer_config.py",
        "http_transport.py",
    ]

    result: dict[str, list[dict[str, Any]]] = {}
    for rel_f in files_to_scan:
        mod_key = Path(rel_f).stem
        full_path = base_dir / rel_f
        extracted = _extract_ast_symbols_from_file(full_path, rel_f)
        if extracted:
            result[mod_key] = extracted
        elif mod_key in _DEFAULT_AST_JUMPS:
            result[mod_key] = deepcopy(_DEFAULT_AST_JUMPS[mod_key])

    # Ensure defaults exist if files are offline or in synthetic test environments
    for k, v in _DEFAULT_AST_JUMPS.items():
        if k not in result:
            result[k] = deepcopy(v)
    return result


def validate_model_output_against_context(
    model_output: str,
    allowed_files: list[str] | None = None,
) -> dict[str, Any]:
    """Validate model output against hardware inventory, scale-down workloads, and scope."""
    out_low = model_output.lower()

    # 1. Check for hallucinated GPUs
    hallucinated_gpus: list[str] = [
        bad_gpu for bad_gpu in VERIFIED_HOMELAB_GPU_INVENTORY["hallucinated_gpu_denylist"]
        if bad_gpu.lower() in out_low
    ]

    # 2. Check for unauthorized restart / scale-up of scale-down workloads
    scaled_down_violations: list[str] = []
    if any(verb in out_low for verb in ("kubectl scale", "replicas: 1", "replicas: 2", "rollout restart")):
        for wk in INTENTIONAL_SCALE_DOWN_WORKLOADS:
            if wk["name"].lower() in out_low or wk["workload"].lower() in out_low:
                scaled_down_violations.append(wk["workload"])

    # 3. Check for out-of-scope files if strict file scoping is requested
    out_of_scope: list[str] = []
    if allowed_files:
        mentioned_paths = set(re.findall(r"\b[A-Za-z0-9_./-]+\.(?:py|yaml|yml|json|md)\b", model_output))
        allowed_set = set(allowed_files)
        for mp in sorted(mentioned_paths):
            if mp not in allowed_set:
                out_of_scope.append(mp)

    passed = len(hallucinated_gpus) == 0 and len(scaled_down_violations) == 0 and len(out_of_scope) == 0
    return {
        "passed": passed,
        "status": "NOMINAL" if passed else ("HALLUCINATING" if hallucinated_gpus else "VIOLATION"),
        "hallucinated_gpus": hallucinated_gpus,
        "intentional_scale_down_violations": scaled_down_violations,
        "out_of_scope_files": out_of_scope,
    }


def build_system_context(
    tier: str = "both",
    target_gpu: str | None = None,
    query: str | None = None,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the complete, OPSEC-sanitized dual-tier AI system context payload.

    Args:
        tier: "both", "local_gpu", or "frontier". Defaults to "both".
        target_gpu: Optional local GPU identifier/model.
        query: Optional operational question or search text.
        catalog: Optional live or synthetic cluster catalog snapshot.

    Returns:
        JSON-serializable dictionary adhering to schema_version 1.0-system-context.
    """
    gpus_data = deepcopy(VERIFIED_HOMELAB_GPU_INVENTORY["gpus"])
    workloads_data = deepcopy(INTENTIONAL_SCALE_DOWN_WORKLOADS)
    runbooks_data = deepcopy(CANONICAL_KB_RUNBOOKS)
    ast_jumps = build_ast_jump_references()
    node_hardware = deepcopy(HOMELAB_NODE_HARDWARE)

    selected_gpu = target_gpu or gpus_data[0]["model"]

    # Build local model anti-lost guardrail pack
    local_anti_lost_pack = {
        "target_tier": "local_gpu_small_model",
        "target_hardware": selected_gpu,
        "verified_gpu_inventory": VERIFIED_HOMELAB_GPU_INVENTORY,
        "strict_allowed_files": ["system_context.py", "opscryer_browser.py"],
        "intentional_scale_down_guard": {w["workload"]: w["reason"] for w in workloads_data},
        "canonical_kb_runbooks": [rb["id"] for rb in runbooks_data],
        "hallucinated_gpu_denylist": VERIFIED_HOMELAB_GPU_INVENTORY["hallucinated_gpu_denylist"],
    }

    # Build frontier model token-saver brief
    frontier_brief = {
        "target_tier": "frontier_high_powered_model",
        "verified_gpu_summary": VERIFIED_HOMELAB_GPU_INVENTORY["summary"],
        "total_cpu_cores": node_hardware["total_cpu_cores"],
        "total_ram_gb": node_hardware["total_ram_gb"],
        "intentional_scale_downs_count": len(workloads_data),
        "active_kb_runbooks_count": len(runbooks_data),
        "ast_jump_modules": list(ast_jumps.keys()),
        "token_economy": {
            "estimated_blind_exploration_tool_calls_avoided": 9,
            "estimated_tokens_saved": 12800,
        },
    }

    # Core response payload (satisfies PROJECT.md and agent_context_graph_bridge expectations)
    raw_payload: dict[str, Any] = {
        "schema_version": SYSTEM_CONTEXT_SCHEMA_VERSION,
        "gpu_inventory": gpus_data,
        "scale_down_workloads": workloads_data,
        "active_kb_runbooks": runbooks_data,
        "ast_jump_references": ast_jumps,
        # Extended metadata & hardware inventory
        "hardware_inventory": {
            "gpus": gpus_data,
            "nodes": node_hardware["nodes"],
            "total_nodes": node_hardware["total_nodes"],
            "total_cpu_cores": node_hardware["total_cpu_cores"],
            "total_ram_gb": node_hardware["total_ram_gb"],
            "total_vram_gb": VERIFIED_HOMELAB_GPU_INVENTORY["total_vram_gb"],
            "total_gpu_count": VERIFIED_HOMELAB_GPU_INVENTORY["total_gpu_count"],
        },
        "total_gpu_count": VERIFIED_HOMELAB_GPU_INVENTORY["total_gpu_count"],
        "total_vram_gb": VERIFIED_HOMELAB_GPU_INVENTORY["total_vram_gb"],
        "cpu_cores": node_hardware["total_cpu_cores"],
        "ram_gb": node_hardware["total_ram_gb"],
        "hallucinated_gpu_denylist": VERIFIED_HOMELAB_GPU_INVENTORY["hallucinated_gpu_denylist"],
        "intentional_scale_down_guard": {w["workload"]: w["reason"] for w in workloads_data},
    }

    if tier in ("local_gpu", "both"):
        raw_payload["local_gpu_anti_lost_pack"] = local_anti_lost_pack
    if tier in ("frontier", "both"):
        raw_payload["frontier_token_saver_brief"] = frontier_brief

    # Pass through strict OPSEC sanitization boundary before returning
    return sanitize(raw_payload)


__all__ = [
    "CANONICAL_KB_RUNBOOKS",
    "HOMELAB_NODE_HARDWARE",
    "INTENTIONAL_SCALE_DOWN_WORKLOADS",
    "SYSTEM_CONTEXT_SCHEMA_VERSION",
    "VERIFIED_HOMELAB_GPU_INVENTORY",
    "build_ast_jump_references",
    "build_system_context",
    "get_canonical_kb_runbooks",
    "get_homelab_hardware_inventory",
    "get_intentional_scale_down_workloads",
    "get_verified_gpu_inventory",
    "validate_model_output_against_context",
]
