# SPDX-License-Identifier: Apache-2.0
"""Spatial graph contracts, knowledge queries, and Jev ticket routing."""

from dogfood_graph import build_dogfood_zoom_catalog, query_node_at_progressive_zoom
from jev_client import SystemOneJevClient, evaluate_ticket_with_jev_tree, predicate_route
from environment_adapters import (
    BaseEnvironmentAdapter,
    register_adapter_profile,
    get_adapter_profile,
    list_adapter_profiles,
    unregister_adapter_profile,
    reset_adapter_registry,
)
from opscryer_backend import (
    CONTRACT_VERSION,
    KnowledgeGraphBackendEngine,
    validate_spatial_graph_contract,
)
from opscryer_config import (
    DEFAULT_CONFIG,
    dump_sanitized_config,
    get_config_value,
    load_unified_config,
    reset_config,
)
from system_context import (
    CANONICAL_KB_RUNBOOKS,
    HOMELAB_NODE_HARDWARE,
    INTENTIONAL_SCALE_DOWN_WORKLOADS,
    SYSTEM_CONTEXT_SCHEMA_VERSION,
    VERIFIED_HOMELAB_GPU_INVENTORY,
    build_ast_jump_references,
    build_system_context,
    get_canonical_kb_runbooks,
    get_homelab_hardware_inventory,
    get_intentional_scale_down_workloads,
    get_verified_gpu_inventory,
    validate_model_output_against_context,
)

__all__ = [
    'CONTRACT_VERSION',
    'KnowledgeGraphBackendEngine',
    'validate_spatial_graph_contract',
    'SystemOneJevClient',
    'evaluate_ticket_with_jev_tree',
    'predicate_route',
    'build_dogfood_zoom_catalog',
    'query_node_at_progressive_zoom',
    'DEFAULT_CONFIG',
    'dump_sanitized_config',
    'get_config_value',
    'load_unified_config',
    'reset_config',
    'CANONICAL_KB_RUNBOOKS',
    'HOMELAB_NODE_HARDWARE',
    'INTENTIONAL_SCALE_DOWN_WORKLOADS',
    'SYSTEM_CONTEXT_SCHEMA_VERSION',
    'VERIFIED_HOMELAB_GPU_INVENTORY',
    'build_ast_jump_references',
    'build_system_context',
    'get_canonical_kb_runbooks',
    'get_homelab_hardware_inventory',
    'get_intentional_scale_down_workloads',
    'get_verified_gpu_inventory',
    'validate_model_output_against_context',
    'BaseEnvironmentAdapter',
    'register_adapter_profile',
    'get_adapter_profile',
    'list_adapter_profiles',
    'unregister_adapter_profile',
    'reset_adapter_registry',
]
