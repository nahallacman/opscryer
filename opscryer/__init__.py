# SPDX-License-Identifier: Apache-2.0
"""Organized public namespace for OpsCryer and its existing top-level modules.

Import subsystems explicitly, for example ``from opscryer import core``.
Inspecting package metadata does not import the application subsystems.
"""

from copy import deepcopy

__version__ = '1.2.0'

PACKAGE_SUBSYSTEMS = {
    'core': {
        'modules': ['opscryer_backend', 'jev_client', 'dogfood_graph', 'opscryer_config', 'system_context'],
        'responsibility': 'Spatial graph contracts, knowledge queries, and Jev ticket routing.',
    },
    'live': {
        'modules': [
            'cluster_harvester', 'cluster_diff_engine', 'live_currencies',
            'live_metrics_poller', 'live_advisor', 'live_gitops_signals',
            'prometheus_loki_adapter', 'metrics_exporter', 'webhook_notifier',
        ],
        'responsibility': 'Live cluster discovery, health, metrics, currencies, and operational advice.',
    },
    'security': {
        'modules': [
            'telemetry_sanitizer', 'security_airlock', 'oscal_compliance',
            'openbao_kms_provenance', 'oidc_rbac_verifier', 'chaos_blast_radius',
            'pqc_security', 'action_cards',
        ],
        'responsibility': 'Telemetry sanitization, security audits, compliance, and chaos isolation.',
    },
    'portals': {
        'modules': [
            'opscryer_browser', 'ticket_chat_portal', 'opscryer_suite_hub',
            'incident_commander', 'capacity_planner', 'network_topology_inspector',
            'gitops_release_cockpit', 'executive_command_center', 'gameday_simulator',
            'playbook_studio', 'model_tier_copilot', 'game_observability_loop',
            'jev_knowledge_explorer', 'storage_zfs_cockpit',
            'secops_vulnerability_cockpit', 'live_metrics_poller',
            'environment_adapters', 'openapi_spec',
        ],
        'responsibility': 'Suite HTML portals and their supporting application catalogs.',
    },
}


def get_package_architecture_map() -> dict:
    """Return subsystem responsibilities and importable top-level module names.

    Shared modules can appear in multiple subsystems. The returned map is an
    independent copy, including its nested dictionaries and module lists.
    """
    return deepcopy(PACKAGE_SUBSYSTEMS)


def __getattr__(name: str):
    """Provide lazy access to top-level adapter modules without eager import side-effects."""
    if name == "prometheus_loki_adapter":
        import prometheus_loki_adapter
        return prometheus_loki_adapter
    if name == "metrics_exporter":
        import metrics_exporter
        return metrics_exporter
    if name == "webhook_notifier":
        import webhook_notifier
        return webhook_notifier
    if name == "environment_adapters":
        import environment_adapters
        return environment_adapters
    if name == "pqc_security":
        import pqc_security
        return pqc_security
    if name == "action_cards":
        import action_cards
        return action_cards
    raise AttributeError(f"module 'opscryer' has no attribute '{name}'")


__all__ = ['__version__', 'PACKAGE_SUBSYSTEMS', 'get_package_architecture_map']

