# SPDX-License-Identifier: Apache-2.0
"""Suite HTML renderers and supporting catalogs from the top-level modules."""

from capacity_planner import render_capacity_planner_html
from environment_adapters import render_adapters_html
from executive_command_center import render_executive_command_center_html
from game_observability_loop import render_game_debug_html
from gameday_simulator import render_gameday_simulator_html
from gitops_release_cockpit import render_gitops_cockpit_html
from incident_commander import build_active_incidents_catalog, render_incident_commander_html
from jev_knowledge_explorer import (
    build_jev_knowledge_catalog,
    render_jev_knowledge_html,
    render_jev_knowledge_html as render_kb_explorer_html,
)
from live_metrics_poller import render_live_metrics_html
from model_tier_copilot import render_model_copilot_html
from network_topology_inspector import render_network_inspector_html
from openapi_spec import render_api_docs_html
from opscryer_browser import build_standalone_demo_dataset, render_standalone_browser_html
from opscryer_suite_hub import build_suite_application_catalog, render_suite_hub_html
from playbook_studio import build_playbook_studio_catalog, render_playbook_studio_html
from secops_vulnerability_cockpit import build_secops_posture_catalog, render_secops_cockpit_html
from storage_zfs_cockpit import render_storage_cockpit_html
from ticket_chat_portal import render_concierge_chat_html

__all__ = [
    'render_standalone_browser_html',
    'render_concierge_chat_html',
    'render_suite_hub_html',
    'render_incident_commander_html',
    'render_capacity_planner_html',
    'render_network_inspector_html',
    'render_gitops_cockpit_html',
    'render_executive_command_center_html',
    'render_gameday_simulator_html',
    'render_playbook_studio_html',
    'render_model_copilot_html',
    'render_game_debug_html',
    'render_kb_explorer_html',
    'render_storage_cockpit_html',
    'render_secops_cockpit_html',
    'render_live_metrics_html',
    'render_adapters_html',
    'render_api_docs_html',
    'render_jev_knowledge_html',
    'build_standalone_demo_dataset',
    'build_suite_application_catalog',
    'build_active_incidents_catalog',
    'build_jev_knowledge_catalog',
    'build_playbook_studio_catalog',
    'build_secops_posture_catalog',
]
