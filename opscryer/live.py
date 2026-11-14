# SPDX-License-Identifier: Apache-2.0
"""Live cluster discovery, health, metrics, and operational advice."""

from cluster_diff_engine import summarize_live_cluster_health
from cluster_harvester import harvest_live_k8s_cluster, build_live_cluster_spatial_catalog
from live_advisor import answer_operational_question
from live_currencies import build_enriched_live_currencies
from live_gitops_signals import derive_live_gitops_and_ci_signals
from live_metrics_poller import poll_live_cluster_metrics
from metrics_exporter import (
    generate_latest_metrics,
    record_http_request,
    calculate_cluster_health_score,
)
from prometheus_loki_adapter import (
    OFFLINE_OBSERVABILITY_FIXTURE,
    collect_observability_signals,
    get_observability_signals_report,
    query_loki_signals,
    query_prometheus_signals,
    query_sanitized_observability_signals,
    signals_to_graph,
)
from webhook_notifier import (
    dispatch_webhook_event,
    notify_cluster_degraded,
    notify_hotspot_detected,
    notify_jev_escalation,
)

__all__ = [
    'harvest_live_k8s_cluster',
    'build_live_cluster_spatial_catalog',
    'summarize_live_cluster_health',
    'build_enriched_live_currencies',
    'poll_live_cluster_metrics',
    'answer_operational_question',
    'derive_live_gitops_and_ci_signals',
    'generate_latest_metrics',
    'record_http_request',
    'calculate_cluster_health_score',
    'query_sanitized_observability_signals',
    'get_observability_signals_report',
    'collect_observability_signals',
    'query_prometheus_signals',
    'query_loki_signals',
    'signals_to_graph',
    'OFFLINE_OBSERVABILITY_FIXTURE',
    'dispatch_webhook_event',
    'notify_cluster_degraded',
    'notify_hotspot_detected',
    'notify_jev_escalation',
]

