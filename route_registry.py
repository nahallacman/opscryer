# SPDX-License-Identifier: Apache-2.0
"""Inspectable metadata for the browser's canonical HTML and JSON routes.

This module performs no application imports or I/O. ``/portal`` is a legacy
alias for ``/chat`` and is not counted as a separate portal. API query parameter
sets describe accepted names; individual handlers still validate their values
and require ``q`` for chat-concierge and live-cluster-ask.
"""


HTML_PORTAL_ROUTES = (
    {"path": "/scale", "title": "Graph Scalability & Performance Benchmark", "subsystem": "portals", "module": "scale_benchmark"},
    {"path": "/", "title": "Spatial Graph Browser", "subsystem": "portals", "module": "opscryer_browser"},
    {"path": "/hub", "title": "Suite Hub", "subsystem": "portals", "module": "opscryer_suite_hub"},
    {"path": "/chat", "title": "Ticket Concierge", "subsystem": "portals", "module": "ticket_chat_portal"},
    {"path": "/incidents", "title": "Incident Commander", "subsystem": "portals", "module": "incident_commander"},
    {"path": "/capacity", "title": "Capacity Planner", "subsystem": "portals", "module": "capacity_planner"},
    {"path": "/network", "title": "Network Inspector", "subsystem": "portals", "module": "network_topology_inspector"},
    {"path": "/gitops", "title": "GitOps Cockpit", "subsystem": "portals", "module": "gitops_release_cockpit"},
    {"path": "/executive", "title": "Executive Command Center", "subsystem": "portals", "module": "executive_command_center"},
    {"path": "/simulator", "title": "Gameday Simulator", "subsystem": "portals", "module": "gameday_simulator"},
    {"path": "/playbooks", "title": "Playbook Studio", "subsystem": "portals", "module": "playbook_studio"},
    {"path": "/models", "title": "Model Copilot", "subsystem": "portals", "module": "model_tier_copilot"},
    {"path": "/games", "title": "Game Debug Loop", "subsystem": "portals", "module": "game_observability_loop"},
    {"path": "/kb", "title": "Knowledge Explorer", "subsystem": "portals", "module": "jev_knowledge_explorer"},
    {"path": "/storage", "title": "Storage Cockpit", "subsystem": "portals", "module": "storage_zfs_cockpit"},
    {"path": "/secops", "title": "SecOps Cockpit", "subsystem": "portals", "module": "secops_vulnerability_cockpit"},
    {"path": "/metrics-live", "title": "Live Metrics", "subsystem": "live", "module": "live_metrics_poller"},
    {"path": "/adapters", "title": "Environment Adapters", "subsystem": "portals", "module": "environment_adapters"},
    {"path": "/jev-eval", "title": "Jev Calibration Benchmark", "subsystem": "portals", "module": "jev_calibration_eval"},
    {"path": "/docs", "title": "API Documentation", "subsystem": "portals", "module": "openapi_spec"},
    {"path": "/tactical-deck", "title": "Tactical Security & Federation Deck", "subsystem": "portals", "module": "tactical_security_deck"},
)


API_V1_ROUTES = {
    "/api/v1/scale-benchmark": {
        "allowed_params": {"nodes"}, "module": "scale_benchmark", "subsystem": "portals",
        "description": "Synthetic graph scalability and local operation latencies."},
    "/api/v1/openapi.json": {
        "allowed_params": set(), "module": "openapi_spec", "subsystem": "portals",
        "description": "OpenAPI v3 endpoint specification."},
    "/api/v1/environment-adapters": {
        "allowed_params": {"adapter"}, "module": "environment_adapters", "subsystem": "portals",
        "description": "Environment adapter compatibility catalog."},
    "/api/v1/graph/catalog": {
        "allowed_params": {"live"}, "module": "cluster_diff_engine", "subsystem": "live",
        "description": "Snapshot graph with enriched currencies and optional live metrics."},
    "/api/v1/live-metrics": {
        "allowed_params": {"live"}, "module": "live_metrics_poller", "subsystem": "live",
        "description": "Offline metrics or explicitly requested live collection."},
    "/api/v1/two-act-status": {
        "allowed_params": {"act"}, "module": "opscryer_browser", "subsystem": "portals",
        "description": "Two-act demonstration status."},
    "/api/v1/dogfood-zoom": {
        "allowed_params": {"node_id", "zoom_level"}, "module": "dogfood_graph", "subsystem": "core",
        "description": "Progressive graph node disclosure."},
    "/api/v1/oscal-summary": {
        "allowed_params": set(), "module": "oscal_compliance", "subsystem": "security",
        "description": "Unassessed OSCAL compliance posture."},
    "/api/v1/live-cluster-health": {
        "allowed_params": set(), "module": "cluster_diff_engine", "subsystem": "live",
        "description": "Cluster snapshot health summary."},
    "/api/v1/live-cluster-currencies": {
        "allowed_params": set(), "module": "live_currencies", "subsystem": "live",
        "description": "Enriched cluster RTS currencies."},
    "/api/v1/live-cluster-ask": {
        "allowed_params": {"q"}, "module": "live_advisor", "subsystem": "live",
        "description": "Answer a required operational question."},
    "/api/v1/chat-concierge": {
        "allowed_params": {"q", "persona"}, "module": "ticket_chat_portal", "subsystem": "portals",
        "description": "Answer a required concierge question for a persona."},
    "/api/v1/chat-walkthrough": {
        "allowed_params": set(), "module": "chat_walkthrough", "subsystem": "portals",
        "description": "Simulated multi-persona chat walkthrough."},
    "/api/v1/incident-commander": {
        "allowed_params": set(), "module": "incident_commander", "subsystem": "portals",
        "description": "Active incident catalog."},
    "/api/v1/gameday-simulator": {
        "allowed_params": {"scenario"}, "module": "gameday_simulator", "subsystem": "portals",
        "description": "Offline gameday scenario simulation."},
    "/api/v1/playbook-studio": {
        "allowed_params": set(), "module": "playbook_studio", "subsystem": "portals",
        "description": "Operational playbook catalog."},
    "/api/v1/model-copilot": {
        "allowed_params": {"q"}, "module": "model_tier_copilot", "subsystem": "portals",
        "description": "Model benchmarks or dual-tier question comparison."},
    "/api/v1/game-debug-loop": {
        "allowed_params": {"game"}, "module": "game_observability_loop", "subsystem": "portals",
        "description": "Game server debugging trace."},
    "/api/v1/kb-explorer": {
        "allowed_params": {"q"}, "module": "jev_knowledge_explorer", "subsystem": "portals",
        "description": "Knowledge catalog with optional question search."},
    "/api/v1/jev-eval": {
        "allowed_params": {"provider"}, "module": "jev_calibration_eval", "subsystem": "portals",
        "description": "Labeled Jev predicate calibration benchmark and accuracy scorecard."},
    "/api/v1/storage-cockpit": {
        "allowed_params": set(), "module": "storage_zfs_cockpit", "subsystem": "portals",
        "description": "Storage topology summary."},
    "/api/v1/secops-cockpit": {
        "allowed_params": set(), "module": "secops_vulnerability_cockpit", "subsystem": "portals",
        "description": "Security operations posture catalog."},
    "/api/v1/capacity-planner": {
        "allowed_params": set(), "module": "capacity_planner", "subsystem": "portals",
        "description": "Cluster capacity summary."},
    "/api/v1/network-inspector": {
        "allowed_params": set(), "module": "network_topology_inspector", "subsystem": "portals",
        "description": "Ingress-to-hardware network routes."},
    "/api/v1/gitops-cockpit": {
        "allowed_params": set(), "module": "gitops_release_cockpit", "subsystem": "portals",
        "description": "Release readiness scorecard."},
    "/api/v1/executive-summary": {
        "allowed_params": set(), "module": "executive_command_center", "subsystem": "portals",
        "description": "Executive posture dossier."},
    "/api/v1/suite-catalog": {
        "allowed_params": set(), "module": "opscryer_suite_hub", "subsystem": "portals",
        "description": "Suite application catalog."},
    "/api/v1/live-cluster-chaos": {
        "allowed_params": set(), "module": "chaos_blast_radius", "subsystem": "security",
        "description": "Six-plane chaos isolation verification."},
    "/api/v1/live-cluster-oidc": {
        "allowed_params": set(), "module": "oidc_rbac_verifier", "subsystem": "security",
        "description": "Ingress OIDC posture audit."},
    "/api/v1/live-cluster-openbao": {
        "allowed_params": set(), "module": "openbao_kms_provenance", "subsystem": "security",
        "description": "OpenBao secret provenance audit."},
    "/api/v1/live-cluster-gitops": {
        "allowed_params": set(), "module": "live_gitops_signals", "subsystem": "live",
        "description": "Live GitOps and CI signals."},
    "/api/v1/contract": {
        "allowed_params": set(), "module": "opscryer_backend", "subsystem": "core",
        "description": "OpenAPI 3.1 contract for the separable spatial graph backend engine."},
    "/api/v1/graph/drilldown": {
        "allowed_params": {"node_id", "id"}, "module": "opscryer_backend", "subsystem": "core",
        "description": "Single entity drilldown inspection and containment children retrieval."},
    "/api/v1/graph/shortest-path": {
        "allowed_params": {"source_id", "target_id", "source", "target"}, "module": "opscryer_backend", "subsystem": "core",
        "description": "Minimum-hop path discovery between two spatial knowledge graph entities."},
    "/api/v1/graph/jev-tree": {
        "allowed_params": set(), "module": "opscryer_backend", "subsystem": "core",
        "description": "System One Jev decision tree with calibrated predicate evaluation nodes."},
    "/api/v1/graph/deflect-ticket": {
        "allowed_params": set(), "module": "opscryer_backend", "subsystem": "core",
        "description": "Deterministic Jev policy evaluation for IT ticket deflection guidance."},
    "/api/v1/graph/search": {
        "allowed_params": {"q", "limit"}, "module": "opscryer_backend", "subsystem": "core",
        "description": "Okapi BM25 full-text search across spatial knowledge graph entities."},
    "/api/v1/system-context": {
        "allowed_params": {"tier", "target_gpu", "q"}, "module": "system_context", "subsystem": "core",
        "description": "Dual-tier AI system context with sanitized GPU inventory, scale-down workloads, runbooks, and AST jump references."},
    "/api/v1/observability-signals": {
        "allowed_params": {"format", "service"}, "module": "prometheus_loki_adapter", "subsystem": "live",
        "description": "Aggregated Prometheus query signals, alert states, and Loki log stream status."},
    "/api/v1/actions/dry-run": {
        "allowed_params": set(), "module": "action_cards", "subsystem": "security",
        "description": "Dry-run blast-radius and outcome prediction preview for candidate actions."},
    "/api/v1/actions/stage": {
        "allowed_params": set(), "module": "action_cards", "subsystem": "security",
        "description": "Stage a cryptographically signed human-in-the-loop action card."},
    "/api/v1/actions/approve": {
        "allowed_params": set(), "module": "action_cards", "subsystem": "security",
        "description": "Approve and execute a staged action card with single or threshold credentials."},
    "/api/v1/actions/reject": {
        "allowed_params": set(), "module": "action_cards", "subsystem": "security",
        "description": "Explicitly reject a staged action card with an audit reason."},
    "/api/v1/actions/status": {
        "allowed_params": {"action_id", "status_filter", "limit"}, "module": "action_cards", "subsystem": "security",
        "description": "Query lifecycle status and cryptographic signatures of action cards."},
    "/api/v1/graph/delta": {
        "allowed_params": {"since_seq"}, "module": "event_stream", "subsystem": "live",
        "description": "Compact graph delta snapshot including added, updated, removed nodes and event log since sequence ID."},
    "/api/v1/events/stream": {
        "allowed_params": {"topics", "max_events"}, "module": "event_stream", "subsystem": "live",
        "description": "Server-Sent Events (SSE) real-time stream of graph, Jev, security, and action events with replay."},
    "/api/v1/security/ingest": {
        "allowed_params": set(), "module": "cybersecurity_bridge", "subsystem": "security",
        "description": "Ingest multi-standard security telemetry (OCSF, ECS, CEF, OTLP, Wazuh, Falco, Suricata, DefectDojo, Elastic, Loki) with Sigma evaluation and 1-hop graph enrichment."},
    "/api/v1/security/incidents": {
        "allowed_params": {"severity", "standard", "since_time", "limit"}, "module": "cybersecurity_bridge", "subsystem": "security",
        "description": "Query normalized, enriched cybersecurity incidents filtered by severity, standard, since_time, or limit."},
    "/api/v1/security/rules": {
        "allowed_params": {"limit"}, "module": "cybersecurity_bridge", "subsystem": "security",
        "description": "List active Sigma detection rules or register new rules dynamically."},
    "/api/v1/federation/status": {
        "allowed_params": set(), "module": "node_federation", "subsystem": "core",
        "description": "Federation cluster regime, active masters, node count, and vector clock summary."},
    "/api/v1/federation/heartbeat": {
        "allowed_params": set(), "module": "node_federation", "subsystem": "core",
        "description": "Submit node heartbeat and obtain master lease with current vector clock."},
    "/api/v1/federation/severance": {
        "allowed_params": set(), "module": "node_federation", "subsystem": "core",
        "description": "Evaluate node severance doctrine and execute quarantine or Encrypt-and-Rest seal."},
    "/api/v1/federation/reconcile": {
        "allowed_params": set(), "module": "node_federation", "subsystem": "core",
        "description": "Submit reconnected contingent delta log to Quarantine-Merge staging queue."},
    "/api/v1/mcp": {
        "allowed_params": set(), "module": "mcp_bridge", "subsystem": "security",
        "description": "Model Context Protocol (MCP) JSON-RPC 2.0 two-tier capability bridge."},
    "/api/v1/gitops-promotion/status": {
        "allowed_params": set(), "module": "gitops_promotion_bridge", "subsystem": "security",
        "description": "Two-stage GitOps dev-to-prod promotion gate status and SHA-256 bundle drift summary."},
    "/api/v1/gitops-promotion/stage": {
        "allowed_params": set(), "module": "gitops_promotion_bridge", "subsystem": "security",
        "description": "Stage a cryptographically signed promote_to_prod Action Card after dev gates pass."},
    "/api/v1/tactical-deck/summary": {
        "allowed_params": set(), "module": "tactical_security_deck", "subsystem": "portals",
        "description": "Unified RTS/TBS tactical security, federation, action card, and MCP summary payload."},
    "/api/v1/itsm/tickets": {
        "allowed_params": {"status", "provider", "limit"}, "module": "itsm_chatops_bridge", "subsystem": "security",
        "description": "Query correlated bi-directional ITSM tickets across GitLab Issues, ServiceNow, Jira, and PagerDuty."},
    "/api/v1/itsm/correlate": {
        "allowed_params": set(), "module": "itsm_chatops_bridge", "subsystem": "security",
        "description": "Correlate an OCSF/Sigma alert, Jev deflection, or Action Card into an idempotent ITSM ticket."},
    "/api/v1/itsm/chatops-callback": {
        "allowed_params": set(), "module": "itsm_chatops_bridge", "subsystem": "security",
        "description": "Process a cryptographically signed ChatOps approval, rejection, or Shamir share callback."},
    "/api/v1/flight-recorder/capsules": {
        "allowed_params": {"capsule_id"}, "module": "flight_recorder", "subsystem": "security",
        "description": "List pre-seeded and exported SHA3-256 hash-chained, WOTS+ signed Flight Recorder incident capsules."},
    "/api/v1/flight-recorder/export": {
        "allowed_params": set(), "module": "flight_recorder", "subsystem": "security",
        "description": "Export an OPSEC-scrubbed, SHA3-256 hash-chained, WOTS+ PQC-signed JSONL incident capsule."},
    "/api/v1/flight-recorder/replay": {
        "allowed_params": set(), "module": "flight_recorder", "subsystem": "security",
        "description": "Deterministically verify and replay a Flight Recorder incident capsule at 1x-100x speed."},
}


def get_allowed_api_params() -> dict[str, set[str]]:
    """Return a mapping of route path to set of allowed query parameters."""
    return {path: set(info.get("allowed_params", set())) for path, info in API_V1_ROUTES.items()}


def build_route_registry_summary() -> dict:
    """Return fresh HTML/API counts, including zero counts for each subsystem.

    Each route has one primary subsystem; security and live application portals
    retain their portal ownership, while metrics belongs to its live module.
    """
    grouped = {name: {"html_routes": 0, "api_routes": 0}
               for name in ("core", "live", "security", "portals")}
    for route in HTML_PORTAL_ROUTES:
        grouped[route["subsystem"]]["html_routes"] += 1
    for route in API_V1_ROUTES.values():
        grouped[route["subsystem"]]["api_routes"] += 1
    return {
        "total_html_routes": len(HTML_PORTAL_ROUTES),
        "total_api_routes": len(API_V1_ROUTES),
        "by_subsystem": grouped,
    }
