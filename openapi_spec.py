# SPDX-License-Identifier: Apache-2.0
"""OpenAPI 3.1 contract and dependency-free interactive API reference."""

from __future__ import annotations

import argparse
from copy import deepcopy
from html import escape
from http.server import ThreadingHTTPServer
import json


# Query names mirror the public browser handler; all operations are GET.
_ROUTES = {
    "scale-benchmark": ("Synthetic graph scalability benchmark", ("nodes",)),
    "graph/catalog": ("Spatial graph catalog", ("live",)),
    "two-act-status": ("Two-act browser status", ("act",)),
    "dogfood-zoom": ("Progressive graph zoom", ("node_id", "zoom_level")),
    "oscal-summary": ("Unassessed OSCAL posture summary", ()),
    "live-cluster-health": ("Cluster health snapshot", ()),
    "live-cluster-currencies": ("Cluster RTS currencies", ()),
    "live-cluster-ask": ("Grounded operational answer", ("q",)),
    "chat-concierge": ("Persona-based concierge answer", ("q", "persona")),
    "chat-walkthrough": ("Simulated chat walkthrough", ()),
    "incident-commander": ("Active incidents catalog", ()),
    "gameday-simulator": ("Offline gameday simulation", ("scenario",)),
    "playbook-studio": ("Playbook catalog", ()),
    "model-copilot": ("Model benchmarks or question comparison", ("q",)),
    "game-debug-loop": ("Game debugging trace", ("game",)),
    "capacity-planner": ("Cluster capacity summary", ()),
    "network-inspector": ("Ingress-to-hardware routes", ()),
    "gitops-cockpit": ("Release readiness scorecard", ()),
    "executive-summary": ("Executive posture dossier", ()),
    "suite-catalog": ("Suite application catalog", ()),
    "live-cluster-chaos": ("Six-plane chaos verification", ()),
    "live-cluster-oidc": ("Ingress OIDC posture audit", ()),
    "live-cluster-openbao": ("OpenBao secret provenance audit", ()),
    "live-cluster-gitops": ("GitOps and CI signals", ()),
    "kb-explorer": ("Knowledge catalog or search", ("q",)),
    "jev-eval": ("Labeled Jev calibration benchmark", ("provider",)),
    "storage-cockpit": ("Storage topology summary", ()),
    "secops-cockpit": ("Security posture catalog", ()),
    "live-metrics": ("Cluster metrics snapshot", ("live",)),
    "environment-adapters": ("Environment adapter compatibility", ("adapter",)),
    "openapi.json": ("OpenAPI 3.1 contract", ()),
    "contract": ("Separable spatial graph OpenAPI contract", ()),
    "graph/drilldown": ("Spatial graph node drilldown", ("node_id", "id")),
    "graph/shortest-path": ("Minimum-hop graph path discovery", ("source_id", "target_id", "source", "target")),
    "graph/jev-tree": ("System One Jev decision tree", ()),
    "graph/deflect-ticket": ("Jev ticket deflection guidance", ()),
    "graph/search": ("Okapi BM25 spatial graph search", ("q", "limit")),
    "system-context": ("Dual-tier AI system context", ("tier", "target_gpu", "q")),
    "observability-signals": ("Aggregated Prometheus query signals, alert states, and Loki log stream status", ("format", "service")),
    "actions/dry-run": ("Simulate blast radius and evaluate outcome worrisomeness for candidate remediation action", ()),
    "actions/stage": ("Stage a cryptographically signed human-in-the-loop action card bound to parameter hash", ()),
    "actions/approve": ("Submit authorization credentials to approve and execute a staged action card", ()),
    "actions/reject": ("Explicitly cancel a staged action card with an audit reason", ()),
    "actions/status": ("Retrieve the lifecycle status, threshold progress, and cryptographic metadata of action cards", ("action_id", "status_filter", "limit")),
    "graph/delta": ("Compact graph delta snapshot since sequence ID", ("since_seq",)),
    "events/stream": ("Server-Sent Events streaming real-time operational events", ("topics", "max_events")),
    "security/ingest": ("Ingest multi-standard security telemetry with Sigma evaluation and 1-hop enrichment", ()),
    "security/incidents": ("Query normalized and enriched cybersecurity incidents", ("severity", "standard", "since_time", "limit")),
    "security/rules": ("List or dynamically register Sigma detection rules", ("limit",)),
    "federation/status": ("Cluster regime, active masters, node count, and vector clock summary", ()),
    "federation/heartbeat": ("Submit node heartbeat and obtain master lease with current vector clock", ()),
    "federation/severance": ("Evaluate node severance doctrine and execute quarantine or Encrypt-and-Rest seal", ()),
    "federation/reconcile": ("Submit reconnected contingent delta log to Quarantine-Merge staging queue", ()),
    "mcp": ("Model Context Protocol (MCP) JSON-RPC 2.0 two-tier capability bridge", ()),
    "gitops-promotion/status": ("Two-stage GitOps dev-to-prod promotion gate status and SHA-256 bundle drift summary", ()),
    "gitops-promotion/stage": ("Stage a cryptographically signed promote_to_prod Action Card after dev gates pass", ()),
    "tactical-deck/summary": ("Unified RTS/TBS tactical security, federation, action card, and MCP summary payload", ()),
    "itsm/tickets": ("Query correlated bi-directional ITSM tickets across GitLab Issues, ServiceNow, Jira, and PagerDuty", ("status", "provider", "limit")),
    "itsm/correlate": ("Correlate an OCSF/Sigma alert, Jev deflection, or Action Card into an idempotent ITSM ticket", ()),
    "itsm/chatops-callback": ("Process a cryptographically signed ChatOps approval, rejection, or Shamir share callback", ()),
    "flight-recorder/capsules": ("List pre-seeded and exported SHA3-256 hash-chained, WOTS+ signed Flight Recorder incident capsules", ("capsule_id",)),
    "flight-recorder/export": ("Export an OPSEC-scrubbed, SHA3-256 hash-chained, WOTS+ PQC-signed JSONL incident capsule", ()),
    "flight-recorder/replay": ("Deterministically verify and replay a Flight Recorder incident capsule at 1x-100x speed", ()),
}

_PARAMETERS = {
    "nodes": ({"type": "integer", "minimum": 10, "maximum": 5000},
              "Synthetic node count; omit to benchmark 100, 500, and 1500 nodes."),
    "live": ({"type": "string", "enum": ["0", "1"], "default": "0"},
              "Use 1 to poll live cluster metrics via kubectl; 0 uses offline data."),
    "act": ({"type": "integer", "enum": [1, 2], "default": 1}, "Browser act."),
    "node_id": ({"type": "string", "default": "root-company"}, "Dogfood graph node ID."),
    "zoom_level": ({"type": "integer", "minimum": 0, "maximum": 4, "default": 0},
                   "Progressive detail level, from 0 through 4."),
    "q": ({"type": "string", "minLength": 1},
          "Nonblank question or search text; control characters are rejected. "
          "Omit for the model benchmark matrix or unfiltered knowledge catalog."),
    "persona": ({"type": "string", "enum": ["household_user", "developer", "executive", "sre"],
                 "default": "household_user"}, "Concierge persona."),
    "scenario": ({"type": "string", "default": "node_down_nodebeta02"},
                 "Supported gameday scenario ID."),
    "game": ({"type": "string", "default": "minecraft"}, "Supported game profile ID."),
    "adapter": ({"type": "string"}, "Supported adapter profile name; omit to list all adapters."),
    "provider": ({"type": "string", "enum": ["deterministic", "ollama", "ollama_single_token"],
                  "default": "deterministic"}, "Jev predicate evaluation provider."),
    "id": ({"type": "string", "default": "root-company"}, "Alias for node_id."),
    "source_id": ({"type": "string", "default": "team-demo-platform"}, "Source graph entity ID for path traversal."),
    "target_id": ({"type": "string", "default": "proc-demo-cicd"}, "Target graph entity ID for path traversal."),
    "source": ({"type": "string", "default": "team-demo-platform"}, "Alias for source_id."),
    "target": ({"type": "string", "default": "proc-demo-cicd"}, "Alias for target_id."),
    "limit": ({"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
              "Maximum number of BM25 search results or action cards to return."),
    "tier": ({"type": "string", "enum": ["both", "local_gpu", "frontier"], "default": "both"},
             "Target model context tier."),
    "target_gpu": ({"type": "string"}, "Specific GPU model identifier."),
    "format": ({"type": "string", "enum": ["summary", "full"], "default": "full"},
               "Observability signal detail format; 'summary' aggregates overall status, 'full' includes raw streams."),
    "service": ({"type": "string"},
                "Optional case-insensitive substring filter for signal IDs, PromQL expressions, or Loki log streams."),
    "action_id": ({"type": "string"}, "Unique identifier of the target action card."),
    "status_filter": ({"type": "string", "enum": ["STAGED", "APPROVED", "REJECTED", "EXECUTED", "EXPIRED"]},
                      "Filter action cards by lifecycle status; omit to list all cards."),
    "since_seq": ({"type": "integer", "minimum": 0, "default": 0},
                  "Sequence ID baseline; events and node mutations after this sequence are returned. Omit or 0 to request full state."),
    "topics": ({"type": "string", "default": "graph,jev,security,actions"},
               "Comma-separated list of event topics to subscribe to (e.g. graph,jev,security,actions)."),
    "max_events": ({"type": "integer", "minimum": 1},
                   "Maximum number of events to receive before closing stream; enables deterministic testing and CLI execution."),
    "severity": ({"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
                 "Filter incidents by severity level; omit to return all severities."),
    "standard": ({"type": "string", "enum": ["ocsf", "ecs", "cef", "otlp", "wazuh", "falco", "suricata", "defectdojo", "elastic", "loki"]},
                 "Filter incidents by original telemetry schema or source connector format."),
    "since_time": ({"type": "string"},
                   "ISO 8601 timestamp baseline; incidents recorded after this timestamp are returned."),
    "status": ({"type": "string", "enum": ["OPEN", "IN_PROGRESS", "MITIGATING", "RESOLVED", "CLOSED"]},
               "Filter ITSM tickets by lifecycle status; omit to return all tickets."),
    "capsule_id": ({"type": "string"},
                   "Filter or inspect a specific Flight Recorder incident capsule ID; omit to list all capsules."),
}

_ROUTE_METHODS: dict[str, str] = {
    "graph/deflect-ticket": "post",
    "actions/dry-run": "post",
    "actions/stage": "post",
    "actions/approve": "post",
    "actions/reject": "post",
    "security/ingest": "post",
    "security/rules": "post",
    "federation/heartbeat": "post",
    "federation/severance": "post",
    "federation/reconcile": "post",
    "mcp": "post",
    "gitops-promotion/stage": "post",
    "itsm/correlate": "post",
    "itsm/chatops-callback": "post",
    "flight-recorder/export": "post",
    "flight-recorder/replay": "post",
}


def build_openapi_v3_spec() -> dict:
    """Return a fresh, JSON-serializable OpenAPI 3.1.0 contract."""
    paths = {}
    for route, (summary, names) in _ROUTES.items():
        parameters = []
        for name in names:
            schema, description = _PARAMETERS[name]
            is_required = (
                (name == "q" and route in {"live-cluster-ask", "chat-concierge", "graph/search"})
                or (name == "node_id" and route == "graph/drilldown")
                or (name in {"source_id", "target_id"} and route == "graph/shortest-path")
            )
            parameters.append({
                "name": name, "in": "query",
                "required": is_required,
                "description": description, "schema": deepcopy(schema),
            })
        responses = {
            "200": {"description": "Successful JSON response.", "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
            "400": {"$ref": "#/components/responses/BadQuery"},
        }
        if route in {"dogfood-zoom", "graph/drilldown"}:
            responses["404"] = {"description": "Unknown node ID.", "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}
        if route in {"live-cluster-ask", "chat-concierge", "model-copilot"}:
            responses["403"] = {"description": "Question blocked by the security airlock.",
                                "content": {"application/json": {
                                    "schema": {"$ref": "#/components/schemas/JsonObject"}}}}
        get_op = {
            "operationId": "get_" + route.replace("/", "_").replace("-", "_").replace(".", "_"),
            "summary": summary,
            "description": "Only the listed query parameters are accepted, once each. "
                           "Unknown, repeated, or malformed parameters return 400.",
            "parameters": parameters, "responses": responses,
        }
        paths["/api/v1/" + route] = {"get": get_op}
        if route == "graph/deflect-ticket":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_graph_deflect_ticket",
                "summary": summary,
                "description": "Deterministic Jev policy evaluation for IT ticket deflection guidance.",
                "requestBody": {
                    "required": True,
                    "description": "IT support ticket parameters for deflection evaluation.",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["ticket_title"],
                                "properties": {
                                    "ticket_title": {
                                        "type": "string",
                                        "minLength": 1,
                                        "description": "Title or summary of the IT support ticket.",
                                    },
                                    "ticket_text": {
                                        "type": "string",
                                        "minLength": 1,
                                        "description": "Alternative alias for ticket text or description.",
                                    },
                                    "min_confidence": {
                                        "type": "number",
                                        "minimum": 0.80,
                                        "maximum": 1.0,
                                        "default": 0.80,
                                        "description": "Minimum calibrated confidence required for automated leaf routing.",
                                    },
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Successful ticket deflection decision.",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TicketDeflectionResult"}}},
                    },
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route == "actions/dry-run":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_actions_dry_run",
                "summary": summary,
                "description": "Simulate blast radius and outcome prediction for candidate action.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Dry-run outcome preview.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                    "404": {"description": "Target node not found.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            }
        elif route == "actions/stage":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_actions_stage",
                "summary": summary,
                "description": "Stage a cryptographically signed Action Card.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Staged action card.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                    "404": {"description": "Target node not found.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            }
        elif route == "actions/approve":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_actions_approve",
                "summary": summary,
                "description": "Approve and execute a staged Action Card.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Approval status or execution result.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                    "404": {"description": "Action card not found.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "409": {"description": "Conflict (tamper detected, card expired, or rejected).", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            }
        elif route == "actions/reject":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_actions_reject",
                "summary": summary,
                "description": "Reject a staged Action Card.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Rejection confirmation.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                    "404": {"description": "Action card not found.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                    "409": {"description": "Cannot reject already executed action.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            }
        elif route == "security/ingest":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_security_ingest",
                "summary": summary,
                "description": "Ingest raw security telemetry across 10 standards with Sigma rule evaluation and 1-hop graph enrichment.",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["standard", "payload"],
                                "properties": {
                                    "standard": {
                                        "type": "string",
                                        "enum": ["ocsf", "ecs", "cef", "otlp", "wazuh", "falco", "suricata", "defectdojo", "elastic", "loki"],
                                        "description": "Format or connector standard of the inbound payload.",
                                    },
                                    "payload": {
                                        "description": "Raw security event payload (JSON object, string, or list).",
                                    },
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Telemetry normalized, evaluated, and enriched successfully.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route == "security/rules":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_security_rules",
                "summary": "Register a new Sigma detection rule",
                "description": "Dynamically register a new Sigma detection rule in the evaluation engine.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "201": {"description": "Rule registered successfully.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route == "federation/heartbeat":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_federation_heartbeat",
                "summary": summary,
                "description": "Submit node heartbeat with trust tier certificate and canary proof.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Heartbeat accepted and lease renewed.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route == "federation/severance":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_federation_severance",
                "summary": summary,
                "description": "Evaluate node severance doctrine (Encrypt-and-Rest vs Persist-Resist-Regrow).",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Severance transition evaluated.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route == "federation/reconcile":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_federation_reconcile",
                "summary": summary,
                "description": "Submit quarantined contingent delta log for Quarantine-Merge review.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Delta log queued in Quarantine-Merge staging.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route == "mcp":
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_mcp",
                "summary": summary,
                "description": "JSON-RPC 2.0 Model Context Protocol endpoint.",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "JSON-RPC 2.0 response object.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
        elif route in {
            "gitops-promotion/stage",
            "itsm/correlate",
            "itsm/chatops-callback",
            "flight-recorder/export",
            "flight-recorder/replay",
        }:
            paths["/api/v1/" + route]["post"] = {
                "operationId": "post_" + route.replace("/", "_").replace("-", "_").replace(".", "_"),
                "summary": summary,
                "description": summary,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}},
                },
                "responses": {
                    "200": {"description": "Successful JSON response.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/JsonObject"}}}},
                    "400": {"$ref": "#/components/responses/BadQuery"},
                },
            }
    return {
        "openapi": "3.1.0",
        "info": {"title": "OpsCryer API", "version": "1.0.0",
                 "description": "Read-only browser API contract. Response objects vary by endpoint; "
                                "telemetry may be offline or simulated.",
                 "license": {"name": "Apache License, Version 2.0", "identifier": "Apache-2.0"}},
        "servers": [{"url": "/", "description": "Current OpsCryer server"}],
        "paths": paths,
        "components": {
            "schemas": {
                "JsonObject": {"type": "object", "additionalProperties": True},
                "Error": {"type": "object", "required": ["error"],
                          "properties": {"error": {"type": "string"}}},
                "SystemContext": {
                    "type": "object",
                    "required": ["schema_version", "gpu_inventory", "scale_down_workloads", "active_kb_runbooks", "ast_jump_references"],
                    "properties": {
                        "schema_version": {"type": "string", "enum": ["1.0-system-context"]},
                        "gpu_inventory": {"type": "array", "items": {"type": "object"}},
                        "scale_down_workloads": {"type": "array", "items": {"type": "object"}},
                        "active_kb_runbooks": {"type": "array", "items": {"type": "object"}},
                        "ast_jump_references": {"type": "object", "additionalProperties": True},
                    },
                },
                "TicketDeflectionResult": {
                    "type": "object",
                    "required": ["schema_version", "route", "direct_access_allowed"],
                    "properties": {
                        "schema_version": {"type": "string"},
                        "route": {"type": "string"},
                        "policy_id": {"type": ["string", "null"]},
                        "direct_access_allowed": {"type": "boolean"},
                        "required_it_tickets": {"type": "array", "items": {"type": "string"}},
                        "anchor_node_id": {"type": ["string", "null"]},
                        "traversal_steps": {"type": "array", "items": {"type": "object"}},
                    },
                },
                "ObservabilitySignals": {
                    "type": "object",
                    "required": ["schema_version", "telemetry_mode", "live_http_active", "signals"],
                    "properties": {
                        "schema_version": {"type": "string"},
                        "telemetry_mode": {"type": "string"},
                        "live_http_active": {"type": "boolean"},
                        "overall_status": {"type": "string", "enum": ["nominal", "degraded", "critical"]},
                        "service_filter": {"type": ["string", "null"]},
                        "signals": {"type": "array", "items": {"type": "object"}},
                        "prometheus_signals": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["signal_id", "promql", "value", "unit", "status"],
                                "properties": {
                                    "signal_id": {"type": "string"},
                                    "promql": {"type": "string"},
                                    "value": {"type": "number"},
                                    "unit": {"type": "string"},
                                    "status": {"type": "string"},
                                },
                            },
                        },
                        "alert_states": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["alert_name", "severity", "state", "active"],
                                "properties": {
                                    "alert_name": {"type": "string"},
                                    "severity": {"type": "string"},
                                    "state": {"type": "string"},
                                    "active": {"type": "boolean"},
                                },
                            },
                        },
                        "loki_log_summaries": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["stream", "sample_line", "error_count_5m"],
                                "properties": {
                                    "stream": {"type": "string"},
                                    "sample_line": {"type": "string"},
                                    "error_count_5m": {"type": "integer"},
                                },
                            },
                        },
                        "noc_catalog_count": {"type": "integer"},
                        "summary": {
                            "type": "object",
                            "properties": {
                                "total_prometheus_signals": {"type": "integer"},
                                "nominal_signals": {"type": "integer"},
                                "warning_signals": {"type": "integer"},
                                "critical_signals": {"type": "integer"},
                                "total_loki_streams": {"type": "integer"},
                                "total_loki_errors_5m": {"type": "integer"},
                                "active_alert_count": {"type": "integer"},
                            },
                        },
                        "alerts": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
            "responses": {"BadQuery": {
                "description": "Invalid, unknown, repeated, or malformed query parameters.",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
            }},
        },
    }


def build_openapi_spec() -> dict:
    """Compatibility alias for build_openapi_v3_spec supporting OpenAPI 3.0 and 3.1 contracts."""
    spec = deepcopy(build_openapi_v3_spec())
    spec["openapi"] = "3.0.3"
    return spec


def render_api_docs_html() -> str:
    """Render all endpoints and same-origin live GET/POST forms without CDN assets."""
    sections = []
    for path, item in build_openapi_v3_spec()["paths"].items():
        for method_name in ("get", "post"):
            if method_name not in item:
                continue
            operation = item[method_name]
            method_upper = method_name.upper()
            fields = []
            for parameter in operation.get("parameters", []):
                schema = parameter["schema"]
                details = parameter["description"]
                if "enum" in schema:
                    details += " Allowed: " + ", ".join(map(str, schema["enum"])) + "."
                if "default" in schema:
                    details += " Default: " + str(schema["default"]) + "."
                if "minimum" in schema:
                    if "maximum" in schema:
                        details += f" Range: {schema['minimum']}–{schema['maximum']}."
                    else:
                        details += f" Minimum: {schema['minimum']}."
                name = escape(parameter["name"], quote=True)
                field_id = escape(path + "-" + parameter["name"], quote=True)
                required = " required" if parameter["required"] else ""
                fields.append(
                    f'<label for="{field_id}">{name} ({schema["type"]}, '
                    f'{"required" if required else "optional"})</label>'
                    f'<input id="{field_id}" name="{name}" type="text"{required}>'
                    f'<small>{escape(details)}</small>')

            if method_name == "post":
                fields.append(
                    f'<label for="{escape(path)}-body">JSON Request Body</label>'
                    f'<textarea id="{escape(path)}-body" name="json_body" rows="4" style="width:100%;box-sizing:border-box">'
                    f'{{"ticket_title": "deploy 3-tier scaffolding project", "min_confidence": 0.80}}</textarea>'
                )

            sections.append(
                f'<section><h2>{method_upper} {escape(path)}</h2><p>{escape(operation["summary"])}</p>'
                f'<form data-path="{escape(path, quote=True)}" data-method="{method_upper}">'
                + ("".join(fields) or "<p>No query parameters allowed.</p>")
                + f'<button type="submit">Test {method_upper}</button></form>'
                '<pre role="status" aria-live="polite">Response will appear here.</pre></section>')
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpsCryer · OpenAPI 3.1 Contract & Endpoint Explorer</title>
<style>
body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;background:#101827;color:#e5edf8}
a{color:#7dd3fc}section{border:1px solid #536179;border-radius:8px;padding:1rem;margin:1rem 0}
h2{font-size:1.1rem;overflow-wrap:anywhere}label,small{display:block;margin:.5rem 0}
input{box-sizing:border-box;width:100%;padding:.5rem}button{padding:.6rem 1rem;margin-top:1rem;cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:32rem;overflow:auto}small{color:#bac9dc}
</style></head><body><h1>OpsCryer API reference</h1>
<p>OpenAPI 3.1.0 · <a href="/api/v1/openapi.json">Download JSON contract</a></p>
<p>Test GET/POST endpoints against this server. Optional blank inputs are omitted.
Unknown or repeated parameters return 400. Live requests may poll cluster telemetry;
question endpoints may invoke configured model services.</p>
""" + "".join(sections) + """
<script>
document.querySelectorAll('form[data-path]').forEach(form => {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const output = form.parentElement.querySelector('pre');
    const button = form.querySelector('button');
    const method = form.dataset.method || 'GET';
    const url = new URL(form.dataset.path, window.location.origin);
    let options = {method: method, headers: {Accept: 'application/json'}};
    if (method === 'POST') {
      const textarea = form.querySelector('textarea[name="json_body"]');
      options.headers['Content-Type'] = 'application/json';
      options.body = textarea ? textarea.value : '{}';
    } else {
      for (const [name, value] of new FormData(form)) {
        if (value !== '') url.searchParams.set(name, value);
      }
    }
    button.disabled = true;
    output.textContent = 'Loading ' + url.pathname + url.search + ' …';
    try {
      const response = await fetch(url, options);
      const body = await response.text();
      let formatted = body;
      try { formatted = JSON.stringify(JSON.parse(body), null, 2); } catch (_) {}
      output.textContent = 'HTTP ' + response.status + ' ' + response.statusText + '\\n' + formatted;
    } catch (error) {
      output.textContent = 'Request failed: ' + error.message;
    } finally { button.disabled = false; }
  });
});
</script></body></html>
"""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Report CLI errors without reflecting potentially sensitive input."""

    def error(self, message):
        super().error("Invalid OpenAPI arguments")


def main(argv: list[str] | None = None) -> int:
    """Print the contract or serve the portal and browser API on loopback."""
    parser = _SafeArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--json", action="store_true", help="Print OpenAPI JSON (default)")
    modes.add_argument("--serve", action="store_true", help="Serve the interactive reference")
    parser.add_argument("--port", type=int, default=8106)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.serve:
        from opscryer_browser import _build_frontend_handler

        class DocsHandler(_build_frontend_handler()):
            def do_GET(self) -> None:
                if self.path == "/":
                    self.path = "/docs"
                super().do_GET()

        with ThreadingHTTPServer(("127.0.0.1", args.port), DocsHandler) as server:
            print(f"OpsCryer API docs: http://127.0.0.1:{args.port}/docs", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    else:
        print(json.dumps(build_openapi_v3_spec(), indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
