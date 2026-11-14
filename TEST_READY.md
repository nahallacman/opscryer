# Test Ready: OpsCryer Connectability & Extensibility E2E Test Suite

Published: 2026-10-31T01:52:00Z
Track: E2E Testing Track (teamwork_test_writer)
Test File: `scratch/opscryer-public-suite/tests/test_e2e_connectability_extensibility.py`

## Overview
Comprehensive, opaque-box E2E and integration test suite covering Tiers 1-4 for OpsCryer production connectability and extensibility features as specified in `PROJECT.md` and `TEST_INFRA.md`.

## Test Matrix & Coverage Summary

| # | Feature / Area | Tier 1 (Primary) | Tier 2 (Boundaries) | Tier 3 (Cross-Feature) | Tier 4 (Real-World) | Total Tests |
|---|----------------|:----------------:|:-------------------:|:----------------------:|:-------------------:|:-----------:|
| 1 | Unified Config Provider | 5 | 5 | Pairwise | ✓ | 10+ |
| 2 | Resilient HTTP Transport | 5 | 5 | Pairwise | ✓ | 10+ |
| 3 | Headless Piece B HTTP Bridge | 5 | 5 | Pairwise | ✓ | 10+ |
| 4 | Dual-Tier AI System Context Endpoint | 5 | 5 | Pairwise | ✓ | 10+ |
| 5 | Route Registry & OpenAPI Sync | 5 | 5 | Pairwise | ✓ | 10+ |
| 6 | Container Lifecycle Probes | 5 | 5 | Pairwise | ✓ | 10+ |
| 7 | Prometheus /metrics Exposition | 5 | 5 | Pairwise | ✓ | 10+ |
| 8 | Observability Adapter Registration | 5 | 5 | Pairwise | ✓ | 10+ |
| 9 | Structured Operational Logging | 5 | 5 | Pairwise | ✓ | 10+ |
| 10 | Outbound Alerting Webhook Sink | 5 | 5 | Pairwise | ✓ | 10+ |
| 11 | Extensible Adapter Registry | 5 | 5 | Pairwise | ✓ | 10+ |
| - | Cross-Feature Interactions (Tier 3) | - | - | 11 | - | 11 |
| - | Real-World Workload Scenarios (Tier 4) | - | - | - | 5 | 5 |
| **Total** | **All 11 Features + Tiers 1-4** | **55** | **55** | **11** | **5** | **126** |

## Tier Breakdown

### Tier 1: Primary Feature Coverage (55 tests)
- `TestTier1UnifiedConfig`: Default loading, file loading, env overrides, key traversal, secret masking.
- `TestTier1ResilientTransport`: GET execution, transient 500 retry, backoff delay, circuit breaker tripping, breaker isolation.
- `TestTier1PieceBHttpBridge`: Contract endpoint, search query, drilldown, shortest path, deflect ticket POST.
- `TestTier1SystemContext`: Status 200, schema version, GPU inventory, workloads & runbooks, AST jump references.
- `TestTier1RouteRegistry`: System context registration, Piece B route registration, metadata fields, OpenAPI spec sync, valid v3 document.
- `TestTier1LifecycleProbes`: Healthz OK status, uptime seconds, readyz status, graph loaded flag, airlock ready flag.
- `TestTier1PrometheusMetrics`: Content-Type header, cluster health gauge, HTTP request counter, uptime gauge, Prometheus 0.0.4 syntax.
- `TestTier1ObservabilityAdapter`: Route registration, signals endpoint, Prometheus query, Loki log query, graph conversion.
- `TestTier1StructuredLogging`: Configurable log level, structured fields, HTTP access logs, exception logging, JSON formatter.
- `TestTier1WebhookNotifier`: Schema version 1.0, required fields, HTTP 200/204 success, default config URL, degradation alert.
- `TestTier1AdapterRegistry`: Custom subclass registration, profile lookup, graph contract generation, compatibility matrix, builtin profile conformance.

### Tier 2: Boundary & Corner Cases (55 tests)
- `TestTier2UnifiedConfigBoundaries`: Missing file fallback, malformed JSON, empty key, token masking edge cases, type coercion.
- `TestTier2ResilientTransportBoundaries`: No retry on 404, timeout boundary, max_retries=0, malformed URL, Request object with custom headers.
- `TestTier2PieceBHttpBridgeBoundaries`: Empty search query, 404 on unknown drilldown node, disconnected shortest path, 400 on malformed ticket JSON, 405 on invalid HTTP methods.
- `TestTier2SystemContextBoundaries`: OPSEC verification (no private WAN IPs/tokens), offline hardware fallback, idempotency, direct function invocation, rejection of POST.
- `TestTier2RouteRegistryBoundaries`: Subsystem partitioning, trailing slash normalization, query param validation, OpenAPI POST operation schema, registry immutability.
- `TestTier2LifecycleProbesBoundaries`: HEAD /healthz, HEAD /readyz, unready 503 handling, 20-request burst load, query parameter tolerance.
- `TestTier2PrometheusMetricsBoundaries`: Label escaping, NaN/Inf handling, degraded cluster state (gauge 0), direct module format, empty catalog handling.
- `TestTier2ObservabilityAdapterBoundaries`: Upstream offline fallback, log secret redaction, reversed time window, empty upstream response, package namespace export.
- `TestTier2StructuredLoggingBoundaries`: Unknown log level fallback, auth token scrubbing, unicode/multiline safety, silent pass elimination, multi-thread concurrency safety.
- `TestTier2WebhookNotifierBoundaries`: Unreachable endpoint, 500 server error, payload OPSEC redaction, empty details dictionary, hanging receiver timeout.
- `TestTier2AdapterRegistryBoundaries`: Invalid class rejection, missing required attributes, unknown profile lookup, None spec fallback, registration isolation.

### Tier 3: Cross-Feature Pairwise Interactions (11 tests)
- `test_pairwise_config_and_webhook_dispatch`: Webhook notifier reads `OPSCRYER_WEBHOOK_URL` from unified config.
- `test_pairwise_config_and_resilient_transport`: Resilient transport loads retries and timeout from config.
- `test_pairwise_config_and_lifecycle_probes`: Probe `/readyz` validates config provider initialization.
- `test_pairwise_resilient_transport_and_observability_adapter`: Adapter utilizes `urlopen_with_retry` for upstream resilience.
- `test_pairwise_piece_b_bridge_and_route_registry`: Piece B endpoints are indexed in `route_registry.API_V1_ROUTES`.
- `test_pairwise_system_context_and_route_registry`: `/api/v1/system-context` registered in registry and OpenAPI spec.
- `test_pairwise_system_context_and_piece_b_graph`: AST jump references correlate to valid Piece B graph node IDs.
- `test_pairwise_lifecycle_probes_and_prometheus_metrics`: `/healthz` status is congruent with `opscryer_cluster_health_status` in `/metrics`.
- `test_pairwise_metrics_exporter_and_structured_logging`: Metrics scrape events generate structured audit logs.
- `test_pairwise_adapter_registry_and_piece_b_backend`: Bespoke graph produced by registered adapter is indexed and queried in Piece B engine.
- `test_pairwise_webhook_notifier_and_structured_logging`: Webhook dispatch events are audited through structured operational logger.

### Tier 4: Real-World Scenarios (5 tests)
1. `test_real_world_scenario_1_pod_crash_alert_pipeline`: Production pod crash triggers degraded `/healthz`, `/metrics` cluster health gauge 0, and critical outbound webhook notification.
2. `test_real_world_scenario_2_dual_tier_ai_knowledge_graph_and_ast_query`: AI agent queries `/api/v1/system-context`, searches graph, drills down, and submits ticket to `/api/v1/graph/deflect-ticket`.
3. `test_real_world_scenario_3_observability_jitter_and_circuit_breaker`: Upstream network flakiness retries with backoff and recovers; persistent failure trips circuit breaker with structured logs.
4. `test_real_world_scenario_4_dynamic_adapter_ingestion_and_graph_traversal`: Custom edge adapter registers, converts IoT hierarchy to graph contract, and Piece B navigates shortest path.
5. `test_real_world_scenario_5_full_cluster_health_scrape_and_metrics_export`: Complete operational scrape cycle across probes, `/metrics`, and structured logger without token leakage.

## Test Execution Commands

```powershell
# Run the complete connectability & extensibility test suite
python -m unittest tests/test_e2e_connectability_extensibility.py -v

# Run full project test discovery (baseline 196 tests + 126 new tests)
python -m unittest discover -s tests -v

# Run targeted fast test runner
python test_runner_fast.py

# Run ephemeral loopback runner
python live_e2e_runner.py --json

# Run pre-push golden path gates
python golden_path_gates.py
```

## Architectural & Design Invariants
1. **Zero External Dependencies**: Pure Python 3.11+ standard library (`unittest`, `urllib`, `json`, `http.server`, `socketserver`, `logging`).
2. **Dynamic Source-of-Truth Contracts**: No brittle hardcoded snapshot counts (User Directive #33).
3. **Fault Isolation**: Every test isolates network resources via `EphemeralHttpServer` using loopback port `0` and clean thread teardown.
4. **OPSEC Compliant**: Zero real tokens or external WAN IPs; synthetic prefixes are dynamically constructed to ensure scanner compliance.
5. **Traceability**: Annotated with `__epics__ = [{"epic": "E2E", "phases": ["T1", "T2", "T3", "T4"]}]`.
