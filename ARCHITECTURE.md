<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpsCryer Architecture

OpsCryer organizes graph queries, local decision routing, telemetry, security,
and presentation behind four public Python subsystems. The implementation uses
the Python standard library and is licensed under Apache License, Version 2.0
in `LICENSE`.

## 1. Package & Subsystem Organization

The `opscryer` package provides a stable namespace over the existing top-level
modules. These modules remain importable for compatibility; shared modules can
belong to more than one subsystem. Importing a subsystem starts no network
collection or subprocesses. `opscryer.get_package_architecture_map()` returns an
independent copy of the subsystem responsibilities and module inventory.

| Public subsystem | Responsibilities and implementation |
| --- | --- |
| `opscryer.core` | SpatialGraphContract v1 validation, knowledge graph queries, canonical knowledge base (`knowledge_base.py`), and Jev ticket routing (`jev_client.py` + `jev_calibration_eval.py`). Re-exports `KnowledgeGraphBackendEngine` from `opscryer_backend.py`, the client and traversal functions from `jev_client.py`, and progressive graph queries from `dogfood_graph.py`. |
| `opscryer.live` | Cluster discovery, snapshot health, node metrics, seven RTS currencies, GitOps signals, and grounded operational advice. Wraps `cluster_harvester.py`, `cluster_diff_engine.py`, `live_metrics_poller.py`, `live_currencies.py`, `live_gitops_signals.py`, and `live_advisor.py`. |
| `opscryer.security` | Telemetry redaction, graph-search airlock policy, container-context audits, OSCAL reports, OpenBao provenance, OIDC posture, and chaos simulations. Re-exports the corresponding security library functions; posture reports describe supplied evidence. |
| `opscryer.portals` | HTML renderers and application catalogs for the spatial browser, concierge, suite hub, knowledge explorer, metrics, adapter studio, and operations cockpits. Composes the same core, live, and security library surfaces. |

`opscryer_cli.py` is the unified reporting entry point, also installed as
`opscryer`. All five commands support `--json`; reports pass through the telemetry
sanitizer before printing. Run these examples from the repository root:

```powershell
python opscryer_cli.py doctor --json
python opscryer_cli.py metrics --json
python opscryer_cli.py metrics --live --json
python opscryer_cli.py routes --json
python opscryer_cli.py adapters --adapter local_host --json
python opscryer_cli.py ask --question "Manifest game server pods are down" --persona household_user --json
```

`doctor` reports runtime capabilities, package organization, and route counts.
`metrics` reads a snapshot by default; `--live` permits kubectl collection.
`routes` lists registered portals and API metadata. `adapters` reports all
environments or one selected profile. `ask` invokes the ticket concierge;
personas affect presentation and confer no additional access.

## 2. Single-Token System-1 Jev Decision Tree & Knowledge Graph Lookup Architecture

The architecture separates expensive knowledge authoring from small, bounded
runtime decisions. In the offline authoring workflow, frontier models help
organize sanitized evidence into graph nodes, dependency edges, predicate
definitions, and decision trees. Authors review policy leaves, graph anchors,
and required IT tickets, then validate and publish the graph/tree artifacts.
This is an authoring workflow: the repository ships example artifacts and
validators rather than an automated frontier-model graph builder.

At runtime, a small local laptop model evaluates one boolean predicate at each
decision node. Application code follows `true_branch` or `false_branch` until a
leaf supplies the reviewed policy and its `anchor_node_id`. Graph lookup then
provides related assets, dependencies, runbooks, or escalation paths. The
knowledge graph backend supplies BM25 search, drilldown, and shortest paths;
`jev_knowledge_explorer.py` presents knowledge and decision-path evidence.

Single-token describes the intended boolean decision unit. The shipped
`SystemOneJevClient` in `jev_client.py` returns structured JSON containing
`predicate_id`, `evaluated_value`, and `calibrated_probability`; its full response
is not literally one generated token. The default provider uses deterministic
demo rules. The optional `ollama` provider sends a constrained JSON schema to a
local `/api/chat` endpoint. Runtime traversal needs no frontier-model call.

`evaluate_ticket_with_jev_tree()` validates the response and traversal structure
before advancing. Confidence in the chosen boolean must be at least 0.80 (or a
higher configured/tree threshold); a confident false follows the false branch.
Invalid JSON, mismatched predicates, malformed branches, cycles, provider errors,
and low confidence stop at `human_escalation` with direct access denied. A valid
leaf preserves its access policy and required tickets. Model confidence needs
evaluation against labeled examples; demo probabilities are synthetic.

## 3. Live Telemetry & Metrics Poller vs. Sanitized Snapshot Airlock

`live_metrics_poller.py` aggregates observations through
`poll_live_cluster_metrics(allow_kubectl=False, ttl_seconds=10, catalog=None)`.
It reports node CPU/RAM and readiness, namespace pod pressure, health, and seven
RTS currencies. Normal calls read the bundled sanitized snapshot, or a supplied
catalog. Explicit `allow_kubectl=True` permits bounded, read-only collection via
`cluster_harvester.py`; collection failure returns a labeled snapshot fallback.
Responses expose `telemetry_mode`, `live_kubectl_active`, and `freshness_label`.
The TTL cache returns independent copies and does not start a background daemon.
The `/metrics-live` portal consumes `/api/v1/live-metrics`; `live=1` opts into
collection. Snapshot provenance must be considered when interpreting health.

The sanitized snapshot airlock consists of two separate boundaries:

1. `telemetry_sanitizer.py` recursively redacts payloads without mutating their
   inputs. Authorized telemetry must be sanitized before rendering, logging,
   exporting, or sending it to a model. Public WAN IPv4 becomes `203.0.113.1`,
   MAC suffixes become `AA:BB:CC:XX:XX:XX`, and credential material is redacted.
   RFC 1918 LAN addresses and `.cluster.example.org` names remain usable. Credentials and
   environment secret files stay outside the checkout.
2. `security_airlock.py` gates graph-only manifest/dependency discovery through
   `evaluate_code_search_airlock()`. Secret-hunting indicators and unsupported
   intent fail closed before graph lookup. Allowed requests receive restricted
   graph identity metadata and escalation paths. The separate
   `audit_container_security_context()` checks supplied container settings.

The poller gathers and summarizes evidence; sanitization controls disclosure;
the search airlock controls allowed query intent. Redaction alone grants no
access. The poller sanitizes catalogs and final reports, while advisor and
concierge flows apply the query airlock before returning grounded answers.
`live_poller.py` separately supports continuous snapshot polling and atomic
catalog export, retaining the last known-good live snapshot on collection failure.

## 4. Multi-Environment Compatibility Adapters & OpenAPI 3.1 Contract

`environment_adapters.py` normalizes parsed infrastructure inventories into
sanitized, validated SpatialGraphContract v1 catalogs with nodes, edges, graph
anchors, and RTS currency metadata. Its adapters use supplied data or offline
reference examples. They do not execute deployment tools or discover hosts.

| Environment | Profile | Input and graph mapping |
| --- | --- | --- |
| Kubernetes | `kubernetes` | Bundled Kubernetes reference catalog; live cluster inventory is collected separately by the explicit harvester/poller path. |
| Docker Compose | `docker_compose` | Parsed Compose specifications mapped into services, containers, networks, volumes, and dependencies. |
| Terraform / OpenTofu | `terraform` | Resource lists, state, or JSON plans mapped into infrastructure resources and relationships. |
| Local Laptop Host | `local_host` | Host hardware, local services, and installed model inventories mapped into CPU/RAM/GPU, service, and model relationships. |

`build_adapter_compatibility_catalog()` supplies the catalog and compatibility
matrix. The `/adapters` studio and `/api/v1/environment-adapters?adapter=local_host`
expose these views. Inventory and model presence do not establish live usage or
inference health; unmeasured currencies are labeled accordingly.

`openapi_spec.py` builds the OpenAPI 3.1.0 browser contract with
`build_openapi_v3_spec()`. The browser serves it at `GET /api/v1/openapi.json`,
and `/docs` provides the interactive endpoint reference. `route_registry.py`
records the HTML routes, API paths, and allowed query parameters used for routing
and CLI inspection. Start the browser with:

```powershell
python opscryer_browser.py --serve --port 8088
```

The contract describes read-only GET operations, query parameters, and JSON
responses, including 400 validation errors and applicable 403 airlock blocks.
Unknown, repeated, or malformed query parameters are rejected. Response schemas
currently allow generic JSON objects, so endpoint behavior and provenance still
matter to consumers. The spatial graph artifact contract and the HTTP OpenAPI
contract are separate: the former validates graph data, the latter describes
browser endpoints. The full backend in-process dispatcher needs an HTTP adapter
for remote use; the browser hosts its own registered API surfaces.
