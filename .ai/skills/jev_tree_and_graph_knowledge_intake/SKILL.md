---
name: jev_tree_and_graph_knowledge_intake
description: Operating protocol for humans, knowledge-gathering skills, and System 2 AI models to propose, validate, and stage new support ticket playbooks, live service probes, and Knowledge Graph node links into the System One Jev decision tree.
---

# Jev Decision Tree & Knowledge Graph Intake Skill

Use this skill whenever a human operator, a Knowledge-Gathering Skill attached to the Knowledge Graph, or a System 2 AI reasoning model (e.g., Argon, FrontierReviewer, Ollama) investigates an issue, discovers a new infrastructure pattern, or needs to propose a new support ticket solution or live service probe into the `Jev` decision tree (`jev_client.py`).

---

## 1. Core Architecture (How Skills & AI Models Interface with `Jev`)

1. **Knowledge-Gathering Skills & System 2 Models Propose; `Jev` Executes Deterministically:**
   - Reasoning models and knowledge-gathering skills never mutate runtime routing logic in ad-hoc prose.
   - Instead, they emit a structured **`SystemOneJevChangeProposal v1`** payload (or invoke the `propose-change` / `add-playbook` / `add-service` CLI) that links:
     - **Target Live Service (`service_id`):** e.g., `harbor`, `gitlab`, `openzfs_nas`, `openbao`, `authentik`, `opscryer_hud`, or a newly discovered service endpoint.
     - **Knowledge Graph Node Lineage (`graph_node_ids`):** e.g., `["res-harbor-registry", "deploy-gitlab-ci"]` so the solution is双向-linked to the Knowledge Graph (`Piece B`) and Spatial Browser (`Piece A`).
     - **Typed `Jev` Predicate (`jev_question` + `symptom_keywords`):** The calibrated boolean condition `Jev` evaluates in parallel.
     - **Deterministic Solution Leaf (`solution_summary` + `remediation_steps` + `required_it_tickets`):** The exact GitLab-native Markdown remediation steps returned when the live probe + predicate match.
     - **Self-Test Verification Sample (`verification_sample_ticket`):** A real or representative support ticket (`title` + `description`) that the proposal must deterministically resolve during dry-run verification.

2. **Automated 4-Gate Dry-Run Sandbox Verification (`propose_jev_tree_change`):**
   - Before any AI-proposed or skill-gathered change is accepted into `.ai/graphify/support_ticket_playbooks.json`, `propose_jev_tree_change()` runs four deterministic gates:
     1. **Gate 1 (`schema_and_keyword_hygiene`):** Verifies required fields, valid `service_id`, non-empty `remediation_steps`, and rejects overly broad 1–2 char stop-word keywords that could cause false positives.
     2. **Gate 2 (`acyclic_dag_integrity`):** Compiles the candidate `SystemOneSupportTicketTree v1` AST and runs `verify_decision_tree_integrity()` to prove zero cycles, zero dangling branches, and 100% leaf reachability.
     3. **Gate 3 (`zero_benchmark_regression`):** Runs `run_benchmark_evaluation()` to confirm `100%` (`16/16` dev, `4/4` holdout) routing accuracy is preserved.
     4. **Gate 4 (`sample_ticket_self_test`):** Evaluates `verification_sample_ticket` through `auto_answer_support_ticket_with_jev()` and verifies that the candidate tree deterministically routes the sample ticket to `matched_playbook_id == playbook_id`.

---

## 2. Quick-Reference Commands (Human Operators & AI Agents)

### A. Propose & Dry-Run Validate a Change from an AI Model or Knowledge Skill (`propose-change`)
```powershell
python jev_client.py propose-change `
  --proposed-by "skill:cluster-log-harvester" `
  --playbook-id "harbor-redis-pool-exhausted" `
  --title "Harbor Redis Session Pool Exhausted on High Concurrency Push" `
  --service-id "harbor" `
  --graph-nodes "res-harbor-registry,deploy-gitlab-ci" `
  --keywords "redis pool exhausted,harbor core 504,failed to get redis connection" `
  --solution "Harbor core is reachable, but the Redis connection pool saturated during parallel Kaniko pushes." `
  --step "Inspect Harbor Redis pod memory and clients: kubectl logs -n harbor -l component=redis --tail=50" `
  --step "Restart Harbor core deployment if stale connections persist: kubectl rollout restart deploy/harbor-core -n harbor" `
  --sample-title "Kaniko image push failing with redis pool exhausted on harbor.cluster.example.org" `
  --sample-description "Parallel CI jobs report failed to get redis connection from Harbor core." `
  --apply
```
*(Omit `--apply` to run a pure read-only dry-run validation that prints the 4-gate receipt and candidate `after_tree_sha256` without modifying `.ai/graphify/support_ticket_playbooks.json`.)*

### B. Direct 1-Liner Playbook or Live Service Addition (`add-playbook` / `add-service`)
```powershell
# Add a new ticket symptom + solution playbook directly
python jev_client.py add-playbook `
  --playbook-id "authentik-oidc-clock-skew" `
  --title "Authentik OIDC Token Rejected Due to NTP Clock Skew" `
  --service-id "authentik" `
  --keywords "iat is in the future,clock skew,jwt expired immediately" `
  --solution "Authentik IdP is healthy, but worker node chrony/NTP clock drifted >30s." `
  --step "Check chrony synchronization across K8s nodes: chronyc tracking"

# Hook up a brand-new live service endpoint for Jev to probe
python jev_client.py add-service `
  --service-id "argocd" `
  --title "ArgoCD GitOps Controller" `
  --health-url "https://argocd.cluster.example.org/healthz" `
  --keywords "argocd,outofsync,gitops sync" `
  --solution "Inspect ArgoCD pods in namespace argocd: kubectl get pods -n argocd"
```

### C. Python API for Knowledge-Gathering Skills
```python
from scripts.devops import system_one_jev_router

receipt = system_one_jev_router.propose_jev_tree_change(
    proposal={
        "proposed_by": "skill:k8s-storage-gatherer",
        "change_type": "add_playbook",
        "playbook_spec": {
            "playbook_id": "openzfs-nfs-stale-file-handle",
            "title": "OpenZFS NFS Stale File Handle After Dataset Snapshot Rollback",
            "service_id": "openzfs_nas",
            "graph_node_ids": ["hw-openzfs-scale", "res-openzfs-zfs"],
            "symptom_keywords": ["stale file handle", "estale", "nfs mount input/output error"],
            "solution_summary": "OpenZFS ZFS pool is online, but rolling back a ZFS snapshot invalidated existing client NFSv4 file handles.",
            "remediation_steps": [
                "Rollout restart pods mounting the NFS PVC so kubelet remounts the fresh ZFS dataset handle.",
            ],
            "required_it_tickets": ["IT-STORAGE-NFS-02"],
            "owning_team": "team-storage-nas",
        },
        "verification_sample_ticket": {
            "title": "Pod logs showing Stale file handle (ESTALE) on OpenZFS NFS mount",
            "description": "After ZFS snapshot rollback on nas.cluster.example.org, worker pods report nfs mount input/output error.",
        },
    },
    apply_if_valid=False,  # Set True to persist to .ai/graphify/support_ticket_playbooks.json
)
assert receipt["approved_for_tree"] is True
```

---

## 3. Sequenced Next Milestone (Only After Finishing RTS/TBS Interface Across All Screens)

1. **Multi-Model `Jev` + Knowledge Graph + Active Live Server Evaluation:**
   - Benchmark and compare candidate local and System 1/System 2 models (`qwen2.5-coder:7b`, `llama3.1:8b`, `gemma2:9b`, `deepseek-r1:8b`, `phi4-mini`, `phi3:latest`) examining the `Jev` decision tree, querying the Multi-Domain Knowledge Graph, and probing active live servers (`harbor`, `gitlab`, `openzfs_nas`, `openbao`, `authentik`, `opscryer_hud`).
2. **Pinned Announcements & Fast Incident Short-Circuit on Support Tickets:**
   - Pin active service announcements / maintenance / incident banners to the Knowledge Graph and support-ticket triage screen.
   - When an active pinned announcement matches a support ticket's service or symptom, short-circuit to a fast verified response: *"We are currently experiencing issues, and will update `#<channel>` when done."*

---

## 4. Pluggable Knowledge Graph + `Jev` Model Abstraction & Swappable Database-Interface Multi-Agent RAMCache (`opscryer_jev_ramcache_abstraction.py`)

When consuming OpsCryer from a **lower-powered AI on a work machine** or plugging new external systems into the Knowledge Graph + `Jev` + Multi-Agent RAMCache without reading 20+ large modules, use [`opscryer_abstraction.py`](file:///<workspace>/opscryer_abstraction.py):

### A. `<350`-Token Quick-Context Digest for Low-Powered AI Models
```powershell
python opscryer_abstraction.py --ai-brief
python opscryer_abstraction.py --demo-plugin-and-ramcache
python opscryer_abstraction.py --benchmark-engines
python opscryer_abstraction.py --herdr-brain-test
python opscryer_abstraction.py --train-graph-over-time
python opscryer_abstraction.py --human-links-matrix
python opscryer_abstraction.py --signed-ramcache-demo
python opscryer_abstraction.py --audit-cluster-observability
python opscryer_abstraction.py --developer-kg-feedback-loop
```

### B. 6-Pillar Human Active Monitoring & Rapid Debug Deep-Link Matrix (`HumanMonitoringLinkMatrix v1`)
Every system registered into `OpsCryerSystemPluginHub` (and all 8 settled production systems in `SETTLED_PRODUCTION_SYSTEM_CATALOG`) carries a verified `human_monitoring_links` dictionary on its Knowledge Graph node (`SpatialGraphContract v1`) and surfaces `human_rapid_debug_links` on every resolved `VERIFIED_EXPLICIT_ACTIONS` plan:
1. **`grafana_dashboard_url`**: System-scoped Grafana dashboard & Explore logs/metrics (`var-namespace` & `var-service`).
2. **`gitlab_source_and_pipelines_url`**: System-scoped GitLab manifest tree & CI/CD pipelines.
3. **`herdr_agent_pane_link`**: Herdr (`hc`) terminal attach URI & command for the active monitoring sub-agent (`herdr://attach/subagent-flash38-kg-01?system=...`).
4. **`dependency_analyzer_url`**: Dependency Mapper / Spatial Topology blast-radius focus view (`?focusNode=sys-...&view=blast-radius`).
5. **`argocd_application_url`**: ArgoCD GitOps Application sync status & live resource tree.
6. **`security_dashboard_url`**: Trivy / OpenBao / OCSF SecOps cockpit deep-link.
7. **`live_opscryer_debug_url`**: Live OpsCryer deployment rapid debug context endpoint (`/api/v1/system-context?system=...&debug=1`).

`ContinuousGraphTrainer` enforces **Gate 6 (`gate_6_human_monitoring_deep_links_verified`)** so no system or playbook can be promoted into the Knowledge Graph unless all 7 links are verified and system-scoped.

### C. Plugging Any System into the Knowledge Graph + `Jev` Abstraction (`OpsCryerSystemPluginHub`)
```python
from scripts.devops.opscryer_jev_ramcache_abstraction import OpsCryerSystemPluginHub

hub = OpsCryerSystemPluginHub(
    organization_name="Enterprise Platform",
    ramcache_engine="sqlite_memory_db",  # or "no_db_dict_ramcache" / "sharded_ring_ramcache"
)

# 1. Plug in any external system (automatically populates SpatialGraphContract v1 + Jev DAG)
hub.register_system(
    system_id="artifact_registry",
    label="Enterprise OCI Artifact Registry",
    domain="deployments_services",
    primary_url="https://registry.example.org",
    probe_fn=lambda: {"healthy": True, "latency_ms": 4.2},
    playbooks=[
        {
            "playbook_id": "registry-redis-pool-exhausted",
            "title": "Artifact Registry Redis Session Pool Exhausted",
            "symptom_keywords": ["redis pool exhausted", "failed to get redis connection"],
            "solution_summary": "Registry is reachable, but Redis session pool saturated during parallel pushes.",
            "remediation_steps": ["Inspect Redis client connections and rollout restart registry core."],
        }
    ],
)

# 2. Any agent publishes observations into the shared RAMCache cross-linked to the system/graph
hub.ramcache.publish_agent_observation(
    agent_id="agent-log-scout",
    system_id="artifact_registry",
    summary="Observed spike in failed to get redis connection errors during parallel pushes.",
)

# 3. Diagnose with Jev (combines System 2 compiled DAG + System 1 calibrated predicates + cross-agent RAMCache)
verdict = hub.diagnose_with_jev("Parallel CI pushes failing on registry", include_agent_ramcache_context=True)

# 4. If throughput or lock contention gets rough, hot-swap to the No-Database RAMCache behind the DB Interface!
swap_receipt = hub.ramcache.auto_switch_on_throughput_pressure(
    observed_p99_latency_ms=3.0,
    observed_ops_per_sec=4000.0,
)
# Callers continue using the exact same Database Interface (select / upsert / execute_query) with 0 code changes:
rows = hub.ramcache.execute_query(
    "SELECT * FROM agent_observations WHERE system_id = :sys LIMIT 10",
    params={"sys": "artifact_registry"},
)
```

### D. Cryptographically Signed Sovereign RAMCache, Delta Patching & Swarm Auto-Update (`SignedSharedRAMCacheFederation v1`)
When operating a fleet of agents across heterogeneous local RAMCache engines (`sqlite_memory_db`, `no_db_dict_ramcache`, `sharded_ring_ramcache`) and propagating newly trained Knowledge Graph systems, playbooks, or self-improvement/goal-alignment directives:
1. **Shared vs. Node-Local Table Boundary (`SHARED_KNOWLEDGE_TABLES`):**
   - Shared tables (`graph_nodes`, `shared_systems`, `swarm_alignment_goals`, `training_epochs`, `agent_observations`) are canonicalized (`canonicalize_shared_record`, stripping local `_updated_at_epoch` and `_generation` fields) and hashed into a deterministic 64-hex state digest (`compute_shared_state_sha256`).
   - Node-local tables (`agent_leases`, `jev_receipts`) stay private to each agent and never pollute the shared cryptographic state hash.
2. **Signed Delta Patch Generation (`SignedKnowledgeGraphPatch v1`):**
   - When `SignedSharedRAMCacheNode.has_significant_shared_update()` detects a significant update (`significance_score >= min_significance_score`), `create_signed_delta_patch()` computes a compact `table_upserts` + `table_deletes` diff from `base_state_sha256` -> `target_state_sha256` and signs it via `CryptographicRAMCacheSigner` (`HMAC-SHA256`).
3. **Dual Subscription Modes (`AUTO_UPDATE` vs. `EXPLICIT_ACCEPT`) on `SignedSharedRAMCacheFederationBus`:**
   - **`AUTO_UPDATE`** (for swarm workers & goal alignment): Automatically verifies the signature and base hash, applies the delta patch to the local RAMCache backend, rehydrates new systems + `Jev` playbooks (`_hydrate_systems_from_shared_table()`), and verifies post-apply `target_state_sha256` lockstep.
   - **`EXPLICIT_ACCEPT`** (for human-in-the-loop workstations): Verifies the signature, stages the patch in `pending_patches` (`STAGED_AWAITING_ACCEPT`), and applies it only when `accept_pending_patch(patch_id)` is called.
   - Forged or tampered patches are deterministically rejected (`REJECTED_INVALID_SIGNATURE`).

### E. 5-Stage Developer-to-Knowledge-Graph Feedback Loop & Rapid Best-Practice Synthesizer (`DeveloperKnowledgeGraphFeedbackLoop v1`)
Use [`scripts/devops/developer_kg_feedback_loop.py`](file:///<workspace>/scripts/devops/developer_kg_feedback_loop.py) (`--developer-kg-feedback-loop`) to iteratively build the Knowledge Graph from how developers and teams actually work:
1. **Stage 1 (`DeveloperKnowledgeInterviewSession`):** Conducts a multi-turn interview with a developer (`developer_handle`, `team_id`, `project_id`) and extracts explicit assumptions (`file_path`, `code_symbol`, `k8s_namespace`, `project_id`, `node_id`, `prometheus_metric`, `settled_system_id`) + `team_best_practices` (`familiar_tools`, `canonical_commands`, `golden_path_components`).
2. **Stage 2 (`AssumptionRealityVerifier`):** Mechanically verifies every assumption against real repository files, Python AST symbols, active K8s namespaces, `SYSTEM_NODE_CATALOG`, and Prometheus recording rules, catching and reconciling any misremembered path or symbol before graph staging.
3. **Stage 3 (`StagedGraphUpdateAndTestHarness`):** Stages the update in an isolated controller, generates a real `unittest.TestCase` class, and executes 5 real test suites (6-Gate `ContinuousGraphTrainer`, positive symptom routing, negative/adversarial refusal, real implementation anchors, and in-memory execution of the generated `unittest` class).
4. **Stage 4 (`DeveloperManagerReviewGate`):** Generates a `DeveloperManagerReviewPacket v1` and enforces explicit Developer or Engineering Manager sign-off (`APPROVED`, `CHANGES_REQUESTED`, or `REJECTED`) before committing to the production Knowledge Graph and pushing a signed RAMCache delta patch (`SignedKnowledgeGraphPatch v1`).
5. **Stage 5 (`BestPracticeArtifactSynthesizer`):** Consumes the approved `team_best_practice` graph nodes to rapidly synthesize AI Skills (`SKILL.md`), `Jev` Playbooks, Architecture Designs (Mermaid), System Connector Integrations, and Golden Path Kubernetes/GitOps Deployments grounded in the exact tools the team already knows and uses.




### F. Ungraphed In-Scope Inventory Analysis & 9-System Batch Onboarding Campaign (`UngraphedScopeInventoryAnalyzer v1`)
Use `UngraphedScopeInventoryAnalyzer` and `run_ungraphed_scope_onboarding_campaign()` (`python scripts/devops/developer_kg_feedback_loop.py --ungraphed-scope-campaign`) to scan the repository (`infrastructure/*`, `streaming/`, `torrenting/`, `runbookgate/`, `dependency-mapper/`, `PROJECT_DEFINITIONS`, `SYSTEM_NODE_CATALOG`) against `SETTLED_PRODUCTION_SYSTEM_CATALOG`, discover all real in-scope systems not yet in the baseline 8-system Knowledge Graph (`defectdojo_secops`, `dependency_mapper_ui`, `devcontainers_herdr_gvisor`, `satisfactory_gameserver`, `media_jellyfin_arr`, `streaming_vesktop_gpu`, `network_vlan_segmentation`, `notification_arbitrator`, `runbookgate_runbooks`), and onboard all 9 sequentially through the 5-stage loop with `.yaml`/`.tf`/`.py` symbol verification and `suite_6_cross_system_jev_collision_free` checks.
