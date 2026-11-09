---
name: "mr_quality_and_compaction_guard"
description: Enforces high-signal, tested, conflict-free Merge Requests over low-quality junk MRs, eliminates notification and click fatigue, ensures clean GitLab-native MR comments, and mandates compaction-proof persistence of all user feedback and session notes.
---

# High-Signal MR Quality Gate & Compaction-Proof Feedback Protocol

**Purpose:** Every second a human spends reviewing code must be spent on real, verified engineering work—never on sifting through broken pipelines, merge conflicts, jumbled bot comments, or fragmented low-value branches. High MR quality is the foundation that allows the workflow to graduate from manual multi-screen MR creation to **1-Click Approval**. Simultaneously, all human feedback and architectural guidance must be persisted to disk immediately so nothing is ever lost to context window compaction.

---

## 1. Anti-Junk MR Mandate & Zero Notification Fatigue

1. **Quality Over Quantity (Zero Junk Branches):**
   * AI agents MUST NEVER push unverified, half-baked, or redundant branches just to inflate task counts.
   * Branches with merge conflicts, failing local tests, missing traceability, or overlapping file locks are classified as **Junk / Conflicted** and will be closed rather than reviewed.
   * Consolidate closely related fixes within the same functional scope into a single cohesive, well-tested MR rather than fragmenting one logical change across multiple tiny MRs that multiply human clicks and CI queue time.
2. **Respect Human Review Time:**
   * Do not trigger notifications or surface a branch as `🟢 Ready to Open` on `https://opscryer.cluster.example.org/mrs` until local unit tests, manifest standards (`tests/test_k8s_manifests.py`), line endings (`scripts/devops/check_line_endings.py`), and secret scans pass 100%.

---

## 2. The 5-Point "Gold-Tier" MR Quality Scorecard (Path to 1-Click Approval)

Before any branch is marked `ready_for_mr` in the Swarm Broker or surfaced on the MR Launchpad, it is evaluated against 5 mandatory gates:

| Gate # | Gate Name | Verification Standard |
| :--- | :--- | :--- |
| **1** | **Local Unit & Manifest Tests Pass** | Specific unit test suite (`tests/test_*.py`) + `tests/test_k8s_manifests.py` executed and passing locally. |
| **2** | **Zero Merge Conflicts (`origin/main`)** | Branch is rebased cleanly onto `origin/main` (`mergeable`, `has_conflicts == False`). |
| **3** | **Disjoint File-Scope Lock** | Modified files do not collide with any other currently open Swarm MR's `locked_scopes`. |
| **4** | **Commitlint, LF & Secret Hygiene** | Lowercase Conventional Commit subject `<= 100` chars (`feat(scope): ... (refs #ID)`), strict `LF` (`\n`) line endings, zero leaked PATs/PII. |
| **5** | **Institutional Knowledge Captured** | Non-trivial architectural, operational, or workflow insights recorded in `.ai/knowledge/` or `.ai/skills/` so the MR Bot audit reports `✅ PASSED`. |

* **Gold-Tier Designation (`🏆 GOLD TIER — VERIFIED READY`):** Branches passing all 5 gates receive priority placement on `https://opscryer.cluster.example.org/mrs` so the human reviewer can confidently use **`⚡ 1-Click Create MR Now`** and move directly to **1-Click Approval & Merge**.

---

## 3. Clean, Un-Jumbled GitLab MR Comments & Descriptions

To prevent jumbled Markdown rendering in self-hosted GitLab MR descriptions and bot notes:

1. **No Raw GitHub Alert Syntax in GitLab MR Notes:**
   * Self-hosted GitLab CE/EE does not render GitHub's `> [!WARNING]`, `> [!TIP]`, or `> [!NOTE]` callout tags inside MR comments—it prints literal `[!WARNING]` text. Always use standard GitLab Markdown headings (`### ⚠️ ...` or `### ✅ ...`) and clean tables (`| Gate | Status | Summary |`).
2. **Contiguous Blockquotes Only:**
   * Every single line inside a Markdown blockquote MUST start with `> ` (including bullet items like `> - item`). Omitting `> ` on list items splits the blockquote into broken fragments.
3. **No `file:///` Links in GitLab Web Comments:**
   * Never emit IDE-only `file:///.ai/knowledge/...` links inside GitLab MR descriptions or bot comments; browsers block `file:///` on `https://gitlab.cluster.example.org`. Use inline code paths (`` `.ai/knowledge/workflow/` ``) or repository-relative web URLs.
4. **Structured Executive Review Card:**
   * Every MR description must include a concise **Executive Review Card** covering:
     * **Summary of Real Work Done**
     * **Scoped Files Modified**
     * **Automated Test & Verification Evidence**
     * **Traceability (`Refs #<Issue> [Epic <N>]`)**

---

## 4. Compaction-Proof User Feedback & Session Notes Protocol

Long autonomous and pair-programming sessions inevitably undergo **context window compaction**, which summarizes older turns and can drop nuanced user instructions if they only exist in chat history.

### Mandatory Persistence Loop (Execute Immediately When User Gives Guidance):
1. **Immediate Disk Capture:**
   * Whenever the user states a workflow preference, UI/UX requirement, architectural pivot, or pain point (e.g., *"I'm clicking too many buttons"*, *"docs as a separate repo isn't working out"*, *"comments are jumbled"*, *"favor high quality tested MRs over junk"*, *"some MRs have conflicts or pipeline issues that need to be bubbled to the top level"*), the agent MUST record it in [`.ai/knowledge/workflow/user_feedback_ledger.md`](file:///<workspace>/.ai/knowledge/workflow/user_feedback_ledger.md) within the same turn or branch.
2. **Promote Durable Rules to Skills & Invariants:**
   * If the feedback changes how future tasks must be executed, immediately codify it in `.ai/skills/` (such as this skill or `mr_process`) and, for global invariants, `.agents/AGENTS.md`.
3. **Inline Documentation in Monorepo (`PersonalProjectDocumentation/`):**
   * All documentation and architecture subplans live directly inside `infra-gitops/PersonalProjectDocumentation/` as regular `100644` LF-tracked files (never as an external `160000` git submodule commit pointer).

---

## 5. Top-Level Merge Blocker & Pipeline Bubbling (`mr blockers`)

1. **Never Hide Blocked or Conflicted Open MRs:**
   * Every open Merge Request (`state == "opened"`) that cannot be merged right now—whether due to `MERGE_CONFLICT`, `NEEDS_REBASE`, `PIPELINE_FAILED`, `PIPELINE_CANCELED`, `MANUAL_JOB_BLOCKING`, `CI_IN_PROGRESS`, `UNRESOLVED_DISCUSSIONS`, `DRAFT_WIP`, or `APPROVAL_REQUIRED`—MUST be bubbled to the top-level **Merge Blocker & Pipeline Alert Banner** on `https://opscryer.cluster.example.org/mrs` and audited via:
     ```powershell
     python scripts/devops/gitlab_ops.py mr blockers
     ```
2. **Deep `/merge_requests/:iid` Inspection:**
   * Never rely solely on `/merge_requests` list endpoints or `pipelines?per_page=50` (which miss older pipelines and omit `head_pipeline`). Always query `/merge_requests/:iid?include_diverged_commits_count=true` and `/pipelines/:id/jobs` for every open MR.

---

## 6. Declarative `devenv` & Standardized Pre-Commit / Session Bootstrap (`devenv.yaml`)

1. **Single-Command Environment Initialization (`devenv init`):**
   * Use `python scripts/devops/devenv.py init --profile <local|remote|agent>` (or `devenv.cmd init` / `./devenv init`) driven by `devenv.yaml` (or `devenv.json`) and `.pre-commit-config.yaml` to standardize Git LF settings, homelab TLS CA bundles, `scratch/*_args.txt` pre-approved runner files, and pre-commit hooks across local workstations, remote devcontainer pods, and autonomous AI agent sessions.
2. **Pre-Commit Hook Standardization:**
   * Every session installs and runs both `.pre-commit-config.yaml` (standard Python `pre-commit` framework) and zero-dependency native fallback hooks (`devenv hooks install` / `devenv hooks run`) enforcing LF line endings, Conventional Commits + `#<Issue>` traceability, OPSEC secret scanning, and K8s manifest namespace hygiene before any branch is pushed.

---

## 7. Pre-Hackathon Infrastructure Change Freeze & Blast-Radius Quarantine

1. **Protect Core Cluster Infrastructure Before Demos/Hackathons:**
   * Never pressure the user to merge core control-plane upgrades (`ArgoCD v10`, `OpenBao`, `Authentik`, `GitLab Runner`), credential fallback removals (`!482`), or breaking `.gitlab-ci.yml` gates (`!262`) before a major demo or hackathon.
2. **Quarantine via `Draft: [Post-Hackathon Freeze]`:**
   * High-blast-radius MRs are automatically placed in `Draft: [Post-Hackathon Freeze]` state so GitLab locks the Merge button (`draft_status`) and they are partitioned into a calm `PARKED FOR POST-HACKATHON FREEZE` bucket rather than cluttering `READY TO MERGE NOW`.

---

## 8. RTS Command HUD, Corner Checkbox Search Popover & Dedicated Search Screen

1. **Zero-Knowledge Secret Provenance (`scripts/security/token_metadata_indexer.py`):**
   * Never store or display plaintext PATs/credentials in the Knowledge Graph or UI. Index only non-reversible SHA-256 prefix fingerprints (`sha256:12-hex`), creator (`created_by`), timestamps (`created_at`, `expires_at`), consuming projects (`used_by_projects`), and OpenBao KV paths (`openbao_path`) with blind `ExternalSecret` handle injection.
2. **Top-Corner Checkbox Search + Popover Overlay + Dedicated Search Screen (`scripts/devops/fuzzy_knowledge_search.py`, `scripts/monitoring/rts_command_hud_builder.py`):**
   * Provide a corner search menu in the RTS Top Ribbon with two independent checkboxes (`[x] Generic Data` and `[ ] Secrets`) that pops down a floating results overlay over the main viewport (`popover_dropdown`) with a **"More Info -> Dedicated Search Screen"** link (`/search` & `/search/secrets`) containing starter filters and reserved extensible filter slots.

---

## 9. Three-Tier Company Hierarchy: Company (Human Employees + AI Agents) &rarr; Projects &rarr; Resources

1. **Distinct Three-Section Layout (`Company` &rarr; `Projects` &rarr; `Resources`):**
   * **Company Section (Human Employees Distinct from AI Agents):** Never collapse all AI agents into a single "AI Company". The Company represents the engineering organization of **Human Employees** across multiple teams (seeded with a realistic simulated multi-team org structure alongside `@opscryer-maintainers`), while **AI Agents** (`member_type: "ai_agent"`) are modeled as a distinct, smaller assistant subset within those teams.
   * **Projects Section:** Explicitly displays the projects/applications those human teams and their assisting AI agents work on.
   * **Resources Section:** Explicitly displays the infrastructure, cluster nodes, databases, OpenBao secret mounts, and Kubernetes workloads that those projects and employees operate on.

---

## 10. Interactive Drill-Down to Real System Control Planes & First-Class URLs in the Knowledge Graph

1. **Zero Dead-End Top-Level Cards — Every Node Drills Down to Live System Control (`GitLab`, `Authentik`, `ArgoCD`, `Grafana`, `OpenBao`, `Harbor`, `DefectDojo`, `RunbookGate`, `OpenZFS`, `NetFilter`):**
   * Top-level items across `Section 1 (Company Teams/Employees/Agents)`, `Section 2 (Projects)`, and `Section 3 (Resources)` must be interactive drill-down nodes that reveal child entities and clickable 1-click links into real cluster control planes (`https://gitlab.cluster.example.org`, `https://auth.cluster.example.org/if/admin/`, `https://argocd.cluster.example.org`, `https://grafana.cluster.example.org`, `https://openbao.cluster.example.org`, `https://harbor.cluster.example.org`, `https://defectdojo.cluster.example.org`, `https://runbookgate.cluster.example.org`, `https://nas.cluster.example.org`, `https://netfilter.cluster.example.org`, `https://opscryer.cluster.example.org/mrs`, `https://dependencymapper.cluster.example.org`).
2. **Knowledge Graph First-Class URL Metadata (`control_plane_urls`, `primary_url`, `drilldown_children`):**
   * Store canonical URLs and control-plane deep links directly inside the Knowledge Graph (`.ai/graphify/graph.json`, `scripts/devops/company_org_model.py`, `scripts/devops/knowledge_sync.py`, `scripts/devops/fuzzy_knowledge_search.py`) so clicking any node in the GUI or searching in the Corner Search Menu surfaces live clickable links to control the underlying system.

---

## 11. Token-Frugal Fleet Dispatch Guard (`<40% Weekly Frontier Quota`)

1. **Zero Frontier Subagent Sprawl Under Low Quota:**
   * When weekly frontier token quota is constrained (`<40%`), NEVER spawn multiple frontier subagents (`invoke_subagent`) that multiply context window overhead.
2. **Local GPU + DDR4 RAM Fleet Offload (`0% Frontier Token Burn`):**
   * Dispatch backlog issues to the in-cluster fleet (`swarm-memory` DDR4 RAM broker, `argon-planner`, `argon-overnight-autopilot`, `workspace-*-0` pods, and local Ollama GPUs on `RTX 3080` + `RTX 5080`) using `local-gpu-zero-token` mode and frontier-distilled playbooks.
3. **Cohesive Multi-Issue Batching:**
   * Group related backlog tasks into single high-signal, locally verified commits/branches (`Refs #A, #B, #C...`) to maximize backlog throughput per token.

---

## 12. Programmable & Configurable Company Ontology, Relationships & Tooling Extension System

1. **Extensible Data Types, Relationships & Tooling Plugins (`.ai/graphify/company_ontology_registry.json`, `scripts/devops/company_org_model.py`):**
   * The single-pane-of-glass Company $\rightarrow$ Projects $\rightarrow$ Resources system must be programmable and configurable via declarative JSON/YAML registry files, CLI commands, REST APIs (`GET /api/v1/ontology`, `POST /api/v1/ontology/register`), and UI controls—allowing users and agents to dynamically register new `entity_types`, `custom_entities`, `relationship_types`, `custom_relationships`, and `tooling_plugins` without rewriting core code.

---

## 13. RTS AI Unit Telemetry, Outsourced vs. Local Hardware Routing, VLAN/Resource Meters & Behavioral Health Detection

1. **RTS AI Unit Drill-Down & Live Multi-Node Fleet Telemetry (`scripts/devops/company_org_model.py`, `scripts/monitoring/rts_command_hud_builder.py`):**
   * Clicking down from the Whole System Overview $\rightarrow$ Company Team / Project $\rightarrow$ AI Agent Unit must reveal live RTS Unit telemetry:
     * **Task & Prompt Lineage:** `dispatched_prompt`, `elapsed_task_seconds` (`elapsed_time_formatted`), and `parent_effort` (how the task fits into a parent Epic/Project).
     * **Outsourced vs. Local Compute Routing:** Explicitly distinguish jobs outsourced to **Antigravity Frontier** (`OUTSOURCED_FRONTIER`) vs. executing on **Local Hardware** (`LOCAL_HARDWARE_GPU` across `nodegamma03` RTX 3080, `workstation-demo-01` RTX 5080, and `amd-cracker-gpu` RTX 3070).
     * **Interfaces, VLANs & Hardware Utilization:** Display active network interfaces/VLANs (`VLAN 30`, `VLAN 40`, `NetFilter 2.5GbE`, `cni0`) and live `CPU %`, `GPU % / VRAM GB`, `Network Mbps`, and `Disk MB/s` meters.
     * **Behavioral Health (`NOMINAL`, `STUCK`, `GOING_ASTRAY`, `HALLUCINATING`):** Detect and surface whether an AI unit is nominal, stuck in a loop, drifting outside its scope lock (going astray), or hallucinating non-existent paths/symbols, with 1-click RTS unit intervention controls.

---

## 14. Deep Test Suite Audit, Logic-Gap Hardening & Overnight Swarm Morning Review

1. **Rigorous Test Quality & Logic-Gap Coverage (`tests/`):**
   * Continuously audit existing tests in `tests/` to replace shallow assertions with strict positive + negative-path, boundary-condition, and security-redaction assertions.
2. **Morning Feature & Test Review Report (`swarm_dispatch.py overnight-review`):**
   * Pair overnight autonomous swarm feature delivery with a structured morning review of all delivered code features and the complete test suite matrix.

---

## 15. Mechanics-First Engineering & Deferred Visual Simplicity Pass

1. **Prioritize Core Backend, Graph & Telemetry Mechanics (`company_org_model.py`, `knowledge_sync.py`, `dependency-mapper/backend/`):**
   * Focus active development on deterministic backend mechanics: multi-hop drill-down graph traversal (`/api/v1/drilldown`), live K8s/GitLab/agent heartbeat ingestion (`/api/v1/ai-units/heartbeat`), AST-verified path/symbol hallucination and file-scope drift mechanics, and `.NET` backend service resilience.
2. **Hold Off on Visual/Layout Churn Until the Dedicated UI Simplicity Pass:**
   * Avoid adding visual bloat or rearranging frontend panels piecemeal; ensure every mechanic is exposed as a clean, well-tested API/CLI primitive so the visual layer can be simplified and reorganized in a dedicated UX pass later.

---

## 16. Unified Full-Viewport Live Information Tree & Level-to-Level Graph Travel

1. **Space-Maximizing Live Information Tree Over Static Expanding Boxes (`swarm-memory.yaml`, `knowledge_sync.py`, `company_org_model.py`, `DependencyGraph.tsx`):**
   * The primary viewport must present a **unified, full-screen Live Information Tree** (`#live-information-tree-stage`) with dynamic SVG cubic-bezier connectors (`#live-tree-svg-edges`) rather than static boxes that expand in place.
2. **True Level-to-Level Camera Travel (`L0 Root` $\rightarrow$ `L1 Team` $\rightarrow$ `L2 Employee / AI Unit / Project` $\rightarrow$ `L3 Resource` $\rightarrow$ `L4 Control Plane`):**
   * Clicking any node (`travelToTreeNode(nodeId)`) must physically travel the graph deeper:
     * **Left Column (Ancestor Lineage Spine):** Compresses the higher levels already traversed (`breadcrumb`) into a vertical/stepped ancestor chain for 1-click travel back up.
     * **Center Column (Active Focus Hub):** Positions the selected node as the focal hub with live telemetry, RTS AI Unit status/orders, and 1-click Control Plane actions.
     * **Right Column (Downstream Child & Grandchild Fan-Out):** Fans out the next deeper level (`drilldown_children`) and grandchild previews (`multi_hop_downstream_tree`) connected by SVG bezier curves so clicking any child travels the graph one level deeper.

---

## 17. Multi-Domain Ecosystem Knowledge Graph (Company, Processes, Deployments, Hardware) & Local GPU AI Q&A

1. **Four First-Class Knowledge Graph Domains (`company_org_model.py`, `knowledge_sync.py`, `swarm-memory.yaml`, `DependencyGraph.tsx`):**
   * The Knowledge Graph and Live Information Tree MUST unify **Company Organization** (`team-*`, `emp-*`, `unit-*`, `proj-*`), **Processes & Runbooks** (`proc-*`), **Kubernetes Deployments & GitOps Workloads** (`deploy-*`), and **Physical Hardware, GPUs & Network Fabric** (`hw-*`) so users and local AI models can traverse and query how people, processes, deployments, and hardware connect end-to-end.
2. **Frontier Graph-Grounded Local GPU AI Q&A (`POST /api/v1/ask-local-ai`):**
   * Local GPU inference (`ollama-service.ai-infra.svc.cluster.local:11434`) must be grounded in real time by injecting the relevant multi-domain Knowledge Graph subgraph + top matching `.ai/knowledge/` and `.ai/skills/` chunks from `nodegamma03` DDR4 RAM, returning clickable graph node citations that travel the Live Information Tree directly to the referenced Process, Deployment, Hardware, or Company entity.
3. **Browser `<script>` Syntax & Python String Escape Hygiene (`r"""` + Node.js `--check` Gate):**
   * Any HTML template embedded inside a Python script or ConfigMap (`swarm-memory.yaml`, `knowledge_sync.py`) MUST use raw strings (`r"""<!DOCTYPE html>`) and avoid single-quoted JS strings containing apostrophes or `\n` escapes, verified by `test_21_rendered_hud_javascript_syntax_and_browser_execution` (`node --check` + Node `vm` DOM execution).
4. **Zero-MR `/dev/shm` Hot-HUD Override & Token-Frugal Single-Context Sprints (`POST /api/v1/dev/hot-hud`, `plan_token_budget_sprint`):**
   * Never use MRs as a trial-and-error debugging loop. Verify all `<script>` compilation, DOM execution, and HTTP contracts locally and via `/dev/shm` Hot-HUD override (`POST /api/v1/dev/hot-hud`) before pushing one consolidated, conflict-free branch, and avoid spawning subagents when conserving weekly frontier token quota (`20% -> 15% tonight target -> 5% safety reserve`).
5. **Knowledge Graph Policy Guardrails, Deployment Disambiguation & Specific IT Ticket Routing (`evaluate_graph_policy_and_ticket_routing`):**
   * Encode explicit **Policy Guardrails** (e.g., direct human DB access & static passwords prohibited under `proc-zero-knowledge-secrets` / `NIST SC-28`), **Required Disambiguation Slots** (must specify target K8s Deployment `deploy-security-iam`, `deploy-gitlab-ci`, `deploy-ai-infra`, or `deploy-dev-envs`), and **Specific IT Ticket Templates** (`IT-SEC-DB-01`, `IT-IAM-DB-02`, `IT-NET-FW-03`, `IT-OPS-MR-04`) directly in the Knowledge Graph and `POST /api/v1/ask-local-ai` so small local GPU models (`phi3:latest`) always return deterministic policy verdicts, clickable deployment disambiguation pills, and 1-click IT tickets rather than generic advice.









6. **Intent-Aware 3-Tier Project Intake vs. DB Credential Blocker & Zero Session Bleed (`IT-PLAT-GP-01`):**
   * Distinguish project/pipeline scaffolding queries (*"How do I start a new 3 tier project pipeline with a database, frontend, and backend?"*) from direct DB credential requests, routing 3-tier project queries to the Golden Path Intake Playbook (`IT-PLAT-GP-01` + `IT-SEC-DB-01`, `gitlab-ci-components`, Ephemeral MR envs) without global `local_ai_qa_history` turn bleed.
7. **Bottom-Up Data-Driven Graph Governance & Full-Chunk BM25 Skill Retrieval (Never Prescribe Questions in `if/elif` Code):**
   * Never hardcode question-specific `if/elif` keyword branches to answer user questions. Store policies, required context slots, and IT ticket templates as declarative `governance_metadata` and `skill_refs` on Knowledge Graph nodes, retrieve full `900`-char `.ai/skills/` & `.ai/knowledge/` chunks via stop-word-filtered BM25 + bigram scoring, propagate chunk relevance across `skill_refs` edges to rank Graph Nodes, and derive policy/ticket guidance bottom-up from the top-ranked Graph Node and retrieved skill chunks.
8. **Strict Two-Piece Architectural Separation for Hackathon & IP Boundary (Frontend Spatial Browser vs. Headless Backend Knowledge Graph):**
   * Maintain a clean, zero-coupling boundary between **Piece A: The Frontend Spatial Browser** (`scripts/devops/spatial_graph_browser.py`) and **Piece B: The Headless Backend Knowledge Graph Engine** (`scripts/devops/knowledge_graph_backend.py`) connected only by a versioned REST/JSON contract (`SpatialGraphContract v1`). Piece A must run standalone with a generic mock/demo adapter (`0` backend code required), and Piece B must run headlessly (`0` UI/HTML required), so the user can demo or hand over either piece independently at a hackathon without giving both pieces to a company.
9. **Sandbox Isolation by Default & Zero Credential Fallbacks (`MONITOR_SANDBOX_CODE` Gate for Note #2931):**
   * Security scanning, DefectDojo ingestion/triage (`scripts/security/ai_security_triage.py`, `infrastructure/security/triage-cronjob.yaml`), topology correlation (`scripts/security/enrich_cluster_topology.py`), and MR traceability (`scripts/ci/enforce_mr_traceability.py`) must never route to or monitor `sandbox` / `ai-sandbox` resources unless `MONITOR_SANDBOX_CODE=true` is explicitly enabled. Never include hardcoded `DEFECTDOJO_API_KEY` hex strings or literal `"${GITLAB_TOKEN}"` unexpanded Python fallbacks.
10. **System 2 Compiled Decision Trees + System One (`Jev`) Calibrated Execution (`jev_client.py`):**
    * For high-assurance routing and policy enforcement, compile declarative Knowledge Graph governance rules into a formal `SystemOneDecisionTree v1` AST (System 2 offline compilation), evaluate input predicates via a calibrated System One model (`Jev` RLCD probabilities or local calibrated System One estimator), and execute tree transitions deterministically in Python with fail-closed confidence thresholds.
11. **Incremental Documentation Capture & Knowledge-Gathering Skill / AI Proposal Interface for `Jev` (`.ai/knowledge/architecture/system_one_jev_decision_trees.md`, `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md`):**
    * Capture concise, actionable documentation as features are built (deferring exhaustive doc polish until the end of the effort), and expose a 4-gate dry-run validated proposal interface (`propose_jev_tree_change` / `propose-change` CLI) so knowledge-gathering skills and System 2 AI models can safely propose new support ticket playbooks, live service probes, and Knowledge Graph node links into the `Jev` tree.
12. **Self-Hosted `ntfy.cluster.example.org`, Zero Public Leakage & Quiet-By-Default Notification Standard (`Epic #266`, Tasks `#267`–`#269`, `scripts/monitoring/notification_filter_engine.py`):**
    * Never send notifications to public `https://ntfy.sh` or bypass `notification-arbitrator` (such as `monitoring/ntfy-bridge.yaml` sending raw Alertmanager descriptions with pod names, namespaces, and internal IPs). All notifications must target the self-hosted `https://ntfy.cluster.example.org` server, scrub 100% of private topology/PII data, and enforce **Quiet-By-Default** sane defaults (**`0` messages/day when nothing is critically broken**, `info`/`warning`/`resolved` suppressed by default, 6-hour flapping cooldown, and customizable category filters with a default daily cap of `<= 2`).
13. **Live Metric-Grounded `Jev` Ticket Triage, Multi-Actor Graph Access & Human Ops Engineer Escalation (`Epic #270`, Tasks `#271`–`#273`, `scripts/devops/jev_live_ticket_triage_and_ops_escalation.py`):**
    * Arbitrary support requests (e.g., *"hey my builds are really slow today"*) must be correlated against live infrastructure telemetry (GitLab runner queue depth, NetFilter/CNI network conntrack saturation, OpenZFS ZFS disk I/O latency, and upstream dependency health) and the 4-Domain Knowledge Graph; when a suggested answer is not viable, route the ticket with its full diagnostic snapshot directly to the owning Human Ops Engineer.


12. **RTS/TBS Top-Level Simplicity Overhaul, Encapsulated Box Layer Zoom & 7-Currency Dropdown Bar (`rts_command_hud_builder.py`, `spatial_graph_browser.py`, `swarm-memory.yaml`, `DependencyGraph.tsx`):**
    * Present top-level overviews as a clean **Big Main Pane of Encapsulated Boxes** for the active layer (`L0` -> `L3`) where single-clicking selects an object into the consistent outer ClassicRTS/FantasyRTS 3/ClassicTBS perimeter HUD (Bottom-Left Minimap, Bottom-Center Wireframe Portrait + Vitals + 6-Slot Stat Grid, Bottom-Right 3x3 Command Card) and scrolling in/double-clicking dives into the next layer of boxes.
    * Render the **Top "Currencies & Food/Supply" Bar** with 7 click-to-open dropdown items: `nodes`, `cpu_load`, `ram_load`, `network_load`, `build_supply` (queued builds / concurrent build slots), `renovate_failures`, and `open_mrs`.
13. **Sequenced Post-RTS Milestone — Multi-Model `Jev` + Knowledge Graph + Live Server Evaluation & Pinned Incident Announcements on Support Tickets:**
    * **Sequencing Gate:** Finish the RTS/TBS interface across **all** top-level overview screens (`opscryer.cluster.example.org/`, `opscryer.cluster.example.org/mrs`, `DependencyGraph.tsx`, `spatial_graph_browser.py`, and Argon Mobile Overview) **before** implementing this next milestone.
    * **Multi-Model Jev & Live Server Evaluation:** Evaluate and benchmark multiple models (`qwen2.5-coder:7b`, `llama3.1:8b`, `gemma2:9b`, `deepseek-r1:8b`, `phi4-mini`, plus calibrated System 1 `Jev` evaluators) for examining the `Jev` tree and synthesizing answers from the Knowledge Graph and active live servers.
    * **Pinned Announcements & Fast Support Ticket Short-Circuit:** Pin active service announcements/incidents to the knowledge base and support-ticket screen; when an announcement matches a support ticket, return a fast deterministic response: *"We are currently experiencing issues, and will update `#<channel>` when done."*
14. **Personal/Open-Source Core Separation, Universal Stack Adapters, Hardware-Agnostic + OpenAI-Compatible AI Provider Layer, Parallel Home/Company Demo & 20%–80% Ticket Deflection Funnel:**
    * Keep the OpsCryer engine cleanly separated from company data so it can be licensed personally or open-sourced, loading `homelab_live` and `downgraded_company_demo` data as pluggable packs.
    * Expose a universal adapter catalog for third-party stacks (GitLab/GitHub/ADO, Jira/ServiceNow, OpenBao/Vault/Okta, Harbor/Artifactory, OpenZFS/S3, Grafana/Datadog/Slack) and a generic AI provider layer supporting `<2ms` CPU `Jev`, Laptop NPU (`1.5B–3.8B`), Local GPU Farm (`7B–14B`), and standard `OPENAI_API_KEY` `/v1/chat/completions` endpoints.
    * Route vague developer/AI questions through a self-service deflection funnel that answers from Pinned Announcements, the Knowledge Graph, and Live Probes first—opening a pre-populated ticket only when unresolved or gated by policy (targeting 20%–80% ticket reduction).


15. **Zero-Hallucination Guided Decision Trees ("I Need a Database" + 5+ Business Day Custom SLA Warning), ServiceDesk Front-Door Replacement, Hybrid AI+Human Authoring, Live-Topology EoL Redirect ("Persistent Hard Drive" -> S3/Azure Blob) & Federated Cross-Team Subtrees (Frontend vs. DevOps):**
    * Guarantee zero-hallucination stack Q&A that either points users to a concrete verified article or forwards them to the right human team.
    * Support interactive multi-option decision trees—specifically the 4-option **"I need a database"** tree (`on_your_machine`, `integrated_into_product_release`, `persistent_shared_multi_user`, and `other_custom_manual_request` with an explicit **5+ business days / over 1 week extra SLA warning** for uncataloged custom solutions).
    * Replace the hated ServiceDesk search/filing UI with a friendly ask-for-help web front door backed by a ServiceDesk adapter, support AI-drafted + human-reviewed tree authoring, intercept EoL/deprecated requests (e.g., *"I need a persistent hard drive"* $\rightarrow$ live **AWS S3** or **Azure Blob Storage** alternative driven by the active company topology view), and allow specialist teams (like **Frontend** vs. **DevOps**) to mount federated subtrees that route notifications and tickets directly to the owning team.
16. **Declarative Doc-to-CLI Command Extraction (`declarative_cli_commands`), Live End-to-End Walkthrough & Problem-Space Test Matrix:**
    * Bind every guided decision tree option, EoL storage redirect, and support playbook to declarative, copy-pasteable CLI commands (`command`, `shell`, `purpose`, `safety_tier`, `expected_success_signal`, `source_doc_path`) extracted directly from `.ai/skills/*/SKILL.md`, `.ai/knowledge/`, and `.ai/graphify/support_ticket_playbooks.json`.
    * Maintain an exhaustive problem-space test suite (`tests/test_declarative_doc_cli_and_problem_space_matrix.py`) covering all decision tree branches, EoL redirects, federated cross-team routing, pinned announcements, live probes, policy blocks, and adversarial/uncataloged inputs.
17. **Broken MR Stack Repair, Major Infrastructure Pre/Post-Upgrade Restart Verification (`OpenBao`, `Authentik`, `ArgoCD`, `GitLab Runner`, `ExternalSecrets`), and Deferred FrontierReviewer Architectural/Security Review Handoff:**
    * Repair failing CI pipelines (`traceability-audit`, `orphan-audit`, `build-frontend-image`, `build-backend-image`) and rebase/re-trigger open MRs (`!790`, `!789`, `!782`, `!780`, `!778`, `!777`, `!754`, `!677`, `!636`–`!633`, `!397`, `!395`, `!377`, `!357`) so the merge stack is green and conflict-free.
    * Before and after upgrading major infrastructure services (`openbao`, `authentik`, `argocd`, `gitlab-runner`, `external-secrets`), restart/verify each service and run pre-upgrade + post-upgrade health checks.
    * Defer the full FrontierReviewer architectural & security review package until the user confirms tonight's feature work is complete.
18. **Global Code Search Version & Dependency Indexer (`Sourcegraph` / `Zoekt` / `OpenGrok`), Red/Blue Team + Trivy/DefectDojo Warning Ingestion & Ops Blast-Radius Scope Page:**
    * Hook into global code search deployments (**Sourcegraph**, **Zoekt**, **OpenGrok**, **GitLab Exact Code Search**) behind a **Zero-Knowledge Manifest-Scoped Airlock** (querying only `Chart.yaml`, `Chart.lock`, `*.csproj`, `package.json`, `go.mod`, `requirements.txt`, `Dockerfile` and storing only structured version/dependency edges, never raw source code).
    * Correlate global code search version hits with **Trivy** container/SBOM reports, **DefectDojo** findings, **Red/Blue Team** security advisories, and **Broken Upgrade Guards** (`Chart.lock` desync, `.NET 8.0` `Microsoft.OpenApi >= 2.0` `TypeLoadException`, `OpenBao` Shamir Raft quorum), highlighting affected projects in the Knowledge Graph and dispatching Ops notifications with a dedicated **Security & Version Blast-Radius Scope Page** (`/api/v1/security/code-search-scope`).
19. **Household Simple Game & Network Ticket Portal ("The Minecraft Server Is Down") + Dual AMD APU-200 Client Metrics Compliance (`REQ-APU200-01-METRICS`, `REQ-APU200-02-METRICS`):**
    * Provide a simple household ticket portal (`POST /api/v1/household/ticket` & `#household-game-ticket-portal`) where anyone in the house can report *"the minecraft server is down"* or *"games can't connect"* and automatically verify: (1) live `game-servers` pod/port/exporter health (`minecraft-survival` `:25565`, `minecraft-creative` `:25566`, `satisfactory` `:7777`/`:9103`, `factorio` `:34197`/`:9102`) and workload mode (`ai` vs `gaming`/`hybrid`), (2) home network, NetFilter 4-port 2.5GbE VLAN 40 routing, and MetalLB BGP `externalTrafficPolicy: Cluster` (`[ARCH-BGP-01]`), and (3) whether **both AMD APU-200 computers** (`apu200-livingroom-01` and `apu200-bedroom-02`) are online and actively serving Prometheus `:9100/metrics` and AMD APU telemetry as required by the cluster.
20. **Overnight Big Overall Sync + Disjoint Multi-Branch Rollout Wave for Morning 1-Click MR Creation:**
    * Before overnight handoff or workstation sleep, execute a full repository/cluster sync (`origin/main`, Helm `Chart.lock` digests, Knowledge Graph, Requirements HUD, live OpsCryer DDR4 RAM Hot-HUD, and FrontierReviewer Architectural/Security Review Handoff) and push a long rollout wave of pairwise-disjoint, unit-tested branches (`5/5 Gold-Tier Scorecard`) with 1-click GitLab Compare/New-MR links ready for the user on return (Rule 4 compliant).
21. **FrontierReviewer Architectural & Security Review Guardrails (`argon_review_notes.md`):**
    * **No Templated Boilerplate Rollout Branches:** Never generate multi-branch waves from a single parameterized template that only changes threshold constants without probing real files or live endpoints; every branch must implement real, non-tautological domain logic and fixture-backed tests.
    * **Read-Only `verify` vs. Explicit `--fix` / `--sync-live` & Safe Lock Handling:** Keep `verify` read-only by default, never blindly delete active `.git/*.lock` files without checking staleness age (`> 300s`), use origin-scoped CORS allowlists instead of wildcard `*` on internal APIs, and centralize homelab CA-bundle TLS verification instead of proliferating `ssl.CERT_NONE`.
22. **Local Pre-Commit & Pre-Push CI Parity Hooks (`helm-lint`, `Chart.lock`, `yamllint`, `k8s-manifest-standards`, `validate-aicac`) Before Pushing to GitLab:**
    * Never rely on the remote GitLab server to catch `helm-lint` (e.g., unescaped Prometheus `{{ $labels.instance }}` variables inside Helm `templates/*.yaml`), `Chart.lock` digest drift, `yamllint`, `k8s-manifest-standards`, or `validate-aicac` failures.
    * Always run `tls_trust.lint_all_helm_charts()`, `tls_trust.verify_all_helm_chart_locks()`, AICaC frontmatter checks, LF line-ending checks, and secret scans locally inside `.git/hooks/pre-commit`, `.git/hooks/pre-push` (`python scripts/devops/devenv.py hooks run`), `.pre-commit-config.yaml`, and `python scripts/devops/inline_docs_migration.py verify` before pushing any branch to `gitlab.cluster.example.org`.
23. **Focused High-Quality MR Wave Loop Skill, Swarm + Argon High Review/Audit Gate & Intentional Scale-Down Registry (`.ai/skills/high_quality_mr_wave_loop/SKILL.md`):**
    * Dispatch parallel swarm agents to audit and refine subsystems, always returning work to the Argon High reviewer/auditor gate (`inline_docs_migration.py verify` + `tls_trust.lint_all_helm_charts()` + K8s Gateway/NetPol/ESO audit + full unittest suite) before pushing focused (`<= 3` functional files), pairwise-disjoint branches with 1-click GitLab Compare Links (Rule 4 compliant).
    * Distinguish real service outages (`dependencies.cluster.example.org`, `dashboard.security.cluster.example.org`, `discord-stream.cluster.example.org`, `nzbget.cluster.example.org` `nodebeta02` pin, ESO `v1beta1` drift) from the **Intentional Scale-Down Registry** (`ollama-model-publisher` / `ai-models.cluster.example.org`, `open-webui` / `chat-sandbox.cluster.example.org`, `packet-aggregator-demo.*`, `kafka-ui.cluster.example.org`, `gitlab-runner-turbo`, `trivy-operator`, `agentic-agent-developer`, `scalable-worker*`).
24. **Zero Broken Links, Zero Fake/Random Telemetry & Workflow-First UI Integrity (`scripts/devops/ui_link_and_data_integrity_auditor.py`):**
    * Never render broken URLs, links to scaled-to-zero (`replicas: 0`) services (`runbookgate.cluster.example.org`, `dashboard.cluster.example.org`, `semaphore.cluster.example.org`, `chat-sandbox.cluster.example.org`, `ai-models.cluster.example.org`, `security-dashboard.cluster.example.org`, `10.20.3.4`), broken deep links (`/finding?test=27`, `/api/v1/oscal/bundle`), or unrouted hostnames (`opscryer.cluster.example.org` missing `HTTPRoute` on `homelab-gateway`).
    * Strictly prohibit `Math.random()` or hardcoded fake counters masquerading as "live data" in `dependency-mapper` (`FocusPanel.tsx`, `CustomNode.tsx`, `HardwareNode.tsx`, `DependencyGraph.tsx`) and `opscryer`.
    * Replace slapped-on RPG/mana window clutter with clean, end-to-end engineering workflows (Live Service & Ingress Reachability Verification, Dependency & Blast-Radius Analysis, and Clickable GitOps Manifest/Requirement/Test Traceability).
25. **Specific Project Landing Pages, Project-Scoped Monitoring & Overall System Nodes/Load View (`scripts/monitoring/project_landing_and_monitoring_hub.py`, `scripts/monitoring/system_nodes_and_load_overview.py`):**
    * Tie graph navigation directly to **Project-Specific Landing Pages** (`/projects/<project_id>` and in-graph Project Landing Hub) featuring project-scoped monitoring (aggregated CPU/RAM/GPU/Network load for that project's namespaces/pods, SLO health, and scoped Grafana/PromQL deep links), team ownership, active MRs/pipelines, and GitOps manifests.
    * Provide an **Overall System Nodes & Load View** (`/nodes` and in-graph System Nodes & Load Overview) displaying every physical and K8s node (`nodegamma03`, `workstation-demo-01`, `nodealpha01`, `nodebeta02`, `openzfs`, `netfilter`, `apu200-*`), its live CPU/RAM/GPU/Disk/Network load, pod distribution, active vs. intentionally scaled-to-zero (`0/0`) workloads, and per-project load attribution.
26. **High-Concurrency Multi-Branch MR Waves (`8–10+` Pairwise-Disjoint Branches Per Wave, `scripts/devops/high_concurrency_wave_planner.py`):**
    * Do not artificially cap waves at 3 branches. Queue **8–10+ pairwise-disjoint branches per wave** by giving each branch its own dedicated `.ai/knowledge/decisions/ADR-00X-<topic>.md` file (or disjoint `.ai/knowledge/` file) so zero branches conflict with each other or with currently running MRs, and every MR passes the `5/5 Gold-Tier Scorecard` (`✅ PASS` on Institutional Memory) for parallel auto-merge across the 16-slot GitLab Runner pool.
27. **Specific Provisioned Grafana `/d/<uid>/<slug>` NOC & Project Dashboard Deep Links (`scripts/monitoring/grafana_deep_link_uid_verifier.py`):**
    * Never point NOC or project/node monitoring buttons to the generic `https://grafana.cluster.example.org/dashboards` folder index. Always link directly to the provisioned Grafana dashboard UIDs in `monitoring`: `/d/god-mode-overview/noc-god-mode-full-system-overview` (NOC God-Mode), `/d/noc-systems/noc-systems-overview` (NOC Systems), `/d/gitlab-cicd-checker/gitlab-ci-cd-pipeline-and-runner-status` (`proj-gitops-launchpad`), `/d/global-security/global-security-dashboard` (`proj-zerotrust-sec`), `/d/openzfs-scale/openzfs-scale-system-stats` (`proj-noc-data` / `openzfs`), `/d/gpu-workloads/gpu-workloads-and-time-slicing-tracker` (`workstation-demo-01` / GPUs), and `/d/rYdddlPWk/node-exporter-full?orgId=1&var-node=<ip>:9100` (per-node host telemetry).
28. **Overnight Post-Merge Verification, DDR4 RAM Write-Behind ZFS Checkpointing & 12-Branch Hackathon Readiness Wave (`scripts/devops/ram_cache_writebehind_checkpoint.py`, `scripts/devops/hackathon_demo_rehearsal_harness.py`):**
    * Keep `/mnt/ram-rag` hot reads/writes in `nodegamma03` DDR4 RAM (`<0.05ms`, zero idle SSD writes) while persisting dirty-bit SHA-256 write-behind snapshots to `/mnt/ram-checkpoint/ram_rag_store.snapshot.json` (OpenZFS ZFS PVC) with automatic SHA-256 verified cold-boot restoration after power loss.
    * After MR waves merge into `origin/main`, fast-forward `main`, run full post-merge verification (`inline_docs_migration.py verify`), and prepare pairwise-disjoint, conflict-free multi-branch waves (`#322`–`#333`) with an 8-scenario Hackathon Demo Rehearsal Harness ready for morning human review.
29. **Raspberry Pi 2B NOC Kiosk (`10.20.4.55`) Last-Graph Button Deadlock Fix & Cluster Overall Stats Default (`kiosk/`, `ADR-042`, `#280`, `!863`):**
    * Eliminate dual-iframe race conditions in `kiosk/kiosk.html` using `navigationSeq`, `cancelPendingTimersAndHandlers()`, separate `dataset.dashboardUrl` vs. `dataset.loadedUrl`, `LOAD_FALLBACK_TIMEOUT_MS: 3500`, and `reclaimKioskFocus()` so cross-origin Grafana iframes or slow-loading dashboards (`god-mode-overview`) never hijack button navigation.
    * Set `DASHBOARDS[0]` (`[1/9]`) in `kiosk/config.js` to Cluster Overall Stats (`https://grafana.cluster.example.org/d/noc-systems/noc-systems-overview?kiosk=1&refresh=5s`), auto-detect Wayland sockets vs. X11 `xdotool` fallback in `kiosk/kiosk_buttons.py`, and ensure both `/d/god-mode-overview` and `/d/noc-systems` show `CPU Load (%)` + `RAM Used (%)` in the top 1080p viewport.
30. **Overnight `/goal` Multi-Wave OpsCryer Polish, Open-Source Licensing, Usage/Test/Data-Retrieval Cookbook Examples & High-Confidence Test Suite (`LICENSE`, `NOTICE.md`, `docs/HACKATHON_USAGE_AND_DATA_RETRIEVAL_GUIDE.md`, `opscryer_data_retrieval_examples.py`, `opscryer_product_confidence_suite.py`):**
    * Provide complete Apache-2.0 open-source licensing (`LICENSE`) and third-party SBOM/SPDX attribution (`NOTICE.md`), runnable `curl`/Python/PowerShell/CLI data retrieval & testing examples across all OpsCryer endpoints, an OpenAPI 3.1 contract, an interactive Frontend Quickstart Drawer, and a comprehensive end-to-end Product Confidence Test Suite across multiple pairwise-disjoint waves.
31. **100% Product Completion, Turnkey 12-Feature Live Demo Showcase & High-Confidence Done-State Gate (`opscryer_live_demo_showcase.py`, `opscryer_done_state_master_verifier.py`, `docs/LIVE_DEMO_OPERATOR_SCRIPT.md`):**
    * Gate "100% done state" on a turnkey, single-command Live Demo of all 12 OpsCryer features (`python scripts/devops/opscryer_live_demo_showcase.py --run-all-live-demos` and interactive `--serve --port 8765` Command Center), backed by per-pillar E2E + mutation-tested verifiers (`#288`–`#299`), zero `Degraded` ArgoCD applications (`cache-warmer-airlock` `tmpfs` cross-device & read-only `/tmp/LICENSE` fix), and 100% pairwise-disjoint branch hygiene across all open MRs and queued waves.
32. **Anti-Fragile Dynamic Test Contracts & Fault Isolation (`Waves 29–33`, `.ai/skills/automated_testing/SKILL.md` Rule 5):**
    * All verifiers and unit tests must use `*_override` dependency injection, dynamic `>=` capability floors instead of brittle exact catalog counts, per-item `try/except` fault isolation, and `try/finally` state restoration.
33. **Token-Budget Conservation Mode & Presentation/FrontierReviewer Handoff Readiness:**
    * When weekly Argon/Flash token quota is low, immediately halt multi-wave MR generation, minimize tool/context overhead, verify existing open MRs (`!909`–`!944`) are green, and maintain turnkey Live Demo commands + a comprehensive FrontierReviewer Export/Review Handoff package.
34. **account-backed Codex CLI/Web Access + Local GPU Ollama Runtime, Commercial-Resale-Ready No-Warranty Public GitHub Release, Progressive-Zoom Dogfood Knowledge Graph, Overnight Epic Swarm & Two-Act Hackathon Demo Sanitizer (`#350`–`#352`):**
    * Use **account-backed Codex (`codex login` / `codex exec` / Codex Web)** for refining the public GitHub repository and running multi-Epic coding swarms (zero raw `sk-...` API key required), and use **Local GPU Ollama (`RTX 5080` + `RTX 3080`)** (plus optional `OPSCRYER_USE_CODEX_CLI=1` subprocess bridge) for OpsCryer's runtime `Jev` model inference during live demos. Export the zero-history GitHub public repository (`https://github.com/nahallacman/opscryer`) under a **single `Apache License 2.0`** (built-in Section 7 **"AS IS" / NO WARRANTY**, Section 8 **No Liability**, and Sections 2/4/9 **Commercial Resale Rights** with zero multi-license conflict risk), dogfood the entire project into a 5-level progressive-disclosure Knowledge Graph (`L0` System -> `L1` Epics/People/Open Tickets -> `L2` Projects & Feature Walkthroughs -> `L3` Backing Tests/MRs/Pipelines -> `L4` Runbooks & Fixes), and support the **Two-Act Hackathon Demo** (Act 1: standalone without live data; Act 2: live home-network telemetry where internal RFC 1918 LAN IPs and `.cluster.example.org` hostnames are kept intact, external public WAN IPs are scrubbed to `203.0.113.1`, and 6-octet MAC addresses are partially masked to `AA:BB:CC:XX:XX:XX`).
35. **Post-Hackathon Codex Token Retirement, Return to Multi-Session Desktop + K8s Antigravity + Local GPU Swarm & Single-Line Rule 9 Runners (`#354`–`#357`):**
    * The Codex CLI token allotment was a one-time hackathon resource and is retired (`max_codex_epics_per_run = 0`). All weekend and ongoing swarm development runs across the **Multi-Session Antigravity Fleet** (`desktop-commander` on `workstation-demo-01` + in-cluster K8s DevContainers `agy-master-sandbox`, `agy-ai-orchestrator`, `agy-frontend-app`) coordinated via `dev-envs/swarm-memory` (`https://opscryer.cluster.example.org` 16 GiB DDR4 RAM `tmpfs` broker) and `argon-planner` (`:8095`), paired with the **Local 3-GPU Ollama Hardware Fleet** (`nodegamma03` RTX 3080 10GB, `workstation-demo-01` RTX 5080 16GB, `amd-cracker-gpu` RTX 3070 8GB).
    * Always execute terminal commands as single-line Rule 9 pre-approved runners (`kubectl <op> (Get-Content <workspace>\scratch\k8s_<op>_args.txt)`, `git <op> (Get-Content <workspace>\scratch\git_<op>_args.txt)`, `python scripts/devops/gitlab_ops.py`) to prevent interactive approval prompts.
36. **Unified Codebase Collapse (`infra-gitops` Canonical), Dual-Tier Knowledge Graph Query Engine (Local Anti-Lost + Frontier Token-Saver) & Authoritative 4-GPU Hardware Inventory (`1x RTX 3080` + `1x RTX 3070 Ti` + `2x GTX 1080 Ti` = `40 GB VRAM`, `#354`):**
    * Collapse `opscryer-burn` (retired), `opscryer-public` (sanitized downstream export target only), and `infra-gitops` into **`<workspace>` as the single canonical codebase** (`python scripts/devops/gitlab_ops.py swarm collapse-clones`) holding `.ai/graphify/live_cluster_catalog.json`, the 5 canonical `kb-*` runbooks, and 1-command public release export (`scripts/devops/opscryer_public_release_builder.py`).
    * Serve the authoritative physical 4-GPU inventory (**`1x NVIDIA GeForce RTX 3080` (`10 GB GDDR6X`) + `1x NVIDIA GeForce RTX 3070 Ti` (`8 GB GDDR6X`) + `2x NVIDIA GeForce GTX 1080 Ti` (`2x 11 GB GDDR5X = 22 GB`) = `4 GPUs / 40 GB VRAM`**) via `swarm query-system` and `/api/v1/system-context`, actively flagging `"RTX 5080"`, `"RTX 4090"`, `"H100"`, or `"A100"` as `HALLUCINATING`.
    * Provide `local_gpu_anti_lost_pack` (strict `<= 2` file scope, exact AST line ranges, Intentional Scale-Down guardrails) so small local Ollama models (`phi3:latest`, `qwen2.5-coder:7b`, `llama3.1:8b`) never get lost, and `frontier_token_saver_brief` (`>95%` exploration token savings) so high-powered frontier models spend minimal tokens.
    * Route all script reads and modifications through the **6 Canonical Script Hubs (`CANONICAL_SCRIPT_HUBS`)** and `.ai/graphify/script_symbol_index.json` (`python scripts/devops/gitlab_ops.py swarm script-map`), using `targeted_read_file_slices` (`<= 60` lines / `~350` tokens) instead of reading whole `5,000`-line files or scanning `321` satellite scripts (`856,698` tokens = `99.95%` token reduction), and keep `scripts/*.py` free of zero-reference throwaway scripts.















37. **Swarm Setup Rework — Durable DDR4+ZFS Persistence, Setup/Execution Knowledge Architecture, High-Speed Indexed RAMCache & AI Orchestrator C2 Patterns (`#354`, `scripts/devops/swarm_c2_orchestrator.py`, `.ai/skills/swarm_c2_and_ramcache_architecture/SKILL.md`):**
    * **Dual-Tier DDR4 `tmpfs` + OpenZFS ZFS PVC Persistence:** Mount `swarm-ram-checkpoint-pvc` at `/mnt/ram-checkpoint` in `dev-envs/swarm-memory` alongside `/mnt/ram-rag` (`16Gi` DDR4 `tmpfs`), auto-hydrating on cold boot from SHA-256 verified snapshots and flushing dirty state via atomic `.tmp` + `os.replace()` snapshots plus an append-only C2 command journal.
    * **Generation-Indexed RAMCache (`<0.05ms` Hot Reads):** Pre-index inverted token/bigram maps and memoize hot C2/graph/RAG endpoints keyed by `store_generation`.
    * **5-Pattern C2 Architecture Integrated with the AI Orchestrator (`agy-ai-orchestrator` + `argon-planner`):** Route all directives, scope leases (with monotonic `fencing_token` and TTL), per-unit C2 command mailboxes (`ISSUED` -> `ACKED` -> `COMPLETED`), heartbeat drift/hallucination self-healing watchdogs, and the Argon High 6-Gate Pre-Push Audit through the central AI Orchestrator.

## 39. Nanomachine Swarm Heads-Up Visualizer (HUD), Measured Loadout Switching Time & Redundant Self-Healing Master Control (2026-10-30)
- **Tactical HUD, Pre-Swap Switching Impact & Overmind Triad Failover (`scripts/devops/swarm_c2_orchestrator.py`, `infrastructure/devcontainers/templates/swarm-memory.yaml`, `infrastructure/devcontainers/templates/nanobot-swarm.yaml`)**: Provide a Heads-Up Visualizer (`swarm c2 hud` + `/api/v1/c2/hud` + `/nanobots`), pre-swap switching time measurement (`evaluate_reconfiguration_switching_cost` with warm/cold VRAM modeling, EMA history, and anti-thrashing guard), and a redundant 3-node self-healing Master Control Quorum (`agy-ai-orchestrator` + `argon-planner` + `argon-overnight-autopilot` with `leader_epoch` failover and auto-rehydration).

## 40. Zero-Argon-Token Multi-Model Brain Takeover Ladder & Cockpit HUD (2026-10-30)
- **Autonomous Multi-Model Brain Takeover (`scripts/devops/swarm_c2_orchestrator.py`)**: Ensure the swarm is never stuck when Argon tokens run out (`0%` quota) by automatically failing over the Overmind Brain across `Tier 1 (Argon Frontier)` -> `Tier 2 (OpenAI/Codex/FrontierReviewer API)` -> `Tier 3 (Local 4-GPU Ollama Overmind: deepseek-r1:8b + qwen2.5-coder:7b + qwen2.5-coder:3b + llama3.1:8b grounded by RAMCache anti-lost packs)` -> `Tier 4 (Deterministic Python AST/C2 Engine)`, and surfacing the active brain provider in the Cockpit HUD.

## 41. Refined Nanobot Swarm Package, Ergonomic QoL (`preset`, `doctor`, `--auto-scope`, `--compact`) & Major Capabilities (Work-Stealing, Swarm Tick, Blackbox Flight Recorder) (2026-10-30)
- **Usable Nanobot Package & Ergonomic QoL (`scripts/devops/swarm_c2_orchestrator.py`, `scripts/devops/swarm_dispatch.py`)**: Provide 1-word operational presets (`code-blitz`, `security-audit`, `preflight-heal`, `deep-recon`, `zero-token`), a self-contained installable package exporter (`export_nanobot_swarm_package`), a 5-point `swarm c2 doctor` self-healer, smart `--auto-scope` ADR file inference on `orchestrate_mission`, and a `--compact` HUD status bar.
- **Cross-GPU Work-Stealing, Autonomous Tick & Blackbox Flight Recorder**: Automatically steal queued tasks from overloaded GPU mailboxes onto idle GPUs with warm VRAM models (`steal_and_rebalance_gpu_work`), advance task lifecycles + release Molecular Fencing Locks (`step_swarm_execution_tick`), and record a ring-buffered causal C2 Flight Recorder (`replay_c2_flight_recorder`).

## 42. Fast Spot-Check Test Runner vs. Mandatory Full Test Suite at Merge Gates (2026-10-30)
- **Inner-Loop Spot Checks vs. Merge Gate Full Verification (`test_runner_fast.py`)**: Fast test suites (`test_runner_fast.py`) are permitted for rapid inner-loop spot checks to minimize disk I/O and network load across multiple agent workspaces, but the **full test suite** (`unittest discover` + `golden_path_gates.py`) MUST run and pass at actual merge and release gates.

## 43. Lazy-Mode GUI Control Deck & Location-Independent `devenv` / `nanobot` Ergonomics (2026-10-30)
- **1-Click Lazy-Mode GUI & CWD-Independent Shims (`scripts/devops/swarm_c2_orchestrator.py`, `scripts/devops/devenv.py`, `nanobot.cmd`)**: Map all Nanobot Swarm CLI workflows to 1-click buttons in `/nanobots` (`POST /api/v1/c2/gui-action` and `swarm nanobot gui`), make bare `devenv` (with no args) default to `status` + repo directory jump, and generate absolute-path PowerShell functions (`devenv`, `nanobot`, `swarm`) so commands work from `PS C:\Users\nahal>` or any directory without `No such file or directory` or `CommandNotFoundException` errors.


## 44. 4-Worker Parallel Multi-Model Nanobot Squad & Concurrent Background Execution Pool (2026-10-30)
- **Full 4-Worker Parallel Multi-Model Squad (`scripts/devops/swarm_c2_orchestrator.py`)**: Maintain all 4 Nanobot workers (`nanobot-swarm-0` `qwen2.5-coder:7b` @ `gpu-worker-rtx3080`, `nanobot-swarm-1` `qwen2.5-coder:3b` @ `gpu-worker-rtx3070ti`, `nanobot-swarm-2` `llama3.1:8b` @ `gpu-worker-gtx1080ti-01`, `nanobot-swarm-3` `deepseek-r1:8b` @ `gpu-worker-gtx1080ti-02`), distribute missions across the least-loaded GPU/worker, and run a 4-thread parallel multi-model execution pool (`run_parallel_multi_model_swarm_wave` / `work-parallel` + background auto-worker in `serve_nanobot_gui`) with live per-worker task, model, and throughput telemetry in the HUD/GUI.

## 45. Local-GPU Nanobot Integration into Blue Team Network Hardening, VLAN Segmentation & End-to-End Traceability (2026-10-30)
- **Target Local 4-GPU Resources at Blue Team Network Protection, VLAN Segmentation & Traceability (`scripts/devops/swarm_c2_orchestrator.py`)**: Coordinate all 4 local-GPU Nanobot workers (`nanobot-swarm-0..3`, `40 GB VRAM`, `0` external tokens) via `run_blue_team_network_and_traceability_sweep` (`swarm nanobot blue-team` + `blue-team-shield` preset + 1-click GUI actions) to audit and harden NetFilter 4-port 2.5GbE VLAN segmentation (`VLAN 10/20/30/40`), K8s `default-deny` NetworkPolicies, MetalLB `externalTrafficPolicy: Cluster`, zero `hostNetwork: true`, DefectDojo `(CVE, Namespace, Target Workload)` composite-key triage (`MONITOR_SANDBOX_CODE=false`), and bidirectional Requirement $\rightarrow$ ADR $\rightarrow$ Manifest $\rightarrow$ Test traceability (`Traceability_Matrix.md` + `enforce_mr_traceability.py`).

## 46. Blue Team Safe Software Deployment & Golden Path Governance Engine (2026-10-30)
- **Blue Team Golden Path & Safe Deployment Doctrine (`scripts/devops/swarm_c2_orchestrator.py`)**: Equip the 4-GPU Nanobot Swarm (`audit_and_scaffold_golden_path_deployment`, `swarm nanobot golden-path`, `golden-path-deploy` preset, and GUI Section 7) with full Blue Team governance over safe software deployment: 3-tier Golden Path CI/CD (`Atomic Components` $\rightarrow$ `Golden Path Facades` $\rightarrow$ `Project Templates` with zero raw `script:` blocks), Zero-Test Hard Gate (`test-intake-reporter`), Secret & License Sovereignty Gates (`gitleaks`, OpenBao `ExternalSecret`, Apache-2.0/MIT/GPL check), Dual-Environment Lifecycle (`pr-<mr_id>-<app>` Ephemeral E2E $\rightarrow$ `vX.Y.Z` SemVer tag $\rightarrow$ ArgoCD `staging` $\rightarrow$ `prod` GitOps with zero direct AI prod deploy or MR auto-merge), and restricted K8s manifest standards (explicit non-`default` namespace, non-root `10001`, `readOnlyRootFilesystem`, and `NetworkPolicy`).

## 47. OpsCryer Wave 2 — Signed Action Cards, SSE + Delta Streaming, Third-Party Cybersecurity Forensics & Self-Healing Multipurpose Node Federation (2026-10-31)
- **OpsCryer Wave 2 Connectability & Autonomous Operations (`scratch/opscryer-public-suite/`)**: Enforce (1) signed 1-click Approve/Reject Human-in-the-Loop Action Cards with dry-run, idempotency, post-quantum SHA3-512/SHAKE-256 + hybrid multi-key exchange, single master key (`1-of-1`) for personal control auto-escalating to $k$-of-$n$ multi-key safety locks via a **4-Signal Composite Outcome Predictor** (blast radius $> K$ or critical tier, dry-run SLO/dependency degradation, active Sigma/OCSF alert on target, or anomalous mutation velocity/drift); (2) Severance Doctrine where prolonged disruption **defaults strictly to Encrypt-and-Rest** (seal state under post-quantum master public key, zeroize RAM secrets, sleep), while independent **"Persist, Resist, and Regrow"** mode is **never a fallback**, requires an explicit pre-signed Master warrant, and enters **Quarantine-Merge staging review** (via vector clocks) on reconnect; (3) Domain-Scoped Multi-Master support + 3-Regime Scale-Adaptive Governance ($N \le 7$ Captain of a Ship $O(1)$, $8 \le N \le 64$ Contingent Senators $O(\sqrt{N})$, $N > 64$ Capped $M_{\max}=13$ Senate $\le 5\%$ overhead with Root-attested trust tiers + peer canary proofs); (4) dual `GET /api/v1/events/stream` SSE + `GET /api/v1/graph/delta?since_seq=N` delta polling; and (5) Multi-Standard Cybersecurity Bridge (OCSF v1.1 + ECS/CEF + OpenTelemetry OTLP + Sigma detection rules with `(RuleID, Namespace/Node, Workload)` composite deduplication, 1-hop graph enrichment, and Wazuh/Falco/Suricata/DefectDojo/Elastic/Loki tiered forwarding) + built-in **Two-Tier MCP Capability Airlock** (read/recon open after airlock; mutating tools only dry-run and stage pending Action Cards).

## 48. Dual ArgoCD Prod + Fast-Test Dev Deployment & OpsCryer Wave 3 (`M11`–`M15`) (2026-10-31)
- **Dual Deployment Architecture & Wave 3 (`scratch/opscryer-public-suite/`, `gitops/apps/opscryer-prod.yaml`, `infrastructure/opscryer-prod/`, `infrastructure/devcontainers/templates/opscryer-suite-dev.yaml`)**: Maintain a GitOps-managed ArgoCD prod deployment (`opscryer-prod` in `namespace: security`) alongside a separate fast-test dev deployment (`opscryer-suite-dev` in `namespace: dev-envs` with dedicated sub-path ingress `ingress/opscryer-suite-dev` on `opscryer.cluster.example.org`). Wave 3 (`M11`–`M15`) implements: (`M11`) `gitops_promotion_bridge.py` (2-stage GitOps dev-to-prod promotion gate with SHA-256 bundle drift detection, full-suite + synthetic probe gates, and signed `promote_to_prod` Action Card + Compare URL); (`M12`) `tactical_security_deck.py` (Unified RTS/TBS `/tactical-deck` UI with live SSE ticker, $k$-of-$n$ Shamir share combiner modal, 1-hop blast-radius rings, OCSF/Sigma alert feed, and 3-Regime Federation/Quarantine-Merge inspector); (`M13`) `itsm_chatops_bridge.py` (bi-directional ITSM/GitLab ticket correlation + HMAC/PQC-signed interactive ChatOps callbacks for Action Card approvals and Tier-1 MCP recon); (`M14`) `flight_recorder.py` (OPSEC-scrubbed, PQC-signed JSONL incident capsules with deterministic $1\times$–$100\times$ replay in `dev-envs`); and (`M15`) `tests/test_e2e_wave3_gitops_tactical_itsm_replay.py` + full-suite merge gate verification.

## 49. Anti-Fragmentation & End-to-End Browser/Ingress/Concurrency Gate Over Isolated Unit Tests (2026-10-31)
- **Why Isolated Unit Tests Missed Live Browser Failures (`opscryer_browser.py`, `opscryer_suite_hub.py`, `tactical_security_deck.py`, `opscryer_public_release_builder.py`)**: Never ship multi-module waves where unit tests only exercise isolated Python functions or single-threaded sequential HTTP calls while the live K8s Ingress (`ingress/opscryer-suite-dev`), HTTP concurrency (`socketserver.TCPServer` deadlocked by an unbounded `EventSource('/api/v1/events/stream')`), and frontend `fetch()` probes (`/hub` probing `/api/v1/chat-concierge` without `?q=...`, `/tactical-deck` default node IDs) fail in a real browser. Always enforce: (1) multithreaded HTTP serving (`ThreadingMixIn` with `daemon_threads = True`), (2) 100% Ingress subpath parity with `route_registry.HTML_PORTAL_ROUTES` and `/api/v1`, and (3) an end-to-end link-crawler, concurrent SSE + parallel `fetch()` probe, and default UI action test before declaring any task done.

## 50. Unified RTS/TBS Spatial Graph Convergence — Second Deployment Simplicity + First Deployment Service Bar/Fast Finder + 60 FPS Multi-Level Zoom (2026-10-31)
- **Converge & Refine in One Centralized Graph (`opscryer_browser.py`)**: Use the second deployment's (`opscryer.cluster.example.org/suite-dev`) clean RTS/TBS simplicity as the primary foundation, combining it with the first deployment's (`opscryer.cluster.example.org/`) top-level service buttons and fast Question/Ops-Deployment/Service/Doc finder (for both humans and AI agents). Support varying levels of semantic zoom (`L0`–`L4` with nested child previews and connection arcs), 60 FPS rapid zoom responses (`<16.6ms` frame times via O(1) index maps and GPU-composited transforms that scale to 1,500+ nodes), and refined video-game system themes (`Terran Command`, `Nexus Warp`, `Civ Strategic`, `High-Contrast NOC`) that make operational data clearer and faster to navigate.

## 51. Clickable Nanomachine Swarm Interface, Non-Blocking Ability Casting HUD, Rolling $\mu$/$\sigma$ Adaptive Timeouts & $\sigma$-Sized Backoffs (2026-10-31)
- **Nanomachine Swarm Higher-Level Operations & Statistical Cast Engine (`opscryer_browser.py`)**: Make the Nanomachine Swarm (`swarm-nanomachine-fleet` and its child units `nanobot-4gpu`, `agy-ai-orchestrator`, `agy-master-sandbox`, `agy-frontend-app`, `argon-planner`, `swarm-memory`) directly clickable from higher-level operations (`L0`–`L2` and the top Fast Finder bar). Include non-blocking 60 FPS ability control buttons that display real-time casting progress, the active bottleneck phase (`DISPATCHING_COMMAND`, `SPINNING_UP_SERVICES`, `AWAITING_SWARM_RESPONSE`), rolling average casting time ($\mu$), standard deviation ($\sigma$), automatic timeout when cast duration exceeds several times the average ($T_{\text{timeout}} = \max(3\mu, \mu + 3\sigma)$), and standard-deviation-sized retry backoffs ($\text{Backoff}_k = \mu + k\sigma$).

## 52. Self-Aware Stage-Chain Latency & Single-Device Persistent Fast-Model Coalescing (2026-11-01)
- **Model Persistence & Stage-Chain Coalescing (`scripts/devops/swarm_c2_orchestrator.py`)**: Prevent multi-stage pipelines (e.g., 8-stage Golden Path `GP-STAGE-1..8` or 4-domain Blue Team sweeps) from stalling on cross-device data transfers and cold KV-cache re-prefills. The Swarm C2 engine (`evaluate_and_coalesce_stage_chain_persistence`, `swarm nanobot persist-model`, `persistent-fast` preset) continuously compares multi-device scatter latency ($T_{\text{scatter}}$) against reusing a single pinned (`keep_alive: "-1"`) fast warm model (`qwen2.5-coder:7b` @ `RTX 3080` or `qwen2.5-coder:3b` @ `RTX 3070 Ti`) with shared KV-cache prefix reuse ($T_{\text{persistent}}$). Whenever $T_{\text{scatter}}$ breaches the stage latency SLA budget, runs in a constrained environment, or $T_{\text{scatter}} / T_{\text{persistent}} \ge 1.25\times$, the swarm automatically coalesces all stages onto the single persistent loaded model (`0` cross-device hops).

## 53. Strict Product & Naming Boundary Between Nanobot Swarm and OpsCryer (2026-11-01)
- **Do Not Call Nanobot Swarm Features OpsCryer Features (`scripts/devops/swarm_c2_orchestrator.py`)**: Keep **Nanobot Swarm** (`nanobot-swarm`, `swarm`, `nanobot`) strictly distinct from **OpsCryer** (`opscryer`). Never label Nanobot Swarm commit messages, Golden Path scaffolded commit subjects, default GUI mission titles, or HUD headers as `feat(opscryer):` or `OPSCRYER C2`; always use `feat(nanobot):` / `feat(swarm):` and `NANOBOT SWARM C2`.

## 54. OpsCryer Connected Systems Relationship Tree & Reflection Data Gathering Engine (2026-11-01)
- **Connected Systems Tree & Live State Reflection (`scripts/devops/swarm_c2_orchestrator.py`)**: Trace and expose the explicit relationship tree (`OPSCRYER_CONNECTED_SYSTEMS_TREE_CATALOG` + `harvest_connected_systems_reflection_tree` + `swarm nanobot systems-tree` + `systems-tree` preset + GUI Section 9) linking OpsCryer (`opscryer-core`) to the 5 sovereign connected system domains (`system:nanobot-swarm`, `system:blue-team-shield`, `system:golden-path-delivery`, `system:identity-and-secrets`, `system:storage-and-telemetry`) and their 16 live child subsystems, gathering live operational state and distilling cross-system reflection telemetry into the `<0.05ms` DDR4 RAMCache.

## 55. Zero Faked/Canned Data on `/nanobots` — Mandatory Real Live Telemetry Probes (2026-11-01)
- **Never Display Static/Fake Numbers on `/nanobots` (`scripts/devops/swarm_c2_orchestrator.py`, `infrastructure/devcontainers/templates/swarm-memory.yaml`)**: Every metric on `/nanobots` (both `https://opscryer.cluster.example.org/nanobots` and `http://127.0.0.1:8099/nanobots`) must come from real live probes (`nvidia-smi` for GPU VRAM/temp/power/utilization, Ollama `/api/ps` + `/api/tags` for actually loaded vs. installed models, concurrent HTTP/TCP probes with real `ms` latency and HTTP status codes for connected systems, and real `git log` / filesystem stats) with explicit provenance badges (`LIVE_NVIDIA_SMI`, `LIVE_OLLAMA_PS`, `LIVE_HTTP_PROBE`, `LIVE_GIT_REPO`, or `REMOTE_UNPROBED`), and must be deployed live to `dev-envs/swarm-memory`.

## 56. Multi-Swarm & Multi-Cluster Separation in OpsCryer + Full Live Service & Infrastructure Audit Inventory (2026-11-01)
- **Composite `(cluster_id, swarm_id)` Tenancy Separation & Full Live Infrastructure Audit (`scripts/devops/swarm_c2_orchestrator.py`)**: Partition multiple Nanobot Swarms (`swarm:alpha-forge-c2`, `swarm:bravo-blue-team-sec`, `swarm:charlie-recon-harvester`) and multiple Kubernetes/compute/edge clusters (`cluster:homelab-prod-k8s`, `cluster:workstation-commander`, `cluster:edge-apu200-apu-fleet`, `cluster:wallboard-kiosk-01`, `cluster:core-network-storage` — `9` distinct hardware/virtual nodes) by `(cluster_id, swarm_id)` so OpsCryer can filter, isolate, and compare them cleanly without lock or telemetry collisions. Expose a live `kubectl` + hardware Service & Infrastructure Audit engine (`audit_multi_cluster_swarms_and_live_infrastructure`, `swarm nanobot infra-audit`, `infra-audit` preset, and GUI Section 10) covering all nodes, namespaces, services, ingresses, workloads, PVCs, and audit anomalies.

## 57. Live In-Cluster Nanobot Swarm (`StatefulSet/nanobot-swarm` 4/4 Pods) & AI Orchestrator (`Deployment/agy-ai-orchestrator:8094`) Integration (2026-11-01)
- **Deploy 4-Pod `nanobot-swarm` StatefulSet & `agy-ai-orchestrator` C2 Daemon on Cluster (`infrastructure/devcontainers/templates/nanobot-swarm.yaml`, `infrastructure/devcontainers/templates/swarm-memory.yaml`, `scripts/devops/swarm_c2_orchestrator.py`)**: Ensure all 4 ordinal Nanobot workers (`nanobot-swarm-0..3`) run live in `namespace: dev-envs` via `StatefulSet/nanobot-swarm` (`replicas: 4`) and are bidirectionally integrated with an in-cluster `Deployment/agy-ai-orchestrator` (`Service/agy-ai-orchestrator:8094`), `argon-planner:8095`, `argon-overnight-autopilot:8098`, and `swarm-memory:8090` (`/api/v1/orchestrator/status`, `/api/v1/orchestrator/dispatch`, `/api/v1/nanobot/execute`, `/api/v1/c2/cluster-swarm`).

## 58. Unified Single-Cockpit OpsCryer & Real Live Tool Integration Over "15 Disjoint Faked Programs" (2026-11-01)
- **Eliminate Disjoint Multi-Page Fragmentation & Fake/Static Data (`opscryer_browser.py`, `infrastructure/devcontainers/templates/swarm-memory.yaml`, `scripts/devops/swarm_c2_orchestrator.py`)**: OpsCryer must not feel like 15 separate mini-programs with different layouts and mocked data. Embed all operational tools (`Nanobot Swarm C2`, `Tactical Security & Action Cards`, `Incidents`, `Capacity & GPUs`, `Network & OIDC`, `GitOps & CI`, `SecOps & CVEs`, `Storage ZFS`, `KB & Runbooks`, `Game Servers`, `Live Infra Audit`) into one cohesive OpsCryer command interface with an integrated contextual Tool Dock bound to the selected graph node, auto-hydrating real live cluster/service state and executing real live service probes/commands (with real measured wall-clock latency for $\mu/\sigma$ casting and explicit `LIVE_CLUSTER_EXECUTION` provenance badges).

## 59. Strict Device Separation: AMD APU-200 APU Computers (`10.20.4.51` / `10.20.4.52`) vs. Raspberry Pi 2B NOC Kiosk (`10.20.4.55`) (2026-11-01)
- **Never Combine `apu-200` and `wallboard-kiosk-01` Into One Node Entry (`scripts/devops/swarm_c2_orchestrator.py`)**: The **AMD APU-200 RDNA2 APU computers** (`apu200-livingroom-01` @ `10.20.4.51` and `apu200-bedroom-02` @ `10.20.4.52`, `6C/12T Zen 2 + 16 GiB Unified GDDR6 RDNA2 APU` Linux gaming/compute clients in `cluster:edge-apu200-apu-fleet`) and the **Raspberry Pi 2B NOC Kiosk** (`wallboard-kiosk-01` @ `10.20.4.55`, `ARMv7 4C 1 GiB RAM` GPIO hardware button wallboard display in `cluster:wallboard-kiosk-01`) are completely separate physical devices with distinct hardware architectures and roles. Always model, filter, and audit them as separate device/cluster entries (`5` federated cluster/device tiers and `9` total hardware/virtual nodes).

## 60. No 10GbE Fiber Backend Yet — Accurate 1 Gbps RJ45 (`TP-Link TL-SG3428`) + NetFilter `4x 2.5GbE` Network Ground Truth (2026-11-01)
- **Never Claim an Active 10G / 10GbE Fiber Backend (`scripts/devops/swarm_c2_orchestrator.py`, `infrastructure/devcontainers/templates/swarm-memory.yaml`)**: All VLAN 30 servers (`nodegamma03` `10.20.3.13`, `nas` OpenZFS SCALE `10.20.3.5`/`10.20.3.10`, `nodealpha01` `10.20.3.2`, `nodebeta02` `10.20.3.10`) currently connect via **single `1 Gbps RJ45` copper uplinks (`~112 MB/s` practical TCP/NFS ceiling)** to the **`TP-Link TL-SG3428`** (`10.20.3.250`, `24x 1GbE RJ45 + 4x 1G SFP`) switch and **`NetFilter Netgate 4200`** (`4x 2.5GbE RJ45`). The `10GbE SFP+` fiber backend is a future upgrade path and is **not installed yet** (`nodebeta02`'s `2x 10GbE SFP+ X710` cages are unpopulated). Always report `1GbE RJ45 (~112 MB/s ceiling; No 10G Fiber Backend Yet)` in VLAN/cluster/storage telemetry.

## 61. Zero-Token Autonomous Swarm Execution Mode (`TIER_3_LOCAL_4GPU_OLLAMA_OVERMIND` + `TIER_4_DETERMINISTIC_PYTHON_AST_C2`, Zero Argon/Antigravity Token Burn) (2026-11-01)
- **100% Local 4-GPU + Deterministic AST Execution Without Argon or Antigravity (`scripts/devops/swarm_c2_orchestrator.py`, `scripts/devops/swarm_dispatch.py`, `https://opscryer.cluster.example.org/nanobots`)**: When weekly cloud tokens are low, lock the Swarm Brain Provider to **`TIER_3_LOCAL_4GPU_OLLAMA_OVERMIND`** (`0%` Argon/Antigravity tokens) via `swarm c2 preset zero-token` (`deepseek-r1:8b`, `qwen2.5-coder:7b`, `qwen2.5-coder:3b`, `llama3.1:8b` across `1x RTX 3080 10GB + 1x RTX 3070 Ti 8GB + 2x GTX 1080 Ti 22GB = 40 GB VRAM`) + **`TIER_4_DETERMINISTIC_PYTHON_AST_C2`**. Tasks can be queued, executed in parallel across all 4 GPUs, and verified via browser (`https://opscryer.cluster.example.org/nanobots` / `https://opscryer.cluster.example.org`), the local GUI daemon (`swarm c2 gui --open` with background `_auto_worker_loop`), or CLI (`swarm c2 orchestrate --prefer-local-gpu`, `swarm c2 work-parallel --complete`, `swarm c2 cluster-sync --dispatch-wave`, `swarm dispatch-backlog`) with zero Argon or Antigravity sessions running.

## 62. Permanent In-Cluster C2 Master (`agy-ai-orchestrator:8094`), Live Working `/nanobots` GUI Buttons, Key-Based Commander Auth, 4-Way Task Subdivision & Local Agent Trigger Skill (2026-11-01)
- **In-Cluster C2 Master, Sovereign Key Auth & Conversational Local Agent Trigger (`infrastructure/devcontainers/templates/nanobot-swarm.yaml`, `infrastructure/devcontainers/templates/swarm-memory.yaml`, `scripts/devops/swarm_c2_orchestrator.py`, `.ai/skills/local_agent_swarm_operator/SKILL.md`)**: Serve `/nanobots`, `/c2`, and `/api/v1/c2/*` permanently from the in-cluster C2 Master (`Deployment/agy-ai-orchestrator` on `:8094` backed by `swarm-memory:8090`) so every GUI button executes real C2 actions and dynamically re-renders live state (never serving a static cached `hot_nanobots_html` snapshot). Enforce **Cryptographic Key-Based Commander Authority (`MasterKeyAuthority` / `X-Swarm-Master-Key`)** so the human operator remains strictly in charge of privileged actions (`master-override`, `emergency-halt`, `set-autonomy-policy`, `promote-prod`) while allowing the C2 Master to autonomously **subdivide** parent missions into 4 disjoint child sub-tasks (`SUBTASK-W0..W3`) across `nanobot-swarm-0..3`, iterate overnight at `0` Argon tokens, and accept natural-language triggers via local Ollama agents (`POST /api/v1/c2/talk` / `swarm c2 talk`).

## 63. High-Signal `ntfy` Notification System Overhaul — Anti-Spam, Deduplication & Actionable Digests (2026-11-04)
- **Noisy `ntfy` Spam Elimination (`notification_arbitrator` skill, `infrastructure/notifications/notification-arbitrator/deployment.yaml`, `infrastructure/notifications/notification-arbitrator/app.py`, `monitoring/ntfy-bridge.yaml`, `scripts/monitoring/notification_filter_engine.py`)**: Never emit raw per-tick, per-subtask, `resolved`, `info`, `warning`, or unthrottled repetitive alerts to `ntfy`. Mount `ConfigMap/notification-arbitrator-app` at `/app/app.py` (`subPath: app.py`), remove legacy 5m/10m GitLab nag timers, route `monitoring/ntfy-bridge` through `http://notification-arbitrator.notifications.svc.cluster.local/webhooks/alertmanager`, and enforce persistent SQLite 6-hour (`21600s`) per-fingerprint deduplication (`push_dedup_ledger`) + daily caps (`push_daily_log`) so the user only receives high-signal Zero-Knowledge notifications (newly opened non-draft MRs ready for review, consolidated Swarm Wave Digests, `main` branch pipeline failures, or genuine critical infrastructure/security incidents).

## 64. Zero Home-Stack Data in OpsCryer Public Releases — Strict OPSEC Isolation (`C:\dev\opscryer-public` & Public Exporters) (2026-11-04)
- **Never Ship Any Copy of the Home Stack in Public Releases (`C:\dev\opscryer-public`, `scratch/opscryer-public-suite`, `scripts/devops/opscryer_public_release_builder.py`, `scripts/devops/agent_context_graph_bridge.py`)**: Never bundle `live-cluster-sanitized.json` (`live_kubectl` cluster dumps) or any homelab topology (`nodegamma03`, `nodebeta02`, `nodealpha01`, `apu200`, `*.cluster.example.org`, `10.10.x.x`, `192.168.1.x`, `packet-aggregator-demo`, `openzfs`, `netfilter`, `runbookgate`, real K8s namespaces/deployments/pods/ingresses, or homelab GPU inventories) into `C:\dev\opscryer-public` or any public release package. Public releases must ship **only** generic synthetic demo data (`example.org`, RFC 5737 `192.0.2.x` / `198.51.100.x` / `203.0.113.x`, generic `node-alpha-01` / `app-production` workloads), enforce hard OPSEC fail-closed tests (`0` violations across `1125` tests), and push only a clean single-commit orphan history to `https://github.com/nahallacman/opscryer`.

## 65. Work-Ready Development Skills & Customizations Package Exporter with Strict PII, Media Stack & VPN Removal (2026-11-06)
- **Sanitized Portable Work Package (`scripts/devops/devenv.py`, `scripts/devops/swarm_dispatch.py`, `export_work_skills_package`, `scan_work_skills_export_for_leaks`)**: When packaging workspace development skills, rules, and knowledge docs for use at work (`python scripts/devops/devenv.py export-work-skills` or `python scripts/devops/gitlab_ops.py swarm export-work-skills`), generate both a Global Antigravity Plugin (`antigravity-plugin/work-dev-skills/`) and a Workspace Repository Starter Kit (`workspace-starter-kit/`) plus `dist/work-dev-skills-package.zip`. Enforce a fail-closed 4-category sanitizer and leak scanner (`0` matches required) that strips all **personal & homelab PII** (`opscryer-maintainers`, `nahal`, `C:\Users\nahal`, `infra-gitops`, `*.cluster.example.org`, `10.10.x.x`, `192.168.x.x`, `nodegamma03`, `nodebeta02`, `nodealpha01`, `openzfs`, `netfilter`, `packet-aggregator-demo`, etc.), **media stack references** (`jellyfin`, `sonarr`, `radarr`, `prowlarr`, `nzbget`, `plex`, `qbittorrent`, `seerr`, `media-stack`, `media-gateway`, `namespace: media`), **VPN connections** (`vpn`, `gluetun`, `tailscale`, `wireguard`, `openvpn`, `wintun`, `headscale`, `mullvad`, `pia`, `hole-punching`), and **gaming/household references** (`factorio`, `satisfactory`, `minecraft`, `helldivers`, `steam-headless`, `vesktop`, `game-servers`).

## 66. Port 4 (`PORT4WIFI` / `opt2` / `10.20.5.0/24`) Upstairs Network Rework & Single Trusted Dev PC Target Architecture (2026-11-06)
- **Upstairs Subnet Ingress Parity & Single Trusted Dev PC Target (`internal-portal/calico-network-policy.yaml`, `infrastructure/network/firewall_rules.tf`, `.ai/knowledge/environment/workstation_and_network.md`)**: On the live Netgate 4200 (`https://router.cluster.example.org`), `PORT2LAN` (`lan`) is `10.20.4.0/24`, `PORT3LAN2` (`opt1`) is `10.20.3.0/24` (K8s Server Rack VLAN), and `PORT4WIFI` (`opt2`) is `10.20.5.0/24` (Upstairs drop to dumb switch with 2 upstairs PCs + Wi-Fi AP). Ensure `ingress-nginx` NetworkPolicy (`internal-portal/calico-network-policy.yaml`) includes `10.20.3.0/24`, `10.20.4.0/24`, and `10.20.5.0/24` so upstairs devices can reach Jellyfin (`172.20.1.210`) and Authentik SSO (`auth.cluster.example.org`) for the Download Organizer stack (`172.20.1.211`), while tracking the target end-state where only the single Trusted Dev PC (`10.20.4.22/32`) has control-plane access once the Living Room VLAN switch is isolated.




























## 67. Staged Cluster Upgrade Sequence — ArgoCD Settlement (`v10.10.5`), GitLab (`puma=4`, `12Gi` on `nodegamma03`) + GitLab Runner (`v0.94.3`), Authentik (`v2026.8.5`), and OpenBao (`v0.30.4`) (2026-11-06)
- **Helm `Chart.lock` Sync, PreSync Istio Exclusion, Puma Headroom & `nodegamma03` Pinning (`infrastructure/argocd/`, `gitlab/`, `scripts/devops/tls_trust.py`, `scripts/devops/swarm_dispatch.py`)**: Always sync `Chart.lock` (`tls_trust.sync_all_helm_chart_locks()` / `swarm_dispatch.py upgrade-preflight`) whenever Renovate bumps `Chart.yaml` (`infrastructure/argocd` `10.10.5`, `gitlab` `gitlab-runner` `0.94.3`), annotate ArgoCD's `redisSecretInit` PreSync Job with `sidecar.istio.io/inject: "false"`, verify GitLab batched background migrations (`0` pending) before upgrade, and pin `Deployment/gitlab` (`StrategyType: Recreate`, ~1–2 min `503` rollout downtime per Rule 8) to `nodegamma03` (`128 GiB` RAM) with `sidecar.istio.io/inject: "false"`, `puma['worker_processes'] = 4`, and `limits.memory: 12Gi`.

## 68. Herdr (`herdr` / `hc`) + Gemini CLI (`gemini`) Multi-Agent Terminal Runtime, Hopper AI Orchestrator (`AIOrchestrator/`) Agent Integration, In-Cluster DevContainer Endpoints & Google gVisor (`runsc`) + OCSF v1.1 Sandboxing (2026-11-06)
- **Herdr + Gemini CLI + Hopper Orchestrator + gVisor (`runsc`) / OCSF v1.1 (`infrastructure/devcontainers/`, `AIOrchestrator/`, `scripts/devops/agy_fleet.py`, `.ai/skills/remote_workspaces/SKILL.md`)**: Provision `/usr/local/bin/herdr-gemini-init` and `/usr/local/bin/hopper-agent-cli` inside `ConfigMap/workspace-agy-bootstrap`, inject `HOPPER_API_URL=http://hopper-api-gateway-service.ai-infra.svc.cluster.local:8000` and `HOPPER_INGRESS_URL=https://aiorchestrator.cluster.example.org` into `dev-envs` DevContainers (`workspace-ai-orchestrator-0` @ `172.20.1.220`, `workspace-frontend-app-0` @ `172.20.1.219`, `workspace-master-sandbox-0` @ `172.20.1.221`), support `RuntimeClass/gvisor` (`handler: runsc`, mutually exclusive with `--dind`) in `statefulset.yaml` and `gvisor-runsc.yaml`, and provide `agy_fleet.py` subcommands (`herdr-init`, `hopper-status`, `gvisor-ocsf-plan`, and `spawn --runtime runsc`) with OCSF v1.1 security event normalization (`class_uid: 1007` Process Activity, `class_uid: 4001` Network Activity, `class_uid: 6003` API Activity).

## 69. Low-Power AI Consumption Entrypoint, Pluggable Knowledge Graph + `Jev` Model Abstraction & Multi-Agent RAMCache with Swappable No-Database / Database-Interface Backends (2026-11-06)
- **Pluggable Knowledge Graph + `Jev` Abstraction & Swappable Database-Interface RAMCache (`opscryer_abstraction.py`, `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md`)**: Provide a `<350`-token quick-context digest (`--ai-brief`) for lower-powered work-machine AI models, a 1-call pluggable system registry (`OpsCryerSystemPluginHub.register_system`) that auto-wires `SpatialGraphContract v1` + System-2/System-1 `Jev` decision trees (`JevModelAbstraction`), and a cross-agent `MultiAgentRAMCacheHub` speaking a uniform `RAMCacheDBInterface` (`upsert`, `select`, `delete`, `search_text`, `execute_query`) that hot-swaps (`switch_engine` / `auto_switch_on_throughput_pressure`) between `sqlite_memory_db`, `no_db_dict_ramcache` ("no-database RAMCache that interacts through the database interface"), and `sharded_ring_ramcache` with zero data loss.

## 70. Satisfactory Nightly Restart CronJob Calico DNAT Fix (`10.20.3.2:6443`) & Elimination of 5:00 PM PDT / 4:00 PM PST (`00:00 UTC`) Auto-Restart (2026-11-06)
- **Satisfactory Dedicated Server Maintenance & Restart Slot Alignment (`infrastructure/game-servers/network-policies.yaml`, `infrastructure/game-servers/satisfactory.yaml`, `infrastructure/game-servers/maintenance.yaml`, `tests/test_game_servers_isolation.py`)**: Allow post-`kube-proxy`-DNAT `10.20.3.2/32` port `6443` in `allow-restart-cronjob-kube-api` so `satisfactory-nightly-restart` can reach the `hostNetwork` `kube-apiserver` on `nodealpha01`, and configure `FG.ServerRestartTimeSlot=660.0` (`11:00 UTC` = 4:00 AM PDT / 3:00 AM PST) in `GameUserSettings.ini` and `Engine.ini` instead of `0.0` (`00:00 UTC` = 5:00 PM PDT / 4:00 PM PST).

## 71. 4-Zone Wi-Fi & 802.1Q VLAN Segmentation Architecture, Bidirectionally Isolated Work VLAN (`VLAN 70`), Living Room + Server Managed Switch VLANs, Knowledge Graph VLAN Encoding & Metrics Rollup (2026-11-07)
- **4 Wi-Fi Zones, Bidirectional Work VLAN (`VLAN 70`), Living Room & Server Managed Switch VLANs, and Knowledge Graph / Metrics Sync (`infrastructure/network/`, `scripts/devops/company_org_model.py`, `.ai/graphify/`, `scripts/monitoring/`)**:
  1. **4 Wi-Fi Zones + Dedicated Work VLAN (`VLAN 70`) + Server Switch Security Camera VLAN (`VLAN 90`)**: (a) **Outside-the-Network Wi-Fi 7 (`172.20.0.0/24`)** with 10GbE passthrough physically between the Fiber Modem and NetFilter `PORT1WAN` (`172.20.0.10`); (b) **Regular Devices (`PORT4WIFI` `10.20.5.0/24` / VLAN 50)** on the upstairs AP + dumb switch + 2 upstairs PCs; (c) **Dedicated IoT Wi-Fi (`VLAN 80` `10.20.8.0/24`)** on a dedicated Living Room switch port + AP; (d) **Dedicated Home Automation Wi-Fi (`VLAN 60` `10.20.6.0/24`)** on a dedicated Living Room switch port + AP; (e) **Dedicated Work Laptop VLAN (`VLAN 70` `10.20.7.0/24`)** with **strict bidirectional isolation** (Work Laptop can ONLY talk to the Internet `!RFC1918_Private` and is blocked even from MetalLB VIPs; and a top-priority Floating/Interface Block rule prevents ALL other networks — including `PORT2LAN` Trusted Dev PC `10.20.4.22` and `PORT3LAN2` servers `10.20.3.0/24` — from initiating connections into `10.20.7.0/24`); (f) **Security Cameras / NVR Enclave (`VLAN 90` `10.20.9.0/24` on `PORT3LAN2` / `igc2.90`)** trunked as Tagged `VLAN 90` to the Server Rack `TP-Link TL-SG3428` (`10.20.3.250`) and broken out to untagged `PVID 90` ports (strictly blocked from both the Internet and general LANs, allowing only local NVR/Frigate ingestion).
  2. **Zero-Trust Firewall Boundary**: Only the single Trusted Dev PC (`10.20.4.22/32` on the Living Room Managed VLAN Switch on `PORT2LAN`) has full Control Plane access (`10.20.3.0/24`, NetFilter GUI `:44380`, K8s `:6443`, OpenZFS `.3.5`, IPMI `.3.4`), except it too is blocked from talking to `WORK_VLAN` (`10.20.7.0/24`). Regular household devices on **Upstairs (`VLAN 50` / `PORT4WIFI` `10.20.5.0/24`)** and **Living Room + Office (`VLAN 40` / `PORT2LAN` `10.20.4.0/24` except `.4.22`)** only reach Homelab User Services via MetalLB VIPs (`172.20.1.210–213`: **`requests`** [`requests.cluster.example.org` / `seerr.cluster.example.org`], **`internal`** [`internal.cluster.example.org` / `media.internal.cluster.example.org`], `auth.cluster.example.org`, Jellyfin, Emby, Download Organizer, and Game Servers) + DNS + Internet, while `WORK_VLAN` (`VLAN 70`), `IOT_VLAN` (`VLAN 80`), `HOMEAUTO_VLAN` (`VLAN 60`), and `CAMERAS_VLAN` (`VLAN 90`) are strictly isolated from all internal subnets and control planes.




## 72. Herdr (`hc`) Brain Controlling a CLI Sub-Agent Fleet (`gemini-3.8-flash`) with Zero-Guessing Knowledge Graph Action Resolution (2026-11-07)
- **Herdr Brain + `gemini-3.8-flash` Sub-Agent Fleet & Zero-Guessing Resolver (`opscryer_abstraction.py`, `scripts/devops/agy_fleet.py`, `infrastructure/devcontainers/templates/configmap.yaml`)**: Spin up `herdr-brain-prime` (`--herdr-brain-test`) to control CLI sub-agents (`subagent-flash38-kg-01` via `gemini -m gemini-3.8-flash`), hydrate the Knowledge Graph + `Jev` playbooks into `MultiAgentRAMCacheHub`, and enforce `verify_no_guessing_contract()` so sub-agents return only `VERIFIED_EXPLICIT_ACTIONS` (exact commands, URLs, IT tickets, `tree_sha256`) or fail-closed `REFUSED_UNVERIFIED_NO_GUESSING` without ever guessing.

## 73. Progressive Knowledge Graph Training Over Time from Settled Production Systems & Rigorous Multi-Epoch / Adversarial / Cross-Engine Testing (2026-11-07)
- **Settled 8-System Integration & 5-Gate Progressive Knowledge Graph Trainer (`opscryer_abstraction.py`, `scripts/devops/graph_knowledge_harvester.py`, `.ai/graphify/support_ticket_playbooks.json`, `tests/test_opscryer_jev_ramcache_abstraction.py`)**: Integrate all 8 settled production systems (`argocd`, `gitlab`, `authentik`, `harbor`, `openbao`, `openzfs_nas`, `opscryer_hud`, `hopper_orchestrator`) and train the Knowledge Graph iteratively across epochs (`ContinuousGraphTrainer` / `--train-graph-over-time`) using a 5-Gate Training Sandbox (`schema_and_keyword_hygiene`, `acyclic_dag_and_spatial_graph_integrity`, `zero_regression_on_settled_benchmark`, `sample_episode_self_test`, `zero_guessing_and_adversarial_refusal_guard`), verified by multi-epoch curriculum tests, adversarial near-miss confusion tests, poisoned-proposal rejection tests, and 3-engine RAMCache hot-swap parity tests.

## 74. Human-Centric Rapid Active Monitoring & Debug Deep-Linking (`HumanMonitoringLinkMatrix v1`) Across Knowledge Graph Nodes & Live OpsCryer Deployment (2026-11-07)
- **6-Pillar Human Active Monitoring Deep-Links (`opscryer_abstraction.py`, `scripts/devops/spatial_graph_browser.py`, `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md`)**: Every Knowledge Graph node and resolved `Jev` action plan MUST bake in accurate, system-scoped `human_monitoring_links` across all 6 active human monitoring surfaces (`grafana_dashboard_url`, `gitlab_source_and_pipelines_url`, `herdr_agent_pane_link`, `dependency_analyzer_url`, `argocd_application_url`, `security_dashboard_url`, plus `live_opscryer_debug_url`), verified by `verify_human_monitoring_link_matrix()` and Gate 6 (`gate_6_human_monitoring_deep_links_verified`) of `ContinuousGraphTrainer`.

## 75. Cryptographically Signed Sovereign RAMCache, Shared Knowledge Graph Delta Patching & Auto-Update / Opt-In Swarm Broadcast (`SignedSharedRAMCacheFederation v1`) (2026-11-07)
- **Signed RAMCache Delta Patches & Swarm Auto-Update (`opscryer_abstraction.py`, `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md`, `tests/test_opscryer_jev_ramcache_abstraction.py`)**: Partition the RAMCache into shared (`graph_nodes`, `training_epochs`, `swarm_alignment_goals`, shared playbooks/observations) vs. node-local state, compute canonical `state_sha256` + cryptographic signatures (`SignedKnowledgeGraphPatch v1`), generate signed delta patches on significant Knowledge Graph or Swarm Control updates, and push them to subscriber RAMCache instances supporting both `AUTO_UPDATE` (immediate verification + application for swarm control, self-improvement, and goal alignment) and `EXPLICIT_ACCEPT` (staging verified patches until accepted), while fail-closed rejecting any tampered signature.

## 76. Autonomous End-to-End Live Cluster Endpoint, Dashboard Panel & Missing-Metric Synthesis Loop (`ClusterFullObservabilityCoverageLoop v1`) (2026-11-07)
- **End-to-End Endpoint, Dashboard Panel & Metric Coverage Loop (`scripts/monitoring/audit_dashboards.py`, `opscryer_abstraction.py`, `monitoring/templates/`)**: Run an autonomous verification loop auditing every live endpoint, cluster node, namespace/project, and Grafana dashboard panel end-to-end; whenever a project, node, endpoint, or panel lacks appropriate Prometheus metrics or Knowledge Graph coverage, create/update the Prometheus recording rules/metrics, dashboard queries, and Knowledge Graph nodes until 100% coverage is verified.

## 77. Developer-to-Knowledge-Graph Interview, Real-Data Assumption Verification, Real-Test Execution, Developer/Manager Re-Review & Rapid Best-Practice Generator Loop (`DeveloperKnowledgeGraphFeedbackLoop v1`) (2026-11-07)
- **5-Stage Developer Knowledge Graph Feedback & Rapid Best-Practice Loop (`scripts/devops/developer_kg_feedback_loop.py`, `opscryer_abstraction.py`, `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md`, `tests/test_opscryer_jev_ramcache_abstraction.py`)**: Provide an end-to-end feedback loop where developers interview with the AI (`DeveloperKnowledgeInterviewSession v1`), the AI verifies every assumption against real repository implementations and live cluster/Prometheus data (`AssumptionRealityVerifier v1`), stages a Knowledge Graph + `Jev` update and executes real tests (`StagedGraphUpdateAndTestHarness v1`), presents a final Re-Review Packet for Developer or Manager sign-off (`DeveloperManagerReviewPacket v1`) before signed RAMCache promotion, and uses the accumulated team-verified graph to rapidly synthesize best-practice Skills, Playbooks, Designs, Integrations, and GitOps Deployments (`BestPracticeArtifactSynthesizer v1`).



## 78. Ungraphed In-Scope Repository & Cluster Inventory Analysis, Multi-System Developer Feedback Loop Onboarding & End-to-End Verification (2026-11-07)
- **Ungraphed Scope Discovery & Batch 5-Stage Feedback Loop Onboarding (`scripts/devops/developer_kg_feedback_loop.py`, `opscryer_abstraction.py`, `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md`, `tests/test_opscryer_jev_ramcache_abstraction.py`)**: Automatically scan the repository (`infrastructure/*`, `gitops/apps/*.yaml`, `dependency-mapper/`, `PROJECT_DEFINITIONS`, `SYSTEM_NODE_CATALOG`) to identify all real in-scope systems not yet in `SETTLED_PRODUCTION_SYSTEM_CATALOG`, and run the 5-stage Developer-to-Knowledge-Graph Feedback Loop (`UngraphedScopeInventoryAnalyzer v1` + `BatchUngraphedScopeOnboardingCampaign v1`) across all ungraphed items (`defectdojo`, `dependency_mapper`, `devcontainers`, `game_servers`, `media`, `streaming`, `network_vlan_firewall`, `monitoring_stack`) with `.yaml`/`.tf`/`.json`/`.py` reality verification, cross-system `Jev` collision guards, Developer/Manager review gates, signed RAMCache federation broadcast, and 5-part best-practice artifact synthesis.


## 79. Devenv Pre-Commit Hook CI Parity & Runner K8s Executor QoS Guard (2026-11-07)
- **Mandate**: Every repository commit and push must be gated locally by the `devenv` pre-commit / pre-push hook (`scripts/devops/tls_trust.py --run-pre-commit-checks`) with 100% parity against the GitLab CI pipeline stages so failures are caught locally before CI/CD runs:
  1. **TruffleHog + Gitleaks Local Secret & High-Entropy Scan (`trufflehog_secret_scan_passed`)**: Scans all modified/staged files and commit diffs for verified secret signatures, private keys, tokens, and high-entropy credentials.
  2. **GitLab Runner K8s Executor QoS & Node-Pinning Audit (`runner_k8s_qos_and_pinning_passed`)**: Verifies that `gitlab/values.yaml` pins `[runners.kubernetes.node_selector]` to `nodegamma03` and defines non-zero `memory_request` and `helper_memory_request` (`Burstable` QoS) so ephemeral CI job pods never run with `request: 0` (`BestEffort`) or get evicted by Kubelet on `nodealpha01`.
  3. **Full Lint & Governance Parity**: Enforces LF line endings, `yamllint-manifests`, `k8s-manifest-standards`, `grafana-dashboard-standards`, `orphan-audit`, `traceability-audit`, `helm-lint`, `Chart.lock` digest sync, and `validate-aicac` (`check_skills.py`).


## 80. Autonomous Live-Cluster & Sub-Agent End-to-End Verification Mandate (2026-11-07)
- **Mandate**: When the user delegates autonomous testing (*"Go for it, test more where you can"*), execute deep live-cluster verification (`LiveClusterKnowledgeGraphVerifier v1`) comparing every Knowledge Graph node, manifest path, service port, and ingress URL against live Kubernetes cluster state (`kubectl get deploy,sts,ds,svc,ingress -A`), onboard any remaining live cluster infrastructure pillars (`istio_ambient_ztunnel`, `cert_manager_pki`, `harbor_registry_proxy`, `renovate_cicd_components`, `opscryer_live_control_plane`), verify with a live Flash 3.8 sub-agent (`0%` guessing), and gate via `devenv` pre-commit CI parity before pushing.

## 81. Anti-Brittle Structural & Property Testing Standard (`2026-11-07`)
- **Mandate**: Never rely on brittle raw substring matching (`assertIn('key: "false"', text)`) or hardcoded magic catalog counts (`assertEqual(count, 23)`) when testing YAML, TOML, or Knowledge Graph catalogs. Always parse structured YAML/TOML (ignoring `#`/`//` comments and parsing Kubernetes resource quantities like `256Mi`/`1Gi` into bytes), derive expected counts dynamically from catalog definitions, reject path traversal (`is_relative_to(repo_root)`), and test adversarial/negative edge cases (commented-out config lines, tampered signatures, out-of-order patches, keyword collisions, and concurrent multi-thread access).

## 82. SteamCMD & Dedicated Game Server Probe, Auto-Recovery Skill & `Jev` / Knowledge Graph Encoding (`2026-11-07`)
- **Mandate**: Maintain `.ai/skills/game_server_steam_probe_and_recovery/SKILL.md`, `probe_steam_and_game_server_health()` / `recover_steam_game_server()` in `scripts/devops/graph_knowledge_harvester.py` (`steam-probe` / `steam-recover`), and playbook `satisfactory-steamcmd-exit8-and-cvar-sigsegv` in `.ai/graphify/support_ticket_playbooks.json` so SteamCMD cold-cache Exit Code 8 (`Missing configuration`), UE5 `UFGUserSettingApplyType::TryRegisterCvarValue()` `SIGSEGV`, Calico DNAT `10.20.3.2:6443` CronJob blocks, and `FG.ServerRestartTimeSlot` (`660.000000` vs `0.0`) are continuously probed, auto-recovered, and encoded into the `Jev` decision tree and Knowledge Graph (`hw-nodegamma03-node`, `deploy-dev-envs`, `res-openzfs-zfs`).


## 82. FrontierReviewer Adversarial Audit Invariants for Knowledge Graph, Jev Router, RAMCache & Devenv (`2026-11-07`)
- **Mandate**: Enforce all 5 architectural invariants uncovered by FrontierReviewer's adversarial review (`frontier_reviewer_opscryer_review_2026_11_07.md`):
  1. **No Auto-Reconcile Laundering**: `AssumptionRealityVerifier` must never substitute hardcoded default placeholders (`nodegamma03`, `default`, `proj-gitops-launchpad`, `opscryer_hud`) for contradicted developer claims, and reconciled claims must require explicit human acknowledgement (`RECONCILED_PENDING_HUMAN_ACK`) with a visible `claimed -> corrected` diff in `DeveloperManagerReviewPacket v1`.
  2. **GitOps Ground-Truth Link & Manifest Alignment**: Every system in `SETTLED_PRODUCTION_SYSTEM_CATALOG` must have its `argocd_app`, `k8s_namespace`, `git_manifest_path`, and `gitlab_source_and_pipelines_url` verified against `gitops/apps/*.yaml` and `PROJECT_DEFINITIONS` (never pointing a `git_manifest_path` at a dashboard panel or non-existent directory).
  3. **Order-Invariant, Word-Boundary, IDF-Scored `Jev` Routing**: `JevModelAbstraction` must match keywords on word boundaries (`(?<![\w-])kw(?![\w-])` so `"UNSEALED"` never matches `"sealed"`), score all playbooks by specificity rather than alphabetical first-hit, require a direct query symptom match (preventing rogue `agent_observations` from forcing `AUTO_RESOLVE`), and unify multi-fault resolution inside `Jev` evaluation.
  4. **Atomic `replace_all_tables` Rollback & Lock-Protected Engine Hot-Swap**: Failed patch/training rollbacks must clear tables before restoring backups (`replace_all_tables`), and `MultiAgentRAMCacheHub` must hold `self._lock` across all CRUD and `switch_engine` operations so 0 writes are lost under concurrency.
  5. **Case-Sensitive K8s Memory Quantities (`m` vs `M`/`Mi`)**: `devenv.parse_k8s_memory_bytes` must treat lowercase `m` as milli-bytes (`1e-3`) and uppercase `M`/`Mi` as Megabytes/Mebibytes (`10^6`/`2^20`), rejecting `"256m"` as below the Burstable QoS minimum.

## 83. Wave 3 GitOps App-of-Apps Ground-Truth Verification & Explicit Reconciliation Acknowledgement (`2026-11-07`)
- **Mandate**: Maintain `ArgoCDGitOpsGroundTruthResolver` (`resolve_argocd_ground_truth` over `gitops/apps/*.yaml`), explicit human reconciliation acknowledgement (`session.acknowledge_reconciled_assumptions` + `RECONCILED_PENDING_ACK` when `require_explicit_reconciliation_ack=True`), and `WAVE3_GITOPS_CLUSTER_INFRASTRUCTURE_SPECIFICATIONS` (`23 -> 30` graphed systems, `210` verified human monitoring links) with property-based, non-hardcoded tests in `tests/test_opscryer_jev_ramcache_abstraction.py`.

## 84. Pre-Commit & Pre-Push Hook Parity for Commit Body Line Length (`<= 100` Chars) & Pushed `--target-ref` (`2026-11-07`)
- **Mandate**: `devenv.check_commit_message()` must enforce `<= 100` characters on both the commit subject (`[header-max-length]`) and every commit body line (`[body-max-line-length]`). `.git/hooks/pre-push` (`devenv.install_git_hooks()`) must pass `--target-ref "$local_sha"` from `stdin` into `devenv.run_precommit_checks()` so branches built via `git commit-tree` / `git update-ref` always diff `origin/main...<target_ref>` and validate all commit messages in `origin/main..<target_ref>` before `git push` succeeds. Always fetch `+refs/heads/main:refs/remotes/origin/main` before rebasing or building a branch.

## 85. Wave 4 Exhaustive Pre-Review Closure (`RealityProvider`, Zero-Seed Ed25519 Verifier, Multi-Doc YAML AST & Mid-Patch Fault-Injection) (`2026-11-07`)
- **Mandate**: Before passing a review packet back to an external frontier reviewer under tight token budgets, exhaustively close every remaining P0–P3 suggestion and hygiene item in a single verified wave (`RealityProvider` / `RepoRealityProvider` / `ClusterRealityProvider` + `detect_repo_vs_cluster_drift`, zero private seed retention in `create_verifier_only()` with RFC 8032 pure-Python `Ed25519` fallback, `(not_before, not_after)` key validity windows, per-table `_generation` + `search_text` parity across all 3 RAMCache backends, multi-doc YAML `yaml_shim.safe_load_all` + Helm `{{ ... }}` stripping in `_file_contains_active_symbol` and `test_k8s_manifests.py`, `expected_git_manifest_path` verification in `verify_human_monitoring_link_matrix`, playbook `kubectl -n <ns>` validation, and `REJECTED_APPLY_EXCEPTION` mid-patch fault-injection rollback testing).

## 86. Zero Silent Fallbacks, Single Source of Truth & Non-Tautological Verification Standard (`2026-11-07`)
- **Mandate**: Never sub, fake, or silently fall back when loading declarative catalogs or running verifiers ("These can't be subbed or faked, that defeats the whole point"):
  1. **Fail-Closed Single Source of Truth**: Declarative data loaders (`load_settled_production_system_catalog`) must never catch exceptions and silently fall back to duplicate hardcoded Python constants. Delete duplicate Python lists, assign `SETTLED_PRODUCTION_SYSTEM_CATALOG = load_settled_production_system_catalog()`, and test both mutation provenance (mutating a temp YAML copy changes the output) and negative fail-closed behavior (corrupt/missing YAML raises `ValueError`/`FileNotFoundError`).
  2. **Non-Tautological Ground-Truth Allowlists**: Verifiers (`LiveClusterKnowledgeGraphVerifier`) must never populate `known_namespaces` or other ground-truth sets from the unverified systems being audited; derive ground truth strictly from `RepoRealityProvider` and `ClusterRealityProvider` and verify both `system_k8s_namespaces_verified` and `playbook_kubectl_namespaces_verified`.
  3. **Production-Wide Zero Hardcoded Signing Secrets & Verifier-Only Subscribers**: Every `SignedSharedRAMCacheNode` subscriber across all production scripts (including `cluster_endpoint_and_dashboard_coverage_loop.py`) must receive `signer.create_verifier_only()` with zero hardcoded `signing_secret` literals, enforced by AST inspection in unit tests.


## 88. Envoy Gateway Outpost Hostname Precedence, Port-80 `Secure` Cookie Redirect & Per-Domain / Per-VLAN Reachability Canary (`2026-11-08`)
- **Mandate**: Maintain `portal-authentik-outpost-route` (with explicit `spec.hostnames` so `/outpost.goauthentik.io/*` is never shadowed by exact-hostname `extAuth` routes), `portal-http-to-https-redirect` + `sectionName: https` on SSO `HTTPRoute`s (so plaintext `:80` requests `301` redirect to `https://` before `extAuth` sets `Secure` session cookies), `requests-route` (`requests.cluster.example.org` + `seerr.cluster.example.org`), `argocd-cluster-example-org` Ingress (`global.domain: argocd.cluster.example.org`), and the 16-domain / 7-VLAN Reachability Canary (`scripts/monitoring/live_endpoint_and_route_health_matrix.py --probe-live` / `--prometheus` and `tests/test_live_endpoint_and_route_health_matrix.py`) across `VLAN 30`, `VLAN 40` (Living Room + Office), and `VLAN 50` (Upstairs).


## 87. 3-Tier NVIDIA Nemotron & Non-Chinese Open-Weight Model Policy (`RTX 3080` -> `Laptop NPU` -> `Work 500k Nemotron Super`) (`2026-11-08`)
- **Mandate**: Enforce `verify_non_chinese_model_policy()` across the Open-Weight Test Bench (`NON_CHINESE_OPEN_WEIGHT_MODEL_CATALOG`), blocking Chinese-origin model families (`qwen`, `deepseek`, `yi`, `baichuan`, `chatglm`, `glm`, `internlm`, `kimi`) and supporting 3 verified US open-weight tiers: (1) **Homelab RTX 3080 (`10 GB` VRAM)** running `nemotron-mini:4b` (`2.7 GB`), `phi3:mini` (`2.3 GB`), or `llama3.2:3b` (`2.0 GB`); (2) **Laptop NPU Stretch Goal** running `llama3.2:1b-npu-int4` (`0.85 GB`) or `phi4-mini-npu-int4` (`2.1 GB`) under `<600`-token constrained prompts (`SmallModelConstrainedGraphDriver`, stripping all model-generated shell commands); and (3) **Work Enterprise `500,000`-Token `Nemotron Super` (`nvidia/llama-3.3-nemotron-super-49b-v1`)** (`NemotronSuper500kContextPackager`) packaging the full 30-system Knowledge Graph and pushing Ed25519-signed RAMCache updates to the edge tiers.


## 89. Producer/Consumer Schema Parity, Complete Store-Write Auth Closure & Split-Brain Harvester Elimination (`2026-11-08`)
- **Mandate**: When remediating adversarial findings, verify the entire producer-to-consumer chain and all sibling store-write paths on the first pass without burning tokens on incomplete fixes:
  1. **Unified `rts_top_currencies` & Host Metrics Schema**: Every currency item emitted by `opscryer-readonly-telemetry` and `swarm-memory` must carry both `{value, color, sub_items}` and `{value_display, status_color, dropdown_items}` with `None`-safe formatting so `renderRtsTopCurrenciesBar()` never renders `undefined` or `"CPU Nonem (None%)"`.
  2. **Complete Store-Write Auth Closure**: `POST /api/v1/sync` must strip `hot_hud_html`, `hot_hud_override_enabled`, and `hot_nanobots_html` unless a valid `X-Swarm-Master-Key` is provided, and `hot_nanobots_html` on `/api/v1/c2/*` requires explicit `hmac.compare_digest` verification.
  3. **Zero Split-Brain Harvester Drift**: Keep `/healthz` and `/api/v1/status` aligned between `opscryer-readonly-telemetry` and `swarm-memory`, normalize `GITLAB_READONLY_API_URL` so `/projects/prod%2Fhome-k8s` is never doubled, and serve live K8s node metrics + explicit `UNAVAILABLE_NO_EXPORTER` cards on `/nodes`.


## 90. 1-Click Discord Stream Reset & Relaunch (`RunbookGate` + Channel Director UI), `jellyfin-mpv-shim` Supervisor, `BedroomTV` 25-Episode Queue Sync & Semaphore RBAC Playbook Authorization (`2026-11-08`)
- **Mandate**: Maintain `discord_control_daemon.py` on `:8099` inside `vesktop-streamer` (`streaming/discord/deployment-vesktop.yaml`, handling both `list` and `dict` `cred.json` formats, checking `/proc/<pid>/stat` for non-zombie `jellyfin-mpv-shim` + `mpv` processes, and guarding `ActionThread.run()` against transient HTTP errors), `reset_discord_stream()` / `/tv-metrics/discord/reset` in `infrastructure/monitoring/tizen-tv-sentinel-manifests.yaml` (plus 25-episode `queue_csv` `NowPlayingQueue` sync for `BedroomTV` and `DiscordStream`), and the 1-click **`Discord Stream: Reset & Relaunch MPV Player + Sync to House TV Channel`** / **`Jev + Semaphore RBAC Playbook`** / **`Discord Stream: Full Pod Restart via Semaphore RBAC`** buttons in `runbookgate/configmap.yaml`. Gate playbook execution (both soft MPV resets `discord-stream-mpv-sync-recovery` and full pod restarts `discord-stream-full-pod-restart`) on **Ansible Semaphore (`https://semaphore.cluster.example.org`) RBAC project roles** (`owner`, `manager`, `task_runner` allowed; `guest` and `anonymous` rejected with `HTTP 403`) rather than restricting pod restarts to human-clicks-only, and maintain `ansible-semaphore/configmap.yaml` (`cookie_hash`, `bootstrap_playbooks.py`), `ansible-semaphore/deployment.yaml`, and `ansible-semaphore/rbac.yaml` (`Role/semaphore-media-playbook-runner` in `namespace: media`).


## 91. 3-Tool Bounded-Context Architecture (`OpsCryer` Visual Discovery, `Brain / KG / Jev` Live Data Engine, `Swarm` Multi-Agent Dev Env) & Strict Live-Process Verification (`2026-11-08`)
- **Mandate**: Decompose the monolithic `swarm-memory` ConfigMap into 3 focused, interoperable tools linked by explicit JSON contracts and deep links: (1) **`OpsCryer`** (read-only visual discovery, NOC navigation, and optional/modular Support Ticket Triage UI), (2) **`The Brain` (`Knowledge Graph` + `Jev` + Live Reality/Prometheus/K8s Harvester)** (single source of real, up-to-date telemetry and deterministic `Jev` diagnosis with zero fabricated `checked_live` numbers), and (3) **`The Swarm`** (authenticated persistent multi-agent AI development environment). Enforce all 6 Definition-of-Done rules from `frontier_reviewer_review_post_merge_995_2026_11_08.md`: `configmap.reloader.stakater.com/reload` + `/healthz.code_sha256` live process verification, zero hardcoded default master keys (`fail-closed 503/403`), behavioral in-process HTTP tests (never source-text `assertIn` greps), single-layer HTML escaping at the render boundary, and zero out-of-band `kubectl apply` mutations on ArgoCD-managed resources.


## 92. Pluggable Metric Extensions, Deterministic Live-Bound `Jev` (Zero-AI Hot Path) & AI Fallback Graph-Expansion Pipeline (`2026-11-08`)
- **Mandate**: Structure all telemetry inside **The Brain** as a **Pluggable Metric Extension System** (`MetricPluginRegistry`) where each extension (`k8s_core`, `prometheus_ql`, `gitlab_gitops`, `openbao_trivy_sec`, `ollama_gpu_vram`, `game_server_probes`, etc.) emits typed `LiveMetricSignal`s (`{value, unit, status, source_plugin, harvested_at_iso, deep_link_url}`) bound directly to Knowledge Graph nodes and `Jev` predicates (`live_metric_bindings`). Enforce a strict two-stage pipeline:
  1. **Stage 1 — Deterministic Hot Path (Zero AI Prompting)**: `Jev` evaluates graph topology + live plugin metric signals deterministically (`ai_invoked=False`) to drive diagnostics, support ticket answers, and verified automatic actions without any LLM in the loop.
  2. **Stage 2 — AI Fallback & Graph-Coverage Expansion Pipeline**: Invoke AI (local GPU/NPU or Swarm) **only** when an error or ticket is uncovered by the deterministic decision graph (`UNCOVERED_BY_DECISION_GRAPH`), producing a staged `GraphCoverageExpansionProposal` (new `Jev` rules, live metric plugin bindings, and playbooks) so the deterministic graph grows to cover the new responsibility without needing AI on future occurrences.


## 93. Closed-Loop Playbook Execution, Live-Plugin Post-Verification & AI Playbook Rework Lifecycle (`2026-11-08`)
- **Mandate**: Ensure playbooks in **The Brain** are machine-executable (`explicit_commands`, `execution_mode`, `verification_metric_bindings`, `expected_healthy_predicate`) so both deterministic runners and Swarm AI agents can run them to complete tasks and verify recovery against live `plugin://` metrics. Automatically flag a playbook as `NEEDS_REWORK` and route it to the AI `PlaybookReworkProposal` pipeline whenever: (1) post-execution live metric verification fails (`PLAYBOOK_RAN_BUT_METRIC_STILL_DEGRADED`), (2) repo/cluster drift invalidates a playbook's commands or paths (`PLAYBOOK_DRIFT_DETECTED`), or (3) a playbook fires repeatedly in a rolling window (`PLAYBOOK_FLAPPING_ROOT_CAUSE_UNFIXED`).


## 94. Work-Export Release Scrubbing, Zero "FrontierReviewer"/"FrontierAI" Mentions in Released Output & Pre-Push Review Gate (`2026-11-08`)
- **Mandate**: Enforce zero mentions of `FrontierReviewer` or `FrontierAI` (case-insensitive) in any exported/public release file, comment, docstring, test, or git history via `FORBIDDEN_PUBLIC_RELEASE_PATTERNS` and `_scrub_text_content()` in `scripts/devops/opscryer_public_release_builder.py`. When preparing an export release for review, run the full scrubber and test suite locally (`push_remote=False`) across `C:\dev\opscryer-public`, `scratch/opscryer-public-suite`, and `dist/opscryer-public-release` so the user can review the scrubbed output before pushing.


## 95. Pre-Release Review Remediation (`R1`–`R5`, `S1`–`S5`): Substring Vendor Gate, Public Test Suite 100% Green Gate & Explicit `--confirm-public-push` Guard (`2026-11-08`)
- **Mandate**: Before declaring `C:\dev\opscryer-public` ready to push:
  1. Ensure `FORBIDDEN_PUBLIC_RELEASE_PATTERNS["ai_vendor_frontier_reviewer"]` uses substring matching `(?i)(frontier_reviewer|frontier_ai)` and `scan_directory_for_opsec_leaks()` scans file names, file contents, and git commit history (`git log --all`).
  2. Ship `CLEAN_PUBLIC_SWARM_TASKS_MD` (`R1`), preserve `https://github.com/nahallacman/opscryer` (`R2`), scrub `opscryer_abstraction.py` -> `opscryer_abstraction.py` (`R3`), scrub split homelab string literals (`R4`) and `platform/infra-gitops` (`S2`), and update `opscryer-public/README.md` with the 3-Tool Architecture (`S1`).
  3. Keep `test_21` `@unittest.skipUnless(Path("C:/dev/opscryer-public").exists(), ...)` and strictly verify-only (`S4`), require `--confirm-public-push` with zero automatic 404 repo creation (`S5`), and verify all `1,516` tests in `C:\dev\opscryer-public` pass (`R5`).


## 96. Gemini CLI Work Export Profile (`GEMINI.md`, `.gemini/settings.json`, `.gemini/commands/*.toml` & Direct CLI Rewrite) (`2026-11-09`)
- **Mandate**: When exporting OpsCryer and AI skills for work environments running **Gemini CLI (`gemini`)** rather than Antigravity 2.0:
  1. Exclude Antigravity-specific exact-string-matching skills (`terminal_execution_protocol`, `antigravity_permissions`, `permission_allowlist_management`), replace them with `gemini_cli_execution_protocol`, and rewrite `(Get-Content ..._args.txt)` command indirection in exported `SKILL.md` files into direct CLI invocations.
  2. Generate and install `GEMINI.md` (lazy-loaded skill index), `.gemini/settings.json` (prefix `tools.allowed`), and `.gemini/commands/**/*.toml` (`/opscryer:brief`, `/opscryer:diagnose`, `/opscryer:rework`, `/skill:use`) via `import_work_suite.py`.



