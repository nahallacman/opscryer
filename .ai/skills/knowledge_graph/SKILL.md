---
name: "knowledge_graph"
description: Instructions for using Graphify to query the AST-based ecosystem knowledge graph, helping agents map out golden paths and system topologies efficiently.
---

# Knowledge Graph (Graphify)

**Purpose:** This skill establishes the standard operating procedure for navigating the massive `infra-gitops` ecosystem without consuming excessive context window tokens. We use an Abstract Syntax Tree (AST) graph engine called **Graphify** (`graphifyy`) to search and correlate code, documentation, and golden paths locally.

## Execution Environment

The Graphify tool is installed within the reproducible Dev Container environment (via `devcontainer.json`'s `postCreateCommand`) or inside the `.venv` directory located at the root of the repository.

To run graphify commands natively (from PowerShell):
```powershell
.\.venv\Scripts\python -m graphify <command>
```
To run graphify commands natively (from Linux/DevContainer):
```bash
.venv/bin/python -m graphify <command>
```

## Graph Querying Protocol

Before guessing how microservices, scaffolding components, or internal frameworks interconnect, agents MUST query the Knowledge Graph.

### 1. General Search
To search the codebase context efficiently without arbitrary `grep`:
```bash
python -m graphify query "What components does dependency-mapper rely on?"
```

### 2. Exploring Topologies
To extract a semantic topology of an application boundary or Golden Path integration:
```bash
python -m graphify query "Draw the relationship between dependency-mapper and the golden-path-fullstack pipeline."
```

## Graph Maintenance
You do **NOT** need to manually run `python -m graphify sync` every time you modify code. 
We have integrated Graphify directly into the repository's automation:
1. **Git Hook:** A custom `pre-commit` hook automatically runs Graphify and exports the AST `graph.json` and visual `architecture.md` (Wiki) into the `.ai/graphify/` directory on every commit.
2. **CI Pipeline:** The `graphify-audit` job runs in the CI pipeline to enforce that the knowledge graph is perfectly synced with the code. 

**Source of Truth:** If you need to read the graph, the most up-to-date representation is always located in `.ai/graphify/graph.json` and `.ai/graphify/architecture.md`. Do NOT attempt to read raw `.gitlab-ci.yml` files recursively across the monorepo to figure out dependencies. This will bloat the context window. Use the generated Graphify exports to map the relationships explicitly!

## Live Metric-Grounded `Jev` Ticket Triage, Multi-Actor Access & Human Ops Engineer Escalation (`Epic #270`, Tasks `#271`–`#273`)
1. **Arbitrary Ticket Intake + Live Infrastructure Metric Correlation (`Task #271`, `scripts/devops/jev_live_ticket_triage_and_ops_escalation.py`):**
   - When an incoming ticket arrives (e.g., *"hey my builds are really slow today"*), the Knowledge Graph resolves the full 4-domain dependency chain (`Company` $\leftrightarrow$ `Processes` $\leftrightarrow$ `Deployments` $\leftrightarrow$ `Hardware`) and correlates it against **live infrastructure metrics**:
     - **Giant GitLab Runner Queue:** `ci_runner_queue_depth >= 15` or `runner_active_slots >= runner_max_slots`.
     - **Network Connections Topped Out:** `network_conntrack_util_pct >= 85%` or `network_link_util_pct >= 85%`.
     - **Disk Infrastructure Bottleneck:** OpenZFS ZFS `disk_iowait_pct >= 25%` or `disk_write_latency_ms >= 25ms`.
     - **Upstream Dependency Service Down:** `unhealthy_services` non-empty (`harbor-registry`, `seaweedfs-s3`, `coredns`, `openbao`, `cnpg-postgres`).
   - `Jev` (System One calibrated decision-tree router) evaluates these live predicates and generates ranked **Suggested Answers** dynamically grounded in the real-time state of company infrastructure.
2. **Viability Gate & Direct Escalation to Owning Human Ops Engineer (`Task #272`):**
   - If `Jev`'s suggested answer is **not viable** (`confidence < 0.80`, requires privileged ops intervention, or is rejected by the requester), the ticket is **passed directly to the owning Human Ops Engineer** from Section 1 of the Knowledge Graph (`@liam.oconnor`, `@tomas.lindqvist`, `@maya.lin`, `@sora.takahashi`, or `@elena.vance`) with the live metrics, ruled-out hypotheses, and 1-click System Control Plane links attached.
3. **Multi-Person & Multi-System Concurrent Graph Access (`Task #273`):**
   - Multiple human roles (**Developers**, **Ops/SRE Engineers**, **Engineering Managers**) and automated systems (**`Jev` Ticket Router**, **Argon 24/7 Watchdog**, **CI Queue Governor**) query the same Knowledge Graph concurrently for role-specific operational knowledge.

