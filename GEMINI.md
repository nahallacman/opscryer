# GEMINI.md — OpsCryer 3-Tool Suite & Lazy Skill Index (Gemini CLI)

This repository includes the **OpsCryer 3-Tool Operations & Knowledge Suite** and a library of
portable engineering skills designed for **Gemini CLI (`gemini`)**.

## 1. Gemini CLI Execution Rules (Token & Prompt Conservation)
- **Direct CLI Execution**: Run standard direct commands (`git status`, `git diff`, `kubectl get`, `python ...`)
  that match the prefix allowlist in `.gemini/settings.json` (`tools.allowed`). Never wrap arguments in
  `(Get-Content ...)` or `$(cat ...)` subshells.
- **Line Endings & Commits**: Preserve `LF` (`\n`) line endings (`newline='\n'` in Python) and use
  lowercase Conventional Commit subjects (`feat: ...`, `fix: ...`).
- **Deterministic Brain First**: Before spending LLM tokens diagnosing known infrastructure or ticket
  issues, check **The Brain** (`python opscryer_abstraction.py --ai-brief` or `/opscryer:diagnose`).

## 2. The 3-Tool Architecture
1. **OpsCryer (`opscryer_browser.py`)**: Fast visual spatial cockpits & support ticket deflection HUD.
2. **The Brain (`opscryer_abstraction.py` -> `MetricPluginRegistry` + `evaluate_jev_with_live_plugins`)**:
   Authoritative Knowledge Graph, deterministic System One Jev decision tree, and live telemetry plugins (`0` AI tokens on match).
3. **The Swarm (`opscryer_abstraction.py` -> `PlaybookExecutionEngine` + `SwarmAIGraphAndPlaybookPipeline`)**:
   Executes deterministic playbooks, detects drift/flapping (`NEEDS_REWORK`), and stages 6-gate validated playbook reworks or graph expansions on fallback.

## 3. Lazy-Loaded Skill Routing Table (`.ai/skills/`)
To conserve context window tokens, **do not** read all skill files upfront. When your task matches one of
the domains below, read its `SKILL.md` file (or run `/skill:use <skill_name>`):

| Skill Name | Path | When to Load |
| :--- | :--- | :--- |
| `authentik_configuration` | `.ai/skills/authentik_configuration/SKILL.md` | Instructions and UI workflows for configuring Authentik Providers, Applications, and Outposts. |
| `automated_testing` | `.ai/skills/automated_testing/SKILL.md` | Automated Testing Philosophy |
| `bash_linux` | `.ai/skills/bash_linux/SKILL.md` | Bash on Linux |
| `cicd_component_publishing` | `.ai/skills/cicd_component_publishing/SKILL.md` | CI/CD Component Tagging & Publishing Rules |
| `dashboard_visual_diffs` | `.ai/skills/dashboard_visual_diffs/SKILL.md` | Rules, standards, and automation procedures for capturing targeted, diff-focused dashboard screenshots and visual comparisons in CI/CD and MR reviews. |
| `dependency_mapper` | `.ai/skills/dependency_mapper/SKILL.md` | Architectural Source of Truth and constraints for the Dependency Mapper application. |
| `dictionary_maintenance` | `.ai/skills/dictionary_maintenance/SKILL.md` | Dictionary Maintenance |
| `e2e_cleanup` | `.ai/skills/e2e_cleanup/SKILL.md` | E2E Workspace Cleanup |
| `edl_review` | `.ai/skills/edl_review/SKILL.md` | Engineering Decisions Log (EDL) Review |
| `environment_provisioning` | `.ai/skills/environment_provisioning/SKILL.md` | Rules and Target Architectures for Ephemeral and Static Environments |
| `game_server_steam_probe_and_recovery` | `.ai/skills/game_server_steam_probe_and_recovery/SKILL.md` | Probe SteamCMD / Valve CM reachability, audit Satisfactory and dedicated game server Kubernetes manifests and Unreal Engine 5 CVar configs, auto-recover CrashLoopBackOff game servers, and encode observations into the System One Jev decision tree and Knowledge Graph. |
| `gemini_cli_execution_protocol` | `.ai/skills/gemini_cli_execution_protocol/SKILL.md` | Native Gemini CLI command execution, prefix allowlisting (.gemini/settings.json), custom TOML slash commands, and lazy skill loading. |
| `git_task_orchestration` | `.ai/skills/git_task_orchestration/SKILL.md` | Standard operating procedure for autonomous and multi-node agent task checkout, branch management, commit auto-tagging, secret scanning, and Merge Request traceability using the git-task CLI. |
| `gitbash_windows` | `.ai/skills/gitbash_windows/SKILL.md` | Git Bash on Windows |
| `gitlab-workflow` | `.ai/skills/gitlab-workflow/SKILL.md` | >- |
| `golden_path_architecture` | `.ai/skills/golden_path_architecture/SKILL.md` | CI/CD Architecture Rules, Golden Paths, Component Development, Semantic Release, and Tagging |
| `golden_path_pipelines` | `.ai/skills/golden_path_pipelines/SKILL.md` | Golden Path CI/CD Pipeline Generation |
| `graph_knowledge_harvester` | `.ai/skills/graph_knowledge_harvester/SKILL.md` | Harvest operational observations from cluster services into Knowledge Graph nodes and dry-run validate new System One Jev decision tree playbooks. |
| `high_quality_mr_wave_loop` | `.ai/skills/high_quality_mr_wave_loop/SKILL.md` | Continuous high-quality focused multi-branch MR wave loop with pairwise-disjoint file locks, AST anti-boilerplate verification, and 6-gate local pre-push CI parity checks. |
| `institutional_knowledge` | `.ai/skills/institutional_knowledge/SKILL.md` | Instructions and operating protocol for reading and capturing developer preferences, workstation environment quirks, operational disaster recovery runbooks, and architectural decisions in .ai/knowledge/. |
| `jev_tree_and_graph_knowledge_intake` | `.ai/skills/jev_tree_and_graph_knowledge_intake/SKILL.md` | Operating protocol for humans, knowledge-gathering skills, and System 2 AI models to propose, validate, and stage new support ticket playbooks, live service probes, and Knowledge Graph node links into the System One Jev decision tree. |
| `knowledge_graph` | `.ai/skills/knowledge_graph/SKILL.md` | Instructions for using Graphify to query the AST-based ecosystem knowledge graph, helping agents map out golden paths and system topologies efficiently. |
| `kubernetes_manifest_standards` | `.ai/skills/kubernetes_manifest_standards/SKILL.md` | Kubernetes Manifest Standards & GitOps Guidelines |
| `local_agent_swarm_operator` | `.ai/skills/local_agent_swarm_operator/SKILL.md` | Operating playbook and conversational local-agent trigger skill for the Permanent In-Cluster Nanobot Swarm C2 Master (agy-ai-orchestrator:8094), 4-Way Task Subdivision across local 4-GPU Ollama workers (0 Argon/cloud tokens), and Cryptographic Key-Based Commander Authority. |
| `mr_process` | `.ai/skills/mr_process/SKILL.md` | Mr Process |
| `mr_quality_and_compaction_guard` | `.ai/skills/mr_quality_and_compaction_guard/SKILL.md` | Enforces high-signal, tested, conflict-free Merge Requests over low-quality junk MRs, eliminates notification and click fatigue, ensures clean GitLab-native MR comments, and mandates compaction-proof persistence of all user feedback and session notes. |
| `network_exposure` | `.ai/skills/network_exposure/SKILL.md` | Network Exposure and Routing Architecture Skill |
| `notification_arbitrator` | `.ai/skills/notification_arbitrator/SKILL.md` | Notification Arbitrator (Zero-Knowledge Gateway) |
| `oidc_rbac` | `.ai/skills/oidc_rbac/SKILL.md` | AI SKILL PLAYBOOK - Keycloak OIDC Integration & Native RBAC Mapping |
| `opscryer_three_tool_suite` | `.ai/skills/opscryer_three_tool_suite/SKILL.md` | Operating guide for the decoupled 3-Tool Operations & Knowledge Suite (OpsCryer Visual Cockpits, The Brain / Jev Graph + MetricPluginRegistry, and The Swarm PlaybookExecutionEngine & SwarmAIGraphAndPlaybookPipeline). |
| `pipeline_management` | `.ai/skills/pipeline_management/SKILL.md` | Rules for handling stale, failed, or missing pipelines on Merge Requests. |
| `powershell_windows` | `.ai/skills/powershell_windows/SKILL.md` | PowerShell on Windows |
| `project_intake` | `.ai/skills/project_intake/SKILL.md` | Project Intake & GitOps Governance |
| `python_windows` | `.ai/skills/python_windows/SKILL.md` | Python Environment Execution (Windows) |
| `remote_workspaces` | `.ai/skills/remote_workspaces/SKILL.md` | Architecture, provisioning, Antigravity 2.0 Remote Control fleet management, and egress whitelisting standards for the Remote Workspaces (Platform-as-a-Product) DevContainers. |
| `renovate_semver` | `.ai/skills/renovate_semver/SKILL.md` | Renovate & Semantic Versioning Rules |
| `script_planning_and_execution` | `.ai/skills/script_planning_and_execution/SKILL.md` | Script Planning and Execution |
| `secret_rotation` | `.ai/skills/secret_rotation/SKILL.md` | Incident Response & Secret Rotation |
| `secret_rotation_and_reloading` | `.ai/skills/secret_rotation_and_reloading/SKILL.md` | Zero-Downtime Secret Rotation & Live Reloading |
| `security_scanning` | `.ai/skills/security_scanning/SKILL.md` | Security Scanning Module (AI_SKILL_SECURITY_SCANNING) |
| `self_signed_certs` | `.ai/skills/self_signed_certs/SKILL.md` | Self-Signed Certificate Security Skill |
| `swarm_c2_and_ramcache_architecture` | `.ai/skills/swarm_c2_and_ramcache_architecture/SKILL.md` | Authoritative architecture, setup, execution lifecycle, Generation-Indexed DDR4 RAMCache, OpenZFS ZFS write-behind persistence, and 5 Command-and-Control (C2) patterns integrated with the AI Orchestrator (agy-ai-orchestrator + argon-planner). |
| `web_application_development` | `.ai/skills/web_application_development/SKILL.md` | Frontend Web Application Design Aesthetics, Technology Stack, Workflow, and SEO Best Practices. |
| `workspace_tool_registry` | `.ai/skills/workspace_tool_registry/SKILL.md` | Workspace Tool Registry Usage & Maintenance |
| `zero_knowledge_secrets` | `.ai/skills/zero_knowledge_secrets/SKILL.md` | Zero-Knowledge Secret Handling & Output Redirection |
