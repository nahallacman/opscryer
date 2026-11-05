# Overnight 9-Epic Swarm Queue (Work-Account Codex + Local 3-GPU Ollama)

- **Public Repository:** `https://github.com/opscryer-maintainers/opscryer`
- **Codex Budget Cap (`max_codex_epics_per_run`):** `12` Epics via Work-Account Codex (`codex exec`), remaining `-3` Epics via Local GPU Ollama (`$0` cost).

## EPIC-1 — Separable Piece A Spatial Information Tree & Classic RTS/TBS Browser
- **Assigned Agent:** `epic-agent-01-spatial-ui`
- **Execution Engine:** Work-Account Codex (`codex exec`)
- **Locked Scopes:** `scripts/devops/spatial_graph_browser.py, tests/test_spatial_graph_browser.py`
- **Automated Verification:** `python -m unittest tests/test_spatial_graph_browser.py`
- **Manual Workflow Check:** Launch `python opscryer_browser.py --serve --port 8088` and zoom from L0 to L3.
- **Codex Prompt:** `In https://github.com/opscryer-maintainers/opscryer, refine `opscryer_browser.py` L0-L4 progressive zoom and verify zero backend imports and 100% DOM XSS safety (`textContent` only).`

## EPIC-2 — System-1 Jev Calibrated Decision Tree & 4-Stage Ticket Deflection
- **Assigned Agent:** `epic-agent-02-jev-triage`
- **Execution Engine:** Work-Account Codex (`codex exec`)
- **Locked Scopes:** `scripts/devops/system_one_jev_router.py, tests/test_system_one_jev_router.py`
- **Automated Verification:** `python -m unittest tests/test_system_one_jev_router.py`
- **Manual Workflow Check:** Run `python scripts/devops/system_one_jev_router.py evaluate-models` and inspect measured latency.
- **Codex Prompt:** `Verify `SystemOneJevClient` structured JSON predicate evaluation against local Ollama and `codex exec`, ensuring `<0.80` confidence fails closed to human escalation.`

## EPIC-3 — Separable Piece B Headless 4-Domain Knowledge Graph & BM25 RAG
- **Assigned Agent:** `epic-agent-03-headless-kg`
- **Execution Engine:** Work-Account Codex (`codex exec`)
- **Locked Scopes:** `scripts/devops/knowledge_graph_backend.py, tests/test_separable_pieces_contract.py`
- **Automated Verification:** `python -m unittest tests/test_separable_pieces_contract.py`
- **Manual Workflow Check:** Run `python scripts/devops/knowledge_graph_backend.py --contract` and inspect OpenAPI 3.1 schema.
- **Codex Prompt:** `Verify `SpatialGraphContract v1` schema validation and custom ontology entity registration with zero UI/HTML coupling.`

## EPIC-4 — Argus Hardened DinD Container Factory, Trivy Correlator & Code Search Airlock
- **Assigned Agent:** `epic-agent-04-argus-secops`
- **Execution Engine:** Local GPU Ollama (`qwen2.5-coder:7b (RTX 3080 10GB)`)
- **Locked Scopes:** `scripts/devops/argus_dind_and_blue_team_loop_verifier.py, tests/test_argus_dind_and_blue_team_loop_verifier.py`
- **Automated Verification:** `python -m unittest tests/test_argus_dind_and_blue_team_loop_verifier.py`
- **Manual Workflow Check:** Run `python scripts/devops/argus_dind_and_blue_team_loop_verifier.py --json`.
- **Codex Prompt:** `Audit DinD SecurityContext (`UID 10001`, `drop: [ALL]`) and manifest-only code search airlock.`

## EPIC-5 — OpenBao Raft KMS, Authentik OIDC & 6-Plane Chaos Blast-Radius Isolation
- **Assigned Agent:** `epic-agent-05-openbao-iam`
- **Execution Engine:** Local GPU Ollama (`llama3.1:8b (RTX 3070 8GB)`)
- **Locked Scopes:** `scripts/devops/cross_subsystem_chaos_resilience_verifier.py, tests/test_cross_subsystem_chaos_resilience_verifier.py`
- **Automated Verification:** `python -m unittest tests/test_cross_subsystem_chaos_resilience_verifier.py`
- **Manual Workflow Check:** Run `python scripts/devops/cross_subsystem_chaos_resilience_verifier.py --json`.
- **Codex Prompt:** `Verify 6-plane chaos fault injection isolation and OpenBao SHA-256 secret provenance.`

## EPIC-6 — GitLab CI Golden Path Ticket Concierge & 6-Gate Pre-Push Parity
- **Assigned Agent:** `epic-agent-06-golden-path`
- **Execution Engine:** Local GPU Ollama (`qwen2.5-coder:7b (RTX 3080 10GB)`)
- **Locked Scopes:** `scripts/devops/opscryer_done_state_master_verifier.py, tests/test_opscryer_done_state_master_verifier.py`
- **Automated Verification:** `python -m unittest tests/test_opscryer_done_state_master_verifier.py`
- **Manual Workflow Check:** Run `python scripts/devops/inline_docs_migration.py verify`.
- **Codex Prompt:** `Verify 6-gate local pre-push CI parity and Golden Path ticket concierge.`

## EPIC-7 — Raspberry Pi 2B NOC Kiosk & Provisioned Grafana Deep-Link Cockpit
- **Assigned Agent:** `epic-agent-07-noc-kiosk`
- **Execution Engine:** Local GPU Ollama (`qwen2.5-coder:7b (RTX 3080 10GB)`)
- **Locked Scopes:** `scripts/monitoring/pi_kiosk_view_cycler_replay_verifier.py, scripts/monitoring/grafana_noc_golden_signals_verifier.py`
- **Automated Verification:** `python -m unittest tests/test_grafana_noc_golden_signals_verifier.py`
- **Manual Workflow Check:** Run `python scripts/monitoring/pi_kiosk_view_cycler_replay_verifier.py`.
- **Codex Prompt:** `Verify Pi Kiosk GPIO button navigation replay and Grafana NOC Golden Signals.`

## EPIC-8 — 3-GPU Hybrid Workload Switcher & Household Game Ticket Portal
- **Assigned Agent:** `epic-agent-08-gpu-household`
- **Execution Engine:** Local GPU Ollama (`qwen2.5-coder:14b (RTX 5080 16GB)`)
- **Locked Scopes:** `scripts/devops/gpu_task_card_and_workload_mode_verifier.py, tests/test_gpu_task_card_and_workload_mode_verifier.py`
- **Automated Verification:** `python -m unittest tests/test_gpu_task_card_and_workload_mode_verifier.py`
- **Manual Workflow Check:** Run `python scripts/devops/system_one_jev_router.py household-ticket --question 'the minecraft server is down'`.
- **Codex Prompt:** `Verify 3-GPU task card allocation and household game server + APU-200 metrics triage.`

## EPIC-9 — Clean Apache-2.0 Public GitHub Release & FedRAMP High OSCAL Exporter
- **Assigned Agent:** `epic-agent-09-public-release`
- **Execution Engine:** Work-Account Codex (`codex exec`)
- **Locked Scopes:** `scripts/devops/opscryer_public_release_builder.py, tests/test_real_jev_llm_and_public_release.py`
- **Automated Verification:** `python -m unittest tests/test_real_jev_llm_and_public_release.py`
- **Manual Workflow Check:** Run `python scripts/devops/opscryer_public_release_builder.py` and verify `https://github.com/opscryer-maintainers/opscryer`.
- **Codex Prompt:** `Verify `opscryer_public_release_builder.py` produces a zero-OPSEC-violation Apache-2.0 package and `nist_800_53_compliance_verifier.py` passes all 9 FedRAMP High controls.`
