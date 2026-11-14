---
name: local_agent_swarm_operator
description: Operating playbook and conversational local-agent trigger skill for the Permanent In-Cluster Nanobot Swarm C2 Master (agy-ai-orchestrator:8094), 4-Way Task Subdivision across local 4-GPU Ollama workers (0 Argon/cloud tokens), and Cryptographic Key-Based Commander Authority.
---

# Local Agent & Nanobot Swarm C2 Master Operator Skill (`0` Cloud Tokens)

Use this skill whenever the user or a local AI agent wants to:
1. **Talk to local GPU agents** (`qwen2.5-coder:7b`, `deepseek-r1:8b`, `qwen2.5-coder:3b`, `llama3.1:8b` on `ollama-service.ai-infra:11434`) to trigger, subdivide, or inspect Nanobot Swarm operations without spending Argon or Antigravity cloud tokens.
2. **Operate the Permanent In-Cluster C2 Master** (`Deployment/agy-ai-orchestrator` on `:8094` exposed at `https://opscryer.cluster.example.org/nanobots` and `https://opscryer.cluster.example.org/c2`).
3. **Subdivide high-level missions** into 4 specialized child sub-tasks (`SUBTASK-W0..W3`) with disjoint Molecular Fencing Locks across `StatefulSet/nanobot-swarm` (`nanobot-swarm-0..3:8096`).
4. **Enforce Cryptographic Key-Based Commander Authority (`MasterKeyAuthority`)** so the human operator (`opscryer-maintainers`) remains strictly in charge of all privileged or mutating C2 overrides.

---

## 1. Architecture & Sovereign Authority Boundary

### 1.1 Permanent In-Cluster C2 Master (`agy-ai-orchestrator:8094`)
- **Kubernetes Deployment:** `Deployment/agy-ai-orchestrator` (`Service/agy-ai-orchestrator:8094` in `namespace: dev-envs` on `nodegamma03`).
- **Live Browser Control Deck:** `https://opscryer.cluster.example.org/nanobots` (and `https://opscryer.cluster.example.org/c2`).
- **4-Pod In-Cluster Worker Squad (`StatefulSet/nanobot-swarm` on `:8096`):**
  - `nanobot-swarm-0` (`forge-replicator`): `qwen2.5-coder:7b` @ `gpu-worker-rtx3080` (`10 GB VRAM`) — Core code & feature synthesis (`SUBTASK-W0`).
  - `nanobot-swarm-1` (`repair-mite`): `qwen2.5-coder:3b` @ `gpu-worker-rtx3070ti` (`8 GB VRAM`) — Fast LF line-ending, Helm `Chart.lock`, & K8s manifest splicing (`SUBTASK-W1`).
  - `nanobot-swarm-2` (`scout-probe`): `llama3.1:8b` + `nomic-embed-text` @ `gpu-worker-gtx1080ti-01` (`11 GB VRAM`) — Knowledge Graph / DDR4 RAMCache grounding & live endpoint recon (`SUBTASK-W2`).
  - `nanobot-swarm-3` (`sentinel-phage`): `deepseek-r1:8b` @ `gpu-worker-gtx1080ti-02` (`11 GB VRAM`) — Blue Team VLAN/NetPol security audit & 6-Gate Pre-Push Verifier (`SUBTASK-W3`).

### 1.2 Two-Tier Cryptographic Key-Based Authority (`MasterKeyAuthority`)
- **Tier A — Autonomous Worker Subdivision (`SUBTASK_AUTONOMOUS_TIER`):**
  - The C2 Master and the 4 `nanobot-swarm-0..3` workers may autonomously subdivide tasks, run local 4-GPU Ollama inference (`0` cloud tokens), acquire disjoint file scope locks, run Blue Team / Golden Path audits, and stage compare branches.
- **Tier B — Sovereign Commander Key-Gated Control (`MASTER_KEY_REQUIRED_TIER`):**
  - The human commander (`opscryer-maintainers`) remains in charge via cryptographic key authentication (`X-Swarm-Master-Key` header or `master_key` field verified via HMAC-SHA256 + SHA3-512 PQC warrant against `Secret/nanobot-c2-master-auth`).
  - Privileged actions (`master-override`, `emergency-halt`, `resume-swarm`, `set-autonomy-policy`, `force-release-locks`, `rotate-master-warrant`) **fail closed (`403 MASTER_KEY_REQUIRED`)** unless signed/authenticated with the Commander Master Key.

---

## 2. Talking to Local Agents to Trigger the Swarm (`0` Cloud Tokens)

### 2.1 From the Browser (`https://opscryer.cluster.example.org/nanobots`)
1. Open **`https://opscryer.cluster.example.org/nanobots`**.
2. In the **💬 Talk to Local Agent & Trigger Swarm (`0` Cloud Tokens)** bar at the top:
   - Type any natural-language request (e.g., *"Subdivide and harden the monitoring alerts and verify all 4 VLANs"* or *"Run an overnight Golden Path and Blue Team sweep across all 4 GPUs"*).
   - Click **🤖 Ask Local Agent & Trigger Swarm**.
   - The in-cluster C2 Master queries local Ollama (`ollama-service.ai-infra:11434`), subdivides the request into `SUBTASK-W0..W3`, dispatches all 4 `nanobot-swarm-0..3` pods in parallel, and updates the live HUD in-place without losing your scroll position.

### 2.2 From the Terminal CLI (`0` Cloud Tokens)
- **Talk to the Local Agent & Auto-Trigger Subdivided Swarm Execution:**
  ```powershell
  python scripts/devops/gitlab_ops.py swarm c2 talk --prompt "Subdivide and audit Blue Team VLANs and Golden Path manifests across all 4 GPUs" --auto-trigger
  ```
- **Subdivide a Specific Mission Across All 4 Nanobot Strains (`SUBTASK-W0..W3`):**
  ```powershell
  python scripts/devops/gitlab_ops.py swarm c2 subdivide --title "feat(nanobot): harden in-cluster c2 master and key auth" --issue-id 354 --scopes scripts/devops/swarm_c2_orchestrator.py infrastructure/devcontainers/templates/nanobot-swarm.yaml
  ```
- **Run an Autonomous Overnight Iteration Wave (`0` Argon Tokens):**
  ```powershell
  python scripts/devops/gitlab_ops.py swarm c2 overnight-iterate --iterations 4
  ```
- **Issue a Commander Key-Authenticated Sovereign Action (`master-override`, `emergency-halt`, `resume-swarm`):**
  ```powershell
  python scripts/devops/gitlab_ops.py swarm c2 master-auth --action verify --master-key "<COMMANDER_MASTER_KEY>"
  ```

---

## 3. REST API Contract on the In-Cluster C2 Master (`https://opscryer.cluster.example.org`)

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/nanobots` (or `/c2`) | `GET` | Live interactive C2 Master Control Deck (rendered dynamically from live cluster + 4-GPU state). |
| `/api/v1/c2/gui-action` | `POST` | Executes any 1-click GUI button (`preset`, `subdivide`, `talk`, `overnight-iterate`, `work-parallel`, `cluster-sync`, `blue-team`, `golden-path`, `doctor`, `steal-work`, `step`, `master-auth`) live on the cluster and returns updated HUD JSON. |
| `/api/v1/c2/subdivide` | `POST` | Decomposes a parent mission into 4 specialized child sub-tasks (`SUBTASK-W0..W3`) across `nanobot-swarm-0..3` with disjoint Molecular Fencing Locks. |
| `/api/v1/c2/talk` | `POST` | Conversational bridge to local GPU Ollama (`qwen2.5-coder:7b` / `deepseek-r1:8b`) that translates natural-language prompts into live Swarm C2 actions. |
| `/api/v1/c2/master-auth` | `POST` | Verifies Commander Master Key (`X-Swarm-Master-Key` / HMAC-SHA256 + SHA3-512 warrant) and executes sovereign Commander actions (`emergency-halt`, `resume-swarm`, `master-override`, `force-release-locks`). |
| `/api/v1/c2/overnight-iterate` | `POST` | Triggers or configures the in-cluster autonomous overnight iteration loop across the 4 Nanobot workers (`0` Argon tokens). |
