---
name: "remote_workspaces"
description: Architecture, provisioning, Antigravity 2.0 Remote Control fleet management, and egress whitelisting standards for the Remote Workspaces (Platform-as-a-Product) DevContainers.
---

# Remote Workspaces & Antigravity 2.0 Multi-Container Fleet (Platform-as-a-Product)

**Purpose:** This skill establishes the 'Source of Truth' for how isolated per-workload Antigravity 2.0 DevContainers and restricted Sandboxes are architected, provisioned, networked, and accessed within the `dev-envs` namespace.

## 1. Access & Antigravity 2.0 Remote Control Model
- **Hybrid Headless Remote Control + SSH:**
  - **No Heavy Embedded Web IDEs:** Remote Workspaces do not run heavy local `code-server` or X11/Chromium desktop processes inside the pod (`~150-300 MB` idle RAM per container on `nodegamma03`).
  - **Antigravity 2.0 Remote Control (`https://antigravity.google.com`):** Each container installs the Antigravity CLI (`~/.local/bin/agy`), Python SDK (`/opt/agy-venv`), and `/usr/local/bin/agy-init-auth` via the `workspace-agy-bootstrap` ConfigMap. Each container registers its headless background daemon as `agy-<workload-name>`, allowing parallel multi-container orchestration from any browser or the Antigravity 2.0 Desktop App switcher.
  - **Isolated Per-Container Authentication:** Each container maintains its own unlocked headless D-Bus + GNOME Keyring (`~/.local/share/keyrings` and `~/.gemini` on its dedicated OpenZFS RWO PVC). Run `/usr/local/bin/agy-init-auth` once inside a new container to complete the one-time SSH OAuth browser link; subsequent pod restarts automatically resume `agy remote-control start --name agy-<workload-name>`.
  - **SSH Only (`port 2222`):** All environments run `sshd` on port `2222` (exposed on port `22` via `Service/workspace-<name>`). Developers and IDEs connect via `ssh-ed25519` key authentication exclusively (`passwords` disabled).

## 2. Container Runtime & Storage Strategy
- **Docker-in-Docker (DinD):** Because Kubernetes nodes natively use `containerd`, agents MUST NOT mount the host socket (`/var/run/docker.sock`). Workspaces requiring container builds (`isPrivileged: true`) use `harbor.cluster.example.org/library/devcontainer-dind:latest` and launch `/usr/local/share/docker-init.sh`.
- **Zero-SSD-Abuse RAM Scratch (`/tmp`):** Every workspace pod mounts `/tmp` as `emptyDir: { medium: Memory, sizeLimit: 4Gi }` (`tmpfs`) so compilation, test artifacts, and agent scratch operations execute in DDR4 RAM without wearing out node boot SSDs.

## 3. Fleet Orchestration CLI (`scripts/devops/agy_fleet.py`)
Use `scripts/devops/agy_fleet.py` (Rule 11 compliant) to manage persistent and ephemeral hackathon workload containers:
- **List Workloads:** `python scripts/devops/agy_fleet.py list`
- **Spawn New Workload Container:**
  ```powershell
  python scripts/devops/agy_fleet.py spawn <workload-name> --repo https://gitlab.cluster.example.org/platform/infra-gitops.git --branch main
  ```
- **Initialize Isolated Per-Container Google OAuth:**
  ```powershell
  python scripts/devops/agy_fleet.py auth-init <workload-name>
  ```
- **Hibernate or Purge Workload Container:**
  ```powershell
  python scripts/devops/agy_fleet.py teardown <workload-name> [--purge]
  ```
- **One-Click `OpsCryer` Workload Profile Switcher (`mode <ai|gaming|hybrid>`):**
  - **`mode ai` (Work / AI Swarm Mode):** Dedicates `nodegamma03` (`128 GiB DDR4 RAM` + `RTX 3080`) to AI (`ollama-gpu-worker`, `swarm-memory`, `dev-envs` containers); scales down `game-servers`, `media`, and `defectdojo`.
  - **`mode gaming` (After-Hours Gaming & Streaming Mode):** Scales up `Satisfactory`, `Factorio`, `Minecraft`, `Jellyfin`, and `Vesktop`; scales down `ollama-gpu-worker` and `ollama-desktop-gpu-worker`.
  - **`mode hybrid` (Co-Scheduled AI + Gaming Mode):** Co-schedules both across `nodegamma03` (`128 GiB DDR4 RAM + RTX 3080`) and `workstation-demo-01` (`RTX 5080 + Samsung 990 PRO NVMe SSD`).
  ```powershell
  python scripts/devops/agy_fleet.py mode ai --manifest-out <workspace>\scratch\agy_mode_ai.yaml
  ```
- **Granular Per-Workload Toggle (`toggle <target> --state <on|off>`):**
  ```powershell
  python scripts/devops/agy_fleet.py toggle ollama-desktop --state on --manifest-out <workspace>\scratch\agy_toggle.yaml
  ```
  *(All profile and per-workload buttons are also available via 1-click UI in **RunbookGate (`https://runbookgate.cluster.example.org`)** and the **`OpsCryer` HUD (`https://opscryer.cluster.example.org`)**).*

## 4. Networking & Egress Whitelisting Playbook (Phase 35B / Task #146)
Network isolation of DevContainers in `dev-envs` is enforced by [`infrastructure/devcontainers/templates/networkpolicy.yaml`](file:///<workspace>/infrastructure/devcontainers/templates/networkpolicy.yaml):
1. **Default Internal DevSecOps Access:** Every workspace is permitted egress to `kube-dns` (`53/UDP`, `53/TCP`), internal cluster namespaces (`gitlab`, `harbor`, `envoy-gateway-system`, `istio-system`, `iam`, `ai-infra`), and Envoy Gateway MetalLB VIPs (`172.20.1.240/32`, `10.20.30.20/32`) so `*.cluster.example.org` services work out of the box.
2. **Antigravity OAuth & Remote Control Tunnel (`enableAntigravity: true`):** Permits outbound `443/TCP` to `0.0.0.0/0` (while blocking RFC1918 lateral LAN subnets `10.0.0.0/8`, `172.20.0.0/16`, `172.16.0.0/12`) so `agy` can authenticate with Google OAuth, reach Gemini APIs, and maintain the `antigravity.google.com` Remote Control tunnel.
3. **Full Internet Egress Override (`allowInternetEgress: true`):** Workspaces requiring non-443 outbound internet protocols set `allowInternetEgress: true` in `infrastructure/devcontainers/values.yaml`.
4. **Punching Custom Egress Holes:** To whitelist an additional internal namespace or external CIDR for a specific workload, add a namespaceSelector or ipBlock rule to `infrastructure/devcontainers/templates/networkpolicy.yaml` gated by a workspace value flag, validate with `helm lint infrastructure/devcontainers`, and sync via ArgoCD (`application/devcontainers`).

## 5. Herdr (`herdr` / `hc`) + Gemini CLI (`gemini`) & Hopper AI Orchestrator (`AIOrchestrator/`) Integration
- **Herdr Multi-Agent Terminal Multiplexer (`herdr` / `hc`):**
  - Each DevContainer installs `/usr/local/bin/herdr-gemini-init` and `/usr/local/bin/hopper-agent-cli` from `ConfigMap/workspace-agy-bootstrap`.
  - Developers can run `herdr` (`hc`) locally on Windows (`irm https://herdr.dev/install.ps1 | iex`) with SSH panes connected to `172.20.1.219–221`, or run `herdr` directly inside the in-cluster DevContainer (`workspace-ai-orchestrator-0` @ `172.20.1.220`) to spawn background/interactive `gemini` CLI and `agy` agents (`hc run --bg --name gemini-hopper gemini`, `herdr agent start gemini --name hopper-worker`, `hc ls`).
  - Generate ready-to-run commands for any workload endpoint via:
    ```powershell
    python scripts/devops/agy_fleet.py herdr-init ai-orchestrator
    ```
- **Hopper AI Orchestrator (`AIOrchestrator/` & `ai-infra/hopper-api-gateway`) Agent Endpoint:**
  - Every DevContainer in `dev-envs` receives `HOPPER_API_URL=http://hopper-api-gateway-service.ai-infra.svc.cluster.local:8000` and `HOPPER_INGRESS_URL=https://aiorchestrator.cluster.example.org` (permitted via the existing `ai-infra` egress rule in `networkpolicy.yaml`).
  - Agents inside `workspace-ai-orchestrator-0` can inspect RabbitMQ (`agent_jobs_gpu` / `agent_jobs_cpu`) and Redis Pub/Sub (`job:<id>`) queue health (`hopper-agent-cli status`), stream completions (`hopper-agent-cli generate --model llama3 --prompt "..."`), and iterate on `AIOrchestrator/hopper_api_updated.py` and `AIOrchestrator/mock_worker_updated.py`.
  - Inspect Hopper topology and CLI commands from the host via:
    ```powershell
    python scripts/devops/agy_fleet.py hopper-status
    ```

## 6. Google gVisor (`runsc`) Secure Container Runtime & OCSF v1.1 Telemetry Standards
- **gVisor (`runsc`) User-Space Kernel Isolation (`RuntimeClass: gvisor`):**
  - Non-privileged DevContainers (`workspace-ai-orchestrator`, `workspace-frontend-app`, and ephemeral agent sandboxes) support `runtimeClassName: gvisor` (`handler: runsc`) via `python scripts/devops/agy_fleet.py spawn <name> --runtime runsc` (mutually exclusive with `--dind`, since `workspace-master-sandbox` requires `runc` for privileged Docker-in-Docker).
  - Cluster `RuntimeClass/gvisor` and OCSF v1.1 telemetry exporter definitions are templated in `infrastructure/devcontainers/templates/gvisor-runsc.yaml` (gated by `.Values.gvisor.enabled`).
- **OCSF v1.1 (Open Cybersecurity Schema Framework) Telemetry Normalization:**
  - All `runsc` container sandbox events, `herdr` + `gemini` agent execution events, and Hopper API Gateway job dispatches normalize to OCSF v1.1 classes:
    - `class_uid: 1007` (**Process Activity**): `runsc` syscall/container process exec and `herdr` (`hc`) agent pane lifecycle (`working`, `blocked`, `idle`, `done`).
    - `class_uid: 4001` (**Network Activity**): Egress policy audit across `dev-envs` $\rightarrow$ `ai-infra` (`hopper-api-gateway-service:8000`, `ollama-service:11434`).
    - `class_uid: 6003` (**API Activity**): Hopper API Gateway (`/v1/chat/completions`, `/v1/generate`, `/v1/status`) and Swarm C2 job dispatches.
  - View the complete phased rollout plan and manifests via:
    ```powershell
    python scripts/devops/agy_fleet.py gvisor-ocsf-plan
    ```


