---
name: "game_server_steam_probe_and_recovery"
description: "Probe SteamCMD / Valve CM reachability, audit Satisfactory and dedicated game server Kubernetes manifests and Unreal Engine 5 CVar configs, auto-recover CrashLoopBackOff game servers, and encode observations into the System One Jev decision tree and Knowledge Graph."
---

# Game Server & SteamCMD Probe, Auto-Recovery & Jev / Knowledge Graph Skill

## 1. Purpose & When to Use

Activate this skill whenever:
- A dedicated game server (`Deployment/satisfactory`, `Deployment/factorio`, `Deployment/minecraft-survival`, `Deployment/minecraft-creative` in namespace `game-servers`) is down, in `CrashLoopBackOff`, or restarting unexpectedly.
- `SteamCMD` fails during container startup with **Exit Code 8** (`ERROR! Failed to install app '1690800' (Missing configuration)` or `Missing file permissions` when `/home/steam/.steam` is ephemeral or `HOME=/root`).
- Unreal Engine 5 (`FactoryServer-Linux-Shipping`) crashes with **`Signal 11 (SIGSEGV)`** in `UFGUserSettingApplyType::TryRegisterCvarValue()` (`FGUserSettingApplyType.cpp:98`) or logs `import failed for mFloatValues` due to malformed `GameUserSettings.ini` / `Engine.ini` CVar entries.
- The nightly `satisfactory-nightly-restart` CronJob fails to reach the Kubernetes API (`10.96.0.1:443` DNAT'd by `kube-proxy` to `10.20.3.2:6443` under Calico `default-deny-all`), or the server restarts at 5:00 PM PDT / 4:00 PM PST (`00:00 UTC`) because `FG.ServerRestartTimeSlot` was set to `0.0`.
- You want to probe the Steam server / game server state, bring the game server back to a verified `2/2 Running` state, and encode the diagnostic playbooks and node relationships into the **System One (`Jev`) Decision Tree** and **4-Domain Knowledge Graph**.

---

## 2. The Four Canonical Steam & Game Server Failure Modes

| Failure Code | Symptom / Log Signature | Root Cause | Deterministic Fix & Guardrail |
| :--- | :--- | :--- | :--- |
| **`STEAMCMD_EXIT_8_MISSING_CONFIG`** | `ERROR! Failed to install app '1690800' (Missing configuration)` (Exit Code `8`) or `Redirecting stderr to '/root/Steam/logs/stderr.txt'` (`Missing file permissions`) | `wolveix/satisfactory-server:latest` keeps `/home/steam/.steam` and `/home/steam/.local/share/Steam` on the ephemeral container rootfs and defaults `HOME=/root` before `/init.sh` runs. Running `steamcmd` on a cold `appcache` without `+app_info_update 1` exits with code `8`, and `/init.sh` deletes `appmanifest_1690800.acf` under `set -e`, causing an infinite `CrashLoopBackOff`. | Persist `/config/.steam-cache/local-steam` and `/config/.steam-cache/steam` on the `satisfactory-data-pvc` ZFS volume, `export HOME="/home/steam"`, run a 3-attempt retry loop with `+login anonymous +app_info_update 1 +app_update 1690800` (clearing only stale `appinfo.vdf` on retry, never `appmanifest_1690800.acf`), and hand off to `SKIPUPDATE="true" exec /init.sh`. |
| **`UE5_CVAR_SIGSEGV_TRY_REGISTER`** | `Signal 11 (SIGSEGV)` in `UFGUserSettingApplyType::TryRegisterCvarValue()` (`FGUserSettingApplyType.cpp:98`) or `Warning: PerObjectConfig import failed for mFloatValues in: (("FG.ServerRestartTimeSlot", 660.000000),)` | Placing `FG.ServerRestartTimeSlot` or `FG.AutosaveInterval` under `[SystemSettings]` in `Engine.ini` pre-registers those CVars as non-float SystemSettings CVars during `FEngineLoop::Init()`, causing `TryRegisterCvarValue()` to dereference `nullptr` (`0x0`). Additionally, replacing `mFloatValues=(` when `mFloatValues=()` is empty leaves a trailing comma `,)` in `GameUserSettings.ini`. | Strip `[SystemSettings]`, `FG.ServerRestartTimeSlot=`, and `FG.AutosaveInterval=` from `Engine.ini`. In `GameUserSettings.ini`, strip `,)` and replace empty `mFloatValues=()` with `mFloatValues=(("FG.ServerRestartTimeSlot", 660.000000))`. |
| **`CALICO_DNAT_CRONJOB_BLOCK`** | `satisfactory-nightly-restart` CronJob times out contacting `10.96.0.1:443` | `kube-proxy` DNATs `10.96.0.1:443` to `hostNetwork` `kube-apiserver` at `10.20.3.2:6443` (`nodealpha01`) before Calico egress evaluation, where `default-deny-all` blocks `10.0.0.0/8`. | Include both `10.96.0.1/32` and `10.20.3.2/32` (ports `443` and `6443` TCP) in `NetworkPolicy/allow-restart-cronjob-kube-api` inside `infrastructure/game-servers/network-policies.yaml`. |
| **`SESSION_RESTART_5PM_UTC0_TRAP`** | `LogServer: Display: Server restart time slot reached. Restarting server.` at `00:00 UTC` (`5:00 PM PDT` / `4:00 PM PST`) | `FG.ServerRestartTimeSlot` is a 24-hour UTC time-of-day in minutes past `00:00 UTC` (`0.0` to `1440.0`), not a boolean toggle. Setting `0.0` schedules a restart at `00:00 UTC` during peak evening gaming hours. | Set `"FG.ServerRestartTimeSlot", 660.000000` (`11 * 60 = 11:00 UTC` = `4:00 AM PDT` / `3:00 AM PST`) in `GameUserSettings.ini` to match `CronJob/satisfactory-nightly-restart` (`0 11 * * *`). |

---

## 3. Reusable Probe & Auto-Recovery CLI Commands

Use the reusable `graph_knowledge_harvester.py` and `system_one_jev_router.py` CLI tools (never ad-hoc one-off scripts, per Rule 11):

### A. Run the 6-Gate Steam & Game Server Diagnostic Probe
```powershell
python scripts/devops/graph_knowledge_harvester.py steam-probe
```
To include live Kubernetes pod inspection (`game-servers` namespace) and live Valve Steam Web API reachability:
```powershell
python scripts/devops/graph_knowledge_harvester.py steam-probe --live-k8s --live-steam-http
```

### B. Run Deterministic Auto-Recovery & Jev / Knowledge Graph Encoding
Dry-run recovery plan + 4-Gate `Jev` decision tree validation:
```powershell
python scripts/devops/graph_knowledge_harvester.py steam-recover
```
Execute live cluster recovery (applies `infrastructure/game-servers/satisfactory.yaml` and `network-policies.yaml` if the probe detects drift or `CrashLoopBackOff`):
```powershell
python scripts/devops/graph_knowledge_harvester.py steam-recover --live-k8s --apply
```

### C. Query the System One (`Jev`) Support Ticket Auto-Responder for Steam / Game Server Incidents
```powershell
python jev_client.py answer-ticket --question "Satisfactory server is in CrashLoopBackOff with SteamCMD Missing configuration exit code 8 and TryRegisterCvarValue SIGSEGV"
```

---

## 4. How This Skill Encodes Into `Jev` & the 4-Domain Knowledge Graph

1. **Knowledge Graph Nodes & Directed Edges (`scripts/devops/graph_knowledge_harvester.py`):**
   - Links operational observations (`obs-satisfactory-steamcmd-appmanifest-and-cvar-guard`) across:
     - **Hardware Domain:** `hw-nodegamma03-node` (`nodegamma03` `10.20.3.13`, `128 GiB DDR4 RAM` + `4Gi` `emptyDir: Memory` RAM-disk).
     - **Deployment Domain:** `deploy-dev-envs` / `deploy-game-servers` (`namespace: game-servers`, MetalLB VIP `172.20.1.213:7777` / `:8888`, exporter `:9103/metrics`).
     - **Storage Resource Domain:** `res-openzfs-zfs` (`satisfactory-data-pvc` on `openzfs-fast` ZFS NVMe/NFS persisting `/config/gamefiles` and `/config/.steam-cache`).
2. **System One (`Jev`) Support Ticket Playbook (`.ai/graphify/support_ticket_playbooks.json`):**
   - Playbook `satisfactory-steamcmd-exit8-and-cvar-sigsegv` compiles directly into `SystemOneSupportTicketTree v1` (`node-ticket-playbook-satisfactory-steamcmd-exit8-and-cvar-sigsegv` -> `leaf-ticket-playbook-satisfactory-steamcmd-exit8-and-cvar-sigsegv`).
   - Validated through the 4-Gate `propose_jev_tree_change` sandbox (`gate_1_schema_and_keyword_hygiene`, `gate_2_acyclic_dag_integrity`, `gate_3_zero_benchmark_regression` across `16/16` dev and `4/4` holdout questions, and `gate_4_sample_ticket_self_test`).

---

## 5. Steam Link Remote Play & Bluetooth Controller Input Troubleshooting (`Stardew Valley` / `Pixel Tablet` / `Nintendo Switch Pro Controller`)

Use this playbook (`steam-link-stardew-controller-input` / Knowledge Graph node `runbook-steam-link-controller-stardew` linked to `hw-desktop-rtx5080`, `res-desktop-5080`, and `deploy-game-servers`) whenever a user streams a game (such as **Stardew Valley**) from the desktop gaming PC (`workstation-demo-01` `10.20.4.22`) to a **Pixel Tablet** via **Steam Link** using a Bluetooth **Nintendo Switch Pro Controller**, and the controller works inside the Steam Link menus/overlay but cannot move or act once in-game:

| Priority | Failure Mode | Why Menus Work But In-Game Fails | Deterministic Resolution |
| :--- | :--- | :--- | :--- |
| **1. Layout Template** | **`STEAM_INPUT_NON_GAMEPAD_TEMPLATE`** | A community layout or Desktop/Web Browser template is active, unbinding the left stick or mapping sticks to mouse regions Stardew ignores. | Open **Steam Overlay** (`...` button or **Home / Capture**) $\rightarrow$ **Controller Settings** $\rightarrow$ **Templates** tab $\rightarrow$ select and apply **`Gamepad`** (or **`Gamepad with Camera Controls`**). |
| **2. Hot-Attach Init** | **`STARDEW_POST_LAUNCH_CONTROLLER_IGNORE`** | Stardew Valley (1.6+) binds XInput/SDL gamepads at process startup and ignores virtual controllers attached or reconfigured after launch. | Keep the Pro Controller connected in Steam Link, exit Stardew Valley completely to **Steam Big Picture**, and relaunch Stardew Valley **using the Pro Controller `A`/`B` buttons** (not touchscreen tap). |
| **3. Slot Ordering** | **`XINPUT_SLOT_2_PLAYER_ORDER_CONFLICT`** | Steam Overlay accepts input from *any* controller slot, whereas single-player Stardew Valley only listens to **Controller Slot 1**. A local controller, 2.4GHz dongle, analog keypad (Razer/Wooting), `vJoy`, or `DS4Windows` on the desktop PC occupies Slot 1. | Open **Steam Overlay** $\rightarrow$ **Controller Settings** $\rightarrow$ **Reorder Controllers** at the top and move the Bluetooth Pro Controller to **Slot 1** (or unplug the extra controller/dongle on the desktop PC). |
| **4. In-Game Toggle** | **`STARDEW_INGAME_GAMEPAD_MODE_OFF`** | Stardew Valley's internal `Gamepad Mode` option is set to `Force Off` or `Auto-Detect` latched onto mouse/touch mode. | Use the **tablet touchscreen** (or hold **Select/`-`** on the Pro Controller for the Steam Link virtual cursor) $\rightarrow$ open Stardew inventory/menu $\rightarrow$ **Options** tab $\rightarrow$ set **Gamepad Mode** to **`Force On`**. |
| **5. OS Window Focus** | **`HOST_PC_WINDOW_UNFOCUSED`** | Closing the Steam Link overlay left the Stardew Valley window unfocused in the background on Windows 11 (`10.20.4.22`). | Tap once in the center of the tablet screen (or switch Steam Link touch mode to **Direct Cursor** and click the game window) to restore active OS window focus on the host PC. |

### Query via System One (`Jev`) Support Ticket Auto-Responder
```powershell
python jev_client.py answer-ticket --question "Using Steam Link to stream Stardew Valley from desktop to Pixel Tablet with Bluetooth Nintendo Switch Pro Controller; can navigate Steam Link menus but cannot move in game"
```

