<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpsCryer presentation runbook

Run commands from the repository root with Python available. The default demo
uses synthetic topology and the bundled sanitized cluster snapshot; it needs no
model service, credentials, or kubectl collection. Keep one terminal for the web
server and another for the commands below.

## Launch all nineteen web portals

```powershell
python opscryer_browser.py --serve --port 8088
```

Open http://127.0.0.1:8088/hub. The server binds to loopback; Ctrl+C stops it.
Eighteen application views plus the suite launchpad make nineteen web portals. Every
route and JSON API below is served by this single command on port 8088.

| Portal | What to show | JSON API (GET) |
| --- | --- | --- |
| `/` | Spatial browser: navigate L0 company through L4 hardware, inspect graph lineage and ticket policy. | `/api/v1/dogfood-zoom` (optional `node_id`, `zoom_level`); `/api/v1/two-act-status?act=1` or `act=2`; `/api/v1/oscal-summary` |
| `/chat` | Plain-language concierge with persona selection, status badges, ticket cards, and citations. | `/api/v1/chat-concierge?q=Manifest%20node%20health&persona=household_user`; `/api/v1/chat-walkthrough` |
| `/incidents` | Prioritized incidents, read-only triage runbooks, and post-incident review evidence. | `/api/v1/incident-commander` |
| `/capacity` | CPU/memory capacity, resource-request audits, GPU/power estimates, and N-1 drain simulation. | `/api/v1/capacity-planner` |
| `/network` | Ingress-to-Service-to-Pod-to-hardware routes, exposure matrix, OIDC observations, and anomalies. | `/api/v1/network-inspector` |
| `/gitops` | GitOps posture, CI/Renovate triage, and release readiness evidence. | `/api/v1/gitops-cockpit` |
| `/executive` | Platform governance dossier, risk register, and evidence gaps. | `/api/v1/executive-summary` |
| `/simulator` | Game-day scenarios with before/after metrics and cascading fault blast radius. | `/api/v1/gameday-simulator` (optional `scenario`) |
| `/playbooks` | Jev decision tree, ticket templates, and multi-persona policy evaluation. | `/api/v1/playbook-studio` |
| `/models` | Low-power vs. high-power model grounding, token compression, and actionable copilot guidance. | `/api/v1/model-copilot` (optional `q`) |
| `/games` | Live Game Server & Cross-Tool Observability Debugging Loop: fleet status, hardware lineage, Grafana pivots, and dual-tier AI guidance. | `/api/v1/game-debug-loop` (optional `game`) |
| `/kb` | Knowledge explorer: search grounded operational knowledge and inspect supporting evidence. | `/api/v1/kb-explorer` (optional `q`) |
| `/jev-eval` | Labeled Jev calibration benchmark: 42-ticket accuracy, 10-bin Expected Calibration Error (ECE), and Brier Score. | `/api/v1/jev-eval` (optional `provider`) |
| `/storage` | OpenZFS ZFS, Democratic-CSI, and CloudNativePG storage topology from the sanitized snapshot. | `/api/v1/storage-cockpit` |
| `/secops` | Security posture, vulnerability evidence, and OIDC/OpenBao observations from the sanitized snapshot. | `/api/v1/secops-cockpit` |
| `/metrics-live` | Cluster metrics, telemetry freshness, and snapshot/live source labels. | `/api/v1/live-metrics` (optional `live=1` explicitly allows kubectl collection) |
| `/adapters` | Kubernetes, Docker Compose, Terraform, and local-host graph compatibility and previews. | `/api/v1/environment-adapters` (optional `adapter`) |
| `/docs` | Interactive API reference and request parameters. | `/api/v1/openapi.json` |
| `/scale` | Measured search, graph traversal, and Jev latency on synthetic enterprise graphs. | `/api/v1/scale-benchmark` (optional `nodes`, 10–5000; default sizes 100, 500, 1500) |
| `/hub` | Launchpad linking every application and its API/CLI entry points. | `/api/v1/suite-catalog` |

The browser also serves these snapshot JSON APIs:

| GET endpoint | Evidence |
| --- | --- |
| `/api/v1/live-cluster-health` | Node, Pod, and Deployment health |
| `/api/v1/live-cluster-currencies` | Seven enriched operational currencies |
| `/api/v1/live-cluster-ask?q=Manifest%20node%20health` | Grounded operational advice and graph citations |
| `/api/v1/live-cluster-chaos` | Six-plane fault simulation |
| `/api/v1/live-cluster-oidc` | Snapshot ingress/OIDC posture |
| `/api/v1/live-cluster-openbao` | OpenBao provenance and quorum placement observations |
| `/api/v1/live-cluster-gitops` | Snapshot GitOps and CI signals |

Use a browser address bar to inspect an API, for example
http://127.0.0.1:8088/api/v1/suite-catalog. Questions must be URL-encoded,
nonempty `q` values. Chat optionally accepts `persona` (`household_user`,
`developer`, `sre`, or `executive`). Unknown or duplicate query parameters fail
with HTTP 400; airlock-blocked chat/advice requests return HTTP 403. The product
summary endpoints accept no query parameters except the simulator's optional
`scenario`, model copilot's and knowledge explorer's optional `q`, and game debug
loop's optional `game`, live metrics' optional `live`, adapters' optional `adapter`,
and scale benchmark's optional `nodes`.
Personas change presentation,
without granting access.

## 2-Act Showcase and live demo script

1. Start at `/hub` and introduce the application suite. Open `/` and explain
   that its topology is synthetic. Run Act 1, then demonstrate L0-L4 navigation,
   graph relationships, ticket anchors, and policy routing.

   ```powershell
   python opscryer_showcase.py --act 1 --json
   ```

2. Run Act 2 and describe the sanitized telemetry boundary. Its checks use
   synthetic telemetry plus the bundled snapshot, report `live_connections:
   false`, and do not collect cluster data. Show `/incidents`, then `/capacity`
   for maintenance simulation and `/network` for ingress lineage. Read findings
   as snapshot observations rather than proof of root cause.

   ```powershell
   python opscryer_showcase.py --act 2 --json
   ```

3. Continue to `/gitops` for release evidence and `/executive` for risks and
   missing evidence. Explain that chaos results are simulations, capacity drains
   are models, and OSCAL controls remain unassessed. Snapshot checks do not
   establish live OIDC enforcement, KMS operation, or compliance certification.
4. Open `/simulator` to compare a game-day fault against the baseline, then
   `/playbooks` to inspect decision paths and required tickets. Use `/models`
   to compare grounded low-power and high-power guidance and review what to do
   next. The default demonstrations are deterministic and need no model service.
5. Open `/games` and present the five-step cross-tool debugging loop below.
   Compare its API and CLI evidence before returning to the other portals.
   Visit `/kb` for knowledge search, `/storage` for storage lineage, and `/secops`
   for security posture. Compare their JSON APIs with the portal evidence;
   storage and security findings are read-only snapshot observations.
6. Tour the Wave 1–4 capabilities: `/metrics-live` for labeled metrics and
   freshness, `/adapters` for environment graph previews, `/docs` for the API
   contract, and `/scale` for synthetic graph timings. Compare each portal with
   its JSON API above. Default metrics use snapshot data; live collection requires
   explicit opt-in. Scale results measure this machine and are not production SLAs.
7. Open `/chat` and perform the five turns below. Finish at `/hub` so the
   audience can revisit any application.

Each act exits 0 on success and 1 on failure. An individual act reports
`epics_verified: 0`; the complete Epic scorecard is a separate command:

```powershell
python opscryer_showcase.py --verify-all-epics --json
python epic_showcase_verifier.py --json
```

The Wave 1–4 verifier retains the nine-Epic suites and both acts, adding live
metrics, environment adapters, and scale benchmark contract tests to EPIC-5.

## Live Game Server & Cross-Tool Observability Debugging Loop

Follow `/games` -> `/api/v1/game-debug-loop` ->
`python game_observability_loop.py --json` to show the same default Minecraft
debugging evidence in the portal, API, and terminal. Select Minecraft,
Satisfactory, Factorio, Palworld, or RomM in the portal; the API accepts, for
example, `/api/v1/game-debug-loop?game=factorio`, and the CLI accepts
`python game_observability_loop.py --game factorio --json`.

1. Classify the player's symptom and review household triage to distinguish
   client lag, network trouble, and server trouble.
2. Trace the game's workload to its hosting hardware, metrics, and active
   incidents. Call out missing placement evidence in the snapshot.
3. Open [Grafana dashboards](https://grafana.cluster.example.org/dashboards) for trends,
   then [Grafana Explore](https://grafana.cluster.example.org/explore) for the supplied
   read-only PromQL and Loki queries over the symptom time window. Confirm
   inventory and metric/log labels before substituting query placeholders.
   Use OpsCryer for graph lineage and incident context; correlate Grafana
   findings with [ArgoCD sync/health](https://argocd.cluster.example.org/applications)
   and [GitLab pipeline timing](https://gitlab.cluster.example.org/prod/home-k8s/-/pipelines).
   Open [RunbookGate](https://runbookgate.cluster.example.org) to review recovery runbooks;
   executing recovery requires an approved ticket.
4. Compare low-power and high-power AI "What To Do" guidance, graph citations,
   read-only kubectl checks, and Jev ticket requirements.
5. Review recovery criteria: stable Grafana metrics and logs, Ready pods and
   hosting nodes, LAN DNS reachability, and confirmation from affected players.
   Attach before/after evidence to the ticket.

The default loop uses the bundled sanitized snapshot without contacting game
servers or external tools. The `.cluster.example.org` links require access to the homelab
LAN; demonstrate their destinations and supplied queries offline when needed.
Snapshot observations and recovery criteria do not establish live recovery.

## 5-Turn Multi-Persona Walkthrough

Run the deterministic transcript, or use its questions in `/chat` with the
matching persona. The CLI executive turn additionally attaches OSCAL posture.

```powershell
python chat_walkthrough.py
python chat_walkthrough.py --catalog live-cluster-sanitized.json --json
python chat_walkthrough.py --markdown
```

| Turn | Persona | Question and presenter cue |
| --- | --- | --- |
| 1 | `household_user` | “Manifest Minecraft/Factorio server pods are down and the living room GPU has low FPS. How can we distinguish server trouble from client lag?” Show household triage and snapshot citations. |
| 2 | `developer` | “Manifest dependencies for scaffolding a new 3-tier project and pipeline.” Show the golden-path ticket policy. |
| 3 | `developer` | “What is the database credentials policy for this project?” Show the deliberate airlock block before diagnostics or ticket-policy evaluation. |
| 4 | `sre` | “Manifest nodebeta02 NotReady and gitlab failed runner pods: what snapshot evidence and diagnostic steps should I review?” Show grounded evidence and suggested read-only checks. |
| 5 | `executive` | “Manifest OSCAL compliance and cluster health summary for leadership.” Show the executive summary and unassessed control map in the CLI transcript. |

Expect five turns, four allowed responses, and one blocked request. The walkthrough
uses the real concierge with snapshot evidence, without polling, model calls,
ticket filing, or remediation.

## Demo Rehearsal and CLI cheat-sheet

Before presenting, run the rehearsal for timings and an integration scorecard:

```powershell
python demo_rehearsal.py
python demo_rehearsal.py --json
python opscryer_cli.py doctor --json
python live_e2e_runner.py --json
python -m unittest tests.test_demo_rehearsal tests.test_epic_showcase_verifier tests.test_opscryer_public_smoke -v
python golden_path_gates.py
```

Rehearsal checks both acts, personas, airlock behavior, snapshot evidence, product
readiness, and loopback HTTP routes. It starts its own local HTTP checks; an
already running presentation server is unnecessary. Rehearsal and E2E exit 0
when passed and 1 on failure. Enclosing timings include child steps, so do not
sum all rows to estimate elapsed time.

Use these commands for standalone evidence or a portable presentation bundle:

```powershell
python incident_commander.py --json
python incident_commander.py --markdown
python capacity_planner.py --json
python capacity_planner.py --drain-node nodebeta02 --json
python network_topology_inspector.py --json
python network_topology_inspector.py --mermaid
python gitops_release_cockpit.py --markdown
python executive_command_center.py --markdown
python gameday_simulator.py --json
python playbook_studio.py --json
python model_tier_copilot.py --json
python game_observability_loop.py --json
python jev_knowledge_explorer.py --json
python storage_zfs_cockpit.py --json
python secops_vulnerability_cockpit.py --json
python opscryer_suite_hub.py --json
python opscryer_suite_hub.py --export-suite-bundle presentation-suite
```

The unified CLI's `doctor --json` reports runtime capabilities, package architecture,
and route counts. Use it before the tour to check the presentation environment.
`python opscryer_cli.py routes --json` lists routes, while `metrics --json` and
`adapters --json` expose the corresponding offline reports. Live metrics collection
requires `python opscryer_cli.py metrics --live --json`.

The portable bundle contains HTML and JSON snapshots. Opening exported files
does not start the Python HTTP APIs.

## Live Cluster Harvester/Poller

Inspect the offline example without contacting a cluster:

```powershell
python cluster_harvester.py --json
$snapshotPath = Join-Path ([System.IO.Path]::GetTempPath()) 'opscryer-cluster-snapshot.json'
python live_poller.py --interval 5 --max-polls 2 --export $snapshotPath --json
```

For authorized live collection, configure kubectl for the intended context and
explicitly opt in. These commands refresh the repository snapshot consumed by
the web snapshot APIs:

```powershell
python cluster_harvester.py --harvest-live --export live-cluster-sanitized.json
python live_poller.py --harvest-live --interval 30 --max-polls 2 --export live-cluster-sanitized.json --json
```

The harvester performs read-only inventory and node-metrics collection with a
default 15-second timeout per command, sanitizing data in memory before export.
Check `source: live_kubectl` and `example: false` before calling evidence live.
`source: offline_fallback` and `example: true` identify fallback data; missing
metrics remain unavailable. Review sanitized exports before sharing: external
WAN addresses must be replaced with `203.0.113.1`, MAC addresses masked as
`AA:BB:CC:XX:XX:XX`, and credentials removed. Private LAN and `.cluster.example.org`
references may remain.

Polling intervals must be at least five seconds. Omit `--max-polls` to continue
until Ctrl+C. Each export atomically replaces the target; its parent directory
must exist. Within one poller instance, a collection failure after a successful
live read retains the last known-good snapshot with `stale: true` and failure
metadata. A saved live snapshot is historical until refreshed.

Refresh the portal after collection. The browser APIs read the bundled snapshot
on request without starting kubectl or a poller; `/` keeps its synthetic topology.
The browser does not support `--live-cluster`.

To rehearse explicit live collection or certify collection plus an Ollama tags
probe, use:

```powershell
python demo_rehearsal.py --harvest-live --json
python live_e2e_runner.py --harvest-live --probe-ollama --json
```

Live rehearsal rejects fallback/stale collection, and the E2E probe must reach
Ollama successfully. Their HTTP checks still exercise the bundled snapshot;
rehearsal act verifiers remain offline. If live collection is unavailable,
present the labeled bundled snapshot and run the default rehearsal commands.
