---
name: notification_arbitrator
description: Notification Arbitrator (Zero-Knowledge Gateway)
---

# AI Skill: Notification Arbitrator (Zero-Knowledge Gateway)

**Skill ID:** 47
**Module:** Notification Arbitration System (Epic 18)
**Last Updated:** 2026-06-27

## 1. Core Philosophy: Zero-Knowledge Alerting
The Notification Arbitrator is the **absolute chokepoint** for all cluster alerts and notifications. It enforces a strict "Zero-Knowledge" policy for any notification leaving the cluster boundary via third-party services (like `ntfy.sh`).

**CRITICAL ARCHITECTURAL RULE:** 
Under no circumstances may an AI agent or developer configure a cluster service to send raw, unsanitized JSON payloads (e.g., GitLab webhooks, Security traces, CI/CD diffs) directly to the public Ntfy push servers. 

All webhooks MUST be routed to the internal Notification Arbitrator first. The Arbitrator MUST strip the payload, store the raw data securely in its internal vault, and only forward a sanitized summary to the external push service.

## 2. Ntfy Topic Strategy & Aggregation
We do not use complex, multi-topic routing. 
- All notifications are pushed to a **single, unified channel**.
- Messages sent to Ntfy MUST be formatted as high-level summary counts or extremely brief descriptors.
- Example allowed formats:
  - "3 MRs are ready for review"
  - "1 Critical Security Alert"
  - "2 Unregistered Devices on VLAN"
- Agents must NOT create new Ntfy topics for different modules.

## 3. Data Retention & The Vault (SQLite)
The Arbitrator uses a persistent SQLite database (mounted via a 1Gi PVC) to store the raw webhook payloads.
- **Retention Rule:** We keep all historical data indefinitely. 
- Agents must **never** implement rolling deletion or data pruning scripts for this database. If the PVC reaches capacity, the correct mitigation is to manually expand the storage volume via Kubernetes manifests.

## 4. Dashboard & Authoritative Authoring
The Arbitrator exposes a React/Vite web dashboard for viewing the full JSON payloads that were stripped from the Ntfy pushes.
- **Access Rule:** The dashboard MUST ALWAYS be placed behind the cluster's Keycloak SSO infrastructure (via OAuth2-Proxy or Ingress annotations).
- "Authoritative Authoring" of routing rules (e.g., changing which events trigger a ping) can only be performed by authenticated users through this dashboard, ensuring a strict chain of custody.

## 5. Development Guidelines for Future Integration
If an AI agent needs to add a new webhook source (e.g., a new security tool or CI platform):
1. Create a new REST endpoint in the FastAPI `app.py` (e.g., `/webhooks/new-tool`).
2. Implement strict Python parsing to extract the full payload.
3. Call `save_notification(...)` to persist the raw data to SQLite.
4. Calculate the summary/aggregate (e.g., "1 New Alert").
5. Dispatch only the summary string to Ntfy. 
6. Do NOT expose sensitive variables in the summary string.

## 6. Epic #266 Rework Mandate: Self-Hosted `ntfy.cluster.example.org`, Zero Private Data Leaks & Quiet-By-Default Filters (`0` Messages When Nominal)
1. **Self-Hosted Ntfy Server Only (`https://ntfy.cluster.example.org`, Task `#267`):**
   - Public `https://ntfy.sh` is strictly prohibited (`allow_public_ntfy_sh: False`). Both `notification-arbitrator` and `monitoring/ntfy-bridge` must route exclusively to the self-hosted homelab `ntfy` instance (`https://ntfy.cluster.example.org`).
2. **Eliminate Direct `monitoring/ntfy-bridge` Bypass & Raw Payload Leaks (Task `#268`):**
   - `monitoring/ntfy-bridge.yaml` must never forward raw Alertmanager `summary` or `description` strings (which leak internal pod names, namespaces, IPs, and hostnames). All Prometheus/Alertmanager alerts must route through the Zero-Knowledge Scrubber (`scripts/monitoring/notification_filter_engine.py`).
3. **Quiet-By-Default Sane Defaults & Easily Customizable Filters (Task `#269`):**
   - **Golden Rule:** *"3 messages in a day with nothing going wrong is a lot!!"* — When nothing is critically wrong, **0 notifications** are sent.
   - Suppress all `info`, `warning`, `resolved`, routine CI pass, and routine agent status messages by default.
   - Enforce a 6-hour (`360m`) flapping alert deduplication cooldown and a default hard daily cap (`max_daily_notifications: 2`–`4`), with declarative user-customizable filter rules.
4. **Live In-Cluster Chokepoint & Persistent SQLite Deduplication (`2026-11-04`):**
   - `infrastructure/notifications/notification-arbitrator/deployment.yaml` mounts `ConfigMap/notification-arbitrator-app` at `/app/app.py` (`subPath: app.py`) so live filtering updates roll out immediately via `kubectl apply` without waiting for an external image rebuild.
   - `/app/data/arbitrator.db` maintains `push_dedup_ledger` (persisting the 6-hour `21600s` per-fingerprint cooldown across pod restarts) and `push_daily_log` (persisting daily push & suppression counters), while `notifications` retains 100% of raw events with zero row deletion.
   - Legacy 5-minute manual-job nag timers (`check_pipeline_manual_jobs_after_delay`) and 10-minute MR pipeline nag timers (`check_pipeline_nag_after_delay`) are permanently removed.
   - `monitoring/ntfy-bridge.yaml` drops all `resolved`, `info`, `warning`, and muted alertnames immediately, enforces a 6-hour (`21600s`) per-alertname cooldown, and forwards qualifying `critical` alerts to `http://notification-arbitrator.notifications.svc.cluster.local/webhooks/alertmanager`.


