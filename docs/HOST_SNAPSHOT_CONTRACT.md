<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpsCryer Host Snapshot Contract (`OPSCRYER_HOST_SNAPSHOT` v1)

This document specifies the generic, provider-agnostic browser `window.postMessage` contract between an embedding host portal (such as Backstage, an internal developer portal, or a NOC shell) and an embedded OpsCryer Spatial Browser iframe.

---

## 1. Design Goals & Architectural Boundary

OpsCryer runs as an independent, decoupled visualization and deterministic triage service. When embedded inside a host developer portal via an `<iframe>`, the host portal may already hold in-browser catalog metadata and provider status summaries (for example, ETag-revalidated merge requests, pipelines, Kubernetes workloads, or cloud inventory).

The **`OPSCRYER_HOST_SNAPSHOT` (`version: 1`)** contract enables the host frame to share a **read-only, pre-sanitized metadata snapshot** with the OpsCryer iframe over origin-scoped `postMessage`:

- **Zero Backend Coupling:** OpsCryer requires no portal-specific backend database access or duplicated API polling.
- **Zero Credential Forwarding:** OAuth tokens, personal access tokens, session cookies, API keys, and secrets NEVER cross the iframe boundary.
- **Provider-Agnostic Extensibility:** Built-in provider namespaces (`gitlab`, `kubernetes`, `aws`) coexist with arbitrary custom provider namespaces (`[provider: string]: object`) and backward-compatible top-level GitOps fields.

---

## 2. Canonical `OPSCRYER_HOST_SNAPSHOT` (`version: 1`) Envelope

```json
{
  "type": "OPSCRYER_HOST_SNAPSHOT",
  "version": 1,
  "source": "backstage",
  "revision": 1,
  "updatedAt": "2026-01-01T00:00:00.000Z",
  "connected": true,
  "data": {
    "catalogEntities": [],
    "providers": {
      "gitlab": { "mergeRequests": [], "starredRepos": [], "pipelines": [] },
      "kubernetes": { "clusters": [], "workloads": [] },
      "aws": { "accounts": [], "resources": [] }
    },
    "mergeRequests": [],
    "starredRepos": [],
    "pipelines": []
  }
}
```

### 2.1 Envelope Fields

| Field | Type | Required | Constraints & Semantics |
| :--- | :--- | :--- | :--- |
| `type` | `string` | Yes | Must be exact literal `"OPSCRYER_HOST_SNAPSHOT"`. |
| `version` | `integer` | Yes (v1) | Must be integer `1`. Legacy payloads omitting `version` are normalized to `1`; any other version value (`0`, `2`, `"1"`, booleans) is rejected. |
| `source` | `string` | Yes | Non-empty host identifier (`1..128` printable characters, e.g., `"backstage"`). |
| `revision` | `integer` | Yes | Non-negative monotonic revision counter (`>= 0`). Defaults to `0` when omitted by legacy senders. |
| `updatedAt` | `string` | Yes | ISO-8601 UTC timestamp string (`<= 64` characters) or `""` when not yet populated. |
| `connected` | `boolean` | Yes | `true` when the host portal has an active authenticated upstream session; `false` otherwise. |
| `data` | `object` | Yes | Sanitized read-only snapshot payload container. |

### 2.2 `data` & Extensible `data.providers` Schema

| Path | Type | Semantics |
| :--- | :--- | :--- |
| `data.catalogEntities` | `array<object>` | Sanitized catalog entity summaries (e.g., `name`, `title`, `kind`, `owner`, `lifecycle`, `system`). |
| `data.providers` | `object` | Map of provider namespace keys (`[A-Za-z0-9_.-]{1,64}`) to provider snapshot objects. |
| `data.providers.gitlab` | `object` | Normalized GitLab summary containing `mergeRequests` (`array`), `starredRepos` (`array`), and `pipelines` (`array`). |
| `data.providers.kubernetes` | `object` *(optional)* | Kubernetes summary containing `clusters` (`array`) and `workloads` (`array`), plus optional custom metadata keys. |
| `data.providers.aws` | `object` *(optional)* | AWS summary containing `accounts` (`array`) and `resources` (`array`), plus optional custom metadata keys. |
| `data.providers.<custom>` | `object` *(optional)* | Extensible provider map entry (e.g., `gcp`, `azure`, `argocd`, `prometheus`) for additional integrations. |
| `data.mergeRequests` | `array` | Backward-compatible mirror of `data.providers.gitlab.mergeRequests`. |
| `data.starredRepos` | `array` | Backward-compatible mirror of `data.providers.gitlab.starredRepos`. |
| `data.pipelines` | `array` | Backward-compatible mirror of `data.providers.gitlab.pipelines`. |

### 2.3 Optional Readiness Handshake (`OPSCRYER_READY`)

When OpsCryer is embedded inside an iframe (`window.parent !== window`) and configured with one or more explicit trusted host origins, OpsCryer posts an origin-scoped readiness notification to each configured host origin:

```json
{
  "type": "OPSCRYER_READY",
  "version": 1
}
```

The host portal MUST verify both `event.origin` and `event.source === iframe.contentWindow` before responding with an `OPSCRYER_HOST_SNAPSHOT` message scoped to the OpsCryer iframe's exact `targetOrigin`.

---

## 3. Backward Compatibility & Normalization Rules

1. **Legacy Unversioned Payloads:** Payloads with `type: "OPSCRYER_HOST_SNAPSHOT"` that omit `version` and/or `data.providers` are accepted as legacy v0 snapshots and normalized to `version: 1`.
2. **Top-Level GitOps Field Normalization:**
   - When `data.providers.gitlab` is omitted, top-level `data.mergeRequests`, `data.starredRepos`, and `data.pipelines` automatically populate `data.providers.gitlab.{mergeRequests, starredRepos, pipelines}`.
   - Conversely, when `data.providers.gitlab` is provided and top-level `mergeRequests`, `starredRepos`, or `pipelines` are omitted, the normalizer populates the top-level arrays from `data.providers.gitlab` so both v1 provider-aware consumers and legacy consumers observe identical arrays.

---

## 4. Mandatory Security Invariants

### 4.1 Zero OAuth / API Tokens or Secrets (Fail-Closed Rejection)
- Host portals MUST strip or omit all authentication credentials before calling `postMessage`.
- Both the Python validator (`host_snapshot_contract.py`) and the browser listener (`index.html`) **recursively inspect every key and string value** across the entire message tree before accepting a snapshot.
- Any payload containing forbidden credential keys — including `token`, `access_token`, `accessToken`, `refresh_token`, `refreshToken`, `id_token`, `private_token`, `privateToken`, `authorization`, `cookie`, `set_cookie`, `secret`, `client_secret`, `clientSecret`, `password`, `passwd`, `passphrase`, `apiKey`, `api_key`, `x-api-key`, `privateKey`, `private_key`, `kubeconfig`, `credentials`, `bearer`, or prototype-pollution keys (`__proto__`, `constructor`, `prototype`) — or `Bearer <credential>` header values is **rejected in full (fail closed)**.
- Rejected messages never overwrite `window.__OPSCRYER_HOST_SNAPSHOT__` and never emit events.

### 4.2 Explicit `event.origin` Allowlist Validation (Fail Closed)
- Wildcard origins (`"*"`), opaque origins (`"null"`), non-HTTP(S) schemes (`javascript:`, `data:`, `file:`), and URLs containing embedded userinfo (`user:pass@`) are unconditionally rejected.
- On the sender side, the host frame MUST pass the exact `new URL(opscryerUrl).origin` as `targetOrigin` to `iframe.contentWindow.postMessage(payload, targetOrigin)`.
- On the receiver side (`index.html`), OpsCryer accepts `OPSCRYER_HOST_SNAPSHOT` messages **only** when `event.origin` matches the resolved trusted host origin allowlist:
  1. **Same-Origin:** `window.location.origin` (when served over `http:` or `https:`).
  2. **URL Query Parameter:** `?hostOrigin=https://portal.example.org` (or comma-separated `?hostOrigins=https://portal.example.org,http://localhost:3000`).
  3. **Runtime Configuration:** `window.__OPSCRYER_HOST_ALLOWED_ORIGINS__` (array or comma/space-separated string of `http(s)://host[:port]` origins) or `window.__OPSCRYER_CONFIG__.hostAllowedOrigins`.
- Deployments embedding OpsCryer cross-origin should also configure `OPSCRYER_FRAME_ANCESTORS="https://portal.example.org"` on the OpsCryer gateway so HTTP `Content-Security-Policy: frame-ancestors` matches the `postMessage` origin allowlist.

### 4.3 Bounded Payload Size, Nesting Depth & Collection Cardinality
- **Maximum Serialized Payload Size:** `524,288` bytes (512 KiB).
- **Maximum Object/Array Nesting Depth:** `16` levels.
- **Maximum Collection Length:** `1,000` items per array (`catalogEntities`, `mergeRequests`, `starredRepos`, `pipelines`, provider resource arrays).
- Payloads exceeding any bound are dropped immediately without allocation or state mutation.

### 4.4 Read-Only In-Memory Semantics
- Accepted snapshots are stored strictly in memory at `window.__OPSCRYER_HOST_SNAPSHOT__` (never written to `localStorage`, `sessionStorage`, or cookies).
- Upon accepting a valid snapshot, OpsCryer dispatches a `CustomEvent('opscryer:host-snapshot', { detail: snapshot })` on `window` and updates the `#host-snapshot-badge` status indicator using `textContent` only (never `innerHTML`).
- Host snapshots are strictly observational metadata and cannot trigger privileged backend mutations or command execution.

---

## 5. Reference Validation Usage

### Python (`host_snapshot_contract.py`)

```python
from host_snapshot_contract import validate_and_sanitize_host_snapshot

sanitized = validate_and_sanitize_host_snapshot(
    raw_payload,
    event_origin="https://portal.example.org",
    allowed_origins=["https://portal.example.org"],
)
```

### Browser Consumer (`index.html`)

```javascript
window.addEventListener('opscryer:host-snapshot', event => {
  const snapshot = event.detail;
  console.log(snapshot.version, snapshot.data.providers.gitlab.mergeRequests.length);
});
```
