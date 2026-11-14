---
name: network_exposure
description: Network Exposure and Routing Architecture Skill
---

# Network Exposure and Routing Architecture Skill

**Context**: This homelab cluster utilizes a strict separation of network edge boundaries. It employs MetalLB (BGP) for Layer 2/3 routing and an NGINX Ingress Controller for Layer 7 HTTP/HTTPS proxying. Additionally, `default-deny-all` NetworkPolicies are commonly used to isolate namespaces.

**Rules**:
When an AI agent is configuring new services, deploying helm charts, or troubleshooting connectivity, it must strictly adhere to the following edge isolation rules:

1. **Standard Web Applications (HTTP/HTTPS)**
   - **MUST** be configured as `type: ClusterIP`.
   - **MUST** be exposed exclusively via the NGINX Ingress Controller (`*.cluster.example.org`).
   - **NEVER** use `type: LoadBalancer` for standard web interfaces (e.g., Sonarr, Radarr, Jellyfin) as this bypasses the Ingress controller and wastes MetalLB BGP IPs.

2. **Raw TCP (e.g., SSH) or UDP (e.g., Game Servers & Streaming)**
   - **CAN** be configured as `type: LoadBalancer`.
   - NGINX Ingress does not natively route raw UDP or non-HTTP TCP without complex ConfigMap passthroughs. Therefore, services like Steam Headless (`steam-headless-svc`), Dev Workspaces (`workspace-ai-orchestrator`), or Sequestered Game Servers (`factorio-svc`, `satisfactory-svc`) are granted dedicated BGP IPs via MetalLB.
   - **Sequestered Game Servers & LoadBalancer Policy**:
     * **MUST** use `externalTrafficPolicy: Cluster`.
     * *Architectural Invariant (NetFilter BGP Single-Peer Constraint)*: Upstream NetFilter FRR BGP is configured to peer exclusively with `10.20.3.2` (`nodealpha01`). Because game server workloads run on `nodegamma03` (`10.20.3.12`), setting `externalTrafficPolicy: Local` forces `nodealpha01` to withdraw the BGP `/32` route advertisement (no local endpoint on the BGP peer node). This causes NetFilter to route client packets to the default WAN gateway, silently blackholing all inbound connections.
     * *Shared IP Constraint*: When services share a VIP using `metallb.universe.tf/allow-shared-ip: "<shared-key>"` (e.g., `game-servers-shared-ip`), all participating services MUST use `externalTrafficPolicy: Cluster` so all nodes advertise and forward traffic consistently.
     * *Zero-Trust Isolation*: Game servers MUST be quarantined with zero-trust NetworkPolicies that block all outbound traffic to RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `172.20.0.0/16`) while permitting outbound internet access for Steam/EOS authentication and explicit NFS access to OpenZFS (`10.20.3.10`).
     * *Desync Mitigation Rule*: Game client desyncs during heavy autosaves are caused by game engine serialization stalls and client bandwidth limits, NOT by Calico overlay network hops. Desyncs must be resolved at the application layer via timeout tuning (e.g., `TIMEOUT: "60"` in container env) and Engine rate limits (`ConfiguredInternetSpeed=1048576`, `MaxClientRate=1048576`), NEVER by setting `externalTrafficPolicy: Local`.

3. **Isolated / Highly Privileged Services**
   - **MUST NOT** be exposed via `LoadBalancer` or `hostNetwork`.
   - Services like internal dashboards or desktop streaming (e.g., Vesktop) should remain entirely isolated. Access them via `kubectl port-forward` or dedicated Tailscale sidecars.
   - *Note on VPN Posture*: Even when using Tailscale sidecars for secure ingress, remember that the encrypted Tailscale traffic physically traverses the NetFilter edge firewall. Ensure NetFilter state/firewall rules are not blocking UDP hole-punching for the Tailscale nodes.

4. **The `hostNetwork: true` Anti-Pattern**
   - **NEVER** use `hostNetwork: true` for application workloads.
   - Placing a pod on the host network breaks Kubernetes encapsulation. It causes the pod's traffic to originate from the Node IP, which will frequently be blocked by intra-cluster `NetworkPolicies` (like `default-deny-all`), breaking communication with other pods on the cluster network (e.g., breaking "Play On" discovery).
   - Only critical cluster networking daemons (like CNI plugins or the ingress controller itself) should ever use `hostNetwork: true`.

**Verification**:
To ensure these rules are followed, the cluster runs an automated test suite (`tests/e2e-golden-path/test_network_exposure.py`) which acts as a regression guard. It will fail if any service uses `type: LoadBalancer` unless it is explicitly on the approved whitelist.

5. **Zero-Trust Network Policies (Default Deny)**
   - **Rule**: Agents must assume every namespace has a `default-deny-ingress` NetworkPolicy that blocks all incoming traffic to pods by default.
   - **Rule**: When deploying an application that requires external web access (via Nginx), the agent **must** add the `networking/allow-ingress: "true"` label to the Pod template.
   - **Rule**: When deploying an application that exports Prometheus metrics, the agent **must** add the `networking/allow-prometheus: "true"` label to the Pod template.
   - **Rule**: Agents must not disable or delete `default-deny` policies to fix connectivity issues. They must write explicit `allow` policies or use the standard labels mentioned above.

6. **Envoy Gateway OIDC Callback Loops (`extAuth`), Hostname Precedence & Port-80 `Secure` Cookie Shadowing**
   - **Rule**: When configuring an Envoy Gateway `SecurityPolicy` to enforce `extAuth` (e.g., Authentik SSO), you **MUST NEVER** target the entire `Gateway` resource if the authentication callback route (e.g., `/outpost.goauthentik.io/callback`) is hosted on that same Gateway.
   - **Rule (Gateway API Hostname Precedence for `/outpost.goauthentik.io`)**: Every `HTTPRoute` that routes `/outpost.goauthentik.io` directly to `authentik-server` (e.g., `portal-authentik-outpost-route` and `authentik-outpost-route` in `media`, `defectdojo-outpost-route` in `security`) **MUST** explicitly list the exact `spec.hostnames` of all SSO-protected routes (`internal.cluster.example.org`, `media.internal.cluster.example.org`, `sonarr.cluster.example.org`, `radarr.cluster.example.org`, `prowlarr.cluster.example.org`, `qbittorrent.cluster.example.org`, `nzbget.cluster.example.org`, `discord-stream.cluster.example.org`). In the Kubernetes Gateway API specification, exact hostname match (`internal.cluster.example.org`) ALWAYS takes precedence over path length (`/outpost.goauthentik.io` vs `/`) if the outpost route omits `spec.hostnames`—which shadows `/outpost.goauthentik.io/callback` behind `extAuth` and causes `HTTP 400 ext_authz_denied`.
   - **Rule (Port-80 HTTP-to-HTTPS `301` Redirect & `Secure` Cookie Preservation)**: Every SSO-protected `HTTPRoute` (`bgp-portal-route`, `media-portal-route`, `sonarr-route`, etc.) **MUST** set `sectionName: https` on `parentRefs` AND `portal-http-to-https-redirect` (`sectionName: http`) must cover exact hostnames + `*.internal.cluster.example.org` and `*.security.cluster.example.org`. Otherwise, typing `internal.cluster.example.org` in a browser starts on plaintext `http://` (`:80`), where `extAuth` attempts to set a `Secure` `authentik_proxy_*` cookie over `http://`; modern browsers reject `Secure` cookies over `http://`, causing `/outpost.goauthentik.io/callback` to fail with `HTTP 400` (`auth callback without a valid session cookie`).
   - **Verification Canary**: Run `python scripts/monitoring/live_endpoint_and_route_health_matrix.py --probe-live` (and `python -m unittest tests.test_live_endpoint_and_route_health_matrix -v`) to verify all 16 domain canaries across `VLAN 30`, `VLAN 40` (Living Room + Office), and `VLAN 50` (Upstairs), including HTTP `301` redirects, HTTPS readiness, and `/outpost.goauthentik.io/ping` (`204 No Content`).

7. **Public Game Server Ingress & Split-Horizon Dynamic DNS (`edgegateway.wan.example.org`)**
   - **Rule**: Game servers requiring access from external internet players (Satisfactory, Factorio, Minecraft) are canonically addressed via `edgegateway.wan.example.org` (resolving externally to the dynamic public WAN IP).
   - **Rule**: Split-horizon DNS MUST be preserved: NetFilter Unbound overrides `edgegateway.wan.example.org` directly to the MetalLB VIP `172.20.1.212` for local LAN clients, while public DNS resolvers (`203.0.113.1` / `203.0.113.1`) resolve it to the WAN gateway for external players.
   - **Rule**: External game server exposure MUST NEVER bypass MetalLB or use `hostNetwork`. WAN traffic MUST be forwarded through NetFilter NAT port forwarding to the designated MetalLB VIP with `externalTrafficPolicy: Cluster`.

