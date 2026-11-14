---
name: oidc_rbac
description: AI SKILL PLAYBOOK - Keycloak OIDC Integration & Native RBAC Mapping
---

# AI SKILL PLAYBOOK: Keycloak OIDC Integration & Native RBAC Mapping

> **AI AGENT CONTEXT:** 
> This document is an executable "Skill" playbook. If the user asks you to "Integrate SSO", "Add Keycloak Authentication", or "Implement Native RBAC" for any application in the cluster (e.g., Grafana, ArgoCD, Proxmox), follow these generalized steps. Do not attempt to use local databases, SQLite hacks, or scripted "stars" for RBAC. Always enforce Single Sign-On (SSO) with OpenID Connect (OIDC).

---

## 🎯 Objective
To completely replace an application's native, local user authentication with centralized Keycloak SSO, and to automatically assign application permissions based on the user's LLDAP group.

## 🛠️ Step 1: Provision the OIDC Client in Keycloak
Because Keycloak configuration is currently manual (until we deploy the Keycloak Terraform Provider), the **Human Operator** must perform this step:
1. Log into the Keycloak Admin Console (`https://auth.cluster.example.org`).
2. Select the appropriate Realm (e.g., `HomeLab`).
3. Navigate to **Clients -> Create client**.
   - **Client type:** `OpenID Connect`
   - **Client ID:** `my-app-name` (e.g., `grafana` or `argocd`)
4. Configure the Client Settings:
   - **Client authentication:** `ON` (This enforces a strict Client Secret).
   - **Valid redirect URIs:** `https://my-app.cluster.example.org/login/generic_oauth` (Check the target application's documentation for the exact callback path).
   - **Web origins:** `+`
5. Navigate to the **Credentials** tab and copy the `Client secret`.

## 🔐 Step 2: Securely Inject the Secret into Kubernetes
**AI Agents:** Never hardcode the `Client secret` into `values.yaml` or Git repositories.
1. Create a Kubernetes Secret in the target application's namespace:
   ```bash
   kubectl create secret generic my-app-oidc-secret \
     --namespace my-namespace \
     --from-literal=client-id="my-app-name" \
     --from-literal=client-secret="<copied_secret_from_keycloak>"
   ```
2. Reference this secret in the GitOps Helm manifests (using `envFrom` or secret references).

## ⚙️ Step 3: Configure the Target Application's Helm Values
Inject the standard Keycloak OpenID endpoints into the application's configuration. Every app's `values.yaml` is different, but they all require these core OIDC parameters:

```yaml
# Generic Example (Mapping OIDC to an App)
auth:
  generic_oauth:
    enabled: true
    name: "Keycloak SSO"
    client_id: $OIDC_CLIENT_ID          # Injected from Secret
    client_secret: $OIDC_CLIENT_SECRET  # Injected from Secret
    scopes: "openid email profile roles"
    
    # Standard Keycloak Endpoints (Replace 'HomeLab' with your Realm)
    auth_url: "https://auth.cluster.example.org/realms/HomeLab/protocol/openid-connect/auth"
    token_url: "https://auth.cluster.example.org/realms/HomeLab/protocol/openid-connect/token"
    api_url: "https://auth.cluster.example.org/realms/HomeLab/protocol/openid-connect/userinfo"
```

## 🧠 Step 4: Map Roles Dynamically (The JMESPath Engine)
To prevent basic users from getting administrative access, we must map Keycloak/LLDAP groups directly to the application's internal roles.

When a user logs in, Keycloak passes their groups in the `roles` JSON array. AI Agents must configure the target application to parse this array (usually via `role_attribute_path` using **JMESPath** syntax).

**Example mapping logic:**
- *If the user is in the `admin` LLDAP group, make them an `Admin`.*
- *If they are in `family`, make them a `Viewer`.*

```yaml
# Example JMESPath mapping for Grafana
role_attribute_path: "contains(roles[*], 'admin') && 'Admin' || contains(roles[*], 'family') && 'Viewer' || 'Viewer'"
```

## 🚀 Step 5: Test the Integration
**AI Agents:** After pushing the GitOps changes, you must physically verify the security perimeter:
1. Ensure the login page successfully redirects to `https://auth.cluster.example.org`.
2. Confirm the application receives the callback and logs the user in.
3. Validate that a non-admin LLDAP user is successfully demoted to a `Viewer` or completely blocked from accessing the application (`403 Forbidden`).
