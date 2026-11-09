---
name: authentik_configuration
description: Instructions and UI workflows for configuring Authentik Providers, Applications, and Outposts.
---

# Authentik Configuration & UI Workflows

This skill documents the exact UI workflows required to configure Authentik, as the UI heavily favors a **Provider-first** creation flow (specifically in version 2026.5+). 

When instructing users to create new Integrations (like OIDC or LDAP for an app), you MUST use the Provider-first flow, as the generic "New Application Wizard" often fails due to unique constraint bugs when applications are created alongside providers.

## The "Provider-First" Creation Workflow

When setting up a new application in Authentik (e.g., ArgoCD, Grafana, GitLab), always instruct the user to follow these exact steps:

### 1. Create the Provider First
1. Navigate to **Applications -> Providers** in the left-hand menu.
2. Click **New Provider** (Do NOT use a wizard if prompted).
3. Select the appropriate Provider type (e.g., `OAuth2/OpenID Provider`).
4. Fill in the required details:
   - **Name**: e.g., `argocd-provider`
   - **Client Type**: `Confidential`
   - **Client ID**: e.g., `argocd` (Crucial: do not leave as random string)
   - **Authorization Flow**: Must be explicitly selected (e.g., `default-provider-authorization-implicit-consent`).
   - **Redirect URIs**: Enter the exact callback URL.
5. Expand **Advanced protocol settings** to select required scopes (`openid`, `email`, `profile`). Note: `groups` scope may require custom mapping if not present by default.
6. Click **Finish**.

### 2. Create the Associated Application
Because of the UI layout, the easiest way to link an application is directly from the Provider's overview page:
1. Stay in **Applications -> Providers** and click directly on the title of the provider you just created (e.g., `argocd-provider`).
2. On the Provider's Overview page, look for the **"Assigned to application"** section.
3. Click the **New Application** button located there.
4. Fill in the Application details:
   - **Name**: e.g., `ArgoCD`
   - **Slug**: e.g., `argocd`
5. Click **Create**.

By creating the Application directly from the Provider's overview, the Provider is automatically and perfectly linked, avoiding the wizard's hidden constraint errors.

## Fetching the Client Secret
After the Provider is created, the user MUST copy the generated `Client Secret` to provide to the AI agent for configuring the Kubernetes manifests (e.g., updating `values.yaml`).
1. In the **Providers** list, edit the provider.
2. Click the "eye" icon next to the Client Secret to reveal it.
3. Copy and paste it to the AI agent.

## Critical Bug: Public Suffix List (PSL) Cookie Rejection on `.cluster.example.org`

When configuring Proxy Providers for subdomains on `.cluster.example.org` (e.g., `sonarr.cluster.example.org`), you will encounter a persistent `400 Bad Request: mismatched session ID` error during the OIDC callback if the cookie domain is misconfigured.

**The Cause:** 
Authentik's Proxy Provider defaults to stripping the first subdomain to determine the SSO cookie domain (e.g., yielding `cluster.example.org`). Because `.cluster.example.org` is an official RFC 8375 reserved domain, modern browsers (like Chrome) strictly enforce it via the Public Suffix List (PSL) and will **silently reject** any `Set-Cookie` header attempting to set `Domain=cluster.example.org`. This results in the browser dropping the proxy session cookie, causing Authentik to fail the callback verification.

**The UI Bug & Mitigation:**
Even when the Provider Mode is changed to `Forward auth (single application)` in the UI, Authentik's background sync will often incorrectly persist or infer `cluster.example.org` as the `cookie_domain`. To definitively fix this, you must patch the Postgres database directly:

1. Identify the provider ID in Postgres.
2. Force the cookie domain explicitly via SQL:
   ```bash
   kubectl exec -n iam authentik-postgresql-0 -- env PGPASSWORD="<password>" psql -U authentik -d authentik -c "UPDATE authentik_providers_proxy_proxyprovider SET cookie_domain = 'sonarr.cluster.example.org' WHERE oauth2provider_ptr_id = <id>;"
   ```
3. Immediately restart the `authentik-server` pod (`kubectl rollout restart deployment authentik-server -n iam`) to flush the embedded outpost's cache.

## GitLab & OIDC Provider Sub Mode & Auto-Link Settings

When setting up OIDC Providers for applications like GitLab:
1. **Sub Mode Requirement:**
   - In Authentik **OAuth2 Provider -> Advanced settings**, set `sub_mode` to **`user_username`** (or `user_email`).
   - Standard `hashed_user_id` produces randomized hashes that prevent existing user accounts from matching by username.
2. **JWT Signing Key:**
   - Always assign a valid **Signing Key** (e.g., `authentik Internal JWT Certificate`) to the OAuth2 provider. Leaving it as `None` causes token verification to fail with `invalid_grant`.
3. **GitLab OmniAuth Auto-Link:**
   - In `gitlab-resources.yaml` (`GITLAB_OMNIBUS_CONFIG`), set `gitlab_rails['omniauth_auto_link_user'] = true` to allow automatic linking by email address.

