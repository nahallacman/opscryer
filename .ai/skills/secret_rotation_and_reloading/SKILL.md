---
name: secret_rotation_and_reloading
description: Zero-Downtime Secret Rotation & Live Reloading
---

# AI Skill: Zero-Downtime Secret Rotation & Live Reloading

## Goal
To guarantee that any Kubernetes secrets deployed by an AI agent are inherently capable of zero-downtime rotation, meaning that when a secret is updated in the central OpenBao vault, the changes are automatically propagated to running application pods without manual intervention.

## Context
When an `ExternalSecret` pulls a new password from Vault and updates the native Kubernetes `Secret`, running Pods that mount this secret as an environment variable **do not** automatically pick up the new value. The Pod must be restarted. If Pods are not automatically restarted, the application will continue using the old revoked credentials and eventually fail.

## Mandatory Rules for AI Agents

1. **Mandatory Reloader Annotations:**
   Whenever you deploy or modify a `Deployment`, `StatefulSet`, or `DaemonSet` that relies on an `ExternalSecret` (or any Kubernetes `ConfigMap`/`Secret`), you **must** include the Stakater Reloader annotations in the workload's metadata to ensure it rolling-restarts gracefully when the secret changes.
   
   **CORRECT IMPLEMENTATION:**
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: my-app
     annotations:
       reloader.stakater.com/auto: "true" # Forces a rolling restart if any mounted configmap/secret changes
   spec:
     template:
       # ...
   ```

2. **File Mounts vs. Environment Variables:**
   If the target application supports native hot-reloading (e.g., watching a file for changes using `fsnotify` or `inotify`), you **must** mount the `Secret` as a volume instead of passing it as an environment variable. 
   - Kubernetes automatically updates mounted `Secret` volumes within ~60 seconds of a change. 
   - If the app supports hot-reloading, do **NOT** use the Reloader annotation, as a restart is unnecessary.

3. **ExternalSecret Configuration:**
   Always set a logical `refreshInterval` on the `ExternalSecret` definition so the External Secrets Operator actively polls OpenBao for rotation changes.
   ```yaml
   apiVersion: external-secrets.io/v1beta1
   kind: ExternalSecret
   spec:
     refreshInterval: "15m" # Mandatory for rotation detection
   ```

4. **Testing Rotation:**
   When testing a secret migration, explicitly verify that changing the underlying value in Vault correctly triggers a rolling restart of the application pods. Do not consider a migration "done" until the rotation pipeline is proven.

5. **External Secrets Operator (`v2.14.0`) Reconciler Flags (`kube-system/external-secrets`):**
   When upgrading or configuring `external-secrets` (`v2.14.0+`) in clusters where `ClusterExternalSecret` CRDs only serve `v1beta1` (or `PushSecret` / `ClusterPushSecret` are unused), `infrastructure/external-secrets/values.yaml` **MUST** set:
   ```yaml
   extraArgs:
     enable-cluster-external-secret-reconciler: "false"
     enable-cluster-push-secret-reconciler: "false"
     enable-push-secret-reconciler: "false"
   ```
   Without these flags, `external-secrets` `v2.14.0` attempts to watch `*v1.ClusterExternalSecret`, times out after 60s (`failed to wait for clusterexternalsecret caches to sync`), and enters `CrashLoopBackOff`.
