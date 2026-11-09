---
name: self_signed_certs
description: Self-Signed Certificate Security Skill
---

# Self-Signed Certificate Security Skill

**Context**: When interacting with internal homelab services (like `gitlab.cluster.example.org`) from within a Dev Container or other Linux environment, AI agents may encounter the following error:
`SSL certificate problem: unable to get local issuer certificate`.

**Rule**: 
1. **NEVER** use `git config --global http.sslVerify false` or disable SSL checks globally to bypass the issue. This is a severe security risk that trains the agent to bypass encryption checks.
2. **ALWAYS** fetch and install the server's public certificate into the system trust store instead.

**Implementation for Debian/Ubuntu environments**:
To properly trust the self-signed certificate of a homelab server, execute the following commands as `root`:

```bash
# 1. Fetch the certificate from the server and save it to the system CA directory
echo -n | openssl s_client -showcerts -connect <hostname>:443 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /usr/local/share/ca-certificates/<hostname>.crt

# 2. Ensure line endings are correct (CRLF can break the certificate parser and cause update-ca-certificates to silently ignore it)
sed -i 's/\r$//' /usr/local/share/ca-certificates/<hostname>.crt

# 3. Update the CA trust store
update-ca-certificates
```

This skill ensures that agents properly manage internal security rather than circumventing it.

**Implementation for Kubernetes Java Applications (PKIX path building failed)**:
When Java applications (e.g. Kafka-UI, Keycloak) reject a cluster's internal certificate authority (like NetFilter) with `PKIX path building failed`, they do not read `/etc/ssl/certs` by default. Instead:
1. Ensure `trust-manager` is deployed to synchronize the cluster CA into a `ConfigMap` across all namespaces.
2. Mount the CA `ConfigMap` to the pod.
3. Use an `initContainer` to run `keytool -import -noprompt -keystore /tmp/truststore.jks -storepass changeit -file /etc/ssl/certs/ca.crt`.
4. Pass the truststore to the main application via `JAVA_OPTS=-Djavax.net.ssl.trustStore=/tmp/truststore.jks -Djavax.net.ssl.trustStorePassword=changeit`.
