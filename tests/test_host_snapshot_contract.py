# SPDX-License-Identifier: Apache-2.0
"""Unit tests for OPSCRYER_HOST_SNAPSHOT v1 contract validator, browser listener, and OPSEC."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from urllib.parse import urlsplit

import golden_path_gates
import host_snapshot_contract as contract
import opscryer_browser as browser

REPO_ROOT = Path(__file__).resolve().parent.parent


class HostSnapshotContractPythonTests(unittest.TestCase):
    """Test Python contract validator, provider extensibility, legacy fallback, and secret rejection."""

    def test_valid_v1_snapshot_with_gitlab_kubernetes_aws_and_custom_providers(self) -> None:
        raw = {
            "type": "OPSCRYER_HOST_SNAPSHOT",
            "version": 1,
            "source": "backstage",
            "revision": 4,
            "updatedAt": "2026-01-01T00:00:00.000Z",
            "connected": True,
            "data": {
                "catalogEntities": [
                    {
                        "name": "graph-service",
                        "title": "Graph Service",
                        "kind": "Component",
                        "owner": "group:default/platform",
                        "lifecycle": "production",
                        "system": "observability",
                    }
                ],
                "providers": {
                    "gitlab": {
                        "mergeRequests": [{"title": "feat: add provider schema", "number": 42, "status": "open"}],
                        "starredRepos": [{"name": "platform/opscryer", "stars": "18"}],
                        "pipelines": [{"project": "platform/opscryer", "status": "ok"}],
                    },
                    "kubernetes": {
                        "clusters": [{"name": "prod-east", "status": "Ready"}],
                        "workloads": [{"name": "opscryer-web", "namespace": "ops", "readyReplicas": 2}],
                    },
                    "aws": {
                        "accounts": [{"accountId": "111122223333", "region": "us-east-1"}],
                        "resources": [{"id": "eks-prod-east", "service": "eks", "status": "ACTIVE"}],
                    },
                    "argocd": {
                        "applications": [{"name": "opscryer", "syncStatus": "Synced", "health": "Healthy"}],
                    },
                },
                "mergeRequests": [],
                "starredRepos": [],
                "pipelines": [],
            },
        }

        sanitized = contract.validate_and_sanitize_host_snapshot(
            raw,
            event_origin="https://portal.example.org",
            allowed_origins=["https://portal.example.org"],
        )

        self.assertEqual(sanitized["type"], "OPSCRYER_HOST_SNAPSHOT")
        self.assertEqual(sanitized["version"], 1)
        self.assertEqual(sanitized["source"], "backstage")
        self.assertEqual(sanitized["revision"], 4)
        self.assertTrue(sanitized["connected"])
        self.assertEqual(len(sanitized["data"]["catalogEntities"]), 1)
        self.assertEqual(len(sanitized["data"]["providers"]["gitlab"]["mergeRequests"]), 1)
        self.assertEqual(len(sanitized["data"]["providers"]["kubernetes"]["clusters"]), 1)
        self.assertEqual(len(sanitized["data"]["providers"]["kubernetes"]["workloads"]), 1)
        self.assertEqual(len(sanitized["data"]["providers"]["aws"]["accounts"]), 1)
        self.assertEqual(len(sanitized["data"]["providers"]["aws"]["resources"]), 1)
        self.assertEqual(
            sanitized["data"]["providers"]["argocd"]["applications"][0]["syncStatus"],
            "Synced",
        )
        # Top-level legacy mirrors are populated when empty so both v1 and legacy readers agree
        self.assertEqual(len(sanitized["data"]["mergeRequests"]), 1)
        self.assertEqual(len(sanitized["data"]["starredRepos"]), 1)
        self.assertEqual(len(sanitized["data"]["pipelines"]), 1)

    def test_legacy_unversioned_snapshot_normalizes_into_providers_gitlab(self) -> None:
        legacy = {
            "type": "OPSCRYER_HOST_SNAPSHOT",
            "source": "backstage",
            "revision": 2,
            "updatedAt": "2026-01-01T12:00:00.000Z",
            "connected": False,
            "data": {
                "catalogEntities": [{"name": "central-brain", "kind": "Component"}],
                "mergeRequests": [{"title": "fix: cache header", "number": 7}],
                "starredRepos": [{"name": "platform/brain"}],
                "pipelines": [{"project": "platform/brain", "runs": [{"status": "success"}]}],
            },
        }

        sanitized = contract.validate_and_sanitize_host_snapshot(legacy)
        self.assertEqual(sanitized["version"], 1)
        self.assertEqual(
            sanitized["data"]["providers"]["gitlab"]["mergeRequests"],
            [{"title": "fix: cache header", "number": 7}],
        )
        self.assertEqual(
            sanitized["data"]["providers"]["gitlab"]["starredRepos"],
            [{"name": "platform/brain"}],
        )
        self.assertEqual(
            sanitized["data"]["providers"]["gitlab"]["pipelines"],
            [{"project": "platform/brain", "runs": [{"status": "success"}]}],
        )
        self.assertEqual(sanitized["data"]["mergeRequests"], sanitized["data"]["providers"]["gitlab"]["mergeRequests"])

    def test_rejects_forbidden_secret_and_token_keys_recursively(self) -> None:
        forbidden_keys = (
            "token",
            "access_token",
            "accessToken",
            "refresh_token",
            "refreshToken",
            "authorization",
            "Authorization",
            "cookie",
            "Set-Cookie",
            "secret",
            "clientSecret",
            "password",
            "dbPassword",
            "apiKey",
            "api_key",
            "x-api-key",
            "private_token",
            "privateToken",
            "privateKey",
            "kubeconfig",
            "aws_secret_access_key",
        )
        for bad_key in forbidden_keys:
            with self.subTest(bad_key=bad_key):
                self.assertTrue(contract.is_forbidden_secret_key(bad_key))
                nested_payload = {
                    "type": "OPSCRYER_HOST_SNAPSHOT",
                    "version": 1,
                    "source": "backstage",
                    "revision": 1,
                    "updatedAt": "2026-01-01T00:00:00.000Z",
                    "connected": True,
                    "data": {
                        "catalogEntities": [],
                        "providers": {
                            "gitlab": {
                                "mergeRequests": [{"title": "ok", "meta": {bad_key: "redacted-test-value"}}],
                                "starredRepos": [],
                                "pipelines": [],
                            }
                        },
                    },
                }
                with self.assertRaises(contract.HostSnapshotValidationError) as ctx:
                    contract.validate_and_sanitize_host_snapshot(nested_payload)
                self.assertEqual(ctx.exception.code, "forbidden_secret_key")
                self.assertNotIn("redacted-test-value", str(ctx.exception))

        # Also reject Bearer credential strings placed inside an otherwise benign field name
        bearer_payload = {
            "type": "OPSCRYER_HOST_SNAPSHOT",
            "version": 1,
            "source": "backstage",
            "revision": 1,
            "updatedAt": "2026-01-01T00:00:00.000Z",
            "connected": True,
            "data": {
                "catalogEntities": [{"name": "svc", "kind": "Component", "note": "Bearer synth-credential-xyz"}],
                "providers": {"gitlab": {"mergeRequests": [], "starredRepos": [], "pipelines": []}},
            },
        }
        with self.assertRaises(contract.HostSnapshotValidationError) as bearer_ctx:
            contract.validate_and_sanitize_host_snapshot(bearer_payload)
        self.assertEqual(bearer_ctx.exception.code, "forbidden_secret_key")

    def test_origin_allowlist_and_envelope_bounds_fail_closed(self) -> None:
        valid_json = json.dumps(
            {
                "type": "OPSCRYER_HOST_SNAPSHOT",
                "version": 1,
                "source": "backstage",
                "revision": 1,
                "updatedAt": "2026-01-01T00:00:00.000Z",
                "connected": True,
                "data": {"catalogEntities": []},
            }
        )

        # Normalization strips default ports and trailing slash, rejects wildcards/null/non-http(s)/paths
        self.assertEqual(contract.normalize_origin("https://portal.example.org:443/"), "https://portal.example.org")
        self.assertEqual(contract.normalize_origin("http://localhost:3000"), "http://localhost:3000")
        for invalid_origin in (
            "",
            "null",
            "*",
            "https://*.example.org",
            "javascript:alert(1)",
            "file:///tmp/index.html",
            "https://user:pass@portal.example.org",
            "https://portal.example.org/subpath",
            "https://portal.example.org?x=1",
        ):
            with self.subTest(invalid_origin=invalid_origin):
                self.assertIsNone(contract.normalize_origin(invalid_origin))
                self.assertFalse(
                    contract.is_trusted_host_origin(
                        invalid_origin,
                        ["https://portal.example.org"],
                    )
                )

        # Empty allowlist fails closed
        self.assertFalse(contract.is_trusted_host_origin("https://portal.example.org", []))
        with self.assertRaises(contract.HostSnapshotValidationError) as untrusted_ctx:
            contract.validate_and_sanitize_host_snapshot(
                valid_json,
                event_origin="https://untrusted.example.com",
                allowed_origins=["https://portal.example.org"],
            )
        self.assertEqual(untrusted_ctx.exception.code, "untrusted_origin")

        # Unsupported version values fail closed
        for bad_ver in (0, 2, "1", True, -1):
            with self.subTest(bad_ver=bad_ver):
                res = contract.inspect_host_snapshot(
                    {
                        "type": "OPSCRYER_HOST_SNAPSHOT",
                        "version": bad_ver,
                        "source": "backstage",
                        "data": {"catalogEntities": []},
                    }
                )
                self.assertFalse(res["valid"])
                self.assertEqual(res["error_code"], "unsupported_version")

        # Payload byte bound fails closed
        oversized = contract.inspect_host_snapshot(valid_json, max_bytes=32)
        self.assertFalse(oversized["valid"])
        self.assertEqual(oversized["error_code"], "payload_too_large")

        # Prototype pollution key rejected
        proto_res = contract.inspect_host_snapshot(
            '{"type":"OPSCRYER_HOST_SNAPSHOT","version":1,"source":"backstage","data":{"catalogEntities":[],"__proto__":{"polluted":true}}}'
        )
        self.assertFalse(proto_res["valid"])
        self.assertEqual(proto_res["error_code"], "forbidden_prototype_key")


class HostSnapshotBrowserListenerTests(unittest.TestCase):
    """Execute shipped index.html JS in Node.js to verify origin checks, secret rejection, and CustomEvent."""

    @unittest.skipUnless(shutil.which("node"), "Node.js is required to execute browser JavaScript")
    def test_index_html_postmessage_listener_enforces_origins_sanitizes_and_emits_event(self) -> None:
        html = browser.render_standalone_browser_html()
        self.assertEqual(html, (REPO_ROOT / "index.html").read_text(encoding="utf-8"))
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]

        harness = r"""
const assert = require('node:assert/strict');
class Element {
  constructor() {
    this.children = [];
    this.style = {display: 'none'};
    this.textContent = '';
    this.listeners = {};
    this.dataset = {};
    this._classes = new Set();
    this.classList = {
      toggle: (name, force) => {
        const next = force === undefined ? !this._classes.has(name) : Boolean(force);
        if (next) this._classes.add(name);
        else this._classes.delete(name);
        return next;
      },
      contains: name => this._classes.has(name),
      add: name => this._classes.add(name),
      remove: name => this._classes.delete(name),
    };
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute() {}
}
const elements = new Map();
global.document = {
  listeners: {},
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  },
  createElement() { return new Element(); },
  addEventListener(type, callback) { this.listeners[type] = callback; }
};
const windowListeners = {};
const dispatchedEvents = [];
const parentPostedMessages = [];
global.CustomEvent = class CustomEvent {
  constructor(type, init) {
    this.type = type;
    this.detail = init ? init.detail : undefined;
  }
};
global.window = {
  location: {
    origin: 'http://localhost:8088',
    hostname: '',
    search: '?mode=mock&hostOrigin=https%3A%2F%2Fportal.example.org',
  },
  parent: {
    postMessage(msg, targetOrigin) {
      parentPostedMessages.push({msg, targetOrigin});
    },
  },
  __OPSCRYER_HOST_ALLOWED_ORIGINS__: ['https://runtime.example.org'],
  addEventListener(type, cb) {
    if (!windowListeners[type]) windowListeners[type] = [];
    windowListeners[type].push(cb);
  },
  dispatchEvent(evt) {
    dispatchedEvents.push(evt);
    (windowListeners[evt.type] || []).forEach(fn => fn(evt));
    return true;
  },
};
"""
        assertions = r"""
(async () => {
  await new Promise(resolve => setImmediate(resolve));
  const bridge = window.OpsCryerHostSnapshotBridge;
  assert.ok(bridge, 'OpsCryerHostSnapshotBridge must be exposed on window');
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__, null);

  // Ready handshake must be sent only to explicit trusted parent origins, NEVER '*'
  assert.ok(parentPostedMessages.length >= 1);
  parentPostedMessages.forEach(call => {
    assert.notEqual(call.targetOrigin, '*');
    assert.equal(call.msg.type, 'OPSCRYER_READY');
    assert.equal(call.msg.version, 1);
  });
  const readyTargets = parentPostedMessages.map(c => c.targetOrigin);
  assert.ok(readyTargets.includes('https://portal.example.org'));
  assert.ok(readyTargets.includes('https://runtime.example.org'));

  const emitMessage = (origin, data) => {
    (windowListeners['message'] || []).forEach(fn => fn({origin, data}));
  };

  // 1. Untrusted origin must be rejected fail-closed
  emitMessage('https://attacker.example.com', {
    type: 'OPSCRYER_HOST_SNAPSHOT',
    version: 1,
    source: 'backstage',
    revision: 1,
    updatedAt: '2026-01-01T00:00:00.000Z',
    connected: true,
    data: {catalogEntities: [{name: 'should-not-accept', kind: 'Component'}]},
  });
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__, null);
  assert.equal(dispatchedEvents.length, 0);

  // 2. Null / opaque origin must be rejected fail-closed
  emitMessage('null', {
    type: 'OPSCRYER_HOST_SNAPSHOT',
    version: 1,
    source: 'backstage',
    revision: 1,
    updatedAt: '2026-01-01T00:00:00.000Z',
    connected: true,
    data: {catalogEntities: []},
  });
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__, null);

  // 3. Trusted query-param origin with v1 providers (gitlab + kubernetes + aws) succeeds
  emitMessage('https://portal.example.org', {
    type: 'OPSCRYER_HOST_SNAPSHOT',
    version: 1,
    source: 'backstage',
    revision: 5,
    updatedAt: '2026-01-01T00:00:00.000Z',
    connected: true,
    data: {
      catalogEntities: [{name: 'svc-alpha', kind: 'Component'}],
      providers: {
        gitlab: {
          mergeRequests: [{title: 'feat: v1 contract', number: 11}],
          starredRepos: [{name: 'org/svc-alpha'}],
          pipelines: [{project: 'org/svc-alpha', status: 'ok'}],
        },
        kubernetes: {clusters: [{name: 'cluster-a'}], workloads: []},
        aws: {accounts: [{accountId: '123456789012'}], resources: []},
      },
      mergeRequests: [],
      starredRepos: [],
      pipelines: [],
    },
  });

  assert.ok(window.__OPSCRYER_HOST_SNAPSHOT__);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.version, 1);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.revision, 5);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.data.providers.gitlab.mergeRequests.length, 1);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.data.providers.kubernetes.clusters.length, 1);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.data.providers.aws.accounts.length, 1);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.data.mergeRequests.length, 1);
  assert.equal(dispatchedEvents.length, 1);
  assert.equal(dispatchedEvents[0].type, 'opscryer:host-snapshot');
  const badge = document.getElementById('host-snapshot-badge');
  assert.equal(badge.style.display, 'inline-flex');
  assert.ok(badge.textContent.includes('1 entities'));
  assert.ok(badge.textContent.includes('1 MRs'));

  // 4. Payload from trusted origin containing ANY forbidden token/secret key must fail closed
  //    and leave the previous valid snapshot untouched!
  for (const badKey of ['token', 'accessToken', 'access_token', 'private_token', 'authorization', 'cookie', 'secret', 'password', 'apiKey']) {
    emitMessage('https://portal.example.org', {
      type: 'OPSCRYER_HOST_SNAPSHOT',
      version: 1,
      source: 'backstage',
      revision: 99,
      updatedAt: '2026-01-01T00:05:00.000Z',
      connected: true,
      data: {
        catalogEntities: [{name: 'poisoned', kind: 'Component', extra: {[badKey]: 'must-reject'}}],
        providers: {gitlab: {mergeRequests: [], starredRepos: [], pipelines: []}},
      },
    });
    assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.revision, 5, 'Must reject key: ' + badKey);
    assert.equal(dispatchedEvents.length, 1);
  }

  // 5. Legacy top-level snapshot from runtime-configured origin normalizes into data.providers.gitlab
  emitMessage('https://runtime.example.org', {
    type: 'OPSCRYER_HOST_SNAPSHOT',
    source: 'backstage',
    revision: 6,
    updatedAt: '2026-01-01T01:00:00.000Z',
    connected: false,
    data: {
      catalogEntities: [{name: 'svc-alpha', kind: 'Component'}, {name: 'svc-beta', kind: 'Component'}],
      mergeRequests: [{title: 'mr-1'}, {title: 'mr-2'}],
      starredRepos: [],
      pipelines: [],
    },
  });
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.version, 1);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.revision, 6);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.data.providers.gitlab.mergeRequests.length, 2);
  assert.equal(dispatchedEvents.length, 2);

  // 6. Same-origin message also succeeds
  emitMessage('http://localhost:8088', {
    type: 'OPSCRYER_HOST_SNAPSHOT',
    version: 1,
    source: 'same-origin-shell',
    revision: 7,
    updatedAt: '2026-01-01T02:00:00.000Z',
    connected: true,
    data: {catalogEntities: []},
  });
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.revision, 7);
  assert.equal(window.__OPSCRYER_HOST_SNAPSHOT__.source, 'same-origin-shell');
})().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
"""
        proc = subprocess.run(
            [shutil.which("node"), "-"],
            input=harness + script + assertions,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)


class HostSnapshotPublicOpsecTests(unittest.TestCase):
    """Ensure contract documentation, validator, and browser HTML contain zero internal leaks."""

    def test_zero_opsec_violations_and_example_only_domains(self) -> None:
        target_files = (
            REPO_ROOT / "docs" / "HOST_SNAPSHOT_CONTRACT.md",
            REPO_ROOT / "host_snapshot_contract.py",
            Path(__file__).resolve(),
        )
        url_re = re.compile(r"https?://[^\s\"'`<>)\],;%]+")
        allowed_Suffixes = (".example.org", ".example.com", ".example.net", ".example")
        allowed_exact = {"example.org", "example.com", "example.net", "localhost", "127.0.0.1"}

        for path in target_files:
            raw = path.read_bytes()
            self.assertNotIn(b"\r\n", raw, f"CRLF line endings found in {path.name}")
            self.assertEqual(
                golden_path_gates._opsec_count(raw),
                0,
                f"OPSEC violation detected in {path.name}",
            )
            text = raw.decode("utf-8")
            for match in url_re.findall(text):
                if "*" in match:
                    continue
                host = (urlsplit(match).hostname or "").lower()
                if not host:
                    continue
                self.assertTrue(
                    host in allowed_exact or host.endswith(allowed_Suffixes),
                    f"Non-generic host '{host}' found in {path.name}",
                )


if __name__ == "__main__":
    unittest.main()
