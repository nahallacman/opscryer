# SPDX-License-Identifier: Apache-2.0
"""Dynamic sensitive fixtures keep source files and test output OPSEC-clean."""

from copy import deepcopy
from ipaddress import IPv4Address
import json
import unittest
from time import perf_counter
from unittest.mock import patch

import telemetry_sanitizer as sanitizer

from telemetry_sanitizer import (
    build_two_act_hackathon_demo_plan,
    sanitize_live_home_telemetry_for_demo as sanitize,
)
from tests.test_opscryer_public_smoke import ROOT, opsec_findings, scan_public_files


def reference_sanitize_text(text):
    """Original unconditional regex pipeline, independent of cache/fast paths."""
    def address(match):
        try:
            ip = IPv4Address(match[0])
        except ValueError:
            return match[0]
        return "203.0.113.1" if ip.is_global and not ip.is_multicast else match[0]

    text = sanitizer._ASSIGNMENT.sub(lambda m: m[1] + m[2] + "[REDACTED]", text)
    text = sanitizer._PEM.sub("[REDACTED]", text)
    text = sanitizer._BEARER.sub("Bearer [REDACTED]", text)
    text = sanitizer._JWT.sub("[REDACTED]", text)
    text = sanitizer._TOKEN.sub("[REDACTED]", text)
    text = sanitizer._GMAIL.sub("[REDACTED]", text)
    text = sanitizer._TAILNET.sub(lambda m: m[1] + "tail-redacted.ts.net", text)
    text = sanitizer._MAC.sub(
        lambda m: m[2].join((m[1], m[3], m[4], "XX", "XX", "XX")), text)
    text = sanitizer._CISCO_MAC.sub(
        lambda m: ":".join((m[1][:2], m[1][2:], m[2], "XX", "XX", "XX")), text)
    return sanitizer._IPV4.sub(address, text)


class TelemetrySanitizerTests(unittest.TestCase):
    def test_fast_paths_match_original_pipeline_including_marker_free_credentials(self):
        samples = ["", "a", "abc", "node", "node123", "identifier", "alpha beta",
                   "Bearer synthetic", "Bearer\tsynthetic", "Bearer\u2003synthetic",
                   "password=synthetic", "token:synthetic", "eyJdemo.payload.signature",
                   "person@" + "gmail.com", "gpu.tailabc.ts.net", "gpu.cluster.example.org",
                   ".".join(("abcd", "efab", "cdef")), "10.0.0.1", "999.999.999.999"]
        samples += [prefix + "a" for prefix in sanitizer._PREFIXES]
        samples += [sep.join(["aA", "bB", "cC", "dd", "ee", "ff"])
                    for sep in (":", "-")]
        for sample in samples:
            # Compare booleans so a regression never prints an unsanitized fixture.
            self.assertTrue(sanitizer._sanitize_text(sample) == reference_sanitize_text(sample))
        for sample in ("node123", "plain", "a", "???"):
            with patch.object(sanitizer, "_ASSIGNMENT") as heavy:
                self.assertEqual(sanitizer._sanitize_text.__wrapped__(sample), sample)
                heavy.sub.assert_not_called()

    def test_live_snapshot_identical_fresh_and_faster_than_original_pipeline(self):
        payload = json.loads((ROOT / "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        snapshot = deepcopy(payload)
        self.assertEqual(len(payload["nodes"]), payload["node_count"])
        self.assertGreater(len(payload["nodes"]), 50)
        with patch.object(sanitizer, "_sanitize_text", reference_sanitize_text):
            started = perf_counter()
            expected = sanitize(payload)
            baseline = perf_counter() - started
        sanitizer._sanitize_text.cache_clear()
        started = perf_counter()
        cold = sanitize(payload)
        cold_time = perf_counter() - started
        self.assertEqual(cold, expected)
        started = perf_counter()
        for _ in range(5):
            result = sanitize(payload)
        warm_time = (perf_counter() - started) / 5
        self.assertLess(warm_time, baseline * 0.7)
        self.assertLess(cold_time, 1.0)
        self.assertEqual(result, expected)
        self.assertEqual(payload, snapshot)
        result["nodes"][0]["drilldown_children"].append("changed")
        result["nodes"].clear()
        self.assertEqual(payload, snapshot)
        self.assertEqual(sanitize(payload), expected)
        self.assertLessEqual(sanitizer._sanitize_text.cache_info().currsize, 8192)

    def test_preserves_allowed_networks_and_nonsecret_scalars(self):
        allowed = ["10.0.0.0", "10.255.255.255", "172.20.0.0", "172.20.255.255",
                   "172.16.0.0", "172.31.255.255", "127.0.0.1",
                   "100.64.0.0", "100.127.255.255", "gpu.cluster.example.org",
                   "nested.switch.cluster.example.org", "203.0.113.1", "999.999.999.999"]
        payload = {"samples": allowed, "values": [None, True, False, 0, 1.5]}
        self.assertEqual(sanitize(payload), payload)

    def test_public_addresses_in_urls_ports_cidr_keys_and_punctuation(self):
        addresses = [str(IPv4Address(number)) for number in
                     (0x08080808, 0x01010101, 0xAC0FFFFF, 0xAC200000,
                      0x64400000 - 1, 0x647FFFFF + 1)]
        for index, address in enumerate(addresses):
            with self.subTest(case=index):
                payload = {address: [f"https://{address}:443/path", f"{address}/24",
                                     f"({address}).", f"wan={address}"]}
                expected = {"203.0.113.1": ["https://203.0.113.1:443/path",
                                          "203.0.113.1/24", "(203.0.113.1).",
                                          "wan=203.0.113.1"]}
                self.assertEqual(sanitize(payload), expected)

    def test_masks_mac_suffixes_with_matching_separator(self):
        octets = ["aA", "bB", "cC", "01", "02", "03"]
        for separator in (":", "-"):
            raw = separator.join(octets)
            expected = separator.join(octets[:3] + ["XX"] * 3)
            self.assertEqual(sanitize("device=" + raw + "."), "device=" + expected + ".")
        dotted = ".".join(("aAbB", "cC01", "0203"))
        self.assertEqual(sanitize(dotted), "aA:bB:cC:XX:XX:XX")

    def test_redacts_credentials_and_personal_gmail(self):
        prefixes = ["gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-",
                    "github" + "_pat_"]
        for index, prefix in enumerate(prefixes):
            with self.subTest(case=index):
                self.assertEqual(sanitize(prefix + "synthetic_test_value"), "[REDACTED]")
        for domain in ("gmail.com", "GMAIL.COM", "googlemail.com"):
            mail = "demo.person+test" + "@" + domain
            self.assertEqual(sanitize("mailto:" + mail), "mailto:[REDACTED]")
            self.assertEqual(sanitize({mail: "owner"}), {"[REDACTED]": "owner"})
        self.assertEqual(sanitize("help@example.org"), "help@example.org")
        self.assertEqual(sanitize("Bearer synthetic.value"), "Bearer [REDACTED]")
        self.assertEqual(sanitize("eyJdemo.payload.signature"), "[REDACTED]")
        self.assertEqual(sanitize('password="synthetic value" token=synthetic'),
                         "password=[REDACTED] token=[REDACTED]")
        for key in ("password", "API_KEY", "access_token", "client-secret", "Authorization"):
            self.assertEqual(sanitize({key: {"value": "synthetic"}}), {key: "[REDACTED]"})

    def test_nested_payload_is_fresh_idempotent_and_opsec_clean(self):
        wan = str(IPv4Address(0x08080808))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        token = "gh" + "p_" + "synthetic_test_value"
        payload = {"events": [{"text": " ".join((wan, mac, token)),
                               "nested": ("gpu.cluster.example.org", {"lan": "10.20.3.1"})}]}
        snapshot = deepcopy(payload)
        result = sanitize(payload)
        # Boolean assertions avoid printing sensitive fixtures on failure.
        self.assertTrue(payload == snapshot, "Input was mutated")
        encoded = json.dumps(result).encode()
        findings = opsec_findings(encoded)
        self.assertEqual(findings, dict.fromkeys(findings, 0))
        self.assertEqual(sanitize(result), result)
        result["events"][0]["nested"][1]["lan"] = "changed"
        self.assertTrue(payload == snapshot, "Output shares mutable input state")

    def test_tailnet_suffixes_in_keys_urls_and_nested_text(self):
        for index, suffix in enumerate(("a1b2", "ABC123", "7")):
            with self.subTest(case=index):
                host = "nested.gpu-node"
                name = host + ".tail" + suffix + ".ts.net"
                clean = host + ".tail-redacted.ts.net"
                payload = {name: [f"https://{name}:443/status", (name + ".",)]}
                snapshot = deepcopy(payload)
                result = sanitize(payload)
                self.assertTrue(result == {clean: [f"https://{clean}:443/status",
                                                   (clean + ".",)]},
                                "Tailnet suffix was not masked")
                self.assertTrue(payload == snapshot, "Input was mutated")
                self.assertEqual(sanitize(result), result)
        for name in ("gpu.cluster.example.org", "gpu.ts.net", "gpu.tail-redacted.ts.net",
                     "gpu.tail.ts.net", "gpu.tailabc.ts.net.example.org"):
            self.assertEqual(sanitize(name), name)
        names = ["gpu.tail" + suffix + ".ts.net" for suffix in ("a1", "b2")]
        with self.assertRaisesRegex(ValueError, "keys collide"):
            sanitize(dict.fromkeys(names, "value"))

    def test_kubernetes_secret_payloads_are_redacted_wholesale(self):
        # Base64-looking strings and arbitrary data keys need object context.
        opaque = "c3lu" + "dGhldGlj"
        for secret_type in ("Opaque", "kubernetes.io/" + "service-account-token"):
            payload = {"items": [{"apiVersion": "v1", "kind": "Secret",
                                  "type": secret_type,
                                  "metadata": {"name": "demo-secret"},
                                  "data": {"session": opaque, "token": opaque},
                                  "stringData": {"session": "synthetic"}}]}
            snapshot = deepcopy(payload)
            expected = deepcopy(payload)
            expected["items"][0].update(data="[REDACTED]", stringData="[REDACTED]")
            result = sanitize(payload)
            self.assertTrue(result == expected, "Secret contents were not redacted")
            self.assertTrue(payload == snapshot, "Input was mutated")
            self.assertEqual(sanitize(result), result)
        for value in (None, 42, [opaque], {"arbitrary": opaque}):
            self.assertTrue(sanitize({"kind": "Secret", "data": value}) ==
                            {"kind": "Secret", "data": "[REDACTED]"})
        ordinary = {"kind": "ConfigMap", "data": {"endpoint": "gpu.cluster.example.org"},
                    "stringData": {"label": "demo"}}
        self.assertEqual(sanitize(ordinary), ordinary)

    def test_service_account_token_fields_and_assignments(self):
        fields = ("token", "tokens", "serviceAccountToken", "service_account_token",
                  "service-account-token", "SERVICE_ACCOUNT_TOKEN", "bearerToken",
                  "bootstrapToken", "id-token")
        for index, field in enumerate(fields):
            with self.subTest(case=index):
                payload = {"kind": "ServiceAccount", "metadata": {"name": "demo"},
                           "secrets": [{"name": "demo-token"}],
                           field: {"opaque": "synthetic"}}
                expected = deepcopy(payload)
                expected[field] = "[REDACTED]"
                self.assertTrue(sanitize(payload) == expected,
                                "ServiceAccount credential was not redacted")
                self.assertEqual(sanitize(field + "=synthetic"), field + "=[REDACTED]")
        request = {"kind": "TokenRequest", "status": {"token": "synthetic"}}
        self.assertEqual(sanitize(request),
                         {"kind": "TokenRequest", "status": {"token": "[REDACTED]"}})

    def test_redacts_pem_private_keys_and_certificates(self):
        rsa = "-----" + "BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----" + "END RSA PRIVATE KEY-----"
        ec = "-----" + "BEGIN EC PRIVATE KEY-----\nMHQC...\n-----" + "END EC PRIVATE KEY-----"
        cert = "-----" + "BEGIN CERTIFICATE-----\nMIID...\n-----" + "END CERTIFICATE-----"
        hdr = "-----" + "BEGIN PRIVATE KEY-----"

        for block in (rsa, ec, cert, hdr):
            self.assertEqual(sanitize(block), "[REDACTED]")
            self.assertEqual(sanitize(f"error: {block} in handshake"), "error: [REDACTED] in handshake")

        for key in ("cert_key", "tls_key", "ssl_key", "ssh_key", "id_rsa", "privkey", "key_pem"):
            self.assertEqual(sanitize({key: "synthetic_key_value"}), {key: "[REDACTED]"})

    def test_changed_sources_are_lf_only(self):
        for name in ("telemetry_sanitizer.py", "tests/test_telemetry_sanitizer.py"):
            self.assertNotIn(b"\r", (ROOT / name).read_bytes())

    def test_unsupported_values_and_key_collisions_fail_without_disclosure(self):
        for value in (object(), b"opaque", {1: "value"}):
            with self.assertRaises(TypeError):
                sanitize(value)
        addresses = [str(IPv4Address(n)) for n in (0x08080808, 0x01010101)]
        with self.assertRaisesRegex(ValueError, "keys collide"):
            sanitize(dict.fromkeys(addresses, "value"))

    def test_demo_plan_has_two_explicit_acts_and_fresh_state(self):
        plan = build_two_act_hackathon_demo_plan()
        first, second = plan["acts"]
        self.assertEqual([act["act"] for act in plan["acts"]], [1, 2])
        self.assertEqual(first["mode"], "OFFLINE_PUBLIC_STANDALONE")
        self.assertIs(first["live_connections"], False)
        self.assertEqual(second["mode"], "SANITIZED_LIVE_HOME_NETWORK")
        self.assertEqual(second["sanitizer"], "sanitize_live_home_telemetry_for_demo")
        self.assertEqual(sanitize(plan), plan)
        findings = opsec_findings(json.dumps(plan).encode())
        self.assertEqual(findings, dict.fromkeys(findings, 0))
        first["steps"].clear()
        self.assertTrue(build_two_act_hackathon_demo_plan()["acts"][0]["steps"])

    def test_public_working_tree_remains_opsec_clean(self):
        findings = scan_public_files(ROOT)
        self.assertEqual(findings, dict.fromkeys(findings, 0))


if __name__ == "__main__":
    unittest.main()
