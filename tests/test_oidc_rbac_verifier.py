# SPDX-License-Identifier: Apache-2.0
"""Fail-closed authorization matrix and observed ingress evidence checks."""

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import oidc_rbac_verifier as verifier


def claims(group="platform-admins", **updates):
    result = {"signature_verified": True, "iss": verifier.TRUSTED_ISSUER,
              "aud": verifier.TRUSTED_AUDIENCE, "sub": "synthetic-subject",
              "exp": 2000, "iat": 900, "groups": [group]}
    result.update(updates)
    return result


def ingress(host="grafana.cluster.example.org", namespace="monitoring", configured=False):
    result = {"kind": "Ingress", "metadata": {"name": "fixture", "namespace": namespace},
              "spec": {"rules": [{"host": host}]}}
    if configured:
        prefix = "nginx.ingress.kubernetes.io/"
        result["metadata"]["annotations"] = {
            prefix + "auth-url": "https://auth.cluster.example.org/outpost.goauthentik.io/auth/nginx",
            prefix + "auth-signin": "https://auth.cluster.example.org/outpost.goauthentik.io/start?rd=$escaped_request_uri"}
        result["spec"]["tls"] = [{"hosts": [host], "secretName": "tls-reference"}]
    return result


def catalog(*resources):
    return {"nodes": [{"resource": r} for r in resources]}


@patch.object(verifier.time, "time", return_value=1000)
class AccessTests(unittest.TestCase):
    def evaluate(self, identity, target="/", data=None):
        return verifier.evaluate_oidc_rbac_access(identity, target,
                                                  catalog() if data is None else data)

    def assertDenied(self, identity, target="/", data=None):
        result = self.evaluate(identity, target, data)
        self.assertIs(result["allowed"], False)
        self.assertEqual(result["status_code"], 403)

    def test_complete_route_group_matrix(self, _clock):
        for route, allowed in verifier.ROUTE_POLICY.items():
            for group in verifier.GROUPS:
                with self.subTest(route=route, group=group):
                    decision = self.evaluate(claims(group), route)
                    self.assertEqual(decision["allowed"], group in allowed)
                    self.assertEqual(decision["status_code"], 200 if group in allowed else 403)
        # Independent expectations protect the intended privilege boundaries.
        self.assertDenied(claims("readonly-viewers"), "/api/v1/live-cluster-ask")
        self.assertDenied(claims("household-gamers"), "/api/v1/live-cluster-health")
        self.assertDenied(claims("sre-operators"), "/admin")
        self.assertTrue(self.evaluate(claims("household-gamers"), "/chat")["allowed"])

    def test_missing_malformed_and_untrusted_claims(self, _clock):
        for identity in (None, {}, [], "raw-token", False):
            self.assertDenied(identity)
        for field in ("signature_verified", "iss", "aud", "sub", "exp", "groups"):
            identity = claims()
            del identity[field]
            self.assertDenied(identity)
        cases = {"signature_verified": [False, 1, "true"],
                 "iss": [None, "https://untrusted.cluster.example.org/", []],
                 "aud": [None, [], ["other"], [verifier.TRUSTED_AUDIENCE, 1]],
                 "sub": [None, "", "  ", []],
                 "exp": [None, True, "2000", 999, 1000, float("nan"), float("inf"), 10**1000],
                 "groups": [None, [], "platform-admins", [1], [["platform-admins"]], [""]]}
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field):
                    self.assertDenied(claims(**{field: value}))
        self.assertDenied(claims("unrecognized-group"))

    def test_temporal_audience_and_multiple_group_validation(self, _clock):
        for field in ("nbf", "iat"):
            for value in (None, True, "900", 1001, float("nan")):
                self.assertDenied(claims(**{field: value}))
        self.assertDenied(claims(aud=[verifier.TRUSTED_AUDIENCE, "other"]))
        self.assertDenied(claims(azp="other"))
        self.assertTrue(self.evaluate(claims(aud=[verifier.TRUSTED_AUDIENCE, "other"],
                                             azp=verifier.TRUSTED_AUDIENCE))["allowed"])
        self.assertTrue(self.evaluate(claims(groups=["unknown", "sre-operators"]),
                                      "/api/v1/live-cluster-ask")["allowed"])

    def test_ingress_namespace_matrix_and_unknown_hosts(self, _clock):
        expectations = {"monitoring": set(verifier.GROUPS[:3]),
                        "gaming": {"platform-admins", "household-gamers"},
                        "media": {"platform-admins", "household-gamers"},
                        "iam": {"platform-admins"},
                        "argocd": set(verifier.GROUPS[:2]),
                        "new-namespace": {"platform-admins"}}
        for namespace, allowed in expectations.items():
            data = catalog(ingress(namespace=namespace))
            for group in verifier.GROUPS:
                for target in ("grafana.cluster.example.org", "https://grafana.cluster.example.org/"):
                    self.assertEqual(self.evaluate(claims(group), target, data)["allowed"],
                                     group in allowed)
        self.assertDenied(claims(), "unknown.cluster.example.org", catalog(ingress()))
        self.assertDenied(claims(), "https://grafana.cluster.example.org/", catalog())
        duplicate = catalog(ingress(), ingress(namespace="iam"))
        self.assertDenied(claims("sre-operators"), "grafana.cluster.example.org", duplicate)

    def test_opscryer_hostname_uses_path_policy(self, _clock):
        data = catalog(ingress("opscryer.cluster.example.org", "dev-envs"))
        self.assertTrue(self.evaluate(claims("household-gamers"),
                                      "https://opscryer.cluster.example.org/chat", data)["allowed"])
        self.assertDenied(claims("readonly-viewers"), "https://opscryer.cluster.example.org/admin", data)
        self.assertDenied(claims(), "https://opscryer.cluster.example.org/unknown", data)
        data["nodes"][0]["resource"]["spec"]["rules"].append({"host": "other.cluster.example.org"})
        self.assertDenied(claims("household-gamers"), "https://other.cluster.example.org/chat", data)

    def test_ambiguous_or_unsupported_targets_deny_admin(self, _clock):
        for target in (None, [], "/unknown", "/admin/child", "//admin", "/%61dmin",
                       "/chat?token=synthetic-sensitive", "/chat#fragment", "/chat/../admin",
                       "https://user@grafana.cluster.example.org", "http://grafana.cluster.example.org",
                       "https://grafana.cluster.example.org:443", "https://grafana.cluster.example.org.evil/",
                       "https://grafana.cluster.example.org/../admin", "https://grafana.cluster.example.org//admin",
                       "https://grafana.cluster.example.org/\n", "*.cluster.example.org", "cluster.example.org"):
            self.assertDenied(claims(), target, catalog(ingress()))

    def test_invalid_catalog_does_not_allow_even_local_routes(self, _clock):
        for data in ({}, {"nodes": [None]}, {"nodes": [{"resource": []}]},
                     catalog({"kind": "Ingress", "metadata": {}, "spec": []})):
            self.assertDenied(claims(), data=data)
        self.assertDenied(claims(), data=Path("does-not-exist.json"))

    def test_no_input_echo_or_mutation(self, _clock):
        identity = claims(sub="synthetic-private-identity", extra="synthetic-sensitive")
        data = catalog(ingress())
        before = deepcopy((identity, data))
        output = self.evaluate(identity, "/", data)
        denied = self.evaluate(claims(iss="synthetic-sensitive"), "synthetic-sensitive", data)
        self.assertNotIn("synthetic", json.dumps([output, denied]))
        self.assertEqual((identity, data), before)


class AuditTests(unittest.TestCase):
    def test_observed_configuration_and_gaps(self):
        data = catalog(ingress(configured=True))
        before = deepcopy(data)
        report = verifier.audit_cluster_ingress_oidc_posture(data)
        self.assertEqual(report["configured_count"], 1)
        self.assertEqual(report["status"], "configured_observed_fields")
        self.assertFalse(report["enforcement_verified"])
        self.assertEqual(data, before)
        report = verifier.audit_cluster_ingress_oidc_posture(catalog(ingress()))
        self.assertEqual(report["configured_count"], 0)
        self.assertEqual(len(report["ingresses"][0]["findings"]), 3)

    def test_untrusted_annotations_and_tls_do_not_count(self):
        for field in ("auth-url", "auth-signin"):
            resource = ingress(configured=True)
            resource["metadata"]["annotations"]["nginx.ingress.kubernetes.io/" + field] = "synthetic-sensitive"
            report = verifier.audit_cluster_ingress_oidc_posture(catalog(resource))
            self.assertEqual(report["configured_count"], 0)
            self.assertNotIn("synthetic-sensitive", json.dumps(report))
        resource = ingress(configured=True)
        resource["spec"]["tls"] = [{"hosts": ["another.cluster.example.org"]}]
        self.assertEqual(verifier.audit_cluster_ingress_oidc_posture(catalog(resource))["configured_count"], 0)

    def test_no_hosts_empty_catalog_and_invalid_catalog(self):
        resource = ingress(configured=True)
        resource["spec"]["rules"] = []
        report = verifier.audit_cluster_ingress_oidc_posture(catalog(resource))
        self.assertEqual(report["status"], "unknown")
        self.assertIn("missing_or_unsupported_host", report["ingresses"][0]["findings"])
        self.assertEqual(verifier.audit_cluster_ingress_oidc_posture(catalog())["status"], "unknown")
        for data in ({}, {"nodes": [None]}, catalog({"kind": "Ingress"})):
            self.assertEqual(verifier.audit_cluster_ingress_oidc_posture(data)["status"], "invalid_catalog")
        resource["spec"]["rules"] = [None]
        self.assertEqual(verifier.audit_cluster_ingress_oidc_posture(catalog(resource))["status"], "invalid_catalog")

    def test_reports_do_not_reflect_arbitrary_metadata(self):
        resource = ingress("synthetic-sensitive", "synthetic-sensitive", True)
        resource["metadata"]["name"] = "synthetic-sensitive"
        report = verifier.audit_cluster_ingress_oidc_posture(catalog(resource))
        self.assertNotIn("synthetic-sensitive", json.dumps(report))
        self.assertEqual(report["configured_count"], 0)

    def test_bundled_catalog_and_cli(self):
        report = verifier.audit_cluster_ingress_oidc_posture()
        self.assertGreater(report["ingress_count"], 0)
        self.assertFalse(report["enforcement_verified"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps(catalog(ingress(configured=True))), encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream):
                code = verifier.main(["--catalog", str(path), "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stream.getvalue())["configured_count"], 1)
            path.write_text("invalid synthetic-sensitive", encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream):
                code = verifier.main(["--catalog", str(path), "--json"])
            self.assertEqual(code, 1)
            self.assertNotIn("synthetic-sensitive", stream.getvalue())
            self.assertEqual(json.loads(stream.getvalue())["status"], "invalid_catalog")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(verifier.main(["--catalog", str(path)]), 1)


if __name__ == "__main__":
    unittest.main()
