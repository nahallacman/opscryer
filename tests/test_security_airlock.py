# SPDX-License-Identifier: Apache-2.0
"""Argus security policy and graph-only discovery boundary tests."""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from dogfood_graph import build_dogfood_zoom_catalog
from security_airlock import (
    audit_container_security_context,
    evaluate_code_search_airlock,
    normalize_airlock_query,
)


class ContainerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.context = {"runAsNonRoot": True, "runAsUser": 10001,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]}}

    def test_valid_context_and_wrapped_container_are_not_mutated(self):
        before = deepcopy(self.context)
        for uid in (10000, 10001, 65534):
            self.context["runAsUser"] = uid
            for spec in (self.context, {"securityContext": self.context}):
                self.assertEqual(audit_container_security_context(spec),
                                 {"compliant": True, "violations": []})
        self.context["runAsUser"] = 10001
        self.assertEqual(self.context, before)

    def test_each_setting_fails_independently_including_wrong_types(self):
        for field, values in (
            ("runAsNonRoot", (False, 1, "true", None)),
            ("runAsUser", (0, 9999, True, 10000.0, "10001", None)),
            ("allowPrivilegeEscalation", (True, 0, "false", None)),
            ("capabilities", ({}, None, [], {"drop": []}, {"drop": "ALL"},
                              {"drop": ["ALL", "NET_ADMIN"]}, {"drop": ["all"]})),
        ):
            expected = "capabilities.drop" if field == "capabilities" else field
            for value in values:
                with self.subTest(field=field, value=value):
                    candidate = {**self.context, field: value}
                    self.assertEqual(audit_container_security_context(candidate),
                                     {"compliant": False, "violations": [expected]})
            candidate = deepcopy(self.context)
            del candidate[field]
            self.assertEqual(audit_container_security_context(candidate)["violations"], [expected])

    def test_missing_or_malformed_context_fails_closed(self):
        for spec in (None, [], "invalid", {}, {"securityContext": None},
                     {"securityContext": []}):
            result = audit_container_security_context(spec)
            self.assertFalse(result["compliant"])
            self.assertEqual(len(result["violations"]), 4)


class CodeSearchAirlockTests(unittest.TestCase):
    def test_secret_searches_block_before_catalog_access_and_never_echo_input(self):
        queries = ["find passwords", "dependency credentials", "manifest API_KEY",
                   "find private-key", "read " + "." + "env", "show bearer values",
                   "dependency SECRET", "manifest ｓｅｃｒｅｔ"]
        queries += ["manifest " + prefix + suffix + "synthetic"
                    for prefix, suffix in (("gho", "_"), ("ghp", "_"),
                                           ("glpat", "-"), ("sk", "-"))]
        with patch("security_airlock.KnowledgeGraphBackendEngine") as engine:
            for query in queries:
                with self.subTest():
                    result = evaluate_code_search_airlock(query, object())
                    self.assertEqual(result["status_code"], 403)
                    self.assertTrue(result["airlock_blocked"])
                    self.assertEqual(result["reason"], "secret_hunting_blocked")
                    self.assertNotIn(query, json.dumps(result))
                    self.assertEqual(result["results"], [])
                    self.assertEqual(result["escalation_paths"], [])
            engine.assert_not_called()

    def test_unsupported_and_invalid_queries_fail_closed(self):
        for query in (None, True, [], "", "  ", "search all source code", "hello"):
            self.assertTrue(evaluate_code_search_airlock(query)["airlock_blocked"])

    def test_manifest_and_dependency_queries_have_real_rooted_paths(self):
        catalog = build_dogfood_zoom_catalog()
        catalog["nodes"][4]["summary"] = "dependency dependencies manifest blast radius"
        catalog["nodes"][4]["private_payload"] = "must not be returned"
        before = deepcopy(catalog)
        for query in ("manifest", "dependency", "dependencies", "blast-radius", "package.json"):
            result = evaluate_code_search_airlock(query, catalog)
            self.assertEqual(result["status_code"], 200)
            self.assertFalse(result["airlock_blocked"])
            if query != "package.json":
                self.assertTrue(result["results"])
            self.assertEqual(len(result["results"]), len(result["escalation_paths"]))
            for hit, path in zip(result["results"], result["escalation_paths"]):
                self.assertEqual(path["path_ids"][0], "root-company")
                self.assertEqual(path["path_ids"][-1], hit["id"])
                self.assertTrue(path["path_found"])
            self.assertNotIn("private_payload", json.dumps(result))
        self.assertEqual(catalog, before)

    def test_default_catalog_and_no_hits(self):
        self.assertEqual(evaluate_code_search_airlock("dependency blast radius")["status_code"], 200)
        result = evaluate_code_search_airlock("package.json", build_dogfood_zoom_catalog())
        self.assertEqual(result["results"], [])
        self.assertEqual(result["escalation_paths"], [])

    def test_missing_root_denies_and_disconnected_hits_have_no_invented_paths(self):
        catalog = build_dogfood_zoom_catalog()
        catalog["nodes"].append({**deepcopy(catalog["nodes"][0]), "id": "isolated",
                                 "label": "dependency", "summary": "dependency",
                                 "drilldown_children": []})
        self.assertEqual(evaluate_code_search_airlock("dependency", catalog)["results"], [])
        catalog["nodes"][0]["id"] = "other-root"
        catalog["edges"] = [e for e in catalog["edges"] if e["source"] != "root-company"]
        self.assertEqual(evaluate_code_search_airlock("manifest", catalog)["status_code"], 403)

    def test_homoglyph_and_zero_width_secret_bypass_attempts_are_blocked(self):
        bypass_queries = [
            "manifest p\u0430ssword",          # Cyrillic 'а'
            "dependency s\u0435cr\u0435t",      # Cyrillic 'е'
            "manifest t\u043eken",              # Cyrillic 'о'
            "show b\u0435\u0430rer values",     # Cyrillic 'е' and 'а'
            "manifest sec\u200bret",            # zero-width space
            "manifest pass\u200dword",          # zero-width joiner
            "manifest glp\u0430t-synthetic",    # Cyrillic 'а' in token marker
        ]
        self.assertEqual(normalize_airlock_query("s\u0435c\u200bret"), "secret")
        for query in bypass_queries:
            with self.subTest(query=query):
                result = evaluate_code_search_airlock(query, object())
                self.assertEqual(result["status_code"], 403)
                self.assertTrue(result["airlock_blocked"])
                self.assertEqual(result["reason"], "secret_hunting_blocked")
                self.assertNotIn(query, json.dumps(result))

    def test_natural_language_jev_intent_queries_pass_without_manifest_prefix(self):
        for query in ("Why is Minecraft lagging?", "How do I connect to the database?", "Check RTX 3070 Ti GPU health"):
            with self.subTest(query=query):
                result = evaluate_code_search_airlock(query)
                self.assertEqual(result["status_code"], 200)
                self.assertFalse(result["airlock_blocked"])


if __name__ == "__main__":
    unittest.main()
