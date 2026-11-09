# SPDX-License-Identifier: Apache-2.0
"""Snapshot-derived currency, signal, reference and CLI contracts."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cluster_harvester import build_live_cluster_spatial_catalog
import live_currencies as currencies


class LiveCurrenciesTests(unittest.TestCase):
    def setUp(self):
        items = []
        for kind, name in (("Pod", "gitlab-runner-abc"),
                           ("Deployment", "gitlab-runner"),
                           ("Pod", "gitlab-server"),
                           ("Service", "gitlab"), ("Ingress", "gitlab")):
            items.append({"kind": kind, "metadata": {"name": name, "namespace": "ci"}})
        self.catalog = build_live_cluster_spatial_catalog(
            {"items": items, "source": "test_snapshot", "example": True})

    def enrich(self, **kwargs):
        result = currencies.build_enriched_live_currencies(self.catalog, **kwargs)
        self.assertEqual([c["currency_id"] for c in result],
                         [c[0] for c in currencies._CURRENCIES])
        ids = {n["id"] for n in self.catalog["nodes"]}
        self.assertTrue(all(item["target_id"] in ids for c in result
                            for item in c["dropdown_items"]))
        return {c["currency_id"]: c for c in result}

    def test_derivation_preservation_and_no_mutation(self):
        before = deepcopy(self.catalog)
        result = self.enrich()
        for original in before["rts_currencies"][:3]:
            self.assertEqual(result[original["currency_id"]], original)
        build = result["build_supply"]
        self.assertTrue(build["available"])
        self.assertEqual(build["display_value"], "1 runner pods / 1 deployments")
        self.assertEqual(len(build["dropdown_items"]), 2)
        self.assertEqual(result["network_load"]["display_value"],
                         "2 routes (Ingress/Service)")
        self.assertEqual(build["source"], "test_snapshot")
        self.assertTrue(build["example"])
        self.assertFalse(result["renovate_failures"]["available"])
        self.assertFalse(result["open_mrs"]["available"])
        build["dropdown_items"].clear()
        self.assertEqual(self.catalog, before)

    def test_empty_and_missing_measurements_are_unavailable(self):
        self.catalog = {"nodes": []}
        result = self.enrich()
        self.assertTrue(all(not c["available"] for c in result.values()))
        self.assertTrue(all(c["dropdown_items"] == [] for c in result.values()))

    def test_runner_labels_and_resource_kind_fallback(self):
        node = next(n for n in self.catalog["nodes"] if n.get("label") == "gitlab-server")
        node.pop("resource_kind")
        node["resource"]["metadata"]["labels"] = {"app": "gitlab-runner"}
        self.assertEqual(len(self.enrich()["build_supply"]["dropdown_items"]), 3)

    def test_signals_zero_override_and_reference_filtering(self):
        target = self.catalog["nodes"][0]["id"]
        signals = {"network_load": {"display_value": "12% measured", "source": "monitor"},
                   "renovate_failures": 0,
                   "open_mrs": {"count": 3, "dropdown_items": [
                       {"label": "MRs", "value": "3", "target_id": target},
                       {"label": "dangling", "target_id": "absent"}]}}
        before = deepcopy(signals)
        self.catalog["rts_currencies"][0]["dropdown_items"].append(
            {"target_id": "absent", "label": "bad"})
        result = self.enrich(extra_signals=signals)
        self.assertEqual(result["network_load"]["display_value"], "12% measured")
        self.assertEqual(result["network_load"]["source"], "monitor")
        self.assertTrue(result["renovate_failures"]["available"])
        self.assertEqual(result["renovate_failures"]["display_value"], "0")
        self.assertEqual(len(result["open_mrs"]["dropdown_items"]), 1)
        self.assertEqual(signals, before)

    def test_signal_text_is_sanitized(self):
        # Construct sensitive examples at runtime to keep public source scanners clean.
        public_ip = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        credential = "gh" + "p_" + "testcredential"
        signal = {"open_mrs": {"display_value": f"{public_ip} {mac} {credential}"}}
        text = json.dumps(self.enrich(extra_signals=signal))
        for sensitive in (public_ip, mac, credential):
            self.assertNotIn(sensitive, text)
        self.assertIn("203.0.113.1", text)
        self.assertIn("AA:BB:CC:XX:XX:XX", text)
        self.assertIn("[REDACTED]", text)

    def test_invalid_counts_and_catalogs(self):
        for value in (-1, True, float("nan"), float("inf"), {"count": -2}, {},
                      {"count": 1, "available": "false"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.enrich(extra_signals={"open_mrs": value})
        for catalog in ({}, {"nodes": [None]}, {"nodes": [{"id": "a"}, {"id": "a"}]}):
            with self.subTest(catalog=catalog), self.assertRaises(ValueError):
                currencies.build_enriched_live_currencies(catalog)

    def test_default_file_path_and_cli(self):
        self.assertEqual(len(currencies.build_enriched_live_currencies()), 7)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            expected = currencies.build_enriched_live_currencies(path)
            with patch.object(currencies, "DEFAULT_CATALOG_PATH", path):
                self.assertEqual(currencies.build_enriched_live_currencies(), expected)
            for flags in (["--json"], []):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(currencies.main(["--catalog", str(path)] + flags), 0)
                if flags:
                    self.assertEqual(json.loads(output.getvalue()), expected)
                else:
                    self.assertIn("Build Supply:", output.getvalue())
        error = io.StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit) as caught:
            currencies.main(["--catalog", "missing-catalog.json", "--json"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("unable to enrich", error.getvalue())


if __name__ == "__main__":
    unittest.main()
