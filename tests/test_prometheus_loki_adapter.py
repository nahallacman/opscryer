# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the sanitized Prometheus & Loki observability adapter."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from prometheus_loki_adapter import (
    OFFLINE_OBSERVABILITY_FIXTURE,
    query_sanitized_observability_signals,
)


class PrometheusLokiAdapterTests(unittest.TestCase):
    def test_offline_default_returns_sanitized_fixture_without_network(self) -> None:
        with patch("prometheus_loki_adapter.urlopen") as mocked:
            result = query_sanitized_observability_signals(allow_live_http=False)
            mocked.assert_not_called()
        self.assertEqual(result["telemetry_mode"], "SNAPSHOT_FIXTURE")
        self.assertFalse(result["live_http_active"])
        self.assertEqual(len(result["prometheus_signals"]), 3)
        self.assertGreaterEqual(result["noc_catalog_count"], 5)

    def test_live_http_success_and_fallback_and_sanitization(self) -> None:
        fake_resp = MagicMock()
        fake_resp.__enter__.return_value.read.return_value = json.dumps(
            {"status": "success", "data": {"result": [{"metric": {"instance": "10.20.3.13:9100"}}]}}
        ).encode("utf-8")
        with patch("prometheus_loki_adapter.urlopen", return_value=fake_resp):
            live = query_sanitized_observability_signals(allow_live_http=True)
        self.assertEqual(live["telemetry_mode"], "LIVE_PROMETHEUS_HTTP")
        self.assertTrue(live["live_http_active"])
        self.assertEqual(live["up_result_count"], 1)

        with patch("prometheus_loki_adapter.urlopen", side_effect=OSError("unreachable")):
            fallback = query_sanitized_observability_signals(allow_live_http=True)
        self.assertEqual(fallback["telemetry_mode"], "SNAPSHOT_FALLBACK")
        self.assertFalse(fallback["live_http_active"])

        with self.assertRaises(ValueError):
            query_sanitized_observability_signals(allow_live_http="yes")  # type: ignore[arg-type]
        self.assertIsNotNone(OFFLINE_OBSERVABILITY_FIXTURE)


if __name__ == "__main__":
    unittest.main()
