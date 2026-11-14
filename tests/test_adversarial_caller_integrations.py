# SPDX-License-Identifier: Apache-2.0
"""Empirical adversarial test suite for caller integrations in jev_client and prometheus_loki_adapter.

Stress-tests:
1. Upstream Ollama flapping recovery (intermittent 503s followed by 200 OK) -> predicate evaluation recovers
2. Permanent outage fail-fast -> circuit breaker trips to OPEN and fails fast to HUMAN_ESCALATION without delays
3. Circuit breaker HALF_OPEN probe recovery
4. Prometheus transient network drops -> SNAPSHOT_FALLBACK avoided on retry recovery
5. Prometheus permanent outage -> circuit breaker trips and fails fast to SNAPSHOT_FALLBACK
6. Non-retryable client errors (400/401) fail fast without retrying or tripping circuit
7. Backward compatibility with legacy mock patching (patch('jev_client.urlopen'))
8. Multithreaded concurrent requests under intermittent flapping
"""

from __future__ import annotations

import io
import json
import time
from typing import Any
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
from urllib.request import Request

from http_transport import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    get_circuit_breaker,
    reset_circuit_breakers,
    urlopen_with_retry,
)
import jev_client as jev
from prometheus_loki_adapter import (
    OFFLINE_OBSERVABILITY_FIXTURE,
    query_sanitized_observability_signals,
)


def _mock_envelope(predicate_id: str = "is_project_scaffolding", value: bool = True, prob: float = 0.96) -> bytes:
    inner = {
        "predicate_id": predicate_id,
        "evaluated_value": value,
        "calibrated_probability": prob,
    }
    envelope = {
        "message": {"role": "assistant", "content": json.dumps(inner)},
        "done": True,
    }
    return json.dumps(envelope).encode("utf-8")


def _mock_single_token_envelope(token: str = "Y", logprob: float = -0.05) -> bytes:
    envelope = {
        "message": {"role": "assistant", "content": token},
        "done": True,
        "logprobs": [{"logprob": logprob}],
    }
    return json.dumps(envelope).encode("utf-8")


def _mock_prometheus_up_envelope(count: int = 1) -> bytes:
    payload = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"__name__": "up", "instance": f"10.10.3.{10+i}:9100", "job": "node"},
                    "value": [1700000000, "1"],
                }
                for i in range(count)
            ],
        },
    }
    return json.dumps(payload).encode("utf-8")


class TestAdversarialCallerIntegrations(unittest.TestCase):
    """Adversarial stress-testing suite for Milestone 1 caller integrations."""

    def setUp(self) -> None:
        reset_circuit_breakers()
        b_ollama = get_circuit_breaker("ollama")
        b_ollama.failure_threshold = 3
        b_ollama.recovery_timeout = 30.0
        b_prom = get_circuit_breaker("prometheus")
        b_prom.failure_threshold = 3
        b_prom.recovery_timeout = 30.0

        # Fast sleep function for unit test execution speed
        self._sleep_patcher = patch.dict(
            urlopen_with_retry.__kwdefaults__,
            {"sleep_fn": lambda s: None, "jitter": False},
        )
        self._sleep_patcher.start()

    def tearDown(self) -> None:
        self._sleep_patcher.stop()
        reset_circuit_breakers()
        b_ollama = get_circuit_breaker("ollama")
        b_ollama.failure_threshold = 3
        b_ollama.recovery_timeout = 30.0
        b_prom = get_circuit_breaker("prometheus")
        b_prom.failure_threshold = 3
        b_prom.recovery_timeout = 30.0

    # -------------------------------------------------------------------------
    # 1. Ollama Flapping Recovery in jev_client.py
    # -------------------------------------------------------------------------

    def test_ollama_flapping_recovery_predicate(self) -> None:
        """Verify that when Ollama flaps with 503s before returning 200 OK,

        evaluate_predicate recovers and returns the valid result rather than
        dropping to HUMAN_ESCALATION.
        """
        success_body = _mock_envelope("is_project_scaffolding", True, 0.96)

        # Flapping pattern: two 503s, then 200 OK
        flapping_responses = [
            urllib.error.HTTPError("http://localhost:11434/api/chat", 503, "Service Unavailable", {}, None),
            urllib.error.HTTPError("http://localhost:11434/api/chat", 503, "Service Unavailable", {}, None),
            io.BytesIO(success_body),
        ]

        mock_opener = MagicMock(side_effect=flapping_responses)
        client = jev.SystemOneJevClient(provider="ollama", ollama_url="http://localhost:11434")

        with patch("jev_client.urlopen", mock_opener):
            result = client.evaluate_predicate("create new 3-tier gitlab pipeline", "is_project_scaffolding")

        # Crucial assertion: NOT HUMAN_ESCALATION
        self.assertNotEqual(result, jev.HUMAN_ESCALATION)
        self.assertEqual(result["predicate_id"], "is_project_scaffolding")
        self.assertTrue(result["evaluated_value"])
        self.assertEqual(result["calibrated_probability"], 0.96)

        # Verify 3 attempts took place (1 initial + 2 retries)
        self.assertEqual(mock_opener.call_count, 3)

        # Verify circuit breaker remained CLOSED because it eventually succeeded
        breaker = get_circuit_breaker("ollama")
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertEqual(breaker.snapshot()["consecutive_failures"], 0)

    def test_ollama_flapping_recovery_single_token_predicate(self) -> None:
        """Verify evaluate_single_token_predicate recovers from transient 503."""
        success_body = _mock_single_token_envelope("Y", -0.05)
        flapping_responses = [
            urllib.error.HTTPError("http://localhost:11434/api/chat", 503, "Unavailable", {}, None),
            io.BytesIO(success_body),
        ]
        mock_opener = MagicMock(side_effect=flapping_responses)
        client = jev.SystemOneJevClient(provider="ollama_single_token")

        with patch("jev_client.urlopen", mock_opener):
            result = client.evaluate_single_token_predicate("spin up new project pipeline", "is_project_scaffolding")

        self.assertNotEqual(result, jev.HUMAN_ESCALATION)
        self.assertTrue(result["evaluated_value"])
        self.assertEqual(mock_opener.call_count, 2)

    def test_ollama_flapping_recovery_full_tree_traversal(self) -> None:
        """Verify full Jev decision tree traversal succeeds despite flapping upstream."""
        # Tree evaluates root (is_project_scaffolding) -> leaf
        resp1 = _mock_envelope("is_project_scaffolding", True, 0.96)

        flapping_responses = [
            urllib.error.HTTPError("http://localhost:11434/api/chat", 503, "Unavailable", {}, None),
            io.BytesIO(resp1),
        ]
        mock_opener = MagicMock(side_effect=flapping_responses)

        with patch("jev_client.urlopen", mock_opener):
            outcome = jev.evaluate_ticket_with_jev_tree(
                ticket_title="spin up new 3 tier project",
                provider="ollama",
            )

        self.assertEqual(outcome["route"], "leaf")
        self.assertTrue(outcome["direct_access_allowed"])
        self.assertEqual(outcome["policy_id"], "playbook-demo-golden-path-3tier")
        self.assertEqual(len(outcome["traversal_steps"]), 2)  # 1 decision step + 1 leaf step

    # -------------------------------------------------------------------------
    # 2. Permanent Outage Fail-Fast in jev_client.py
    # -------------------------------------------------------------------------

    def test_ollama_permanent_outage_circuit_trip_and_fail_fast(self) -> None:
        """Verify that when Ollama is permanently down:

        1. The initial calls exhaust retries and return HUMAN_ESCALATION.
        2. Once failure_threshold is reached, the circuit trips to OPEN.
        3. Subsequent calls fail fast immediately without making network calls or delaying.
        """
        breaker = get_circuit_breaker("ollama", failure_threshold=3, recovery_timeout=30.0)
        self.assertEqual(breaker.state, CircuitState.CLOSED)

        outage_error = urllib.error.HTTPError(
            "http://localhost:11434/api/chat", 503, "Permanent Service Down", {}, None
        )
        mock_opener = MagicMock(side_effect=outage_error)
        client = jev.SystemOneJevClient(provider="ollama")

        with patch("jev_client.urlopen", mock_opener):
            # Request 1: exhausts 4 attempts (1 + 3 retries) -> consecutive_failures = 1
            res1 = client.evaluate_predicate("ticket 1", "is_project_scaffolding")
            self.assertEqual(res1, jev.HUMAN_ESCALATION)
            self.assertEqual(breaker.snapshot()["consecutive_failures"], 1)
            self.assertEqual(breaker.state, CircuitState.CLOSED)
            self.assertEqual(mock_opener.call_count, 4)

            # Request 2: exhausts 4 attempts -> consecutive_failures = 2
            res2 = client.evaluate_predicate("ticket 2", "is_project_scaffolding")
            self.assertEqual(res2, jev.HUMAN_ESCALATION)
            self.assertEqual(breaker.snapshot()["consecutive_failures"], 2)
            self.assertEqual(breaker.state, CircuitState.CLOSED)
            self.assertEqual(mock_opener.call_count, 8)

            # Request 3: exhausts 4 attempts -> consecutive_failures = 3 -> TRIPS to OPEN!
            res3 = client.evaluate_predicate("ticket 3", "is_project_scaffolding")
            self.assertEqual(res3, jev.HUMAN_ESCALATION)
            self.assertEqual(breaker.state, CircuitState.OPEN)
            self.assertGreaterEqual(breaker.snapshot()["total_trips"], 1)
            self.assertEqual(mock_opener.call_count, 12)

            # Request 4 (FAIL-FAST): Circuit is OPEN.
            # Must NOT call opener, must fail fast with HUMAN_ESCALATION
            call_count_before = mock_opener.call_count
            start_t = time.perf_counter()
            res4 = client.evaluate_predicate("ticket 4", "is_project_scaffolding")
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0

            self.assertEqual(res4, jev.HUMAN_ESCALATION)
            # Opener was NOT invoked!
            self.assertEqual(mock_opener.call_count, call_count_before)
            # Fails fast in milliseconds
            self.assertLess(elapsed_ms, 50.0)

            # Request 5 (FAIL-FAST again)
            res5 = client.evaluate_predicate("ticket 5", "is_project_scaffolding")
            self.assertEqual(res5, jev.HUMAN_ESCALATION)
            self.assertEqual(mock_opener.call_count, call_count_before)

    def test_ollama_circuit_breaker_half_open_probe_recovery(self) -> None:
        """Verify that when recovery_timeout elapses, circuit transitions to

        HALF_OPEN, allows a probe request through, and closes if successful.
        """
        breaker = get_circuit_breaker("ollama")
        breaker.failure_threshold = 2
        breaker.recovery_timeout = 0.05

        # Force trip to OPEN
        breaker.record_failure()
        breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)

        # Wait for recovery_timeout
        time.sleep(0.06)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)

        # Now simulate Ollama recovered
        success_body = _mock_envelope("is_project_scaffolding", True, 0.96)
        mock_opener = MagicMock(return_value=io.BytesIO(success_body))
        client = jev.SystemOneJevClient(provider="ollama")

        with patch("jev_client.urlopen", mock_opener):
            result = client.evaluate_predicate("ticket after recovery", "is_project_scaffolding")

        # Recovered probe succeeds
        self.assertEqual(result["predicate_id"], "is_project_scaffolding")
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertEqual(breaker.snapshot()["consecutive_failures"], 0)

    # -------------------------------------------------------------------------
    # 3. Prometheus Transient Drops in prometheus_loki_adapter.py
    # -------------------------------------------------------------------------

    def test_prometheus_transient_network_drops_avoids_snapshot_fallback(self) -> None:
        """Verify that transient network blips (connection reset, 503) against

        Prometheus are retried and do NOT cause SNAPSHOT_FALLBACK when retry succeeds.
        """
        prom_body = _mock_prometheus_up_envelope(count=2)
        transient_error = urllib.error.URLError(OSError("Connection reset by peer"))

        flapping_responses = [
            transient_error,
            io.BytesIO(prom_body),
        ]
        mock_opener = MagicMock(side_effect=flapping_responses)

        with patch("prometheus_loki_adapter.urlopen", mock_opener):
            signals = query_sanitized_observability_signals(allow_live_http=True)

        # Crucial assertion: SNAPSHOT_FALLBACK is AVOIDED!
        self.assertEqual(signals["telemetry_mode"], "LIVE_PROMETHEUS_HTTP")
        self.assertTrue(signals["live_http_active"])
        self.assertEqual(signals["up_result_count"], 2)
        self.assertEqual(mock_opener.call_count, 2)

    def test_prometheus_permanent_outage_circuit_trip_and_fail_fast(self) -> None:
        """Verify that when Prometheus is permanently dead:

        1. Retries fail and fall back to SNAPSHOT_FALLBACK.
        2. Breaker trips to OPEN.
        3. Subsequent calls fail fast to SNAPSHOT_FALLBACK without socket attempts.
        """
        breaker = get_circuit_breaker("prometheus")
        breaker.failure_threshold = 2
        breaker.recovery_timeout = 30.0
        outage_error = urllib.error.URLError(OSError("No route to host"))
        mock_opener = MagicMock(side_effect=outage_error)

        with patch("prometheus_loki_adapter.urlopen", mock_opener):
            # Call 1: retries exhausted -> failure 1
            s1 = query_sanitized_observability_signals(allow_live_http=True)
            self.assertEqual(s1["telemetry_mode"], "SNAPSHOT_FALLBACK")
            self.assertFalse(s1["live_http_active"])
            self.assertEqual(breaker.state, CircuitState.CLOSED)

            # Call 2: retries exhausted -> failure 2 -> trips to OPEN!
            s2 = query_sanitized_observability_signals(allow_live_http=True)
            self.assertEqual(s2["telemetry_mode"], "SNAPSHOT_FALLBACK")
            self.assertEqual(breaker.state, CircuitState.OPEN)

            # Call 3 (FAIL-FAST):
            call_count_before = mock_opener.call_count
            start_t = time.perf_counter()
            s3 = query_sanitized_observability_signals(allow_live_http=True)
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0

            self.assertEqual(s3["telemetry_mode"], "SNAPSHOT_FALLBACK")
            self.assertFalse(s3["live_http_active"])
            # Opener was NOT called
            self.assertEqual(mock_opener.call_count, call_count_before)
            self.assertLess(elapsed_ms, 50.0)

    # -------------------------------------------------------------------------
    # 4. Non-Retryable Client Error Fast-Fail Semantics
    # -------------------------------------------------------------------------

    def test_non_retryable_client_error_fail_fast_without_circuit_trip(self) -> None:
        """Verify that HTTP 400 Bad Request or HTTP 401 Unauthorized fails fast

        immediately (call_count == 1) and does NOT trip the circuit breaker.
        """
        mock_opener = MagicMock(
            side_effect=urllib.error.HTTPError("http://ollama", 400, "Bad Request", {}, None)
        )
        client = jev.SystemOneJevClient(provider="ollama")

        with patch("jev_client.urlopen", mock_opener):
            result = client.evaluate_predicate("bad ticket", "is_project_scaffolding")

        # Fails closed to HUMAN_ESCALATION
        self.assertEqual(result, jev.HUMAN_ESCALATION)
        # Did NOT retry 3 times wasting time on a client error
        self.assertEqual(mock_opener.call_count, 1)

        # Circuit breaker was NOT tripped by a client error!
        breaker = get_circuit_breaker("ollama")
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertEqual(breaker.snapshot()["consecutive_failures"], 0)

    # -------------------------------------------------------------------------
    # 5. Backward Compatibility Verification
    # -------------------------------------------------------------------------

    def test_backward_compatibility_mock_patching_and_default_parameters(self) -> None:
        """Verify that existing test idioms patching jev_client.urlopen continue to work."""
        success_body = _mock_envelope("is_project_scaffolding", False, 0.94)
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = success_body

        with patch("jev_client.urlopen", return_value=mock_resp) as legacy_mock:
            client = jev.SystemOneJevClient(provider="ollama")
            result = client.evaluate_predicate("some title", "is_project_scaffolding")

        self.assertEqual(result["evaluated_value"], False)
        self.assertEqual(result["calibrated_probability"], 0.94)
        self.assertEqual(legacy_mock.call_count, 1)

    def test_deterministic_provider_remains_purely_in_memory(self) -> None:
        """Verify that deterministic provider requires zero network and bypasses transport."""
        with patch("jev_client.urlopen") as mock_opener:
            client = jev.SystemOneJevClient(provider="deterministic")
            result = client.evaluate_predicate("new 3-tier gitlab pipeline", "is_project_scaffolding")
            mock_opener.assert_not_called()

        self.assertEqual(result["evaluated_value"], True)
        self.assertEqual(result["calibrated_probability"], 0.96)

    def test_prometheus_offline_default_requires_zero_network(self) -> None:
        """Verify that allow_live_http=False bypasses network transport completely."""
        with patch("prometheus_loki_adapter.urlopen") as mock_opener:
            signals = query_sanitized_observability_signals(allow_live_http=False)
            mock_opener.assert_not_called()

        self.assertEqual(signals["telemetry_mode"], "SNAPSHOT_FIXTURE")
        self.assertFalse(signals["live_http_active"])

    def test_concurrent_multithreaded_flapping_recovery(self) -> None:
        """Verify thread safety of CircuitBreaker and caller recovery under concurrent load."""
        import threading

        success_body = _mock_envelope("is_project_scaffolding", True, 0.96)
        lock = threading.Lock()
        counter = {"calls": 0}

        def mock_open(*args: Any, **kwargs: Any) -> io.BytesIO:
            with lock:
                counter["calls"] += 1
                call_num = counter["calls"]
            # Odd calls fail with 503, even calls succeed with 200
            if call_num % 2 == 1:
                raise urllib.error.HTTPError("http://localhost:11434/api/chat", 503, "Flapping", {}, None)
            return io.BytesIO(success_body)

        client = jev.SystemOneJevClient(provider="ollama")
        results: list[Any] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                res = client.evaluate_predicate("create new 3-tier scaffolding", "is_project_scaffolding")
                results.append(res)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        with patch("jev_client.urlopen", side_effect=mock_open):
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 10)
        for r in results:
            self.assertNotEqual(r, jev.HUMAN_ESCALATION)
            self.assertTrue(r["evaluated_value"])


if __name__ == "__main__":
    unittest.main()

