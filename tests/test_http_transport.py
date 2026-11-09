# SPDX-License-Identifier: Apache-2.0
"""Unit and boundary test suite for http_transport.py."""

from __future__ import annotations

import concurrent.futures
import io
import threading
import time
import unittest
from unittest.mock import MagicMock
import urllib.error
from urllib.request import Request

from http_transport import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    HTTPResponseBytes,
    clear_circuit_breakers,
    get_circuit_breaker,
    reset_circuit_breakers,
    urlopen_with_retry,
)


class TestHTTPTransport(unittest.TestCase):
    """Test suite for resilient HTTP transport, exponential backoff, and circuit breaking."""

    def setUp(self) -> None:
        reset_circuit_breakers(clear=True)

    def tearDown(self) -> None:
        reset_circuit_breakers(clear=True)

    # -----------------------------------------------------------------------
    # Tier 1: Feature Tests (Core Functionality)
    # -----------------------------------------------------------------------

    def test_successful_request_string_url(self) -> None:
        """Verify successful HTTP GET using a string URL returns HTTPResponseBytes."""
        mock_opener = MagicMock()
        mock_opener.return_value = io.BytesIO(b'{"status":"ok","value":1}')

        res = urlopen_with_retry("http://127.0.0.1:9090/api/v1/query", opener=mock_opener)
        self.assertIsInstance(res, bytes)
        self.assertIsInstance(res, HTTPResponseBytes)
        self.assertEqual(res, b'{"status":"ok","value":1}')
        self.assertEqual(mock_opener.call_count, 1)

    def test_successful_request_request_object(self) -> None:
        """Verify successful HTTP POST using a urllib.request.Request object."""
        req = Request(
            "http://localhost:11434/api/chat",
            data=b'{"model":"qwen2.5"}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        mock_opener = MagicMock()
        mock_opener.return_value = io.BytesIO(b'{"done":true,"message":{"content":"Y"}}')

        res = urlopen_with_retry(req, timeout=3.0, opener=mock_opener)
        self.assertEqual(res, b'{"done":true,"message":{"content":"Y"}}')
        self.assertEqual(mock_opener.call_count, 1)

    def test_retry_on_503_and_eventual_success(self) -> None:
        """Verify that a transient 503 triggers exponential backoff and succeeds on retry."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.HTTPError("http://ollama", 503, "Service Unavailable", {}, None),
            io.BytesIO(b'{"status":"recovered"}'),
        ]
        mock_sleep = MagicMock()

        res = urlopen_with_retry(
            "http://ollama/api",
            max_retries=3,
            backoff_factor=0.2,
            opener=mock_opener,
            sleep_fn=mock_sleep,
            jitter=False,
        )
        self.assertEqual(res, b'{"status":"recovered"}')
        self.assertEqual(mock_opener.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1)
        mock_sleep.assert_called_with(0.2)  # 0.2 * (2**0)

    def test_retry_on_429_rate_limit_and_eventual_success(self) -> None:
        """Verify that HTTP 429 Too Many Requests is retried and succeeds."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.HTTPError("http://api", 429, "Too Many Requests", {}, None),
            io.BytesIO(b'{"status":"ok_after_throttle"}'),
        ]
        mock_sleep = MagicMock()

        res = urlopen_with_retry("http://api", max_retries=2, opener=mock_opener, sleep_fn=mock_sleep)
        self.assertEqual(res, b'{"status":"ok_after_throttle"}')
        self.assertEqual(mock_opener.call_count, 2)
        self.assertEqual(mock_sleep.call_count, 1)

    def test_retry_on_urlerror_and_timeout_eventual_success(self) -> None:
        """Verify that transient network URLError and TimeoutError are retried."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.URLError("Connection reset by peer"),
            TimeoutError("Socket read timed out"),
            io.BytesIO(b'{"status":"success_on_attempt_3"}'),
        ]
        mock_sleep = MagicMock()

        res = urlopen_with_retry(
            "http://upstream",
            max_retries=3,
            backoff_factor=0.2,
            opener=mock_opener,
            sleep_fn=mock_sleep,
            jitter=False,
        )
        self.assertEqual(res, b'{"status":"success_on_attempt_3"}')
        self.assertEqual(mock_opener.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)
        mock_sleep.assert_any_call(0.2)  # Attempt 1 -> 0.2s
        mock_sleep.assert_any_call(0.4)  # Attempt 2 -> 0.4s

    def test_retry_exhaustion_raises_final_exception(self) -> None:
        """Verify that when all retries are exhausted, the underlying HTTPError is raised."""
        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.HTTPError(
            "http://down", 504, "Gateway Timeout", {}, None
        )
        mock_sleep = MagicMock()

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urlopen_with_retry(
                "http://down",
                max_retries=3,
                opener=mock_opener,
                sleep_fn=mock_sleep,
            )
        self.assertEqual(ctx.exception.code, 504)
        # Total attempts: 1 initial + 3 retries = 4
        self.assertEqual(mock_opener.call_count, 4)
        self.assertEqual(mock_sleep.call_count, 3)

    def test_non_retryable_client_errors_fail_fast(self) -> None:
        """Verify that 4xx client errors (400, 401, 403, 404) fail fast without retrying."""
        for code in (400, 401, 403, 404, 405, 422):
            mock_opener = MagicMock()
            mock_opener.side_effect = urllib.error.HTTPError(
                f"http://test/{code}", code, "Client Error", {}, None
            )
            mock_sleep = MagicMock()

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urlopen_with_retry(
                    f"http://test/{code}",
                    max_retries=3,
                    opener=mock_opener,
                    sleep_fn=mock_sleep,
                )
            self.assertEqual(ctx.exception.code, code)
            self.assertEqual(mock_opener.call_count, 1, f"Status code {code} must fail fast on attempt 1")
            self.assertEqual(mock_sleep.call_count, 0, f"Status code {code} must not sleep")

    # -----------------------------------------------------------------------
    # Tier 2: Circuit Breaker State Machine & Boundary Tests
    # -----------------------------------------------------------------------

    def test_circuit_breaker_trips_to_open_after_threshold(self) -> None:
        """Verify circuit breaker trips to OPEN after failure threshold and fails fast."""
        breaker = get_circuit_breaker("test_breaker", failure_threshold=3, recovery_timeout=60.0)
        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.HTTPError("http://err", 503, "Unavailable", {}, None)
        mock_sleep = MagicMock()

        # 3 calls with max_retries=0 so each call fails once and records a failure
        for _ in range(3):
            with self.assertRaises(urllib.error.HTTPError):
                urlopen_with_retry(
                    "http://err",
                    max_retries=0,
                    circuit_breaker_name="test_breaker",
                    opener=mock_opener,
                    sleep_fn=mock_sleep,
                )

        self.assertEqual(breaker.state, CircuitState.OPEN)
        self.assertEqual(mock_opener.call_count, 3)

        # 4th call: Breaker is OPEN -> must raise CircuitBreakerOpenError without calling opener
        with self.assertRaises(CircuitBreakerOpenError) as ctx:
            urlopen_with_retry(
                "http://err",
                circuit_breaker_name="test_breaker",
                opener=mock_opener,
            )
        self.assertEqual(ctx.exception.breaker_name, "test_breaker")
        self.assertEqual(mock_opener.call_count, 3, "Network must NOT be called when breaker is OPEN")

    def test_circuit_breaker_half_open_probe_recovery(self) -> None:
        """Verify that after recovery timeout, HALF_OPEN probe allows recovery to CLOSED."""
        breaker = get_circuit_breaker("probe_breaker", failure_threshold=2, recovery_timeout=0.05)

        # Fail twice to trip breaker
        breaker.record_failure()
        breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)

        # Wait past recovery timeout to transition to HALF_OPEN
        time.sleep(0.08)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)

        # Execute probe call that succeeds
        mock_opener = MagicMock()
        mock_opener.return_value = io.BytesIO(b'{"status":"probe_success"}')

        res = urlopen_with_retry(
            "http://upstream",
            circuit_breaker_name="probe_breaker",
            opener=mock_opener,
        )
        self.assertEqual(res, b'{"status":"probe_success"}')
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertEqual(breaker.snapshot()["consecutive_failures"], 0)

    def test_circuit_breaker_half_open_probe_failure_re_opens(self) -> None:
        """Verify that if a probe fails during HALF_OPEN, the breaker immediately re-opens."""
        breaker = get_circuit_breaker("probe_fail_breaker", failure_threshold=1, recovery_timeout=0.05)
        breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)

        time.sleep(0.06)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)

        # Probe fails
        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.HTTPError("http://err", 500, "Still Down", {}, None)

        with self.assertRaises(urllib.error.HTTPError):
            urlopen_with_retry(
                "http://err",
                max_retries=0,
                circuit_breaker_name="probe_fail_breaker",
                opener=mock_opener,
            )
        self.assertEqual(breaker.state, CircuitState.OPEN)

    def test_isolated_named_circuit_breakers(self) -> None:
        """Verify that different circuit breaker names maintain isolated states."""
        b_ollama = get_circuit_breaker("ollama", failure_threshold=2)
        b_prom = get_circuit_breaker("prometheus", failure_threshold=2)

        b_ollama.record_failure()
        b_ollama.record_failure()
        self.assertEqual(b_ollama.state, CircuitState.OPEN)
        self.assertEqual(b_prom.state, CircuitState.CLOSED)

        # Calls with breaker 'prometheus' succeed normally
        mock_opener = MagicMock()
        mock_opener.return_value = io.BytesIO(b'{"up":1}')
        res = urlopen_with_retry(
            "http://prom/up",
            circuit_breaker_name="prometheus",
            opener=mock_opener,
        )
        self.assertEqual(res, b'{"up":1}')

    def test_max_retries_zero_executes_single_attempt(self) -> None:
        """Verify max_retries=0 makes exactly 1 attempt and does not retry on 503."""
        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.HTTPError("http://test", 503, "Unavailable", {}, None)
        mock_sleep = MagicMock()

        with self.assertRaises(urllib.error.HTTPError):
            urlopen_with_retry("http://test", max_retries=0, opener=mock_opener, sleep_fn=mock_sleep)
        self.assertEqual(mock_opener.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 0)

    def test_exponential_backoff_progression_math(self) -> None:
        """Verify exact exponential backoff calculation sequence (0.2s, 0.4s, 0.8s)."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.HTTPError("", 503, "", {}, None),
            urllib.error.HTTPError("", 503, "", {}, None),
            urllib.error.HTTPError("", 503, "", {}, None),
            io.BytesIO(b"ok"),
        ]
        mock_sleep = MagicMock()

        res = urlopen_with_retry(
            "http://test",
            max_retries=3,
            backoff_factor=0.2,
            opener=mock_opener,
            sleep_fn=mock_sleep,
            jitter=False,
        )
        self.assertEqual(res, b"ok")
        self.assertEqual(mock_sleep.call_count, 3)
        self.assertAlmostEqual(mock_sleep.call_args_list[0][0][0], 0.2)  # 0.2 * 2^0
        self.assertAlmostEqual(mock_sleep.call_args_list[1][0][0], 0.4)  # 0.2 * 2^1
        self.assertAlmostEqual(mock_sleep.call_args_list[2][0][0], 0.8)  # 0.2 * 2^2

    def test_http_response_bytes_compatibilities(self) -> None:
        """Verify HTTPResponseBytes acts as bytes and supports .read() and context managers."""
        raw = b'{"hello":"world"}'
        resp = HTTPResponseBytes(raw)
        self.assertEqual(resp, raw)
        self.assertEqual(len(resp), len(raw))
        self.assertEqual(resp.read(), raw)
        self.assertEqual(resp.read(5), raw[:5])
        with resp as r:
            self.assertEqual(r.read(), raw)


    # -----------------------------------------------------------------------
    # Tier 3: Empirical Challenger Concurrency & Boundary Tests
    # -----------------------------------------------------------------------

    def test_challenge_concurrent_circuit_breaker_failing_burst_50_threads(self) -> None:
        """Challenge: 50 concurrent threads firing failing requests against CircuitBreaker."""
        breaker_name = "burst_fail_breaker"
        breaker = get_circuit_breaker(breaker_name, failure_threshold=5, recovery_timeout=60.0)

        mock_opener = MagicMock()
        mock_opener.side_effect = urllib.error.HTTPError("http://burst", 503, "Service Unavailable", {}, None)

        num_threads = 50
        barrier = threading.Barrier(num_threads)

        def worker():
            barrier.wait()
            try:
                urlopen_with_retry(
                    "http://burst",
                    max_retries=0,
                    circuit_breaker_name=breaker_name,
                    opener=mock_opener,
                )
            except Exception as e:
                return e

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker) for _ in range(num_threads)]
            results = [f.result() for f in futures]

        self.assertEqual(breaker.state, CircuitState.OPEN)

        http_errors = [r for r in results if isinstance(r, urllib.error.HTTPError)]
        cb_errors = [r for r in results if isinstance(r, CircuitBreakerOpenError)]

        self.assertEqual(len(http_errors) + len(cb_errors), num_threads)
        self.assertGreaterEqual(len(http_errors), 5)
        self.assertGreaterEqual(len(cb_errors), 1)

        snap = breaker.snapshot()
        self.assertEqual(snap["total_trips"], 1)
        self.assertEqual(mock_opener.call_count, len(http_errors))

    def test_challenge_concurrent_half_open_probe_transition(self) -> None:
        """Challenge: Breaker is in HALF_OPEN. Multiple concurrent threads hit it."""
        breaker_name = "half_open_concurrent"
        breaker = get_circuit_breaker(breaker_name, failure_threshold=2, recovery_timeout=0.04)

        breaker.record_failure()
        breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)

        time.sleep(0.06)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)

        num_threads = 20
        barrier = threading.Barrier(num_threads)
        mock_opener = MagicMock()
        mock_opener.side_effect = lambda *a, **kw: io.BytesIO(b'{"probe":"ok"}')

        def worker():
            barrier.wait()
            try:
                return urlopen_with_retry(
                    "http://probe",
                    max_retries=0,
                    circuit_breaker_name=breaker_name,
                    opener=mock_opener,
                )
            except Exception as e:
                return e

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker) for _ in range(num_threads)]
            results = [f.result() for f in futures]

        self.assertEqual(breaker.state, CircuitState.CLOSED)
        for r in results:
            self.assertIsInstance(r, HTTPResponseBytes)
            self.assertEqual(r, b'{"probe":"ok"}')

    def test_challenge_jitter_bounds_strictly_enforced(self) -> None:
        """Challenge: Jitter offset must be strictly within [0.0, 0.1 * base_delay]."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.HTTPError("", 503, "", {}, None),
            urllib.error.HTTPError("", 503, "", {}, None),
            urllib.error.HTTPError("", 503, "", {}, None),
            io.BytesIO(b"ok"),
        ]
        sleep_durations = []
        def capturing_sleep(d: float) -> None:
            sleep_durations.append(d)

        res = urlopen_with_retry(
            "http://jitter-test",
            max_retries=3,
            backoff_factor=0.5,
            opener=mock_opener,
            sleep_fn=capturing_sleep,
            jitter=True,
        )
        self.assertEqual(res, b"ok")
        self.assertEqual(len(sleep_durations), 3)

        self.assertGreaterEqual(sleep_durations[0], 0.5)
        self.assertLessEqual(sleep_durations[0], 0.550001)

        self.assertGreaterEqual(sleep_durations[1], 1.0)
        self.assertLessEqual(sleep_durations[1], 1.100001)

        self.assertGreaterEqual(sleep_durations[2], 2.0)
        self.assertLessEqual(sleep_durations[2], 2.200001)

    def test_challenge_zero_and_negative_retries_behavior(self) -> None:
        """Challenge: max_retries <= 0 executes exactly 1 attempt and fails cleanly."""
        for mr in (0, -1, -99):
            mock_opener = MagicMock()
            mock_opener.side_effect = urllib.error.HTTPError("http://neg", 503, "Err", {}, None)
            mock_sleep = MagicMock()

            with self.assertRaises(urllib.error.HTTPError):
                urlopen_with_retry(
                    "http://neg",
                    max_retries=mr,
                    opener=mock_opener,
                    sleep_fn=mock_sleep,
                )
            self.assertEqual(mock_opener.call_count, 1)
            self.assertEqual(mock_sleep.call_count, 0)

    def test_challenge_extreme_timeout_values(self) -> None:
        """Challenge: Extreme timeout values passed directly to opener without error."""
        for t_val in (0.001, 1e5, 0.0):
            mock_opener = MagicMock()
            mock_opener.return_value = io.BytesIO(b"ok")

            res = urlopen_with_retry("http://timeout-check", timeout=t_val, opener=mock_opener)
            self.assertEqual(res, b"ok")
            mock_opener.assert_called_once()
            _, kwargs = mock_opener.call_args
            self.assertEqual(kwargs.get("timeout"), t_val)

    def test_challenge_zero_backoff_factor(self) -> None:
        """Challenge: backoff_factor=0.0 sleeps for 0.0 seconds without crashing."""
        mock_opener = MagicMock()
        mock_opener.side_effect = [
            urllib.error.HTTPError("", 503, "", {}, None),
            io.BytesIO(b"ok"),
        ]
        mock_sleep = MagicMock()

        res = urlopen_with_retry("http://test", backoff_factor=0.0, opener=mock_opener, sleep_fn=mock_sleep, jitter=False)
        self.assertEqual(res, b"ok")
        self.assertEqual(mock_sleep.call_count, 1)
        mock_sleep.assert_called_with(0.0)

    def test_challenge_custom_error_subclasses_handling(self) -> None:
        """Challenge: Custom subclasses of URLError, OSError, ConnectionResetError."""
        class CustomNetworkError(urllib.error.URLError):
            pass

        class CustomSocketError(ConnectionResetError):
            pass

        class NonNetworkError(ValueError):
            pass

        # 1. Custom URLError subclass should be retried
        mock_opener1 = MagicMock()
        mock_opener1.side_effect = [CustomNetworkError("custom socket failure"), io.BytesIO(b"recovered")]
        mock_sleep1 = MagicMock()

        res1 = urlopen_with_retry("http://net", opener=mock_opener1, sleep_fn=mock_sleep1)
        self.assertEqual(res1, b"recovered")
        self.assertEqual(mock_opener1.call_count, 2)

        # 2. Custom ConnectionResetError (OSError subclass) should be retried
        mock_opener2 = MagicMock()
        mock_opener2.side_effect = [CustomSocketError("reset"), io.BytesIO(b"recovered_os")]
        mock_sleep2 = MagicMock()

        res2 = urlopen_with_retry("http://socket", opener=mock_opener2, sleep_fn=mock_sleep2)
        self.assertEqual(res2, b"recovered_os")
        self.assertEqual(mock_opener2.call_count, 2)

        # 3. Non-network error (ValueError) must NOT be caught or retried
        mock_opener3 = MagicMock()
        mock_opener3.side_effect = NonNetworkError("programming bug")
        mock_sleep3 = MagicMock()

        with self.assertRaises(NonNetworkError):
            urlopen_with_retry("http://bug", opener=mock_opener3, sleep_fn=mock_sleep3)
        self.assertEqual(mock_opener3.call_count, 1)
        self.assertEqual(mock_sleep3.call_count, 0)

    def test_challenge_http_status_code_matrix(self) -> None:
        """Challenge: Comprehensive status code matrix test (retryable vs fail-fast)."""
        for code in (429, 500, 502, 503, 504, 599):
            mock_opener = MagicMock()
            mock_opener.side_effect = [
                urllib.error.HTTPError("http://s", code, "Err", {}, None),
                io.BytesIO(b"ok"),
            ]
            mock_sleep = MagicMock()
            res = urlopen_with_retry("http://s", opener=mock_opener, sleep_fn=mock_sleep)
            self.assertEqual(res, b"ok")
            self.assertEqual(mock_opener.call_count, 2, f"Status code {code} must be retried")

        for code in (400, 401, 403, 404, 405, 410, 422):
            mock_opener = MagicMock()
            mock_opener.side_effect = urllib.error.HTTPError("http://s", code, "Err", {}, None)
            mock_sleep = MagicMock()
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urlopen_with_retry("http://s", max_retries=3, opener=mock_opener, sleep_fn=mock_sleep)
            self.assertEqual(ctx.exception.code, code)
            self.assertEqual(mock_opener.call_count, 1, f"Status code {code} must fail fast on attempt 1")
            self.assertEqual(mock_sleep.call_count, 0)

    def test_circuit_breaker_reset_clears_cumulative_telemetry(self) -> None:
        """Verify CircuitBreaker.reset() zeroes cumulative metrics when reset_metrics=True."""
        breaker = CircuitBreaker("telemetry_reset_test", failure_threshold=2, recovery_timeout=30.0)
        breaker.allow_request()
        breaker.record_failure()
        breaker.allow_request()
        breaker.record_failure()

        self.assertEqual(breaker.state, CircuitState.OPEN)
        snap1 = breaker.snapshot()
        self.assertEqual(snap1["total_requests"], 2)
        self.assertEqual(snap1["total_failures"], 2)
        self.assertEqual(snap1["total_trips"], 1)

        # Reset without resetting metrics
        breaker.reset(reset_metrics=False)
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertEqual(breaker.snapshot()["consecutive_failures"], 0)
        self.assertEqual(breaker.snapshot()["total_trips"], 1)
        self.assertEqual(breaker.snapshot()["total_requests"], 2)
        self.assertEqual(breaker.snapshot()["total_failures"], 2)

        # Reset with default reset_metrics=True
        breaker.reset(reset_metrics=True)
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        snap2 = breaker.snapshot()
        self.assertEqual(snap2["total_requests"], 0)
        self.assertEqual(snap2["total_failures"], 0)
        self.assertEqual(snap2["total_trips"], 0)
        self.assertEqual(snap2["consecutive_failures"], 0)

    def test_circuit_breaker_registry_clear_and_reset_clear_isolation(self) -> None:
        """Verify clear_circuit_breakers() and reset_circuit_breakers(clear=True) remove instances."""
        b1 = get_circuit_breaker("custom_breaker_1", failure_threshold=10, recovery_timeout=120.0)
        self.assertEqual(b1.failure_threshold, 10)
        self.assertEqual(b1.recovery_timeout, 120.0)

        # clear_circuit_breakers removes instances
        clear_circuit_breakers()
        b2 = get_circuit_breaker("custom_breaker_1", failure_threshold=2, recovery_timeout=15.0)
        self.assertEqual(b2.failure_threshold, 2)
        self.assertEqual(b2.recovery_timeout, 15.0)

        # reset_circuit_breakers(clear=True) on specific breaker
        reset_circuit_breakers("custom_breaker_1", clear=True)
        b3 = get_circuit_breaker("custom_breaker_1", failure_threshold=4, recovery_timeout=45.0)
        self.assertEqual(b3.failure_threshold, 4)

    def test_challenge_concurrent_circuit_breaker_consecutive_loopback_invariance(self) -> None:
        """Verify that consecutive in-process runs of 50-thread burst do not accumulate trip count."""
        breaker_name = "loopback_invariance_breaker"

        for cycle in (1, 2):
            reset_circuit_breakers(clear=True)
            breaker = get_circuit_breaker(breaker_name, failure_threshold=5, recovery_timeout=60.0)
            mock_opener = MagicMock()
            mock_opener.side_effect = urllib.error.HTTPError("http://burst", 503, "Unavailable", {}, None)

            num_threads = 20
            barrier = threading.Barrier(num_threads)

            def worker():
                barrier.wait()
                try:
                    urlopen_with_retry(
                        "http://burst",
                        max_retries=0,
                        circuit_breaker_name=breaker_name,
                        opener=mock_opener,
                    )
                except Exception as e:
                    return e

            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(worker) for _ in range(num_threads)]
                _ = [f.result() for f in futures]

            self.assertEqual(breaker.state, CircuitState.OPEN)
            snap = breaker.snapshot()
            self.assertEqual(
                snap["total_trips"],
                1,
                f"Cycle {cycle}: total_trips must be 1, found {snap['total_trips']}",
            )


if __name__ == "__main__":
    unittest.main()

