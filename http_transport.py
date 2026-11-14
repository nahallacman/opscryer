# SPDX-License-Identifier: Apache-2.0
"""Resilient HTTP transport with exponential backoff, jitter, and circuit breaking."""

from __future__ import annotations

from enum import Enum
import math
import random
import threading
import time
from typing import Any, Callable
import urllib.error
from urllib.request import Request, urlopen

RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 502, 503, 504})
NON_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({400, 401, 403, 404, 405, 410, 422})

__all__ = [
    "RETRYABLE_STATUS_CODES",
    "NON_RETRYABLE_STATUS_CODES",
    "CircuitState",
    "CircuitBreakerOpenError",
    "HTTPResponseBytes",
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "get_circuit_breaker",
    "reset_circuit_breakers",
    "clear_circuit_breakers",
    "urlopen_with_retry",
]


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenError(urllib.error.URLError):
    """Raised when an HTTP call is blocked because the Circuit Breaker is OPEN.

    Subclasses URLError (and OSError) so existing callers catching URLError
    or OSError catch it cleanly while allowing specific inspection.
    """

    def __init__(self, breaker_name: str, cooldown_remaining: float):
        self.breaker_name = breaker_name
        self.cooldown_remaining = max(0.0, float(cooldown_remaining))
        super().__init__(
            f"Circuit breaker '{breaker_name}' is OPEN. "
            f"Failing fast to protect upstream service. "
            f"Cooldown remaining: {self.cooldown_remaining:.2f}s"
        )


class HTTPResponseBytes(bytes):
    """Bytes container supporting .read() and context manager protocols."""

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            return bytes(self)
        return bytes(self[:amt])

    def __enter__(self) -> HTTPResponseBytes:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


def _publish_event_safe(topic: str, event_type: str, data: dict[str, Any] | None = None) -> None:
    try:
        from event_stream import publish_event
        publish_event(topic, event_type, data)
    except Exception:
        pass


class CircuitBreaker:
    """Lightweight in-memory thread-safe circuit breaker."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
    ):
        self.name = name
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_timeout = max(0.01, float(recovery_timeout))
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float = 0.0
        self._total_requests = 0
        self._total_failures = 0
        self._total_trips = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._opened_at
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    _publish_event_safe("security", "circuit_breaker_transition", {
                        "name": self.name, "from_state": "open", "to_state": "half_open"
                    })
            return self._state

    def allow_request(self) -> bool:
        """Check if request is allowed through; raises CircuitBreakerOpenError if OPEN."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._opened_at
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    _publish_event_safe("security", "circuit_breaker_transition", {
                        "name": self.name, "from_state": "open", "to_state": "half_open"
                    })
                else:
                    raise CircuitBreakerOpenError(self.name, self.recovery_timeout - elapsed)
            self._total_requests += 1
            return True

    def record_success(self) -> None:
        """Record successful call, resetting failure counters and closing circuit."""
        with self._lock:
            prev_state = self._state
            self._consecutive_failures = 0
            self._state = CircuitState.CLOSED
            if prev_state != CircuitState.CLOSED:
                _publish_event_safe("security", "circuit_breaker_transition", {
                    "name": self.name, "from_state": prev_state.value, "to_state": "closed"
                })

    def record_failure(self, error: BaseException | None = None) -> None:
        """Record failed call; trip circuit to OPEN if consecutive failures exceed threshold."""
        with self._lock:
            self._total_failures += 1
            self._consecutive_failures += 1
            if self._state == CircuitState.HALF_OPEN or self._consecutive_failures >= self.failure_threshold:
                prev_state = self._state
                if self._state != CircuitState.OPEN:
                    self._total_trips += 1
                self._state = CircuitState.OPEN
                self._opened_at = time.time()
                if prev_state != CircuitState.OPEN:
                    _publish_event_safe("security", "circuit_breaker_transition", {
                        "name": self.name,
                        "from_state": prev_state.value,
                        "to_state": "open",
                        "consecutive_failures": self._consecutive_failures,
                        "failure_threshold": self.failure_threshold,
                    })

    def reset(self, reset_metrics: bool = True) -> None:
        """Manually reset circuit breaker to initial CLOSED state and optionally zero telemetry.

        Parameters:
        - reset_metrics: If True (default), resets cumulative telemetry counters
          (_total_requests, _total_failures, _total_trips) to 0. If False,
          retains cumulative telemetry while restoring state to CLOSED.
        """
        with self._lock:
            self._state = CircuitState.CLOSED
            self._consecutive_failures = 0
            self._opened_at = 0.0
            if reset_metrics:
                self._total_requests = 0
                self._total_failures = 0
                self._total_trips = 0

    def snapshot(self) -> dict[str, Any]:
        """Return diagnostic metrics snapshot."""
        with self._lock:
            remaining = 0.0
            if self._state == CircuitState.OPEN:
                remaining = max(0.0, self.recovery_timeout - (time.time() - self._opened_at))
            return {
                "name": self.name,
                "state": self._state.value,
                "consecutive_failures": self._consecutive_failures,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "total_requests": self._total_requests,
                "total_failures": self._total_failures,
                "total_trips": self._total_trips,
                "cooldown_remaining_seconds": round(remaining, 2),
            }


class CircuitBreakerRegistry:
    """Thread-safe registry of named CircuitBreaker instances."""

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
    ) -> CircuitBreaker:
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(
                    name=name,
                    failure_threshold=failure_threshold,
                    recovery_timeout=recovery_timeout,
                )
            return self._breakers[name]

    def clear(self) -> None:
        """Remove all registered circuit breaker instances from the registry."""
        with self._lock:
            self._breakers.clear()

    def reset(
        self,
        name: str | None = None,
        *,
        reset_metrics: bool = True,
        clear: bool = False,
    ) -> None:
        """Reset or clear registered circuit breakers.

        Parameters:
        - name: Optional breaker name. If None, applies to all registered breakers.
        - reset_metrics: If True (default), zeroes cumulative telemetry counters.
        - clear: If True, removes breaker instance(s) from registry instead of resetting in place.
        """
        with self._lock:
            if clear:
                if name is None:
                    self._breakers.clear()
                elif name in self._breakers:
                    del self._breakers[name]
                return
            if name is None:
                for breaker in self._breakers.values():
                    breaker.reset(reset_metrics=reset_metrics)
            elif name in self._breakers:
                self._breakers[name].reset(reset_metrics=reset_metrics)

    def get_all_snapshots(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {name: b.snapshot() for name, b in self._breakers.items()}


_GLOBAL_REGISTRY = CircuitBreakerRegistry()


def get_circuit_breaker(name: str, **kwargs: Any) -> CircuitBreaker:
    return _GLOBAL_REGISTRY.get_or_create(name, **kwargs)


def reset_circuit_breakers(
    name: str | None = None,
    *,
    reset_metrics: bool = True,
    clear: bool = False,
) -> None:
    """Reset or clear global circuit breaker instances.

    Parameters:
    - name: Optional breaker name. If None, applies to all registered breakers.
    - reset_metrics: If True (default), resets cumulative telemetry counters.
    - clear: If True, removes breaker instance(s) from registry.
    """
    _GLOBAL_REGISTRY.reset(name, reset_metrics=reset_metrics, clear=clear)


def clear_circuit_breakers() -> None:
    """Clear all registered circuit breakers from the global registry."""
    _GLOBAL_REGISTRY.clear()


def urlopen_with_retry(
    request: Request | str,
    timeout: float = 5.0,
    max_retries: int = 3,
    backoff_factor: float = 0.2,
    circuit_breaker_name: str | None = None,
    *,
    opener: Callable[..., Any] = urlopen,
    sleep_fn: Callable[[float], None] = time.sleep,
    jitter: bool = True,
) -> HTTPResponseBytes:
    """Execute HTTP request with exponential backoff, jitter, and circuit breaking.

    Parameters:
    - request: urllib.request.Request or URL string.
    - timeout: Socket timeout in seconds per attempt.
    - max_retries: Number of retry attempts after initial failure (total attempts: 1 + max_retries).
    - backoff_factor: Base backoff multiplier (delays: 0.2s, 0.4s, 0.8s for factor=0.2).
    - circuit_breaker_name: Optional circuit breaker key (e.g. 'ollama', 'prometheus').
    - opener: Injectable urlopen function (defaults to urllib.request.urlopen; allows test mocks).
    - sleep_fn: Injectable timer sleep callable (allows fast mock timer testing).
    - jitter: Whether to apply randomized additive jitter.

    Returns:
    - HTTPResponseBytes (bytes subclass supporting .read() and context managers).

    Raises:
    - CircuitBreakerOpenError: When circuit breaker is OPEN.
    - urllib.error.HTTPError: On non-retryable 4xx or exhausted 5xx.
    - urllib.error.URLError / OSError: On network exhaustion.
    """
    if isinstance(request, str):
        req_obj = Request(request)
    else:
        req_obj = request

    breaker = get_circuit_breaker(circuit_breaker_name) if circuit_breaker_name else None
    attempts = max(0, int(max_retries)) + 1
    last_error: BaseException | None = None

    for attempt in range(attempts):
        if breaker:
            breaker.allow_request()

        try:
            with opener(req_obj, timeout=timeout) as response:
                body = response.read() if hasattr(response, "read") else response
                if breaker:
                    breaker.record_success()
                return HTTPResponseBytes(body if isinstance(body, (bytes, bytearray)) else b"")
        except urllib.error.HTTPError as err:
            last_error = err
            # Non-retryable client errors (400, 401, 403, 404, etc.) fail fast immediately
            if err.code in NON_RETRYABLE_STATUS_CODES:
                raise err

            # Retryable server status codes (429, 502, 503, 504) or unclassified 5xx
            is_retryable = (err.code in RETRYABLE_STATUS_CODES) or (500 <= err.code <= 599)
            if not is_retryable or attempt >= attempts - 1:
                if breaker:
                    breaker.record_failure(err)
                raise err

            # Calculate backoff delay with jitter
            base_delay = backoff_factor * (2 ** attempt)
            jitter_offset = random.uniform(0.0, 0.1 * base_delay) if jitter else 0.0
            sleep_fn(base_delay + jitter_offset)

        except urllib.error.URLError as err:
            last_error = err
            # Malformed URL schemes / ValueError wrapped in URLError fail fast immediately
            if isinstance(getattr(err, "reason", None), ValueError):
                raise err

            if attempt >= attempts - 1:
                if breaker:
                    breaker.record_failure(err)
                raise err

            base_delay = backoff_factor * (2 ** attempt)
            jitter_offset = random.uniform(0.0, 0.1 * base_delay) if jitter else 0.0
            sleep_fn(base_delay + jitter_offset)

        except (TimeoutError, OSError) as err:
            last_error = err
            if attempt >= attempts - 1:
                if breaker:
                    breaker.record_failure(err)
                raise err

            base_delay = backoff_factor * (2 ** attempt)
            jitter_offset = random.uniform(0.0, 0.1 * base_delay) if jitter else 0.0
            sleep_fn(base_delay + jitter_offset)

    if last_error is not None:
        raise last_error
    raise RuntimeError("Unexpected retry loop termination")
