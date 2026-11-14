# SPDX-License-Identifier: Apache-2.0
"""Fast deterministic unit test runner with optional slow/E2E test selection."""

from __future__ import annotations

import argparse
import json
import os
from time import perf_counter
from typing import Any
import unittest


FAST_TEST_MODULES: tuple[str, ...] = (
    "tests.test_opscryer_config",
    "tests.test_http_transport",
    "tests.test_piece_b_bridge",
    "tests.test_system_context",
    "tests.test_knowledge_base",
    "tests.test_jev_client",
    "tests.test_jev_calibration_eval",
    "tests.test_security_airlock",
    "tests.test_route_registry",
    "tests.test_ui_theme",
    "tests.test_gpu_and_household_triage",
    "tests.test_prometheus_loki_adapter",
    "tests.test_jev_tree_author",
    "tests.test_telemetry_sanitizer",
    "tests.test_dogfood_graph",
    "tests.test_lifecycle_probes",
    "tests.test_metrics_exporter",
    "tests.test_webhook_notifier",
    "tests.test_environment_adapters",
    "tests.test_pqc_security",
    "tests.test_action_cards",
    "tests.test_event_stream",
    "tests.test_cybersecurity_bridge",
    "tests.test_node_federation",
    "tests.test_mcp_bridge",
    "tests.test_tier5_adversarial_transport",
    "tests.test_tier5_adversarial_extensibility",
    "tests.test_e2e_wave2_autonomous_security_federation",
    "tests.test_gitops_promotion_bridge",
    "tests.test_tactical_security_deck",
    "tests.test_itsm_chatops_bridge",
    "tests.test_flight_recorder",
    "tests.test_e2e_wave3_gitops_tactical_itsm_replay",
)

SLOW_E2E_TEST_MODULES: tuple[str, ...] = (
    "tests.test_live_e2e_runner",
    "tests.test_demo_rehearsal",
    "tests.test_epic_showcase_verifier",
    "tests.test_opscryer_showcase",
)


def should_run_slow_tests(include_slow: bool = False) -> bool:
    """Return True when slow E2E tests are requested via argument or environment."""
    if include_slow is True:
        return True
    return os.environ.get("OPSCRYER_SLOW_TESTS", "").strip() == "1"


def select_test_modules(include_slow: bool = False) -> list[str]:
    """Return the ordered list of test modules for the selected speed tier."""
    modules = list(FAST_TEST_MODULES)
    if should_run_slow_tests(include_slow):
        modules.extend(SLOW_E2E_TEST_MODULES)
    return modules


def run_fast_test_suite(include_slow: bool = False) -> dict[str, Any]:
    """Execute the selected test modules in-process and return a JSON summary."""
    started = perf_counter()
    modules = select_test_modules(include_slow=include_slow)
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for mod in modules:
        suite.addTests(loader.loadTestsFromName(mod))
    runner = unittest.TextTestRunner(stream=open(os.devnull, "w", encoding="utf-8"), verbosity=0)
    try:
        result = runner.run(suite)
    finally:
        runner.stream.close()
    elapsed_ms = round((perf_counter() - started) * 1000.0, 2)
    return {
        "schema_version": "1.0-fast-test-runner",
        "mode": "full_with_slow" if should_run_slow_tests(include_slow) else "fast_unit_only",
        "modules_selected": modules,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "failure_details": [{"test": str(f[0]), "error": str(f[1])} for f in result.failures],
        "error_details": [{"test": str(e[0]), "error": str(e[1])} for e in result.errors],
        "passed": result.wasSuccessful() and result.testsRun > 0,
        "elapsed_ms": elapsed_ms,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slow", action="store_true", help="Include slow loopback E2E suites")
    parser.add_argument("--list", action="store_true", help="List selected test modules without running")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    args = parser.parse_args(argv)
    if args.list:
        payload = {
            "mode": "full_with_slow" if should_run_slow_tests(args.slow) else "fast_unit_only",
            "modules": select_test_modules(args.slow),
        }
        print(json.dumps(payload, indent=2))
        return 0
    report = run_fast_test_suite(include_slow=args.slow)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
