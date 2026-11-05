# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the fast test suite selector and runner."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from test_runner_fast import (
    FAST_TEST_MODULES,
    SLOW_E2E_TEST_MODULES,
     select_test_modules,
    should_run_slow_tests,
)


class FastTestRunnerTests(unittest.TestCase):
    def test_default_selection_excludes_slow_e2e_modules(self) -> None:
        with patch.dict(os.environ, {"OPSCRYER_SLOW_TESTS": "0"}, clear=False):
            self.assertFalse(should_run_slow_tests(False))
            selected = select_test_modules(False)
            self.assertEqual(selected, list(FAST_TEST_MODULES))
            for slow in SLOW_E2E_TEST_MODULES:
                self.assertNotIn(slow, selected)

    def test_slow_flag_or_env_var_includes_slow_modules(self) -> None:
        self.assertTrue(should_run_slow_tests(True))
        selected = select_test_modules(True)
        for slow in SLOW_E2E_TEST_MODULES:
            self.assertIn(slow, selected)
        with patch.dict(os.environ, {"OPSCRYER_SLOW_TESTS": "1"}, clear=False):
            self.assertTrue(should_run_slow_tests(False))
            self.assertEqual(select_test_modules(False), selected)


if __name__ == "__main__":
    unittest.main()
