# SPDX-License-Identifier: Apache-2.0
"""Wave capability registration and showcase scorecard failure handling."""

from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

import epic_showcase_verifier as verifier
import opscryer_showcase as showcase


class EpicShowcaseVerifierTests(unittest.TestCase):
    def test_wave_suites_extend_existing_checks_without_recursion(self):
        registered = [name for modules in verifier.EPIC_TESTS.values() for name in modules]
        for name in ("live_metrics_poller", "environment_adapters", "scale_benchmark"):
            self.assertEqual(registered.count("tests.test_" + name), 1)
        self.assertNotIn(__name__, registered)
        self.assertNotIn("tests.test_opscryer_showcase", registered)
        for epic, modules in showcase.EPIC_TESTS.items():
            self.assertTrue(set(modules) <= set(verifier.EPIC_TESTS[epic]))
        self.assertNotIn("tests.test_live_metrics_poller", showcase.EPIC_TESTS["EPIC-5"])

    def test_wave_capability_suites_pass(self):
        modules = verifier.EPIC_TESTS["EPIC-5"][len(showcase.EPIC_TESTS["EPIC-5"]):]
        result = verifier._run_epic("Wave 1–4", modules)
        self.assertTrue(result["passed"], result)
        self.assertGreater(result["tests_run"], 0)

    def test_scorecard_requires_every_epic_and_both_acts(self):
        for failed in (None, "EPIC-5", "act_2"):
            def run(epic, modules):
                return {"epic_id": epic, "passed": epic != failed}

            with self.subTest(failed=failed), patch.object(
                    verifier, "_run_epic", side_effect=run) as checks, patch.object(
                    verifier, "verify_act", side_effect=lambda act: {
                        "act": act, "passed": not (failed == "act_2" and act == 2)}):
                report = verifier.verify_all_epics()
            self.assertEqual(report["passed"], failed is None)
            self.assertEqual(report["epics_verified"], 8 if failed == "EPIC-5" else 9)
            self.assertEqual(checks.call_count, 9)
            self.assertEqual(checks.call_args_list[4].args[1], verifier.EPIC_TESTS["EPIC-5"])

    def test_cli_json_and_exit_status(self):
        for passed in (True, False):
            report = {"passed": passed, "epics_verified": 9 if passed else 8}
            with patch.object(verifier, "verify_all_epics", return_value=report), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(verifier.main(["--json"]), 0 if passed else 1)
            self.assertEqual(json.loads(output.getvalue()), report)


if __name__ == "__main__":
    unittest.main()
