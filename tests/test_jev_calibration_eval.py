# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Jev calibration benchmark, ECE/Brier/F1 metrics, and /jev-eval portal."""

import unittest

import jev_calibration_eval as jev_eval


class JevCalibrationEvalTests(unittest.TestCase):
    def test_labeled_eval_set_has_at_least_40_examples_and_high_accuracy(self):
        self.assertGreaterEqual(len(jev_eval.LABELED_JEV_EVAL_SET), 40)
        report = jev_eval.evaluate_jev_calibration_benchmark("deterministic")
        self.assertEqual(report["total_examples"], len(jev_eval.LABELED_JEV_EVAL_SET))
        self.assertGreaterEqual(report["policy_accuracy"], 0.90)
        self.assertGreaterEqual(report["macro_f1"], 0.85)
        self.assertGreaterEqual(report["expected_calibration_error_ece"], 0.0)
        self.assertLessEqual(report["expected_calibration_error_ece"], 1.0)
        self.assertGreaterEqual(report["brier_score"], 0.0)
        self.assertLessEqual(report["brier_score"], 1.0)
        self.assertEqual(len(report["per_predicate_metrics"]), 7)

    def test_markdown_and_html_render_cleanly_without_unsafe_sinks(self):
        md = jev_eval.render_jev_eval_markdown()
        self.assertIn("System-1 Jev Calibration & Routing Accuracy Benchmark", md)
        self.assertIn("`is_database_provisioning`", md)
        html = jev_eval.render_jev_eval_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn('id="jev-eval-predicate-table"', html)
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(unsafe, html)

    def test_invalid_provider_raises_value_error(self):
        with self.assertRaises(ValueError):
            jev_eval.evaluate_jev_calibration_benchmark("unsupported-provider")


if __name__ == "__main__":
    unittest.main()
