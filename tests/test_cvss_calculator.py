#!/usr/bin/env python3
"""Tests for WSHawk CVSS Calculator."""

import unittest

from wshawk.cvss_calculator import CVSSCalculator, CVSSScore


class CVSSCalculatorTests(unittest.TestCase):
    VALID_SEVERITIES = {"None", "Low", "Medium", "High", "Critical"}

    def setUp(self):
        self.calc = CVSSCalculator()

    def test_score_between_0_and_10(self):
        vuln_types = [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "XXE",
            "SSRF",
            "Path Traversal",
            "NoSQL Injection",
        ]
        for vuln_type in vuln_types:
            for confidence in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                score = self.calc.calculate_for_vulnerability(vuln_type, confidence)
                self.assertGreaterEqual(score.base_score, 0.0)
                self.assertLessEqual(score.base_score, 10.0)

    def test_severity_labels_follow_cvss_bands(self):
        score = self.calc.calculate_for_vulnerability("SQL Injection", "HIGH")
        self.assertIn(score.severity, self.VALID_SEVERITIES)
        self.assertEqual(self.calc._get_severity(0.0), "None")
        self.assertEqual(self.calc._get_severity(3.9), "Low")
        self.assertEqual(self.calc._get_severity(5.0), "Medium")
        self.assertEqual(self.calc._get_severity(7.5), "High")
        self.assertEqual(self.calc._get_severity(9.5), "Critical")

    def test_vector_contains_expected_metrics(self):
        score = self.calc.calculate_for_vulnerability("Command Injection", "HIGH")
        self.assertTrue(score.vector_string.startswith("CVSS:3.1/"))
        for metric in ["AV:", "AC:", "PR:", "UI:", "S:", "C:", "I:", "A:"]:
            self.assertIn(metric, score.vector_string)

    def test_vulnerability_type_ranges_are_reasonable(self):
        sql_score = self.calc.calculate_for_vulnerability("SQL Injection", "CRITICAL")
        cmd_score = self.calc.calculate_for_vulnerability("Command Injection", "CRITICAL")
        path_score = self.calc.calculate_for_vulnerability("Path Traversal", "HIGH")
        xss_score = self.calc.calculate_for_vulnerability("Cross-Site Scripting (XSS)", "MEDIUM")
        unknown_score = self.calc.calculate_for_vulnerability("UnknownVulnType", "MEDIUM")

        self.assertGreaterEqual(sql_score.base_score, 7.0)
        self.assertGreaterEqual(cmd_score.base_score, 7.0)
        self.assertLessEqual(path_score.base_score, cmd_score.base_score)
        self.assertIn("UI:R", xss_score.vector_string)
        self.assertGreaterEqual(unknown_score.base_score, 0.0)
        self.assertLessEqual(unknown_score.base_score, 10.0)

    def test_returns_cvss_score_dataclass(self):
        score = self.calc.calculate_for_vulnerability("XXE", "HIGH")
        self.assertIsInstance(score, CVSSScore)
        self.assertIsInstance(score.breakdown, dict)
        self.assertIn("AV", score.breakdown)


if __name__ == "__main__":
    unittest.main()
