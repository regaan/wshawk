#!/usr/bin/env python3
"""Tests for WSHawk WAF Detector."""

import unittest

from wshawk.waf.detector import WAFDetector


class WAFDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = WAFDetector()

    def test_detects_known_wafs(self):
        self.assertEqual(self.detector.detect({"cf-ray": "abc123"}, "").name, "Cloudflare")
        self.assertEqual(self.detector.detect({}, "Blocked by Cloudflare security").name, "Cloudflare")
        self.assertEqual(self.detector.detect({"x-akamai-session": "123"}, "").name, "Akamai")
        self.assertEqual(self.detector.detect({}, "Request blocked by Imperva Incapsula").name, "Imperva")
        self.assertEqual(self.detector.detect({}, "Blocked by mod_security rule 942100").name, "ModSecurity")

    def test_returns_none_for_clean_responses(self):
        result = self.detector.detect({"content-type": "application/json"}, '{"status": "ok"}')
        self.assertIsNone(result)

    def test_detection_is_case_insensitive_and_exposes_metadata(self):
        result = self.detector.detect({"CF-RAY": "abc123"}, "")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "Cloudflare")
        self.assertTrue(hasattr(result, "recommended_strategy"))
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)


if __name__ == "__main__":
    unittest.main()
