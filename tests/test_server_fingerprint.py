#!/usr/bin/env python3
"""Tests for WSHawk Server Fingerprinter."""

import unittest

from wshawk.server_fingerprint import ServerFingerprint, ServerFingerprinter


class ServerFingerprinterTests(unittest.TestCase):
    def setUp(self):
        self.fingerprinter = ServerFingerprinter()

    def test_language_detection(self):
        self.fingerprinter.add_response('Traceback (most recent call last):\n  File "app.py", line 42')
        self.assertEqual(self.fingerprinter.fingerprint().language, "python")

        fingerprinter = ServerFingerprinter()
        fingerprinter.add_response("Error: Cannot read property\n    at Object.<anonymous> (/app/server.js:15:3)")
        self.assertEqual(fingerprinter.fingerprint().language, "nodejs")

        fingerprinter = ServerFingerprinter()
        fingerprinter.add_response("java.lang.NullPointerException\n\tat com.app.Main.run(Main.java:15)")
        self.assertEqual(fingerprinter.fingerprint().language, "java")

    def test_fingerprint_structure_and_ranges(self):
        self.fingerprinter.add_response("test")
        fingerprint = self.fingerprinter.fingerprint()
        self.assertIsInstance(fingerprint, ServerFingerprint)
        self.assertTrue(hasattr(fingerprint, "language"))
        self.assertTrue(hasattr(fingerprint, "framework"))
        self.assertTrue(hasattr(fingerprint, "database"))
        self.assertTrue(hasattr(fingerprint, "libraries"))
        self.assertTrue(hasattr(fingerprint, "confidence"))
        self.assertGreaterEqual(fingerprint.confidence, 0.0)
        self.assertLessEqual(fingerprint.confidence, 1.0)
        self.assertIsInstance(fingerprint.libraries, list)

    def test_payload_recommendations_and_info(self):
        self.fingerprinter.add_response('Traceback (most recent call last):\ndjango')
        fingerprint = self.fingerprinter.fingerprint()
        recommendations = self.fingerprinter.get_recommended_payloads(fingerprint)
        self.assertIsInstance(recommendations, (list, dict))
        self.assertIsInstance(self.fingerprinter.get_info(), dict)


if __name__ == "__main__":
    unittest.main()
