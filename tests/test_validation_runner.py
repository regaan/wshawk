import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from validation.common import REDACTION_MARKER, redact_artifact_data
from validation.run_validation import run_lab, run_labs


class ValidationRunnerTests(unittest.TestCase):
    def test_recursive_redaction_masks_sensitive_fields_and_references(self):
        raw = {
            "authorization": "Bearer bearer-secret-1234",
            "headers": {"Set-Cookie": "session_id=cookie-secret-5678; Path=/; HttpOnly"},
            "artifacts": {
                "approval_token": "approve-beta-9001",
                "message": "Approval token approve-beta-9001 approved.",
                "url": "wss://example.test/ws?token=query-secret-9012&channel=ops",
                "approval_token_reused": True,
            },
        }

        redacted = redact_artifact_data(raw)
        serialized = json.dumps(redacted)

        self.assertEqual(redacted["authorization"], REDACTION_MARKER)
        self.assertEqual(redacted["headers"]["Set-Cookie"], REDACTION_MARKER)
        self.assertEqual(redacted["artifacts"]["approval_token"], REDACTION_MARKER)
        self.assertEqual(redacted["artifacts"]["message"], f"Approval token {REDACTION_MARKER} approved.")
        self.assertIn(f"token={REDACTION_MARKER}", redacted["artifacts"]["url"])
        self.assertTrue(redacted["artifacts"]["approval_token_reused"])
        for secret in ("bearer-secret-1234", "cookie-secret-5678", "approve-beta-9001", "query-secret-9012"):
            self.assertNotIn(secret, serialized)

    def test_run_lab_evaluates_raw_result_but_persists_only_redacted_data(self):
        raw_result = {
            "lab": "full_stack_realtime_saas",
            "checks": {"token_matches": True},
            "summary": {"status": "passed"},
            "artifacts": {
                "approval_token": "approve-beta-9001",
                "message": "Replayed approve-beta-9001 successfully.",
            },
        }
        expected = {"required_checks": {"token_matches": True}}

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "artifacts"
            with (
                patch("validation.run_validation.load_scenario_runner", return_value=lambda: raw_result),
                patch("validation.run_validation.load_expected", return_value=expected),
            ):
                bundle = run_lab("full_stack_realtime_saas", artifact_root=root)

            result_text = (root / "full_stack_realtime_saas" / "result.json").read_text(encoding="utf-8")
            bundle_text = (root / "full_stack_realtime_saas" / "bundle.json").read_text(encoding="utf-8")

        self.assertTrue(bundle["evaluation"]["passed"])
        self.assertEqual(bundle["result"]["artifacts"]["approval_token"], REDACTION_MARKER)
        self.assertNotIn("approve-beta-9001", result_text)
        self.assertNotIn("approve-beta-9001", bundle_text)
        self.assertIn(REDACTION_MARKER, result_text)

    def test_runner_writes_artifacts_and_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "artifacts"
            summary = run_labs(["full_stack_realtime_saas"], artifact_root=root)

            self.assertTrue(summary["overall_passed"])
            self.assertTrue((root / "summary.json").exists())
            self.assertTrue((root / "full_stack_realtime_saas" / "result.json").exists())
            self.assertTrue((root / "full_stack_realtime_saas" / "evaluation.json").exists())
            self.assertTrue((root / "full_stack_realtime_saas" / "bundle.json").exists())


if __name__ == "__main__":
    unittest.main()
