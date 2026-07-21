import tempfile
import unittest
from pathlib import Path

from validation.run_validation import run_labs


class SecurityAttackBenchmarkLabTests(unittest.TestCase):
    def test_attack_benchmarks_match_expected_baselines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_root = Path(temp_dir) / "artifacts"
            summary = run_labs(
                [
                    "web_attack_benchmark",
                    "websocket_attack_benchmark",
                    "industry_security_controls_benchmark",
                ],
                artifact_root=artifact_root,
            )

            self.assertTrue(summary["overall_passed"])
            self.assertEqual(len(summary["labs"]), 3)
            for lab in summary["labs"]:
                self.assertTrue(lab["passed"], lab)
                self.assertGreater(lab["summary"]["checks_passed"], 0)
                self.assertGreater(lab["summary"]["total_timed_ms"], 0)
                self.assertTrue((artifact_root / lab["lab"] / "bundle.json").exists())


if __name__ == "__main__":
    unittest.main()
