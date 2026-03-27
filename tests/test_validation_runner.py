import tempfile
import unittest
from pathlib import Path

from validation.run_validation import run_labs


class ValidationRunnerTests(unittest.TestCase):
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
