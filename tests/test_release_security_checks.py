import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "release_security_checks.py"


class ReleaseSecurityChecksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("release_security_checks", SCRIPT_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        cls.module = module

    def test_release_security_report_has_no_remote_asset_findings(self):
        report = self.module.run_checks()
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["remote_asset_findings"], [])
        self.assertGreater(report["repro_manifest"]["entry_count"], 0)
        self.assertTrue(report["python_sbom"])
        self.assertTrue(report["node_sbom"])


if __name__ == "__main__":
    unittest.main()
