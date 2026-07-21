import importlib.util
import unittest
from pathlib import Path

from wshawk._version_info import __version__


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
        self.assertEqual(report["version_consistency"]["canonical"], __version__)
        self.assertEqual(report["version_consistency"]["mismatches"], [])
        self.assertEqual(report["unpinned_workflow_actions"], [])
        self.assertGreater(report["repro_manifest"]["entry_count"], 0)
        self.assertTrue(report["python_sbom"])
        self.assertTrue(report["node_sbom"])

    def test_repro_manifest_excludes_generated_and_mutable_paths(self):
        ignored = [
            Path(".mypy_cache/3.10/cache.db"),
            Path("desktop/bin/wshawk-bridge.exe"),
            Path("validation/artifacts/summary.json"),
            Path("wshawk.egg-info/PKG-INFO"),
        ]

        for path in ignored:
            with self.subTest(path=path):
                self.assertTrue(self.module.should_ignore_manifest_path(path))

        self.assertFalse(self.module.should_ignore_manifest_path(Path("wshawk/scanner_v2.py")))


if __name__ == "__main__":
    unittest.main()
