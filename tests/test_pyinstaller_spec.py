import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_pyinstaller_hiddenimports.py"
SPEC_PATH = REPO_ROOT / "wshawk-bridge.spec"


class PyInstallerSpecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("verify_pyinstaller_hiddenimports", SCRIPT_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        cls.module = module

    def test_desktop_hidden_imports_are_available(self):
        declared = self.module.declared_hidden_imports(SPEC_PATH)

        self.assertGreater(len(declared), 20)
        self.assertEqual(self.module.unavailable_hidden_imports(SPEC_PATH), [])

    def test_invalid_hidden_import_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "invalid.spec"
            spec_path.write_text("base_hiddenimports = ['module_that_does_not_exist_12345']\n", encoding="utf-8")

            unavailable = self.module.unavailable_hidden_imports(spec_path)

        self.assertEqual(unavailable, ["module_that_does_not_exist_12345"])


if __name__ == "__main__":
    unittest.main()
