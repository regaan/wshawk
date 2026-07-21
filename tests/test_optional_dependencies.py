import builtins
import importlib
import sys
import unittest
from unittest.mock import patch


class OptionalDependencyTests(unittest.TestCase):
    def test_dom_invader_imports_without_playwright(self):
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == "playwright" or name.startswith("playwright."):
                raise ImportError("Playwright intentionally unavailable for test")
            return original_import(name, *args, **kwargs)

        module_names = (
            "wshawk.dom_invader",
            "wshawk.dom_auth",
            "wshawk.dom_xss",
            "wshawk.dom_browser",
            "wshawk.dom_models",
            "wshawk.dom_runtime",
        )
        previous_modules = {
            name: sys.modules.pop(name)
            for name in module_names
            if name in sys.modules
        }
        try:
            with patch("builtins.__import__", side_effect=guarded_import):
                module = importlib.import_module("wshawk.dom_invader")

            self.assertFalse(module.HAS_PLAYWRIGHT)
            self.assertIsNone(module.async_playwright)
        finally:
            for name in module_names:
                sys.modules.pop(name, None)
            sys.modules.update(previous_modules)


if __name__ == "__main__":
    unittest.main()
