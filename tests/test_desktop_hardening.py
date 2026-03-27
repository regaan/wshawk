import unittest
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class DesktopHardeningTests(unittest.TestCase):
    def test_desktop_uses_sandbox_and_strict_script_csp(self):
        content = (REPO_ROOT / "desktop" / "index.js").read_text(encoding="utf-8")
        self.assertIn("app.enableSandbox()", content)
        self.assertIn("sandbox: !WSHAWK_E2E_NO_SANDBOX", content)
        self.assertIn("\"script-src 'self'\"", content)
        self.assertNotIn("\"script-src 'self' 'unsafe-inline'\"", content)

    def test_desktop_renderer_contains_no_inline_event_handlers(self):
        for path in (REPO_ROOT / "desktop" / "src").rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".html", ".js"}:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn("onclick=", content, str(path))
            self.assertNotIn("onchange=", content, str(path))
            self.assertNotIn("oninput=", content, str(path))
            self.assertNotIn("onsubmit=", content, str(path))

    def test_desktop_smoke_mode_and_runner_are_wired(self):
        index_content = (REPO_ROOT / "desktop" / "index.js").read_text(encoding="utf-8")
        self.assertIn("WSHAWK_DESKTOP_SMOKE", index_content)
        self.assertIn("writeDesktopSmokeSnapshot", index_content)
        self.assertIn("captureDesktopSmokeSnapshot", index_content)

        smoke_script = REPO_ROOT / "desktop" / "scripts" / "smoke-check.js"
        self.assertTrue(smoke_script.exists())

        package_json = json.loads((REPO_ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package_json["scripts"]["smoke"], "node scripts/smoke-check.js")


if __name__ == "__main__":
    unittest.main()
