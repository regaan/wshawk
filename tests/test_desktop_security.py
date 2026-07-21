import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def version_tuple(value: str):
    return tuple(int(part) for part in value.split(".")[:3])


class DesktopSecurityTests(unittest.TestCase):
    def test_patched_runtime_dependency_versions_are_locked(self):
        lock = json.loads((REPO_ROOT / "desktop" / "package-lock.json").read_text(encoding="utf-8"))
        packages = lock["packages"]

        self.assertGreaterEqual(version_tuple(packages["node_modules/electron"]["version"]), (43, 1, 1))
        self.assertGreaterEqual(version_tuple(packages["node_modules/engine.io-client"]["version"]), (6, 6, 6))
        self.assertGreaterEqual(version_tuple(packages["node_modules/socket.io-parser"]["version"]), (4, 2, 6))
        self.assertGreaterEqual(version_tuple(packages["node_modules/ws"]["version"]), (8, 21, 0))

    def test_electron_renderer_security_flags_remain_enabled(self):
        source = (REPO_ROOT / "desktop" / "index.js").read_text(encoding="utf-8")

        self.assertIn("nodeIntegration: false", source)
        self.assertIn("contextIsolation: true", source)
        self.assertIn("sandbox: !WSHAWK_E2E_NO_SANDBOX", source)
        self.assertIn('"object-src \'none\'"', source)

    def test_scan_history_does_not_interpolate_untrusted_html(self):
        source = (REPO_ROOT / "desktop" / "src" / "modules" / "web_pentest.js").read_text(encoding="utf-8")

        self.assertNotIn('title="${scan.target}"', source)
        self.assertNotIn("<td>${scan.target}", source)
        self.assertNotIn("<td>${f.title || f.type}", source)
        self.assertNotIn('title="${f.detail}"', source)
        self.assertNotIn('title="${f.value}"', source)
        self.assertNotIn("${e.message}</", source)
        self.assertIn("appendTextCell(tr, scan.target", source)

    def test_extension_bridge_is_restricted_to_loopback(self):
        background = (REPO_ROOT / "extension" / "background.js").read_text(encoding="utf-8")
        popup = (REPO_ROOT / "extension" / "popup.js").read_text(encoding="utf-8")

        self.assertIn("function isLoopbackBridgeHost", background)
        self.assertIn("!isLoopbackBridgeHost(parsed.hostname)", background)
        self.assertIn("parsed.username || parsed.password", background)
        self.assertIn("Bridge URL must use HTTP(S) on localhost", background)
        self.assertIn("if (!response.ok)", popup)


if __name__ == "__main__":
    unittest.main()
