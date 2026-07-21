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

    def test_desktop_views_use_the_static_registry_and_shared_state(self):
        source_root = REPO_ROOT / "desktop" / "src"
        index_content = (source_root / "index.html").read_text(encoding="utf-8")
        registry = (source_root / "components" / "view_registry.js").read_text(encoding="utf-8")
        renderer = (source_root / "renderer.js").read_text(encoding="utf-8")

        for script in (
            "components/view_registry.js",
            "components/core_views.js",
            "components/web_workspace_views.js",
            "components/web_security_views.js",
            "components/collaboration_views.js",
            "components/mount_views.js",
            "modules/state.js",
            "modules/dom.js",
        ):
            self.assertIn(f'src="{script}"', index_content)

        self.assertIn("Unsafe markup in static view component", registry)
        self.assertIn("window.WSHawkRendererState", renderer)
        self.assertIn("window.WSHawkDOM", renderer)
        self.assertLess((source_root / "index.html").stat().st_size, 80_000)

    def test_runtime_findings_and_history_use_safe_dom_helpers(self):
        modules = REPO_ROOT / "desktop" / "src" / "modules"
        evidence = (modules / "evidence.js").read_text(encoding="utf-8")
        traffic = (modules / "traffic.js").read_text(encoding="utf-8")

        self.assertNotIn("findingsContainer.insertAdjacentHTML", evidence)
        self.assertNotIn("historyTbody.insertAdjacentHTML", traffic)
        self.assertIn("global.WSHawkDOM.emptyState", evidence)
        self.assertIn("global.WSHawkDOM.emptyTable", traffic)

    def test_desktop_smoke_mode_and_runner_are_wired(self):
        index_content = (REPO_ROOT / "desktop" / "index.js").read_text(encoding="utf-8")
        self.assertIn("WSHAWK_DESKTOP_SMOKE", index_content)
        self.assertIn("writeDesktopSmokeSnapshot", index_content)
        self.assertIn("captureDesktopSmokeSnapshot", index_content)

        smoke_script = REPO_ROOT / "desktop" / "scripts" / "smoke-check.js"
        self.assertTrue(smoke_script.exists())

        package_json = json.loads((REPO_ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package_json["scripts"]["smoke"], "node scripts/smoke-check.js")

        packaged_files = package_json["build"]["files"]
        self.assertIn("!scripts/**", packaged_files)

    def test_development_sidecar_supports_standard_python_environments(self):
        content = (REPO_ROOT / "desktop" / "index.js").read_text(encoding="utf-8")
        self.assertIn("process.env.WSHAWK_PYTHON", content)
        self.assertIn("process.env.VIRTUAL_ENV", content)
        self.assertIn("path.join(repoRoot, '.venv'", content)

    def test_desktop_shutdown_terminates_the_sidecar_process_tree(self):
        content = (REPO_ROOT / "desktop" / "index.js").read_text(encoding="utf-8")
        self.assertIn("function stopPythonSidecar()", content)
        self.assertIn("app.on('before-quit', stopPythonSidecar)", content)
        self.assertIn("execFileSync('taskkill.exe'", content)
        self.assertIn("['/PID', String(child.pid), '/T', '/F']", content)

        window_close_handler = content.split("app.on('window-all-closed', () => {", 1)[1]
        self.assertIn("stopPythonSidecar();", window_close_handler)
        self.assertNotIn("pythonProcess.kill()", window_close_handler)


if __name__ == "__main__":
    unittest.main()
