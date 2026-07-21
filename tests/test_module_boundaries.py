"""Regression guards for the feature-module refactor."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _line_count(relative_path: str) -> int:
    return len((REPO_ROOT / relative_path).read_text(encoding="utf-8").splitlines())


def test_refactored_public_modules_stay_below_god_file_limits():
    limits = {
        "wshawk/daemon/web_routes.py": 1_000,
        "wshawk/daemon/platform_routes.py": 1_000,
        "wshawk/legacy_core.py": 100,
        "wshawk/legacy_runtime.py": 1_000,
        "wshawk/store/project_store.py": 1_000,
        "wshawk/scanner_v2.py": 700,
        "wshawk/dom_invader.py": 250,
        "wshawk/db_manager.py": 900,
        "wshawk/binary_handler.py": 700,
    }

    for relative_path, limit in limits.items():
        assert _line_count(relative_path) <= limit, relative_path


def test_extracted_feature_modules_are_present():
    expected = {
        "wshawk/daemon/platform_route_support.py",
        "wshawk/daemon/web_route_support.py",
        "wshawk/daemon/session_routes.py",
        "wshawk/daemon/web_workflow_routes.py",
        "wshawk/store/project_correlation.py",
        "wshawk/scanner_attacks.py",
        "wshawk/database_rows.py",
        "wshawk/binary_mutations.py",
        "wshawk/dom_browser.py",
        "wshawk/dom_xss.py",
        "wshawk/dom_auth.py",
    }

    assert all((REPO_ROOT / relative_path).is_file() for relative_path in expected)


def test_active_cli_has_no_legacy_runtime_dependency():
    main_source = (REPO_ROOT / "wshawk" / "__main__.py").read_text(encoding="utf-8")
    interactive_source = (REPO_ROOT / "wshawk" / "interactive.py").read_text(encoding="utf-8")
    advanced_source = (REPO_ROOT / "wshawk" / "advanced_cli.py").read_text(encoding="utf-8")

    assert "legacy_core" not in main_source
    assert "legacy_runtime" not in main_source
    assert "import *" not in main_source
    assert "legacy_core" not in interactive_source
    assert "legacy_runtime" not in interactive_source
    assert "legacy_advanced_cli" not in advanced_source
    assert "import *" not in advanced_source


def test_desktop_shell_remains_componentized():
    index_path = REPO_ROOT / "desktop" / "src" / "index.html"
    assert index_path.stat().st_size < 80_000
    assert _line_count("desktop/src/index.html") < 1_000

    for component in (
        "core_views.js",
        "web_workspace_views.js",
        "web_security_views.js",
        "collaboration_views.js",
    ):
        assert (REPO_ROOT / "desktop" / "src" / "components" / component).is_file()
