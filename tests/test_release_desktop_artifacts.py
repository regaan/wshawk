import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from release_desktop_artifacts import generate_release_notes, index_artifacts  # noqa: E402


class ReleaseDesktopArtifactsTests(unittest.TestCase):
    def test_workflow_exposes_all_installers_and_generates_release_notes(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        for expected in (
            "WSHawk-${{ matrix.platform }}-installers",
            "desktop/dist/*.exe",
            "desktop/dist/*.dmg",
            "desktop/dist/*.AppImage",
            "desktop/dist/*.deb",
            "desktop/dist/*.pacman",
            "body_path: release-notes.md",
            "generate_release_notes: true",
            "artifacts/SHA256SUMS.txt",
        ):
            self.assertIn(expected, workflow)

        self.assertTrue((REPO_ROOT / ".github" / "release.yml").exists())

    def test_readme_links_both_research_records(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("https://zenodo.org/records/21290858", readme)
        self.assertIn("https://doi.org/10.6084/m9.figshare.32955467", readme)

    def test_index_artifacts_requires_and_indexes_each_linux_format(self):
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            for name in ("wshawk-4.0.3.AppImage", "wshawk-4.0.3.deb", "wshawk-4.0.3.pacman"):
                (dist / name).write_bytes(name.encode("utf-8"))
            summary = dist / "summary.md"

            manifest = index_artifacts(dist, "Linux", summary)

            self.assertEqual(manifest.name, "SHA256SUMS-Linux.txt")
            self.assertEqual(len(manifest.read_text(encoding="utf-8").splitlines()), 3)
            summary_text = summary.read_text(encoding="utf-8")
            self.assertIn("WSHawk Linux installers", summary_text)
            self.assertIn("wshawk-4.0.3.AppImage", summary_text)

    def test_release_notes_include_installers_checksums_research_and_changelog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / "artifacts"
            names = {
                "Windows": "WSHawk Setup 4.0.3.exe",
                "Linux": "wshawk-4.0.3.AppImage",
                "macOS": "WSHawk-4.0.3.dmg",
                "Python": "wshawk-4.0.3-py3-none-any.whl",
            }
            for platform, name in names.items():
                platform_dir = artifacts / platform
                platform_dir.mkdir(parents=True)
                (platform_dir / name).write_bytes(name.encode("utf-8"))

            changelog = root / "CHANGELOG.md"
            changelog.write_text(
                "## [4.0.3] - 2026-07-23\n\n### Added\n- Release automation.\n\n## [4.0.2]\n",
                encoding="utf-8",
            )
            output = root / "release-notes.md"

            manifest = generate_release_notes(
                artifacts,
                "v4.0.3",
                "regaan/wshawk",
                changelog,
                output,
            )

            notes = output.read_text(encoding="utf-8")
            self.assertIn("WSHawk%20Setup%204.0.3.exe", notes)
            self.assertIn("Zenodo preprint", notes)
            self.assertIn("Figshare preprint", notes)
            self.assertIn("Release automation.", notes)
            self.assertTrue(manifest.exists())
            self.assertEqual(len(manifest.read_text(encoding="utf-8").splitlines()), 4)


if __name__ == "__main__":
    unittest.main()
