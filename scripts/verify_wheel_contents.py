#!/usr/bin/env python3
"""Reject release wheels that contain repository-only files or wrong metadata."""

from __future__ import annotations

import argparse
import glob
import re
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = REPO_ROOT / "wshawk" / "_version_info.py"
FORBIDDEN_PARTS = {
    ".github",
    "desktop",
    "docs",
    "examples",
    "extension",
    "scripts",
    "tests",
    "validation",
}
EXPECTED_CONSOLE_SCRIPTS = {
    "wshawk": "wshawk.__main__:cli",
    "wshawk-advanced": "wshawk.advanced_cli:cli",
    "wshawk-defensive": "wshawk.defensive_cli:cli",
    "wshawk-interactive": "wshawk.interactive:cli",
}


def canonical_version() -> str:
    source = VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.MULTILINE)
    if not match:
        raise ValueError(f"Cannot read canonical version from {VERSION_FILE}")
    return match.group(1)


def verify_wheel(path: Path) -> list[str]:
    errors: list[str] = []
    expected_version = canonical_version()
    expected_dist_info = f"wshawk-{expected_version}.dist-info"

    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        roots = {name.split("/", 1)[0] for name in names}
        allowed_roots = {"wshawk", expected_dist_info}
        unexpected_roots = sorted(roots - allowed_roots)
        if unexpected_roots:
            errors.append(f"unexpected wheel roots: {', '.join(unexpected_roots)}")

        forbidden = sorted(
            name for name in names if FORBIDDEN_PARTS.intersection(Path(name).parts)
        )
        if forbidden:
            errors.append(f"repository-only files included: {', '.join(forbidden[:10])}")

        required = {
            "wshawk/__init__.py",
            "wshawk/__main__.py",
            f"{expected_dist_info}/METADATA",
            f"{expected_dist_info}/RECORD",
            f"{expected_dist_info}/entry_points.txt",
        }
        missing = sorted(required - set(names))
        if missing:
            errors.append(f"required wheel files missing: {', '.join(missing)}")

        metadata_name = f"{expected_dist_info}/METADATA"
        if metadata_name in names:
            metadata = archive.read(metadata_name).decode("utf-8", errors="replace")
            if f"Version: {expected_version}\n" not in metadata.replace("\r\n", "\n"):
                errors.append(f"METADATA version does not match {expected_version}")

        entry_points_name = f"{expected_dist_info}/entry_points.txt"
        if entry_points_name in names:
            entry_points = archive.read(entry_points_name).decode("utf-8", errors="replace")
            normalized_lines = {line.strip() for line in entry_points.splitlines() if line.strip()}
            missing_scripts = sorted(
                f"{name} = {target}"
                for name, target in EXPECTED_CONSOLE_SCRIPTS.items()
                if f"{name} = {target}" not in normalized_lines
            )
            if missing_scripts:
                errors.append(f"console scripts missing or incorrect: {', '.join(missing_scripts)}")

    return errors


def expand_paths(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matches = glob.glob(pattern)
        paths.extend(Path(match) for match in matches)
    return sorted(set(paths))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", help="Wheel paths or glob patterns")
    args = parser.parse_args()

    wheels = expand_paths(args.wheels)
    if not wheels:
        parser.error("no wheel files matched")

    failures = 0
    for wheel in wheels:
        errors = verify_wheel(wheel)
        if errors:
            failures += 1
            print(f"FAIL {wheel}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS {wheel}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
