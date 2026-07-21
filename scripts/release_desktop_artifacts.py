#!/usr/bin/env python3
"""Index desktop installers and generate a GitHub Release body."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from urllib.parse import quote


PLATFORM_FORMATS = {
    "Windows": {
        ".exe": "NSIS installer",
    },
    "Linux": {
        ".AppImage": "AppImage",
        ".deb": "Debian/Ubuntu package",
        ".pacman": "Arch Linux package",
    },
    "macOS": {
        ".dmg": "DMG installer",
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    raise AssertionError("unreachable")


def platform_artifacts(dist: Path, platform: str) -> list[Path]:
    formats = PLATFORM_FORMATS.get(platform)
    if formats is None:
        raise ValueError(f"unsupported platform: {platform}")

    artifacts = sorted(
        path
        for path in dist.iterdir()
        if path.is_file() and any(path.name.endswith(suffix) for suffix in formats)
    )
    missing = [
        suffix
        for suffix in formats
        if not any(path.name.endswith(suffix) for path in artifacts)
    ]
    if missing:
        raise ValueError(f"{platform} build is missing expected artifact types: {', '.join(missing)}")
    return artifacts


def index_artifacts(dist: Path, platform: str, summary: Path | None = None) -> Path:
    artifacts = platform_artifacts(dist, platform)
    manifest = dist / f"SHA256SUMS-{platform}.txt"
    manifest.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in artifacts),
        encoding="utf-8",
    )

    if summary is not None:
        rows = [
            f"| `{path.name}` | {human_size(path.stat().st_size)} | `{sha256(path)}` |"
            for path in artifacts
        ]
        with summary.open("a", encoding="utf-8") as stream:
            stream.write(f"## WSHawk {platform} installers\n\n")
            stream.write("| File | Size | SHA-256 |\n")
            stream.write("| --- | ---: | --- |\n")
            stream.write("\n".join(rows))
            stream.write(f"\n\nChecksum manifest: `{manifest.name}`\n")
    return manifest


def release_kind(path: Path) -> tuple[str, str] | None:
    for platform, formats in PLATFORM_FORMATS.items():
        for suffix, description in formats.items():
            if path.name.endswith(suffix):
                return platform, description
    if path.name.endswith(".whl"):
        return "Python", "Wheel"
    if path.name.endswith(".tar.gz"):
        return "Python", "Source distribution"
    return None


def extract_changelog(changelog: Path, version: str) -> str:
    lines = changelog.read_text(encoding="utf-8").splitlines()
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)")
    start = next((index for index, line in enumerate(lines) if heading.match(line)), None)
    if start is None:
        return ""
    end = next(
        (index for index in range(start + 1, len(lines)) if lines[index].startswith("## [")),
        len(lines),
    )
    return "\n".join(lines[start + 1 : end]).strip()


def generate_release_notes(
    artifacts_root: Path,
    tag: str,
    repository: str,
    changelog: Path,
    output: Path,
) -> Path:
    release_files = sorted(
        path
        for path in artifacts_root.rglob("*")
        if path.is_file() and release_kind(path) is not None
    )
    by_platform: dict[str, list[tuple[Path, str]]] = {
        platform: [] for platform in ("Windows", "Linux", "macOS", "Python")
    }
    names: set[str] = set()
    for path in release_files:
        if path.name in names:
            raise ValueError(f"duplicate release asset name: {path.name}")
        names.add(path.name)
        kind = release_kind(path)
        assert kind is not None
        platform, description = kind
        by_platform[platform].append((path, description))

    missing = [platform for platform in ("Windows", "Linux", "macOS") if not by_platform[platform]]
    if missing:
        raise ValueError(f"release is missing platform installers: {', '.join(missing)}")

    combined_manifest = artifacts_root / "SHA256SUMS.txt"
    combined_manifest.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in release_files),
        encoding="utf-8",
    )

    version = tag.removeprefix("v")
    base_url = f"https://github.com/{repository}/releases/download/{quote(tag, safe='')}"
    rows: list[str] = []
    for platform in ("Windows", "Linux", "macOS", "Python"):
        for path, description in by_platform[platform]:
            url = f"{base_url}/{quote(path.name, safe='')}"
            rows.append(f"| {platform} | [{path.name}]({url}) | {description} |")

    changes = extract_changelog(changelog, version)
    notes = [
        f"WSHawk {version} packages the CLI, defensive validator, and desktop security testing application.",
        "",
        "## Downloads",
        "",
        "| Platform | Package | Format |",
        "| --- | --- | --- |",
        *rows,
        "",
        "## Verify downloads",
        "",
        f"Download [SHA256SUMS.txt]({base_url}/SHA256SUMS.txt) and compare the SHA-256 value before installation.",
        "",
        "## Installation notes",
        "",
        "- **Windows:** run the NSIS `.exe` installer.",
        "- **Linux:** use the portable `.AppImage`, install the `.deb` on Debian/Ubuntu, or install the `.pacman` package on Arch Linux.",
        "- **macOS:** open the `.dmg` and move WSHawk into Applications.",
        "- **Python:** install the wheel with `python -m pip install <wheel-file>`.",
        "",
        "## Research paper",
        "",
        "- [Zenodo preprint (10.5281/zenodo.21290858)](https://zenodo.org/records/21290858)",
        "- [Figshare preprint (10.6084/m9.figshare.32955467.v1)](https://doi.org/10.6084/m9.figshare.32955467)",
    ]
    if changes:
        notes.extend(["", "## What's changed", "", changes])
    notes.extend(
        [
            "",
            "---",
            "",
            "GitHub's contributor and pull-request changelog is appended below.",
            "",
        ]
    )
    output.write_text("\n".join(notes), encoding="utf-8")
    return combined_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    index_parser = subparsers.add_parser("index", help="validate and index one platform build")
    index_parser.add_argument("--dist", type=Path, required=True)
    index_parser.add_argument("--platform", choices=PLATFORM_FORMATS, required=True)
    index_parser.add_argument("--summary", type=Path)

    notes_parser = subparsers.add_parser("notes", help="generate a release body and combined checksums")
    notes_parser.add_argument("--artifacts", type=Path, required=True)
    notes_parser.add_argument("--tag", required=True)
    notes_parser.add_argument("--repository", required=True)
    notes_parser.add_argument("--changelog", type=Path, required=True)
    notes_parser.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "index":
            manifest = index_artifacts(args.dist, args.platform, args.summary)
            print(manifest)
        else:
            manifest = generate_release_notes(
                args.artifacts,
                args.tag,
                args.repository,
                args.changelog,
                args.output,
            )
            print(args.output)
            print(manifest)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
