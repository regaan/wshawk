#!/usr/bin/env python3
import argparse
import hashlib
import importlib.metadata
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DESKTOP_SRC = REPO_ROOT / "desktop" / "src"
NODE_LOCK = REPO_ROOT / "desktop" / "package-lock.json"
PYTHON_VERSION_FILE = REPO_ROOT / "wshawk" / "_version_info.py"
CITATION_FILE = REPO_ROOT / "CITATION.cff"
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
IGNORED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".wshawk",
    "__pycache__",
    "artifacts",
    "bin",
    "build",
    "dist",
    "node_modules",
    "out",
    "reports",
    "venv",
}
IGNORED_DIR_SUFFIXES = (".egg-info",)
IGNORED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".db",
    ".sqlite",
    ".log",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def should_ignore_manifest_path(path: Path) -> bool:
    return any(
        part in IGNORED_DIRS or part.endswith(IGNORED_DIR_SUFFIXES)
        for part in path.parts
    )


def collect_python_sbom() -> list[dict]:
    packages = []
    for dist in sorted(
        importlib.metadata.distributions(),
        key=lambda item: str(item.metadata.get("Name", "")).lower(),
    ):
        packages.append(
            {
                "name": dist.metadata.get("Name", ""),
                "version": dist.version,
                "license": dist.metadata.get("License", ""),
                "summary": dist.metadata.get("Summary", ""),
            }
        )
    return packages


def collect_node_sbom() -> list[dict]:
    if not NODE_LOCK.exists():
        return []
    payload = json.loads(NODE_LOCK.read_text(encoding="utf-8"))
    packages = []
    for package_path, info in sorted((payload.get("packages") or {}).items()):
        if not package_path:
            continue
        packages.append(
            {
                "path": package_path,
                "name": info.get("name") or package_path.split("node_modules/")[-1],
                "version": info.get("version", ""),
                "resolved": info.get("resolved", ""),
                "integrity": info.get("integrity", ""),
            }
        )
    return packages


def scan_remote_assets() -> list[dict]:
    findings = []
    asset_patterns = [
        re.compile(r"""src\s*=\s*["']https?://""", re.IGNORECASE),
        re.compile(r"""<link\b[^>]*href\s*=\s*["']https?://""", re.IGNORECASE),
        re.compile(r"""url\(\s*["']?https?://""", re.IGNORECASE),
        re.compile(r"""(?:fetch|axios|XMLHttpRequest|openExternal)\s*\(\s*["']https?://""", re.IGNORECASE),
    ]
    for path in DESKTOP_SRC.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".html", ".css", ".js"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("<!--") or stripped.startswith("//"):
                continue
            if not any(pattern.search(stripped) for pattern in asset_patterns):
                continue
            if "../node_modules/socket.io-client/dist/socket.io.min.js" in stripped:
                continue
            findings.append(
                {
                    "path": str(path.relative_to(REPO_ROOT)),
                    "line": line_no,
                    "content": stripped[:240],
                }
            )
    return findings


def check_version_consistency() -> dict:
    source = PYTHON_VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.MULTILINE)
    if not match:
        return {"canonical": "", "artifacts": {}, "mismatches": ["wshawk/_version_info.py"]}

    canonical = match.group(1)
    package_payload = json.loads((REPO_ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))
    extension_payload = json.loads((REPO_ROOT / "extension" / "manifest.json").read_text(encoding="utf-8"))
    docker_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    docker_match = re.search(r'LABEL\s+version=["\']([^"\']+)["\']', docker_text)
    citation_text = CITATION_FILE.read_text(encoding="utf-8")
    citation_match = re.search(r'^version:\s*["\']?([^\s"\']+)', citation_text, re.MULTILINE)
    artifacts = {
        "desktop/package.json": str(package_payload.get("version", "")),
        "extension/manifest.json": str(extension_payload.get("version", "")),
        "Dockerfile": docker_match.group(1) if docker_match else "",
        "CITATION.cff": citation_match.group(1) if citation_match else "",
    }
    mismatches = [path for path, version in artifacts.items() if version != canonical]
    return {"canonical": canonical, "artifacts": artifacts, "mismatches": mismatches}


def scan_unpinned_workflow_actions() -> list[dict]:
    findings = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match:
                continue
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                findings.append({
                    "path": str(path.relative_to(REPO_ROOT)),
                    "line": line_no,
                    "reference": reference,
                })
    return findings


def build_repro_manifest() -> dict:
    entries = []
    for path in sorted(REPO_ROOT.rglob("*")):
        relative = path.relative_to(REPO_ROOT)
        if should_ignore_manifest_path(relative):
            continue
        if path.is_dir():
            continue
        if path.suffix.lower() in IGNORED_SUFFIXES:
            continue
        entries.append(
            {
                "path": str(relative),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    return {
        "entry_count": len(entries),
        "entries": entries,
        "manifest_sha256": hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def run_checks() -> dict:
    remote_assets = scan_remote_assets()
    versions = check_version_consistency()
    workflow_pins = scan_unpinned_workflow_actions()
    return {
        "status": "ok" if not remote_assets and not versions["mismatches"] and not workflow_pins else "error",
        "python_sbom": collect_python_sbom(),
        "node_sbom": collect_node_sbom(),
        "remote_asset_findings": remote_assets,
        "version_consistency": versions,
        "unpinned_workflow_actions": workflow_pins,
        "repro_manifest": build_repro_manifest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run WSHawk release security checks.")
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "build" / "release_security_report.json"),
        help="Path to write the JSON report.",
    )
    args = parser.parse_args()

    report = run_checks()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(output_path)
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
