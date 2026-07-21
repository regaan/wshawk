#!/usr/bin/env python3
"""Fail when a PyInstaller spec declares hidden imports that are unavailable."""

from __future__ import annotations

import argparse
import ast
import importlib.util
from pathlib import Path


def declared_hidden_imports(path: str | Path) -> list[str]:
    spec_path = Path(path)
    tree = ast.parse(spec_path.read_text(encoding="utf-8"), filename=str(spec_path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "base_hiddenimports" for target in node.targets):
            continue
        values = ast.literal_eval(node.value)
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError("base_hiddenimports must be a literal list of module names")
        return values
    raise ValueError(f"base_hiddenimports was not found in {spec_path}")


def unavailable_hidden_imports(path: str | Path) -> list[str]:
    unavailable = []
    for module_name in declared_hidden_imports(path):
        try:
            available = importlib.util.find_spec(module_name) is not None
        except (AttributeError, ImportError, ModuleNotFoundError, ValueError):
            available = False
        if not available:
            unavailable.append(module_name)
    return unavailable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", nargs="?", default="wshawk-bridge.spec", help="PyInstaller spec to verify")
    args = parser.parse_args(argv)

    unavailable = unavailable_hidden_imports(args.spec)
    if unavailable:
        print("FAIL unavailable PyInstaller hidden imports:")
        for module_name in unavailable:
            print(f"  - {module_name}")
        return 1
    print(f"PASS {len(declared_hidden_imports(args.spec))} PyInstaller hidden imports are available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
