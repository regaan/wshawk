from __future__ import annotations

import argparse
import importlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from validation.common import evaluate_expected, load_expected, write_json

EXPECTED_DIR = ROOT / "expected"
DEFAULT_ARTIFACT_DIR = ROOT / "artifacts"

LAB_MODULES = {
    "full_stack_realtime_saas": "validation.full_stack_realtime_saas.scenario",
    "socketio_saas": "validation.socketio_saas.scenario",
    "graphql_subscriptions_lab": "validation.graphql_subscriptions_lab.scenario",
}


def available_labs() -> list[str]:
    return list(LAB_MODULES.keys())


def expected_path_for(lab_name: str) -> Path:
    return EXPECTED_DIR / f"{lab_name}.json"


def load_scenario_runner(lab_name: str):
    module_name = LAB_MODULES.get(lab_name)
    if not module_name:
        raise KeyError(f"Unknown validation lab: {lab_name}")
    module = importlib.import_module(module_name)
    runner = getattr(module, "run_validation_scenario", None)
    if runner is None:
        raise AttributeError(f"{module_name} does not expose run_validation_scenario()")
    return runner


def run_lab(lab_name: str, artifact_root: str | Path = DEFAULT_ARTIFACT_DIR) -> dict[str, Any]:
    runner = load_scenario_runner(lab_name)
    result = runner()
    expected = load_expected(expected_path_for(lab_name))
    evaluation = evaluate_expected(result, expected)

    lab_dir = Path(artifact_root) / lab_name
    write_json(lab_dir / "result.json", result)
    write_json(lab_dir / "evaluation.json", evaluation)

    bundle = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lab": lab_name,
        "expected_path": str(expected_path_for(lab_name)),
        "result": result,
        "evaluation": evaluation,
    }
    write_json(lab_dir / "bundle.json", bundle)
    return bundle


def run_labs(lab_names: list[str], artifact_root: str | Path = DEFAULT_ARTIFACT_DIR) -> dict[str, Any]:
    runs = [run_lab(name, artifact_root=artifact_root) for name in lab_names]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "labs": [
            {
                "lab": run["lab"],
                "passed": run["evaluation"]["passed"],
                "summary": run["result"].get("summary", {}),
                "check_results": run["evaluation"]["check_results"],
            }
            for run in runs
        ],
        "overall_passed": all(run["evaluation"]["passed"] for run in runs),
    }
    write_json(Path(artifact_root) / "summary.json", summary)
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local WSHawk validation labs against expected baselines.")
    parser.add_argument(
        "labs",
        nargs="*",
        help="Specific lab names to run. Defaults to all registered labs.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available validation labs and exit.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=str(DEFAULT_ARTIFACT_DIR),
        help="Directory where result/evaluation artifacts should be written.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list:
        for lab in available_labs():
            print(lab)
        return 0

    lab_names = args.labs or available_labs()
    unknown = [lab for lab in lab_names if lab not in LAB_MODULES]
    if unknown:
        raise SystemExit(f"Unknown validation lab(s): {', '.join(unknown)}")

    summary = run_labs(lab_names, artifact_root=args.artifacts_dir)
    for item in summary["labs"]:
        verdict = "PASS" if item["passed"] else "FAIL"
        print(f"[{verdict}] {item['lab']}")
    print(f"Artifacts: {Path(args.artifacts_dir).resolve()}")
    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
