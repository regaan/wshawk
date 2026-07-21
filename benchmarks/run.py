from __future__ import annotations

import argparse
import importlib
import json
import math
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from validation.common import write_json

DEFAULT_THRESHOLDS = ROOT / "thresholds.json"
DEFAULT_OUTPUT = ROOT / "results" / "latest.json"
LAB_MODULES = {
    "web_attack_benchmark": "validation.web_attack_benchmark.scenario",
    "websocket_attack_benchmark": "validation.websocket_attack_benchmark.scenario",
    "industry_security_controls_benchmark": "benchmarks.industry_lab.scenario",
}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(float(ordered[index]), 2)


def _load_runner(lab_name: str) -> Callable[[], dict[str, Any]]:
    module = importlib.import_module(LAB_MODULES[lab_name])
    runner = getattr(module, "run_validation_scenario", None)
    if not callable(runner):
        raise RuntimeError(f"{LAB_MODULES[lab_name]} does not expose run_validation_scenario()")
    return runner


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _portable_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return path.name


def _aggregate_lab(lab_name: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    wall_times = [float(run["wall_ms"]) for run in runs]
    timed_totals = [float(run["result"].get("summary", {}).get("total_timed_ms", 0)) for run in runs]
    checks = [run["result"].get("checks", {}) for run in runs]
    failed_checks = sorted(
        {
            check_name
            for run_checks in checks
            for check_name, passed in run_checks.items()
            if not passed
        }
    )
    total_checks = max((len(run_checks) for run_checks in checks), default=0)
    passed_checks = sum(sum(1 for passed in run_checks.values() if passed) for run_checks in checks)
    evaluated_checks = sum(len(run_checks) for run_checks in checks)

    return {
        "lab": lab_name,
        "run_count": len(runs),
        "checks_per_run": total_checks,
        "failed_checks": failed_checks,
        "check_pass_rate": round(passed_checks / evaluated_checks, 6) if evaluated_checks else 0.0,
        "wall_ms": {
            "min": round(min(wall_times), 2),
            "median": round(statistics.median(wall_times), 2),
            "p95": _percentile(wall_times, 0.95),
            "max": round(max(wall_times), 2),
            "mean": round(statistics.fmean(wall_times), 2),
            "stdev": round(statistics.pstdev(wall_times), 2),
        },
        "tool_timed_ms": {
            "median": round(statistics.median(timed_totals), 2),
            "p95": _percentile(timed_totals, 0.95),
        },
    }


def _evaluate_thresholds(
    aggregates: dict[str, dict[str, Any]],
    thresholds: dict[str, Any],
) -> dict[str, Any]:
    default_rules = thresholds.get("defaults", {})
    failures: list[dict[str, Any]] = []
    lab_results: dict[str, Any] = {}

    for lab_name, aggregate in aggregates.items():
        rules = {**default_rules, **thresholds.get("labs", {}).get(lab_name, {})}
        checks = {
            "minimum_runs": aggregate["run_count"] >= int(rules.get("min_runs", 1)),
            "minimum_checks": aggregate["checks_per_run"] >= int(rules.get("min_checks", 0)),
            "maximum_failed_checks": len(aggregate["failed_checks"]) <= int(rules.get("max_failed_checks", 0)),
            "minimum_check_pass_rate": aggregate["check_pass_rate"] >= float(rules.get("min_check_pass_rate", 1.0)),
            "maximum_p95_wall_time": aggregate["wall_ms"]["p95"] <= float(rules.get("max_p95_wall_ms", 60000)),
        }
        lab_results[lab_name] = {"passed": all(checks.values()), "checks": checks, "rules": rules}
        for check_name, passed in checks.items():
            if not passed:
                failures.append({"lab": lab_name, "check": check_name})

    return {
        "passed": not failures,
        "failures": failures,
        "labs": lab_results,
    }


def run_benchmarks(
    lab_names: list[str],
    *,
    iterations: int,
    warmup: int,
    thresholds_path: Path = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    iterations = max(1, int(iterations))
    warmup = max(0, int(warmup))
    thresholds = _load_json(thresholds_path)
    measured_runs: dict[str, list[dict[str, Any]]] = {lab: [] for lab in lab_names}

    for lab_name in lab_names:
        runner = _load_runner(lab_name)
        for _ in range(warmup):
            runner()
        for iteration in range(1, iterations + 1):
            started = time.perf_counter()
            result = runner()
            wall_ms = round((time.perf_counter() - started) * 1000, 2)
            measured_runs[lab_name].append(
                {
                    "iteration": iteration,
                    "wall_ms": wall_ms,
                    "result": result,
                }
            )

    aggregates = {
        lab_name: _aggregate_lab(lab_name, runs)
        for lab_name, runs in measured_runs.items()
    }
    evaluation = _evaluate_thresholds(aggregates, thresholds)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
            "ci": bool(os.getenv("CI")),
            "revision": os.getenv("GITHUB_SHA", "")[:12],
        },
        "configuration": {
            "labs": lab_names,
            "iterations": iterations,
            "warmup": warmup,
            "thresholds": _portable_path(thresholds_path),
        },
        "aggregates": aggregates,
        "evaluation": evaluation,
        "runs": measured_runs,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run repeatable localhost WSHawk security benchmarks.")
    parser.add_argument("labs", nargs="*", choices=sorted(LAB_MODULES), help="Specific benchmark labs to run.")
    parser.add_argument("--iterations", type=int, default=3, help="Measured runs per lab (default: 3).")
    parser.add_argument("--warmup", type=int, default=1, help="Unmeasured warm-up runs per lab (default: 1).")
    parser.add_argument("--thresholds", type=Path, default=DEFAULT_THRESHOLDS, help="Regression threshold JSON file.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Machine-readable benchmark report path.")
    parser.add_argument("--list", action="store_true", help="List benchmark labs and exit.")
    parser.add_argument(
        "--no-fail-on-regression",
        action="store_true",
        help="Write and print failed thresholds without returning a non-zero exit status.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list:
        for lab_name in LAB_MODULES:
            print(lab_name)
        return 0

    lab_names = args.labs or list(LAB_MODULES)
    report = run_benchmarks(
        lab_names,
        iterations=args.iterations,
        warmup=args.warmup,
        thresholds_path=args.thresholds,
    )
    write_json(args.output, report)

    for lab_name in lab_names:
        aggregate = report["aggregates"][lab_name]
        lab_passed = report["evaluation"]["labs"][lab_name]["passed"]
        verdict = "PASS" if lab_passed else "FAIL"
        print(
            f"[{verdict}] {lab_name}: checks={aggregate['check_pass_rate']:.3f}, "
            f"median={aggregate['wall_ms']['median']:.2f}ms, p95={aggregate['wall_ms']['p95']:.2f}ms"
        )
    print(f"Report: {args.output.resolve()}")

    if report["evaluation"]["passed"] or args.no_fail_on_regression:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
