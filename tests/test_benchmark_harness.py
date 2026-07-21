import unittest

from benchmarks.run import _aggregate_lab, _evaluate_thresholds, _percentile


class BenchmarkHarnessTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(_percentile([10.0, 20.0, 30.0, 40.0], 0.95), 40.0)
        self.assertEqual(_percentile([10.0], 0.95), 10.0)
        self.assertEqual(_percentile([], 0.95), 0.0)

    def test_aggregation_and_threshold_evaluation(self):
        runs = [
            {
                "wall_ms": 100.0,
                "result": {
                    "checks": {"detects_vulnerable": True, "rejects_hardened": True},
                    "summary": {"total_timed_ms": 80.0},
                },
            },
            {
                "wall_ms": 120.0,
                "result": {
                    "checks": {"detects_vulnerable": True, "rejects_hardened": True},
                    "summary": {"total_timed_ms": 90.0},
                },
            },
        ]
        aggregate = _aggregate_lab("paired", runs)
        evaluation = _evaluate_thresholds(
            {"paired": aggregate},
            {
                "defaults": {"min_runs": 2, "min_check_pass_rate": 1.0, "max_failed_checks": 0},
                "labs": {"paired": {"min_checks": 2, "max_p95_wall_ms": 200}},
            },
        )

        self.assertEqual(aggregate["check_pass_rate"], 1.0)
        self.assertEqual(aggregate["wall_ms"]["median"], 110.0)
        self.assertTrue(evaluation["passed"])


if __name__ == "__main__":
    unittest.main()
