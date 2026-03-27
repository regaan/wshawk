import unittest

from validation.common import evaluate_expected, load_expected
from validation.socketio_saas.scenario import run_validation_scenario


class ValidationSocketIOLabTests(unittest.TestCase):
    def test_socketio_lab_matches_expected_baseline(self):
        result = run_validation_scenario()
        expected = load_expected("validation/expected/socketio_saas.json")
        evaluation = evaluate_expected(result, expected)
        self.assertTrue(evaluation["passed"], evaluation)


if __name__ == "__main__":
    unittest.main()
