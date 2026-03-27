import unittest

from validation.common import evaluate_expected, load_expected
from validation.graphql_subscriptions_lab.scenario import run_validation_scenario


class ValidationGraphQLSubscriptionsLabTests(unittest.TestCase):
    def test_graphql_subscriptions_lab_matches_expected_baseline(self):
        result = run_validation_scenario()
        expected = load_expected("validation/expected/graphql_subscriptions_lab.json")
        evaluation = evaluate_expected(result, expected)
        self.assertTrue(evaluation["passed"], evaluation)


if __name__ == "__main__":
    unittest.main()
