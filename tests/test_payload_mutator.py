#!/usr/bin/env python3
"""Tests for WSHawk Payload Mutation Engine."""

import unittest

from wshawk.payload_mutator import MutationStrategy, PayloadMutator


class PayloadMutatorTests(unittest.TestCase):
    def setUp(self):
        self.mutator = PayloadMutator()

    def test_mutation_generation_produces_output(self):
        self.assertTrue(self.mutator.mutate_payload("<script>alert(1)</script>", MutationStrategy.ENCODING, count=5))
        self.assertTrue(self.mutator.mutate_payload("SELECT * FROM users", MutationStrategy.CASE_VARIATION, count=5))
        self.assertTrue(self.mutator.mutate_payload("' OR 1=1--", MutationStrategy.COMMENT_INJECTION, count=5))
        self.assertTrue(self.mutator.mutate_payload("test payload", MutationStrategy.WHITESPACE, count=5))
        self.assertTrue(self.mutator.mutate_payload("alert(1)", MutationStrategy.CONCATENATION, count=5))
        self.assertTrue(self.mutator.mutate_payload("<script>alert(1)</script>", MutationStrategy.BYPASS_FILTER, count=5))
        self.assertTrue(self.mutator.mutate_payload("<img src=x onerror=alert(1)>", MutationStrategy.TAG_BREAKING, count=5))
        self.assertTrue(self.mutator.mutate_payload("test", MutationStrategy.POLYGLOT, count=5))

    def test_mutations_are_diverse(self):
        results = self.mutator.mutate_payload("<script>alert(1)</script>", MutationStrategy.ENCODING, count=10)
        self.assertGreaterEqual(len(set(results)), len(results) // 2)

        original = "<script>alert(1)</script>"
        different = [result for result in results if result != original]
        self.assertTrue(different)

    def test_adaptive_payloads_behave(self):
        results = self.mutator.generate_adaptive_payloads("<script>alert(1)</script>", max_count=10)
        self.assertIsInstance(results, list)
        self.assertIn("<script>alert(1)</script>", results)

        limited = self.mutator.generate_adaptive_payloads("' OR 1=1--", max_count=5)
        self.assertLessEqual(len(limited), 5)
        self.assertIsInstance(self.mutator.generate_adaptive_payloads("", max_count=5), list)

    def test_learning_tracks_history_and_strategy(self):
        self.mutator.learn_from_response(
            payload="<script>alert(1)</script>",
            response="403 Forbidden - Request blocked by WAF",
            is_blocked=True,
            response_time=0.1,
        )
        self.assertTrue(self.mutator.mutation_history)
        self.assertIn("<script>alert(1)</script>", self.mutator.failed_mutations)

        self.mutator.learn_from_response(
            payload="<ScRiPt>alert(1)</ScRiPt>",
            response="<div><ScRiPt>alert(1)</ScRiPt></div>",
            is_blocked=False,
            response_time=0.05,
        )
        self.assertIsInstance(self.mutator.get_recommended_strategy(), MutationStrategy)

    def test_edge_cases_do_not_crash(self):
        self.assertIsInstance(self.mutator.mutate_payload("A" * 10000, MutationStrategy.ENCODING, count=3), list)
        self.assertIsInstance(self.mutator.mutate_payload("テスト<script>alert('XSS')</script>", MutationStrategy.ENCODING, count=3), list)
        self.assertIsInstance(self.mutator.mutate_payload("'; DROP TABLE users; --\x00\n\r\t", MutationStrategy.BYPASS_FILTER, count=3), list)


if __name__ == "__main__":
    unittest.main()
