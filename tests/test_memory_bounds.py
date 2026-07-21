import unittest
from unittest.mock import AsyncMock

from wshawk.scanner_v2 import WSHawkV2
from wshawk.smart_payloads.feedback_loop import FeedbackLoop


class FeedbackLoopBoundsTests(unittest.TestCase):
    def test_feedback_buffers_drop_oldest_entries_at_their_limits(self):
        loop = FeedbackLoop(max_history=3, max_interesting=2)
        loop.establish_baseline("one", 0.1)
        loop.establish_baseline("two", 0.1)
        loop.establish_baseline("three", 0.1)
        loop.establish_baseline("four", 0.1)

        for index in range(5):
            loop.analyze_response(
                f"payload-{index}",
                "mysql syntax error",
                0.1,
                category="sqli",
            )

        self.assertEqual(list(loop.baseline_responses), ["two", "three", "four"])
        self.assertEqual(len(loop.response_history), 3)
        self.assertEqual(len(loop.interesting_payloads), 2)
        self.assertEqual(loop.interesting_payloads[0]["payload"], "payload-3")


class ScannerRunResetTests(unittest.IsolatedAsyncioTestCase):
    async def test_reused_scanner_does_not_retain_previous_run_findings(self):
        scanner = WSHawkV2("wss://example.test/socket")
        scanner.vulnerabilities.append({"type": "stale"})
        scanner.traffic_logs.append({"direction": "out"})
        scanner.messages_sent = 10
        scanner.messages_received = 5
        scanner.connect = AsyncMock(return_value=None)

        result = await scanner.run_heuristic_scan()

        self.assertEqual(result, [])
        self.assertEqual(scanner.vulnerabilities, [])
        self.assertEqual(scanner.traffic_logs, [])
        self.assertEqual(scanner.messages_sent, 0)
        self.assertEqual(scanner.messages_received, 0)


if __name__ == "__main__":
    unittest.main()
