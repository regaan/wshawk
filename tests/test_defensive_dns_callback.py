import asyncio
import unittest
from unittest.mock import patch

from wshawk.defensive_validation import DNSExfiltrationTest


class DefensiveDNSCallbackTests(unittest.TestCase):
    def test_missing_oast_api_is_inconclusive(self):
        with patch.dict("os.environ", {}, clear=True):
            validator = DNSExfiltrationTest("ws://127.0.0.1:9000/ws")
            result = asyncio.run(validator._check_dns_callback("probe.example.test"))

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
