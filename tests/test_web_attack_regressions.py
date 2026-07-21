import unittest

from wshawk.web_pentest.cors_tester import _build_test_origins
from wshawk.web_pentest.redirect_scanner import WSHawkRedirectHunter


class WebAttackRegressionTests(unittest.TestCase):
    def test_redirect_same_hostname_is_not_external_when_ports_differ(self):
        hunter = WSHawkRedirectHunter()

        self.assertFalse(
            hunter._is_external("http://127.0.0.1:9000/next", "127.0.0.1:8000")
        )
        self.assertTrue(
            hunter._is_external("https://evil.example/next", "127.0.0.1:8000")
        )

    def test_cors_http_downgrade_probe_only_applies_to_https_targets(self):
        http_names = {item["name"] for item in _build_test_origins("http://app.example")}
        https_names = {item["name"] for item in _build_test_origins("https://app.example")}

        self.assertNotIn("HTTP Downgrade", http_names)
        self.assertIn("HTTP Downgrade", https_names)


if __name__ == "__main__":
    unittest.main()
