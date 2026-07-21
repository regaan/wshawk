import unittest

from wshawk.daemon.errors import error_payload, public_error_message


class DaemonErrorEnvelopeTests(unittest.TestCase):
    def test_client_error_keeps_actionable_message(self):
        payload = error_payload(400, "Target URL is required")

        self.assertEqual(
            payload,
            {
                "status": "error",
                "code": "http_400",
                "message": "Target URL is required",
                "detail": "Target URL is required",
            },
        )

    def test_server_error_hides_internal_exception_text(self):
        secret = "sqlite3.OperationalError at C:/private/path/database.sqlite"
        payload = error_payload(500, secret)

        self.assertEqual(payload["message"], "Internal server error")
        self.assertEqual(payload["detail"], "Internal server error")
        self.assertNotIn(secret, str(payload))
        self.assertEqual(public_error_message(503, secret), "Internal server error")


if __name__ == "__main__":
    unittest.main()
