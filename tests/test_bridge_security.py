import unittest
from datetime import datetime, timezone

from wshawk.bridge_security import (
    DEFAULT_EXTENSION_TOKEN_TTL_SECONDS,
    MAX_EXTENSION_TOKEN_TTL_SECONDS,
    ExtensionPairingRegistry,
)


class MemorySecretStore:
    def __init__(self):
        self.values = {}

    def get(self, key, default=""):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)


class ExtensionTokenLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.registry = ExtensionPairingRegistry(secret_store=MemorySecretStore())
        approval = self.registry.begin_pairing()
        self.approval_code = approval["approval_code"]

    @staticmethod
    def seconds_until(expires_at):
        expiry = datetime.fromisoformat(expires_at)
        return (expiry - datetime.now(timezone.utc)).total_seconds()

    def test_default_extension_session_lasts_no_more_than_one_hour(self):
        session = self.registry.issue_token(
            "chrome-extension://trusted-id",
            extension_id="trusted-id",
            approval_code=self.approval_code,
        )

        self.assertLessEqual(
            self.seconds_until(session["expires_at"]),
            DEFAULT_EXTENSION_TOKEN_TTL_SECONDS + 1,
        )

    def test_requested_extension_session_is_capped(self):
        self.registry.issue_token(
            "chrome-extension://trusted-id",
            extension_id="trusted-id",
            approval_code=self.approval_code,
        )
        session = self.registry.issue_token(
            "chrome-extension://trusted-id",
            extension_id="trusted-id",
            ttl_seconds=30 * 24 * 60 * 60,
        )

        self.assertLessEqual(
            self.seconds_until(session["expires_at"]),
            MAX_EXTENSION_TOKEN_TTL_SECONDS + 1,
        )


if __name__ == "__main__":
    unittest.main()
