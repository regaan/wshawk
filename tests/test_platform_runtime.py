import unittest

from wshawk.platform_runtime import (
    build_ws_headers,
    serialize_ws_payload,
    summarize_authz_diff,
)


class PlatformRuntimeTests(unittest.TestCase):
    def test_build_ws_headers_merges_identity_material(self):
        identity = {
            "headers": {"X-Role": "user"},
            "cookies": [{"name": "session", "value": "abc123"}],
            "tokens": {"session_token": "jwt-token"},
        }

        headers = build_ws_headers(identity=identity, override_headers={"X-Trace": "1"})

        self.assertEqual(headers["X-Role"], "user")
        self.assertEqual(headers["X-Trace"], "1")
        self.assertEqual(headers["Cookie"], "session=abc123")
        self.assertEqual(headers["Authorization"], "Bearer jwt-token")

    def test_build_ws_headers_preserves_explicit_authorization(self):
        identity = {
            "headers": {"Authorization": "Bearer existing"},
            "tokens": {"session_token": "ignored"},
        }

        headers = build_ws_headers(identity=identity)

        self.assertEqual(headers["Authorization"], "Bearer existing")

    def test_serialize_ws_payload_handles_structured_values(self):
        self.assertEqual(serialize_ws_payload({"action": "ping"}), '{"action": "ping"}')
        self.assertEqual(serialize_ws_payload(b"pong"), "pong")

    def test_summarize_authz_diff_flags_behavior_changes(self):
        summary = summarize_authz_diff(
            [
                {
                    "identity_id": "1",
                    "identity_alias": "guest",
                    "status": "received",
                    "response": '{"ok": false}',
                    "response_length": 13,
                    "response_preview": '{"ok": false}',
                },
                {
                    "identity_id": "2",
                    "identity_alias": "user",
                    "status": "received",
                    "response": '{"ok": false}',
                    "response_length": 13,
                    "response_preview": '{"ok": false}',
                },
                {
                    "identity_id": "3",
                    "identity_alias": "admin",
                    "status": "received",
                    "response": '{"ok": true, "items": 9}',
                    "response_length": 24,
                    "response_preview": '{"ok": true, "items": 9}',
                },
            ]
        )

        self.assertTrue(summary["behavior_changed"])
        self.assertEqual(summary["behavior_group_count"], 2)
        self.assertEqual(summary["status_breakdown"]["received"], 3)
        self.assertEqual(summary["interesting_identities"][0]["identity_alias"], "admin")


if __name__ == "__main__":
    unittest.main()
