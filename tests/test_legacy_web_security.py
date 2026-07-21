import hashlib
import tempfile
import unittest
from pathlib import Path

from wshawk.web.legacy_app import (
    create_app,
    hash_password,
    is_loopback_bind_host,
    run_web,
    validate_websocket_target,
    verify_password,
)


class LegacyWebSecurityTests(unittest.TestCase):
    def test_passwords_use_scrypt_and_verify_in_constant_format(self):
        hashed, salt = hash_password("correct horse battery staple")

        self.assertTrue(verify_password("correct horse battery staple", hashed, salt))
        self.assertFalse(verify_password("wrong", hashed, salt))
        self.assertNotEqual(hashed, hashlib.sha256(f"{salt}correct horse battery staple".encode()).hexdigest())

    def test_loopback_detection_rejects_wildcard_and_remote_addresses(self):
        self.assertTrue(is_loopback_bind_host("127.0.0.1"))
        self.assertTrue(is_loopback_bind_host("::1"))
        self.assertTrue(is_loopback_bind_host("localhost"))
        self.assertFalse(is_loopback_bind_host("0.0.0.0"))
        self.assertFalse(is_loopback_bind_host("192.168.1.20"))

    def test_remote_bind_without_authentication_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Refusing non-loopback"):
            run_web(host="0.0.0.0", auth_enabled=False)

    def test_remote_target_policy_blocks_internal_and_metadata_addresses(self):
        for target in (
            "ws://127.0.0.1/admin",
            "ws://10.10.10.10/internal",
            "ws://169.254.169.254/latest/meta-data",
            "ws://[::1]/admin",
        ):
            valid, error = validate_websocket_target(target, allow_private_targets=False)
            self.assertFalse(valid, target)
            self.assertIn("disabled", error)

        valid, error = validate_websocket_target("wss://127.0.0.1/test", allow_private_targets=True)
        self.assertTrue(valid)
        self.assertEqual(error, "")

    def test_authentication_requires_a_password(self):
        with self.assertRaisesRegex(ValueError, "no web password"):
            create_app(auth_enabled=True, auth_password=None)

    def test_state_changing_request_requires_csrf_or_api_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(db_path=str(Path(temp_dir) / "legacy.db"))
            app.config.update(TESTING=True)
            client = app.test_client()

            response = client.post("/api/scan", json={"target": "wss://example.test/ws"})
            self.assertEqual(response.status_code, 403)

            response = client.post(
                "/api/scan",
                json={},
                headers={"X-API-Key": app.config["API_KEY"]},
            )
            self.assertEqual(response.status_code, 400)

    def test_login_form_uses_csrf_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = create_app(
                db_path=str(Path(temp_dir) / "legacy.db"),
                auth_enabled=True,
                auth_password="strong-test-password",
            )
            app.config.update(TESTING=True)
            client = app.test_client()

            self.assertEqual(client.post("/login", data={"username": "admin", "password": "strong-test-password"}).status_code, 403)
            client.get("/login")
            with client.session_transaction() as session:
                token = session["_csrf_token"]

            response = client.post(
                "/login",
                data={"username": "admin", "password": "strong-test-password", "_csrf_token": token},
            )
            self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()
