import os
import platform
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from wshawk.config import WSHawkConfig
from wshawk.secret_store import SecretStore, SecretStoreError, _BaseBackend
from wshawk.secure_store import SensitiveDataCipher


class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.original_backend = os.environ.get("WSHAWK_SECRET_BACKEND")
        self.original_data_dir = os.environ.get("WSHAWK_DATA_DIR")
        os.environ["WSHAWK_SECRET_BACKEND"] = "file"

    def tearDown(self):
        if self.original_backend is None:
            os.environ.pop("WSHAWK_SECRET_BACKEND", None)
        else:
            os.environ["WSHAWK_SECRET_BACKEND"] = self.original_backend

        if self.original_data_dir is None:
            os.environ.pop("WSHAWK_DATA_DIR", None)
        else:
            os.environ["WSHAWK_DATA_DIR"] = self.original_data_dir

    def test_config_secret_reference_resolves_from_secret_store(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["WSHAWK_DATA_DIR"] = temp_dir
            base_dir = Path(temp_dir)
            store = SecretStore("wshawk-config", base_dir=base_dir)
            store.set("jira_api_token", "top-secret-token")

            cfg = WSHawkConfig(
                {
                    "integrations": {
                        "jira": {
                            "api_token": store.reference("jira_api_token"),
                        }
                    }
                }
            )

            self.assertEqual(cfg.get("integrations.jira.api_token"), "top-secret-token")

    def test_sensitive_cipher_migrates_legacy_key_file_into_secret_store(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            legacy_key = Fernet.generate_key()
            legacy_path = base_dir / ".wshawk_data.key"
            legacy_path.write_text(legacy_key.decode("ascii"), encoding="utf-8")

            cipher = SensitiveDataCipher(base_dir)
            encrypted = cipher.encrypt_text("classified")

            self.assertEqual(cipher.decrypt_text(encrypted), "classified")
            self.assertFalse(legacy_path.exists())

            store = SecretStore("wshawk-data", base_dir=base_dir)
            self.assertTrue(store.get(cipher.key_name))

    def test_file_backend_recreates_deleted_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            store = SecretStore("wshawk-config", base_dir=base_dir)
            shutil.rmtree(store.fallback.path.parent)

            store.set("api-token", "recreated-safely")

            self.assertEqual(store.get("api-token"), "recreated-safely")

    def test_primary_failure_never_writes_plaintext_fallback(self):
        class FailingBackend(_BaseBackend):
            name = "failing-secure-backend"

            def get(self, key: str) -> str:
                raise SecretStoreError("unavailable")

            def set(self, key: str, value: str) -> None:
                raise SecretStoreError("unavailable")

            def delete(self, key: str) -> None:
                raise SecretStoreError("unavailable")

        with tempfile.TemporaryDirectory() as temp_dir:
            store = SecretStore("wshawk-config", base_dir=Path(temp_dir))
            store.primary = FailingBackend()

            with self.assertRaises(SecretStoreError):
                store.set("api-token", "must-not-be-plaintext")

            self.assertFalse(store.fallback.path.exists())

    def test_plaintext_fallback_is_migrated_to_primary_backend(self):
        class MemoryBackend(_BaseBackend):
            name = "memory-secure-backend"

            def __init__(self):
                self.values = {}

            def get(self, key: str) -> str:
                return self.values.get(key, "")

            def set(self, key: str, value: str) -> None:
                self.values[key] = value

            def delete(self, key: str) -> None:
                self.values.pop(key, None)

        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            legacy_store = SecretStore("wshawk-config", base_dir=base_dir)
            legacy_store.set("api-token", "legacy-plaintext")
            primary = MemoryBackend()

            os.environ["WSHAWK_SECRET_BACKEND"] = "auto"
            with patch.object(SecretStore, "_build_primary_backend", return_value=primary):
                migrated_store = SecretStore("wshawk-config", base_dir=base_dir)

            self.assertEqual(migrated_store.get("api-token"), "legacy-plaintext")
            self.assertFalse(migrated_store.fallback.path.exists())

    @unittest.skipUnless(platform.system().lower() == "windows", "Windows DPAPI integration test")
    def test_windows_dpapi_round_trip_does_not_create_plaintext_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["WSHAWK_SECRET_BACKEND"] = "dpapi"
            store = SecretStore("wshawk-dpapi-test", base_dir=Path(temp_dir))
            store.set("token", "dpapi-round-trip-secret")

            self.assertEqual(store.backend_name, "windows-dpapi")
            self.assertEqual(store.get("token"), "dpapi-round-trip-secret")
            self.assertFalse(store.fallback.path.exists())
            self.assertNotIn("dpapi-round-trip-secret", store.primary.path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
