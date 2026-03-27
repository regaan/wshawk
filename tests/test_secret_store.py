import os
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

from wshawk.config import WSHawkConfig
from wshawk.secret_store import SecretStore
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


if __name__ == "__main__":
    unittest.main()
