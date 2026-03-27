import json
import os
import hashlib
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from wshawk.secret_store import SecretStore


ENC_PREFIX = "enc::"


class SensitiveDataCipher:
    """Encrypt sensitive values at rest while remaining backward compatible."""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        key_suffix = hashlib.sha256(str(self.base_dir.resolve()).encode("utf-8")).hexdigest()[:24]
        self.key_name = f"data-key:{key_suffix}"
        self.legacy_key_path = self.base_dir / ".wshawk_data.key"
        self.secret_store = SecretStore("wshawk-data", base_dir=self.base_dir)
        self._fernet = None

    def _load_fernet(self) -> Fernet:
        if self._fernet is not None:
            return self._fernet

        key = self.secret_store.get(self.key_name, "")
        if not key and self.legacy_key_path.exists():
            key = self.legacy_key_path.read_text(encoding="utf-8").strip()
            if key:
                self.secret_store.set(self.key_name, key)
                try:
                    self.legacy_key_path.unlink()
                except OSError:
                    pass

        if not key:
            key = Fernet.generate_key()
            self.secret_store.set(self.key_name, key.decode("ascii"))
        elif isinstance(key, str):
            key = key.encode("ascii")
        self._fernet = Fernet(key)
        return self._fernet

    def encrypt_text(self, value: Any) -> str:
        if value is None:
            return ""
        text = str(value)
        if not text:
            return ""
        token = self._load_fernet().encrypt(text.encode("utf-8")).decode("ascii")
        return f"{ENC_PREFIX}{token}"

    def decrypt_text(self, value: Any) -> str:
        if value is None:
            return ""
        text = str(value)
        if not text:
            return ""
        if not text.startswith(ENC_PREFIX):
            return text
        try:
            return self._load_fernet().decrypt(text[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return ""

    def dump_json(self, value: Any) -> str:
        return self.encrypt_text(json.dumps(value))

    def load_json(self, raw: Any, default: Any) -> Any:
        try:
            text = self.decrypt_text(raw)
            return json.loads(text) if text else default
        except (TypeError, json.JSONDecodeError):
            return default
