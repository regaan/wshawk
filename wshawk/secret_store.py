import base64
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Optional


DEFAULT_NAMESPACE = "wshawk"


class SecretStoreError(RuntimeError):
    pass


class _BaseBackend:
    name = "base"

    def get(self, key: str) -> str:
        raise NotImplementedError

    def set(self, key: str, value: str) -> None:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError


class _FileFallbackBackend(_BaseBackend):
    name = "file-fallback"

    def __init__(self, namespace: str, base_dir: Optional[Path] = None):
        resolved_base = Path(base_dir or os.environ.get("WSHAWK_DATA_DIR") or (Path.home() / ".wshawk"))
        resolved_base.mkdir(parents=True, exist_ok=True)
        self.path = resolved_base / ".secret_store" / f"{namespace}.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._chmod(self.path.parent, 0o700)

    @staticmethod
    def _chmod(path: Path, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _save(self, payload: dict) -> None:
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        self._chmod(self.path, 0o600)

    def get(self, key: str) -> str:
        return str(self._load().get(key, "") or "")

    def set(self, key: str, value: str) -> None:
        payload = self._load()
        payload[str(key)] = str(value)
        self._save(payload)

    def delete(self, key: str) -> None:
        payload = self._load()
        if str(key) in payload:
            payload.pop(str(key), None)
            self._save(payload)


class _SecretToolBackend(_BaseBackend):
    name = "secret-tool"

    def __init__(self, namespace: str):
        self.namespace = namespace

    def _run(self, args, input_text: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=check,
        )

    def get(self, key: str) -> str:
        result = self._run(
            ["secret-tool", "lookup", "service", self.namespace, "account", str(key)],
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    def set(self, key: str, value: str) -> None:
        result = self._run(
            ["secret-tool", "store", "--label", f"WSHawk {key}", "service", self.namespace, "account", str(key)],
            input_text=str(value),
            check=False,
        )
        if result.returncode != 0:
            raise SecretStoreError(result.stderr.strip() or "secret-tool store failed")

    def delete(self, key: str) -> None:
        self._run(
            ["secret-tool", "clear", "service", self.namespace, "account", str(key)],
            check=False,
        )


class _MacKeychainBackend(_BaseBackend):
    name = "macos-keychain"

    def __init__(self, namespace: str):
        self.namespace = namespace

    def _run(self, args, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(args, text=True, capture_output=True, check=check)

    def get(self, key: str) -> str:
        result = self._run(
            ["security", "find-generic-password", "-a", str(key), "-s", self.namespace, "-w"],
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    def set(self, key: str, value: str) -> None:
        result = self._run(
            ["security", "add-generic-password", "-U", "-a", str(key), "-s", self.namespace, "-w", str(value)],
            check=False,
        )
        if result.returncode != 0:
            raise SecretStoreError(result.stderr.strip() or "security add-generic-password failed")

    def delete(self, key: str) -> None:
        self._run(
            ["security", "delete-generic-password", "-a", str(key), "-s", self.namespace],
            check=False,
        )


class _WindowsDPAPIBackend(_BaseBackend):
    name = "windows-dpapi"

    def __init__(self, namespace: str, base_dir: Optional[Path] = None):
        self.namespace = namespace
        resolved_base = Path(base_dir or os.environ.get("WSHAWK_DATA_DIR") or (Path.home() / ".wshawk"))
        resolved_base.mkdir(parents=True, exist_ok=True)
        self.path = resolved_base / ".secret_store" / f"{namespace}.dpapi.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _run_powershell(command: str, input_text: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if not shell:
            raise SecretStoreError("PowerShell is not available for DPAPI secret storage")
        return subprocess.run(
            [shell, "-NoProfile", "-Command", command],
            input=input_text,
            text=True,
            capture_output=True,
            check=check,
        )

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _save(self, payload: dict) -> None:
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _encrypt(self, value: str) -> str:
        result = self._run_powershell(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8; "
            "$raw=[Console]::In.ReadToEnd(); "
            "$bytes=[Text.Encoding]::UTF8.GetBytes($raw); "
            "$enc=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); "
            "[Convert]::ToBase64String($enc)",
            input_text=value,
            check=False,
        )
        if result.returncode != 0:
            raise SecretStoreError(result.stderr.strip() or "DPAPI encrypt failed")
        return result.stdout.strip()

    def _decrypt(self, value: str) -> str:
        if not value:
            return ""
        result = self._run_powershell(
            "$raw=[Console]::In.ReadToEnd().Trim(); "
            "$bytes=[Convert]::FromBase64String($raw); "
            "$dec=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); "
            "[Text.Encoding]::UTF8.GetString($dec)",
            input_text=value,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    def get(self, key: str) -> str:
        payload = self._load()
        return self._decrypt(str(payload.get(str(key), "") or ""))

    def set(self, key: str, value: str) -> None:
        payload = self._load()
        payload[str(key)] = self._encrypt(str(value))
        self._save(payload)

    def delete(self, key: str) -> None:
        payload = self._load()
        if str(key) in payload:
            payload.pop(str(key), None)
            self._save(payload)


class SecretStore:
    """Platform-aware secret storage with a controlled fallback for tests/headless flows."""

    def __init__(self, namespace: str = DEFAULT_NAMESPACE, base_dir: Optional[Path] = None):
        self.namespace = str(namespace or DEFAULT_NAMESPACE)
        self.base_dir = Path(base_dir) if base_dir else None
        self.primary = self._build_primary_backend()
        self.fallback = _FileFallbackBackend(self.namespace, base_dir=self.base_dir)

    def _build_primary_backend(self) -> Optional[_BaseBackend]:
        forced = str(os.environ.get("WSHAWK_SECRET_BACKEND", "auto") or "auto").strip().lower()
        if forced == "file":
            return None
        if forced == "secret-tool":
            return _SecretToolBackend(self.namespace)
        if forced in {"macos", "keychain", "security"}:
            return _MacKeychainBackend(self.namespace)
        if forced in {"windows", "dpapi"}:
            return _WindowsDPAPIBackend(self.namespace, base_dir=self.base_dir)

        system_name = platform.system().lower()
        if system_name == "linux" and shutil.which("secret-tool"):
            return _SecretToolBackend(self.namespace)
        if system_name == "darwin" and shutil.which("security"):
            return _MacKeychainBackend(self.namespace)
        if system_name == "windows":
            return _WindowsDPAPIBackend(self.namespace, base_dir=self.base_dir)
        return None

    @property
    def backend_name(self) -> str:
        return self.primary.name if self.primary else self.fallback.name

    def _try_primary(self, method: str, *args):
        if not self.primary:
            raise SecretStoreError("no primary secret backend configured")
        return getattr(self.primary, method)(*args)

    def get(self, key: str, default: str = "") -> str:
        try:
            value = self._try_primary("get", key)
            if value:
                return value
        except Exception:
            pass
        fallback_value = self.fallback.get(key)
        return fallback_value if fallback_value else default

    def set(self, key: str, value: str) -> None:
        try:
            self._try_primary("set", key, value)
            self.fallback.delete(key)
            return
        except Exception:
            self.fallback.set(key, value)

    def delete(self, key: str) -> None:
        try:
            self._try_primary("delete", key)
        except Exception:
            pass
        self.fallback.delete(key)

    def reference(self, key: str) -> str:
        return f"secret:{self.namespace}:{key}"

    @staticmethod
    def parse_reference(reference: str) -> tuple[str, str]:
        if not isinstance(reference, str) or not reference.startswith("secret:"):
            raise ValueError("Not a secret reference")
        parts = reference.split(":", 2)
        if len(parts) == 2:
            return DEFAULT_NAMESPACE, parts[1]
        return parts[1] or DEFAULT_NAMESPACE, parts[2]

    @classmethod
    def resolve_reference(cls, reference: str, default: str = "", base_dir: Optional[Path] = None) -> str:
        try:
            namespace, key = cls.parse_reference(reference)
        except ValueError:
            return default
        return cls(namespace=namespace, base_dir=base_dir).get(key, default=default)
