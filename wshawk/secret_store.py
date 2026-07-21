import base64
import json
import os
import platform
import shutil
import subprocess
import tempfile
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
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SecretStoreError(f"Unable to read secret store {self.path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise SecretStoreError(f"Secret store {self.path} does not contain an object")
        return payload

    def _save(self, payload: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            self._chmod(temporary_path, 0o600)
            os.replace(temporary_path, self.path)
        finally:
            temporary_path.unlink(missing_ok=True)
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
            if payload:
                self._save(payload)
            else:
                self.path.unlink(missing_ok=True)

    def items(self) -> dict:
        return self._load()


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
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if not shell:
            raise SecretStoreError("PowerShell is not available for DPAPI secret storage")
        self.shell = shell

    def _run_powershell(self, command: str, input_text: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            input=input_text,
            text=True,
            capture_output=True,
            check=check,
        )

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SecretStoreError(f"Unable to read DPAPI secret store {self.path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise SecretStoreError(f"DPAPI secret store {self.path} does not contain an object")
        return payload

    def _save(self, payload: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            try:
                os.chmod(temporary_path, 0o600)
            except OSError:
                pass
            os.replace(temporary_path, self.path)
        finally:
            temporary_path.unlink(missing_ok=True)

    def _encrypt(self, value: str) -> str:
        result = self._run_powershell(
            "Add-Type -AssemblyName System.Security; "
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8; "
            "$raw=[Console]::In.ReadToEnd(); "
            "$bytes=[Text.Encoding]::UTF8.GetBytes($raw); "
            "$enc=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser); "
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
            "Add-Type -AssemblyName System.Security; "
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8; "
            "$raw=[Console]::In.ReadToEnd().Trim(); "
            "$bytes=[Convert]::FromBase64String($raw); "
            "$dec=[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser); "
            "[Text.Encoding]::UTF8.GetString($dec)",
            input_text=value,
            check=False,
        )
        if result.returncode != 0:
            raise SecretStoreError(result.stderr.strip() or "DPAPI decrypt failed")
        return result.stdout.rstrip("\r\n")

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
    """Platform-aware secret storage that never silently downgrades a backend.

    Plaintext file storage is used only when explicitly selected or when the
    current platform has no supported operating-system secret backend.
    """

    def __init__(self, namespace: str = DEFAULT_NAMESPACE, base_dir: Optional[Path] = None):
        self.namespace = str(namespace or DEFAULT_NAMESPACE)
        self.base_dir = Path(base_dir) if base_dir else None
        self.primary = self._build_primary_backend()
        self.fallback = _FileFallbackBackend(self.namespace, base_dir=self.base_dir)
        if self.primary:
            self._migrate_legacy_fallback()

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
        try:
            return getattr(self.primary, method)(*args)
        except SecretStoreError:
            raise
        except Exception as exc:
            raise SecretStoreError(f"{self.primary.name} secret operation failed: {exc}") from exc

    def _migrate_legacy_fallback(self) -> int:
        legacy_values = self.fallback.items()
        if not legacy_values:
            return 0

        migrated = 0
        for key, value in legacy_values.items():
            self._try_primary("set", str(key), str(value))
            self.fallback.delete(str(key))
            migrated += 1
        return migrated

    def get(self, key: str, default: str = "") -> str:
        if self.primary:
            value = self._try_primary("get", key)
        else:
            value = self.fallback.get(key)
        return value if value else default

    def set(self, key: str, value: str) -> None:
        if self.primary:
            self._try_primary("set", key, value)
            self.fallback.delete(key)
            return
        self.fallback.set(key, value)

    def delete(self, key: str) -> None:
        if self.primary:
            self._try_primary("delete", key)
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
