"""Packaged attack-payload catalog shared by scanners and daemon routes."""

from importlib.resources import files
from typing import Dict, List

from .console import Logger


class WSPayloads:
    """Load bundled WebSocket attack payloads with process-local caching."""

    _payloads_cache: Dict[str, List[str]] = {}

    @classmethod
    def load_payloads(cls, filename: str) -> List[str]:
        if filename in cls._payloads_cache:
            return cls._payloads_cache[filename]

        try:
            payload_file = files("wshawk").joinpath("payloads", filename)
            payloads = [
                line.strip()
                for line in payload_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
        except FileNotFoundError:
            Logger.warning(f"Payload file not found: {filename}")
            return []
        except Exception as exc:
            Logger.error(f"Error loading payloads from {filename}: {exc}")
            return []

        cls._payloads_cache[filename] = payloads
        return payloads

    @classmethod
    def get_sql_injection(cls):
        return cls.load_payloads("sql_injection.txt")

    @classmethod
    def get_xss(cls):
        return cls.load_payloads("xss.txt")

    @classmethod
    def get_command_injection(cls):
        return cls.load_payloads("command_injection.txt")

    @classmethod
    def get_nosql_injection(cls):
        return cls.load_payloads("nosql_injection.txt")

    @classmethod
    def get_path_traversal(cls):
        return cls.load_payloads("path_traversal.txt")

    @classmethod
    def get_ldap_injection(cls):
        return cls.load_payloads("ldap_injection.txt")

    @classmethod
    def get_xxe(cls):
        return cls.load_payloads("xxe.txt")

    @classmethod
    def get_ssti(cls):
        return cls.load_payloads("ssti.txt")

    @classmethod
    def get_open_redirect(cls):
        return cls.load_payloads("open_redirect.txt")

    @classmethod
    def get_csv_injection(cls):
        return cls.load_payloads("csv_injection.txt")


__all__ = ["WSPayloads"]
