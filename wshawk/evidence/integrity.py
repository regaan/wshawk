import base64
import getpass
import hashlib
import json
import platform
import socket
from pathlib import Path
from typing import Any, Dict, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from wshawk import __version__
from wshawk.secret_store import SecretStore


class EvidenceIntegrityService:
    def __init__(self, base_dir: Path | None = None):
        self.secret_store = SecretStore("wshawk-evidence", base_dir=base_dir)
        self.private_key_name = "ed25519-private-key"

    @staticmethod
    def _canonical_json(data: Any) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def _sha256_hex(cls, data: Any) -> str:
        text = data if isinstance(data, str) else cls._canonical_json(data)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def _hash_chain(cls, items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        previous = ""
        count = 0
        for item in items:
            previous = cls._sha256_hex({"previous": previous, "item": item})
            count += 1
        return {"count": count, "root": previous}

    def _load_private_key(self) -> Ed25519PrivateKey:
        encoded = self.secret_store.get(self.private_key_name, "")
        if encoded:
            raw = base64.b64decode(encoded.encode("ascii"))
            return Ed25519PrivateKey.from_private_bytes(raw)

        private_key = Ed25519PrivateKey.generate()
        raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.secret_store.set(self.private_key_name, base64.b64encode(raw).decode("ascii"))
        return private_key

    def attach(self, bundle: Dict[str, Any], export_format: str) -> Dict[str, Any]:
        enriched = dict(bundle or {})
        enriched["provenance"] = {
            "tool": "WSHawk",
            "version": __version__,
            "format": str(export_format or "json"),
            "operator": getpass.getuser(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "generated_at": enriched.get("generated_at"),
        }

        timeline = enriched.get("timeline") or {}
        chain_roots = {
            "events": self._hash_chain(enriched.get("events", []) or []),
            "evidence": self._hash_chain(enriched.get("evidence", []) or []),
            "findings": self._hash_chain(timeline.get("findings", []) or []),
            "http_flows": self._hash_chain(timeline.get("http_flows", []) or []),
            "ws_connections": self._hash_chain(timeline.get("ws_connections", []) or []),
            "ws_frames": self._hash_chain(timeline.get("ws_frames", []) or []),
        }

        signable = dict(enriched)
        signable.pop("integrity", None)
        canonical = self._canonical_json(signable)
        private_key = self._load_private_key()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signature = private_key.sign(canonical.encode("utf-8"))

        enriched["integrity"] = {
            "scheme": "ed25519-sha256",
            "key_id": hashlib.sha256(public_key).hexdigest()[:16],
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "content_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "signature": base64.b64encode(signature).decode("ascii"),
            "chain_roots": chain_roots,
        }
        return enriched

    def verify(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(bundle, dict):
            return {"ok": False, "reason": "bundle is not a JSON object"}

        integrity = bundle.get("integrity") or {}
        public_key_b64 = integrity.get("public_key")
        signature_b64 = integrity.get("signature")
        expected_sha = integrity.get("content_sha256")
        if not public_key_b64 or not signature_b64 or not expected_sha:
            return {"ok": False, "reason": "integrity metadata missing"}

        signable = dict(bundle)
        signable.pop("integrity", None)
        canonical = self._canonical_json(signable)
        actual_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if actual_sha != expected_sha:
            return {"ok": False, "reason": "bundle hash mismatch"}

        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64.encode("ascii")))
            public_key.verify(
                base64.b64decode(signature_b64.encode("ascii")),
                canonical.encode("utf-8"),
            )
        except (ValueError, InvalidSignature):
            return {"ok": False, "reason": "signature verification failed"}

        timeline = signable.get("timeline") or {}
        actual_roots = {
            "events": self._hash_chain(signable.get("events", []) or []),
            "evidence": self._hash_chain(signable.get("evidence", []) or []),
            "findings": self._hash_chain(timeline.get("findings", []) or []),
            "http_flows": self._hash_chain(timeline.get("http_flows", []) or []),
            "ws_connections": self._hash_chain(timeline.get("ws_connections", []) or []),
            "ws_frames": self._hash_chain(timeline.get("ws_frames", []) or []),
        }
        if actual_roots != (integrity.get("chain_roots") or {}):
            return {"ok": False, "reason": "chain root mismatch"}

        return {"ok": True, "key_id": integrity.get("key_id", ""), "content_sha256": actual_sha}
