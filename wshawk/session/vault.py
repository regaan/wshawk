from datetime import datetime
from typing import Any, Dict, List, Optional

from wshawk.db_manager import WSHawkDatabase
from wshawk.store import ProjectStore


class IdentityVaultService:
    """Project-backed identity vault with token lineage recording."""

    def __init__(self, db: Optional[WSHawkDatabase] = None, store: Optional[ProjectStore] = None):
        self.db = db or WSHawkDatabase()
        self.store = store or ProjectStore(self.db)

    def save_identity(
        self,
        *,
        project_id: str,
        alias: str,
        source: str = "manual",
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        tokens: Optional[Dict[str, Any]] = None,
        storage: Optional[Dict[str, Any]] = None,
        notes: str = "",
        identity_id: Optional[str] = None,
        last_validated_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_cookies = cookies or []
        if isinstance(normalized_cookies, dict):
            normalized_cookies = [
                {"name": str(name), "value": str(value)}
                for name, value in normalized_cookies.items()
            ]
        identity = self.db.save_identity(
            project_id=project_id,
            alias=alias,
            source=source,
            cookies=normalized_cookies,
            headers=headers or {},
            tokens=tokens or {},
            storage=storage or {},
            notes=notes,
            identity_id=identity_id,
            last_validated_at=last_validated_at,
        )
        self.store.add_browser_artifact(
            project_id=project_id,
            identity_id=identity["id"],
            artifact_type="identity_lineage",
            source=source,
            url="",
            payload={
                "alias": alias,
                "source": source,
                "token_keys": sorted((tokens or {}).keys()),
                "header_keys": sorted((headers or {}).keys()),
                "stored_at": datetime.now().isoformat(),
            },
        )
        return identity

    def save_auth_tokens(
        self,
        *,
        project_id: str,
        alias: str,
        source: str,
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        session_token: str = "",
        storage: Optional[Dict[str, Any]] = None,
        flow: Optional[Dict[str, Any]] = None,
        role: str = "",
    ) -> Dict[str, Any]:
        tokens = {}
        if session_token:
            tokens["session_token"] = session_token
        if role:
            tokens["role"] = role

        identity = self.save_identity(
            project_id=project_id,
            alias=alias,
            source=source,
            cookies=cookies,
            headers=headers,
            tokens=tokens,
            storage=storage,
            last_validated_at=datetime.now().isoformat(),
        )
        self.store.add_browser_artifact(
            project_id=project_id,
            identity_id=identity["id"],
            artifact_type="auth_flow_replay",
            source=source,
            url=(flow or {}).get("target_ws_url", ""),
            payload={
                "flow": flow or {},
                "cookies": cookies or [],
                "headers": headers or {},
                "session_token": session_token,
                "role": role,
                "captured_at": datetime.now().isoformat(),
            },
        )
        return identity

    def list_identities(self, project_id: str):
        return self.db.list_identities(project_id)
