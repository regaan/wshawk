import os
from pathlib import Path
from typing import Any, Dict

from fastapi import HTTPException

from wshawk.secret_store import SecretStore
from wshawk.bridge_security import EXTENSION_PAIRING

from .context import BridgeContext


SECRET_FILE_MAP = {
    "jiraToken": "jira_api_token",
    "ddKey": "defectdojo_api_key",
    "ai_api_key": "ai_api_key",
}


def _resolve_config_path() -> Path:
    config_path = Path("./wshawk.yaml")
    if config_path.exists():
        return config_path
    alternate = Path("./wshawk.yml")
    if alternate.exists():
        return alternate
    return config_path


def _write_secret_reference(config_path: Path, secret_name: str, incoming_value: Any, existing_reference: str = "") -> str:
    secret_value = str(incoming_value or "").strip()
    if not secret_value:
        return existing_reference or ""

    secret_store = SecretStore("wshawk-config", base_dir=config_path.parent)
    secret_store.set(secret_name, secret_value)
    return secret_store.reference(secret_name)


def register_system_routes(ctx: BridgeContext) -> None:
    @ctx.app.get("/status")
    async def get_status():
        return {
            "status": "online",
            "scanning": ctx.state.scanner is not None,
            "interception": ctx.state.interception_enabled,
            "active_scans": len(ctx.state.active_scans),
            "token_required": True,
            "projects": len(ctx.db.list_projects(limit=1000)),
        }

    @ctx.app.get("/config/get")
    async def get_config():
        try:
            from wshawk.config import WSHawkConfig

            config = WSHawkConfig.load()
            secret_backend = SecretStore("wshawk-config", base_dir=_resolve_config_path().parent).backend_name
            return {
                "status": "success",
                "jiraUrl": config.get("integrations.jira.url", ""),
                "jiraEmail": config.get("integrations.jira.email", ""),
                "jiraProject": config.get("integrations.jira.project_key", "SEC"),
                "jiraTokenConfigured": bool(config.get("integrations.jira.api_token", "")),
                "ddUrl": config.get("integrations.defectdojo.url", ""),
                "ddKeyConfigured": bool(config.get("integrations.defectdojo.api_key", "")),
                "ai_provider": config.get("ai.provider", "ollama"),
                "ai_model": config.get("ai.model", ""),
                "ai_base_url": config.get("ai.base_url", ""),
                "aiApiKeyConfigured": bool(config.get("ai.api_key", "")),
                "secretBackend": secret_backend,
            }
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.post("/config/save")
    async def save_config(data: Dict[str, Any]):
        try:
            import yaml

            config_path = _resolve_config_path()

            current_data = {}
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    current_data = yaml.safe_load(f) or {}

            integrations = current_data.setdefault("integrations", {})
            jira_data = integrations.setdefault("jira", {})
            dd_data = integrations.setdefault("defectdojo", {})
            ai_data = current_data.setdefault("ai", {})

            if data.get("jiraUrl"):
                jira_data["url"] = data.get("jiraUrl")
            if data.get("jiraEmail"):
                jira_data["email"] = data.get("jiraEmail")
            if data.get("jiraProject"):
                jira_data["project_key"] = data.get("jiraProject")
            jira_data["api_token"] = _write_secret_reference(
                config_path,
                SECRET_FILE_MAP["jiraToken"],
                data.get("jiraToken"),
                str(jira_data.get("api_token", "") or ""),
            )
            jira_data["enabled"] = bool(str(jira_data.get("url", "")).strip() and str(jira_data.get("api_token", "")).strip())

            if data.get("ddUrl"):
                dd_data["url"] = data.get("ddUrl")
            dd_data["api_key"] = _write_secret_reference(
                config_path,
                SECRET_FILE_MAP["ddKey"],
                data.get("ddKey"),
                str(dd_data.get("api_key", "") or ""),
            )
            dd_data["enabled"] = bool(str(dd_data.get("url", "")).strip() and str(dd_data.get("api_key", "")).strip())

            if data.get("ai_provider"):
                ai_data["provider"] = data.get("ai_provider")
            if data.get("ai_model"):
                ai_data["model"] = data.get("ai_model")
            if data.get("ai_base_url"):
                ai_data["base_url"] = data.get("ai_base_url")
            ai_data["api_key"] = _write_secret_reference(
                config_path,
                SECRET_FILE_MAP["ai_api_key"],
                data.get("ai_api_key"),
                str(ai_data.get("api_key", "") or ""),
            )

            with open(config_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(current_data, f, default_flow_style=False, sort_keys=False)

            return {"status": "success"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

    @ctx.app.get("/extension/pairing/status")
    async def extension_pairing_status():
        return {
            "status": "success",
            "pairing": EXTENSION_PAIRING.describe(),
        }

    @ctx.app.post("/extension/pairing/reset")
    async def extension_pairing_reset(data: Dict[str, Any]):
        EXTENSION_PAIRING.revoke(clear_trust=bool((data or {}).get("clear_trust", True)))
        return {"status": "success"}

    @ctx.app.post("/ai/context-exploit")
    async def ai_context_exploit(data: Dict[str, Any]):
        try:
            from wshawk.ai_engine import AIEngine
            from wshawk.ai_exploit_engine import AIExploitEngine
            from wshawk.config import WSHawkConfig

            full_text = data.get("full_text", "")
            selection = data.get("selection", "")
            cursor_pos = data.get("cursor_pos", 0)
            vuln_types = data.get("vuln_types", None)
            count = data.get("count", 10)

            if not selection:
                return {"status": "error", "msg": "No text selected"}

            ai_engine = None
            try:
                cfg = WSHawkConfig.load(str(_resolve_config_path()))
                provider = cfg.get("ai.provider", "ollama")
                model = cfg.get("ai.model", "")
                base_url = cfg.get("ai.base_url", "")
                api_key = cfg.get("ai.api_key", "")
                if model:
                    ai_engine = AIEngine(
                        provider=provider,
                        model=model,
                        base_url=base_url or None,
                        api_key=api_key or None,
                    )
            except Exception as e:
                ctx.logger.warning(f"AI engine init failed, using fallback payloads: {e}")

            exploit_engine = AIExploitEngine(ai_engine=ai_engine)
            result = await exploit_engine.generate_exploits(
                full_text=full_text,
                selection=selection,
                cursor_pos=cursor_pos,
                vuln_types=vuln_types,
                count=count,
            )

            return {"status": "success", **result}
        except Exception as e:
            ctx.logger.error(f"AI context-exploit error: {e}")
            raise HTTPException(status_code=500, detail=str(e))
