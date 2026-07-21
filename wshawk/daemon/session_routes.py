"""Desktop session persistence routes and snapshot sanitization."""

import json
from datetime import datetime
from typing import Any, Dict

from fastapi import HTTPException
from wshawk._version_info import __version__

from .context import BridgeContext


def _sanitize_session_snapshot(raw_session: Dict[str, Any]) -> Dict[str, Any]:
    session = raw_session if isinstance(raw_session, dict) else {}
    snapshots = session.get("snapshots") if isinstance(session.get("snapshots"), dict) else {}

    tables = {}
    for key, rows in list((snapshots.get("tables") or {}).items())[:32]:
        if not isinstance(rows, list):
            continue
        sanitized_rows = []
        for row in rows[:500]:
            if not isinstance(row, list):
                continue
            sanitized_rows.append([str(cell)[:4096] for cell in row[:16]])
        tables[str(key)[:128]] = sanitized_rows

    sections = {}
    for key, value in list((snapshots.get("sections") or {}).items())[:32]:
        sections[str(key)[:128]] = str(value)[:65536]

    stats = {}
    for key, value in list((snapshots.get("stats") or {}).items())[:64]:
        stats[str(key)[:128]] = str(value)[:256]

    return {
        "target": str(session.get("target", ""))[:4096],
        "snapshots": {
            "tables": tables,
            "sections": sections,
            "stats": stats,
        },
    }


def register_session_routes(ctx: BridgeContext) -> None:
    @ctx.app.post("/session/save")
    async def session_save(data: Dict[str, Any]):
        name = data.get("name", "").strip() or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        safe_name = "".join(c for c in name if c.isalnum() or c in "-_").strip()
        if not safe_name:
            safe_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        session_data = {
            "type": "session_snapshot",
            "name": safe_name,
            "created": datetime.now().isoformat(),
            "version": __version__,
            "data": _sanitize_session_snapshot(data.get("session", {})),
        }
        try:
            project = ctx.db.save_project(
                name=safe_name,
                target_url=session_data["data"].get("target", ""),
                metadata=session_data,
                project_id=data.get("project_id"),
            )
            return {"status": "success", "path": f"db:{project['id']}", "name": safe_name, "project_id": project["id"]}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            ctx.logger.exception("Unexpected session persistence failure")
            raise HTTPException(status_code=500, detail="Session persistence failed") from exc

    @ctx.app.post("/session/load")
    async def session_load(data: Dict[str, Any]):
        name = data.get("name", "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Session name required")

        project = ctx.db.get_project_by_name(name)
        if not project:
            raise HTTPException(status_code=404, detail=f"Session '{name}' not found")

        metadata = project.get("metadata") or {}
        if "data" not in metadata:
            metadata = {
                "type": "session_snapshot",
                "name": project["name"],
                "created": project["created_at"],
                "version": __version__,
                "data": _sanitize_session_snapshot(metadata),
            }
        metadata["data"] = _sanitize_session_snapshot(metadata.get("data", {}))
        return {"status": "success", "session": metadata, "project_id": project["id"]}

    @ctx.app.get("/session/list")
    async def session_list():
        sessions = []
        for project in ctx.db.list_projects(limit=500):
            metadata = project.get("metadata") or {}
            if metadata.get("type") not in ("session_snapshot", None):
                continue
            sessions.append(
                {
                    "name": project["name"],
                    "created": metadata.get("created", project["created_at"]),
                    "size": len(json.dumps(metadata)),
                    "project_id": project["id"],
                }
            )

        return {"status": "success", "sessions": sessions, "count": len(sessions)}

    @ctx.app.delete("/session/delete")
    async def session_delete(data: Dict[str, Any]):
        name = data.get("name", "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Session name required")

        if ctx.db.delete_project_by_name(name):
            return {"status": "success"}
        raise HTTPException(status_code=404, detail="Session not found")


__all__ = ["register_session_routes"]
