from datetime import datetime
from typing import Any, Dict

from fastapi import HTTPException

from wshawk.team_engine import TeamEngine

from .context import BridgeContext


def register_team_routes(ctx: BridgeContext) -> None:
    team = TeamEngine()
    ctx.team = team

    @ctx.app.post("/team/create")
    async def team_create(data: Dict[str, Any]):
        name = data.get("name", "Operator").strip() or "Operator"
        target = data.get("target", "")
        room = team.create_room(name, target)
        return {"status": "success", "room_code": room.code}

    @ctx.app.post("/team/join")
    async def team_join(data: Dict[str, Any]):
        code = data.get("room_code", "").strip().upper()
        room = team.get_room(code)
        if not room:
            raise HTTPException(status_code=404, detail="Room not found. Check the room code.")
        return {
            "status": "success",
            "room_code": room.code,
            "operator_count": room.operator_count,
            "target": room.target,
            "created_by": room.created_by,
        }

    @ctx.app.get("/team/info/{room_code}")
    async def team_info(room_code: str):
        room = team.get_room(room_code)
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
        return {"status": "success", **room.info()}

    @ctx.app.post("/team/leave")
    async def team_leave_rest(data: Dict[str, Any]):
        code = data.get("room_code", "").strip().upper()
        name = data.get("name", "Operator")
        team.leave_room_by_name(code, name)
        return {"status": "success"}

    @ctx.app.get("/team/stats")
    async def team_stats():
        return {"status": "success", **team.stats()}

    @ctx.sio.on("team_join")
    async def sio_team_join(sid, data):
        code = data.get("room_code", "").strip().upper()
        name = data.get("name", "Operator")
        room, op = team.join_room(code, sid, name)
        if not room:
            await ctx.sio.emit("team_error", {"error": "Room not found"}, room=sid)
            return

        await ctx.sio.enter_room(sid, room.sio_room)
        await ctx.sio.emit("team_roster", {"operators": room.roster(), "room_code": room.code}, room=room.sio_room)
        await ctx.sio.emit(
            "team_activity",
            {"type": "join", "operator": op.name, "color": op.color, "time": op.joined_at},
            room=room.sio_room,
        )
        await ctx.sio.emit(
            "team_state",
            {
                "shared_notes": room.shared_notes,
                "shared_endpoints": room.shared_endpoints,
                "target": room.target,
            },
            room=sid,
        )
        print(f"[Team] {name} joined room {room.code} ({room.operator_count} operators)")

    @ctx.sio.on("team_leave")
    async def sio_team_leave(sid, data=None):
        room, op = team.leave_room(sid)
        if not room or not op:
            return

        await ctx.sio.leave_room(sid, room.sio_room)
        await ctx.sio.emit("team_roster", {"operators": room.roster(), "room_code": room.code}, room=room.sio_room)
        await ctx.sio.emit(
            "team_activity",
            {"type": "leave", "operator": op.name, "color": op.color, "time": datetime.now().isoformat()},
            room=room.sio_room,
        )
        print(f"[Team] {op.name} left room {room.code}")

    @ctx.sio.on("team_notes_update")
    async def sio_team_notes_update(sid, data):
        result = team.update_notes(sid, data.get("content", ""))
        if not result:
            return
        room, op = result
        await ctx.sio.emit(
            "team_notes_sync",
            {
                "content": data.get("content", ""),
                "cursor_pos": data.get("cursor_pos", 0),
                "operator": op.name,
                "color": op.color,
            },
            room=room.sio_room,
            skip_sid=sid,
        )

    @ctx.sio.on("team_cursor_move")
    async def sio_team_cursor_move(sid, data):
        result = team.update_cursor(sid, data.get("position"), data.get("tab", "notes"))
        if not result:
            return
        room, op = result
        await ctx.sio.emit(
            "team_cursor_sync",
            {
                "sid": sid,
                "operator": op.name,
                "color": op.color,
                "position": data.get("position"),
                "tab": data.get("tab", "notes"),
            },
            room=room.sio_room,
            skip_sid=sid,
        )

    @ctx.sio.on("team_endpoint_add")
    async def sio_team_endpoint_add(sid, data):
        result = team.add_endpoint(sid, data.get("endpoint", {}))
        if not result:
            return
        room, op = result
        await ctx.sio.emit(
            "team_endpoint_sync",
            {"endpoint": data.get("endpoint", {}), "operator": op.name, "color": op.color},
            room=room.sio_room,
            skip_sid=sid,
        )

    @ctx.sio.on("team_finding")
    async def sio_team_finding(sid, data):
        result = team.log_finding(sid, data.get("finding", {}))
        if not result:
            return
        room, entry = result
        await ctx.sio.emit("team_activity", entry.to_dict(), room=room.sio_room)

    @ctx.sio.on("team_scan_event")
    async def sio_team_scan_event(sid, data):
        result = team.log_scan_event(
            sid,
            data.get("scan_type", "unknown"),
            data.get("target", ""),
            data.get("status", "started"),
            data.get("results_count", 0),
        )
        if not result:
            return
        room, entry = result
        await ctx.sio.emit("team_activity", entry.to_dict(), room=room.sio_room)
