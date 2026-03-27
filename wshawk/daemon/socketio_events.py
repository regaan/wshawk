from datetime import datetime

from wshawk.bridge_security import socketio_client_is_local, socketio_has_valid_token, socketio_origin_is_trusted

from .context import BridgeContext


def register_socketio_events(ctx: BridgeContext) -> None:
    @ctx.sio.event
    async def connect(sid, environ, auth=None):
        if not socketio_client_is_local(environ):
            raise ConnectionRefusedError("bridge only accepts local clients")

        if not socketio_origin_is_trusted(environ):
            raise ConnectionRefusedError("bridge rejected an untrusted browser origin")

        if not socketio_has_valid_token(environ, auth):
            raise ConnectionRefusedError("bridge authentication required")

        print(f"[*] Frontend connected: {sid}")
        await ctx.sio.emit(
            "system_info",
            {
                "os": __import__("sys").platform,
                "version": ctx.bridge_version,
                "status": "ready",
            },
            room=sid,
        )

    @ctx.sio.event
    async def disconnect(sid):
        print(f"[*] Frontend disconnected: {sid}")
        if not ctx.team:
            return

        try:
            room, op = ctx.team.leave_room(sid)
            if room and op:
                await ctx.sio.leave_room(sid, room.sio_room)
                await ctx.sio.emit(
                    "team_roster",
                    {"operators": room.roster(), "room_code": room.code},
                    room=room.sio_room,
                )
                activity = {
                    "type": "leave",
                    "operator": op.name,
                    "color": op.color,
                    "time": datetime.now().isoformat(),
                }
                await ctx.sio.emit("team_activity", activity, room=room.sio_room)
        except Exception:
            pass
