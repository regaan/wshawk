from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn


async def asgi_request(
    app,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    body: bytes = b"",
    client_host: str = "127.0.0.1",
):
    headers = headers or {}
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers = {**headers, "content-type": "application/json"}

    split = urlsplit(path)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": split.path,
        "raw_path": split.path.encode("utf-8"),
        "query_string": split.query.encode("utf-8"),
        "headers": [(key.lower().encode("utf-8"), value.encode("utf-8")) for key, value in headers.items()],
        "client": (client_host, 12000),
        "server": ("testserver", 80),
    }
    messages = []
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            await asyncio.sleep(0)
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    payload = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    response_headers = {key.decode("utf-8"): value.decode("utf-8") for key, value in start.get("headers", [])}
    return start["status"], response_headers, payload.decode("utf-8", errors="replace")


def load_expected(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate_expected(result: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    required_checks = expected.get("required_checks", {})
    actual_checks = result.get("checks", {})
    check_results = {name: bool(actual_checks.get(name)) == bool(expected_value) for name, expected_value in required_checks.items()}
    return {
        "lab": result.get("lab"),
        "passed": all(check_results.values()),
        "required_checks": required_checks,
        "actual_checks": actual_checks,
        "check_results": check_results,
        "summary": result.get("summary", {}),
    }


def write_json(path: str | Path, data: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def find_free_port(host: str = "127.0.0.1") -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind((host, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError as exc:  # pragma: no cover - timing-dependent
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {host}:{port} to accept connections: {last_error}")


class LiveASGIServer:
    def __init__(self, app, host: str = "127.0.0.1", port: int | None = None):
        self.app = app
        self.host = host
        self.port = port or find_free_port(host)
        self.server = None
        self.thread = None

    def __enter__(self):
        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="error",
            access_log=False,
            lifespan="on",
        )
        self.server = uvicorn.Server(config)

        def runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self.server.serve())
            finally:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.run_until_complete(loop.shutdown_default_executor())
                loop.close()

        self.thread = threading.Thread(target=runner, daemon=True)
        self.thread.start()
        wait_for_port(self.host, self.port)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=5)
