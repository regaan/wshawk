from __future__ import annotations

import argparse
import json
import os
import socket
from pathlib import Path
from typing import Any

import uvicorn

from benchmarks.desktop_security_lab.app import app, ground_truth, reset_state


READY_PREFIX = "WSHAWK_DESKTOP_LAB_READY="


def bind_loopback(port: int = 0) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", max(0, int(port))))
    listener.listen(128)
    return listener


def ready_payload(port: int) -> dict[str, Any]:
    truth = ground_truth()
    base_url = f"http://127.0.0.1:{port}"
    return {
        "schema_version": 1,
        "pid": os.getpid(),
        "host": "127.0.0.1",
        "port": port,
        "base_url": base_url,
        "vulnerable_url": f"{base_url}/vulnerable/portal",
        "hardened_url": f"{base_url}/hardened/portal",
        "vulnerable_ws_url": f"ws://127.0.0.1:{port}/vulnerable/ws",
        "hardened_ws_url": f"ws://127.0.0.1:{port}/hardened/ws",
        "vulnerable_probe_ws_url": f"ws://127.0.0.1:{port}/vulnerable/probe-ws",
        "hardened_probe_ws_url": f"ws://127.0.0.1:{port}/hardened/probe-ws",
        "health_url": f"{base_url}/lab/health",
        "ground_truth_url": f"{base_url}/lab/ground-truth",
        "case_count": len(truth["cases"]),
    }


def write_ready_file(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the localhost-only WSHawk desktop security lab.")
    parser.add_argument("--port", type=int, default=0, help="Loopback port; 0 chooses an ephemeral port.")
    parser.add_argument("--ready-file", type=Path, help="Optional JSON file receiving lab connection details.")
    parser.add_argument("--log-level", default="warning", choices=("critical", "error", "warning", "info"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    reset_state()
    listener = bind_loopback(args.port)
    port = int(listener.getsockname()[1])
    payload = ready_payload(port)
    if args.ready_file:
        write_ready_file(args.ready_file, payload)
    print(f"{READY_PREFIX}{json.dumps(payload, sort_keys=True)}", flush=True)

    config = uvicorn.Config(app, log_level=args.log_level, lifespan="on")
    server = uvicorn.Server(config)
    try:
        server.run(sockets=[listener])
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
