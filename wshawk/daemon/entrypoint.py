import uvicorn


def run_daemon(socket_app, host: str, port: int):
    """Shared daemon entrypoint used by compatibility launchers."""
    uvicorn.run(socket_app, host=host, port=port, log_level="warning")
