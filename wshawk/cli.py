"""Primary command-line entry point for the modern scanner runtime."""

import argparse
import asyncio
import sys

from ._version_info import __version__
from .console import Colors, Logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"WSHawk v{__version__} - Professional WebSocket Security Scanner"
    )
    parser.add_argument("target", nargs="?", help="Target WebSocket URL (ws:// or wss://)")
    parser.add_argument("--version", action="version", version=f"wshawk {__version__}")
    parser.add_argument("--web", action="store_true", help="Launch the Web Management Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Web dashboard port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Web dashboard host (default: 127.0.0.1)")
    return parser


async def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.web:
        try:
            from .web.app import run_web
        except ImportError:
            Logger.error("Flask required for Web GUI. Install: pip install flask")
            return 1
        run_web(host=args.host, port=args.port)
        return 0

    target_url = args.target
    if not target_url:
        if not sys.stdin.isatty():
            parser.error("a WebSocket URL is required unless --web is used")
        Logger.banner()
        print(f"{Colors.CYAN}Enter WebSocket URL (e.g., ws://example.com or wss://example.com):{Colors.END}")
        target_url = input(f"{Colors.YELLOW}> {Colors.END}").strip()

    if not target_url:
        parser.error("a WebSocket URL is required")
    if not target_url.startswith(("ws://", "wss://")):
        parser.error("URL must start with ws:// or wss://")

    from .scanner_v2 import WSHawkV2

    Logger.info(f"Using WSHawk v{__version__} Advanced Scanner")
    scanner = WSHawkV2(target_url, max_rps=10)
    scanner.use_headless_browser = False
    scanner.use_oast = True
    await scanner.run_heuristic_scan()
    return 0 if scanner.scan_completed else 1


def cli(argv=None) -> int:
    try:
        return asyncio.run(main(argv))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        return 130
    except RuntimeError as exc:
        Logger.error(f"CLI runtime failed: {exc}")
        return 1


__all__ = ["build_parser", "main", "cli"]
