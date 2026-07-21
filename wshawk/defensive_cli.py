#!/usr/bin/env python3
"""
WSHawk Defensive Validation CLI
Entry point for defensive security validation
"""

import argparse
import asyncio
import sys
from ._version_info import __version__
from .defensive_validation import run_defensive_validation
from .console import Colors


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wshawk-defensive",
        description="Run WSHawk defensive validation against an authorized WebSocket target.",
    )
    parser.add_argument("url", nargs="?", help="Target WebSocket URL (ws:// or wss://)")
    parser.add_argument("--version", action="version", version=f"wshawk-defensive {__version__}")
    parser.add_argument(
        "--origin-limit",
        type=_positive_int,
        default=12,
        help="maximum representative Origin values to probe (default: 12)",
    )
    parser.add_argument(
        "--origin-concurrency",
        type=_positive_int,
        default=4,
        help="maximum concurrent Origin handshakes (default: 4)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=_positive_float,
        default=5.0,
        help="connection and response timeout in seconds (default: 5)",
    )
    return parser


async def main(argv=None):
    """
    Main entry point for defensive validation
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    target_url = args.url
    if not target_url:
        if not sys.stdin.isatty():
            parser.error("a WebSocket URL is required")
        print(f"{Colors.CYAN}╦ ╦╔═╗╦ ╦╔═╗╦ ╦╦╔═{Colors.END}")
        print(f"{Colors.CYAN}║║║╚═╗╠═╣╠═╣║║║╠╩╗{Colors.END}")
        print(f"{Colors.CYAN}╚╩╝╚═╝╩ ╩╩ ╩╚╩╝╩ ╩{Colors.END}")
        print()
        print(f"{Colors.BOLD}Defensive Validation Suite{Colors.END}")
        print(f"Created by: Regaan (@regaan)")
        print("━" * 70)
        print()
        print(f"{Colors.CYAN}Enter WebSocket URL (e.g., ws://example.com or wss://example.com):{Colors.END}")
        target_url = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if not target_url:
        parser.error("a WebSocket URL is required")
    
    # Validate URL
    if not target_url.startswith(('ws://', 'wss://')):
        parser.error("URL must start with ws:// or wss://")
    
    # Run defensive validation
    result = await run_defensive_validation(
        target_url,
        origin_limit=args.origin_limit,
        origin_concurrency=args.origin_concurrency,
        connection_timeout=args.connect_timeout,
    )
    return getattr(result, 'exit_code', 0)


def cli(argv=None):
    """Entry point for pip-installed command"""
    try:
        return asyncio.run(main(argv))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Validation interrupted by user{Colors.END}")
        return 130
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
