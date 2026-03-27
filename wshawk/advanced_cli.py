#!/usr/bin/env python3
"""
Thin compatibility wrapper for the frozen advanced legacy CLI.
"""

from .legacy_advanced_cli import *  # noqa: F401,F403
from .legacy_advanced_cli import cli as legacy_cli
from .legacy_advanced_cli import main as legacy_main


async def main():
    return await legacy_main()


def cli():
    return legacy_cli()


if __name__ == "__main__":
    cli()
