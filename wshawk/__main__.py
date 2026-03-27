#!/usr/bin/env python3
"""
Thin compatibility wrapper for the frozen legacy CLI/runtime.

Legacy scanner classes and helpers now live in `wshawk.legacy_core` so the
platform entrypoint can stay small and stable.
"""

from .legacy_core import *  # noqa: F401,F403
from .legacy_core import cli as legacy_cli
from .legacy_core import main as legacy_main


async def main():
    return await legacy_main()


def cli():
    return legacy_cli()


if __name__ == "__main__":
    cli()
