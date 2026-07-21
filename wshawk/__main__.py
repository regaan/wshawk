#!/usr/bin/env python3
"""Executable module for the modern WSHawk command-line interface."""

from .cli import build_parser, cli as modern_cli, main as modern_main

__all__ = ["build_parser", "main", "cli"]


async def main(argv=None):
    return await modern_main(argv)


def cli(argv=None):
    return modern_cli(argv)


if __name__ == "__main__":
    raise SystemExit(cli())
