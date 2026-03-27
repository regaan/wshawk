#!/usr/bin/env python3
"""
WSHawk - Defensive Validation Example

Demonstrates the current defensive helper entrypoint.
"""

import asyncio
from wshawk.defensive_validation import run_defensive_validation


async def defensive_demo():
    target = "ws://localhost:8080/ws"

    print("=" * 60)
    print("WSHawk Defensive Validation")
    print("=" * 60)
    print(f"Target: {target}\n")

    await run_defensive_validation(target)


if __name__ == "__main__":
    asyncio.run(defensive_demo())
