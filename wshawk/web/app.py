#!/usr/bin/env python3
"""
Thin compatibility wrapper for the frozen legacy Flask dashboard.
"""

from .legacy_app import *  # noqa: F401,F403
from .legacy_app import create_app, run_web


if __name__ == "__main__":
    run_web(debug=True)
