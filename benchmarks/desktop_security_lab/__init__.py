"""Standalone targets for end-to-end WSHawk desktop security validation."""

from .app import app, ground_truth, reset_state

__all__ = ["app", "ground_truth", "reset_state"]
