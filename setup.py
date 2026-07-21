"""Compatibility entry point for tools that still invoke ``setup.py``.

All project metadata, dependencies, package discovery, and version information
live in pyproject.toml.
"""

from setuptools import setup


setup()
