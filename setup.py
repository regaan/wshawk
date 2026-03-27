from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Define requirements 
requirements = [
    "websockets>=12.0",
    "aiohttp>=3.9.0",
    "PyYAML>=6.0",
    "flask>=3.0.0",
    "uvicorn>=0.25.0",
    "fastapi>=0.109.0",
    "python-socketio>=5.10.0",
    "dnspython>=2.4.0",
    "python-whois>=0.8.0",
    "cryptography>=41.0.0",
]

setup(
    name="wshawk",
    version="4.0.0",
    author="Regaan",
    description="Professional WebSocket security scanner with real vulnerability verification, session hijacking tests, and CVSS scoring",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/regaan/wshawk",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*", "docs"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wshawk=wshawk.__main__:cli",
            "wshawk-interactive=wshawk.interactive:cli",
            "wshawk-advanced=wshawk.advanced_cli:cli",
            "wshawk-defensive=wshawk.defensive_cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "wshawk": [
            "payloads/*.txt",
            "payloads/**/*.json",
            "web/templates/*.html",
            "web/static/*",
        ],
    },
    keywords="websocket security scanner penetration-testing bug-bounty vulnerability xss sqli session-hijacking cvss playwright oast waf-bypass",
    project_urls={
        "Bug Reports": "https://github.com/regaan/wshawk/issues",
        "Source": "https://github.com/regaan/wshawk",
        "Documentation": "https://github.com/regaan/wshawk/blob/main/README.md",
    },
)
