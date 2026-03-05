# -*- mode: python ; coding: utf-8 -*-
# WSHawk V3.0.4 — PyInstaller spec for the GUI Bridge sidecar binary
# Bundles the full backend: core scanner, web_pentest toolkit, smart payloads,
# payload mutator, database manager, and all data files.

from PyInstaller.utils.hooks import collect_data_files

all_datas = collect_data_files('certifi') + collect_data_files('aiohttp') + [
        # Payload wordlists (used by scanner + blaster)
        ('wshawk/payloads', 'wshawk/payloads'),
        # Flask web dashboard templates/static (if present)
        ('wshawk/web', 'wshawk/web'),
    ]

a = Analysis(
    ['wshawk/gui_bridge.py'],
    pathex=['.'],
    binaries=[],
    datas=all_datas,
    hiddenimports=[
        # ── Core WSHawk modules ──
        'wshawk',
        'wshawk.__init__',
        'wshawk.__main__',
        'wshawk.scanner_v2',
        'wshawk.config',
        'wshawk.db_manager',
        'wshawk.payload_mutator',
        'wshawk.ws_discovery',
        'wshawk.oast_provider',
        'wshawk.logger',
        'wshawk.rate_limiter',
        'wshawk.resilience',
        'wshawk.cvss_calculator',
        'wshawk.server_fingerprint',
        'wshawk.message_intelligence',
        'wshawk.binary_handler',
        'wshawk.state_machine',
        'wshawk.vulnerability_verifier',
        'wshawk.wss_security_validator',
        'wshawk.session_hijacking_tester',
        'wshawk.ssrf_test',
        'wshawk.enhanced_reporter',
        'wshawk.report_exporter',
        'wshawk.plugin_system',
        'wshawk.defensive_validation',
        'wshawk.ai_engine',
        'wshawk.ai_exploit_engine',        # NEW: Heuristic Auto-Exploit (Highlight-to-Hack)
        'wshawk.dom_invader',              # NEW: Headless DOM XSS Verifier + Auth Flow Recorder
        'wshawk.headless_xss_verifier',    # Legacy verifier (kept for compat)

        # ── Smart Payload Engine ──
        'wshawk.smart_payloads',
        'wshawk.smart_payloads.context_generator',
        'wshawk.smart_payloads.feedback_loop',
        'wshawk.smart_payloads.payload_evolver',

        # ── WAF module ──
        'wshawk.waf',
        'wshawk.waf.detector',

        # ── Web Pentest Toolkit (22 engines) ──
        'wshawk.web_pentest',
        'wshawk.web_pentest.http_proxy',
        'wshawk.web_pentest.fuzzer',
        'wshawk.web_pentest.dir_scanner',
        'wshawk.web_pentest.header_analyzer',
        'wshawk.web_pentest.subdomain_finder',
        'wshawk.web_pentest.crawler',
        'wshawk.web_pentest.vuln_scanner',
        'wshawk.web_pentest.report_gen',
        'wshawk.web_pentest.tech_fingerprint',
        'wshawk.web_pentest.ssl_analyzer',
        'wshawk.web_pentest.sensitive_finder',
        'wshawk.web_pentest.waf_detector',
        'wshawk.web_pentest.cors_tester',
        'wshawk.web_pentest.port_scanner',
        'wshawk.web_pentest.dns_lookup',
        'wshawk.web_pentest.csrf_forge',
        'wshawk.web_pentest.ssrf_prober',
        'wshawk.web_pentest.redirect_scanner',
        'wshawk.web_pentest.proto_polluter',
        'wshawk.web_pentest.proxy_ca',
        'wshawk.web_pentest.attack_chainer',

        # ── Third-party libraries PyInstaller may miss ──
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'fastapi.middleware',
        'fastapi.middleware.cors',
        'starlette',
        'starlette.routing',
        'starlette.middleware',
        'starlette.middleware.cors',
        'starlette.responses',
        'socketio',
        'engineio',
        'aiohttp',
        'websockets',
        'websockets.legacy',
        'websockets.legacy.client',
        'dns',
        'dns.resolver',
        'dns.reversename',
        'dns.rdatatype',
        'dns.exception',
        'whois',
        'cryptography',
        'cryptography.x509',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.serialization',
        'cryptography.hazmat.backends',
        'yaml',
        'sqlite3',

        # ── Playwright (optional — graceful fallback if not installed) ────────
        # PyInstaller won't auto-detect these due to lazy try/except imports.
        # If playwright is not installed, dom_invader falls back cleanly.
        'playwright',
        'playwright.async_api',
        'playwright._impl._api_types',
        'playwright._impl._browser',
        'playwright._impl._browser_context',
        'playwright._impl._page',
        'playwright._impl._network',
        'playwright._impl._dialog',
        'playwright.sync_api',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy dev/test deps not needed at runtime
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'pytest',
        'pyinstaller',
        # NOTE: playwright is no longer excluded — it's an optional runtime dep
        # bundled via hiddenimports above. If not installed, dom_invader
        # will gracefully degrade (HAS_PLAYWRIGHT = False).
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='wshawk-bridge',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
