All notable changes to WSHawk will be documented in this file.

## [4.0.0] - 2026-03-25

### Added
- **Platform Refactor** — Split the bridge into daemon, store, transport, session, protocol, attacks, and evidence layers with a project-backed offensive workflow model.
- **Extension Upgrade** — Migrated the browser companion to Manifest V3 with dynamic bridge discovery, optional token support, and project-aware handshake capture.

### Changed
- **Version Synchronization** — Unified current release surfaces to `4.0.0` across packaging, desktop, bridge, extension, reports, templates, integrations, and runtime banners.
- **Web Pentest Platforming** — Promoted the HTTP toolkit into the same project/evidence model used by the WebSocket offensive stack.

## [3.0.6] - 2026-03-23

### Fixed
- **XSS Scanner Module Crash** — Fixed `AttributeError: type object 'WSPayloads' has no attribute 'get_xss_payloads'` in `scanner_v2.py` that caused a fatal abort during the XSS testing phase. The correct method `get_xss()` is now called.
- **CLI Banner Version Drift** — Banner previously displayed `V3.0.2` regardless of actual version; now correctly shows `V3.0.6`.

### Changed
- **Version Synchronization** — Unified version to `3.0.6` across all project surfaces: `pyproject.toml`, `desktop/package.json`, `wshawk/__init__.py`, `wshawk-bridge.spec`, `PKGBUILD`, `CITATION.cff`, `homebrew-tap/Casks/wshawk.rb`, `debian/changelog`, CLI banner, and README.

## [3.0.4] - 2026-03-05

### Changed
- **License Transition** — Migrated project from MIT to **AGPL-3.0** to ensure open-source longevity and protect intellectual property for Rot Hackers.
- **Unified Branding** — Synchronized versioning and legal metadata across all interfaces (CLI, Web, Desktop).
- **Metadata Refresh** — Updated PyPI, Debian, and Arch Linux package specs for the new license and version.


## [3.0.3] - 2026-03-01

### Added
- **Headless DOM Invader** — New `wshawk/dom_invader.py` engine with three components:
  - `BrowserPool` — manages up to 4 reusable Chromium contexts (no cold-start per payload).
  - `XSSVerifier` — renders WebSocket responses in a sandboxed headless page, instruments `alert()`, `eval()`, MutationObserver, and DOM sink hooks to confirm real JS execution — zero false positives.
  - `AuthFlowRecorder` — records SSO/OAuth login flows in a visible browser, captures cookies/tokens, and replays headlessly to mint fresh session tokens for long fuzzing operations.
- **Payload Blaster: DOM Verify toggle** — Enable headless XSS verification inline per response.
- **Payload Blaster: Record Auth Flow** — One-click auth recording from within the Blaster panel.
- **Auto Session Reconnect** — Blaster detects `ConnectionClosed` and auto-replays the auth flow (up to 3 attempts) to resume fuzzing without interruption.
- **Five new REST routes** — `/dom/status`, `/dom/verify`, `/dom/verify/batch`, `/dom/auth/record`, `/dom/auth/replay`.
- **Blaster results: DOM Verified column** — Each result shows `CONFIRMED XSS` (pulsing red badge) or `Unverified`.
- **`dom_xss_confirmed` Socket.IO event** — Fires a critical log entry when browser-confirmed XSS is detected.
- **AI Exploit Engine** (`wshawk/ai_exploit_engine.py`) — Context-aware payload generation from ReqForge right-click menu.
- **PyInstaller spec** — Added `dom_invader`, `ai_exploit_engine`, `headless_xss_verifier`, and full `playwright._impl.*` submodules to `hiddenimports`; removed `playwright` from `excludes`.

## [3.0.0] - 2026-02-18

### Added
- **Major Architecture Shift** - Enterprise-grade resilience and dashbord persistence.
- **Fixed Asset Distribution** - Patched TemplateNotFound errors by adding MANIFEST.in.
- **CLI Argparse Refactor** - Full support for flags like --web and --version.

## [2.0.8] - 2026-02-18

### Fixed
- **CLI Entry Point** - Refactored `wshawk` command to properly handle `--web`, `--version`, and port/host flags using argparse.
- **Async Safety** - Fixed "Event loop already running" errors when launching the scanner via CLI.

## [2.0.7] - 2026-02-18

### Added
- **Production-Grade Resilience Layer** - Integrated `ResilientSession` with Exponential Backoff and Circuit Breakers for all integrations
- **Smart Payload Evolution** - New adaptive learning phase that evolves payloads based on server feedback loops
- **Persistent Web Dashboard** - SQLite-backed GUI with scan history and professional user management
- **Hardened Web Authentication** - Secure login system with SHA-256 hashing and API key support
- **Enterprise Integrations** - Multi-platform support for Jira, DefectDojo, and Webhooks (Slack, Discord, Teams)
- **Hierarchical Configuration** - Professional `wshawk.yaml` with environment variable secret resolution

### Improved
- **Professional Logging** - Centralized logging system with persistent file logs and custom security log levels
- **Endpoint Discovery** - Resilient crawler for finding hidden WebSocket endpoints behind hardened targets
- **Refined Reporting** - Support for SARIF, JSON, and CSV exports for SOC/CI-CD integration

## [2.0.6] - 2026-02-10

### Added
- **Comprehensive Test Suite** - 90+ unit and integration tests covering all core modules
- **Full OAST Integration** - Complete interact.sh API integration (registration, polling, and deregistration)
- **Expanded WAF Detection** - Added support for 8 additional WAFs (total 12 detected)
- **Examples Directory** - New `examples/` directory with practical usage scripts for the scanner, mutator, and defensive module

### Fixed
- **Interactive Mode** - Fixed bug where user test selections were completely ignored
- **Code Quality** - Replaced all 18 bare `except:` blocks with specific exception handling
- **Version Mismatch** - Synced version across `__init__.py`, `pyproject.toml`, and `setup.py`

### Removed
- **Redundant Files** - Removed orphaned drafts (`scanner_v2_additions.py`, `scanner_v2_new.py`, `payload_mutator_v3.py`)
- **Dead Dependencies** - Removed unused `asyncio-mqtt` from `requirements.txt`

## [2.0.5] - 2025-12-08

### Fixed
- CSWSH test compatibility with newer websockets library (use `additional_headers` instead of `extra_headers`)
- Defensive validation now correctly detects Origin header vulnerabilities

## [2.0.4] - 2025-12-08

### Added
- **Defensive Validation Module** - New module for blue teams to validate security controls
  - DNS Exfiltration Prevention Test - Validates egress filtering effectiveness
  - Bot Detection Validation Test - Tests anti-bot measure effectiveness  
  - CSWSH (Cross-Site WebSocket Hijacking) Test - Validates Origin header enforcement
  - **WSS Protocol Security Validation** - Tests TLS/SSL configuration for secure WebSocket connections
    - TLS version validation (detects SSLv2/v3, TLS 1.0/1.1)
    - Weak cipher suite detection (RC4, DES, 3DES, etc.)
    - Certificate validation (expiration, self-signed, chain integrity)
    - Forward secrecy verification
    - TLS renegotiation security
- New CLI command: `wshawk-defensive` for running defensive validation tests
- 216+ malicious origin payloads for comprehensive CSWSH testing
- Comprehensive documentation in `docs/DEFENSIVE_VALIDATION.md`
- CVSS scoring for all defensive validation findings

### Improved
- Payload management - Malicious origins now loaded from `payloads/malicious_origins.txt`
- Better separation between offensive and defensive testing capabilities
- Enhanced documentation for blue team security validation

## [2.0.3] - 2025-12-07

### Fixed
- Version mismatch between `__init__.py` and package files (now all 2.0.2)
- Inconsistent time usage: Changed `time.time()` to `time.monotonic()` in scanner_v2.py for system-time-change safety
- Added missing PyYAML dependency
- Fixed entry point for `wshawk` command

### Added
- Centralized logging system (`wshawk/logger.py`) with colored output and file logging support
- Configurable authentication in SessionHijackingTester - no longer hardcoded to user1/pass1
- CHANGELOG.md for tracking all changes

### Improved
- Session tester now accepts `auth_config` parameter for custom authentication flows
- Better error handling with specific exception types (ongoing)
- All CLI commands work correctly (wshawk, wshawk-interactive, wshawk-advanced)

## [2.0.1] - 2025-12-07

### Changed
- Cleaned up documentation
- Removed attribution text from README

## [2.0.0] - 2025-12-07

### Added
- Complete rewrite with advanced features
- Real vulnerability verification with Playwright
- OAST integration for blind vulnerabilities
- Session hijacking tests (6 security tests)
- Advanced mutation engine with WAF bypass
- CVSS v3.1 scoring
- Professional HTML reporting
- Adaptive rate limiting
- Plugin system
- Three CLI modes (quick, interactive, advanced)

### Changed
- Scanner API completely rewritten
- New command-line interface
- Python 3.8+ required
- New dependencies: playwright, aiohttp, PyYAML

## [1.0.6] - Previous

### Features
- Basic WebSocket scanning
- Reflection-based detection
- 22,000+ payloads
