All notable changes to WSHawk will be documented in this file.

## [4.0.2] - 2026-07-17

### Added
- **DOM Invader Decomposition** — Split the monolithic `dom_invader.py` into focused modules: `dom_auth.py` (auth flow recording/replay), `dom_browser.py` (browser pool management), `dom_xss.py` (XSS verification engine), `dom_models.py` (data models), and `dom_runtime.py` (runtime coordination).
- **Scanner Attack Engine** (`scanner_attacks.py`) — Extracted attack orchestration from `scanner_v2.py` into a dedicated module with structured error types (`scanner_errors.py`).
- **Legacy Runtime Extraction** (`legacy_runtime.py`) — Extracted 982-line runtime logic from `legacy_core.py` to reduce module size from 1200+ lines.
- **Binary Mutations Module** (`binary_mutations.py`) — Dedicated binary protocol mutation engine separated from `binary_handler.py`.
- **Project Correlation Engine** (`store/project_correlation.py`) — Cross-project vulnerability correlation and trending analysis.
- **WAF Signature Database** (`waf/signatures.py`) — Externalized WAF detection signatures from inline detector logic.
- **Payload Catalog** (`payload_catalog.py`) — Centralized payload registry replacing scattered payload references.
- **TLS Utilities** (`tls.py`) — Shared TLS/SSL helper for certificate and cipher validation.
- **Daemon Route Decomposition** — Split massive route files into focused modules: `platform_route_support.py`, `web_route_support.py`, `web_workflow_routes.py`, `session_routes.py`, and `errors.py`.
- **CLI Overhaul** — New `cli.py` and `console.py` modules providing unified entry points and UTF-8-safe console output.
- **Database Row Models** (`database_rows.py`) — Typed row models for the SQLite project store.
- **Benchmark Suite** — New `benchmarks/` framework with `desktop_security_lab`, `industry_lab`, and `run.py` harness for reproducible security validation.
- **Validation Benchmarks** — Added `web_attack_benchmark` and `websocket_attack_benchmark` scenarios with deterministic apps and scoring.
- **Release Scripts** — `release_desktop_artifacts.py`, `verify_pyinstaller_hiddenimports.py`, and `verify_wheel_contents.py` for release-gate automation.

### Security
- **Secret Storage** — Fixed Windows DPAPI initialization and made configured secure backends fail closed instead of silently falling back to plaintext.
- **Local Services** — Defaulted the legacy dashboard to loopback, required authentication for remote binds, added CSRF/throttling/security headers, and blocked remote requests to private scan targets.
- **Extension Pairing** — Added short-lived, desktop-approved first-time pairing and origin-bound extension sessions.
- **Renderer Hardening** — Removed unsafe dynamic HTML rendering paths and added regression checks for desktop and extension JavaScript.
- **Validation Artifact Redaction** — Redacted authentication and session material at the validation persistence boundary, including secret copies embedded in messages and URL query parameters.
- **Dependency Auditing** — Added Python advisory auditing to the release-security gate alongside the existing production and complete npm audits.
- **Bridge Security** — Hardened bridge authentication and CSRF protections in `bridge_security.py`.
- **Sandbox Enforcement** — Desktop smoke tests now always disable sandbox in CI to prevent SIGTRAP crashes, while production builds retain full sandbox enforcement.
- **Path Validation** — Added `tempfile.gettempdir()` to allowed roots in `fuzzer.py` and `dir_scanner.py` for safe temporary file access during test execution.

### Changed
- **Compatibility Baseline** — Declared Python 3.10–3.13 and moved optional browser and analysis dependencies into extras.
- **Release Gates** — Added cross-platform Python/desktop jobs, installed CLI and Electron smoke tests, dependency audits, Ruff, targeted mypy, wheel inspection, and release-security checks.
- **Packaging** — Made `pyproject.toml` and `wshawk/_version_info.py` authoritative, excluded repository-only files from wheels, and consolidated container publishing.
- **Research Publication** — Added the WSHawk preprint records from Zenodo and Figshare to the project README and generated release notes.
- **GitHub Releases** — Platform installers now appear as clearly named Actions artifacts and are attached to tagged releases with SHA-256 manifests, installation guidance, categorized changes, and direct download links.
- **Desktop Electron Hardening** — Rewrote headless CI switches: removed crash-inducing `--single-process` and `--in-process-gpu`, added `--headless=new`, `--no-zygote`, `--disable-gpu-sandbox`, platform-guarded `--ozone-platform` to Linux only.
- **Defensive Validation Expansion** — Extended `defensive_validation.py` with 400+ lines of new validation logic including enhanced CSWSH, DNS exfiltration, and origin threshold testing.
- **WSS Security Validator** — Expanded TLS/cipher/certificate validation with 240+ lines of additional checks.
- **Advanced CLI** — Refactored `advanced_cli.py` and `legacy_advanced_cli.py` with improved argument handling and interactive mode.
- **Scanner v2 Slimming** — Reduced `scanner_v2.py` by 596 lines by extracting attack orchestration to `scanner_attacks.py`.
- **DOM Invader Slimming** — Reduced `dom_invader.py` by 793 lines by decomposing into focused sub-modules.
- **Legacy Core Slimming** — Reduced `legacy_core.py` by 1221 lines by extracting runtime logic.
- **Web Routes Slimming** — Reduced `daemon/web_routes.py` by 617 lines by extracting workflow and support modules.
- **Platform Routes Slimming** — Reduced `daemon/platform_routes.py` by 387 lines into `platform_route_support.py`.
- **Secret Store** — Refactored with 120 lines of improved platform-specific secure storage backends.
- **Session Hijacking Tester** — Hardened with additional auth flow and token validation checks.
- **Smart Payloads** — Improved `context_generator.py`, `feedback_loop.py`, and `payload_evolver.py` with better error handling and adaptive tuning.
- **Web Pentest Modules** — Hardened `ssrf_prober.py`, `waf_detector.py`, `tech_fingerprint.py`, `cors_tester.py`, `redirect_scanner.py`, and `header_analyzer.py` with stricter validation and error handling.
- **Integration Connectors** — Improved error handling in `defectdojo.py`, `jira_connector.py`, and `webhook.py`.
- **GUI Bridge** — Enhanced Python sidecar with 82 lines of improved bridge communication and error recovery.

### Fixed
- **Desktop Sidecar Packaging** — Removed stale PyInstaller hidden imports and added a pre-build verifier that fails when declared runtime modules are unavailable.
- **Container Build Context** — Excluded desktop dependencies and other repository-only inputs from Docker build contexts.
- **CLI Reliability** — Unified all installed command versions and bounded defensive DNS/origin probing behavior for unavailable targets.
- **Desktop CI Smoke Crash (Linux)** — `SIGTRAP` caused by `--single-process` forcing renderer/GPU into main process. Removed.
- **Desktop CI Smoke Crash (macOS arm64)** — `SIGTRAP` caused by unstable `--single-process` on ARM and `--ozone-platform=headless` (Linux-only flag). Fixed.
- **Desktop CI Smoke Crash (Windows)** — `ContextResult::kFatalFailure` caused by `--in-process-gpu` conflicting with `--disable-gpu`. Removed.
- **Wordlist Empty Error** — `ValueError` in fuzzer/scanner tests when temp directories were outside hardcoded `allowed_roots`.
- **Legacy Web Security** — Fixed rendering and authentication paths in `web/legacy_app.py` templates.

### Removed
- **`ssrf_test.py`** — Removed obsolete standalone SSRF test module (functionality consolidated into `web_pentest/ssrf_prober.py`).

### Tests
- Added 18 new test modules: `test_benchmark_harness`, `test_bridge_security`, `test_cli_entrypoints`, `test_cli_scan_reliability`, `test_daemon_errors`, `test_daemon_state`, `test_defensive_dns_callback`, `test_desktop_security`, `test_desktop_security_lab`, `test_legacy_web_security`, `test_memory_bounds`, `test_module_boundaries`, `test_optional_dependencies`, `test_pyinstaller_spec`, `test_release_desktop_artifacts`, `test_security_attack_benchmark_labs`, `test_web_attack_regressions`, `test_http_attack_services`.
- Expanded existing tests: `test_report_exporter`, `test_secret_store`, `test_validation_runner`, `test_vulnerability_verifier`, `test_web_platform_runtime`, `test_release_security_checks`.



## [4.0.1] - 2026-03-28

### Fixed
- **Release Automation** — Corrected the v4.0.1 release workflow and package publication path.

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
