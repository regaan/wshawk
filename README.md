# WSHawk - WebSocket Security Testing & Web Penetration Testing Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/wshawk.svg)](https://badge.fury.io/py/wshawk)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Playwright](https://img.shields.io/badge/Playwright-Supported-green.svg)](https://playwright.dev/)
[![Desktop](https://img.shields.io/badge/Desktop-Linux%20%7C%20Windows%20%7C%20macOS-2563eb)](https://github.com/regaan/wshawk/tree/main/desktop)
[![Validation Labs](https://img.shields.io/badge/Validation-Local%20Labs%20Included-16a34a)](https://github.com/regaan/wshawk/tree/main/validation)

**WSHawk** is an open-source toolkit for WebSocket security testing, web application penetration testing, and stateful attack validation. It combines a CLI scanner, web dashboard, Electron desktop app, browser companion, and project-backed workflows for authorized security assessments.

As of v4.0.0, WSHawk ships under the **AGPL-3.0 license** and includes the platform refactor, project-backed HTTP and WebSocket workflows, identity-aware replay and diffing, race testing, Playwright-assisted browser evidence collection for XSS testing, and local validation labs for realtime application scenarios.

> [!IMPORTANT]
> **Full Documentation:**
> - 🦅 **[WSHawk v4: Complete Guide](docs/V4_COMPLETE_GUIDE.md)** — Architecture, workflows, configuration, validation, and integrations
> - 💻 **[WSHawk Desktop v4: Full Feature Guide](docs/DESKTOP_V4_GUIDE.md)** — Desktop setup, projects, replay, interception, evidence, and web pentest workflows

---

## Why WSHawk — WebSocket and Web App Security Features

- **Stateful WebSocket testing** — persistent connections, asynchronous response handling, replay, and protocol-aware attack execution
- **Smart Payload Evolution** — context-aware payload generation and mutation based on target behavior, timing, and blocking signals
- **Browser-assisted XSS evidence collection** via Playwright for reflected and DOM-style payload testing
- **Blind vulnerability detection** via OAST callbacks for XXE, SSRF, and related out-of-band flows
- **Full-duplex WebSocket interceptor** — local proxy with frame-by-frame forward, drop, and edit controls
- **Identity-aware replay and diffing** for HTTP and WebSocket traffic across captured sessions and stored identities
- **Desktop web pentest workspace** with crawler, fuzzer, directory scan, header analysis, CORS, redirect, SSRF, TLS, and prototype-pollution tooling
- **Project-backed evidence** — local identities, notes, traffic, findings, and export bundles tied to a reusable project record
- **CVSS v3.1 scoring** for scanner findings and generated reports
- **Integrations** — Jira, DefectDojo, and webhook notifications
- **Reporting and exports** — HTML, JSON, Markdown, PDF, CSV, and SARIF outputs across the platform
- **Cross-platform desktop app** — Electron + Python hybrid for Linux, Windows, and macOS

---

## ⚡ Performance & Adoption Benchmarks

- **Current release**: `v4.0.0`
- **Interfaces**: CLI, web dashboard, desktop app, and browser companion
- **Validation coverage**: `full_stack_realtime_saas`, `socketio_saas`, and `graphql_subscriptions_lab`
- **Primary focus**: authenticated, stateful, and asynchronous web application testing rather than passive HTTP-only scanning

---

## WebSocket Vulnerability Scanner

WSHawk's core engine focuses on stateful, bidirectional WebSocket security testing. Unlike HTTP-only scanners, it keeps live connections open, captures handshake context, and evaluates asynchronous behavior that may appear well after a payload is sent. This fits chat systems, collaboration platforms, internal dashboards, trading interfaces, and other realtime SaaS targets.

### Vulnerability Detection

| Category | Technique |
|---|---|
| **SQL Injection** | Error-based, time-based (SLEEP/WAITFOR), boolean-based blind |
| **Cross-Site Scripting (XSS)** | Reflection analysis, context detection, DOM sink identification, browser evidence collection |
| **Command Injection** | Timing attacks, command chaining (`&&`, `\|`, `;`), out-of-band detection |
| **XML External Entity (XXE)** | Entity expansion, OAST callback detection, parameter entities |
| **Server-Side Request Forgery (SSRF)** | Internal IP probing, cloud metadata access, DNS rebinding |
| **NoSQL Injection** | MongoDB operator injection (`$gt`, `$ne`, `$regex`, `$where`) |
| **Path Traversal / LFI** | File content markers (`/etc/passwd`, `win.ini`), encoding bypass |

### Smart Payload Engine

The SPE system adapts attack payloads in real-time:

1. **Context Generator** — Detects message format (JSON, XML, plaintext) and generates payloads matching the target's protocol schema
2. **Feedback Loop** — Analyzes server signals (errors, reflections, timing anomalies, WAF blocks) and adjusts strategy dynamically
3. **Payload Evolver** — Genetic algorithm that crossovers and mutates successful payloads to discover novel WAF bypasses

---

## Web Application Penetration Testing Toolkit (Enhanced in v4.0.0)

The WSHawk desktop workspace also includes HTTP security tools organized into six phases so WebSocket and web application assessments can share the same project, identities, notes, and evidence trail.

### Reconnaissance & Discovery Tools

| Tool | Description |
|---|---|
| **Web Crawler** | BFS spider with form extraction, API endpoint discovery, robots.txt and sitemap.xml parsing |
| **Subdomain Finder** | Passive enumeration via crt.sh (Certificate Transparency) and AlienVault OTX, plus active DNS brute-forcing with resolution validation |
| **Technology Fingerprinter** | Identifies 35+ technologies (Nginx, Apache, WordPress, React, Cloudflare, etc.) from headers, cookies, and page content |
| **DNS / WHOIS Lookup** | Full record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA) with WHOIS registration data |
| **TCP Port Scanner** | Async connect scanner with service identification, banner grabbing, and preset port lists (top-100, web, database, full) |

### Vulnerability Scanning Tools

| Tool | Description |
|---|---|
| **HTTP Fuzzer** | Parameter fuzzing with `§FUZZ§` markers, built-in wordlists, encoding options (URL/Base64/Hex), and heuristic vuln detection |
| **Directory Scanner** | Path brute-forcing with extension permutation, recursive scanning, custom wordlists (up to 50K entries), and WAF-evasion throttling |
| **Automated Vulnerability Scanner** | Multi-phase orchestrator: Crawl → Header Analysis → Directory Scan → Fuzz → Sensitive Data Scan, with auto-escalation (SQLi → LFI chaining) |
| **Security Header Analyzer** | Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, CORS, Server, and X-Powered-By with risk ratings |
| **Sensitive Data Finder** | Regex detection for 30+ secret types — AWS keys, Google API keys, JWTs, GitHub tokens, database connection strings, internal IPs |

### Offensive Security Tools

| Tool | Description |
|---|---|
| **WAF Detector** | Passive and active fingerprinting of 15+ WAFs (Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, ModSecurity, F5 BIG-IP) |
| **CORS Misconfiguration Tester** | Probes 6 attack patterns — wildcard origin, null origin, subdomain suffix attack, domain prefix injection, HTTP downgrade |
| **SSL/TLS Analyzer** | Certificate inspection, protocol version testing (TLS 1.0–1.3), weak cipher detection, expiry and self-signed checks |
| **SSRF Prober** | 40+ payloads targeting AWS/GCP/Azure metadata endpoints, internal services, DNS rebinding, and URL parser confusion |
| **Open Redirect Scanner** | 25+ bypass techniques with auto-detection of 20+ common redirect parameter names |
| **Prototype Pollution Tester** | `__proto__` and `constructor.prototype` injection via query params and JSON bodies with escalation detection |

### Exploit Generation & Attack Chaining

| Tool | Description |
|---|---|
| **CSRF Exploit Forge** | Generates proof-of-concept HTML pages — auto-submitting forms, Fetch API XHR, multipart — with CSRF token detection |
| **Attack Chainer** | Multi-step HTTP attack sequencing with regex-based value extraction and `{{variable}}` templating across requests |
| **Proxy CA Generator** | Root Certificate Authority (RSA 4096-bit, 10-year validity) for HTTPS interception with per-host certificate signing |
| **HTTP Request Forge** | Manual HTTP request builder (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS) routed through Python to bypass browser CORS |
| **Report Generator** | Professional HTML reports with executive summary, severity charts, and remediation guidance. Also exports JSON, PDF, CSV, SARIF |

---

## WSHawk Desktop — Native Security Testing Application

A native Electron + Python desktop application with three operating modes:

| Mode | What You Get |
|---|---|
| **Standard** | WebSocket scanner dashboard, request forge, findings panel, traffic history, system log |
| **Advanced** | + Payload blaster, real-time WebSocket interceptor, endpoint map, auth builder, mutation lab, scheduler, codec, comparer, notes |
| **Web Pentest** | + All 22 HTTP security tools with real-time streaming results |

### Desktop-Exclusive Features

- **Real-Time WebSocket Interceptor** — Full-duplex MitM proxy with frame-by-frame forward, drop, and edit controls
- **Payload Blaster** — High-speed WebSocket fuzzer with 11 payload categories and Smart Payload Evolution toggle
- **WebSocket Endpoint Map** — Automated discovery via HTTP Upgrade probing, HTML crawling, and JavaScript source analysis
- **Auth Builder** — Multi-step authentication sequence with regex token extraction and variable substitution
- **Exploit PoC Generator** — Standalone Python proof-of-concept export for selected findings
- **Project Files** — Save and reopen sanitized local `.wshawk` project files
- **Project Evidence** — Local project database for identities, traffic, findings, notes, and export bundles
- **Tamper-Evident Exports** — Provenance and integrity metadata for exported project bundles
- **HawkSearch** — `Ctrl+K` command palette for instant navigation to any tool

**Builds for:** Linux (.pacman, .AppImage, .deb) · Windows (.exe NSIS installer) · macOS (.dmg)

**[Full Desktop Documentation →](docs/DESKTOP_V4_GUIDE.md)**

---

## Installation

### Install via pip

```bash
pip install wshawk

# Optional: Browser-based XSS verification
playwright install chromium
```

### Install on macOS (Homebrew)

**Method 1: Direct Cask URL**
```bash
brew install --cask https://raw.githubusercontent.com/regaan/homebrew-tap/main/Casks/wshawk.rb
```

**Method 2: Via Tap**
```bash
# Register the WSHawk tap
brew tap regaan/tap

# Install the cask
brew install --cask wshawk
```

### Install on Kali Linux / Debian

If you use the published Debian/Kali package feed:

```bash
# Add the WSHawk GPG key
curl -sSL https://regaan.github.io/wshawk-repo/wshawk_repo.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/wshawk-archive-keyring.gpg

# Add the WSHawk APT repository
echo "deb [signed-by=/usr/share/keyrings/wshawk-archive-keyring.gpg] https://regaan.github.io/wshawk-repo stable main" | sudo tee /etc/apt/sources.list.d/wshawk.list

# Install WSHawk
sudo apt update && sudo apt install wshawk
```

### Install on Arch Linux

If you use the published Arch User Repository (AUR) package:

```bash
# Install WSHawk via yay
yay -S wshawk
```

### Install via Docker

```bash
docker pull rothackers/wshawk:latest
docker run --rm rothackers/wshawk ws://target.com
```

See [Docker Guide](docs/DOCKER.md) for detailed usage.

### Build Desktop Application

```bash
git clone https://github.com/regaan/wshawk
cd wshawk

# Build Python sidecar binary
pip install -e . && pip install pyinstaller
pyinstaller wshawk-bridge.spec

# Build desktop installer
mkdir -p desktop/bin && cp dist/wshawk-bridge desktop/bin/
cd desktop && npm install && npm run dist
```

---

## Quick Start Guide

### WebSocket Scan (CLI)
```bash
wshawk ws://target.com
```

### Interactive Mode
```bash
wshawk-interactive
```

### Advanced Scan with All Features
```bash
wshawk-advanced ws://target.com --smart-payloads --playwright --full
```

### Web Dashboard
```bash
export WSHAWK_WEB_PASSWORD='your-password'
wshawk --web --port 5000
```

### Desktop Application
```bash
cd desktop && npm start
```

### Python API
```python
import asyncio
from wshawk.scanner_v2 import WSHawkV2

scanner = WSHawkV2("ws://target.com")
scanner.use_headless_browser = True
scanner.use_oast = True
asyncio.run(scanner.run_heuristic_scan())
```

---

## Interface Comparison

| Capability | CLI | Web Dashboard | Desktop App |
|---|---|---|---|
| WebSocket Scanner | ✅ | ✅ | ✅ |
| Web Pentest Toolkit (22 tools) | — | — | ✅ |
| WebSocket Interceptor (MitM) | — | — | ✅ |
| Payload Blaster / Fuzzer | — | — | ✅ |
| Endpoint Discovery Map | — | — | ✅ |
| Scan Persistence | — | SQLite | SQLite + Projects |
| Exploit PoC Export | — | — | ✅ |
| Report Formats | HTML / JSON / CSV / SARIF | HTML / PDF | HTML / JSON / Markdown |
| Best For | Automation, CI/CD, scripted runs | Shared browser access and review | Manual pentesting, interception, replay, and red-team workflows |

---

## Configuration

### wshawk.yaml
```bash
python3 -m wshawk.config --generate
```

```yaml
integrations:
  jira:
    api_token: "env:JIRA_TOKEN"
    project: "SEC"
  defectdojo:
    api_key: "env:DD_API_KEY"
    url: "https://defectdojo.your-org.com"
```

| Environment Variable | Description |
|---|---|
| `WSHAWK_BRIDGE_PORT` | Local bridge port (default: 8080) |
| `WSHAWK_WEB_PASSWORD` | Web dashboard authentication password |
| `WSHAWK_API_KEY` | Legacy web API key used by the older Flask dashboard path |

---

## Defensive Validation Module

Blue team module for validating your WebSocket security controls:

```bash
wshawk-defensive ws://your-server.com
```

- **DNS Exfiltration Prevention** — Validates egress filtering effectiveness
- **Bot Detection** — Tests anti-bot measures against headless browser evasion
- **CSWSH Protection** — Origin header validation with 216+ malicious origins
- **WSS Protocol Security** — TLS versions, cipher suites, certificate chain, forward secrecy

See [Defensive Validation Guide](docs/DEFENSIVE_VALIDATION.md).

---

## Security Warning — Use Official Sources

> Download WSHawk only from the official project sources or a package mirror you control.
>
> **Preferred sources:**
> - **GitHub:** [`https://github.com/regaan/wshawk`](https://github.com/regaan/wshawk)
> - **PyPI:** `pip install wshawk`
> - **Docker:** `docker pull rothackers/wshawk`

---

## Documentation

| Guide | Description |
|---|---|
| **[💻 Desktop v4 Full Feature Guide](docs/DESKTOP_V4_GUIDE.md)** | Current desktop guide for projects, replay, interception, web pentest workflows, and evidence |
| **[🦅 WSHawk v4 Complete Guide](docs/V4_COMPLETE_GUIDE.md)** | Current v4 architecture, workflows, configuration, validation, and integrations |
| [Getting Started](docs/getting_started.md) | First scan, output format, common use cases |
| [Advanced Usage](docs/advanced_usage.md) | Current Python API, scanner automation, and module-level examples |
| [Validation Checklist](docs/validation_checklist.md) | Local validation lab workflow and expected outcomes |
| [Defensive Validation](docs/DEFENSIVE_VALIDATION.md) | Blue team security control testing |
| [Vulnerability Details](docs/vulnerabilities.md) | Full vulnerability coverage reference |
| [Session Security Tests](docs/session_tests.md) | WebSocket session hijacking tests |
| [Docker Deployment](docs/DOCKER.md) | Container deployment guide |

---

## Responsible Use

WSHawk is designed for authorized penetration testing, bug bounty programs, security research, and education. **Always obtain explicit permission before scanning any target.**

The author is not responsible for misuse of this tool. If you use packaged builds, prefer the official project sources or mirrors you control.

## License

AGPL-3.0 License — see [LICENSE](LICENSE)

## Author

**Regaan** | Lead Researcher at **[ROT Independent Security Research Lab](https://rothackers.com)**

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md)

## Support

| Channel | Link |
|---|---|
| Issues | [GitHub Issues](https://github.com/regaan/wshawk/issues) |
| Documentation | [docs/](docs/) |
| Email | support@rothackers.com |

---

**WSHawk v4.0.0** — WebSocket Security Testing, Interception, and Web Pentest Toolkit

---

### Latest Updates (v4.0.0)
- **Platform Refactor**: The runtime is split into daemon, transport, session, protocol, attacks, evidence, and store layers for cleaner project-backed workflows.
- **Project-Backed Operations**: HTTP and WebSocket replay, AuthZ diffing, race testing, captured identities, and evidence now live in the same local project record.
- **Browser Companion Pairing**: The extension uses session pairing and explicit capture scopes for WebSocket handshake ingestion.
- **Tamper-Evident Exports**: Project bundle exports include provenance and integrity metadata for later verification.
- **Validation Labs**: Local scenarios cover full-stack realtime SaaS, Socket.IO, and GraphQL subscription testing paths.

*Built for security professionals, by Regaan.*
