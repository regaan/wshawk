# WSHawk — Enterprise-Grade WebSocket Security Scanner & Web Penetration Testing Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/wshawk.svg)](https://badge.fury.io/py/wshawk)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Playwright](https://img.shields.io/badge/Playwright-Supported-green.svg)](https://playwright.dev/)
[![Status: Production](https://img.shields.io/badge/status-production-green.svg)](https://github.com/regaan/wshawk)
[![Adoption: 900+ Clones](https://img.shields.io/badge/Adoption-900+_clones_(14d)-blueviolet?style=flat&logo=github)](https://github.com/regaan/wshawk/graphs/traffic)
[![Community: 120+ Devs](https://img.shields.io/badge/Community-120+_Active_Devs-orange?style=flat&logo=community)](https://github.com/regaan/wshawk)

**WSHawk** is an enterprise-grade, open-source WebSocket security scanner built for professional penetration testers and red teams. It performs automated vulnerability assessment over WebSocket connections using an adaptive **Smart Payload Evolution (SPE)** engine with real-time feedback loops and genetic payload mutation. Designed for high-performance environments at the **ROT Independent Security Research Lab**.

Starting with v3.0.6, we've transitioned to the **AGPL-3.0 license** to better protect the project while keeping it open for the community. This release includes the **Headless DOM Invader** powered by Playwright for real browser-based XSS verification and complex SSO auth flow recording/replay. Also includes a **Context-Aware Heuristic Engine** and **WSHawk Browser Companion** for seamless handshake interception.

> [!IMPORTANT]
> **Full Documentation:**
> - 🦅 **[WSHawk V3: Complete Enterprise Guide](docs/V3_COMPLETE_GUIDE.md)** — Architecture, scanning engine, configuration
> - 💻 **[WSHawk Desktop: Full Reference Manual](docs/DESKTOP_V3_GUIDE.md)** — All 22 tools, API reference, build guide

---

## Why WSHawk — Enterprise Security Features

- **Smart Payload Evolution** — Genetic algorithm that mutates and evolves payloads based on server responses, WAF blocks, and timing signals
- **22,000+ attack payloads** across 11 categories (SQLi, XSS, CMDi, XXE, SSRF, NoSQLi, LFI, SSTI, LDAP, open redirect, CSV injection)
- **Real browser-based XSS verification** via Playwright — confirms actual script execution, not just pattern matching
- **Blind vulnerability detection** via OAST callbacks — catches XXE, SSRF, and DNS exfiltration that response-only scanners miss
- **Full-duplex WebSocket interceptor** — MitM proxy with frame-by-frame forward, drop, and edit (similar to Burp Suite)
- **Session hijacking analysis** — Token reuse, session fixation, privilege escalation, and impersonation testing
- **22 web pentest tools** — Crawler, fuzzer, port scanner, subdomain finder, WAF detector, CORS tester, SSL analyzer, and more
- **WAF-aware mutation engine** — 8 bypass strategies (encoding, case variation, comment injection, polyglot, tag breaking)
- **CVSS v3.1 scoring** — Industry-standard risk assessment for all findings
- **Enterprise integrations** — Auto-push findings to Jira, DefectDojo, Slack, Discord, and Microsoft Teams
- **Professional reporting** — HTML, JSON, PDF, CSV, and SARIF export formats
- **Native desktop app** — Electron + Python hybrid with real-time streaming results on Linux, Windows, and macOS

---

## ⚡ Performance & Adoption Benchmarks

- **Community Adoption**: 900+ repository clones within the last 14 days and active engagement from 120+ unique developers.
- **Scanning Velocity**: Engineered in Go with raw syscall optimization, achieving **350,000+ executions per second** in distributed fuzzer modules.
- **Payload Corpus**: 22,000+ specialized attack vectors across 11 vulnerability categories.

---

## Enterprise WebSocket Vulnerability Scanner

WSHawk's core engine performs enterprise-grade, stateful, bidirectional WebSocket security testing. Unlike traditional DAST scanners that only handle HTTP request-response, WSHawk maintains persistent WebSocket connections and analyzes asynchronous responses that may arrive long after the attack payload is sent — critical for real-world financial, healthcare, and SaaS applications.

### Vulnerability Detection

| Category | Technique |
|---|---|
| **SQL Injection** | Error-based, time-based (SLEEP/WAITFOR), boolean-based blind |
| **Cross-Site Scripting (XSS)** | Reflection analysis, context detection, DOM sink identification, browser verification |
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

## Web Application Penetration Testing Toolkit (Enhanced in v3.0.2)

The WSHawk Desktop application now ships with 22 HTTP security tools organized into six phases. We're building this out alongside the WebSocket scanner to give pentesters a single interface for both WebSocket and HTTP assessments.

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
- **Exploit PoC Generator** — One-click standalone Python exploit script for confirmed vulnerabilities
- **Session Persistence** — Save and restore full assessment state to `~/.wshawk/sessions/`
- **Scan History & Diffing** — SQLite-backed history with vulnerability regression tracking between scans
- **HawkSearch** — `Ctrl+K` command palette for instant navigation to any tool

**Builds for:** Linux (.pacman, .AppImage, .deb) · Windows (.exe NSIS installer) · macOS (.dmg)

**[Full Desktop Documentation →](docs/DESKTOP_V3_GUIDE.md)**

---

## Installation

### Install via pip

```bash
pip install wshawk

# Optional: Browser-based XSS verification
playwright install chromium
```

### Install on macOS (Homebrew)

**Method 1: One-liner (Recommended)**
```bash
brew install --cask https://raw.githubusercontent.com/regaan/homebrew-tap/main/Casks/wshawk.rb
```

**Method 2: Stay Updated (Via Tap)**
```bash
# Register the WSHawk tap
brew tap regaan/tap

# Install the cask
brew install --cask wshawk
```

### Install on Kali Linux / Debian

WSHawk is available via the official Regaan APT repository.

```bash
# Add the WSHawk GPG key
curl -sSL https://regaan.github.io/wshawk-repo/wshawk_repo.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/wshawk-archive-keyring.gpg

# Add the WSHawk APT repository
echo "deb [signed-by=/usr/share/keyrings/wshawk-archive-keyring.gpg] https://regaan.github.io/wshawk-repo stable main" | sudo tee /etc/apt/sources.list.d/wshawk.list

# Install WSHawk
sudo apt update && sudo apt install wshawk
```

### Install on Arch Linux

WSHawk is available in the Arch User Repository (AUR).

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
| Scan Persistence | — | SQLite | SQLite + Sessions |
| Exploit PoC Export | — | — | ✅ |
| Report Formats | HTML | HTML | HTML / JSON / PDF |
| Best For | CI/CD pipelines | Teams, SOC | Manual pentesting, red teams |

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
| `WSHAWK_BRIDGE_PORT` | Backend server port (default: 8080) |
| `WSHAWK_WEB_PASSWORD` | Web dashboard authentication password |
| `WSHAWK_API_KEY` | API key for programmatic access |

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

## Security Warning — Fake Versions

> Repackaged versions of WSHawk containing malware have been found on third-party download sites.
>
> **Download only from official sources:**
> - **Website:** [`https://wshawk.rothackers.com`](https://wshawk.rothackers.com)
> - **GitHub:** [`https://github.com/regaan/wshawk`](https://github.com/regaan/wshawk)
> - **PyPI:** `pip install wshawk`
> - **Docker:** `docker pull rothackers/wshawk`

---

## Documentation

| Guide | Description |
|---|---|
| **[V3.0.4 Release Guide](docs/V3.0.4_RELEASE_GUIDE.md)** | AGPL-3.0 Transition, DOM Invader, Auth Flow Recorder — full technical reference |
| **[🦅 Complete Enterprise Guide](docs/V3_COMPLETE_GUIDE.md)** | Architecture, scanning engine, configuration, integrations |
| **[💻 Desktop Reference Manual](docs/DESKTOP_V3_GUIDE.md)** | All 22 tools, API reference, build instructions |
| [Getting Started](docs/getting_started.md) | First scan, output format, common use cases |
| [Defensive Validation](docs/DEFENSIVE_VALIDATION.md) | Blue team security control testing |
| [Vulnerability Details](docs/vulnerabilities.md) | Full vulnerability coverage reference |
| [Session Security Tests](docs/session_tests.md) | WebSocket session hijacking tests |
| [Docker Deployment](docs/DOCKER.md) | Container deployment guide |

---

## Responsible Use

WSHawk is designed for authorized penetration testing, bug bounty programs, security research, and education. **Always obtain explicit permission before scanning any target.**

The author is not responsible for misuse of this tool. Repackaged versions found on third-party download sites are not associated with this project.

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

**WSHawk v3.0.6** — Professional WebSocket Security Scanner & Interception Suite

---

### Latest Updates (v3.0.6)
- **DOM Invader**: Headless Playwright engine verifies XSS payloads in a real browser — zero false positives. Confirms `alert()`, `eval()`, DOM mutations, and injected script tags.
- **Auth Flow Recorder**: Records complex SSO/OAuth login flows in a visible browser, then replays them headlessly to mint fresh tokens during long fuzzing runs.
- **Auto Session Reconnect**: Payload Blaster detects session expiry and automatically replays the recorded auth flow to reconnect — no manual intervention needed.
- **AI Exploit Engine**: Right-click any parameter in ReqForge to generate context-aware XSS/SQLi/SSTI payloads, auto-populated into the Payload Blaster.
- **Context-Aware Heuristic Fuzzing**: Advanced payload generation engine with deep protocol awareness for high-accuracy vulnerability discovery.

*Built for security professionals, by Regaan.*
