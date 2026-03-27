# WSHawk v4 Defensive Validation

The defensive validation path is for authorized blue-team style checks against WebSocket-facing controls.

Current entrypoints:

- CLI: `wshawk-defensive`
- Python helper: `wshawk.defensive_validation.run_defensive_validation`

This guide describes the module as it exists now, not as earlier docs described it.

---

## Current Implemented Coverage

The current `wshawk.defensive_validation` module implements three main areas:

| Module | Current Purpose |
|---|---|
| **DNSExfiltrationTest** | exercise XXE- and SSRF-style DNS egress paths |
| **BotDetectionValidator** | check whether basic and lightly evasive headless browsers are noticed |
| **CSWSHValidator** | test Origin validation and simple CSRF-style assumptions for WebSocket actions |

---

## Important Reality Notes

These points matter if you are using this module seriously:

1. The DNS callback checker is currently a placeholder.
The `_check_dns_callback()` path returns `False` unless you replace it with a real OAST integration. The module can still exercise the code path, but it does not ship with turnkey positive callback confirmation.

2. Older docs overstated WSS/TLS validation.
The current `wshawk.defensive_validation.py` file does not implement a separate WSS/TLS hardening validator. If you need TLS posture checks, use the web pentest TLS tooling instead of assuming the defensive module covers it.

3. This is a helper module, not the main v4 platform workflow.
For project-backed replay, evidence, and cross-identity abuse testing, use the desktop and platform routes.

---

## Installation

```bash
pip install wshawk
```

Optional for bot-detection checks:

```bash
playwright install chromium
```

---

## CLI Usage

```bash
wshawk-defensive ws://target.example/ws
```

or:

```bash
wshawk-defensive wss://target.example/ws
```

---

## Python Usage

### Run the Full Defensive Helper

```python
import asyncio
from wshawk.defensive_validation import run_defensive_validation

asyncio.run(run_defensive_validation("wss://target.example/ws"))
```

### Use Individual Modules

```python
import asyncio
import websockets
from wshawk.defensive_validation import (
    DNSExfiltrationTest,
    BotDetectionValidator,
    CSWSHValidator,
)


async def run():
    async with websockets.connect("wss://target.example/ws") as ws:
        dns = DNSExfiltrationTest("wss://target.example/ws")
        await dns.run_all_tests(ws)
        print(dns.findings)

    bot = BotDetectionValidator("wss://target.example/ws")
    await bot.run_all_tests()
    print(bot.findings)

    cswsh = CSWSHValidator("wss://target.example/ws")
    await cswsh.run_all_tests()
    print(cswsh.findings)


asyncio.run(run())
```

---

## What the Checks Actually Try

### DNS Exfiltration Test

The DNS module currently sends payloads intended to trigger:

- XXE-driven outbound lookups
- SSRF-driven outbound lookups

Use it as a validation helper for egress assumptions, but do not assume shipped positive callback proof without wiring in your own OAST backend.

### Bot Detection Validation

The bot module uses Playwright and checks whether the target page appears to block or notice:

- a plain headless browser
- a lightly modified browser context with simple anti-detection changes

This is a useful practical signal, but it is not a complete anti-bot benchmark suite.

### CSWSH Validation

The CSWSH module tries:

- WebSocket connections with attacker-controlled `Origin` headers
- a simple sensitive action without an explicit CSRF token

This is helpful for spotting weak origin validation quickly.

---

## Findings Format

The defensive module records findings like:

```python
{
    "test": "CSWSH - Origin Header Validation",
    "vulnerable": True,
    "severity": "CRITICAL",
    "description": "Server accepts WebSocket connections from untrusted origins.",
    "recommendation": "Only accept connections from trusted origins.",
    "cvss": 9.1,
    "timestamp": 1234567890.0,
}
```

---

## When to Use This Module

Use the defensive module when you want:

- a quick blue-team check against WebSocket-facing controls
- repeatable local control validation in staging
- a helper path for origin-validation and basic anti-bot testing

Do not confuse it with the main v4 offensive workflow layer. The defensive module is a narrow helper, not a replacement for the desktop or validation labs.
