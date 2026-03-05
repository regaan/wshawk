# WSHawk Defensive Validation Module

## Overview

The Defensive Validation Module helps organizations validate their security controls by testing defensive capabilities against common attack techniques. This module is designed for **blue teams** to assess the effectiveness of their security measures.

## WARNING

**AUTHORIZED TESTING ONLY**
- Only use with explicit written authorization
- These tests validate defensive capabilities
- Designed to help blue teams improve security
- NOT for unauthorized testing

## Modules

### 1. DNS Exfiltration Prevention Test

Tests if the target network properly blocks DNS-based data exfiltration.

**Attack Scenario:**
- Attackers use DNS queries to exfiltrate data
- Common in APT attacks and malware C2 communications
- Often bypasses basic firewalls

**Defensive Goal:**
- Ensure DNS queries to unknown domains are blocked/monitored
- Validate egress filtering effectiveness
- Detect potential data exfiltration channels

**Tests Performed:**
- DNS exfiltration via XXE vulnerability
- DNS exfiltration via SSRF vulnerability

**CVSS Scores:**
- HIGH (7.5-8.2) if vulnerable

---

### 2. Bot Detection Validation Test

Tests if anti-bot measures can detect and block automated browsers.

**Attack Scenario:**
- Credential stuffing attacks
- Automated scraping
- Account takeover attempts

**Defensive Goal:**
- Ensure bot detection catches headless browsers
- Validate anti-automation measures
- Identify gaps in bot protection

**Tests Performed:**
- Basic headless browser detection
- Evasion resistance testing (with anti-detection techniques)

**CVSS Scores:**
- MEDIUM (5.3) for basic detection failure
- HIGH (7.8) for evasion resistance failure

---

### 3. CSWSH (Cross-Site WebSocket Hijacking) Test

Tests if WebSocket connections properly validate Origin headers.

**Attack Scenario:**
- Attacker hosts malicious page
- Page connects to victim's WebSocket
- Uses victim's session to perform actions

**Defensive Goal:**
- Ensure Origin header is validated
- Prevent cross-site WebSocket connections
- Protect user sessions

**Tests Performed:**
- Origin header validation (216+ malicious origins tested)
- CSRF token requirement validation

**CVSS Scores:**
- CRITICAL (9.1) for Origin validation failure
- HIGH (7.5) for missing CSRF tokens

---

### 4. WSS Protocol Security Validation

Tests TLS/SSL configuration for secure WebSocket (wss://) connections.

**Attack Scenario:**
- Protocol downgrade attacks (POODLE, BEAST)
- Weak cipher exploitation
- Man-in-the-Middle (MITM) attacks
- Certificate forgery

**Defensive Goal:**
- Ensure only modern TLS versions are supported (TLS 1.2+)
- Validate strong cipher suites with forward secrecy
- Verify certificate validity and chain integrity
- Prevent protocol downgrade attacks

**Tests Performed:**
- TLS version support (SSLv2, SSLv3, TLS 1.0, TLS 1.1 detection)
- Weak cipher suite detection (RC4, DES, 3DES, MD5, NULL, EXPORT)
- Certificate validation (expiration, self-signed, signature algorithm)
- Certificate chain integrity
- Forward secrecy verification (ECDHE, DHE)
- TLS renegotiation security

**CVSS Scores:**
- CRITICAL (9.8) for deprecated TLS versions
- HIGH (7.5) for weak ciphers or certificate issues
- MEDIUM (5.3) for missing forward secrecy

---

## Installation

The defensive validation module is included with WSHawk v2.0.4+.

```bash
pip install wshawk
```

Or install from source:

```bash
git clone https://github.com/noobforanonymous/wshawk
cd wshawk
pip install -e .
```

---

## Usage

### Command Line

```bash
# Run defensive validation
wshawk-defensive ws://localhost:8765

# Or with wss://
wshawk-defensive wss://secure-target.com
```

### Python API

```python
import asyncio
from wshawk.defensive_validation import run_defensive_validation

# Run all defensive tests
asyncio.run(run_defensive_validation("ws://localhost:8765"))
```

### Individual Module Usage

```python
import asyncio
import websockets
from wshawk.defensive_validation import (
    DNSExfiltrationTest,
    BotDetectionValidator,
    CSWSHValidator
)

async def test_dns_exfiltration():
    async with websockets.connect("ws://localhost:8765") as ws:
        dns_test = DNSExfiltrationTest("ws://localhost:8765")
        results = await dns_test.run_all_tests(ws)
        print(dns_test.findings)

async def test_bot_detection():
    bot_test = BotDetectionValidator("ws://localhost:8765")
    results = await bot_test.run_all_tests()
    print(bot_test.findings)

async def test_cswsh():
    cswsh_test = CSWSHValidator("ws://localhost:8765")
    results = await cswsh_test.run_all_tests()
    print(cswsh_test.findings)

# Run tests
asyncio.run(test_dns_exfiltration())
asyncio.run(test_bot_detection())
asyncio.run(test_cswsh())
```

---

## Output Example

```
======================================================================
WSHawk Defensive Validation Suite
======================================================================

WARNING: AUTHORIZED TESTING ONLY
These tests validate defensive security controls.
Only use with explicit written authorization.

======================================================================

[*] Testing DNS Exfiltration Prevention...
[*] Validating Bot Detection Effectiveness...
[*] Testing CSWSH Prevention...

======================================================================
DEFENSIVE VALIDATION SUMMARY
======================================================================

Findings:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 1

[CRITICAL] CSWSH - Origin Header Validation
  Description: Server accepts WebSocket connections from untrusted origins: https://evil-attacker.com, http://localhost:666. CSWSH is possible.
  Recommendation: CRITICAL: Implement Origin header validation immediately. Only accept connections from trusted origins.
  CVSS: 9.1

[HIGH] DNS Exfiltration Prevention
  Description: DNS-based data exfiltration is possible. External DNS query to xxe-test-abc123.oast.me was successful.
  Recommendation: Implement DNS egress filtering. Only allow DNS queries to authorized DNS servers. Monitor for suspicious DNS patterns.
  CVSS: 7.5

[MEDIUM] Basic Headless Detection
  Description: Anti-bot system failed to detect basic headless browser.
  Recommendation: Implement or improve bot detection. Consider: navigator.webdriver checks, User-Agent validation, behavioral analysis, commercial bot detection.
  CVSS: 5.3
```

---

## Findings Structure

Each finding includes:

```python
{
    'test': 'Test Name',
    'vulnerable': True/False,
    'severity': 'CRITICAL/HIGH/MEDIUM/LOW/INFO',
    'description': 'Detailed description of the finding',
    'recommendation': 'How to fix the vulnerability',
    'cvss': 9.1,  # CVSS v3.1 score
    'timestamp': 1234567890.0
}
```

---

## Severity Levels

| Severity | CVSS Range | Description |
|----------|------------|-------------|
| CRITICAL | 9.0-10.0 | Immediate action required |
| HIGH | 7.0-8.9 | Urgent remediation needed |
| MEDIUM | 4.0-6.9 | Should be addressed soon |
| LOW | 0.1-3.9 | Minor security concern |
| INFO | 0.0 | Informational only |

---

## Payload Files

The module uses payload files located in `wshawk/payloads/`:

- `malicious_origins.txt` - 216+ malicious origin headers for CSWSH testing

These payloads are automatically loaded and used during testing.

---

## Remediation Guidance

### DNS Exfiltration Prevention

**If vulnerable:**
1. Implement DNS egress filtering
2. Only allow DNS queries to authorized DNS servers
3. Monitor for suspicious DNS patterns:
   - Long subdomains
   - High query rates
   - Unusual TLDs
4. Use DNS security solutions (DNSSEC, DNS firewall)

**Example firewall rule:**
```bash
# Only allow DNS to authorized servers
iptables -A OUTPUT -p udp --dport 53 -d 8.8.8.8 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j DROP
```

---

### Bot Detection Improvement

**If vulnerable:**
1. Implement navigator.webdriver detection
2. Validate User-Agent consistency
3. Analyze mouse/keyboard patterns
4. Use canvas/WebGL fingerprinting
5. Consider commercial bot detection:
   - Cloudflare Bot Management
   - DataDome
   - PerimeterX
   - Akamai Bot Manager

**Example detection code:**
```javascript
// Detect headless browsers
if (navigator.webdriver) {
    console.log("Automated browser detected");
}

// Check for missing plugins
if (navigator.plugins.length === 0) {
    console.log("Suspicious: No plugins");
}
```

---

### CSWSH Prevention

**If vulnerable:**
1. Implement Origin header validation
2. Only accept connections from trusted origins
3. Implement CSRF token validation
4. Use secure WebSocket (wss://)

**Example server-side validation (Python):**
```python
async def websocket_handler(websocket, path):
    origin = websocket.request_headers.get('Origin')
    
    ALLOWED_ORIGINS = [
        'https://yourdomain.com',
        'https://app.yourdomain.com'
    ]
    
    if origin not in ALLOWED_ORIGINS:
        await websocket.close(1008, "Unauthorized origin")
        return
    
    # Continue with normal handling
    await handle_client(websocket)
```

**Example server-side validation (Node.js):**
```javascript
wss.on('connection', (ws, req) => {
    const origin = req.headers.origin;
    
    const allowedOrigins = [
        'https://yourdomain.com',
        'https://app.yourdomain.com'
    ];
    
    if (!allowedOrigins.includes(origin)) {
        ws.close(1008, 'Unauthorized origin');
        return;
    }
    
    // Continue with normal handling
    handleClient(ws);
});
```

---

## Integration with CI/CD

You can integrate defensive validation into your CI/CD pipeline:

```yaml
# .github/workflows/security-validation.yml
name: Security Validation

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  defensive-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      
      - name: Install WSHawk
        run: pip install wshawk
      
      - name: Run Defensive Validation
        run: wshawk-defensive ws://staging-server:8765
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-validation-results
          path: wshawk_defensive_report.json
```

---

## Best Practices

1. **Always get authorization** before running tests
2. **Run regularly** to ensure defenses remain effective
3. **Document findings** and track remediation
4. **Test in staging** before production
5. **Combine with other security tools** for comprehensive coverage
6. **Keep WSHawk updated** for latest tests and payloads

---

## Limitations

- **DNS Exfiltration Test:** Requires OAST server integration for full functionality
- **Bot Detection Test:** Requires Playwright installation
- **CSWSH Test:** Tests Origin header only, not full session security

---

## Contributing

To add new defensive tests:

1. Create a new class inheriting from `DefensiveValidationModule`
2. Implement test methods
3. Add to `run_defensive_validation()` function
4. Update documentation
5. Submit pull request

---

## Support

- **GitHub Issues:** https://github.com/noobforanonymous/wshawk/issues
- **Documentation:** https://github.com/noobforanonymous/wshawk
- **Email:** regaan48@gmail.com

---

## License

AGPL-3.0 License - See LICENSE file for details

---

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for version history.
