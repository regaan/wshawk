"""
WSHawk Advanced Defensive Validation Modules
============================================

These modules help organizations validate their defensive security controls.

WARNING: ETHICAL USE ONLY
- Only use with explicit written authorization
- These tests validate defensive capabilities
- Designed to help blue teams improve security
- NOT for unauthorized testing

Modules:
1. DNS Exfiltration Prevention Test
2. Bot Detection Validation Test  
3. CSWSH (Cross-Site WebSocket Hijacking) Test
4. WSS Protocol Security Validation Test
"""

import asyncio
import json
import os
import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import quote

import aiohttp
import websockets


class DefensiveValidationResult(list):
    """List-compatible validation result with explicit partial-failure state."""

    def __init__(self):
        super().__init__()
        self.errors: List[Dict[str, str]] = []

    def record_error(self, module: str, error: object) -> None:
        self.errors.append({'module': module, 'error': str(error)})

    @property
    def exit_code(self) -> int:
        return 1 if self.errors else 0


async def connect_with_retry(target_url: str, timeout: float, attempts: int = 3):
    """Open a WebSocket with bounded retries for transient resolver/network errors."""
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            return await asyncio.wait_for(
                websockets.connect(
                    target_url,
                    open_timeout=timeout,
                    close_timeout=timeout,
                ),
                timeout=timeout + 1.0,
            )
        except Exception as exc:
            last_error = exc
            if attempt < attempts:
                print(f"[!] Connection attempt {attempt}/{attempts} failed: {exc}; retrying...")
                await asyncio.sleep(0.25 * attempt)

    raise last_error


class DefensiveValidationModule:
    """Base class for defensive validation tests"""
    
    def __init__(self, target_url: str, oast_domain: str = "oast.me"):
        self.target_url = target_url
        self.oast_domain = oast_domain
        self.findings = []
        
    def add_finding(self, test_name: str, vulnerable: bool, severity: str, 
                   description: str, recommendation: str, cvss: float = 0.0):
        """Add a defensive validation finding"""
        self.findings.append({
            'test': test_name,
            'vulnerable': vulnerable,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'cvss': cvss,
            'timestamp': time.time()
        })


class DNSExfiltrationTest(DefensiveValidationModule):
    """
    DNS Exfiltration Prevention Validator
    
    Tests if the target network properly blocks DNS-based data exfiltration.
    This helps organizations validate their egress filtering policies.
    
    Attack Scenario:
    - Attackers use DNS queries to exfiltrate data
    - Common in APT attacks and malware C2
    - Often bypasses basic firewalls
    
    Defensive Goal:
    - Ensure DNS queries to unknown domains are blocked/monitored
    - Validate egress filtering effectiveness
    - Detect potential data exfiltration channels
    """
    
    def __init__(
        self,
        target_url: str,
        oast_domain: str = "oast.me",
        callback_check_url: Optional[str] = None,
        callback_auth_token: Optional[str] = None,
    ):
        super().__init__(target_url, oast_domain)
        self.dns_tests = []
        self.callback_check_url = callback_check_url or os.getenv("WSHAWK_OAST_CALLBACK_URL", "")
        self.callback_auth_token = callback_auth_token or os.getenv("WSHAWK_OAST_API_TOKEN", "")
        
    async def test_dns_exfiltration_via_xxe(self, websocket) -> Dict:
        """
        Test DNS exfiltration through XXE vulnerability
        
        Validates if:
        1. XML parser processes external entities
        2. DNS queries reach external servers
        3. Egress filtering blocks DNS tunneling
        """
        test_id = str(uuid.uuid4())[:8]
        test_domain = f"xxe-test-{test_id}.{self.oast_domain}"
        
        # XXE payload that triggers DNS lookup
        xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://{test_domain}/data">
]>
<root>&xxe;</root>'''
        
        payload = {
            "action": "parse_xml",
            "xml": xxe_payload
        }
        
        try:
            await websocket.send(str(payload))
            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            
            # Wait for DNS callback
            await asyncio.sleep(3)
            
            # Check if DNS query was received
            dns_received = await self._check_dns_callback(test_domain)
            
            if dns_received is True:
                self.add_finding(
                    test_name="DNS Exfiltration Prevention",
                    vulnerable=True,
                    severity="HIGH",
                    description=f"DNS-based data exfiltration is possible. "
                               f"External DNS query to {test_domain} was successful.",
                    recommendation="Implement DNS egress filtering. Only allow DNS "
                                 "queries to authorized DNS servers. Monitor for "
                                 "suspicious DNS patterns (long subdomains, high query rates).",
                    cvss=7.5
                )
                return {'vulnerable': True, 'domain': test_domain}
            elif dns_received is False:
                self.add_finding(
                    test_name="DNS Exfiltration Prevention",
                    vulnerable=False,
                    severity="INFO",
                    description="DNS egress filtering is properly configured. "
                               "External DNS queries are blocked.",
                    recommendation="Continue monitoring DNS traffic for anomalies."
                )
                return {'vulnerable': False}
            else:
                self.add_finding(
                    test_name="DNS Exfiltration Prevention",
                    vulnerable=False,
                    severity="INFO",
                    description="DNS callback verification was inconclusive because no OAST callback API is configured.",
                    recommendation="Configure WSHAWK_OAST_CALLBACK_URL before drawing a DNS egress conclusion.",
                )
                return {'vulnerable': False, 'inconclusive': True, 'callback_domain': test_domain}
                
        except Exception as e:
            return {'error': str(e)}
    
    async def test_dns_exfiltration_via_ssrf(self, websocket) -> Dict:
        """
        Test DNS exfiltration through SSRF vulnerability
        
        Validates if SSRF can be used to trigger DNS lookups
        """
        test_id = str(uuid.uuid4())[:8]
        test_domain = f"ssrf-test-{test_id}.{self.oast_domain}"
        
        payload = {
            "action": "fetch_url",
            "url": f"http://{test_domain}/callback"
        }
        
        try:
            await websocket.send(str(payload))
            await asyncio.wait_for(websocket.recv(), timeout=5.0)
            await asyncio.sleep(3)
            
            dns_received = await self._check_dns_callback(test_domain)
            
            if dns_received is True:
                self.add_finding(
                    test_name="SSRF-based DNS Exfiltration",
                    vulnerable=True,
                    severity="HIGH",
                    description="SSRF vulnerability allows DNS-based data exfiltration.",
                    recommendation="Implement URL validation and egress filtering. "
                                 "Block access to internal networks and metadata services.",
                    cvss=8.2
                )
                return {'vulnerable': True}
            elif dns_received is False:
                return {'vulnerable': False}
            return {'vulnerable': False, 'inconclusive': True, 'callback_domain': test_domain}
                
        except Exception as e:
            return {'error': str(e)}
    
    async def _check_dns_callback(self, domain: str) -> Optional[bool]:
        """Query a configured OAST callback API for the generated domain."""
        if not self.callback_check_url:
            return None

        encoded_domain = quote(domain, safe="")
        if "{domain}" in self.callback_check_url:
            endpoint = self.callback_check_url.replace("{domain}", encoded_domain)
        else:
            separator = "&" if "?" in self.callback_check_url else "?"
            endpoint = f"{self.callback_check_url}{separator}domain={encoded_domain}"

        headers = {"Accept": "application/json"}
        if self.callback_auth_token:
            headers["Authorization"] = f"Bearer {self.callback_auth_token}"

        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(endpoint, timeout=timeout) as response:
                if response.status == 404:
                    return False
                response.raise_for_status()
                raw = await response.text(errors="ignore")

        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            payload = raw

        serialized = json.dumps(payload, sort_keys=True) if not isinstance(payload, str) else payload
        if domain.lower() in serialized.lower():
            return True
        if isinstance(payload, dict):
            for key in ("found", "received", "callback_received", "exists"):
                if payload.get(key) is True:
                    return True
            if payload.get("count") not in (None, 0, "0"):
                return True
        return False
    
    async def run_all_tests(self, websocket) -> List[Dict]:
        """Run all DNS exfiltration tests"""
        results = []
        
        print("[*] Testing DNS Exfiltration Prevention...")
        
        result = await self.test_dns_exfiltration_via_xxe(websocket)
        results.append(result)
        
        result = await self.test_dns_exfiltration_via_ssrf(websocket)
        results.append(result)
        
        return results


class BotDetectionValidator(DefensiveValidationModule):
    """
    Anti-Bot Detection Effectiveness Validator
    
    Tests if anti-bot measures can detect and block automated browsers.
    Helps organizations validate their bot protection effectiveness.
    
    Attack Scenario:
    - Credential stuffing attacks
    - Automated scraping
    - Account takeover attempts
    
    Defensive Goal:
    - Ensure bot detection catches headless browsers
    - Validate anti-automation measures
    - Identify gaps in bot protection
    """

    @staticmethod
    def _browser_runtime_missing(error: Exception) -> bool:
        message = str(error).lower()
        return "executable doesn't exist" in message and "playwright" in message
    
    async def test_basic_headless_detection(self) -> Dict:
        """
        Test if basic headless browser is detected
        
        Uses standard Playwright without evasion techniques
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {'error': 'Playwright not installed', 'skipped': True}
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                await page.goto(self.target_url.replace('ws://', 'http://').replace('wss://', 'https://'))
                content = await page.content()
                
                blocked_indicators = [
                    'access denied', 'bot detected', 'automated',
                    'captcha', 'cloudflare', 'please verify'
                ]
                
                is_blocked = any(indicator in content.lower() for indicator in blocked_indicators)
                
                await browser.close()
                
                if is_blocked:
                    self.add_finding(
                        test_name="Basic Headless Detection",
                        vulnerable=False,
                        severity="INFO",
                        description="Anti-bot system successfully detected basic headless browser.",
                        recommendation="Continue monitoring for evasion attempts."
                    )
                    return {'detected': True}
                else:
                    self.add_finding(
                        test_name="Basic Headless Detection",
                        vulnerable=True,
                        severity="MEDIUM",
                        description="Anti-bot system failed to detect basic headless browser.",
                        recommendation="Implement or improve bot detection. Consider: "
                                     "navigator.webdriver checks, User-Agent validation, "
                                     "behavioral analysis, commercial bot detection.",
                        cvss=5.3
                    )
                    return {'detected': False}
                    
        except Exception as e:
            if self._browser_runtime_missing(e):
                return {
                    'error': 'Playwright browser runtime is not installed',
                    'skipped': True,
                }
            return {'error': str(e)}
    
    async def test_evasion_resistance(self) -> Dict:
        """
        Test if anti-bot can detect browsers with evasion techniques
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {'error': 'Playwright not installed', 'skipped': True}
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
                )
                page = await context.new_page()
                
                # Apply anti-detection measures
                await page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false
                    });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5]
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en']
                    });
                """)
                
                await page.goto(self.target_url.replace('ws://', 'http://').replace('wss://', 'https://'))
                content = await page.content()
                
                blocked_indicators = [
                    'access denied', 'bot detected', 'automated',
                    'captcha', 'cloudflare', 'please verify'
                ]
                
                is_blocked = any(indicator in content.lower() for indicator in blocked_indicators)
                
                await browser.close()
                
                if is_blocked:
                    self.add_finding(
                        test_name="Evasion Resistance Test",
                        vulnerable=False,
                        severity="INFO",
                        description="Anti-bot system detected browser even with evasion techniques.",
                        recommendation="Excellent! Continue monitoring and updating detection rules."
                    )
                    return {'evaded': False}
                else:
                    self.add_finding(
                        test_name="Evasion Resistance Test",
                        vulnerable=True,
                        severity="HIGH",
                        description="Anti-bot system failed to detect headless browser with evasion.",
                        recommendation="URGENT: Upgrade bot detection. Consider behavioral analysis, "
                                     "canvas/WebGL fingerprinting, TLS fingerprinting, or commercial services.",
                        cvss=7.8
                    )
                    return {'evaded': True}
                    
        except Exception as e:
            if self._browser_runtime_missing(e):
                return {
                    'error': 'Playwright browser runtime is not installed',
                    'skipped': True,
                }
            return {'error': str(e)}
    
    async def run_all_tests(self) -> List[Dict]:
        """Run all bot detection validation tests"""
        results = []
        
        print("[*] Validating Bot Detection Effectiveness...")
        
        result = await self.test_basic_headless_detection()
        results.append(result)
        
        if not result.get('detected', False) and not result.get('skipped'):
            result = await self.test_evasion_resistance()
            results.append(result)
        
        return results


class CSWSHValidator(DefensiveValidationModule):
    """
    Cross-Site WebSocket Hijacking (CSWSH) Validator
    
    Tests if WebSocket connections properly validate Origin headers.
    Critical for preventing cross-site attacks.
    
    Attack Scenario:
    - Attacker hosts malicious page
    - Page connects to victim's WebSocket
    - Uses victim's session to perform actions
    
    Defensive Goal:
    - Ensure Origin header is validated
    - Prevent cross-site WebSocket connections
    - Protect user sessions
    """
    
    def __init__(
        self,
        target_url: str,
        oast_domain: str = "oast.me",
        max_origins: int = 12,
        origin_concurrency: int = 4,
        connection_timeout: float = 5.0,
    ):
        super().__init__(target_url, oast_domain)
        self.max_origins = max(1, max_origins)
        self.origin_concurrency = max(1, origin_concurrency)
        self.connection_timeout = max(0.1, connection_timeout)

    def _load_malicious_origins(self) -> List[str]:
        """Load a bounded, de-duplicated set of representative origins."""
        import os

        payload_file = os.path.join(
            os.path.dirname(__file__),
            'payloads',
            'malicious_origins.txt',
        )

        try:
            with open(payload_file, 'r', encoding='utf-8') as payload_handle:
                candidates = [
                    line.strip()
                    for line in payload_handle
                    if line.strip() and not line.lstrip().startswith('#')
                ]
        except FileNotFoundError:
            candidates = [
                'https://evil-attacker.com',
                'http://localhost:666',
                'null',
            ]

        return list(dict.fromkeys(candidates))[:self.max_origins]

    async def _probe_origin(self, origin: str):
        """Return ``(accepted, error)`` for a single Origin handshake."""
        last_error = None
        for attempt in range(2):
            websocket = None
            try:
                websocket = await asyncio.wait_for(
                    websockets.connect(
                        self.target_url,
                        additional_headers={'Origin': origin},
                        open_timeout=self.connection_timeout,
                        close_timeout=self.connection_timeout,
                    ),
                    timeout=self.connection_timeout + 1.0,
                )
                return True, None
            except Exception as exc:
                # An explicit HTTP handshake rejection is a valid negative test.
                # DNS, TCP, TLS, and timeout failures make the probe inconclusive.
                if type(exc).__name__ in {'InvalidStatus', 'InvalidStatusCode'}:
                    return False, None
                last_error = str(exc)
            finally:
                if websocket is not None:
                    try:
                        await asyncio.wait_for(websocket.close(), timeout=self.connection_timeout)
                    except Exception:
                        pass

            if attempt == 0:
                await asyncio.sleep(0.1)

        return False, last_error

    async def test_origin_validation(self) -> Dict:
        """
        Test if server validates Origin header
        
        Attempts connection with malicious origins
        """
        malicious_origins = self._load_malicious_origins()
        semaphore = asyncio.Semaphore(self.origin_concurrency)
        completed = 0
        progress_step = max(1, len(malicious_origins) // 4)

        async def run_probe(origin: str):
            nonlocal completed
            async with semaphore:
                accepted, error = await self._probe_origin(origin)
            completed += 1
            if completed == len(malicious_origins) or completed % progress_step == 0:
                print(f"    Origin probes: {completed}/{len(malicious_origins)}")
            return origin, accepted, error

        probe_results = await asyncio.gather(*(run_probe(origin) for origin in malicious_origins))
        accepted_origins = [origin for origin, accepted, _ in probe_results if accepted]
        probe_errors = [
            {'origin': origin, 'error': error}
            for origin, _, error in probe_results
            if error
        ]

        if accepted_origins:
            preview = ', '.join(accepted_origins[:5])
            if len(accepted_origins) > 5:
                preview += f", and {len(accepted_origins) - 5} more"
            self.add_finding(
                test_name="WebSocket Origin Policy Observation",
                vulnerable=False,
                severity="INFO",
                description=(
                    f"Server accepted {len(accepted_origins)}/{len(malicious_origins)} sampled untrusted origins "
                    f"({preview}). Origin acceptance alone does not prove CSWSH without browser-supplied "
                    "credentials and demonstrated unauthorized impact."
                ),
                recommendation=(
                    "If the endpoint uses cookies or ambient browser credentials, manually verify impact and "
                    "restrict Origin to an explicit allowlist. Public unauthenticated endpoints may intentionally "
                    "accept arbitrary origins."
                ),
            )
            return {
                'vulnerable': False,
                'accepted_origins': accepted_origins,
                'requires_manual_verification': True,
                'tested_origins': len(malicious_origins),
                'errors': probe_errors,
            }
        else:
            self.add_finding(
                test_name="CSWSH - Origin Header Validation",
                vulnerable=False,
                severity="INFO",
                description=(
                    "No sampled untrusted Origin completed a handshake. Review any probe errors before concluding "
                    "that Origin validation is enforced."
                ),
                recommendation="Continue enforcing an explicit Origin allowlist for credentialed browser endpoints."
            )
            return {
                'vulnerable': False,
                'tested_origins': len(malicious_origins),
                'errors': probe_errors,
            }
    
    async def test_csrf_token_requirement(self) -> Dict:
        """
        Test if WebSocket requires CSRF tokens
        """
        try:
            async with websockets.connect(
                self.target_url,
                open_timeout=self.connection_timeout,
                close_timeout=self.connection_timeout,
            ) as websocket:
                test_payload = {
                    "action": "sensitive_action",
                    "data": "test"
                }
                serialized_payload = str(test_payload)

                await websocket.send(serialized_payload)
                response = await asyncio.wait_for(websocket.recv(), timeout=self.connection_timeout)

                if response == serialized_payload:
                    return {'vulnerable': False, 'echoed': True, 'requires_manual_verification': True}

                if 'success' in response.lower():
                    self.add_finding(
                        test_name="CSRF Token Requirement",
                        vulnerable=True,
                        severity="HIGH",
                        description="WebSocket accepts sensitive actions without CSRF token.",
                        recommendation="Implement CSRF token validation for WebSocket messages.",
                        cvss=7.5
                    )
                    return {'vulnerable': True}

                return {'vulnerable': False}
            
        except Exception as e:
            return {'error': str(e)}
    
    async def run_all_tests(self) -> List[Dict]:
        """Run all CSWSH validation tests"""
        results = []
        
        print("[*] Testing CSWSH Prevention...")
        
        result = await self.test_origin_validation()
        results.append(result)
        
        result = await self.test_csrf_token_requirement()
        results.append(result)
        
        return results


async def run_defensive_validation(
    target_url: str,
    *,
    origin_limit: int = 12,
    origin_concurrency: int = 4,
    connection_timeout: float = 5.0,
):
    """
    Run all defensive validation modules
    
    Helps organizations validate their security controls
    """
    print("=" * 70)
    print("WSHawk Defensive Validation Suite")
    print("=" * 70)
    print()
    print("WARNING: AUTHORIZED TESTING ONLY")
    print("These tests validate defensive security controls.")
    print("Only use with explicit written authorization.")
    print()
    print("=" * 70)
    print()
    
    all_findings = DefensiveValidationResult()

    def record_result_errors(module: str, results: List[Dict]) -> None:
        for result in results:
            if not isinstance(result, dict):
                all_findings.record_error(module, 'test returned no structured result')
                continue
            if result.get('error') and not result.get('skipped'):
                all_findings.record_error(module, result['error'])
            for probe_error in result.get('errors', []):
                all_findings.record_error(
                    module,
                    f"{probe_error.get('origin', 'probe')}: {probe_error.get('error', 'unknown error')}",
                )
    
    # 1. DNS Exfiltration Prevention Test
    try:
        ws = await connect_with_retry(target_url, connection_timeout)
        try:
            dns_test = DNSExfiltrationTest(target_url)
            dns_results = await dns_test.run_all_tests(ws)
            record_result_errors('DNS exfiltration', dns_results)
            all_findings.extend(dns_test.findings)
        finally:
            await ws.close()
    except Exception as e:
        print(f"[!] DNS test error: {e}")
        all_findings.record_error('DNS exfiltration', e)
    
    # 2. Bot Detection Validation
    try:
        bot_test = BotDetectionValidator(target_url)
        bot_results = await bot_test.run_all_tests()
        record_result_errors('Bot detection', bot_results)
        all_findings.extend(bot_test.findings)
    except Exception as e:
        print(f"[!] Bot detection test error: {e}")
        all_findings.record_error('Bot detection', e)
    
    # 3. CSWSH Validation
    try:
        cswsh_test = CSWSHValidator(
            target_url,
            max_origins=origin_limit,
            origin_concurrency=origin_concurrency,
            connection_timeout=connection_timeout,
        )
        cswsh_results = await cswsh_test.run_all_tests()
        record_result_errors('CSWSH', cswsh_results)
        all_findings.extend(cswsh_test.findings)
    except Exception as e:
        print(f"[!] CSWSH test error: {e}")
        all_findings.record_error('CSWSH', e)
    
    # 4. WSS Protocol Security Validation (only for wss:// URLs)
    if target_url.startswith('wss://'):
        try:
            from .wss_security_validator import WSSSecurityValidator
            wss_test = WSSSecurityValidator(target_url)
            wss_results = wss_test.run_all_tests()
            record_result_errors('WSS security', wss_results)
            all_findings.extend(wss_test.findings)
        except Exception as e:
            print(f"[!] WSS security test error: {e}")
            all_findings.record_error('WSS security', e)
    else:
        print("[*] Skipping WSS security tests (requires wss:// URL)")
    
    # Print summary
    print("\n" + "=" * 70)
    print("DEFENSIVE VALIDATION SUMMARY")
    print("=" * 70)
    
    critical = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in all_findings if f['severity'] == 'HIGH')
    medium = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')
    
    print(f"\nFindings:")
    print(f"  CRITICAL: {critical}")
    print(f"  HIGH: {high}")
    print(f"  MEDIUM: {medium}")
    print(f"  TEST ERRORS: {len(all_findings.errors)}")
    print()

    if all_findings.errors:
        print("Incomplete modules:")
        for error in all_findings.errors:
            print(f"  - {error['module']}: {error['error']}")
    
    for finding in all_findings:
        if finding['vulnerable']:
            print(f"\n[{finding['severity']}] {finding['test']}")
            print(f"  Description: {finding['description']}")
            print(f"  Recommendation: {finding['recommendation']}")
            if finding.get('cvss'):
                print(f"  CVSS: {finding['cvss']}")
    
    return all_findings
