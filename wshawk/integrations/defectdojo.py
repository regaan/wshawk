#!/usr/bin/env python3
"""
WSHawk DefectDojo Integration
Push scan results directly to DefectDojo vulnerability management platform

Author: Regaan (@regaan)
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from .._version_info import __version__
except ImportError:
    __version__ = "4.0.0"

try:
    from ..__main__ import Logger
except ImportError:
    class Logger:
        @staticmethod
        def info(msg): print(f"[*] {msg}")
        @staticmethod
        def success(msg): print(f"[+] {msg}")
        @staticmethod
        def error(msg): print(f"[-] {msg}")
        @staticmethod
        def warning(msg): print(f"[!] {msg}")


class DefectDojoIntegration:
    """
    Push WSHawk scan results to DefectDojo.
    
    DefectDojo is an open-source vulnerability management platform.
    This integration supports:
    - Creating engagements and tests automatically
    - Importing scan results via the /import-scan/ API
    - Mapping WSHawk severity to DefectDojo severity
    - Re-importing to update existing findings
    
    Usage:
        dd = DefectDojoIntegration(
            url="https://defectdojo.company.com",
            api_key="your-api-key",
            product_id=1
        )
        await dd.push_results(vulnerabilities, scan_info)
    """
    
    # DefectDojo severity mapping
    SEVERITY_MAP = {
        'CRITICAL': 'Critical',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low',
        'INFO': 'Info',
    }
    
    def __init__(self,
                 url: str,
                 api_key: str,
                 product_id: int = None,
                 product_name: str = None,
                 engagement_id: int = None,
                 auto_create_engagement: bool = True,
                 verify_ssl: bool = True,
                 environment: str = "Development"):
        """
        Args:
            url: DefectDojo base URL (e.g., https://defectdojo.company.com)
            api_key: DefectDojo API key (Token or API v2 key)
            product_id: DefectDojo product ID to push findings to
            product_name: Product name (used if product_id not provided)
            engagement_id: Existing engagement ID (optional)
            auto_create_engagement: Create engagement automatically if none exists
            verify_ssl: Verify SSL certificates
            environment: DefectDojo environment name
        """
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.product_id = product_id
        self.product_name = product_name or "WSHawk Scans"
        self.engagement_id = engagement_id
        self.auto_create_engagement = auto_create_engagement
        self.verify_ssl = verify_ssl
        self.environment = environment
        
    def _get_headers(self) -> Dict:
        """Get authentication headers."""
        return {
            'Authorization': f'Token {self.api_key}',
            'Accept': 'application/json',
        }
    
    async def push_results(self,
                           vulnerabilities: List[Dict],
                           scan_info: Dict,
                           scan_type: str = "Generic Findings Import",
                           test_title: str = None) -> Dict[str, Any]:
        """
        Push scan results to DefectDojo.
        
        Args:
            vulnerabilities: List of WSHawk vulnerabilities
            scan_info: Scan metadata
            scan_type: DefectDojo scan type
            test_title: Custom test title
            
        Returns:
            Dict with import results
        """
        if not aiohttp:
            Logger.error("aiohttp required for DefectDojo integration. Install: pip install aiohttp")
            return {'success': False, 'error': 'aiohttp not installed'}
        
        # Use resilient session when available
        try:
            from ..resilience import ResilientSession, RetryConfig, CircuitBreaker
            
            breaker = CircuitBreaker(name='defectdojo', failure_threshold=5, reset_timeout=60.0)
            retry = RetryConfig(max_retries=3, base_delay=2.0)
            
            if not breaker.can_execute():
                Logger.warning("DefectDojo circuit breaker is OPEN — skipping push")
                return {'success': False, 'error': 'Circuit breaker open (service unavailable)'}
            
            async with ResilientSession(
                timeout=30.0, retry_config=retry, circuit_breaker=breaker
            ) as session:
                return await self._execute_push(
                    session._session, vulnerabilities, scan_info, scan_type, test_title
                )
        except ImportError:
            pass
        
        # Fallback: raw aiohttp without resilience
        import ssl as ssl_module
        ssl_ctx = None
        if not self.verify_ssl:
            ssl_ctx = ssl_module.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_module.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            return await self._execute_push(
                session, vulnerabilities, scan_info, scan_type, test_title
            )
    
    async def _execute_push(self,
                            session,
                            vulnerabilities: List[Dict],
                            scan_info: Dict,
                            scan_type: str,
                            test_title: str = None) -> Dict[str, Any]:
        """Execute the actual push logic."""
        try:
            # Step 1: Resolve product
            if not self.product_id:
                self.product_id = await self._find_or_create_product(session)
                if not self.product_id:
                    return {'success': False, 'error': 'Could not resolve product'}
            
            # Step 2: Resolve engagement
            if not self.engagement_id and self.auto_create_engagement:
                self.engagement_id = await self._create_engagement(
                    session, scan_info
                )
                if not self.engagement_id:
                    return {'success': False, 'error': 'Could not create engagement'}
            
            # Step 3: Convert findings to DefectDojo format
            dd_findings = self._convert_findings(vulnerabilities, scan_info)
            
            # Step 4: Import via API
            result = await self._import_scan(
                session, dd_findings, scan_info, scan_type, test_title
            )
            
            return result
            
        except Exception as e:
            Logger.error(f"DefectDojo push failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _find_or_create_product(self, session: aiohttp.ClientSession) -> Optional[int]:
        """Find existing product or create new one."""
        # Search for existing product
        search_url = f"{self.url}/api/v2/products/?name={self.product_name}"
        async with session.get(search_url, headers=self._get_headers()) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get('count', 0) > 0:
                    product_id = data['results'][0]['id']
                    Logger.info(f"Found existing product: {self.product_name} (ID: {product_id})")
                    return product_id
        
        # Create new product
        create_url = f"{self.url}/api/v2/products/"
        product_data = {
            'name': self.product_name,
            'description': 'WSHawk WebSocket Security Scanner findings',
            'prod_type': 1,  # Default product type
        }
        
        async with session.post(
            create_url,
            headers={**self._get_headers(), 'Content-Type': 'application/json'},
            json=product_data
        ) as resp:
            if resp.status in (200, 201):
                data = await resp.json()
                product_id = data['id']
                Logger.success(f"Created product: {self.product_name} (ID: {product_id})")
                return product_id
            else:
                error = await resp.text()
                Logger.error(f"Failed to create product: {error}")
                return None
    
    async def _create_engagement(self,
                                  session: aiohttp.ClientSession,
                                  scan_info: Dict) -> Optional[int]:
        """Create a new engagement for this scan."""
        create_url = f"{self.url}/api/v2/engagements/"
        
        now = datetime.now()
        engagement_data = {
            'name': f"WSHawk Scan - {scan_info.get('target', 'Unknown')}",
            'description': (
                f"Automated WebSocket security scan by WSHawk v{__version__}\n"
                f"Target: {scan_info.get('target', 'Unknown')}\n"
                f"Duration: {scan_info.get('duration', 0):.1f}s"
            ),
            'product': self.product_id,
            'target_start': now.strftime('%Y-%m-%d'),
            'target_end': now.strftime('%Y-%m-%d'),
            'engagement_type': 'CI/CD',
            'status': 'Completed',
            'build_id': f"wshawk-{now.strftime('%Y%m%d%H%M%S')}",
            'commit_hash': '',
            'environment': self.environment,
        }
        
        async with session.post(
            create_url,
            headers={**self._get_headers(), 'Content-Type': 'application/json'},
            json=engagement_data
        ) as resp:
            if resp.status in (200, 201):
                data = await resp.json()
                engagement_id = data['id']
                Logger.success(f"Created engagement (ID: {engagement_id})")
                return engagement_id
            else:
                error = await resp.text()
                Logger.error(f"Failed to create engagement: {error}")
                return None
    
    async def _import_scan(self,
                           session: aiohttp.ClientSession,
                           findings: List[Dict],
                           scan_info: Dict,
                           scan_type: str,
                           test_title: str = None) -> Dict:
        """Import findings via the import-scan endpoint."""
        import_url = f"{self.url}/api/v2/import-scan/"
        
        # Create the findings JSON
        scan_report = json.dumps({
            'findings': findings
        })
        
        # Use multipart form data
        form = aiohttp.FormData()
        form.add_field('scan_type', scan_type)
        form.add_field('engagement', str(self.engagement_id))
        form.add_field('verified', 'true')
        form.add_field('active', 'true')
        form.add_field('minimum_severity', 'Info')
        form.add_field('scan_date', datetime.now().strftime('%Y-%m-%d'))
        
        if test_title:
            form.add_field('test_title', test_title)
        else:
            form.add_field('test_title', f"WSHawk - {scan_info.get('target', 'Scan')}")
        
        form.add_field(
            'file',
            scan_report.encode(),
            filename='wshawk_findings.json',
            content_type='application/json'
        )
        
        async with session.post(
            import_url,
            headers={'Authorization': f'Token {self.api_key}'},
            data=form
        ) as resp:
            if resp.status in (200, 201):
                data = await resp.json()
                test_id = data.get('test', 'unknown')
                finding_count = data.get('finding_count', len(findings))
                Logger.success(
                    f"DefectDojo import successful! "
                    f"Test ID: {test_id}, Findings: {finding_count}"
                )
                return {
                    'success': True,
                    'test_id': test_id,
                    'findings_imported': finding_count,
                    'url': f"{self.url}/test/{test_id}"
                }
            else:
                error = await resp.text()
                Logger.error(f"Import failed (HTTP {resp.status}): {error}")
                return {'success': False, 'error': error}
    
    def _convert_findings(self,
                          vulnerabilities: List[Dict],
                          scan_info: Dict) -> List[Dict]:
        """Convert WSHawk vulnerabilities to DefectDojo finding format."""
        findings = []
        
        for i, vuln in enumerate(vulnerabilities):
            severity = self.SEVERITY_MAP.get(
                vuln.get('confidence', vuln.get('severity', 'MEDIUM')).upper(),
                'Medium'
            )
            
            finding = {
                'title': f"[WSHawk] {vuln.get('type', 'Unknown Vulnerability')}",
                'description': self._build_description(vuln, scan_info),
                'severity': severity,
                'date': datetime.now().strftime('%Y-%m-%d'),
                'cwe': self._get_cwe(vuln.get('type', '')),
                'verified': vuln.get('browser_verified', False),
                'active': True,
                'numerical_severity': vuln.get('cvss_score', 0),
                'cvssv3': vuln.get('cvss_vector', ''),
                'cvssv3_score': vuln.get('cvss_score', 0),
                'steps_to_reproduce': self._build_reproduction_steps(vuln, scan_info),
                'mitigation': vuln.get('recommendation', ''),
                'impact': f"CVSS {vuln.get('cvss_score', 'N/A')} - {vuln.get('cvss_severity', 'Unknown')}",
                'references': 'https://github.com/regaan/wshawk',
                'unique_id_from_tool': f"WSHAWK-{i+1:04d}",
                'vuln_id_from_tool': f"WSHAWK-{vuln.get('type', 'UNK').replace(' ', '-').upper()}",
            }
            
            findings.append(finding)
        
        return findings
    
    def _build_description(self, vuln: Dict, scan_info: Dict) -> str:
        """Build detailed description for DefectDojo."""
        parts = [
            f"**Vulnerability Type:** {vuln.get('type', 'Unknown')}",
            f"**Target:** {scan_info.get('target', 'Unknown')}",
            f"**Confidence:** {vuln.get('confidence', vuln.get('severity', 'Unknown'))}",
            f"**Description:** {vuln.get('description', 'N/A')}",
            "",
            f"**Payload Used:**",
            f"```",
            f"{str(vuln.get('payload', 'N/A'))[:500]}",
            f"```",
            "",
            f"**Server Response:**",
            f"```",
            f"{str(vuln.get('response_snippet', 'N/A'))[:500]}",
            f"```",
            "",
            f"**Scanner:** WSHawk v{__version__} by Regaan",
            f"**Scan Duration:** {scan_info.get('duration', 0):.1f}s",
        ]
        
        if vuln.get('browser_verified'):
            parts.insert(0, "⚠️ **BROWSER EVIDENCE** - This finding includes sandboxed headless browser execution evidence.\n")
        
        return '\n'.join(parts)
    
    def _build_reproduction_steps(self, vuln: Dict, scan_info: Dict) -> str:
        """Build reproduction steps."""
        return (
            f"1. Connect to WebSocket endpoint: {scan_info.get('target', 'ws://target')}\n"
            f"2. Send the following payload:\n"
            f"   ```\n"
            f"   {str(vuln.get('payload', 'N/A'))[:300]}\n"
            f"   ```\n"
            f"3. Observe the server response for {vuln.get('type', 'vulnerability')} indicators\n"
            f"4. CVSS Score: {vuln.get('cvss_score', 'N/A')}\n"
        )
    
    def _get_cwe(self, vuln_type: str) -> int:
        """Map vulnerability type to CWE ID."""
        cwe_map = {
            'sql injection': 89,
            'xss': 79,
            'command injection': 78,
            'path traversal': 22,
            'xxe': 611,
            'nosql injection': 943,
            'ssrf': 918,
            'ssti': 1336,
            'open redirect': 601,
            'ldap injection': 90,
            'session': 384,
            'csrf': 352,
            'cswsh': 352,
        }
        vuln_lower = vuln_type.lower()
        for key, cwe in cwe_map.items():
            if key in vuln_lower:
                return cwe
        return 0


# ─── Environment-based configuration ────────────────────────────

def from_env() -> Optional[DefectDojoIntegration]:
    """Create DefectDojo integration from environment variables."""
    url = os.environ.get('DEFECTDOJO_URL')
    api_key = os.environ.get('DEFECTDOJO_API_KEY')
    product_id = os.environ.get('DEFECTDOJO_PRODUCT_ID')
    
    if not url or not api_key:
        return None
    
    return DefectDojoIntegration(
        url=url,
        api_key=api_key,
        product_id=int(product_id) if product_id else None,
        verify_ssl=os.environ.get('DEFECTDOJO_VERIFY_SSL', 'true').lower() == 'true'
    )
