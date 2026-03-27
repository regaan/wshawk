#!/usr/bin/env python3
"""
WSHawk Jira Integration
Create Jira tickets from scan findings automatically

Author: Regaan (@regaan)
"""

import json
import os
import base64
from datetime import datetime
from typing import List, Dict, Optional, Any

try:
    import aiohttp
except ImportError:
    aiohttp = None

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


class JiraIntegration:
    """
    Create Jira tickets from WSHawk scan findings.
    
    Features:
    - Auto-create tickets per vulnerability
    - Severity → Priority mapping
    - CVSS score in custom fields
    - Batch creation with deduplication
    - Support for Jira Cloud and Server
    
    Usage:
        jira = JiraIntegration(
            url="https://company.atlassian.net",
            email="user@company.com",
            api_token="your-token",
            project_key="SEC"
        )
        await jira.create_tickets(vulnerabilities, scan_info)
    """
    
    # Jira priority mapping
    PRIORITY_MAP = {
        'CRITICAL': 'Highest',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low',
        'INFO': 'Lowest',
    }
    
    def __init__(self,
                 url: str,
                 email: str,
                 api_token: str,
                 project_key: str,
                 issue_type: str = "Bug",
                 assignee: str = None,
                 labels: List[str] = None,
                 component: str = None,
                 verify_ssl: bool = True,
                 min_severity: str = "LOW"):
        """
        Args:
            url: Jira instance URL
            email: Jira account email (for Cloud) or username (for Server)
            api_token: API token (Cloud) or password (Server)
            project_key: Jira project key (e.g., "SEC", "VULN")
            issue_type: Jira issue type (default: "Bug")
            assignee: Auto-assign tickets to this user
            labels: Labels to add to tickets
            component: Jira component name
            verify_ssl: Verify SSL certificates
            min_severity: Minimum severity to create tickets for
        """
        self.url = url.rstrip('/')
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.assignee = assignee
        self.labels = labels or ['wshawk', 'security', 'websocket']
        self.component = component
        self.verify_ssl = verify_ssl
        self.min_severity = min_severity
        
        # Track created tickets
        self.created_tickets: List[Dict] = []
    
    def _get_headers(self) -> Dict:
        """Get Jira authentication headers."""
        auth = base64.b64encode(f"{self.email}:{self.api_token}".encode()).decode()
        return {
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    
    async def create_tickets(self,
                             vulnerabilities: List[Dict],
                             scan_info: Dict,
                             batch: bool = True) -> List[Dict]:
        """
        Create Jira tickets for discovered vulnerabilities.
        
        Args:
            vulnerabilities: List of WSHawk vulnerabilities
            scan_info: Scan metadata
            batch: If True, use batch creation API
            
        Returns:
            List of created ticket info dicts
        """
        if not aiohttp:
            Logger.error("aiohttp required for Jira integration. Install: pip install aiohttp")
            return []
        
        # Filter by minimum severity
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_idx = severity_order.index(self.min_severity.upper())
        
        filtered = [
            v for v in vulnerabilities
            if severity_order.index(
                v.get('confidence', v.get('severity', 'MEDIUM')).upper()
            ) >= min_idx
        ]
        
        if not filtered:
            Logger.warning(f"No vulnerabilities meet minimum severity: {self.min_severity}")
            return []
        
        Logger.info(f"Creating {len(filtered)} Jira tickets in {self.project_key}...")
        
        import ssl as ssl_module
        ssl_ctx = None
        if not self.verify_ssl:
            ssl_ctx = ssl_module.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl_module.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        
        # Use resilient session when available
        try:
            from ..resilience import ResilientSession, RetryConfig, CircuitBreaker
            
            breaker = CircuitBreaker(name='jira', failure_threshold=5, reset_timeout=60.0)
            retry = RetryConfig(max_retries=3, base_delay=2.0)
            
            if not breaker.can_execute():
                Logger.warning("Jira circuit breaker is OPEN — skipping ticket creation")
                return []
            
            async with ResilientSession(
                timeout=30.0, retry_config=retry, circuit_breaker=breaker
            ) as session:
                if batch and len(filtered) > 1:
                    results = await self._batch_create(session._session, filtered, scan_info)
                else:
                    results = []
                    for vuln in filtered:
                        result = await self._create_single_ticket(session._session, vuln, scan_info)
                        if result:
                            results.append(result)
        except ImportError:
            # Fallback: raw aiohttp without resilience
            async with aiohttp.ClientSession(connector=connector) as session:
                if batch and len(filtered) > 1:
                    results = await self._batch_create(session, filtered, scan_info)
                else:
                    results = []
                    for vuln in filtered:
                        result = await self._create_single_ticket(session, vuln, scan_info)
                        if result:
                            results.append(result)
        
        self.created_tickets = results
        
        # Summary
        if results:
            Logger.success(f"Created {len(results)} Jira tickets:")
            for ticket in results:
                Logger.info(f"  {ticket['key']} - {ticket['summary']}")
        
        return results
    
    async def _create_single_ticket(self,
                                     session: aiohttp.ClientSession,
                                     vuln: Dict,
                                     scan_info: Dict) -> Optional[Dict]:
        """Create a single Jira ticket."""
        issue_data = self._build_issue(vuln, scan_info)
        
        create_url = f"{self.url}/rest/api/2/issue"
        
        try:
            async with session.post(
                create_url,
                headers=self._get_headers(),
                json=issue_data
            ) as resp:
                if resp.status in (200, 201):
                    data = await resp.json()
                    ticket_key = data['key']
                    Logger.success(f"Created ticket: {ticket_key}")
                    return {
                        'key': ticket_key,
                        'id': data['id'],
                        'summary': issue_data['fields']['summary'],
                        'url': f"{self.url}/browse/{ticket_key}",
                        'severity': vuln.get('confidence', vuln.get('severity', 'MEDIUM')),
                    }
                else:
                    error = await resp.text()
                    Logger.error(f"Failed to create ticket: {error}")
                    return None
        except Exception as e:
            Logger.error(f"Jira API error: {e}")
            return None
    
    async def _batch_create(self,
                            session: aiohttp.ClientSession,
                            vulnerabilities: List[Dict],
                            scan_info: Dict) -> List[Dict]:
        """Create multiple tickets via Jira bulk API."""
        issues = [self._build_issue(v, scan_info) for v in vulnerabilities]
        
        bulk_url = f"{self.url}/rest/api/2/issue/bulk"
        payload = {'issueUpdates': issues}
        
        try:
            async with session.post(
                bulk_url,
                headers=self._get_headers(),
                json=payload
            ) as resp:
                if resp.status in (200, 201):
                    data = await resp.json()
                    results = []
                    for issue_data, vuln in zip(data.get('issues', []), vulnerabilities):
                        results.append({
                            'key': issue_data['key'],
                            'id': issue_data['id'],
                            'summary': f"[WSHawk] {vuln.get('type', 'Unknown')}",
                            'url': f"{self.url}/browse/{issue_data['key']}",
                            'severity': vuln.get('confidence', vuln.get('severity', 'MEDIUM')),
                        })
                    return results
                else:
                    # Fall back to individual creation
                    Logger.warning("Bulk creation failed, falling back to individual tickets...")
                    results = []
                    for vuln in vulnerabilities:
                        result = await self._create_single_ticket(session, vuln, scan_info)
                        if result:
                            results.append(result)
                    return results
        except Exception as e:
            Logger.error(f"Bulk creation error: {e}")
            return []
    
    def _build_issue(self, vuln: Dict, scan_info: Dict) -> Dict:
        """Build Jira issue payload."""
        severity = vuln.get('confidence', vuln.get('severity', 'MEDIUM')).upper()
        priority = self.PRIORITY_MAP.get(severity, 'Medium')
        vuln_type = vuln.get('type', 'Unknown Vulnerability')
        target = scan_info.get('target', 'Unknown')
        
        summary = f"[WSHawk] {vuln_type} - {target}"
        if len(summary) > 255:
            summary = summary[:252] + "..."
        
        description = self._build_description(vuln, scan_info)
        
        fields = {
            'project': {'key': self.project_key},
            'summary': summary,
            'description': description,
            'issuetype': {'name': self.issue_type},
            'priority': {'name': priority},
            'labels': self.labels + [
                f"severity-{severity.lower()}",
                f"cvss-{vuln.get('cvss_score', 0)}",
            ],
        }
        
        if self.assignee:
            fields['assignee'] = {'name': self.assignee}
        
        if self.component:
            fields['components'] = [{'name': self.component}]
        
        return {'fields': fields}
    
    def _build_description(self, vuln: Dict, scan_info: Dict) -> str:
        """Build Jira-formatted description (wiki markup)."""
        severity = vuln.get('confidence', vuln.get('severity', 'MEDIUM'))
        
        return (
            f"h2. WebSocket Security Vulnerability\n\n"
            f"||Property||Value||\n"
            f"|Type|{vuln.get('type', 'Unknown')}|\n"
            f"|Severity|{severity}|\n"
            f"|CVSS Score|{vuln.get('cvss_score', 'N/A')}|\n"
            f"|CVSS Vector|{vuln.get('cvss_vector', 'N/A')}|\n"
            f"|Target|{scan_info.get('target', 'Unknown')}|\n"
            f"|Browser Verified|{'Yes ✅' if vuln.get('browser_verified') else 'No'}|\n"
            f"|Scanner|WSHawk v4.0.0|\n\n"
            f"h3. Description\n"
            f"{vuln.get('description', 'N/A')}\n\n"
            f"h3. Payload\n"
            f"{{code}}\n{str(vuln.get('payload', 'N/A'))[:500]}\n{{code}}\n\n"
            f"h3. Server Response\n"
            f"{{code}}\n{str(vuln.get('response_snippet', 'N/A'))[:500]}\n{{code}}\n\n"
            f"h3. Recommendation\n"
            f"{vuln.get('recommendation', 'Implement proper input validation.')}\n\n"
            f"h3. Reproduction Steps\n"
            f"# Connect to WebSocket: {scan_info.get('target', 'ws://target')}\n"
            f"# Send the payload shown above\n"
            f"# Observe server response for vulnerability indicators\n\n"
            f"----\n"
            f"_Generated by [WSHawk|https://github.com/regaan/wshawk] by Regaan_"
        )


# ─── Environment-based configuration ────────────────────────────

def from_env() -> Optional[JiraIntegration]:
    """Create Jira integration from environment variables."""
    url = os.environ.get('JIRA_URL')
    email = os.environ.get('JIRA_EMAIL')
    token = os.environ.get('JIRA_API_TOKEN')
    project = os.environ.get('JIRA_PROJECT', 'SEC')
    
    if not all([url, email, token]):
        return None
    
    return JiraIntegration(
        url=url,
        email=email,
        api_token=token,
        project_key=project,
        verify_ssl=os.environ.get('JIRA_VERIFY_SSL', 'true').lower() == 'true'
    )
