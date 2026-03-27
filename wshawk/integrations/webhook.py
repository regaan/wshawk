#!/usr/bin/env python3
"""
WSHawk Webhook Notifier
Send scan results to Slack, Discord, Teams, or any webhook URL

Author: Regaan (@regaan)
"""

import json
import os
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


class WebhookNotifier:
    """
    Send scan notifications to webhooks.
    
    Supports:
    - Slack (Incoming Webhooks)
    - Discord (Webhooks)
    - Microsoft Teams (Incoming Webhook)
    - Generic JSON POST webhooks
    
    Usage:
        notifier = WebhookNotifier(
            webhook_url="https://hooks.slack.com/services/xxx",
            platform="slack"
        )
        await notifier.notify(vulnerabilities, scan_info)
    """
    
    PLATFORMS = ['slack', 'discord', 'teams', 'generic']
    
    SEVERITY_EMOJI = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢',
        'INFO': '⚪',
    }
    
    def __init__(self,
                 webhook_url: str,
                 platform: str = "generic",
                 notify_on: str = "all",
                 min_severity: str = "LOW",
                 include_payloads: bool = False):
        """
        Args:
            webhook_url: Webhook endpoint URL
            platform: Platform type (slack, discord, teams, generic)
            notify_on: When to notify: "all", "findings_only", "summary_only"
            min_severity: Minimum severity to include in notifications
            include_payloads: Include payload details (may contain sensitive data)
        """
        self.webhook_url = webhook_url
        self.platform = platform.lower()
        self.notify_on = notify_on
        self.min_severity = min_severity.upper()
        self.include_payloads = include_payloads
        
        if self.platform not in self.PLATFORMS:
            Logger.warning(f"Unknown platform '{platform}', using generic format")
            self.platform = 'generic'
    
    async def notify(self,
                     vulnerabilities: List[Dict],
                     scan_info: Dict) -> bool:
        """
        Send scan notification.
        
        Returns:
            True if notification was sent successfully
        """
        if not aiohttp:
            Logger.error("aiohttp required for webhooks. Install: pip install aiohttp")
            return False
        
        # Build platform-specific payload
        if self.platform == 'slack':
            payload = self._build_slack_payload(vulnerabilities, scan_info)
        elif self.platform == 'discord':
            payload = self._build_discord_payload(vulnerabilities, scan_info)
        elif self.platform == 'teams':
            payload = self._build_teams_payload(vulnerabilities, scan_info)
        else:
            payload = self._build_generic_payload(vulnerabilities, scan_info)
        
        # Send
        try:
            # Use resilient session when available
            try:
                from ..resilience import ResilientSession, RetryConfig, CircuitBreaker
                
                breaker = CircuitBreaker(name=f'webhook_{self.platform}', failure_threshold=3, reset_timeout=30.0)
                retry = RetryConfig(max_retries=2, base_delay=1.0)
                
                if not breaker.can_execute():
                    Logger.warning(f"Webhook '{self.platform}' circuit breaker is OPEN — skipping notification")
                    return False
                
                async with ResilientSession(
                    timeout=15.0, retry_config=retry, circuit_breaker=breaker
                ) as session:
                    resp = await session.post(
                        self.webhook_url,
                        json=payload,
                        headers={'Content-Type': 'application/json'}
                    )
                    if resp.status in (200, 201, 204):
                        Logger.success(f"Webhook notification sent ({self.platform})")
                        return True
                    else:
                        error = await resp.text()
                        Logger.error(f"Webhook failed (HTTP {resp.status}): {error[:200]}")
                        return False
            except ImportError:
                # Fallback: raw aiohttp without resilience
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.webhook_url,
                        json=payload,
                        headers={'Content-Type': 'application/json'}
                    ) as resp:
                        if resp.status in (200, 201, 204):
                            Logger.success(f"Webhook notification sent ({self.platform})")
                            return True
                        else:
                            error = await resp.text()
                            Logger.error(f"Webhook failed (HTTP {resp.status}): {error[:200]}")
                            return False
        except Exception as e:
            Logger.error(f"Webhook error: {e}")
            return False
    
    # ─── Slack Format ───────────────────────────────────────────────
    
    def _build_slack_payload(self, vulns: List[Dict], scan_info: Dict) -> Dict:
        """Build Slack Block Kit message."""
        severity_counts = self._count_severities(vulns)
        target = scan_info.get('target', 'Unknown')
        total = len(vulns)
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🦅 WSHawk Scan Complete",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{scan_info.get('duration', 0):.1f}s"},
                    {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                    {"type": "mrkdwn", "text": f"*Messages:*\n{scan_info.get('messages_sent', 0)} sent"},
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": self._severity_summary_text(severity_counts)
                }
            },
        ]
        
        # Add top findings
        if vulns and self.notify_on != "summary_only":
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top Findings:*"}
            })
            
            for vuln in vulns[:5]:
                sev = vuln.get('confidence', vuln.get('severity', 'MEDIUM')).upper()
                emoji = self.SEVERITY_EMOJI.get(sev, '⚪')
                text = f"{emoji} *{vuln.get('type', 'Unknown')}* [{sev}]"
                if vuln.get('cvss_score'):
                    text += f" (CVSS: {vuln['cvss_score']})"
                text += f"\n{vuln.get('description', '')[:100]}"
                
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text}
                })
        
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"_WSHawk V4.0.0 by Regaan | {datetime.now().strftime('%Y-%m-%d %H:%M')}_ "}
            ]
        })
        
        return {"blocks": blocks}
    
    # ─── Discord Format ─────────────────────────────────────────────
    
    def _build_discord_payload(self, vulns: List[Dict], scan_info: Dict) -> Dict:
        """Build Discord embed message."""
        severity_counts = self._count_severities(vulns)
        target = scan_info.get('target', 'Unknown')
        
        # Color based on highest severity
        color_map = {
            'CRITICAL': 0xFF0000,
            'HIGH': 0xFF6600,
            'MEDIUM': 0xFFCC00,
            'LOW': 0x00CC00,
        }
        highest = 'LOW'
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity_counts.get(sev, 0) > 0:
                highest = sev
                break
        
        fields = [
            {"name": "🎯 Target", "value": f"`{target}`", "inline": True},
            {"name": "⏱️ Duration", "value": f"{scan_info.get('duration', 0):.1f}s", "inline": True},
            {"name": "📊 Total Findings", "value": str(len(vulns)), "inline": True},
        ]
        
        # Add severity breakdown
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                emoji = self.SEVERITY_EMOJI.get(sev, '⚪')
                fields.append({
                    "name": f"{emoji} {sev}",
                    "value": str(count),
                    "inline": True
                })
        
        # Add top findings
        if vulns and self.notify_on != "summary_only":
            findings_text = ""
            for v in vulns[:5]:
                sev = v.get('confidence', v.get('severity', 'MEDIUM')).upper()
                emoji = self.SEVERITY_EMOJI.get(sev, '⚪')
                findings_text += f"{emoji} **{v.get('type', 'Unknown')}** [{sev}]\n"
            
            fields.append({
                "name": "🔍 Top Findings",
                "value": findings_text or "None",
                "inline": False
            })
        
        embed = {
            "title": "🦅 WSHawk Scan Complete",
            "color": color_map.get(highest, 0x808080),
            "fields": fields,
            "footer": {
                "text": f"WSHawk V4.0.0 by Regaan • {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            },
            "thumbnail": {
                "url": "https://github.com/regaan.png"
            }
        }
        
        return {"embeds": [embed]}
    
    # ─── Microsoft Teams Format ─────────────────────────────────────
    
    def _build_teams_payload(self, vulns: List[Dict], scan_info: Dict) -> Dict:
        """Build Microsoft Teams Adaptive Card."""
        severity_counts = self._count_severities(vulns)
        target = scan_info.get('target', 'Unknown')
        
        # Color based on severity
        highest_color = "good"
        for sev in ['CRITICAL', 'HIGH']:
            if severity_counts.get(sev, 0) > 0:
                highest_color = "attention"
                break
        
        facts = [
            {"name": "Target", "value": target},
            {"name": "Duration", "value": f"{scan_info.get('duration', 0):.1f}s"},
            {"name": "Total Findings", "value": str(len(vulns))},
            {"name": "Messages Sent", "value": str(scan_info.get('messages_sent', 0))},
        ]
        
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                facts.append({"name": f"{sev}", "value": str(count)})
        
        sections = [
            {
                "activityTitle": "🦅 WSHawk Scan Complete",
                "activitySubtitle": f"WebSocket Security Assessment | {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "facts": facts,
                "markdown": True
            }
        ]
        
        # Add findings
        if vulns and self.notify_on != "summary_only":
            findings_text = ""
            for v in vulns[:5]:
                sev = v.get('confidence', v.get('severity', 'MEDIUM')).upper()
                emoji = self.SEVERITY_EMOJI.get(sev, '⚪')
                findings_text += f"- {emoji} **{v.get('type', 'Unknown')}** [{sev}]  \n"
            
            sections.append({
                "title": "Top Findings",
                "text": findings_text,
                "markdown": True
            })
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if highest_color == "attention" else "00CC00",
            "summary": f"WSHawk: {len(vulns)} findings on {target}",
            "sections": sections,
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "View WSHawk Repo",
                    "targets": [
                        {"os": "default", "uri": "https://github.com/regaan/wshawk"}
                    ]
                }
            ]
        }
    
    # ─── Generic Format ─────────────────────────────────────────────
    
    def _build_generic_payload(self, vulns: List[Dict], scan_info: Dict) -> Dict:
        """Build generic JSON webhook payload."""
        return {
            'event': 'scan_complete',
            'scanner': 'WSHawk V4.0.0',
            'timestamp': datetime.now().isoformat(),
            'scan_info': {
                'target': scan_info.get('target', 'Unknown'),
                'duration': scan_info.get('duration', 0),
                'messages_sent': scan_info.get('messages_sent', 0),
                'messages_received': scan_info.get('messages_received', 0),
            },
            'summary': {
                'total_findings': len(vulns),
                'severity_counts': self._count_severities(vulns),
                'risk_level': self._get_risk_level(vulns),
            },
            'findings': [
                {
                    'type': v.get('type', 'Unknown'),
                    'severity': v.get('confidence', v.get('severity', 'MEDIUM')),
                    'cvss_score': v.get('cvss_score', 0),
                    'description': v.get('description', ''),
                    'verified': v.get('browser_verified', False),
                }
                for v in vulns[:20]
            ],
        }
    
    # ─── Helpers ────────────────────────────────────────────────────
    
    def _count_severities(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {}
        for v in vulns:
            sev = v.get('confidence', v.get('severity', 'MEDIUM')).upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _severity_summary_text(self, counts: Dict[str, int]) -> str:
        """Build severity summary text."""
        parts = []
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = counts.get(sev, 0)
            if count > 0:
                emoji = self.SEVERITY_EMOJI.get(sev, '⚪')
                parts.append(f"{emoji} {sev}: *{count}*")
        return ' | '.join(parts) if parts else "No findings"
    
    def _get_risk_level(self, vulns: List[Dict]) -> str:
        """Calculate overall risk level."""
        severities = [v.get('confidence', v.get('severity', 'LOW')).upper() for v in vulns]
        if 'CRITICAL' in severities: return 'CRITICAL'
        if 'HIGH' in severities: return 'HIGH'
        if 'MEDIUM' in severities: return 'MEDIUM'
        if 'LOW' in severities: return 'LOW'
        return 'NONE'


# ─── Environment-based configuration ────────────────────────────

def from_env() -> Optional[WebhookNotifier]:
    """Create webhook notifier from environment variables."""
    url = os.environ.get('WSHAWK_WEBHOOK_URL')
    if not url:
        return None
    
    platform = os.environ.get('WSHAWK_WEBHOOK_PLATFORM', 'generic')
    return WebhookNotifier(webhook_url=url, platform=platform)
