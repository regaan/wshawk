#!/usr/bin/env python3
"""
WSHawk Enhanced HTML Report Generator v2
Complete professional reporting with CVSS, screenshots, and replay sequences
"""

import json
import base64
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

# Import CVSS calculator
try:
    from .cvss_calculator import CVSSCalculator
except ImportError:
    from cvss_calculator import CVSSCalculator

class EnhancedHTMLReporter:
    """
    Generate professional HTML reports with:
    - CVSS v3.1 scoring
    - Screenshots (for XSS)
    - Message replay sequences
    - Traffic logs
    - Server fingerprints
    """
    
    def __init__(self):
        self.cvss_calc = CVSSCalculator()
        self.template = self._get_template()
    
    def generate_report(self, 
                       vulnerabilities: List[Dict],
                       scan_info: Dict,
                       fingerprint_info: Optional[Dict] = None,
                       traffic_logs: Optional[List[Dict]] = None,
                       screenshots: Optional[Dict[str, str]] = None) -> str:
        """
        Generate comprehensive HTML report
        
        Args:
            vulnerabilities: List of found vulnerabilities
            scan_info: Scan metadata
            fingerprint_info: Server fingerprint
            traffic_logs: WebSocket traffic logs
            screenshots: Dict of vuln_id -> screenshot_path
        """
        # Calculate CVSS scores for all vulnerabilities
        for vuln in vulnerabilities:
            cvss = self.cvss_calc.calculate_for_vulnerability(
                vuln.get('type', 'Unknown'),
                vuln.get('confidence', 'LOW')
            )
            vuln['cvss_score'] = cvss.base_score
            vuln['cvss_severity'] = cvss.severity
            vuln['cvss_vector'] = cvss.vector_string
        
        # Calculate statistics
        stats = self._calculate_stats(vulnerabilities)
        
        # Generate vulnerability cards
        vuln_html = self._generate_vulnerability_cards(vulnerabilities, screenshots or {})
        
        # Generate fingerprint section
        fingerprint_html = self._generate_fingerprint_section(fingerprint_info) if fingerprint_info else ""
        
        # Generate traffic logs
        traffic_html = self._generate_traffic_logs(traffic_logs) if traffic_logs else ""
        
        # Fill template
        report = self.template.format(
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_url=scan_info.get('target', 'Unknown'),
            scan_duration=scan_info.get('duration', 0),
            messages_sent=scan_info.get('messages_sent', 0),
            messages_received=scan_info.get('messages_received', 0),
            total_vulns=stats['total'],
            critical_count=stats['critical'],
            high_count=stats['high'],
            medium_count=stats['medium'],
            low_count=stats['low'],
            avg_cvss=stats['avg_cvss'],
            fingerprint_section=fingerprint_html,
            vulnerability_cards=vuln_html,
            traffic_logs=traffic_html
        )
        
        return report
    
    def _calculate_stats(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate vulnerability statistics"""
        stats = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v.get('confidence') == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v.get('confidence') == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v.get('confidence') == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v.get('confidence') == 'LOW'),
        }
        
        # Calculate average CVSS
        if vulnerabilities:
            total_cvss = sum(v.get('cvss_score', 0) for v in vulnerabilities)
            stats['avg_cvss'] = round(total_cvss / len(vulnerabilities), 1)
        else:
            stats['avg_cvss'] = 0.0
        
        return stats
    
    def _generate_vulnerability_cards(self, vulnerabilities: List[Dict], screenshots: Dict[str, str]) -> str:
        """Generate HTML cards for each vulnerability"""
        cards = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.get('confidence', 'LOW').lower()
            vuln_id = f"vuln_{i}"
            
            # Generate reproduction steps
            reproduction = self._generate_reproduction_steps(vuln)
            
            # Generate message replay sequence
            replay = self._generate_replay_sequence(vuln)
            
            # Screenshot section
            screenshot_html = ""
            if vuln_id in screenshots or vuln.get('screenshot'):
                screenshot_path = screenshots.get(vuln_id) or vuln.get('screenshot')
                screenshot_html = f"""
                <div class="screenshot-section">
                    <strong>Screenshot Evidence:</strong>
                    <img src="{screenshot_path}" alt="Vulnerability Screenshot" class="screenshot">
                </div>
                """
            
            # CVSS section
            cvss_html = f"""
            <div class="cvss-section">
                <strong>CVSS v3.1 Score:</strong>
                <div class="cvss-score {vuln.get('cvss_severity', 'Low').lower()}">
                    {vuln.get('cvss_score', 0.0)}
                </div>
                <div class="cvss-severity">{vuln.get('cvss_severity', 'Low')}</div>
                <div class="cvss-vector">{vuln.get('cvss_vector', 'N/A')}</div>
            </div>
            """
            
            card = f"""
            <div class="vuln-card {severity_class}">
                <div class="vuln-header">
                    <h3>#{i}. {vuln.get('type', 'Unknown')}</h3>
                    <span class="severity-badge {severity_class}">{vuln.get('confidence', 'LOW')}</span>
                </div>
                <div class="vuln-body">
                    <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                    
                    {cvss_html}
                    
                    <div class="code-block">
                        <strong>Payload:</strong>
                        <pre><code>{self._escape_html(vuln.get('payload', 'N/A')[:200])}</code></pre>
                    </div>
                    
                    <div class="code-block">
                        <strong>Response Snippet:</strong>
                        <pre><code>{self._escape_html(vuln.get('response_snippet', 'N/A')[:300])}</code></pre>
                    </div>
                    
                    {screenshot_html}
                    
                    <div class="reproduction">
                        <strong>Reproduction Steps:</strong>
                        {reproduction}
                    </div>
                    
                    {replay}
                    
                    <div class="recommendation">
                        <strong>Recommendation:</strong>
                        <p>{vuln.get('recommendation', 'Review and fix this vulnerability')}</p>
                    </div>
                </div>
            </div>
            """
            cards.append(card)
        
        return '\n'.join(cards)
    
    def _generate_reproduction_steps(self, vuln: Dict) -> str:
        """Generate reproduction steps for vulnerability"""
        steps = f"""
        <ol>
            <li>Connect to the WebSocket endpoint</li>
            <li>Send the following payload:
                <pre><code>{self._escape_html(vuln.get('payload', 'N/A')[:150])}</code></pre>
            </li>
            <li>Observe the response for vulnerability indicators</li>
            <li>Verify the {vuln.get('type', 'vulnerability')} is exploitable</li>
        </ol>
        """
        return steps
    
    def _generate_replay_sequence(self, vuln: Dict) -> str:
        """Generate message replay sequence"""
        if 'replay_sequence' not in vuln:
            return ""
        
        sequence = vuln['replay_sequence']
        messages = []
        
        for msg in sequence:
            messages.append(f"""
            <div class="replay-message">
                <span class="replay-direction">{msg.get('direction', '→')}</span>
                <pre>{self._escape_html(msg.get('content', '')[:100])}</pre>
            </div>
            """)
        
        return f"""
        <div class="replay-section">
            <strong>Message Replay Sequence:</strong>
            <div class="replay-container">
                {''.join(messages)}
            </div>
        </div>
        """
    
    def _generate_fingerprint_section(self, fingerprint: Dict) -> str:
        """Generate server fingerprint section"""
        return f"""
        <div class="fingerprint-section">
            <h2>Server Fingerprint</h2>
            <div class="fingerprint-grid">
                <div class="fingerprint-item">
                    <strong>Language:</strong> {fingerprint.get('language', 'Unknown')}
                </div>
                <div class="fingerprint-item">
                    <strong>Framework:</strong> {fingerprint.get('framework', 'Unknown')}
                </div>
                <div class="fingerprint-item">
                    <strong>Database:</strong> {fingerprint.get('database', 'Unknown')}
                </div>
                <div class="fingerprint-item">
                    <strong>Confidence:</strong> {fingerprint.get('confidence', 'N/A')}
                </div>
            </div>
            <div class="libraries">
                <strong>Detected Libraries:</strong> {', '.join(fingerprint.get('libraries', []))}
            </div>
        </div>
        """
    
    def _generate_traffic_logs(self, logs: List[Dict]) -> str:
        """Generate traffic logs section"""
        log_entries = []
        for log in logs[:100]:  # Limit to 100 entries
            direction_icon = "→" if log.get('direction') == 'sent' else "←"
            log_entries.append(f"""
            <div class="log-entry">
                <span class="log-direction">{direction_icon}</span>
                <span class="log-timestamp">{log.get('timestamp', 'N/A')}</span>
                <pre class="log-content">{self._escape_html(log.get('content', '')[:200])}</pre>
            </div>
            """)
        
        return f"""
        <div class="traffic-logs">
            <h2>Traffic Logs</h2>
            <div class="logs-container">
                {''.join(log_entries)}
            </div>
        </div>
        """
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def _get_template(self) -> str:
        """Get HTML template with CVSS and screenshot support"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSHawk Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .content {{
            padding: 30px;
        }}
        .vuln-card {{
            background: white;
            border-left: 5px solid #ccc;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .vuln-card.critical {{ border-left-color: #dc3545; }}
        .vuln-card.high {{ border-left-color: #fd7e14; }}
        .vuln-card.medium {{ border-left-color: #ffc107; }}
        .vuln-card.low {{ border-left-color: #28a745; }}
        .vuln-header {{
            padding: 20px;
            background: #f8f9fa;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
        }}
        .severity-badge.critical {{ background: #dc3545; }}
        .severity-badge.high {{ background: #fd7e14; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #28a745; }}
        .vuln-body {{
            padding: 20px;
        }}
        .cvss-section {{
            background: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .cvss-score {{
            font-size: 2em;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 5px;
            color: white;
        }}
        .cvss-score.critical {{ background: #dc3545; }}
        .cvss-score.high {{ background: #fd7e14; }}
        .cvss-score.medium {{ background: #ffc107; color: #333; }}
        .cvss-score.low {{ background: #28a745; }}
        .cvss-score.none {{ background: #6c757d; }}
        .cvss-vector {{
            font-family: monospace;
            font-size: 0.85em;
            color: #666;
        }}
        .screenshot-section {{
            margin: 15px 0;
        }}
        .screenshot {{
            max-width: 100%;
            border: 2px solid #ddd;
            border-radius: 5px;
            margin-top: 10px;
        }}
        .replay-section {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        .replay-message {{
            background: white;
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid #667eea;
            display: flex;
            gap: 10px;
        }}
        .replay-direction {{
            font-weight: bold;
            color: #667eea;
        }}
        .code-block {{
            background: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            border-left: 3px solid #667eea;
        }}
        .code-block pre {{
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .recommendation {{
            background: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border-left: 3px solid #0066cc;
        }}
        .traffic-logs {{
            margin-top: 30px;
        }}
        .log-entry {{
            background: #f8f9fa;
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid #28a745;
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }}
        .log-direction {{
            font-weight: bold;
            color: #28a745;
        }}
        .footer {{
            background: #333;
            color: white;
            text-align: center;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WSHawk Security Scan Report</h1>
            <p class="subtitle">WebSocket Vulnerability Assessment</p>
            <p style="margin-top: 10px;">Generated: {scan_date}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">{total_vulns}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="number">{avg_cvss}</div>
                <div class="label">Avg CVSS Score</div>
            </div>
            <div class="stat-card">
                <div class="number">{scan_duration:.2f}s</div>
                <div class="label">Scan Duration</div>
            </div>
            <div class="stat-card">
                <div class="number">{messages_sent}</div>
                <div class="label">Messages Sent</div>
            </div>
        </div>
        
        <div class="content">
            <h2 style="margin-bottom: 20px;">Target Information</h2>
            <div class="code-block">
                <strong>URL:</strong> {target_url}
            </div>
            
            {fingerprint_section}
            
            <h2 style="margin: 30px 0 20px 0;">Vulnerabilities Found</h2>
            {vulnerability_cards}
            
            {traffic_logs}
        </div>
        
        <div class="footer">
            <p>Generated by WSHawk v4.0.0 - WebSocket Security Scanner</p>
            <p style="margin-top: 10px; opacity: 0.8;">Professional-Grade Security Testing</p>
        </div>
    </div>
</body>
</html>
        """

if __name__ == "__main__":
    reporter = EnhancedHTMLReporter()
    print("Enhanced HTML report generator loaded.")
