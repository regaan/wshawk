#!/usr/bin/env python3
"""
WSHawk Multi-Format Report Exporter
Supports JSON, CSV, and SARIF output for CI/CD integration

Author: Regaan (@regaan)
"""

import json
import csv
import io
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path

# Import CVSS calculator
try:
    from .cvss_calculator import CVSSCalculator
except ImportError:
    from cvss_calculator import CVSSCalculator


class ReportExporter:
    """
    Export scan results in multiple formats:
    - JSON: Full structured data for programmatic access
    - CSV: Tabular format for spreadsheets and data analysis
    - SARIF: Static Analysis Results Interchange Format (GitHub/Azure DevOps)
    """

    SUPPORTED_FORMATS = ['json', 'csv', 'sarif']

    def __init__(self):
        self.cvss_calc = CVSSCalculator()

    def export(self,
               vulnerabilities: List[Dict],
               scan_info: Dict,
               output_format: str = 'json',
               output_file: Optional[str] = None,
               fingerprint_info: Optional[Dict] = None,
               traffic_logs: Optional[List[Dict]] = None) -> str:
        """
        Export scan results in the specified format.

        Args:
            vulnerabilities: List of found vulnerabilities
            scan_info: Scan metadata (target, duration, messages, etc.)
            output_format: One of 'json', 'csv', 'sarif'
            output_file: Optional file path to write output (auto-generated if None)
            fingerprint_info: Optional server fingerprint data
            traffic_logs: Optional WebSocket traffic logs

        Returns:
            The output file path
        """
        output_format = output_format.lower()
        if output_format not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {output_format}. Use one of: {self.SUPPORTED_FORMATS}")

        # Enrich vulnerabilities with CVSS data
        enriched_vulns = self._enrich_vulnerabilities(vulnerabilities)

        # Generate output
        if output_format == 'json':
            content = self._export_json(enriched_vulns, scan_info, fingerprint_info, traffic_logs)
            ext = '.json'
        elif output_format == 'csv':
            content = self._export_csv(enriched_vulns, scan_info)
            ext = '.csv'
        elif output_format == 'sarif':
            content = self._export_sarif(enriched_vulns, scan_info)
            ext = '.sarif'

        # Write to file
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"wshawk_report_{timestamp}{ext}"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)

        return output_file

    def _enrich_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Add CVSS scores to vulnerabilities if missing."""
        enriched = []
        for vuln in vulnerabilities:
            v = dict(vuln)  # Copy
            if 'cvss_score' not in v:
                cvss = self.cvss_calc.calculate_for_vulnerability(
                    v.get('type', 'Unknown'),
                    v.get('confidence', 'LOW')
                )
                v['cvss_score'] = cvss.base_score
                v['cvss_severity'] = cvss.severity
                v['cvss_vector'] = cvss.vector_string
            enriched.append(v)
        return enriched

    # ─── JSON Export ────────────────────────────────────────────────

    def _export_json(self,
                     vulnerabilities: List[Dict],
                     scan_info: Dict,
                     fingerprint_info: Optional[Dict] = None,
                     traffic_logs: Optional[List[Dict]] = None) -> str:
        """Generate structured JSON report."""

        # Count by severity
        severity_counts = {}
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_counts[level.lower()] = sum(
                1 for v in vulnerabilities
                if v.get('confidence', v.get('severity', '')).upper() == level
            )

        # Calculate average CVSS
        cvss_scores = [v.get('cvss_score', 0) for v in vulnerabilities if v.get('cvss_score')]
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0

        report = {
            'wshawk_report': {
                'version': '4.0.0',
                'generated_at': datetime.now().isoformat(),
                'scanner': 'WSHawk by Regaan (@regaan)',
                'format_version': '1.0'
            },
            'scan_info': {
                'target': scan_info.get('target', 'Unknown'),
                'start_time': scan_info.get('start_time', datetime.now().isoformat()),
                'duration_seconds': scan_info.get('duration', 0),
                'messages_sent': scan_info.get('messages_sent', 0),
                'messages_received': scan_info.get('messages_received', 0),
            },
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'severity_counts': severity_counts,
                'average_cvss': avg_cvss,
                'risk_level': self._calculate_risk_level(vulnerabilities),
            },
            'vulnerabilities': [
                {
                    'id': f"WSHAWK-{i+1:04d}",
                    'type': v.get('type', 'Unknown'),
                    'severity': v.get('confidence', v.get('severity', 'MEDIUM')).upper(),
                    'cvss_score': v.get('cvss_score', 0),
                    'cvss_severity': v.get('cvss_severity', 'None'),
                    'cvss_vector': v.get('cvss_vector', ''),
                    'description': v.get('description', ''),
                    'payload': str(v.get('payload', ''))[:500],
                    'response_snippet': str(v.get('response_snippet', ''))[:500],
                    'recommendation': v.get('recommendation', self._get_recommendation(v.get('type', ''))),
                    'verified': v.get('browser_verified', False),
                }
                for i, v in enumerate(vulnerabilities)
            ],
        }

        # Optional sections
        if fingerprint_info:
            report['server_fingerprint'] = fingerprint_info

        if traffic_logs:
            report['traffic_log_count'] = len(traffic_logs)
            # Include first 50 traffic entries to keep file size reasonable
            report['traffic_logs'] = traffic_logs[:50]

        return json.dumps(report, indent=2, default=str, ensure_ascii=False)

    # ─── CSV Export ─────────────────────────────────────────────────

    def _export_csv(self,
                    vulnerabilities: List[Dict],
                    scan_info: Dict) -> str:
        """Generate CSV report with one row per vulnerability."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        # Header
        writer.writerow([
            'ID',
            'Type',
            'Severity',
            'CVSS Score',
            'CVSS Severity',
            'Description',
            'Payload',
            'Response Snippet',
            'Recommendation',
            'Browser Verified',
            'Target',
            'Scan Date',
        ])

        # Vulnerability rows
        for i, vuln in enumerate(vulnerabilities):
            writer.writerow([
                f"WSHAWK-{i+1:04d}",
                vuln.get('type', 'Unknown'),
                vuln.get('confidence', vuln.get('severity', 'MEDIUM')).upper(),
                vuln.get('cvss_score', 0),
                vuln.get('cvss_severity', 'None'),
                vuln.get('description', ''),
                str(vuln.get('payload', ''))[:200],
                str(vuln.get('response_snippet', ''))[:200],
                vuln.get('recommendation', self._get_recommendation(vuln.get('type', ''))),
                vuln.get('browser_verified', False),
                scan_info.get('target', 'Unknown'),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ])

        # Summary row (empty line + summary)
        writer.writerow([])
        writer.writerow(['# Summary'])
        writer.writerow(['Total Vulnerabilities', len(vulnerabilities)])
        writer.writerow(['Target', scan_info.get('target', 'Unknown')])
        writer.writerow(['Duration (seconds)', scan_info.get('duration', 0)])
        writer.writerow(['Messages Sent', scan_info.get('messages_sent', 0)])
        writer.writerow(['Messages Received', scan_info.get('messages_received', 0)])
        writer.writerow(['Scanner', 'WSHawk V4.0.0 by Regaan'])

        return output.getvalue()

    # ─── SARIF Export ───────────────────────────────────────────────

    def _export_sarif(self,
                      vulnerabilities: List[Dict],
                      scan_info: Dict) -> str:
        """
        Generate SARIF 2.1.0 report.
        SARIF (Static Analysis Results Interchange Format) is supported by:
        - GitHub Code Scanning
        - Azure DevOps
        - VS Code SARIF Viewer
        """
        # Build rules from unique vulnerability types
        rules = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in rules:
                rules[vuln_type] = {
                    'id': vuln_type.replace(' ', '-').lower(),
                    'name': vuln_type,
                    'shortDescription': {
                        'text': f"WebSocket {vuln_type} vulnerability"
                    },
                    'fullDescription': {
                        'text': f"WSHawk detected a potential {vuln_type} vulnerability in WebSocket communication."
                    },
                    'defaultConfiguration': {
                        'level': self._sarif_level(vuln.get('confidence', 'MEDIUM'))
                    },
                    'properties': {
                        'tags': ['security', 'websocket', vuln_type.lower().replace(' ', '-')]
                    }
                }

        # Build results
        results = []
        for i, vuln in enumerate(vulnerabilities):
            vuln_type = vuln.get('type', 'Unknown')
            result = {
                'ruleId': vuln_type.replace(' ', '-').lower(),
                'level': self._sarif_level(vuln.get('confidence', 'MEDIUM')),
                'message': {
                    'text': vuln.get('description', f'{vuln_type} detected')
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': scan_info.get('target', 'ws://unknown'),
                            'uriBaseId': 'WEBSOCKET_TARGET'
                        }
                    }
                }],
                'properties': {
                    'cvss_score': vuln.get('cvss_score', 0),
                    'cvss_vector': vuln.get('cvss_vector', ''),
                    'payload': str(vuln.get('payload', ''))[:200],
                    'browser_verified': vuln.get('browser_verified', False),
                    'id': f"WSHAWK-{i+1:04d}"
                }
            }
            results.append(result)

        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'WSHawk',
                        'version': '4.0.0',
                        'semanticVersion': '4.0.0',
                        'informationUri': 'https://github.com/regaan/wshawk',
                        'organization': 'Rot Hackers',
                        'rules': list(rules.values())
                    }
                },
                'results': results,
                'invocations': [{
                    'executionSuccessful': True,
                    'startTimeUtc': scan_info.get('start_time', datetime.now().isoformat()),
                    'endTimeUtc': datetime.now().isoformat(),
                    'toolExecutionNotifications': []
                }],
                'properties': {
                    'target': scan_info.get('target', 'Unknown'),
                    'duration_seconds': scan_info.get('duration', 0),
                    'messages_sent': scan_info.get('messages_sent', 0),
                    'messages_received': scan_info.get('messages_received', 0),
                }
            }]
        }

        return json.dumps(sarif, indent=2, default=str, ensure_ascii=False)

    # ─── Helpers ────────────────────────────────────────────────────

    def _sarif_level(self, severity: str) -> str:
        """Convert WSHawk severity to SARIF level."""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
        }
        return mapping.get(severity.upper(), 'warning')

    def _calculate_risk_level(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall risk level from vulnerabilities."""
        if not vulnerabilities:
            return 'NONE'

        severities = [v.get('confidence', v.get('severity', 'LOW')).upper() for v in vulnerabilities]

        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _get_recommendation(self, vuln_type: str) -> str:
        """Get default recommendation for vulnerability type."""
        recommendations = {
            'SQL Injection': 'Use parameterized queries and input validation for all WebSocket message fields.',
            'XSS': 'Sanitize and encode all user-supplied data before rendering in browser contexts.',
            'Command Injection': 'Never pass user input directly to system commands. Use allow-lists and proper escaping.',
            'Path Traversal': 'Validate and sanitize file paths. Use chroot or jail for file access.',
            'XXE': 'Disable external entity processing in XML parsers.',
            'NoSQL Injection': 'Use parameterized queries for NoSQL databases. Validate input types.',
            'SSRF': 'Validate and restrict URLs to allowed hosts. Block internal network access.',
            'SSTI': 'Use logic-less templates and sandbox template engines.',
            'Open Redirect': 'Validate redirect targets against an allow-list of trusted domains.',
            'LDAP Injection': 'Use parameterized LDAP queries and proper input encoding.',
        }
        for key, rec in recommendations.items():
            if key.lower() in vuln_type.lower():
                return rec
        return 'Implement proper input validation and output encoding for WebSocket messages.'


# ─── Convenience Functions ──────────────────────────────────────

def export_json(vulnerabilities, scan_info, output_file=None, **kwargs):
    """Quick JSON export."""
    return ReportExporter().export(vulnerabilities, scan_info, 'json', output_file, **kwargs)

def export_csv(vulnerabilities, scan_info, output_file=None, **kwargs):
    """Quick CSV export."""
    return ReportExporter().export(vulnerabilities, scan_info, 'csv', output_file, **kwargs)

def export_sarif(vulnerabilities, scan_info, output_file=None, **kwargs):
    """Quick SARIF export."""
    return ReportExporter().export(vulnerabilities, scan_info, 'sarif', output_file, **kwargs)


if __name__ == "__main__":
    # Demo with sample data
    sample_vulns = [
        {
            'type': 'XSS',
            'confidence': 'HIGH',
            'description': 'Reflected XSS in WebSocket echo response',
            'payload': '<script>alert(1)</script>',
            'response_snippet': 'Echo: <script>alert(1)</script>',
            'browser_verified': True,
        },
        {
            'type': 'SQL Injection',
            'confidence': 'MEDIUM',
            'description': 'SQL error in response after injection payload',
            'payload': "' OR 1=1--",
            'response_snippet': 'SQL syntax error near...',
        }
    ]

    sample_info = {
        'target': 'ws://example.com/ws',
        'duration': 45.2,
        'messages_sent': 150,
        'messages_received': 148,
    }

    exporter = ReportExporter()

    # Export all formats
    for fmt in ['json', 'csv', 'sarif']:
        path = exporter.export(sample_vulns, sample_info, fmt)
        print(f"[OK] {fmt.upper()} report saved: {path}")
