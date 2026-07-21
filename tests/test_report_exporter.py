#!/usr/bin/env python3
"""
Tests for WSHawk Report Exporter
"""
import json
import csv
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wshawk.report_exporter import ReportExporter


class TestReportExporter(unittest.TestCase):

    def setUp(self):
        self.exporter = ReportExporter()
        self.sample_vulns = [
            {
                'type': 'XSS',
                'confidence': 'HIGH',
                'description': 'Reflected XSS in WebSocket echo',
                'payload': '<script>alert(1)</script>',
                'response_snippet': 'Echo: <script>alert(1)</script>',
                'browser_verified': True,
            },
            {
                'type': 'SQL Injection',
                'confidence': 'CRITICAL',
                'description': 'SQL error in response',
                'payload': "' OR 1=1--",
                'response_snippet': 'SQL syntax error...',
            },
            {
                'type': 'Command Injection',
                'confidence': 'MEDIUM',
                'description': 'Possible command injection',
                'payload': '; whoami',
                'response_snippet': 'root',
            }
        ]
        self.scan_info = {
            'target': 'ws://test.example.com/ws',
            'duration': 42.5,
            'messages_sent': 200,
            'messages_received': 195,
        }

    def tearDown(self):
        # Clean up generated files
        for f in os.listdir('.'):
            if f.startswith('wshawk_report_') and f.endswith(('.json', '.csv', '.sarif')):
                os.remove(f)

    # ─── JSON Tests ─────────────────────────────────────────────

    def test_json_export_structure(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'json')
        self.assertTrue(os.path.exists(path))

        with open(path) as f:
            report = json.load(f)

        self.assertIn('wshawk_report', report)
        self.assertIn('scan_info', report)
        self.assertIn('summary', report)
        self.assertIn('vulnerabilities', report)
        self.assertEqual(report['wshawk_report']['scanner'], 'WSHawk by Regaan (@regaan)')

    def test_json_vulnerability_count(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'json')
        with open(path) as f:
            report = json.load(f)

        self.assertEqual(report['summary']['total_vulnerabilities'], 3)
        self.assertEqual(report['summary']['severity_counts']['critical'], 1)
        self.assertEqual(report['summary']['severity_counts']['high'], 1)
        self.assertEqual(report['summary']['severity_counts']['medium'], 1)

    def test_json_cvss_enrichment(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'json')
        with open(path) as f:
            report = json.load(f)

        for vuln in report['vulnerabilities']:
            self.assertIn('cvss_score', vuln)
            self.assertIn('cvss_severity', vuln)
            self.assertIn('cvss_vector', vuln)
            self.assertGreaterEqual(vuln['cvss_score'], 0)

    def test_json_vuln_ids(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'json')
        with open(path) as f:
            report = json.load(f)

        ids = [v['id'] for v in report['vulnerabilities']]
        self.assertEqual(ids, ['WSHAWK-0001', 'WSHAWK-0002', 'WSHAWK-0003'])

    def test_json_risk_level(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'json')
        with open(path) as f:
            report = json.load(f)

        self.assertEqual(report['summary']['risk_level'], 'CRITICAL')

    def test_json_empty_vulns(self):
        path = self.exporter.export([], self.scan_info, 'json')
        with open(path) as f:
            report = json.load(f)

        self.assertEqual(report['summary']['total_vulnerabilities'], 0)
        self.assertEqual(report['summary']['risk_level'], 'NONE')

    # ─── CSV Tests ──────────────────────────────────────────────

    def test_csv_export_structure(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'csv')
        self.assertTrue(os.path.exists(path))
        self.assertTrue(path.endswith('.csv'))

        with open(path) as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 3 vulns + empty + summary header + 6 summary rows
        self.assertGreater(len(rows), 4)
        self.assertEqual(rows[0][0], 'ID')  # Header check

    def test_csv_vulnerability_data(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'csv')
        with open(path) as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Check first vulnerability row
        self.assertEqual(rows[1][0], 'WSHAWK-0001')
        self.assertEqual(rows[1][1], 'XSS')
        self.assertEqual(rows[1][2], 'HIGH')

    # ─── SARIF Tests ────────────────────────────────────────────

    def test_sarif_export_structure(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'sarif')
        self.assertTrue(os.path.exists(path))

        with open(path) as f:
            sarif = json.load(f)

        self.assertEqual(sarif['version'], '2.1.0')
        self.assertEqual(len(sarif['runs']), 1)
        self.assertEqual(sarif['runs'][0]['tool']['driver']['name'], 'WSHawk')

    def test_sarif_results_count(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'sarif')
        with open(path) as f:
            sarif = json.load(f)

        results = sarif['runs'][0]['results']
        self.assertEqual(len(results), 3)

    def test_sarif_severity_mapping(self):
        path = self.exporter.export(self.sample_vulns, self.scan_info, 'sarif')
        with open(path) as f:
            sarif = json.load(f)

        levels = [r['level'] for r in sarif['runs'][0]['results']]
        self.assertIn('error', levels)    # HIGH/CRITICAL → error
        self.assertIn('warning', levels)  # MEDIUM → warning

    # ─── Custom Output Path ─────────────────────────────────────

    def test_custom_output_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_path = str(Path(temp_dir) / 'wshawk_test_output.json')
            path = self.exporter.export(self.sample_vulns, self.scan_info, 'json', custom_path)
            self.assertEqual(path, custom_path)
            self.assertTrue(os.path.exists(custom_path))

    # ─── Invalid Format ─────────────────────────────────────────

    def test_invalid_format_raises(self):
        with self.assertRaises(ValueError):
            self.exporter.export(self.sample_vulns, self.scan_info, 'pdf')


if __name__ == '__main__':
    unittest.main()
