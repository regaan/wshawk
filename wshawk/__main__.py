#!/usr/bin/env python3

"""
WSHawk - WebSocket Security Scanner
Created: December 2025
Author: Regaan (@regaan)
"""

import asyncio
import websockets
import json
import time
import re
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
import ssl

# Force UTF-8 output on Windows to prevent charmap encoding crashes
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from .logger import setup_logging, get_logger, VULN_LEVEL, SUCCESS_LEVEL, Colors

# Initialize logging on import
logger = setup_logging()

class Logger:
    @staticmethod
    def banner():
        try:
            banner = f"""
{Colors.CYAN}{Colors.BOLD}
╦ ╦╔═╗╦ ╦╔═╗╦ ╦╦╔═
║║║╚═╗╠═╣╠═╣║║║╠╩╗
╚╩╝╚═╝╩ ╩╩ ╩╚╩╝╩ ╩
{Colors.END}
{Colors.YELLOW}WebSocket Security Scanner V3.0.6{Colors.END}
{Colors.CYAN}Created by: Regaan (@regaan){Colors.END}
{Colors.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
"""
            print(banner)
        except UnicodeEncodeError:
            # ASCII fallback for terminals that can't render Unicode
            banner = f"""
{Colors.CYAN}{Colors.BOLD}
 _    _ ___ _  _ ____ _    _ _  _
 |    |  |  |__| |__| |    | |_/
 |_/|_|  |  |  | |  | |_/|_| | \\_
{Colors.END}
{Colors.YELLOW}WebSocket Security Scanner V3.0.6{Colors.END}
{Colors.CYAN}Created by: Regaan (@regaan){Colors.END}
{Colors.BLUE}========================================{Colors.END}
"""
            print(banner)
    
    @staticmethod
    def info(msg):
        get_logger().info(msg)
    
    @staticmethod
    def success(msg):
        get_logger().log(SUCCESS_LEVEL, msg)
    
    @staticmethod
    def warning(msg):
        get_logger().warning(msg)
    
    @staticmethod
    def error(msg):
        get_logger().error(msg)
    
    @staticmethod
    def vuln(msg):
        get_logger().log(VULN_LEVEL, msg)


class WSPayloads:
    """
    Comprehensive WebSocket attack payload database
    Loads 2500+ payloads from external files
    """
    
    _payloads_cache = {}
    
    @staticmethod
    def load_payloads(filename):
        """Load payloads from file with caching"""
        if filename in WSPayloads._payloads_cache:
            return WSPayloads._payloads_cache[filename]
        
        try:
            # Try importlib.resources first (for pip-installed packages)
            try:
                if hasattr(__import__('importlib.resources'), 'files'):
                    # Python 3.9+
                    from importlib.resources import files
                    payload_file = files('wshawk').joinpath('payloads', filename)
                    payloads = payload_file.read_text(encoding='utf-8', errors='ignore').strip().split('\n')
                else:
                    # Python 3.8
                    from importlib.resources import read_text
                    content = read_text('wshawk.payloads', filename, encoding='utf-8', errors='ignore')
                    payloads = content.strip().split('\n')
            except (ImportError, FileNotFoundError, TypeError):
                # Fallback to file system (for development/source install)
                filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'payloads', filename)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip()]
            
            payloads = [p.strip() for p in payloads if p.strip()]
            WSPayloads._payloads_cache[filename] = payloads
            return payloads
        except FileNotFoundError:
            Logger.warning(f"Payload file not found: {filename}")
            return []
        except Exception as e:
            Logger.error(f"Error loading payloads from {filename}: {e}")
            return []
    
    @staticmethod
    def get_sql_injection():
        return WSPayloads.load_payloads('sql_injection.txt')
    
    @staticmethod
    def get_xss():
        return WSPayloads.load_payloads('xss.txt')
    
    @staticmethod
    def get_command_injection():
        return WSPayloads.load_payloads('command_injection.txt')
    
    @staticmethod
    def get_nosql_injection():
        return WSPayloads.load_payloads('nosql_injection.txt')
    
    @staticmethod
    def get_path_traversal():
        return WSPayloads.load_payloads('path_traversal.txt')
    
    @staticmethod
    def get_ldap_injection():
        return WSPayloads.load_payloads('ldap_injection.txt')
    
    @staticmethod
    def get_xxe():
        return WSPayloads.load_payloads('xxe.txt')
    
    @staticmethod
    def get_ssti():
        return WSPayloads.load_payloads('ssti.txt')
    
    @staticmethod
    def get_open_redirect():
        return WSPayloads.load_payloads('open_redirect.txt')
    
    @staticmethod
    def get_csv_injection():
        return WSPayloads.load_payloads('csv_injection.txt')


class WSHawk:
    """
    Main WebSocket Security Scanner
    """
    
    def __init__(self, url: str, headers: Optional[Dict] = None, proxy: Optional[str] = None, max_payloads: int = None):
        self.url = url
        self.headers = headers or {}
        self.proxy = proxy
        self.max_payloads = max_payloads  # None = test ALL payloads
        self.vulnerabilities = []
        self.start_time = None
        self.end_time = None
        self.messages_sent = 0
        self.messages_received = 0
        
    async def connect(self, origin: Optional[str] = None, timeout: int = 10):
        """
        Establish WebSocket connection with error handling
        """
        try:
            # Build headers
            extra_headers = {}
            if self.headers:
                extra_headers.update(self.headers)
            if origin:
                extra_headers['Origin'] = origin
            
            # SSL context for wss://
            ssl_context = None
            if self.url.startswith('wss://'):
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Connect with proper API
            ws = await asyncio.wait_for(
                websockets.connect(
                    self.url,
                    additional_headers=extra_headers if extra_headers else None,
                    ssl=ssl_context
                ),
                timeout=timeout
            )
            
            return ws
            
        except asyncio.TimeoutError:
            Logger.error(f"Connection timeout after {timeout}s")
            return None
        except Exception as e:
            Logger.error(f"Connection failed: {e}")
            return None
    
    async def send_and_receive(self, ws, message: str, timeout: int = 5) -> Optional[str]:
        """
        Send message and receive response with timeout
        """
        try:
            await ws.send(message)
            self.messages_sent += 1
            
            response = await asyncio.wait_for(ws.recv(), timeout=timeout)
            self.messages_received += 1
            
            return response
            
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            Logger.error(f"Send/Receive error: {e}")
            return None
    
    async def test_connection(self) -> bool:
        """
        Test basic WebSocket connection
        """
        Logger.info("Testing WebSocket connection...")
        
        ws = await self.connect()
        if not ws:
            Logger.error("Failed to establish WebSocket connection")
            return False
        
        try:
            # Send ping
            pong = await ws.ping()
            await asyncio.wait_for(pong, timeout=5)
            Logger.success("WebSocket connection established")
            await ws.close()
            return True
            
        except Exception as e:
            Logger.error(f"Connection test failed: {e}")
            return False
    
    async def test_origin_bypass(self) -> List[Dict]:
        """
        Test for Cross-Site WebSocket Hijacking (CSWSH)
        """
        Logger.info("Testing origin validation bypass (CSWSH)...")
        
        results = []
        malicious_origins = [
            # Null and empty origins
            "null",
            "",
            " ",
            
            # Common attack domains
            "http://evil.com",
            "https://attacker.com",
            "http://malicious.com",
            "https://phishing.com",
            "http://hacker.com",
            
            # Localhost variations
            "http://localhost",
            "https://localhost",
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://localhost.localdomain",
            
            # Internal IPs
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # Case manipulation
            "HTTP://EVIL.COM",
            "HtTp://EvIl.CoM",
            
            # Protocol manipulation
            "file://",
            "ftp://evil.com",
            "data:text/html,<script>alert(1)</script>",
            
            # Subdomain attacks
            "http://evil.target.com",
            "http://target.com.evil.com",
            "http://evil-target.com",
            
            # Unicode/IDN attacks
            "http://еvil.com",  # Cyrillic 'e'
            "http://evil。com",  # Fullwidth dot
            
            # Port manipulation
            "http://evil.com:80",
            "https://evil.com:443",
            "http://evil.com:8080",
            
            # Path traversal in origin
            "http://evil.com/../../",
            "http://evil.com/../target.com",
            
            # Special characters
            "http://evil.com@target.com",
            "http://target.com#evil.com",
            "http://target.com?evil.com",
            
            # Encoded origins
            "http%3A%2F%2Fevil.com",
            "http://evil%2Ecom",
            
            # Wildcard attempts
            "*",
            "http://*",
            "https://*",
            "*://evil.com",
            
            # JavaScript protocol
            "javascript:alert(1)",
            "javascript://evil.com",
            
            # Double encoding
            "http%253A%252F%252Fevil.com",
            
            # Mixed case protocols
            "HtTpS://evil.com",
            "hTTp://evil.com",
        ]
        
        for origin in malicious_origins:
            ws = await self.connect(origin=origin)
            if ws:
                Logger.warning(f"Origin bypass successful with: {origin}")
                self.vulnerabilities.append({
                    'type': 'Cross-Site WebSocket Hijacking (CSWSH)',
                    'severity': 'CRITICAL',
                    'description': f'WebSocket accepts connections from malicious origin: {origin}',
                    'recommendation': 'Implement strict origin validation',
                    'payload': origin
                })
                results.append({'origin': origin, 'success': True})
                await ws.close()
            else:
                results.append({'origin': origin, 'success': False})
        
        return results
    
    async def test_sql_injection(self) -> List[Dict]:
        """
        Test for SQL injection in WebSocket messages
        """
        all_payloads = WSPayloads.get_sql_injection()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing SQL injection ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            # Use max_payloads if set, otherwise test ALL
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                # Test in JSON message
                message = json.dumps({"query": payload, "action": "search"})
                response = await self.send_and_receive(ws, message)
                
                if response:
                    # Check for SQL error indicators
                    sql_errors = [
                        'sql syntax', 'mysql', 'postgresql', 'sqlite',
                        'syntax error', 'unclosed quotation', 'quoted string',
                        'database error', 'sql error'
                    ]
                    
                    response_lower = response.lower()
                    if any(error in response_lower for error in sql_errors):
                        Logger.vuln(f"SQL Injection detected: {payload[:50]}")
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'description': 'SQL injection vulnerability in WebSocket message',
                            'payload': payload,
                            'response': response[:200],
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)  # Rate limiting
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"SQL injection test error: {e}")
        
        return results
    
    async def test_xss(self) -> List[Dict]:
        """
        Test for XSS in WebSocket messages
        """
        all_payloads = WSPayloads.get_xss()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing XSS injection ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            # Use max_payloads if set, otherwise test ALL
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"message": payload, "action": "post"})
                response = await self.send_and_receive(ws, message)
                
                if response and payload in response:
                    Logger.vuln(f"XSS reflection detected: {payload[:50]}")
                    self.vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'description': 'XSS payload reflected in WebSocket response',
                        'payload': payload,
                        'recommendation': 'Sanitize and encode all user input'
                    })
                    results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"XSS test error: {e}")
        
        return results
    
    async def test_command_injection(self) -> List[Dict]:
        """
        Test for command injection
        """
        all_payloads = WSPayloads.get_command_injection()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing command injection ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            # Use max_payloads if set, otherwise test ALL
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"cmd": payload, "action": "execute"})
                
                start_time = time.time()
                response = await self.send_and_receive(ws, message, timeout=10)
                elapsed = time.time() - start_time
                
                # Check for command execution indicators
                if response:
                    indicators = ['root:', 'uid=', 'gid=', 'bin/bash', 'cmd.exe']
                    if any(ind in response for ind in indicators):
                        Logger.vuln(f"Command injection detected: {payload[:50]}")
                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'severity': 'CRITICAL',
                            'description': 'OS command injection in WebSocket message',
                            'payload': payload,
                            'response': response[:200],
                            'recommendation': 'Never execute user input as system commands'
                        })
                        results.append({'payload': payload, 'vulnerable': True})
                
                # Timing-based detection (sleep command)
                if 'sleep' in payload.lower() and elapsed > 4:
                    Logger.vuln(f"Timing-based command injection: {payload[:50]}")
                    self.vulnerabilities.append({
                        'type': 'Command Injection (Timing-based)',
                        'severity': 'CRITICAL',
                        'description': f'Timing attack successful (delay: {elapsed:.2f}s)',
                        'payload': payload,
                        'recommendation': 'Implement input validation and sandboxing'
                    })
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"Command injection test error: {e}")
        
        return results
    
    async def test_nosql_injection(self) -> List[Dict]:
        """
        Test for NoSQL injection vulnerabilities
        """
        all_payloads = WSPayloads.get_nosql_injection()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing NoSQL injection ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"query": payload, "action": "find"})
                response = await self.send_and_receive(ws, message)
                
                if response:
                    nosql_indicators = ['mongodb', 'syntax error', 'bson', 'couchdb', 'redis']
                    if any(ind in response.lower() for ind in nosql_indicators):
                        Logger.vuln(f"NoSQL injection detected: {payload[:50]}")
                        self.vulnerabilities.append({
                            'type': 'NoSQL Injection',
                            'severity': 'CRITICAL',
                            'description': 'NoSQL injection vulnerability detected',
                            'payload': payload,
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"NoSQL injection test error: {e}")
        
        return results
    
    async def test_ldap_injection(self) -> List[Dict]:
        """
        Test for LDAP injection vulnerabilities
        """
        all_payloads = WSPayloads.get_ldap_injection()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing LDAP injection ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"filter": payload, "action": "search"})
                response = await self.send_and_receive(ws, message)
                
                if response:
                    ldap_indicators = ['ldap', 'directory', 'dn:', 'cn=']
                    if any(ind in response.lower() for ind in ldap_indicators):
                        Logger.vuln(f"LDAP injection detected: {payload[:50]}")
                        self.vulnerabilities.append({
                            'type': 'LDAP Injection',
                            'severity': 'HIGH',
                            'description': 'LDAP injection vulnerability detected',
                            'payload': payload,
                            'recommendation': 'Sanitize LDAP queries and use proper escaping'
                        })
                        results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"LDAP injection test error: {e}")
        
        return results
    
    async def test_path_traversal(self) -> List[Dict]:
        """
        Test for path traversal vulnerabilities
        """
        all_payloads = WSPayloads.get_path_traversal()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing path traversal ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"file": payload, "action": "read"})
                response = await self.send_and_receive(ws, message)
                
                if response:
                    file_indicators = ['root:', '/etc/passwd', 'boot.ini', '[extensions]']
                    if any(ind in response.lower() for ind in file_indicators):
                        Logger.vuln(f"Path traversal detected: {payload[:50]}")
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'severity': 'HIGH',
                            'description': 'Path traversal vulnerability detected',
                            'payload': payload,
                            'recommendation': 'Validate and sanitize file paths'
                        })
                        results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"Path traversal test error: {e}")
        
        return results
    
    async def test_ssti(self) -> List[Dict]:
        """
        Test for Server Side Template Injection
        """
        all_payloads = WSPayloads.get_ssti()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing SSTI ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"template": payload, "action": "render"})
                response = await self.send_and_receive(ws, message)
                
                if response and payload in response:
                    Logger.vuln(f"SSTI detected: {payload[:50]}")
                    self.vulnerabilities.append({
                        'type': 'Server Side Template Injection',
                        'severity': 'CRITICAL',
                        'description': 'SSTI payload reflected/executed',
                        'payload': payload,
                        'recommendation': 'Use safe template rendering and input validation'
                    })
                    results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"SSTI test error: {e}")
        
        return results
    
    async def test_xxe(self) -> List[Dict]:
        """
        Test for XML External Entity injection
        """
        all_payloads = WSPayloads.get_xxe()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing XXE ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                response = await self.send_and_receive(ws, payload)
                
                if response:
                    xxe_indicators = ['<!entity', 'system', 'file://', 'root:']
                    if any(ind in response.lower() for ind in xxe_indicators):
                        Logger.vuln(f"XXE detected: {payload[:50]}")
                        self.vulnerabilities.append({
                            'type': 'XML External Entity (XXE)',
                            'severity': 'CRITICAL',
                            'description': 'XXE vulnerability detected',
                            'payload': payload,
                            'recommendation': 'Disable external entity processing in XML parsers'
                        })
                        results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"XXE test error: {e}")
        
        return results
    
    async def test_open_redirect(self) -> List[Dict]:
        """
        Test for open redirect vulnerabilities
        """
        all_payloads = WSPayloads.get_open_redirect()
        payload_count = len(all_payloads) if self.max_payloads is None else min(self.max_payloads, len(all_payloads))
        Logger.info(f"Testing open redirect ({payload_count}/{len(all_payloads)} payloads)...")
        
        results = []
        ws = await self.connect()
        if not ws:
            return results
        
        try:
            payloads = all_payloads[:payload_count]
            
            for payload in payloads:
                message = json.dumps({"redirect": payload, "action": "navigate"})
                response = await self.send_and_receive(ws, message)
                
                if response and ('http://' in response or 'https://' in response):
                    Logger.vuln(f"Open redirect detected: {payload[:50]}")
                    self.vulnerabilities.append({
                        'type': 'Open Redirect',
                        'severity': 'MEDIUM',
                        'description': 'Open redirect vulnerability detected',
                        'payload': payload,
                        'recommendation': 'Validate redirect URLs against whitelist'
                    })
                    results.append({'payload': payload, 'vulnerable': True})
                
                await asyncio.sleep(0.1)
            
            await ws.close()
            
        except Exception as e:
            Logger.error(f"Open redirect test error: {e}")
        
        return results
    async def test_message_replay(self) -> bool:
        """
        Test for message replay vulnerabilities
        """
        Logger.info("Testing message replay attacks...")
        
        ws = await self.connect()
        if not ws:
            return False
        
        try:
            # Send initial message
            original_message = json.dumps({"action": "transfer", "amount": 100})
            response1 = await self.send_and_receive(ws, original_message)
            
            await asyncio.sleep(1)
            
            # Replay the same message
            response2 = await self.send_and_receive(ws, original_message)
            
            # If both succeed, replay is possible
            if response1 and response2 and response1 == response2:
                Logger.warning("Message replay attack possible")
                self.vulnerabilities.append({
                    'type': 'Message Replay Attack',
                    'severity': 'HIGH',
                    'description': 'WebSocket messages can be replayed without nonce/timestamp validation',
                    'recommendation': 'Implement message nonces or timestamps'
                })
                await ws.close()
                return True
            
            await ws.close()
            return False
            
        except Exception as e:
            Logger.error(f"Replay test error: {e}")
            return False
    
    async def test_rate_limiting(self) -> Dict:
        """
        Test for rate limiting on WebSocket
        """
        Logger.info("Testing rate limiting...")
        
        ws = await self.connect()
        if not ws:
            return {'tested': False}
        
        try:
            messages_sent = 0
            start_time = time.time()
            
            # Send 100 messages rapidly
            for i in range(100):
                message = json.dumps({"test": f"message_{i}"})
                try:
                    await ws.send(message)
                    messages_sent += 1
                except (websockets.exceptions.WebSocketException, ConnectionError, OSError):
                    break
            
            elapsed = time.time() - start_time
            rate = messages_sent / elapsed if elapsed > 0 else 0
            
            if messages_sent >= 90:  # If most messages went through
                Logger.warning(f"No rate limiting detected ({messages_sent} msgs in {elapsed:.2f}s)")
                self.vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'severity': 'MEDIUM',
                    'description': f'Sent {messages_sent} messages without rate limiting',
                    'recommendation': 'Implement rate limiting to prevent abuse'
                })
            
            await ws.close()
            return {'tested': True, 'messages_sent': messages_sent, 'rate': rate}
            
        except Exception as e:
            Logger.error(f"Rate limiting test error: {e}")
            return {'tested': False}
    
    async def test_authentication_bypass(self) -> List[Dict]:
        """
        Test for authentication bypass
        """
        Logger.info("Testing authentication bypass...")
        
        results = []
        
        # Test connection without auth
        ws = await self.connect()
        if ws:
            # Try to send authenticated actions
            auth_actions = [
                {"action": "admin", "command": "list_users"},
                {"action": "delete", "resource": "user"},
                {"action": "modify", "target": "settings"},
            ]
            
            for action in auth_actions:
                message = json.dumps(action)
                response = await self.send_and_receive(ws, message)
                
                if response and 'unauthorized' not in response.lower() and 'forbidden' not in response.lower():
                    Logger.warning(f"Possible auth bypass: {action}")
                    self.vulnerabilities.append({
                        'type': 'Authentication Bypass',
                        'severity': 'CRITICAL',
                        'description': 'Sensitive actions accessible without authentication',
                        'payload': str(action),
                        'recommendation': 'Implement proper authentication checks'
                    })
                    results.append({'action': action, 'bypassed': True})
            
            await ws.close()
        
        return results
    
    async def run_all_tests(self) -> Dict:
        """
        Run all security tests
        """
        self.start_time = datetime.now()
        Logger.banner()
        Logger.info(f"Target: {self.url}")
        Logger.info("Starting comprehensive WebSocket security scan...")
        print()
        
        # Test connection first
        if not await self.test_connection():
            Logger.error("Cannot proceed without valid connection")
            return self.generate_report()
        
        print()
        
        # Run all tests concurrently where possible
        await asyncio.gather(
            self.test_origin_bypass(),
            self.test_sql_injection(),
            self.test_xss(),
            self.test_command_injection(),
            self.test_message_replay(),
            self.test_rate_limiting(),
            self.test_authentication_bypass(),
            return_exceptions=True
        )
        
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        print()
        Logger.success(f"Scan complete in {duration:.2f}s")
        Logger.info(f"Messages sent: {self.messages_sent}")
        Logger.info(f"Messages received: {self.messages_received}")
        Logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """
        Generate JSON report
        """
        report = {
            'scan_info': {
                'target': self.url,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration': (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0,
                'scanner': 'WSHawk by Regaan',
                'messages_sent': self.messages_sent,
                'messages_received': self.messages_received
            },
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']),
            }
        }
        
        return report
    
    def generate_html_report(self, filename: str = 'wshawk_report.html') -> str:
        """
        Generate beautiful HTML report
        """
        report = self.generate_report()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WSHawk Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 30px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{ 
            font-size: 42px; 
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header .subtitle {{ 
            font-size: 18px; 
            opacity: 0.9;
        }}
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 30px 0;
        }}
        .stat-box {{ 
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white; 
            padding: 25px; 
            border-radius: 10px; 
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }}
        .stat-box:hover {{ transform: translateY(-5px); }}
        .stat-number {{ font-size: 48px; font-weight: bold; }}
        .stat-label {{ font-size: 16px; opacity: 0.9; margin-top: 10px; }}
        .vuln-card {{ 
            background: #fff; 
            border-left: 5px solid #f44336; 
            padding: 20px; 
            margin: 15px 0; 
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        .vuln-card:hover {{ transform: translateX(5px); }}
        .severity {{ 
            display: inline-block; 
            padding: 8px 20px; 
            border-radius: 25px; 
            color: white; 
            font-weight: bold;
            font-size: 13px;
            text-transform: uppercase;
        }}
        .severity.CRITICAL {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .severity.HIGH {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .severity.MEDIUM {{ background: linear-gradient(135deg, #30cfd0 0%, #330867 100%); }}
        code {{ 
            background: #f5f5f5; 
            padding: 3px 8px; 
            border-radius: 4px; 
            font-family: 'Courier New', monospace;
            color: #e83e8c;
        }}
        .footer {{ 
            text-align: center; 
            color: #666; 
            margin-top: 40px; 
            padding-top: 20px;
            border-top: 2px solid #eee;
        }}
        h2 {{ color: #333; margin: 30px 0 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WSHawk Security Report</h1>
            <div class="subtitle">WebSocket Vulnerability Assessment</div>
        </div>
        
        <p><strong>Target:</strong> <code>{report['scan_info']['target']}</code></p>
        <p><strong>Scan Duration:</strong> {report['scan_info']['duration']:.2f} seconds</p>
        <p><strong>Messages Sent:</strong> {report['scan_info']['messages_sent']}</p>
        <p><strong>Messages Received:</strong> {report['scan_info']['messages_received']}</p>
        <p><strong>Scanner:</strong> {report['scan_info']['scanner']}</p>
        
        <h2>Vulnerability Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{report['summary']['total']}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report['summary']['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report['summary']['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{report['summary']['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>
        
        <h2>Vulnerabilities Detected</h2>
"""
        
        if report['vulnerabilities']:
            for vuln in report['vulnerabilities']:
                severity = vuln.get('severity', 'MEDIUM')
                html += f"""
        <div class="vuln-card">
            <h3>{vuln.get('type', 'Unknown')} <span class="severity {severity}">{severity}</span></h3>
            <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
            <p><strong>Payload:</strong> <code>{str(vuln.get('payload', 'N/A'))[:100]}</code></p>
            <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'N/A')}</p>
        </div>
"""
        else:
            html += '<p style="color: green; font-size: 18px;">No vulnerabilities detected!</p>'
        
        html += f"""
        <div class="footer">
            <p><strong>WSHawk v1.0</strong> | Created by <strong>Regaan (@regaan)</strong></p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html)
        
        Logger.success(f"HTML report saved to: {filename}")
        return filename


async def main():
    """
    Main entry point - handles CLI arguments and starts scanner or web GUI
    """
    import argparse
    import sys
    from .__init__ import __version__

    parser = argparse.ArgumentParser(description=f"WSHawk v{__version__} - Professional WebSocket Security Scanner")
    parser.add_argument("target", nargs="?", help="Target WebSocket URL (ws:// or wss://)")
    parser.add_argument("--version", action="store_true", help="Show version information")
    parser.add_argument("--web", action="store_true", help="Launch the Web Management Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Web dashboard port (default: 5000)")
    parser.add_argument("--host", default="0.0.0.0", help="Web dashboard host (default: 0.0.0.0)")

    args = parser.parse_args()

    # Handle Version
    if args.version:
        Logger.banner()
        print(f"WSHawk Version: {__version__}")
        return

    # Handle Web GUI
    if args.web:
        try:
            from .web.app import run_web
            run_web(host=args.host, port=args.port)
        except ImportError:
            Logger.error("Flask required for Web GUI. Install: pip install flask")
        return

    # Handle URL Scan (Positional or Interactive)
    target_url = args.target
    if not target_url:
        Logger.banner()
        print(f"{Colors.CYAN}Enter WebSocket URL (e.g., ws://example.com or wss://example.com):{Colors.END}")
        target_url = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if not target_url:
        Logger.error("No URL provided")
        return
    
    # Validate URL
    if not target_url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss://")
        return
    
    # Use advanced scanner_v2
    from .scanner_v2 import WSHawkV2
    
    Logger.info(f"Using WSHawk v{__version__} Advanced Scanner")
    scanner = WSHawkV2(target_url, max_rps=10)
    
    # Enable defaults for quick scan
    scanner.use_headless_browser = False
    scanner.use_oast = True
    
    # Run heuristic scan
    await scanner.run_heuristic_scan()


def cli():
    """Entry point for pip-installed command"""
    try:
        # Use a new loop to avoid "RuntimeError: This event loop is already running" 
        # when called from other async contexts
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(main())
        finally:
            loop.close()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")


if __name__ == "__main__":
    cli()
