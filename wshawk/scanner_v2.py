#!/usr/bin/env python3
"""
WSHawk v4.0.0 - Advanced WebSocket Security Scanner
Integrated with all analyzer modules + smart payload generation
"""

import os
import asyncio
import websockets
import json
import time
from typing import List, Dict, Optional
from datetime import datetime

# Import analysis modules
from .message_intelligence import MessageAnalyzer, MessageFormat
from .vulnerability_verifier import VulnerabilityVerifier, ConfidenceLevel
from .server_fingerprint import ServerFingerprinter
from .state_machine import SessionStateMachine, SessionState
from .rate_limiter import TokenBucketRateLimiter
from .enhanced_reporter import EnhancedHTMLReporter
try:
    from .headless_xss_verifier import HeadlessBrowserXSSVerifier
except ImportError:
    HeadlessBrowserXSSVerifier = None
from .oast_provider import OASTProvider, SimpleOASTServer
from .session_hijacking_tester import SessionHijackingTester
from .report_exporter import ReportExporter
from .binary_handler import BinaryMessageHandler
from .ai_engine import AIEngine

# Smart payload modules
from .smart_payloads.context_generator import ContextAwareGenerator
from .smart_payloads.feedback_loop import FeedbackLoop, ResponseSignal
from .smart_payloads.payload_evolver import PayloadEvolver

# Import existing modules
from .__main__ import WSPayloads, Logger, Colors

class WSHawkV2:
    """
    Enhanced WebSocket Security Scanner with Heuristic Analysis
    """
    
    def __init__(self, url: str, headers: Optional[Dict] = None, 
                 auth_sequence: Optional[str] = None,
                 max_rps: int = 10,
                 config: Optional['WSHawkConfig'] = None,
                 event_callback = None):
        self.url = url
        self.headers = headers or {}
        self.vulnerabilities = []
        self.event_callback = event_callback
        
        # Load config if not provided
        if config is None:
            from .config import WSHawkConfig
            self.config = WSHawkConfig.load()
        else:
            self.config = config
            
        rate_limit = self.config.get('scanner.rate_limit', max_rps)
        
        # Initialize analysis modules
        self.message_analyzer = MessageAnalyzer()
        self.verifier = VulnerabilityVerifier()
        self.fingerprinter = ServerFingerprinter()
        self.state_machine = SessionStateMachine()
        self.rate_limiter = TokenBucketRateLimiter(
            tokens_per_second=rate_limit,
            bucket_size=rate_limit * 2,
            enable_adaptive=True
        )
        self.reporter = EnhancedHTMLReporter()
        self.report_exporter = ReportExporter()
        self.binary_handler = BinaryMessageHandler()
        
        # Smart payload modules
        self.context_generator = ContextAwareGenerator()
        self.feedback_loop = FeedbackLoop()
        self.payload_evolver = PayloadEvolver(population_size=100)
        self.use_smart_payloads = False
        
        # AI Engine
        self.ai_engine = AIEngine(
            provider=self.config.get('ai.provider', 'ollama'),
            model=self.config.get('ai.model', 'codellama'),
            base_url=self.config.get('ai.base_url'),
            api_key=self.config.get('ai.api_key')
        )
        self.use_ai = self.config.get('scanner.features.ai_fuzzing', False)
        
        # Advanced verification (optional, can be disabled)
        self.use_headless_browser = True
        self.headless_verifier = None
        
        # OAST for blind vulnerabilities
        self.use_oast = True
        self.oast_provider = None
        
        # Load auth sequence if provided
        self.raw_auth_payload = None
        if auth_sequence:
            if auth_sequence.strip().startswith('{') or '\n' not in auth_sequence:
                self.raw_auth_payload = auth_sequence
            else:
                try:
                    self.state_machine.load_sequence_from_yaml(auth_sequence)
                except Exception as e:
                    Logger.warning(f"YAML parsing failed, falling back to raw payload")
                    self.raw_auth_payload = auth_sequence
        
        # Statistics
        self.messages_sent = 0
        self.messages_received = 0
        self.start_time = None
        self.end_time = None
        
        # Learning phase
        self.learning_complete = False
        self.sample_messages = []
        
        # Traffic logs for reporting
        self.traffic_logs = []
    
    async def connect(self):
        """Establish WebSocket connection"""
        try:
            ws = await websockets.connect(self.url, additional_headers=self.headers)
            self.state_machine._update_state('connected')
            return ws
        except Exception as e:
            Logger.error(f"Connection failed: {e}")
            if self.event_callback:
                asyncio.create_task(self.event_callback('scan_error', {'error': str(e)}))
            return None
    
    async def learning_phase(self, ws, duration: int = 5):
        """
        Learning phase: collect sample messages to understand protocol heuristics
        """
        Logger.info(f"Starting learning phase ({duration}s)...")
        Logger.info("Listening to identify message patterns...")
        
        start = time.monotonic()
        samples = []
        
        try:
            while time.monotonic() - start < duration:
                try:
                    # Set timeout for receiving
                    message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    samples.append(message)
                    self.messages_received += 1
                    
                    # Add to fingerprinter
                    self.fingerprinter.add_response(message)
                    
                    if self.event_callback:
                        asyncio.create_task(self.event_callback('message_sent', {'response': message}))
                        
                    if len(samples) <= 3:
                        Logger.info(f"Sample message {len(samples)}: {message[:100]}...")
                
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    break
        
        except Exception as e:
            Logger.error(f"Learning phase error: {e}")
        
        # Learn from collected samples
        if samples:
            self.message_analyzer.learn_from_messages(samples)
            self.sample_messages = samples
            
            # Get format info
            format_info = self.message_analyzer.get_format_info()
            Logger.success(f"Detected format: {format_info['format']}")
            
            if format_info['injectable_fields']:
                Logger.info(f"Injectable fields: {', '.join(format_info['injectable_fields'][:5])}")
            
            # Feed into smart payload context generator
            if self.use_smart_payloads:
                for msg in samples:
                    if isinstance(msg, str):
                        self.context_generator.learn_from_message(msg)
                        self.feedback_loop.establish_baseline(msg, 0.1)
                if self.context_generator.analysis_complete:
                    Logger.success(f"Smart payloads: learned {self.context_generator.context.get('format', 'unknown')} format")
            
            # Fingerprint server
            fingerprint = self.fingerprinter.fingerprint()
            if fingerprint.language:
                Logger.success(f"Server: {fingerprint.language or 'unknown'} / {fingerprint.framework or 'unknown'}")
            if fingerprint.database:
                Logger.info(f"Database: {fingerprint.database}")
            
            self.learning_complete = True
        else:
            Logger.warning("No messages received during learning phase")
            Logger.info("Will use basic payload injection")
    
    async def test_sql_injection_v2(self, ws) -> List[Dict]:
        """
        Enhanced SQL injection testing with automated verification
        """
        Logger.info("Testing SQL injection with heuristic verification...")
        
        results = []
        payloads = WSPayloads.get_sql_injection()[:100]
        
        # AI Integration
        if self.use_ai:
            context = "\n".join(self.sample_messages[:5])
            ai_payloads = await self.ai_engine.generate_payloads(context, "SQL Injection")
            if ai_payloads:
                Logger.info(f"AI Engine generated {len(ai_payloads)} targeted SQLi payloads")
                payloads = ai_payloads + payloads[:50]
        
        # Get server-specific payloads if fingerprinted
        fingerprint = self.fingerprinter.fingerprint()
        if fingerprint.database:
            recommended = self.fingerprinter.get_recommended_payloads(fingerprint)
            if recommended.get('sql'):
                Logger.info(f"Using {fingerprint.database}-specific payloads")
                payloads = recommended['sql'] + payloads[:50]
        
        # Get base message for injection
        base_message = self.sample_messages[0] if self.sample_messages else '{"test": "value"}'
        
        for payload in payloads:
            try:
                # Automated injection into message structure
                if self.learning_complete and self.message_analyzer.detected_format == MessageFormat.JSON:
                    injected_messages = self.message_analyzer.inject_payload_into_message(
                        base_message, payload
                    )
                else:
                    injected_messages = [payload]
                
                for msg in injected_messages:
                    await ws.send(msg)
                    self.messages_sent += 1
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Automated verification - not just reflection
                        is_vuln, confidence, description = self.verifier.verify_sql_injection(
                            response, payload
                        )
                        
                        # Feed response to smart feedback loop
                        if self.use_smart_payloads:
                            resp_time = time.monotonic() - start_time if 'start_time' in dir() else 0.1
                            signal, sig_conf = self.feedback_loop.analyze_response(
                                payload, response, resp_time, category='sqli'
                            )
                        
                        if is_vuln and confidence != ConfidenceLevel.LOW:
                            Logger.vuln(f"SQL Injection [{confidence.value}]: {description}")
                            Logger.vuln(f"Payload: {payload[:80]}")
                            
                            vuln_data = {
                                'type': 'SQL Injection',
                                'severity': confidence.value,
                                'confidence': confidence.value,
                                'description': description,
                                'payload': payload,
                                'response_snippet': response[:200],
                                'recommendation': 'Use parameterized queries'
                            }
                            
                            if self.event_callback:
                                asyncio.create_task(self.event_callback('vulnerability_found', vuln_data))
                            
                            # Seed successful payload into evolver
                            if self.use_smart_payloads:
                                self.payload_evolver.seed([payload])
                                self.payload_evolver.update_fitness(payload, 1.0)
                            
                            self.vulnerabilities.append(vuln_data)
                            results.append({'payload': payload, 'confidence': confidence.value})
                    
                    except asyncio.TimeoutError:
                        pass
                    
                    if self.event_callback:
                        asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                    
                    await asyncio.sleep(0.05)  # Rate limiting
            
            except Exception as e:
                Logger.error(f"SQL test error: {e}")
                continue
        
        return results
    
    async def test_xss_v2(self, ws) -> List[Dict]:
        """
        Enhanced XSS testing with context analysis
        """
        Logger.info("Testing XSS and reflective injection...")
        
        results = []
        payloads = WSPayloads.get_xss()[:100]
        
        # AI Integration
        if self.use_ai:
            context = "\n".join(self.sample_messages[:5])
            ai_payloads = await self.ai_engine.generate_payloads(context, "Cross-Site Scripting (XSS)")
            if ai_payloads:
                Logger.info(f"AI Engine generated {len(ai_payloads)} targeted XSS payloads")
                payloads = ai_payloads + payloads[:50]
        
        base_message = self.sample_messages[0] if self.sample_messages else '{"input": "test"}'
        
        for payload in payloads:
            try:
                if self.learning_complete and self.message_analyzer.detected_format == MessageFormat.JSON:
                    injected_messages = self.message_analyzer.inject_payload_into_message(
                        base_message, payload
                    )
                else:
                    injected_messages = [payload]
                
                for msg in injected_messages:
                    await ws.send(msg)
                    self.messages_sent += 1
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Automated verification with context analysis
                        is_vuln, confidence, description = self.verifier.verify_xss(
                            response, payload
                        )
                        
                        if is_vuln and confidence != ConfidenceLevel.LOW:
                            # For HIGH confidence, verify with headless browser
                            browser_verified = False
                            if confidence == ConfidenceLevel.HIGH and self.use_headless_browser:
                                try:
                                    if not self.headless_verifier:
                                        self.headless_verifier = HeadlessBrowserXSSVerifier()
                                        await self.headless_verifier.start()
                                    
                                    is_executed, evidence = await self.headless_verifier.verify_xss_execution(
                                        response, payload
                                    )
                                    
                                    if is_executed:
                                        browser_verified = True
                                        confidence = ConfidenceLevel.HIGH
                                        description = f"Sandboxed browser execution observed: {evidence}"
                                except Exception as e:
                                    Logger.error(f"Browser verification failed: {e}")
                            
                            Logger.vuln(f"XSS [{confidence.value}]: {description}")
                            Logger.vuln(f"Payload: {payload[:80]}")
                            if browser_verified:
                                Logger.vuln("  [BROWSER EVIDENCE] Sandboxed browser execution was observed.")
                            
                            vuln_info = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': confidence.value,
                                'confidence': confidence.value,
                                'description': description,
                                'payload': payload,
                                'response_snippet': response[:200],
                                'browser_verified': browser_verified,
                                'recommendation': 'Sanitize and encode all user input'
                            }
                            
                            if self.event_callback:
                                asyncio.create_task(self.event_callback('vulnerability_found', vuln_info))
                            
                            # Seed into evolver
                            if self.use_smart_payloads:
                                self.payload_evolver.seed([payload])
                                self.payload_evolver.update_fitness(payload, 1.0)
                            
                            self.vulnerabilities.append(vuln_info)
                            results.append({'payload': payload, 'confidence': confidence.value})
                    
                    except asyncio.TimeoutError:
                        pass
                    
                    if self.event_callback:
                        asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                    
                    await asyncio.sleep(0.05)
            
            except Exception as e:
                continue
        
        return results
    
    async def test_command_injection_v2(self, ws) -> List[Dict]:
        """
        Enhanced command injection with timing attacks
        """
        Logger.info("Testing command injection with execution detection...")
        
        results = []
        payloads = WSPayloads.get_command_injection()[:100]
        
        # AI Integration
        if self.use_ai:
            context = "\n".join(self.sample_messages[:5])
            ai_payloads = await self.ai_engine.generate_payloads(context, "Command Injection")
            if ai_payloads:
                Logger.info(f"AI Engine generated {len(ai_payloads)} targeted Command Injection payloads")
                payloads = ai_payloads + payloads[:50]
        
        # Get language-specific payloads
        fingerprint = self.fingerprinter.fingerprint()
        if fingerprint.language:
            recommended = self.fingerprinter.get_recommended_payloads(fingerprint)
            if recommended.get('command'):
                Logger.info(f"Using {fingerprint.language}-specific command payloads")
                payloads = recommended['command'] + payloads[:50]
        
        base_message = self.sample_messages[0] if self.sample_messages else '{"cmd": "test"}'
        
        for payload in payloads:
            try:
                if self.learning_complete and self.message_analyzer.detected_format == MessageFormat.JSON:
                    injected_messages = self.message_analyzer.inject_payload_into_message(
                        base_message, payload
                    )
                else:
                    injected_messages = [payload]
                
                for msg in injected_messages:
                    await ws.send(msg)
                    self.messages_sent += 1
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Automated verification
                        is_vuln, confidence, description = self.verifier.verify_command_injection(
                            response, payload
                        )
                        
                        if is_vuln and confidence != ConfidenceLevel.LOW:
                            Logger.vuln(f"Command Injection [{confidence.value}]: {description}")
                            Logger.vuln(f"Payload: {payload[:80]}")
                            
                            vuln_info = {
                                'type': 'Command Injection',
                                'severity': confidence.value,
                                'confidence': confidence.value,
                                'description': description,
                                'payload': payload,
                                'response_snippet': response[:200],
                                'recommendation': 'Never pass user input to system commands'
                            }
                            
                            if self.event_callback:
                                asyncio.create_task(self.event_callback('vulnerability_found', vuln_info))
                            
                            self.vulnerabilities.append(vuln_info)
                            results.append({'payload': payload, 'confidence': confidence.value})
                    
                    except asyncio.TimeoutError:
                        pass
                    
                    if self.event_callback:
                        asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                    
                    await asyncio.sleep(0.05)
            
            except Exception as e:
                continue
        
        return results
    
    async def test_path_traversal_v2(self, ws) -> List[Dict]:
        """Enhanced path traversal testing"""
        Logger.info("Testing path traversal...")
        
        results = []
        payloads = WSPayloads.get_path_traversal()[:50]
        
        for payload in payloads:
            try:
                msg = json.dumps({"action": "read_file", "filename": payload})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    is_vuln, confidence, description = self.verifier.verify_path_traversal(response, payload)
                    
                    if is_vuln and confidence != ConfidenceLevel.LOW:
                        Logger.vuln(f"Path Traversal [{confidence.value}]: {description}")
                        self.vulnerabilities.append({
                            'type': 'Path Traversal',
                            'severity': confidence.value,
                            'confidence': confidence.value,
                            'description': description,
                            'payload': payload,
                            'response_snippet': response[:200],
                            'recommendation': 'Validate and sanitize file paths'
                        })
                        results.append({'payload': payload, 'confidence': confidence.value})
                
                except asyncio.TimeoutError:
                    pass
                
                if self.event_callback:
                    asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                
                await asyncio.sleep(0.05)
            except Exception as e:
                continue
        
        return results
    
    async def test_xxe_v2(self, ws) -> List[Dict]:
        """Enhanced XXE testing with OAST"""
        Logger.info("Testing XXE with OAST...")
        
        results = []
        payloads = WSPayloads.get_xxe()[:30]
        
        # Start OAST if enabled
        if self.use_oast and not self.oast_provider:
            try:
                self.oast_provider = OASTProvider(use_interactsh=False, custom_server="localhost:8888")
                await self.oast_provider.start()
                Logger.info("OAST provider started for blind XXE detection")
            except Exception as e:
                Logger.error(f"OAST start failed: {e}")
                self.use_oast = False
        
        for payload in payloads:
            try:
                # Generate OAST payload if available
                if self.use_oast and self.oast_provider:
                    oast_payload = self.oast_provider.generate_payload('xxe', f'test{len(results)}')
                    msg = json.dumps({"action": "parse_xml", "xml": oast_payload})
                else:
                    msg = json.dumps({"action": "parse_xml", "xml": payload})
                
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    xxe_indicators = ['<!entity', 'system', 'file://', 'root:', 'XML Parse Error']
                    if any(ind.lower() in response.lower() for ind in xxe_indicators):
                        Logger.vuln(f"XXE [HIGH]: Entity processing detected")
                        vuln_info = {
                            'type': 'XML External Entity (XXE)',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'description': 'XXE vulnerability - external entities processed',
                            'payload': payload[:80],
                            'response_snippet': response[:200],
                            'recommendation': 'Disable external entity processing'
                        }
                        if self.event_callback:
                            asyncio.create_task(self.event_callback('vulnerability_found', vuln_info))
                        self.vulnerabilities.append(vuln_info)
                        results.append({'payload': payload, 'confidence': 'HIGH'})
                
                except asyncio.TimeoutError:
                    pass
                
                if self.event_callback:
                    asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                
                await asyncio.sleep(0.05)
            except Exception as e:
                continue
        
        return results
    
    async def test_nosql_injection_v2(self, ws) -> List[Dict]:
        """Enhanced NoSQL injection testing"""
        Logger.info("Testing NoSQL injection...")
        
        results = []
        payloads = WSPayloads.get_nosql_injection()[:50]
        
        for payload in payloads:
            try:
                msg = json.dumps({"action": "find_user", "query": {"username": payload}})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    nosql_indicators = ['mongodb', 'bson', 'query error', '$ne', '$gt', 'Query Error']
                    if any(ind.lower() in response.lower() for ind in nosql_indicators):
                        Logger.vuln(f"NoSQL Injection [HIGH]: Query manipulation detected")
                        vuln_info = {
                            'type': 'NoSQL Injection',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'description': 'NoSQL injection vulnerability detected',
                            'payload': payload,
                            'response_snippet': response[:200],
                            'recommendation': 'Use parameterized queries'
                        }
                        if self.event_callback:
                            asyncio.create_task(self.event_callback('vulnerability_found', vuln_info))
                        self.vulnerabilities.append(vuln_info)
                        results.append({'payload': payload, 'confidence': 'HIGH'})
                
                except asyncio.TimeoutError:
                    pass
                
                if self.event_callback:
                    asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                
                await asyncio.sleep(0.05)
            except Exception as e:
                continue
        
        return results
    
    async def test_ssrf_v2(self, ws) -> List[Dict]:
        """Enhanced SSRF testing"""
        Logger.info("Testing SSRF...")
        
        results = []
        internal_targets = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal',
        ]
        
        for target in internal_targets:
            try:
                await self.rate_limiter.acquire()
                
                msg = json.dumps({"action": "fetch_url", "url": target})
                await ws.send(msg)
                self.messages_sent += 1
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    self.messages_received += 1
                    
                    ssrf_indicators = ['connection refused', 'timeout', 'metadata', 'instance-id', 'localhost']
                    if any(ind.lower() in response.lower() for ind in ssrf_indicators):
                        Logger.vuln(f"SSRF [HIGH]: Internal endpoint accessible - {target}")
                        vuln_info = {
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'description': f'SSRF vulnerability - accessed {target}',
                            'payload': target,
                            'response_snippet': response[:200],
                            'recommendation': 'Validate and whitelist allowed URLs'
                        }
                        if self.event_callback:
                            asyncio.create_task(self.event_callback('vulnerability_found', vuln_info))
                        self.vulnerabilities.append(vuln_info)
                        results.append({'payload': target, 'confidence': 'HIGH'})
                
                except asyncio.TimeoutError:
                    pass
                
                if self.event_callback:
                    asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                    
                await asyncio.sleep(0.1)
            except Exception as e:
                continue
        
        return results
    
    async def run_heuristic_scan(self):
        """
        Run full heuristic scan with all modules
        """
        self.start_time = datetime.now()
        Logger.banner()
        Logger.info(f"Target: {self.url}")
        Logger.info("Starting automated scan with rate limiting...")
        print()
        
        # Connect
        ws = await self.connect()
        if not ws:
            return []
        
        Logger.success("Connected!")
        
        # If we have a single auth payload (Skeleton Key), fire it first string
        if self.raw_auth_payload:
            Logger.info(f"Firing Skeleton Key (Auth Payload)")
            try:
                await ws.send(self.raw_auth_payload)
                resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
                Logger.success(f"Auth Response received: {resp[:50]}")
            except Exception as e:
                Logger.error(f"Failed to execute Skeleton Key: {e}")
                
        print()
        
        # Learning phase
        await self.learning_phase(ws, duration=5)
        print()
        
        # Run ALL tests with heuristics and rate limiting
        await self.test_sql_injection_v2(ws)
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_progress', {'progress': 15, 'phase': 'SQL Injection'}))
        print()
        
        await self.test_xss_v2(ws)
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_progress', {'progress': 30, 'phase': 'XSS'}))
        print()
        
        await self.test_command_injection_v2(ws)
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_progress', {'progress': 45, 'phase': 'Command Injection'}))
        print()
        
        await self.test_path_traversal_v2(ws)
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_progress', {'progress': 60, 'phase': 'Path Traversal'}))
        print()
        
        await self.test_xxe_v2(ws)
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_progress', {'progress': 75, 'phase': 'XXE'}))
        print()
        
        await self.test_nosql_injection_v2(ws)
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_progress', {'progress': 90, 'phase': 'NoSQL'}))
        print()
        
        await self.test_ssrf_v2(ws)
        print()
        
        # ─── Smart Payload Evolution Phase ──────────────────────
        if self.use_smart_payloads and len(self.payload_evolver.population) > 0:
            Logger.info("Running evolved payload phase...")
            evolved = self.payload_evolver.evolve(count=30)
            
            # Also generate context-aware payloads
            priorities = self.feedback_loop.get_priority_categories()
            for category, _ in priorities[:3]:
                ctx_payloads = self.context_generator.generate_payloads(category, count=10)
                evolved.extend(ctx_payloads)
            
            if evolved:
                Logger.info(f"Testing {len(evolved)} evolved/context payloads...")
                base_message = self.sample_messages[0] if self.sample_messages else '{"test": "value"}'
                
                for payload in evolved:
                    try:
                        if self.learning_complete and self.message_analyzer.detected_format == MessageFormat.JSON:
                            injected = self.message_analyzer.inject_payload_into_message(base_message, payload)
                        else:
                            injected = [payload]
                        
                        for msg in injected:
                            await ws.send(msg)
                            self.messages_sent += 1
                            
                            try:
                                t0 = time.monotonic()
                                response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                                elapsed = time.monotonic() - t0
                                self.messages_received += 1
                                
                                # Feed to feedback loop
                                signal, conf = self.feedback_loop.analyze_response(
                                    payload, response, elapsed
                                )
                                
                                # Check all vulnerability types
                                for check_fn, vuln_type in [
                                    (self.verifier.verify_sql_injection, 'SQL Injection'),
                                    (self.verifier.verify_xss, 'Cross-Site Scripting (XSS)'),
                                    (self.verifier.verify_command_injection, 'Command Injection'),
                                ]:
                                    is_vuln, confidence, desc = check_fn(response, payload)
                                    if is_vuln and confidence != ConfidenceLevel.LOW:
                                        Logger.vuln(f"[EVOLVED] {vuln_type} [{confidence.value}]: {desc}")
                                        self.payload_evolver.update_fitness(payload, 1.0)
                                        self.vulnerabilities.append({
                                            'type': f'{vuln_type} (Evolved)',
                                            'severity': confidence.value,
                                            'confidence': confidence.value,
                                            'description': f'[Smart Payload] {desc}',
                                            'payload': payload,
                                            'response_snippet': response[:200],
                                            'recommendation': f'Novel payload discovered by evolutionary mutation'
                                        })
                                        break
                                
                            except asyncio.TimeoutError:
                                pass
                            
                            if self.event_callback:
                                asyncio.create_task(self.event_callback('message_sent', {'msg': msg, 'response': response if 'response' in locals() else None}))
                                
                            await asyncio.sleep(0.05)
                    except Exception:
                        continue
                
                Logger.success(f"Evolution phase complete (gen {self.payload_evolver.generation})")
            print()
        
        # Close connection
        await ws.close()
        
        # Run session hijacking tests
        Logger.info("\n" + "="*50)
        Logger.info("Running Session Hijacking Tests...")
        Logger.info("="*50)
        try:
            session_tester = SessionHijackingTester(self.url)
            session_results = await session_tester.run_all_tests()
            
            # Add session vulnerabilities to main results
            for result in session_results:
                if result.is_vulnerable:
                    self.vulnerabilities.append({
                        'type': f'Session Security: {result.vuln_type.value}',
                        'severity': result.confidence,
                        'confidence': result.confidence,
                        'description': result.description,
                        'payload': 'N/A',
                        'response_snippet': str(result.evidence)[:200],
                        'recommendation': result.recommendation,
                        'cvss_score': result.cvss_score
                    })
            
            Logger.success(f"Session tests complete: {len(session_results)} tests run")
        except Exception as e:
            Logger.error(f"Session hijacking tests failed: {e}")
        
        # Cleanup verification resources
        if self.headless_verifier:
            try:
                await self.headless_verifier.stop()
                Logger.info("Headless browser stopped")
            except Exception as e:
                Logger.error(f"Browser cleanup error: {e}")
        
        if self.oast_provider:
            try:
                await self.oast_provider.stop()
                Logger.info("OAST provider stopped")
            except Exception as e:
                Logger.error(f"OAST cleanup error: {e}")
        
        # Summary
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        Logger.success(f"Scan complete in {duration:.2f}s")
        Logger.info(f"Messages sent: {self.messages_sent}")
        Logger.info(f"Messages received: {self.messages_received}")
        Logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        # Show confidence breakdown
        if self.vulnerabilities:
            print()
            Logger.info("Confidence breakdown:")
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = sum(1 for v in self.vulnerabilities if v['confidence'] == level)
                if count > 0:
                    print(f"  {level}: {count}")
        
        # Prepare paths
        output_dir = self.config.get('reporting.output_dir', '.')
        if output_dir != '.':
            os.makedirs(output_dir, exist_ok=True)
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = os.path.join(output_dir, f"wshawk_report_{timestamp}.html")
        
        # Prepare scan info for exporters
        scan_info = {
            'target': self.url,
            'duration': duration,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received
        }
        fingerprint_info = self.fingerprinter.get_info()
        
        # Generate enhanced HTML report
        report_html = self.reporter.generate_report(
            self.vulnerabilities,
            scan_info,
            fingerprint_info
        )
        
        with open(report_filename, 'w') as f:
            f.write(report_html)
        Logger.success(f"Enhanced HTML report saved: {report_filename}")
        
        # Export other formats if configured
        formats = [fmt for fmt in self.config.get('reporting.formats', ['json']) if fmt in self.report_exporter.SUPPORTED_FORMATS]
        for fmt in formats:
            try:
                out_file = self.report_exporter.export(
                    self.vulnerabilities, scan_info, fmt,
                    fingerprint_info=fingerprint_info
                )
                Logger.success(f"{fmt.upper()} report saved: {out_file}")
            except Exception as e:
                Logger.error(f"Failed to export {fmt}: {e}")
        
        # ─── Automated Integrations ─────────────────────────────────
        
        # 1. DefectDojo
        if self.config.get('integrations.defectdojo.enabled'):
            try:
                from .integrations.defectdojo import DefectDojoIntegration
                dojo = DefectDojoIntegration(
                    url=self.config.get('integrations.defectdojo.url'),
                    api_key=self.config.get('integrations.defectdojo.api_key'),
                    product_id=self.config.get('integrations.defectdojo.product_id')
                )
                await dojo.push_findings(self.vulnerabilities, scan_info)
            except Exception as e:
                Logger.error(f"DefectDojo integration failed: {e}")
                
        # 2. Jira
        if self.config.get('integrations.jira.enabled'):
            try:
                from .integrations.jira_connector import JiraIntegration
                jira = JiraIntegration(
                    url=self.config.get('integrations.jira.url'),
                    email=self.config.get('integrations.jira.email'),
                    api_token=self.config.get('integrations.jira.api_token'),
                    project_key=self.config.get('integrations.jira.project')
                )
                await jira.create_tickets(self.vulnerabilities, scan_info)
            except Exception as e:
                Logger.error(f"Jira integration failed: {e}")
                
        # 3. Webhooks
        if self.config.get('integrations.webhook.enabled'):
            try:
                from .integrations.webhook import WebhookNotifier
                webhook = WebhookNotifier(
                    webhook_url=self.config.get('integrations.webhook.url'),
                    platform=self.config.get('integrations.webhook.platform')
                )
                await webhook.notify(self.vulnerabilities, scan_info)
            except Exception as e:
                Logger.error(f"Webhook notification failed: {e}")

        # Show rate limiter stats
        rate_stats = self.rate_limiter.get_stats()
        Logger.info(f"Rate limiter: {rate_stats['total_requests']} requests, {rate_stats['total_waits']} waits")
        
        return self.vulnerabilities
