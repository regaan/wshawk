#!/usr/bin/env python3
"""
WSHawk Advanced WebSocket Security Scanner
Integrated with all analyzer modules + smart payload generation
"""

import os
import asyncio
import websockets
import json
import time
from collections import deque
from typing import TYPE_CHECKING, List, Dict, Optional
from datetime import datetime

# Import analysis modules
from .message_intelligence import MessageAnalyzer, MessageFormat
from .vulnerability_verifier import VulnerabilityVerifier, ConfidenceLevel
from .server_fingerprint import ServerFingerprinter
from .state_machine import SessionStateMachine, SessionState
from .rate_limiter import TokenBucketRateLimiter
from .enhanced_reporter import EnhancedHTMLReporter
from .session_hijacking_tester import SessionHijackingTester
from .report_exporter import ReportExporter
from .binary_handler import BinaryMessageHandler
from .ai_engine import AIEngine

# Smart payload modules
from .smart_payloads.context_generator import ContextAwareGenerator
from .smart_payloads.feedback_loop import FeedbackLoop, ResponseSignal
from .smart_payloads.payload_evolver import PayloadEvolver
from .tls import build_websocket_ssl_context
from .scanner_attacks import ScannerAttackMixin
from .scanner_errors import SCANNER_OPERATION_ERRORS

# Shared services avoid importing the legacy CLI runtime.
from .console import Colors, Logger

if TYPE_CHECKING:
    from .config import WSHawkConfig

class WSHawkV2(ScannerAttackMixin):
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
                except SCANNER_OPERATION_ERRORS as e:
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
        self.recent_requests = deque(maxlen=1024)
        self.scan_completed = False
        self.last_error = None
        self.verify_ssl = self.config.get('scanner.verify_ssl', True) is not False
    
    async def connect(self):
        """Establish WebSocket connection"""
        last_error = None
        ssl_context = build_websocket_ssl_context(self.url, verify_ssl=self.verify_ssl)
        if ssl_context is not None and not self.verify_ssl:
            Logger.warning("TLS certificate verification is disabled for this connection")
        for attempt in range(1, 4):
            try:
                ws = await websockets.connect(
                    self.url,
                    additional_headers=self.headers,
                    ssl=ssl_context,
                )
                self.state_machine._update_state('connected')
                return ws
            except SCANNER_OPERATION_ERRORS as exc:
                last_error = exc
                if attempt < 3:
                    Logger.warning(f"Connection attempt {attempt}/3 failed: {exc}; retrying...")
                    await asyncio.sleep(0.25 * attempt)

        self.last_error = str(last_error)
        Logger.error(f"Connection failed after 3 attempts: {last_error}")
        if self.event_callback:
            asyncio.create_task(self.event_callback('scan_error', {'error': str(last_error)}))
        return None

    async def _send_message(self, websocket, message) -> None:
        """Send one scanner message through the shared rate limiter."""
        await self.rate_limiter.acquire()
        try:
            await websocket.send(message)
            self.recent_requests.append(message)
            self.messages_sent += 1
        finally:
            await self.rate_limiter.done()
    
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
                except SCANNER_OPERATION_ERRORS as e:
                    break
        
        except SCANNER_OPERATION_ERRORS as e:
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
    
    async def run_heuristic_scan(self):
        """
        Run full heuristic scan with all modules
        """
        self.start_time = datetime.now()
        self.vulnerabilities.clear()
        self.traffic_logs.clear()
        self.recent_requests.clear()
        self.messages_sent = 0
        self.messages_received = 0
        self.scan_completed = False
        self.last_error = None
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
                await self._send_message(ws, self.raw_auth_payload)
                resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
                Logger.success(f"Auth Response received: {resp[:50]}")
            except SCANNER_OPERATION_ERRORS as e:
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
                            await self._send_message(ws, msg)
                            
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
                                    is_vuln, confidence, desc = check_fn(
                                        response,
                                        payload,
                                        tuple(self.recent_requests),
                                    )
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
                    except SCANNER_OPERATION_ERRORS as exc:
                        Logger.warning(f"Smart-payload mutation failed: {exc}")
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
        except SCANNER_OPERATION_ERRORS as e:
            Logger.error(f"Session hijacking tests failed: {e}")
        
        # Cleanup verification resources
        if self.headless_verifier:
            try:
                await self.headless_verifier.stop()
                Logger.info("Headless browser stopped")
            except SCANNER_OPERATION_ERRORS as e:
                Logger.error(f"Browser cleanup error: {e}")
        
        if self.oast_provider:
            try:
                await self.oast_provider.stop()
                Logger.info("OAST provider stopped")
            except SCANNER_OPERATION_ERRORS as e:
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
            except SCANNER_OPERATION_ERRORS as e:
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
            except SCANNER_OPERATION_ERRORS as e:
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
            except SCANNER_OPERATION_ERRORS as e:
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
            except SCANNER_OPERATION_ERRORS as e:
                Logger.error(f"Webhook notification failed: {e}")

        # Show rate limiter stats
        rate_stats = self.rate_limiter.get_stats()
        Logger.info(f"Rate limiter: {rate_stats['total_requests']} requests, {rate_stats['total_waits']} waits")
        
        self.scan_completed = True
        return self.vulnerabilities
