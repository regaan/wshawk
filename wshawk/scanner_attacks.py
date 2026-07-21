"""Attack-specific checks mixed into the modern WebSocket scanner."""

import asyncio
import json
import time
from typing import Dict, List

try:
    from .headless_xss_verifier import HeadlessBrowserXSSVerifier
except ImportError:
    HeadlessBrowserXSSVerifier = None

from .console import Logger
from .message_intelligence import MessageFormat
from .oast_provider import OASTProvider
from .payload_catalog import WSPayloads
from .scanner_errors import SCANNER_OPERATION_ERRORS
from .vulnerability_verifier import ConfidenceLevel


class ScannerAttackMixin:
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
                    request_started_at = time.monotonic()
                    await self._send_message(ws, msg)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Automated verification - not just reflection
                        is_vuln, confidence, description = self.verifier.verify_sql_injection(
                            response, payload, tuple(self.recent_requests)
                        )
                        
                        # Feed response to smart feedback loop
                        if self.use_smart_payloads:
                            resp_time = time.monotonic() - request_started_at
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
            
            except SCANNER_OPERATION_ERRORS as e:
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
                    await self._send_message(ws, msg)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Automated verification with context analysis
                        is_vuln, confidence, description = self.verifier.verify_xss(
                            response, payload, tuple(self.recent_requests)
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
                                except SCANNER_OPERATION_ERRORS as e:
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
            
            except SCANNER_OPERATION_ERRORS as e:
                Logger.warning(f"XSS payload failed: {e}")
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
                    await self._send_message(ws, msg)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        self.messages_received += 1
                        
                        # Automated verification
                        is_vuln, confidence, description = self.verifier.verify_command_injection(
                            response, payload, tuple(self.recent_requests)
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
            
            except SCANNER_OPERATION_ERRORS as e:
                Logger.warning(f"Command-injection payload failed: {e}")
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
                await self._send_message(ws, msg)
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    is_vuln, confidence, description = self.verifier.verify_path_traversal(
                        response,
                        payload,
                        tuple(self.recent_requests),
                    )
                    
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
            except SCANNER_OPERATION_ERRORS as e:
                Logger.warning(f"Path-traversal payload failed: {e}")
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
            except SCANNER_OPERATION_ERRORS as e:
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
                
                await self._send_message(ws, msg)
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    xxe_indicators = ['<!entity', 'system', 'file://', 'root:', 'XML Parse Error']
                    if (
                        not self.verifier.is_unmodified_reflection(response, tuple(self.recent_requests))
                        and any(ind.lower() in response.lower() for ind in xxe_indicators)
                    ):
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
            except SCANNER_OPERATION_ERRORS as e:
                Logger.warning(f"XXE payload failed: {e}")
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
                await self._send_message(ws, msg)
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                    self.messages_received += 1
                    
                    nosql_indicators = ['mongodb', 'bson', 'query error', '$ne', '$gt', 'Query Error']
                    if (
                        not self.verifier.is_unmodified_reflection(response, tuple(self.recent_requests))
                        and any(ind.lower() in response.lower() for ind in nosql_indicators)
                    ):
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
            except SCANNER_OPERATION_ERRORS as e:
                Logger.warning(f"NoSQL payload failed: {e}")
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
                msg = json.dumps({"action": "fetch_url", "url": target})
                await self._send_message(ws, msg)
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    self.messages_received += 1
                    
                    ssrf_indicators = ['connection refused', 'timeout', 'metadata', 'instance-id', 'localhost']
                    if (
                        not self.verifier.is_unmodified_reflection(response, tuple(self.recent_requests))
                        and any(ind.lower() in response.lower() for ind in ssrf_indicators)
                    ):
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
            except SCANNER_OPERATION_ERRORS as e:
                Logger.warning(f"SSRF payload failed: {e}")
                continue
        
        return results
    


__all__ = ["ScannerAttackMixin"]
