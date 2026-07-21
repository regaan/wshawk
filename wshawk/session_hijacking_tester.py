#!/usr/bin/env python3
"""
WSHawk Session Hijacking & Replay Testing Module
Professional-grade session security testing

Tests:
- Token reuse attacks
- Subscription spoofing
- Impersonation attempts
- Channel boundary violations
- Session fixation
- Privilege escalation via session manipulation
"""

import asyncio
import json
import websockets
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import hashlib
import re
from collections import deque


class SessionVulnType(Enum):
    """Session vulnerability types"""
    TOKEN_REUSE = "token_reuse"
    SUBSCRIPTION_SPOOFING = "subscription_spoofing"
    IMPERSONATION = "impersonation"
    CHANNEL_VIOLATION = "channel_boundary_violation"
    SESSION_FIXATION = "session_fixation"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class SessionTestResult:
    """Result of a session security test"""
    vuln_type: SessionVulnType
    is_vulnerable: bool
    confidence: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: Dict
    recommendation: str
    cvss_score: float = 0.0


class SessionHijackingTester:
    """
    Professional session hijacking and replay testing
    
    Features:
    - Token extraction and reuse testing
    - Subscription spoofing detection
    - Impersonation attack testing
    - Channel boundary violation checks
    - Session fixation testing
    - Privilege escalation detection
    """
    
    def __init__(self, target_url: str, auth_config: Optional[Dict] = None):
        """
        Initialize session tester
        
        Args:
            target_url: WebSocket URL to test
            auth_config: Optional authentication configuration
                {
                    'action': 'login',  # or custom action
                    'username_field': 'username',  # field name for username
                    'password_field': 'password',  # field name for password
                    'username': 'user1',  # default username
                    'password': 'pass1',  # default password
                    'custom_payload': {...}  # or provide full custom auth payload
                }
        """
        self.target_url = target_url
        self.results: List[SessionTestResult] = []
        self.captured_tokens: Dict[str, str] = {}
        self.captured_sessions: List[Dict] = []
        self.user_sessions: Dict[str, Dict] = {}  # user_id -> session_data
        self.recent_requests = deque(maxlen=128)
        
        # Default auth config
        self.auth_config = auth_config or {
            'action': 'login',
            'username_field': 'username',
            'password_field': 'password',
            'username': 'user1',
            'password': 'pass1'
        }
    
    def _get_auth_payload(self, username: str = None, password: str = None) -> str:
        """Generate authentication payload based on config"""
        if 'custom_payload' in self.auth_config:
            return json.dumps(self.auth_config['custom_payload'])
        
        username = username or self.auth_config.get('username', 'user1')
        password = password or self.auth_config.get('password', 'pass1')
        
        payload = {
            self.auth_config.get('action', 'login'): True,
            self.auth_config.get('username_field', 'username'): username,
            self.auth_config.get('password_field', 'password'): password
        }
        
        # Handle action as separate field
        if 'action' in self.auth_config:
            payload = {
                'action': self.auth_config['action'],
                self.auth_config.get('username_field', 'username'): username,
                self.auth_config.get('password_field', 'password'): password
            }
        
        return json.dumps(payload)

    async def _send_message(self, websocket, message: str) -> None:
        await websocket.send(message)
        self.recent_requests.append(message)
    
    async def run_all_tests(self) -> List[SessionTestResult]:
        """Run all session security tests"""
        print("=" * 70)
        print("WSHawk Session Hijacking & Replay Testing")
        print("=" * 70)
        
        # Test 1: Token reuse
        print("\n1. Testing token reuse...")
        await self._test_token_reuse()
        
        # Test 2: Subscription spoofing
        print("\n2. Testing subscription spoofing...")
        await self._test_subscription_spoofing()
        
        # Test 3: Impersonation
        print("\n3. Testing impersonation...")
        await self._test_impersonation()
        
        # Test 4: Channel boundary violations
        print("\n4. Testing channel boundary violations...")
        await self._test_channel_violations()
        
        # Test 5: Session fixation
        print("\n5. Testing session fixation...")
        await self._test_session_fixation()
        
        # Test 6: Privilege escalation
        print("\n6. Testing privilege escalation...")
        await self._test_privilege_escalation()
        
        return self.results
    
    async def _test_token_reuse(self):
        """Test if tokens can be reused across sessions"""
        try:
            # Session 1: Capture token
            async with websockets.connect(self.target_url) as ws1:
                # Send auth request
                auth_msg = self._get_auth_payload()
                await self._send_message(ws1, auth_msg)
                
                response = await asyncio.wait_for(ws1.recv(), timeout=3.0)
                
                # Extract token
                token = self._extract_token(response)
                
                if token:
                    self.captured_tokens['user1'] = token
                    
                    # Close first session
                    await ws1.close()
                    
                    # Wait a bit
                    await asyncio.sleep(1)
                    
                    # Session 2: Try to reuse token
                    async with websockets.connect(self.target_url) as ws2:
                        # Try to use captured token
                        reuse_msg = json.dumps({"action": "authenticate", "token": token})
                        await self._send_message(ws2, reuse_msg)
                        
                        response2 = await asyncio.wait_for(ws2.recv(), timeout=3.0)
                        
                        # Check if token was accepted
                        if (
                            not self._is_exact_echo(response2, tuple(self.recent_requests))
                            and self._is_auth_success(response2)
                        ):
                            self.results.append(SessionTestResult(
                                vuln_type=SessionVulnType.TOKEN_REUSE,
                                is_vulnerable=True,
                                confidence="HIGH",
                                description="Session token can be reused after session termination",
                                evidence={
                                    'token': token[:20] + "...",
                                    'reuse_response': response2[:200]
                                },
                                recommendation="Invalidate tokens on session close. Implement token expiration.",
                                cvss_score=7.5
                            ))
                            print("  [VULN] Token reuse possible!")
                        else:
                            print("  [OK] Token reuse prevented")
        
        except Exception as e:
            print(f"  [ERROR] Token reuse test failed: {e}")
    
    async def _test_subscription_spoofing(self):
        """Test if users can subscribe to unauthorized channels"""
        try:
            async with websockets.connect(self.target_url) as ws:
                # Try to subscribe to admin channel without auth
                spoofed_channels = [
                    "admin",
                    "private_user_123",
                    "system",
                    "internal",
                    "../admin",
                    "user/admin"
                ]
                
                vulnerabilities = []
                
                for channel in spoofed_channels:
                    subscribe_msg = json.dumps({
                        "action": "subscribe",
                        "channel": channel
                    })
                    
                    await self._send_message(ws, subscribe_msg)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        
                        # Check if subscription was accepted
                        if (
                            not self._is_exact_echo(response, tuple(self.recent_requests))
                            and self._is_subscription_success(response)
                        ):
                            vulnerabilities.append({
                                'channel': channel,
                                'response': response[:200]
                            })
                    except asyncio.TimeoutError:
                        pass
                
                if vulnerabilities:
                    self.results.append(SessionTestResult(
                        vuln_type=SessionVulnType.SUBSCRIPTION_SPOOFING,
                        is_vulnerable=True,
                        confidence="HIGH",
                        description=f"Can subscribe to {len(vulnerabilities)} unauthorized channels",
                        evidence={'spoofed_channels': vulnerabilities},
                        recommendation="Implement proper channel access control. Validate user permissions before subscription.",
                        cvss_score=8.1
                    ))
                    print(f"  [VULN] Subscription spoofing: {len(vulnerabilities)} channels accessible")
                else:
                    print("  [OK] Subscription spoofing prevented")
        
        except Exception as e:
            print(f"  [ERROR] Subscription spoofing test failed: {e}")
    
    async def _test_impersonation(self):
        """Test if users can impersonate other users"""
        try:
            # Create two sessions
            async with websockets.connect(self.target_url) as ws1:
                # User 1 authenticates
                auth1 = self._get_auth_payload()
                await self._send_message(ws1, auth1)
                response1 = await asyncio.wait_for(ws1.recv(), timeout=3.0)
                
                user1_id = self._extract_user_id(response1)
                
                # Try impersonation attacks
                impersonation_attempts = [
                    {"action": "send_message", "from_user": "admin", "message": "test"},
                    {"action": "send_message", "user_id": "admin", "message": "test"},
                    {"action": "update_profile", "user_id": "user2", "data": "hacked"},
                    {"action": "get_messages", "user_id": "user2"},
                ]
                
                successful_impersonations = []
                
                for attempt in impersonation_attempts:
                    serialized_attempt = json.dumps(attempt)
                    await self._send_message(ws1, serialized_attempt)
                    
                    try:
                        response = await asyncio.wait_for(ws1.recv(), timeout=2.0)
                        
                        # Check if impersonation succeeded
                        if (
                            not self._is_exact_echo(response, tuple(self.recent_requests))
                            and not self._is_error_response(response)
                        ):
                            successful_impersonations.append({
                                'attempt': attempt,
                                'response': response[:200]
                            })
                    except asyncio.TimeoutError:
                        pass
                
                if successful_impersonations:
                    self.results.append(SessionTestResult(
                        vuln_type=SessionVulnType.IMPERSONATION,
                        is_vulnerable=True,
                        confidence="CRITICAL",
                        description=f"User impersonation possible via {len(successful_impersonations)} methods",
                        evidence={'successful_attempts': successful_impersonations},
                        recommendation="Validate user identity server-side. Never trust client-provided user IDs.",
                        cvss_score=9.1
                    ))
                    print(f"  [VULN] Impersonation possible: {len(successful_impersonations)} methods")
                else:
                    print("  [OK] Impersonation prevented")
        
        except Exception as e:
            print(f"  [ERROR] Impersonation test failed: {e}")
    
    async def _test_channel_violations(self):
        """Test channel boundary violations"""
        try:
            async with websockets.connect(self.target_url) as ws:
                # Auth as regular user
                auth = self._get_auth_payload()
                await self._send_message(ws, auth)
                await asyncio.wait_for(ws.recv(), timeout=3.0)
                
                # Try to access other users' private channels
                violation_attempts = [
                    {"action": "read", "channel": "user:user2:private"},
                    {"action": "read", "channel": "user:admin:messages"},
                    {"action": "subscribe", "channel": "private:user2"},
                    {"action": "get_history", "channel": "dm:user2_user3"},
                ]
                
                violations = []
                
                for attempt in violation_attempts:
                    serialized_attempt = json.dumps(attempt)
                    await self._send_message(ws, serialized_attempt)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        
                        # Check if we got data we shouldn't have
                        if (
                            not self._is_exact_echo(response, tuple(self.recent_requests))
                            and self._contains_private_data(response)
                        ):
                            violations.append({
                                'attempt': attempt,
                                'response': response[:200]
                            })
                    except asyncio.TimeoutError:
                        pass
                
                if violations:
                    self.results.append(SessionTestResult(
                        vuln_type=SessionVulnType.CHANNEL_VIOLATION,
                        is_vulnerable=True,
                        confidence="HIGH",
                        description=f"Channel boundary violations: {len(violations)} successful",
                        evidence={'violations': violations},
                        recommendation="Implement strict channel access control. Validate user permissions for all channel operations.",
                        cvss_score=8.6
                    ))
                    print(f"  [VULN] Channel violations: {len(violations)} successful")
                else:
                    print("  [OK] Channel boundaries enforced")
        
        except Exception as e:
            print(f"  [ERROR] Channel violation test failed: {e}")
    
    async def _test_session_fixation(self):
        """Test session fixation vulnerabilities"""
        try:
            # Generate a session ID
            fixed_session = hashlib.md5(b"attacker_session").hexdigest()
            
            async with websockets.connect(self.target_url) as ws:
                # Try to set a specific session ID
                fixation_attempts = [
                    {"action": "login", "username": "user1", "password": "pass1", "session_id": fixed_session},
                    {"action": "authenticate", "session": fixed_session},
                    {"action": "set_session", "id": fixed_session},
                ]
                
                for attempt in fixation_attempts:
                    serialized_attempt = json.dumps(attempt)
                    await self._send_message(ws, serialized_attempt)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        
                        # Check if our session ID was accepted
                        if (
                            not self._is_exact_echo(response, tuple(self.recent_requests))
                            and fixed_session in response
                        ):
                            self.results.append(SessionTestResult(
                                vuln_type=SessionVulnType.SESSION_FIXATION,
                                is_vulnerable=True,
                                confidence="HIGH",
                                description="Session fixation possible - attacker can set session ID",
                                evidence={
                                    'fixed_session': fixed_session,
                                    'response': response[:200]
                                },
                                recommendation="Generate session IDs server-side. Never accept client-provided session IDs.",
                                cvss_score=7.8
                            ))
                            print("  [VULN] Session fixation possible!")
                            return
                    except asyncio.TimeoutError:
                        pass
                
                print("  [OK] Session fixation prevented")
        
        except Exception as e:
            print(f"  [ERROR] Session fixation test failed: {e}")
    
    async def _test_privilege_escalation(self):
        """Test privilege escalation via session manipulation"""
        try:
            async with websockets.connect(self.target_url) as ws:
                # Auth as regular user
                auth = self._get_auth_payload()
                await self._send_message(ws, auth)
                response = await asyncio.wait_for(ws.recv(), timeout=3.0)
                
                # Extract session data
                session_data = self._extract_session_data(response)
                
                # Try privilege escalation
                escalation_attempts = [
                    {"action": "update_role", "role": "admin"},
                    {"action": "set_permissions", "permissions": ["admin", "write", "delete"]},
                    {"action": "elevate", "to": "admin"},
                    {"action": "login", "username": "user1", "password": "pass1", "role": "admin"},
                ]
                
                successful_escalations = []
                
                for attempt in escalation_attempts:
                    serialized_attempt = json.dumps(attempt)
                    await self._send_message(ws, serialized_attempt)
                    
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                        
                        # Check if we gained elevated privileges
                        if (
                            not self._is_exact_echo(response, tuple(self.recent_requests))
                            and self._has_elevated_privileges(response)
                        ):
                            successful_escalations.append({
                                'attempt': attempt,
                                'response': response[:200]
                            })
                    except asyncio.TimeoutError:
                        pass
                
                if successful_escalations:
                    self.results.append(SessionTestResult(
                        vuln_type=SessionVulnType.PRIVILEGE_ESCALATION,
                        is_vulnerable=True,
                        confidence="CRITICAL",
                        description=f"Privilege escalation via session manipulation: {len(successful_escalations)} methods",
                        evidence={'escalations': successful_escalations},
                        recommendation="Enforce server-side role validation. Never trust client-provided role/permission data.",
                        cvss_score=9.8
                    ))
                    print(f"  [VULN] Privilege escalation: {len(successful_escalations)} methods")
                else:
                    print("  [OK] Privilege escalation prevented")
        
        except Exception as e:
            print(f"  [ERROR] Privilege escalation test failed: {e}")
    
    # Helper methods

    @staticmethod
    def _is_exact_echo(response: object, request: object) -> bool:
        """Treat an unchanged request reflection as no authorization evidence."""
        if isinstance(request, (list, tuple, set, frozenset)):
            return any(SessionHijackingTester._is_exact_echo(response, candidate) for candidate in request)
        return response == request
    
    def _extract_token(self, response: str) -> Optional[str]:
        """Extract authentication token from response"""
        try:
            data = json.loads(response)
            return data.get('token') or data.get('auth_token') or data.get('session_token')
        except (json.JSONDecodeError, ValueError):
            # Try regex extraction
            match = re.search(r'"token":\s*"([^"]+)"', response)
            return match.group(1) if match else None
    
    def _extract_user_id(self, response: str) -> Optional[str]:
        """Extract user ID from response"""
        try:
            data = json.loads(response)
            return data.get('user_id') or data.get('id') or data.get('uid')
        except (json.JSONDecodeError, ValueError):
            return None
    
    def _extract_session_data(self, response: str) -> Dict:
        """Extract session data from response"""
        try:
            return json.loads(response)
        except (json.JSONDecodeError, ValueError):
            return {}
    
    def _is_auth_success(self, response: str) -> bool:
        """Check if authentication was successful"""
        success_indicators = ['success', 'authenticated', 'logged in', 'token', 'welcome']
        response_lower = response.lower()
        return any(indicator in response_lower for indicator in success_indicators)
    
    def _is_subscription_success(self, response: str) -> bool:
        """Check if subscription was successful"""
        success_indicators = ['subscribed', 'joined', 'success', 'channel']
        error_indicators = ['error', 'denied', 'unauthorized', 'forbidden']
        response_lower = response.lower()
        
        has_success = any(indicator in response_lower for indicator in success_indicators)
        has_error = any(indicator in response_lower for indicator in error_indicators)
        
        return has_success and not has_error
    
    def _is_error_response(self, response: str) -> bool:
        """Check if response indicates an error"""
        error_indicators = ['error', 'denied', 'unauthorized', 'forbidden', 'invalid', 'failed']
        return any(indicator in response.lower() for indicator in error_indicators)
    
    def _contains_private_data(self, response: str) -> bool:
        """Check if response contains private data"""
        private_indicators = ['private', 'message', 'data', 'content', 'user']
        return any(indicator in response.lower() for indicator in private_indicators) and len(response) > 50
    
    def _has_elevated_privileges(self, response: str) -> bool:
        """Check if response indicates elevated privileges"""
        privilege_indicators = ['admin', 'elevated', 'role', 'permissions', 'granted']
        return any(indicator in response.lower() for indicator in privilege_indicators)
    
    def generate_report(self) -> Dict:
        """Generate comprehensive session security report"""
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.is_vulnerable)
        critical = sum(1 for r in self.results if r.is_vulnerable and r.confidence == 'CRITICAL')
        
        return {
            'summary': {
                'total_tests': total,
                'vulnerable': vulnerable,
                'critical_vulnerabilities': critical,
                'risk_level': 'CRITICAL' if critical > 0 else ('HIGH' if vulnerable > 0 else 'LOW')
            },
            'vulnerabilities': [
                {
                    'type': r.vuln_type.value,
                    'vulnerable': r.is_vulnerable,
                    'confidence': r.confidence,
                    'description': r.description,
                    'cvss_score': r.cvss_score,
                    'recommendation': r.recommendation,
                    'evidence': r.evidence
                }
                for r in self.results if r.is_vulnerable
            ]
        }


# Test the session hijacking tester
async def main():
    tester = SessionHijackingTester("ws://localhost:9999")
    
    results = await tester.run_all_tests()
    
    print("\n" + "=" * 70)
    print("SESSION SECURITY TEST RESULTS")
    print("=" * 70)
    
    report = tester.generate_report()
    
    print(f"\nTotal Tests: {report['summary']['total_tests']}")
    print(f"Vulnerabilities Found: {report['summary']['vulnerable']}")
    print(f"Critical: {report['summary']['critical_vulnerabilities']}")
    print(f"Risk Level: {report['summary']['risk_level']}")
    
    if report['vulnerabilities']:
        print("\nVulnerabilities:")
        for vuln in report['vulnerabilities']:
            print(f"\n  [{vuln['confidence']}] {vuln['type']}")
            print(f"  CVSS: {vuln['cvss_score']}")
            print(f"  {vuln['description']}")
            print(f"  Fix: {vuln['recommendation']}")
    
    print("\n[SUCCESS] Session hijacking tests complete!")


if __name__ == "__main__":
    asyncio.run(main())
