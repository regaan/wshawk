"""
WSS (WebSocket Secure) Protocol Security Validator

Tests server-side TLS/SSL configuration for common vulnerabilities.
This module validates the cryptographic security of WSS connections.

Tests:
1. TLS Protocol Version Support (TLS 1.0/1.1 deprecation)
2. Weak Cipher Suite Detection
3. Certificate Signature Algorithm Validation
4. Certificate Chain Integrity
5. TLS Renegotiation Security
"""

import ssl
import socket
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse


class WSSSecurityValidator:
    """
    Validates WSS (WebSocket Secure) protocol security
    
    Tests server-side TLS/SSL configuration for vulnerabilities including:
    - Deprecated TLS versions (1.0, 1.1)
    - Weak cipher suites (RC4, DES, 3DES, etc.)
    - Insecure signature algorithms (SHA-1)
    - Certificate chain issues
    - Insecure renegotiation
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings = []
        
        # Parse URL to get host and port
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        
        # Deprecated TLS versions that should NOT be supported. SSLv2 and
        # SSLv3 aren't exposed by modern Python/OpenSSL and must never be
        # represented by an auto-negotiating context.
        self.deprecated_protocols = {
            'TLSv1.0': ssl.TLSVersion.TLSv1,
            'TLSv1.1': ssl.TLSVersion.TLSv1_1,
        }
        
        # Weak cipher suites that should NOT be supported
        # Based on OWASP recommendations and industry standards
        self.weak_cipher_patterns = [
            'RC4',      # Broken stream cipher
            'DES',      # Weak encryption
            '3DES',     # Deprecated
            'MD5',      # Broken hash
            'NULL',     # No encryption
            'EXPORT',   # Intentionally weakened
            'anon',     # Anonymous (no authentication)
            'ADH',      # Anonymous Diffie-Hellman
            'AECDH',    # Anonymous ECDH
        ]
        
        # Recommended modern cipher suites (forward secrecy)
        self.recommended_ciphers = [
            'ECDHE',    # Elliptic Curve Diffie-Hellman Ephemeral
            'DHE',      # Diffie-Hellman Ephemeral
        ]
    
    def add_finding(self, test_name: str, vulnerable: bool, severity: str,
                   description: str, recommendation: str, cvss: float = 0.0,
                   details: Optional[Dict] = None):
        """Add a security finding"""
        finding = {
            'test': test_name,
            'vulnerable': vulnerable,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'cvss': cvss,
            'details': details or {}
        }
        self.findings.append(finding)
    
    def _probe_tls_version(self, tls_version: ssl.TLSVersion) -> Optional[str]:
        """Attempt a handshake pinned to exactly one TLS version."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = tls_version
        context.maximum_version = tls_version

        # Modern OpenSSL security levels disable TLS 1.0/1.1 cipher suites
        # before the server can be tested. Lowering the local security level is
        # safe here because this isolated connection is only a compatibility
        # probe and certificate data isn't trusted or consumed.
        try:
            context.set_ciphers('ALL:@SECLEVEL=0')
        except ssl.SSLError:
            pass

        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as secure_socket:
                return secure_socket.version()

    def test_tls_version_support(self) -> Dict:
        """
        Test if server supports deprecated TLS versions
        
        Tests for TLS 1.0 and TLS 1.1 by pinning both the minimum and maximum
        version. Modern Python doesn't expose SSLv2/SSLv3 clients, so those
        versions are not guessed from an auto-negotiated connection.
        
        Only TLS 1.2+ should be supported
        """
        vulnerable_versions = []
        negotiated_versions = {}
        probe_errors = {}
        
        # Test each deprecated protocol
        for protocol_name, tls_version in self.deprecated_protocols.items():
            try:
                negotiated = self._probe_tls_version(tls_version)
                if negotiated:
                    vulnerable_versions.append(protocol_name)
                    negotiated_versions[protocol_name] = negotiated
            except (ssl.SSLError, OSError, socket.timeout, ValueError) as exc:
                probe_errors[protocol_name] = str(exc)
        
        if vulnerable_versions:
            self.add_finding(
                test_name="TLS Protocol Downgrade Vulnerability",
                vulnerable=True,
                severity="HIGH",
                description=f"Server completed handshakes pinned to deprecated versions: "
                           f"{', '.join(vulnerable_versions)}.",
                recommendation="Disable TLS 1.0 and TLS 1.1. "
                             "Only enable TLS 1.2 and TLS 1.3. "
                             "Configure server to reject connections using deprecated protocols.",
                cvss=7.4,
                details={
                    'vulnerable_versions': vulnerable_versions,
                    'negotiated_versions': negotiated_versions,
                    'probe_errors': probe_errors,
                }
            )
            return {
                'vulnerable': True,
                'versions': vulnerable_versions,
                'negotiated_versions': negotiated_versions,
            }
        else:
            self.add_finding(
                test_name="TLS Protocol Downgrade Vulnerability",
                vulnerable=False,
                severity="INFO",
                description="No handshake pinned to TLS 1.0 or TLS 1.1 succeeded.",
                recommendation="Continue enforcing TLS 1.2+ only.",
                details={'probe_errors': probe_errors},
            )
            return {'vulnerable': False}
    
    def test_cipher_suites(self) -> Dict:
        """
        Test for weak cipher suites
        
        Checks for:
        - RC4 (broken stream cipher)
        - DES/3DES (weak/deprecated encryption)
        - MD5 (broken hash)
        - NULL ciphers (no encryption)
        - EXPORT ciphers (intentionally weakened)
        - Anonymous ciphers (no authentication)
        
        Should use: ECDHE, AES-GCM, ChaCha20-Poly1305
        """
        try:
            # Create context with default settings to get supported ciphers
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_version = cipher[1]
                        cipher_bits = cipher[2]
                        
                        # Check if cipher is weak
                        is_weak = any(weak in cipher_name.upper() for weak in self.weak_cipher_patterns)
                        has_forward_secrecy = (
                            cipher_version == 'TLSv1.3'
                            or any(rec in cipher_name.upper() for rec in self.recommended_ciphers)
                        )
                        
                        if is_weak:
                            self.add_finding(
                                test_name="Weak Cipher Suite",
                                vulnerable=True,
                                severity="HIGH",
                                description=f"Server negotiated weak cipher: {cipher_name} ({cipher_bits} bits). "
                                           f"This cipher is vulnerable to cryptographic attacks.",
                                recommendation="Disable weak ciphers (RC4, DES, 3DES, MD5, NULL, EXPORT, anon). "
                                             "Use modern ciphers with forward secrecy: "
                                             "ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256, "
                                             "ECDHE-RSA-CHACHA20-POLY1305.",
                                cvss=7.5,
                                details={
                                    'cipher_name': cipher_name,
                                    'cipher_version': cipher_version,
                                    'cipher_bits': cipher_bits
                                }
                            )
                            return {'vulnerable': True, 'cipher': cipher_name}
                        
                        elif not has_forward_secrecy:
                            self.add_finding(
                                test_name="Missing Forward Secrecy",
                                vulnerable=True,
                                severity="MEDIUM",
                                description=f"Server uses cipher without forward secrecy: {cipher_name}. "
                                           f"Compromised private keys can decrypt past traffic.",
                                recommendation="Enable ciphers with forward secrecy (ECDHE, DHE). "
                                             "Prefer ECDHE-based ciphers for better performance.",
                                cvss=5.3,
                                details={'cipher_name': cipher_name}
                            )
                            return {'vulnerable': True, 'cipher': cipher_name, 'issue': 'no_forward_secrecy'}
                        
                        else:
                            self.add_finding(
                                test_name="Cipher Suite Security",
                                vulnerable=False,
                                severity="INFO",
                                description=f"Server uses strong cipher with forward secrecy: {cipher_name}.",
                                recommendation="Continue using modern cipher suites.",
                                details={'cipher_name': cipher_name}
                            )
                            return {'vulnerable': False, 'cipher': cipher_name}
        
        except Exception as e:
            return {'error': str(e)}
    
    def test_certificate_signature_algorithm(self) -> Dict:
        """
        Test certificate signature algorithm
        
        Checks for:
        - SHA-1 (cryptographically broken, allows forgery)
        - MD5 (completely broken)
        
        Should use: SHA-256, SHA-384, SHA-512
        """
        try:
            from cryptography import x509

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    der_certificate = ssock.getpeercert(binary_form=True)
                    if not der_certificate:
                        return {'error': 'server did not provide a certificate'}

                    certificate = x509.load_der_x509_certificate(der_certificate)
                    signature_hash = certificate.signature_hash_algorithm
                    signature_name = signature_hash.name.lower() if signature_hash else 'unknown'
                    subject = certificate.subject.rfc4514_string()
                    issuer = certificate.issuer.rfc4514_string()

                    try:
                        expiry = certificate.not_valid_after_utc
                    except AttributeError:
                        from datetime import timezone
                        expiry = certificate.not_valid_after.replace(tzinfo=timezone.utc)

                    from datetime import datetime, timezone
                    if expiry < datetime.now(timezone.utc):
                        self.add_finding(
                            test_name="Certificate Expiration",
                            vulnerable=True,
                            severity="HIGH",
                            description=f"Server certificate expired at {expiry.isoformat()}.",
                            recommendation="Renew the TLS certificate immediately.",
                            cvss=7.5,
                            details={'expiry_date': expiry.isoformat()},
                        )
                        return {'vulnerable': True, 'issue': 'expired'}

                    if signature_name in {'md5', 'sha1'}:
                        self.add_finding(
                            test_name="Weak Certificate Signature",
                            vulnerable=True,
                            severity="HIGH",
                            description=f"Certificate uses the deprecated {signature_name.upper()} signature hash.",
                            recommendation="Replace the certificate with one signed using SHA-256 or stronger.",
                            cvss=7.4,
                            details={'signature_hash': signature_name},
                        )
                        return {'vulnerable': True, 'issue': 'weak_signature'}

                    if subject == issuer:
                        self.add_finding(
                            test_name="Self-Signed Certificate",
                            vulnerable=True,
                            severity="MEDIUM",
                            description="Server uses a self-signed certificate.",
                            recommendation="Use a certificate from a trusted Certificate Authority.",
                            cvss=5.3,
                            details={'subject': subject},
                        )
                        return {'vulnerable': True, 'issue': 'self_signed'}

                    self.add_finding(
                        test_name="Certificate Signature Validation",
                        vulnerable=False,
                        severity="INFO",
                        description=f"Certificate uses {signature_name.upper()} and is not expired.",
                        recommendation="Continue monitoring certificate expiration and signature policy.",
                        details={
                            'subject': subject,
                            'issuer': issuer,
                            'signature_hash': signature_name,
                            'expiry_date': expiry.isoformat(),
                        },
                    )
                    return {'vulnerable': False, 'signature_hash': signature_name}
        
        except Exception as e:
            return {'error': str(e)}
    
    def test_certificate_chain(self) -> Dict:
        """
        Test certificate chain integrity
        
        Checks for:
        - Incomplete certificate chain
        - Invalid intermediate certificates
        - Untrusted root certificates
        """
        try:
            # Create context that validates certificate chain
            context = ssl.create_default_context()
            context.check_hostname = True
            
            try:
                with socket.create_connection((self.host, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                        # If we get here, certificate chain is valid
                        cert = ssock.getpeercert()
                        
                        self.add_finding(
                            test_name="Certificate Chain Integrity",
                            vulnerable=False,
                            severity="INFO",
                            description="Certificate chain is complete and valid.",
                            recommendation="Continue using valid certificate chains."
                        )
                        return {'vulnerable': False, 'valid_chain': True}
            
            except ssl.SSLCertVerificationError as e:
                self.add_finding(
                    test_name="Certificate Chain Integrity",
                    vulnerable=True,
                    severity="HIGH",
                    description=f"Certificate chain validation failed: {str(e)}. "
                               f"This may indicate missing intermediate certificates or untrusted root.",
                    recommendation="Ensure the server provides the complete certificate chain "
                                 "(server cert + intermediate certs). "
                                 "Verify all certificates are from trusted CAs.",
                    cvss=7.5,
                    details={'error': str(e)}
                )
                return {'vulnerable': True, 'error': str(e)}
        
        except Exception as e:
            return {'error': str(e)}
    
    def test_renegotiation_security(self) -> Dict:
        """
        Test for insecure TLS renegotiation
        
        Insecure renegotiation allows attackers to inject data
        into established TLS sessions.
        
        Note: Python's ssl module doesn't directly expose renegotiation
        testing, so we check if the connection supports secure renegotiation.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Modern Python ssl module enforces secure renegotiation by default
            # If connection succeeds, renegotiation is secure
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    # Check SSL/TLS options
                    # OP_NO_RENEGOTIATION is set by default in modern Python
                    
                    self.add_finding(
                        test_name="TLS Renegotiation Security",
                        vulnerable=False,
                        severity="INFO",
                        description=(
                            "A modern TLS connection was established. Python's ssl API doesn't expose an active "
                            "renegotiation test, so renegotiation security remains unverified."
                        ),
                        recommendation="Verify secure renegotiation with a dedicated TLS scanner when required.",
                        details={'inconclusive': True},
                    )
                    return {'vulnerable': False, 'inconclusive': True}
        
        except Exception as e:
            return {'error': str(e)}
    
    def run_all_tests(self) -> List[Dict]:
        """Run all WSS security tests"""
        results = []
        
        print("[*] Testing WSS Protocol Security...")
        
        # Test 1: TLS Version Support
        print("[*] Checking TLS protocol versions...")
        result = self.test_tls_version_support()
        results.append(result)
        
        # Test 2: Cipher Suites
        print("[*] Analyzing cipher suites...")
        result = self.test_cipher_suites()
        results.append(result)
        
        # Test 3: Certificate Signature
        print("[*] Validating certificate signature...")
        result = self.test_certificate_signature_algorithm()
        results.append(result)
        
        # Test 4: Certificate Chain
        print("[*] Verifying certificate chain...")
        result = self.test_certificate_chain()
        results.append(result)
        
        # Test 5: Renegotiation Security
        print("[*] Testing TLS renegotiation...")
        result = self.test_renegotiation_security()
        results.append(result)
        
        return results


async def test_wss_security(target_url: str):
    """
    Test WSS (WebSocket Secure) protocol security
    
    Usage:
        await test_wss_security("wss://secure-server.com")
    """
    if not target_url.startswith('wss://'):
        print("[!] Warning: URL should use wss:// for secure WebSocket testing")
        return None
    
    validator = WSSSecurityValidator(target_url)
    results = validator.run_all_tests()
    
    # Print summary
    print("\n" + "=" * 70)
    print("WSS SECURITY VALIDATION SUMMARY")
    print("=" * 70)
    
    critical = sum(1 for f in validator.findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in validator.findings if f['severity'] == 'HIGH')
    medium = sum(1 for f in validator.findings if f['severity'] == 'MEDIUM')
    
    print(f"\nFindings:")
    print(f"  CRITICAL: {critical}")
    print(f"  HIGH: {high}")
    print(f"  MEDIUM: {medium}")
    print()
    
    for finding in validator.findings:
        if finding['vulnerable']:
            print(f"\n[{finding['severity']}] {finding['test']}")
            print(f"  Description: {finding['description']}")
            print(f"  Recommendation: {finding['recommendation']}")
            if finding.get('cvss'):
                print(f"  CVSS: {finding['cvss']}")
    
    return validator.findings


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "wss://echo.websocket.org"
    
    asyncio.run(test_wss_security(target))
