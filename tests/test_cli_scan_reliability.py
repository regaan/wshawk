import ssl
import unittest
from unittest.mock import AsyncMock, patch

from wshawk.defensive_cli import main as defensive_main
from wshawk.defensive_validation import (
    BotDetectionValidator,
    CSWSHValidator,
    DefensiveValidationResult,
    connect_with_retry,
)
from wshawk.payload_catalog import WSPayloads
from wshawk.scanner_v2 import WSHawkV2
from wshawk.session_hijacking_tester import SessionHijackingTester
from wshawk.vulnerability_verifier import VulnerabilityVerifier
from wshawk.wss_security_validator import WSSSecurityValidator
from wshawk.tls import build_websocket_ssl_context


class CliFailureStatusTests(unittest.IsolatedAsyncioTestCase):
    def test_missing_playwright_browser_is_recognized_as_optional_runtime(self):
        error = RuntimeError(
            "BrowserType.launch: Executable doesn't exist; please run playwright install"
        )
        self.assertTrue(BotDetectionValidator._browser_runtime_missing(error))

    async def test_defensive_cli_returns_nonzero_for_partial_validation(self):
        result = DefensiveValidationResult()
        result.record_error("DNS exfiltration", "temporary resolver failure")

        with patch("wshawk.defensive_cli.run_defensive_validation", AsyncMock(return_value=result)) as run:
            exit_code = await defensive_main([
                "wss://example.test/socket",
                "--origin-limit", "4",
                "--origin-concurrency", "2",
                "--connect-timeout", "1",
            ])

        self.assertEqual(exit_code, 1)
        run.assert_awaited_once_with(
            "wss://example.test/socket",
            origin_limit=4,
            origin_concurrency=2,
            connection_timeout=1.0,
        )

    async def test_origin_acceptance_is_an_observation_not_confirmed_cswsh(self):
        validator = CSWSHValidator(
            "wss://example.test/socket",
            max_origins=3,
            origin_concurrency=2,
            connection_timeout=0.5,
        )
        origins = ["https://evil.example", "null", "http://localhost"]

        with patch.object(validator, "_load_malicious_origins", return_value=origins):
            with patch.object(validator, "_probe_origin", AsyncMock(return_value=(True, None))) as probe:
                result = await validator.test_origin_validation()

        self.assertFalse(result["vulnerable"])
        self.assertTrue(result["requires_manual_verification"])
        self.assertEqual(result["accepted_origins"], origins)
        self.assertEqual(probe.await_count, 3)
        self.assertEqual(validator.findings[0]["severity"], "INFO")
        self.assertFalse(validator.findings[0]["vulnerable"])

    async def test_defensive_connection_retries_transient_failure(self):
        websocket = object()
        with patch(
            "wshawk.defensive_validation.websockets.connect",
            AsyncMock(side_effect=[OSError("temporary resolver failure"), websocket]),
        ) as connect:
            with patch("wshawk.defensive_validation.asyncio.sleep", AsyncMock()) as sleep:
                result = await connect_with_retry("wss://example.test/socket", 1.0)

        self.assertIs(result, websocket)
        self.assertEqual(connect.await_count, 2)
        sleep.assert_awaited_once()


class ScannerReflectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_nosql_exact_echo_is_not_reported_as_injection(self):
        class EchoWebSocket:
            last_message = ""

            async def send(self, message):
                self.last_message = message

            async def recv(self):
                return self.last_message

        scanner = WSHawkV2("wss://example.test/socket")
        scanner.rate_limiter.acquire = AsyncMock()
        scanner.rate_limiter.done = AsyncMock()

        with patch.object(WSPayloads, "get_nosql_injection", return_value=["$ne"]):
            results = await scanner.test_nosql_injection_v2(EchoWebSocket())

        self.assertEqual(results, [])
        self.assertEqual(scanner.vulnerabilities, [])
        scanner.rate_limiter.acquire.assert_awaited_once()
        scanner.rate_limiter.done.assert_awaited_once()

    async def test_rate_limiter_slot_is_released_when_send_fails(self):
        scanner = WSHawkV2("wss://example.test/socket")
        scanner.rate_limiter.acquire = AsyncMock()
        scanner.rate_limiter.done = AsyncMock()
        websocket = unittest.mock.Mock()
        websocket.send = AsyncMock(side_effect=RuntimeError("send failed"))

        with self.assertRaisesRegex(RuntimeError, "send failed"):
            await scanner._send_message(websocket, "payload")

        scanner.rate_limiter.acquire.assert_awaited_once()
        scanner.rate_limiter.done.assert_awaited_once()

    async def test_late_echo_from_an_earlier_request_is_not_a_finding(self):
        delayed_echo = '{"action":"find_user","query":{"username":"$ne"}}'

        class DelayedEchoWebSocket:
            async def send(self, message):
                self.last_message = message

            async def recv(self):
                return delayed_echo

        scanner = WSHawkV2("wss://example.test/socket")
        scanner.recent_requests.append(delayed_echo)
        scanner.rate_limiter.acquire = AsyncMock()
        scanner.rate_limiter.done = AsyncMock()

        with patch.object(WSPayloads, "get_nosql_injection", return_value=["$gt"]):
            results = await scanner.test_nosql_injection_v2(DelayedEchoWebSocket())

        self.assertEqual(results, [])
        self.assertEqual(scanner.vulnerabilities, [])

    async def test_connection_failure_leaves_scan_in_failed_state(self):
        scanner = WSHawkV2("wss://example.test/socket")
        scanner.connect = AsyncMock(return_value=None)

        results = await scanner.run_heuristic_scan()

        self.assertEqual(results, [])
        self.assertFalse(scanner.scan_completed)

    async def test_scanner_connection_retries_transient_failure(self):
        scanner = WSHawkV2("wss://example.test/socket")
        websocket = object()

        with patch(
            "wshawk.scanner_v2.websockets.connect",
            AsyncMock(side_effect=[OSError("temporary resolver failure"), websocket]),
        ) as connect:
            with patch("wshawk.scanner_v2.asyncio.sleep", AsyncMock()) as sleep:
                result = await scanner.connect()

        self.assertIs(result, websocket)
        self.assertEqual(connect.await_count, 2)
        sleep.assert_awaited_once()


class ReflectionClassificationTests(unittest.TestCase):
    def test_exact_echo_is_not_execution_evidence(self):
        verifier = VulnerabilityVerifier()
        request = '{"action":"find","query":"$ne"}'

        self.assertTrue(verifier.is_unmodified_reflection(request, request))
        self.assertTrue(verifier.is_unmodified_reflection("late echo", ("older", "late echo", request)))
        self.assertFalse(verifier.verify_sql_injection(request, "$ne", request)[0])
        self.assertFalse(verifier.verify_xss(request, "$ne", request)[0])
        self.assertFalse(verifier.verify_command_injection(request, "$ne", request)[0])
        self.assertFalse(verifier.verify_path_traversal(request, "$ne", request)[0])

    def test_session_checks_reject_exact_echoes(self):
        self.assertTrue(SessionHijackingTester._is_exact_echo("same", "same"))
        self.assertFalse(SessionHijackingTester._is_exact_echo("accepted", "request"))


class TLSVersionValidationTests(unittest.TestCase):
    def test_websocket_tls_context_verifies_certificates_by_default(self):
        context = build_websocket_ssl_context("wss://example.test/socket")

        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(build_websocket_ssl_context("ws://example.test/socket"))

    def test_websocket_tls_verification_requires_explicit_opt_out(self):
        context = build_websocket_ssl_context("wss://example.test/socket", verify_ssl=False)

        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_only_strict_tls_10_and_11_probes_are_defined(self):
        validator = WSSSecurityValidator("wss://example.test/socket")
        self.assertEqual(set(validator.deprecated_protocols), {"TLSv1.0", "TLSv1.1"})
        self.assertNotIn("SSLv2", validator.deprecated_protocols)
        self.assertNotIn("SSLv3", validator.deprecated_protocols)

    def test_modern_auto_negotiation_cannot_be_mislabeled_as_sslv2(self):
        validator = WSSSecurityValidator("wss://example.test/socket")

        with patch.object(validator, "_probe_tls_version", side_effect=[None, None]) as probe:
            result = validator.test_tls_version_support()

        self.assertFalse(result["vulnerable"])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(validator.findings[0]["severity"], "INFO")

    def test_successful_pinned_deprecated_handshake_is_high_not_critical(self):
        validator = WSSSecurityValidator("wss://example.test/socket")

        with patch.object(validator, "_probe_tls_version", side_effect=["TLSv1", None]):
            result = validator.test_tls_version_support()

        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["versions"], ["TLSv1.0"])
        self.assertEqual(validator.findings[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
