import unittest
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO

from wshawk._version_info import __version__
from wshawk.defensive_cli import build_parser
from wshawk.interactive import build_parser as build_interactive_parser
from wshawk.legacy_core import build_parser as build_main_parser


class DefensiveCliTests(unittest.TestCase):
    def test_modern_scanner_import_does_not_load_legacy_runtime(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; import wshawk.scanner_v2; "
                    "assert 'wshawk.legacy_core' not in sys.modules"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_main_entrypoint_does_not_load_legacy_runtime(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; import wshawk.__main__; "
                    "assert 'wshawk.legacy_runtime' not in sys.modules"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compatibility_parser_import_is_lazy(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; from wshawk.legacy_core import build_parser; "
                    "assert build_parser; "
                    "assert 'wshawk.legacy_runtime' not in sys.modules"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_advanced_entrypoint_does_not_load_legacy_cli(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; import wshawk.advanced_cli; "
                    "assert 'wshawk.legacy_advanced_cli' not in sys.modules; "
                    "assert 'wshawk.legacy_runtime' not in sys.modules"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_parser_accepts_websocket_target(self):
        args = build_parser().parse_args(["wss://example.test/socket"])
        self.assertEqual(args.url, "wss://example.test/socket")

    def test_help_exits_successfully(self):
        with self.assertRaises(SystemExit) as context:
            build_parser().parse_args(["--help"])
        self.assertEqual(context.exception.code, 0)

    def test_version_exits_successfully(self):
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as context:
            build_parser().parse_args(["--version"])
        self.assertEqual(context.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"wshawk-defensive {__version__}")

    def test_main_cli_version_uses_central_version(self):
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as context:
            build_main_parser().parse_args(["--version"])
        self.assertEqual(context.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"wshawk {__version__}")

    def test_interactive_cli_version_uses_central_version(self):
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as context:
            build_interactive_parser().parse_args(["--version"])
        self.assertEqual(context.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"wshawk-interactive {__version__}")

    def test_defensive_operational_limits_are_validated(self):
        args = build_parser().parse_args([
            "wss://example.test/socket",
            "--origin-limit", "8",
            "--origin-concurrency", "2",
            "--connect-timeout", "1.5",
        ])
        self.assertEqual(args.origin_limit, 8)
        self.assertEqual(args.origin_concurrency, 2)
        self.assertEqual(args.connect_timeout, 1.5)

        with self.assertRaises(SystemExit) as context:
            build_parser().parse_args(["wss://example.test/socket", "--origin-limit", "0"])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
