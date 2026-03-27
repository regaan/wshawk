import tempfile
import textwrap
import asyncio
import unittest
from pathlib import Path

from wshawk.plugin_system import PluginManager


PLUGIN_SOURCE = """
import builtins

setattr(builtins, "WSHAWK_PLUGIN_IMPORTED", True)

from wshawk.plugin_system import DetectorPlugin, PayloadPlugin, PluginMetadata, ProtocolPlugin


class TempPayloads(PayloadPlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="temp_payloads",
            version="1.0.0",
            description="Temporary payload provider",
        )

    def get_payloads(self, vuln_type: str):
        if vuln_type == "xss":
            return ["<svg onload=alert(1)>"]
        return []


class TempDetector(DetectorPlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="temp_detector",
            version="1.0.0",
            description="Temporary detector",
        )

    def detect(self, response: str, payload: str, context=None):
        if "marker" in response:
            return (True, "HIGH", "marker detected")
        return (False, "LOW", "clean")


class TempProtocol(ProtocolPlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="temp_protocol",
            version="1.0.0",
            description="Temporary protocol handler",
        )

    async def handle_message(self, message: str, context=None):
        return message.upper()
"""


CRASH_PLUGIN_SOURCE = """
from wshawk.plugin_system import PayloadPlugin, PluginMetadata, ProtocolPlugin


class CrashPayloads(PayloadPlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="crash_payloads",
            version="1.0.0",
            description="Crashes when invoked",
        )

    def get_payloads(self, vuln_type: str):
        raise RuntimeError("boom")


class CrashProtocol(ProtocolPlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="crash_protocol",
            version="1.0.0",
            description="Crashes when invoked",
        )

    async def handle_message(self, message: str, context=None):
        raise RuntimeError("kaboom")
"""


class PluginIsolationTests(unittest.TestCase):
    def test_plugin_manager_loads_from_file_path_and_runs_methods_in_subprocess(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "temp_plugin.py").write_text(textwrap.dedent(PLUGIN_SOURCE), encoding="utf-8")
            Path(temp_dir, "crash_plugin.py").write_text(textwrap.dedent(CRASH_PLUGIN_SOURCE), encoding="utf-8")

            import builtins
            if hasattr(builtins, "WSHAWK_PLUGIN_IMPORTED"):
                delattr(builtins, "WSHAWK_PLUGIN_IMPORTED")

            manager = PluginManager(plugin_dir=temp_dir, cache_dir=str(Path(temp_dir) / ".cache"))
            manager.load_all_plugins()

            payloads = manager.get_payloads("xss")
            detections = manager.run_detectors("response with marker", "<svg onload=alert(1)>")
            protocol_result = asyncio.run(manager.handle_protocol_message("TEMP_PROTOCOL", "ping"))
            crash_result = asyncio.run(manager.handle_protocol_message("CRASH_PROTOCOL", "pong"))

            self.assertIn("<svg onload=alert(1)>", payloads)
            self.assertEqual(len(detections), 1)
            self.assertEqual(detections[0]["plugin"], "temp_detector")
            self.assertEqual(protocol_result, "PING")
            self.assertEqual(crash_result, "pong")
            self.assertIn("temp_payloads", manager.list_plugins(loaded_only=True)["payload_plugins"])
            self.assertIn("temp_protocol", manager.list_plugins(loaded_only=True)["protocol_plugins"])
            self.assertFalse(hasattr(builtins, "WSHAWK_PLUGIN_IMPORTED"))


if __name__ == "__main__":
    unittest.main()
