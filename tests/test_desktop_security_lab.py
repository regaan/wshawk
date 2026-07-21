from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import aiohttp
from websockets.asyncio.client import connect

from benchmarks.desktop_security_lab import app, ground_truth, reset_state
from benchmarks.desktop_security_lab.server import bind_loopback, ready_payload
from validation.common import LiveASGIServer
from wshawk.payload_catalog import WSPayloads
from wshawk.scanner_v2 import WSHawkV2
from wshawk.web_pentest import WSHawkFuzzer


class DesktopSecurityLabManifestTests(unittest.TestCase):
    def test_ground_truth_is_complete_and_stable(self):
        truth = ground_truth()
        cases = truth["cases"]
        identifiers = [case["id"] for case in cases]

        self.assertEqual(truth["schema_version"], 1)
        self.assertEqual(len(cases), 26)
        self.assertEqual(len(set(identifiers)), len(identifiers))
        self.assertEqual(sum(case["channel"] == "http" for case in cases), 16)
        self.assertEqual(sum(case["channel"] == "websocket" for case in cases), 10)
        self.assertTrue(all(case["expected"]["vulnerable"] == "finding_required" for case in cases))
        self.assertTrue(all(case["expected"]["hardened"] == "no_finding" for case in cases))
        required_fields = {"id", "channel", "technique", "cwe", "severity", "target", "probe", "expected"}
        for case in cases:
            self.assertTrue(required_fields.issubset(case), case["id"])
            self.assertIn(case["severity"], {"critical", "high", "medium", "low", "info"})
            self.assertTrue(case["cwe"].startswith("CWE-"))
            self.assertTrue(case["target"].startswith("/"))

        self.assertEqual(truth["lab_version"], "1.0.0")
        self.assertEqual(truth["fixtures"]["trusted_origin"], "https://trusted.example")

    def test_controller_binds_only_to_loopback(self):
        listener = bind_loopback()
        try:
            host, port = listener.getsockname()
            payload = ready_payload(port)
            self.assertEqual(host, "127.0.0.1")
            self.assertEqual(payload["host"], "127.0.0.1")
            self.assertEqual(payload["case_count"], 26)
            self.assertTrue(payload["base_url"].startswith("http://127.0.0.1:"))
        finally:
            listener.close()


class DesktopSecurityLabBehaviorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        reset_state()
        self.server_context = LiveASGIServer(app)
        self.server = self.server_context.__enter__()
        self.base_url = f"http://{self.server.host}:{self.server.port}"

    async def asyncTearDown(self):
        self.server_context.__exit__(None, None, None)

    async def test_http_profiles_have_opposite_security_outcomes(self):
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/lab/health") as response:
                health = await response.json()
            self.assertTrue(health["ok"])
            self.assertEqual(health["case_count"], 26)

            probes = [
                ("api/search", {"q": "' OR 1=1--"}, "SQL syntax"),
                ("api/search", {"q": "<svg/onload=alert(1)>"}, "<svg/onload=alert(1)>") ,
                ("api/execute", {"cmd": "status;id"}, "uid=1000"),
                ("api/file", {"path": "../../etc/passwd"}, "root:x:0:0:"),
                ("api/nosql", {"filter": '{"username":{"$ne":null}}'}, "MongoDB"),
            ]
            for route, params, marker in probes:
                async with session.get(f"{self.base_url}/vulnerable/{route}", params=params) as vulnerable:
                    vulnerable_text = await vulnerable.text()
                async with session.get(f"{self.base_url}/hardened/{route}", params=params) as hardened:
                    hardened_text = await hardened.text()
                self.assertIn(marker, vulnerable_text, route)
                self.assertNotIn(marker, hardened_text, route)

            xxe_payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            async with session.post(f"{self.base_url}/vulnerable/api/xml", data=xxe_payload) as vulnerable:
                self.assertIn("root:x:0:0:", await vulnerable.text())
            async with session.post(f"{self.base_url}/hardened/api/xml", data=xxe_payload) as hardened:
                self.assertEqual(hardened.status, 400)

    async def test_wshawk_fuzzer_detects_vulnerable_sqli_and_keeps_hardened_clean(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            wordlist = Path(temporary_directory) / "sqli.txt"
            wordlist.write_text("' OR 1=1--\n", encoding="utf-8")
            scanner = WSHawkFuzzer()
            vulnerable = await scanner.run_fuzz(
                method="GET",
                url=f"{self.base_url}/vulnerable/api/search?q=§FUZZ§",
                wordlist_name="custom",
                custom_file=str(wordlist),
                grep_regex=r"SQL syntax|mysql_",
            )
            hardened = await scanner.run_fuzz(
                method="GET",
                url=f"{self.base_url}/hardened/api/search?q=§FUZZ§",
                wordlist_name="custom",
                custom_file=str(wordlist),
                grep_regex=r"SQL syntax|mysql_",
            )

        self.assertTrue(any(item.get("grepped") for item in vulnerable["findings"]))
        self.assertEqual(hardened["findings"], [])

    async def test_websocket_probe_profiles_have_opposite_security_outcomes(self):
        vulnerable_url = self.base_url.replace("http://", "ws://") + "/vulnerable/probe-ws"
        hardened_url = self.base_url.replace("http://", "ws://") + "/hardened/probe-ws"
        headers = {"Authorization": "Bearer industry-user-token"}
        probe = json.dumps({"action": "probe", "attack": "sqli", "payload": "' OR 1=1--"})

        async with connect(vulnerable_url, origin="https://attacker.example", additional_headers=headers) as websocket:
            await websocket.recv()
            await websocket.send(probe)
            vulnerable = json.loads(await websocket.recv())

        async with connect(hardened_url, origin="https://trusted.example", additional_headers=headers) as websocket:
            await websocket.recv()
            await websocket.send(probe)
            hardened = json.loads(await websocket.recv())

        self.assertIn("SQL syntax", vulnerable["evidence"])
        self.assertEqual(hardened["error"], "input_rejected")
        self.assertEqual(hardened["status_code"], 400)

    async def test_wshawk_websocket_xss_keeps_hardened_profile_clean(self):
        template = json.dumps({"action": "probe", "attack": "sqli", "payload": "benchmark"})

        async def scan(profile: str, origin: str | None = None) -> int:
            url = self.base_url.replace("http://", "ws://") + f"/{profile}/probe-ws"
            headers = {"Authorization": "Bearer industry-user-token"}
            if origin:
                headers["Origin"] = origin
            scanner = WSHawkV2(url, headers=headers, max_rps=100)
            scanner.use_headless_browser = False
            scanner.use_oast = False
            scanner.rate_limiter.tokens_per_second = 100
            scanner.rate_limiter.bucket_size = 200
            scanner.sample_messages = [template]
            scanner.message_analyzer.learn_from_messages([template])
            scanner.learning_complete = True
            websocket = await scanner.connect()
            self.assertIsNotNone(websocket)
            await websocket.recv()
            try:
                with (
                    patch.object(WSPayloads, "get_xss", return_value=["<svg/onload=alert(1)>"]),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    return len(await scanner.test_xss_v2(websocket))
            finally:
                await websocket.close()

        vulnerable_findings = await scan("vulnerable")
        hardened_findings = await scan("hardened", "https://trusted.example")
        self.assertGreater(vulnerable_findings, 0)
        self.assertEqual(hardened_findings, 0)


if __name__ == "__main__":
    unittest.main()
