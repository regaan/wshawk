"""Exercise the legacy Python implementation against the Electron/Go parity lab."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
import tracemalloc
from pathlib import Path

from wshawk.attacks import WebSocketReplayService
from wshawk.web_pentest import WSHawkFuzzer


FUZZ_MARKER = "§FUZZ§"


async def run(http_url: str, ws_url: str) -> dict:
    started = time.perf_counter()
    tracemalloc.start()
    fuzzer = WSHawkFuzzer()
    payload_dir = Path(__file__).resolve().parent
    vulnerable_sqli = await fuzzer.run_fuzz(
        method="GET",
        url=f"{http_url}/scan?q={FUZZ_MARKER}",
        wordlist_name="custom",
        custom_file=str(payload_dir / "legacy-sqli.txt"),
        grep_regex=r"SQL syntax error",
    )
    vulnerable_xss = await fuzzer.run_fuzz(
        method="GET",
        url=f"{http_url}/scan?q={FUZZ_MARKER}",
        wordlist_name="custom",
        custom_file=str(payload_dir / "legacy-xss.txt"),
    )
    safe_sqli = await fuzzer.run_fuzz(
        method="GET",
        url=f"{http_url}/safe?q={FUZZ_MARKER}",
        wordlist_name="custom",
        custom_file=str(payload_dir / "legacy-sqli.txt"),
        grep_regex=r"SQL syntax error",
    )
    safe_xss = await fuzzer.run_fuzz(
        method="GET",
        url=f"{http_url}/safe?q={FUZZ_MARKER}",
        wordlist_name="custom",
        custom_file=str(payload_dir / "legacy-xss.txt"),
    )
    replay = await WebSocketReplayService().replay(
        project_id="electron-go-identical-lab",
        url=ws_url,
        payload="legacy-parity-echo",
        timeout=3.0,
    )
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    findings = []
    if any(item.get("grepped") for item in vulnerable_sqli.get("findings", [])):
        findings.append("sql-injection")
    if any(item.get("xss") for item in vulnerable_xss.get("findings", [])):
        findings.append("xss")
    false_positives = len(safe_sqli.get("findings", [])) + len(safe_xss.get("findings", []))
    checks = {
        "expected_http_findings": {"sql-injection", "xss"}.issubset(findings),
        "safe_endpoint_has_no_findings": false_positives == 0,
        "websocket_text_echo": (
            replay.get("status") == "received"
            and replay.get("response") == "legacy-parity-echo"
        ),
    }
    return {
        "implementation": "legacy-python",
        "passed": all(checks.values()),
        "checks": checks,
        "http_findings": sorted(findings),
        "false_positives": false_positives,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "peak_python_memory_bytes": peak_bytes,
        "websocket_status": replay.get("status"),
        "websocket_error": replay.get("error", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("http_url")
    parser.add_argument("ws_url")
    args = parser.parse_args()
    result = asyncio.run(run(args.http_url, args.ws_url))
    print("WSHAWK_LEGACY_PARITY=" + json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
