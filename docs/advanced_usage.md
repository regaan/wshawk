# WSHawk v4 Advanced Usage

This guide focuses on current module-level usage for the repo as it exists today.

Two things matter up front:

- the compatibility scanner path is still available through `wshawk.scanner_v2.WSHawkV2`
- the most complete v4 workflows for replay, AuthZ diff, race testing, and evidence collection are primarily driven through the desktop app and local daemon

If you want the operator workflow, start with [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md). If you want current architecture and route layout, see [WSHawk v4 Complete Guide](V4_COMPLETE_GUIDE.md).

---

## Scanner API

Use `WSHawkV2` when you want the compatibility scanner path from Python.

### Minimal Scan

```python
import asyncio
from wshawk.scanner_v2 import WSHawkV2


async def run():
    scanner = WSHawkV2("wss://target.example/ws", max_rps=5)
    scanner.use_headless_browser = False
    scanner.use_oast = False

    findings = await scanner.run_heuristic_scan()
    print(f"Findings: {len(findings)}")

    for finding in findings[:5]:
        print(f"[{finding.get('confidence', 'UNKNOWN')}] {finding.get('type', 'unknown')}")


asyncio.run(run())
```

### Scanner Toggles

These current attributes exist on `WSHawkV2`:

- `use_headless_browser`
- `use_oast`
- `use_smart_payloads`
- `use_ai`

Example:

```python
scanner = WSHawkV2("wss://target.example/ws")
scanner.use_headless_browser = True
scanner.use_oast = True
scanner.use_smart_payloads = True
```

### Configuration-Driven Scanner

```python
import asyncio
from wshawk.config import WSHawkConfig
from wshawk.scanner_v2 import WSHawkV2


async def run():
    config = WSHawkConfig.load()
    config.set("scanner.rate_limit", 3)
    config.set("scanner.timeout", 8)
    config.set("scanner.verify_ssl", True)

    scanner = WSHawkV2("wss://target.example/ws", config=config)
    scanner.use_headless_browser = False
    findings = await scanner.run_heuristic_scan()
    print(len(findings))


asyncio.run(run())
```

---

## Session Security Tester

The session security module still exists as a standalone component in:

- `wshawk/session_hijacking_tester.py`

Use it directly when you want to exercise the older session-focused checks without running the full scanner.

```python
import asyncio
from wshawk.session_hijacking_tester import SessionHijackingTester


async def run():
    tester = SessionHijackingTester("wss://target.example/ws")
    results = await tester.run_all_tests()

    for result in results:
        if result.is_vulnerable:
            print(result.vuln_type.value, result.cvss_score, result.description)


asyncio.run(run())
```

This module is also invoked near the end of `WSHawkV2.run_heuristic_scan()`.

For newer project-backed identity workflows, prefer the desktop app and its replay, AuthZ diff, and race tooling.

---

## Payload Mutation

The current payload mutation module is:

- `wshawk.payload_mutator.PayloadMutator`

### Strategy-Based Mutation

```python
from wshawk.payload_mutator import PayloadMutator, MutationStrategy

mutator = PayloadMutator()

variants = mutator.mutate_payload(
    "<script>alert(1)</script>",
    MutationStrategy.TAG_BREAKING,
    count=5,
)

for payload in variants:
    print(payload)
```

### Adaptive Mutation

```python
from wshawk.payload_mutator import PayloadMutator

mutator = PayloadMutator()

adaptive = mutator.generate_adaptive_payloads("' OR 1=1--", max_count=10)
for payload in adaptive:
    print(payload)
```

### Learning From Responses

```python
from wshawk.payload_mutator import PayloadMutator

mutator = PayloadMutator()

mutator.learn_from_response(
    payload="<script>alert(1)</script>",
    response="403 Forbidden - Blocked by Cloudflare",
    is_blocked=True,
    response_time=0.02,
)

print(mutator.get_recommended_strategy().value)
```

---

## CVSS Scoring

```python
from wshawk.cvss_calculator import CVSSCalculator

calc = CVSSCalculator()
score = calc.calculate_for_vulnerability("SQL Injection", "HIGH")

print(score.base_score)
print(score.severity)
print(score.vector_string)
```

---

## Reporting Output

The compatibility scanner path writes:

- HTML output through `EnhancedHTMLReporter`
- JSON / CSV / SARIF output through `ReportExporter`

The default reporting directory is controlled through config:

```python
from wshawk.config import WSHawkConfig

config = WSHawkConfig.load()
config.set("reporting.output_dir", "./reports")
config.set("reporting.formats", ["html", "json", "sarif"])
```

After a scan, the compatibility path will emit files such as:

- `reports/wshawk_report_<timestamp>.html`
- additional JSON / CSV / SARIF files if those formats are enabled

---

## When Not to Use the Python Scanner API

Use the desktop app instead of direct module calls when you need:

- project-backed identities
- HTTP replay templates
- WebSocket replay with stored project context
- AuthZ diff across identities
- race testing
- evidence bundle export and verification
- browser companion pairing and scoped capture

Those are v4 platform workflows, not just scanner API features.
