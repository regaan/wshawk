# WSHawk v4 Session Security Testing

WSHawk still ships a session-focused testing module in:

- `wshawk/session_hijacking_tester.py`

This module belongs to the compatibility scanner path and is also invoked by `WSHawkV2.run_heuristic_scan()`.

For newer v4 identity workflows, use the desktop app for:

- project-backed identity storage
- replay across identities
- AuthZ diff
- race testing
- evidence collection

The session tester is still useful when you want a direct WebSocket-focused check against session handling.

---

## Covered Test Areas

| Test | What It Checks |
|---|---|
| **Token Reuse** | whether a captured token still works after session termination |
| **Subscription Spoofing** | whether unauthorized channels or topics can be subscribed to |
| **Impersonation** | whether client-supplied identity fields are trusted |
| **Channel Boundary Violation** | whether private or cross-user channels leak data |
| **Session Fixation** | whether the server accepts attacker-supplied session identifiers |
| **Privilege Escalation** | whether role or permission fields can be elevated client-side |

---

## Run the Tester Directly

```python
import asyncio
from wshawk.session_hijacking_tester import SessionHijackingTester


async def run():
    tester = SessionHijackingTester("wss://target.example/ws")
    results = await tester.run_all_tests()

    for result in results:
        verdict = "VULNERABLE" if result.is_vulnerable else "OK"
        print(verdict, result.vuln_type.value, result.cvss_score)


asyncio.run(run())
```

If the target needs a specific login shape, pass `auth_config` when you build the tester.

Example:

```python
tester = SessionHijackingTester(
    "wss://target.example/ws",
    auth_config={
        "action": "login",
        "username_field": "username",
        "password_field": "password",
        "username": "alice",
        "password": "alice123",
    },
)
```

---

## Scanner Integration

If you run the compatibility scanner:

```bash
wshawk wss://target.example/ws
```

the scanner will attempt the session tester near the end of `run_heuristic_scan()` and merge vulnerable results into the scan findings list.

That means the session tester still matters even if you do not call it directly.

---

## What the Results Mean

Each result is a `SessionTestResult` with:

- `vuln_type`
- `is_vulnerable`
- `confidence`
- `description`
- `evidence`
- `recommendation`
- `cvss_score`

The exact result quality depends on how well the target accepts the tester's assumptions about login and message format. Targets with unusual auth bootstraps often work better through the desktop app, browser companion, and identity vault flow.

---

## When to Prefer v4 Project Workflows

Use the desktop app instead of only the session tester when:

- the target mixes HTTP bootstrap with WebSocket actions
- you need multiple identities in the same operation
- you want replay recipes and exported evidence
- you need AuthZ diff or race testing against stored identities

For that workflow, see [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md).
