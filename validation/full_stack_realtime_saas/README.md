# Full-Stack Realtime SaaS Validation Target

This is a local, intentionally vulnerable validation app for WSHawk.

It is designed to cover the main desktop/operator workflow:

1. Create a project in WSHawk
2. Open this app in a browser
3. Capture the WebSocket handshake with the WSHawk extension
4. Record browser auth in WSHawk
5. Replay HTTP flows
6. Pivot into WebSocket replay
7. Run authz diff and race testing
8. Export evidence
9. Restart WSHawk and verify project recovery

## Run

```bash
./venv/bin/python -m uvicorn validation.full_stack_realtime_saas.app:app --host 127.0.0.1 --port 8010
```

Or:

```bash
./venv/bin/python validation/full_stack_realtime_saas/app.py
```

## Default Accounts

| Username | Password | Role | Tenant |
|---|---|---|---|
| `alice` | `alice123` | `user` | `tenant-alpha` |
| `mallory` | `mallory123` | `manager` | `tenant-alpha` |
| `bob` | `bob123` | `user` | `tenant-beta` |
| `brenda` | `brenda123` | `manager` | `tenant-beta` |
| `admin` | `admin123` | `admin` | `tenant-root` |

## Built-In Validation Scenarios

- **Browser bootstrap**: login sets a cookie, a bearer token, and a CSRF token; the dashboard stores tokens in `localStorage`.
- **Handshake capture**: the dashboard auto-connects to `/ws` on load.
- **HTTP replay / authz diff**: `/api/invoices`, `/api/invoices/{id}`, `/api/team/messages`.
- **Cross-tenant leak**: `/api/invoices/inv-beta-9001?preview=true`.
- **Replay / approval-token abuse**: `/api/invoices/{id}/refund` and WS `approve_refund`.
- **Stale token reuse**: logout clears the cookie but old bearer tokens remain valid.
- **Subscription abuse**: WS `subscribe_invoice` and `list_team_messages` trust attacker-supplied tenant/invoice values.
- **Race condition**: issue multiple concurrent refund requests against the same invoice.
- **Web pentest checks**:
  - open redirect: `/api/public/redirect?next=https://example.org`
  - SSRF simulation: `/api/internal/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  - content discovery: `/robots.txt`, `/internal/health`, `/exports/invoices.csv`

## Notes

- This target is intentionally insecure.
- It is for local validation and authorized lab use only.
