# Socket.IO SaaS Validation Lab

This lab focuses on protocol-specific Socket.IO coverage for WSHawk.

It is intentionally vulnerable and designed to validate that WSHawk can reason about:

- Socket.IO authentication and session bootstrap
- room/subscription abuse across tenants
- leaked approval token replay
- manager-only authorization paths

## Run

```bash
./venv/bin/python -m uvicorn validation.socketio_saas.app:app --host 127.0.0.1 --port 8011
```

## Default Accounts

| Username | Password | Role | Tenant |
|---|---|---|---|
| `alice` | `alice123` | `user` | `tenant-alpha` |
| `mallory` | `mallory123` | `manager` | `tenant-alpha` |
| `bob` | `bob123` | `user` | `tenant-beta` |
| `brenda` | `brenda123` | `manager` | `tenant-beta` |

## Validation Behaviors

- `subscribe_order` leaks a foreign tenant order snapshot.
- `list_room_messages` leaks foreign tenant room traffic.
- `approve_refund` requires a manager or a leaked approval token.
- The same approval token can be replayed cross-tenant.
