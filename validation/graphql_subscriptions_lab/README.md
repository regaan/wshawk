# GraphQL Subscriptions Validation Lab

This lab focuses on GraphQL-over-WebSocket coverage using the `graphql-transport-ws` protocol.

It is intentionally vulnerable and designed to validate that WSHawk can reason about:

- `connection_init` authentication
- cross-tenant subscription exposure
- tenant message leakage over subscriptions
- privileged refund replay using a leaked approval token

## Run

```bash
./venv/bin/python -m uvicorn validation.graphql_subscriptions_lab.app:app --host 127.0.0.1 --port 8012
```

## Default Accounts

| Username | Password | Role | Tenant |
|---|---|---|---|
| `alice` | `alice123` | `user` | `tenant-alpha` |
| `mallory` | `mallory123` | `manager` | `tenant-alpha` |
| `bob` | `bob123` | `user` | `tenant-beta` |
| `brenda` | `brenda123` | `manager` | `tenant-beta` |

## Validation Behaviors

- `invoiceUpdates` leaks a foreign tenant invoice.
- `tenantMessages` leaks foreign tenant message rows.
- `approveRefund` requires a manager or a leaked approval token.
- A leaked approval token can be replayed successfully by the wrong tenant/user.
