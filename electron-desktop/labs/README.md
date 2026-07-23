# Electron + Go Security Lab

The lab provides repeatable HTTP, GraphQL, and WebSocket targets for WSHawk
development and demonstrations. It contains secure controls and deliberately
vulnerable counterparts. It is not a sample production server.

## Safety boundary

The server listens on `127.0.0.1`. Do not expose it through port forwarding,
a tunnel, a reverse proxy, or a public network interface.

## Start

From `electron-desktop/`:

```powershell
npm run lab
```

The first line of output contains the selected HTTP and WebSocket origins.

To use a fixed port:

```powershell
$env:WSHAWK_LAB_PORT = '8765'
npm run lab
```

## Accounts

| Username | Password | Role | Owned resources |
| --- | --- | --- | --- |
| `user_a` | `user-a-lab-pass` | user | `resource-a`, `resource-a-2` |
| `user_b` | `user-b-lab-pass` | user | `resource-b`, `resource-b-2` |
| `admin` | `admin-lab-pass` | admin | all resources |

Authentication starts at `/login`. `/auth/me` returns the active identity,
`POST /auth/expire` expires it, and `POST /auth/logout` ends it.

## Attack targets

| Category | Endpoint |
| --- | --- |
| SQL injection and reflected XSS | `/scan?q=baseline` |
| Command injection | `/command?q=baseline` |
| Path traversal | `/traversal?q=baseline` |
| NoSQL injection | `POST /nosql` |
| Prototype pollution | `POST /prototype` |
| XXE | `POST /xxe` |
| SSRF/OAST | `/ssrf?url=VALUE` and `/oast-callback` |
| Open redirect | `/redirect?next=VALUE` |
| Race behavior | `POST /race` |
| DOM XSS | `/dom-xss` |
| GraphQL | `POST /graphql` |
| WebSocket echo/binary | `/ws/echo` |
| WebSocket authentication | `/ws/auth` |

## Authorization controls

Secure routes enforce the documented boundary. Routes containing
`-insecure` deliberately omit that boundary.

| Boundary | Secure | Vulnerable |
| --- | --- | --- |
| Object ownership | `/auth/resource/:id` | `/auth/resource-insecure/:id` |
| Numeric IDs | `/auth/resource-numeric/:id` | `/auth/resource-numeric-insecure/:id` |
| UUIDs | `/auth/uuid/:uuid` | `/auth/uuid-insecure/:uuid` |
| Nested account/order | `/auth/accounts/:account/orders/:order` | `/auth/accounts-insecure/:account/orders/:order` |
| Query IDs | `/auth/resource-query?account_id=:id` | `/auth/resource-query-insecure?account_id=:id` |
| JSON body IDs | `POST /auth/resource-json` | `POST /auth/resource-json-insecure` |
| Tenant isolation | `/auth/tenant/:id` | `/auth/tenant-insecure/:id` |
| Missing authentication | `/auth/missing-auth/:id` | `/auth/missing-auth-insecure/:id` |
| Vertical privilege | `/auth/admin` | `/auth/admin-insecure` |
| Function-level access | `/auth/admin-action` | `/auth/admin-action-insecure` |
| Admin-only action | `/auth/admin-operation` | `/auth/admin-operation-insecure` |
| Write IDOR | `PATCH /auth/resource/:id/note` | `PATCH /auth/resource-insecure/:id/note` |
| Ownership transfer | `POST /auth/ownership-transfer/:id` | `POST /auth/ownership-transfer-insecure/:id` |
| Mass assignment | `PATCH /auth/mass-assignment/:id` | `PATCH /auth/mass-assignment-insecure/:id` |
| WebSocket room | `/ws/room-secure` | `/ws/room-insecure` |
| WebSocket subscription | `/ws/subscription-secure` | `/ws/subscription-insecure` |

GraphQL uses the `resource` field as the secure resolver and
`resourceInsecure` as the vulnerable resolver.

State-changing routes return rollback tokens. `GET /auth/write-state/:id`
captures state and `POST /auth/rollback` restores it.

## Automated checks

```text
npm run test:parity
npm run test:parity:legacy
npm run test:e2e
npm run test:authorization-benchmark
```

`test:parity` runs the Go engine against the lab. `test:parity:legacy` compares
the Python and Go implementations against the same targets.
`test:authorization-benchmark` scores the secure and vulnerable authorization
pairs and writes reports under `audit-results/`.

Expected attack findings and timing limits are defined in
`ground-truth.json`.
