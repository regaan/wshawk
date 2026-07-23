# WSHawk Electron + Go 4.0.4 Operator Guide

This guide covers the Electron + Go desktop edition and its local security
lab. The application uses a sandboxed Electron renderer and a private Go worker
connected over standard input/output. It does not require the Python bridge or
open a local control port.

Only test systems that are owned by the operator or covered by explicit
authorization.

## Install a packaged build

Packaged Electron + Go builds are published in the GitHub release named
`WSHawk Electron + Go v4.0.4`. This release is separate from the classic
WSHawk desktop release.

Choose the package for the host operating system:

| Platform | Package |
| --- | --- |
| Windows | NSIS `.exe` installer |
| Linux | AppImage, Debian `.deb`, or `.tar.gz` |
| macOS | `.dmg` or `.zip` |

Release assets include a SHA-256 manifest. Verify the package before running
it.

## Run from source

Source development requires Node.js 24 or newer and the Go version declared in
`backend-go/go.mod`.

From `electron-desktop/`:

```powershell
npm ci
npm run build:go
npm start
```

The source command rebuilds the private Go worker before Electron starts.

## Desktop modes

The mode button at the bottom of the sidebar cycles through three workspaces:

| Mode | Main tools |
| --- | --- |
| Standard | Dashboard, WebSocket connections, traffic, sessions, projects |
| Advanced | Interceptor, WS Forge, attack operations, Findings, Blaster, DOM Invader |
| Web | HTTP Forge, crawler, directory scan, fuzzer, web scanner, headers, CORS, TLS, SSRF and related HTTP tools |

The authorization controls are split by protocol:

- HTTP and GraphQL: **Web mode → HTTP Forge**
- WebSocket rooms and subscriptions: **Advanced mode → WS Forge**
- Saved authorization results: **Advanced mode → Findings**

## Start the local lab

The lab is deliberately vulnerable and binds to `127.0.0.1` only.

From `electron-desktop/`:

```powershell
npm run lab
```

The process prints a JSON object containing the selected HTTP and WebSocket
origins. Keep the terminal open while testing.

To use port 8765 in PowerShell:

```powershell
$env:WSHAWK_LAB_PORT = '8765'
npm run lab
```

The fixed origins are then:

```text
http://127.0.0.1:8765
ws://127.0.0.1:8765/ws/echo
```

Do not publish, proxy, tunnel, or bind this lab to another network interface.

## Create a lab project

1. Start the lab and copy the printed HTTP origin.
2. Start the desktop and accept the authorized-testing notice.
3. Create a project using the lab origin as its target.
4. Open **Web mode → HTTP Forge** for HTTP and GraphQL requests.
5. Open **Advanced mode → WS Forge** for WebSocket requests.

## Disposable lab accounts

| Alias | Username | Password | Role | Owned objects |
| --- | --- | --- | --- | --- |
| User A | `user_a` | `user-a-lab-pass` | user | `resource-a` and `resource-a-2` |
| User B | `user_b` | `user-b-lab-pass` | user | `resource-b` and `resource-b-2` |
| Admin | `admin` | `admin-lab-pass` | admin | all objects |

The login page is `/login`. Sessions last one hour and include an HttpOnly
cookie, bearer token, session identifier, and CSRF token.

### Record identities

1. Set the desktop target to the printed lab origin.
2. Open **Advanced → Blaster** and select **Record Auth Flow**.
3. Enter the full `/login` URL.
4. Sign in as User A in the isolated browser window.
5. Open **WS Forge** and select **Store DOM Identity**.
6. Save the identity as `lab-user-a`.
7. Repeat for User B and Admin.
8. Replay `GET /auth/me` with each identity and confirm the username and role.

Refreshing or re-recording authentication creates a new browser capture. It
does not create a stored project identity until **Store DOM Identity** is used.

## HTTP scanner targets

| Check | Request |
| --- | --- |
| SQL injection and reflected XSS | `GET /scan?q=baseline` |
| Command injection | `GET /command?q=baseline` |
| Path traversal | `GET /traversal?q=baseline` |
| NoSQL injection | `POST /nosql` with `{"user":"guest"}` |
| Prototype pollution | `POST /prototype` with `{"user":"guest"}` |
| XXE | `POST /xxe` with `<r>baseline</r>` |
| SSRF/OAST | `GET /ssrf?url=VALUE` |
| Open redirect | `GET /redirect?next=VALUE` |
| HTTP race | `POST /race` |
| DOM-XSS evidence | `GET /dom-xss` with marker `wshawk_xss_probe` |

For the combined scanner:

1. Switch to **Web** mode.
2. Select the **Attacks** workspace.
3. Open **Vuln Scanner**.
4. Enter the full URL, for example `http://127.0.0.1:8765/scan?q=baseline`.
5. Keep `q` as the query parameter and select **Launch Scan**.

The default scan is bounded to 20 crawl pages, one crawl level, four active
workers, five-second request timeouts, and a 60-second operation budget.

## Authorization matrix

Open **Web mode → HTTP Forge**. The matrix evaluates every stored identity and
an optional anonymous request against the same objects.

1. Select User A as the primary or attacker identity.
2. Select User B as the owner/control identity.
3. Choose an authorization policy.
4. Enter the request URL, headers, and body.
5. Select the object location: path, query, JSON body, or GraphQL variable.
6. Select **Discover object IDs** or enter up to ten candidate values.
7. Keep the confirmation threshold at two foreign objects when possible.
8. Select **AuthZ Matrix**.

The result grid shows the status, semantic access state, expected policy, and
violation state for every identity/object pair.

### Authorization policies

- Horizontal IDOR/BOLA
- Vertical privilege escalation
- Missing authentication
- Function-level authorization/BFLA
- Admin-only operations
- Tenant isolation
- Ownership transfer

### Secure and vulnerable controls

| Case | Secure endpoint | Deliberately vulnerable endpoint |
| --- | --- | --- |
| Horizontal object access | `/auth/resource/resource-b` | `/auth/resource-insecure/resource-b` |
| Numeric object | `/auth/resource-numeric/2002` | `/auth/resource-numeric-insecure/2002` |
| UUID object | `/auth/uuid/22222222-2222-4222-8222-222222222222` | `/auth/uuid-insecure/22222222-2222-4222-8222-222222222222` |
| Nested account/order | `/auth/accounts/account-b/orders/order-b` | `/auth/accounts-insecure/account-b/orders/order-b` |
| Query object | `/auth/resource-query?account_id=resource-b` | `/auth/resource-query-insecure?account_id=resource-b` |
| JSON document | `POST /auth/resource-json` | `POST /auth/resource-json-insecure` |
| Tenant boundary | `/auth/tenant/resource-b` | `/auth/tenant-insecure/resource-b` |
| Missing authentication | `/auth/missing-auth/resource-b` | `/auth/missing-auth-insecure/resource-b` |
| Vertical privilege | `/auth/admin` | `/auth/admin-insecure` |
| Function-level access | `/auth/admin-action` | `/auth/admin-action-insecure` |
| Admin operation | `/auth/admin-operation` | `/auth/admin-operation-insecure` |
| Ownership transfer | `POST /auth/ownership-transfer/resource-b` | `POST /auth/ownership-transfer-insecure/resource-b` |
| Mass assignment | `PATCH /auth/mass-assignment/resource-b` | `PATCH /auth/mass-assignment-insecure/resource-b` |

## GraphQL authorization

GraphQL uses the HTTP authorization matrix. Send this request to `/graphql`:

```json
{
  "query": "query($id: ID!) { resourceInsecure(id: $id) { id owner secret } }",
  "variables": {
    "id": "resource-b"
  }
}
```

Set:

- Object location: **GraphQL variable**
- Object field: `id`
- Candidates: `resource-b` and `resource-b-2`
- Policy: **Horizontal IDOR/BOLA**
- Minimum confirmations: `2`

Use `resource` for the secure control and `resourceInsecure` for the
deliberately vulnerable control. GraphQL HTTP 200 responses containing errors
are treated as denied unless usable partial data is also returned.

## Safe write testing

POST, PUT, PATCH, and DELETE matrices start in dry-run mode. Dry-run records the
planned cases without transmitting the state-changing requests.

Execution requires:

1. Enabling the bounded write-operation checkbox.
2. Accepting the in-application confirmation dialog.
3. Selecting **execute** or **execute + verify + rollback**.

Rollback mode requires before, after, and cleanup request templates. The lab
returns a `rollback_token` that can be inserted into the cleanup body as
`{{rollback_token}}`. Restoration is verified against the before response.
The full campaign is capped at 80 network requests.

## WebSocket authorization

Open **Advanced mode → WS Forge** and load the stored identities.

| Test | Endpoint |
| --- | --- |
| Echo and binary frames | `/ws/echo` |
| Authenticated handshake | `/ws/auth` |
| Secure room | `/ws/room-secure?room=user_b` |
| Vulnerable room | `/ws/room-insecure?room=user_b` |
| Secure subscription | `/ws/subscription-secure` |
| Vulnerable subscription | `/ws/subscription-insecure` |

For subscriptions, use a JSON payload such as:

```json
{"action":"subscribe","room":"user_b"}
```

The matrix can mutate `room`, `channel`, or `tenant` and replay the event under
User A, User B, Admin, and anonymous contexts.

## Findings and evidence

Open **Advanced mode → Findings** to:

- set open, confirmed, rejected, fixed, or inconclusive state;
- edit severity and confidence;
- review duplicate counts;
- retest a saved authorization recipe;
- preview sanitized evidence;
- explicitly reveal and copy retained bodies;
- export selected findings as JSON, Markdown, or CSV.

Evidence supports redacted, hash-only, and full-body modes. Redacted mode is the
default. Project content is encrypted at rest with AES-256-GCM; Electron keeps
the project key in operating-system protected storage.

## Validation commands

Run these commands from `electron-desktop/`:

```text
npm run test:all
npm run test:parity
npm run test:parity:legacy
npm run test:e2e
npm run test:authorization-benchmark
```

The authorization benchmark runs 34 secure/vulnerable scenarios across HTTP,
GraphQL, and WebSocket controls.

## Build packages

Run only the command for the current operating system:

```text
npm run dist:win
npm run dist:linux
npm run dist:mac
```

The build stages a platform-specific Go worker and Playwright Chromium runtime.
Generated packages are written to `dist-electron-go/`.

## Troubleshooting

| Problem | Resolution |
| --- | --- |
| Browser runtime missing | Run `npm run prepare:browser` or set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` |
| Worker fails to start | Run `npm run build:go` and `npm run smoke:worker` |
| Lab request fails | Confirm the printed port and keep the lab terminal running |
| Stored identity returns 401 | Re-record the login and store the replacement identity |
| Installed app lacks new controls | Install the Electron + Go 4.0.4 release or run the current source |
