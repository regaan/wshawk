# WSHawk Validation Gate

This checklist is the release gate for operator-facing validation.

## Scope

These checks confirm that:

- the desktop workflow can capture and reuse identities
- HTTP and WebSocket replay are working against a real local target
- authz drift is visible and reproducible
- race behavior is captured and exported as evidence
- exported artifacts are redacted and categorized correctly

## Primary Lab

Run the full-stack lab:

```bash
./venv/bin/python -m uvicorn validation.full_stack_realtime_saas.app:app --host 127.0.0.1 --port 8010
```

## Manual Desktop Checklist

### Project bootstrap

- Create a new WSHawk project.
- Save the project once.
- Restart WSHawk.
- Reload the same project and confirm the project opens cleanly.

### Identity capture

- Record and store:
  - `alice / alice123`
  - `mallory / mallory123`
  - `bob / bob123`
  - `brenda / brenda123`
- Confirm identities appear in:
  - Request Forge
  - HTTP Forge

### WebSocket validation

- Run `{"action":"whoami"}` as Alice and confirm tenant-alpha identity.
- Run `{"action":"subscribe_invoice","invoice_id":"inv-beta-9001"}` as Alice and confirm cross-tenant invoice exposure.
- Run `{"action":"list_team_messages","tenant_id":"tenant-beta"}` as Alice and confirm cross-tenant message exposure.
- Run `{"action":"approve_refund","invoice_id":"inv-beta-9001","reason":"no token"}` with `AuthZ Diff` and confirm:
  - Brenda succeeds
  - Alice, Mallory, and Bob fail
- Run `{"action":"approve_refund","invoice_id":"inv-beta-9001","approval_token":"approve-beta-9001","reason":"ws replay"}` as Alice and confirm replay success.
- Run `Race Attack` with that replay body and confirm duplicate success.

### HTTP validation

- `GET /api/profile` as Alice and confirm baseline identity.
- `GET /api/invoices` as Alice and confirm only alpha invoices are returned.
- `GET /api/invoices/inv-beta-9001?preview=true` as Alice and confirm cross-tenant exposure plus approval token.
- `POST /api/invoices/inv-beta-9001/refund` with body `{"reason":"http no token"}` and confirm app-level `403`.
- Run `HTTP AuthZ Diff` on the no-token POST and confirm:
  - Brenda succeeds
  - Alice, Mallory, and Bob fail
- Run HTTP replay with body `{"reason":"http replay","approval_token":"approve-beta-9001"}` as Alice and confirm replay success.
- Run HTTP race with that replay body and confirm duplicate success.

### Evidence/export

- Export JSON from Evidence Vault.
- Confirm the bundle includes:
  - `http_authz_diff`
  - `http_data_exposure`
  - `http_token_replay`
  - `http_race`
  - `websocket_authz_diff`
  - `websocket_data_exposure`
  - `websocket_token_replay`
  - `websocket_race`
- Confirm approval tokens, cookies, and API keys are redacted.

## Automated Validation

Run:

```bash
./venv/bin/python validation/run_validation.py
```

This writes artifacts under `validation/artifacts/` and compares each lab result with the expected baseline in `validation/expected/`.
Expected checks are evaluated against the raw in-memory scenario result. Before any JSON is written, the runner recursively
redacts approval/authentication tokens, authorization and cookie values, API keys, session material, passwords, and secrets.
Copies embedded in free text or sensitive URL query parameters are replaced with `[REDACTED]` as well.

Expected generated artifacts:

- `validation/artifacts/<lab>/result.json`
- `validation/artifacts/<lab>/evaluation.json`
- `validation/artifacts/<lab>/bundle.json`
- `validation/artifacts/summary.json`

Each bundle includes `redaction.applied: true` and the marker used for persisted secret values. A raw secret in any generated
artifact is a release-gate failure even when all behavioral checks pass.

### Attack engine benchmarks

Run the web, raw WebSocket, and paired vulnerable/hardened attack implementations against deterministic localhost targets:

```bash
./venv/bin/python validation/run_validation.py web_attack_benchmark websocket_attack_benchmark industry_security_controls_benchmark
```

The web benchmark covers discovery, fuzzing, directory scanning, headers, CORS, fingerprinting, sensitive-data detection,
redirects, SSRF with a false-positive control, prototype pollution, WAF detection, CSRF replay, a targeted port scan, and
stateful HTTP replay/AuthZ/race services. The WebSocket benchmark covers welcome-frame handling, application error scoring,
replay, AuthZ diffing, subscription mutation, concurrent race waves, and Origin-policy observation. The paired industry lab
checks that WSHawk distinguishes deliberately vulnerable controls from hardened controls across HTTP and WebSocket paths.

For repeatable warm-up, iteration, percentile, and regression-threshold measurements, run:

```bash
./venv/bin/python -m benchmarks.run --iterations 3 --warmup 1
```

See `benchmarks/README.md` for the method and `docs/ATTACK_IMPLEMENTATION_AUDIT.md` for the coverage and limitation matrix.

### Desktop end-to-end security target

Start the paired 26-case HTTP/WebSocket target before running desktop UI automation:

```bash
./venv/bin/python -m benchmarks.desktop_security_lab.server --ready-file build/desktop-security-lab.json
```

The ready file provides ephemeral loopback URLs for the vulnerable and hardened profiles. The lab ground truth is available at
`/lab/ground-truth`, and `POST /lab/reset` resets state between benchmark iterations. See
`benchmarks/desktop_security_lab/README.md` for fixtures and safety rules. This command starts the target only; it does not yet
drive the Electron interface.

## Secondary Protocol Labs

- Socket.IO protocol coverage:

```bash
./venv/bin/python -m uvicorn validation.socketio_saas.app:app --host 127.0.0.1 --port 8011
```

Confirm:

- Socket.IO connect succeeds with bearer auth
- foreign tenant order data is exposed
- foreign tenant room messages are exposed
- refund without approval token is denied
- refund with leaked approval token succeeds

- GraphQL subscriptions protocol coverage:

```bash
./venv/bin/python -m uvicorn validation.graphql_subscriptions_lab.app:app --host 127.0.0.1 --port 8012
```

Confirm:

- `connection_ack` is received after `connection_init`
- foreign tenant invoice subscription data is exposed
- foreign tenant message subscription data is exposed
- refund without approval token is denied
- refund with leaked approval token succeeds
