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

Expected generated artifacts:

- `validation/artifacts/<lab>/result.json`
- `validation/artifacts/<lab>/evaluation.json`
- `validation/artifacts/<lab>/bundle.json`
- `validation/artifacts/summary.json`

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
