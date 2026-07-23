# WSHawk Electron Desktop (Direct IPC)

This directory contains the Electron + Go desktop edition. It combines an
Electron frontend, a private Go backend, and Electron-owned Playwright browser
automation. The renderer does not depend on the localhost FastAPI/Socket.IO
bridge. The edition has its own application identity and data directory, so it
can be installed alongside the classic application under `desktop/`.

## Why Electron

- Reuses the existing componentized HTML, CSS, and JavaScript interface.
- Produces a self-contained Go worker without a Python runtime dependency.
- Keeps the current Windows, Linux, and macOS packaging knowledge.
- Supports a sandboxed renderer and narrow, validated Electron IPC surface.
- Avoids the complete UI rewrite and Java/Python interoperability layer that a
  JavaFX implementation would require.

## Target architecture

```text
Sandboxed renderer
    -> allowlisted Electron IPC
Electron main process
    -> versioned JSON-RPC over private stdin/stdout
Bundled Go worker
    -> scanner, transport, storage, evidence, and reports
Electron main process
    -> Playwright browser verification and auth recording
```

The Go worker is an implementation detail of the packaged application. It does
not open a localhost HTTP API, Socket.IO server, or bridge port. Existing Python
behavior remains the independent legacy benchmark baseline.

## Implemented capabilities

- Componentized WSHawk renderer with direct IPC and bounded worker events. The
  large UI is split across view/component and behavior modules; continued
  conversion of inherited, escaped HTML templates to DOM helper calls is a
  maintainability hardening task rather than a bridge dependency.
- Pure-Go SQLite projects with AES-256-GCM encrypted content, OS-protected key
  handoff, migrations, backups, copied-project imports,
  identities, sessions, evidence, HTTP flows and WebSocket frames.
- WebSocket TLS, headers, origins, cookies, subprotocols, text/binary capture,
  replay, interception, reconnect, probes, races and authorization checks.
- Authorization-gated HTTP and WebSocket mutation testing, injection payloads,
  AuthZ diff, subscription abuse, OAST substitution and binary analysis.
- Policy-aware authorization matrices across stored and anonymous identities,
  with a visual access grid, automatic captured/numeric/UUID object discovery,
  path/query/JSON/GraphQL object mutation, semantic denial detection,
  multi-object confirmation, redacted evidence, finding lifecycle and retest
  recipes. IDOR/BOLA, missing-authentication, tenant, vertical, BFLA,
  admin-only and ownership-transfer modes are explicit to avoid inferring
  policy from response differences alone. State-changing campaigns support
  non-transmitting dry runs or before/after/cleanup/rollback evidence.
- Dedicated Findings workspace with lifecycle, severity and confidence
  editing, fingerprint-based duplicate consolidation, retesting, protected
  reveal/copy, selected JSON/Markdown/CSV export, evidence retention limits,
  and explicit fixed/still-vulnerable/expired/changed/inconclusive outcomes.
- Playwright DOM verification, authentication record/replay, browser storage,
  cookies, screenshots, bounded timeouts and automatic cleanup.
- HTTP forge, crawling, directory scanning, headers, CORS, WAF, TLS, CSRF,
  sensitive-data, redirect, prototype, SSRF and attack-chain workflows.
- JSON, HTML, CSV and SARIF reports, integrity-verifiable evidence bundles,
  Jira, DefectDojo, webhook and certificate utilities.
- Owned web application lab, memory/cancellation/crash gates, Electron Playwright E2E and
  separate Windows, Linux and macOS packaging.

## Verification commands

```text
npm run test:all
npm run test:parity
npm run test:parity:legacy
npm run test:e2e
npm run test:authorization-benchmark
npm run dist:win
npm run dist:linux
npm run dist:mac
```

For a production-safe smoke audit of a web target with confirmed authorization,
set the explicit target and ownership gate before running the Electron
Playwright harness. The harness uses bounded same-target GET probes, limits
crawling and concurrency, checks only ports 80 and 443, and records workflows
that require OAST or state changes as limited.

```powershell
$env:WSHAWK_AUTHORIZED_TARGET='https://owned.example'
$env:WSHAWK_AUTHORIZATION_CONFIRMED='I_OWN_OR_AM_AUTHORIZED'
npm run audit:authorized-web
```

Machine-readable JSON and a Markdown assessment are written to
`audit-results/`, which is excluded from version control.

`test:authorization-benchmark` runs 34 secure/vulnerable HTTP, GraphQL and
WebSocket authorization scenarios against the loopback-owned lab and writes
JSON, Markdown, HTML and findings reports under `audit-results/`.

For the slower full unauthenticated production assessment, enable the separate
full-pentest gate. This adds passive certificate discovery, wildcard-aware DNS
enumeration, HTTP host confirmation, deeper crawling and directory discovery,
expanded active injection and redirect checks, passive service banners,
content-confirmed sensitive-path validation, and JSON/HTML/CSV/SARIF reports.

```powershell
$env:WSHAWK_AUTHORIZED_TARGET='https://owned.example'
$env:WSHAWK_AUTHORIZATION_CONFIRMED='I_OWN_OR_AM_AUTHORIZED'
$env:WSHAWK_FULL_PENTEST='YES'
npm run pentest:authorized-full
```

Full results are written to `pentest-results/`. Active state-changing tests,
authenticated authorization checks, and blind OAST confirmation still require
appropriate test accounts and controlled endpoints.

Packaging stages a platform-specific Playwright Chromium runtime. Source runs
can use `npm run prepare:browser`, a supported local Chromium installation, or
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`.

## Isolation rules

1. Do not edit or delete files under `desktop/` while building this application.
2. Use a different package name, application ID, user-data directory, build
   output directory, and test database.
3. Do not migrate or overwrite an existing WSHawk database in place.
4. Do not change current release workflows until the parity gate passes.
5. Port behavior into bounded Go packages; do not copy backend implementations
   into the renderer.
6. Keep Node integration disabled, context isolation enabled, and the Electron
   sandbox enabled.
7. Enforce the explicit IPC method allowlist, object-only parameters, protocol
   version, timeouts, and request/response byte limits. Add per-method field
   validation where a handler accepts security-sensitive input.
8. Never send secrets to renderer logs or expose unrestricted filesystem,
   process, shell, or IPC access.

## Release gates

Electron + Go packages are published only after the following gates pass:

- Functional parity tests against the same local web and WebSocket labs.
- Project, evidence, identity, export, and report compatibility tests.
- Cancellation, timeout, worker-crash, and application-shutdown tests.
- Windows, Linux, and macOS packaged smoke and lifecycle tests on their native
  runners.
- Security checks for IPC allowlists, schema validation, sandboxing, CSP, path
  traversal, secret leakage, and unsafe external navigation.
- Performance comparison with the current desktop on representative scans.

See [LAB_AND_DESKTOP_GUIDE.md](LAB_AND_DESKTOP_GUIDE.md) for installation,
workspace usage, owned-lab testing, packaging, and troubleshooting.
