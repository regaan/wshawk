# WSHawk Electron + Go Desktop

Version 4.0.4 includes a second desktop edition built around a private Go
worker. It is released separately from the classic Electron + Python desktop so
both applications can be installed and evaluated independently.

## Choose an edition

| Edition | Backend | Release tag | Recommended use |
| --- | --- | --- | --- |
| WSHawk | Python sidecar and project services | `v4.0.4` | Existing desktop workflows, CLI integration, and compatibility |
| WSHawk Electron + Go | Private Go process over stdio JSON-RPC | `electron-go-v4.0.4` | Bridge-free desktop operation, bounded native scanning, and isolated evaluation |

The editions use different application identifiers and data directories. An
Electron + Go project does not overwrite a classic desktop project.

## Architecture

```text
Sandboxed renderer
    │ allowlisted Electron IPC
Electron main process
    │ versioned JSON-RPC over private stdin/stdout
Go worker
    ├ projects and encrypted SQLite storage
    ├ HTTP and WebSocket transports
    ├ scanners and authorization policies
    └ reports and evidence

Electron main process
    └ isolated Playwright contexts for browser evidence and auth recording
```

The worker does not expose a localhost HTTP or Socket.IO bridge. Electron keeps
Node integration disabled in the renderer and validates requests against a
versioned IPC allowlist.

## Install

Open the GitHub release named **WSHawk Electron + Go v4.0.4** and download the
package for the target system:

- Windows: NSIS `.exe`
- Linux: AppImage, `.deb`, or `.tar.gz`
- macOS: `.dmg` or `.zip`

Verify the package with `SHA256SUMS-ELECTRON-GO.txt` from the same release.

## First project

1. Start WSHawk Electron + Go.
2. Read and accept the authorized-testing notice.
3. Create a project and enter an authorized HTTP or WebSocket target.
4. Store authentication identities only when cross-account replay is required.
5. Run bounded discovery before active mutation.
6. Review findings and evidence before exporting a report.

Project records contain targets, notes, identities, sessions, HTTP flows,
WebSocket frames, protocol maps, timelines, and findings. Sensitive fields are
encrypted with AES-256-GCM. Electron protects the project key with the
operating-system secure storage service.

## Workspaces

The sidebar mode button cycles through Standard, Advanced, and Web modes.

### Standard

- project and target selection;
- WebSocket connection and traffic capture;
- sessions, protocol maps, and timelines;
- notes and report access.

### Advanced

- frame interception and replay;
- WS Forge;
- payload mutation and attack operations;
- DOM Invader and Playwright auth recording;
- authorization findings management.

### Web

- HTTP Forge and replay;
- crawler and directory discovery;
- vulnerability scanner and fuzzer;
- header, CORS, WAF, TLS, SSRF, redirect, CSRF, prototype-pollution, and
  sensitive-data checks.

## Authorization testing

HTTP Forge can test User A, User B, Admin, and anonymous access in one matrix.
Object identifiers can be discovered in URL paths, query strings, JSON bodies,
and GraphQL variables. Numeric neighbors and identifiers captured in project
traffic can be used as bounded candidates.

Available policies:

- horizontal IDOR/BOLA;
- vertical privilege escalation;
- missing authentication;
- function-level authorization/BFLA;
- admin-only operations;
- tenant isolation;
- ownership transfer.

The response analyzer handles application-level denial messages, GraphQL errors
returned with HTTP 200, partial GraphQL data, volatile timestamps and session
identifiers, and sensitive owner fields. A finding can require the same policy
failure across two or more foreign objects.

POST, PUT, PATCH, and DELETE checks start in dry-run mode. Executed writes
require an in-application confirmation. The rollback mode captures before and
after evidence, runs a cleanup request, verifies restoration, and enforces an
80-request campaign limit.

WebSocket authorization uses the same stored identities for handshake rooms,
message channels, tenant fields, subscriptions, and replayed events.

## Findings

The dedicated Findings workspace supports:

- open, confirmed, rejected, fixed, and inconclusive states;
- severity and confidence editing;
- duplicate consolidation;
- stable-ID retesting;
- sanitized evidence preview;
- explicit reveal and copy controls;
- selected JSON, Markdown, and CSV exports.

Retesting classifies a saved finding as still vulnerable, fixed,
authentication expired, endpoint changed, or inconclusive.

Evidence can store redacted bodies, response hashes only, or full bodies.
Saved authorization evidence includes sanitized requests, replay instructions,
identity expiration state, timestamps, WSHawk version, target fingerprint,
response hashes, optional screenshots, and a sanitized cURL reproduction.

## Local training lab

The repository includes a loopback-only lab with secure and deliberately
vulnerable HTTP, GraphQL, and WebSocket routes:

```powershell
cd electron-desktop
npm ci
npm run lab
```

The lab must remain on `127.0.0.1`. See the
[Electron + Go operator guide](../electron-desktop/LAB_AND_DESKTOP_GUIDE.md)
for accounts, endpoint pairs, GraphQL examples, write rollback, and WebSocket
subscription testing.

## Build from source

Requirements:

- Node.js 24 or newer;
- the Go version declared in `electron-desktop/backend-go/go.mod`;
- a supported Windows, Linux, or macOS desktop.

```powershell
cd electron-desktop
npm ci
npm run build:go
npm start
```

Validation:

```text
npm run test:all
npm run test:parity
npm run test:e2e
npm run test:authorization-benchmark
```

Platform packages:

```text
npm run dist:win
npm run dist:linux
npm run dist:mac
```

Only the command matching the host operating system should be run locally.
GitHub Actions builds all platforms on their native runners.
