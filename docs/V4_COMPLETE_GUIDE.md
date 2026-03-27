# WSHawk v4 — Complete Guide
## Architecture, Workflows, Configuration, and Validation

---

## Table of Contents

1. [Overview](#overview)
2. [What v4 Is](#what-v4-is)
3. [Current Architecture](#current-architecture)
4. [Interfaces and Entry Points](#interfaces-and-entry-points)
5. [Project-Backed Workflow Model](#project-backed-workflow-model)
6. [WebSocket Security Testing](#websocket-security-testing)
7. [Web Application Pentest Workflows](#web-application-pentest-workflows)
8. [Sessions, Identities, and Browser Capture](#sessions-identities-and-browser-capture)
9. [Evidence, Exports, and Integrity](#evidence-exports-and-integrity)
10. [Validation Labs](#validation-labs)
11. [Configuration](#configuration)
12. [Integrations](#integrations)
13. [Installation, Packaging, and Release Flow](#installation-packaging-and-release-flow)
14. [Security Model](#security-model)
15. [Troubleshooting](#troubleshooting)

---

## Overview

WSHawk v4 is a local offensive security platform for authorized testing of:

- WebSocket applications
- stateful HTTP workflows
- browser-authenticated sessions
- replayable authorization flaws
- race conditions
- realtime application evidence collection

The repository now contains both:

- legacy scanner and CLI surfaces that remain available for compatibility
- newer platform layers that back the desktop, project store, replay services, and evidence workflows

If you want the shortest honest summary of v4, it is this:

WSHawk is no longer just a WebSocket scanner. It is a project-backed local platform for replay, diffing, race testing, browser capture, and evidence-driven web application operations.

---

## What v4 Is

The v4 line is centered on structured local projects rather than disposable sessions.

### Main v4 Characteristics

- local daemon with route groups for platform, transport, system, scan, and web operations
- desktop app as the primary operator interface
- browser companion for scoped handshake capture
- identity vault and browser replay helpers
- HTTP and WebSocket replay services
- AuthZ diff and race workflows
- evidence bundle export with integrity metadata
- local validation labs for realtime application scenarios

### What Stayed Legacy

The base CLI entry points still exist, but the top-level `wshawk` and `wshawk-advanced` commands are compatibility wrappers around the older scanner path:

- `wshawk.__main__` delegates to `wshawk.legacy_core`
- `wshawk.advanced_cli` delegates to `wshawk.legacy_advanced_cli`

That matters because the most complete v4 experience is not the old standalone CLI path. It is the desktop plus local daemon plus project-backed services.

---

## Current Architecture

WSHawk v4 is organized around a local runtime with clear service groups.

### Primary Runtime Layers

| Layer | Main Paths | Purpose |
|---|---|---|
| **Desktop** | `desktop/` | Electron operator interface |
| **Bridge / Daemon** | `wshawk/gui_bridge.py`, `wshawk/daemon/` | Loopback HTTP and Socket.IO service layer |
| **Transport** | `wshawk/transport/` | HTTP and WebSocket proxying and traffic capture |
| **Session** | `wshawk/session/` | browser capture, replay, and identity vault services |
| **Attacks** | `wshawk/attacks/` | replay, AuthZ diff, race, subscription abuse, workflows |
| **Protocol** | `wshawk/protocol/` | protocol graphing, inference, target packs, templates |
| **Store** | `wshawk/store/`, `wshawk/db_manager.py` | local project-backed persistence |
| **Evidence** | `wshawk/evidence/` | bundles, timeline, export, redaction, integrity |
| **Web Pentest** | `wshawk/web_pentest/` | crawler, fuzzer, recon, SSRF, CORS, redirects, and related tooling |
| **Validation** | `validation/` | local benchmark labs and expected baselines |

### Daemon Route Groups

The daemon is split by route responsibility instead of being one monolithic API surface.

| Route Group | File | Purpose |
|---|---|---|
| **Platform** | `wshawk/daemon/platform_routes.py` | projects, identities, replay, attacks, events, evidence, exports |
| **Transport** | `wshawk/daemon/transport_routes.py` | extension ingestion, DOM tooling, interceptor operations |
| **System** | `wshawk/daemon/system_routes.py` | status, config, pairing status, extension reset |
| **Scan** | `wshawk/daemon/scan_routes.py` | WebSocket scan lifecycle |
| **Web** | `wshawk/daemon/web_routes.py` | HTTP/web-pentest tools and reporting |

### Why the Split Matters

This layout makes the v4 platform easier to reason about:

- scan routes handle scanning
- platform routes handle structured offensive workflows
- transport routes handle capture and interceptor-adjacent operations
- evidence routes stay tied to project records instead of scattered export code

### Desktop as the Primary v4 Frontend

The desktop app is not just a GUI shell. It is where v4 features are most visible:

- projects
- identities
- replay and diff actions
- race controls
- evidence review
- web pentest workspaces
- browser companion pairing flow

For desktop-specific detail, see [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md).

---

## Interfaces and Entry Points

WSHawk v4 exposes several ways to work with the platform.

### CLI Entry Points

| Command | Purpose |
|---|---|
| `wshawk` | compatibility scanner CLI |
| `wshawk-interactive` | interactive terminal workflow |
| `wshawk-advanced` | compatibility advanced CLI |
| `wshawk-defensive` | defensive validation CLI |

### Desktop

The desktop app lives in `desktop/` and is the most complete v4 operator interface.

Run from source:

```bash
cd desktop
npm install
npm start
```

Lightweight smoke check:

```bash
cd desktop
npm run smoke
```

### Browser Companion

The extension in `extension/` pairs with the local bridge and captures scoped WebSocket handshake context for project-backed identity workflows.

### Web Dashboard

The repository still includes web dashboard surfaces. Some parts of that path are older than the newer platform-backed desktop model, but they remain useful for report viewing, scanner history, and browser-based access in local environments.

### Validation Runner

The local validation harness is in `validation/run_validation.py`.

List available labs:

```bash
./venv/bin/python validation/run_validation.py --list
```

Run all labs:

```bash
./venv/bin/python validation/run_validation.py
```

---

## Project-Backed Workflow Model

This is the biggest conceptual change in v4.

### What a Project Represents

A project is the local unit of work for an operation or assessment. It can hold:

- target metadata
- identities
- targets
- findings
- notes
- events
- evidence
- HTTP flows
- WebSocket connections and frames
- attack runs
- browser artifacts
- export bundles

### Why That Matters

Instead of treating each action as isolated, v4 lets you tie related work together:

1. capture a handshake
2. store an identity
3. replay an action
4. diff behavior across identities
5. run a race
6. review evidence in one place
7. export a bundle

### Project APIs

Core platform routes include:

- `/platform/projects`
- `/platform/projects/{project_id}`
- `/platform/projects/{project_id}/identities`
- `/platform/projects/{project_id}/findings`
- `/platform/projects/{project_id}/events`
- `/platform/projects/{project_id}/evidence`
- `/platform/projects/{project_id}/exports/{fmt}`
- `/platform/exports/verify`

### Desktop Projects vs Platform Projects

There are two related but distinct storage concepts:

- `.wshawk` files for desktop state save and reopen
- structured platform project data in the local store and database

The desktop can sync and reuse both.

---

## WebSocket Security Testing

WebSocket testing remains the core protocol focus of the project.

### Main Capabilities

- stateful connection handling
- async response analysis
- handshake-aware replay
- stored identity-backed header replay
- WebSocket race testing
- protocol-guided workflow execution
- subscription abuse flows
- interceptor-backed manual tampering

### Scanner Path

The legacy and compatibility scanner surfaces still cover:

- SQL injection
- XSS-oriented payload testing
- command injection
- XXE
- SSRF
- NoSQL injection
- path traversal / local file indicators

Smart Payload Evolution is still part of the scanning model, but in v4 the scanner is only one part of the larger workflow.

### Replay Services

The replay services in `wshawk/attacks/replay.py` and `wshawk/attacks/common.py` support controlled WebSocket action reproduction with:

- explicit target URL
- optional stored identity
- header overrides
- structured result recording

### AuthZ Diff

The WebSocket AuthZ diff workflow compares behavior across stored identities and groups differences for operator review. This is useful for cross-tenant and cross-role exposure testing where the same action should behave differently depending on the identity used.

### Race Testing

The WebSocket race service focuses on state-changing actions that may be vulnerable to duplicate execution, stale token reuse, or timing windows around invalidation.

### Subscription Abuse

The subscription abuse service is aimed at realtime subscription-style targets where data access may change depending on topic, tenant, or identity context.

### Manual Operator Flow

A typical WebSocket v4 workflow looks like this:

1. create or link a project
2. capture or build an identity
3. replay a known action
4. diff it across identities
5. race it if the action changes state
6. review resulting evidence

---

## Web Application Pentest Workflows

v4 is not limited to WebSockets. The web pentest side of the platform shares the same project and evidence model.

### Main HTTP Capabilities

The `wshawk/web_pentest/` package includes tooling for:

- crawling
- request fuzzing
- directory scanning
- security header analysis
- technology fingerprinting
- subdomain discovery
- TLS inspection
- sensitive data detection
- WAF detection
- CORS testing
- SSRF probing
- open redirect scanning
- prototype pollution testing
- CSRF proof generation
- chained attack flows

### HTTP Replay and Diffing

The HTTP attack services in `wshawk/attacks/http_replay.py`, `wshawk/attacks/http_authz_diff.py`, and `wshawk/attacks/http_race.py` let the platform treat HTTP requests the same way it treats WebSocket actions:

- replay with a stored identity
- compare behavior across identities
- race state-changing requests

### Why This Matters

Modern targets often split the workflow between:

- browser-authenticated HTTP endpoints
- realtime sockets
- shared CSRF or session state

v4 is designed to keep those parts in the same local operation record rather than forcing you to jump between unrelated tools.

### Web Pentest in the Desktop

The desktop exposes this through:

- Discovery
- Requests
- Attacks
- Evidence

That layout is documented in more detail in [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md).

---

## Sessions, Identities, and Browser Capture

The session and identity layer is a major part of the v4 platform.

### Identity Vault

The identity vault in `wshawk/session/vault.py` stores project-scoped identities with material such as:

- cookies
- headers
- tokens
- browser storage snapshots
- alias and lineage information

These identities can then be reused across replay, AuthZ diff, and race workflows.

### Browser Capture and Replay

Session-related helpers include:

- `wshawk/session/browser_capture.py`
- `wshawk/session/replay.py`

These support browser-assisted collection and replay logic where browser state matters to the operation.

### Browser Companion

The extension uses explicit session pairing and scoped capture.

Current extension flow:

1. pair to the local bridge
2. restrict capture to configured domains
3. ingest handshake context through the extension route
4. attach captured material to a project and identity flow

This is intentionally more constrained than a raw unrestricted browser interceptor.

### DOM / Browser-Assisted Testing

Transport routes also expose DOM-related actions for:

- browser-assisted payload verification
- auth recording
- auth replay

Those helpers are useful for targets that require browser state to mint or refresh valid application credentials.

---

## Evidence, Exports, and Integrity

The evidence system is one of the most important v4 additions.

### Evidence Layers

The evidence subsystem includes:

- `wshawk/evidence/bundles.py`
- `wshawk/evidence/timeline.py`
- `wshawk/evidence/redaction.py`
- `wshawk/evidence/exporters.py`
- `wshawk/evidence/integrity.py`

### What the Evidence Bundle Contains

A project bundle can include:

- project metadata
- findings
- evidence items
- notes
- events
- attack runs
- HTTP flows
- WebSocket connections
- WebSocket frames
- replay recipes
- protocol map context

### Export Formats

Structured project bundle export currently supports:

- `json`
- `markdown`
- `html`

Other reporting paths in the repository also support:

- HTML
- PDF
- CSV
- SARIF

### Integrity and Provenance

The v4 export path adds integrity metadata and verification support so exported bundles are not just loose notes. The goal is to make later review easier and make tampering easier to detect.

Use the verification route:

- `/platform/exports/verify`

### Redaction

The evidence path also includes redaction helpers so exports can be sanitized before wider sharing, even when the underlying local project contains sensitive operator material.

---

## Validation Labs

WSHawk ships with local validation labs instead of relying only on anecdotal examples.

### Available Labs

| Lab | Purpose |
|---|---|
| `full_stack_realtime_saas` | full-stack realtime app behaviors and cross-tenant / replay style checks |
| `socketio_saas` | Socket.IO-specific realtime workflow coverage |
| `graphql_subscriptions_lab` | GraphQL subscription-style realtime testing |

### Files

Key validation paths:

- `validation/run_validation.py`
- `validation/expected/`
- `validation/full_stack_realtime_saas/`
- `validation/socketio_saas/`
- `validation/graphql_subscriptions_lab/`

### Why the Labs Matter

They provide:

- repeatable local regression checks
- expected baselines
- a way to validate replay, diff, race, and evidence behaviors after refactors

### Typical Validation Run

```bash
./venv/bin/python validation/run_validation.py
```

Artifacts are written under `validation/artifacts/` during execution. Those outputs are runtime artifacts and usually should not be committed.

---

## Configuration

WSHawk uses YAML configuration with environment overrides.

### Main Config Entry

Generate a sample config:

```bash
python3 -m wshawk.config --generate
```

Common search paths include:

- `./wshawk.yaml`
- `./wshawk.yml`
- `~/.wshawk/config.yaml`
- `~/.wshawk/config.yml`
- `/etc/wshawk/config.yaml`

### Configuration Areas

| Section | Purpose |
|---|---|
| `scanner` | rate limits, timeout, payload count, SSL verification, scanner features |
| `ai` | optional local or external payload-assist settings |
| `reporting` | output directory and report formats |
| `integrations` | Jira, DefectDojo, webhook settings |
| `web` | host, port, auth, database |

### Defaults That Matter in v4

- `scanner.verify_ssl` defaults to `True`
- desktop and daemon secrets resolve through the secret backend instead of plaintext config exposure
- bridge and extension pairing settings are managed by the local runtime rather than only static config

### Secret Resolution

The config manager resolves secret references rather than requiring cleartext in the YAML. The platform secret backend supports environment-style and secret-store-backed resolution paths.

---

## Integrations

WSHawk supports several workflow integrations.

### Supported Integration Paths

- Jira
- DefectDojo
- generic webhooks

### Typical Uses

- push findings to Jira
- import findings into DefectDojo
- send notifications through Slack, Discord, Teams, or generic webhook endpoints

### Important Practical Note

Integrations are useful for workflow handoff, but the strongest v4 evidence path is still the local project bundle because that is where replay context, identities, notes, and timeline data stay together.

---

## Installation, Packaging, and Release Flow

### Python Install

```bash
pip install wshawk
```

### Source Install

```bash
git clone https://github.com/regaan/wshawk
cd wshawk
pip install -e .
```

### Desktop Build

```bash
pip install pyinstaller
pyinstaller wshawk-bridge.spec
cd desktop
npm install
npm run dist
```

### Desktop Targets

The desktop package configuration covers:

- Linux
- Windows
- macOS

### Release Security Checks

The repository also includes a local release checker:

```bash
./venv/bin/python scripts/release_security_checks.py
```

That check helps review dependency inventory, packaged asset expectations, and release metadata before publishing artifacts.

---

## Security Model

v4 is an offensive tool, but the platform still has to protect its own local trust boundaries.

### Main Security Decisions in the Current Platform

- Electron renderer isolation and sandboxing are enabled for the desktop runtime
- desktop and extension trust paths are separated
- browser companion access uses explicit pairing and scoped capture
- secrets and local encryption keys go through a platform-aware secret backend
- project exports include integrity metadata
- extension ingestion is narrower than the general desktop bridge path

### What to Keep in Mind Operationally

- treat local project data as sensitive
- keep validation artifacts, runtime caches, and local secret stores out of source control
- use official or controlled package sources
- prefer scoped browser capture over broad indiscriminate capture

---

## Troubleshooting

### The Desktop Starts but the Bridge Never Comes Online

Check:

- Python dependencies are installed
- the bridge port is free
- the bundled sidecar exists if using a packaged desktop build

Fast check:

```bash
cd desktop
npm run smoke
```

### The Browser Companion Does Not Pair

Check:

- the desktop app is already running
- auto-detect is enabled or the bridge URL is correct
- capture domains are configured
- the extension is trying to pair against a local bridge, not a remote host

### Replay or Diff Flows Show No Useful Results

Check:

- the correct project is linked
- identities were actually stored
- the request or payload depends on a variable you did not supply
- the target needs a fresh browser-backed token set

### Validation Labs Fail After Refactoring

Run the specific lab directly and inspect:

- `validation/expected/*.json`
- `validation/artifacts/<lab>/result.json`
- `validation/artifacts/<lab>/evaluation.json`

### Which Guide Should I Read First

Use this guide for platform shape and current v4 concepts. Use the desktop guide for operator workflow:

- [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md)

---

**WSHawk v4** is best understood as a local project-backed offensive platform for web and realtime application operations, with the desktop app as the main operator surface and the validation labs as the main regression proof path.
