# WSHawk Desktop v4 — Full Feature Guide

> **Version 4.0.0** · Author: Regaan ([@regaan](https://github.com/regaan))
> Practical guide for using the WSHawk desktop app for WebSocket testing, web pentesting, replay, AuthZ diffing, race testing, and evidence collection.

---

## Table of Contents

1. [Overview](#overview)
2. [What Changed in v4](#what-changed-in-v4)
3. [Installation & Launch](#installation--launch)
4. [Desktop Layout](#desktop-layout)
5. [Projects & Persistence](#projects--persistence)
6. [Standard Mode](#standard-mode)
7. [Advanced Mode](#advanced-mode)
8. [Web Pentest Mode](#web-pentest-mode)
9. [Browser Companion & Identity Capture](#browser-companion--identity-capture)
10. [Evidence Vault & Exports](#evidence-vault--exports)
11. [Security Model](#security-model)
12. [Keyboard Shortcuts](#keyboard-shortcuts)
13. [Troubleshooting](#troubleshooting)

---

## Overview

WSHawk Desktop is the main operator interface for the project. It wraps the local Python sidecar in an Electron application and gives you one place to manage:

- WebSocket scanning
- live interception and traffic review
- project-backed HTTP and WebSocket replay
- identity capture and cross-identity comparison
- race testing
- evidence review and bundle export
- desktop web pentest tooling

The desktop app is intended for authorized manual assessments where you need more than a one-shot CLI scan. v4 shifts the focus from one-off sessions to reusable local projects that keep identities, traffic, findings, notes, and exports together.

### Core Capabilities

- WebSocket dashboard, heuristic scan, and activity stream
- Request Forge with replay, AuthZ diff, and race controls
- Payload Blaster for repeated WebSocket payload execution
- Interceptor for frame-by-frame capture, forwarding, dropping, and editing
- Endpoint map, Auth Builder, Mutation Lab, Scheduler, Codec, Comparer, and Notes
- Web Pentest workspace with discovery, request, attack, and evidence flows
- Project-backed evidence timeline and tamper-evident export bundles

---

## What Changed in v4

The v4 desktop is not just a skin refresh over the older desktop guide. The main changes are architectural and workflow-oriented:

- Projects are first-class and backed by the platform store
- identities are reusable across HTTP and WebSocket workflows
- replay, AuthZ diff, and race actions write into the same evidence trail
- browser companion capture is session-paired and scope-limited
- evidence exports now include provenance and integrity metadata
- the desktop runtime is sandboxed more aggressively than the older builds

If you used the v3 desktop, the main mental shift is this:

1. create or open a project
2. capture or build identities
3. replay and compare stateful actions
4. review evidence and export a bundle

---

## Installation & Launch

### Requirements

- Python `3.8+`
- Node.js `18+`
- npm
- Playwright Chromium if you want browser-assisted XSS evidence collection

### Run from Source

```bash
git clone https://github.com/regaan/wshawk
cd wshawk
pip install -e .
cd desktop
npm install
npm start
```

### Optional Browser Runtime

```bash
playwright install chromium
```

### Lightweight Desktop Sanity Check

```bash
cd desktop
npm run smoke
```

This smoke run is lighter than a full headless E2E pass. It validates that the desktop window loads, the preload bridge is available, and the local sidecar becomes ready.

### Packaged Builds

The repository also supports packaged desktop builds for Linux, Windows, and macOS through `electron-builder`. Packaged builds still rely on the bundled Python sidecar resource.

---

## Desktop Layout

The app opens with a welcome overlay:

- `Create New Project`
- `Open Existing Project`

After the project is loaded, the desktop is split into:

- title bar with mode badge
- left navigation for tools and workspaces
- main content area for the active tool
- status widgets, logs, findings, and traffic panes depending on the view

### Main Navigation Areas

| Area | Purpose |
|---|---|
| **Overview** | Dashboard and scan history |
| **Advanced Tools** | Interceptor, Request Forge, Attack Ops, Payload Blaster, utilities, and Evidence Vault |
| **Web Pentest** | Discovery, Requests, Attacks, and Evidence workspaces plus HTTP tooling |

### Operating Modes

| Mode | Best For |
|---|---|
| **Standard** | Starting a target, scanning, and reading results |
| **Advanced** | Manual WebSocket operations, interception, replay, and evidence work |
| **Web Pentest** | HTTP workflows tied to the same project and identities |

---

## Projects & Persistence

Projects are central in the v4 desktop.

### What a Project Stores

- target URL
- local findings shown in the desktop
- system log history
- traffic rows and captured payloads
- linked platform project ID
- stored identities
- notes
- attack runs
- evidence records

### Project Files

Desktop project files are saved locally as `.wshawk` files. They are intended for saving and reopening desktop state safely.

Typical flow:

1. open the desktop
2. choose `Create New Project`
3. set the target URL
4. run a scan, capture traffic, or link a request workflow
5. press `Ctrl+S` or the save button to write a `.wshawk` file

### Platform-Backed Project Sync

Many advanced actions also ensure a local platform project behind the scenes. That project is where HTTP and WebSocket evidence, identities, and replay artifacts are stored for deeper workflows.

In practice:

- light desktop state is saved to the `.wshawk` file
- structured offensive workflow data is saved into the local project store

---

## Standard Mode

Standard mode is the fastest way to get from a target URL to a first set of findings.

### Dashboard

Use the dashboard to:

- set the target WebSocket URL
- launch the main scan
- watch vulnerability count and message count
- review live findings
- inspect the system log

Standard mode is the right choice when you want:

- initial WebSocket exposure mapping
- basic vulnerability discovery
- fast triage before moving into replay or interception

### Scan History

The scan history view is for reviewing previous local runs. It helps when you want to compare behavior over time or return to a target later without starting from zero.

### Recommended Standard Workflow

1. create a project
2. enter the WebSocket target URL
3. run the scan
4. review findings and traffic
5. move to Request Forge or Interceptor if the target looks stateful

---

## Advanced Mode

Advanced mode is where the desktop becomes an operator tool instead of just a scanner UI.

### Activity History

Use this view to inspect captured frame history and review request or response content in order.

### Interceptor

The interceptor is for live WebSocket manipulation.

Use it when you want to:

- inspect frames as they pass through
- drop or forward selected messages
- edit payloads before they hit the target
- observe server-side reactions in near real time

This is the right tool for protocol tampering, message sequencing checks, and workflow abuse testing that needs live control.

### Request Forge

Request Forge is the main workspace for manual WebSocket operations.

Key actions:

- send crafted messages
- replay captured actions
- select a stored identity or stay anonymous
- run `AuthZ Diff`
- run `Race Attack`
- store a DOM-captured identity into the current project

Use Request Forge when you want to turn captured behavior into a repeatable operation.

### Attack Ops

Attack Ops collects project-backed offensive workflows and results. It is the place to review and organize replay-heavy work after you start using identities, AuthZ diffing, or race testing.

### Payload Blaster

Payload Blaster is the high-volume WebSocket fuzzing surface in the desktop.

Use it when you want:

- repeated payload execution
- category-driven payload selection
- Smart Payload Evolution during longer runs
- browser-assisted evidence collection when applicable

This is stronger than a single scan when the target requires repetition, timing pressure, or repeated protocol interaction.

### Endpoint Map

Endpoint Map helps with WebSocket surface discovery. It is useful when the target application hides socket endpoints behind front-end flows, generated scripts, or non-obvious upgrade paths.

### Auth Builder

Auth Builder helps you define multi-step authentication sequences with value extraction and substitution. Use it when a target requires:

- login before socket connection
- token refresh before replay
- multi-step bootstrap to obtain cookies or bearer tokens

### Mutation Lab

Mutation Lab is for experimenting with payload transformations and bypass ideas before feeding them into a more structured attack workflow.

### Scheduler

Use the scheduler for delayed or repeated task execution when you want to stage a test without constantly re-triggering it manually.

### Codec

Codec is the utility view for encoding and decoding content during analysis.

### Comparer

Comparer is useful when you need to line up two payloads, two responses, or two workflow states and spot drift quickly.

### Notes

Use notes to keep target-specific observations in the same project instead of scattering them across external files.

### Evidence Vault

Evidence Vault is the review layer for structured project evidence. It shows recorded evidence items, replay recipes, and project summary information generated from attacks and findings.

---

## Web Pentest Mode

Web Pentest mode extends the same project into HTTP-focused work. The important difference in v4 is that this is not a separate app inside the desktop. It shares:

- the current project
- stored identities
- evidence output
- request templates
- notes and findings context

### Workspace Switcher

The web workspace is split into four top-level boards:

| Workspace | Purpose |
|---|---|
| **Discovery** | Map targets, surface area, and reusable context |
| **Requests** | Build HTTP templates and run replay operations |
| **Attacks** | Run active HTTP abuse workflows such as AuthZ diff and race |
| **Evidence** | Review project evidence generated by HTTP workflows |

### Discovery Workspace

Use Discovery to bootstrap a target:

- crawl the application
- find endpoints
- analyze headers
- identify technologies
- inspect TLS posture
- gather inputs for later replay

This workspace is also where project telemetry becomes reusable intelligence instead of just one-off scan output.

### Requests Workspace

The Requests workspace is centered on HTTP Forge and replay templates.

Typical use:

1. build or paste a request
2. attach a stored identity if needed
3. create a replay template
4. inject variables such as CSRF or workflow tokens
5. replay the request against the target

### Attacks Workspace

The Attacks workspace is where stateful HTTP abuse happens.

Key actions:

- `Replay`
- `AuthZ Diff`
- `Race`

These actions are project-aware and can reuse stored identities to compare target behavior across tenants, roles, or sessions.

### Main HTTP Tools

The desktop exposes a larger web pentest toolbox. The most important operator-facing tools are:

- Web Crawler
- HTTP Fuzzer
- Dir Scanner
- Header Analyzer
- Subdomain Finder
- SSL/TLS Analyzer
- Tech Fingerprint
- Sensitive Finder
- Port Scanner
- DNS / WHOIS
- WAF Detector
- CORS Tester
- SSRF Prober
- Redirect Hunter
- Proto Polluter
- CSRF Forge
- Attack Chainer
- Proxy CA
- Reports

### Suggested HTTP Workflow

1. create or sync a project
2. run discovery against the target origin
3. build a useful request in HTTP Forge
4. save or reuse an identity
5. replay the request
6. run AuthZ diff across at least two identities
7. run race mode if the route changes state
8. review Evidence and export a bundle

---

## Browser Companion & Identity Capture

The browser companion is the easiest way to feed browser-authenticated context into the desktop without copying headers by hand.

### What the Companion Does

- captures scoped WebSocket handshake metadata from the browser
- sends it to the local WSHawk bridge
- can attach capture to a project ID
- works with short-lived pairing instead of a long-lived bridge token

### Pairing Flow

1. start the desktop app so the local bridge is running
2. open the browser companion popup
3. leave `Auto-detect bridge on localhost:8080-8089` enabled, or set the handshake URL manually
4. set `Capture Domains`
5. optionally set a project ID
6. press `AUTO-DETECT`
7. browse the target application

### Important Notes

- capture scopes are required
- pairing is session-based
- the extension is meant to ingest handshake context, not unrestricted browser traffic
- captured identities can later be reused in Request Forge or HTTP replay flows

### DOM Identity Storage

If browser-assisted flows produce useful session material, the desktop can store that material into the current project identity vault so it becomes reusable for replay, AuthZ diff, and race workflows.

---

## Evidence Vault & Exports

The Evidence Vault is the operator review surface for the project record.

### What Shows Up There

- findings
- evidence records
- notes
- attack summaries
- replay recipes
- timeline summaries

### Export Formats

From the desktop evidence flow, project bundle exports support:

- JSON
- Markdown
- HTML

Other parts of the platform also generate:

- HTML reports
- PDF reports
- JSON, CSV, and SARIF outputs for scanner/report workflows

### Why the Bundle Export Matters

v4 evidence bundles are intended to be more defensible than ad hoc screenshots. They include provenance and integrity metadata so the output is easier to review later or hand to another operator.

### Recommended Evidence Workflow

1. keep all replay and attack work inside one project when possible
2. store identities with clear aliases
3. add notes while testing, not after
4. export the project bundle when the workflow is complete
5. keep the `.wshawk` file and the evidence export together for the engagement record

---

## Security Model

The desktop app is a local operator tool, but the runtime still follows some important boundaries:

- Electron renderer isolation is enabled
- Electron sandboxing is enabled for the renderer
- the local bridge is intended for loopback-only usage
- desktop and extension trust paths are separated
- extension pairing is explicit and short-lived
- secrets and local encryption keys are stored through a platform-aware secret backend
- project exports include integrity metadata

The practical takeaway is that the desktop is designed to support offensive workflows without treating the renderer, extension, or export path as implicitly trusted.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+S` | Save current project |
| `Ctrl+Enter` | Execute the active action in the current view |
| `Ctrl+K` | Open HawkSearch / global search |

Depending on the active view, additional local shortcuts may exist for specific widgets and inputs.

---

## Troubleshooting

### The Desktop Opens but the Bridge Never Becomes Ready

Check:

- Python dependencies are installed
- the local bridge port is free
- the sidecar binary exists if you are using a packaged build

For a fast health check:

```bash
cd desktop
npm run smoke
```

### The Browser Companion Does Not Capture Anything

Check:

- the desktop app is running
- capture is enabled in the companion
- `Capture Domains` is set correctly
- the socket target hostname matches the configured scope
- the bridge was detected and paired successfully

### Replay or AuthZ Diff Says No Identity Is Available

You likely need one of these:

- store a DOM identity into the project
- capture handshake context with the companion
- manually save or refresh identities tied to the current project

### Race Testing Looks Inconclusive

Try:

- increasing concurrency
- increasing waves
- reducing client-side throttling
- replaying with a fresher identity or token set

### Evidence Vault Looks Empty

Evidence is strongest when the project is actually linked and the workflow writes structured data. Run replay, AuthZ diff, race, or project-backed web operations instead of staying only in passive discovery views.

---

WSHawk Desktop v4 is built for operators who need to move from initial discovery to reproducible abuse and defensible evidence without changing tools mid-engagement.
