# Getting Started with WSHawk v4

This guide is for the current v4 repo layout.

If you only remember one thing: the CLI is still available, but the strongest v4 workflow is the desktop app plus a local validation target or a real authorized target.

---

## Install

### PyPI

```bash
pip install wshawk
```

### Optional Browser Runtime

If you want browser-assisted XSS evidence collection or DOM-related flows:

```bash
playwright install chromium
```

### From Source

```bash
git clone https://github.com/regaan/wshawk
cd wshawk
pip install -e .
```

---

## Choose a Starting Path

### 1. Quick CLI Scan

Use this when you already have a WebSocket endpoint and want a fast first pass.

```bash
wshawk wss://target.example/ws
```

### 2. Desktop Workflow

Use this when the target is stateful, authenticated, or browser-driven.

```bash
cd desktop
npm install
npm start
```

### 3. Local Validation Lab

Use this when you want a realistic local target that matches current v4 workflows.

```bash
./venv/bin/python -m uvicorn validation.full_stack_realtime_saas.app:app --host 127.0.0.1 --port 8010
```

Then:

1. start the desktop app
2. create a new project
3. browse to `http://127.0.0.1:8010`
4. pair the browser companion if you want handshake capture
5. replay HTTP and WebSocket actions from the same project

---

## First Useful v4 Workflow

The most realistic first run is the local full-stack validation lab.

### Start the Target

```bash
./venv/bin/python -m uvicorn validation.full_stack_realtime_saas.app:app --host 127.0.0.1 --port 8010
```

### Start the Desktop

```bash
cd desktop
npm start
```

### Work Through the Flow

1. create a new WSHawk project
2. open the validation app in your browser
3. capture the handshake with the browser companion if needed
4. store identities such as `alice`, `mallory`, `bob`, and `brenda`
5. use HTTP Forge or Request Forge to replay actions
6. run `AuthZ Diff`
7. run `Race`
8. review Evidence Vault
9. export the project bundle

This path matches the current v4 architecture far better than pointing a scanner at a dead public echo service.

---

## Understanding Output

### Compatibility Scanner Output

The scanner path can generate:

- HTML reports
- JSON reports
- CSV reports
- SARIF reports

By default, reports go under `./reports` unless you change `reporting.output_dir` in config.

### Desktop / Platform Output

The desktop project workflow can export project bundles as:

- JSON
- Markdown
- HTML

These exports are tied to the local project and include replay- and evidence-oriented context.

---

## Common Next Steps

### Need the full architecture and current workflow model?

Read [WSHawk v4 Complete Guide](V4_COMPLETE_GUIDE.md).

### Need the desktop workflow?

Read [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md).

### Need module-level Python examples?

Read [Advanced Usage](advanced_usage.md).

### Need local regression coverage?

Read [Validation Checklist](validation_checklist.md).

### Need vulnerability coverage details?

Read [Vulnerability Details](vulnerabilities.md).

### Need session-security coverage?

Read [Session Security Tests](session_tests.md).
