# WSHawk Docker Guide

The Docker image is best for CLI-oriented and compatibility-runtime use.

It is not the primary way to use the v4 desktop workflow.

If you want the full v4 operator path, use the desktop app from source or packaged builds. Use Docker when you want:

- a disposable CLI runtime
- a quick scanner container
- a CI job that runs the compatibility scanner

---

## Pull the Image

```bash
docker pull rothackers/wshawk:latest
```

---

## Basic Scanner Usage

The image entrypoint is `wshawk`, so the simplest run looks like:

```bash
docker run --rm rothackers/wshawk wss://target.example/ws
```

Show help:

```bash
docker run --rm rothackers/wshawk --help
```

---

## Running Other CLI Entry Points

Because the container entrypoint is `wshawk`, non-default commands need `--entrypoint`.

### Defensive Validation

```bash
docker run --rm --entrypoint wshawk-defensive rothackers/wshawk wss://target.example/ws
```

### Interactive Mode

```bash
docker run --rm -it --entrypoint wshawk-interactive rothackers/wshawk
```

### Advanced CLI

```bash
docker run --rm --entrypoint wshawk-advanced rothackers/wshawk wss://target.example/ws --full
```

---

## Build Locally

```bash
docker build -t rothackers/wshawk:latest .
```

Then run:

```bash
docker run --rm rothackers/wshawk:latest --help
```

---

## Persist Reports

The default reporting directory is `./reports` inside the container workdir, which maps naturally to `/app/reports`.

```bash
mkdir -p reports

docker run --rm \
  -v "$(pwd)/reports:/app/reports" \
  rothackers/wshawk \
  wss://target.example/ws
```

---

## Useful Environment Variables

Use actual WSHawk config environment overrides rather than made-up container variables.

Example:

```bash
docker run --rm \
  -e PYTHONUNBUFFERED=1 \
  -e WSHAWK_TIMEOUT=30 \
  rothackers/wshawk \
  wss://target.example/ws
```

---

## Playwright and Browser-Assisted Features

The image is primarily a CLI runtime. If you need browser-assisted features, treat that as a custom container concern.

Practical note:

- the Python package path is there
- the base image is not intended to be a polished desktop or full browser lab image
- if you need Chromium for browser-assisted flows, build a derived image and install it during image build

Example pattern:

```dockerfile
FROM rothackers/wshawk:latest

RUN python -m pip install playwright && \
    playwright install chromium
```

---

## Docker Compose

The repository includes a `docker-compose.yml`, but it is better treated as a convenience shell setup than as the primary validation path for v4 features.

For reproducible validation, prefer the local apps under:

- `validation/full_stack_realtime_saas/`
- `validation/socketio_saas/`
- `validation/graphql_subscriptions_lab/`

Those targets are designed for current v4 workflows.

---

## When Docker Is the Wrong Tool

Do not expect the Docker image to replace:

- the desktop app
- browser companion pairing
- local packaged desktop behavior
- the richest project-backed evidence workflow

Those are better served by the desktop runtime on the host.
