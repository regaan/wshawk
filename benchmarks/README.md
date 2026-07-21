# WSHawk Security Benchmark Suite

This directory contains the repeatable benchmark harness and the paired industry controls lab. All targets bind to ephemeral `127.0.0.1` ports and contain only synthetic data.

The standalone target for desktop UI qualification lives in `benchmarks/desktop_security_lab/`. It contains 26 paired HTTP/WebSocket ground-truth cases and can be started independently before the Electron automation layer is added:

```bash
python -m benchmarks.desktop_security_lab.server --ready-file build/desktop-security-lab.json
```

See `benchmarks/desktop_security_lab/README.md` for its endpoints, fixtures, lifecycle, and safety rules.

## Quick Run

```bash
python -m benchmarks.run --iterations 3 --warmup 1
```

The command runs WSHawk itself against three controlled labs, evaluates correctness and regression thresholds, and writes a redacted machine-readable report to `benchmarks/results/latest.json`.

Run one lab or choose another output path:

```bash
python -m benchmarks.run industry_security_controls_benchmark --iterations 5 --warmup 1 --output build/benchmarks/industry.json
```

List available benchmarks:

```bash
python -m benchmarks.run --list
```

## Benchmark Design

The suite separates three concerns:

1. `web_attack_benchmark` exercises broad HTTP/web tool coverage against known vulnerable behavior.
2. `websocket_attack_benchmark` exercises raw WebSocket replay, application errors, authorization differences, subscription mutation, race waves, and Origin probing.
3. `industry_security_controls_benchmark` runs the same WSHawk techniques against paired vulnerable and hardened SaaS controls.

The paired lab validates both sensitivity and specificity:

| Control | Vulnerable profile | Hardened profile |
|---|---|---|
| Object authorization | cross-tenant order returned | cross-tenant order rejected |
| SSRF | metadata content returned | link-local and unsafe schemes blocked |
| Redirects | external destination accepted | local relative destinations only |
| CORS | arbitrary Origin reflected with credentials | explicit trusted Origin only |
| Sensitive configuration | synthetic credentials exposed | non-secret configuration returned |
| CSRF | state-changing replay accepted | token required |
| HTTP race | duplicate redemption accepted | idempotency key enforced |
| WebSocket subscription | foreign tenant accepted | tenant ownership enforced |
| WebSocket race | duplicate action accepted | idempotency key enforced |
| WebSocket Origin | untrusted origins accepted | explicit Origin allowlist |

## Measurement Method

- Warm-up runs are excluded from reported results.
- Each measured iteration starts a fresh target on an ephemeral localhost port and resets mutable state.
- Wall-clock duration includes target startup, WSHawk execution, and target shutdown.
- Tool timing is also collected from each scenario.
- Median, p95, minimum, maximum, mean, and population standard deviation are reported.
- Correctness checks must pass on every iteration.
- Thresholds are stored in `benchmarks/thresholds.json` and intentionally leave enough time margin for shared CI runners.
- Reports use the same recursive secret redactor as the validation suite.

This is a functional and regression benchmark. It is not a denial-of-service, maximum-throughput, or internet-scanning harness.

## Standards Alignment

`benchmarks/manifest.json` maps controls to:

- OWASP Application Security Verification Standard 5.0.0
- OWASP Web Security Testing Guide 4.2
- OWASP API Security Top 10 2023

The mapping establishes coverage context; it does not claim full compliance with any standard.

## CI

The `Controlled security benchmarks` GitHub Actions job runs three measured iterations after one warm-up and uploads `build/benchmarks/report.json`. A failed correctness check or regression threshold fails the job.

## Safety Rules

- Keep the lab bound to localhost.
- Do not replace synthetic tokens or data with production material.
- Do not point the benchmark runner at external hosts.
- Treat heuristic findings as evidence candidates until manually confirmed.
