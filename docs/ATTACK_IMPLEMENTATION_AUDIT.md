# Attack Implementation Audit and Benchmarks

This document records the local source audit and deterministic attack-engine benchmarks for WSHawk 4.0.3. The benchmark targets bind only to `127.0.0.1` and are intentionally vulnerable. They must not be exposed to another network.

## Run the Benchmarks

```bash
python validation/run_validation.py web_attack_benchmark websocket_attack_benchmark
```

The runner compares every correctness check with the files in `validation/expected/` and writes redacted timing and evidence artifacts under `validation/artifacts/`.

For a clean benchmark run, all selected labs must report `PASS`. Timing values are diagnostic measurements, not fixed pass thresholds, because operating-system load and Python runtime versions affect latency.

For repeatable warm-up, iteration, percentile, and regression-threshold measurement, use the dedicated benchmark harness:

```bash
python -m benchmarks.run --iterations 3 --warmup 1
```

The additional `industry_security_controls_benchmark` compares vulnerable and hardened controls for object authorization,
SSRF, redirects, CORS, secret leakage, CSRF, HTTP/WebSocket idempotency, tenant subscription authorization, and WebSocket
Origin policy. Its first paired run exposed and corrected an SSRF false positive where an explicit `403` egress block had
been reported as a vulnerability anomaly.

## Live Local Coverage

| Area | Implementations exercised against live targets | Benchmark result |
|---|---|---|
| HTTP discovery | crawler, sensitive-file probes, directory scanner | expected paths, forms, APIs, and `.env` exposure detected |
| HTTP input attacks | fuzzer, open redirect, SSRF, prototype pollution, CSRF replay | vulnerable controls detected; SSRF long-page negative control remains clean |
| HTTP analysis | header analyzer, CORS tester, technology fingerprinting, sensitive-data finder, WAF detector | expected security posture and fingerprints detected |
| Network support | HTTP transport and targeted TCP port scan | authenticated requests and local listening port verified |
| Stateful HTTP attacks | replay, multi-identity AuthZ diff, duplicate-action race | identity behavior drift and duplicate success detected |
| Raw WebSocket attacks | replay, application-error classification, multi-identity AuthZ diff | welcome frames skipped and authorization behavior compared |
| Stateful WebSocket attacks | subscription/tenant mutation and concurrent race waves | tenant hop and duplicate success detected |
| WebSocket defensive observation | untrusted Origin sampling | accepted origins reported as requiring manual CSWSH impact verification |
| Other realtime protocols | Socket.IO and GraphQL WebSocket labs | covered by `socketio_saas` and `graphql_subscriptions_lab` |

The current benchmark baseline contains 17 web checks and 7 WebSocket checks. A typical run exercises more than 100 HTTP payload attempts and multiple concurrent WebSocket waves.

## Correctness Repairs from the Audit

- Direct-mode authenticated scanners now preserve supplied headers and cookies in the header, CORS, sensitive-data, redirect, SSRF, prototype-pollution, and directory-scanning paths.
- Technology fingerprinting and WAF detection now support the same project, identity, proxy, correlation, and evidence context as the other web tools.
- The project-backed vulnerability scanner now performs header analysis through its configured HTTP transport and identity context.
- SSRF testing now establishes a baseline, separates strong internal-content indicators from reflection, and does not report an unchanged long `200` page merely because it is large.
- HTTP race scoring now rejects application-level JSON failures such as `{"ok": false}` even when the transport status is `200`.
- HTTP request bodies are decoded as JSON only when their content type is JSON; JSON-shaped form or text bodies remain byte-for-byte text.
- Redirect destination comparison now normalizes hostnames separately from ports, preventing same-host redirects from being mislabeled as external.
- HTTP targets no longer receive an HTTPS-only CORS downgrade finding, and missing HSTS on a plain HTTP response is marked not applicable.
- DNS exfiltration validation can query a configured OAST callback API; an unconfigured callback checker is reported as inconclusive instead of falsely reporting that egress was blocked.

## Environment-Dependent Coverage

The following features are implemented but cannot have a universal offline pass result:

| Feature | Required environment | Correct interpretation |
|---|---|---|
| DNS lookup and passive subdomain enumeration | working DNS plus external provider access | provider or network failure is not a target-security result |
| SSL/TLS analyzer | a reachable TLS service and certificate chain | use a controlled TLS endpoint for release qualification |
| Bot-detection validation | Playwright package and installed browser runtime | missing browser runtime is a skipped dependency, not a target pass |
| DNS exfiltration callback confirmation | `WSHAWK_OAST_CALLBACK_URL` and optional `WSHAWK_OAST_API_TOKEN` | missing configuration produces an inconclusive result |
| Proxy CA host certificates | local cryptography support and writable certificate directory | validate separately because it changes local certificate material |

Heuristic tools such as WAF detection, technology fingerprinting, SSRF anomaly analysis, and prototype-pollution probing identify evidence candidates. Their output still requires operator review before being treated as a confirmed vulnerability.

## Benchmark Safety

- The targets use synthetic credentials, secrets, and tenant data.
- The servers use ephemeral localhost ports.
- Persisted artifacts pass through the validation redactor.
- The labs never scan an internet host.
- Maximum-throughput or denial-of-service testing is intentionally outside this benchmark.
