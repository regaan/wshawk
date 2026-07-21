# WSHawk Desktop Security Lab

This is the controlled target for the future desktop end-to-end benchmark. It extends the paired industry controls lab with deterministic HTTP and WebSocket injection targets. It does not execute operating-system commands, database queries, local-file reads, XML entities, or outbound requests; it returns synthetic evidence when a known probe is received.

## Start the lab

From the repository root:

```bash
python -m benchmarks.desktop_security_lab.server --ready-file build/desktop-security-lab.json
```

The server selects an ephemeral port, prints a `WSHAWK_DESKTOP_LAB_READY=` JSON record, and optionally writes the same connection information atomically to the ready file. The connection record includes the vulnerable and hardened HTTP and WebSocket targets.

Useful endpoints:

- `/lab/health` reports readiness, schema version, profiles, and ground-truth case count.
- `/lab/ground-truth` exposes the expected case manifest to the benchmark controller.
- `POST /lab/reset` clears deterministic HTTP and WebSocket race state between runs.
- `/vulnerable/portal` is the intentionally vulnerable crawler entry point.
- `/hardened/portal` is the paired false-positive control.
- `/{profile}/ws` covers authorization, tenant mutation, Origin policy, and race behavior.
- `/{profile}/probe-ws` covers message-level injection probes.

## Ground truth

`ground_truth.json` defines 26 stable cases: 16 HTTP cases and 10 WebSocket cases. Every case identifies its channel, technique, CWE, severity, target, probe intent, and expected result for both profiles.

This mapping supports reproducible comparison of true positives, false positives, true negatives, false negatives, precision, recall, specificity, and F1 score. It describes coverage; it does not claim certification or complete compliance with OWASP ASVS, WSTG, or the API Security Top 10.

## Safety

- The controller binds only to `127.0.0.1`.
- All identities, keys, tenant records, and vulnerability evidence are synthetic.
- Do not expose the lab through port forwarding, a public proxy, or a non-loopback container mapping.
- Do not replace simulated handlers with real command execution, file reads, XML entity resolution, database queries, or network fetches.
