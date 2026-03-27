# WSHawk v4 Vulnerability Coverage

WSHawk covers multiple vulnerability families, but not all of them are found the same way.

In v4, coverage comes from a mix of:

- compatibility scanner heuristics
- browser-assisted evidence collection
- HTTP and WebSocket replay
- AuthZ diff across identities
- race testing
- project-backed evidence review

That means the right question is not only "what does WSHawk detect?" but also "which workflow discovers it?"

---

## Compatibility Scanner Coverage

The current `WSHawkV2` scanner path covers these major classes:

| Area | Primary Detection Style | Notes |
|---|---|---|
| **SQL Injection** | error, reflection, and timing signals | strongest on targets that visibly reflect or delay |
| **Cross-Site Scripting (XSS)** | reflection and context heuristics, plus optional browser-assisted evidence collection | browser evidence is supportive, not a guarantee of exploitability everywhere |
| **Command Injection** | output and timing markers | depends on target feedback quality |
| **XXE** | parser behavior plus out-of-band style checks | blind confirmation quality depends on OAST support |
| **SSRF** | internal access patterns and OAST-style signals | also covered in web pentest tooling |
| **NoSQL Injection** | operator and logic tampering payloads | strongest where message structure is inferred well |
| **Path Traversal / LFI** | known file markers and encoded path variants | most useful when responses leak content or errors |

The scanner can also append session security findings from the session tester module.

---

## Web Pentest Coverage

The `wshawk/web_pentest/` toolkit extends coverage into HTTP-focused work:

| Area | Typical Tooling |
|---|---|
| **Header security** | Header Analyzer |
| **Content discovery** | Web Crawler, Dir Scanner |
| **Input fuzzing** | HTTP Fuzzer |
| **CORS issues** | CORS Tester |
| **SSRF** | SSRF Prober |
| **Open Redirect** | Redirect Hunter |
| **Prototype Pollution** | Proto Polluter |
| **Sensitive data exposure** | Sensitive Finder |
| **TLS posture** | SSL/TLS Analyzer |
| **Technology and WAF fingerprinting** | Tech Fingerprint, WAF Detector |

These tools are most useful when paired with the v4 desktop project workflow so the results stay tied to identities, notes, and evidence.

---

## Project-Backed Offensive Workflows

Some of the most important v4 findings come from replay and comparison workflows rather than one-shot scanning.

### HTTP and WebSocket Replay

Replay helps validate whether a captured action still works when repeated with:

- a different identity
- a stale token
- a modified header set
- edited variables

### AuthZ Diff

AuthZ diff compares behavior across stored identities. This is especially important for:

- cross-tenant leaks
- role confusion
- object-level access control drift
- subscription exposure

### Race Testing

Race testing helps uncover:

- duplicate state changes
- replay-before-invalidation windows
- token reuse timing flaws
- concurrent update bugs

### Subscription Abuse

Subscription abuse workflows are useful for:

- topic or room overreach
- cross-tenant realtime data leakage
- privileged update replay over subscription-style targets

---

## Session Security Coverage

The session tester module focuses on:

- token reuse
- subscription spoofing
- impersonation
- channel boundary violations
- session fixation
- privilege escalation

See [Session Security Tests](session_tests.md) for that module specifically.

---

## Evidence Quality Notes

Not every finding class has the same confidence profile.

- reflection-only results are weaker than state-changing replay results
- timing-based findings need operator judgment
- browser-assisted XSS evidence helps, but should not be treated as absolute proof in every deployment model
- replay, AuthZ diff, race, and exported evidence are often the strongest v4 proof paths

For current operator workflow, pair this guide with:

- [Desktop v4 Full Feature Guide](DESKTOP_V4_GUIDE.md)
- [WSHawk v4 Complete Guide](V4_COMPLETE_GUIDE.md)
