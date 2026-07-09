# Security Policy

## Supported Versions

fingerprintd is pre-1.0 software. Only the **latest released version** receives
security updates; older releases are not patched — please upgrade to the most
recent release before reporting an issue.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.** Public
disclosure before a fix is available puts all users at risk.

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to <https://github.com/WuChenDi/fingerprintd/security/advisories>.
2. Click **"Report a vulnerability"**.
3. Fill in the advisory form with the details below.

This opens a private channel visible only to the maintainers and you.

### What to include

- A clear description of the vulnerability and its impact.
- The affected version (and platform/OS, if relevant).
- Step-by-step reproduction instructions or a proof of concept.
- Any relevant logs, requests, or configuration (with secrets redacted).
- Your assessment of severity and possible mitigations, if known.

## Response Timeline

- **Acknowledgement** — within **72 hours**.
- **Triage** — we assess and confirm the issue and share an initial severity
  assessment.
- **Fix & disclosure** — we develop a fix, release it, and coordinate public
  disclosure with you.

## Scope and threat model

fingerprintd is an anti-fraud device-identification service; its security model is
documented in [`DESIGN.md` architecture §2](DESIGN.md#2-goals-and-threat-model)
and [`§4`](DESIGN.md#4-architecture-challenge-response--server-side-fusion).
Please keep reports consistent with that model:

- The service does **not** claim unbreakable defense. An L3 adversary forging any
  single signal (via curl-impersonate / uTLS) is a documented limitation, not a
  vulnerability — the value is raising forgery cost and cross-checking signals.
- The probe and response-signing keys embedded in client WASM/JS are **defense in
  depth, not a decisive control**; extracting them is expected. The one-time nonce
  and TLS are the primary guarantees.

In scope (please report): replay of a consumed/expired nonce, bypass of the
server-side identity decision, acceptance of a client-supplied passive signal
outside the configured trust boundary, injection via unmodeled request fields,
privacy/erasure failures (retained raw values, ineffective `DELETE /visitor/{id}`),
and secret leakage in logs or responses.
