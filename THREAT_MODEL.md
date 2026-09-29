# Threat model

SpoofGuard is a security tool, so it is held to the standard it measures: what
it trusts, what it refuses to trust, and how it fails are stated here
explicitly. The guiding invariant is one sentence — **an incomplete or
ambiguous result renders UNKNOWN, never a confident "safe"** — and everything
below serves it.

## What we are protecting

The **accuracy of the grade**. SpoofGuard's entire value is that a user can
trust its verdict. The worst possible failure is a *false reassurance*: telling
someone their domain is protected when email can in fact be forged in their
name. Every design choice below is ranked against that single harm.

## Trust boundaries

| Boundary | Trusted? | Why / mitigation |
|---|---|---|
| The DNS-over-HTTPS resolver's responses | **Partially** | Responses are parsed defensively; malformed, contradictory, or missing data grades **UNKNOWN**, never PASS. A resolver cannot induce a false "safe" by returning junk. |
| The domain string supplied by the caller | **No** | Treated as untrusted input; used only to build DoH query URLs, never shell-interpolated or executed. |
| The user's own systems | **Never touched** | SpoofGuard reads public DNS only. No credentials, no port scans, no probes of the target's infrastructure. Out of scope by construction. |
| Third-party runtime code | **None exists** | Zero runtime dependencies (Python standard library only). There is no dependency to compromise, pin, or audit. |

## Attack surface and mitigations

1. **Malformed / adversarial DNS records.** A hostile record (e.g.
   `v=spf1 +all -all`, an empty DKIM `p=`, contradictory multi-records) must
   never crash the scanner or produce a false PASS. *Mitigation:* defensive
   parsing, first-match SPF `all` semantics (RFC 7208 §4.6.2), and a fuzz suite
   (`tests/test_fuzz_parser.py`) that drives 2,500+ random/malformed records
   through the parser asserting crash-free operation and no false PASS on a
   leading `+all`.
2. **A hostile or broken resolver.** *Mitigation:* per-lookup timeouts, a
   failed/anomalous lookup becomes `UNKNOWN` (a `LookupFailed`), and an
   incomplete scan is never scored strong — enforced in code and pinned by
   `tests/test_hostile_review_regressions.py`.
3. **HTML report injection.** The HTML report embeds a domain and raw DNS
   strings. *Mitigation:* every dynamic value is HTML-escaped; the report loads
   no external scripts, fonts, or images, so it renders identically offline and
   carries no injection or exfiltration surface.
4. **Supply chain.** *Mitigation:* zero runtime dependencies; CI pins the
   GitHub Actions ecosystem via Dependabot and runs CodeQL (`security-extended`)
   on every push and weekly.
5. **The network egress itself.** *Mitigation:* DoH over HTTPS to a
   user-selectable resolver (Cloudflare/Google), TLS-verified, size- and
   time-bounded. No other network activity of any kind.

## Explicit non-goals (out of scope by design)

- SpoofGuard does **not** perform active scanning, port probing, or any
  interaction with the target's servers.
- It does **not** use, request, or store credentials.
- It does **not** send email or test deliverability.
- It is a **posture check of public DNS**, not a full security audit or
  penetration test — and every report says so in its own footer.

## Reporting a vulnerability

See [SECURITY.md](./SECURITY.md). Report privately via GitHub Security
Advisories; do not open a public issue for an exploitable finding.
