# Security Policy

SpoofGuard is a security tool, so how we handle security reports *about*
SpoofGuard matters as much as what it checks. This policy is deliberately
concrete rather than a form letter.

## Supported versions

SpoofGuard is pre-1.0. The `main` branch is the only supported version —
there is no long-term-support branch yet. Once a 1.0 is tagged, this table
will list which major versions still receive fixes.

| Version | Supported |
| ------- | --------- |
| `main` / latest `0.x` release | ✅ |

## Reporting a vulnerability

**Preferred: GitHub Security Advisories** (no account other than GitHub
needed, and the report is private until resolved):

<https://github.com/kyle4814/spoofguard/security/advisories/new>

This keeps the report private between you and the maintainer until a fix is
ready, then can be published as a credited advisory with a CVE if warranted.

**Do not open a public GitHub issue for a security vulnerability.** Public
issues are fine for "this check gives a wrong result" (that's a correctness
bug, not a security report) but not for anything that could be actively
exploited before a fix ships.

Please include, as far as you can:

- What you found and why it's a security issue (not just "this seems wrong").
- Steps to reproduce, or a minimal example.
- The impact you believe it has (e.g. "this can be used to make a spoofable
  domain grade as PASS" is a serious finding for a tool whose whole purpose
  is not doing that).
- Whether you'd like credit in the fix's release notes.

## What's in scope

- The check and grading logic in `spoofguard/scanner.py` — in particular,
  anything that could make an actually-spoofable domain grade as PASS/A, or
  cause a crash/hang on untrusted DNS response data.
- The report renderers in `spoofguard/report.py` — in particular, any way
  untrusted DNS data (a TXT record, a domain name) could inject markup,
  scripts, or otherwise escape its intended context in the HTML report.
- The CLI (`spoofguard/cli.py`) — argument handling, file writing.

## What's out of scope

- The DNS-over-HTTPS resolvers themselves (Cloudflare, Google) — report
  issues with them to Cloudflare/Google directly.
- "This domain's real-world email security is bad" is not a SpoofGuard
  vulnerability — that's the tool doing its job. A vulnerability is SpoofGuard
  *misreporting* that.
- Denial of service against a *target domain's* DNS infrastructure — SpoofGuard
  only ever issues ordinary DoH lookups a browser would also make; it does
  not, and will not, add flooding/brute-force capability.

## Response

This is currently a one-maintainer project. Best-effort targets: acknowledgement
within 5 business days, an initial assessment within 14. If that slips, it
means the maintainer hasn't seen it yet — a follow-up comment on the advisory
is welcome and will not be seen as impatient.

## Safe harbor

Good-faith security research against this **open-source code** (reading it,
testing it locally, or reporting a bug found through normal use) will never
be treated as hostile. This policy does not cover, and does not authorise,
scanning or testing *other people's* domains without their permission —
SpoofGuard reads public DNS only, and that authorisation extends to public
DNS, never to systems behind it.

## Machine-readable copy

A [`security.txt`](./.well-known/security.txt) (RFC 9116) file mirrors the
contact information above in a format automated tools can parse. If this
project is ever served from its own domain, that file should be published at
`/.well-known/security.txt` on that domain too — see the file itself for the
`Expires` date to keep current.
