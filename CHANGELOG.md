# Changelog

All notable changes to SpoofGuard are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project is
pre-1.0, so the public API and grading thresholds may still change — any change
that affects what a user's report says is called out explicitly.

## [Unreleased]

### Added
- `THREAT_MODEL.md` — explicit trust boundaries, attack surface, and the
  UNKNOWN-never-strong invariant.
- `GOVERNANCE.md` — decision model, the five trust invariants as constitution,
  MIT license as the succession plan.
- `CODE_OF_CONDUCT.md`.
- Fuzz + property suite (`tests/test_fuzz_parser.py`): 2,500+ random/malformed
  records asserting crash-free parsing and no false PASS on a leading `+all`.
- CodeQL (`security-extended`) analysis in CI; Dependabot for the GitHub Actions
  ecosystem; least-privilege CI permissions; PR template.

### Fixed
- **SPF first-match grading** — `v=spf1 +all -all` (wide open) was graded PASS
  because the *last* `all` token was read instead of the first. Now honours
  RFC 7208 §4.6.2 first-match semantics. (Was a false PASS on a spoofable
  domain — the one failure the tool promises never to make.)
- **DKIM revoked/empty key** — an empty `p=` (RFC 6376 revoked key) and a stray
  `p=` substring in an unrelated record were both read as a valid signing key.
- **UNKNOWN never renders strong** — an incomplete scan previously rendered
  "controls are strong" in all three output formats; it now renders
  "not assessed" everywhere.
- Regression tests pin all three (`tests/test_hostile_review_regressions.py`).

## [0.1.0] — initial public release
- SPF / DMARC / DKIM / DNSSEC / MX / MTA-STS scan over DNS-over-HTTPS.
- A/B/C/D grade with an honest UNKNOWN for incomplete scans.
- Markdown, self-contained HTML, and JSON reports; single-domain and batch CLI.
- Zero runtime dependencies (Python standard library only).
