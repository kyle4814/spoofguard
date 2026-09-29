# Governance

SpoofGuard is a small, single-maintainer project, and this document says so
plainly rather than pretending to a committee that doesn't exist. It exists so
that a contributor, a user, or a funder can see exactly how decisions get made,
what is non-negotiable, and what happens if the maintainer disappears.

## Who maintains it

SpoofGuard is maintained by **Kyle Deligny** (TITANOS, Australia), the current
sole maintainer and decision-maker. The maintainer merges changes, cuts
releases, and is accountable for the project's security posture.

This is a "benevolent maintainer" model, bounded hard by the invariants below.
It is not personal rule: the maintainer cannot override the invariants either —
changing one is a constitution-level change (see below), not a merge decision.

## How decisions are made

- **Small fixes** (a bug, a doc correction, a test) — a pull request with a
  passing test suite is enough. The maintainer reviews and merges.
- **Anything that changes behaviour a user relies on** — a new check, a change
  to grading thresholds, a change to output format — starts as an **issue**
  first, so the reasoning is public before code is written. See
  [CONTRIBUTING.md](./CONTRIBUTING.md).
- **A change that touches an invariant below** — is a constitution-level change
  (see the next section). These are rare and deliberately hard.
- **Disagreement** is resolved in the open, on the issue, on the technical
  merits. The maintainer has the final call and states the reason for it in the
  thread, so the decision is a matter of record, not mood.

## The invariants (the constitution)

These are the properties that make SpoofGuard trustworthy. They are not up for
casual change, and no single pull request may quietly erode one. Changing any of
them requires a dedicated issue, an explicit rationale, and a migration note in
the changelog — never a silent edit.

1. **Zero runtime dependencies.** Python standard library only. Auditable
   end-to-end; runs anywhere, offline, forever.
2. **A failed lookup is `UNKNOWN`, never a confident grade.** An incomplete scan
   must never render as "safe." This is the single most important promise the
   tool makes.
3. **No test touches the network.** Every check is driven through an injected
   fetch callable with canned data, so the suite is deterministic and offline.
4. **A security check must never regress into a false PASS.** The false-pass
   guard tests exist because this project has already graded a spoofable domain
   as safe once, caught it, fixed it, and pinned it. That regression class stays
   pinned.
5. **Passive and public-record only.** SpoofGuard reads public DNS. It does not
   scan anyone's systems, use credentials, or send anything. Any feature that
   would change that is out of scope by default.

## Becoming a maintainer

There is a real path, not a closed door. A contributor who lands several
quality changes, shows they understand the invariants above (especially #2 and
#4), and reviews others' work well can be invited by the maintainer to become a
co-maintainer with merge rights. The project is deliberately kept small enough
that one or two maintainers can hold the whole thing in their head — that
simplicity is a feature, not a stage to grow out of.

## Succession and bus factor

SpoofGuard is MIT-licensed on purpose. If the maintainer becomes unavailable,
anyone may fork and continue it with no permission required — the license is the
succession plan. There is no private key, no proprietary service, and no hidden
dependency that a fork would lack: the repository *is* the project, and a fresh
clone reproduces it completely. This is the same property the tool itself is
built on — nothing load-bearing lives outside what you can read.

## Releases

Pre-1.0, `main` is the supported line (see [SECURITY.md](./SECURITY.md)).
Releases are tagged by the maintainer; each release runs the full test suite in
CI first, and real green gates the tag. The changelog records what changed and,
for any invariant-adjacent change, why.

## Code of conduct

Be straight, be civil, argue the code not the person. Harassment or bad-faith
conduct gets a warning then a ban, at the maintainer's discretion. Report
conduct concerns privately via the contact in [SECURITY.md](./SECURITY.md).
