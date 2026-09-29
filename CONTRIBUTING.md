# Contributing to SpoofGuard

Thanks for considering it. This project is small on purpose (zero runtime
dependencies, stdlib only) — keep that in mind before proposing anything that
would need a third-party package.

## Ground rules

1. **Zero runtime dependencies stays non-negotiable.** SpoofGuard runs
   anywhere Python 3.10+ runs, with nothing to `pip install` beyond itself.
   If a change needs a third-party library at runtime, it needs a very good
   reason and it needs to be discussed in an issue first.
2. **A failed DNS lookup is UNKNOWN, never FAIL.** This is the single most
   important invariant in the codebase (see `scanner.py`'s module docstring
   and `LookupFailed`). If you're touching a check function, make sure a
   network/timeout error still produces `Finding(..., "UNKNOWN", ...)`, not a
   finding that looks like a real, absent-record result.
3. **No test may touch the network.** Every test drives the checks through an
   injected `fetch` callable that returns canned DoH JSON (see
   `tests/test_scanner.py::make_fetch`). If you add a check or change grading,
   add the test case the same way.
4. **A security check must never regress from a real bug to a worse one.**
   Several existing tests exist specifically because a naive implementation
   graded an actually-spoofable domain as PASS (see
   `TestFalsePassGuards` in `tests/test_scanner.py`). If you're changing SPF/
   DMARC/DKIM logic, read those tests before you start — they document the
   exact edge cases (multiple SPF/DMARC records, `pct` below 100, `+all`,
   `sp=reject` vs `p=reject`) that have already burned this project once.

## Getting set up

```bash
git clone https://github.com/kyle4814/spoofguard.git
cd spoofguard
python -m unittest discover -s tests -v
```

No virtual environment or dependency install is required to run the tests —
that's deliberate. To install the CLI locally for manual testing:

```bash
python -m pip install -e .
spoofguard example.com
```

## Making a change

1. Open an issue first for anything beyond a small fix — especially for a new
   check (e.g. BIMI, ARC) or a change to the grading thresholds, since those
   affect what every existing user's report says.
2. Add or update tests alongside the change. A PR that changes `scanner.py`
   grading behaviour without a test demonstrating the *old* behaviour was
   wrong will be asked for one.
3. Run the full test suite before opening the PR:
   ```bash
   python -m unittest discover -s tests -v
   ```
4. Keep the honesty invariants intact: no fabricated grade, no silent
   swallowing of a lookup failure into a "PASS" or "FAIL", no dynamic content
   in `report.py`'s HTML output left unescaped.

## Reporting a bug vs. reporting a security issue

- **"This check gives a wrong result for a domain I control"** — open a
  normal GitHub issue with the domain's *sanitised* DNS records (don't paste
  someone else's real domain without their say-so; a synthetic example that
  reproduces the same records is just as useful and doesn't expose anyone).
- **"This could be used to make a spoofable domain look safe"**, or any other
  actual security concern — see [`SECURITY.md`](./SECURITY.md) instead; please
  don't file those as public issues.

## Code style

- Stdlib only, `from __future__ import annotations`, type hints on public
  functions.
- Match the existing docstring style — each module explains *why* it's built
  the way it is, not just what it does. A future contributor (including you,
  in six months) benefits more from the reasoning than from the code alone.
- No emoji in code or docstrings; the Markdown/HTML report output uses a
  small fixed set (✅ ⚠️ ❌ ❔) as status glyphs and that set shouldn't grow
  without a reason.

## Scope: what this project is not

SpoofGuard reads public DNS and reports on it. Contributions that would turn
it into something that touches a domain's actual mail flow, scans ports,
brute-forces subdomains, or otherwise goes beyond a public, read-only DNS
lookup are out of scope — that would change its legal/ethical posture (see
the README's Limitations section) and won't be accepted.
