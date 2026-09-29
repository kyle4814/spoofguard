<!-- Thanks for contributing. Keep it small and keep the invariants intact. -->

## What this changes

<!-- One or two sentences. -->

## Checklist

- [ ] Tests pass locally: `python -m unittest discover -s tests -v`
- [ ] Zero runtime dependencies preserved (stdlib only)
- [ ] A failed DNS lookup still grades **UNKNOWN**, never PASS/FAIL
- [ ] No security check regressed to a false PASS (see `tests/test_hostile_review_regressions.py` and `tests/test_fuzz_parser.py`)
- [ ] Any HTML report output stays escaped (no unescaped dynamic content)
- [ ] If grading behaviour changed, a test demonstrates the old behaviour was wrong
- [ ] Security-sensitive change? See [SECURITY.md](../SECURITY.md) — do not disclose an exploit in a public PR
