"""Tests for `spoofguard/scanner.py` — the checks and grading.

No test touches the network: every check is driven by an injected fetch_fn
that returns canned DoH JSON. The load-bearing properties: an absent control
is reported FAIL/absent (never hand-waved), a present-but-weak control is
WARN not PASS, and the grade reflects the spoofing-critical controls.

Ported from the private internal repository's `test_email_security_report.py`
— the grading logic and every regression case below are unchanged. Only the
import path changed (`spoofguard.scanner` instead of an internal module), and
a handful of tests were added at the bottom for code that is new in this
standalone package (the DoH resolver selection and batch triage)."""

import json
import unittest

from spoofguard.scanner import (
    assess_email_security,
    triage_domains,
    make_doh_fetch,
    DOH_RESOLVERS,
    Finding,
)
from spoofguard.report import render_report_md


def _doh(answers):
    """Build a DoH JSON body from a list of TXT/record data strings."""
    return json.dumps({"Status": 0,
                       "Answer": [{"data": a} for a in answers]}).encode()


def make_fetch(records):
    """records: dict mapping 'name|TYPE' -> list of data strings."""
    def fetch(url: str) -> bytes:
        # url like https://cloudflare-dns.com/dns-query?name=X&type=TXT
        q = url.split("?", 1)[1]
        parts = dict(kv.split("=", 1) for kv in q.split("&"))
        key = f"{parts['name']}|{parts['type']}"
        return _doh(records.get(key, []))
    return fetch


class TestStrongDomain(unittest.TestCase):
    def setUp(self):
        self.records = {
            "good.com|TXT": ["v=spf1 include:_spf.google.com -all"],
            "_dmarc.good.com|TXT": ["v=DMARC1; p=reject; rua=mailto:a@good.com"],
            "default._domainkey.good.com|TXT": ["v=DKIM1; k=rsa; p=MIGf..."],
            "good.com|DS": ["12345 8 2 ABCDEF"],
            "good.com|MX": ["10 aspmx.l.google.com."],
        }

    def test_strong_domain_grades_A(self):
        r = assess_email_security("good.com", make_fetch(self.records))
        self.assertEqual(r.grade, "A — strong")
        self.assertEqual(r.fails, ())

    def test_spf_hardfail_is_pass(self):
        r = assess_email_security("good.com", make_fetch(self.records))
        spf = next(f for f in r.findings if f.check == "SPF")
        self.assertEqual(spf.status, "PASS")


class TestSpoofableDomain(unittest.TestCase):
    def test_no_spf_no_dmarc_is_fail_and_low_grade(self):
        # empty records = nothing configured
        r = assess_email_security("bad.com", make_fetch({}))
        spf = next(f for f in r.findings if f.check == "SPF")
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(spf.status, "FAIL")
        self.assertEqual(dmarc.status, "FAIL")
        self.assertIn("forge", spf.detail.lower())
        self.assertIn(r.grade[0], ("C", "D"))
        # absent controls surface with a concrete fix, never hand-waved
        self.assertTrue(spf.fix and dmarc.fix)

    def test_soft_spf_is_warn_not_pass(self):
        recs = {"weak.com|TXT": ["v=spf1 include:x ~all"]}
        r = assess_email_security("weak.com", make_fetch(recs))
        spf = next(f for f in r.findings if f.check == "SPF")
        self.assertEqual(spf.status, "WARN")

    def test_spf_plus_all_is_fail_not_warn(self):
        # +all explicitly authorises ANY sender — worse than no SPF. Regression:
        # a substring/"ends with all" read graded it WARN (soft). It is FAIL.
        for rec in ("v=spf1 +all", "v=spf1 include:x +all", "v=spf1 all"):
            r = assess_email_security("open.com", make_fetch({"open.com|TXT": [rec]}))
            spf = next(f for f in r.findings if f.check == "SPF")
            self.assertEqual(spf.status, "FAIL", rec)
            self.assertIn("all senders", spf.detail.lower())

    def test_spf_hardfail_still_passes_and_neutral_still_warns(self):
        cases = {"v=spf1 -all": "PASS", "v=spf1 ~all": "WARN", "v=spf1 ?all": "WARN"}
        for rec, want in cases.items():
            r = assess_email_security("d.com", make_fetch({"d.com|TXT": [rec]}))
            spf = next(f for f in r.findings if f.check == "SPF")
            self.assertEqual(spf.status, want, rec)

    def test_dmarc_p_quarantine_with_sp_reject_is_not_misread_as_reject(self):
        # Live-found bug: p=quarantine; sp=reject must grade WARN (quarantine),
        # not PASS — a substring match on "p=reject" wrongly caught "sp=reject".
        recs = {"gh.com|TXT": ["v=spf1 -all"],
                "_dmarc.gh.com|TXT": ["v=DMARC1; p=quarantine; sp=reject; pct=100"]}
        r = assess_email_security("gh.com", make_fetch(recs))
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(dmarc.status, "WARN")
        self.assertIn("quarantine", dmarc.detail.lower())

    def test_dmarc_monitor_only_is_warn_not_pass(self):
        recs = {"m.com|TXT": ["v=spf1 -all"],
                "_dmarc.m.com|TXT": ["v=DMARC1; p=none"]}
        r = assess_email_security("m.com", make_fetch(recs))
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(dmarc.status, "WARN")
        self.assertIn("p=none", dmarc.detail.lower())


class TestFalsePassGuards(unittest.TestCase):
    """A security check must never say PASS when the domain is actually
    spoofable. These three configs each render enforcement void but were graded
    PASS before: two SPF records (PermError, SPF ignored), two DMARC records
    (DMARC ignored), and p=reject with pct below 100 (most failing mail bypasses
    the policy). A false PASS is the worst error this tool can make."""

    def test_two_spf_records_is_fail(self):
        r = assess_email_security("d.com", make_fetch(
            {"d.com|TXT": ["v=spf1 -all", "v=spf1 include:x ~all"]}))
        spf = next(f for f in r.findings if f.check == "SPF")
        self.assertEqual(spf.status, "FAIL")
        self.assertIn("multiple spf", spf.detail.lower())

    def test_two_dmarc_records_is_fail(self):
        r = assess_email_security("d.com", make_fetch(
            {"_dmarc.d.com|TXT": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}))
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(dmarc.status, "FAIL")
        self.assertIn("multiple dmarc", dmarc.detail.lower())

    def test_reject_with_pct_zero_is_warn_not_pass(self):
        r = assess_email_security("d.com", make_fetch(
            {"_dmarc.d.com|TXT": ["v=DMARC1; p=reject; pct=0"]}))
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(dmarc.status, "WARN")
        self.assertIn("pct=0", dmarc.detail)

    def test_reject_with_pct_100_is_pass(self):
        r = assess_email_security("d.com", make_fetch(
            {"_dmarc.d.com|TXT": ["v=DMARC1; p=reject; pct=100"]}))
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(dmarc.status, "PASS")

    def test_reject_without_pct_defaults_to_full_enforcement(self):
        r = assess_email_security("d.com", make_fetch(
            {"_dmarc.d.com|TXT": ["v=DMARC1; p=reject"]}))
        dmarc = next(f for f in r.findings if f.check == "DMARC")
        self.assertEqual(dmarc.status, "PASS")


class TestLookupFailureIsUnknownNotAbsent(unittest.TestCase):
    """A failed DNS read must never be scored as 'record absent'. Regression
    for a live-found defect in the internal predecessor of this tool: an
    exhausted query budget made later checks (MX, MTA-STS) read as 'No
    record' — manufacturing false 'spoofable' grades on domains (paypal.com,
    google.com) that are in fact well configured. This package has no query
    budget at all, but the UNKNOWN-on-failure contract that prevents that
    class of bug is exactly what these tests pin."""

    def test_every_check_unknown_when_fetch_raises(self):
        def boom(url):
            raise RuntimeError("network down / DNS resolver unreachable")
        r = assess_email_security("x.com", boom)
        self.assertTrue(all(f.status == "UNKNOWN" for f in r.findings))

    def test_lookup_failure_never_counts_as_a_fail(self):
        def boom(url):
            raise RuntimeError("network down")
        r = assess_email_security("x.com", boom)
        self.assertEqual(r.fails, ())

    def test_incomplete_report_grades_unknown_not_a_letter(self):
        def boom(url):
            raise RuntimeError("network down")
        r = assess_email_security("x.com", boom)
        self.assertTrue(r.grade.startswith("UNKNOWN"))
        self.assertNotIn(r.grade[0], ("A", "B", "C", "D"))

    def test_one_failed_check_does_not_poison_the_others(self):
        # SPF reads fine (absent → FAIL), but MX lookup fails → MX UNKNOWN.
        # The whole report is then UNKNOWN (not fully assessed), but the SPF
        # FAIL is a real absent-record finding, not a fabricated one.
        def fetch(url):
            if "type=MX" in url:
                raise RuntimeError("MX lookup failed")
            return json.dumps({"Status": 0, "Answer": []}).encode()
        r = assess_email_security("x.com", fetch)
        mx = next(f for f in r.findings if f.check == "MX")
        spf = next(f for f in r.findings if f.check == "SPF")
        self.assertEqual(mx.status, "UNKNOWN")
        self.assertEqual(spf.status, "FAIL")   # genuine absent, fetch succeeded
        self.assertTrue(r.grade.startswith("UNKNOWN"))


class TestReportRendering(unittest.TestCase):
    def test_report_has_grade_actions_and_scope_disclaimer(self):
        r = assess_email_security("bad.com", make_fetch({}))
        md = render_report_md(r)
        self.assertIn("Email Security Report — bad.com", md)
        self.assertIn("Overall grade", md)
        self.assertIn("What to fix", md)
        # honest scope statement present — not sold as a full audit
        self.assertIn("not a full security audit", md)

    def test_domain_is_normalised(self):
        r = assess_email_security("  Good.COM.  ", make_fetch(
            {"good.com|TXT": ["v=spf1 -all"]}))
        self.assertEqual(r.domain, "good.com")


# ---------------------------------------------------------------------------
# New in the standalone package: DoH resolver selection and batch triage.
# ---------------------------------------------------------------------------

class TestDohResolverSelection(unittest.TestCase):
    """`make_doh_fetch` is the only piece of this package that touches the
    network. These tests exercise its resolver validation without making a
    real request — the fetch closure itself is never invoked here."""

    def test_both_documented_resolvers_are_constructible(self):
        for name in DOH_RESOLVERS:
            fetch = make_doh_fetch(resolver=name)
            self.assertTrue(callable(fetch))

    def test_unknown_resolver_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            make_doh_fetch(resolver="not-a-real-resolver")
        self.assertIn("not-a-real-resolver", str(ctx.exception))

    def test_default_resolver_is_cloudflare(self):
        # Cloudflare is the resolver used when a caller specifies none —
        # pinned so a future edit can't silently change the default.
        r = assess_email_security("d.com", make_fetch({"d.com|TXT": ["v=spf1 -all"]}))
        self.assertEqual(r.domain, "d.com")  # sanity: injected fetch still wins
        self.assertIn("cloudflare", DOH_RESOLVERS)
        self.assertEqual(DOH_RESOLVERS["cloudflare"], "https://cloudflare-dns.com/dns-query")


class TestTriageDomains(unittest.TestCase):
    """Batch scanning: many domains in, sorted most-exposed-first."""

    def setUp(self):
        self.records = {
            # clean.com: strong on everything asked
            "clean.com|TXT": ["v=spf1 -all"],
            "_dmarc.clean.com|TXT": ["v=DMARC1; p=reject"],
            # weak.com: one soft SPF, no DMARC record
            "weak.com|TXT": ["v=spf1 ~all"],
            # wide-open.com: nothing at all
        }

    def _fetch(self):
        return make_fetch(self.records)

    def test_sorted_most_exposed_first(self):
        results = triage_domains(["clean.com", "weak.com", "wide-open.com"],
                                 self._fetch())
        self.assertEqual([r.domain for r in results],
                         ["wide-open.com", "weak.com", "clean.com"])

    def test_severity_matches_spoofability(self):
        results = {r.domain: r for r in
                  triage_domains(["clean.com", "weak.com", "wide-open.com"], self._fetch())}
        self.assertEqual(results["clean.com"].severity, 0)
        self.assertFalse(results["clean.com"].spoofable)
        self.assertGreater(results["wide-open.com"].severity, results["weak.com"].severity)
        self.assertTrue(results["wide-open.com"].spoofable)
        self.assertTrue(results["weak.com"].spoofable)

    def test_blank_entries_are_skipped(self):
        results = triage_domains(["clean.com", "  ", "", "weak.com"], self._fetch())
        self.assertEqual({r.domain for r in results}, {"clean.com", "weak.com"})

    def test_critical_gaps_are_plain_english_not_empty_for_bad_domain(self):
        results = {r.domain: r for r in
                  triage_domains(["wide-open.com"], self._fetch())}
        self.assertTrue(results["wide-open.com"].critical_gaps)


if __name__ == "__main__":
    unittest.main()


class TestResolverFailureIsUnknown(unittest.TestCase):
    """A resolver SERVFAIL/REFUSED is valid JSON with no Answer. It is a failed
    read (UNKNOWN), never 'record absent'. NXDOMAIN (3) stays a real empty
    answer. Found 2026-10-01: Status 2 graded 'FAIL: No SPF record'."""

    def _status_fetch(self, status):
        def fetch(url):
            return json.dumps({"Status": status}).encode()
        return fetch

    def test_servfail_and_refused_are_unknown_not_fail(self):
        for status in (2, 5):
            r = assess_email_security("x.com", self._status_fetch(status))
            spf = next(f for f in r.findings if f.check == "SPF")
            dmarc = next(f for f in r.findings if f.check == "DMARC")
            self.assertEqual(spf.status, "UNKNOWN", status)
            self.assertEqual(dmarc.status, "UNKNOWN", status)
            self.assertTrue(r.grade.startswith("UNKNOWN"), status)

    def test_nxdomain_is_still_absent(self):
        r = assess_email_security("x.com", self._status_fetch(3))
        spf = next(f for f in r.findings if f.check == "SPF")
        self.assertEqual(spf.status, "FAIL")
