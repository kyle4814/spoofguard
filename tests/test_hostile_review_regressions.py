"""Regression tests for the 2026-09-29 hostile-review findings.

Each pins a bug that the original 39-test suite passed straight over — a live
reminder that a green suite is a hypothesis, not a verdict:

  #1  SPF: the FIRST `all`-mechanism governs (RFC 7208 §4.6.2). Reading the
      last one graded `v=spf1 +all -all` (wide open) as a PASS — a false PASS
      on a spoofable domain, the one thing this tool promises never to do.
  #2  DKIM: an empty `p=` (RFC 6376 revoked key) and a stray `p=` substring in
      an unrelated record were both read as a valid signing key.
  #3  An UNKNOWN (incomplete) scan rendered "No action needed — controls are
      strong" in all three output formats.
"""

import io
import json
import unittest
from contextlib import redirect_stdout

from spoofguard.scanner import assess_email_security, EmailSecurityReport, Finding
from spoofguard.report import render_report_md, render_report_html
from spoofguard.cli import _print_text


def _make_fetch(records):
    """records: dict 'name|TYPE' -> list of record-data strings."""
    def fetch(url: str) -> bytes:
        q = url.split("?", 1)[1]
        parts = dict(kv.split("=", 1) for kv in q.split("&"))
        key = f"{parts['name']}|{parts['type']}"
        return json.dumps(
            {"Status": 0, "Answer": [{"data": a} for a in records.get(key, [])]}
        ).encode()
    return fetch


class TestSpfFirstMatchWins(unittest.TestCase):
    def _spf(self, record):
        r = assess_email_security("d.com", _make_fetch({"d.com|TXT": [record]}))
        return next(f for f in r.findings if f.check == "SPF")

    def test_plus_all_before_hardfail_is_fail_not_pass(self):
        # +all matches first → anyone can send. The trailing -all is unreachable.
        self.assertEqual(self._spf("v=spf1 +all -all").status, "FAIL")

    def test_hardfail_before_stray_soft_is_pass(self):
        # -all governs (first); a trailing ~all left over from an edit is dead.
        self.assertEqual(self._spf("v=spf1 include:x -all ~all").status, "PASS")

    def test_plain_hardfail_still_passes(self):
        self.assertEqual(self._spf("v=spf1 include:x -all").status, "PASS")


class TestDkimRevokedAndSubstring(unittest.TestCase):
    def _dkim(self, record):
        recs = {"default._domainkey.d.com|TXT": [record]}
        r = assess_email_security("d.com", _make_fetch(recs))
        return next(f for f in r.findings if f.check == "DKIM")

    def test_revoked_empty_p_is_not_pass(self):
        self.assertNotEqual(self._dkim("v=DKIM1; p=").status, "PASS")

    def test_valid_key_is_pass(self):
        self.assertEqual(self._dkim("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3AAA").status, "PASS")

    def test_unrelated_p_substring_is_not_pass(self):
        self.assertNotEqual(self._dkim("site-verify=abc123&p=9&ref=x").status, "PASS")


class TestUnknownNeverRendersStrong(unittest.TestCase):
    def _unknown_report(self):
        findings = (
            Finding("SPF", "UNKNOWN", "DNS lookup failed for this check.", ""),
            Finding("DMARC", "PASS", "ok", ""),
            Finding("DKIM", "PASS", "ok", ""),
            Finding("DNSSEC", "PASS", "ok", ""),
            Finding("MX", "PASS", "ok", ""),
            Finding("MTA-STS", "PASS", "ok", ""),
        )
        r = EmailSecurityReport(domain="u.com", findings=findings)
        self.assertTrue(r.grade.startswith("UNKNOWN"))
        return r

    def test_markdown(self):
        md = render_report_md(self._unknown_report()).lower()
        self.assertNotIn("no action needed", md)
        self.assertNotIn("are strong", md)
        self.assertIn("not assessed", md)

    def test_html(self):
        html = render_report_html(self._unknown_report()).lower()
        self.assertNotIn("no action needed", html)
        self.assertNotIn("already strong", html)
        self.assertIn("not assessed", html)

    def test_cli_text(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _print_text(self._unknown_report())
        out = buf.getvalue().lower()
        self.assertNotIn("no action needed", out)
        self.assertNotIn("are strong", out)
        self.assertIn("not assessed", out)


if __name__ == "__main__":
    unittest.main()
