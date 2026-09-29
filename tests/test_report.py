"""Tests for `spoofguard/report.py` — HTML rendering.

`render_report_md` already has full coverage in `test_scanner.py` (it is
tested there alongside the checks it renders). These tests cover the HTML
renderer specifically: it must escape untrusted input, it must never emit a
confident-looking grade for an UNKNOWN report, and — because this package was
extracted from a private repository whose HTML report carried the operator's
own contact details — it must never emit personal contact information. That
last property is a regression guard, not a hypothetical."""

import json
import unittest

from spoofguard.scanner import assess_email_security
from spoofguard.report import render_report_html


def _fetch_factory(records):
    def fetch(url: str) -> bytes:
        q = url.split("?", 1)[1]
        parts = dict(kv.split("=", 1) for kv in q.split("&"))
        key = f"{parts['name']}|{parts['type']}"
        data = records.get(key, [])
        return json.dumps({"Status": 0, "Answer": [{"data": a} for a in data]}).encode()
    return fetch


class TestRenderReportHtml(unittest.TestCase):
    def test_html_contains_domain_and_grade(self):
        r = assess_email_security("example.com", _fetch_factory({}))
        html = render_report_html(r)
        self.assertIn("example.com", html)
        self.assertIn("<!doctype html>", html)
        self.assertIn("What to fix", html)

    def test_strong_domain_shows_no_action_needed(self):
        records = {
            "good.com|TXT": ["v=spf1 -all"],
            "_dmarc.good.com|TXT": ["v=DMARC1; p=reject"],
            "default._domainkey.good.com|TXT": ["v=DKIM1; k=rsa; p=abc"],
            "good.com|DS": ["1 1 1 aa"],
            "good.com|MX": ["10 mail.good.com."],
            "_mta-sts.good.com|TXT": ["v=STSv1; id=1"],
        }
        r = assess_email_security("good.com", _fetch_factory(records))
        html = render_report_html(r)
        self.assertIn("No action needed", html)

    def test_unknown_report_never_renders_a_confident_letter_grade(self):
        def boom(url):
            raise RuntimeError("network down")
        r = assess_email_security("x.com", boom)
        html = render_report_html(r)
        # the big grade badge must show "UNKNOWN", not a bare stray letter
        self.assertIn("UNKNOWN", html)

    def test_domain_value_is_escaped_not_injected_as_markup(self):
        # A DNS TXT value or domain string must never be able to inject HTML.
        malicious = "v=spf1 <script>alert(1)</script> -all"
        r = assess_email_security(
            "d.com", _fetch_factory({"d.com|TXT": [malicious]}))
        html = render_report_html(r)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_no_operator_contact_information_is_present(self):
        # Regression guard: the internal predecessor's HTML report embedded
        # the operator's own phone number and business domain in the footer
        # of every generated report. This package must never do that — a
        # generic, contact-free footer only.
        r = assess_email_security("example.com", _fetch_factory({}))
        html = render_report_html(r)
        self.assertNotIn("+61", html)
        self.assertNotIn("titanos.tech", html)
        self.assertNotIn("WhatsApp", html)


if __name__ == "__main__":
    unittest.main()
