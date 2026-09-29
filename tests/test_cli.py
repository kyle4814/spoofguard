"""Tests for `spoofguard/cli.py`. No network: `assess_email_security` /
`triage_domains` are patched at the point `cli.py` imports them, so these
tests exercise argument parsing, exit codes, and file output only."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from spoofguard import cli
from spoofguard.scanner import EmailSecurityReport, Finding, DomainResult


def _fake_report(domain="example.com", grade="A — strong"):
    findings = (
        Finding("SPF", "PASS", "Strong SPF (hard fail): v=spf1 -all", ""),
        Finding("DMARC", "PASS", "Enforcing DMARC (p=reject)", ""),
    )
    return EmailSecurityReport(domain=domain, findings=findings)


class TestCliArgParsing(unittest.TestCase):
    def test_no_domain_and_no_batch_is_an_error(self):
        self.assertEqual(cli.main([]), cli.EXIT_ERROR)

    def test_resolver_choices_are_restricted(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["example.com", "--resolver", "bogus"])


class TestCliSingleDomain(unittest.TestCase):
    @patch("spoofguard.cli.assess_email_security")
    def test_json_output_contains_grade_and_findings(self, mock_assess):
        mock_assess.return_value = _fake_report()
        with patch("builtins.print") as mock_print:
            rc = cli.main(["example.com", "--json"])
        self.assertEqual(rc, cli.EXIT_OK)
        printed = "\n".join(str(c.args[0]) for c in mock_print.call_args_list)
        payload = json.loads(printed)
        self.assertEqual(payload["domain"], "example.com")
        self.assertEqual(payload["grade"], "A — strong")
        self.assertEqual(len(payload["findings"]), 2)

    @patch("spoofguard.cli.assess_email_security")
    def test_md_flag_writes_a_file(self, mock_assess):
        mock_assess.return_value = _fake_report()
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.md")
            rc = cli.main(["example.com", "--md", out])
            self.assertEqual(rc, cli.EXIT_OK)
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("example.com", content)

    @patch("spoofguard.cli.assess_email_security")
    def test_html_flag_writes_a_file(self, mock_assess):
        mock_assess.return_value = _fake_report()
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.html")
            rc = cli.main(["example.com", "--html", out])
            self.assertEqual(rc, cli.EXIT_OK)
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("<!doctype html>", content)

    @patch("spoofguard.cli.assess_email_security")
    def test_resolver_and_timeout_are_forwarded(self, mock_assess):
        mock_assess.return_value = _fake_report()
        with patch("builtins.print"):
            cli.main(["example.com", "--resolver", "google", "--timeout", "5"])
        _, kwargs = mock_assess.call_args
        self.assertEqual(kwargs["resolver"], "google")
        self.assertEqual(kwargs["timeout"], 5.0)


class TestCliBatch(unittest.TestCase):
    @patch("spoofguard.cli.triage_domains")
    def test_batch_reads_file_skips_blank_and_comment_lines(self, mock_triage):
        mock_triage.return_value = [
            DomainResult("bad.com", "D — high risk, easily spoofed", True, 3, ("no SPF",)),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "domains.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# a comment\nbad.com\n\n   \n")
            with patch("builtins.print"):
                rc = cli.main(["--batch", path])
        self.assertEqual(rc, cli.EXIT_OK)
        mock_triage.assert_called_once()
        (domains_arg,), _ = mock_triage.call_args
        self.assertEqual(domains_arg, ["bad.com"])

    def test_batch_missing_file_is_a_clean_error_not_a_traceback(self):
        rc = cli.main(["--batch", "/no/such/file/exists.txt"])
        self.assertEqual(rc, cli.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()
