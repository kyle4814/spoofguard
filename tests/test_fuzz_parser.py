"""Fuzz + property tests for the record parser — the exact surface where the
2026-09-29 hostile review found three grading bugs (SPF last-token, DKIM
revoked-key, UNKNOWN-renders-strong).

Zero dependencies, deterministic (seeded): stdlib `random` only, so this runs
in the same offline, no-install environment as the rest of the suite.

Two invariants, both security-critical for a tool whose one promise is "never
call a spoofable domain safe":

  1. CRASH-FREE: no random or malformed DNS record may raise out of
     `assess_email_security`. A scanner that crashes on a hostile record is a
     scanner an attacker can silence.
  2. NO FALSE PASS ON `+all`: whenever the SPF record's FIRST all-mechanism is
     `+all` (anyone may send — wide open), the SPF finding must never be PASS,
     no matter what noise surrounds it. This is the precise bug class that
     graded `v=spf1 +all -all` as PASS before the fix.
"""

import random
import string
import unittest

from spoofguard.scanner import assess_email_security


def _make_fetch(records):
    """records: dict 'name|TYPE' -> list of record-data strings."""
    import json

    def fetch(url: str) -> bytes:
        q = url.split("?", 1)[1]
        parts = dict(kv.split("=", 1) for kv in q.split("&"))
        key = f"{parts['name']}|{parts['type']}"
        return json.dumps(
            {"Status": 0, "Answer": [{"data": a} for a in records.get(key, [])]}
        ).encode()

    return fetch


def _grade_letter(report):
    return report.grade[0]


_SPF_TOKENS = [
    "v=spf1", "include:example.org", "include:", "ip4:1.2.3.0/24", "ip6:::1",
    "a", "mx", "ptr", "exists:%{i}", "redirect=x.com", "exp=e.com",
    "~all", "-all", "+all", "?all", "all", "", "  ", "v=spf1 v=spf1",
    "%%%", "=", "::", "\t", "include", "ip4:", "999.999.999.999/0",
]
_DMARC_TOKENS = [
    "v=DMARC1", "p=none", "p=quarantine", "p=reject", "sp=reject", "sp=none",
    "pct=100", "pct=0", "pct=50", "rua=mailto:x@y.com", "adkim=s", "aspf=r",
    "", "p=", "p=bogus", "v=DMARC1 v=DMARC1", "garbage", ";;;",
]
_DKIM_TOKENS = [
    "v=DKIM1", "k=rsa", "p=MIGfMA0GCSqGSIb3AAA", "p=", "t=y", "h=sha256",
    "", "p=;", "site-verify=abc&p=9", "v=DKIM1; p=", "notakey", "====",
]


def _noise(rng):
    return "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 40)))


class TestParserNeverCrashes(unittest.TestCase):
    def test_random_records_never_raise_and_always_grade(self):
        rng = random.Random(1141)
        for _ in range(2000):
            spf = " ".join(rng.choice(_SPF_TOKENS + [_noise(rng)])
                           for _ in range(rng.randint(0, 8)))
            dmarc = ";".join(rng.choice(_DMARC_TOKENS + [_noise(rng)])
                             for _ in range(rng.randint(0, 6)))
            dkim = ";".join(rng.choice(_DKIM_TOKENS + [_noise(rng)])
                            for _ in range(rng.randint(0, 6)))
            records = {
                "d.com|TXT": [spf],
                "_dmarc.d.com|TXT": [dmarc],
                "default._domainkey.d.com|TXT": [dkim],
                "d.com|MX": ["10 mail.d.com."],
                "d.com|DNSKEY": [],
                "_mta-sts.d.com|TXT": [],
            }
            report = assess_email_security("d.com", _make_fetch(records))
            self.assertIn(_grade_letter(report), set("ABCDU"),
                          f"invalid grade {report.grade!r} for spf={spf!r}")


class TestNoFalsePassUnderFuzz(unittest.TestCase):
    def test_plus_all_first_is_never_spf_pass(self):
        """The bug class that graded `v=spf1 +all -all` as PASS. Put +all as the
        first all-mechanism, bury it in random noise, and SPF must never PASS."""
        rng = random.Random(4814)
        trailers = ["-all", "~all", "?all", "-all ~all", "", "-all -all"]
        for _ in range(500):
            noise = " ".join(rng.choice(["include:x.com", "ip4:1.2.3.4", "a", "mx", "exists:z"])
                             for _ in range(rng.randint(0, 4)))
            spf = f"v=spf1 {noise} +all {rng.choice(trailers)}".strip()
            records = {"d.com|TXT": [spf]}
            report = assess_email_security("d.com", _make_fetch(records))
            spf_finding = next(f for f in report.findings if f.check == "SPF")
            self.assertNotEqual(
                spf_finding.status, "PASS",
                f"FALSE PASS: SPF with a leading +all graded PASS for {spf!r}")


if __name__ == "__main__":
    unittest.main()
