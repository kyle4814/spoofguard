"""
SpoofGuard — a zero-dependency, honest-by-construction email spoofing scanner.

Reads a domain's public DNS (SPF, DMARC, DKIM, DNSSEC, MX, MTA-STS) over
DNS-over-HTTPS and grades how resistant it is to email spoofing — the
technique behind invoice fraud and phishing-as-you. See README.md for the
full pitch, the grading rules, and the honest limitations.

    >>> from spoofguard import assess_email_security, render_report_md
    >>> report = assess_email_security("example.com")   # doctest: +SKIP
    >>> print(render_report_md(report))                 # doctest: +SKIP
"""

from .scanner import (
    Finding,
    EmailSecurityReport,
    DomainResult,
    FetchFn,
    CRITICAL_CHECKS,
    DOH_RESOLVERS,
    assess_email_security,
    triage_domains,
    make_doh_fetch,
    LookupFailed,
)
from .report import render_report_md, render_report_html

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Finding",
    "EmailSecurityReport",
    "DomainResult",
    "FetchFn",
    "CRITICAL_CHECKS",
    "DOH_RESOLVERS",
    "assess_email_security",
    "triage_domains",
    "make_doh_fetch",
    "LookupFailed",
    "render_report_md",
    "render_report_html",
]
