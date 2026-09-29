"""SpoofGuard command-line interface.

    python -m spoofguard example.com
    python -m spoofguard example.com --html report.html
    python -m spoofguard example.com --md report.md
    python -m spoofguard example.com --json
    python -m spoofguard --batch domains.txt

Reads public DNS only. No credentials, no scanning of anyone's systems.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import List, Optional, Sequence

from .scanner import assess_email_security, triage_domains, EmailSecurityReport
from .report import render_report_md, render_report_html

EXIT_OK = 0
EXIT_ERROR = 2


def _report_to_dict(report: EmailSecurityReport) -> dict:
    return {
        "domain": report.domain,
        "grade": report.grade,
        "findings": [
            {"check": f.check, "status": f.status, "detail": f.detail, "fix": f.fix}
            for f in report.findings
        ],
    }


def _print_text(report: EmailSecurityReport) -> None:
    print(f"SpoofGuard — {report.domain}")
    print(f"Grade: {report.grade}")
    print()
    width = max(len(f.check) for f in report.findings)
    for f in report.findings:
        print(f"  {f.check.ljust(width)}  {f.status:<8}{f.detail}")
    actions = [f for f in report.findings if f.status in ("FAIL", "WARN") and f.fix]
    print()
    if actions:
        print("What to fix:")
        for f in actions:
            print(f"  - [{f.check}] {f.fix}")
    else:
        print("No action needed — email security controls are strong.")


def _print_batch_text(results) -> None:
    print(f"SpoofGuard batch — {len(results)} domain(s), most exposed first")
    print()
    if not results:
        print("  (no domains given)")
        return
    width = max(len(r.domain) for r in results)
    for r in results:
        flag = "SPOOFABLE" if r.spoofable else "ok"
        print(f"  [{r.severity}] {r.domain.ljust(width)}  {r.grade:<32}{flag}")


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spoofguard",
        description="Scan a domain's public DNS for email-spoofing exposure "
                    "(SPF / DMARC / DKIM / DNSSEC / MX / MTA-STS). "
                    "Reads public DNS only — no credentials, no scanning of "
                    "anyone's systems.",
    )
    p.add_argument("domain", nargs="?",
                   help="domain to scan, e.g. example.com")
    p.add_argument("--batch", metavar="FILE",
                   help="scan every domain listed in FILE (one per line, "
                        "'#' comments allowed), sorted most-exposed-first")
    p.add_argument("--md", metavar="FILE", help="write a Markdown report to FILE")
    p.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    p.add_argument("--json", action="store_true",
                   help="print machine-readable JSON instead of text")
    p.add_argument("--resolver", choices=("cloudflare", "google"), default="cloudflare",
                   help="DNS-over-HTTPS resolver to use (default: cloudflare)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-lookup network timeout in seconds (default: 10)")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.domain and not args.batch:
        parser.print_usage(sys.stderr)
        print("spoofguard: error: provide a domain, or --batch FILE", file=sys.stderr)
        return EXIT_ERROR

    if args.batch:
        try:
            with open(args.batch, "r", encoding="utf-8") as fh:
                domains: List[str] = [
                    line.strip() for line in fh
                    if line.strip() and not line.strip().startswith("#")
                ]
        except OSError as e:
            print(f"spoofguard: error: could not read {args.batch}: {e}", file=sys.stderr)
            return EXIT_ERROR
        results = triage_domains(domains, resolver=args.resolver, timeout=args.timeout)
        if args.json:
            print(json.dumps([asdict(r) for r in results], indent=2))
        else:
            _print_batch_text(results)
        return EXIT_OK

    report = assess_email_security(args.domain, resolver=args.resolver, timeout=args.timeout)

    wrote_a_file = False
    if args.md:
        _write(args.md, render_report_md(report))
        print(f"Wrote Markdown report to {args.md}")
        wrote_a_file = True
    if args.html:
        _write(args.html, render_report_html(report))
        print(f"Wrote HTML report to {args.html}")
        wrote_a_file = True

    if args.json:
        print(json.dumps(_report_to_dict(report), indent=2))
    elif not wrote_a_file:
        _print_text(report)
    else:
        print(f"Grade: {report.grade}")

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
