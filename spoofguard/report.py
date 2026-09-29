"""
SpoofGuard report rendering — turn an `EmailSecurityReport` into something a
human reads: a Markdown report (terminal/GitHub/ticket-friendly) or a
self-contained HTML report (open in any browser, attach to an email, no
external resources — no fonts, no scripts, no images, so it renders
identically offline).

HONEST BY CONSTRUCTION, same as `scanner.py`:
  - Every value shown comes from the report; nothing here is invented.
  - An UNKNOWN (incomplete) scan renders as UNKNOWN, never a confident grade.
  - All dynamic text in the HTML report is escaped — a domain or a DNS string
    cannot inject markup.
  - The scope disclaimer (posture check, not a full audit) travels with both
    formats, always.
"""

from __future__ import annotations

from html import escape
from typing import List

from .scanner import EmailSecurityReport, Finding, CRITICAL_CHECKS

__all__ = ["render_report_md", "render_report_html"]

_MARK = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "UNKNOWN": "❔"}


def render_report_md(report: EmailSecurityReport) -> str:
    L: List[str] = []
    L.append(f"# Email Security Report — {report.domain}")
    L.append("")
    L.append(f"**Overall grade: {report.grade}**")
    L.append("")
    L.append("What this checks: your domain's public email-security controls — "
             "the settings that decide whether criminals can send email that "
             "looks like it came from you (spoofing / phishing / invoice fraud).")
    L.append("")
    L.append("| Check | Status | Finding |")
    L.append("|---|---|---|")
    for f in report.findings:
        L.append(f"| **{f.check}** | {_MARK[f.status]} {f.status} | {f.detail} |")
    L.append("")
    actions = [f for f in report.findings if f.status in ("FAIL", "WARN") and f.fix]
    if actions:
        L.append("## What to fix (in priority order)")
        crit = [f for f in actions if f.check in CRITICAL_CHECKS]
        rest = [f for f in actions if f.check not in CRITICAL_CHECKS]
        for i, f in enumerate(crit + rest, 1):
            L.append(f"{i}. **{f.check}** — {f.fix}")
    else:
        L.append("## No action needed — email security controls are strong. ✅")
    L.append("")
    L.append("---")
    L.append("*Scope: this report reads public DNS records only. It is an "
             "email-security posture check, not a full security audit or "
             "penetration test. Findings reflect the domain's DNS at the time of "
             "the check.*")
    return "\n".join(L)


# Grade letter -> (accent colour, plain-English one-liner). Neutral, brandable.
_GRADE_STYLE = {
    "A": ("#1a7f4b", "Strong — email spoofing is well defended."),
    "B": ("#3d7a1f", "Good, with minor gaps worth closing."),
    "C": ("#b8860b", "Real gaps — this domain can be spoofed."),
    "D": ("#b3261e", "High risk — email can be forged in your name right now."),
    "U": ("#5a5a5a", "Not assessed — some DNS lookups did not complete."),
}

_STATUS_STYLE = {
    "PASS": ("#1a7f4b", "PASS"),
    "WARN": ("#b8860b", "WARN"),
    "FAIL": ("#b3261e", "FAIL"),
    "UNKNOWN": ("#5a5a5a", "UNKNOWN"),
}


def _grade_key(report: EmailSecurityReport) -> str:
    g = report.grade[0]
    return g if g in ("A", "B", "C", "D") else "U"


def render_report_html(report: EmailSecurityReport,
                       title: str = "Email Security Report") -> str:
    """A complete, self-contained HTML report for one domain: grade, what is
    exposed, and what to fix, in priority order."""
    domain = escape(report.domain)
    gk = _grade_key(report)
    accent, gradeline = _GRADE_STYLE[gk]

    finding_rows = []
    for f in report.findings:
        colour, label = _STATUS_STYLE.get(f.status, _STATUS_STYLE["UNKNOWN"])
        finding_rows.append(
            "<tr>"
            f"<td class=\"chk\">{escape(f.check)}</td>"
            f"<td><span class=\"pill\" style=\"background:{colour}\">{label}</span></td>"
            f"<td>{escape(f.detail)}</td>"
            "</tr>")

    actions = [f for f in report.findings if f.status in ("FAIL", "WARN") and f.fix]
    fixes_section = ""
    if actions:
        crit = [f for f in actions if f.check in CRITICAL_CHECKS]
        rest = [f for f in actions if f.check not in CRITICAL_CHECKS]
        items = "".join(
            f"<li><strong>{escape(f.check)}</strong> — {escape(f.fix)}</li>"
            for f in crit + rest)
        fixes_section = f"""
    <section>
      <h2>What to fix (in priority order)</h2>
      <ol class="fixes">
{items}
      </ol>
    </section>"""
    else:
        fixes_section = """
    <section>
      <h2>No action needed ✅</h2>
      <p>Every email-security control checked here is already strong.</p>
    </section>"""

    body = f"""
  <header class="hero">
    <div class="grade" style="border-color:{accent};color:{accent}">
      {escape(report.grade.split(' ')[0])}
    </div>
    <div class="head-text">
      <h1>Email security: {domain}</h1>
      <p class="lead" style="color:{accent}">{escape(gradeline)}</p>
    </div>
  </header>

  <section>
    <h2>What this checks</h2>
    <p>The public DNS settings that decide whether a criminal can send email that
    looks exactly like it came from {domain} — the fake-invoice and phishing risk
    to your own customers and suppliers.</p>
    <table class="findings">
      <thead><tr><th>Control</th><th>Status</th><th>What we found</th></tr></thead>
      <tbody>
{chr(10).join(finding_rows)}
      </tbody>
    </table>
  </section>
{fixes_section}

  <footer>
    <p>Generated from {domain}'s public DNS records only — no scanning of your
    systems, no credentials, nothing collected. This is an email-security posture
    check, not a full security audit or penetration test; it reflects your DNS at
    the time of the check.</p>
    <p class="sigil">Generated by <strong>SpoofGuard</strong> — a free, open-source,
    zero-dependency email security scanner.<br>
    <a href="https://github.com/kyle4814/spoofguard">github.com/kyle4814/spoofguard</a></p>
  </footer>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} — {domain}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#f6f7f9; color:#1a1c1e;
         font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:760px; margin:0 auto; padding:28px 20px 56px; }}
  .hero {{ display:flex; gap:20px; align-items:center; background:#fff;
          border:1px solid #e3e6ea; border-radius:14px; padding:22px 24px; margin-bottom:22px; }}
  .grade {{ flex:0 0 auto; width:74px; height:74px; border:3px solid; border-radius:14px;
           display:flex; align-items:center; justify-content:center;
           font-size:34px; font-weight:800; letter-spacing:-1px; }}
  h1 {{ font-size:22px; margin:0 0 4px; letter-spacing:-.3px; }}
  .lead {{ margin:0; font-weight:600; }}
  section {{ background:#fff; border:1px solid #e3e6ea; border-radius:14px;
            padding:20px 24px; margin-bottom:18px; }}
  h2 {{ font-size:16px; margin:0 0 12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:14.5px; }}
  th {{ text-align:left; color:#5a5f66; font-weight:600; border-bottom:2px solid #eceef1;
       padding:8px 10px; }}
  td {{ padding:9px 10px; border-bottom:1px solid #f0f2f4; vertical-align:top; }}
  .chk {{ font-weight:600; white-space:nowrap; }}
  .pill {{ color:#fff; font-size:12px; font-weight:700; padding:2px 9px; border-radius:20px;
          letter-spacing:.4px; }}
  .fixes {{ margin:0; padding-left:20px; font-size:14.5px; }}
  .fixes li {{ margin-bottom:8px; }}
  .sigil {{ margin-top:14px; padding-top:12px; border-top:1px solid #e3e6ea; color:#3a3f45; }}
  .sigil a {{ color:inherit; }}
  footer {{ color:#6b7076; font-size:12.5px; padding:4px 6px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#15171a; color:#e6e8ea; }}
    .hero, section {{ background:#1e2125; border-color:#2c3037; }}
    th {{ color:#9aa0a6; border-bottom-color:#2c3037; }}
    td {{ border-bottom-color:#24272c; }}
    .sigil, footer {{ color:#9aa0a6; }}
  }}
</style>
</head>
<body>
  <div class="wrap">
{body}
  </div>
</body>
</html>"""
