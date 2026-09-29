"""
SpoofGuard scanner — the checks, the grading, and the DNS-over-HTTPS fetch.

Give it a domain and it reads that domain's PUBLIC DNS records (SPF, DMARC,
DKIM, DNSSEC, MX, MTA-STS) and grades how resistant it is to email spoofing —
the technique behind invoice fraud and "CEO fraud" phishing, where a criminal
sends mail that looks exactly like it came from a real business. No client
credentials, no intrusion, nothing beyond a public DNS lookup: it is safe and
legal to run against any domain.

HONEST BY CONSTRUCTION:
  - This reads public DNS only. It is an email-security POSTURE check, not a
    full security audit — the report says so, every time.
  - A control that is absent is reported as absent (FAIL / spoofable), never
    hand-waved. A control that is present but weak is WARN, never PASS.
  - A control whose DNS lookup FAILED (network error, timeout, malformed
    response) is UNKNOWN — never scored as absent. A failed read is not
    evidence of a missing record. A report with any UNKNOWN check grades
    UNKNOWN, not a letter, because it was not fully assessed. This is the
    single most important property in this file: it is what stops a network
    hiccup from manufacturing a false "this domain is spoofable" finding.
  - Every check takes a `fetch` callable as its actual dependency (see
    `FetchFn` below). Tests inject a fake one and never touch the network;
    `assess_email_security()` builds a real one (`make_doh_fetch`) only when
    the caller doesn't supply their own.

WHAT CHANGED FROM THE INTERNAL VERSION THIS WAS EXTRACTED FROM: the original
routed every DNS lookup through a private governance stack (an internal
authorization policy, a query-budget ledger, a communication gate) that only
makes sense inside the larger private system it came from. None of that
belongs in a standalone public tool, so it has been removed entirely — this
file's only runtime dependency is the Python standard library
(`urllib.request`). The check logic and grading rules are unchanged.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

__all__ = [
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
]

# ---------------------------------------------------------------------------
# DNS-over-HTTPS fetch — the only network-touching code in this package.
# ---------------------------------------------------------------------------

# Public DoH resolvers that speak the same JSON shape (Google's native format,
# which Cloudflare also implements when asked for `application/dns-json`):
# {"Status": 0, "Answer": [{"name": ..., "type": ..., "data": "..."}, ...]}.
# `_query()` below always builds its request URL against the Cloudflare path;
# `make_doh_fetch()` retargets the host (keeping the query string) when a
# different resolver is chosen. That indirection is what lets a caller inject
# any fetch callable at all — including the tests' fake one, which ignores the
# host entirely and only looks at the query string.
DOH_RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}
DEFAULT_RESOLVER = "cloudflare"
DEFAULT_TIMEOUT = 10.0

_QUERY_URL_BASE = DOH_RESOLVERS[DEFAULT_RESOLVER]
_USER_AGENT = "SpoofGuard/0.1.0 (open-source email security posture scanner)"

# Common DKIM selectors to probe (a domain may use a custom one — absence here
# is reported as "not found at common selectors", never as "no DKIM").
_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail",
                   "dkim", "s1", "s2", "zoho", "mandrill", "sendgrid")

# A single scan issues up to ~17 DoH lookups (DKIM alone probes 12 selectors).
# Public resolvers are built for exactly this volume from a single client; no
# internal rate-limiting is applied here. Batch scanning many domains (see
# `triage_domains`) is a courtesy to the resolver you choose, at your call.

FetchFn = Callable[[str], bytes]


class LookupFailed(Exception):
    """The DoH read itself failed (network error, timeout, unparseable
    response). This is NOT the same as a successful lookup that returned no
    records — a failed read is UNKNOWN, an empty read is absent. Conflating
    the two is exactly how a broken fetch manufactures a false 'spoofable'
    finding, so the two paths are kept strictly separate everywhere below."""


def make_doh_fetch(resolver: str = DEFAULT_RESOLVER,
                   timeout: float = DEFAULT_TIMEOUT) -> FetchFn:
    """Build a real `FetchFn` that resolves a DoH query via stdlib
    `urllib.request` against a public resolver — zero third-party
    dependencies. Raises on any network/HTTP/timeout error; callers (via
    `_query`) turn that into `LookupFailed`, which every check treats as
    UNKNOWN, never as 'record absent'."""
    try:
        target = DOH_RESOLVERS[resolver]
    except KeyError:
        raise ValueError(
            f"unknown DoH resolver {resolver!r}; choose one of "
            f"{sorted(DOH_RESOLVERS)}") from None

    def fetch(url: str) -> bytes:
        query = urllib.parse.urlsplit(url).query
        full_url = f"{target}?{query}"
        req = urllib.request.Request(
            full_url,
            headers={"Accept": "application/dns-json", "User-Agent": _USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https DoH host)
            return resp.read()

    return fetch


def _query(name: str, rrtype: str, fetch: FetchFn) -> dict:
    """One DoH query. Returns the parsed JSON dict (with Answer/AD/Status) on
    success — including a valid response that simply has no Answer. Raises
    `LookupFailed` if the fetch or JSON parse fails, so a caller can tell
    'record absent' from 'could not read'."""
    qs = urllib.parse.urlencode({"name": name, "type": rrtype})
    url = f"{_QUERY_URL_BASE}?{qs}"
    try:
        raw = fetch(url)
    except Exception as e:
        raise LookupFailed(f"fetch failed for {name}/{rrtype}: {e}") from e
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise LookupFailed(f"unparseable DoH response for {name}/{rrtype}: {e}") from e


def _txt_records(name: str, fetch: FetchFn) -> List[str]:
    d = _query(name, "TXT", fetch)
    out: List[str] = []
    for a in d.get("Answer", []) or []:
        val = str(a.get("data", "")).strip()
        # DoH returns TXT wrapped in quotes; concatenate multi-string TXT.
        val = val.replace('" "', "").strip('"')
        if val:
            out.append(val)
    return out


# ---------------------------------------------------------------------------
# Findings and checks — the crown jewels. Logic unchanged from the internal
# version; only the fetch layer above it changed.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    check: str          # e.g. "SPF"
    status: str         # PASS / WARN / FAIL / UNKNOWN
    detail: str         # what was found
    fix: str            # plain-English remediation ("" if PASS)


def _spf(domain: str, fetch: FetchFn) -> Finding:
    spf_records = [r for r in _txt_records(domain, fetch)
                   if r.lower().startswith("v=spf1")]
    if not spf_records:
        return Finding("SPF", "FAIL",
                       "No SPF record — anyone can forge email from this domain.",
                       "Publish an SPF TXT record listing your mail senders, "
                       "ending in -all (hard fail).")
    if len(spf_records) > 1:
        # RFC 7208 §3.2: more than one v=spf1 record is a PermError, and
        # receivers then apply NO SPF policy at all — the domain is spoofable
        # despite "having SPF". A false PASS here is the worst error a security
        # check can make, so this is FAIL, not a footnote.
        return Finding("SPF", "FAIL",
                       f"Multiple SPF records ({len(spf_records)}) — this is a "
                       f"permanent error (PermError); receivers ignore SPF "
                       f"entirely, so the domain is spoofable despite having SPF.",
                       "Publish exactly ONE SPF TXT record: merge every sender "
                       "into a single v=spf1 record ending in -all.")
    spf = spf_records[0]
    # Read the qualifier on the FIRST `all` mechanism. RFC 7208 §4.6.2: SPF
    # mechanisms are evaluated left-to-right and the FIRST match wins; `all`
    # always matches, so the first `all`-mechanism is the one a real receiver
    # applies, and anything after it is unreachable. Scanning in reverse would
    # read whichever `all` was written LAST — e.g. `v=spf1 +all -all` is wide
    # open (+all matches first) yet a reverse read sees -all and calls it
    # "strong": a false PASS on a spoofable domain, the worst error possible.
    # Match the mechanism EXACTLY (strip the qualifier, compare to "all") so a
    # domain literally ending in "…all" cannot masquerade as an all-mechanism.
    # SPF qualifiers: - fail (good), ~ softfail, ? neutral, + pass; a bare
    # `all` with no qualifier DEFAULTS to +all = pass, so both authorise ANY
    # sender and must be FAIL.
    tokens = spf.lower().split()
    all_tok = next((t for t in tokens if t.lstrip("+-~?") == "all"), None)
    if all_tok == "-all":
        return Finding("SPF", "PASS", f"Strong SPF (hard fail): {spf}", "")
    if all_tok in ("+all", "all"):
        return Finding("SPF", "FAIL",
                       f"SPF explicitly authorises ALL senders "
                       f"({all_tok}) — anyone can send as this domain; this is "
                       f"worse than having no SPF: {spf}",
                       "Change the SPF record's ending to -all (hard fail) so only "
                       "your listed senders are authorised. Never use +all.")
    if all_tok in ("~all", "?all"):
        return Finding("SPF", "WARN",
                       f"SPF present but soft/neutral, not enforced ({all_tok}): {spf}",
                       "Change the SPF record's ending to -all so forged mail is "
                       "rejected, not just flagged.")
    return Finding("SPF", "WARN", f"SPF present, no explicit all mechanism: {spf}",
                   "Add a -all mechanism to the end of the SPF record.")


def _dmarc_tag(rec: str, tag: str) -> str:
    """The value of one DMARC tag (e.g. `p`, `sp`, `pct`), lowercased, or "".
    Parses the actual tag — NOT a substring match, which would read `p=reject`
    out of the `sp=reject` (subdomain policy) tag. Found live against a domain
    whose record was `p=quarantine; sp=reject`."""
    for part in rec.split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            if key.strip().lower() == tag:
                return val.strip().lower()
    return ""


def _dmarc_policy(rec: str) -> str:
    """The DMARC domain policy (`p=`), lowercased, or ""."""
    return _dmarc_tag(rec, "p")


def _dmarc(domain: str, fetch: FetchFn) -> Finding:
    recs = [r for r in _txt_records(f"_dmarc.{domain}", fetch)
            if r.lower().startswith("v=dmarc1")]
    if not recs:
        return Finding("DMARC", "FAIL",
                       "No DMARC record — no policy telling receivers what to do "
                       "with forged mail, and no visibility of abuse.",
                       "Publish a _dmarc TXT record, start at p=none with rua "
                       "reporting, then move to p=quarantine and p=reject.")
    if len(recs) > 1:
        # RFC 7489 §6.6.3: when more than one DMARC record is published,
        # receivers apply NONE of them. A domain with two DMARC records is
        # unprotected despite "having DMARC" — a false PASS, so it is FAIL.
        return Finding("DMARC", "FAIL",
                       f"Multiple DMARC records ({len(recs)}) — receivers ignore "
                       f"DMARC entirely when more than one is published, so forged "
                       f"mail is not blocked despite DMARC being present.",
                       "Publish exactly ONE _dmarc TXT record.")
    rec = recs[0]
    policy = _dmarc_policy(rec)
    pct = _dmarc_tag(rec, "pct")
    # pct defaults to 100 when absent. A pct below 100 means the policy is
    # applied to only that share of failing mail; the rest bypasses it, so
    # p=reject;pct=0 rejects NOTHING. Enforcement below 100% is not full.
    weak_pct = pct.isdigit() and int(pct) < 100
    if policy == "reject" and not weak_pct:
        return Finding("DMARC", "PASS", f"Enforcing DMARC (p=reject): {rec}", "")
    if policy == "reject" and weak_pct:
        return Finding("DMARC", "WARN",
                       f"DMARC p=reject but only pct={pct}% enforced — the other "
                       f"{100 - int(pct)}% of failing mail bypasses the policy: {rec}",
                       "Set pct=100 (or remove the pct tag) so the reject policy "
                       "applies to all forged mail.")
    if policy == "quarantine":
        extra = f" and only pct={pct}% enforced" if weak_pct else ""
        return Finding("DMARC", "WARN",
                       f"DMARC quarantining, not rejecting (p=quarantine){extra}: {rec}",
                       "Once reports look clean, move the policy to p=reject "
                       "with pct=100.")
    return Finding("DMARC", "WARN",
                   f"DMARC in monitor-only mode (p={policy or 'none'}): {rec}",
                   "p=none only watches — move to p=quarantine then p=reject to "
                   "actually block forged mail.")


def _dkim(domain: str, fetch: FetchFn) -> Finding:
    found = []
    for sel in _DKIM_SELECTORS:
        d = _query(f"{sel}._domainkey.{domain}", "TXT", fetch)
        recs = [str(a.get("data", "")) for a in d.get("Answer", []) or []]
        # A selector "has a key" only if it publishes a NON-EMPTY p= tag,
        # parsed as a real DKIM tag rather than matched as a substring.
        # RFC 6376 §3.6.1: an empty p= (`v=DKIM1; p=`) is an explicitly REVOKED
        # key — there is no signing key — and a bare "p=" substring can also
        # appear inside unrelated records. `_dmarc_tag` parses `key=value;`
        # tags and returns "" for both the revoked and the substring cases.
        if any(_dmarc_tag(r, "p") for r in recs):
            found.append(sel)
    if found:
        return Finding("DKIM", "PASS",
                       f"DKIM signing keys found (selectors: {', '.join(found)}).", "")
    return Finding("DKIM", "WARN",
                   "No DKIM key found at common selectors (a custom selector may "
                   "be in use — confirm with the mail provider).",
                   "Enable DKIM signing with your mail provider and publish the "
                   "key, so receivers can cryptographically verify your mail.")


def _dnssec(domain: str, fetch: FetchFn) -> Finding:
    d = _query(domain, "DS", fetch)
    if d.get("Answer"):
        return Finding("DNSSEC", "PASS",
                       "DNSSEC enabled (DS record present) — DNS answers are "
                       "signed and tamper-evident.", "")
    return Finding("DNSSEC", "WARN",
                   "DNSSEC not enabled — DNS responses are not cryptographically "
                   "signed.",
                   "Enable DNSSEC at your DNS host to protect against DNS "
                   "spoofing/cache poisoning.")


def _mx(domain: str, fetch: FetchFn) -> Finding:
    d = _query(domain, "MX", fetch)
    ans = d.get("Answer", []) or []
    if ans:
        hosts = ", ".join(sorted({str(a.get("data", "")).split()[-1].rstrip(".")
                                  for a in ans if a.get("data")}))
        return Finding("MX", "PASS", f"Mail servers configured: {hosts}", "")
    return Finding("MX", "WARN",
                   "No MX records — this domain does not receive email (or is "
                   "misconfigured).",
                   "If this domain should receive mail, add MX records.")


def _mta_sts(domain: str, fetch: FetchFn) -> Finding:
    rec = next((r for r in _txt_records(f"_mta-sts.{domain}", fetch)
                if r.lower().startswith("v=stsv1")), None)
    if rec:
        return Finding("MTA-STS", "PASS",
                       "MTA-STS present — enforces TLS on inbound mail.", "")
    return Finding("MTA-STS", "WARN",
                   "No MTA-STS — inbound mail can be delivered over unencrypted "
                   "connections.",
                   "Publish an MTA-STS policy to require TLS for mail to your "
                   "domain (optional, best-practice).")


# Order shown in the report: the spoofing-critical three first.
_CHECKS = (_spf, _dmarc, _dkim, _dnssec, _mx, _mta_sts)
# Weight the report grade toward the controls that actually stop spoofing.
CRITICAL_CHECKS = frozenset({"SPF", "DMARC", "DKIM"})

_CHECK_LABELS = {
    _spf: "SPF", _dmarc: "DMARC", _dkim: "DKIM",
    _dnssec: "DNSSEC", _mx: "MX", _mta_sts: "MTA-STS",
}


@dataclass(frozen=True)
class EmailSecurityReport:
    domain: str
    findings: Tuple[Finding, ...]

    @property
    def grade(self) -> str:
        # A report that could not complete every check was not fully assessed;
        # it does not get a confident letter. UNKNOWN is not FAIL — a failed
        # lookup is never scored as a spoofable gap.
        if any(f.status == "UNKNOWN" for f in self.findings):
            return "UNKNOWN — lookup incomplete, not assessed"
        crit = [f for f in self.findings if f.check in CRITICAL_CHECKS]
        crit_fail = sum(1 for f in crit if f.status == "FAIL")
        crit_warn = sum(1 for f in crit if f.status == "WARN")
        any_fail = any(f.status == "FAIL" for f in self.findings)
        if crit_fail == 0 and crit_warn == 0 and not any_fail:
            return "A — strong"
        if crit_fail == 0 and crit_warn <= 1:
            return "B — good, minor gaps"
        if crit_fail <= 1:
            return "C — real gaps, spoofable"
        return "D — high risk, easily spoofed"

    @property
    def fails(self) -> Tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.status == "FAIL")


def _run_check(check, domain: str, fetch: FetchFn) -> Finding:
    """Run one check; if the DNS read failed, return UNKNOWN rather than
    letting an absent-record path score a lookup failure as a finding."""
    try:
        return check(domain, fetch)
    except LookupFailed as e:
        return Finding(_CHECK_LABELS[check], "UNKNOWN",
                       f"DNS lookup failed for this check — status not assessed "
                       f"({e}).", "")


def assess_email_security(domain: str,
                          fetch_fn: Optional[FetchFn] = None,
                          resolver: str = DEFAULT_RESOLVER,
                          timeout: float = DEFAULT_TIMEOUT) -> EmailSecurityReport:
    """Scan one domain and return its graded email-security posture report.

    `fetch_fn`, when given, replaces the network entirely (this is the seam
    every test in this package uses). When omitted, a real DoH fetch is built
    against `resolver` ("cloudflare" or "google", see `DOH_RESOLVERS`)."""
    domain = domain.strip().lower().rstrip(".")
    fetch = fetch_fn or make_doh_fetch(resolver=resolver, timeout=timeout)
    findings = tuple(_run_check(check, domain, fetch) for check in _CHECKS)
    return EmailSecurityReport(domain=domain, findings=findings)


# ---------------------------------------------------------------------------
# Batch scanning — prioritise many domains by how exposed they are.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DomainResult:
    """One domain's result inside a batch scan: the graded report plus a
    `severity` sort key. Useful for an MSP triaging client domains, or a
    company auditing its own subsidiary/brand domains, by which needs
    attention first. Reuses `EmailSecurityReport` rather than duplicating its
    fields — this is a ranking view over it, not a second source of truth."""
    domain: str
    grade: str
    spoofable: bool
    severity: int                    # 0 (clean) .. 3 (most exposed) — a sort key, not a claim
    critical_gaps: Tuple[str, ...]    # failing/weak SPF+DMARC+DKIM findings, plain-English


def _to_domain_result(report: EmailSecurityReport) -> DomainResult:
    by_check = {f.check: f for f in report.findings}
    spf_s = by_check["SPF"].status if "SPF" in by_check else "FAIL"
    dmarc_s = by_check["DMARC"].status if "DMARC" in by_check else "FAIL"

    spoofable = spf_s in ("FAIL", "WARN") or dmarc_s in ("FAIL", "WARN")
    fails = sum(1 for s in (spf_s, dmarc_s) if s == "FAIL")
    warns = sum(1 for s in (spf_s, dmarc_s) if s == "WARN")
    if fails >= 2:
        severity = 3
    elif fails == 1:
        severity = 2
    elif warns >= 1:
        severity = 1
    else:
        severity = 0

    critical_gaps = tuple(f.detail for f in report.findings
                          if f.check in CRITICAL_CHECKS and f.status in ("FAIL", "WARN"))
    return DomainResult(domain=report.domain, grade=report.grade, spoofable=spoofable,
                        severity=severity, critical_gaps=critical_gaps)


def triage_domains(domains: List[str],
                   fetch_fn: Optional[FetchFn] = None,
                   resolver: str = DEFAULT_RESOLVER,
                   timeout: float = DEFAULT_TIMEOUT) -> List[DomainResult]:
    """Scan many domains and return results sorted MOST-EXPOSED-FIRST — e.g.
    "which of the domains I'm responsible for needs attention first." Reads
    public DNS only, exactly like a single scan; `fetch_fn` is injected in
    tests the same way as `assess_email_security`."""
    results = [_to_domain_result(assess_email_security(d, fetch_fn, resolver=resolver,
                                                        timeout=timeout))
               for d in domains if str(d).strip()]
    results.sort(key=lambda r: (-r.severity, r.domain))
    return results
