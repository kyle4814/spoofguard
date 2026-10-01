"""
spoofguard.mcp_server — a zero-dependency Model Context Protocol (MCP) server
exposing SpoofGuard's email-spoofing posture checks (SPF / DMARC / DKIM /
DNSSEC / MX / MTA-STS, read from public DNS only) as MCP tools over stdio.

PROTOCOL VERSION AND SOURCE — verified 2026-10-01
--------------------------------------------------
Checked directly against the primary source at https://modelcontextprotocol.io/
on 2026-10-01 (fetched: /specification, /specification/2026-07-28/basic,
/specification/2026-07-28/basic/versioning, /specification/2026-07-28/server/tools,
/specification/2025-06-18/basic/lifecycle, /specification/2025-06-18/basic/transports).

As of that date the *current* published spec revision is **2026-07-28**. That
revision is a genuine redesign: it DROPS the `initialize` handshake entirely
in favour of a stateless protocol where every request carries its own
`protocolVersion` in a `_meta` field
(https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning).
That page names 2026-07-28-and-later the "Modern" era and 2025-11-25-and-
earlier the "Legacy" (handshake-based) era, and its own compatibility matrix
states plainly: "Legacy Client / Modern Server: Fails."

Every MCP client in real-world use today (Claude Desktop, Claude Code,
Cursor, the registry ecosystem this server is built to be listed on —
Smithery, PulseMCP, Glama, the official MCP Registry) implements the Legacy,
`initialize`-handshake lifecycle. The Modern stateless redesign was roughly
two months old at the time this file was written and has, as far as this
build could verify, no deployed client support yet. Building strictly to
2026-07-28 would therefore make this server unable to complete a handshake
with almost every real client that might install it.

This server deliberately implements the **Legacy** lifecycle instead, at
protocol version **2025-06-18**
(https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle),
negotiating down to 2025-03-26 or 2024-11-05 if a client asks for one of
those (see `SUPPORTED_PROTOCOL_VERSIONS` below). This is a deliberate
compatibility choice, not an oversight: the versioning page's own backward-
compatibility section confirms "Legacy / Legacy: Works according to the
legacy revision" and a Legacy or Dual-era client both interoperate cleanly
with a pure Legacy server. Revisit this choice once Modern-era clients are
in real-world use — see docs/mcp-protocol-version.md (registry pack) for
the note to future maintainers.

Message shapes (from /specification/2025-06-18/basic/lifecycle, quoted in
the handlers below): `initialize` request carries `protocolVersion`,
`capabilities`, `clientInfo`; the response carries the same three keys plus
`serverInfo` and an optional `instructions` string. The client then sends a
`notifications/initialized` notification (no `id`, no response). `tools/list`
and `tools/call` shapes are from /specification/2026-07-28/server/tools,
which documents the pre-"resultType" legacy shape identically in its own
"earlier protocol versions" backward-compatibility note (a `result` with a
`content` array and an `isError` boolean, no `resultType` wrapper — this
server never emits `resultType`, matching the 2025-06-18 wire shape).

STDIO TRANSPORT RULES (from /specification/2025-06-18/basic/transports,
quoted): "Messages are delimited by newlines, and MUST NOT contain embedded
newlines." "The server MAY write UTF-8 strings to its standard error
(stderr) for logging purposes." "The server MUST NOT write anything to its
stdout that is not a valid MCP message." This implementation honours all
three: `json.dumps(...)` never embeds a literal newline inside a JSON
string's content by default, every stdout write is exactly one compact JSON
object followed by one `\n`, and `_log()` below is the only thing that ever
touches stderr.

TOOLS
-----
  check_domain     — full SPF/DMARC/DKIM/DNSSEC/MX/MTA-STS posture for one
                      domain, as structured JSON plus a short text summary.
                      Same facts as `spoofguard.scanner.assess_email_security`.
  check_domains    — batch version of the above, capped at BATCH_CAP domains
                      per call (see `check_domains`'s own inputSchema).
  explain_finding  — static, no-network explanation of what a check or a
                      status generally means. Never makes a claim about any
                      specific domain; makes zero network calls.

HONESTY RULE (same as scanner.py and report.py): an incomplete or failed DNS
lookup grades UNKNOWN, never a confident letter grade, and this server does
not add any logic on top of the scanner that could turn an UNKNOWN into a
false PASS or FAIL — it only shapes the scanner's own output into MCP's wire
format.

ERROR-REPORTING SPLIT (a convention adopted for this file, consistent with
but not fully specified by the MCP spec's own two-category model documented
on /specification/2026-07-28/server/tools under "Error Handling"):
  - Structural violations of a tool's declared `inputSchema` (the `name`
    field missing or not a string, `arguments` not an object, an unknown
    tool name, or a *required* argument key absent) are reported as
    JSON-RPC **protocol errors**, code -32602 (Invalid params) — matching
    the spec's own worked example, which uses -32602 for "Unknown tool:
    invalid_tool_name".
  - Everything about the *value* of an otherwise well-typed argument (a
    syntactically invalid domain string, an out-of-range batch size, an
    unrecognised `check` name for `explain_finding`) is reported as a
    **tool execution error** — `isError: true` in the tool result, with a
    plain-English, self-correction-friendly message — matching the spec's
    own classification of "Input validation errors (e.g. ... value out of
    range)" as Tool Execution Errors a language model can act on.

TEST SEAM — no network in tests. Real DNS lookups go through
`spoofguard.scanner.make_doh_fetch()`, same as the CLI. For
`tests/test_mcp_server.py`, which drives this server as a real subprocess
over real stdin/stdout pipes, there is no in-process closure to inject — so
this module reads the `SPOOFGUARD_MCP_TEST_FIXTURE` environment variable at
start-up; if set, it points at a JSON fixture file in the exact shape used
by `tests/test_scanner.py`'s own `make_fetch()` helper (a `name|TYPE` ->
list-of-record-strings map), plus an optional `fail` list of `name|TYPE`
keys that simulate a raised lookup failure. See `_load_fixture_fetch()`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import __version__ as _PACKAGE_VERSION
from .scanner import (
    DEFAULT_RESOLVER,
    DOH_RESOLVERS,
    EmailSecurityReport,
    FetchFn,
    assess_email_security,
    triage_domains,
)
from .report import _MARK as _STATUS_MARK  # reuse report.py's existing glyphs

__all__ = ["main", "serve"]

# ---------------------------------------------------------------------------
# Protocol identity
# ---------------------------------------------------------------------------

SERVER_NAME = "spoofguard-mcp"
SERVER_VERSION = _PACKAGE_VERSION

# The version echoed back when the client's requested version is unknown to
# us, per /specification/2025-06-18/basic/lifecycle#version-negotiation:
# "Otherwise, the server MUST respond with another protocol version it
# supports. This SHOULD be the latest version supported by the server."
DEFAULT_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

SERVER_INSTRUCTIONS = (
    "SpoofGuard checks a domain's PUBLIC DNS records (SPF, DMARC, DKIM, "
    "DNSSEC, MX, MTA-STS) for email-spoofing exposure. It reads public DNS "
    "only — no credentials, no scanning of the target's systems. A DNS "
    "lookup that fails grades UNKNOWN, never a confident PASS or FAIL; this "
    "is a posture signal, not a full security audit."
)

# ---------------------------------------------------------------------------
# JSON-RPC error codes — standard range, per
# /specification/2025-06-18 (unchanged from base JSON-RPC 2.0) and the
# worked example on /specification/2026-07-28/server/tools ("Unknown tool"
# -> -32602).
# ---------------------------------------------------------------------------

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

BATCH_CAP = 25

_CHECK_NAMES = ("SPF", "DMARC", "DKIM", "DNSSEC", "MX", "MTA-STS")
_STATUS_NAMES = ("PASS", "WARN", "FAIL", "UNKNOWN")


# ---------------------------------------------------------------------------
# stdio plumbing — exactly one JSON object per line on stdout, everything
# else (if anything) on stderr. See the transport-rules note above.
# ---------------------------------------------------------------------------

def _log(message: str) -> None:
    sys.stderr.write(f"[spoofguard-mcp] {message}\n")
    sys.stderr.flush()


def _write(obj: Dict[str, Any], out) -> None:
    out.write(json.dumps(obj, separators=(",", ":")) + "\n")
    out.flush()


def _error_obj(code: int, message: str, data: Optional[Any] = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return err


def _error_response(id_: Any, code: int, message: str,
                     data: Optional[Any] = None) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "error": _error_obj(code, message, data)}


def _result_response(id_: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


# ---------------------------------------------------------------------------
# Domain validation — strict: no URLs, no IPs, length-bounded, IDNA-aware.
#
# `scanner.assess_email_security()` itself only normalises with
# `.strip().lower().rstrip(".")` and otherwise passes the string straight
# into the DNS query's `name` parameter — it performs NO IDNA translation of
# its own (see scanner.py's module docstring: its one job is the DNS-over-
# HTTPS fetch and the grading, not input hygiene). This validator applies
# that SAME normalisation first, so "the domain" means the same string in
# both places, and then goes further: it converts a Unicode domain to its
# ASCII/punycode `xn--` form via Python's standard-library `idna` codec
# (RFC 3490) before the scanner ever sees it, because an un-encoded Unicode
# string passed through `urllib.parse.urlencode` would not reliably survive
# as a DNS-queryable name. That extra step is strictly additive to, and
# never in conflict with, the scanner's own normalisation.
# ---------------------------------------------------------------------------

_MAX_DOMAIN_LEN = 253
# Characters that have no legitimate place in a bare domain name but do
# appear in URLs, paths, ports, and IPv6 literals — rejecting them up front
# catches "https://example.com", "example.com/path", "example.com:8080",
# and "::1" / "[::1]" without needing a URL parser.
_FORBIDDEN_CHARS_RE = re.compile(r'[\s/\\?#@:\[\]<>"\'`^|%$&*()+={};,!~]')


def _validate_domain(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """Return (ascii_domain, None) if `raw` is a valid bare domain name, or
    (None, reason) if not. Never raises."""
    if not isinstance(raw, str):
        return None, "domain must be a string"
    s = raw.strip()
    if not s:
        return None, "domain must not be empty"
    if len(s) > _MAX_DOMAIN_LEN + 2:
        return None, f"domain exceeds the {_MAX_DOMAIN_LEN}-character DNS name limit"
    if _FORBIDDEN_CHARS_RE.search(s):
        return None, ("domain must be a bare hostname: no URL scheme, path, "
                       "port, brackets, or whitespace")
    normalised = s.rstrip(".").lower()
    if not normalised:
        return None, "domain must not be empty"
    try:
        ipaddress.ip_address(normalised)
        return None, "domain must be a hostname, not an IP address"
    except ValueError:
        pass
    try:
        ascii_domain = normalised.encode("idna").decode("ascii")
    except UnicodeError as e:
        return None, f"invalid domain syntax: {e}"
    if not ascii_domain or len(ascii_domain) > _MAX_DOMAIN_LEN:
        return None, f"domain exceeds the {_MAX_DOMAIN_LEN}-character DNS name limit"
    for label in ascii_domain.split("."):
        if not label or len(label) > 63:
            return None, "domain contains an empty or overlong label"
    return ascii_domain, None


# ---------------------------------------------------------------------------
# Test seam — a fixture-driven fake DNS fetch, loaded once at start-up from
# SPOOFGUARD_MCP_TEST_FIXTURE. See the module docstring's "TEST SEAM" note.
# ---------------------------------------------------------------------------

_FIXTURE_ENV = "SPOOFGUARD_MCP_TEST_FIXTURE"


def _load_fixture_fetch() -> Optional[FetchFn]:
    path = os.environ.get(_FIXTURE_ENV)
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        fixture = json.load(fh)
    records: Dict[str, List[str]] = fixture.get("records", {})
    fail_keys = set(fixture.get("fail", []))

    def fetch(url: str) -> bytes:
        import urllib.parse
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        name = q.get("name", [""])[0]
        rrtype = q.get("type", [""])[0]
        key = f"{name}|{rrtype}"
        if key in fail_keys:
            raise RuntimeError(f"simulated DNS failure for {key}")
        data = records.get(key, [])
        return json.dumps({"Status": 0,
                            "Answer": [{"data": d} for d in data]}).encode()

    return fetch


_FAKE_FETCH: Optional[FetchFn] = _load_fixture_fetch()


# ---------------------------------------------------------------------------
# explain_finding's static knowledge — no network, ever. Consistent with
# README.md's "What it checks" table and scanner.py's grading docstrings;
# written fresh here rather than imported, because this is user-facing
# explanatory prose, not executable logic.
# ---------------------------------------------------------------------------

_CHECK_EXPLANATIONS: Dict[str, str] = {
    "SPF": ("SPF (Sender Policy Framework) is a DNS TXT record that lists "
            "which mail servers are allowed to send email claiming to be "
            "from your domain. Missing, or ending in a soft/neutral "
            "qualifier instead of a hard fail (-all), means mail servers "
            "cannot reliably reject forged senders. More than one SPF "
            "record is a protocol-level PermError (RFC 7208 SS3.2): "
            "receivers then ignore SPF entirely, so the domain is "
            "spoofable despite technically 'having SPF'."),
    "DMARC": ("DMARC is a DNS TXT record (published at _dmarc.<domain>) "
              "that tells receiving mail servers what to do with mail that "
              "fails SPF/DKIM: p=none only monitors, p=quarantine sends it "
              "to spam, p=reject blocks it outright. It also gives the "
              "domain owner visibility of abuse via aggregate reports. "
              "More than one DMARC record means receivers apply NEITHER "
              "(RFC 7489 SS6.6.3), and a pct= tag below 100 means only that "
              "share of failing mail is enforced."),
    "DKIM": ("DKIM (DomainKeys Identified Mail) cryptographically signs "
             "outgoing mail with a private key so receivers can verify, "
             "using a public key published in DNS, that the message was "
             "not altered and genuinely came from a server the domain "
             "authorised. Detection here is best-effort: it checks a set "
             "of common selector names, so a domain using a custom "
             "selector can show as not-found even when DKIM is correctly "
             "configured."),
    "DNSSEC": ("DNSSEC cryptographically signs DNS responses so they "
               "cannot be silently tampered with in transit (e.g. DNS "
               "cache poisoning / spoofing). It protects the integrity of "
               "the SPF/DMARC/DKIM records themselves, among other DNS "
               "data, but is not itself an email-spoofing control."),
    "MX": ("MX records configure where a domain's incoming mail is routed. "
           "This is a liveness/configuration signal, not a security "
           "control: a domain with no MX records probably does not "
           "receive mail at all, but it can still be used to SEND forged "
           "mail (SPF/DMARC govern sending, not receiving)."),
    "MTA-STS": ("MTA-STS is a DNS + HTTPS policy that requires TLS "
                "encryption for inbound mail to a domain, so it cannot be "
                "intercepted or downgraded over an unencrypted connection "
                "in transit. It is best-practice, not required for a "
                "strong grade here."),
}

_STATUS_EXPLANATIONS: Dict[str, str] = {
    "PASS": "The control is present and strongly configured. No action needed for this control specifically.",
    "WARN": ("The control is present but weak (e.g. a soft-fail SPF, a "
             "DMARC policy of quarantine or none, DKIM not found at a "
             "common selector) — worth strengthening, not yet an active "
             "spoofing gap on its own."),
    "FAIL": ("The control is absent, or configured in a way that provides "
             "no real protection (no record at all; an SPF/DMARC record "
             "that explicitly authorises any sender; more than one "
             "SPF/DMARC record, which receivers then ignore entirely). "
             "This is an active email-spoofing gap."),
    "UNKNOWN": ("The DNS lookup for this check did not complete — a "
                "network error, timeout, or resolver failure, not a "
                "statement about what is or isn't published. SpoofGuard "
                "never scores a failed lookup as FAIL; if ANY check in a "
                "report is UNKNOWN, the whole report grades UNKNOWN rather "
                "than a confident letter, because it was not fully "
                "assessed. Re-run the check."),
}


def _explain(check: str, status: Optional[str]) -> str:
    parts = [_CHECK_EXPLANATIONS[check]]
    if status:
        parts.append(_STATUS_EXPLANATIONS[status])
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Tool result shaping
# ---------------------------------------------------------------------------

def _report_to_dict(report: EmailSecurityReport) -> Dict[str, Any]:
    return {
        "domain": report.domain,
        "grade": report.grade,
        "findings": [
            {"check": f.check, "status": f.status, "detail": f.detail, "fix": f.fix}
            for f in report.findings
        ],
    }


def _format_domain_summary(report: EmailSecurityReport) -> str:
    lines = [f"{report.domain}: {report.grade}"]
    for f in report.findings:
        mark = _STATUS_MARK.get(f.status, "?")
        lines.append(f"  {mark} {f.check}: {f.detail}")
    return "\n".join(lines)


def _tool_text_result(text: str, structured: Optional[Dict[str, Any]] = None,
                       is_error: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }
    if structured is not None:
        result["structuredContent"] = structured
    return result


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _tool_check_domain(args: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Returns (tool_result, protocol_error_message). A protocol_error_message
    means the arguments failed the tool's structural contract (-32602);
    anything else is reported inside tool_result as isError."""
    if "domain" not in args:
        return None, "missing required argument: domain"
    if not isinstance(args["domain"], str):
        return None, "domain must be a string"
    resolver = args.get("resolver", DEFAULT_RESOLVER)
    if not isinstance(resolver, str):
        return None, "resolver must be a string"
    if resolver not in DOH_RESOLVERS:
        return _tool_text_result(
            f"Unknown resolver {resolver!r}; choose one of {sorted(DOH_RESOLVERS)}.",
            is_error=True), None

    domain, err = _validate_domain(args["domain"])
    if err:
        return _tool_text_result(
            f"Invalid domain {args['domain']!r}: {err}",
            structured={"domain": args["domain"], "error": err},
            is_error=True), None

    try:
        report = assess_email_security(domain, fetch_fn=_FAKE_FETCH, resolver=resolver)
    except Exception as e:  # a scanner bug must not take the server down
        return _tool_text_result(f"Scan failed: {e}", is_error=True), None

    return _tool_text_result(_format_domain_summary(report),
                              structured=_report_to_dict(report)), None


def _tool_check_domains(args: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if "domains" not in args:
        return None, "missing required argument: domains"
    domains = args["domains"]
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        return None, "domains must be an array of strings"
    resolver = args.get("resolver", DEFAULT_RESOLVER)
    if not isinstance(resolver, str):
        return None, "resolver must be a string"
    if resolver not in DOH_RESOLVERS:
        return _tool_text_result(
            f"Unknown resolver {resolver!r}; choose one of {sorted(DOH_RESOLVERS)}.",
            is_error=True), None
    if len(domains) > BATCH_CAP:
        return _tool_text_result(
            f"Too many domains in one call: got {len(domains)}, the cap is "
            f"{BATCH_CAP} per call. Split into smaller batches.",
            is_error=True), None
    if not domains:
        return _tool_text_result(
            "domains must contain at least one domain.", is_error=True), None

    valid: List[str] = []
    invalid: List[Dict[str, str]] = []
    for raw in domains:
        if not raw.strip():
            continue
        d, err = _validate_domain(raw)
        if err:
            invalid.append({"domain": raw, "reason": err})
        else:
            valid.append(d)

    results = []
    if valid:
        try:
            results = triage_domains(valid, fetch_fn=_FAKE_FETCH, resolver=resolver)
        except Exception as e:
            return _tool_text_result(f"Batch scan failed: {e}", is_error=True), None

    results_dicts = [
        {"domain": r.domain, "grade": r.grade, "spoofable": r.spoofable,
         "severity": r.severity, "critical_gaps": list(r.critical_gaps)}
        for r in results
    ]
    structured = {"results": results_dicts, "invalid": invalid, "cap": BATCH_CAP}

    lines = [f"Checked {len(results_dicts)} domain(s) (cap {BATCH_CAP}/call)."]
    if invalid:
        lines.append(f"{len(invalid)} rejected as invalid input.")
    for r in results_dicts:
        flag = "SPOOFABLE" if r["spoofable"] else "ok"
        lines.append(f"  [{r['severity']}] {r['domain']}: {r['grade']} ({flag})")
    for inv in invalid:
        lines.append(f"  [invalid] {inv['domain']}: {inv['reason']}")

    return _tool_text_result("\n".join(lines), structured=structured), None


def _tool_explain_finding(args: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if "check" not in args:
        return None, "missing required argument: check"
    check = args["check"]
    if not isinstance(check, str):
        return None, "check must be a string"
    status = args.get("status")
    if status is not None and not isinstance(status, str):
        return None, "status must be a string"

    check_upper = check.upper() if check.upper() in _CHECK_NAMES else check
    if check_upper not in _CHECK_NAMES:
        return _tool_text_result(
            f"Unknown check {check!r}; must be one of {', '.join(_CHECK_NAMES)}.",
            is_error=True), None
    if status is not None and status.upper() not in _STATUS_NAMES:
        return _tool_text_result(
            f"Unknown status {status!r}; must be one of {', '.join(_STATUS_NAMES)}.",
            is_error=True), None
    status_upper = status.upper() if status else None

    explanation = _explain(check_upper, status_upper)
    structured = {"check": check_upper, "status": status_upper, "explanation": explanation}
    return _tool_text_result(explanation, structured=structured), None


# ---------------------------------------------------------------------------
# Tool registry — name -> (description, inputSchema, outputSchema, handler)
# ---------------------------------------------------------------------------

_RESOLVER_PROPERTY = {
    "type": "string",
    "enum": sorted(DOH_RESOLVERS),
    "description": "DNS-over-HTTPS resolver to use.",
    "default": DEFAULT_RESOLVER,
}

_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "check": {"type": "string"},
        "status": {"type": "string", "enum": list(_STATUS_NAMES)},
        "detail": {"type": "string"},
        "fix": {"type": "string"},
    },
    "required": ["check", "status", "detail", "fix"],
}

_TOOLS: Dict[str, Dict[str, Any]] = {
    "check_domain": {
        "description": (
            "Check one domain's email-spoofing posture (SPF, DMARC, DKIM, "
            "DNSSEC, MX, MTA-STS) by reading its PUBLIC DNS records only. "
            "No credentials, no scanning of the target's systems. Returns "
            "the same facts as the spoofguard CLI's report, plus an "
            "overall letter grade (A-D, or UNKNOWN if any check's DNS "
            "lookup failed to complete)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": (
                        "Domain name to check, e.g. example.com. Must be a "
                        "bare hostname: no URL scheme, no path, no port, "
                        "not an IP address. Unicode (IDNA) domains are "
                        "accepted and converted to punycode before lookup."
                    ),
                    "minLength": 1,
                    "maxLength": _MAX_DOMAIN_LEN,
                },
                "resolver": _RESOLVER_PROPERTY,
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "grade": {"type": "string"},
                "findings": {"type": "array", "items": _FINDING_SCHEMA},
            },
            "required": ["domain", "grade", "findings"],
        },
        "handler": _tool_check_domain,
    },
    "check_domains": {
        "description": (
            f"Check up to {BATCH_CAP} domains' email-spoofing posture in "
            "one call, sorted most-exposed-first. Same checks and the same "
            "public-DNS-only scope as check_domain. Useful for triaging an "
            "MSP's client list or a company's own brand/subsidiary domains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": BATCH_CAP,
                    "description": f"Domains to check in one call, {BATCH_CAP} max.",
                },
                "resolver": _RESOLVER_PROPERTY,
            },
            "required": ["domains"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "domain": {"type": "string"},
                            "grade": {"type": "string"},
                            "spoofable": {"type": "boolean"},
                            "severity": {"type": "integer"},
                            "critical_gaps": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["domain", "grade", "spoofable", "severity", "critical_gaps"],
                    },
                },
                "invalid": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"domain": {"type": "string"}, "reason": {"type": "string"}},
                        "required": ["domain", "reason"],
                    },
                },
                "cap": {"type": "integer"},
            },
            "required": ["results", "invalid", "cap"],
        },
        "handler": _tool_check_domains,
    },
    "explain_finding": {
        "description": (
            "Explain, in general, what an email-security check (SPF, "
            "DMARC, DKIM, DNSSEC, MX, MTA-STS) or a status (PASS, WARN, "
            "FAIL, UNKNOWN) means. Static reference text only — makes no "
            "network calls and no claim about any specific domain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "check": {
                    "type": "string",
                    "enum": list(_CHECK_NAMES),
                    "description": "Which check to explain.",
                },
                "status": {
                    "type": "string",
                    "enum": list(_STATUS_NAMES),
                    "description": "Optional: explain this status specifically for the given check.",
                },
            },
            "required": ["check"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "check": {"type": "string"},
                "status": {"type": ["string", "null"]},
                "explanation": {"type": "string"},
            },
            "required": ["check", "explanation"],
        },
        "handler": _tool_explain_finding,
    },
}


def _tools_list_result() -> Dict[str, Any]:
    tools = []
    for name, spec in _TOOLS.items():
        tools.append({
            "name": name,
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
            "outputSchema": spec["outputSchema"],
        })
    return {"tools": tools}


# ---------------------------------------------------------------------------
# JSON-RPC message handling
# ---------------------------------------------------------------------------

def _handle_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    requested = params.get("protocolVersion")
    negotiated = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
    return {
        "protocolVersion": negotiated,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": SERVER_INSTRUCTIONS,
    }


def _handle_tools_call(params: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Returns (result, protocol_error_message)."""
    name = params.get("name")
    if not isinstance(name, str):
        return None, "params.name must be a string"
    arguments = params.get("arguments", {})
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return None, "params.arguments must be an object"

    tool = _TOOLS.get(name)
    if tool is None:
        return None, f"Unknown tool: {name}"

    try:
        result, proto_err = tool["handler"](arguments)
    except Exception as e:  # a handler bug must not take the server down
        _log(f"unhandled exception in tool {name!r}: {e}")
        return _tool_text_result(f"Internal error running {name}: {e}", is_error=True), None
    return result, proto_err


def _dispatch_request(method: str, params: Dict[str, Any], id_: Any) -> Dict[str, Any]:
    if method == "initialize":
        return _result_response(id_, _handle_initialize(params))
    if method == "tools/list":
        return _result_response(id_, _tools_list_result())
    if method == "tools/call":
        result, proto_err = _handle_tools_call(params)
        if proto_err is not None:
            return _error_response(id_, INVALID_PARAMS, proto_err)
        return _result_response(id_, result)
    return _error_response(id_, METHOD_NOT_FOUND, f"Method not found: {method}")


def _handle_line(line: str, out) -> None:
    line = line.strip()
    if not line:
        return

    try:
        msg = json.loads(line)
    except Exception:
        _write(_error_response(None, PARSE_ERROR, "Parse error: invalid JSON"), out)
        return

    if not isinstance(msg, dict):
        _write(_error_response(None, INVALID_REQUEST,
                                "Invalid Request: message must be a JSON object"), out)
        return

    has_id = "id" in msg
    id_ = msg.get("id")

    if msg.get("jsonrpc") != "2.0":
        if has_id:
            _write(_error_response(id_, INVALID_REQUEST,
                                    'Invalid Request: "jsonrpc" must be "2.0"'), out)
        return  # malformed notification: no response, per the notification rule

    method = msg.get("method")
    if not isinstance(method, str) or not method:
        if has_id:
            _write(_error_response(id_, INVALID_REQUEST,
                                    "Invalid Request: missing method"), out)
        return

    params = msg.get("params")
    if not isinstance(params, dict):
        params = {}

    if not has_id:
        # Notification: MUST NOT receive a response, regardless of method
        # or outcome (/specification/2025-06-18 "Notifications MUST NOT
        # include an ID" + the receiver "MUST NOT send a response").
        if method == "notifications/initialized":
            _log("client sent notifications/initialized")
        else:
            _log(f"ignoring notification: {method}")
        return

    try:
        response = _dispatch_request(method, params, id_)
    except Exception as e:  # last-resort guard: never let one message kill the loop
        _log(f"unhandled exception dispatching {method!r}: {e}")
        response = _error_response(id_, INTERNAL_ERROR, f"Internal error: {e}")
    _write(response, out)


def serve(in_stream=None, out_stream=None) -> None:
    """Read newline-delimited JSON-RPC messages from `in_stream` (default
    sys.stdin) and write responses to `out_stream` (default sys.stdout)
    until the input stream closes. Never writes anything to stdout that is
    not a single JSON-RPC message followed by one newline."""
    in_stream = in_stream if in_stream is not None else sys.stdin
    out_stream = out_stream if out_stream is not None else sys.stdout
    _log(f"{SERVER_NAME} {SERVER_VERSION} starting "
         f"(protocol {DEFAULT_PROTOCOL_VERSION}, fixture="
         f"{'yes' if _FAKE_FETCH else 'no'})")
    for line in in_stream:
        _handle_line(line, out_stream)
    _log(f"{SERVER_NAME} stdin closed, exiting")


def main() -> int:
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
