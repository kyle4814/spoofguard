# SpoofGuard

**Can someone send email that looks exactly like it came from your domain? SpoofGuard tells you, in one command, using only public DNS.**

[![tests](https://github.com/kyle4814/spoofguard/actions/workflows/tests.yml/badge.svg)](https://github.com/kyle4814/spoofguard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](./pyproject.toml)

```
$ python -m spoofguard yourdomain.com
```

No sign-up, no API key, no `pip install` even required to try it — clone and
run. It reads your domain's public DNS records over DNS-over-HTTPS, checks
the six controls that decide whether email can be forged in your name, and
grades the result A through D (or an honest **UNKNOWN** if the check
couldn't complete — see [How grading works](#how-grading-works)).

## Why this matters

Email spoofing is the mechanism behind two of the most expensive frauds a
business can suffer:

- **Business Email Compromise (BEC) / invoice fraud** — a criminal sends an
  email that appears to come from a real supplier, a real executive, or your
  own domain, asking for a payment or a bank-detail change. The FBI's
  Internet Crime Complaint Center logged **$3.05 billion in reported BEC
  losses in the US in 2025 alone** (24,768 complaints), and **more than
  $55.4 billion worldwide across 300,000+ incidents from 2013–2023**
  ([IC3 2025 Annual Report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf)).
- **Phishing-as-you** — the same forged-sender trick used against *your*
  customers, damaging trust in your brand even though your systems were
  never touched.

Three DNS records — SPF, DMARC, and DKIM — are what stop this. When they're
missing or misconfigured, anyone can send mail claiming to be you, and
nothing tells the receiving mail server otherwise. The scale of the gap is
larger than most businesses assume: live monitoring of 41,934 Australian
domains found **70.8% have no effective DMARC protection**
([DmarcDkim.com, Australia adoption tracker](https://dmarcdkim.com/dmarc-adoption/australia),
checked 2026-09-29). A separate methodology from PowerDMARC's own 2026
Australia report puts nominal DMARC *adoption* at 92.3%, but finds **53.3%
of those domains still don't enforce a reject policy** — different
measurement, same underlying story: having a DMARC record is not the same
as being protected by one, and most domains aren't.

## What it checks

| Control | What it stops | 
|---|---|
| **SPF** | Declares which mail servers are allowed to send as your domain. Missing or misconfigured = anyone can send as you. |
| **DMARC** | Tells receiving mail servers what to do with mail that fails SPF/DKIM (nothing / quarantine / reject), and gives you visibility of abuse via reports. |
| **DKIM** | Cryptographically signs your outgoing mail so receivers can verify it wasn't altered or forged. |
| **DNSSEC** | Signs your DNS responses so they can't be silently tampered with in transit (protects the records above, among other things). |
| **MX** | Confirms mail routing is configured as expected (a liveness/configuration signal, not a security control on its own). |
| **MTA-STS** | Requires TLS for inbound mail, so it can't be intercepted over an unencrypted connection. |

Every check reads public DNS only — no login, no credentials, no scanning of
your (or anyone else's) systems. It is exactly as legal and safe to run
against a domain as looking it up in a phone book.

## Quickstart

No installation required to try it:

```bash
git clone https://github.com/kyle4814/spoofguard.git
cd spoofguard
python -m spoofguard yourdomain.com
```

Or install it properly (still zero third-party dependencies):

```bash
pip install .          # from a clone, until this is published to PyPI
spoofguard yourdomain.com
```

```
usage: spoofguard [-h] [--batch FILE] [--md FILE] [--html FILE] [--json]
                   [--resolver {cloudflare,google}] [--timeout TIMEOUT]
                   [domain]

  yourdomain.com            scan one domain, print a text summary
  --html report.html        write a self-contained HTML report (no external
                             resources — safe to email as an attachment)
  --md report.md            write a Markdown report
  --json                    print machine-readable JSON instead of text
  --batch domains.txt       scan every domain in a file, sorted most-exposed-first
  --resolver google         use Google's DoH resolver instead of the default (Cloudflare)
```

## Example output

This is real output from a real run against a real, well-known domain — not
a fabricated example (see [`docs/example-run.md`](./docs/example-run.md) for
the full transcript and how to reproduce it):

```
$ python -m spoofguard google.com
SpoofGuard — google.com
Grade: C — real gaps, spoofable

  SPF      WARN    SPF present but soft/neutral, not enforced (~all): v=spf1 include:_spf.google.com ~all
  DMARC    PASS    Enforcing DMARC (p=reject): v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
  DKIM     WARN    No DKIM key found at common selectors (a custom selector may be in use — confirm with the mail provider).
  DNSSEC   WARN    DNSSEC not enabled — DNS responses are not cryptographically signed.
  MX       PASS    Mail servers configured: smtp.google.com
  MTA-STS  PASS    MTA-STS present — enforces TLS on inbound mail.

What to fix:
  - [SPF] Change the SPF record's ending to -all so forged mail is rejected, not just flagged.
  - [DKIM] Enable DKIM signing with your mail provider and publish the key, so receivers can cryptographically verify your mail.
  - [DNSSEC] Enable DNSSEC at your DNS host to protect against DNS spoofing/cache poisoning.
```

(The DKIM "WARN" above is a **known limitation, not a claim that Google has
no DKIM** — see [Limitations](#honest-limitations). Google's own DMARC
aggregate-report address is visible in the DMARC line, which is a genuine,
independently-verifiable public record.)

## How grading works

`A` / `B` / `C` / `D` weight the three controls that actually stop
spoofing — **SPF, DMARC, DKIM** — more heavily than the other three:

| Grade | Meaning |
|---|---|
| **A — strong** | No failures anywhere, no warnings on SPF/DMARC/DKIM. |
| **B — good, minor gaps** | No critical failures; at most one warning on SPF/DMARC/DKIM. |
| **C — real gaps, spoofable** | At most one critical failure. |
| **D — high risk, easily spoofed** | More than one critical failure — email can be forged in your name essentially without obstruction. |
| **UNKNOWN — lookup incomplete, not assessed** | See below. This is not a fifth grade on the same scale — it means the scan could not be completed. |

**The rule this tool will never break: a DNS lookup that fails is UNKNOWN,
never FAIL.** A network hiccup, a timeout, or an exhausted rate limit is not
evidence that a record is missing — treating it as one would manufacture a
false "this domain is spoofable" result, which is the single worst mistake a
security tool can make. If *any* check comes back UNKNOWN, the whole report
grades UNKNOWN rather than a confident letter, because it was not fully
assessed. This same discipline is why a present-but-weak control (e.g. SPF
ending in `~all` instead of `-all`, or DMARC at `p=quarantine` instead of
`p=reject`) is graded **WARN**, never **PASS** — and it's also why
technically-present-but-broken configurations (two SPF records, which RFC
7208 makes a hard PermError; two DMARC records, which RFC 7489 says
receivers must ignore both) are graded **FAIL**, not a hollow PASS for
"having a record." A tool that can be tricked into saying PASS on a
spoofable domain is worse than no tool at all — this project has regression
tests pinned specifically against that failure mode (see
[`tests/test_scanner.py::TestFalsePassGuards`](./tests/test_scanner.py)).

## Batch scanning

Scanning more than one domain — an MSP's client list, a company's own
portfolio of brand/subsidiary domains — is a first-class use case:

```bash
python -m spoofguard --batch domains.txt
```

```
SpoofGuard batch — 3 domain(s), most exposed first
  [3] wide-open.example.com   D — high risk, easily spoofed    SPOOFABLE
  [2] partial.example.com     C — real gaps, spoofable         SPOOFABLE
  [0] strong.example.com      A — strong                       ok
```

`domains.txt` is one domain per line; `#` starts a comment.

## MCP server

SpoofGuard also runs as a Model Context Protocol (MCP) server, so an AI
assistant or agent can call it as a tool instead of a human running the
CLI. It speaks JSON-RPC 2.0 over stdio, uses the standard library only
(same zero-dependency rule as the rest of the project), and reads public
DNS only, same as everywhere else in this project.

```bash
python -m spoofguard.mcp_server
```

or, once installed:

```bash
spoofguard-mcp
```

Add it to an MCP client's config, for example:

```json
{
  "mcpServers": {
    "spoofguard": {
      "command": "spoofguard-mcp"
    }
  }
}
```

It exposes three tools:

| Tool | What it does |
|---|---|
| `check_domain` | Full SPF/DMARC/DKIM/DNSSEC/MX/MTA-STS posture for one domain, as structured JSON plus a short text summary. |
| `check_domains` | The same, for up to 25 domains in one call, sorted most exposed first. |
| `explain_finding` | A static explanation of what a check or a status means in general. No network calls, and no claim about any specific domain. |

Domain input is checked strictly before any lookup runs: no URLs, no IP
addresses, and length limits consistent with a real DNS name. A Unicode
domain is converted to its ASCII (punycode) form before the lookup, so it
resolves correctly.

The same honesty rule applies here as everywhere else in this project: a
DNS lookup that fails grades UNKNOWN, never a confident PASS or FAIL. This
is never reported back as a tool error, since an UNKNOWN result is still a
complete and correct answer, not a failure.

This server implements the MCP protocol's older, `initialize`-handshake
lifecycle (protocol version `2025-06-18`), because that is what the MCP
clients in real use today actually speak. See the top of
`spoofguard/mcp_server.py` for the full reasoning and the sources checked.

## Honest limitations

SpoofGuard is a **public-DNS posture signal**, not a full security audit,
not a penetration test, and not proof of anything about a domain's actual
mail infrastructure beyond what its DNS publishes:

- **DKIM detection is best-effort.** It checks 12 common selector names
  (`default`, `google`, `selector1`, `s1`, …). A domain using a custom
  selector will show as WARN ("not found at common selectors") even if DKIM
  is correctly configured — the report says this explicitly rather than
  claiming DKIM is absent.
- **MX is a liveness/configuration signal, not a security control.** A
  domain with no MX records probably doesn't receive mail at all — but it
  can still be *spoofed* (SPF/DMARC govern sending, not receiving), so a
  weak MX finding never suppresses a real SPF/DMARC gap.
- **A result reflects DNS at the moment of the check.** DNS changes; re-run
  the scan after making changes, and periodically in general.
- **It depends on a public DoH resolver being reachable** (Cloudflare by
  default, Google as an alternative via `--resolver google`). If your
  network blocks DNS-over-HTTPS, checks will read UNKNOWN — by design, this
  is never silently misreported as a passing or failing grade.
- **It does not check** mailbox security, employee training, attachment/
  content filtering, or anything beyond the six public DNS controls listed
  above. A domain graded "A" here can still be compromised through a
  phished password — SpoofGuard only answers "can someone forge your
  From: address," which is one real, specific, and very common attack, not
  the whole of email security.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). The short version: zero runtime
dependencies stays non-negotiable, every check has a test that injects fake
DNS data (no test touches the real network), and a failed lookup must always
stay UNKNOWN, never FAIL.

## Security

See [`SECURITY.md`](./SECURITY.md) to report a vulnerability — please don't
use a public issue for anything that could be actively exploited before a
fix ships.

## License

[MIT](./LICENSE) — use it, fork it, ship it.
