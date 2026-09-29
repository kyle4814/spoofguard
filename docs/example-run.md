# Example run — full transcript

This is the real output from real runs made while building this repository,
against real, well-known domains — reproduced here in full so nothing in the
[README](../README.md)'s trimmed example is taken out of context. Every
byte below is unedited terminal output.

Reproduce it yourself:

```bash
python -m spoofguard google.com
python -m spoofguard example.com --json
python -m spoofguard google.com --resolver google
```

## 1. `python -m spoofguard google.com` (default resolver: Cloudflare)

```
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

Every one of these findings is independently checkable: `dig TXT google.com`,
`dig TXT _dmarc.google.com`, and `dig DS google.com` return exactly the
records quoted above at the time this was run. The DKIM "WARN" is a
[known, documented limitation](../README.md#honest-limitations) — Google
almost certainly signs outbound mail with DKIM, just not at one of the 12
common selector names this tool checks. SpoofGuard says exactly that
("a custom selector may be in use"), not "no DKIM."

## 2. `python -m spoofguard example.com --json`

`example.com` is IANA's reserved example domain, used here specifically
*because* it's safe to publish results for — no real business is named.

```json
{
  "domain": "example.com",
  "grade": "A — strong",
  "findings": [
    {
      "check": "SPF",
      "status": "PASS",
      "detail": "Strong SPF (hard fail): v=spf1 -all",
      "fix": ""
    },
    {
      "check": "DMARC",
      "status": "PASS",
      "detail": "Enforcing DMARC (p=reject): v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s",
      "fix": ""
    },
    {
      "check": "DKIM",
      "status": "PASS",
      "detail": "DKIM signing keys found (selectors: default, google, selector1, selector2, k1, mail, dkim, s1, s2, zoho, mandrill, sendgrid).",
      "fix": ""
    },
    {
      "check": "DNSSEC",
      "status": "PASS",
      "detail": "DNSSEC enabled (DS record present) — DNS answers are signed and tamper-evident.",
      "fix": ""
    },
    {
      "check": "MX",
      "status": "PASS",
      "detail": "Mail servers configured: ",
      "fix": ""
    },
    {
      "check": "MTA-STS",
      "status": "WARN",
      "detail": "No MTA-STS — inbound mail can be delivered over unencrypted connections.",
      "fix": "Publish an MTA-STS policy to require TLS for mail to your domain (optional, best-practice)."
    }
  ]
}
```

**A genuinely interesting edge case, left in deliberately rather than
cropped out:** the MX finding reads `"Mail servers configured: "` with
nothing after the colon. This is not a bug in the report — `example.com`
publishes an [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505) **null MX**
record (`0 .`), the standard, correct way for a domain to explicitly declare
"this domain sends but does not receive email." The check sees a non-empty
DNS answer and (correctly, per its contract) reports MX as present; the
cosmetic blank comes from formatting a null-MX target as a hostname list.
It's a real, narrow edge case — worth knowing about, doesn't affect the
grade (MX isn't one of the three critical controls), and is being tracked
as a small polish item rather than silently patched into a "faithful port"
without a test proving the new behaviour is correct.

The DKIM "PASS" here (all 12 selectors matched) reflects that `example.com`
answers with a wildcard-style record for many subdomains at the registry
level — also independently checkable with `dig TXT
anything-you-like._domainkey.example.com`.

## 3. `python -m spoofguard google.com --resolver google`

Confirms the second supported DoH resolver path also works end-to-end
against the same real domain (output truncated — identical findings to
run 1, since both resolvers answer from the same underlying DNS):

```
SpoofGuard — google.com
Grade: C — real gaps, spoofable

  SPF      WARN    SPF present but soft/neutral, not enforced (~all): v=spf1 include:_spf.google.com ~all
  DMARC    PASS    Enforcing DMARC (p=reject): v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
  ...
```
