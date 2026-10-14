---
name: domain-deliverability-checker
description: >-
  Audit the email deliverability health of one or many sending domains — DNS
  authentication (SPF, DKIM, DMARC, MX, PTR/rDNS, MTA-STS, TLS-RPT, BIMI),
  DNSBL/RBL blacklist status across ~20 curated lists (tiered by real-world impact), and live inbox-placement
  metrics (warmup score, bounce rate, provider-wise inbox rate) from a connected
  Smartlead account. Use this skill whenever the user wants to "check domain
  health", "run a blacklist check", "is my domain blacklisted", "check
  deliverability", "audit my sending domains", "why are my emails going to spam",
  "check SPF/DKIM/DMARC", "MXToolbox", "is my email set up right", "check my
  cold-email domains", or shares one or more domains/a CSV of domains and asks
  about their sending reputation or inbox placement. Also trigger for pre-launch
  domain checks before a cold-email campaign and for diagnosing a drop in reply
  rates. Prefer this skill over ad-hoc dig commands — it handles the return-code
  and resolver gotchas that make naive blacklist checks silently wrong.
---

# Domain Deliverability Checker

Audits sending domains for email deliverability across three layers, then
produces a scorecard. It is **native and free** — DNS work is done by shelling
out to `dig` (no MXToolbox, no API keys); live inbox metrics come from the
user's Smartlead MCP when available.

Native `dig` vs MXToolbox — use both, for different jobs. A blacklist lookup *is*
a DNS query, so the native engine does the bulk of the work: it's fast,
scriptable, batchable, checks **every** sending IP (not just the domain's A
record), and interprets return codes correctly. Its one blind spot is that
Spamhaus/URIBL/Invaluement refuse queries from cloud and public-resolver IPs.
MXToolbox's **free** web SuperTool covers exactly that blind spot — it runs a
licensed resolver backend, so it can read those lists (and ~68 total) for free.
So: native engine for speed/batch/all-IP coverage; MXToolbox as the browser-driven
gap-filler for the blocked/paywalled lists. See
[references/mxtoolbox-supplement.md](references/mxtoolbox-supplement.md). (The paid
MXToolbox *REST API* is a separate thing and is not needed for any of this.)

## The three layers

1. **DNS authentication & config** — SPF (incl. the 10-lookup limit), DKIM,
   DMARC, MX, reverse-DNS, MTA-STS, TLS-RPT, BIMI. Run by the bundled script.
2. **Blacklist / reputation** — ~20 DNSBLs (scored/advisory tiers) against every sending IP plus
   domain-based URI blacklists. Run by the bundled script.
3. **Live deliverability** — warmup score, bounce/spam rate, provider-wise inbox
   placement. Pulled from Smartlead MCP (only if the domain is in their account).

## Workflow

### Step 1 — Get the domains
Accept a single domain, several domains, or a CSV/list file. If the user pasted
email addresses, strip to the domain. If they gave a Smartlead campaign instead
of domains, pull the sending domains from it first (see Step 3).

### Step 2 — Run the DNS + blacklist engine
This is a deterministic, parallelized script — always use it rather than issuing
`dig` commands by hand.

```bash
# single or several
python3 scripts/domain_health.py acme.io getacme.com --pretty

# batch from a file (first CSV column is used; header rows skipped)
python3 scripts/domain_health.py --file domains.csv

# machine JSON (default, no --pretty) when you need to build a table/report
python3 scripts/domain_health.py --file domains.csv > results.json
```

Use `--pretty` for a quick human summary; omit it to get JSON you can turn into
a comparison table. `--workers N` tunes parallelism (default 16).

**Spamhaus DQS (recommended for reliable Spamhaus coverage).** The public
Spamhaus/URIBL zones refuse queries from cloud and big-public-resolver networks
— from those vantage points the skill honestly reports Spamhaus as
*unchecked/blocked* rather than guessing "clean". A free Spamhaus DQS key fixes
this: with a key set, the engine queries the authenticated `*.dq.spamhaus.net`
zones (ZEN + DBL + the ZRD new-domain list) and gets real answers everywhere.
The first line of `--pretty` output reports which mode is active. Key resolution
order: `--dqs-key` flag → `SPAMHAUS_DQS_KEY` env var → `SPAMHAUS_DQS_KEY` in the
skill-root `.env` (copy `.env.example`). If a batch comes back with Spamhaus
"unchecked", tell the user this is why and point them at DQS.

### Step 3 — Add live Smartlead metrics (when relevant)
If these are the user's own cold-email domains and Smartlead MCP is connected,
enrich the DNS picture with real inbox data. Map metrics to tools using
[references/smartlead-metrics.md](references/smartlead-metrics.md) — the key ones:
- `check_mailbox_domain_deliverability` — deliverability check for a domain
- `get_mailbox_domain_wise_health_metrics` — health per sending domain
- `get_email_warmup_stats` — warmup progress / reputation ramp
- `get_campaign_diagnostics` / `check_campaign_bounce_or_lead_quality` — bounce & spam signals

Only pull these for domains that plausibly live in the account; don't guess.

### Step 3b — Google / Microsoft provider signals
Gmail and Outlook publish **no queryable blacklist** — their reputation is
proprietary, so a "Gmail blacklist check" over DNS is impossible (the DNS engine
only checks the third-party lists they *consume*, like Spamhaus). Get real
provider-specific signal from [references/provider-signals.md](references/provider-signals.md):
- `get_mailbox_provider_wise_performance` (Smartlead) — actual Gmail-vs-Outlook
  inbox/reply split from your sends. This is the only programmatic provider signal.
- Point the user to **Google Postmaster Tools** (authoritative for Gmail) and
  **Microsoft SNDS/JMRP** (authoritative for Outlook) — dashboards that need
  one-time setup; you can't read them via DNS.
Tie any weak provider back to the DNS engine's blacklist/auth findings (e.g. poor
Outlook numbers + a Spamhaus listing = same root cause).

### Step 3c — MXToolbox gap-filler for blocked/paywalled lists
When the native engine reports Spamhaus/URIBL as **unchecked/blocked** (no DQS
key), or the user wants the paywalled lists (Invaluement) or full 68-list breadth,
drive the free MXToolbox SuperTool through the browser tools. This reads the lists
`dig` can't reach from here, for free. Follow
[references/mxtoolbox-supplement.md](references/mxtoolbox-supplement.md) — it has
the exact URL, how to read the results table, and the important caveats (checks
one IP not all; rate-limits/CAPTCHAs at scale; keep to interactive/small-batch use
of the user's own domains). Reconcile its results with the native run: they should
agree on domain-list hits, and MXToolbox fills in the blocked-list verdicts.

### Step 4 — Interpret, don't just dump
Read [references/blacklists.md](references/blacklists.md) before explaining
blacklist results. The two interpretation traps that matter most:

- **Resolver blocks ≠ clean.** Spamhaus and URIBL refuse queries from big public
  resolvers (8.8.8.8 / 1.1.1.1) and cloud IPs, answering with a `127.255.255.x`
  or bare `127.0.0.1` "refused" code. The script reports these as
  **unchecked/blocked**, never clean. If many lists come back blocked, tell the
  user to re-run from a normal ISP connection or pass `--resolver <isp-resolver>`
  — otherwise a blacklisting can hide behind a "clean" result.
- **Advisory listings ≠ your fault.** UCEPROTECT L2/L3 list entire ISP ranges,
  so a hit usually reflects a noisy neighbor, not the domain. Surface it, but
  don't treat it like a Spamhaus ZEN listing.

### Step 5 — Deliver the scorecard
Use the output template below. Lead with the verdict and the fixes, not raw DNS.

## Output format

For a **single domain**, produce a scorecard:

```
# Deliverability Report — <domain>          Grade: <A–F>  (<score>/100)

**Verdict:** <one line — safe to send / fix before sending / do not send>

## Authentication
- SPF    ✅/⚠️/❌  <record summary; flag >10 lookups, +all/none>
- DKIM   ✅/⚠️/❌  <selectors found, or "custom selector — verify manually">
- DMARC  ✅/⚠️/❌  <policy p=…; flag p=none and missing rua>
- MX / rDNS <summary>

## Blacklists
- Clean on N/N checked lists  —  OR  Listed on: <lists>
- Advisory (range-based): <lists or none>
- Unchecked (resolver-blocked): <lists or none>

## Live deliverability (Smartlead)   ← only if pulled
- Warmup score / inbox rate / bounce rate / provider breakdown

## Fix list (priority order)
1. <highest-impact fix, concrete>
2. …
```

For a **batch**, lead with a ranked table (worst first), then a short "who needs
attention" list, then offer per-domain detail on request:

| Domain | Grade | Score | SPF | DKIM | DMARC | Blacklisted | Notes |
|--------|-------|-------|-----|------|-------|-------------|-------|

## Interpretation cheatsheet

- **SPF >10 DNS lookups** → PermError; receivers may ignore SPF entirely. Common
  when stacking many `include:`s. Fix by flattening or removing unused includes.
- **DMARC p=none** → monitoring only, zero enforcement. Fine while warming, but a
  domain sending cold volume should progress to `quarantine`/`reject`.
- **No DKIM selector found** → the script only probes common selectors; a custom
  one won't show. Don't declare DKIM broken — say "verify the selector."
- **Listed on Spamhaus ZEN / SpamCop / Barracuda** → real, act now: identify the
  IP, request delisting, and pause sending from it until resolved.
- **PTR missing** → informational for shared infra (Google/Microsoft frontends
  rotate IPs); matters most for self-hosted senders.

## Notes
- IPv6 sending IPs aren't reversed for DNSBLs (most cold-email infra is IPv4).
- The 0–100 score is a heuristic to *rank* a batch, not a certification. The flag
  list and the fixes are the real output.
- Nothing here sends email or changes any record — it is read-only reconnaissance.
