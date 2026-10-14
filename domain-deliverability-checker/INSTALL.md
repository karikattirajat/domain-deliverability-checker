# Install — domain-deliverability-checker

Audits email sending domains for deliverability: DNS auth (SPF/DKIM/DMARC/MX/PTR/
MTA-STS/TLS-RPT/BIMI), ~20 tiered blacklists, and — when available — live inbox
metrics. Works with **zero setup**; optional keys make it stronger.

## Requirements
- `dig` (or `nslookup`) and `python3` — standard on macOS/Linux. No pip installs,
  no paid APIs required.
- Optional: a connected **Smartlead MCP** (for live warmup/bounce/provider metrics).

## Install

### Claude Code (CLI / desktop)
Unzip the `.skill` into your skills directory:
```bash
unzip domain-deliverability-checker.skill -d ~/.claude/skills/
```
It auto-loads. Verify with a quick run:
```bash
python3 ~/.claude/skills/domain-deliverability-checker/scripts/domain_health.py example.com --pretty
```

### Claude Code web / claude.ai
Open the `.skill` file card and click **Save skill** (if your org allows skill
creation). Otherwise, add the unzipped `domain-deliverability-checker/` folder to
your project's skills directory.

## Use
Just ask, in natural language:
- "check domain health for acme.io"
- "is getacme.com blacklisted?"
- "audit these sending domains: a.com, b.com, c.com"
- "why are my cold emails going to spam?"

Or run the engine directly:
```bash
# one or many
python3 scripts/domain_health.py acme.io getacme.com --pretty
# batch from a file (first CSV column; header row skipped)
python3 scripts/domain_health.py --file domains.csv > results.json
```

## Optional upgrades (recommended)
Copy `.env.example` to `.env` in the skill root and fill in:

- **`SPAMHAUS_DQS_KEY`** — a **free** Spamhaus DQS key. Without it, Spamhaus/URIBL
  are often "unchecked" from cloud/public-resolver networks (the skill says so
  honestly rather than guessing "clean"). With it, Spamhaus/URIBL/ZRD work
  reliably and scriptably at any volume. This is the single best upgrade.
  Get one: https://www.spamhaus.com (Free Data Query Service).
- **`INVALUEMENT_ENABLED=1`** — only if you have a paid Invaluement subscription
  AND run with `--resolver <your-licensed-resolver>`. Leave blank otherwise
  (enabling it unlicensed produces false "clean" results).

## Good to know
- **MXToolbox gap-filler** (free, browser-driven): the skill can read the ~68-list
  MXToolbox SuperTool for the lists `dig` can't reach (Spamhaus/URIBL/Invaluement).
  It's for **interactive/small-batch** spot-checks and is built to **stop at a
  CAPTCHA, not evade it** — for volume, use the native engine + DQS instead.
- **Read-only:** the skill never sends email or changes any DNS record. It's
  reconnaissance only.
- **Blacklist tiering:** ~13 lists are *scored* (real deliverability impact); the
  rest are *advisory* (surfaced but don't affect the grade). See
  `references/blacklists.md` for the rationale.
- **No secrets are bundled** — only `.env.example`. Your `.env` stays local.
