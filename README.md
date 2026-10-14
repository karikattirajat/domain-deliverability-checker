# Domain Deliverability Checker

A [Claude Code](https://claude.com/claude-code) **skill** that audits whether your email sending
domains are set up to reach the inbox. Ask in plain language, for one domain or a CSV of many:

> *"Is getacme.com blacklisted?"*  ·  *"Audit these sending domains: a.com, b.com, c.com"*  ·
> *"Why are my cold emails going to spam?"*

## What it checks
| Layer | Details |
|---|---|
| **DNS authentication** | SPF, DKIM, DMARC, MX, PTR/rDNS, MTA-STS, TLS-RPT, BIMI |
| **Blacklists** | ~20 curated DNSBL/RBL lists, tiered by real-world impact: *scored* (Spamhaus ZEN/DBL, SURBL, URIBL, Barracuda, SpamCop...), *advisory*, and *informational*, so a hit on a fringe list can't tank a grade the way a Spamhaus hit should |
| **Live inbox metrics** *(optional)* | Warmup score, bounce rate and provider-wise (Gmail vs Outlook) performance, pulled from a connected Smartlead MCP for your own sending domains |
| **MXToolbox gap-filler** *(optional)* | Browser-driven read of the ~68-list SuperTool for lists `dig` can't reach. Stops at a CAPTCHA, never evades it |

## How a run goes
1. You give one or more domains (or a CSV / email addresses; it strips to the domain).
2. The engine (`scripts/domain_health.py`) runs the DNS and blacklist checks and handles the
   return-code and resolver gotchas that make naive blacklist checks silently wrong. It says
   "unchecked" rather than guessing "clean" when a list can't be reached.
3. If the domains are yours and Smartlead MCP is connected, live send metrics are added.
4. You get a graded report per domain: what's broken, how severe, and the fix, plus a verdict
   such as *"config is fine, the problem is list quality"* or *"authentication is the root cause"*.

## Install
```bash
git clone https://github.com/karikattirajat/domain-deliverability-checker.git
mkdir -p ~/.claude/skills
cp -R domain-deliverability-checker/domain-deliverability-checker ~/.claude/skills/
python3 ~/.claude/skills/domain-deliverability-checker/scripts/domain_health.py example.com --pretty
```
Needs only `python3` and `dig`/`nslookup`, with no pip installs and no paid APIs. See
`domain-deliverability-checker/INSTALL.md` for details.

## Optional keys (yours, never committed)
Copy `.env.example` to `.env` inside the skill folder and add a **free** Spamhaus DQS key for
reliable Spamhaus/URIBL results from cloud networks. `.env` is git-ignored. This repository
contains no keys or credentials.
