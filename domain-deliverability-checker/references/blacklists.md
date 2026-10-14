# DNSBL blacklists & return-code interpretation

A DNSBL ("blacklist") lookup is a plain DNS query. For an IP `a.b.c.d` you query
`d.c.b.a.<zone>` and read the `A` answer. For a domain URI list you query
`domain.<zone>`. An answer means *listed*; NXDOMAIN (empty) means *not listed* —
**except** for the special codes below, which is where naive tools go wrong.

## Return-code rules the engine applies

| Answer | Meaning | Engine status |
|--------|---------|---------------|
| empty / NXDOMAIN | not listed | `clean` |
| `127.0.0.2`–`127.0.0.254` (normal lists) | genuinely listed | `listed` |
| `127.255.255.x` | query blocked / rate-limited / not a listing | `error` (unchecked) |
| bare `127.0.0.1` (normal lists) | query refused / not permitted over public DNS | `error` (unchecked) |
| `127.0.0.1` on an **inverted** list (HostKarma) | **whitelisted** (good) | `whitelisted` |

**Why `127.0.0.1` is not a hit.** URIBL and SURBL return `127.0.0.1` to *every*
query that arrives via a public resolver without a datafeed key — including
google.com. Spamhaus uses `127.255.255.252-254` to signal a blocked/over-quota
query. Reporting either as "listed" is the classic false positive that makes
blacklist tools untrustworthy. Real listings begin at `127.0.0.2`.

## The resolver problem (most important operational caveat)

Spamhaus (ZEN, DBL), URIBL and others **refuse queries from large public
resolvers** (Google `8.8.8.8`, Cloudflare `1.1.1.1`, Quad9) and from most cloud
provider IPs. From such a vantage point they answer with a blocked code, which
the engine surfaces as **unchecked/blocked** — NOT clean.

If a run shows many lists blocked:
- Re-run from a host on a normal residential/business ISP connection, **or**
- Pass `--resolver <your-ISP-resolver-IP>` so queries originate from an allowed
  network, **or**
- **Best fix — Spamhaus DQS (implemented).** Get a free Spamhaus DQS key and set
  `SPAMHAUS_DQS_KEY` (via `--dqs-key`, env var, or skill-root `.env`). The engine
  then queries the authenticated zones — `<rev-ip>.<key>.zen.dq.spamhaus.net`,
  `<domain>.<key>.dbl.dq.spamhaus.net`, and the ZRD new-domain list — which are
  not subject to the public-resolver block, so Spamhaus results become real from
  any network. The `--pretty` header reports whether DQS is active. Return codes
  are interpreted identically to the public zones (including `127.255.255.x` =
  over-quota/error). Free tier is generous; get a key at
  spamhaus.com (Free Data Query Service).

Never tell the user a domain is "clean on Spamhaus" if Spamhaus came back
blocked. Say it couldn't be checked from this network.

## The list set (scripts/domain_health.py → DNSBLS)

Not every list deserves equal weight. The engine sorts them into three buckets so
a hit on a fringe list can't tank a grade the way a Spamhaus hit should:

**SCORED — genuinely move deliverability at major receivers / SpamAssassin (13):**
- **Spamhaus ZEN** — combined SBL+XBL+PBL; the single most important list, and
  heavily consumed by Outlook/Microsoft, so it doubles as a Microsoft signal.
- **Spamhaus DBL** — domain reputation; widely consumed.
- **SURBL**, **URIBL**, **SEM URIRED** — URI/content lists SpamAssassin and many
  filters check against sender domains and links (this is what catches
  lookalike domains on shared infrastructure).
- **Barracuda** — used by the large installed base of Barracuda appliances.
- **SpamCop** — consumed by a range of receivers; listings expire quickly.
- **PSBL**, **Mailspike BL**, **NiX Spam**, **SpamRats**, **GBUdb Truncate**,
  **SpamEatingMonkey** — secondary lists that contribute SpamAssassin score;
  individually minor, collectively meaningful.

**ADVISORY — surfaced but NOT scored (low adoption / controversial / niche):**
- **UCEPROTECT L1 / L2 / L3** — controversial pay-to-delist operator that lists
  whole ISP ranges; Gmail/Outlook largely ignore it. A UCEPROTECT hit alone
  rarely blocks real mail, so it informs but never lowers the grade. (This is a
  deliberate answer to "does everything I check affect deliverability?" — these
  don't much, so they don't count against you.)
- **0Spam**, **InterServer** — real lists but limited broad adoption; kept as weak
  corroborating signal only.
- **Backscatterer** — misdirected-bounce list; catches legit mailflow easily.
- **Spamhaus ZRD** — new-domain reputation (DQS-only); "new" isn't "bad".

**INVERTED:** **HostKarma** — `127.0.0.1` = whitelisted (good), `.2` = blacklisted.

**SUBSCRIPTION-GATED — off by default (see below):** Invaluement ivmSIP,
ivmSIP/24, ivmURI.

## Invaluement (paid, subscription-gated)

Invaluement (ivmSIP for IPs, ivmSIP/24 for /24 blocks, ivmURI for domains) is a
genuinely high-value list used by serious enterprise filters — arguably the best
non-Spamhaus data. But it is a **paid subscription**, and its full data serves
only to **licensed resolvers** (you register your resolver's IP, or rsync the zone
locally). From an unlicensed resolver, real lookups return nothing — a silent
false "clean", exactly the SORBS failure mode.

So it is **off by default** and only queried when explicitly enabled:
- Enable with `--invaluement`, `INVALUEMENT_ENABLED=1` in env, or in skill-root `.env`.
- You **must** also query from your licensed resolver: `--resolver <your-ivm-resolver>`.
- When enabled, `--pretty` prints a warning to that effect. Enabling it without a
  subscription is worse than leaving it off (false confidence).

If the user wants Invaluement coverage and has a subscription, wire in their
resolver. If they don't, don't pretend — recommend Spamhaus DQS (free) as the
highest-value list they can actually query.

## Removed / deliberately excluded:
- **SORBS** (dnsbl.sorbs.net + spam.dnsbl.sorbs.net) — retired in 2024; the zones
  no longer resolve, so querying them silently returns "clean" forever. Dropped.
- **DroneBL** — returns `127.0.0.1` for listings, which collides with the
  universal "query refused" code; also botnet-focused, low relevance to domain
  deliverability. Excluded to avoid misclassification.
- **WPBL** (db.wpbl.info) — nameservers unreachable/unreliable; excluded so it
  can't produce false "clean" results.
- **Gmail / Outlook** — no public DNSBL exists (see
  [provider-signals.md](provider-signals.md)); their reputation is proprietary.

## Adding or removing lists

Edit the `DNSBLS` list in `scripts/domain_health.py`. Each entry:
`{"zone": ..., "type": "ip"|"domain", "label": ..., "advisory"?: True, "inverted"?: True}`.
Prefer lists that real mail receivers actually consume; a long list of obscure
zones adds noise and false positives, not signal.
