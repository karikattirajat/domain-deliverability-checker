# MXToolbox gap-filler (free web SuperTool, browser-driven)

The native `dig` engine can't reach Spamhaus, URIBL, or Invaluement from cloud /
public-resolver networks (those lists refuse such queries). MXToolbox's **free**
web SuperTool can — it runs a licensed resolver backend and checks ~68 lists at
once, no paid API and no login. Use it to fill exactly the gaps the native run
reports as `unchecked/blocked`, and to read the paywalled lists (Invaluement).

This is **not** the paid MXToolbox REST API. It's the same public web tool a human
uses; we just drive it with the browser tools.

## Procedure

1. Open the SuperTool blacklist check directly by URL (one domain or IP):
   ```
   https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a<DOMAIN_OR_IP>&run=toolpage
   ```
   e.g. `...action=blacklist%3aexample.com&run=toolpage`
   Use `preview_start`/`navigate` to open it.
2. The check is async (~5–15s for 68 lists). Take a screenshot or read the page;
   if the results table isn't populated yet, wait a few seconds and re-read.
3. Read the results with `get_page_text`. The header line reports what was checked,
   e.g. *"Checking <domain> which resolves to <IP> against 68 known blacklists...
   Listed N times with M timeouts"*. Then a table of `LISTED` / `OK` / `TIMEOUT`
   rows per list (SURBL multi, Spamhaus ZEN, Spamhaus DBL, ivmURI/ivmSIP/ivmSIP24,
   Barracuda, SpamCop, UCEPROTECT L1–3, etc.).
4. Extract every `LISTED` row (and any `TIMEOUT`, which means "not checked", not
   "clean" — same honesty rule as the native engine).

## How to combine with the native run

- **Domain-list hits should match** the native engine (SURBL/DBL). If MXToolbox
  says SURBL LISTED and so did native — that's a confirmed, high-confidence hit.
- **Blocked lists get resolved:** wherever native said `unchecked/blocked`
  (Spamhaus/URIBL), take MXToolbox's `OK`/`LISTED` verdict as the answer.
- **Invaluement:** native skips it unless subscribed; MXToolbox shows ivmURI/
  ivmSIP/ivmSIP24 for free — read them here instead.
- Report the union, but say where each verdict came from (native dig vs MXToolbox)
  so the user knows what was actually reached.

## Important caveats (state these, don't hide them)

- **One IP, not all.** MXToolbox resolves the domain to its A-record IP and runs
  IP-based lists against that single IP. The native engine checks *all* sending
  IPs (every MX host's IP + the A record). For M365/Google-hosted domains the
  provider's shared IPs are the sending reputation, so domain-based lists matter
  most — but don't claim MXToolbox cleared "the sending IPs" when it checked one.
- **Interactive / small-batch only, and pace the requests.** It's browser-driven
  and MXToolbox rate-limits. Space out queries (a few seconds between domains) —
  this is simply being a courteous client and keeps load light. For a whole pool,
  run the native engine for the batch and use MXToolbox only to spot-check the few
  that came back blocked or suspicious — not all 100 at once.
- **A CAPTCHA is a STOP sign, not an obstacle to route around.** If MXToolbox
  presents a CAPTCHA or other bot-detection, that is the service declining
  automated use. Do not attempt to solve it, and do not try to evade detection
  (clearing/rotating cookies, spoofing, IP rotation, etc.) — that crosses from
  "polite automation" into circumventing an anti-bot control, which this skill
  does not do. Instead, fall back to the sanctioned path below.
- **The sanctioned at-volume path is Spamhaus DQS, not scraping.** A free DQS key
  gives the native engine *licensed* Spamhaus/URIBL access — no bot-detection to
  fight, batchable, reliable. The moment you need more than a few interactive
  checks, use DQS (and Invaluement's own subscription if you need ivm* at scale),
  rather than pushing MXToolbox harder.
- **Terms.** MXToolbox's terms discourage heavy scripted use; keep this to
  good-faith, interactive checks of the user's own domains.
- **Layout can change.** Read the visible results text rather than depending on
  fixed pixel positions; if the table shape changes, adapt from the page text.
