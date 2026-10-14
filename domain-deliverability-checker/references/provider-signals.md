# Google & Microsoft deliverability signals

**There is no public blacklist to `dig` for Gmail or Outlook.** Google and
Microsoft keep sender reputation proprietary — you cannot query "is my IP blocked
by Gmail?" over DNS. Any tool claiming a "Gmail blacklist check" via DNS is
either checking a third-party list those providers *consume* (Spamhaus, SpamCop —
already covered by the DNS engine) or making it up. So provider-specific signal
has to come from three real sources instead:

## 1. Actual send performance (available now, via Smartlead)

This is the only Google/Microsoft signal we can pull programmatically today, and
it's the most honest one — it's your real inbox/reply performance split by
receiving provider.

- `get_mailbox_provider_wise_performance` (`start_date`, `end_date` ISO) — metrics
  grouped by provider (Gmail, Outlook, etc.). Use it to answer "am I inboxing at
  Google but spam-foldering at Microsoft?"

How to read it:
- **Google fine, Microsoft poor** → very common. Microsoft (Outlook/M365) leans
  hard on Spamhaus and IP reputation; a Spamhaus/SORBS-class listing or a cold IP
  hits Microsoft first. Cross-check the DNS engine's blacklist result for that IP.
- **Microsoft fine, Google poor** → Gmail weighs engagement and domain reputation
  (spam-complaint rate, authentication consistency) more than IP lists. Points to
  content/engagement or DKIM alignment, not an IP blacklist.
- **Both poor on a specific domain** → treat as a domain-reputation problem
  (check DBL/SURBL/ZRD), not a per-provider quirk.

Pair this with `get_mailbox_name_wise_health_metrics` to see which individual
mailboxes drag a provider's numbers down.

## 2. Google Postmaster Tools (authoritative for Gmail)

The real Gmail reputation source. Requires one-time setup, then reading the
dashboard or API — not a DNS lookup, so it's a "point the user here" step:
- Verify the domain at postmaster.google.com (add the TXT record it gives you).
- It then reports **Domain reputation, IP reputation, Spam rate, Authentication
  (SPF/DKIM/DMARC pass %), and Encryption** for mail Gmail received from you.
- The number that matters most for cold email: **spam rate < 0.10%**. Above ~0.3%
  Gmail throttling begins.
If the user runs cold email at any volume and hasn't set up GPT, that's the single
highest-value recommendation you can make — it's the only window into Gmail's view.

## 3. Microsoft SNDS + JMRP (authoritative for Outlook/M365)

Microsoft's equivalents, also setup-gated:
- **SNDS** (Smart Network Data Services, sendersupport.olc.protection.outlook.com/snds)
  — per-IP data: complaint rates, trap hits, filter result. Requires proving you
  control the IP range.
- **JMRP** (Junk Mail Reporting Program) — a feedback loop that forwards
  Outlook.com "this is junk" complaints back to you so you can suppress those
  recipients.
- Outlook also honors **Spamhaus** heavily, which the DNS engine already checks —
  so a Spamhaus ZEN listing is effectively a strong Microsoft-deliverability
  warning even before you touch SNDS.

## Summary: how to answer "check Google/Microsoft signals"

1. Pull `get_mailbox_provider_wise_performance` (if Smartlead is connected) and
   report the Gmail-vs-Outlook split from real sends.
2. Tie any weak provider back to the DNS engine's blacklist/auth findings.
3. Recommend Google Postmaster Tools (Gmail) and Microsoft SNDS/JMRP (Outlook) as
   the authoritative dashboards, and note they need one-time setup — you can't
   read them via DNS.
Never claim a domain is "clean at Gmail/Outlook" from DNS alone — DNS can only
show the third-party lists those providers reference, not their internal verdict.
