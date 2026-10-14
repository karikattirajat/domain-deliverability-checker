# Live deliverability from Smartlead MCP

The DNS engine tells you whether a domain is *configured* to deliver. Smartlead
tells you whether it *actually is* — real bounce rates, warmup progress, and
inbox placement from live sending. Pull these only for domains that belong to the
user's Smartlead account (their own sending domains), never for arbitrary/target
domains.

If the Smartlead MCP is not connected, skip this layer and say so — the DNS audit
still stands on its own.

## Which tool for which metric

| You want… | Tool | Key args | Notes |
|-----------|------|----------|-------|
| Deliverability + DNS + reputation for one domain | `check_mailbox_domain_deliverability` | `domain` | Smartlead's own view; cross-check against the DNS engine. |
| Health metrics grouped by sending domain | `get_mailbox_domain_wise_health_metrics` | `start_date`, `end_date` (ISO); optional `campaign_ids`, `limit` | Best for a whole-pool audit; returns per-domain reputation/health. |
| Warmup progress / reputation ramp for a mailbox | `get_email_warmup_stats` | `email_account_id` (number) | Needs the account ID — resolve it first (below). |
| List mailboxes / find an account ID | `get_email_accounts` | `username` (email), `limit`, `offset` | Filter by `username` to map an address → `email_account_id`. |
| Bounce rate & lead-quality problems | `check_campaign_bounce_or_lead_quality` | `campaignId` (number) | High bounces tank domain reputation fast. |
| Full campaign diagnostics (config + perf) | `get_campaign_diagnostics` | `campaignId` (number) | Surfaces sending issues at the campaign level. |
| **Gmail-vs-Outlook performance split** | `get_mailbox_provider_wise_performance` | `start_date`, `end_date` (ISO) | The real Google/Microsoft signal — see [provider-signals.md](provider-signals.md). |
| Health per individual mailbox | `get_mailbox_name_wise_health_metrics` | `start_date`, `end_date` (ISO) | Find which mailbox is dragging a provider's numbers. |

## Resolving domain → warmup stats

`get_email_warmup_stats` is per-mailbox, keyed by `email_account_id`. To go from a
domain to warmup numbers:

1. `get_email_accounts` (optionally `username` filtered) → find the mailboxes on
   that domain and read each `email_account_id`.
2. `get_email_warmup_stats(email_account_id=...)` for each mailbox.
3. Aggregate: report the domain's warmup as the range/average across its
   mailboxes, and flag any single mailbox with a poor warmup score.

## Reading the numbers

- **Warmup score / reputation** — a low or falling score on an established domain
  means reputation damage; pair it with any blacklist hit from the DNS engine.
- **Bounce rate** — anything sustained above ~3–5% is a reputation and list-hygiene
  red flag; above ~8–10% providers start throttling. Tie high bounces back to
  lead quality (`check_campaign_bounce_or_lead_quality`), not just the domain.
- **Provider-wise inbox rate** — if Google inboxes but Microsoft spams (or vice
  versa), that's a provider-specific reputation/auth issue, not a blanket one;
  call it out separately.

## Combining both layers in the verdict

The strongest reports fuse the two:
- DNS clean + Smartlead healthy → "safe to send / scale."
- DNS clean + Smartlead bounces climbing → "config is fine; the problem is list
  quality or volume ramp — fix hygiene, not DNS."
- DNS broken (SPF/DMARC) + Smartlead spam-foldering → "authentication is the root
  cause; fix records first, then re-warm."
- Blacklisted (Spamhaus/SpamCop) → "pause this IP/domain, request delisting,"
  regardless of what warmup says.
