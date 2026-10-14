#!/usr/bin/env python3
"""
domain_health.py — native DNS-based domain health + blacklist engine.

No third-party dependencies, no API keys. Shells out to `dig` (falls back to
`nslookup` if dig is missing). Designed for auditing cold-email sending domains.

What it checks per domain:
  - MX, A records and the IPs actually used to send/receive
  - SPF   (presence, syntax, DNS-lookup count vs the 10-limit, ~all/-all policy)
  - DMARC (presence, policy p=/sp=, pct, rua reporting address)
  - DKIM  (probes a list of common selectors; reports which resolve)
  - PTR / reverse-DNS for each sending IP
  - MTA-STS, TLS-RPT, BIMI presence
  - DNSBL blacklist status for every IP (and domain-based URI blacklists)

Output: a JSON object per domain on stdout (use --pretty for humans, or the
default machine JSON to feed a report). Exit code is always 0 unless the CLI
itself is misused — "domain is unhealthy" is data, not an error.

IMPORTANT resolver caveat: Spamhaus and some other DNSBLs REFUSE queries that
arrive via large public resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1) or from
cloud IPs. They answer with a 127.255.255.x code that means "your query was
blocked", NOT "not listed". Treating that as clean is a false-negative that
ships a blacklisted domain. This script detects those codes and reports the
zone as "error" (unknown), never "clean". If you see lots of errors, run from a
host on a normal ISP connection or pass --resolver <your-isp-resolver>.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from typing import Optional


def resolve_dqs_key(cli_value: Optional[str]) -> Optional[str]:
    """Spamhaus DQS key precedence: --dqs-key > env SPAMHAUS_DQS_KEY > skill-root .env."""
    if cli_value:
        return cli_value.strip()
    if os.environ.get("SPAMHAUS_DQS_KEY"):
        return os.environ["SPAMHAUS_DQS_KEY"].strip()
    # skill root is the parent of scripts/
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    try:
        with open(env_path) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("SPAMHAUS_DQS_KEY") and "=" in line:
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return None


def _env_flag(name: str) -> bool:
    """True if `name` is truthy in env or the skill-root .env (1/true/yes/on)."""
    def truthy(v: str) -> bool:
        return v.strip().strip('"').strip("'").lower() in ("1", "true", "yes", "on")
    if os.environ.get(name):
        return truthy(os.environ[name])
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    try:
        with open(env_path) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(name) and "=" in line:
                    return truthy(line.split("=", 1)[1])
    except FileNotFoundError:
        pass
    return False


# --------------------------------------------------------------------------- #
# DNS plumbing
# --------------------------------------------------------------------------- #

DIG = shutil.which("dig")
NSLOOKUP = shutil.which("nslookup")
DNS_TIMEOUT = 4  # seconds per query


def _dig(name: str, rtype: str, resolver: Optional[str]) -> list[str]:
    """Return the short answer records for name/rtype, or [] on no-answer."""
    if DIG:
        # +tries=2 lets dig itself retry on UDP packet loss / timeout (the main
        # cause of flaky results under a parallel fan-out). It does NOT retry a
        # genuine NXDOMAIN, so legitimately-absent records still return fast —
        # we don't pay the retry cost on the 20+ missing DKIM selectors.
        cmd = ["dig", "+short", "+time=3", "+tries=2", name, rtype]
        if resolver:
            cmd.append(f"@{resolver}")
    elif NSLOOKUP:
        cmd = ["nslookup", f"-type={rtype}", name] + ([resolver] if resolver else [])
    else:
        raise RuntimeError("Neither 'dig' nor 'nslookup' is installed.")
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=DNS_TIMEOUT + 2
        ).stdout
    except subprocess.TimeoutExpired:
        return []
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if DIG:
        # dig +short already gives clean rdata; drop CNAME chains for A queries
        return [ln for ln in lines if not ln.endswith(".") or rtype in ("MX", "NS", "CNAME", "PTR")]
    # crude nslookup parsing fallback
    vals = []
    for ln in lines:
        if "=" in ln:
            vals.append(ln.split("=", 1)[1].strip().strip('"'))
        elif rtype == "TXT" and ln.startswith('"'):
            vals.append(ln.strip('"'))
    return vals


def txt(name: str, resolver) -> list[str]:
    # dig returns TXT wrapped in quotes, possibly split into chunks — join them.
    raw = _dig(name, "TXT", resolver)
    out = []
    for r in raw:
        out.append(r.replace('" "', "").strip('"'))
    return out


def a_records(name: str, resolver) -> list[str]:
    return [r for r in _dig(name, "A", resolver) if _is_ip(r)]


def mx_hosts(name: str, resolver) -> list[tuple[int, str]]:
    res = []
    for r in _dig(name, "MX", resolver):
        parts = r.split()
        if len(parts) == 2 and parts[0].isdigit():
            res.append((int(parts[0]), parts[1].rstrip(".")))
    return sorted(res)


def ptr(ip: str, resolver) -> Optional[str]:
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return None
    ans = _dig(rev, "PTR", resolver)
    return ans[0].rstrip(".") if ans else None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Blacklists — see references/blacklists.md for the reasoning behind this set.
# type: "ip" reverses the IP octets; "domain" queries the bare domain.
# inverted: hostkarma-style zones where a hit can mean *whitelisted*.
# advisory: range-based lists (uceprotect L2/L3) — a listing rarely means the
#           domain itself did anything wrong, so we surface but don't score hard.
# --------------------------------------------------------------------------- #

DNSBLS = [
    # Spamhaus entries carry a `dqs_zone`. When a Spamhaus DQS key is supplied
    # we query the authenticated `*.dq.spamhaus.net` zones instead of the public
    # ones — same data, but no public-resolver block, so results are real rather
    # than "unchecked". `dqs_only` lists are skipped entirely without a key.
    {"zone": "zen.spamhaus.org",        "type": "ip", "label": "Spamhaus ZEN", "dqs_zone": "zen.dq.spamhaus.net"},
    {"zone": "bl.spamcop.net",          "type": "ip", "label": "SpamCop"},
    {"zone": "b.barracudacentral.org",  "type": "ip", "label": "Barracuda"},
    {"zone": "psbl.surriel.com",        "type": "ip", "label": "PSBL"},
    {"zone": "bl.mailspike.net",        "type": "ip", "label": "Mailspike BL"},
    {"zone": "ix.dnsbl.manitu.net",     "type": "ip", "label": "NiX Spam"},
    {"zone": "all.spamrats.com",        "type": "ip", "label": "SpamRats"},
    {"zone": "truncate.gbudb.net",      "type": "ip", "label": "GBUdb Truncate"},
    {"zone": "bl.spameatingmonkey.net", "type": "ip", "label": "SpamEatingMonkey"},
    # --- Advisory IP lists: real, but low adoption at major receivers or
    #     controversial operators. Surfaced, never scored, so a hit here informs
    #     rather than tanks the grade. ---
    # UCEPROTECT lists whole ISP ranges and is widely regarded as pay-to-delist;
    # Gmail/Outlook largely ignore it. L1 is per-IP but still marginal; L2/L3 are
    # range-based. All advisory — a UCEPROTECT hit alone rarely blocks real mail.
    {"zone": "dnsbl-1.uceprotect.net",  "type": "ip", "label": "UCEPROTECT L1", "advisory": True},
    {"zone": "dnsbl-2.uceprotect.net",  "type": "ip", "label": "UCEPROTECT L2", "advisory": True},
    {"zone": "dnsbl-3.uceprotect.net",  "type": "ip", "label": "UCEPROTECT L3", "advisory": True},
    {"zone": "bl.0spam.org",            "type": "ip", "label": "0Spam", "advisory": True},
    {"zone": "rbl.interserver.net",     "type": "ip", "label": "InterServer", "advisory": True},
    # Backscatterer lists IPs seen sending misdirected bounces/backscatter — niche,
    # prone to catching legit mailflow.
    {"zone": "ips.backscatterer.org",   "type": "ip", "label": "Backscatterer", "advisory": True},
    {"zone": "hostkarma.junkemailfilter.com", "type": "ip", "label": "HostKarma", "inverted": True},
    # --- Invaluement: genuinely high-value (used by serious enterprise filters),
    #     but a PAID subscription list. Its full data only serves licensed
    #     resolvers; from an unlicensed one, real lookups return nothing — a
    #     silent false "clean". So it's subscription-gated: skipped entirely
    #     unless --invaluement is set, and you must query from your licensed
    #     resolver (--resolver). Enabling it without a subscription is worse than
    #     leaving it off. ---
    {"zone": "sip.invaluement.com",     "type": "ip",     "label": "Invaluement ivmSIP",    "sub_only": True},
    {"zone": "sip24.invaluement.com",   "type": "ip",     "label": "Invaluement ivmSIP/24", "sub_only": True},
    {"zone": "uri.invaluement.com",     "type": "domain", "label": "Invaluement ivmURI",    "sub_only": True},
    # domain / URI blacklists
    {"zone": "dbl.spamhaus.org",        "type": "domain", "label": "Spamhaus DBL", "dqs_zone": "dbl.dq.spamhaus.net"},
    {"zone": "multi.uribl.com",         "type": "domain", "label": "URIBL"},
    {"zone": "multi.surbl.org",         "type": "domain", "label": "SURBL"},
    {"zone": "urired.spameatingmonkey.net", "type": "domain", "label": "SEM URIRED"},
    # ZRD = Zero Reputation Domains (brand-new registrations). DQS-only. Useful
    # for cold email: a hit means receivers may distrust the domain simply for
    # being new — advisory, not a spam accusation.
    {"zone": None, "type": "domain", "label": "Spamhaus ZRD", "dqs_zone": "zrd.dq.spamhaus.net", "dqs_only": True, "advisory": True},
]

# 127.255.255.x (and Spamhaus 127.255.255.252-254) = query blocked / rate-limited
# / not-a-real-listing. Never interpret these as a genuine hit.
BLOCK_CODES_PREFIX = "127.255.255."


def _query_bl(bl: dict, query: str, resolver) -> dict:
    ans = _dig(query, "A", resolver)
    ans = [a for a in ans if _is_ip(a)]
    if not ans:
        return {"status": "clean", "codes": []}
    if any(a.startswith(BLOCK_CODES_PREFIX) for a in ans):
        return {"status": "error", "codes": ans}  # resolver blocked / rate-limited
    if bl.get("inverted"):
        # hostkarma: 127.0.0.1 == whitelist (good), anything else == bad
        if ans == ["127.0.0.1"]:
            return {"status": "whitelisted", "codes": ans}
        return {"status": "listed", "codes": ans}
    # For normal lists, 127.0.0.1 is NEVER a spam hit — it universally means
    # "query refused / not permitted over public DNS / rate-limited" (URIBL,
    # SURBL, some IP lists). Real listings start at 127.0.0.2. Reporting a bare
    # .1 as "listed" is the classic blacklist false-positive.
    if ans == ["127.0.0.1"]:
        return {"status": "error", "codes": ans}
    return {"status": "listed", "codes": ans}


def _bl_query(bl: dict, target: str, dqs_key: Optional[str], invaluement: bool = False) -> Optional[str]:
    """Build the lookup name, DQS-aware. Returns None if the list must be skipped."""
    if bl.get("dqs_only") and not dqs_key:
        return None
    if bl.get("sub_only") and not invaluement:
        return None  # subscription list not enabled — skip rather than false-clean
    if bl.get("dqs_zone") and dqs_key:
        # DQS format: <reversed-ip-or-domain>.<key>.<zone>.dq.spamhaus.net
        return f"{target}.{dqs_key}.{bl['dqs_zone']}"
    return f"{target}.{bl['zone']}"


def check_blacklists(ips: list[str], domain: str, resolver, workers: int,
                     dqs_key: Optional[str] = None, invaluement: bool = False) -> dict:
    jobs = []  # (bl, target_label, query)
    for ip in ips:
        try:
            rev = ".".join(reversed(ip.split(".")))  # IPv4 only for DNSBLs
        except Exception:
            continue
        for bl in DNSBLS:
            if bl["type"] == "ip":
                q = _bl_query(bl, rev, dqs_key, invaluement)
                if q:
                    jobs.append((bl, ip, q))
    for bl in DNSBLS:
        if bl["type"] == "domain":
            q = _bl_query(bl, domain, dqs_key, invaluement)
            if q:
                jobs.append((bl, domain, q))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        fut = {pool.submit(_query_bl, bl, q, resolver): (bl, tgt) for bl, tgt, q in jobs}
        for f in concurrent.futures.as_completed(fut):
            bl, tgt = fut[f]
            r = f.result()
            status = r["status"]
            results.append({
                "list": bl["label"], "zone": bl["zone"], "target": tgt,
                "status": status, "codes": r["codes"],
                "advisory": bl.get("advisory", False),
            })

    listed = [r for r in results if r["status"] == "listed" and not r["advisory"]]
    advisory = [r for r in results if r["status"] == "listed" and r["advisory"]]
    errors = [r for r in results if r["status"] == "error"]
    return {
        "listed_on": sorted({r["list"] for r in listed}),
        "advisory_listings": sorted({r["list"] for r in advisory}),
        "unchecked_blocked": sorted({r["list"] for r in errors}),
        "clean": not listed,
        "detail": sorted(results, key=lambda r: (r["status"] != "listed", r["list"])),
    }


# --------------------------------------------------------------------------- #
# Email auth records
# --------------------------------------------------------------------------- #

DKIM_SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "k3", "dkim", "default",
    "s1", "s2", "mail", "smtp", "mandrill", "mxvault", "sig1", "scph0", "scph1",
    "zoho", "zmail", "everlytickey1", "everlytickey2", "pm", "pmta", "mte1",
]


def _count_spf_lookups(spf: str, domain: str, resolver, depth=0, seen=None) -> int:
    """
    Approximate SPF DNS-lookup count. Each include/a/mx/ptr/exists/redirect
    costs one lookup; includes/redirects recurse. RFC 7208 fails SPF above 10.
    """
    if seen is None:
        seen = set()
    if depth > 10 or domain in seen:
        return 0
    seen.add(domain)
    count = 0
    for tok in spf.split():
        t = tok.lower().lstrip("+-~?")
        if t.startswith(("include:", "a:", "mx:", "ptr:", "exists:", "a", "mx", "ptr")) or t.startswith("redirect="):
            if t in ("a", "mx", "ptr") or t.startswith(("a:", "mx:", "ptr:", "exists:")):
                count += 1
            elif t.startswith("include:") or t.startswith("redirect="):
                count += 1
                target = tok.split(":", 1)[-1] if ":" in tok else tok.split("=", 1)[-1]
                sub = [r for r in txt(target, resolver) if r.lower().startswith("v=spf1")]
                if sub:
                    count += _count_spf_lookups(sub[0], target, resolver, depth + 1, seen)
    return count


def check_spf(domain: str, resolver) -> dict:
    recs = [r for r in txt(domain, resolver) if r.lower().startswith("v=spf1")]
    if not recs:
        return {"present": False, "issue": "No SPF record found"}
    if len(recs) > 1:
        return {"present": True, "record": recs, "valid": False,
                "issue": "Multiple SPF records — only one is allowed (PermError)"}
    spf = recs[0]
    lookups = _count_spf_lookups(spf, domain, resolver)
    all_mech = "none"
    for tok in spf.split():
        if tok.lower().endswith("all"):
            all_mech = {"-": "hardfail (-all)", "~": "softfail (~all)",
                        "?": "neutral (?all)", "+": "pass-all (+all, insecure)"}.get(tok[0], tok)
    issues = []
    if lookups > 10:
        issues.append(f"{lookups} DNS lookups — exceeds the 10-lookup limit (PermError)")
    if all_mech in ("none", "pass-all (+all, insecure)"):
        issues.append(f"Weak/absent 'all' mechanism: {all_mech}")
    return {"present": True, "record": spf, "dns_lookups": lookups,
            "all_mechanism": all_mech, "issues": issues, "valid": not issues}


def check_dmarc(domain: str, resolver) -> dict:
    recs = [r for r in txt(f"_dmarc.{domain}", resolver) if r.lower().startswith("v=dmarc1")]
    if not recs:
        return {"present": False, "issue": "No DMARC record found"}
    rec = recs[0]
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    p = tags.get("p", "none")
    issues = []
    if p == "none":
        issues.append("Policy p=none — monitoring only, provides no enforcement")
    if not tags.get("rua"):
        issues.append("No rua= aggregate-report address — you're flying blind on auth failures")
    return {"present": True, "record": rec, "policy": p,
            "subdomain_policy": tags.get("sp", p), "pct": tags.get("pct", "100"),
            "rua": tags.get("rua"), "issues": issues,
            "valid": p in ("quarantine", "reject") and not issues}


def check_dkim(domain: str, resolver, workers: int) -> dict:
    found = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        fut = {pool.submit(txt, f"{s}._domainkey.{domain}", resolver): s for s in DKIM_SELECTORS}
        for f in concurrent.futures.as_completed(fut):
            s = fut[f]
            recs = [r for r in f.result() if "p=" in r.lower() or "v=dkim1" in r.lower()]
            if recs:
                found[s] = recs[0][:80] + ("..." if len(recs[0]) > 80 else "")
    return {"present": bool(found), "selectors_found": found,
            "note": "Only common selectors are probed; absence here is not proof "
                    "DKIM is missing — the real selector may be custom."}


# --------------------------------------------------------------------------- #
# Per-domain orchestration + scoring
# --------------------------------------------------------------------------- #

def audit_domain(domain: str, resolver, workers: int, dqs_key: Optional[str] = None,
                 invaluement: bool = False) -> dict:
    domain = domain.strip().lower().rstrip(".")
    mx = mx_hosts(domain, resolver)
    a = a_records(domain, resolver)

    # Sending/receiving IPs: MX host IPs + the domain's own A record(s).
    ips = list(dict.fromkeys(
        [ip for _, host in mx for ip in a_records(host, resolver)] + a
    ))
    rdns = {ip: ptr(ip, resolver) for ip in ips}

    spf = check_spf(domain, resolver)
    dmarc = check_dmarc(domain, resolver)
    dkim = check_dkim(domain, resolver, workers)
    bl = check_blacklists(ips, domain, resolver, workers, dqs_key, invaluement)

    mta_sts = bool([r for r in txt(f"_mta-sts.{domain}", resolver) if "v=stsv1" in r.lower()])
    tls_rpt = bool([r for r in txt(f"_smtp._tls.{domain}", resolver) if "v=tlsrptv1" in r.lower()])
    bimi = bool([r for r in txt(f"default._bimi.{domain}", resolver) if "v=bimi1" in r.lower()])

    # Scoring: start at 100, subtract for real problems. This is a heuristic to
    # rank a batch, not gospel — the detail below is what actually matters.
    score = 100
    flags = []
    if not mx:
        score -= 25; flags.append("No MX record — cannot receive mail")
    if not spf.get("valid"):
        score -= 20; flags.append("SPF: " + "; ".join(spf.get("issues") or [spf.get("issue", "invalid")]))
    if not dmarc.get("present"):
        score -= 20; flags.append("DMARC missing")
    elif not dmarc.get("valid"):
        score -= 10; flags.append("DMARC weak: " + "; ".join(dmarc.get("issues", [])))
    if not dkim.get("present"):
        score -= 10; flags.append("No DKIM selector resolved (verify the real selector)")
    if bl["listed_on"]:
        score -= 25; flags.append("Blacklisted on: " + ", ".join(bl["listed_on"]))
    if any(v is None for v in rdns.values()) and ips:
        flags.append("One or more sending IPs lack reverse DNS (PTR)")
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    return {
        "domain": domain,
        "score": score, "grade": grade,
        "top_flags": flags,
        "mx": [f"{p} {h}" for p, h in mx],
        "sending_ips": ips,
        "reverse_dns": rdns,
        "spf": spf, "dmarc": dmarc, "dkim": dkim,
        "blacklist": bl,
        "mta_sts": mta_sts, "tls_rpt": tls_rpt, "bimi": bimi,
    }


def load_domains(args) -> list[str]:
    doms = list(args.domains)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                # accept plain lists or CSV; take the first comma-field, skip header-ish rows
                cell = line.split(",")[0].strip().strip('"')
                if cell and "." in cell and cell.lower() not in ("domain", "domains", "website"):
                    doms.append(cell)
    # de-dupe, strip scheme/path if a URL slipped in
    clean = []
    for d in doms:
        d = d.strip().lower()
        for pre in ("https://", "http://", "www."):
            if d.startswith(pre):
                d = d[len(pre):]
        d = d.split("/")[0].split("@")[-1]
        if d and d not in clean:
            clean.append(d)
    return clean


def main():
    ap = argparse.ArgumentParser(description="Native DNS domain health + blacklist audit.")
    ap.add_argument("domains", nargs="*", help="one or more domains")
    ap.add_argument("--file", help="file with domains (one per line, or CSV; first column used)")
    ap.add_argument("--resolver", help="DNS resolver IP (e.g. your ISP's) to dodge Spamhaus public-resolver blocks")
    ap.add_argument("--dqs-key", help="Spamhaus DQS key (free tier). Else read from env SPAMHAUS_DQS_KEY or skill-root .env")
    ap.add_argument("--invaluement", action="store_true",
                    help="enable the paid Invaluement lists (only meaningful from your LICENSED resolver via --resolver; "
                         "else read from env INVALUEMENT_ENABLED or skill-root .env)")
    ap.add_argument("--workers", type=int, default=16, help="parallel DNS queries (lower = gentler on the resolver, fewer timeouts)")
    ap.add_argument("--pretty", action="store_true", help="human-readable summary instead of JSON")
    args = ap.parse_args()

    domains = load_domains(args)
    if not domains:
        ap.error("no domains given (positional args or --file)")

    dqs_key = resolve_dqs_key(args.dqs_key)
    invaluement = args.invaluement or _env_flag("INVALUEMENT_ENABLED")
    if args.pretty:
        print(f"[Spamhaus DQS: {'enabled — authenticated Spamhaus/ZRD checks' if dqs_key else 'not set — Spamhaus falls back to public zones (may be resolver-blocked)'}]")
        if invaluement:
            print("[Invaluement: enabled — ensure you are querying from your licensed resolver (--resolver), else results are unreliable]")

    results = [audit_domain(d, args.resolver, args.workers, dqs_key, invaluement) for d in domains]

    if args.pretty:
        for r in results:
            print(f"\n{'='*60}\n{r['domain']}   [{r['grade']}]  score {r['score']}/100")
            for fl in r["top_flags"]:
                print(f"  ⚠  {fl}")
            if not r["top_flags"]:
                print("  ✓  No major issues detected")
            print(f"  MX: {', '.join(r['mx']) or 'none'}")
            print(f"  IPs: {', '.join(r['sending_ips']) or 'none'}")
            bl = r["blacklist"]
            print(f"  Blacklist: {'LISTED on ' + ', '.join(bl['listed_on']) if bl['listed_on'] else 'clean'}"
                  + (f"  (advisory: {', '.join(bl['advisory_listings'])})" if bl["advisory_listings"] else "")
                  + (f"  (unchecked/blocked: {', '.join(bl['unchecked_blocked'])})" if bl["unchecked_blocked"] else ""))
        print()
    else:
        json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
