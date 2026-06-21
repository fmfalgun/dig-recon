#!/usr/bin/env python3
"""
dig-recon.py — Standalone DNS reconnaissance with TTL cache + community submit

Runs a full DNS sweep for a single domain:
  A / AAAA / NS / MX / TXT / SOA / CAA / DNSKEY / PTR / AXFR + subdomain brute.
Analyses SPF + DMARC, fingerprints hosting infrastructure, caches results
in a local SQLite TTL cache, and optionally submits to a public community board.

Output behaviour:
  - stdout     : always (terminal summary)
  - cache.db   : always (SQLite TTL cache, ./cache.db — auto-created)
  - JSON file  : optional (--output <path>)

Cache behaviour:
  - Results are cached for 24 hours by default (tune with --ttl)
  - Use --no-cache to force a fresh fetch (cache is still written)

Usage examples:
  python3 dig-recon.py -d startbitsolutions.com
  python3 dig-recon.py -d startbitsolutions.com -o results.json
  python3 dig-recon.py -d startbitsolutions.com --no-cache
  python3 dig-recon.py -d startbitsolutions.com --ttl 6 --submit
  python3 dig-recon.py --reconfigure
  python3 dig-recon.py --version
"""

import sys
import json
import sqlite3
import re
import ipaddress
import argparse
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Optional

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.rdatatype
    import dns.exception
    import dns.reversename
    import dns.name
except ImportError:
    sys.exit("[!] dnspython not installed.  Run: pip install dnspython")


# ─── version + paths ──────────────────────────────────────────────────────────

__version__       = "1.0.0"
CACHE_DB          = "./cache.db"
CONFIG_PATH       = Path.home() / ".config" / "dig-recon" / "config.json"
GITHUB_ISSUES_URL = "https://api.github.com/repos/fmfalgun/dig-recon/issues"


# ─── constants ────────────────────────────────────────────────────────────────

TIMEOUT      = 5        # seconds per query
DNS64_PREFIX = "64:ff9b::"

# Common subdomains to brute-force
BRUTE_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "webmail", "cpanel", "whm", "admin", "portal",
    "shop", "blog", "training", "newsite", "dev",
    "staging", "api", "app", "m", "mobile",
    "autodiscover", "lyncdiscover", "vpn", "remote",
    "direct", "secure", "test", "beta", "old",
    "static", "cdn", "assets", "img", "media",
    "support", "help", "login", "dashboard",
    "webdisk", "cpcalendars", "cpcontacts",
]

# Record types required for a complete domain sweep
REQUIRED_TYPES = frozenset({"A", "AAAA", "NS", "SOA", "MX", "TXT", "DMARC", "CAA", "DNSKEY"})

# Skip subdomain FQDNs that are clearly CDN cache nodes (IP-address labels, deep nesting)
_IP_IN_LABEL = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# Cloudflare CIDR blocks (as of mid-2025)
CLOUDFLARE_CIDRS = [
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
]


# ─── Cache ────────────────────────────────────────────────────────────────────

def get_cache_db() -> sqlite3.Connection:
    """Open (or create) cache.db and ensure the schema exists."""
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS dig_cache (
        domain     TEXT PRIMARY KEY,
        data       TEXT NOT NULL,
        cached_at  TEXT NOT NULL
    )""")
    conn.commit()
    return conn


def cache_get(domain: str, ttl_hours: int = 24) -> Optional[dict]:
    """Return cached result dict if within ttl_hours, else None."""
    conn = get_cache_db()
    try:
        row = conn.execute(
            "SELECT data, cached_at FROM dig_cache WHERE domain = ?", (domain,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    data_str, cached_at_str = row
    try:
        cached_at = datetime.fromisoformat(cached_at_str)
        if cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    if datetime.now(timezone.utc) - cached_at > timedelta(hours=ttl_hours):
        return None  # expired

    return json.loads(data_str)


def cache_put(domain: str, data: dict) -> None:
    """UPSERT a result dict into the cache."""
    cached_at = datetime.now(timezone.utc).isoformat()
    conn = get_cache_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO dig_cache (domain, data, cached_at) VALUES (?, ?, ?)",
            (domain, json.dumps(data), cached_at),
        )
        conn.commit()
    finally:
        conn.close()


# ─── Config + submit ──────────────────────────────────────────────────────────

def load_config() -> Optional[dict]:
    """Load stored config from CONFIG_PATH. Returns None if not found or invalid."""
    if not CONFIG_PATH.exists():
        return None
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return None


def save_config(cfg: dict) -> None:
    """Write config dict to CONFIG_PATH, creating parent dirs as needed."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def setup_wizard() -> dict:
    """
    First-time interactive setup. Asks for GitHub PAT, display name, location.
    Saves to CONFIG_PATH and returns the config dict.
    """
    print("\n[setup] dig-recon first-time configuration")
    print("        Your GitHub PAT needs Issues: write scope.")
    print("        Create one at: https://github.com/settings/tokens\n")

    token        = input("  GitHub PAT       : ").strip()
    display_name = input("  Display name     : ").strip()
    display_loc  = input("  Location (city)  : ").strip()

    cfg = {
        "github_token": token,
        "display_name": display_name,
        "display_loc":  display_loc,
    }
    save_config(cfg)
    print(f"[setup] Config saved to {CONFIG_PATH}\n")
    return cfg


def submit_result(result: dict, config: dict) -> None:
    """
    POST a GitHub Issue to the dig-recon repo.
    Title: [submission] domain
    Body: JSON of the full result.
    """
    import urllib.request

    domain = result.get("domain", "")
    token  = config.get("github_token", "")

    if not token:
        print("[!] No GitHub token in config — run with --reconfigure to set one.")
        return

    body_data = {
        "domain":         domain,
        "display_name":   config.get("display_name", ""),
        "display_loc":    config.get("display_loc", ""),
        "queried_at":     result.get("queried_at", ""),
        "hosting_type":   result.get("hosting_type"),
        "hosting_provider": result.get("hosting_provider"),
        "email_provider": result.get("email_provider"),
        "email_spoofable": result.get("email_spoofable"),
        "spoofable_reason": result.get("spoofable_reason"),
        "caa_present":    result.get("caa_present"),
        "dnssec_present": result.get("dnssec_present"),
        "axfr_success":   result.get("axfr_success"),
        "subdomain_count": result.get("subdomain_count"),
        "unique_ips":     result.get("unique_ips"),
        "records":        result.get("records", {}),
    }

    issue = {
        "title": f"[submission] {domain}",
        "body":  json.dumps(body_data),
    }

    req = urllib.request.Request(
        GITHUB_ISSUES_URL,
        data=json.dumps(issue).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/vnd.github+json",
            "User-Agent":    f"dig-recon/{__version__}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_data = json.loads(resp.read())
            issue_url = resp_data.get("html_url", "")
            print(f"[+] Submitted → {issue_url}")
            print("    Your result will appear on the community board once GitHub Actions processes it (~2 min).")
    except Exception as e:
        print(f"[!] Submission failed: {e}")


# ─── DNS query helpers ────────────────────────────────────────────────────────

_resolver = dns.resolver.Resolver()
_resolver.timeout  = TIMEOUT
_resolver.lifetime = TIMEOUT * 3   # allow TCP fallback for large record sets (e.g. google.com TXT)


def _query(domain: str, rtype: str) -> list[tuple[str, int]]:
    """Generic DNS query. Returns [(value, ttl), ...] or []."""
    try:
        ans = _resolver.resolve(domain, rtype, raise_on_no_answer=False)
        return [(str(rr), ans.ttl) for rr in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout):
        return []


def query_txt(domain: str) -> list[tuple[str, int]]:
    """TXT records — join multi-string RRs into one string."""
    try:
        ans = _resolver.resolve(domain, "TXT", raise_on_no_answer=False)
        results = []
        for rr in ans:
            joined = "".join(
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rr.strings
            )
            results.append((joined, ans.ttl))
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout):
        return []


def ptr_lookup(ip: str) -> Optional[str]:
    try:
        rev  = dns.reversename.from_address(ip)
        ans  = _resolver.resolve(rev, "PTR", raise_on_no_answer=False)
        return str(ans[0]).rstrip(".") if ans else None
    except Exception:
        return None


def resolve_ns_ips(ns_name: str) -> list[str]:
    return [v for v, _ in _query(ns_name.rstrip("."), "A")]


def _axfr_inner(domain: str, ns_ip: str) -> list[str]:
    """Inner AXFR — called from a thread so we can enforce a hard wall-clock timeout."""
    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=TIMEOUT, lifetime=TIMEOUT))
    records = []
    for name, node in z.nodes.items():
        for rdset in node.rdatasets:
            for rdata in rdset:
                records.append(
                    f"{name} {rdset.ttl} {dns.rdatatype.to_text(rdset.rdtype)} {rdata}"
                )
    return records


def axfr_attempt(domain: str, ns_ip: str) -> list[str]:
    """
    Try AXFR with a hard wall-clock timeout.
    Cloudflare and some servers accept the TCP connection then send nothing,
    causing dns.query.xfr to block on socket.recv() indefinitely.
    We submit to a daemon thread (daemon=True so it dies with the process),
    then abandon it after timeout — never wait=True on the pool exit.
    """
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="axfr")
    future = pool.submit(_axfr_inner, domain, ns_ip)
    try:
        result = future.result(timeout=TIMEOUT + 2)
        pool.shutdown(wait=False)
        return result
    except Exception:
        pool.shutdown(wait=False)   # don't wait — the thread stays blocked on the socket
        return []


def is_dns64(aaaa: str) -> bool:
    return aaaa.startswith(DNS64_PREFIX)


# ─── Infrastructure fingerprinting ───────────────────────────────────────────

def classify_ip(ip_str: str, ptr: Optional[str]) -> tuple[str, str, int, str]:
    """
    Returns (hosting_label, provider, is_cdn, cdn_name).
    Checks CDN CIDRs first, then PTR patterns.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", "unknown", 0, ""

    for cidr in CLOUDFLARE_CIDRS:
        if ip in cidr:
            return "Cloudflare edge — NOT origin server", "Cloudflare", 1, "Cloudflare"

    if ptr:
        p = ptr.lower()
        if p.endswith(".1e100.net"):
            return "Google Cloud / GCP", "Google", 0, ""
        if ".unifiedlayer.com" in p:
            return "Unified Layer / HostGator / PDR shared hosting", "Unified Layer", 0, ""
        if ".cloudfront.net" in p:
            return "AWS CloudFront CDN", "AWS", 1, "CloudFront"
        if ".akamaitech.net" in p or ".akamai.net" in p:
            return "Akamai CDN", "Akamai", 1, "Akamai"
        if "hostinger" in p:
            return "Hostinger hosting", "Hostinger", 0, ""
        if "amazonaws" in p:
            return "AWS EC2 / infrastructure", "AWS", 0, ""
        if "nocdirect" in p:
            return "NTHL / nocdirect.com (PDR mail relay)", "NTHL/PDR", 0, ""

    # IP block heuristics
    try:
        if ip in ipaddress.ip_network("162.251.80.0/22"):
            return "PDR / HostGator shared hosting (162.251.80.0/22)", "PDR/HostGator", 0, ""
        if ip in ipaddress.ip_network("162.215.240.0/23"):
            return "PDR mail-sending infra (162.215.240.0/23)", "PDR", 0, ""
        if ip in ipaddress.ip_network("217.21.80.0/16"):
            return "Hostinger India (AS47583)", "Hostinger", 0, ""
    except Exception:
        pass

    return "Unknown", "Unknown", 0, ""


def detect_email_provider(mx_names: list[str]) -> str:
    for name in mx_names:
        n = name.lower()
        if "outlook" in n or "protection.microsoft" in n:
            return "Microsoft 365"
        if "google" in n or "gmail" in n or "aspmx" in n:
            return "Google Workspace"
        if "hostinger" in n:
            return "Hostinger"
        if "mxroute" in n:
            return "MXRoute"
        if "pphosted" in n or "proofpoint" in n:
            return "Proofpoint"
        if "mailgun" in n:
            return "Mailgun"
        if "sendgrid" in n:
            return "SendGrid"
    return "Self-hosted / Unknown"


# ─── SPF + DMARC parsers ─────────────────────────────────────────────────────

def parse_spf(raw: str) -> dict:
    result = {"raw": raw, "all": None, "includes": [], "ip4": [], "ip6": [], "a": False, "mx": False}
    for token in raw.split():
        t = token.lower()
        if t in ("-all", "~all", "+all", "?all"):
            result["all"] = t
        elif t.startswith("include:"):
            result["includes"].append(token[8:])
        elif t.startswith("ip4:"):
            result["ip4"].append(token[4:])
        elif t.startswith("ip6:"):
            result["ip6"].append(token[4:])
        elif t in ("+a", "a"):
            result["a"] = True
        elif t in ("+mx", "mx"):
            result["mx"] = True
    return result


def parse_dmarc(raw: str) -> dict:
    result = {
        "raw": raw,
        "policy": None, "subdomain_policy": None,
        "pct": 100, "rua": None, "ruf": None,
    }
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("p="):
            result["policy"] = part[2:].strip()
        elif part.startswith("sp="):
            result["subdomain_policy"] = part[3:].strip()
        elif part.startswith("pct="):
            try:
                result["pct"] = int(part[4:])
            except ValueError:
                pass
        elif part.startswith("rua="):
            result["rua"] = part[4:].strip()
        elif part.startswith("ruf="):
            result["ruf"] = part[4:].strip()
    return result


def assess_email(spf: Optional[dict], dmarc: Optional[dict]) -> tuple[bool, str]:
    """Returns (spoofable, reason)."""
    if not dmarc:
        if not spf:
            return True, "No SPF, no DMARC — fully open to spoofing"
        return True, "No DMARC — receiving servers ignore SPF failures, fully spoofable"

    p = (dmarc.get("policy") or "").lower()

    if p == "none":
        has_reporting = dmarc.get("rua") or dmarc.get("ruf")
        if has_reporting:
            return True, "DMARC p=none — monitoring only (has reporting), no enforcement"
        return True, "DMARC p=none — monitoring only, no reporting, fully blind"

    if p == "quarantine":
        pct = dmarc.get("pct", 100)
        if pct < 100:
            return True, f"DMARC p=quarantine pct={pct} — only {pct}% quarantined, rest delivered"
        return False, "DMARC p=quarantine (100%) — spoofed mail sent to spam"

    if p == "reject":
        pct = dmarc.get("pct", 100)
        if pct < 100:
            return True, f"DMARC p=reject pct={pct} — partial protection ({pct}%)"
        return False, "DMARC p=reject (100%) — fully protected, spoofed mail rejected"

    return True, f"Unrecognised DMARC policy: {p}"


# ─── DMARC resolver (handles hosted CNAME pattern) ───────────────────────────

def resolve_dmarc(domain: str) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (dmarc_raw, cname_via).
    Handles: direct TXT, CNAME → TXT at target.
    """
    dmarc_host = f"_dmarc.{domain}"

    # Direct TXT
    for val, _ in query_txt(dmarc_host):
        if val.startswith("v=DMARC1"):
            return val, None

    # CNAME (hosted DMARC services like mxtoolbox.dmarc-report.com)
    cname_res = _query(dmarc_host, "CNAME")
    if cname_res:
        target = cname_res[0][0].rstrip(".")
        for val, _ in query_txt(target):
            if val.startswith("v=DMARC1"):
                return val, target

    return None, None


# ─── Core recon ───────────────────────────────────────────────────────────────

def run(domain: str) -> dict:
    """
    Full DNS sweep for one domain. Returns a structured result dict.
    No SQLite writes — caller handles caching.
    """
    now = datetime.now(timezone.utc).isoformat()

    result: dict = {
        "domain":     domain,
        "queried_at": now,
        "cached":     False,
        "records": {
            "a":      [],
            "aaaa":   [],
            "ns":     [],
            "mx":     [],
            "txt":    [],
            "soa":    None,
            "caa":    [],
            "dnskey": False,
        },
        "spf":              None,
        "dmarc":            None,
        "email_spoofable":  True,
        "spoofable_reason": "",
        "axfr_success":     False,
        "subdomains":       [],
        "hosting_type":     "unknown",
        "hosting_provider": "unknown",
        "email_provider":   "Self-hosted / Unknown",
        "caa_present":      False,
        "dnssec_present":   False,
        "unique_ips":       0,
        "subdomain_count":  0,
    }

    banner = f"  DNS Recon  →  {domain}"
    print(f"\n{'=' * 65}")
    print(banner)
    print(f"{'=' * 65}")

    all_ips:   list[str] = []
    ptr_cache: dict      = {}   # ip → ptr string or None (used for hosting classification)

    def do_ptr(ip: str, label: str = "") -> Optional[str]:
        if ip in ptr_cache:
            return ptr_cache[ip]
        ptr = ptr_lookup(ip)
        hosting, provider, is_cdn, cdn_name = classify_ip(ip, ptr)
        ptr_cache[ip] = ptr
        tag = f"  [{label}]" if label else ""
        print(f"    {ip}{tag}  ->  {ptr or 'NXDOMAIN'}  [{hosting}]")
        return ptr

    # ── A ──────────────────────────────────────────────────────────────────
    print(f"\n[*] A")
    for val, ttl in _query(domain, "A"):
        result["records"]["a"].append(val)
        all_ips.append(val)
        print(f"    {val}  TTL={ttl}s")

    # ── AAAA ───────────────────────────────────────────────────────────────
    print(f"[*] AAAA")
    for val, ttl in _query(domain, "AAAA"):
        result["records"]["aaaa"].append(val)
        note = " [DNS64 -- synthesised, not real IPv6]" if is_dns64(val) else " [real IPv6]"
        print(f"    {val}{note}  TTL={ttl}s")

    # ── NS ─────────────────────────────────────────────────────────────────
    print(f"[*] NS")
    ns_names: list[str] = []
    for val, ttl in _query(domain, "NS"):
        stripped = val.rstrip(".")
        ns_names.append(stripped)
        result["records"]["ns"].append(stripped)
        print(f"    {val}  TTL={ttl}s")

    # ── SOA ────────────────────────────────────────────────────────────────
    print(f"[*] SOA")
    for val, ttl in _query(domain, "SOA"):
        result["records"]["soa"] = val
        # Decode admin email: first label before domain replaces "." with "@"
        parts = val.split()
        if len(parts) >= 2:
            admin_raw = parts[1].rstrip(".")
            dot_idx = admin_raw.find(".")
            if dot_idx > 0:
                local       = admin_raw[:dot_idx].replace(".", "@")
                domain_part = admin_raw[dot_idx + 1:]
                admin_email = f"{local}@{domain_part}"
                print(f"    {val}")
                print(f"    [admin email] {admin_email}")
            else:
                print(f"    {val}")
        else:
            print(f"    {val}")
        break   # SOA is a singleton

    # ── MX ─────────────────────────────────────────────────────────────────
    print(f"[*] MX")
    mx_names: list[str] = []
    for val, ttl in _query(domain, "MX"):
        parts = val.split(None, 1)
        if len(parts) == 2:
            mx_names.append(parts[1].rstrip("."))
        result["records"]["mx"].append(val)
        print(f"    {val}  TTL={ttl}s")

    # ── TXT / SPF ──────────────────────────────────────────────────────────
    print(f"[*] TXT")
    spf_raw: Optional[str] = None
    txt_records = query_txt(domain)
    if txt_records:
        for val, ttl in txt_records:
            if val == "NODATA":
                continue
            result["records"]["txt"].append(val)
            if val.startswith("v=spf1"):
                spf_raw = val
                print(f"    [SPF] {val}")
            else:
                print(f"    {val[:100]}{'...' if len(val) > 100 else ''}")
    else:
        print(f"    NODATA")

    # ── DMARC ──────────────────────────────────────────────────────────────
    print(f"[*] DMARC  (_dmarc.{domain})")
    dmarc_raw, dmarc_cname = resolve_dmarc(domain)
    if dmarc_raw:
        if dmarc_cname:
            print(f"    [via CNAME -> {dmarc_cname}]")
        print(f"    {dmarc_raw}")
    else:
        print(f"    NODATA -- no DMARC record found")

    # ── CAA ────────────────────────────────────────────────────────────────
    print(f"[*] CAA")
    caa_records = _query(domain, "CAA")
    caa_present = len(caa_records) > 0
    result["caa_present"] = caa_present
    if caa_records:
        for val, ttl in caa_records:
            result["records"]["caa"].append(val)
            print(f"    {val}")
    else:
        print(f"    NODATA -- any CA can issue certs for this domain")

    # ── DNSKEY ─────────────────────────────────────────────────────────────
    print(f"[*] DNSKEY  (DNSSEC check)")
    dnskey_records = _query(domain, "DNSKEY")
    dnssec_present = len(dnskey_records) > 0
    result["dnssec_present"] = dnssec_present
    result["records"]["dnskey"] = dnssec_present
    status = "DNSKEY found -- DNSSEC deployed" if dnssec_present else "NODATA -- DNSSEC not deployed"
    print(f"    {status}")

    # ── PTR for main A records ─────────────────────────────────────────────
    print(f"\n[*] PTR -- main A records")
    for ip in all_ips:
        do_ptr(ip)

    # ── AXFR ───────────────────────────────────────────────────────────────
    print(f"\n[*] AXFR attempts")
    axfr_success = False
    for ns in ns_names[:3]:
        ns_ips = resolve_ns_ips(ns)
        for ns_ip in ns_ips[:1]:
            print(f"    {ns} ({ns_ip}) ... ", end="", flush=True)
            records = axfr_attempt(domain, ns_ip)
            if records:
                axfr_success = True
                print(f"SUCCESS -- {len(records)} records")
            else:
                print("Transfer failed (blocked)")
    result["axfr_success"] = axfr_success

    # ── Subdomain enumeration ───────────────────────────────────────────────
    print(f"\n[*] Subdomain enumeration")
    wordlist = sorted(set(BRUTE_WORDLIST))
    found_subs = 0

    for label in wordlist:
        fqdn = f"{label}.{domain}"

        a_res    = _query(fqdn, "A")
        cname_res = _query(fqdn, "CNAME")

        if a_res:
            for val, ttl in a_res:
                result["subdomains"].append({
                    "fqdn":   fqdn,
                    "type":   "A",
                    "value":  val,
                    "source": "brute",
                })
                if val not in all_ips:
                    all_ips.append(val)
            ips_str = ", ".join(v for v, _ in a_res)
            print(f"    {fqdn}  ->  {ips_str}")
            found_subs += 1

        elif cname_res:
            target, ttl = cname_res[0]
            target = target.rstrip(".")
            result["subdomains"].append({
                "fqdn":   fqdn,
                "type":   "CNAME",
                "value":  target,
                "source": "brute",
            })
            print(f"    {fqdn}  ->  CNAME {target}")
            found_subs += 1

    if found_subs == 0:
        print(f"    (none resolved)")

    result["subdomain_count"] = found_subs

    # ── Email security assessment ───────────────────────────────────────────
    print(f"\n[*] Email security analysis")
    spf_parsed   = parse_spf(spf_raw)   if spf_raw   else None
    dmarc_parsed = parse_dmarc(dmarc_raw) if dmarc_raw else None
    spoofable, reason = assess_email(spf_parsed, dmarc_parsed)

    result["spf"]              = spf_parsed
    result["dmarc"]            = dmarc_parsed
    result["email_spoofable"]  = spoofable
    result["spoofable_reason"] = reason

    spf_str   = spf_parsed["all"]      if spf_parsed  else "MISSING"
    dmarc_str = dmarc_parsed["policy"] if dmarc_parsed else "MISSING"
    print(f"    SPF   : {spf_raw or 'NOT FOUND'}")
    print(f"    DMARC : {dmarc_raw or 'NOT FOUND'}")
    print(f"    -> SPF qualifier: {spf_str}   DMARC policy: {dmarc_str}")
    print(f"    -> Spoofable: {'YES' if spoofable else 'NO'}  --  {reason}")

    # ── Infrastructure classification ───────────────────────────────────────
    hosting_type = hosting_provider = "unknown"
    if all_ips:
        hosting_type, hosting_provider, _, _ = classify_ip(
            all_ips[0], ptr_cache.get(all_ips[0])
        )

    email_provider = detect_email_provider(mx_names)

    result["hosting_type"]     = hosting_type
    result["hosting_provider"] = hosting_provider
    result["email_provider"]   = email_provider
    result["unique_ips"]       = len(set(all_ips))

    # ── Console summary ─────────────────────────────────────────────────────
    print_result(result)

    return result


def print_result(result: dict) -> None:
    """Print the section summary block to stdout."""
    domain    = result.get("domain", "")
    spoofable = result.get("email_spoofable", True)
    reason    = result.get("spoofable_reason", "")
    caa_count = len(result.get("records", {}).get("caa", []))

    print(f"\n{'-' * 65}")
    print(f"  Summary  ->  {domain}")
    print(f"{'-' * 65}")
    print(f"  Hosting        : {result.get('hosting_type', 'unknown')}")
    print(f"  Email          : {result.get('email_provider', 'unknown')}")
    print(f"  Spoofable      : {'YES' if spoofable else 'NO'}  --  {reason}")
    print(f"  CAA            : {'Present -- ' + str(caa_count) + ' record(s)' if result.get('caa_present') else 'Missing -- any CA can issue certs'}")
    print(f"  DNSSEC         : {'Deployed' if result.get('dnssec_present') else 'Not deployed'}")
    print(f"  AXFR           : {'SUCCESS' if result.get('axfr_success') else 'Blocked'}")
    print(f"  Subdomains     : {result.get('subdomain_count', 0)} resolved")
    print(f"  Unique IPs     : {result.get('unique_ips', 0)}")
    if result.get("cached"):
        print(f"  [cached result — queried at {result.get('queried_at', '')}]")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description=f"dig-recon {__version__} — DNS reconnaissance with TTL cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dig-recon.py -d startbitsolutions.com
  python3 dig-recon.py -d startbitsolutions.com -o results.json
  python3 dig-recon.py -d startbitsolutions.com --no-cache
  python3 dig-recon.py -d startbitsolutions.com --ttl 6
  python3 dig-recon.py -d startbitsolutions.com --submit
  python3 dig-recon.py --reconfigure
        """,
    )

    ap.add_argument(
        "-d", "--domain", metavar="DOMAIN",
        help="Domain to recon (required unless --reconfigure or --version)",
    )
    ap.add_argument(
        "-o", "--output", metavar="FILE", default=None,
        help="Write full JSON result to this file path (optional)",
    )
    ap.add_argument(
        "--no-cache", action="store_true",
        help="Bypass cache read — always fetch fresh (result is still written to cache)",
    )
    ap.add_argument(
        "--ttl", type=int, default=24, metavar="HOURS",
        help="Cache TTL in hours (default: 24)",
    )
    ap.add_argument(
        "--submit", action="store_true",
        help="Submit result to the public community board (opt-in; requires GitHub token on first use)",
    )
    ap.add_argument(
        "--reconfigure", action="store_true",
        help="Re-run setup wizard to update stored GitHub token / display name",
    )
    ap.add_argument(
        "--version", action="store_true",
        help="Print version and exit",
    )

    args = ap.parse_args()

    # --version
    if args.version:
        print(f"dig-recon {__version__}")
        return

    # --reconfigure
    if args.reconfigure:
        setup_wizard()
        return

    # --domain is required for all other operations
    if not args.domain:
        ap.error("argument -d/--domain is required (unless --reconfigure or --version)")

    # Strip accidental protocol prefix — common mistake
    domain = args.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1].split("/")[0]
        print(f"[*] Stripped protocol prefix -> querying: {domain}")

    # Load config early if --submit, so we can run wizard before the scan
    config = None
    if args.submit:
        config = load_config()
        if config is None:
            config = setup_wizard()

    # ── Cache check ────────────────────────────────────────────────────────
    result = None
    if not args.no_cache:
        result = cache_get(domain, args.ttl)
        if result is not None:
            print(f"\n[*] Cache hit (TTL={args.ttl}h) -- using cached result for: {domain}")
            result["cached"] = True
            print_result(result)

    # ── Fresh run if no cache hit ──────────────────────────────────────────
    if result is None:
        result = run(domain)
        result["cached"] = False
        cache_put(domain, result)
        print(f"[*] Cached -> {CACHE_DB}")

    # ── Optional JSON output ───────────────────────────────────────────────
    if args.output:
        Path(args.output).write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[*] JSON written -> {args.output}")

    # ── Optional community submit ──────────────────────────────────────────
    if args.submit and result and config:
        print(f"\n  Domain     : {result.get('domain')}")
        print(f"  Hosting    : {result.get('hosting_type')}")
        print(f"  Spoofable  : {'YES' if result.get('email_spoofable') else 'NO'}")
        print(f"  Listed as  : {config.get('display_name')} -- {config.get('display_loc')}")
        print("\n  This result will be publicly listed on the community board.")
        confirm = input("  Submit? [y/N] : ").strip().lower()
        if confirm == "y":
            submit_result(result, config)
        else:
            print("[*] Submission cancelled.")


if __name__ == "__main__":
    main()
