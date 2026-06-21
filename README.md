# dig-recon

Full DNS sweep — A/AAAA/NS/MX/TXT/SOA/CAA/DNSKEY + SPF/DMARC email security + AXFR + subdomain brute + hosting fingerprint.

**[→ DNS Board](https://fmfalgun.github.io/dig-recon/dns-board.html)** — community DNS sweeps, browsable without the tool.

## Requirements

- Python 3.8+
- `pip install dnspython`

## Usage

```bash
# full DNS sweep
python3 dig-recon.py -d nmap.org

# save structured JSON
python3 dig-recon.py -d nmap.org -o results.json

# bypass 24h cache
python3 dig-recon.py -d nmap.org --no-cache

# submit to DNS Board
python3 dig-recon.py -d nmap.org --submit
```

## Output schema

```json
{
  "domain": "nmap.org",
  "records": {
    "a": ["45.33.32.156"],
    "ns": ["ns1.linode.com", "..."],
    "mx": ["10 li463-156.members.linode.com"],
    "txt": ["v=spf1 mx -all", "..."],
    "dnskey": false
  },
  "spf":   { "raw": "v=spf1 mx -all", "all": "-all", "includes": [] },
  "dmarc": { "raw": "v=DMARC1; p=reject; ...", "policy": "reject", "pct": 100 },
  "email_spoofable":  false,
  "spoofable_reason": "DMARC p=reject (100%) — fully protected",
  "axfr_success":     false,
  "subdomains":       [{"fqdn": "scanme.nmap.org", "type": "A", "value": "45.33.32.156"}],
  "hosting_type":     "Linode/Akamai VPS",
  "caa_present":      false,
  "dnssec_present":   false
}
```

## Flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Domain to query |
| `-o`, `--output` | Write JSON to file |
| `--no-cache` | Bypass 24h SQLite cache |
| `--ttl` | Cache TTL hours (default: 24) |
| `--submit` | Submit result to DNS Board |
| `--reconfigure` | Update stored credentials |

## Pairs with

- [whois-extracter](https://github.com/fmfalgun/whois-extracter) — registry WHOIS + risk scoring
- [whois-deep](https://github.com/fmfalgun/whois-deep) — registrar WHOIS + IP WHOIS via RIR
- [subfinder-recon](https://github.com/fmfalgun/subfinder-recon) — passive subdomain enumeration

---

MIT License · Built by [Falgun Marothia](https://fmfalgun.github.io)
