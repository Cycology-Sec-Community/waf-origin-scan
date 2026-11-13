# waf-origin-scan

Passive + active WAF/CDN origin-exposure detection. Python 3 stdlib only.

## Why
State of WAF Report 2026 (ionix.io): 29% of WAF-protected apps answer direct
origin requests; 81% of WAF bypasses need only the correct Host header (the
remaining 19% need a spoofed client-IP header). This tool surfaces those
exposures automatically, before someone else does.

## Features
- Passive subdomain enumeration via crt.sh Certificate Transparency logs
- DNS A-record resolution per subdomain
- IP classification (private / CDN / unknown; IPinfo token hook included)
- Optional active test: Host-header spoofing to detect origin serving (WAF bypass indicator)
- JSON or table report

## Usage
```
python3 waf_origin_scan.py example.com --output results.json
python3 waf_origin_scan.py example.com --active   # active tests, may trigger alerts
```

## Output
- `subdomains`: unique names from CT logs
- `ip_map`: subdomain -> resolved IPv4
- `cdn_classification`: per-IP family guess
- `origin_suspected`: list of `{target, flag, severity, detail}` for active tests
  - `STATUS_MISMATCH` (HIGH): spoofed Host returned different HTTP status than real Host
  - `CONTENT_LENGTH_DIFFERENT` (MEDIUM): body length differs >100 bytes

## Limitations
- CDN classification is a stub by default; set `APIINFO_TOKEN` and extend `classify_cdn()` with IPinfo
- crt.sh has transient 502s; built-in retry included
- Active tests rate-limited (0.2s sleep)
- No IPv6/AAAA, no wildcard expansion yet

## License
MIT
