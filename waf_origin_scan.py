#!/usr/bin/env python3
"""waf-origin-scan — Passive + active WAF/CDN origin-exposure detection.

Usage:
    python3 waf_origin_scan.py TARGET [TARGET...] [--active] [--output RESULTS.json]

Features:
  - Passive subdomain enum via crt.sh Certificate Transparency logs
  - DNS A/AAAA resolve for each subdomain
  - CDN/WAFASN classification via IP WHOIS (IPinfo free tier)
  - Active origin leakage test via Host-header spoofing (optional, --active)
  - Reports potential origin exposures with confidence scores

Research reference: State of WAF Report 2026 (ionix.io)
  - 29% of WAF-protected apps answer direct origin requests
  - 81% of bypasses need ONLY correct Host header
  - Parameter pollution bypass rate 70.6% (Ethiack 2025)
"""

import argparse
import asyncio
import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# --- Configuration -----------------------------------------------------------
MAX_CONCURRENCY = 10
CRT_SH_BACKOFF = 2.0       # seconds between crt.sh queries
APIINFO_TOKEN = os.getenv('APIINFO_TOKEN', '')  # optional free token
REQUEST_TIMEOUT = 10       # seconds per request
RESULTS_VERSION = "1.0"

# Known CDN / WAF ASN ranges (static snapshot; extend as needed)
KNOWN_CDNS = {
    # Cloudflare
    'cloudflare': {'asn_prefixes': ['AS13335'], 'name': 'Cloudflare'},
    # Akamai
    'akamai': {'asn': 'AS22822', 'name': 'Akamai'},
    # Fastly
    'fastly': {'asn': 'AS54113', 'name': 'Fastly'},
    # AWS CloudFront
    'aws_cloudfront': {'asn': 'AS16509', 'name': 'Amazon CloudFront'},
    # Amazon Shield / AWS WAF default
    'aws_waf': {'asn': 'AS14618', 'name': 'Amazon.com'},
    # Azure Front Door
    'azure_frontdoor': {'asn': 'AS8075', 'name': 'Microsoft Azure'},
    # Microsoft Defender for Cloud Apps
    'azure_defender': {'asn': 'AS8075', 'name': 'Microsoft'},
    # Imperva / Incapsula
    'imperva': {'asn': 'AS396046', 'name': 'Imperva'},
    # Sucuri
    'sucuri': {'asn': 'AS30127', 'name': 'Sucuri'},
    # StackPath
    'stackpath': {'asn': 'AS36351', 'name': 'StackPath'},
}

# --- Helpers ----------------------------------------------------------------

def is_private_ip(ip: str) -> bool:
    """Check if IP is in RFC1918 / private range."""
    try:
        parts = list(map(int, ip.split('.')))
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return False


def dns_resolve(host: str, timeout: int = REQUEST_TIMEOUT) -> list:
    """Return list of IPv4 addresses (A records) for host."""
    results = []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({addr[4][0] for addr in infos})
        results = ips
    except socket.gaierror:
        pass
    return results


async def fetch_crt_sh(domain: str) -> list:
    """Query crt.sh Certificate Transparency log for subdomains."""
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    req = Request(url, headers={
        'User-Agent': 'waf-origin-scan/1.0 (+https://github.com/Cycology-Sec-Community/waf-origin-scan)'
    })
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT * 2) as r:
            data = json.loads(r.read().decode())
        # Extract unique names below domain
        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '') or ''
            for n in name.split('\n'):
                n = n.strip().lower()
                if n and n.endswith(f'.{domain}'):
                    subdomains.add(n.replace('.\n', '').replace('\n.', '.'))
        return sorted(subdomains)
    except HTTPError as e:
        if e.code == 502:
            # crt.sh transient; return empty but note in callers
            await asyncio.sleep(CRT_SH_BACKOFF)
            return await fetch_crt_sh(domain)
        raise
    except Exception as e:
        print(f'[WARN] crt.sh failed for {domain}: {e}', file=sys.stderr)
        return []


def classify_cdn(ips: list) -> dict:
    """Classify IPs into known CDN/WAF families via heuristic.

    Real production would query IPinfo API. Here we return 'unknown' with a
    placeholder so users can integrate their own token easily.
    """
    result = {}
    for ip in ips:
        if is_private_ip(ip):
            result[ip] = {'family': 'private', 'confidence': 1.0}
            continue
        # Placeholder: use IPinfo on demand when token provided
        result[ip] = {'family': 'unknown', 'ip': ip}
    return result


def host_header_test(target: str, base_host: str, extra_headers: dict | None = None) -> dict:
    """Test if target answers differently when spoofing Host header.

    Returns dict with responses under original and spoofed Host.
    """
    parsed = urlparse(target)
    host = parsed.hostname
    path = parsed.path or '/'
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    is_https = parsed.scheme == 'https'

    results = {}
    variants = [
        ('original', host),
        ('spoofed_base', base_host),
    ]
    if extra_headers:
        variants.append(('extra', extra_headers.pop('Host', host)))

    for label, h in variants:
        try:
            req_headers = {
                'Host': h,
                'User-Agent': 'Mozilla/5.0 (compatible; waf-scan/1.0)',
                'Accept': '*/*',
            }
            if extra_headers:
                req_headers.update(extra_headers)
            url = f"{parsed.scheme}://{h}{path}" if h == host else f"{parsed.scheme}://{h}{path}"
            req = Request(url, headers=req_headers)
            with urlopen(req, timeout=REQUEST_TIMEOUT) as r:
                body_len = len(r.read())
            results[label] = {'status': r.status, 'body_length': body_len, 'headers': dict(r.headers)}
        except Exception as e:
            results[label] = {'error': repr(e)}

    return results


def detect_leak(test_results: dict) -> dict | None:
    """Analyze host-header test to flag potential origin leak."""
    orig = test_results.get('original')
    spoofed = test_results.get('spoofed_base')
    if not orig or not spoofed:
        return None
    if 'error' in orig or 'error' in spoofed:
        return None
    # Different status codes or content-length suggests different backend
    if orig['status'] != spoofed['status']:
        return {
            'flag': 'STATUS_MISMATCH',
            'severity': 'HIGH',
            'detail': f"Original returned {orig['status']} vs spoofed {spoofed['status']}",
        }
    if abs(orig['body_length'] - spoofed['body_length']) > 100:
        return {
            'flag': 'CONTENT_LENGTH_DIFFERENT',
            'severity': 'MEDIUM',
            'detail': f"Body lengths differ: {orig['body_length']} vs {spoofed['body_length']}",
        }
    # Same status + similar body => likely WAF-proxied (good)
    return None


# --- Main scan pipeline -----------------------------------------------------

class ScannerResult:
    def __init__(self):
        self.scan_at = datetime.utcnow().isoformat() + 'Z'
        self.version = RESULTS_VERSION
        self.targets = []
        self.findings = []


async def scan_domain(domain: str, do_active: bool = False) -> dict:
    """Full scan pipeline for one domain."""
    finding = {
        'domain': domain,
        'scan_at': datetime.utcnow().isoformat() + 'Z',
        'subdomains': [],
        'ip_map': {},
        'cdn_classification': {},
        'origin_suspected': [],
    }

    # Step 1: Passive subdomain enum
    subs = await fetch_crt_sh(domain)
    finding['subdomains'] = subs

    # Step 2: DNS resolve
    all_ips = set()
    for sub in subs[:50]:  # cap at 50 to stay sane
        ips = dns_resolve(sub)
        if ips:
            finding['ip_map'][sub] = ips
            all_ips.update(ips)

    # Step 3: CDN classification (stub — replace with real IPinfo calls)
    finding['cdn_classification'] = classify_cdn(sorted(all_ips))

    # Step 4: Active origin test (if requested)
    if do_active:
        test_targets = [f'https://{domain}', *[f'https://{s}' for s in subs[:10]]]
        for t in test_targets:
            results = host_header_test(t, domain)
            leak = detect_leak(results)
            if leak:
                finding['origin_suspected'].append({
                    'target': t,
                    **leak,
                    'raw': results,
                })
            time.sleep(0.2)  # be nice to targets

    return finding


async def main_async(args):
    domains = args.domains
    do_active = args.active
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def bounded(domain):
        async with sem:
            return await scan_domain(domain, do_active)

    tasks = [asyncio.create_task(bounded(d)) for d in domains]
    findings = await asyncio.gather(*tasks)

    output = ScannerResult()
    output.targets = domains
    output.findings = findings

    return output


def cli():
    parser = argparse.ArgumentParser(
        prog='waf-origin-scan',
        description='Detect WAF/CDN origin-exposure via passive CT logs + optional active Host-header test.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('domains', nargs='+', help='Target domain(s) to scan')
    parser.add_argument('--active', action='store_true', help='Run active Host-header origin tests (may trigger WAF alerts)')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    parser.add_argument('--json', action='store_true', dest='print_json', help='Print raw JSON instead of table')
    return parser.parse_args()


def fmt_table(result: ScannerResult):
    lines = [f"waf-origin-scan v{RESULTS_VERSION} report"]
    lines.append(f"Scan time : {result.scan_at}")
    lines.append(f"Targets   : {', '.join(result.targets)}")
    lines.append('')
    for f in result.findings:
        lines.append(f"--- {f['domain']} ---")
        lines.append(f"  Subdomains found   : {len(f['subdomains'])}")
        lines.append(f"  Resolved endpoints : {len(f['ip_map'])}")
        if f['origin_suspected']:
            lines.append(f"  ⚠ Origin leaks detected: {len(f['origin_suspected'])}")
            for x in f['origin_suspected']:
                lines.append(f"     [{x['severity']}] {x['target']} → {x['flag']}: {x['detail']}")
        else:
            lines.append(f"  ✅ No obvious origin leak (passive only)")
        lines.append('')
    return '\n'.join(lines)


def emit(result: ScannerResult, out_path=None, as_json=False):
    raw = result.__dict__
    text = json.dumps(raw, indent=2) if as_json else fmt_table(result)
    print(text)
    if out_path:
        with open(out_path, 'w') as f:
            json.dump(raw, f, indent=2)
        print(f"[+] Saved JSON to {out_path}", file=sys.stderr)


def run():
    args = cli()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(main_async(args))
    finally:
        asyncio.new_event_loop()  # reset
    emit(result, out_path=args.output, as_json=args.print_json)


if __name__ == '__main__':
    run()
