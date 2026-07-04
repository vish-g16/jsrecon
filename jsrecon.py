#!/usr/bin/env python3
"""
Auto JS Recon Tool
Extracts JS files from subdomains, downloads them, and scans for secrets/endpoints.
Usage:
    python jsrecon.py -d mahafood.gov.in              # auto Sublist3r + JS recon
    python jsrecon.py -l subdomains.txt               # skip Sublist3r, use file
    python jsrecon.py -d example.com --skip-sublist3r # skip Sublist3r, scan just the domain
    python jsrecon.py -d example.com -o report.txt
"""

import os, re, sys, hashlib, json, argparse, time, tempfile
import requests, concurrent.futures, subprocess
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

BANNER = """
  ╔═══╗╦═╗╦╔═╗╦═╗╦╔═╗╦╔═╗╦
  ╚═╗║╠╦╝║║╣ ╠╦╝║║╬║║║╣ ║
  ╚═╝╝╩╚═╩╚═╝╩╚═╩╚═╝╩╚═╝╩
           JS Recon Tool
"""

SECRET_PATTERNS = {
    "AWS Key": r'AKIA[0-9A-Z]{16}',
    "Google API": r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase URL": r'https?://[a-zA-Z0-9-]+\.firebaseio\.com',
    "Slack Token": r'xox[baprs]-[0-9a-zA-Z-]+',
    "JWT Token": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    "Generic API Key": r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\'][^"\']{8,}["\']',
    "Token/Secret": r'(?i)(token|secret|password|passwd|access_token|bearer|auth_token)\s*[:=]\s*["\'][^"\']{8,}["\']',
    "Private Key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "Mongo URI": r'mongodb(?:\+srv)?://[^\s"\'<>]+',
    "Postgres URI": r'postgres(?:ql)?://[^\s"\'<>]+',
    "Stripe Key": r'(?i)(sk_live|pk_live|sk_test|pk_test)_[0-9a-zA-Z]{10,}',
    "GitHub Token": r'gh[pousr]_[0-9a-zA-Z]{36}',
}

interesting_keywords = ['password', 'passwd', 'secret', 'api_key', 'apikey',
                        'token', 'access_token', 'bearer', 'jwt', 'config',
                        'base_url', 'baseurl', 'api_url', 'apiurl',
                        'endpoint', 'admin', 'dashboard', 'internal',
                        'staging', 'dev.', 'development', 'test.']


SUBLIST3R = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sublist3r.py')


def parse_args():
    p = argparse.ArgumentParser(description='Auto JS Recon Tool')
    p.add_argument('-d', '--domain', help='Target domain (auto-runs Sublist3r)')
    p.add_argument('-l', '--list', help='File with subdomains (skip Sublist3r)')
    p.add_argument('-o', '--output', help='Output report file')
    p.add_argument('--gau', action='store_true', help='Also fetch archived URLs via gau')
    p.add_argument('--threads', type=int, default=10, help='Threads for downloading (default: 10)')
    p.add_argument('--skip-sublist3r', action='store_true', help='With -d, skip Sublist3r and scan just the domain')
    return p.parse_args()


def run_sublist3r(domain):
    """Run Sublist3r and return list of discovered subdomains."""
    print(f"[*] Running Sublist3r on {domain}...")
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='sublist3r_')
    tmp.close()
    try:
        result = subprocess.run(
            [sys.executable, SUBLIST3R, '-d', domain, '-o', tmp.name],
            capture_output=True, text=True, timeout=180
        )
        # Sublist3r sometimes writes output even on non-zero exit
        if os.path.exists(tmp.name):
            with open(tmp.name) as f:
                subs = [l.strip() for l in f if l.strip()]
            if subs:
                print(f"  [+] Sublist3r found {len(subs)} subdomains")
                os.unlink(tmp.name)
                return subs
    except subprocess.TimeoutExpired:
        print("  [!] Sublist3r timed out, using partial results if available")
        if os.path.exists(tmp.name):
            with open(tmp.name) as f:
                subs = [l.strip() for l in f if l.strip()]
            if subs:
                os.unlink(tmp.name)
                return subs
    except Exception as e:
        print(f"  [!] Sublist3r error: {e}")
    os.unlink(tmp.name)
    return []


def get_subdomains(args):
    if args.list:
        with open(args.list) as f:
            subs = [l.strip() for l in f if l.strip()]
        print(f"[*] Loaded {len(subs)} subdomains from {args.list}")
        return subs

    if args.domain:
        if args.skip_sublist3r:
            return [args.domain]
        subs = run_sublist3r(args.domain)
        if subs:
            return subs
        print("  [!] Sublist3r returned nothing, falling back to domain-only")
        return [args.domain]

    return []


def fetch_js_from_live(url, timeout=10):
    """Fetch a page and extract JS file URLs."""
    js_urls = set()
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'})
        if r.status_code != 200:
            return js_urls
        for m in re.finditer(r'(["\'])([^"\']*\.js[^"\']*?)\1', r.text, re.I):
            js = m.group(2)
            if js.startswith('//'):
                js = 'https:' + js
            elif js.startswith('/'):
                js = f'https://{url.split("/")[2]}{js}'
            elif not js.startswith('http'):
                js = f'{url.rstrip("/")}/{js}'
            js_urls.add(js)
    except:
        pass
    return js_urls


def fetch_js_gau(subdomains):
    """Use gau to get archived JS URLs."""
    js_urls = set()
    for sub in subdomains:
        try:
            result = subprocess.run(
                ['gau', '--subs', sub],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                if '.js' in line and re.search(r'\.js(?:\?|#|$)', line):
                    js_urls.add(line.strip())
        except:
            pass
    return js_urls


def download_js(js_urls, threads=10):
    """Download JS files, return {hash: url} mapping and file paths."""
    outdir = 'js_files'
    os.makedirs(outdir, exist_ok=True)
    hash_map = {}
    results = {}

    def dl(url):
        try:
            r = requests.get(url, timeout=15, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0'},
                             allow_redirects=True)
            if r.status_code == 200 and r.text.strip():
                h = hashlib.md5(url.encode()).hexdigest()
                fpath = os.path.join(outdir, f'{h}.js')
                with open(fpath, 'w', errors='ignore') as f:
                    f.write(r.text)
                return (h, url, len(r.text))
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(dl, js_urls):
            if res:
                h, url, size = res
                hash_map[h] = url
                results[h] = {'url': url, 'size': size}

    with open(os.path.join(outdir, 'hash_map.txt'), 'w') as f:
        for h in sorted(hash_map):
            f.write(f"{h} {hash_map[h]}\n")

    return results, outdir


def scan_secrets(content, url):
    """Scan content for secret patterns."""
    findings = []
    for label, pat in SECRET_PATTERNS.items():
        for m in re.finditer(pat, content):
            start = max(0, m.start() - 30)
            end = min(len(content), m.end() + 30)
            ctx = content[start:end].replace('\n', ' ')
            findings.append((label, m.group(), url, ctx.strip()))
    return findings


def scan_endpoints(content, url):
    """Extract API routes, internal paths, gov domains."""
    findings = []
    tag = url.split('/')[-1].split('?')[0] if '/' in url else url

    # AJAX/fetch calls
    for m in re.finditer(r'(?:\.load|\.get|\.post|\.ajax|fetch|getJSON)\s*\(\s*["\']([^"\'()]+)["\']', content, re.I):
        ep = m.group(1).strip()
        if len(ep) > 3 and ep not in ['next', 'prev', '', '/']:
            findings.append(("AJAX/API Call", ep, tag))

    # .gov.in URLs
    for m in re.finditer(r'https?://([a-zA-Z0-9.-]*gov\.in)[^\s"\'<>]*', content):
        findings.append(("Gov Domain", m.group(), tag))

    # Internal IPs
    for m in re.finditer(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', content):
        findings.append(("Internal IP", m.group(), tag))

    # Likely endpoints/paths
    for m in re.finditer(r'["\']/([a-zA-Z0-9_?&=.%-]{4,}\.(jsp|php|asp|aspx|do|action|py|json|xml))["\']', content, re.I):
        findings.append(("Page Endpoint", f"/{m.group(1)}", tag))

    return findings


def scan_interesting_vars(content, url):
    """Find interesting variable assignments."""
    findings = []
    tag = url.split('/')[-1].split('?')[0]
    for m in re.finditer(r'(?i)(var|let|const)\s+(\w*(' + '|'.join(interesting_keywords) + r')\w*)\s*=\s*["\']([^"\']+)["\']', content):
        findings.append((m.group(2), m.group(4), tag))
    for m in re.finditer(r'(?i)(' + '|'.join(['base_url', 'baseurl', 'api_url', 'apiurl', 'rest_url', 'endpoint', 'server_url']) + r')\s*[=:]\s*["\']([^"\']+)["\']', content):
        findings.append((m.group(1), m.group(2), tag))
    return findings


def main():
    args = parse_args()
    print(BANNER)

    start_time = time.time()

    # Step 1: Get subdomains
    subs = get_subdomains(args)
    if not subs:
        print("[-] No targets. Use -d <domain> or -l <file>")
        sys.exit(1)
    print(f"[*] Target: {', '.join(subs)}")
    print(f"[*] Total: {len(subs)} subdomain(s)\n")

    # Step 2: Fetch JS from live subdomains
    all_js = set()
    print("[*] Fetching JS from live subdomains...")
    for sub in subs:
        for proto in ['https', 'http']:
            url = f'{proto}://{sub}'
            js = fetch_js_from_live(url)
            if js:
                print(f"  [+] {url} -> {len(js)} JS refs")
                all_js.update(js)
                break

    # Step 3: Fetch from archives via gau
    if args.gau:
        print("\n[*] Fetching archived JS via gau...")
        gau_js = fetch_js_gau(subs)
        if gau_js:
            print(f"  [+] gau found {len(gau_js)} JS URLs")
            all_js.update(gau_js)

    if not all_js:
        print("\n[-] No JS files found.")
        sys.exit(0)

    all_js = sorted(all_js)
    print(f"\n[*] Total unique JS URLs: {len(all_js)}")

    # Step 4: Download JS files
    print(f"[*] Downloading JS files ({args.threads} threads)...")
    results, outdir = download_js(all_js, args.threads)
    print(f"  [+] Downloaded {len(results)} files to {outdir}/")

    # Step 5: Scan for secrets and endpoints
    print("\n[*] Scanning for secrets and endpoints...")
    secrets = []
    endpoints = []
    interesting_vars = []
    drupal_modules = set()
    file_sizes = []

    for h, info in results.items():
        fpath = os.path.join(outdir, f'{h}.js')
        url = info['url']
        try:
            content = open(fpath, 'r', errors='ignore').read()
        except:
            continue
        file_sizes.append((url, info['size']))
        secrets.extend(scan_secrets(content, url))
        endpoints.extend(scan_endpoints(content, url))
        interesting_vars.extend(scan_interesting_vars(content, url))

        # Detect Drupal modules
        for m in re.finditer(r'sites/all/modules/(?:custom|contributed)s?/([a-zA-Z_]+)', url):
            drupal_modules.add(m.group(1))

    # --- REPORT ---
    report_lines = []

    def L(*args):
        line = ' '.join(str(a) for a in args)
        report_lines.append(line)
        print(line)

    elapsed = time.time() - start_time
    L(f"\n{'='*60}")
    L(f"JS RECON REPORT - {', '.join(subs)}")
    L(f"Completed in {elapsed:.1f}s")
    L(f"{'='*60}")

    L(f"\n[SUBJECT]")
    for s in subs:
        L(f"  {s}")

    L(f"\n[SUMMARY]")
    L(f"  JS URLs found: {len(all_js)}")
    L(f"  Downloaded: {len(results)}")
    L(f"  Total size: {sum(s for _,s in file_sizes) / 1024:.1f} KB")

    if secrets:
        L(f"\n[SECRETS / API KEYS]")
        for label, match, url, ctx in secrets:
            L(f"  [{label}]")
            L(f"  Match: {match}")
            L(f"  File: {url}")
            L(f"  Context: {ctx[:150]}")

    if endpoints:
        L(f"\n[ENDPOINTS & ROUTES]")
        for etype, val, tag in sorted(set(endpoints)):
            L(f"  [{etype}] {val}")
            if tag:
                L(f"     -> {tag}")

    if interesting_vars:
        L(f"\n[INTERESTING VARIABLES]")
        for var, val, tag in interesting_vars:
            L(f"  {var} = {val[:120]}")
            L(f"     -> {tag}")

    if drupal_modules:
        L(f"\n[DRUPAL MODULES DETECTED]")
        for m in sorted(drupal_modules):
            L(f"  - {m}")

    # Top 10 largest files
    L(f"\n[LARGEST JS FILES]")
    for url, size in sorted(file_sizes, key=lambda x: -x[1])[:10]:
        L(f"  {size/1024:7.1f} KB  {url}")

    L(f"\n[ALL JS FILES]")
    for url in all_js:
        L(f"  {url}")

    # Write report
    report = '\n'.join(report_lines)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n[+] Report saved to {args.output}")
    else:
        print(report)

    print("\n[DONE]")


if __name__ == '__main__':
    main()
