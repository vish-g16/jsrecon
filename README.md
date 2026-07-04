# JSRecon - Automated JavaScript Recon Tool

Automated bug bounty recon tool that discovers subdomains, extracts JavaScript files, downloads them, and scans for secrets, API keys, endpoints, and internal routes.

Built on top of [Sublist3r](https://github.com/aboul3la/Sublist3r) for subdomain enumeration with a custom JS analysis pipeline.

## Features

- **Auto subdomain discovery** via Sublist3r (or use your own list)
- **JS extraction** from live subdomains (parses HTML for `<script src>` references)
- **Optional archived JS** via `gau` (Wayback Machine, CommonCrawl, URLScan)
- **Multithreaded download** with MD5-hashed filenames + URL mapping
- **Secrets scanning** for 14+ patterns:
  - AWS keys, Google API keys, Firebase URLs
  - JWTs, Slack tokens, Stripe keys, GitHub tokens
  - Hardcoded passwords, tokens, private keys
  - MongoDB, PostgreSQL, Redis connection strings
- **Endpoint extraction**:
  - AJAX/fetch/GET/POST calls
  - Internal `.jsp`, `.php`, `.asp`, `.json` endpoints
  - domains
  - Internal IPs (RFC 1918)
- **Tech stack detection** (Drupal modules, frameworks)
- **Comprehensive report** with file sizes, all findings, and full JS URL list

## Installation

```bash
git clone https://github.com/yourusername/jsrecon.git
cd jsrecon
pip install requests

# Optional - for archived JS fetching:
# Install gau: https://github.com/lc/gau
```

The tool includes Sublist3r in the same directory (ships with the repo).

## Usage

```bash
# Full pipeline: Sublist3r → JS recon → report
python jsrecon.py -d example.com

# Save report to file
python jsrecon.py -d example.com -o report.txt

# Use existing subdomain list (skip Sublist3r)
python jsrecon.py -l subdomains.txt

# Skip Sublist3r, scan just the input domain
python jsrecon.py -d example.com --skip-sublist3r

# Include archived JS via gau
python jsrecon.py -d example.com --gau -o report.txt
```

## Arguments

| Argument | Description |
|----------|-------------|
| `-d` | Target domain (auto-runs Sublist3r) |
| `-l` | File with subdomains (one per line, skips Sublist3r) |
| `-o` | Save report to file |
| `--gau` | Also fetch archived JS URLs via `gau` |
| `--threads` | Download threads (default: 10) |
| `--skip-sublist3r` | With `-d`, skip Sublist3r and scan just the domain |

## Output

```
js_files/               # Downloaded JS files (MD5-hashed filenames)
js_files/hash_map.txt   # Hash → original URL mapping
report.txt              # (if -o specified) Full analysis report
```

## Example Report Sections

- **Secrets / API Keys** — Matches for AWS keys, Google APIs, tokens, passwords, etc.
- **Endpoints & Routes** — AJAX calls, API routes, JSP/PHP pages, internal domains
- **Interesting Variables** — `base_url`, `api_url`, `token` assignments
- **Drupal Modules Detected** — Custom and contributed modules
- **Largest JS Files** — Top 10 by size
- **All JS Files** — Complete deduplicated URL list

## Example Run

```
python jsrecon.py -d example.com -o report.txt

[*] Running Sublist3r on example.com...
  [+] Sublist3r found 12 subdomains
[*] Target: sub1.example.com, sub2.example.com, ...

[*] Fetching JS from live subdomains...
  [+] https://sub1.example.com -> 34 JS refs
  [+] https://sub2.example.com -> 18 JS refs

[*] Total unique JS URLs: 52
[*] Downloading JS files (10 threads)...
  [+] Downloaded 40 files to js_files/
...
```

## Requirements

- Python 3.6+
- `requests`
- Sublist3r (bundled)
- `gau` (optional, for archived JS)

## License

MIT
