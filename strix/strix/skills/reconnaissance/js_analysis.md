---
name: js_analysis
description: JavaScript file discovery and analysis - gather all JS files from a web page, extract API endpoints, subdomains, paths, secrets, tokens, credentials, and sensitive information from client-side code
---

# JavaScript File Analysis

JavaScript files are a gold mine for bug bounty hunters. Frontend code often exposes hidden API endpoints, internal subdomains, hardcoded secrets, authentication tokens, S3 bucket names, and developer comments revealing business logic. Always enumerate and analyze JS files before moving to active testing.

## Phase 1: Discover All JS Files

### Passive Discovery via Wayback Machine

```bash
TARGET="target.com"

# Pull all archived JS URLs
waybackurls $TARGET | grep "\.js" | grep -v ".json" | sort -u > js_wayback.txt
gau $TARGET | grep "\.js$" | sort -u >> js_wayback.txt

# Combine and deduplicate
cat js_wayback.txt | sort -u > all_js_urls.txt
echo "[*] Found $(wc -l < all_js_urls.txt) JS URLs from passive sources"
```

### Active Crawling with Katana

```bash
# Crawl and collect all JS endpoints (depth 3, headless for SPAs)
katana -u "https://$TARGET" -d 3 -jc -kf all -o katana_output.txt 2>/dev/null
grep "\.js" katana_output.txt | sort -u >> all_js_urls.txt

# Headless mode for JS-heavy SPAs (React/Vue/Angular)
katana -u "https://$TARGET" -d 3 -jc -headless -kf all 2>/dev/null | \
  grep "\.js" | sort -u >> all_js_urls.txt
```

### Crawling with Hakrawler

```bash
echo "https://$TARGET" | hakrawler -d 3 -subs | grep "\.js" | sort -u >> all_js_urls.txt
```

### Extract JS from Page Source (Python)

```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

def extract_js_from_page(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        
        js_urls = set()
        
        # <script src="..."> tags
        for tag in soup.find_all('script', src=True):
            js_url = urljoin(url, tag['src'])
            js_urls.add(js_url)
        
        # Inline scripts — extract for later analysis
        inline_scripts = [tag.string for tag in soup.find_all('script', src=False) if tag.string]
        
        return list(js_urls), inline_scripts
    except Exception as e:
        print(f"Error: {e}")
        return [], []

# Usage
js_files, inline = extract_js_from_page("https://target.com")
for f in js_files:
    print(f)
```

### LinkFinder (Comprehensive Endpoint Extraction)

```bash
# From a live URL
python3 linkfinder.py -i "https://target.com" -d -o cli | sort -u > linkfinder_results.txt

# From a local JS file
python3 linkfinder.py -i /tmp/app.js -o cli

# From a list of JS URLs
while IFS= read -r url; do
    python3 linkfinder.py -i "$url" -o cli 2>/dev/null
done < all_js_urls.txt | sort -u > all_endpoints.txt
```

### Download All Discovered JS Files

```bash
mkdir -p js_files
while IFS= read -r url; do
    filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
    curl -s -L "$url" -o "js_files/$filename" --max-time 10 2>/dev/null
    echo "$url -> js_files/$filename"
done < all_js_urls.txt
```

## Phase 2: Extract API Endpoints & Paths

### Using grep Patterns on Downloaded JS

```bash
JS_DIR="js_files"

echo "=== API Endpoints (fetch/axios/XHR) ==="
grep -rhoP '(fetch|axios\.get|axios\.post|axios\.put|axios\.delete|XMLHttpRequest)\s*\(\s*[`'"'"'"][^`'"'"'"]+[`'"'"'"]' "$JS_DIR" | \
  grep -oP '[`'"'"'"][^`'"'"'"]+[`'"'"'"]' | tr -d '"'"'"'`' | sort -u

echo ""
echo "=== URL Paths ==="
grep -rhoP '["'"'"'][/][a-zA-Z0-9_./-]{3,}["'"'"']' "$JS_DIR" | tr -d '"'"'"'' | \
  grep -v "^//" | sort -u

echo ""
echo "=== API Prefixes ==="
grep -rhoP '["'"'"']/(api|v[0-9]+|rest|graphql|internal|admin|auth|user|account|payment)[^"'"'"']*["'"'"']' "$JS_DIR" | \
  tr -d '"'"'"'' | sort -u

echo ""
echo "=== GraphQL Operations ==="
grep -rhoP '(query|mutation|subscription)\s+\w+' "$JS_DIR" | sort -u
```

### Python-Based Endpoint Extractor

```python
import re
import os
import sys

# Patterns that indicate API endpoints and paths
PATTERNS = {
    "api_endpoints": [
        r'["\'`](/api/[a-zA-Z0-9_./-]+)["\' `]',
        r'["\'`](/v[0-9]+/[a-zA-Z0-9_./-]+)["\'`]',
        r'["\'`](/rest/[a-zA-Z0-9_./-]+)["\'`]',
        r'["\'`](/graphql[a-zA-Z0-9_./-]*)["\'`]',
        r'(fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`\'"](https?://[^`\'"]+|/[^`\'"]+)[`\'"']',
        r'url\s*:\s*[`\'"](https?://[^`\'"]+|/[^`\'"]+)[`\'"]',
        r'baseURL\s*[:=]\s*[`\'"](https?://[^`\'"]+)[`\'"]',
        r'endpoint\s*[:=]\s*[`\'"](https?://[^`\'"]+|/[^`\'"]+)[`\'"]',
    ],
    "subdomains": [
        r'["\'`]https?://([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\'`]',
        r'//([a-zA-Z0-9-]+\.target\.com)',  # replace target.com
    ],
    "s3_buckets": [
        r'([a-zA-Z0-9-]+\.s3(?:[-.][\w-]+)?\.amazonaws\.com)',
        r's3://([a-zA-Z0-9-]+)',
        r'["\'`](https?://s3[^"\'`]+)["\'`]',
    ],
    "paths": [
        r'["\'`](/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+){1,})["\'`]',
        r'route\s*[:=]\s*[`\'"](/[a-zA-Z0-9_/-]+)[`\'"]',
        r'path\s*[:=]\s*[`\'"](/[a-zA-Z0-9_/-]+)[`\'"]',
    ],
}

def analyze_js_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except:
        return {}

    results = {}
    for category, patterns in PATTERNS.items():
        found = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for m in matches:
                val = m if isinstance(m, str) else m[0] if m else ''
                if val and len(val) > 2:
                    found.add(val.strip())
        if found:
            results[category] = sorted(found)
    return results

# Run on directory
js_dir = sys.argv[1] if len(sys.argv) > 1 else "js_files"
all_results = {}

for fname in os.listdir(js_dir):
    if fname.endswith('.js'):
        fpath = os.path.join(js_dir, fname)
        res = analyze_js_file(fpath)
        for cat, items in res.items():
            if cat not in all_results:
                all_results[cat] = set()
            all_results[cat].update(items)

for cat, items in all_results.items():
    print(f"\n{'='*40}")
    print(f"  {cat.upper()} ({len(items)} found)")
    print('='*40)
    for item in sorted(items):
        print(f"  {item}")
```

## Phase 3: Secret & Credential Hunting

### SecretFinder

```bash
# Run SecretFinder on all collected JS files
python3 SecretFinder.py -i "https://target.com" -e -o cli 2>/dev/null

# On a specific JS URL
python3 SecretFinder.py -i "https://target.com/static/main.js" -o cli

# On all downloaded JS files
for f in js_files/*.js; do
    echo "=== $f ==="
    python3 SecretFinder.py -i "$f" -o cli 2>/dev/null
done
```

### Hardcoded Secret Patterns with grep

```bash
JS_DIR="js_files"

echo "=== API Keys ==="
grep -rhoiP '(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*[`'"'"'"][A-Za-z0-9_\-]{16,}[`'"'"'"]' "$JS_DIR"

echo ""
echo "=== JWT / Bearer Tokens ==="
grep -rhoP 'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "$JS_DIR"
grep -rhoiP '(bearer|authorization)\s*[:=]\s*[`'"'"'"][A-Za-z0-9_. -]{20,}[`'"'"'"]' "$JS_DIR"

echo ""
echo "=== AWS Credentials ==="
grep -rhoP 'AKIA[0-9A-Z]{16}' "$JS_DIR"  # AWS Access Key ID
grep -rhoiP '(aws[_-]?secret|aws[_-]?access)\s*[:=]\s*[`'"'"'"][A-Za-z0-9/+=]{30,}[`'"'"'"]' "$JS_DIR"

echo ""
echo "=== Google / Firebase ==="
grep -rhoiP 'AIza[0-9A-Za-z_-]{35}' "$JS_DIR"  # Google API key
grep -rhoiP '"apiKey"\s*:\s*"AIza[0-9A-Za-z_-]{35}"' "$JS_DIR"
grep -rhoP '[a-zA-Z0-9-]+\.firebaseio\.com' "$JS_DIR"
grep -rhoP '[a-zA-Z0-9-]+\.firebaseapp\.com' "$JS_DIR"

echo ""
echo "=== Private Keys / Certificates ==="
grep -rhoP '-----BEGIN [A-Z ]+ KEY-----.*?-----END [A-Z ]+ KEY-----' "$JS_DIR" | head -5

echo ""
echo "=== Passwords / Credentials ==="
grep -rhoiP '(password|passwd|pwd|secret|token|credential)\s*[:=]\s*[`'"'"'"][^`'"'"'"]{6,}[`'"'"'"]' "$JS_DIR" | \
  grep -iv '(placeholder|example|test|demo|your[-_]|<|{)'

echo ""
echo "=== Database Connection Strings ==="
grep -rhoiP '(mongodb|postgresql|mysql|redis|amqp):\/\/[^\s"'"'"'`]+' "$JS_DIR"

echo ""
echo "=== Stripe / Payment Keys ==="
grep -rhoP '(sk_live|pk_live|sk_test|pk_test)_[0-9a-zA-Z]{24,}' "$JS_DIR"

echo ""
echo "=== Slack / Discord Webhooks ==="
grep -rhoP 'https://hooks\.slack\.com/services/[A-Za-z0-9/]+' "$JS_DIR"
grep -rhoP 'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+' "$JS_DIR"

echo ""
echo "=== GitHub / GitLab Tokens ==="
grep -rhoP 'ghp_[A-Za-z0-9]{36}' "$JS_DIR"  # GitHub PAT
grep -rhoP 'glpat-[A-Za-z0-9_-]{20}' "$JS_DIR"  # GitLab PAT
```

### Trufflehog on JS Directory

```bash
trufflehog filesystem ./js_files/ --json 2>/dev/null | python3 -m json.tool
```

### gitleaks on Downloaded JS

```bash
gitleaks detect --source ./js_files/ --no-git -f json -r js_secrets.json 2>/dev/null
cat js_secrets.json | python3 -m json.tool
```

## Phase 4: Subdomain Extraction from JS

```bash
TARGET="target.com"

echo "=== Subdomains Found in JS Files ==="
grep -rhoP '[a-zA-Z0-9_-]+\.'"$TARGET" js_files/ | sort -u | tee js_subdomains.txt

echo ""
echo "=== Internal/Dev Domains ==="
grep -rhoiP '[a-zA-Z0-9_-]*(dev|staging|test|internal|uat|preprod|sandbox|qa|stg|local)[a-zA-Z0-9_-]*\.[a-zA-Z]{2,}' js_files/ | \
  sort -u

echo ""
echo "=== Full URLs Discovered ==="
grep -rhoP 'https?://[a-zA-Z0-9._/-]+' js_files/ | sort -u | tee js_full_urls.txt

# Probe discovered subdomains for liveness
cat js_subdomains.txt | httpx -silent -status-code -title -o js_subdomain_live.txt
```

## Phase 5: Webpack / Bundler Analysis

### Identify Chunked Files (React, Vue, Angular)

```bash
# Webpack chunk pattern
grep -rhoP 'chunk\.[a-f0-9]{8}\.js|[a-f0-9]{20}\.chunk\.js' js_files/ | sort -u

# Source map discovery (VERY sensitive — contains original source)
curl -s "https://target.com/static/js/main.chunk.js.map" -o main.chunk.js.map
if [ -s main.chunk.js.map ]; then
    echo "[!] Source map found! Extracting original sources..."
    python3 -c "
import json, os
with open('main.chunk.js.map') as f:
    sm = json.load(f)
os.makedirs('sourcemap_sources', exist_ok=True)
for i, src in enumerate(sm.get('sources', [])):
    content = sm.get('sourcesContent', [''] * (i+1))[i] or ''
    fname = src.replace('../', '').replace('/', '_')
    with open(f'sourcemap_sources/{i}_{fname}', 'w') as out:
        out.write(content)
    print(f'Extracted: {src}')
print(f'[+] Extracted {len(sm.get(\"sources\", []))} source files')
"
fi

# Check for .map files on all discovered JS
while IFS= read -r url; do
    map_url="${url}.map"
    status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url" --max-time 5)
    if [ "$status" = "200" ]; then
        echo "[!] Source map found: $map_url"
        curl -s "$map_url" -o "$(basename $map_url)"
    fi
done < all_js_urls.txt
```

### Extract Routes from SPA (React Router / Vue Router)

```bash
echo "=== React Router Paths ==="
grep -rhoP '<Route[^>]*path\s*=\s*[{"'"'"'][^}"'"'"']+[}"'"'"']' js_files/ | \
  grep -oP '"[^"]+"|'"'"'[^'"'"']+'"'" | tr -d '"'"'"'

echo ""
echo "=== Vue Router Paths ==="
grep -rhoP 'path\s*:\s*['"'"'"`][^'"'"'"`]+['"'"'"`]' js_files/ | \
  grep -oP '['"'"'"`][^'"'"'"`]+['"'"'"`]' | tr -d '"'"'"'`' | grep "^/" | sort -u

echo ""
echo "=== Angular Routes ==="
grep -rhoP 'path\s*:\s*'"'"'[^'"'"']+'"'"'' js_files/ | sort -u
```

## Phase 6: Environment Variable Leakage

```bash
echo "=== Environment Variables in JS ==="
grep -rhoiP 'process\.env\.[A-Z_]+' js_files/ | sort -u

echo ""
echo "=== Hardcoded ENV values ==="
grep -rhoiP '(NODE_ENV|REACT_APP_|VUE_APP_|NEXT_PUBLIC_)[A-Z_]+\s*[=:]\s*['"'"'"`][^'"'"'"`]+['"'"'"`]' js_files/ | sort -u

echo ""
echo "=== Config objects ==="
grep -rhoiP '(?:config|settings|env)\s*[=:]\s*\{[^}]{20,200}\}' js_files/ | head -20
```

## Automated Full Pipeline

```bash
#!/bin/bash
# JS Analysis Automation Script
# Usage: ./js_analyze.sh target.com

TARGET="${1:?Usage: $0 <target.com>}"
OUTDIR="js_analysis_${TARGET}"
mkdir -p "$OUTDIR/js_files"

echo "[*] Phase 1: Discovering JS files for $TARGET"

# Passive URLs
echo "  → Wayback Machine..."
waybackurls "$TARGET" 2>/dev/null | grep -iP '\.js(\?|$)' | sort -u > "$OUTDIR/js_urls_wayback.txt"

# Active crawl
echo "  → Katana crawl..."
katana -u "https://$TARGET" -d 3 -jc -silent 2>/dev/null | \
  grep -iP '\.js(\?|$)' | sort -u > "$OUTDIR/js_urls_katana.txt"

# Combine
cat "$OUTDIR"/js_urls_*.txt | sort -u > "$OUTDIR/all_js_urls.txt"
TOTAL=$(wc -l < "$OUTDIR/all_js_urls.txt")
echo "[+] Found $TOTAL unique JS URLs"

# Download
echo "[*] Phase 2: Downloading JS files..."
while IFS= read -r url; do
    filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
    curl -s -L "$url" -o "$OUTDIR/js_files/$filename" --max-time 15 2>/dev/null
done < "$OUTDIR/all_js_urls.txt"
echo "[+] Downloaded to $OUTDIR/js_files/"

# LinkFinder for endpoints
echo "[*] Phase 3: Extracting endpoints with LinkFinder..."
while IFS= read -r url; do
    python3 /opt/LinkFinder/linkfinder.py -i "$url" -o cli 2>/dev/null
done < "$OUTDIR/all_js_urls.txt" | sort -u > "$OUTDIR/endpoints_linkfinder.txt"
echo "[+] $(wc -l < "$OUTDIR/endpoints_linkfinder.txt") endpoints found"

# Subdomains
echo "[*] Phase 4: Extracting subdomains from JS..."
grep -rhoP "[a-zA-Z0-9_-]+\.$TARGET" "$OUTDIR/js_files/" | sort -u > "$OUTDIR/js_subdomains.txt"
grep -rhoP 'https?://[a-zA-Z0-9._/-]+' "$OUTDIR/js_files/" | sort -u >> "$OUTDIR/js_full_urls.txt"
echo "[+] $(wc -l < "$OUTDIR/js_subdomains.txt") subdomains found"

# Secrets
echo "[*] Phase 5: Hunting secrets..."
{
    echo "=== API Keys ==="
    grep -rhoiP '(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["'"'"'`][A-Za-z0-9_\-]{16,}["'"'"'`]' "$OUTDIR/js_files/"
    echo "=== JWTs ==="
    grep -rhoP 'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "$OUTDIR/js_files/"
    echo "=== AWS Keys ==="
    grep -rhoP 'AKIA[0-9A-Z]{16}' "$OUTDIR/js_files/"
    echo "=== Google Keys ==="
    grep -rhoiP 'AIza[0-9A-Za-z_-]{35}' "$OUTDIR/js_files/"
    echo "=== Passwords ==="
    grep -rhoiP '(password|passwd|secret|token)\s*[:=]\s*["'"'"'`][^"'"'"'`]{6,}["'"'"'`]' "$OUTDIR/js_files/" | \
      grep -iv '(placeholder|example|test|your)'
} > "$OUTDIR/secrets_found.txt" 2>/dev/null

SECRETS=$(grep -c . "$OUTDIR/secrets_found.txt" 2>/dev/null || echo 0)
echo "[+] $SECRETS secret patterns found — see $OUTDIR/secrets_found.txt"

# Source maps
echo "[*] Phase 6: Checking for source maps..."
while IFS= read -r url; do
    map_url="${url}.map"
    status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url" --max-time 5)
    if [ "$status" = "200" ]; then
        echo "[!!!] SOURCE MAP EXPOSED: $map_url"
        echo "$map_url" >> "$OUTDIR/sourcemaps_exposed.txt"
    fi
done < "$OUTDIR/all_js_urls.txt"

# Final summary
echo ""
echo "=============================="
echo "  JS Analysis Complete"
echo "=============================="
echo "  JS Files       : $TOTAL"
echo "  Endpoints      : $(wc -l < "$OUTDIR/endpoints_linkfinder.txt" 2>/dev/null)"
echo "  Subdomains     : $(wc -l < "$OUTDIR/js_subdomains.txt" 2>/dev/null)"
echo "  Secret Patterns: $SECRETS"
echo "  Output         : $OUTDIR/"
```

## What to Look for in Findings

| Finding Type | Why It Matters |
|---|---|
| Internal API endpoints | May bypass WAF, expose unauthenticated routes |
| Dev/staging subdomains | Often lack security controls of production |
| Hardcoded API keys | Direct account takeover or data access |
| JWT tokens | Replay attacks, ATO |
| AWS keys (`AKIA...`) | Cloud account takeover |
| Firebase config | Misconfigured rules → data read/write |
| Source maps exposed | Full original source code recovery |
| GraphQL operations | Introspect hidden mutations/queries |
| Internal IP addresses | SSRF pivot targets, network topology |
| Version numbers | Match against known CVEs |

## Validation Approach

1. Collect JS URLs from both passive (Wayback) and active (crawl) sources
2. Download all JS files locally for offline analysis
3. Run LinkFinder AND grep patterns — they catch different things
4. For each secret found: verify it's real before reporting (test the key/token)
5. For source maps: download and extract original source, analyze recovered code
6. Probe all discovered subdomains with httpx to confirm liveness
7. Report endpoints as potential attack surface for follow-up HTTP testing

## Tools

- `katana` — fast active JS-aware crawler
- `waybackurls` / `gau` — passive historical URL discovery
- `hakrawler` — fast web crawler
- `linkfinder` — endpoint extraction from JS
- `SecretFinder` — secret/credential patterns in JS
- `trufflehog` — high-signal secret detection
- `gitleaks` — additional secret scanning
- `httpx` — probe discovered subdomains/endpoints
