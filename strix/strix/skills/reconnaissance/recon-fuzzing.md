---
name: recon-fuzzing
description: Deep reconnaissance and fuzzing pipeline for bug bounty and pentesting. 12-phase systematic workflow covering subdomain discovery, alive-host dedup with CDN filtering, port scanning, service fingerprinting, nuclei vuln scan, content discovery, JS analysis, parameter discovery, header fuzzing, URL crawling, custom wordlist building, and 403 bypass.
---

# DEEP RECON & FUZZING PIPELINE

Systematic 12-phase pipeline: single domain → fully mapped, prioritised attack surface.
Sources: YesWeHack Recon Series #1 · InfoSec Write-ups practical fuzzing workflow.

## SETUP

```bash
export T="target.com"
export RECON="$HOME/recon/$T"
mkdir -p $RECON/{subs,ports,js,params,fuzz,nuclei,nmap}
```

---

## PHASE 1 — SUBDOMAIN DISCOVERY

```bash
# crt.sh — CT logs, no API key
curl -s "https://crt.sh/?q=%.${T}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $RECON/subs/crt.txt

# Chaos + Subfinder + Assetfinder
chaos -d $T -o $RECON/subs/chaos.txt -key $CHAOS_API_KEY 2>/dev/null
subfinder -d $T -silent -o $RECON/subs/subfinder.txt
assetfinder --subs-only $T > $RECON/subs/assetfinder.txt

# Merge
cat $RECON/subs/*.txt | sort -u > $RECON/subs/all.txt
echo "[TOTAL] $(wc -l < $RECON/subs/all.txt) unique subdomains"
```

---

## PHASE 2 — ALIVE HOSTS & IP DEDUPLICATION

```bash
# DNS resolution
cat $RECON/subs/all.txt | dnsx -silent -o $RECON/subs/resolved.txt

# HTTP probe
httpx -l $RECON/subs/resolved.txt \
  -status-code -title -tech-detect -ip -follow-redirects -silent \
  -o $RECON/subs/live.txt

# Extract IPs + CDN filter (CRITICAL — never scan Cloudflare/Akamai edge IPs)
cat $RECON/subs/live.txt \
  | grep -oE '\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]' \
  | tr -d '[]' | sort -u > $RECON/ports/unique-ips.txt

httpx -l $RECON/ports/unique-ips.txt -title -silent \
  | grep -viE "cloudflare|akamai|fastly|incapsula|sucuri" \
  > $RECON/ports/origin-ips.txt

cat $RECON/subs/live.txt | awk '{print $1}' > $RECON/subs/live-urls.txt
```

> CDN filter is mandatory. Scanning Cloudflare IPs = banned + zero useful findings.

---

## PHASE 3 — PORT SCANNING

```bash
# Top-100 ports via naabu
naabu -l $RECON/ports/origin-ips.txt \
  -top-ports 100 -rate 1500 -verify -silent \
  -o $RECON/ports/naabu.txt

# Non-standard high-value ports
naabu -l $RECON/ports/origin-ips.txt \
  -p 8080,8443,8000,8888,3000,9200,9300,6379,27017,5432,3306,5601,4848,2181 \
  -verify -silent | anew $RECON/ports/naabu.txt
```

High-value non-standard: `:8080/actuator`, `:9200` ES, `:6379` Redis, `:27017` Mongo, `:5601` Kibana.

---

## PHASE 4 — SERVICE FINGERPRINTING

```bash
awk -F: '{print $1}' $RECON/ports/naabu.txt | sort -u > /tmp/scan-ips.txt
nmap -iL /tmp/scan-ips.txt \
  -sV -sC --script=http-title,http-headers,http-methods,http-auth \
  -oX $RECON/nmap/scan.xml -oN $RECON/nmap/scan.txt \
  -T4 --open
```

In output prioritise: version + `searchsploit`, VULNERABLE in NSE output, HTTP OPTIONS with PUT/DELETE, default credentials in banner.

---

## PHASE 5 — NUCLEI AUTOMATED VULN SCAN

```bash
# Web hosts
nuclei -l $RECON/subs/live-urls.txt \
  -tags cve,misconfig,default-login,exposure \
  -severity critical,high,medium -bs 200 \
  -o $RECON/nuclei/web.txt

# ALL ports — catches non-web services (Spring Actuator, ES, Redis, etc.)
cat $RECON/ports/naabu.txt | nuclei -tags cve -bs 200 \
  -o $RECON/nuclei/ports.txt
```

CRITICAL/HIGH finding → stop and validate NOW before continuing.

---

## PHASE 6 — CONTENT DISCOVERY & FUZZING

```bash
# Baseline error size
ERROR_SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://$T/doesnotexist12345")

# Standard directory fuzz
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://$T/FUZZ -mc 200,301,302,403 -fs $ERROR_SIZE \
  -t 40 -rate 50 -c -o $RECON/fuzz/dirs.json -of json

# Deep pass
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -u https://$T/FUZZ -mc 200,301,302,403 -fs $ERROR_SIZE -t 40 -rate 50 -c

# Quick probe of high-value paths
for path in /admin /api /actuator /actuator/env /actuator/beans /swagger-ui.html \
            /v2/api-docs /openapi.json /debug /.env /.git /phpinfo.php /server-status; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$T$path")
  [[ "$code" != "404" ]] && echo "[$code] https://$T$path"
done

# Collect 403s for Phase 12
cat $RECON/fuzz/dirs.json | jq -r '.results[]|select(.status==403)|.url' \
  > $RECON/fuzz/403s.txt
```

Rule: **403 = always run Phase 12 bypass**. Use `-fs $ERROR_SIZE` not status codes alone.

---

## PHASE 7 — JAVASCRIPT ANALYSIS

```bash
# Collect JS URLs
katana -u https://$T -d 5 -jc -kf all -silent | grep "\.js$" | sort -u > $RECON/js/js-urls.txt
waybackurls $T | grep "\.js$" | anew $RECON/js/js-urls.txt
gau $T | grep "\.js$" | anew $RECON/js/js-urls.txt

# LinkFinder — extract hidden API endpoints from JS
while read url; do
  python3 ~/tools/LinkFinder/linkfinder.py -i "$url" -o cli 2>/dev/null
done < $RECON/js/js-urls.txt | sort -u > $RECON/js/endpoints-from-js.txt
cat $RECON/js/endpoints-from-js.txt | anew $RECON/fuzz/custom-wordlist.txt

# SecretFinder — extract keys/tokens
while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done < $RECON/js/js-urls.txt | tee $RECON/js/secrets-found.txt

# Manual grep (downloaded JS)
grep -rn "api_key\|apiKey\|client_secret\|access_token\|AWS_SECRET\|AKIA\|Bearer " \
  $RECON/js/files/ 2>/dev/null | tee $RECON/js/hardcoded.txt
```

JS is the #1 source of hidden endpoints, feature flags, undocumented params, and leaked keys.

---

## PHASE 8 — PARAMETER DISCOVERY

```bash
arjun -u https://$T/api/v1/endpoint -m GET -o $RECON/params/arjun-get.json
arjun -u https://$T/api/v1/endpoint -m POST -o $RECON/params/arjun-post.json

ERROR_SIZE=$(curl -sk -o /dev/null -w "%{size_download}" "https://$T/endpoint?404param=1")
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://$T/api/endpoint?FUZZ=test" -mc 200 -fs $ERROR_SIZE -t 40

# Custom param wordlist from collected URLs
cat $RECON/fuzz/all-urls.txt \
  | grep -oP '(?<=[?&])[^=&]+(?==)' | sort -u \
  > $RECON/params/custom-params.txt
arjun -u https://$T/target-endpoint -w $RECON/params/custom-params.txt
```

---

## PHASE 9 — HEADER FUZZING

```bash
# Methods
curl -sk -X OPTIONS https://$T/ -v 2>&1 | grep -i "allow:"

# IP/Origin spoof (access control bypass)
curl -sk -H "X-Forwarded-For: 127.0.0.1" https://$T/admin/
curl -sk -H "X-Original-URL: /admin" https://$T/
curl -sk -H "X-Rewrite-URL: /admin" https://$T/

# Version / debug leaks
curl -sk -I https://$T/ | grep -iE "server:|x-powered-by:|via:|x-aspnet-version:|x-runtime:"
```

High-value: `X-Forwarded-For`, `X-Original-URL`, `X-HTTP-Method-Override`, `Accept-Version: *`, `Content-Type: text/xml` (→ XXE).

---

## PHASE 10 — URL CRAWL & HISTORICAL HARVEST

```bash
katana -u https://$T -d 5 -jc -kf all -silent -o $RECON/fuzz/katana-urls.txt
waybackurls $T | anew $RECON/fuzz/all-urls.txt
gau $T --subs | anew $RECON/fuzz/all-urls.txt
cat $RECON/fuzz/katana-urls.txt | anew $RECON/fuzz/all-urls.txt

# gf patterns — filter by vuln class
cat $RECON/fuzz/all-urls.txt | gf sqli    > $RECON/fuzz/sqli-candidates.txt
cat $RECON/fuzz/all-urls.txt | gf xss     > $RECON/fuzz/xss-candidates.txt
cat $RECON/fuzz/all-urls.txt | gf ssrf    > $RECON/fuzz/ssrf-candidates.txt
cat $RECON/fuzz/all-urls.txt | gf redirect> $RECON/fuzz/redirect-candidates.txt
cat $RECON/fuzz/all-urls.txt | gf lfi     > $RECON/fuzz/lfi-candidates.txt
cat $RECON/fuzz/all-urls.txt | gf idor    > $RECON/fuzz/idor-candidates.txt

# High-signal params
cat $RECON/fuzz/all-urls.txt \
  | grep -E "[?&](id|user|uid|file|path|url|redirect|next|src|token|key|api_key|secret|admin|debug|cmd|exec|query|sql)=" \
  > $RECON/fuzz/interesting-params.txt
```

---

## PHASE 11 — CUSTOM WORDLIST BUILDING

```bash
cewl -d 3 -m 4 -w $RECON/fuzz/cewl-wordlist.txt https://$T
cat $RECON/fuzz/all-urls.txt | sed 's|https\?://[^/]*/||' \
  | tr '/?&=_-' '\n' | sort -u | grep -E '^[a-zA-Z]{3,}$' >> $RECON/fuzz/cewl-wordlist.txt
cat $RECON/js/endpoints-from-js.txt | sed 's|/||g' | tr '-_' '\n' | sort -u \
  | anew $RECON/fuzz/custom-wordlist.txt
cat $RECON/fuzz/custom-wordlist.txt \
  $RECON/fuzz/cewl-wordlist.txt \
  /usr/share/seclists/Discovery/Web-Content/common.txt \
  /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  | sort -u > $RECON/fuzz/final-wordlist.txt

ffuf -w $RECON/fuzz/final-wordlist.txt \
  -u https://$T/FUZZ -mc 200,301,302,403 -fs $ERROR_SIZE \
  -t 40 -rate 50 -c -o $RECON/fuzz/final-fuzz.json -of json
```

**Iteration rule:** every new endpoint/dir/param found → add to wordlist → re-run ffuf on that path.

---

## PHASE 12 — 403 BYPASS

```bash
TARGET_403="https://$T/admin"

for bypass in "/" "/." "//" "%2f" "%2F" "..;/" "?anything" "#bypass"; do
  code=$(curl -sk "${TARGET_403}${bypass}" -o /dev/null -w "%{http_code}")
  echo "[$code] ${TARGET_403}${bypass}"
done

curl -sk "$TARGET_403" -H "X-Original-URL: /admin" -o /dev/null -w "%{http_code}\n"
curl -sk "$TARGET_403" -H "X-Forwarded-For: 127.0.0.1" -o /dev/null -w "%{http_code}\n"
curl -sk "https://$T/" -H "X-Original-URL: /admin" -o /dev/null -w "%{http_code}\n"
curl -sk "$TARGET_403" -X TRACE -o /dev/null -w "%{http_code}\n"
```

---

## DECISION FLOW

```
New target
├─ Full program scope (multiple domains)?
│   YES → start Phase 1 full subdomain enum
│   NO  → start at Phase 3 with known IP/domain
├─ After Phase 2: count of live hosts < 10?
│   YES → deep manual per host; skip port automation
├─ After Phase 4: versions disclosed?
│   YES → searchsploit immediately before continuing
├─ After Phase 5: CRITICAL/HIGH nuclei findings?
│   YES → validate manually NOW; stop
├─ Phase 6: any 403s found?
│   YES → run Phase 12 on ALL 403 paths
└─ Iteration rule: new endpoint → add to wordlist → re-run ffuf → re-run arjun
```

## KILL SIGNALS

```
✗ All subdomains = parked / NXDOMAIN
✗ httpx = 0-5 live hosts, no auth, no forms
✗ Every URL = identical response size (static CDN)
✗ nuclei 0 findings + nmap shows only 80/443
✗ JS files are all vendor bundles with no internal routes
```
