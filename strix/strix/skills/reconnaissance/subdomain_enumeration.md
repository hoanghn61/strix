---
name: subdomain_enumeration
description: Subdomain and asset discovery - passive DNS, certificate transparency, brute force, live host probing, port scanning, attack surface mapping
---

# Subdomain Enumeration & Asset Discovery

Comprehensive subdomain enumeration reveals the true attack surface: staging environments, admin panels, legacy apps, and forgotten subdomains that skip security updates. Combine passive sources with active brute force and validate with live probing.

## Phase 1: Passive Enumeration

### Certificate Transparency (No DNS Needed)

```bash
# crt.sh — free CT log search
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
  sort -u > ct_subs.txt

# Also check wildcard certs:
curl -s "https://crt.sh/?q=target.com&output=json" | \
  python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
  grep '\*\.' | sort -u

# crtsh via direct query
python3 -c "
import requests
r = requests.get('https://crt.sh/?q=%.target.com&output=json')
subs = set()
for cert in r.json():
    for name in cert['name_value'].split('\n'):
        if 'target.com' in name:
            subs.add(name.replace('*.', '').strip())
for s in sorted(subs):
    print(s)
"
```

### Subfinder (Multi-Source Passive)

```bash
# Configure API keys in ~/.config/subfinder/provider-config.yaml first
subfinder -d target.com -o subfinder_results.txt -all
subfinder -d target.com -o subfinder_results.txt -sources shodan,virustotal,certspotter,dnsdumpster

# Multiple domains
subfinder -dL domains.txt -o all_subs.txt -t 50
```

### Amass (OSINT + Passive)

```bash
amass enum -passive -d target.com -o amass_passive.txt

# More thorough (slower)
amass enum -d target.com -o amass_active.txt -config /etc/amass/config.yaml \
  -timeout 30

# ASN-based discovery (finds all assets belonging to company)
amass intel -org "Target Corporation" -o asns.txt
amass intel -asn 12345 -o asn_hosts.txt
```

### Additional Passive Sources

```bash
# Assetfinder
assetfinder --subs-only target.com >> passive_subs.txt

# findomain
findomain -t target.com -o

# chaos API (ProjectDiscovery - requires API key)
chaos -d target.com -o chaos_subs.txt -key API_KEY

# RIDE / SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: YOUR_KEY" | python3 -m json.tool | grep '"'

# Shodan
shodan search "ssl:target.com" --fields ip_str,port,hostname | grep target.com
shodan search "hostname:target.com" --fields ip_str,port,hostname
```

## Phase 2: Active Brute Force

```bash
# DNS brute force with puredns (fast + accurate)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  target.com -r /opt/resolvers.txt -o puredns_results.txt

# dnsx for validation of found subdomains
cat all_subs.txt | dnsx -o valid_subs.txt -resp -rl 300

# dnsgen (pattern generation from known subdomains)
cat valid_subs.txt | dnsgen - | dnsx -silent >> generated_subs.txt

# Gobuster DNS mode
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r 8.8.8.8 -o gobuster_dns.txt -t 50

# Amass brute
amass enum -brute -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

## Phase 3: Live Host Probing

```bash
# Consolidate all discovered subdomains
cat ct_subs.txt subfinder_results.txt amass_passive.txt puredns_results.txt | \
  sort -u > all_subs.txt

# HTTP/HTTPS probing with httpx
httpx -l all_subs.txt -o live_hosts.txt \
  -title -status-code -content-length -tech-detect \
  -follow-redirects -timeout 10

# Filter interesting status codes
grep -v " 404 " live_hosts.txt | grep -v " 400 " > interesting_hosts.txt

# Get screenshots (aquatone)
cat live_hosts.txt | aquatone -out screenshots/ -threads 10
# Or: gowitness file -f live_hosts.txt -d screenshots/
```

## Phase 4: Port Scanning Live Hosts

```bash
# Extract IPs from live hosts
cat live_hosts.txt | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u > live_ips.txt

# Fast scan all IPs for common web ports
nmap -sS -p 80,443,8080,8443,8000,8888,3000,4000,5000,3001 \
  -iL live_ips.txt --open -T4 -oA web_ports

# Full port scan on high-value targets
nmap -sS -p- -T4 --open TARGET_IP -oA TARGET_full_ports
```

## Phase 5: Subdomain Takeover

```bash
# subjack — automated takeover check
subjack -w all_subs.txt -t 100 -timeout 30 -ssl -o takeover.txt

# subzy — takes subdomain list, checks for takeover fingerprints
subzy run --targets all_subs.txt --output takeover_results.json

# Manual signs of takeover vulnerability:
# - CNAME pointing to unclaimed cloud service
# - Response: "NoSuchBucket", "Repository not found", "404 Not Found" on GitHub Pages
# - "There's nothing here" (Tumblr), "Domain not configured" (AWS)

# Check CNAME chains
for sub in $(cat all_subs.txt); do
    cname=$(dig +short CNAME $sub 2>/dev/null)
    if [ -n "$cname" ]; then
        echo "$sub → $cname"
    fi
done
```

## Phase 6: DNS Record Harvesting

```bash
# Get all record types for each subdomain
for sub in $(cat live_subs.txt | head -50); do
    echo "=== $sub ==="
    dig $sub A AAAA MX TXT CNAME NS 2>/dev/null | grep -v "^;"
done

# Find mail servers (SPF, DMARC, DKIM misconfiguration)
for sub in $(cat live_subs.txt); do
    spf=$(dig +short TXT $sub | grep "v=spf1")
    if [ -n "$spf" ]; then
        echo "$sub: $spf"
    fi
done

# DMARC
dig +short TXT _dmarc.target.com
```

## Automation Script

```bash
#!/bin/bash
TARGET=$1
OUTDIR="recon_${TARGET}"
mkdir -p "$OUTDIR"

echo "[*] CT logs..."
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
  python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin) if isinstance(x, dict)]" 2>/dev/null | \
  sort -u > "${OUTDIR}/ct.txt"

echo "[*] Subfinder..."
subfinder -d "$TARGET" -silent -o "${OUTDIR}/subfinder.txt" 2>/dev/null

echo "[*] Consolidating..."
cat "${OUTDIR}"/*.txt | sort -u > "${OUTDIR}/all_subs.txt"
TOTAL=$(wc -l < "${OUTDIR}/all_subs.txt")
echo "[+] $TOTAL unique subdomains found"

echo "[*] Probing live hosts..."
httpx -l "${OUTDIR}/all_subs.txt" -o "${OUTDIR}/live.txt" \
  -status-code -title -silent 2>/dev/null

LIVE=$(wc -l < "${OUTDIR}/live.txt")
echo "[+] $LIVE live hosts"
cat "${OUTDIR}/live.txt"
```

## Validation Approach

1. Run passive sources first (no noise on target DNS servers)
2. Consolidate → deduplicate → probe for live hosts
3. Review httpx output for interesting titles (admin, internal, dev, staging)
4. Run takeover check on all subdomains
5. Document: total subs found → live hosts → interesting targets for further testing

## Tools

- `subfinder` — passive subdomain discovery
- `amass` — OSINT + active enumeration
- `puredns` — fast DNS brute force with accuracy
- `httpx` — HTTP probing + fingerprinting
- `dnsx` — DNS validation
- `subjack` / `subzy` — subdomain takeover detection
- `aquatone` / `gowitness` — screenshot collection
