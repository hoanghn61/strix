---
name: osint
description: Open-source intelligence gathering - company/org discovery, GitHub/GitLab secret scanning, git history analysis, employee enumeration, infrastructure from code
---

# OSINT — Open Source Intelligence

OSINT for security testing focuses on discovering leaked credentials, exposed infrastructure, and attack surface data through publicly available sources — without touching the target directly. Most impactful: GitHub secret scanning and employee enumeration.

## Phase 1: Company & Infrastructure Discovery

### Organization Mapping

```bash
# Find all GitHub orgs related to a company
# Method 1: search github.com/search?q=targetcorp
# Method 2: employees' profiles → their org memberships
# Method 3: cert transparency → code repositories mentioned

# LinkedIn employee count → estimate infra size
# Google dorks:
site:github.com "targetcorp"
site:github.com "@targetcorp.com"
site:gitlab.com "targetcorp"

# Find infrastructure in job postings (reveals tech stack + cloud provider):
site:linkedin.com "targetcorp" "engineer" "AWS" OR "Azure" OR "Kubernetes"
```

### ASN & IP Range Discovery

```bash
# Find all ASN for a company (maps entire IP space)
whois -h whois.radb.net "!gAS12345"
amass intel -org "Target Corp"

# BGP.HE.NET
curl -s "https://bgp.he.net/search?search%5Bsearch%5D=Target+Corp&commit=Search"

# Shodan org search
shodan search org:"Target Corporation" --fields ip_str,port,org,hostnames

# RIPE/ARIN lookup
whois -h whois.arin.net "n Target Corp"
```

## Phase 2: GitHub Secret Scanning

### trufflehog (Most Comprehensive)

```bash
# Scan entire GitHub org
trufflehog github --org targetcorp --token GITHUB_TOKEN \
  --json --only-verified 2>/dev/null > secrets_org.json

# Scan specific repo
trufflehog github --repo https://github.com/targetcorp/backend
trufflehog git file://./local-repo

# Scan git history (includes deleted content)
trufflehog git https://github.com/targetcorp/infra \
  --since-commit HEAD~1000
```

### gitleaks

```bash
# Scan local repo
gitleaks detect --source . -r gitleaks.json --no-git

# Scan with git history
gitleaks detect --source . -r gitleaks.json

# Scan remote
gitleaks detect --source https://github.com/targetcorp/repo.git

# Config for custom patterns
cat > custom_rules.toml << 'EOF'
[[rules]]
description = "Slack Token"
regex = '''(xox[baprs]-([0-9a-zA-Z]{10,48}))'''
tags = ["slack", "token"]
EOF
gitleaks detect -c custom_rules.toml
```

### GitHub Search (Manual Dorking)

```bash
# GitHub Advanced Search (search.github.com):
org:targetcorp password
org:targetcorp secret
org:targetcorp api_key
org:targetcorp "BEGIN RSA PRIVATE KEY"
org:targetcorp "AKIA"              # AWS access key prefix
org:targetcorp ".env"
org:targetcorp "database_url"
org:targetcorp "DB_PASSWORD"

# Language-specific secret patterns:
org:targetcorp language:yaml "password:"
org:targetcorp language:json "aws_secret_access_key"
org:targetcorp "s3.amazonaws.com" filename:.env

# Via GitHub API
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=targetcorp+api_key&per_page=100"
```

### Git History Analysis

```bash
# Full history grep for secrets
git clone --depth=10000 https://github.com/target/repo
cd repo
git log --all --full-history --oneline | wc -l    # count commits to search

# grep all commits for specific patterns
git log -p --all | grep -E "(password|secret|api_key|token|credential)" | grep "^\+"

# Search all branches
for branch in $(git branch -r); do
    git diff $branch | grep -E "^\+(.*)(password|secret|api_key)" 
done

# gitjacker — automated git history OSINT
gitjacker https://target.com/.git/    # when .git is exposed via HTTP
```

## Phase 3: Employee Enumeration

### LinkedIn → Phishing Targets

```bash
# LinkedIn company employees (requires account or Hunter.io)
# hunter.io: finds email pattern + validates employee emails
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=API_KEY" | \
  python3 -m json.tool | grep email

# OSINT Industries / Clearbit / RocketReach (commercial)

# theHarvester — multi-source email/domain harvest
theHarvester -d target.com -b all -l 500 -f harvester_results
```

### Email Pattern Discovery

```bash
# Once one email format known (first.last@, flast@, f.last@):
# Validate others with SMTP VRFY or verify.email API

# Common patterns to test:
firstname.lastname@target.com
f.lastname@target.com
firstnamelastname@target.com
flastname@target.com

# Validate via Hunter.io pattern:
curl "https://api.hunter.io/v2/email-verifier?email=john.smith@target.com&api_key=KEY"
```

## Phase 4: Infrastructure From Code

### Find IPs / Domains in Source Code

```bash
# After cloning all repos:
grep -r "192\.168\.\|10\.0\.\|172\.16\.\|localhost" --include="*.yaml" --include="*.json" .
grep -r "\.internal\|\.local\|\.corp" --include="*.yaml" .
grep -r "s3\.amazonaws\.com\|\.blob\.core\.windows\.net" --include="*.py" --include="*.js" .

# Find hardcoded IPs (likely internal services)
grep -rEo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' . | grep -v "127.0\|0.0.0.0"

# CI/CD configuration leaks (secrets in pipelines)
find . -name ".travis.yml" -o -name ".circleci" -o -name "Jenkinsfile" | \
  xargs grep -l "secret\|password\|token" 2>/dev/null
```

### Docker Hub / Container Registries

```bash
# Check for public container images with embedded secrets
docker pull targetcorp/app:latest
docker history targetcorp/app:latest    # shows build layers
docker save targetcorp/app:latest | tar -xvf -
# Extract all layers and grep for secrets
find . -name "*.json" -o -name "*.env" -o -name "*.conf" | xargs grep -l "password\|key\|secret"
```

### Wayback Machine

```bash
# Historical URLs (may reveal old endpoints, leaked parameters)
waybackurls target.com | sort -u > wayback_urls.txt
gau target.com | sort -u >> wayback_urls.txt

# Filter for interesting endpoints
cat wayback_urls.txt | grep -E "\.json$|\.env$|\.bak$|backup|download|export|admin|internal|debug"

# Find parameters used historically
cat wayback_urls.txt | grep "?" | grep -oP "(?<=\?|&)[^=&]+" | sort | uniq -c | sort -rn | head -30
```

## Phase 5: Paste Site Monitoring

```bash
# Check Pastebin, PrivateBin, etc. for company data
# Use dehashed.com API or leakix.net for leaked databases:
curl -s -H "Accept: application/json" -H "X-EMAIL: you@example.com" \
  "https://leakix.net/search?scope=leak&q=email%3A%40target.com" | python3 -m json.tool

# pwndb (Tor-based leaked credential search)
# Intelligence X (intelx.io) — commercial paste/leak search
```

## GitHub Dork Reference

```
# 100+ GitHub dork patterns for secrets:
"target.com" password
"target.com" secret
"@target.com" api_key
filename:.env DB_PASSWORD
filename:id_rsa
filename:credentials aws_access_key_id
extension:pem "-----BEGIN"
extension:ppk "PuTTY-User-Key-File"
"AKIA" "SECRET"
"ghp_" github token
"xoxb-" slack bot token
"sk-" openai key
"AIza" google api key
"EAACEb" facebook token
org:targetcorp "heroku" "postgres"
org:targetcorp "mongodb://"
org:targetcorp "redis://"
org:targetcorp JWT_SECRET
```

## Validation Approach

1. Start with passive sources (crt.sh, Shodan, GitHub search) — zero noise on target
2. Run trufflehog/gitleaks on all discovered repos
3. Validate any discovered credentials before reporting (safe read-only check)
4. Document: source found → exact location (URL/file/line) → type of secret → evidence it's valid (if safely verifiable)
5. Do NOT use leaked credentials for unauthorized access — report them

## Tools

- `trufflehog` — git/GitHub secret scanning
- `gitleaks` — local repo secret detection
- `theHarvester` — email/domain enumeration
- `amass intel` — ASN/org discovery
- `shodan` — internet-wide host search
- `waybackurls` / `gau` — historical URL discovery
- `subfinder` — subdomain discovery from OSINT sources
