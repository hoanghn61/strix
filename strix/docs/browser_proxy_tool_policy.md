# Browser-Proxy Tool Usage Policy for Strix

## Purpose

This document defines the enforced tool usage contract between `browser_action` and the proxy tools (`list_requests`, `view_request`, `send_request`, `repeat_request`). Following this policy eliminates the false-positive problem caused by the agent inferring API behavior from UI screenshots alone.

---

## The Problem This Solves

| Before This Policy | After This Policy |
|-------------------|-------------------|
| Agent clicks "Login" → reads screenshot → guesses POST /login exists | Agent clicks "Login" → reads `proxy_correlation` → knows POST `/api/v2/auth/login` exists with exact params |
| Agent reports XSS based on DOM reflection → no proxy confirmation | Agent reports XSS only after `view_request` confirms the reflected value appeared in a real response |
| Agent misses SPA background API calls | Agent captures all XHR/fetch via automatic proxy correlation |
| High false positive rate | Only proxy-evidenced findings progress to reports |

---

## Tool Usage Rules

### Rule 1: Read proxy_correlation ALWAYS

After every `browser_action` with `action` in `{goto, click, double_click, press_key, back, forward}`:

```
REQUIRED: inspect response["proxy_correlation"]["requests"]
FORBIDDEN: proceed to next browser action without reading proxy_correlation
```

### Rule 2: Never Test Endpoints Without Proxy Evidence

```
ALLOWED:   list_requests confirms endpoint exists → test it
ALLOWED:   proxy_correlation from click confirms endpoint → test it  
FORBIDDEN: HTML form action="/login" → test /login without proxy confirmation
FORBIDDEN: JS source contains "/api/users" → test it without proxy confirmation
```

### Rule 3: Validate All Findings With Proxy Request IDs

Every vulnerability report MUST include:
- `request_id` of the triggering request (from `list_requests` or `proxy_correlation`)
- `request_id` of the exploited request (from `send_request` or `repeat_request`)
- Response showing the impact (from `view_request(part="response")`)

### Rule 4: Confidence Before Action

| Confidence | Evidence Required | May Be Tested? |
|-----------|------------------|----------------|
| HIGH | In proxy_correlation during explicit action | YES — test immediately |
| MEDIUM | In list_requests sweep, path matches API pattern | YES — after one validation trigger |
| LOW | Only in JS/HTML source | ONLY after triggering in browser and seeing in proxy |
| NONE | Guessed/inferred | NEVER |

### Rule 5: Retry Before Giving Up on Proxy Data

If `proxy_correlation.captured_count == 0`:

1. `browser_action(action="wait", duration=1.5)` — allow async requests to complete
2. Check `list_requests()` — confirm proxy health
3. Inject XHR/fetch interceptors via `browser_action(action="execute_js", ...)` — capture client-side calls
4. Only conclude "no API" after all three steps yield nothing

---

## HTTPQL Reference for Common Attack Patterns

Use these filters with `list_requests(httpql_filter=...)`:

```
# Auth endpoints
'req.path.regex:"(login|signin|auth|token|session|oauth|sso|jwt|refresh|password)"'

# JSON APIs (any method)
'req.path.regex:"/api/.*"'

# POST only (form submissions, mutations)
'req.method.eq:"POST"'

# GraphQL
'req.path.regex:"(graphql|gql)"'

# File operations
'req.path.regex:"(upload|export|download|backup|import|file)"'

# Admin / privileged
'req.path.regex:"(/admin|/internal|/management|/staff|/superuser)"'

# Error responses (potential disclosure)
'resp.code.gte:400 AND resp.code.lt:600'

# Fast responses (potential cache/IDOR candidates)
'resp.roundtrip.lt:50'

# Combine filters with AND
'req.method.eq:"POST" AND req.path.regex:"/api/" AND resp.code.eq:200'
```

---

## Tool Chain Templates

### Template A: Login Form API Discovery

```
browser_action(goto, target_url)                   → read proxy_correlation
browser_action(click, username_field)
browser_action(type, "probe@test.invalid")
browser_action(click, password_field)
browser_action(type, "PROBE_PASS_123!")
browser_action(press_key, "Enter")                 → READ proxy_correlation → find POST /api/auth
view_request(id=<auth_id>, part="request")         → extract: endpoint, params, headers
view_request(id=<auth_id>, part="response")        → extract: token structure, response shape
```

### Template B: Authenticated API Sweep

```
# After login, sweep all authenticated calls
list_requests(
    httpql_filter='req.path.regex:"/api/"',
    sort_by="timestamp",
    sort_order="desc",
    page_size=50
)
# For each result:
view_request(id=<id>, part="request")   → parameter inventory
view_request(id=<id>, part="response")  → response shape + data exposure check
```

### Template C: IDOR Probe (requires Template B first)

```
# From Template B, found: GET /api/users/1234
# Extracted auth token from Template A
repeat_request(
    request_id=<original_id>,
    modifications={"path": "/api/users/1235"}
)
# View response to check if cross-account data returned
view_request(id=<repeated_id>, part="response")
```

### Template D: JS XHR Fallback (when proxy_correlation.captured_count == 0)

```javascript
// Inject into page before triggering the action
browser_action(action="execute_js", js_code="""
  window._apiCalls = [];
  const origFetch = window.fetch;
  window.fetch = function(url, opts) {
    window._apiCalls.push({
      type: 'fetch',
      url: String(url),
      method: ((opts||{}).method || 'GET').toUpperCase()
    });
    return origFetch.apply(this, arguments);
  };
  const origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    window._apiCalls.push({type: 'xhr', url: String(url), method: method.toUpperCase()});
    return origXHROpen.apply(this, arguments);
  };
  'interceptors_installed'
""")

// Trigger the action (click, submit, etc.)
browser_action(action="click", coordinate="<submit>")

// Read what was captured
browser_action(action="execute_js", js_code="({calls: window._apiCalls})")
```

---

## Validation Checklist (Pre-Report Gate)

Before calling `create_vulnerability_report`, confirm ALL of the following:

- [ ] The vulnerable endpoint appeared in `proxy_correlation` or `list_requests` — not just guessed
- [ ] You have a `request_id` for the original request
- [ ] You crafted and sent an exploit via `send_request` or `repeat_request`
- [ ] You have a `request_id` for the exploit request
- [ ] `view_request(exploit_id, part="response")` shows concrete impact
- [ ] You reproduced the finding at least twice (not a transient state)
- [ ] The finding is NOT on the always-rejected list (rate limits, self-XSS, missing headers on non-sensitive pages, etc.)

---

## Integration With Other Skills

When `api_discovery` completes, the endpoint inventory feeds directly into:

| Discovered Endpoint Type | Next Skill to Load |
|--------------------------|-------------------|
| `GET /api/resource/{id}` | `idor` |
| `POST /api/auth/login` | `authentication_jwt` |
| `POST /graphql` | Use `web_search` for GraphQL testing methodology |
| Any input parameter | `sql_injection`, `xss`, `ssrf` |
| File upload endpoint | `insecure_file_uploads` |
| Admin panel | `broken_function_level_authorization` |
| Redirect parameters | `open_redirect` |

Load the relevant skill with `load_skill` immediately after classifying the endpoint — do not guess technique syntax from memory.
