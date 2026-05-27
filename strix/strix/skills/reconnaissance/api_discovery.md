---
name: api_discovery
description: Browser-driven API endpoint discovery using browser_action + proxy_correlation feedback loop. Maps real attack surface from live HTTP traffic before any vulnerability testing begins.
---

# API Discovery via Browser-Proxy Correlation

> Core principle: **Browser is the surface. Proxy is ground truth.**
> Every browser interaction triggers real HTTP traffic. That traffic is your actual attack surface.
> Screenshots tell you the UI exists. `proxy_correlation` tells you what the app *actually does*.

---

## Phase 0 — Pre-Discovery Setup

Before any browser interaction:

1. **Verify proxy is active**  
   Call `list_requests` with no filter. If it returns requests, proxy is working.  
   If it errors or returns 0, stop and fix the proxy before proceeding.

2. **Set scope**  
   Call `scope_rules` to restrict the proxy capture to your target domain only.  
   This reduces noise and makes `proxy_correlation` results clean.

3. **Record baseline**  
   Note the current request count from `list_requests`. Everything above this baseline is from your testing session.

---

## Phase 1 — Surface Mapping (Browser-Driven)

### A. Navigate to Target

```
browser_action(action="launch")
browser_action(action="goto", url="https://target.com")
```

**Immediately after `goto`:** inspect `proxy_correlation` in the response.  
- Captures initial page load, static resource requests, background API polling  
- Look for: `/api/`, `/graphql`, `/v1/`, `/v2/`, auth‑init endpoints

### B. Trigger All Entry Points

For every link, button, tab, and navigation item visible in the screenshot:

```
browser_action(action="click", coordinate="x,y")
# → proxy_correlation automatically attached to response
# → read it before the next action
```

**Per-click loop:**
1. Read `proxy_correlation.requests` from the response
2. For each entry with `method: POST` or path containing `/api/`:
   - Record: `{method, host, path, id}`
   - Call `view_request(request_id=<id>, part="request")` for full headers + body
   - Call `view_request(request_id=<id>, part="response")` for full response
3. Add discovered endpoints to your working API inventory (use `add_note`)

### C. Trigger Form Interactions

For every login form, search box, registration form, or data submission form:

**Step 1 — Fill with probe credentials**
```
browser_action(action="click", coordinate="<username_field>")
browser_action(action="type", text="probe@test.invalid")
browser_action(action="click", coordinate="<password_field>")
browser_action(action="type", text="probePassword123!")
```

**Step 2 — Submit and capture**
```
browser_action(action="press_key", key="Enter")
# OR: browser_action(action="click", coordinate="<submit_button>")
```

**Step 3 — Parse proxy_correlation immediately**
```
# proxy_correlation now contains the real POST /api/login (or equivalent)
for req in proxy_correlation["requests"]:
    if req["method"] == "POST":
        view_request(request_id=req["id"], part="request")   # → see auth params
        view_request(request_id=req["id"], part="response")  # → see token structure
```

---

## Phase 2 — Proxy Sweep (Historical Enrichment)

After browser interactions, do a comprehensive proxy sweep to catch anything missed:

### A. Catch All POST Endpoints
```
list_requests(
    httpql_filter='req.method.eq:"POST"',
    page_size=50,
    sort_by="timestamp",
    sort_order="desc"
)
```

### B. Catch All JSON API Endpoints
```
list_requests(
    httpql_filter='req.path.regex:"/api/.*"',
    page_size=50
)
```

### C. Catch Auth-Related Endpoints
```
list_requests(
    httpql_filter='req.path.regex:"(login|auth|token|session|signin|oauth|sso|jwt|refresh)"',
    page_size=50
)
```

### D. Catch GraphQL
```
list_requests(
    httpql_filter='req.path.regex:"(graphql|gql)"',
    page_size=50
)
```

### E. Catch File Upload / Data Export
```
list_requests(
    httpql_filter='req.path.regex:"(upload|export|download|backup|import)"',
    page_size=50
)
```

---

## Phase 3 — Smart Filtering and Classification

For each discovered endpoint, classify it using this decision table:

| Criteria | Classification | Priority |
|----------|---------------|----------|
| POST + JSON body + `/api/auth/` | Auth endpoint | CRITICAL |
| POST + JSON body + user/account data | Data mutation | HIGH |
| GET + numeric/UUID path param | IDOR candidate | HIGH |
| POST + file in body | File upload | HIGH |
| GET/POST + `url=`, `redirect=`, `next=` | SSRF/redirect | HIGH |
| GET + `/admin/` or `/internal/` | Auth bypass target | HIGH |
| POST + `query:` or GraphQL introspection | GraphQL | MEDIUM |
| GET + static resources (`.js`, `.css`, `.png`) | Skip | LOW |

### Confidence Scoring

Assign a confidence score to each discovered endpoint:

- `HIGH confidence` — seen in `proxy_correlation` during an explicit user action (e.g., form submit)
- `MEDIUM confidence` — seen in proxy sweep, path matches auth/API pattern
- `LOW confidence` — only visible in JS source or HTML, not yet in proxy traffic

**Only attack HIGH confidence endpoints first.** Medium confidence requires one validation step (actually trigger it) before testing.

---

## Phase 4 — Deep Endpoint Analysis

For each HIGH-priority endpoint, extract the full request:

```python
# Get full request detail
req_detail = view_request(request_id="<id>", part="request")
resp_detail = view_request(request_id="<id>", part="response")

# Extract from raw:
# - All parameters (query, body, path)
# - Authentication headers (Authorization, Cookie, X-CSRF-Token)
# - Request content-type (application/json vs form-encoded)
# - Response structure (JWT payload, session id, user object)
```

**Parameter Inventory per Endpoint:**
- Path params: `/api/users/{id}` → `id` is IDOR candidate
- Body params: `{"username":..., "password":...}` → injection targets
- Headers: `Authorization: Bearer <jwt>` → token analysis target
- Response: `{"token": "...", "user": {...}}` → data exposure check

---

## Phase 5 — API Inventory Output Format

Document discoveries in this structure using `add_note`:

```markdown
# API Inventory — <target>

## Authentication Endpoints
- POST /api/auth/login  [proxy_id: 1234]  [confidence: HIGH]
  Params: {username, password}
  Response: {token, refresh_token, user_id}
  Attack Surface: credential stuffing, JWT analysis, auth bypass

## Data Endpoints
- GET /api/users/{id}  [proxy_id: 1236]  [confidence: HIGH]
  Params: id (integer, path)
  Response: {id, email, role, ...}
  Attack Surface: IDOR, enumeration

## Admin Endpoints
- GET /api/admin/users  [proxy_id: 1240]  [confidence: MEDIUM]
  Params: none observed
  Attack Surface: broken access control

## GraphQL
- POST /graphql  [proxy_id: 1242]  [confidence: HIGH]
  Attack Surface: introspection, batching, field-level auth
```

---

## Phase 6 — Validation Gates (Anti-False-Positive)

**Before reporting ANY vulnerability:**

- [ ] `proxy_correlation` OR `list_requests` confirms the endpoint exists and is reachable
- [ ] `view_request` raw data shows the actual parameter structure (no guessing)
- [ ] The exploit was triggered via `send_request` or `repeat_request` and produced observable evidence in the proxy response
- [ ] The response deviation is NOT explainable by expected application behavior
- [ ] Reproduced at least once with a second `send_request` call to rule out transient state

**Minimum evidence package per finding:**
1. Original request (full raw from `view_request`)
2. Exploit request (full raw)
3. Response showing impact (data leaked, status change, etc.)
4. Proxy request IDs for both

---

## Workflow Summary (State Machine)

```
START
  └─ setup_proxy_scope()
       └─ browser: goto(target)
            └─ read proxy_correlation → extract endpoints
                 └─ for each clickable UI element:
                       └─ browser: click()
                            └─ read proxy_correlation → classify endpoints
                                 └─ for each form:
                                       └─ browser: fill → submit
                                            └─ read proxy_correlation → auth endpoints
                                                 └─ proxy_sweep(POST, /api/, auth, graphql)
                                                      └─ classify + score endpoints
                                                           └─ deep_analyze(HIGH priority)
                                                                └─ validate → report
```

---

## Adaptive Retry Logic

If `proxy_correlation.captured_count == 0` after a click/submit:

1. **Check proxy health:** `list_requests()` with no filter — if 0 results, proxy is down
2. **Check browser proxy config:** verify browser launched with proxy settings
3. **Try broader sweep:** `list_requests(sort_by="timestamp", sort_order="desc", page_size=10)` to see most recent general traffic
4. **Manual XHR extraction:** 
   ```
   browser_action(action="execute_js", js_code="
     window._xhrLog = [];
     const orig = XMLHttpRequest.prototype.open;
     XMLHttpRequest.prototype.open = function(m, u) {
       window._xhrLog.push({method: m, url: u});
       return orig.apply(this, arguments);
     };
   ")
   # Then after the action:
   browser_action(action="execute_js", js_code="({captured: window._xhrLog})")
   ```
5. **Fetch API interception:**
   ```
   browser_action(action="execute_js", js_code="
     window._fetchLog = [];
     const orig = window.fetch;
     window.fetch = function(url, opts) {
       window._fetchLog.push({url: String(url), method: (opts||{}).method||'GET'});
       return orig.apply(this, arguments);
     };
   ")
   ```

---

## GLM-4.7 Optimization Notes

This skill is designed for a long-context model (GLM-4.7-358B) running as part of Strix:

**Forced reflection checkpoints** — after every major phase, ask yourself:
- "Did I read `proxy_correlation` after my last browser action?"
- "Do I have proxy evidence (not just a screenshot) for every endpoint I plan to attack?"
- "Is my confidence score for this finding backed by actual proxy traffic?"

**Tool chaining pattern (DO this):**
```
browser_action(click) → read proxy_correlation → view_request(for interesting IDs) → classify → continue
```

**Anti-pattern (NEVER do this):**
```
browser_action(click) → [ignore proxy_correlation] → guess API from screenshot → report vulnerability
```

**Memory management for long sessions:**
Use `add_note("api_inventory")` to persist your endpoint map. Do not rely on conversation memory across many tool calls for endpoint lists — the context window will drift.
