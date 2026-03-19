# Penetration Testing Lab — Metasploitable 2

A hands-on offensive security lab using Metasploitable 2 as the target VM, covering the full penetration testing lifecycle: reconnaissance, scanning, exploitation, post-exploitation, and reporting.

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux (latest) |
| Target | Metasploitable 2 (10.56.237.233) |
| Network | Host-only / NAT isolated network |
| Tools | Metasploit, Nmap, Burp Suite, SQLmap, Nikto, Hydra |

## Methodology (PTES)

```
1. Reconnaissance  →  2. Scanning  →  3. Exploitation  →  4. Post-Exploitation  →  5. Reporting
```

## Exploits Demonstrated

| Vulnerability | CVE | Tool | Service |
|--------------|-----|------|---------|
| VSFTPd 2.3.4 Backdoor | CVE-2011-2523 | Metasploit | FTP (21) |
| Samba MS-RPC Shell | CVE-2007-2447 | Metasploit | SMB (445) |
| UnrealIRCd Backdoor | CVE-2010-2075 | Metasploit | IRC (6667) |
| DVWA SQL Injection | - | SQLmap | HTTP (80) |
| Tomcat Manager Upload | CVE-2009-3548 | Metasploit | HTTP (8180) |
| Distcc Daemon RCE | CVE-2004-2687 | Metasploit | distcc (3632) |
| PostgreSQL RCE | CVE-2007-3280 | Metasploit | Postgres (5432) |

## Scripts

- `recon/nmap_scan.sh` — Full port + service + script scan
- `exploit/run_exploits.py` — Automated Metasploit exploit runner
- `post_exploit/enum.sh` — Post-exploitation enumeration
- `reports/findings_template.md` — Pentest report template

## Usage

```bash
# 1. Run full recon
./recon/nmap_scan.sh 10.56.237.233

# 2. Run automated exploits
python3 exploit/run_exploits.py --target 10.56.237.233

# 3. Manual Metasploit
msfconsole -r exploit/vsftpd_backdoor.rc
```

## ⚠️ Disclaimer
This lab is for **educational purposes only** in an isolated, controlled environment. Never use these techniques against systems you do not own or have explicit written permission to test.
