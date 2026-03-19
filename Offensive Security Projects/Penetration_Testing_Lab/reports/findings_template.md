# Penetration Test Report — Metasploitable 2

**Tester:** Kousik Gunasekaran  
**Target:** Metasploitable 2 (10.56.237.233)  
**Date:** [DATE]  
**Classification:** CONFIDENTIAL — Lab Use Only

---

## Executive Summary

A penetration test was conducted against the Metasploitable 2 VM in an isolated lab environment. The assessment identified **7 critical vulnerabilities** allowing full system compromise via multiple attack vectors. All findings are from intentionally vulnerable software for educational purposes.

---

## Findings Summary

| # | Vulnerability | Severity | CVE | Status |
|---|--------------|----------|-----|--------|
| 1 | VSFTPd 2.3.4 Backdoor | CRITICAL | CVE-2011-2523 | Exploited |
| 2 | Samba usermap_script RCE | CRITICAL | CVE-2007-2447 | Exploited |
| 3 | UnrealIRCd Backdoor | CRITICAL | CVE-2010-2075 | Exploited |
| 4 | Distcc Daemon RCE | HIGH | CVE-2004-2687 | Exploited |
| 5 | Tomcat Manager WAR Upload | HIGH | CVE-2009-3548 | Exploited |
| 6 | PostgreSQL RCE | HIGH | CVE-2007-3280 | Exploited |
| 7 | DVWA SQL Injection | HIGH | - | Exploited |

---

## Detailed Findings

### Finding 1 — VSFTPd 2.3.4 Backdoor
**Severity:** CRITICAL  
**CVE:** CVE-2011-2523  
**Port:** 21/TCP  

**Description:**  
VSFTPd version 2.3.4 contains a backdoor introduced by an attacker who compromised the distribution package. When a username containing `:)` is provided, the server opens a bind shell on port 6200.

**Proof of Concept:**
```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 10.56.237.233
msf6 > run
[+] Command shell session opened
```

**Impact:** Unauthenticated remote code execution as root.

**Remediation:** Upgrade to VSFTPd 3.x. Verify package integrity via GPG signature.

---

### Finding 2 — Samba usermap_script RCE
**Severity:** CRITICAL  
**CVE:** CVE-2007-2447  
**Port:** 445/TCP  

**Description:**  
Samba versions 3.0.20 through 3.0.25rc3 allow remote attackers to execute commands via shell metacharacters in the SamrChangePassword MS-RPC call.

**Proof of Concept:**
```
msf6 > use exploit/multi/samba/usermap_script
msf6 > set RHOSTS 10.56.237.233
msf6 > run
[+] Command shell session opened
```

**Impact:** Unauthenticated RCE as root via SMB.

**Remediation:** Upgrade Samba to 3.0.26+. Apply vendor security patches immediately.

---

## Attack Path

```
Nmap Scan → Open Ports Discovered → VSFTPd Backdoor → Root Shell → 
Pivot to internal network → Credential harvest → Persistence
```

## Remediation Priorities

1. **Immediate:** Patch all CRITICAL CVEs (VSFTPd, Samba, UnrealIRCd)
2. **Short-term:** Disable unnecessary services (distcc, IRC, Tomcat default creds)
3. **Long-term:** Implement network segmentation, IDS/IPS, disable default credentials

---

*Report generated for educational purposes in isolated lab environment.*
