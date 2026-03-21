#!/usr/bin/env python3
"""
LAB 4: DFIR — Digital Forensics & Incident Response
=====================================================
Objective: Analyze simulated forensic artifacts from a compromised
Windows endpoint. Build an incident timeline, identify IOCs,
map to MITRE ATT&CK, and write a formal IR report.

Author: Kousik Gunasekaran
"""

import json
import hashlib
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  LAB 4 — DFIR                                           ║
║  Forensic Artifacts · IOC Extraction · IR Report        ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
# EXERCISE 1: Simulated Forensic Artifacts
# ─────────────────────────────────────────────

FORENSIC_ARTIFACTS = {
    "prefetch_files": [
        {"name": "CHROME.EXE-A1B2C3D4.pf",   "run_count": 152, "last_run": "2025-03-15T08:22:14Z"},
        {"name": "POWERSHELL.EXE-B2C3D4E5.pf","run_count": 3,   "last_run": "2025-03-15T10:47:33Z"},
        {"name": "PSEXEC64.EXE-C3D4E5F6.pf",  "run_count": 1,   "last_run": "2025-03-15T10:52:11Z"},
        {"name": "RUNDLL32.EXE-D4E5F6A7.pf",  "run_count": 2,   "last_run": "2025-03-15T10:49:08Z"},
        {"name": "MIMIKATZ.EXE-E5F6A7B8.pf",  "run_count": 1,   "last_run": "2025-03-15T10:53:44Z"},
        {"name": "SCHTASKS.EXE-F6A7B8C9.pf",  "run_count": 1,   "last_run": "2025-03-15T10:55:01Z"},
        {"name": "OUTLOOK.EXE-A7B8C9D0.pf",   "run_count": 44,  "last_run": "2025-03-15T08:15:09Z"},
    ],
    "windows_event_logs": [
        {"time": "2025-03-15T08:15:09Z", "id": 4624,  "user": "bob",           "logon_type": 2,  "note": "Interactive logon — normal"},
        {"time": "2025-03-15T10:33:52Z", "id": 4625,  "user": "carol",         "logon_type": 3,  "note": "Failed network logon"},
        {"time": "2025-03-15T10:34:01Z", "id": 4625,  "user": "carol",         "logon_type": 3,  "note": "Failed network logon"},
        {"time": "2025-03-15T10:34:09Z", "id": 4625,  "user": "carol",         "logon_type": 3,  "note": "Failed network logon"},
        {"time": "2025-03-15T10:34:17Z", "id": 4625,  "user": "carol",         "logon_type": 3,  "note": "Failed network logon"},
        {"time": "2025-03-15T10:47:33Z", "id": 4688,  "user": "bob",           "process": "powershell.exe", "cmdline": "powershell.exe -nop -ep bypass -enc SQBFAFgA..."},
        {"time": "2025-03-15T10:49:08Z", "id": 4688,  "user": "bob",           "process": "rundll32.exe",   "cmdline": "rundll32.exe comsvcs.dll, MiniDump 668 lsass.dmp full"},
        {"time": "2025-03-15T10:52:11Z", "id": 4688,  "user": "bob",           "process": "PsExec64.exe",   "cmdline": "PsExec64.exe \\\\SRV-DC-01 -u admin -p P@ss cmd"},
        {"time": "2025-03-15T10:52:14Z", "id": 4624,  "user": "DOMAIN\\admin", "logon_type": 3,  "note": "Network logon from WS-BOB-02 — lateral movement"},
        {"time": "2025-03-15T10:53:44Z", "id": 4688,  "user": "DOMAIN\\admin", "process": "mimikatz.exe",   "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"},
        {"time": "2025-03-15T10:55:01Z", "id": 4688,  "user": "DOMAIN\\admin", "process": "schtasks.exe",   "cmdline": 'schtasks /create /tn "WindowsUpdate" /tr "C:\\Temp\\payload.exe" /sc onlogon /ru SYSTEM'},
        {"time": "2025-03-15T11:02:45Z", "id": 4698,  "user": "SYSTEM",        "task": "WindowsUpdate",     "note": "Scheduled task created"},
        {"time": "2025-03-15T11:15:33Z", "id": 5156,  "user": "SYSTEM",        "dest_ip": "185.220.101.47", "dest_port": 443, "note": "Outbound connection to C2"},
    ],
    "registry_keys": [
        {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
         "value": "C:\\Windows\\Temp\\payload.exe", "modified": "2025-03-15T10:55:22Z"},
        {"key": "HKLM\\System\\CurrentControlSet\\Services\\TrustedInstaller",
         "value": "Normal", "modified": "2025-03-14T09:00:00Z"},
        {"key": "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\Internet\\Server Cache\\",
         "value": "185.220.101.47", "modified": "2025-03-15T09:41:02Z"},
    ],
    "network_connections": [
        {"time": "2025-03-15T09:41:00Z", "src": "WS-BOB-02", "dst": "185.220.101.47", "port": 80,  "bytes": 2048,  "note": "Initial beacon — HTTP"},
        {"time": "2025-03-15T10:45:00Z", "src": "WS-BOB-02", "dst": "185.220.101.47", "port": 443, "bytes": 512000,"note": "Payload download over HTTPS"},
        {"time": "2025-03-15T11:15:00Z", "src": "SRV-DC-01", "dst": "185.220.101.47", "port": 443, "bytes": 8192,  "note": "C2 comms from DC"},
        {"time": "2025-03-15T11:20:00Z", "src": "SRV-DC-01", "dst": "185.220.101.47", "port": 53,  "bytes": 32000, "note": "Potential DNS exfiltration"},
    ],
    "files_of_interest": [
        {"path": "C:\\Users\\bob\\AppData\\Local\\Temp\\PsExec64.exe",  "size_kb": 628,   "md5": "3337e3875b05e0bfba69ab926532e3cf", "created": "2025-03-15T10:51:50Z"},
        {"path": "C:\\Users\\bob\\AppData\\Local\\Temp\\lsass.dmp",     "size_kb": 98304, "md5": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "created": "2025-03-15T10:49:15Z"},
        {"path": "C:\\Windows\\Temp\\payload.exe",                      "size_kb": 312,   "md5": "f1e2d3c4b5a6978869504132211a0b0c", "created": "2025-03-15T10:55:00Z"},
        {"path": "C:\\Windows\\Temp\\mimikatz.exe",                     "size_kb": 1240,  "md5": "9e2e3a00b3d94e67c9b1d5ad80c8c8d2", "created": "2025-03-15T10:53:30Z"},
    ]
}

KNOWN_MALICIOUS_IPS = {"185.220.101.47", "10.10.10.55"}
KNOWN_MALICIOUS_MD5 = {
    "3337e3875b05e0bfba69ab926532e3cf": "PsExec (dual-use)",
    "9e2e3a00b3d94e67c9b1d5ad80c8c8d2": "Mimikatz credential dumper",
    "f1e2d3c4b5a6978869504132211a0b0c": "Generic trojan dropper",
}


# ─────────────────────────────────────────────
# EXERCISE 2: IOC Extraction
# ─────────────────────────────────────────────

def extract_iocs(artifacts: dict) -> dict:
    iocs = {"ips": set(), "file_hashes": {}, "file_paths": [], "registry_keys": [], "domains": set()}

    for conn in artifacts.get("network_connections", []):
        dst = conn.get("dst", "")
        if dst not in ("WS-BOB-02", "SRV-DC-01"):
            iocs["ips"].add(dst)

    for f in artifacts.get("files_of_interest", []):
        iocs["file_hashes"][f["md5"]] = f["path"]
        iocs["file_paths"].append(f["path"])

    for reg in artifacts.get("registry_keys", []):
        val = reg.get("value", "")
        if "Temp" in val or "AppData" in val:
            iocs["registry_keys"].append(reg["key"])

    iocs["ips"] = list(iocs["ips"])
    return iocs


# ─────────────────────────────────────────────
# EXERCISE 3: ATT&CK Mapping
# ─────────────────────────────────────────────

ATTACK_MAPPING = [
    {"technique": "T1566.001", "tactic": "Initial Access",       "description": "Spearphishing attachment (assumed initial vector via Outlook)"},
    {"technique": "T1059.001", "tactic": "Execution",            "description": "PowerShell with -enc flag and -ExecutionPolicy Bypass"},
    {"technique": "T1003.001", "tactic": "Credential Access",    "description": "LSASS memory dump via comsvcs.dll MiniDump"},
    {"technique": "T1134.001", "tactic": "Privilege Escalation", "description": "Token impersonation via Mimikatz privilege::debug"},
    {"technique": "T1021.002", "tactic": "Lateral Movement",     "description": "PsExec64 used to move to SRV-DC-01"},
    {"technique": "T1053.005", "tactic": "Persistence",          "description": "Scheduled task 'WindowsUpdate' runs payload.exe on logon"},
    {"technique": "T1547.001", "tactic": "Persistence",          "description": "Registry Run key HKCU\\...\\Run\\WindowsUpdate"},
    {"technique": "T1071.001", "tactic": "C2",                   "description": "HTTPS C2 beacon to 185.220.101.47 port 443"},
    {"technique": "T1048.001", "tactic": "Exfiltration",         "description": "Potential DNS exfiltration from SRV-DC-01"},
]


# ─────────────────────────────────────────────
# EXERCISE 4: Build Incident Timeline
# ─────────────────────────────────────────────

def build_timeline(artifacts: dict) -> list:
    events = []
    for log in artifacts.get("windows_event_logs", []):
        desc = log.get("cmdline") or log.get("note") or log.get("task", "")
        events.append({
            "time": log["time"],
            "source": f"EventLog[{log['id']}]",
            "actor": log.get("user", "?"),
            "description": desc,
            "suspicious": log["id"] in (4688,) and any(
                kw in desc.lower() for kw in ["psexec", "mimikatz", "comsvcs", "payload", "enc", "schtasks"]
            )
        })
    for conn in artifacts.get("network_connections", []):
        events.append({
            "time": conn["time"],
            "source": "Network",
            "actor": conn["src"],
            "description": f"{conn['src']} → {conn['dst']}:{conn['port']} ({conn['bytes']//1024}KB) — {conn['note']}",
            "suspicious": conn["dst"] in KNOWN_MALICIOUS_IPS
        })
    return sorted(events, key=lambda x: x["time"])


# ─────────────────────────────────────────────
# EXERCISE 5: Write IR Report
# ─────────────────────────────────────────────

def write_ir_report(iocs: dict, timeline: list, attack_map: list) -> str:
    suspicious_events = [e for e in timeline if e.get("suspicious")]
    report = f"""
════════════════════════════════════════════════════════════════
INCIDENT RESPONSE REPORT
════════════════════════════════════════════════════════════════
Report Date    : {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
Analyst        : Kousik Gunasekaran
Incident ID    : INC-2025-0315-001
Classification : CONFIDENTIAL
Severity       : CRITICAL

1. EXECUTIVE SUMMARY
────────────────────────────────────────────────────────────────
A targeted intrusion was detected on WS-BOB-02 on 2025-03-15.
The attacker established initial access through a phishing email,
executed a PowerShell dropper, dumped LSASS credentials via
comsvcs.dll, and laterally moved to SRV-DC-01 using stolen admin
credentials via PsExec. Mimikatz was used on the DC to harvest
additional credentials. The attacker established persistence via
a scheduled task and registry Run key, then initiated C2
communications and DNS-based data exfiltration.

2. INDICATORS OF COMPROMISE (IOCs)
────────────────────────────────────────────────────────────────
  IP Addresses (block immediately):
"""
    for ip in iocs["ips"]:
        threat = "Known malicious" if ip in KNOWN_MALICIOUS_IPS else "Unknown"
        report += f"    • {ip} [{threat}]\n"

    report += "\n  File Hashes (MD5):\n"
    for md5, path in iocs["file_hashes"].items():
        classification = KNOWN_MALICIOUS_MD5.get(md5, "Unclassified")
        report += f"    • {md5}  {classification}\n"
        report += f"      Path: {path}\n"

    report += "\n  Malicious File Paths:\n"
    for path in iocs["file_paths"]:
        report += f"    • {path}\n"

    report += "\n  Registry Persistence:\n"
    for key in iocs["registry_keys"]:
        report += f"    • {key}\n"

    report += f"""
3. MITRE ATT&CK MAPPING
────────────────────────────────────────────────────────────────
  {'Technique':<14} {'Tactic':<22} Description
  {'─'*14} {'─'*22} {'─'*38}
"""
    for t in attack_map:
        report += f"  {t['technique']:<14} {t['tactic']:<22} {t['description']}\n"

    report += f"""
4. INCIDENT TIMELINE (Suspicious Events Only)
────────────────────────────────────────────────────────────────
"""
    for e in suspicious_events:
        report += f"  {e['time']}  [{e['source']}]  {e['actor']}\n"
        report += f"    {e['description'][:90]}\n\n"

    report += f"""
5. CONTAINMENT ACTIONS (Immediate)
────────────────────────────────────────────────────────────────
  [x] Isolate WS-BOB-02 from network
  [x] Isolate SRV-DC-01 from network
  [x] Block 185.220.101.47 at perimeter firewall
  [x] Disable user accounts: bob, DOMAIN\\admin (pending review)
  [x] Force password reset for all domain accounts
  [x] Delete scheduled task "WindowsUpdate" on SRV-DC-01
  [x] Remove registry Run key persistence

6. RECOMMENDATIONS
────────────────────────────────────────────────────────────────
  • Implement Credential Guard to protect LSASS process
  • Enable PowerShell Constrained Language Mode and AMSI
  • Deploy application allowlisting (AppLocker / WDAC)
  • Implement Privileged Access Workstations (PAW) for admins
  • Enable Windows Defender Credential Guard
  • Audit and restrict PsExec usage via AppLocker rules
  • Deploy DNS monitoring for long query detection

════════════════════════════════════════════════════════════════
END OF REPORT
════════════════════════════════════════════════════════════════
"""
    return report


def run_lab():
    print(BANNER)
    out = Path("lab4_output")
    out.mkdir(exist_ok=True)

    print("[EXERCISE 1] Examining forensic artifacts")
    print("─" * 55)
    print(f"  Prefetch files     : {len(FORENSIC_ARTIFACTS['prefetch_files'])}")
    print(f"  Windows event logs : {len(FORENSIC_ARTIFACTS['windows_event_logs'])}")
    print(f"  Registry keys      : {len(FORENSIC_ARTIFACTS['registry_keys'])}")
    print(f"  Network connections: {len(FORENSIC_ARTIFACTS['network_connections'])}")
    print(f"  Files of interest  : {len(FORENSIC_ARTIFACTS['files_of_interest'])}")

    print("\n  Suspicious prefetch (run count anomalies):")
    for pf in FORENSIC_ARTIFACTS["prefetch_files"]:
        flag = " ← SUSPICIOUS (run count 1 + known-bad name)" if pf["run_count"] <= 2 and any(
            k in pf["name"].lower() for k in ["psexec", "mimikatz", "rundll", "schtasks"]) else ""
        print(f"    {pf['name']:<45} runs={pf['run_count']}{flag}")

    print("\n[EXERCISE 2] Extracting IOCs")
    print("─" * 55)
    iocs = extract_iocs(FORENSIC_ARTIFACTS)
    print(f"  IPs        : {iocs['ips']}")
    print(f"  File hashes: {len(iocs['file_hashes'])}")
    print(f"  File paths : {len(iocs['file_paths'])}")
    print(f"  Reg keys   : {len(iocs['registry_keys'])}")

    print("\n  Hash reputation check:")
    for md5, path in iocs["file_hashes"].items():
        classification = KNOWN_MALICIOUS_MD5.get(md5, "CLEAN")
        flag = "🔴 MALICIOUS" if md5 in KNOWN_MALICIOUS_MD5 else "⚪ UNKNOWN"
        print(f"    {flag} {md5[:12]}... — {classification}")

    print("\n[EXERCISE 3] MITRE ATT&CK Mapping")
    print("─" * 55)
    for t in ATTACK_MAPPING:
        print(f"  {t['technique']} | {t['tactic']:<22} | {t['description'][:50]}")

    print("\n[EXERCISE 4] Building Incident Timeline")
    print("─" * 55)
    timeline = build_timeline(FORENSIC_ARTIFACTS)
    suspicious = [e for e in timeline if e.get("suspicious")]
    print(f"  Total timeline events    : {len(timeline)}")
    print(f"  Suspicious events flagged: {len(suspicious)}")
    print(f"\n  Attack chain (suspicious events only):")
    for e in suspicious:
        print(f"    {e['time']}  {e['description'][:70]}")

    print("\n[EXERCISE 5] Writing IR Report")
    print("─" * 55)
    report = write_ir_report(iocs, timeline, ATTACK_MAPPING)
    report_path = out / "IR_Report_INC-2025-0315-001.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(report)
    print(f"  ✓ Report saved: {report_path}")

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  LAB 4 COMPLETE                                         ║
╠══════════════════════════════════════════════════════════╣
║  CHALLENGE: Add a Dwell Time calculation                ║
║  (initial access → detection) and add it to the report  ║
║  Hint: First event vs. first detection event            ║
╠══════════════════════════════════════════════════════════╣
║  Key Concepts Covered:                                  ║
║  • Forensic artifact analysis (Prefetch, Event Logs)    ║
║  • IOC extraction and hash reputation                   ║
║  • MITRE ATT&CK mapping for incident analysis           ║
║  • Incident timeline reconstruction                     ║
║  • IR report writing with executive summary             ║
╚══════════════════════════════════════════════════════════╝""")


if __name__ == "__main__":
    run_lab()
