#!/usr/bin/env python3
"""
LAB 1: Detection Engineering — Write, Validate & Deploy Sigma Rules
=====================================================================
Objective: Author a new Sigma detection rule, validate its ATT&CK tags,
convert it to Splunk SPL and Sentinel KQL, and simulate deployment.

Prerequisites: pip install pyyaml
Author: Kousik Gunasekaran
"""

import yaml
import json
import uuid
import sys
from datetime import datetime, timezone
from pathlib import Path

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  LAB 1 — Detection Engineering                          ║
║  Write · Validate · Convert · Deploy Sigma Rules        ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
# EXERCISE 1: Sigma Rule Template
# ─────────────────────────────────────────────

SIGMA_TEMPLATE = {
    "title": "Mimikatz Token Impersonation via SeDebugPrivilege",
    "id": str(uuid.uuid4()),
    "status": "experimental",
    "description": (
        "Detects Mimikatz privilege escalation via SeDebugPrivilege token impersonation. "
        "Attackers use this to escalate to SYSTEM and dump credentials from LSASS."
    ),
    "references": [
        "https://attack.mitre.org/techniques/T1134/001/",
        "https://github.com/gentilkiwi/mimikatz"
    ],
    "author": "Kousik Gunasekaran",
    "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
    "tags": [
        "attack.privilege_escalation",
        "attack.t1134.001",
        "attack.credential_access",
        "attack.t1003.001"
    ],
    "logsource": {
        "category": "process_creation",
        "product": "windows"
    },
    "detection": {
        "selection_image": {
            "Image|endswith": ["\\mimikatz.exe", "\\mimilib.dll"]
        },
        "selection_commandline": {
            "CommandLine|contains": [
                "privilege::debug",
                "sekurlsa::logonpasswords",
                "lsadump::sam",
                "token::elevate"
            ]
        },
        "selection_parent": {
            "ParentImage|endswith": ["\\cmd.exe", "\\powershell.exe"]
        },
        "condition": "selection_image or selection_commandline or selection_parent"
    },
    "falsepositives": [
        "Security testing by authorized red team operators",
        "Forensic tools run by incident responders"
    ],
    "level": "critical"
}


# ─────────────────────────────────────────────
# EXERCISE 2: ATT&CK Validator
# ─────────────────────────────────────────────

VALID_TACTICS = {
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact"
}

VALID_TECHNIQUES = {
    "t1134", "t1134.001", "t1134.002",
    "t1003", "t1003.001", "t1003.002", "t1003.003",
    "t1059", "t1059.001", "t1059.003",
    "t1021", "t1021.002",
    "t1053", "t1053.005",
    "t1548", "t1548.002",
    "t1055", "t1055.001",
    "t1027", "t1070", "t1070.004",
}


def validate_sigma_rule(rule: dict) -> dict:
    result = {"passed": True, "errors": [], "warnings": [], "techniques": [], "tactics": []}

    required = ["title", "description", "detection", "level", "tags", "logsource"]
    for field in required:
        if not rule.get(field):
            result["errors"].append(f"Missing required field: '{field}'")
            result["passed"] = False

    detection = rule.get("detection", {})
    if "condition" not in detection:
        result["errors"].append("Detection block missing 'condition' field")
        result["passed"] = False

    for tag in rule.get("tags", []):
        t = tag.lower()
        if t.startswith("attack.t"):
            tech = t.replace("attack.", "")
            result["techniques"].append(tech)
            if tech not in VALID_TECHNIQUES:
                result["warnings"].append(f"Technique '{tech}' not in local ATT&CK cache — verify online")
        elif t.startswith("attack."):
            tactic = t.replace("attack.", "")
            result["tactics"].append(tactic)
            if tactic not in VALID_TACTICS:
                result["errors"].append(f"Unknown ATT&CK tactic: '{tactic}'")
                result["passed"] = False

    if not result["techniques"]:
        result["warnings"].append("No ATT&CK technique tags — add at least one attack.tXXXX tag")

    level = rule.get("level", "").lower()
    if level not in ("critical", "high", "medium", "low", "informational"):
        result["errors"].append(f"Invalid severity level: '{level}'")
        result["passed"] = False

    return result


# ─────────────────────────────────────────────
# EXERCISE 3: Sigma → SPL Converter
# ─────────────────────────────────────────────

def sigma_to_splunk(rule: dict) -> str:
    title = rule.get("title", "")
    tags = rule.get("tags", [])
    detection = rule.get("detection", {})
    logsource = rule.get("logsource", {})

    index = "index=windows " if logsource.get("product") == "windows" else ""
    clauses = []

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            parts = []
            for field, matcher in val.items():
                base = field.split("|")[0]
                op = field.split("|")[1] if "|" in field else "eq"
                if isinstance(matcher, list):
                    if "contains" in op:
                        inner = " OR ".join(f'{base}="*{v}*"' for v in matcher)
                    elif "endswith" in op:
                        inner = " OR ".join(f'{base}="*{v}"' for v in matcher)
                    else:
                        inner = " OR ".join(f'{base}="{v}"' for v in matcher)
                    parts.append(f"({inner})")
                else:
                    parts.append(f'{base}="{matcher}"')
            if parts:
                clauses.append("(" + " AND ".join(parts) + ")")

    condition = detection.get("condition", "")
    spl_condition = condition
    for key in detection:
        if key != "condition":
            spl_condition = spl_condition.replace(key, f"[{key}]")

    # Simplified: join with OR for OR conditions, AND for AND
    search_str = " OR ".join(clauses) if clauses else "*"

    return f"""| comment: {title}
| comment: ATT&CK: {', '.join(tags)}
{index}EventCode=4688 OR EventCode=1
| search {search_str}
| table _time, host, user, CommandLine, Image, ParentImage, EventCode
| sort -_time"""


# ─────────────────────────────────────────────
# EXERCISE 4: Sigma → KQL Converter
# ─────────────────────────────────────────────

def sigma_to_kql(rule: dict) -> str:
    title = rule.get("title", "")
    tags = rule.get("tags", [])
    detection = rule.get("detection", {})

    clauses = []
    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            parts = []
            for field, matcher in val.items():
                base = field.split("|")[0]
                op = field.split("|")[1] if "|" in field else "eq"
                if isinstance(matcher, list):
                    if "contains" in op:
                        inner = " or ".join(f'{base} contains "{v}"' for v in matcher)
                    elif "endswith" in op:
                        inner = " or ".join(f'{base} endswith "{v}"' for v in matcher)
                    else:
                        inner = " or ".join(f'{base} == "{v}"' for v in matcher)
                    parts.append(f"({inner})")
                else:
                    parts.append(f'{base} == "{matcher}"')
            if parts:
                clauses.append("(" + " and ".join(parts) + ")")

    where_clause = "\nor ".join(clauses) if clauses else "true"

    return f"""// {title}
// ATT&CK: {', '.join(tags)}
DeviceProcessEvents
| where TimeGenerated >= ago(1h)
| where {where_clause}
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc"""


# ─────────────────────────────────────────────
# EXERCISE 5: Simulate SIEM Deployment
# ─────────────────────────────────────────────

def simulate_deployment(rule: dict, spl: str, kql: str):
    print("\n[EXERCISE 5] Simulating SIEM Deployment")
    print("─" * 50)

    deployment_record = {
        "rule_id": rule.get("id"),
        "title": rule.get("title"),
        "level": rule.get("level"),
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "targets": {
            "splunk": {
                "saved_search_name": f"sigma_{rule.get('title','').lower().replace(' ', '_')[:40]}",
                "schedule": "*/15 * * * *",
                "status": "DEPLOYED (simulated)"
            },
            "sentinel": {
                "analytics_rule": f"sigma-{rule.get('id','')[:8]}",
                "frequency": "PT15M",
                "status": "DEPLOYED (simulated)"
            }
        },
        "alert_actions": ["slack_notification", "jira_ticket_creation"]
    }
    print(json.dumps(deployment_record, indent=2))
    return deployment_record


# ─────────────────────────────────────────────
# CHALLENGE: Write Your Own Rule
# ─────────────────────────────────────────────

CHALLENGE_TEMPLATE = {
    "title": "YOUR RULE TITLE",
    "id": str(uuid.uuid4()),
    "status": "experimental",
    "description": "Describe what this rule detects and why it matters",
    "tags": [
        "attack.TACTIC_NAME",
        "attack.tXXXX.XXX"
    ],
    "logsource": {
        "category": "process_creation OR network_connection OR dns",
        "product": "windows OR linux"
    },
    "detection": {
        "selection": {
            "FieldName|contains": ["suspicious_value"]
        },
        "condition": "selection"
    },
    "falsepositives": ["Describe known benign triggers"],
    "level": "high"
}


# ─────────────────────────────────────────────
# Main Lab Runner
# ─────────────────────────────────────────────

def run_lab():
    print(BANNER)
    out = Path("lab1_output")
    out.mkdir(exist_ok=True)

    # Ex 1: Save rule
    print("[EXERCISE 1] Writing Sigma Rule")
    print("─" * 50)
    rule_path = out / "mimikatz_detection.yml"
    with open(rule_path, "w") as f:
        yaml.dump(SIGMA_TEMPLATE, f, default_flow_style=False, sort_keys=False)
    print(f"  ✓ Rule written: {rule_path}")
    print(f"  Title    : {SIGMA_TEMPLATE['title']}")
    print(f"  Level    : {SIGMA_TEMPLATE['level'].upper()}")
    print(f"  ATT&CK   : {', '.join(SIGMA_TEMPLATE['tags'])}\n")

    # Ex 2: Validate
    print("[EXERCISE 2] Validating ATT&CK Tags & Required Fields")
    print("─" * 50)
    result = validate_sigma_rule(SIGMA_TEMPLATE)
    status = "✓ PASS" if result["passed"] else "✗ FAIL"
    print(f"  Validation: {status}")
    print(f"  Techniques: {result['techniques']}")
    print(f"  Tactics   : {result['tactics']}")
    for err in result["errors"]:
        print(f"  ERROR: {err}")
    for warn in result["warnings"]:
        print(f"  WARN : {warn}")
    print()

    # Ex 3: SPL
    print("[EXERCISE 3] Converting to Splunk SPL")
    print("─" * 50)
    spl = sigma_to_splunk(SIGMA_TEMPLATE)
    spl_path = out / "mimikatz_detection.spl"
    with open(spl_path, "w") as f:
        f.write(spl)
    print(spl)
    print(f"\n  ✓ Saved: {spl_path}\n")

    # Ex 4: KQL
    print("[EXERCISE 4] Converting to Microsoft Sentinel KQL")
    print("─" * 50)
    kql = sigma_to_kql(SIGMA_TEMPLATE)
    kql_path = out / "mimikatz_detection.kql"
    with open(kql_path, "w") as f:
        f.write(kql)
    print(kql)
    print(f"\n  ✓ Saved: {kql_path}\n")

    # Ex 5: Deploy
    simulate_deployment(SIGMA_TEMPLATE, spl, kql)

    # Challenge
    challenge_path = out / "YOUR_RULE_challenge.yml"
    with open(challenge_path, "w") as f:
        yaml.dump(CHALLENGE_TEMPLATE, f, default_flow_style=False, sort_keys=False)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  LAB 1 COMPLETE                                         ║
╠══════════════════════════════════════════════════════════╣
║  CHALLENGE: Edit {str(challenge_path):<35} ║
║  Then rerun: python lab1_detection_engineering.py       ║
║                                                          ║
║  Key Concepts Covered:                                  ║
║  • Sigma rule structure & field modifiers               ║
║  • MITRE ATT&CK tactic/technique tagging                ║
║  • SPL and KQL query generation                         ║
║  • CI/CD-style validation before deployment             ║
╚══════════════════════════════════════════════════════════╝""")

if __name__ == "__main__":
    run_lab()
