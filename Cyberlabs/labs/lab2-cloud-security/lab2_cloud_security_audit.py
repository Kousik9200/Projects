#!/usr/bin/env python3
"""
LAB 2: Cloud Security Auditing — CIS Benchmark Assessment
==========================================================
Objective: Audit a simulated AWS environment for misconfigurations,
score findings by risk, and produce a prioritized remediation plan.

Runs entirely in mock mode — no AWS credentials needed.
Author: Kousik Gunasekaran
"""

import json
from datetime import datetime, timezone
from pathlib import Path

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  LAB 2 — Cloud Security Auditing                        ║
║  CIS Benchmark · Risk Scoring · Remediation Planning    ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
# EXERCISE 1: Simulated AWS Environment
# ─────────────────────────────────────────────

MOCK_AWS_ENV = {
    "account_id": "123456789012",
    "region": "us-east-1",
    "environment": "production",
    "iam": {
        "root_mfa_enabled": False,                    # BAD
        "users": [
            {"name": "alice",  "console": True,  "mfa": True,  "key_age_days": 45},
            {"name": "bob",    "console": True,  "mfa": False, "key_age_days": 102},  # BAD
            {"name": "ci-bot", "console": False, "mfa": False, "key_age_days": 134},  # BAD
        ],
        "policies": [
            {"name": "DevFullAccess", "wildcard_action": True,  "wildcard_resource": True},   # BAD
            {"name": "S3ReadOnly",    "wildcard_action": False, "wildcard_resource": False},
            {"name": "EC2Describe",   "wildcard_action": False, "wildcard_resource": True},   # WARN
        ]
    },
    "s3_buckets": [
        {"name": "prod-customer-pii",  "public_block": False, "encryption": True,  "logging": True},   # CRITICAL
        {"name": "internal-docs",      "public_block": True,  "encryption": False, "logging": False},  # MEDIUM
        {"name": "cloudtrail-logs",    "public_block": True,  "encryption": True,  "logging": True},
        {"name": "dev-scratch",        "public_block": True,  "encryption": False, "logging": False},  # LOW
    ],
    "security_groups": [
        {"id": "sg-001", "name": "prod-web",  "open_ports": [80, 443, 22],    "all_traffic": False},  # HIGH (SSH)
        {"id": "sg-002", "name": "prod-db",   "open_ports": [3306, 5432],     "all_traffic": False},  # CRITICAL
        {"id": "sg-003", "name": "mgmt",      "open_ports": [22, 3389],       "all_traffic": False},  # CRITICAL (RDP)
        {"id": "sg-004", "name": "internal",  "open_ports": [443],            "all_traffic": False},
        {"id": "sg-005", "name": "old-test",  "open_ports": [],               "all_traffic": True},   # CRITICAL
    ],
    "cloudtrail": {
        "enabled": True,
        "multi_region": False,          # BAD
        "log_validation": False,        # BAD
        "cloudwatch_integrated": True,
        "s3_bucket_public": False,
    }
}

DANGEROUS_PORTS = {
    22: ("SSH", "CRITICAL"), 3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "CRITICAL"), 5432: ("PostgreSQL", "HIGH"),
    1433: ("MSSQL", "HIGH"), 27017: ("MongoDB", "HIGH"),
}


# ─────────────────────────────────────────────
# EXERCISE 2: Audit Functions
# ─────────────────────────────────────────────

def audit_iam(env: dict) -> list:
    findings = []
    iam = env["iam"]

    if not iam["root_mfa_enabled"]:
        findings.append({
            "id": "IAM-001", "cis": "CIS 1.5", "severity": "CRITICAL",
            "title": "Root account MFA is disabled",
            "resource": "root account",
            "fix": "Enable hardware MFA on root account. Lock away root credentials after setup.",
            "effort": "15 min"
        })

    for user in iam["users"]:
        if user["console"] and not user["mfa"]:
            findings.append({
                "id": f"IAM-002-{user['name']}", "cis": "CIS 1.10", "severity": "HIGH",
                "title": f"Console user '{user['name']}' has no MFA",
                "resource": f"iam/user/{user['name']}",
                "fix": f"Enforce MFA for {user['name']}. Apply IAM policy denying all actions without MFA.",
                "effort": "10 min"
            })
        if user["key_age_days"] > 90:
            findings.append({
                "id": f"IAM-003-{user['name']}", "cis": "CIS 1.14", "severity": "MEDIUM",
                "title": f"Access key for '{user['name']}' is {user['key_age_days']} days old",
                "resource": f"iam/user/{user['name']}",
                "fix": f"Rotate key for {user['name']}. Create new → update apps → disable old → delete.",
                "effort": "30 min"
            })

    for policy in iam["policies"]:
        if policy["wildcard_action"] and policy["wildcard_resource"]:
            findings.append({
                "id": f"IAM-004-{policy['name']}", "cis": "CIS 1.16", "severity": "CRITICAL",
                "title": f"Policy '{policy['name']}' grants Action:* Resource:* (full admin)",
                "resource": f"iam/policy/{policy['name']}",
                "fix": "Scope policy to minimum required actions and specific resource ARNs.",
                "effort": "2–4 hours"
            })

    return findings


def audit_s3(env: dict) -> list:
    findings = []
    for bucket in env["s3_buckets"]:
        name = bucket["name"]
        if not bucket["public_block"]:
            findings.append({
                "id": f"S3-001-{name[:16]}", "cis": "CIS 2.1.5", "severity": "CRITICAL",
                "title": f"S3 bucket '{name}' has no public access block",
                "resource": f"arn:aws:s3:::{name}",
                "fix": "Enable all 4 S3 Block Public Access settings. Audit ACLs and bucket policies.",
                "effort": "5 min"
            })
        if not bucket["encryption"]:
            findings.append({
                "id": f"S3-002-{name[:16]}", "cis": "CIS 2.1.1", "severity": "MEDIUM",
                "title": f"S3 bucket '{name}' has no default encryption",
                "resource": f"arn:aws:s3:::{name}",
                "fix": "Enable SSE-S3 or SSE-KMS as default encryption. Use KMS CMK for PII buckets.",
                "effort": "5 min"
            })
        if not bucket["logging"]:
            findings.append({
                "id": f"S3-003-{name[:16]}", "cis": "CIS 2.6", "severity": "LOW",
                "title": f"S3 bucket '{name}' has no access logging",
                "resource": f"arn:aws:s3:::{name}",
                "fix": "Enable server access logging to a central security bucket.",
                "effort": "5 min"
            })
    return findings


def audit_security_groups(env: dict) -> list:
    findings = []
    for sg in env["security_groups"]:
        if sg["all_traffic"]:
            findings.append({
                "id": f"SG-001-{sg['id']}", "cis": "CIS 5.2", "severity": "CRITICAL",
                "title": f"SG '{sg['name']}' ({sg['id']}) allows ALL inbound traffic from 0.0.0.0/0",
                "resource": f"ec2/security-group/{sg['id']}",
                "fix": "Delete the all-traffic rule. Add specific rules for only required ports and sources.",
                "effort": "10 min"
            })
        for port in sg["open_ports"]:
            if port in DANGEROUS_PORTS:
                service, sev = DANGEROUS_PORTS[port]
                findings.append({
                    "id": f"SG-002-{sg['id']}-{port}", "cis": "CIS 5.2", "severity": sev,
                    "title": f"SG '{sg['name']}' exposes {service} (port {port}) to 0.0.0.0/0",
                    "resource": f"ec2/security-group/{sg['id']}",
                    "fix": f"Restrict {service} to specific IP ranges or route through VPN/bastion host. Never expose to 0.0.0.0/0.",
                    "effort": "5 min"
                })
    return findings


def audit_cloudtrail(env: dict) -> list:
    findings = []
    ct = env["cloudtrail"]
    if not ct["multi_region"]:
        findings.append({
            "id": "CT-001", "cis": "CIS 3.1", "severity": "MEDIUM",
            "title": "CloudTrail is not multi-region",
            "resource": "aws/cloudtrail",
            "fix": "Update trail: aws cloudtrail update-trail --name <trail> --is-multi-region-trail",
            "effort": "5 min"
        })
    if not ct["log_validation"]:
        findings.append({
            "id": "CT-002", "cis": "CIS 3.2", "severity": "MEDIUM",
            "title": "CloudTrail log file validation is disabled",
            "resource": "aws/cloudtrail",
            "fix": "Enable: aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
            "effort": "2 min"
        })
    return findings


# ─────────────────────────────────────────────
# EXERCISE 3: Risk Scoring
# ─────────────────────────────────────────────

SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 7.5, "MEDIUM": 5, "LOW": 2.5}
CATEGORY_WEIGHT = {"IAM": 1.3, "S3": 1.2, "SG": 1.2, "CT": 1.0}

def score_findings(findings: list, env: str = "production") -> list:
    env_mult = {"production": 1.5, "staging": 1.0, "dev": 0.6}.get(env, 1.0)
    for f in findings:
        cat = f["id"].split("-")[0]
        base = SEVERITY_SCORE.get(f["severity"], 2.5)
        weight = CATEGORY_WEIGHT.get(cat, 1.0)
        f["risk_score"] = round(base * weight * env_mult, 1)
    return sorted(findings, key=lambda x: -x["risk_score"])


# ─────────────────────────────────────────────
# EXERCISE 4: Remediation Planning
# ─────────────────────────────────────────────

def generate_remediation_plan(findings: list) -> dict:
    immediate    = [f for f in findings if f["severity"] == "CRITICAL"]
    this_week    = [f for f in findings if f["severity"] == "HIGH"]
    this_month   = [f for f in findings if f["severity"] == "MEDIUM"]
    backlog      = [f for f in findings if f["severity"] == "LOW"]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "phases": {
            "IMMEDIATE (24h)": {
                "count": len(immediate),
                "items": [{"title": f["title"], "score": f["risk_score"], "effort": f["effort"]} for f in immediate]
            },
            "THIS WEEK (7d)": {
                "count": len(this_week),
                "items": [{"title": f["title"], "score": f["risk_score"], "effort": f["effort"]} for f in this_week]
            },
            "THIS MONTH (30d)": {
                "count": len(this_month),
                "items": [{"title": f["title"], "score": f["risk_score"], "effort": f["effort"]} for f in this_month]
            },
            "BACKLOG": {
                "count": len(backlog),
                "items": [{"title": f["title"], "score": f["risk_score"], "effort": f["effort"]} for f in backlog]
            }
        }
    }


# ─────────────────────────────────────────────
# CHALLENGE: Spot the Hidden Finding
# ─────────────────────────────────────────────

CHALLENGE_ENV = {
    **MOCK_AWS_ENV,
    "s3_buckets": MOCK_AWS_ENV["s3_buckets"] + [
        {"name": "cloudtrail-logs-backup", "public_block": False, "encryption": True, "logging": True},
    ],
    "iam": {
        **MOCK_AWS_ENV["iam"],
        "users": MOCK_AWS_ENV["iam"]["users"] + [
            {"name": "service-account-prod", "console": False, "mfa": False, "key_age_days": 0},
        ],
        "policies": MOCK_AWS_ENV["iam"]["policies"] + [
            {"name": "LambdaFullAccess", "wildcard_action": True, "wildcard_resource": False},
        ]
    }
}


def run_lab():
    print(BANNER)
    out = Path("lab2_output")
    out.mkdir(exist_ok=True)

    print("[EXERCISE 1] Inspecting simulated AWS environment")
    print("─" * 55)
    print(f"  Account : {MOCK_AWS_ENV['account_id']}")
    print(f"  Region  : {MOCK_AWS_ENV['region']}")
    print(f"  Env     : {MOCK_AWS_ENV['environment'].upper()}")
    print(f"  Users   : {len(MOCK_AWS_ENV['iam']['users'])}")
    print(f"  Buckets : {len(MOCK_AWS_ENV['s3_buckets'])}")
    print(f"  Sec grps: {len(MOCK_AWS_ENV['security_groups'])}\n")

    print("[EXERCISE 2] Running CIS Benchmark Audit")
    print("─" * 55)
    all_findings = []
    all_findings += audit_iam(MOCK_AWS_ENV)
    all_findings += audit_s3(MOCK_AWS_ENV)
    all_findings += audit_security_groups(MOCK_AWS_ENV)
    all_findings += audit_cloudtrail(MOCK_AWS_ENV)
    print(f"  Raw findings: {len(all_findings)}\n")

    print("[EXERCISE 3] Risk Scoring")
    print("─" * 55)
    scored = score_findings(all_findings, MOCK_AWS_ENV["environment"])
    by_sev = {}
    for f in scored:
        s = f["severity"]
        by_sev[s] = by_sev.get(s, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = by_sev.get(sev, 0)
        bar = "█" * count
        print(f"  {sev:<10} {bar} ({count})")

    print(f"\n  Top 3 highest risk:")
    for f in scored[:3]:
        print(f"    [{f['risk_score']:5.1f}] {f['title'][:60]}")

    print("\n[EXERCISE 4] Remediation Plan")
    print("─" * 55)
    plan = generate_remediation_plan(scored)
    for phase, data in plan["phases"].items():
        print(f"\n  {phase} — {data['count']} items")
        for item in data["items"]:
            print(f"    • [Score {item['score']:.1f}] {item['title'][:55]}")
            print(f"      Effort: {item['effort']}")

    # Save outputs
    json_path = out / "audit_findings.json"
    with open(json_path, "w") as f:
        json.dump({"findings": scored, "plan": plan}, f, indent=2)
    print(f"\n  ✓ Full report saved: {json_path}")

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  CHALLENGE: Run the audit on CHALLENGE_ENV              ║
║  Hint: 3 additional findings are hidden in it           ║
║  Edit this script — replace MOCK_AWS_ENV with           ║
║  CHALLENGE_ENV in run_lab() and re-run.                 ║
╠══════════════════════════════════════════════════════════╣
║  Key Concepts Covered:                                  ║
║  • CIS AWS Foundations Benchmark v1.5                   ║
║  • IAM, S3, SG, CloudTrail security checks              ║
║  • CVSS-inspired risk scoring with env multipliers      ║
║  • Prioritized remediation planning                     ║
╚══════════════════════════════════════════════════════════╝""")


if __name__ == "__main__":
    run_lab()
