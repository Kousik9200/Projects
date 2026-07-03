"""
scanner.py — Cloud Security Hardening & Vulnerability Management Framework
Main orchestrator: runs IAM, secrets, and network checks; generates report.

Usage:
    python scanner.py --profile default --region us-east-1
    python scanner.py --demo          # runs with mock data (no AWS needed)
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

from iam_auditor    import IAMAuditor
from secrets_scanner import SecretsScanner
from report_generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ── Demo / mock mode ─────────────────────────────────────────────────────────

DEMO_FINDINGS = [
    {"severity": "CRITICAL", "check_id": "ROOT_NO_MFA",        "description": "Root account MFA not enabled",                      "remediation": "Enable MFA on root account",                          "reference": "CIS 1.5",  "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "CRITICAL", "check_id": "PUBLIC_S3_BUCKET",   "description": "S3 bucket 'prod-backups' is publicly accessible",   "remediation": "Enable Block Public Access",                          "resource":  "s3://prod-backups", "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "HIGH",     "check_id": "WILDCARD_POLICY",    "description": "Policy 'DevAccess' grants iam:* wildcard actions",  "remediation": "Scope down to minimum required IAM actions",          "reference": "CIS 1.16", "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "HIGH",     "check_id": "STALE_ACCESS_KEY",   "description": "Access key AKIAIOSFODNN7EXAMPLE is 120 days old",   "remediation": "Rotate or deactivate the access key",                 "reference": "CIS 1.14", "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "HIGH",     "check_id": "PLAINTEXT_SSM_PARAM","description": "SSM param '/prod/db/password' stored as plaintext", "remediation": "Convert to SecureString with KMS",                    "resource":  "ssm:/prod/db/password", "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "HIGH",     "check_id": "OPEN_SSH_PORT",      "description": "Security group 'sg-0abc' exposes port 22 to 0.0.0.0/0","remediation": "Restrict SSH to bastion host IP range",           "resource":  "sg-0abc", "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "MEDIUM",   "check_id": "INLINE_POLICY",      "description": "User 'dev-alice' has 2 inline policies",            "remediation": "Convert to customer-managed policies",                "reference": "CIS 1.16", "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "MEDIUM",   "check_id": "CLOUDTRAIL_DISABLED","description": "CloudTrail not enabled in eu-west-1",               "remediation": "Enable CloudTrail in all regions",                    "reference": "CIS 3.1",  "timestamp": datetime.now(timezone.utc).isoformat()},
    {"severity": "LOW",      "check_id": "NO_FLOW_LOGS",       "description": "VPC vpc-001 has no flow logs enabled",              "remediation": "Enable VPC Flow Logs to CloudWatch",                  "resource":  "vpc-001", "timestamp": datetime.now(timezone.utc).isoformat()},
]


def run_demo() -> list[dict]:
    log.info("Running in DEMO mode — no AWS credentials required")
    return DEMO_FINDINGS


# ── Live AWS scan ─────────────────────────────────────────────────────────────

def run_live_scan(profile: str, region: str) -> list[dict]:
    try:
        import boto3
        session    = boto3.Session(profile_name=profile, region_name=region)
        iam_client = session.client("iam")
        s3_client  = session.client("s3")
        ec2_client = session.client("ec2", region_name=region)
        ssm_client = session.client("ssm", region_name=region)
    except ImportError:
        log.error("boto3 not installed. Run: pip install boto3")
        sys.exit(1)

    findings: list[dict] = []

    log.info("Running IAM audit …")
    findings.extend(IAMAuditor(iam_client).run_all_checks())

    log.info("Running secrets scan …")
    findings.extend(SecretsScanner(s3_client, ec2_client, ssm_client).run_all_scans())

    return findings


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(findings: list[dict]):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\n" + "═" * 60)
    print("  CLOUD SECURITY SCAN SUMMARY")
    print("═" * 60)
    for sev, count in counts.items():
        bar = "█" * count
        print(f"  {sev:<10} {count:>3}  {bar}")
    print("═" * 60)
    print(f"  Total findings: {len(findings)}")
    print("═" * 60 + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cloud Security Hardening & Vuln Management Scanner")
    parser.add_argument("--profile", default="default",   help="AWS profile name")
    parser.add_argument("--region",  default="us-east-1", help="AWS region")
    parser.add_argument("--demo",    action="store_true",  help="Run with mock data (no AWS needed)")
    parser.add_argument("--output",  choices=["json", "html", "both"], default="both")
    args = parser.parse_args()

    findings = run_demo() if args.demo else run_live_scan(args.profile, args.region)

    print_summary(findings)

    rg = ReportGenerator(findings)
    if args.output in ("json", "both"):
        rg.save_json("scan_report.json")
    if args.output in ("html", "both"):
        rg.save_html("scan_report.html")


if __name__ == "__main__":
    main()
