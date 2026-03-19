#!/usr/bin/env python3
"""
main.py - Cloud Misconfiguration Scanner entry point
Orchestrates all audit modules and generates reports.

Usage:
    python main.py --profile my-aws-profile --region us-east-1 --env prod
    python main.py --mock                   # Run with simulated findings (no AWS creds needed)

Author: Kousik Gunasekaran
"""

import sys
import json
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from scanner.scorer import score_all_findings, generate_summary
from reporter.generate_report import render_html_report, save_json_report


def run_mock_scan(environment: str = "prod") -> list:
    """
    Return a realistic set of simulated findings for demo/testing
    when no AWS credentials are available.
    """
    mock_findings = [
        {
            "finding_id": "IAM-001",
            "cis_control": "CIS AWS 1.5",
            "resource": "root account",
            "title": "Root account MFA not enabled",
            "severity": "CRITICAL",
            "description": "The AWS root account does not have MFA enabled.",
            "remediation": "Enable MFA for the root account via IAM console using a hardware MFA device.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "IAM-003-AdminFullAccess",
            "cis_control": "CIS AWS 1.16",
            "resource": "arn:aws:iam::123456789012:policy/AdminFullAccess",
            "title": "IAM policy 'AdminFullAccess' grants full admin (Action:* Resource:*)",
            "severity": "CRITICAL",
            "description": "This policy grants unrestricted access to all AWS services and resources.",
            "remediation": "Apply least privilege. Replace wildcard permissions with specific actions required.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "IAM-002-dev-john",
            "cis_control": "CIS AWS 1.10",
            "resource": "iam/user/dev-john",
            "title": "IAM user 'dev-john' has console access but no MFA",
            "severity": "HIGH",
            "description": "User dev-john can log into AWS console but has no MFA device configured.",
            "remediation": "Require MFA for user dev-john. Add MFA enforcement policy or SCP.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "S3-001-prod-customer-data",
            "cis_control": "CIS AWS 2.1.5",
            "resource": "arn:aws:s3:::prod-customer-data",
            "title": "S3 bucket 'prod-customer-data' has no public access block configuration",
            "severity": "CRITICAL",
            "description": "No S3 Block Public Access configuration exists for this production data bucket.",
            "remediation": "Apply all four S3 Block Public Access settings at the bucket and account level.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "S3-002-prod-customer-data",
            "cis_control": "CIS AWS 2.1.5",
            "resource": "arn:aws:s3:::prod-customer-data",
            "title": "S3 bucket 'prod-customer-data' ACL grants READ to public internet",
            "severity": "CRITICAL",
            "description": "Bucket ACL grants READ permission to AllUsers (public internet).",
            "remediation": "Remove public grants from bucket ACL. Use bucket policies with specific principals.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "S3-004-logs-archive",
            "cis_control": "CIS AWS 2.1.1",
            "resource": "arn:aws:s3:::logs-archive-2024",
            "title": "S3 bucket 'logs-archive-2024' does not have default encryption",
            "severity": "MEDIUM",
            "description": "Server-side encryption is not configured as default for this bucket.",
            "remediation": "Enable default encryption using SSE-S3 or SSE-KMS.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "SG-001-sg-0abc12345",
            "cis_control": "CIS AWS 5.2",
            "resource": "arn:aws:ec2:::security-group/sg-0abc12345",
            "title": "Security group 'prod-web-sg' allows ALL inbound traffic from internet",
            "severity": "CRITICAL",
            "description": "Security group sg-0abc12345 (prod-web-sg) allows all inbound traffic (0.0.0.0/0).",
            "remediation": "Remove the all-traffic rule. Allow only required ports with restricted CIDRs.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "SG-002-sg-0def67890-22",
            "cis_control": "CIS AWS 5.2",
            "resource": "arn:aws:ec2:::security-group/sg-0def67890",
            "title": "Security group 'bastion-sg' exposes port 22 (SSH) to internet",
            "severity": "CRITICAL",
            "description": "Inbound rule allows SSH (port 22) from 0.0.0.0/0.",
            "remediation": "Restrict SSH to specific admin IP ranges or use AWS Systems Manager Session Manager.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "SG-002-sg-0ghi11111-3306",
            "cis_control": "CIS AWS 5.2",
            "resource": "arn:aws:ec2:::security-group/sg-0ghi11111",
            "title": "Security group 'rds-sg' exposes port 3306 (MySQL) to internet",
            "severity": "HIGH",
            "description": "MySQL port 3306 is directly accessible from 0.0.0.0/0.",
            "remediation": "Place RDS in private subnets. Allow 3306 only from application security groups.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "CT-001",
            "cis_control": "CIS AWS 3.1",
            "resource": "aws:cloudtrail",
            "title": "CloudTrail trail 'prod-trail' is not multi-region",
            "severity": "MEDIUM",
            "description": "Single-region trail misses API activity in other AWS regions.",
            "remediation": "Update trail to IsMultiRegionTrail=true to capture events across all regions.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "CT-003-prod-trail",
            "cis_control": "CIS AWS 3.2",
            "resource": "arn:aws:cloudtrail:us-east-1:123456789012:trail/prod-trail",
            "title": "CloudTrail trail 'prod-trail' does not have log file validation enabled",
            "severity": "MEDIUM",
            "description": "Without log file validation, tampered log files cannot be detected.",
            "remediation": "Enable log file validation: aws cloudtrail update-trail --enable-log-file-validation",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "CT-006-root_login",
            "cis_control": "CIS AWS 3.x",
            "resource": "aws:cloudwatch",
            "title": "No CloudWatch alarm configured for: root login",
            "severity": "MEDIUM",
            "description": "CIS benchmark requires a CloudWatch alarm to alert on root account console logins.",
            "remediation": "Create a metric filter and SNS alarm for root login events in CloudTrail.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "IAM-004-AKIA12345678",
            "cis_control": "CIS AWS 1.14",
            "resource": "iam/user/ci-deploy/key/AKIA12345678...",
            "title": "Access key for 'ci-deploy' is 127 days old",
            "severity": "MEDIUM",
            "description": "Access key has not been rotated in 127 days (threshold: 90 days).",
            "remediation": "Rotate access keys for ci-deploy. Create new key, update CI/CD, then deactivate old key.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "S3-005-dev-assets",
            "cis_control": "CIS AWS 2.6",
            "resource": "arn:aws:s3:::dev-assets-bucket",
            "title": "S3 bucket 'dev-assets-bucket' does not have access logging enabled",
            "severity": "LOW",
            "description": "S3 access logging is not configured. Unauthorized access attempts are unlogged.",
            "remediation": "Enable S3 server access logging directed to a centralized security bucket.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "finding_id": "SG-004-sg-0orphan999",
            "cis_control": "Security hygiene",
            "resource": "arn:aws:ec2:::security-group/sg-0orphan999",
            "title": "Security group 'old-test-sg' is not attached to any resource",
            "severity": "LOW",
            "description": "Unused security groups add complexity and may represent orphaned infrastructure.",
            "remediation": "Review and delete unused security groups to reduce attack surface.",
            "detected_at": datetime.now(timezone.utc).isoformat()
        },
    ]
    return mock_findings


def run_live_scan(profile: str, region: str) -> list:
    """Run all live AWS audit modules."""
    from scanner.iam_audit import run_iam_audit
    from scanner.s3_audit import run_s3_audit
    from scanner.sg_audit import run_sg_audit
    from scanner.cloudtrail_audit import run_cloudtrail_audit

    all_findings = []
    all_findings += run_iam_audit(profile=profile, region=region)
    all_findings += run_s3_audit(profile=profile, region=region)
    all_findings += run_sg_audit(profile=profile, region=region)
    all_findings += run_cloudtrail_audit(profile=profile, region=region)
    return all_findings


def print_console_summary(findings: list, summary: dict):
    """Print a clean console summary."""
    COLORS = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM": "\033[33m",   "LOW": "\033[36m",
        "RESET": "\033[0m",     "BOLD": "\033[1m"
    }
    print(f"\n{COLORS['BOLD']}{'='*60}{COLORS['RESET']}")
    print(f"{COLORS['BOLD']}  Cloud Misconfiguration Scan — Summary{COLORS['RESET']}")
    print(f"{'='*60}")
    print(f"  Total findings : {summary['total']}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary["by_severity"].get(sev, 0)
        color = COLORS.get(sev, "")
        print(f"  {color}{sev:<10}{COLORS['RESET']}: {count}")
    print(f"{'='*60}")

    print(f"\n{COLORS['BOLD']}  Top Critical Findings:{COLORS['RESET']}")
    for f in findings[:5]:
        sev = f.get("severity", "")
        color = COLORS.get(sev, "")
        score = f.get("risk_score", 0)
        print(f"  {color}[{sev}]{COLORS['RESET']} (score {score}) {f['title'][:65]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--env", default="prod", choices=["prod","staging","dev","sandbox"])
    parser.add_argument("--mock", action="store_true", help="Run with mock findings (no AWS creds)")
    parser.add_argument("--jira", action="store_true", help="File Jira tickets for critical findings")
    parser.add_argument("--output-dir", default="output", help="Output directory for reports")
    args = parser.parse_args()

    logger.info("Starting Cloud Misconfiguration Scanner")
    logger.info(f"  Mode      : {'MOCK' if args.mock else 'LIVE'}")
    logger.info(f"  Region    : {args.region}")
    logger.info(f"  Environment: {args.env}")

    # Run scan
    if args.mock:
        raw_findings = run_mock_scan(args.env)
        account_id = "123456789012"
    else:
        raw_findings = run_live_scan(args.profile, args.region)
        account_id = "live-account"

    # Score and sort
    findings = score_all_findings(raw_findings, environment=args.env)
    summary  = generate_summary(findings)

    # Console output
    print_console_summary(findings, summary)

    # Save reports
    output_dir = Path(args.output_dir)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = save_json_report(findings, summary, output_dir / f"scan_report_{ts}.json")
    html_path = render_html_report(
        findings, summary,
        account_id=account_id,
        region=args.region,
        environment=args.env,
        output_path=output_dir / f"scan_report_{ts}.html"
    )

    if html_path:
        logger.info(f"HTML report: {html_path}")
    logger.info(f"JSON report: {json_path}")

    # Optional: file Jira tickets
    if args.jira:
        from integrations.jira_ticket import file_tickets_for_critical_findings
        tickets = file_tickets_for_critical_findings(findings, min_severity="HIGH")
        logger.info(f"Jira tickets filed: {len(tickets)}")

    return 0 if summary["by_severity"].get("CRITICAL", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
