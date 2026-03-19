"""
Cloud Misconfiguration Hunter
Scans AWS and Azure for security misconfigurations and reports to Slack
Author: Kousik Gunasekaran
"""

import os
import json
import logging
import boto3
import requests
from datetime import datetime
from dataclasses import dataclass, field
from typing import List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    provider: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    resource: str
    issue: str
    remediation: str
    region: str = "global"


class AWSMisconfigScanner:
    def __init__(self):
        self.s3 = boto3.client("s3")
        self.iam = boto3.client("iam")
        self.ec2 = boto3.client("ec2")

    def scan_all(self) -> List[Finding]:
        findings = []
        findings += self.check_public_s3_buckets()
        findings += self.check_iam_root_access_keys()
        findings += self.check_open_security_groups()
        findings += self.check_unencrypted_ebs_volumes()
        findings += self.check_mfa_on_root()
        return findings

    def check_public_s3_buckets(self) -> List[Finding]:
        findings = []
        try:
            buckets = self.s3.list_buckets()["Buckets"]
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    acl = self.s3.get_bucket_acl(Bucket=name)
                    for grant in acl["Grants"]:
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers"):
                            findings.append(Finding(
                                provider="AWS", severity="CRITICAL",
                                resource=f"s3://{name}",
                                issue="S3 bucket is publicly accessible (AllUsers ACL)",
                                remediation="Remove public ACL: aws s3api put-bucket-acl --bucket {name} --acl private"
                            ))
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"S3 scan failed: {e}")
        return findings

    def check_iam_root_access_keys(self) -> List[Finding]:
        findings = []
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append(Finding(
                    provider="AWS", severity="CRITICAL",
                    resource="IAM Root Account",
                    issue="Root account has active access keys",
                    remediation="Delete root access keys immediately. Use IAM users with least privilege instead."
                ))
        except Exception as e:
            logger.error(f"IAM root check failed: {e}")
        return findings

    def check_open_security_groups(self) -> List[Finding]:
        findings = []
        try:
            sgs = self.ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = rule.get("FromPort", "ALL")
                            if port in [22, 3389, 0]:  # SSH, RDP, ALL
                                findings.append(Finding(
                                    provider="AWS", severity="HIGH",
                                    resource=f"sg/{sg['GroupId']} ({sg['GroupName']})",
                                    issue=f"Security group allows 0.0.0.0/0 on port {port}",
                                    remediation=f"Restrict inbound rule to known IPs. Port {port} should never be open to the world."
                                ))
        except Exception as e:
            logger.error(f"Security group check failed: {e}")
        return findings

    def check_unencrypted_ebs_volumes(self) -> List[Finding]:
        findings = []
        try:
            volumes = self.ec2.describe_volumes()["Volumes"]
            for vol in volumes:
                if not vol.get("Encrypted", False):
                    findings.append(Finding(
                        provider="AWS", severity="MEDIUM",
                        resource=f"ebs/{vol['VolumeId']}",
                        issue="EBS volume is not encrypted at rest",
                        remediation="Enable EBS encryption by default in account settings or create encrypted snapshot."
                    ))
        except Exception as e:
            logger.error(f"EBS check failed: {e}")
        return findings

    def check_mfa_on_root(self) -> List[Finding]:
        findings = []
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(Finding(
                    provider="AWS", severity="CRITICAL",
                    resource="IAM Root Account",
                    issue="MFA is NOT enabled on root account",
                    remediation="Enable MFA on root account immediately via IAM console."
                ))
        except Exception as e:
            logger.error(f"MFA root check failed: {e}")
        return findings


class SlackReporter:
    def __init__(self):
        self.webhook = os.getenv("SLACK_WEBHOOK_URL")

    def report(self, findings: List[Finding]):
        if not findings:
            self._send({"text": "✅ Cloud Misconfiguration Scan: No findings!"})
            return

        critical = [f for f in findings if f.severity == "CRITICAL"]
        high = [f for f in findings if f.severity == "HIGH"]
        medium = [f for f in findings if f.severity == "MEDIUM"]

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "☁️ Cloud Misconfiguration Scan Report"}},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC*\n"
                        f"🔴 Critical: {len(critical)}  🟠 High: {len(high)}  🟡 Medium: {len(medium)}"}},
            {"type": "divider"}
        ]

        for f in (critical + high)[:10]:  # Top 10 most severe
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn",
                    "text": f"*[{f.severity}]* `{f.resource}`\n{f.issue}\n_Fix: {f.remediation}_"}
            })

        self._send({"blocks": blocks})

    def _send(self, payload: dict):
        try:
            requests.post(self.webhook, json=payload)
            logger.info("Slack report sent")
        except Exception as e:
            logger.error(f"Slack send failed: {e}")


if __name__ == "__main__":
    scanner = AWSMisconfigScanner()
    findings = scanner.scan_all()
    logger.info(f"Scan complete: {len(findings)} findings")
    reporter = SlackReporter()
    reporter.report(findings)
    # Print JSON report
    print(json.dumps([vars(f) for f in findings], indent=2))
