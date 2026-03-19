#!/usr/bin/env python3
"""
iam_audit.py - AWS IAM Security Auditor
Checks IAM configurations against CIS AWS Foundations Benchmark v1.5

Author: Kousik Gunasekaran
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


def get_iam_client(profile: Optional[str] = None, region: str = "us-east-1"):
    """Create a boto3 IAM client."""
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("iam")


def check_root_mfa(iam_client) -> list:
    """CIS 1.5 - Ensure MFA is enabled for the root account."""
    findings = []
    try:
        summary = iam_client.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({
                "finding_id": "IAM-001",
                "cis_control": "CIS AWS 1.5",
                "resource": "root account",
                "title": "Root account MFA not enabled",
                "severity": "CRITICAL",
                "description": "The AWS root account does not have MFA enabled. Root account access without MFA is extremely high risk.",
                "remediation": "Enable MFA for the root account immediately via IAM console. Use a hardware MFA device for root accounts.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
        else:
            logger.info("  [PASS] Root account MFA is enabled")
    except ClientError as e:
        logger.error(f"IAM root MFA check failed: {e}")
    return findings


def check_user_mfa(iam_client) -> list:
    """CIS 1.10 - Ensure MFA is enabled for all IAM users with console access."""
    findings = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # Check if user has console access
                try:
                    iam_client.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console = False
                    else:
                        continue

                if not has_console:
                    continue

                # Check MFA devices
                mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa_devices:
                    findings.append({
                        "finding_id": f"IAM-002-{username}",
                        "cis_control": "CIS AWS 1.10",
                        "resource": f"iam/user/{username}",
                        "title": f"IAM user '{username}' has console access but no MFA",
                        "severity": "HIGH",
                        "description": f"User {username} can log into AWS console but has no MFA device configured.",
                        "remediation": f"Require MFA for user {username}. Add an MFA enforcement policy or use AWS Organizations SCP.",
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    })
                else:
                    logger.info(f"  [PASS] User {username} has MFA enabled")

    except ClientError as e:
        logger.error(f"User MFA check failed: {e}")
    return findings


def check_wildcard_policies(iam_client) -> list:
    """CIS 1.16 - Ensure IAM policies do not have full '*:*' administrative privileges."""
    findings = []
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):  # only customer-managed
            for policy in page["Policies"]:
                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                version_id = policy["DefaultVersionId"]

                try:
                    version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )["PolicyVersion"]["Document"]
                except ClientError:
                    continue

                statements = version.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    effect = stmt.get("Effect", "Deny")
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])

                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    if effect == "Allow" and "*" in actions and "*" in resources:
                        findings.append({
                            "finding_id": f"IAM-003-{policy_name}",
                            "cis_control": "CIS AWS 1.16",
                            "resource": policy_arn,
                            "title": f"IAM policy '{policy_name}' grants full admin (Action:* Resource:*)",
                            "severity": "CRITICAL",
                            "description": "This policy grants unrestricted access to all AWS services and resources.",
                            "remediation": "Apply least privilege. Replace wildcard permissions with specific actions and resources needed.",
                            "detected_at": datetime.now(timezone.utc).isoformat()
                        })

    except ClientError as e:
        logger.error(f"Wildcard policy check failed: {e}")
    return findings


def check_old_access_keys(iam_client, max_age_days: int = 90) -> list:
    """CIS 1.14 - Ensure access keys are rotated every 90 days or less."""
    findings = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]

                for key in keys:
                    if key["Status"] != "Active":
                        continue

                    created = key["CreateDate"]
                    age_days = (datetime.now(timezone.utc) - created).days

                    if age_days > max_age_days:
                        findings.append({
                            "finding_id": f"IAM-004-{key['AccessKeyId'][:8]}",
                            "cis_control": "CIS AWS 1.14",
                            "resource": f"iam/user/{username}/key/{key['AccessKeyId'][:8]}...",
                            "title": f"Access key for '{username}' is {age_days} days old",
                            "severity": "MEDIUM",
                            "description": f"Access key {key['AccessKeyId'][:8]}... has not been rotated in {age_days} days (threshold: {max_age_days}).",
                            "remediation": f"Rotate access keys for {username}. Create a new key, update applications, then deactivate and delete the old key.",
                            "detected_at": datetime.now(timezone.utc).isoformat()
                        })

    except ClientError as e:
        logger.error(f"Access key age check failed: {e}")
    return findings


def check_inactive_users(iam_client, inactive_days: int = 90) -> list:
    """CIS 1.12 - Ensure credentials unused for 90+ days are disabled."""
    findings = []
    try:
        report = iam_client.generate_credential_report()
        import time
        while report["State"] != "COMPLETE":
            time.sleep(2)
            report = iam_client.generate_credential_report()

        content = iam_client.get_credential_report()["Content"].decode("utf-8")
        lines = content.strip().split("\n")
        headers = lines[0].split(",")

        for line in lines[1:]:
            values = dict(zip(headers, line.split(",")))
            username = values.get("user", "")
            if username in ("<root_account>", "root"):
                continue

            password_last_used = values.get("password_last_used", "N/A")
            if password_last_used not in ("N/A", "no_information", "not_supported", ""):
                try:
                    last_used = datetime.strptime(password_last_used, "%Y-%m-%dT%H:%M:%S+00:00")
                    last_used = last_used.replace(tzinfo=timezone.utc)
                    days_inactive = (datetime.now(timezone.utc) - last_used).days
                    if days_inactive > inactive_days:
                        findings.append({
                            "finding_id": f"IAM-005-{username}",
                            "cis_control": "CIS AWS 1.12",
                            "resource": f"iam/user/{username}",
                            "title": f"IAM user '{username}' inactive for {days_inactive} days",
                            "severity": "MEDIUM",
                            "description": f"User {username} has not logged in for {days_inactive} days. Unused accounts increase attack surface.",
                            "remediation": f"Disable or remove user {username}. Confirm with the user's manager before deletion.",
                            "detected_at": datetime.now(timezone.utc).isoformat()
                        })
                except ValueError:
                    pass

    except ClientError as e:
        logger.error(f"Inactive user check failed: {e}")
    return findings


def run_iam_audit(profile: Optional[str] = None, region: str = "us-east-1") -> list:
    """Run all IAM audit checks and return combined findings."""
    logger.info("Starting IAM audit...")
    all_findings = []

    try:
        iam = get_iam_client(profile, region)
        all_findings += check_root_mfa(iam)
        all_findings += check_user_mfa(iam)
        all_findings += check_wildcard_policies(iam)
        all_findings += check_old_access_keys(iam)
        all_findings += check_inactive_users(iam)
    except NoCredentialsError:
        logger.error("No AWS credentials found. Configure via environment, ~/.aws/credentials, or IAM role.")

    logger.info(f"IAM audit complete: {len(all_findings)} findings")
    return all_findings
