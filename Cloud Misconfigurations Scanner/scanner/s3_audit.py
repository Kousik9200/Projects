#!/usr/bin/env python3
"""
s3_audit.py - AWS S3 Security Auditor
Checks S3 bucket configurations against CIS AWS Foundations Benchmark v1.5

Author: Kousik Gunasekaran
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


def get_s3_client(profile: Optional[str] = None, region: str = "us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("s3")


def check_bucket_public_access_block(s3_client, bucket_name: str) -> list:
    """CIS 2.1.5 - Ensure S3 bucket has block public access settings enabled."""
    findings = []
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        issues = []
        if not config.get("BlockPublicAcls"):
            issues.append("BlockPublicAcls is disabled")
        if not config.get("IgnorePublicAcls"):
            issues.append("IgnorePublicAcls is disabled")
        if not config.get("BlockPublicPolicy"):
            issues.append("BlockPublicPolicy is disabled")
        if not config.get("RestrictPublicBuckets"):
            issues.append("RestrictPublicBuckets is disabled")

        if issues:
            findings.append({
                "finding_id": f"S3-001-{bucket_name[:20]}",
                "cis_control": "CIS AWS 2.1.5",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "title": f"S3 bucket '{bucket_name}' has public access block misconfigured",
                "severity": "HIGH",
                "description": f"Public access block settings are not fully enabled: {', '.join(issues)}",
                "remediation": "Enable all four public access block settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append({
                "finding_id": f"S3-001-{bucket_name[:20]}",
                "cis_control": "CIS AWS 2.1.5",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "title": f"S3 bucket '{bucket_name}' has no public access block configuration",
                "severity": "CRITICAL",
                "description": "No S3 Block Public Access configuration exists for this bucket.",
                "remediation": "Apply S3 Block Public Access settings at both bucket and account level.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
    return findings


def check_bucket_acl(s3_client, bucket_name: str) -> list:
    """Check S3 bucket ACLs for public access grants."""
    findings = []
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                permission = grant.get("Permission", "UNKNOWN")
                audience = "public internet" if "AllUsers" in uri else "all authenticated AWS users"
                findings.append({
                    "finding_id": f"S3-002-{bucket_name[:20]}",
                    "cis_control": "CIS AWS 2.1.5",
                    "resource": f"arn:aws:s3:::{bucket_name}",
                    "title": f"S3 bucket '{bucket_name}' ACL grants {permission} to {audience}",
                    "severity": "CRITICAL",
                    "description": f"Bucket ACL grants {permission} permission to {audience}. This may expose sensitive data.",
                    "remediation": "Remove public grants from bucket ACL. Use bucket policies with specific principals instead.",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })
    except ClientError as e:
        logger.warning(f"Could not check ACL for {bucket_name}: {e}")
    return findings


def check_bucket_policy_public(s3_client, bucket_name: str) -> list:
    """Check S3 bucket policy for public principal (*)."""
    findings = []
    try:
        policy = json.loads(
            s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"]
        )
        for stmt in policy.get("Statement", []):
            effect = stmt.get("Effect", "Deny")
            principal = stmt.get("Principal", {})

            is_public = (
                principal == "*"
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
            )

            if effect == "Allow" and is_public:
                actions = stmt.get("Action", [])
                findings.append({
                    "finding_id": f"S3-003-{bucket_name[:20]}",
                    "cis_control": "CIS AWS 2.1.5",
                    "resource": f"arn:aws:s3:::{bucket_name}",
                    "title": f"S3 bucket '{bucket_name}' policy allows public principal",
                    "severity": "CRITICAL",
                    "description": f"Bucket policy has Principal:* with Effect:Allow for actions: {actions}",
                    "remediation": "Remove or restrict the wildcard Principal in the bucket policy. Use specific IAM ARNs.",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            logger.warning(f"Could not check policy for {bucket_name}: {e}")
    return findings


def check_bucket_encryption(s3_client, bucket_name: str) -> list:
    """CIS 2.1.1 - Ensure S3 bucket server-side encryption is enabled."""
    findings = []
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        logger.info(f"  [PASS] Encryption enabled on {bucket_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"):
            findings.append({
                "finding_id": f"S3-004-{bucket_name[:20]}",
                "cis_control": "CIS AWS 2.1.1",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "title": f"S3 bucket '{bucket_name}' does not have default encryption enabled",
                "severity": "MEDIUM",
                "description": "Server-side encryption is not configured as default for this bucket.",
                "remediation": "Enable default encryption using SSE-S3 or SSE-KMS. Use KMS CMK for regulated data.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
    return findings


def check_bucket_logging(s3_client, bucket_name: str) -> list:
    """CIS 2.6 - Ensure S3 bucket access logging is enabled."""
    findings = []
    try:
        logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in logging_config:
            findings.append({
                "finding_id": f"S3-005-{bucket_name[:20]}",
                "cis_control": "CIS AWS 2.6",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "title": f"S3 bucket '{bucket_name}' does not have access logging enabled",
                "severity": "LOW",
                "description": "S3 access logging is not configured. Without logging, unauthorized access attempts are invisible.",
                "remediation": "Enable S3 server access logging. Direct logs to a centralized security bucket.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
    except ClientError as e:
        logger.warning(f"Could not check logging for {bucket_name}: {e}")
    return findings


def run_s3_audit(profile: Optional[str] = None, region: str = "us-east-1") -> list:
    """Run all S3 audit checks across all buckets."""
    logger.info("Starting S3 audit...")
    all_findings = []

    try:
        s3 = get_s3_client(profile, region)
        buckets = s3.list_buckets().get("Buckets", [])
        logger.info(f"  Found {len(buckets)} S3 buckets to audit")

        for bucket in buckets:
            name = bucket["Name"]
            logger.info(f"  Auditing bucket: {name}")
            all_findings += check_bucket_public_access_block(s3, name)
            all_findings += check_bucket_acl(s3, name)
            all_findings += check_bucket_policy_public(s3, name)
            all_findings += check_bucket_encryption(s3, name)
            all_findings += check_bucket_logging(s3, name)

    except NoCredentialsError:
        logger.error("No AWS credentials found for S3 audit.")
    except ClientError as e:
        logger.error(f"S3 audit error: {e}")

    logger.info(f"S3 audit complete: {len(all_findings)} findings")
    return all_findings
