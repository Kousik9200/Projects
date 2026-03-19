#!/usr/bin/env python3
"""
cloudtrail_audit.py - AWS CloudTrail Security Auditor
Verifies CloudTrail logging is correctly configured per CIS AWS Foundations Benchmark.

Author: Kousik Gunasekaran
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


def get_clients(profile: Optional[str], region: str):
    session = boto3.Session(profile_name=profile, region_name=region)
    return (
        session.client("cloudtrail", region_name=region),
        session.client("s3"),
        session.client("cloudwatch", region_name=region),
        session.client("logs", region_name=region)
    )


def check_trail_enabled(ct_client) -> list:
    """CIS 3.1 - Ensure CloudTrail is enabled in all regions."""
    findings = []
    try:
        trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            findings.append({
                "finding_id": "CT-001",
                "cis_control": "CIS AWS 3.1",
                "resource": "aws:cloudtrail",
                "title": "No CloudTrail trails found in this region",
                "severity": "CRITICAL",
                "description": "CloudTrail is not configured. All API activity is unlogged — forensic investigation would be impossible.",
                "remediation": "Enable a multi-region CloudTrail trail that captures all management events. Store logs in a dedicated S3 bucket.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
            return findings

        for trail in trails:
            trail_name = trail.get("Name")
            is_multi_region = trail.get("IsMultiRegionTrail", False)
            is_logging = False

            try:
                status = ct_client.get_trail_status(Name=trail["TrailARN"])
                is_logging = status.get("IsLogging", False)
            except ClientError:
                pass

            if not is_logging:
                findings.append({
                    "finding_id": f"CT-001-{trail_name}",
                    "cis_control": "CIS AWS 3.1",
                    "resource": trail.get("TrailARN", trail_name),
                    "title": f"CloudTrail trail '{trail_name}' is not actively logging",
                    "severity": "CRITICAL",
                    "description": "The trail exists but logging is disabled. API calls are not being recorded.",
                    "remediation": "Enable logging on the trail via console or CLI: aws cloudtrail start-logging --name <trail-name>",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })

            if not is_multi_region:
                findings.append({
                    "finding_id": f"CT-002-{trail_name}",
                    "cis_control": "CIS AWS 3.1",
                    "resource": trail.get("TrailARN", trail_name),
                    "title": f"CloudTrail trail '{trail_name}' is not multi-region",
                    "severity": "MEDIUM",
                    "description": "Single-region trail misses activity in other regions. Attackers often pivot to less-monitored regions.",
                    "remediation": "Update trail to IsMultiRegionTrail=true. Ensure all regions write to the same S3 bucket.",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })

    except ClientError as e:
        logger.error(f"CloudTrail enabled check failed: {e}")
    return findings


def check_log_file_validation(ct_client) -> list:
    """CIS 3.2 - Ensure CloudTrail log file validation is enabled."""
    findings = []
    try:
        trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            if not trail.get("LogFileValidationEnabled", False):
                findings.append({
                    "finding_id": f"CT-003-{trail['Name']}",
                    "cis_control": "CIS AWS 3.2",
                    "resource": trail.get("TrailARN", trail["Name"]),
                    "title": f"CloudTrail trail '{trail['Name']}' does not have log file validation enabled",
                    "severity": "MEDIUM",
                    "description": "Without log file validation, tampered or deleted log files cannot be detected.",
                    "remediation": "Enable log file validation: aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })
    except ClientError as e:
        logger.error(f"Log file validation check failed: {e}")
    return findings


def check_cloudtrail_s3_not_public(ct_client, s3_client) -> list:
    """CIS 3.3 - Ensure CloudTrail S3 bucket is not publicly accessible."""
    findings = []
    try:
        trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            bucket_name = trail.get("S3BucketName")
            if not bucket_name:
                continue

            try:
                config = s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
                if not all([
                    config.get("BlockPublicAcls"),
                    config.get("IgnorePublicAcls"),
                    config.get("BlockPublicPolicy"),
                    config.get("RestrictPublicBuckets")
                ]):
                    findings.append({
                        "finding_id": f"CT-004-{bucket_name[:20]}",
                        "cis_control": "CIS AWS 3.3",
                        "resource": f"arn:aws:s3:::{bucket_name}",
                        "title": f"CloudTrail S3 bucket '{bucket_name}' may be publicly accessible",
                        "severity": "CRITICAL",
                        "description": "The S3 bucket storing CloudTrail logs does not have all public access block settings enabled.",
                        "remediation": "Enable all S3 Block Public Access settings on the CloudTrail log bucket.",
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    })
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "finding_id": f"CT-004-{bucket_name[:20]}",
                        "cis_control": "CIS AWS 3.3",
                        "resource": f"arn:aws:s3:::{bucket_name}",
                        "title": f"CloudTrail S3 bucket '{bucket_name}' has no public access block configuration",
                        "severity": "CRITICAL",
                        "description": "No S3 Block Public Access config on CloudTrail log bucket.",
                        "remediation": "Apply S3 Block Public Access settings to the CloudTrail log bucket immediately.",
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    })
    except ClientError as e:
        logger.error(f"CloudTrail S3 public check failed: {e}")
    return findings


def check_cloudwatch_alarms(ct_client, logs_client, cw_client) -> list:
    """CIS 3.x - Ensure CloudWatch alarms exist for critical API calls."""
    findings = []

    REQUIRED_ALARM_FILTERS = {
        "root_login": '{ $.userIdentity.type = "Root" && $.eventType != "AwsServiceEvent" }',
        "iam_policy_changes": '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) }',
        "console_login_without_mfa": '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
        "cloudtrail_config_changes": '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StopLogging) || ($.eventName = StartLogging) }',
        "s3_policy_changes": '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = DeleteBucketPolicy)) }',
    }

    try:
        log_groups = logs_client.describe_log_groups().get("logGroups", [])
        log_group_names = {lg["logGroupName"] for lg in log_groups}

        # Check if any trail is connected to CloudWatch Logs
        trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
        trail_log_groups = set()
        for trail in trails:
            if lg := trail.get("CloudWatchLogsLogGroupArn"):
                name = lg.split(":")[6] if len(lg.split(":")) > 6 else lg
                trail_log_groups.add(name)

        if not trail_log_groups:
            findings.append({
                "finding_id": "CT-005",
                "cis_control": "CIS AWS 3.4",
                "resource": "aws:cloudwatch",
                "title": "CloudTrail is not integrated with CloudWatch Logs",
                "severity": "HIGH",
                "description": "Without CloudWatch Logs integration, real-time alerting on API events is not possible.",
                "remediation": "Configure CloudTrail to send logs to a CloudWatch Log Group, then create metric filters and alarms.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
        else:
            # Check for metric filters per required pattern
            for alarm_name, filter_pattern in REQUIRED_ALARM_FILTERS.items():
                found = False
                try:
                    for lg_name in trail_log_groups:
                        filters = logs_client.describe_metric_filters(
                            logGroupName=lg_name
                        ).get("metricFilters", [])
                        for f in filters:
                            if any(k in f.get("filterPattern", "") for k in ["Root", "ConsoleLogin", "DeleteTrail", "PutBucketPolicy", "DeleteGroupPolicy"]):
                                found = True
                                break
                except ClientError:
                    pass

                if not found:
                    findings.append({
                        "finding_id": f"CT-006-{alarm_name}",
                        "cis_control": "CIS AWS 3.x",
                        "resource": "aws:cloudwatch",
                        "title": f"No CloudWatch alarm configured for: {alarm_name.replace('_', ' ')}",
                        "severity": "MEDIUM",
                        "description": f"CIS benchmark requires a CloudWatch metric filter and alarm for: {alarm_name}",
                        "remediation": f"Create a CloudWatch metric filter with pattern: {filter_pattern[:100]}... and attach an alarm with SNS notification.",
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    })

    except ClientError as e:
        logger.error(f"CloudWatch alarm check failed: {e}")
    return findings


def run_cloudtrail_audit(profile: Optional[str] = None, region: str = "us-east-1") -> list:
    """Run all CloudTrail audit checks."""
    logger.info(f"Starting CloudTrail audit in region {region}...")
    all_findings = []

    try:
        ct, s3, cw, logs = get_clients(profile, region)
        all_findings += check_trail_enabled(ct)
        all_findings += check_log_file_validation(ct)
        all_findings += check_cloudtrail_s3_not_public(ct, s3)
        all_findings += check_cloudwatch_alarms(ct, logs, cw)
    except NoCredentialsError:
        logger.error("No AWS credentials for CloudTrail audit.")

    logger.info(f"CloudTrail audit complete: {len(all_findings)} findings")
    return all_findings
