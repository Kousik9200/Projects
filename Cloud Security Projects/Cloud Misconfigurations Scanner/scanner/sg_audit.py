#!/usr/bin/env python3
"""
sg_audit.py - AWS Security Group Auditor
Checks EC2 security group rules for overly permissive configurations.

Author: Kousik Gunasekaran
"""

import logging
from datetime import datetime, timezone
from typing import Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Ports that should never be open to the internet
SENSITIVE_PORTS = {
    22:   ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    1433: ("MSSQL", "HIGH"),
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    27017:("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch HTTP", "HIGH"),
    9300: ("Elasticsearch Transport", "HIGH"),
    2181: ("Zookeeper", "MEDIUM"),
    8080: ("HTTP Alt", "MEDIUM"),
    8443: ("HTTPS Alt", "MEDIUM"),
    21:   ("FTP", "HIGH"),
    23:   ("Telnet", "CRITICAL"),
    25:   ("SMTP", "MEDIUM"),
    445:  ("SMB", "CRITICAL"),
    135:  ("MSRPC", "HIGH"),
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def get_ec2_client(profile: Optional[str] = None, region: str = "us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("ec2", region_name=region)


def is_rule_open_to_internet(ip_ranges: list, ipv6_ranges: list) -> bool:
    """Check if any IP range allows access from the public internet."""
    for r in ip_ranges:
        if r.get("CidrIp") in PUBLIC_CIDRS:
            return True
    for r in ipv6_ranges:
        if r.get("CidrIpv6") in PUBLIC_CIDRS:
            return True
    return False


def check_open_ports(ec2_client, sg: dict) -> list:
    """Check inbound rules for dangerous open ports."""
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)
    vpc_id = sg.get("VpcId", "unknown")

    for rule in sg.get("IpPermissions", []):
        ip_proto = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        ip_ranges = rule.get("IpRanges", [])
        ipv6_ranges = rule.get("Ipv6Ranges", [])

        if not is_rule_open_to_internet(ip_ranges, ipv6_ranges):
            continue

        # All traffic open (protocol = -1)
        if ip_proto == "-1":
            findings.append({
                "finding_id": f"SG-001-{sg_id}",
                "cis_control": "CIS AWS 5.2",
                "resource": f"arn:aws:ec2:::security-group/{sg_id}",
                "title": f"Security group '{sg_name}' allows ALL inbound traffic from internet",
                "severity": "CRITICAL",
                "description": f"Security group {sg_id} ({sg_name}) in VPC {vpc_id} allows all inbound traffic (0.0.0.0/0, all ports, all protocols).",
                "remediation": "Remove the all-traffic inbound rule. Specify only required protocols and ports with restricted CIDRs.",
                "detected_at": datetime.now(timezone.utc).isoformat()
            })
            continue

        # Specific sensitive port open
        for port_num, (service_name, severity) in SENSITIVE_PORTS.items():
            if from_port <= port_num <= to_port:
                findings.append({
                    "finding_id": f"SG-002-{sg_id}-{port_num}",
                    "cis_control": "CIS AWS 5.2",
                    "resource": f"arn:aws:ec2:::security-group/{sg_id}",
                    "title": f"Security group '{sg_name}' exposes port {port_num} ({service_name}) to internet",
                    "severity": severity,
                    "description": f"Inbound rule allows {service_name} (port {port_num}) from 0.0.0.0/0. Service: {service_name}.",
                    "remediation": f"Restrict {service_name} access to specific IP ranges or use a VPN/bastion host. Never expose {service_name} directly to 0.0.0.0/0.",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })

    return findings


def check_all_traffic_egress(ec2_client, sg: dict) -> list:
    """Flag security groups with unrestricted outbound (data exfiltration risk)."""
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)

    for rule in sg.get("IpPermissionsEgress", []):
        if rule.get("IpProtocol") == "-1":
            for r in rule.get("IpRanges", []):
                if r.get("CidrIp") == "0.0.0.0/0":
                    findings.append({
                        "finding_id": f"SG-003-{sg_id}",
                        "cis_control": "CIS AWS 5.4",
                        "resource": f"arn:aws:ec2:::security-group/{sg_id}",
                        "title": f"Security group '{sg_name}' allows unrestricted outbound traffic",
                        "severity": "LOW",
                        "description": "Unrestricted outbound traffic can enable data exfiltration or C2 communication.",
                        "remediation": "Restrict outbound rules to only required ports and destinations. Apply egress filtering.",
                        "detected_at": datetime.now(timezone.utc).isoformat()
                    })
    return findings


def check_unused_security_groups(ec2_client) -> list:
    """Identify security groups not attached to any resource (cleanup candidates)."""
    findings = []
    try:
        all_sgs = {
            sg["GroupId"]: sg.get("GroupName", sg["GroupId"])
            for page in ec2_client.get_paginator("describe_security_groups").paginate()
            for sg in page["SecurityGroups"]
        }

        # Collect SGs in use by EC2 instances
        used_sgs = set()
        for page in ec2_client.get_paginator("describe_instances").paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    for sg in instance.get("SecurityGroups", []):
                        used_sgs.add(sg["GroupId"])

        for sg_id, sg_name in all_sgs.items():
            if sg_name == "default":
                continue
            if sg_id not in used_sgs:
                findings.append({
                    "finding_id": f"SG-004-{sg_id}",
                    "cis_control": "Security hygiene",
                    "resource": f"arn:aws:ec2:::security-group/{sg_id}",
                    "title": f"Security group '{sg_name}' is not attached to any resource",
                    "severity": "LOW",
                    "description": "Unused security groups add complexity and may represent orphaned infrastructure.",
                    "remediation": "Review and remove unused security groups to reduce attack surface.",
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })
    except ClientError as e:
        logger.error(f"Unused SG check failed: {e}")
    return findings


def run_sg_audit(profile: Optional[str] = None, region: str = "us-east-1") -> list:
    """Run all security group audit checks."""
    logger.info(f"Starting security group audit in region {region}...")
    all_findings = []

    try:
        ec2 = get_ec2_client(profile, region)
        paginator = ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                all_findings += check_open_ports(ec2, sg)
                all_findings += check_all_traffic_egress(ec2, sg)

        all_findings += check_unused_security_groups(ec2)

    except NoCredentialsError:
        logger.error("No AWS credentials for security group audit.")
    except ClientError as e:
        logger.error(f"SG audit error: {e}")

    logger.info(f"Security group audit complete: {len(all_findings)} findings")
    return all_findings
