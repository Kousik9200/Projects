"""
policy_engine.py — Security Guardrails & Policy Enforcement Framework
Policy-as-code engine: evaluates infrastructure resources against security policies
and blocks non-compliant deployments before they reach production.

Usage:
    python policy_engine.py --plan terraform.json           # evaluate a Terraform plan
    python policy_engine.py --demo                          # run with built-in mock plan
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


# ── Policy definition ─────────────────────────────────────────────────────────

@dataclass
class Policy:
    id:           str
    name:         str
    description:  str
    severity:     str          # CRITICAL | HIGH | MEDIUM | LOW
    frameworks:   list[str]    # NIST CSF, CIS, SOC 2, etc.
    check:        callable = field(repr=False)


@dataclass
class Violation:
    policy_id:    str
    severity:     str
    resource:     str
    description:  str
    remediation:  str
    frameworks:   list[str]


# ── Built-in policies ─────────────────────────────────────────────────────────

def _check_s3_public_access(resource: dict) -> tuple[bool, str]:
    cfg = resource.get("values", {})
    if cfg.get("bucket_public_access_block", {}).get("block_public_acls") is False:
        return False, "S3 bucket does not block public ACLs"
    return True, ""


def _check_encryption_at_rest(resource: dict) -> tuple[bool, str]:
    rtype = resource.get("type", "")
    vals  = resource.get("values", {})
    if "s3" in rtype:
        if not vals.get("server_side_encryption_configuration"):
            return False, "S3 bucket has no server-side encryption configured"
    if "rds" in rtype or "db_instance" in rtype:
        if not vals.get("storage_encrypted"):
            return False, "RDS instance has encryption at rest disabled"
    return True, ""


def _check_mfa_delete_s3(resource: dict) -> tuple[bool, str]:
    if "s3_bucket" not in resource.get("type", ""):
        return True, ""
    versioning = resource.get("values", {}).get("versioning", {})
    if versioning.get("enabled") and not versioning.get("mfa_delete"):
        return False, "S3 bucket versioning enabled but MFA delete is disabled"
    return True, ""


def _check_security_group_ssh(resource: dict) -> tuple[bool, str]:
    if "security_group" not in resource.get("type", ""):
        return True, ""
    for rule in resource.get("values", {}).get("ingress", []):
        if rule.get("from_port") == 22 and "0.0.0.0/0" in rule.get("cidr_blocks", []):
            return False, "Security group exposes SSH (port 22) to 0.0.0.0/0"
    return True, ""


def _check_logging_enabled(resource: dict) -> tuple[bool, str]:
    rtype = resource.get("type", "")
    vals  = resource.get("values", {})
    if "cloudtrail" in rtype and not vals.get("enable_log_file_validation"):
        return False, "CloudTrail log file validation is disabled"
    if "s3_bucket" in rtype and not vals.get("logging"):
        return False, "S3 bucket access logging is disabled"
    return True, ""


def _check_least_privilege_iam(resource: dict) -> tuple[bool, str]:
    if "iam_policy" not in resource.get("type", ""):
        return True, ""
    try:
        doc = json.loads(resource.get("values", {}).get("policy", "{}"))
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "*" in actions or "iam:*" in actions:
                    return False, f"IAM policy grants wildcard actions: {actions[:3]}"
    except (json.JSONDecodeError, TypeError):
        pass
    return True, ""


POLICIES: list[Policy] = [
    Policy("P001", "S3 Block Public Access",       "All S3 buckets must block public access",             "CRITICAL", ["CIS 2.1", "NIST CSF PR.AC-3"],  _check_s3_public_access),
    Policy("P002", "Encryption at Rest",            "Storage resources must be encrypted at rest",         "CRITICAL", ["CIS 2.3", "SOC 2 C1.1"],         _check_encryption_at_rest),
    Policy("P003", "S3 MFA Delete",                 "Versioned S3 buckets must require MFA delete",        "HIGH",     ["CIS 2.2"],                         _check_mfa_delete_s3),
    Policy("P004", "No SSH from 0.0.0.0/0",         "SSH must not be exposed to the public internet",      "CRITICAL", ["CIS 5.2", "NIST CSF PR.AC-5"],  _check_security_group_ssh),
    Policy("P005", "Logging Enabled",               "CloudTrail and S3 access logging must be enabled",   "HIGH",     ["CIS 3.1", "SOC 2 CC7.1"],         _check_logging_enabled),
    Policy("P006", "IAM Least Privilege",           "IAM policies must not use wildcard actions",          "HIGH",     ["CIS 1.16", "NIST CSF PR.AC-4"], _check_least_privilege_iam),
]


# ── Engine ────────────────────────────────────────────────────────────────────

class PolicyEngine:
    def __init__(self, policies: list[Policy] = None):
        self.policies   = policies or POLICIES
        self.violations: list[Violation] = []

    def evaluate(self, plan: dict) -> list[Violation]:
        """Evaluate all resources in a Terraform plan against all policies."""
        resources = self._extract_resources(plan)
        log.info("Evaluating %d resources against %d policies …", len(resources), len(self.policies))

        for resource in resources:
            for policy in self.policies:
                passed, reason = policy.check(resource)
                if not passed:
                    v = Violation(
                        policy_id=   policy.id,
                        severity=    policy.severity,
                        resource=    f"{resource.get('type','?')}.{resource.get('name','?')}",
                        description= reason,
                        remediation= f"Fix '{resource.get('name')}' to comply with: {policy.name}",
                        frameworks=  policy.frameworks,
                    )
                    self.violations.append(v)
                    log.warning("[%s] %s — %s", policy.severity, v.resource, reason)

        return self.violations

    def should_block(self) -> bool:
        """Return True if any CRITICAL violations exist (blocks deployment)."""
        return any(v.severity == "CRITICAL" for v in self.violations)

    @staticmethod
    def _extract_resources(plan: dict) -> list[dict]:
        """Extract planned resources from a Terraform JSON plan."""
        resources = []
        # terraform show -json format
        planned = plan.get("planned_values", {}).get("root_module", {}).get("resources", [])
        resources.extend(planned)
        # Also check child modules
        for module in plan.get("planned_values", {}).get("root_module", {}).get("child_modules", []):
            resources.extend(module.get("resources", []))
        return resources


# ── Mock plan (demo) ──────────────────────────────────────────────────────────

DEMO_PLAN = {
    "planned_values": {
        "root_module": {
            "resources": [
                {"type": "aws_s3_bucket",        "name": "app-data",     "values": {"bucket_public_access_block": {"block_public_acls": False}, "server_side_encryption_configuration": None, "logging": None}},
                {"type": "aws_security_group",   "name": "web-sg",       "values": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}},
                {"type": "aws_iam_policy",        "name": "dev-access",   "values": {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}]})}},
                {"type": "aws_cloudtrail",        "name": "main-trail",   "values": {"enable_log_file_validation": True}},
                {"type": "aws_db_instance",       "name": "prod-db",      "values": {"storage_encrypted": True}},
                {"type": "aws_s3_bucket",         "name": "logs-bucket",  "values": {"bucket_public_access_block": {"block_public_acls": True}, "server_side_encryption_configuration": {"rule": {}}, "logging": {"target_bucket": "audit-logs"}}},
            ]
        }
    }
}


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Security Guardrails & Policy Enforcement Engine")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", metavar="FILE", help="Path to terraform show -json output")
    group.add_argument("--demo", action="store_true", help="Run with built-in mock Terraform plan")
    args   = parser.parse_args()

    plan = DEMO_PLAN if args.demo else json.loads(open(args.plan).read())

    engine     = PolicyEngine()
    violations = engine.evaluate(plan)

    print(f"\n{'═'*65}")
    print("  POLICY ENFORCEMENT REPORT")
    print(f"{'═'*65}")
    if not violations:
        print("  ✅ All resources comply with security policies — deployment allowed.")
    else:
        counts = {}
        for v in violations:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts.get(sev):
                print(f"  {'🔴' if sev=='CRITICAL' else '🟠' if sev=='HIGH' else '🟡' if sev=='MEDIUM' else '🟢'} {sev}: {counts[sev]}")
        print()
        for v in violations:
            print(f"  [{v.severity}] {v.resource}")
            print(f"    Issue:       {v.description}")
            print(f"    Fix:         {v.remediation}")
            print(f"    Frameworks:  {', '.join(v.frameworks)}")
            print()

    if engine.should_block():
        print("  🚫 DEPLOYMENT BLOCKED — critical policy violations detected.")
        print(f"{'═'*65}\n")
        sys.exit(1)
    else:
        print(f"{'═'*65}\n")


if __name__ == "__main__":
    main()
