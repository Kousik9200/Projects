"""
secrets_scanner.py — Secrets & Exposed Credential Scanner
Scans S3 buckets, environment variables, and EC2 user-data for exposed secrets.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# Secret patterns (regex)
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS_SECRET_KEY":    re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "PRIVATE_KEY":       re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GITHUB_TOKEN":      re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "SLACK_TOKEN":       re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,72}"),
    "GENERIC_PASSWORD":  re.compile(r"(?i)(password|passwd|secret|token|api_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
    "DATABASE_URL":      re.compile(r"(?i)(mysql|postgres|mongodb|redis):\/\/[^:\s]+:[^@\s]+@"),
}


class SecretsScanner:
    """Scans AWS resources for accidentally exposed secrets."""

    def __init__(self, s3_client, ec2_client, ssm_client):
        self.s3  = s3_client
        self.ec2 = ec2_client
        self.ssm = ssm_client
        self.findings: list[dict] = []

    def run_all_scans(self) -> list[dict]:
        log.info("Starting secrets scan …")
        self._scan_public_s3_buckets()
        self._scan_ec2_userdata()
        self._scan_ssm_parameters()
        log.info("Secrets scan complete — %d findings", len(self.findings))
        return self.findings

    # ── Scan targets ──────────────────────────────────────────────────────────

    def _scan_public_s3_buckets(self):
        """Check for public S3 buckets and scan their objects for secrets."""
        try:
            for bucket in self.s3.list_buckets().get("Buckets", []):
                name = bucket["Name"]
                acl  = self.s3.get_bucket_acl(Bucket=name)
                is_public = any(
                    grant["Grantee"].get("URI", "").endswith("/AllUsers")
                    for grant in acl.get("Grants", [])
                )
                if is_public:
                    self._add("CRITICAL", "PUBLIC_S3_BUCKET",
                              f"S3 bucket '{name}' is publicly accessible",
                              f"Enable Block Public Access on bucket '{name}'",
                              resource=f"s3://{name}")
                    self._scan_bucket_objects(name)
        except Exception as exc:
            log.warning("S3 scan failed: %s", exc)

    def _scan_bucket_objects(self, bucket: str):
        """Download and scan text objects for embedded secrets."""
        try:
            paginator = self.s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    key  = obj["Key"]
                    size = obj["Size"]
                    if size > 1_000_000 or not self._is_text_file(key):
                        continue
                    body = self.s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode(errors="ignore")
                    self._scan_text(body, resource=f"s3://{bucket}/{key}")
        except Exception as exc:
            log.warning("Object scan failed for %s: %s", bucket, exc)

    def _scan_ec2_userdata(self):
        """Scan EC2 instance user-data scripts for embedded credentials."""
        try:
            import base64
            instances = self.ec2.describe_instances()
            for res in instances.get("Reservations", []):
                for inst in res.get("Instances", []):
                    iid = inst["InstanceId"]
                    ud  = self.ec2.describe_instance_attribute(
                        InstanceId=iid, Attribute="userData"
                    ).get("UserData", {}).get("Value", "")
                    if ud:
                        decoded = base64.b64decode(ud).decode(errors="ignore")
                        self._scan_text(decoded, resource=f"ec2:userdata:{iid}")
        except Exception as exc:
            log.warning("EC2 user-data scan failed: %s", exc)

    def _scan_ssm_parameters(self):
        """Flag SSM parameters stored as String (not SecureString)."""
        try:
            paginator = self.ssm.get_paginator("describe_parameters")
            for page in paginator.paginate():
                for param in page.get("Parameters", []):
                    if param["Type"] == "String" and any(
                        kw in param["Name"].lower()
                        for kw in ("password", "secret", "key", "token", "credential")
                    ):
                        self._add("HIGH", "PLAINTEXT_SSM_PARAM",
                                  f"SSM parameter '{param['Name']}' stores sensitive data as plaintext String",
                                  "Convert to SecureString with KMS encryption",
                                  resource=f"ssm:{param['Name']}")
        except Exception as exc:
            log.warning("SSM scan failed: %s", exc)

    # ── Text scanner ──────────────────────────────────────────────────────────

    def _scan_text(self, text: str, resource: str):
        for pattern_name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                self._add("CRITICAL", f"EXPOSED_SECRET_{pattern_name}",
                          f"Potential {pattern_name} found in {resource}",
                          "Rotate the exposed credential immediately and remove from source",
                          resource=resource)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_text_file(key: str) -> bool:
        return key.endswith((".txt", ".env", ".json", ".yaml", ".yml",
                             ".sh", ".py", ".tf", ".conf", ".cfg", ".ini", ".xml"))

    def _add(self, severity: str, check_id: str, description: str,
             remediation: str, resource: str = ""):
        self.findings.append({
            "severity":    severity,
            "check_id":    check_id,
            "description": description,
            "remediation": remediation,
            "resource":    resource,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })
