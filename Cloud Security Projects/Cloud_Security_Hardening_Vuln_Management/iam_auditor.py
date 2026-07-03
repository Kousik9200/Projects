"""
iam_auditor.py — AWS IAM Policy Auditor
Scans IAM users, roles, and policies for least-privilege violations.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

log = logging.getLogger(__name__)

# Dangerous action patterns
WILDCARD_ACTIONS   = {"*", "iam:*", "s3:*", "ec2:*", "lambda:*"}
ADMIN_ACTIONS      = {"iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy"}
SENSITIVE_SERVICES = {"iam", "sts", "organizations", "secretsmanager", "kms"}


class IAMAuditor:
    """Audits AWS IAM configuration for security misconfigurations."""

    def __init__(self, iam_client):
        self.iam  = iam_client
        self.findings: list[dict] = []

    def run_all_checks(self) -> list[dict]:
        """Run all IAM checks and return consolidated findings."""
        log.info("Starting IAM audit …")
        self._check_root_mfa()
        self._check_unused_credentials()
        self._check_wildcard_policies()
        self._check_inline_policies()
        self._check_key_rotation()
        log.info("IAM audit complete — %d findings", len(self.findings))
        return self.findings

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_root_mfa(self):
        """CIS 1.1 / 1.5 — root account MFA must be enabled."""
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
            if not summary.get("AccountMFAEnabled", 0):
                self._add("CRITICAL", "ROOT_NO_MFA",
                          "Root account does not have MFA enabled",
                          "Enable MFA on the root account immediately",
                          "CIS 1.5")
        except Exception as exc:
            log.warning("root MFA check failed: %s", exc)

    def _check_unused_credentials(self):
        """CIS 1.3 — disable credentials unused for 90+ days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        try:
            for user in self._paginate("list_users", "Users"):
                uid  = user["UserName"]
                cred = self.iam.get_credential_report()  # simplified
                last = user.get("PasswordLastUsed")
                if last and last < cutoff:
                    self._add("HIGH", "UNUSED_CREDENTIALS",
                              f"User '{uid}' has not logged in for 90+ days",
                              f"Disable or remove user '{uid}'",
                              "CIS 1.3")
        except Exception as exc:
            log.warning("unused credentials check failed: %s", exc)

    def _check_wildcard_policies(self):
        """Detect overly-permissive IAM policies with wildcard actions."""
        try:
            for policy in self._paginate("list_policies", "Policies",
                                         extra_kwargs={"Scope": "Local"}):
                arn     = policy["Arn"]
                version = policy["DefaultVersionId"]
                doc     = self.iam.get_policy_version(
                    PolicyArn=arn, VersionId=version
                )["PolicyVersion"]["Document"]

                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    wildcards = [a for a in actions if a in WILDCARD_ACTIONS or a == "*"]
                    if wildcards:
                        self._add("HIGH", "WILDCARD_POLICY",
                                  f"Policy '{policy['PolicyName']}' grants wildcard actions: {wildcards}",
                                  "Scope down to minimum required actions",
                                  "CIS 1.16")
        except Exception as exc:
            log.warning("wildcard policy check failed: %s", exc)

    def _check_inline_policies(self):
        """Flag inline policies — use managed policies instead."""
        try:
            for user in self._paginate("list_users", "Users"):
                uid      = user["UserName"]
                inlines  = self.iam.list_user_policies(UserName=uid)["PolicyNames"]
                if inlines:
                    self._add("MEDIUM", "INLINE_POLICY",
                              f"User '{uid}' has {len(inlines)} inline policy/ies",
                              "Convert inline policies to customer-managed policies",
                              "CIS 1.16")
        except Exception as exc:
            log.warning("inline policy check failed: %s", exc)

    def _check_key_rotation(self):
        """CIS 1.14 — access keys must be rotated every 90 days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        try:
            for user in self._paginate("list_users", "Users"):
                uid  = user["UserName"]
                keys = self.iam.list_access_keys(UserName=uid)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] == "Active" and key["CreateDate"] < cutoff:
                        self._add("HIGH", "STALE_ACCESS_KEY",
                                  f"Access key {key['AccessKeyId']} for '{uid}' is >90 days old",
                                  "Rotate or deactivate the access key",
                                  "CIS 1.14")
        except Exception as exc:
            log.warning("key rotation check failed: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add(self, severity: str, check_id: str, description: str,
             remediation: str, reference: str = ""):
        self.findings.append({
            "severity":    severity,
            "check_id":    check_id,
            "description": description,
            "remediation": remediation,
            "reference":   reference,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })

    def _paginate(self, method: str, key: str, extra_kwargs: dict | None = None):
        kwargs = extra_kwargs or {}
        paginator = self.iam.get_paginator(method)
        for page in paginator.paginate(**kwargs):
            yield from page.get(key, [])
