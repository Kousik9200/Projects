#!/usr/bin/env python3
"""
jira_ticket.py - Creates Jira tickets for critical/high cloud misconfiguration findings.

Author: Kousik Gunasekaran
"""

import os
import json
import base64
import logging
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)

JIRA_BASE_URL  = os.environ.get("JIRA_BASE_URL", "https://yourorg.atlassian.net")
JIRA_EMAIL     = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT   = os.environ.get("JIRA_PROJECT_KEY", "SEC")

SEVERITY_TO_PRIORITY = {
    "CRITICAL": "Highest",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
}


def _jira_request(method: str, endpoint: str, payload: dict = None) -> Optional[dict]:
    """Make an authenticated Jira Cloud REST API v3 call."""
    url = f"{JIRA_BASE_URL}/rest/api/3/{endpoint}"
    creds = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    headers = {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.error(f"Jira API error {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        logger.error(f"Jira request failed: {e}")
    return None


def create_ticket_for_finding(finding: dict) -> Optional[str]:
    """Create a single Jira issue for one finding. Returns issue key."""
    severity  = finding.get("severity", "MEDIUM").upper()
    title     = finding.get("title", "Cloud misconfiguration detected")
    resource  = finding.get("resource", "unknown")
    cis       = finding.get("cis_control", "")
    desc_text = finding.get("description", "")
    remediation = finding.get("remediation", "")
    score     = finding.get("risk_score", 0)
    env       = finding.get("environment", "unknown")
    category  = finding.get("category", "MISC")
    detected  = finding.get("detected_at", "")

    summary = f"[{severity}][{category}] {title}"

    description = {
        "version": 1,
        "type": "doc",
        "content": [
            {"type": "heading", "attrs": {"level": 2},
             "content": [{"type": "text", "text": "Finding Details"}]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": f"Severity: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": severity}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "Risk Score: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": str(score)}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "Environment: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": env}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "CIS Control: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": cis}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "Affected Resource: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": resource}
            ]},
            {"type": "paragraph", "content": [
                {"type": "text", "text": "Detected at: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": detected}
            ]},
            {"type": "heading", "attrs": {"level": 3},
             "content": [{"type": "text", "text": "Description"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": desc_text}]},
            {"type": "heading", "attrs": {"level": 3},
             "content": [{"type": "text", "text": "Remediation Steps"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": remediation}]},
        ]
    }

    payload = {
        "fields": {
            "project":     {"key": JIRA_PROJECT},
            "summary":     summary,
            "description": description,
            "issuetype":   {"name": "Bug"},
            "priority":    {"name": SEVERITY_TO_PRIORITY.get(severity, "Medium")},
            "labels": [
                "cloud-security",
                f"severity-{severity.lower()}",
                f"env-{env.lower()}",
                category.lower()
            ]
        }
    }

    result = _jira_request("POST", "issue", payload)
    if result:
        key = result.get("key")
        logger.info(f"  Created Jira ticket {key} for: {title[:60]}")
        return key
    return None


def file_tickets_for_critical_findings(findings: list, min_severity: str = "HIGH") -> dict:
    """
    File Jira tickets for all findings at or above min_severity.
    Returns a dict mapping finding_id -> jira_key.
    """
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    threshold = severity_rank.get(min_severity.upper(), 1)

    tickets_created = {}
    eligible = [
        f for f in findings
        if severity_rank.get(f.get("severity", "LOW").upper(), 99) <= threshold
    ]

    logger.info(f"Filing Jira tickets for {len(eligible)} findings (severity >= {min_severity})")

    for finding in eligible:
        fid = finding.get("finding_id", "unknown")
        key = create_ticket_for_finding(finding)
        if key:
            tickets_created[fid] = key

    logger.info(f"Jira tickets created: {len(tickets_created)}/{len(eligible)}")
    return tickets_created
