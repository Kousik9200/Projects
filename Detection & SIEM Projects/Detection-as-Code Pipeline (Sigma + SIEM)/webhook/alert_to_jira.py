#!/usr/bin/env python3
"""
alert_to_jira.py - Flask webhook that receives SIEM alerts and creates Jira tickets

Deploy this as a lightweight service reachable from your SIEM.
Supports Splunk alert webhooks and Microsoft Sentinel Logic App webhooks.

Author: Kousik Gunasekaran
"""

import os
import json
import logging
import hashlib
import hmac
import base64
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from functools import wraps
from typing import Optional

# Flask is the only external dependency
from flask import Flask, request, jsonify, abort

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─────────────────────────────────────────────
# Configuration (set via environment variables)
# ─────────────────────────────────────────────

JIRA_BASE_URL   = os.environ.get("JIRA_BASE_URL", "https://yourorg.atlassian.net")
JIRA_EMAIL      = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN  = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT    = os.environ.get("JIRA_PROJECT_KEY", "SEC")
WEBHOOK_SECRET  = os.environ.get("WEBHOOK_SECRET", "changeme")
SLACK_WEBHOOK   = os.environ.get("SLACK_WEBHOOK_URL", "")

SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Lowest"
}

MITRE_TAG_MAP = {
    "t1059": "Execution - Command & Scripting Interpreter",
    "t1003": "Credential Access - OS Credential Dumping",
    "t1021": "Lateral Movement - Remote Services",
    "t1053": "Persistence - Scheduled Task/Job",
    "t1110": "Credential Access - Brute Force",
    "t1048": "Exfiltration - Alternative Protocol",
    "t1027": "Defense Evasion - Obfuscated Files",
    "t1190": "Initial Access - Exploit Public-Facing App",
}


# ─────────────────────────────────────────────
# Auth middleware
# ─────────────────────────────────────────────

def require_webhook_auth(f):
    """Decorator: validate webhook secret or HMAC signature."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Support simple bearer token
        auth_header = request.headers.get("Authorization", "")
        if auth_header == f"Bearer {WEBHOOK_SECRET}":
            return f(*args, **kwargs)

        # Support HMAC-SHA256 signature (Splunk-style)
        sig_header = request.headers.get("X-Signature", "")
        if sig_header and WEBHOOK_SECRET:
            body = request.get_data()
            expected = hmac.new(
                WEBHOOK_SECRET.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(sig_header, f"sha256={expected}"):
                return f(*args, **kwargs)

        logger.warning(f"Unauthorized webhook attempt from {request.remote_addr}")
        abort(401)
    return decorated


# ─────────────────────────────────────────────
# Jira helpers
# ─────────────────────────────────────────────

def jira_request(method: str, endpoint: str, payload: dict = None) -> Optional[dict]:
    """Make an authenticated Jira REST API call."""
    url = f"{JIRA_BASE_URL}/rest/api/3/{endpoint}"
    credentials = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.error(f"Jira API error {e.code}: {e.read().decode()}")
        return None
    except Exception as e:
        logger.error(f"Jira request failed: {e}")
        return None


def create_jira_ticket(alert: dict) -> Optional[str]:
    """Create a Jira security issue from an alert payload. Returns issue key."""
    rule_name = alert.get("rule_name", "Unknown Detection Rule")
    severity = alert.get("severity", "medium").lower()
    host = alert.get("host", "unknown")
    user = alert.get("user", "unknown")
    technique = alert.get("technique", "")
    sigma_rule_id = alert.get("sigma_rule_id", "")
    log_entry = alert.get("log_entry", "")
    siem_link = alert.get("siem_link", "")
    detected_at = alert.get("detected_at", datetime.utcnow().isoformat())

    technique_desc = MITRE_TAG_MAP.get(technique.lower().replace("t1", "t1"), technique)
    priority = SEVERITY_TO_PRIORITY.get(severity, "Medium")

    summary = f"[{severity.upper()}] Security Alert: {rule_name} on {host}"

    description = {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Detection Rule: {rule_name}"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Severity: {severity.upper()}"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Host: {host} | User: {user}"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Detected at: {detected_at}"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"MITRE ATT&CK: {technique} — {technique_desc}"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Sigma Rule ID: {sigma_rule_id}"}]
            },
            {
                "type": "heading",
                "attrs": {"level": 3},
                "content": [{"type": "text", "text": "Triggering Log Entry"}]
            },
            {
                "type": "codeBlock",
                "content": [{"type": "text", "text": log_entry or "Not provided"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"SIEM Link: {siem_link}"}]
            },
        ]
    }

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": [
                "security-alert",
                f"severity-{severity}",
                f"mitre-{technique.lower()}" if technique else "mitre-unknown"
            ]
        }
    }

    result = jira_request("POST", "issue", payload)
    if result:
        key = result.get("key")
        logger.info(f"Created Jira ticket: {key}")
        return key
    return None


def send_slack_notification(alert: dict, jira_key: Optional[str]):
    """Post a Slack notification about the alert."""
    if not SLACK_WEBHOOK:
        return

    severity = alert.get("severity", "medium").upper()
    emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":red_circle:", "MEDIUM": ":large_yellow_circle:"}.get(severity, ":white_circle:")
    rule_name = alert.get("rule_name", "Unknown Rule")
    host = alert.get("host", "unknown")
    jira_link = f"{JIRA_BASE_URL}/browse/{jira_key}" if jira_key else "N/A"

    message = {
        "text": f"{emoji} *Security Alert* [{severity}]",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *Security Alert Detected* [{severity}]\n"
                        f"*Rule:* {rule_name}\n"
                        f"*Host:* {host}\n"
                        f"*ATT&CK:* {alert.get('technique', 'N/A')}\n"
                        f"*Jira:* {jira_link}"
                    )
                }
            }
        ]
    }

    try:
        body = json.dumps(message).encode()
        req = urllib.request.Request(
            SLACK_WEBHOOK, data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning(f"Slack notification failed: {e}")


# ─────────────────────────────────────────────
# Webhook endpoint: Splunk
# ─────────────────────────────────────────────

@app.route("/webhook/splunk", methods=["POST"])
@require_webhook_auth
def splunk_webhook():
    """Handle Splunk saved search alert webhooks."""
    data = request.get_json(force=True, silent=True) or {}

    # Splunk sends results under 'result' key
    result = data.get("result", data)

    alert = {
        "rule_name": data.get("search_name", result.get("source", "Splunk Alert")),
        "severity": result.get("severity", data.get("severity", "medium")),
        "host": result.get("host", result.get("Computer", "unknown")),
        "user": result.get("user", result.get("Account", "unknown")),
        "technique": result.get("technique", ""),
        "sigma_rule_id": result.get("sigma_rule_id", ""),
        "log_entry": json.dumps(result, indent=2)[:2000],
        "siem_link": data.get("results_link", ""),
        "detected_at": result.get("_time", datetime.utcnow().isoformat()),
        "source": "splunk"
    }

    logger.info(f"Received Splunk alert: {alert['rule_name']} | {alert['severity']}")
    jira_key = create_jira_ticket(alert)
    send_slack_notification(alert, jira_key)

    return jsonify({
        "status": "ok",
        "jira_ticket": jira_key,
        "alert": alert["rule_name"]
    }), 200


# ─────────────────────────────────────────────
# Webhook endpoint: Sentinel
# ─────────────────────────────────────────────

@app.route("/webhook/sentinel", methods=["POST"])
@require_webhook_auth
def sentinel_webhook():
    """Handle Microsoft Sentinel Logic App alert webhooks."""
    data = request.get_json(force=True, silent=True) or {}

    # Sentinel alert schema
    entities = data.get("entities", [{}])
    entity = entities[0] if entities else {}

    alert = {
        "rule_name": data.get("AlertDisplayName", data.get("ruleName", "Sentinel Alert")),
        "severity": data.get("Severity", "medium").lower(),
        "host": entity.get("HostName", data.get("CompromisedEntity", "unknown")),
        "user": entity.get("AccountName", "unknown"),
        "technique": data.get("ExtendedProperties", {}).get("mitreTechnique", ""),
        "sigma_rule_id": data.get("ExtendedProperties", {}).get("sigmaRuleId", ""),
        "log_entry": json.dumps(data.get("ExtendedProperties", {}), indent=2)[:2000],
        "siem_link": data.get("AlertLink", ""),
        "detected_at": data.get("TimeGenerated", datetime.utcnow().isoformat()),
        "source": "sentinel"
    }

    logger.info(f"Received Sentinel alert: {alert['rule_name']} | {alert['severity']}")
    jira_key = create_jira_ticket(alert)
    send_slack_notification(alert, jira_key)

    return jsonify({
        "status": "ok",
        "jira_ticket": jira_key,
        "alert": alert["rule_name"]
    }), 200


# ─────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "alert-to-jira-webhook"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting alert-to-jira webhook on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
