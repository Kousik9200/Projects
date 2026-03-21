#!/usr/bin/env python3
"""
LAB 5: Phishing Analysis & Incident Response
=============================================
Objective: Analyze a suspicious email, extract IOCs, score
threat severity, classify the phishing campaign type,
and initiate an automated response workflow.

Author: Kousik Gunasekaran
"""

import re
import json
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  LAB 5 — Phishing Analysis & Incident Response          ║
║  Email Forensics · IOC Extraction · Auto-Response       ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
# EXERCISE 1: Simulated Suspicious Emails
# ─────────────────────────────────────────────

PHISHING_EMAILS = [
    {
        "id": "EMAIL-001",
        "subject": "URGENT: Your Microsoft 365 Account Will Be Suspended",
        "sender": "security-alert@micros0ft-verify.com",
        "reply_to": "no-reply@suspicious-domain.ru",
        "recipient": "bob@company.com",
        "received_from": "203.0.113.42",
        "spf_result": "FAIL",
        "dkim_result": "NONE",
        "dmarc_result": "FAIL",
        "timestamp": "2025-03-15T09:38:00Z",
        "body": """
Dear Microsoft User,

Your account requires immediate verification. Failure to verify
within 24 hours will result in account suspension.

Click here to verify: http://micros0ft-login.serverfree.com/verify?user=bob@company.com&token=dXNlcjoxMjM0NTY=

If you did not request this, click: http://micros0ft-login.serverfree.com/unsubscribe

Microsoft Support Team
        """,
        "attachments": [],
        "expected_category": "credential_harvesting"
    },
    {
        "id": "EMAIL-002",
        "subject": "Invoice #INV-20250315 - Payment Required",
        "sender": "billing@legit-vendor.com.evil.ru",
        "reply_to": "billing@evil.ru",
        "recipient": "alice@company.com",
        "received_from": "198.51.100.87",
        "spf_result": "SOFTFAIL",
        "dkim_result": "FAIL",
        "dmarc_result": "FAIL",
        "timestamp": "2025-03-15T11:00:00Z",
        "body": """
Please find attached Invoice #INV-20250315.

Amount Due: $48,320.00
Due Date: March 20, 2025

To process payment, please review the attached invoice document.

Thank you for your business.
        """,
        "attachments": [
            {
                "filename": "Invoice_INV20250315.doc",
                "size_kb": 412,
                "md5": "9e2e3a00b3d94e67c9b1d5ad80c8c8d2",
                "type": "application/msword"
            }
        ],
        "expected_category": "malware_delivery"
    },
    {
        "id": "EMAIL-003",
        "subject": "Q1 2025 Board Report — Confidential",
        "sender": "ceo@company.com.phishing-domains.xyz",
        "reply_to": "ceo-urgent@gmail.com",
        "recipient": "finance@company.com",
        "received_from": "45.33.32.156",
        "spf_result": "FAIL",
        "dkim_result": "NONE",
        "dmarc_result": "FAIL",
        "timestamp": "2025-03-15T14:22:00Z",
        "body": """
Hi,

I need you to process an urgent wire transfer of $127,500 to our
new vendor. This is time-sensitive — please process by EOD today.

Wire Details:
Bank: First National Bank
Account: 4532015112830366
Routing: 021000021
Reference: Q1-BOARD-2025

Please confirm once done. Do not discuss with others — NDA applies.

Thanks,
John (CEO)
        """,
        "attachments": [],
        "expected_category": "bec_fraud"
    }
]

KNOWN_MALICIOUS_IPS = {"203.0.113.42", "198.51.100.87", "45.33.32.156"}
KNOWN_MALICIOUS_DOMAINS = {"micros0ft-login.serverfree.com", "evil.ru", "phishing-domains.xyz"}
KNOWN_MALICIOUS_MD5 = {"9e2e3a00b3d94e67c9b1d5ad80c8c8d2": "Macro-enabled doc dropper (Emotet variant)"}
LOOKALIKE_PATTERNS = [r"micros0ft", r"paypa1", r"g00gle", r"arnazon", r"app1e"]


# ─────────────────────────────────────────────
# EXERCISE 2: Email Header Analysis
# ─────────────────────────────────────────────

def analyze_headers(email: dict) -> dict:
    findings = []
    score = 0

    if email["spf_result"] in ("FAIL", "SOFTFAIL"):
        findings.append(f"SPF {email['spf_result']}: sender IP not authorized by domain")
        score += 30 if email["spf_result"] == "FAIL" else 15

    if email["dkim_result"] in ("FAIL", "NONE"):
        findings.append(f"DKIM {email['dkim_result']}: message not cryptographically signed by sender")
        score += 20

    if email["dmarc_result"] == "FAIL":
        findings.append("DMARC FAIL: domain policy not satisfied — high phishing indicator")
        score += 25

    if email.get("reply_to") and email["reply_to"] != email["sender"]:
        reply_domain = email["reply_to"].split("@")[-1]
        sender_domain = email["sender"].split("@")[-1]
        if reply_domain != sender_domain:
            findings.append(f"Reply-To mismatch: replies go to '{reply_domain}' not '{sender_domain}'")
            score += 20

    for pattern in LOOKALIKE_PATTERNS:
        if re.search(pattern, email["sender"], re.IGNORECASE):
            findings.append(f"Lookalike domain detected in sender: '{email['sender']}'")
            score += 30
            break

    return {"header_score": min(score, 100), "findings": findings}


# ─────────────────────────────────────────────
# EXERCISE 3: URL & IOC Extraction
# ─────────────────────────────────────────────

URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+')
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')


def extract_iocs(email: dict) -> dict:
    iocs = {"urls": [], "domains": [], "ips": [], "hashes": {}, "encoded_strings": [], "bank_accounts": []}

    body = email.get("body", "")

    # URLs
    urls = URL_PATTERN.findall(body)
    for url in urls:
        parsed = urlparse(url)
        iocs["urls"].append(url)
        if parsed.hostname:
            iocs["domains"].append(parsed.hostname)

    # Try base64 decode
    tokens = BASE64_PATTERN.findall(body)
    for token in tokens:
        try:
            padding = 4 - len(token) % 4
            decoded = base64.b64decode(token + "=" * padding).decode("utf-8", errors="ignore")
            if len(decoded) > 5 and decoded.isprintable():
                iocs["encoded_strings"].append({"b64": token[:30] + "...", "decoded": decoded})
        except Exception:
            pass

    # Source IP
    if email.get("received_from"):
        iocs["ips"].append(email["received_from"])

    # Attachment hashes
    for att in email.get("attachments", []):
        iocs["hashes"][att["md5"]] = att["filename"]

    # Wire transfer / account numbers
    acct_pattern = re.compile(r'\b\d{10,18}\b')
    accounts = acct_pattern.findall(body)
    iocs["bank_accounts"] = accounts

    return iocs


# ─────────────────────────────────────────────
# EXERCISE 4: Threat Scoring & Classification
# ─────────────────────────────────────────────

PHISHING_CATEGORIES = {
    "credential_harvesting": {
        "indicators": ["login", "verify", "account", "password", "suspended", "click here"],
        "response": "Block URL, quarantine email, notify recipient, reset credentials if clicked"
    },
    "malware_delivery": {
        "indicators": ["invoice", "receipt", "attachment", ".doc", ".xls", ".zip", ".exe"],
        "response": "Block attachment hash, quarantine email, scan recipient endpoint, detonate sample"
    },
    "bec_fraud": {
        "indicators": ["wire transfer", "urgent", "ceo", "payment", "bank account", "routing", "nda"],
        "response": "Alert finance team immediately, verify via phone, block sender domain, preserve evidence"
    }
}


def classify_and_score(email: dict, header_analysis: dict, iocs: dict) -> dict:
    score = header_analysis["header_score"]
    category_scores = {}

    body_lower = email.get("body", "").lower() + email.get("subject", "").lower()
    for cat, config in PHISHING_CATEGORIES.items():
        hits = sum(1 for ind in config["indicators"] if ind in body_lower)
        category_scores[cat] = hits

    category = max(category_scores, key=category_scores.get)

    # Add IOC-based scoring
    for ip in iocs["ips"]:
        if ip in KNOWN_MALICIOUS_IPS:
            score += 25
    for domain in iocs["domains"]:
        if any(domain.endswith(bad) or domain == bad for bad in KNOWN_MALICIOUS_DOMAINS):
            score += 20
    for md5 in iocs["hashes"]:
        if md5 in KNOWN_MALICIOUS_MD5:
            score += 40

    if iocs["bank_accounts"]:
        score += 30

    score = min(score, 100)
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"

    return {
        "score": score,
        "level": level,
        "category": category,
        "response": PHISHING_CATEGORIES[category]["response"],
        "category_scores": category_scores
    }


# ─────────────────────────────────────────────
# EXERCISE 5: Automated Response Actions
# ─────────────────────────────────────────────

def simulate_response(email: dict, classification: dict, iocs: dict) -> dict:
    actions = []
    timestamp = datetime.now(timezone.utc).isoformat()

    # Always: quarantine
    actions.append({
        "action": "QUARANTINE_EMAIL",
        "target": email["id"],
        "status": "EXECUTED",
        "timestamp": timestamp
    })

    # Block sender domain
    sender_domain = email["sender"].split("@")[-1]
    actions.append({
        "action": "BLOCK_SENDER_DOMAIN",
        "target": sender_domain,
        "status": "EXECUTED",
        "timestamp": timestamp
    })

    # Block malicious IPs
    for ip in iocs["ips"]:
        if ip in KNOWN_MALICIOUS_IPS:
            actions.append({
                "action": "BLOCK_IP_FIREWALL",
                "target": ip,
                "status": "EXECUTED",
                "timestamp": timestamp
            })

    # Block URLs
    for url in iocs["urls"]:
        actions.append({
            "action": "BLOCK_URL_PROXY",
            "target": url[:60] + ("..." if len(url) > 60 else ""),
            "status": "EXECUTED",
            "timestamp": timestamp
        })

    # Malware-specific: endpoint scan
    if iocs["hashes"]:
        for md5, fname in iocs["hashes"].items():
            actions.append({
                "action": "ENDPOINT_HASH_HUNT",
                "target": f"{md5} ({fname})",
                "status": "TRIGGERED",
                "timestamp": timestamp
            })

    # BEC: alert finance
    if classification["category"] == "bec_fraud":
        actions.append({
            "action": "ALERT_FINANCE_TEAM",
            "target": email["recipient"],
            "status": "NOTIFICATION_SENT",
            "message": "Potential BEC — do NOT process any wire transfer requests from this sender",
            "timestamp": timestamp
        })

    # Notify recipient
    actions.append({
        "action": "NOTIFY_RECIPIENT",
        "target": email["recipient"],
        "status": "EMAIL_SENT",
        "timestamp": timestamp
    })

    return {"response_actions": actions, "total": len(actions)}


def run_lab():
    print(BANNER)
    out = Path("lab5_output")
    out.mkdir(exist_ok=True)

    all_results = []
    for email in PHISHING_EMAILS:
        print(f"\n{'='*60}")
        print(f"  Analyzing: {email['id']} — {email['subject'][:45]}")
        print(f"{'='*60}")

        print("\n  [EXERCISE 2] Header Analysis")
        header = analyze_headers(email)
        print(f"    Header risk score: {header['header_score']}/100")
        for f in header["findings"]:
            print(f"    ⚠ {f}")

        print("\n  [EXERCISE 3] IOC Extraction")
        iocs = extract_iocs(email)
        print(f"    URLs      : {len(iocs['urls'])}")
        print(f"    Domains   : {iocs['domains']}")
        print(f"    Source IPs: {iocs['ips']}")
        print(f"    Hashes    : {list(iocs['hashes'].keys())}")
        if iocs["encoded_strings"]:
            for enc in iocs["encoded_strings"]:
                print(f"    Decoded b64: '{enc['decoded']}'")
        if iocs["bank_accounts"]:
            print(f"    ⚠ Bank accounts found: {iocs['bank_accounts']}")

        print("\n  [EXERCISE 4] Classification & Scoring")
        classification = classify_and_score(email, header, iocs)
        print(f"    Score     : {classification['score']}/100")
        print(f"    Level     : {classification['level']}")
        print(f"    Category  : {classification['category'].upper()}")
        correct = "✓ CORRECT" if classification["category"] == email["expected_category"] else "✗ WRONG"
        print(f"    Expected  : {email['expected_category'].upper()} {correct}")
        print(f"    Response  : {classification['response']}")

        print("\n  [EXERCISE 5] Automated Response")
        response = simulate_response(email, classification, iocs)
        for action in response["response_actions"]:
            print(f"    [{action['status']}] {action['action']}: {action['target'][:50]}")

        all_results.append({
            "email_id": email["id"],
            "subject": email["subject"],
            "header_analysis": header,
            "iocs": {k: list(v) if isinstance(v, set) else v for k, v in iocs.items()},
            "classification": classification,
            "response": response
        })

    with open(out / "phishing_analysis_results.json", "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"""
\n╔══════════════════════════════════════════════════════════╗
║  LAB 5 COMPLETE — {len(PHISHING_EMAILS)} emails analyzed                  ║
╠══════════════════════════════════════════════════════════╣
║  CHALLENGE: Add a DKIM signature verification function  ║
║  that parses the DKIM-Signature header and validates    ║
║  the 'bh' (body hash) value.                           ║
╠══════════════════════════════════════════════════════════╣
║  Key Concepts Covered:                                  ║
║  • SPF / DKIM / DMARC header authentication             ║
║  • URL and IOC extraction from email bodies             ║
║  • Phishing campaign classification (BEC, cred harvest) ║
║  • Automated response: quarantine, block, notify        ║
╚══════════════════════════════════════════════════════════╝""")


if __name__ == "__main__":
    run_lab()
