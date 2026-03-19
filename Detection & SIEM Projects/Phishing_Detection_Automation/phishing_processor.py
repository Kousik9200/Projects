"""
Phishing Detection Pipeline
Processes email payloads from n8n Gmail trigger,
analyzes URLs via URLScan.io + VirusTotal, scores risk, alerts Slack.
Author: Kousik Gunasekaran
"""

import os
import re
import json
import httpx
import asyncio
import logging
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Phishing Detection Webhook Processor")

URLSCAN_API = "https://urlscan.io/api/v1"
VT_API = "https://www.virustotal.com/api/v3"
URL_REGEX = re.compile(r'https?://[^\s"<>]+')

RISK_THRESHOLDS = {"LOW": 0, "MEDIUM": 20, "HIGH": 50, "CRITICAL": 75}


class EmailPayload(BaseModel):
    message_id: str
    sender: str
    subject: str
    body: str
    received_at: str


class PhishingAnalysisResult(BaseModel):
    message_id: str
    sender: str
    subject: str
    risk_level: str
    risk_score: int
    suspicious_urls: List[dict]
    verdict: str
    analyzed_at: str


@app.post("/webhook/email", response_model=PhishingAnalysisResult)
async def process_email(payload: EmailPayload):
    """Called by n8n when a new email arrives in Gmail."""
    logger.info(f"Processing email: {payload.message_id} from {payload.sender}")

    urls = extract_urls(payload.body + " " + payload.subject)
    url_results = []
    total_score = 0

    if urls:
        for url in urls[:5]:  # Analyze top 5 URLs
            result = await analyze_url(url)
            url_results.append(result)
            total_score = max(total_score, result.get("risk_score", 0))

    # Heuristic scoring on email metadata
    heuristic_score = calculate_heuristic_score(payload)
    final_score = max(total_score, heuristic_score)

    risk_level = get_risk_level(final_score)
    verdict = generate_verdict(final_score, url_results, payload)

    result = PhishingAnalysisResult(
        message_id=payload.message_id,
        sender=payload.sender,
        subject=payload.subject,
        risk_level=risk_level,
        risk_score=final_score,
        suspicious_urls=url_results,
        verdict=verdict,
        analyzed_at=datetime.utcnow().isoformat()
    )

    if final_score >= RISK_THRESHOLDS["HIGH"]:
        await send_slack_alert(result)

    return result


async def analyze_url(url: str) -> dict:
    result = {"url": url, "risk_score": 0, "vt_malicious": 0, "urlscan_verdict": "unknown"}
    async with httpx.AsyncClient(timeout=20) as client:
        # VirusTotal check
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
            resp = await client.get(f"{VT_API}/urls/{url_id}", headers=headers)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                result["vt_malicious"] = malicious
                result["risk_score"] += malicious * 15 + suspicious * 5
        except Exception as e:
            logger.error(f"VT check failed for {url}: {e}")

        # URLScan submission
        try:
            headers = {"API-Key": os.getenv("URLSCAN_API_KEY"), "Content-Type": "application/json"}
            resp = await client.post(f"{URLSCAN_API}/scan/", headers=headers,
                                     json={"url": url, "visibility": "private"})
            if resp.status_code == 200:
                result["urlscan_uuid"] = resp.json().get("uuid")
                result["urlscan_verdict"] = "submitted"
        except Exception as e:
            logger.error(f"URLScan failed for {url}: {e}")

    result["risk_score"] = min(result["risk_score"], 100)
    return result


def extract_urls(text: str) -> List[str]:
    return list(set(URL_REGEX.findall(text)))


def calculate_heuristic_score(payload: EmailPayload) -> int:
    score = 0
    subject_lower = payload.subject.lower()
    body_lower = payload.body.lower()

    phishing_keywords = ["urgent", "verify your account", "click here", "password expired",
                         "suspended", "unusual activity", "confirm your identity", "act now"]
    for kw in phishing_keywords:
        if kw in subject_lower or kw in body_lower:
            score += 15

    suspicious_domains = ["bit.ly", "tinyurl", "t.co", "short.link", "ow.ly"]
    for domain in suspicious_domains:
        if domain in payload.body:
            score += 20

    if not payload.sender.split("@")[-1] in ["gmail.com", "outlook.com"]:
        if payload.sender.count("@") > 1 or payload.sender.count(".") > 3:
            score += 25

    return min(score, 100)


def get_risk_level(score: int) -> str:
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def generate_verdict(score: int, url_results: list, payload: EmailPayload) -> str:
    if score >= 75:
        return f"PHISHING DETECTED — {len([u for u in url_results if u.get('vt_malicious', 0) > 0])} malicious URL(s). Quarantine immediately."
    elif score >= 50:
        return "SUSPICIOUS EMAIL — Manual review required. Do not click any links."
    elif score >= 20:
        return "LOW RISK — Minor indicators present. Proceed with caution."
    return "CLEAN — No phishing indicators detected."


async def send_slack_alert(result: PhishingAnalysisResult):
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    emoji = "🚨" if result.risk_level == "CRITICAL" else "⚠️"
    payload = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} Phishing Alert: {result.risk_level}"}},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*From:* {result.sender}\n*Subject:* {result.subject}\n*Score:* {result.risk_score}/100\n*Verdict:* {result.verdict}"}}
        ]
    }
    async with httpx.AsyncClient() as client:
        await client.post(webhook, json=payload)
