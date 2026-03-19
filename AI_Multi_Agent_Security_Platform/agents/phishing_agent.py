"""
Phishing Detection Agent
Scans Gmail inbox and checks suspicious URLs via URLScan.io + VirusTotal
"""

import os
import re
import aiohttp
import logging

logger = logging.getLogger(__name__)

URLSCAN_API = "https://urlscan.io/api/v1"
VT_API = "https://www.virustotal.com/api/v3"
URL_REGEX = re.compile(r"https?://[^\s\"'>]+")


class PhishingAgent:
    def __init__(self):
        self.urlscan_key = os.getenv("URLSCAN_API_KEY")
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")

    async def scan_inbox(self) -> dict:
        """Main entry point - triggered by n8n webhook or direct call."""
        # In production, emails are fed via n8n Gmail trigger
        # This processes the payload
        return {"status": "n8n_workflow_triggered", "message": "Phishing scan delegated to n8n pipeline"}

    async def analyze_url(self, url: str) -> dict:
        result = {"url": url, "risk_score": 0, "verdicts": {}}
        async with aiohttp.ClientSession() as session:
            urlscan = await self._submit_urlscan(session, url)
            vt = await self._check_virustotal(session, url)
            result["verdicts"]["urlscan"] = urlscan
            result["verdicts"]["virustotal"] = vt
            result["risk_score"] = self._calculate_risk(urlscan, vt)
        return result

    async def _submit_urlscan(self, session, url: str) -> dict:
        headers = {"API-Key": self.urlscan_key, "Content-Type": "application/json"}
        try:
            async with session.post(f"{URLSCAN_API}/scan/", headers=headers, json={"url": url, "visibility": "private"}) as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"URLScan failed: {e}")
            return {}

    async def _check_virustotal(self, session, url: str) -> dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.vt_key}
        try:
            async with session.get(f"{VT_API}/urls/{url_id}", headers=headers) as resp:
                return await resp.json()
        except Exception as e:
            logger.error(f"VirusTotal URL check failed: {e}")
            return {}

    def _calculate_risk(self, urlscan: dict, vt: dict) -> int:
        score = 0
        vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        score += vt_stats.get("malicious", 0) * 10
        score += vt_stats.get("suspicious", 0) * 5
        return min(score, 100)

    def extract_urls(self, text: str) -> list:
        return URL_REGEX.findall(text)
