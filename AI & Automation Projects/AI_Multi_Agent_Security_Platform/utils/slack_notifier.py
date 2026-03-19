"""
Slack Notifier - Sends enriched security alerts to Slack
"""

import os
import aiohttp
import json
import logging

logger = logging.getLogger(__name__)


class SlackNotifier:
    def __init__(self):
        self.webhook = os.getenv("SLACK_WEBHOOK_URL")

    async def send_summary(self, results: dict):
        blocks = self._build_blocks(results)
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(self.webhook, json={"blocks": blocks})
                logger.info("Slack notification sent")
            except Exception as e:
                logger.error(f"Slack notification failed: {e}")

    def _build_blocks(self, results: dict) -> list:
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🛡️ Security Platform Scan Report"}},
            {"type": "divider"}
        ]
        if "websec" in results:
            ws = results["websec"]
            critical = len(ws.get("critical", []))
            high = len(ws.get("high", []))
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Web Security*\n🔴 Critical: {critical}  🟠 High: {high}"}
            })
        if "threat_intel" in results:
            kev_count = len(results["threat_intel"].get("cisa_kev", []))
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Threat Intelligence*\n📋 CISA KEV entries: {kev_count}"}
            })
        return blocks
