"""
Multi-Agent Security Platform - Main Orchestrator
Author: Kousik Gunasekaran
"""

import asyncio
import logging
from agents.awareness_agent import AwarenessAgent
from agents.phishing_agent import PhishingAgent
from agents.websec_agent import WebSecAgent
from agents.mcp_agent import MCPAgent
from utils.slack_notifier import SlackNotifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class SecurityOrchestrator:
    def __init__(self):
        self.awareness = AwarenessAgent()
        self.phishing = PhishingAgent()
        self.websec = WebSecAgent()
        self.mcp = MCPAgent()
        self.notifier = SlackNotifier()

    async def run_full_scan(self, target_url: str = None, check_emails: bool = True):
        logger.info("=== Security Platform Scan Started ===")
        results = {}

        # 1. Threat Intelligence
        logger.info("[1/4] Running Awareness Agent...")
        results["threat_intel"] = await self.awareness.fetch_latest_threats()

        # 2. Phishing Detection
        if check_emails:
            logger.info("[2/4] Running Phishing Detection Agent...")
            results["phishing"] = await self.phishing.scan_inbox()

        # 3. Web Security Audit
        if target_url:
            logger.info("[3/4] Running WebSecScan Auditor...")
            results["websec"] = await self.websec.audit(target_url)

        # 4. MCP Autonomous Response
        logger.info("[4/4] Running MCP Response Agent...")
        results["response"] = await self.mcp.respond(results)

        # Notify
        await self.notifier.send_summary(results)
        logger.info("=== Scan Complete ===")
        return results


if __name__ == "__main__":
    orchestrator = SecurityOrchestrator()
    asyncio.run(orchestrator.run_full_scan(target_url="https://example.com"))
