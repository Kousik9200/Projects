"""
MCP Cyber Agent - Autonomous Incident Response using Model Context Protocol
"""

import os
import logging
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an autonomous cybersecurity incident response agent.
Given threat intelligence and scan results, you must:
1. Prioritize findings by severity and exploitability
2. Generate a structured incident report
3. Recommend immediate remediation actions
4. Identify affected MITRE ATT&CK techniques
Respond in structured JSON format."""


class MCPAgent:
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4",
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=0.1
        )

    async def respond(self, scan_results: dict) -> dict:
        summary = self._summarize_results(scan_results)
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"Analyze and respond to these security findings:\n{summary}")
        ]
        try:
            response = self.llm.invoke(messages)
            return {"status": "success", "response": response.content}
        except Exception as e:
            logger.error(f"MCP Agent failed: {e}")
            return {"status": "error", "error": str(e)}

    def _summarize_results(self, results: dict) -> str:
        lines = []
        if "websec" in results:
            ws = results["websec"]
            lines.append(f"WebSec Findings: {ws.get('total_findings', 0)} total")
            for f in ws.get("critical", []):
                lines.append(f"  [CRITICAL] {f['check']}: {f['detail']}")
        if "phishing" in results:
            lines.append(f"Phishing Status: {results['phishing'].get('status', 'N/A')}")
        if "threat_intel" in results:
            ti = results["threat_intel"]
            lines.append(f"Threat Intel: {len(ti.get('cisa_kev', []))} KEV entries fetched")
        return "\n".join(lines)
