"""
Awareness Agent - Threat Intelligence Ingestion
Fetches latest threats from VirusTotal, AlienVault OTX, and CISA
"""

import os
import aiohttp
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
OTX_API = "https://otx.alienvault.com/api/v1"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class AwarenessAgent:
    def __init__(self):
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")

    async def fetch_latest_threats(self) -> dict:
        results = {}
        async with aiohttp.ClientSession() as session:
            results["virustotal"] = await self._fetch_vt_feed(session)
            results["otx_pulses"] = await self._fetch_otx_pulses(session)
            results["cisa_kev"] = await self._fetch_cisa_kev(session)
        logger.info(f"Threat intel fetched: {len(results)} sources")
        return results

    async def _fetch_vt_feed(self, session) -> list:
        headers = {"x-apikey": self.vt_key}
        url = f"{VIRUSTOTAL_API}/feeds/files"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("data", [])[:10]
        except Exception as e:
            logger.error(f"VirusTotal fetch failed: {e}")
        return []

    async def _fetch_otx_pulses(self, session) -> list:
        headers = {"X-OTX-API-KEY": self.otx_key}
        url = f"{OTX_API}/pulses/subscribed?limit=10"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("results", [])
        except Exception as e:
            logger.error(f"OTX fetch failed: {e}")
        return []

    async def _fetch_cisa_kev(self, session) -> list:
        try:
            async with session.get(CISA_KEV) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulns = data.get("vulnerabilities", [])
                    # Return 10 most recently added
                    return sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:10]
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}")
        return []
