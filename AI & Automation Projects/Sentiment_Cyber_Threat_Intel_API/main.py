"""
Sentiment-Driven Cyber Threat Intelligence API
FastAPI + LangChain service ingesting NVD, AlienVault OTX, CISA KEV feeds
and classifying threats by urgency, sector relevance, and exploitability.
Author: Kousik Gunasekaran
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import httpx
import os
import logging
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Cyber Threat Intel API",
    description="NLP-powered threat intelligence with urgency scoring",
    version="1.0.0"
)

llm = ChatOpenAI(model="gpt-4", api_key=os.getenv("OPENAI_API_KEY"), temperature=0.0)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class ThreatIntelItem(BaseModel):
    cve_id: str
    description: str
    cvss_score: float
    urgency_score: int       # 0-100 NLP-derived urgency
    sector_relevance: List[str]
    exploitability: str      # LOW / MEDIUM / HIGH / ACTIVE
    in_cisa_kev: bool
    recommended_action: str
    analyzed_at: str


CLASSIFICATION_PROMPT = """You are a cybersecurity threat analyst. Analyze this CVE and return a JSON object with:
- urgency_score (0-100): higher = more urgent to patch
- sector_relevance (list): affected industries e.g. ["finance", "healthcare", "critical_infrastructure"]
- exploitability: "LOW" | "MEDIUM" | "HIGH" | "ACTIVE_EXPLOITATION"
- recommended_action: one sentence on what to do

CVE Description: {description}
CVSS Score: {cvss}
In CISA KEV (actively exploited): {in_kev}

Return ONLY valid JSON, no markdown."""


@app.get("/threats/latest", response_model=List[ThreatIntelItem])
async def get_latest_threats(
    limit: int = Query(default=10, le=50),
    sector: Optional[str] = Query(default=None, description="Filter by sector e.g. 'finance'"),
    min_urgency: int = Query(default=50, ge=0, le=100)
):
    """Fetch and analyze the latest CVEs from NVD with NLP scoring."""
    cves = await _fetch_nvd_recent(limit * 2)
    kev_ids = await _fetch_cisa_kev_ids()

    results = []
    for cve in cves[:limit]:
        item = await _analyze_cve(cve, kev_ids)
        if item.urgency_score >= min_urgency:
            if sector is None or sector.lower() in [s.lower() for s in item.sector_relevance]:
                results.append(item)

    results.sort(key=lambda x: x.urgency_score, reverse=True)
    return results[:limit]


@app.get("/threats/{cve_id}", response_model=ThreatIntelItem)
async def get_cve_analysis(cve_id: str):
    """Analyze a specific CVE."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{NVD_API}?cveId={cve_id.upper()}")
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        kev_ids = await _fetch_cisa_kev_ids()
        return await _analyze_cve(vulns[0], kev_ids)


@app.get("/threats/sector/{sector}")
async def get_threats_by_sector(sector: str, limit: int = 10):
    """Get threats relevant to a specific sector."""
    return await get_latest_threats(limit=limit, sector=sector, min_urgency=0)


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


async def _fetch_nvd_recent(limit: int) -> list:
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.get(f"{NVD_API}?resultsPerPage={limit}&startIndex=0")
            return resp.json().get("vulnerabilities", [])
        except Exception as e:
            logger.error(f"NVD fetch failed: {e}")
            return []


async def _fetch_cisa_kev_ids() -> set:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(CISA_KEV)
            vulns = resp.json().get("vulnerabilities", [])
            return {v["cveID"] for v in vulns}
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}")
            return set()


async def _analyze_cve(cve_data: dict, kev_ids: set) -> ThreatIntelItem:
    cve = cve_data.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
    metrics = cve.get("metrics", {})
    cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2", [])))
    cvss_score = 0.0
    if cvss_data:
        cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0.0)

    in_kev = cve_id in kev_ids

    prompt = CLASSIFICATION_PROMPT.format(description=description[:500], cvss=cvss_score, in_kev=in_kev)
    try:
        import json
        response = llm.invoke([HumanMessage(content=prompt)])
        analysis = json.loads(response.content)
    except Exception as e:
        logger.error(f"LLM analysis failed for {cve_id}: {e}")
        analysis = {
            "urgency_score": int(cvss_score * 10),
            "sector_relevance": ["general"],
            "exploitability": "ACTIVE_EXPLOITATION" if in_kev else "MEDIUM",
            "recommended_action": "Review and patch according to vendor advisory."
        }

    if in_kev and analysis.get("urgency_score", 0) < 80:
        analysis["urgency_score"] = max(analysis.get("urgency_score", 0), 85)

    return ThreatIntelItem(
        cve_id=cve_id,
        description=description[:300],
        cvss_score=cvss_score,
        urgency_score=analysis.get("urgency_score", 50),
        sector_relevance=analysis.get("sector_relevance", ["general"]),
        exploitability=analysis.get("exploitability", "MEDIUM"),
        in_cisa_kev=in_kev,
        recommended_action=analysis.get("recommended_action", ""),
        analyzed_at=datetime.utcnow().isoformat()
    )
