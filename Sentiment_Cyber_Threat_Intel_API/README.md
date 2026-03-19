# Sentiment-Driven Cyber Threat Intel API

FastAPI + LangChain service that ingests live threat feeds from NVD, AlienVault OTX, and CISA and applies NLP classification to rank threats by urgency, sector relevance, and exploitability.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/threats/latest` | Latest CVEs with NLP scoring |
| GET | `/threats/{cve_id}` | Analyze a specific CVE |
| GET | `/threats/sector/{sector}` | Filter threats by sector |
| GET | `/health` | Health check |

## Example Response

```json
{
  "cve_id": "CVE-2024-12345",
  "description": "Remote code execution vulnerability in...",
  "cvss_score": 9.8,
  "urgency_score": 95,
  "sector_relevance": ["finance", "critical_infrastructure"],
  "exploitability": "ACTIVE_EXPLOITATION",
  "in_cisa_kev": true,
  "recommended_action": "Patch immediately — active exploitation detected in the wild."
}
```

## Running the API

```bash
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
```

## Docker

```bash
docker build -t threat-intel-api .
docker run -p 8000:8000 --env-file .env threat-intel-api
```

## Query Examples

```bash
# Get top 10 urgent threats
curl http://localhost:8000/threats/latest?limit=10&min_urgency=80

# Get finance sector threats
curl http://localhost:8000/threats/sector/finance

# Analyze specific CVE
curl http://localhost:8000/threats/CVE-2024-21413
```
