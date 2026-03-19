# AI-Powered Multi-Agent Security Platform

A capstone cybersecurity project integrating four autonomous security agents using the Brain-Bridge-Muscle (BBM) architecture for end-to-end threat detection and incident response.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              MULTI-AGENT SECURITY PLATFORM              │
├───────────────┬───────────────┬────────────┬────────────┤
│  Awareness    │   Phishing    │ WebSecScan │    MCP     │
│    Agent      │  Detection    │  Auditor   │   Agent    │
│  (Threat      │  Workflow     │  (OWASP)   │ (Response) │
│   Intel)      │   (n8n)       │            │            │
└───────┬───────┴───────┬───────┴─────┬──────┴─────┬──────┘
        │               │             │            │
        └───────────────┴──────┬──────┴────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Orchestrator /    │
                    │   Central Brain     │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Slack Alerting /  │
                    │   Incident Report   │
                    └─────────────────────┘
```

## Components

| Agent | Role | Tools |
|-------|------|-------|
| Awareness Agent | Threat intel ingestion from VirusTotal, OTX, CISA | Python, REST APIs |
| Phishing Detection | Email scanning + URL analysis pipeline | n8n, Gmail API, URLScan.io |
| WebSecScan Auditor | OWASP Top 10 scanning + reporting | Python, requests, BeautifulSoup |
| MCP Cyber Agent | Autonomous incident response via MCP protocol | MCP, LangChain |

## Stack
- Python 3.11
- n8n (workflow automation)
- LangChain + OpenAI
- VirusTotal API
- Slack Webhooks
- MCP (Model Context Protocol)

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# Fill in API keys in .env
python main.py
```

## Environment Variables

```
VIRUSTOTAL_API_KEY=
OPENAI_API_KEY=
SLACK_WEBHOOK_URL=
N8N_BASE_URL=
URLSCAN_API_KEY=
```
