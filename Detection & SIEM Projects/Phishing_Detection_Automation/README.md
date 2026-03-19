# Phishing Detection Automation Workflow

Production-grade n8n + FastAPI pipeline that ingests Gmail alerts, analyzes suspicious URLs via URLScan.io and VirusTotal, scores threat severity, and dispatches real-time Slack notifications.

## Architecture

```
Gmail (n8n trigger) → Extract URLs → URLScan.io + VirusTotal → Risk Score → Slack Alert
```

## Components

| File | Description |
|------|-------------|
| `phishing_processor.py` | FastAPI webhook processor — scores emails and URLs |
| `n8n_workflow.json` | Import into n8n to wire Gmail → processor → Slack |

## Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 75–100 | CRITICAL | Auto-quarantine + Slack alert |
| 50–74 | HIGH | Slack alert + manual review |
| 20–49 | MEDIUM | Log only |
| 0–19 | LOW | No action |

## Setup

```bash
# Start webhook processor
pip install -r requirements.txt
uvicorn phishing_processor:app --port 8001

# Import n8n_workflow.json into your n8n instance
# Configure Gmail credentials and Slack webhook in n8n
```
