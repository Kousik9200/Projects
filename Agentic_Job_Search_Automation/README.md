# Agentic AI Job Search Automation

A multi-agent pipeline for automated job discovery, resume tailoring, ATS optimization, and application tracking — built with LangChain, Python, and n8n.

## Agent Architecture

```
┌─────────────────────────────────────────────────────────┐
│              JOB SEARCH AUTOMATION PIPELINE             │
├──────────────┬──────────────┬──────────────┬────────────┤
│   Scraper    │   Analyzer   │   Tailor     │  Tracker   │
│   Agent      │   Agent      │   Agent      │  Agent     │
│  (Discover   │ (Score job   │ (Customize   │ (Log to    │
│   postings)  │  fit %)      │  resume/CL)  │  Notion)   │
└──────┬───────┴──────┬───────┴──────┬───────┴─────┬──────┘
       │              │              │              │
       └──────────────┴──────┬───────┴──────────────┘
                             │
                  ┌──────────▼──────────┐
                  │   Orchestrator       │
                  │   (LangChain Agent)  │
                  └─────────────────────┘
```

## Features

- Scrapes job postings from LinkedIn, Indeed, and Glassdoor
- Scores job-resume fit using NLP (0–100%)
- Auto-tailors resume bullets to match job description keywords
- Generates ATS-optimized cover letters
- Tracks all applications in a structured log

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
python orchestrator.py --search "Security Engineer" --location "New York"
```

## Environment Variables

```
OPENAI_API_KEY=
NOTION_API_KEY=
NOTION_DATABASE_ID=
```
