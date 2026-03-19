# RAG System for SEC 10-K Security Risk Analysis

A Retrieval-Augmented Generation (RAG) system that ingests SEC 10-K filings and enables natural language Q&A over cybersecurity risk disclosures.

## Features
- Ingest any company's 10-K filing from SEC EDGAR
- Semantic search across all ingested filings
- Natural language Q&A powered by GPT-4 + ChromaDB
- Filters results to cybersecurity-relevant sections only

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ingest` | Ingest a company's 10-K by ticker |
| POST | `/query` | Ask a question across all filings |
| GET | `/search` | Semantic keyword search |

## Example Usage

```bash
# Ingest Microsoft's 2023 10-K
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{"ticker": "MSFT", "year": 2023}'

# Ask a question
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"question": "What cybersecurity incidents did Microsoft disclose?", "company": "MSFT"}'
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
uvicorn rag_api:app --reload --port 8000
```
