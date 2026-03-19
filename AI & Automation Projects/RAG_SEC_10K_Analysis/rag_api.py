"""
RAG System for SEC 10-K Security Risk Analysis
Enables semantic search and NL Q&A over SEC 10-K filings
Author: Kousik Gunasekaran
"""

import os
import logging
import httpx
from pathlib import Path
from typing import List, Optional
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from langchain.chains import RetrievalQA
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SEC 10-K Security Risk RAG API")

EDGAR_FULL_TEXT_SEARCH = "https://efts.sec.gov/LATEST/search-index?q={query}&dateRange=custom&startdt=2023-01-01&forms=10-K"
SECURITY_KEYWORDS = [
    "cybersecurity", "data breach", "ransomware", "information security",
    "cyber attack", "security incident", "data loss", "unauthorized access",
    "material cybersecurity incident", "cyber risk"
]

embeddings = OpenAIEmbeddings(api_key=os.getenv("OPENAI_API_KEY"))
llm = ChatOpenAI(model="gpt-4", api_key=os.getenv("OPENAI_API_KEY"), temperature=0)
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1500, chunk_overlap=200)

vector_store = None


class QueryRequest(BaseModel):
    question: str
    company: Optional[str] = None
    top_k: int = 5


class IngestRequest(BaseModel):
    ticker: str
    year: int = 2023


@app.post("/ingest")
async def ingest_10k(req: IngestRequest):
    """Fetch and ingest a company's 10-K into the vector store."""
    global vector_store
    logger.info(f"Ingesting 10-K for {req.ticker} ({req.year})")

    filing_text = await fetch_10k_text(req.ticker, req.year)
    if not filing_text:
        raise HTTPException(status_code=404, detail=f"Could not retrieve 10-K for {req.ticker}")

    security_sections = extract_security_sections(filing_text, req.ticker)
    docs = text_splitter.create_documents(
        texts=[s["content"] for s in security_sections],
        metadatas=[{"ticker": req.ticker, "section": s["section"], "year": req.year} for s in security_sections]
    )

    if vector_store is None:
        vector_store = Chroma.from_documents(docs, embeddings, persist_directory="./chroma_db")
    else:
        vector_store.add_documents(docs)
        vector_store.persist()

    logger.info(f"Ingested {len(docs)} chunks for {req.ticker}")
    return {"status": "success", "chunks_ingested": len(docs), "ticker": req.ticker}


@app.post("/query")
async def query_filings(req: QueryRequest):
    """Ask a natural language question about security disclosures."""
    if vector_store is None:
        raise HTTPException(status_code=400, detail="No filings ingested. Call /ingest first.")

    search_kwargs = {"k": req.top_k}
    if req.company:
        search_kwargs["filter"] = {"ticker": req.company.upper()}

    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs=search_kwargs),
        return_source_documents=True
    )

    result = qa_chain({"query": req.question})
    sources = [
        {"ticker": doc.metadata.get("ticker"), "section": doc.metadata.get("section")}
        for doc in result.get("source_documents", [])
    ]

    return {"answer": result["result"], "sources": sources}


@app.get("/search")
async def search_security_disclosures(keyword: str, limit: int = 10):
    """Semantic search across all ingested filings."""
    if vector_store is None:
        raise HTTPException(status_code=400, detail="No filings ingested.")
    docs = vector_store.similarity_search(keyword, k=limit)
    return [{"content": doc.page_content[:300], "metadata": doc.metadata} for doc in docs]


async def fetch_10k_text(ticker: str, year: int) -> Optional[str]:
    """Fetch 10-K text from SEC EDGAR."""
    try:
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "Kousik Gunasekaran kousik9200@gmail.com"}) as client:
            search_url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&ticker={ticker}&type=10-K&dateb=&owner=include&count=5&search_text="
            resp = await client.get(search_url)
            # Simplified: in production, parse the filing index and fetch the actual 10-K document
            return f"[10-K text for {ticker} {year} - fetched from EDGAR]"
    except Exception as e:
        logger.error(f"EDGAR fetch failed: {e}")
        return None


def extract_security_sections(text: str, ticker: str) -> List[dict]:
    """Extract cybersecurity-relevant sections from 10-K text."""
    sections = []
    paragraphs = text.split("\n\n")
    for i, para in enumerate(paragraphs):
        para_lower = para.lower()
        if any(kw in para_lower for kw in SECURITY_KEYWORDS):
            sections.append({
                "section": f"security_disclosure_{i}",
                "content": para,
                "ticker": ticker
            })
    if not sections:
        sections.append({"section": "full_text", "content": text, "ticker": ticker})
    return sections
