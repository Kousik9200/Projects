"""
Tailor Agent — Customizes resume and generates cover letters using LLM
"""
import os
import logging
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage

logger = logging.getLogger(__name__)


class TailorAgent:
    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4", api_key=os.getenv("OPENAI_API_KEY"), temperature=0.3)

    def tailor_resume(self, resume: str, jd: str) -> str:
        prompt = f"""Rewrite the experience bullet points in this resume to better match the job description.
Keep all facts accurate. Use keywords from the JD naturally. Keep it concise.

RESUME: {resume[:2000]}
JOB DESCRIPTION: {jd[:1000]}

Return only the updated experience section."""
        try:
            return self.llm.invoke([HumanMessage(content=prompt)]).content
        except Exception as e:
            logger.error(f"Resume tailoring failed: {e}")
            return resume

    def generate_cover_letter(self, resume: str, job: dict) -> str:
        prompt = f"""Write a professional, concise cover letter (3 paragraphs max) for this job.
Be specific, confident, and avoid clichés. Focus on measurable achievements.

CANDIDATE RESUME: {resume[:1500]}
JOB TITLE: {job.get('title')}
COMPANY: {job.get('company')}
JOB DESCRIPTION: {job.get('description', '')[:800]}

Write the cover letter now:"""
        try:
            return self.llm.invoke([HumanMessage(content=prompt)]).content
        except Exception as e:
            logger.error(f"Cover letter generation failed: {e}")
            return ""
