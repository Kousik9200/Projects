"""
Analyzer Agent — Scores resume-to-job fit using keyword overlap + LLM
"""
import os
import re
import logging
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage

logger = logging.getLogger(__name__)

SCORE_PROMPT = """Score how well this resume matches this job description on a scale of 0-100.
Return ONLY a JSON object: {{"score": <number>, "matching_skills": [<list>], "missing_skills": [<list>]}}

RESUME:
{resume}

JOB DESCRIPTION:
{jd}"""


class AnalyzerAgent:
    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4", api_key=os.getenv("OPENAI_API_KEY"), temperature=0)

    def score_fit(self, resume: str, jd: str) -> int:
        try:
            import json
            response = self.llm.invoke([HumanMessage(content=SCORE_PROMPT.format(resume=resume[:2000], jd=jd[:1500]))])
            result = json.loads(response.content)
            return result.get("score", 50)
        except Exception as e:
            logger.error(f"Scoring failed: {e}")
            return self._keyword_score(resume, jd)

    def _keyword_score(self, resume: str, jd: str) -> int:
        """Fallback: simple keyword overlap scoring."""
        jd_words = set(re.findall(r'\b\w{4,}\b', jd.lower()))
        resume_words = set(re.findall(r'\b\w{4,}\b', resume.lower()))
        overlap = len(jd_words & resume_words)
        return min(int((overlap / max(len(jd_words), 1)) * 200), 100)
