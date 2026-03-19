"""
Agentic Job Search Automation — Orchestrator
Author: Kousik Gunasekaran
"""

import os
import json
import logging
import argparse
from datetime import datetime
from agents.scraper_agent import ScraperAgent
from agents.analyzer_agent import AnalyzerAgent
from agents.tailor_agent import TailorAgent
from agents.tracker_agent import TrackerAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MY_RESUME = """
Kousik Gunasekaran | Cybersecurity Engineer | kousik9200@gmail.com
CISSP | CompTIA Security+ | CCNA
M.S. Cybersecurity, Yeshiva University (In Progress)

EXPERIENCE:
- Cybersecurity Architecture Intern, Peblink/Gennisi Group (Jan 2026–Present)
  Designed Zero Trust architecture for CPTS securing Berbera-Ethiopia logistics corridor.
  Threat modeling using MITRE ATT&CK for ICS.

- Cybersecurity Engineer, Sacha Engineering (Ford), India (2023–2024)
  Network security architecture, SIEM deployment, DevSecOps integration, NIST CSF.

- SOC Analyst, Tata Consultancy Services, India (2020–2023)
  Splunk/QRadar monitoring, phishing IR, MITRE ATT&CK threat hunting, MTTR reduction 40%.

SKILLS: Python, Splunk, Microsoft Sentinel, AWS/Azure/GCP, Zero Trust, MITRE ATT&CK,
n8n, LangChain, Docker, Metasploit, Burp Suite, NIST, ISO 27001
"""


class JobSearchOrchestrator:
    def __init__(self):
        self.scraper = ScraperAgent()
        self.analyzer = AnalyzerAgent()
        self.tailor = TailorAgent()
        self.tracker = TrackerAgent()

    def run(self, job_title: str, location: str, max_jobs: int = 20):
        logger.info(f"Starting job search: '{job_title}' in '{location}'")

        # Step 1: Scrape postings
        jobs = self.scraper.search(job_title, location, limit=max_jobs)
        logger.info(f"Found {len(jobs)} job postings")

        results = []
        for job in jobs:
            # Step 2: Score fit
            score = self.analyzer.score_fit(MY_RESUME, job["description"])
            job["fit_score"] = score
            logger.info(f"  [{score}%] {job['title']} @ {job['company']}")

            if score >= 70:
                # Step 3: Tailor resume + cover letter
                job["tailored_resume"] = self.tailor.tailor_resume(MY_RESUME, job["description"])
                job["cover_letter"] = self.tailor.generate_cover_letter(MY_RESUME, job)

                # Step 4: Log to tracker
                self.tracker.log(job)
                results.append(job)

        logger.info(f"\nHigh-fit jobs (>=70%): {len(results)}/{len(jobs)}")
        self._save_results(results)
        return results

    def _save_results(self, results: list):
        path = f"./output/job_search_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        os.makedirs("./output", exist_ok=True)
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--search", default="Security Engineer", help="Job title to search")
    parser.add_argument("--location", default="New York", help="Location")
    parser.add_argument("--max", type=int, default=20, help="Max jobs to scrape")
    args = parser.parse_args()

    orch = JobSearchOrchestrator()
    orch.run(args.search, args.location, args.max)
