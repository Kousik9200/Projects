"""
Tracker Agent — Logs job applications to JSON file
"""
import json
import os
from datetime import datetime


class TrackerAgent:
    def __init__(self):
        self.log_path = "./output/application_tracker.json"
        self.applications = self._load()

    def log(self, job: dict):
        entry = {
            "id": job.get("id"),
            "title": job.get("title"),
            "company": job.get("company"),
            "location": job.get("location"),
            "url": job.get("url"),
            "fit_score": job.get("fit_score"),
            "status": "To Apply",
            "applied_at": None,
            "logged_at": datetime.utcnow().isoformat(),
            "notes": ""
        }
        self.applications.append(entry)
        self._save()

    def _load(self):
        os.makedirs("./output", exist_ok=True)
        try:
            with open(self.log_path) as f:
                return json.load(f)
        except Exception:
            return []

    def _save(self):
        with open(self.log_path, "w") as f:
            json.dump(self.applications, f, indent=2)
