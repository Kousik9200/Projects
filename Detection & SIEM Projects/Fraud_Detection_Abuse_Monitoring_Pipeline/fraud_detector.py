"""
fraud_detector.py — Fraud Detection & Abuse Monitoring Pipeline
Main orchestrator: ingest event → score → classify → triage → alert.

Usage:
    python fraud_detector.py --event event.json
    python fraud_detector.py --stream          # mock real-time stream mode
"""

import argparse
import json
import logging
import sys
import time
import random
from datetime import datetime, timezone

from behavioral_scorer import BehaviouralScorer
from siem_integration import SIEMClient
from config import RISK_THRESHOLDS, TRIAGE_ACTIONS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ── Risk classifier ───────────────────────────────────────────────────────────

def classify_risk(score: float) -> str:
    for level, threshold in sorted(RISK_THRESHOLDS.items(), key=lambda x: -x[1]):
        if score >= threshold:
            return level
    return "LOW"


# ── Auto-triage dispatcher ────────────────────────────────────────────────────

def triage(event: dict, score_result: dict, siem: SIEMClient) -> dict:
    risk_level = classify_risk(score_result["composite_score"])
    actions    = TRIAGE_ACTIONS.get(risk_level, ["log_event"])

    log.info(
        "Session %s | Score=%.1f | Risk=%s | Actions=%s",
        score_result["session_id"],
        score_result["composite_score"],
        risk_level,
        actions,
    )

    triage_result = {
        "session_id":  score_result["session_id"],
        "user_id":     score_result["user_id"],
        "risk_level":  risk_level,
        "score":       score_result["composite_score"],
        "actions":     actions,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "dimensions":  score_result["dimensions"],
    }

    if "alert_siem" in actions:
        siem.send_alert(triage_result)

    if "alert_slack" in actions:
        siem.send_slack(triage_result)

    if "block_session" in actions:
        log.warning("BLOCKING session %s", score_result["session_id"])
        triage_result["blocked"] = True

    if "queue_review" in actions:
        log.info("Queuing session %s for manual review", score_result["session_id"])
        triage_result["queued_for_review"] = True

    return triage_result


# ── Pipeline ──────────────────────────────────────────────────────────────────

def process_event(event: dict, siem: SIEMClient) -> dict:
    """Full pipeline: score → classify → triage."""
    history = event.pop("history", {})
    scorer  = BehaviouralScorer(session=event, history=history)
    result  = scorer.score()
    return triage(event, result, siem)


def run_stream_mode(siem: SIEMClient, duration_s: int = 30):
    """Simulate a real-time event stream for demo purposes."""
    log.info("Starting stream mode for %ds …", duration_s)
    start = time.time()
    while time.time() - start < duration_s:
        event = _mock_event()
        result = process_event(event, siem)
        print(json.dumps(result, indent=2))
        time.sleep(random.uniform(0.3, 1.2))


# ── Mock event generator (demo / testing) ────────────────────────────────────

def _mock_event() -> dict:
    import uuid
    risk_profile = random.choices(
        ["low", "medium", "high", "critical"],
        weights=[50, 25, 15, 10],
    )[0]

    profiles = {
        "low":      dict(logins_per_minute=1,  travel_speed_kmh=0,    headless_browser=False, ip_reputation_score=5,  failed_auth_attempts=0, total_auth_attempts=1,  txns_per_hour=2,  amount_zscore=0.5),
        "medium":   dict(logins_per_minute=5,  travel_speed_kmh=200,  headless_browser=False, ip_reputation_score=30, failed_auth_attempts=3, total_auth_attempts=5,  txns_per_hour=8,  amount_zscore=1.8),
        "high":     dict(logins_per_minute=12, travel_speed_kmh=600,  headless_browser=True,  ip_reputation_score=65, failed_auth_attempts=8, total_auth_attempts=10, txns_per_hour=18, amount_zscore=3.5),
        "critical": dict(logins_per_minute=30, travel_speed_kmh=2000, headless_browser=True,  ip_reputation_score=95, failed_auth_attempts=20, total_auth_attempts=21, txns_per_hour=40, amount_zscore=6.0),
    }

    p = profiles[risk_profile]
    return {
        "session_id":        str(uuid.uuid4()),
        "user_id":           f"user_{random.randint(1000, 9999)}",
        "ip_address":        f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
        "new_device":        risk_profile in ("high", "critical"),
        "new_country":       risk_profile == "critical",
        "tor_exit_node":     risk_profile == "critical",
        "headless_browser":  p["headless_browser"],
        "ip_reputation_score": p["ip_reputation_score"],
        "history": {
            "logins_per_minute":    p["logins_per_minute"],
            "travel_speed_kmh":     p["travel_speed_kmh"],
            "failed_auth_attempts": p["failed_auth_attempts"],
            "total_auth_attempts":  p["total_auth_attempts"],
            "txns_per_hour":        p["txns_per_hour"],
            "amount_zscore":        p["amount_zscore"],
        },
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Fraud Detection & Abuse Monitoring Pipeline")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--event",  metavar="FILE", help="Path to JSON event file")
    group.add_argument("--stream", action="store_true", help="Run mock real-time stream (30s)")
    args = parser.parse_args()

    siem = SIEMClient()

    if args.stream:
        run_stream_mode(siem)
    else:
        with open(args.event) as f:
            event = json.load(f)
        result = process_event(event, siem)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
