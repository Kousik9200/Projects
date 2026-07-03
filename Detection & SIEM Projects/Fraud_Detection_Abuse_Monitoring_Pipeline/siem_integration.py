"""
siem_integration.py — SIEM & Slack Alert Integration
Sends enriched fraud events to a SIEM endpoint and Slack webhook.
"""

import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from config import SIEM, SLACK

log = logging.getLogger(__name__)


class SIEMClient:
    """Thin HTTP client for SIEM and Slack alerting (no extra dependencies)."""

    def __init__(self):
        self.siem_endpoint = SIEM["endpoint"]
        self.siem_key      = os.getenv(SIEM["api_key_env"], "")
        self.slack_webhook = os.getenv(SLACK["webhook_env"], "")

    # ── SIEM ──────────────────────────────────────────────────────────────────

    def send_alert(self, triage: dict) -> bool:
        """POST enriched event to SIEM ingest endpoint."""
        payload = {
            "source":     SIEM["source"],
            "index":      SIEM["index"],
            "event_type": "fraud_detection",
            "severity":   triage["risk_level"],
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "data":       triage,
        }
        return self._post(self.siem_endpoint, payload, headers={
            "Authorization": f"Bearer {self.siem_key}",
            "Content-Type":  "application/json",
        }, label="SIEM")

    # ── Slack ─────────────────────────────────────────────────────────────────

    def send_slack(self, triage: dict) -> bool:
        """POST alert to Slack webhook."""
        if not self.slack_webhook:
            log.warning("SLACK_WEBHOOK_URL not set — skipping Slack alert")
            return False

        emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "ℹ️"}.get(
            triage["risk_level"], "🔔"
        )
        text = (
            f"{emoji} *Fraud Alert — {triage['risk_level']}*\n"
            f"Session: `{triage['session_id']}`  |  User: `{triage['user_id']}`\n"
            f"Score: *{triage['score']:.1f}/100*  |  "
            f"Actions: `{', '.join(triage['actions'])}`\n"
            f"Top signals: "
            + ", ".join(
                f"{k}={v:.0f}"
                for k, v in sorted(triage["dimensions"].items(), key=lambda x: -x[1])[:3]
            )
        )
        return self._post(self.slack_webhook, {"text": text}, label="Slack")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _post(self, url: str, payload: dict, headers: dict | None = None, label: str = "") -> bool:
        if not url or url.startswith("https://your-"):
            log.debug("%s endpoint not configured — skipping", label)
            return False
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.info("%s alert sent — HTTP %s", label, resp.status)
                return resp.status < 300
        except urllib.error.URLError as exc:
            log.error("%s alert failed: %s", label, exc)
            return False
