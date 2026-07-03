"""
behavioral_scorer.py — Behavioural Analytics Scoring Engine
Scores each session event (0–100) across six risk dimensions.
"""

import math
import statistics
from datetime import datetime, timezone
from typing import Any
from config import SCORING_WEIGHTS, CREDENTIAL_STUFFING, ACCOUNT_TAKEOVER, PAYMENT_ANOMALY


class BehaviouralScorer:
    """
    Computes a composite fraud risk score (0–100) for a login or payment session.
    Each dimension is scored 0–100 and weighted per config.SCORING_WEIGHTS.
    """

    def __init__(self, session: dict[str, Any], history: dict[str, Any]):
        """
        Args:
            session : current event (login attempt, payment, etc.)
            history : aggregated stats for the user / IP over the lookback window
        """
        self.session = session
        self.history = history

    # ── Public interface ──────────────────────────────────────────────────────

    def score(self) -> dict[str, Any]:
        """Return composite score and per-dimension breakdown."""
        dimensions = {
            "login_velocity":       self._score_login_velocity(),
            "geo_anomaly":          self._score_geo_anomaly(),
            "device_fingerprint":   self._score_device_fingerprint(),
            "failed_auth_ratio":    self._score_failed_auth_ratio(),
            "transaction_velocity": self._score_transaction_velocity(),
            "ip_reputation":        self._score_ip_reputation(),
        }

        composite = sum(
            dimensions[dim] * (SCORING_WEIGHTS[dim] / 100)
            for dim in dimensions
        )

        return {
            "composite_score": round(composite, 2),
            "dimensions":      dimensions,
            "session_id":      self.session.get("session_id"),
            "user_id":         self.session.get("user_id"),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
        }

    # ── Dimension scorers ─────────────────────────────────────────────────────

    def _score_login_velocity(self) -> float:
        """High logins-per-minute from same IP → high score."""
        logins_per_min = self.history.get("logins_per_minute", 0)
        threshold = CREDENTIAL_STUFFING["max_failed_logins_per_minute"]
        return min(100.0, (logins_per_min / threshold) * 100)

    def _score_geo_anomaly(self) -> float:
        """Impossible travel or entirely new country."""
        speed_kmh = self.history.get("travel_speed_kmh", 0)
        is_new_country = self.session.get("new_country", False)
        threshold = ACCOUNT_TAKEOVER["impossible_travel_km_per_hour"]

        if is_new_country:
            geo_score = 50.0
        else:
            geo_score = 0.0

        travel_score = min(100.0, (speed_kmh / threshold) * 100) if speed_kmh else 0.0
        return min(100.0, geo_score + travel_score)

    def _score_device_fingerprint(self) -> float:
        """New device fingerprint or headless-browser signals."""
        is_new_device  = self.session.get("new_device", False)
        is_headless    = self.session.get("headless_browser", False)
        is_tor         = self.session.get("tor_exit_node", False)
        score = 0.0
        if is_new_device:  score += 30.0
        if is_headless:    score += 50.0
        if is_tor:         score += 20.0
        return min(100.0, score)

    def _score_failed_auth_ratio(self) -> float:
        """Ratio of failed logins to total attempts."""
        total   = self.history.get("total_auth_attempts", 1)
        failed  = self.history.get("failed_auth_attempts", 0)
        ratio   = failed / total
        return min(100.0, ratio * 100)

    def _score_transaction_velocity(self) -> float:
        """Transactions per hour vs user baseline; z-score on amount."""
        txns_per_hour = self.history.get("txns_per_hour", 0)
        max_txns      = PAYMENT_ANOMALY["max_txns_per_hour"]
        velocity_score = min(100.0, (txns_per_hour / max_txns) * 100)

        amount_zscore = abs(self.history.get("amount_zscore", 0))
        z_threshold   = PAYMENT_ANOMALY["max_txn_amount_zscore"]
        zscore_score  = min(100.0, (amount_zscore / z_threshold) * 50)

        return min(100.0, velocity_score * 0.6 + zscore_score * 0.4)

    def _score_ip_reputation(self) -> float:
        """External threat-intel reputation score (already 0–100)."""
        return float(self.session.get("ip_reputation_score", 0))
