"""
Zero Trust Policy Engine — CPTS Berbera Logistics
Validates every checkpoint access request against Zero Trust principles
"""

import hashlib
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AccessRequest:
    device_id: str
    operator_id: str
    checkpoint_id: str
    cargo_rfid: str
    timestamp: datetime
    gps_lat: float
    gps_lon: float
    certificate_fingerprint: str


@dataclass
class AccessDecision:
    granted: bool
    reason: str
    risk_score: int
    requires_mfa: bool


CHECKPOINT_COORDINATES = {
    "CHK_BERBERA_PORT": (10.4366, 45.0139),
    "CHK_TOGOCHALE": (11.3167, 42.7167),
    "CHK_DIRE_DAWA": (9.5932, 41.8661),
    "CHK_ADDIS": (9.0167, 38.7500),
}

MAX_COORDINATE_DEVIATION_KM = 0.5


class ZeroTrustPolicyEngine:
    """
    Never Trust, Always Verify — every request evaluated independently.
    """

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        risk_score = 0
        reasons = []

        # 1. Verify device certificate
        if not self._verify_certificate(request.certificate_fingerprint, request.device_id):
            return AccessDecision(granted=False, reason="Invalid device certificate", risk_score=100, requires_mfa=False)

        # 2. Verify checkpoint GPS coordinates
        coord_valid, coord_deviation = self._verify_coordinates(request.checkpoint_id, request.gps_lat, request.gps_lon)
        if not coord_valid:
            risk_score += 40
            reasons.append(f"GPS deviation: {coord_deviation:.2f}km from expected checkpoint location")

        # 3. Check timestamp freshness (replay attack prevention)
        if not self._verify_timestamp(request.timestamp):
            return AccessDecision(granted=False, reason="Request timestamp expired (possible replay attack)", risk_score=100, requires_mfa=False)

        # 4. Validate RFID cargo tag format
        if not self._verify_rfid_format(request.cargo_rfid):
            risk_score += 20
            reasons.append("RFID tag format invalid")

        # 5. Least privilege — operator only accesses their assigned checkpoint
        if not self._verify_operator_assignment(request.operator_id, request.checkpoint_id):
            risk_score += 30
            reasons.append("Operator not assigned to this checkpoint")

        requires_mfa = risk_score >= 20
        granted = risk_score < 70

        reason = "; ".join(reasons) if reasons else "All checks passed"
        logger.info(f"Access {'GRANTED' if granted else 'DENIED'} for {request.operator_id} @ {request.checkpoint_id} | Risk: {risk_score}")

        return AccessDecision(granted=granted, reason=reason, risk_score=risk_score, requires_mfa=requires_mfa)

    def _verify_certificate(self, fingerprint: str, device_id: str) -> bool:
        # In production: validates against PKI Certificate Authority
        return len(fingerprint) == 64 and all(c in "0123456789abcdef" for c in fingerprint.lower())

    def _verify_coordinates(self, checkpoint_id: str, lat: float, lon: float):
        expected = CHECKPOINT_COORDINATES.get(checkpoint_id)
        if not expected:
            return False, 999.0
        deviation = self._haversine(expected[0], expected[1], lat, lon)
        return deviation <= MAX_COORDINATE_DEVIATION_KM, deviation

    def _verify_timestamp(self, ts: datetime) -> bool:
        now = datetime.utcnow()
        return abs((now - ts).total_seconds()) < 300  # 5-minute window

    def _verify_rfid_format(self, rfid: str) -> bool:
        return rfid.startswith("RFID-") and len(rfid) == 21

    def _verify_operator_assignment(self, operator_id: str, checkpoint_id: str) -> bool:
        # In production: database lookup
        return True

    def _haversine(self, lat1, lon1, lat2, lon2) -> float:
        import math
        R = 6371
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
        return R * 2 * math.asin(math.sqrt(a))
