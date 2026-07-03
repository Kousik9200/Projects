"""
control_validator.py — SOC 2 Control Validator
Validates each SOC 2 Trust Service Criterion against live evidence.
"""

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# SOC 2 Trust Service Criteria (CC = Common Criteria)
SOC2_CONTROLS = {
    "CC6.1":  "Logical access controls restrict access to information assets",
    "CC6.2":  "Access is removed when no longer required",
    "CC6.3":  "Role-based access controls are implemented and reviewed",
    "CC7.1":  "System events are logged and monitored",
    "CC7.2":  "Security incidents are detected and responded to",
    "CC7.3":  "Vulnerability management identifies and remediates risks",
    "CC8.1":  "Changes to production systems follow change management procedures",
    "CC9.1":  "Risk assessment identifies and manages business risks",
    "A1.1":   "System availability meets defined uptime commitments",
    "C1.1":   "Confidential data is classified and protected",
    "PI1.1":  "Data processing is complete, accurate, and timely",
}

CONTROL_THRESHOLDS = {
    "CC6.1": {"mfa_coverage_pct": 100, "privileged_access_reviewed_days": 90},
    "CC6.2": {"orphaned_accounts_max": 0, "deprovisioning_hours_max": 24},
    "CC7.1": {"log_retention_days_min": 365, "siem_coverage_pct": 100},
    "CC7.2": {"mttd_hours_max": 24, "mttr_hours_max": 72},
    "CC7.3": {"critical_vuln_sla_days": 7, "high_vuln_sla_days": 30},
    "CC8.1": {"change_approval_pct": 100, "unauthorized_changes_max": 0},
}


class ControlValidator:
    """
    Validates SOC 2 controls against collected evidence.
    Returns pass/fail per control with gap analysis.
    """

    def __init__(self, evidence: dict[str, Any]):
        self.evidence = evidence
        self.results:  list[dict] = []

    def validate_all(self) -> list[dict]:
        for control_id, description in SOC2_CONTROLS.items():
            result = self._validate_control(control_id, description)
            self.results.append(result)
            status = "✅ PASS" if result["status"] == "PASS" else "❌ FAIL"
            log.info("%s  %s — %s", status, control_id, description[:60])
        return self.results

    def _validate_control(self, control_id: str, description: str) -> dict:
        validator = getattr(self, f"_check_{control_id.replace('.', '_').lower()}", None)
        if validator:
            passed, gaps = validator()
        else:
            # Default: check evidence completeness
            passed, gaps = self._check_evidence_exists(control_id)

        return {
            "control_id":   control_id,
            "description":  description,
            "status":       "PASS" if passed else "FAIL",
            "gaps":         gaps,
            "evidence_ref": self.evidence.get(control_id, {}).get("source", "N/A"),
            "timestamp":    datetime.now(timezone.utc).isoformat(),
        }

    # ── Control checkers ──────────────────────────────────────────────────────

    def _check_cc6_1(self):
        ev     = self.evidence.get("CC6.1", {})
        thresh = CONTROL_THRESHOLDS["CC6.1"]
        gaps   = []
        mfa    = ev.get("mfa_coverage_pct", 0)
        if mfa < thresh["mfa_coverage_pct"]:
            gaps.append(f"MFA coverage {mfa}% — must be 100%")
        days = ev.get("privileged_access_reviewed_days", 999)
        if days > thresh["privileged_access_reviewed_days"]:
            gaps.append(f"Privileged access last reviewed {days} days ago (max {thresh['privileged_access_reviewed_days']})")
        return (len(gaps) == 0), gaps

    def _check_cc6_2(self):
        ev     = self.evidence.get("CC6.2", {})
        thresh = CONTROL_THRESHOLDS["CC6.2"]
        gaps   = []
        orphans = ev.get("orphaned_accounts", 0)
        if orphans > thresh["orphaned_accounts_max"]:
            gaps.append(f"{orphans} orphaned accounts detected (max 0)")
        depr_hrs = ev.get("avg_deprovisioning_hours", 0)
        if depr_hrs > thresh["deprovisioning_hours_max"]:
            gaps.append(f"Avg deprovisioning time {depr_hrs}h (max {thresh['deprovisioning_hours_max']}h)")
        return (len(gaps) == 0), gaps

    def _check_cc7_1(self):
        ev     = self.evidence.get("CC7.1", {})
        thresh = CONTROL_THRESHOLDS["CC7.1"]
        gaps   = []
        retention = ev.get("log_retention_days", 0)
        if retention < thresh["log_retention_days_min"]:
            gaps.append(f"Log retention {retention} days (min {thresh['log_retention_days_min']})")
        coverage = ev.get("siem_coverage_pct", 0)
        if coverage < thresh["siem_coverage_pct"]:
            gaps.append(f"SIEM coverage {coverage}% (required 100%)")
        return (len(gaps) == 0), gaps

    def _check_cc7_2(self):
        ev     = self.evidence.get("CC7.2", {})
        thresh = CONTROL_THRESHOLDS["CC7.2"]
        gaps   = []
        mttd = ev.get("mttd_hours", 999)
        if mttd > thresh["mttd_hours_max"]:
            gaps.append(f"MTTD {mttd}h exceeds {thresh['mttd_hours_max']}h SLA")
        mttr = ev.get("mttr_hours", 999)
        if mttr > thresh["mttr_hours_max"]:
            gaps.append(f"MTTR {mttr}h exceeds {thresh['mttr_hours_max']}h SLA")
        return (len(gaps) == 0), gaps

    def _check_cc7_3(self):
        ev     = self.evidence.get("CC7.3", {})
        thresh = CONTROL_THRESHOLDS["CC7.3"]
        gaps   = []
        crit_overdue = ev.get("critical_vulns_overdue", 0)
        if crit_overdue:
            gaps.append(f"{crit_overdue} critical vulns exceed {thresh['critical_vuln_sla_days']}-day SLA")
        high_overdue = ev.get("high_vulns_overdue", 0)
        if high_overdue:
            gaps.append(f"{high_overdue} high vulns exceed {thresh['high_vuln_sla_days']}-day SLA")
        return (len(gaps) == 0), gaps

    def _check_cc8_1(self):
        ev     = self.evidence.get("CC8.1", {})
        thresh = CONTROL_THRESHOLDS["CC8.1"]
        gaps   = []
        approval_pct = ev.get("change_approval_pct", 0)
        if approval_pct < thresh["change_approval_pct"]:
            gaps.append(f"Change approval rate {approval_pct}% (required 100%)")
        unauth = ev.get("unauthorized_changes", 0)
        if unauth > thresh["unauthorized_changes_max"]:
            gaps.append(f"{unauth} unauthorized changes detected")
        return (len(gaps) == 0), gaps

    def _check_evidence_exists(self, control_id: str):
        has_evidence = bool(self.evidence.get(control_id))
        gaps = [] if has_evidence else [f"No evidence collected for {control_id}"]
        return has_evidence, gaps
