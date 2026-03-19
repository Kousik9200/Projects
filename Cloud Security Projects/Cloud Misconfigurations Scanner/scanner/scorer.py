#!/usr/bin/env python3
"""
scorer.py - Risk scoring engine for cloud misconfiguration findings
Applies asset criticality multipliers and produces prioritized finding lists.

Author: Kousik Gunasekaran
"""

from typing import Optional

SEVERITY_BASE_SCORES = {
    "CRITICAL": 10.0,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "INFO":     1.0,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

ACCOUNT_ENV_MULTIPLIERS = {
    "prod":    1.5,
    "staging": 1.0,
    "dev":     0.6,
    "sandbox": 0.4,
}

CATEGORY_WEIGHTS = {
    "IAM":         1.3,
    "S3":          1.2,
    "SG":          1.2,
    "CT":          1.0,
    "RDS":         1.1,
    "EC2":         1.0,
}


def score_finding(finding: dict, environment: str = "prod") -> dict:
    """
    Add a numeric risk score and enriched metadata to a finding.

    Score = base_severity_score * category_weight * environment_multiplier
    """
    severity = finding.get("severity", "LOW").upper()
    finding_id = finding.get("finding_id", "UNKNOWN")

    base_score = SEVERITY_BASE_SCORES.get(severity, 2.5)
    env_multiplier = ACCOUNT_ENV_MULTIPLIERS.get(environment.lower(), 1.0)

    # Derive category from finding ID prefix
    category = finding_id.split("-")[0].upper() if "-" in finding_id else "MISC"
    category_weight = CATEGORY_WEIGHTS.get(category, 1.0)

    risk_score = round(base_score * category_weight * env_multiplier, 2)

    finding["risk_score"] = risk_score
    finding["environment"] = environment
    finding["category"] = category
    finding["priority_rank"] = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 99

    return finding


def score_all_findings(findings: list, environment: str = "prod") -> list:
    """Score all findings and return sorted by risk_score descending."""
    scored = [score_finding(f, environment) for f in findings]
    return sorted(scored, key=lambda x: (-x["risk_score"], x["priority_rank"]))


def generate_summary(findings: list) -> dict:
    """Generate a statistics summary from a list of scored findings."""
    summary = {
        "total": len(findings),
        "by_severity": {s: 0 for s in SEVERITY_ORDER},
        "by_category": {},
        "critical_resources": [],
        "top_5_by_score": []
    }

    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1

        cat = f.get("category", "MISC")
        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        if sev == "CRITICAL":
            summary["critical_resources"].append(f.get("resource", "unknown"))

    summary["top_5_by_score"] = [
        {"title": f.get("title", ""), "score": f.get("risk_score", 0), "severity": f.get("severity", "")}
        for f in findings[:5]
    ]

    return summary
