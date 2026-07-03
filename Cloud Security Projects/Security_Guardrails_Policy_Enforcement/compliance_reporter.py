"""
compliance_reporter.py — Security Guardrails & Policy Enforcement Framework
Aggregates policy violations by control family and produces compliance reports
aligned to NIST CSF, CIS Controls, and SOC 2 Trust Service Criteria.

Usage:
    from policy_engine import PolicyEngine, DEMO_PLAN
    from compliance_reporter import ComplianceReporter

    engine = PolicyEngine()
    violations = engine.evaluate(DEMO_PLAN)
    reporter = ComplianceReporter(violations)
    reporter.print_summary()
    reporter.save_html("report.html")
    reporter.save_json("report.json")
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ── Framework mappings ────────────────────────────────────────────────────────

FRAMEWORK_FAMILIES = {
    "NIST CSF": {
        "IDENTIFY":  ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM"],
        "PROTECT":   ["PR.AC", "PR.AT", "PR.DS", "PR.IP", "PR.MA", "PR.PT"],
        "DETECT":    ["DE.AE", "DE.CM", "DE.DP"],
        "RESPOND":   ["RS.AN", "RS.CO", "RS.IM", "RS.MI", "RS.RP"],
        "RECOVER":   ["RC.CO", "RC.IM", "RC.RP"],
    },
    "CIS": {
        "Access Control":   ["CIS 1", "CIS 5", "CIS 6"],
        "Data Protection":  ["CIS 2", "CIS 3"],
        "Network Security": ["CIS 4", "CIS 12", "CIS 13"],
        "Audit & Log":      ["CIS 8", "CIS 3.1"],
        "IAM":              ["CIS 1.16"],
    },
    "SOC 2": {
        "Common Criteria":    ["CC6", "CC7", "CC8", "CC9"],
        "Availability":       ["A1"],
        "Confidentiality":    ["C1"],
        "Processing Integrity": ["PI1"],
    },
}

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class FrameworkSummary:
    framework:    str
    category:     str
    total_checks: int
    violations:   int
    score:        float           # 0-100
    controls:     list[str]       # framework references hit


@dataclass
class ComplianceReport:
    generated_at:      str
    total_violations:  int
    critical_count:    int
    high_count:        int
    medium_count:      int
    low_count:         int
    overall_score:     float
    frameworks:        list[FrameworkSummary]
    top_violations:    list[dict]


# ── Reporter ──────────────────────────────────────────────────────────────────

class ComplianceReporter:
    def __init__(self, violations: list):
        self.violations = violations
        self.report: Optional[ComplianceReport] = None
        self._build_report()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_report(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.violations:
            counts[v.severity] = counts.get(v.severity, 0) + 1

        weighted_score = self._calculate_score()
        frameworks     = self._aggregate_by_framework()

        # Top 5 most severe
        top = sorted(self.violations, key=lambda v: SEVERITY_WEIGHTS.get(v.severity, 0), reverse=True)[:5]

        self.report = ComplianceReport(
            generated_at=     datetime.now(timezone.utc).isoformat(),
            total_violations= len(self.violations),
            critical_count=   counts["CRITICAL"],
            high_count=       counts["HIGH"],
            medium_count=     counts["MEDIUM"],
            low_count=        counts["LOW"],
            overall_score=    weighted_score,
            frameworks=       frameworks,
            top_violations=[  {
                "policy_id":   v.policy_id,
                "severity":    v.severity,
                "resource":    v.resource,
                "description": v.description,
                "frameworks":  v.frameworks,
            } for v in top],
        )

    def _calculate_score(self) -> float:
        """Weighted compliance score: 100 − penalty per violation."""
        if not self.violations:
            return 100.0
        penalty = sum(SEVERITY_WEIGHTS.get(v.severity, 1) * 5 for v in self.violations)
        return max(0.0, round(100.0 - penalty, 1))

    def _aggregate_by_framework(self) -> list[FrameworkSummary]:
        summaries = []
        for framework, categories in FRAMEWORK_FAMILIES.items():
            for category, prefixes in categories.items():
                hits = [
                    v for v in self.violations
                    if any(
                        any(ref.startswith(p) for p in prefixes)
                        for ref in v.frameworks
                    )
                ]
                # Normalise check count against a baseline of 3 per category
                total  = max(len(hits) + 3, 3)
                score  = round((total - len(hits)) / total * 100, 1)
                refs   = list({ref for v in hits for ref in v.frameworks if any(ref.startswith(p) for p in prefixes)})
                summaries.append(FrameworkSummary(
                    framework=    framework,
                    category=     category,
                    total_checks= total,
                    violations=   len(hits),
                    score=        score,
                    controls=     refs,
                ))
        return summaries

    # ── Public API ────────────────────────────────────────────────────────────

    def print_summary(self):
        r = self.report
        print(f"\n{'═'*65}")
        print("  COMPLIANCE REPORT — SECURITY GUARDRAILS")
        print(f"  Generated: {r.generated_at}")
        print(f"{'═'*65}")
        print(f"  Overall Score : {r.overall_score:.1f} / 100")
        print(f"  Violations    : {r.total_violations}  "
              f"(CRITICAL={r.critical_count}, HIGH={r.high_count}, "
              f"MEDIUM={r.medium_count}, LOW={r.low_count})")
        print()

        print("  BY FRAMEWORK:")
        current_fw = None
        for fs in r.frameworks:
            if fs.violations > 0:
                if fs.framework != current_fw:
                    print(f"    ── {fs.framework} ──")
                    current_fw = fs.framework
                bar   = "█" * int(fs.score / 10) + "░" * (10 - int(fs.score / 10))
                print(f"    {fs.category:<22} [{bar}] {fs.score:5.1f}%  ({fs.violations} violations)")

        if r.top_violations:
            print()
            print("  TOP VIOLATIONS:")
            for v in r.top_violations:
                print(f"    [{v['severity']}] {v['resource']}")
                print(f"       {v['description']}")
        print(f"{'═'*65}\n")

    def save_json(self, path: str) -> str:
        out = {
            "generated_at":     self.report.generated_at,
            "overall_score":    self.report.overall_score,
            "total_violations": self.report.total_violations,
            "severity_counts": {
                "CRITICAL": self.report.critical_count,
                "HIGH":     self.report.high_count,
                "MEDIUM":   self.report.medium_count,
                "LOW":      self.report.low_count,
            },
            "frameworks": [
                {
                    "framework":    f.framework,
                    "category":     f.category,
                    "score":        f.score,
                    "violations":   f.violations,
                    "controls_hit": f.controls,
                }
                for f in self.report.frameworks if f.violations > 0
            ],
            "top_violations": self.report.top_violations,
        }
        Path(path).write_text(json.dumps(out, indent=2))
        log.info("Compliance report (JSON) saved: %s", path)
        return path

    def save_html(self, path: str) -> str:
        r = self.report
        score_color = "#22c55e" if r.overall_score >= 80 else "#f59e0b" if r.overall_score >= 60 else "#ef4444"
        rows = ""
        for v in r.top_violations:
            badge = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}.get(v["severity"], "#6b7280")
            rows += f"""
            <tr>
              <td><span style="background:{badge};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{v["severity"]}</span></td>
              <td style="font-family:monospace">{v["resource"]}</td>
              <td>{v["description"]}</td>
              <td style="font-size:12px">{", ".join(v["frameworks"])}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Compliance Report — Security Guardrails</title>
<style>
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }}
  h1   {{ color:#f1f5f9; font-size:24px; margin-bottom:4px; }}
  .meta{{ color:#94a3b8; font-size:13px; margin-bottom:24px; }}
  .card{{ background:#1e293b; border-radius:10px; padding:20px; margin-bottom:16px; }}
  .score{{ font-size:48px; font-weight:700; color:{score_color}; }}
  table{{ width:100%; border-collapse:collapse; font-size:14px; }}
  th   {{ text-align:left; padding:10px; background:#0f172a; color:#94a3b8; font-weight:600; }}
  td   {{ padding:10px; border-bottom:1px solid #334155; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
</style>
</head>
<body>
<h1>Security Guardrails — Compliance Report</h1>
<div class="meta">Generated: {r.generated_at}</div>

<div class="card">
  <div class="score">{r.overall_score:.1f}<span style="font-size:20px;color:#94a3b8"> / 100</span></div>
  <div style="color:#94a3b8;margin-top:4px">Overall Compliance Score</div>
  <div style="margin-top:16px">
    <span style="background:#ef4444;color:#fff;padding:4px 12px;border-radius:6px;margin-right:8px">CRITICAL: {r.critical_count}</span>
    <span style="background:#f97316;color:#fff;padding:4px 12px;border-radius:6px;margin-right:8px">HIGH: {r.high_count}</span>
    <span style="background:#f59e0b;color:#fff;padding:4px 12px;border-radius:6px;margin-right:8px">MEDIUM: {r.medium_count}</span>
    <span style="background:#22c55e;color:#fff;padding:4px 12px;border-radius:6px">LOW: {r.low_count}</span>
  </div>
</div>

<div class="card">
  <h2 style="margin-top:0;font-size:16px;color:#94a3b8">TOP VIOLATIONS</h2>
  <table>
    <tr><th>Severity</th><th>Resource</th><th>Issue</th><th>Frameworks</th></tr>
    {rows}
  </table>
</div>
</body>
</html>"""
        Path(path).write_text(html)
        log.info("Compliance report (HTML) saved: %s", path)
        return path


# ── CLI demo ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from policy_engine import PolicyEngine, DEMO_PLAN

    engine     = PolicyEngine()
    violations = engine.evaluate(DEMO_PLAN)
    reporter   = ComplianceReporter(violations)
    reporter.print_summary()
    reporter.save_html("/tmp/guardrails_report.html")
    reporter.save_json("/tmp/guardrails_report.json")
    print("Reports saved to /tmp/guardrails_report.{html,json}")
