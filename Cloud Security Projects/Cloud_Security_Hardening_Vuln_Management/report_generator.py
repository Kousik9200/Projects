"""
report_generator.py — Remediation Report Generator
Produces JSON and HTML reports with per-finding remediation guidance.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#34c759",
}


class ReportGenerator:
    def __init__(self, findings: list[dict]):
        self.findings  = sorted(findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW"].index(f["severity"]))
        self.generated = datetime.now(timezone.utc).isoformat()

    # ── JSON ──────────────────────────────────────────────────────────────────

    def save_json(self, path: str = "scan_report.json"):
        report = {
            "generated":     self.generated,
            "total_findings": len(self.findings),
            "summary":       self._counts(),
            "findings":      self.findings,
        }
        Path(path).write_text(json.dumps(report, indent=2))
        log.info("JSON report saved → %s", path)

    # ── HTML ─────────────────────────────────────────────────────────────────

    def save_html(self, path: str = "scan_report.html"):
        rows = ""
        for f in self.findings:
            color = SEVERITY_COLORS.get(f["severity"], "#888")
            rows += f"""
            <tr>
              <td><span style="color:{color};font-weight:bold">{f['severity']}</span></td>
              <td><code>{f['check_id']}</code></td>
              <td>{f['description']}</td>
              <td>{f['remediation']}</td>
              <td>{f.get('resource', f.get('reference', '—'))}</td>
            </tr>"""

        counts = self._counts()
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cloud Security Scan Report</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 40px; }}
    h1   {{ color: #58a6ff; }}
    .summary {{ display:flex; gap:20px; margin:20px 0; }}
    .badge {{ padding:10px 20px; border-radius:6px; font-weight:bold; font-size:1.1em; }}
    table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
    th    {{ background:#161b22; color:#8b949e; text-align:left; padding:10px; }}
    td    {{ padding:10px; border-bottom:1px solid #21262d; vertical-align:top; }}
    code  {{ background:#21262d; padding:2px 6px; border-radius:4px; font-size:.85em; }}
    tr:hover td {{ background:#161b22; }}
  </style>
</head>
<body>
  <h1>☁️ Cloud Security Scan Report</h1>
  <p>Generated: {self.generated} | Total findings: <strong>{len(self.findings)}</strong></p>
  <div class="summary">
    <div class="badge" style="background:#3d0016;color:#ff2d55">🔴 CRITICAL: {counts['CRITICAL']}</div>
    <div class="badge" style="background:#3d2200;color:#ff9500">🟠 HIGH: {counts['HIGH']}</div>
    <div class="badge" style="background:#3d3000;color:#ffcc00">🟡 MEDIUM: {counts['MEDIUM']}</div>
    <div class="badge" style="background:#0d3318;color:#34c759">🟢 LOW: {counts['LOW']}</div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Check ID</th><th>Description</th><th>Remediation</th><th>Resource / Ref</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
        Path(path).write_text(html)
        log.info("HTML report saved → %s", path)

    def _counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts
