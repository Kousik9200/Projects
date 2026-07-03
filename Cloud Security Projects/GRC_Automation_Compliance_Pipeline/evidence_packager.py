"""
evidence_packager.py — Automated Evidence Package Generator
Bundles collected evidence + validation results into audit-ready ZIP packages.
"""

import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


class EvidencePackager:
    """
    Produces a dated ZIP evidence package containing:
      - evidence.json       (raw collected evidence per control)
      - validation.json     (pass/fail results with gaps)
      - summary.html        (human-readable audit-ready report)
      - gap_report.json     (only failing controls with remediation steps)
    """

    def __init__(self, evidence: dict, validation_results: list[dict]):
        self.evidence   = evidence
        self.results    = validation_results
        self.timestamp  = datetime.now(timezone.utc)
        self.date_str   = self.timestamp.strftime("%Y-%m-%d")

    def package(self, output_dir: str = ".") -> str:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        zip_name = out_path / f"soc2_evidence_{self.date_str}.zip"

        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("evidence.json",    json.dumps(self.evidence, indent=2, default=str))
            zf.writestr("validation.json",  json.dumps(self.results,  indent=2, default=str))
            zf.writestr("summary.html",     self._build_html())
            zf.writestr("gap_report.json",  json.dumps(self._gap_report(), indent=2))

        log.info("Evidence package saved → %s", zip_name)
        return str(zip_name)

    # ── Report builders ───────────────────────────────────────────────────────

    def _gap_report(self) -> dict:
        failing = [r for r in self.results if r["status"] == "FAIL"]
        return {
            "generated":       self.timestamp.isoformat(),
            "failing_controls": len(failing),
            "gaps": [
                {
                    "control_id":  r["control_id"],
                    "description": r["description"],
                    "gaps":        r["gaps"],
                }
                for r in failing
            ],
        }

    def _build_html(self) -> str:
        passing = sum(1 for r in self.results if r["status"] == "PASS")
        failing = len(self.results) - passing
        score   = round(passing / max(len(self.results), 1) * 100, 1)

        color = "#34c759" if score >= 90 else "#ff9500" if score >= 70 else "#ff2d55"

        rows = ""
        for r in self.results:
            status_badge = (
                '<span style="color:#34c759">✅ PASS</span>'
                if r["status"] == "PASS"
                else '<span style="color:#ff2d55">❌ FAIL</span>'
            )
            gaps_html = "<br>".join(f"• {g}" for g in r["gaps"]) if r["gaps"] else "—"
            rows += f"""
            <tr>
              <td><strong>{r['control_id']}</strong></td>
              <td>{r['description']}</td>
              <td>{status_badge}</td>
              <td style="font-size:.85em;color:#888">{gaps_html}</td>
              <td style="font-size:.8em">{r.get('evidence_ref','—')}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SOC 2 Evidence Package — {self.date_str}</title>
  <style>
    body  {{ font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9; margin:40px; }}
    h1    {{ color:#58a6ff; }}
    .score{{ font-size:3em; font-weight:bold; color:{color}; }}
    table {{ width:100%; border-collapse:collapse; margin-top:24px; }}
    th    {{ background:#161b22; color:#8b949e; padding:10px; text-align:left; }}
    td    {{ padding:10px; border-bottom:1px solid #21262d; vertical-align:top; }}
    tr:hover td {{ background:#161b22; }}
  </style>
</head>
<body>
  <h1>SOC 2 Compliance Evidence Package</h1>
  <p>Generated: {self.timestamp.isoformat()} | Period: {self.date_str}</p>
  <p class="score">{score}%</p>
  <p>{passing} controls passing · {failing} gaps identified</p>
  <table>
    <thead>
      <tr><th>Control</th><th>Description</th><th>Status</th><th>Gaps</th><th>Evidence</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
