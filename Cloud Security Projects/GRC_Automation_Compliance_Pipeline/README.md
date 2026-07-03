# GRC Automation & Continuous Compliance Pipeline

Continuous compliance pipeline automating **SOC 2 control evidence collection and validation** using Python and GitHub Actions. KQL-powered control health monitoring integrates with SIEM to track control posture in real time; automated evidence packages eliminate manual audit prep and surface control gaps before audit windows.

---

## Architecture

```
GitHub Actions (weekly + on push)
        │
        ▼
ComplianceCollector          ← pulls live evidence per SOC 2 control
        │
        ▼
ControlValidator             ← pass/fail per control against thresholds
        │
        ▼
EvidencePackager             ← builds dated ZIP artifact
  ├── evidence.json          (raw evidence per control)
  ├── validation.json        (pass/fail results + gaps)
  ├── summary.html           (audit-ready HTML report)
  └── gap_report.json        (failing controls + remediation steps)
        │
        ▼
CI Artifact (retained 365 days for audit trail)
```

---

## SOC 2 Controls Covered

| Control | Trust Service Criterion | Checks |
|---|---|---|
| CC6.1 | Logical access controls | MFA coverage 100%, privileged access review |
| CC6.2 | Access removal | Orphaned accounts = 0, deprovisioning ≤ 24h |
| CC7.1 | Logging & monitoring | Log retention ≥ 365d, SIEM coverage 100% |
| CC7.2 | Incident response | MTTD ≤ 24h, MTTR ≤ 72h |
| CC7.3 | Vulnerability management | Critical vulns patched ≤ 7d, High ≤ 30d |
| CC8.1 | Change management | Change approval 100%, 0 unauthorized changes |
| CC9.1 | Risk assessment | Risk register currency |
| A1.1 | Availability | Uptime ≥ 99.9% |
| C1.1 | Confidentiality | Data classification, encryption at rest/transit |

---

## Quick Start

```bash
# Demo mode — no AWS credentials required
python compliance_pipeline.py --demo

# Live run with AWS credentials
pip install boto3
python compliance_pipeline.py --profile default --output ./evidence
```

**Output:**
```
══════════════════════════════════════════════════════════════════════
  SOC 2 CONTINUOUS COMPLIANCE PIPELINE — RESULTS
══════════════════════════════════════════════════════════════════════
  Compliance Score: 88.9%   (8 pass / 1 fail)
──────────────────────────────────────────────────────────────────────
  ❌ FAILING CONTROLS:
     [CC7.3] Vulnerability management identifies and remediates risks
          → 2 high vulns exceed 30-day SLA
══════════════════════════════════════════════════════════════════════
```

---

## CI/CD Integration

The pipeline **exits with code 1** if any critical compliance gaps are detected, blocking merges to main. Evidence packages are uploaded as GitHub Actions artifacts and retained for **365 days** as an audit trail.

---

## Files

| File | Purpose |
|---|---|
| `compliance_pipeline.py` | Main orchestrator |
| `compliance_collector.py` | Evidence collection from AWS, SIEM |
| `control_validator.py` | SOC 2 control validation logic |
| `evidence_packager.py` | ZIP evidence package generator |
| `.github/workflows/compliance-pipeline.yml` | Weekly CI pipeline |

---

*Part of the portfolio of Kousik Gunasekaran — Cybersecurity Engineer*
