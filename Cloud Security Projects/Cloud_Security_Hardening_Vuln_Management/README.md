# Cloud Security Hardening & Vulnerability Management Framework

Automated vulnerability scanning, IAM policy enforcement, and secrets management framework across **AWS and Azure**. Python-driven scanner flags misconfigured roles, exposed secrets, and open attack surface; Terraform + GitHub Actions enforce least-privilege guardrails in CI/CD and generate remediation reports per finding.

---

## Architecture

```
GitHub Actions (daily + on push)
        │
        ├─► scanner.py ──────────────────────────────────────┐
        │       ├─ IAMAuditor        (CIS IAM checks)        │
        │       ├─ SecretsScanner    (S3 / EC2 / SSM)        │
        │       └─ ReportGenerator   (HTML + JSON)            │
        │                                                     ▼
        └─► terraform validate    Scan Report (HTML + JSON artifact)
                └─ main.tf  →  GuardDuty, CloudTrail, IAM policy,
                               S3 block-public, Security Hub
```

---

## Checks Performed

### IAM Audit (CIS AWS Foundations)
| Check | Severity | CIS Ref |
|---|---|---|
| Root account MFA disabled | CRITICAL | 1.5 |
| Wildcard IAM policies (`*`) | HIGH | 1.16 |
| Access keys > 90 days old | HIGH | 1.14 |
| Unused credentials (90+ days) | HIGH | 1.3 |
| Inline policies on users | MEDIUM | 1.16 |

### Secrets Scanner
| Check | Severity |
|---|---|
| Public S3 bucket | CRITICAL |
| AWS keys / tokens in S3 objects | CRITICAL |
| Private keys in EC2 user-data | CRITICAL |
| SSM parameters stored as plaintext | HIGH |

### Terraform Guardrails (`terraform/main.tf`)
- IAM account password policy (16 char min, 90-day rotation)
- S3 Block Public Access at account level
- GuardDuty enabled with 6-hour publishing
- Security Hub + CIS Benchmark standard
- Multi-region CloudTrail with log validation
- CloudWatch alarm for root account usage

---

## Quick Start

```bash
# Demo mode — no AWS credentials required
python scanner.py --demo

# Live AWS scan
pip install boto3
python scanner.py --profile default --region us-east-1

# Deploy Terraform guardrails
cd terraform
terraform init
terraform plan -var="alert_email=you@example.com"
terraform apply
```

---

## Output

Running the scanner produces:
- `scan_report.html` — colour-coded findings with remediation steps
- `scan_report.json` — machine-readable findings for SIEM ingestion

---

## Files

| File | Purpose |
|---|---|
| `scanner.py` | Main orchestrator |
| `iam_auditor.py` | CIS IAM checks |
| `secrets_scanner.py` | S3 / EC2 / SSM secrets scan |
| `report_generator.py` | HTML & JSON report generation |
| `terraform/main.tf` | Least-privilege guardrails (IaC) |
| `.github/workflows/security-scan.yml` | Daily CI scan + Terraform validate |

---

*Part of the portfolio of Kousik Gunasekaran — Cybersecurity Engineer*
