# Security Guardrails & Policy Enforcement Framework

Policy-as-code framework that **blocks non-compliant infrastructure deployments** before they reach production. Evaluates Terraform plans against 6 built-in security policies mapped to NIST CSF, CIS Controls, and SOC 2, then produces gated CI/CD enforcement with compliance reports.

---

## Architecture

```
Terraform Plan (JSON)
        │
        ▼
PolicyEngine.evaluate()          ← checks 6 policies across all resources
        │
        ├── CRITICAL violations? → sys.exit(1) → CI/CD BLOCKED
        │
        ▼
ComplianceReporter               ← aggregates violations by framework
  ├── print_summary()            (console output)
  ├── save_html()                (dark-theme HTML report)
  └── save_json()                (machine-readable output)

GitHub Actions CI:
  ├── terraform validate         (format + syntax check)
  ├── policy-check               (policy engine + reporter)
  ├── tfsec                      (static analysis)
  └── checkov                    (IaC policy scan → SARIF → GitHub Security tab)
```

---

## Policies

| ID | Policy | Severity | Frameworks |
|---|---|---|---|
| P001 | S3 Block Public Access | CRITICAL | CIS 2.1, NIST PR.AC-3 |
| P002 | Encryption at Rest | CRITICAL | CIS 2.3, SOC 2 C1.1 |
| P003 | S3 MFA Delete | HIGH | CIS 2.2 |
| P004 | No SSH from 0.0.0.0/0 | CRITICAL | CIS 5.2, NIST PR.AC-5 |
| P005 | Logging Enabled | HIGH | CIS 3.1, SOC 2 CC7.1 |
| P006 | IAM Least Privilege | HIGH | CIS 1.16, NIST PR.AC-4 |

Any **CRITICAL** violation blocks the deployment (exit code 1).

---

## Quick Start

```bash
# Demo mode — no infrastructure required
python policy_engine.py --demo

# Evaluate a real Terraform plan
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
python policy_engine.py --plan plan.json

# Run the compliance reporter
python compliance_reporter.py
```

**Sample output (demo):**
```
═════════════════════════════════════════════════════════════════
  POLICY ENFORCEMENT REPORT
═════════════════════════════════════════════════════════════════
  🔴 CRITICAL: 3
  🟠 HIGH: 2

  [CRITICAL] aws_s3_bucket.app-data
    Issue:       S3 bucket does not block public ACLs
    Fix:         Fix 'app-data' to comply with: S3 Block Public Access
    Frameworks:  CIS 2.1, NIST CSF PR.AC-3

  🚫 DEPLOYMENT BLOCKED — critical policy violations detected.
═════════════════════════════════════════════════════════════════
```

---

## Terraform Guardrails

Multi-cloud Terraform modules that enforce security baselines at the cloud account/organization level.

| File | Cloud | Controls Deployed |
|---|---|---|
| `guardrails/aws.tf` | AWS | GuardDuty, CloudTrail, S3 Block Public Access, IAM password policy, Config Rules (14), Security Hub (CIS v1.4) |
| `guardrails/azure.tf` | Azure | Defender for Cloud (10 plans), CIS Benchmark initiative, deny-public-storage policy, Activity Log alerts |
| `guardrails/gcp.tf` | GCP | 6 Org Policy constraints, Cloud Audit Logs, Monitoring alert policies (4), Security Command Center findings export |

Deploy AWS guardrails:
```bash
cd guardrails
terraform init
terraform plan -var="alert_email=security@example.com" \
               -var="log_bucket_name=my-audit-logs"
terraform apply
```

---

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/policy-enforcement.yml`) runs four jobs on every PR:

1. **terraform-validate** — `terraform validate` + `terraform fmt` check
2. **policy-check** — policy engine evaluation; PRs are blocked and commented on CRITICAL failures
3. **tfsec** — static Terraform security analysis
4. **checkov** — IaC policy scan; results uploaded as SARIF to GitHub Security tab

---

## Files

| File | Purpose |
|---|---|
| `policy_engine.py` | Policy-as-code engine; evaluates Terraform plans |
| `compliance_reporter.py` | Framework-level compliance report (NIST/CIS/SOC 2) |
| `guardrails/aws.tf` | AWS security baseline Terraform |
| `guardrails/azure.tf` | Azure security baseline Terraform |
| `guardrails/gcp.tf` | GCP security baseline Terraform |
| `.github/workflows/policy-enforcement.yml` | CI/CD policy gate |

---

*Part of the portfolio of Kousik Gunasekaran — Cybersecurity Engineer*
