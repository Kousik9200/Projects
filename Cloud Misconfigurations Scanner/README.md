# Cloud Misconfiguration Scanner

An automated Python scanner that audits AWS environments against CIS Foundations Benchmark v1.5, scores findings by risk severity, and generates HTML + JSON reports with optional Jira integration.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with mock data (no AWS credentials needed)
python main.py --mock --env prod

# Run against a live AWS account
python main.py --profile my-aws-profile --region us-east-1 --env prod

# Run and auto-file Jira tickets for critical/high findings
python main.py --mock --env prod --jira
```

Reports are saved to `output/scan_report_<timestamp>.html` and `.json`.

## Architecture

```
AWS APIs (boto3)
    ├── IAM Auditor    → CIS 1.x controls
    ├── S3 Auditor     → CIS 2.x controls
    ├── SG Auditor     → CIS 5.x controls
    └── CloudTrail     → CIS 3.x controls
            ↓
      Risk Scorer     (severity × env multiplier × category weight)
            ↓
    HTML Report + JSON Report
            ↓
    Jira Tickets (critical/high findings)
```

## Project Structure

```
cloud-misconfig-scanner/
├── scanner/
│   ├── iam_audit.py           # IAM checks (MFA, wildcards, key rotation)
│   ├── s3_audit.py            # S3 checks (public access, encryption, logging)
│   ├── sg_audit.py            # Security group checks (open ports, egress)
│   ├── cloudtrail_audit.py    # CloudTrail checks (enabled, validation, alarms)
│   └── scorer.py              # Risk scoring engine
├── reporter/
│   ├── report.html.j2         # Jinja2 HTML report template
│   └── generate_report.py     # Renders HTML and JSON reports
├── integrations/
│   └── jira_ticket.py         # Creates Jira issues for critical findings
├── .github/workflows/
│   └── scheduled_scan.yml     # Daily GitHub Actions scan
├── output/                    # Generated reports (gitignored)
├── main.py                    # Orchestrator / CLI entry point
└── requirements.txt
```

## Audit Coverage

| Module | CIS Control | What It Checks |
|--------|-------------|----------------|
| IAM | 1.5 | Root account MFA |
| IAM | 1.10 | User MFA for console access |
| IAM | 1.14 | Access key rotation (90 days) |
| IAM | 1.16 | Wildcard IAM policies (Action:* Resource:*) |
| IAM | 1.12 | Inactive user credentials |
| S3 | 2.1.5 | Public access block settings |
| S3 | 2.1.5 | Bucket ACL public grants |
| S3 | 2.1.5 | Bucket policy wildcard principal |
| S3 | 2.1.1 | Default server-side encryption |
| S3 | 2.6 | Server access logging |
| SG | 5.2 | Sensitive ports open to 0.0.0.0/0 |
| SG | 5.2 | All-traffic inbound rules |
| SG | 5.4 | Unrestricted outbound |
| CloudTrail | 3.1 | Trail enabled and logging |
| CloudTrail | 3.1 | Multi-region trail |
| CloudTrail | 3.2 | Log file validation |
| CloudTrail | 3.3 | Log S3 bucket not public |
| CloudTrail | 3.x | CloudWatch alarms for critical API calls |

## Risk Scoring

`risk_score = base_severity × category_weight × environment_multiplier`

| Severity | Base Score | Prod Multiplier |
|----------|-----------|----------------|
| CRITICAL | 10.0 | 1.5× |
| HIGH | 7.5 | 1.5× |
| MEDIUM | 5.0 | 1.5× |
| LOW | 2.5 | 1.5× |

## Environment Variables

```bash
# For Jira integration
export JIRA_BASE_URL=https://yourorg.atlassian.net
export JIRA_EMAIL=you@yourorg.com
export JIRA_API_TOKEN=your_jira_api_token
export JIRA_PROJECT_KEY=SEC
```

## GitHub Secrets Required

| Secret | Description |
|--------|-------------|
| `AWS_ROLE_ARN` | IAM role ARN for OIDC authentication |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for alerts |
| `JIRA_BASE_URL` | Jira instance URL |
| `JIRA_EMAIL` | Jira account email |
| `JIRA_API_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | Jira project key (e.g. SEC) |

## IAM Permissions Required (least privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:ListAccessKeys",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetPublicAccessBlock",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "cloudwatch:DescribeAlarms"
      ],
      "Resource": "*"
    }
  ]
}
```
