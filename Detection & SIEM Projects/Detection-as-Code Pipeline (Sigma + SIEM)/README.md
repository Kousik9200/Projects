# Detection-as-Code Pipeline

A CI/CD pipeline that treats SIEM detection rules as code — version-controlled, peer-reviewed, automatically validated, and deployed.

## Architecture

```
Sigma Rules (YAML) → pySigma Converter → Splunk SPL / Sentinel KQL
                  ↓
         MITRE ATT&CK Validator
                  ↓
         GitHub Actions (PR gate)
                  ↓
    Auto-deploy on merge to main
                  ↓
     SIEM Alert → Flask Webhook → Jira Ticket
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Validate all rules
python scripts/validate_attack.py

# Convert rules to SIEM queries
python scripts/convert.py

# Outputs written to:
#   queries/splunk/*.spl
#   queries/sentinel/*.kql
#   queries/conversion_report.json
```

## Project Structure

```
detection-as-code/
├── rules/                        # Sigma YAML detection rules
├── queries/
│   ├── splunk/                   # Auto-generated Splunk SPL queries
│   └── sentinel/                 # Auto-generated Sentinel KQL queries
├── scripts/
│   ├── convert.py                # Sigma → SPL/KQL converter
│   └── validate_attack.py        # ATT&CK tag validator
├── webhook/
│   └── alert_to_jira.py          # Flask webhook: SIEM → Jira
├── .github/workflows/
│   └── pipeline.yml              # CI/CD pipeline definition
└── requirements.txt
```

## Writing a Sigma Rule

```yaml
title: Your Detection Title
id: <uuid>
status: stable | experimental
description: What this rule detects
tags:
  - attack.<tactic>              # e.g. attack.execution
  - attack.t<id>                 # e.g. attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'suspicious_string'
  condition: selection
falsepositives:
  - Known legitimate use cases
level: critical | high | medium | low
```

## GitHub Secrets Required

| Secret | Description |
|--------|-------------|
| `SPLUNK_URL` | Splunk instance URL |
| `SPLUNK_TOKEN` | Splunk API token |
| `AZURE_TENANT_ID` | Azure tenant for Sentinel |
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `SENTINEL_WORKSPACE` | Log Analytics workspace name |
| `SENTINEL_RESOURCE_GROUP` | Azure resource group |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook |
| `WEBHOOK_SECRET` | Shared secret for alert webhook |

## Webhook Deployment

```bash
# Set environment variables
export JIRA_BASE_URL=https://yourorg.atlassian.net
export JIRA_EMAIL=you@yourorg.com
export JIRA_API_TOKEN=your_token
export JIRA_PROJECT_KEY=SEC
export WEBHOOK_SECRET=your_secret
export SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# Run webhook
python webhook/alert_to_jira.py
```

## Coverage

| Rule | Tactic | Technique | Severity |
|------|--------|-----------|----------|
| LSASS Credential Dump | Credential Access | T1003.001 | High |
| Lateral Movement via PsExec | Lateral Movement | T1021.002 | High |
| PowerShell Encoded Command | Execution / Defense Evasion | T1059.001, T1027 | Medium |
| Brute Force Login | Credential Access | T1110 | Medium |
| DNS Tunneling | Exfiltration / C2 | T1048.001, T1071.004 | Medium |
| Scheduled Task Persistence | Persistence | T1053.005 | Medium |
