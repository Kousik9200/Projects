# Splunk Threat Hunting Dashboard

Custom Splunk Enterprise Security dashboards mapping real-time log data to MITRE ATT&CK technique IDs, featuring lateral movement detection, beaconing analysis, and UEBA.

## Dashboard Panels

| Panel | Description | Data Source |
|-------|-------------|-------------|
| ATT&CK Heatmap | Maps alerts to MITRE techniques | All indexes |
| Lateral Movement | Detects east-west traffic anomalies | Windows Event Logs |
| Beaconing Detector | Statistical C2 beacon analysis | Network flows |
| UEBA Anomalies | User behavior baseline deviations | Windows Security |
| Failed Logins | Brute force + credential stuffing | WinEventLog |
| Privilege Escalation | Token manipulation + UAC bypass | Sysmon |

## SPL Queries

See `queries/` folder for all detection queries.

## Setup

1. Install Splunk Enterprise Security
2. Configure data inputs (Windows Event Logs, Sysmon, network flows)
3. Import dashboard XML from `dashboards/`
4. Set up scheduled searches from `searches/`

## Requirements
- Splunk Enterprise 9.x
- Splunk ES 7.x
- Sysmon v15+
- Windows Universal Forwarder
