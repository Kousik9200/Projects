# Cloud Misconfiguration Hunter

Automated AWS/Azure misconfiguration scanner that continuously audits S3 buckets, IAM policies, security groups, and cloud storage, delivering prioritized risk reports to Slack.

## Checks Performed

### AWS
| Check | Severity | Description |
|-------|----------|-------------|
| Public S3 Buckets | CRITICAL | Detects AllUsers ACL on S3 buckets |
| Root Access Keys | CRITICAL | Root account with active API keys |
| Root MFA Disabled | CRITICAL | No MFA on root account |
| Open Security Groups | HIGH | SGs allowing 0.0.0.0/0 on SSH/RDP |
| Unencrypted EBS | MEDIUM | EBS volumes without encryption |
| IAM Password Policy | MEDIUM | Weak or missing password policy |
| CloudTrail Disabled | HIGH | Logging not enabled |
| Public RDS Instances | HIGH | Database publicly accessible |

### Azure (via ScoutSuite)
- Storage accounts with public blob access
- NSG rules with overly permissive inbound rules
- Unencrypted storage
- Missing Azure Defender plans

## Usage

```bash
pip install -r requirements.txt
cp .env.example .env
# Configure AWS credentials and Slack webhook

# Run AWS scan
python cloud_hunter.py

# Run ScoutSuite (multi-cloud)
scout aws --report-dir ./reports
scout azure --cli --report-dir ./reports
```

## Scheduling (Cron)
```bash
# Run every 6 hours
0 */6 * * * /usr/bin/python3 /opt/cloud_hunter/cloud_hunter.py >> /var/log/cloud_hunter.log 2>&1
```
