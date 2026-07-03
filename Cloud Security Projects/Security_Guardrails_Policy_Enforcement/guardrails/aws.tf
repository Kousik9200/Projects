# guardrails/aws.tf — AWS Security Guardrails
# Deploys mandatory security controls via Terraform:
# GuardDuty, Config Rules, S3 Block Public Access, CloudTrail,
# IAM password policy, Security Hub (CIS standard), and SNS alerting.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "aws_region"       { default = "us-east-1" }
variable "alert_email"      { description = "Email for security alert notifications" }
variable "environment"      { default = "prod" }
variable "log_bucket_name"  { description = "S3 bucket for centralized audit logs" }

# ── SNS: Security Alerts ──────────────────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  name              = "security-guardrails-alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = { Environment = var.environment, ManagedBy = "terraform" }
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── GuardDuty ─────────────────────────────────────────────────────────────────

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs              { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection   { scan_ec2_instance_with_findings { ebs_volumes { enable = true } } }
  }

  tags = { Environment = var.environment }
}

# Forward GuardDuty HIGH/CRITICAL findings to SNS
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-high-severity-findings"
  description = "Capture GuardDuty HIGH and CRITICAL findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# ── CloudTrail ────────────────────────────────────────────────────────────────

resource "aws_cloudtrail" "main" {
  name                          = "org-cloudtrail"
  s3_bucket_name                = var.log_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true    # CIS 3.2

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  tags = { Environment = var.environment }
}

# ── S3: Block Public Access (account-level) ───────────────────────────────────

resource "aws_s3_account_public_access_block" "main" {
  block_public_acls       = true    # CIS 2.1.2
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── IAM Password Policy ───────────────────────────────────────────────────────

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 16       # CIS 1.8
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24       # CIS 1.9
  max_password_age               = 90       # CIS 1.10
}

# ── AWS Config: Managed Rules ─────────────────────────────────────────────────

resource "aws_config_configuration_recorder" "main" {
  name     = "security-guardrails-recorder"
  role_arn = aws_iam_role.config_role.arn
  recording_group { all_supported = true }
}

resource "aws_config_delivery_channel" "main" {
  name           = "security-guardrails-channel"
  s3_bucket_name = var.log_bucket_name
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_iam_role" "config_role" {
  name               = "aws-config-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# CIS Config Rules
locals {
  config_managed_rules = {
    "s3-bucket-public-read-prohibited"         = {}
    "s3-bucket-public-write-prohibited"        = {}
    "s3-bucket-server-side-encryption-enabled" = {}
    "s3-bucket-logging-enabled"                = {}
    "ec2-security-group-attached-to-eni"       = {}
    "restricted-ssh"                           = {}          # CIS 5.2
    "iam-user-mfa-enabled"                     = {}          # CIS 1.2
    "root-account-mfa-enabled"                 = {}          # CIS 1.1
    "iam-password-policy"                      = {}          # CIS 1.7-1.11
    "cloud-trail-enabled"                      = {}          # CIS 3.1
    "cloud-trail-log-file-validation-enabled"  = {}          # CIS 3.2
    "guardduty-enabled-centralized"            = {}
    "rds-storage-encrypted"                    = {}
    "ebs-optimized-instance"                   = {}
  }
}

resource "aws_config_config_rule" "managed_rules" {
  for_each   = local.config_managed_rules
  name       = each.key
  depends_on = [aws_config_configuration_recorder.main]

  source {
    owner             = "AWS"
    source_identifier = upper(replace(each.key, "-", "_"))
  }
}

# ── Security Hub (CIS AWS Foundations Benchmark) ──────────────────────────────

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "aws_best_practices" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

# Forward Security Hub CRITICAL findings to SNS
resource "aws_cloudwatch_event_rule" "securityhub_critical" {
  name        = "securityhub-critical-findings"
  description = "Forward CRITICAL Security Hub findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail      = {
      findings = {
        Severity    = { Label = ["CRITICAL", "HIGH"] }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_sns" {
  rule      = aws_cloudwatch_event_rule.securityhub_critical.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "guardduty_detector_id" { value = aws_guardduty_detector.main.id }
output "security_alerts_topic" { value = aws_sns_topic.security_alerts.arn }
output "cloudtrail_arn"        { value = aws_cloudtrail.main.arn }
