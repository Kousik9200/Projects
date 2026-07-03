# ── Cloud Security Hardening — Terraform Least-Privilege Guardrails ──────────
# Enforces IAM password policy, CloudTrail, S3 Block Public Access,
# GuardDuty, and Security Hub across the AWS account.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region"      { default = "us-east-1" }
variable "alert_email" { description = "Email for security alert SNS topic" }

provider "aws" {
  region = var.region
}

# ── IAM Password Policy ───────────────────────────────────────────────────────
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 16
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# ── S3 Block Public Access (account level) ────────────────────────────────────
resource "aws_s3_account_public_access_block" "block_all" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── GuardDuty ────────────────────────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "SIX_HOURS"
}

# ── Security Hub ─────────────────────────────────────────────────────────────
resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

# ── CloudTrail ────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "security-hardening-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

# ── SNS Alert Topic ───────────────────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name = "security-hardening-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── CloudWatch Alarm: Root Account Usage ──────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "RootAccountUsage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

data "aws_caller_identity" "current" {}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "guardduty_detector_id" { value = aws_guardduty_detector.main.id }
output "cloudtrail_bucket"     { value = aws_s3_bucket.cloudtrail.bucket }
output "security_alerts_topic" { value = aws_sns_topic.security_alerts.arn }
