# guardrails/gcp.tf — GCP Security Guardrails
# Deploys GCP Organization Policy constraints and Security Command Center
# settings aligned to CIS Google Cloud Platform Foundations Benchmark.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "organization_id" { description = "GCP Organization ID (digits only)" }
variable "project_id"      { description = "GCP project ID" }
variable "region"          { default = "us-central1" }
variable "alert_email"     { description = "Security notification email" }
variable "log_bucket_id"   { description = "Cloud Storage bucket for audit logs" }

# ── Organization Policies ─────────────────────────────────────────────────────

# Disable public IP for Cloud SQL (CIS 6.2)
resource "google_org_policy_policy" "no_sql_public_ip" {
  name   = "organizations/${var.organization_id}/policies/sql.restrictPublicIp"
  parent = "organizations/${var.organization_id}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# Require OS Login for Compute Engine (CIS 4.1)
resource "google_org_policy_policy" "require_os_login" {
  name   = "organizations/${var.organization_id}/policies/compute.requireOsLogin"
  parent = "organizations/${var.organization_id}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# Restrict public GCS buckets (CIS 5.1)
resource "google_org_policy_policy" "no_public_gcs" {
  name   = "organizations/${var.organization_id}/policies/storage.publicAccessPrevention"
  parent = "organizations/${var.organization_id}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# Restrict allowed VPC peering domains
resource "google_org_policy_policy" "restrict_vpc_peering" {
  name   = "organizations/${var.organization_id}/policies/compute.restrictVpcPeering"
  parent = "organizations/${var.organization_id}"

  spec {
    rules {
      deny_all = "TRUE"
    }
  }
}

# Disable serial port access on VMs (CIS 4.5)
resource "google_org_policy_policy" "no_serial_port" {
  name   = "organizations/${var.organization_id}/policies/compute.disableSerialPortAccess"
  parent = "organizations/${var.organization_id}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# Restrict default service account usage (CIS 4.2)
resource "google_org_policy_policy" "no_default_sa_roles" {
  name   = "organizations/${var.organization_id}/policies/iam.automaticIamGrantsForDefaultServiceAccounts"
  parent = "organizations/${var.organization_id}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# ── Cloud Audit Logs ──────────────────────────────────────────────────────────

resource "google_organization_iam_audit_config" "all_services" {
  org_id  = var.organization_id
  service = "allServices"

  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# Export audit logs to Cloud Storage
resource "google_logging_organization_sink" "audit_sink" {
  name             = "security-guardrails-audit-sink"
  org_id           = var.organization_id
  include_children = true
  destination      = "storage.googleapis.com/${var.log_bucket_id}"

  filter = <<-EOT
    logName:"cloudaudit.googleapis.com" OR
    logName:"data_access" OR
    logName:"activity"
  EOT
}

# ── Cloud Monitoring: Security Alerting Policies ──────────────────────────────

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Guardrails Alert Email"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

locals {
  alert_policies = {
    "iam-owner-changes" = {
      display_name = "IAM owner/editor changes"
      filter       = "resource.type=\"project\" AND protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=~\"roles/(owner|editor)\""
    }
    "bucket-acl-changes" = {
      display_name = "GCS bucket IAM/ACL changes"
      filter       = "resource.type=\"gcs_bucket\" AND protoPayload.methodName=~\"storage.buckets.(update|setIamPermissions)\""
    }
    "firewall-rule-changes" = {
      display_name = "VPC firewall rule changes"
      filter       = "resource.type=\"gce_firewall_rule\" AND jsonPayload.event_subtype=~\"(insert|patch|delete)\""
    }
    "audit-config-changes" = {
      display_name = "Audit log config changes"
      filter       = "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
    }
  }
}

resource "google_logging_metric" "security_events" {
  for_each    = local.alert_policies
  name        = replace(each.key, "-", "_")
  description = each.value.display_name
  filter      = each.value.filter

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "security_events" {
  for_each     = local.alert_policies
  display_name = each.value.display_name
  combiner     = "OR"

  conditions {
    display_name = each.value.display_name
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${replace(each.key, "-", "_")}\" resource.type=\"global\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "86400s"    # 24 hours
  }
}

# ── Security Command Center ───────────────────────────────────────────────────

# Enable Security Command Center Standard tier findings export
resource "google_scc_notification_config" "high_severity" {
  config_id    = "security-guardrails-scc"
  organization = var.organization_id
  description  = "Export HIGH and CRITICAL SCC findings"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "state = \"ACTIVE\" AND severity = \"HIGH\" OR severity = \"CRITICAL\""
  }
}

resource "google_pubsub_topic" "scc_findings" {
  name = "security-guardrails-scc-findings"
}

resource "google_pubsub_subscription" "scc_findings_email" {
  name  = "scc-findings-email-sub"
  topic = google_pubsub_topic.scc_findings.id

  push_config {
    # Wire to your own alerting webhook or Cloud Run function
    push_endpoint = "https://hooks.example.com/scc-findings"
  }

  expiration_policy { ttl = "" }    # never expire
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "scc_notification_config" { value = google_scc_notification_config.high_severity.name }
output "scc_pubsub_topic"        { value = google_pubsub_topic.scc_findings.id }
output "audit_log_sink_writer"   { value = google_logging_organization_sink.audit_sink.writer_identity }
