# guardrails/azure.tf — Azure Security Guardrails
# Deploys Azure Policy definitions and Defender for Cloud settings
# aligned to CIS Microsoft Azure Foundations Benchmark.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "subscription_id"      { description = "Azure subscription ID" }
variable "resource_group_name"  { default = "security-guardrails-rg" }
variable "location"             { default = "eastus" }
variable "alert_email"          { description = "Security contact email" }
variable "log_analytics_id"     { description = "Log Analytics workspace resource ID" }

# ── Resource group ─────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "guardrails" {
  name     = var.resource_group_name
  location = var.location
  tags     = { ManagedBy = "terraform", Purpose = "security-guardrails" }
}

# ── Microsoft Defender for Cloud ──────────────────────────────────────────────

locals {
  defender_plans = [
    "AppServices", "ContainerRegistry", "Containers",
    "Dns", "KeyVaults", "KubernetesService",
    "SqlServers", "SqlServerVirtualMachines",
    "StorageAccounts", "VirtualMachines",
  ]
}

resource "azurerm_security_center_subscription_pricing" "defender_plans" {
  for_each      = toset(local.defender_plans)
  tier          = "Standard"
  resource_type = each.value
}

resource "azurerm_security_center_contact" "main" {
  email               = var.alert_email
  alert_notifications = true
  alerts_to_admins    = true
}

resource "azurerm_security_center_setting" "mcsb" {
  setting_name = "MCAS"
  enabled      = true
}

# ── Azure Policy: CIS Benchmark Initiative ────────────────────────────────────

resource "azurerm_subscription_policy_assignment" "cis_benchmark" {
  name                 = "cis-azure-foundations-v200"
  display_name         = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/06f19060-9e68-4070-92ca-f15cc126059e"
  subscription_id      = "/subscriptions/${var.subscription_id}"

  identity {
    type = "SystemAssigned"
  }

  location = var.location
}

# ── Azure Policy: No public storage accounts ──────────────────────────────────

resource "azurerm_policy_definition" "deny_public_storage" {
  name         = "deny-public-storage-accounts"
  display_name = "Deny public access to Storage Accounts"
  description  = "Storage Accounts must not allow public blob access"
  policy_type  = "Custom"
  mode         = "All"

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type",                          equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", equals = "true" }
      ]
    }
    then = { effect = "Deny" }
  })
}

resource "azurerm_subscription_policy_assignment" "deny_public_storage" {
  name                 = "deny-public-storage"
  display_name         = "Deny Public Storage Accounts"
  policy_definition_id = azurerm_policy_definition.deny_public_storage.id
  subscription_id      = "/subscriptions/${var.subscription_id}"
}

# ── Azure Policy: Require HTTPS on Storage ────────────────────────────────────

resource "azurerm_policy_definition" "require_https_storage" {
  name         = "require-https-storage"
  display_name = "Require HTTPS for Storage Accounts"
  policy_type  = "Custom"
  mode         = "All"

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type",                                                      equals = "Microsoft.Storage/storageAccounts" },
        { field = "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", equals = "false" }
      ]
    }
    then = { effect = "Deny" }
  })
}

resource "azurerm_subscription_policy_assignment" "require_https_storage" {
  name                 = "require-https-storage"
  display_name         = "Require HTTPS on Storage Accounts"
  policy_definition_id = azurerm_policy_definition.require_https_storage.id
  subscription_id      = "/subscriptions/${var.subscription_id}"
}

# ── Azure Monitor: Activity Log Alerts ────────────────────────────────────────

resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "security-guardrails-alerts"
  resource_group_name = azurerm_resource_group.guardrails.name
  short_name          = "sec-alerts"

  email_receiver {
    name          = "SecurityTeam"
    email_address = var.alert_email
  }
}

locals {
  activity_log_alerts = {
    "policy-assignment-write" = {
      category    = "Administrative"
      operation   = "Microsoft.Authorization/policyAssignments/write"
      description = "Alert on policy assignment changes"
    }
    "security-policy-update" = {
      category    = "Administrative"
      operation   = "Microsoft.Security/policies/write"
      description = "Alert on security policy updates"
    }
    "nsg-delete" = {
      category    = "Administrative"
      operation   = "Microsoft.Network/networkSecurityGroups/delete"
      description = "Alert on NSG deletion"
    }
  }
}

resource "azurerm_monitor_activity_log_alert" "security_alerts" {
  for_each            = local.activity_log_alerts
  name                = each.key
  resource_group_name = azurerm_resource_group.guardrails.name
  scopes              = ["/subscriptions/${var.subscription_id}"]
  description         = each.value.description

  criteria {
    category       = each.value.category
    operation_name = each.value.operation
  }

  action {
    action_group_id = azurerm_monitor_action_group.security_alerts.id
  }
}

# ── Log Analytics: Diagnostic settings export ─────────────────────────────────

resource "azurerm_monitor_diagnostic_setting" "subscription_logs" {
  name               = "security-guardrails-diag"
  target_resource_id = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = var.log_analytics_id

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "resource_group_id"          { value = azurerm_resource_group.guardrails.id }
output "action_group_id"            { value = azurerm_monitor_action_group.security_alerts.id }
output "cis_assignment_id"          { value = azurerm_subscription_policy_assignment.cis_benchmark.id }
