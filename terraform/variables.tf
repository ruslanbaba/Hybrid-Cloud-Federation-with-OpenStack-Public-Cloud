# Terraform Variables - Enterprise Hybrid Cloud Federation
# No hard-coded values - all sourced from environment or Vault

# Environment Configuration
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "cost_center" {
  description = "Cost center for billing allocation"
  type        = string
}

variable "owner" {
  description = "Team or individual responsible for the infrastructure"
  type        = string
}

# OpenStack Configuration
variable "openstack_auth_url" {
  description = "OpenStack Keystone authentication URL"
  type        = string
}

variable "openstack_region" {
  description = "OpenStack region"
  type        = string
  default     = "RegionOne"
}

variable "openstack_project_domain" {
  description = "OpenStack project domain name"
  type        = string
  default     = "Default"
}

variable "openstack_user_domain" {
  description = "OpenStack user domain name"
  type        = string
  default     = "Default"
}

variable "openstack_network_cidr" {
  description = "CIDR block for OpenStack network"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.openstack_network_cidr, 0))
    error_message = "OpenStack network CIDR must be a valid IPv4 CIDR block."
  }
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_assume_role_arn" {
  description = "AWS IAM role ARN to assume for federation"
  type        = string
}

variable "aws_vpc_cidr" {
  description = "CIDR block for AWS VPC"
  type        = string
  default     = "10.1.0.0/16"
  validation {
    condition     = can(cidrhost(var.aws_vpc_cidr, 0))
    error_message = "AWS VPC CIDR must be a valid IPv4 CIDR block."
  }
}

# Google Cloud Configuration
variable "gcp_project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "gcp_region" {
  description = "Google Cloud region"
  type        = string
  default     = "us-central1"
}

variable "gcp_vpc_cidr" {
  description = "CIDR block for GCP VPC"
  type        = string
  default     = "10.2.0.0/16"
  validation {
    condition     = can(cidrhost(var.gcp_vpc_cidr, 0))
    error_message = "GCP VPC CIDR must be a valid IPv4 CIDR block."
  }
}

# Azure Configuration
variable "azure_region" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}

variable "azure_vnet_cidr" {
  description = "CIDR block for Azure VNet"
  type        = string
  default     = "10.3.0.0/16"
  validation {
    condition     = can(cidrhost(var.azure_vnet_cidr, 0))
    error_message = "Azure VNet CIDR must be a valid IPv4 CIDR block."
  }
}

# Vault Configuration
variable "vault_address" {
  description = "HashiCorp Vault server address"
  type        = string
}

# Federation Configuration
variable "federation_providers" {
  description = "Identity federation providers configuration"
  type = map(object({
    provider_type = string
    endpoint_url  = string
    enabled      = bool
    attributes_mapping = map(string)
  }))
  default = {
    aws = {
      provider_type = "saml"
      endpoint_url  = ""
      enabled       = true
      attributes_mapping = {
        "email" = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        "name"  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
      }
    }
    gcp = {
      provider_type = "oidc"
      endpoint_url  = ""
      enabled       = true
      attributes_mapping = {
        "email" = "email"
        "name"  = "name"
      }
    }
    azure = {
      provider_type = "saml"
      endpoint_url  = ""
      enabled       = true
      attributes_mapping = {
        "email" = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        "name"  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname"
      }
    }
  }
}

# Burst Controller Configuration
variable "controller_node_types" {
  description = "Instance types for burst controller nodes"
  type        = map(string)
  default = {
    aws   = "t3.large"
    gcp   = "n2-standard-2"
    azure = "Standard_D2s_v3"
  }
}

variable "scaling_policies" {
  description = "Auto-scaling policies for workload bursting"
  type = object({
    scale_out_threshold    = number
    scale_in_threshold     = number
    scale_out_cooldown     = string
    scale_in_cooldown      = string
    max_burst_instances    = number
    min_instances_per_cloud = number
    preferred_cloud_order  = list(string)
  })
  default = {
    scale_out_threshold    = 80
    scale_in_threshold     = 20
    scale_out_cooldown     = "5m"
    scale_in_cooldown      = "10m"
    max_burst_instances    = 100
    min_instances_per_cloud = 2
    preferred_cloud_order  = ["aws", "gcp", "azure"]
  }
}

# Cost Management Configuration
variable "cost_budgets" {
  description = "Cost budget configuration per cloud provider"
  type = map(object({
    monthly_limit_usd = number
    alert_thresholds  = list(number)
    actions = list(string)
  }))
  default = {
    openstack = {
      monthly_limit_usd = 10000
      alert_thresholds  = [50, 75, 90, 100]
      actions          = ["alert", "restrict", "terminate"]
    }
    aws = {
      monthly_limit_usd = 5000
      alert_thresholds  = [50, 75, 90]
      actions          = ["alert", "restrict"]
    }
    gcp = {
      monthly_limit_usd = 5000
      alert_thresholds  = [50, 75, 90]
      actions          = ["alert", "restrict"]
    }
    azure = {
      monthly_limit_usd = 5000
      alert_thresholds  = [50, 75, 90]
      actions          = ["alert", "restrict"]
    }
  }
}

variable "cost_alerts" {
  description = "Cost alerting configuration"
  type = object({
    notification_channels = list(string)
    daily_reports        = bool
    weekly_reports       = bool
    monthly_reports      = bool
    anomaly_detection    = bool
  })
  default = {
    notification_channels = ["slack", "email"]
    daily_reports        = true
    weekly_reports       = true
    monthly_reports      = true
    anomaly_detection    = true
  }
}

# Security Configuration
variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for all storage"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit for all communications"
  type        = bool
  default     = true
}

variable "certificate_validity_days" {
  description = "Validity period for generated certificates in days"
  type        = number
  default     = 365
  validation {
    condition     = var.certificate_validity_days > 0 && var.certificate_validity_days <= 3650
    error_message = "Certificate validity must be between 1 and 3650 days."
  }
}

# Monitoring Configuration
variable "monitoring_retention_days" {
  description = "Metrics retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.monitoring_retention_days >= 7 && var.monitoring_retention_days <= 365
    error_message = "Monitoring retention must be between 7 and 365 days."
  }
}

variable "enable_distributed_tracing" {
  description = "Enable distributed tracing with Jaeger"
  type        = bool
  default     = true
}

# Network Configuration
variable "enable_network_segmentation" {
  description = "Enable network segmentation and micro-segmentation"
  type        = bool
  default     = true
}

variable "bgp_asn" {
  description = "BGP Autonomous System Number for routing"
  type        = number
  default     = 65000
  validation {
    condition     = var.bgp_asn >= 64512 && var.bgp_asn <= 65534
    error_message = "BGP ASN must be in the private range 64512-65534."
  }
}

# High Availability Configuration
variable "enable_multi_az" {
  description = "Enable multi-availability zone deployment"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 7
    error_message = "Backup retention must be at least 7 days."
  }
}

# Compliance Configuration
variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.log_retention_days >= 30
    error_message = "Log retention must be at least 30 days for compliance."
  }
}
