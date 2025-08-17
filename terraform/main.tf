# Main Terraform Configuration for Enterprise Hybrid Cloud Federation
# Orchestrates all modules to create comprehensive enterprise-grade platform

terraform {
  required_version = ">= 1.5"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.31"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.20"
    }
    grafana = {
      source  = "grafana/grafana"
      version = "~> 2.9"
    }
    github = {
      source  = "integrations/github"
      version = "~> 5.34"
    }
  }
  
  backend "s3" {
    bucket         = var.terraform_state_bucket
    key            = "federation/terraform.tfstate"
    region         = var.aws_region
    encrypt        = true
    dynamodb_table = var.terraform_lock_table
  }
}

# Provider Configurations
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment   = var.environment
      Project       = "hybrid-cloud-federation"
      ManagedBy     = "terraform"
      CostCenter    = var.cost_center
      Owner         = var.owner
      Classification = var.data_classification
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  
  default_labels = {
    environment    = var.environment
    project        = "hybrid-cloud-federation"
    managed-by     = "terraform"
    cost-center    = var.cost_center
    owner          = var.owner
    classification = var.data_classification
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

provider "openstack" {
  auth_url    = var.openstack_auth_url
  tenant_name = var.openstack_project_name
  user_name   = var.openstack_username
  password    = var.openstack_password
  region      = var.openstack_region
}

provider "kubernetes" {
  host                   = module.reliability_dr.kubernetes_cluster_endpoint
  cluster_ca_certificate = base64decode(module.reliability_dr.kubernetes_cluster_ca_certificate)
  token                  = module.reliability_dr.kubernetes_cluster_token
}

provider "helm" {
  kubernetes {
    host                   = module.reliability_dr.kubernetes_cluster_endpoint
    cluster_ca_certificate = base64decode(module.reliability_dr.kubernetes_cluster_ca_certificate)
    token                  = module.reliability_dr.kubernetes_cluster_token
  }
}

provider "vault" {
  address = module.security_identity.vault_address
  token   = var.vault_token
}

provider "grafana" {
  url  = module.observability_aiops.grafana_url
  auth = "${var.grafana_username}:${var.grafana_password}"
}

provider "github" {
  token = var.github_token
  owner = var.github_organization
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Core Infrastructure Modules

# 1. Reliability & Disaster Recovery
module "reliability_dr" {
  source = "./modules/reliability-dr"
  
  environment    = var.environment
  aws_region     = var.aws_region
  gcp_project_id = var.gcp_project_id
  gcp_region     = var.gcp_region
  azure_location = var.azure_location
  
  # OpenStack Configuration
  openstack_endpoint    = var.openstack_auth_url
  openstack_project_id  = var.openstack_project_id
  openstack_region      = var.openstack_region
  
  # DNS and Networking
  domain_name           = var.domain_name
  route53_zone_id       = var.route53_zone_id
  health_check_regions  = var.health_check_regions
  
  # High Availability Configuration
  enable_active_active     = var.enable_active_active
  enable_cross_region_backup = var.enable_cross_region_backup
  backup_retention_days    = var.backup_retention_days
  
  # Masakari Configuration
  enable_masakari          = var.enable_masakari
  masakari_notification_driver = var.masakari_notification_driver
  
  # Senlin Configuration
  enable_senlin           = var.enable_senlin
  senlin_scaling_policies = var.senlin_scaling_policies
  
  tags = local.common_tags
}

# 2. Security & Identity Management
module "security_identity" {
  source = "./modules/security-identity"
  
  environment = var.environment
  domain_name = var.domain_name
  
  # Identity Provider Configuration
  enable_keystone_federation = var.enable_keystone_federation
  oidc_provider_url         = var.oidc_provider_url
  saml_provider_metadata    = var.saml_provider_metadata
  
  # Vault Configuration
  vault_cluster_size = var.vault_cluster_size
  enable_vault_hsm   = var.enable_vault_hsm
  hsm_slot_id        = var.hsm_slot_id
  
  # AWS IAM Integration
  aws_account_id     = data.aws_caller_identity.current.account_id
  aws_region         = var.aws_region
  
  # GCP IAM Integration
  gcp_project_id     = var.gcp_project_id
  gcp_project_number = var.gcp_project_number
  
  # Azure AD Integration
  azure_tenant_id    = var.azure_tenant_id
  azure_subscription_id = var.azure_subscription_id
  
  # OPA Policy Configuration
  opa_policies = var.opa_policies
  
  # Boundary Configuration
  enable_boundary = var.enable_boundary
  boundary_workers = var.boundary_workers
  
  tags = local.common_tags
  
  depends_on = [module.reliability_dr]
}

# 3. Networking & Performance
module "networking_performance" {
  source = "./modules/networking-performance"
  
  environment = var.environment
  
  # Multi-Cloud Networking
  aws_vpc_cidr    = var.aws_vpc_cidr
  gcp_vpc_cidr    = var.gcp_vpc_cidr
  azure_vnet_cidr = var.azure_vnet_cidr
  openstack_network_cidr = var.openstack_network_cidr
  
  # BGP Configuration
  enable_bgp        = var.enable_bgp
  bgp_asn_openstack = var.bgp_asn_openstack
  bgp_asn_aws       = var.bgp_asn_aws
  bgp_asn_gcp       = var.bgp_asn_gcp
  bgp_asn_azure     = var.bgp_asn_azure
  
  # WireGuard VPN Configuration
  enable_wireguard = var.enable_wireguard
  wireguard_port   = var.wireguard_port
  
  # Global Load Balancing
  enable_global_lb = var.enable_global_lb
  lb_algorithm     = var.lb_algorithm
  
  # eBPF Observability
  enable_ebpf_observability = var.enable_ebpf_observability
  
  # Service Mesh Integration
  enable_service_mesh = var.enable_service_mesh
  service_mesh_type   = var.service_mesh_type
  
  tags = local.common_tags
  
  depends_on = [module.reliability_dr, module.security_identity]
}
    aws       = var.aws_vpc_cidr
    gcp       = var.gcp_vpc_cidr
    azure     = var.azure_vnet_cidr
  }

  enable_vpn_gateways    = true
  enable_transit_gateway = true
  enable_bgp_routing     = true
  
  tags = local.common_tags
}

# Burst Controller Infrastructure
module "burst_controller" {
  source = "./modules/burst-controller"

  environment = var.environment
  
  # Kubernetes cluster configuration
  cluster_name         = "${var.environment}-burst-controller"
  node_instance_types = var.controller_node_types
  min_nodes           = 2
  max_nodes           = 10
  
  # Controller configuration
  burst_threshold     = local.federation_config.burst_threshold_percent
  scaling_policies    = var.scaling_policies
  monitoring_enabled  = true
  
  # Multi-cloud access
  cloud_providers = [
    "openstack",
    "aws", 
    "gcp",
    "azure"
  ]
  
  tags = local.common_tags

  depends_on = [
    module.openstack_federation,
    module.multi_cloud_networking
  ]
}

# Security and Secrets Management
module "security" {
  source = "./modules/security"

  environment = var.environment
  
  # Vault configuration
  vault_cluster_size = 3
  vault_ha_enabled  = true
  
  # Barbican integration
  barbican_enabled = true
  barbican_backend = "vault"
  
  # PKI and certificates
  enable_pki         = true
  certificate_domains = [
    "*.${var.environment}.federation.local",
    "*.openstack.${var.environment}.local",
    "*.burst.${var.environment}.local"
  ]
  
  # Network security
  enable_network_policies = true
  enable_pod_security     = true
  enable_rbac            = true
  
  tags = local.common_tags
}

# Monitoring and Observability
module "monitoring" {
  source = "./modules/monitoring"

  environment = var.environment
  
  # Prometheus configuration
  prometheus_retention = "30d"
  prometheus_storage  = "100Gi"
  
  # Grafana configuration
  grafana_admin_password = data.vault_generic_secret.cloud_credentials.data["grafana_admin_password"]
  
  # Alerting
  enable_alertmanager = true
  alert_channels = [
    "slack",
    "pagerduty",
    "email"
  ]
  
  # Metrics collection
  scrape_configs = [
    "openstack-exporter",
    "aws-cloudwatch",
    "gcp-monitoring",
    "azure-monitor",
    "burst-controller"
  ]
  
  tags = local.common_tags
}

# Cost Management and Policies
module "governance" {
  source = "./modules/governance"

  environment = var.environment
  
  # Cost management
  cost_budgets = var.cost_budgets
  cost_alerts  = var.cost_alerts
  
  # Policy enforcement
  enable_opa_policies = true
  policy_violations_action = "alert" # alert, block, or remediate
  
  # Compliance
  compliance_frameworks = [
    "SOC2",
    "PCI-DSS", 
    "GDPR",
    "HIPAA"
  ]
  
  tags = local.common_tags
}

# Outputs for other modules and external systems
output "federation_endpoints" {
  description = "Federation service endpoints"
  value = {
    keystone_federation = module.openstack_federation.federation_endpoint
    burst_controller   = module.burst_controller.controller_endpoint
    monitoring        = module.monitoring.grafana_endpoint
    vault             = module.security.vault_endpoint
  }
  sensitive = true
}

output "network_configuration" {
  description = "Multi-cloud network configuration"
  value = {
    vpn_gateways      = module.multi_cloud_networking.vpn_gateways
    transit_gateways  = module.multi_cloud_networking.transit_gateways
    bgp_configurations = module.multi_cloud_networking.bgp_configurations
  }
}

output "security_configuration" {
  description = "Security configuration details"
  value = {
    vault_cluster_url = module.security.vault_cluster_url
    pki_ca_cert      = module.security.ca_certificate
    barbican_endpoint = module.security.barbican_endpoint
  }
  sensitive = true
}
