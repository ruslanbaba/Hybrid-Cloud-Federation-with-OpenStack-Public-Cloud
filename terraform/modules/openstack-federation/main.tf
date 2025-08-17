# OpenStack Federation Terraform Module
# Enterprise-grade Keystone-to-Cloud federation

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.50"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

# Keystone Federation Protocol Configuration
resource "openstack_identity_protocol_v3" "saml_protocol" {
  for_each = {
    for k, v in var.federation_providers : k => v
    if v.provider_type == "saml" && v.enabled
  }

  protocol    = "saml2"
  identity_provider = openstack_identity_provider_v3.cloud_providers[each.key].id
  mapping     = openstack_identity_mapping_v3.federation_mapping[each.key].id
}

resource "openstack_identity_protocol_v3" "oidc_protocol" {
  for_each = {
    for k, v in var.federation_providers : k => v
    if v.provider_type == "oidc" && v.enabled
  }

  protocol    = "openid_connect"
  identity_provider = openstack_identity_provider_v3.cloud_providers[each.key].id
  mapping     = openstack_identity_mapping_v3.federation_mapping[each.key].id
}

# Identity Provider Configuration
resource "openstack_identity_provider_v3" "cloud_providers" {
  for_each = var.federation_providers

  name        = each.key
  description = "Federation with ${upper(each.key)} cloud provider"
  enabled     = each.value.enabled
  
  # Remote IDs for each provider
  remote_ids = each.key == "aws" ? [
    "arn:aws:iam::${data.vault_generic_secret.aws_config.data["account_id"]}:saml-provider/OpenStackFederation"
  ] : each.key == "gcp" ? [
    "https://accounts.google.com"
  ] : each.key == "azure" ? [
    "https://sts.windows.net/${data.vault_generic_secret.azure_config.data["tenant_id"]}/"
  ] : []

  tags = var.tags
}

# Mapping Rules for Attribute Transformation
resource "openstack_identity_mapping_v3" "federation_mapping" {
  for_each = var.federation_providers

  mapping_id = "${each.key}_federation_mapping"
  rules = jsonencode([
    {
      local = [
        {
          user = {
            name = "{0}"
          }
        },
        {
          group = {
            id = openstack_identity_group_v3.federated_users[each.key].id
          }
        }
      ]
      remote = [
        {
          type = each.value.provider_type == "saml" ? 
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" :
            "email"
        }
      ]
    },
    {
      local = [
        {
          projects = [
            {
              name = openstack_identity_project_v3.federation_project.name
              roles = [
                {
                  name = openstack_identity_role_v3.federation_role.name
                }
              ]
            }
          ]
        }
      ]
      remote = [
        {
          type = "openstack_project"
          any_one_of = ["federation"]
        }
      ]
    }
  ])
}

# Federated User Groups
resource "openstack_identity_group_v3" "federated_users" {
  for_each = var.federation_providers

  name        = "${each.key}_federated_users"
  description = "Federated users from ${upper(each.key)}"
  
  tags = var.tags
}

# Federation Project
resource "openstack_identity_project_v3" "federation_project" {
  name        = "federation_project"
  description = "Project for federated cloud resources"
  domain_id   = data.openstack_identity_project_v3.default_domain.domain_id
  enabled     = true
  is_domain   = false
  
  tags = var.tags
}

# Federation Role
resource "openstack_identity_role_v3" "federation_role" {
  name = "federation_user"
  
  # Custom role with specific permissions for federation
  description = "Role for federated cloud users with burst capabilities"
}

# Role Assignments for Federation Groups
resource "openstack_identity_role_assignment_v3" "federation_assignment" {
  for_each = var.federation_providers

  group_id   = openstack_identity_group_v3.federated_users[each.key].id
  project_id = openstack_identity_project_v3.federation_project.id
  role_id    = openstack_identity_role_v3.federation_role.id
}

# Service Provider Configuration for External Clouds
resource "openstack_identity_service_provider_v3" "external_sp" {
  for_each = var.federation_providers

  sp_id       = "${each.key}_service_provider"
  description = "Service Provider for ${upper(each.key)} integration"
  enabled     = each.value.enabled
  
  # Authentication URL for the external provider
  auth_url = each.value.endpoint_url
  
  tags = var.tags
}

# Network for Federation Services
resource "openstack_networking_network_v2" "federation_network" {
  name           = "federation_management_network"
  description    = "Network for federation service communications"
  admin_state_up = "true"
  shared         = false
  
  tags = var.tags
}

resource "openstack_networking_subnet_v2" "federation_subnet" {
  name            = "federation_management_subnet"
  network_id      = openstack_networking_network_v2.federation_network.id
  cidr            = "192.168.100.0/24"
  ip_version      = 4
  enable_dhcp     = true
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
  
  allocation_pool {
    start = "192.168.100.10"
    end   = "192.168.100.250"
  }
  
  tags = var.tags
}

# Security Group for Federation Services
resource "openstack_networking_secgroup_v2" "federation_secgroup" {
  name        = "federation_security_group"
  description = "Security group for federation services"
  
  tags = var.tags
}

# Security Group Rules
resource "openstack_networking_secgroup_rule_v2" "federation_https" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.federation_secgroup.id
  description       = "HTTPS for federation endpoints"
}

resource "openstack_networking_secgroup_rule_v2" "federation_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "10.0.0.0/8"
  security_group_id = openstack_networking_secgroup_v2.federation_secgroup.id
  description       = "SSH for management access"
}

resource "openstack_networking_secgroup_rule_v2" "federation_monitoring" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9090
  port_range_max    = 9100
  remote_ip_prefix  = "192.168.100.0/24"
  security_group_id = openstack_networking_secgroup_v2.federation_secgroup.id
  description       = "Monitoring and metrics"
}

# Load Balancer for Federation Endpoints
resource "openstack_lb_loadbalancer_v2" "federation_lb" {
  vip_subnet_id      = openstack_networking_subnet_v2.federation_subnet.id
  name              = "federation_load_balancer"
  description       = "Load balancer for federation services"
  admin_state_up    = true
  loadbalancer_provider = "octavia"
  
  tags = var.tags
}

resource "openstack_lb_listener_v2" "federation_listener" {
  protocol        = "HTTPS"
  protocol_port   = 443
  loadbalancer_id = openstack_lb_loadbalancer_v2.federation_lb.id
  name           = "federation_https_listener"
  
  # TLS termination with certificate from Barbican
  default_tls_container_ref = openstack_keymanager_container_v1.federation_cert.container_ref
}

# Certificate Management with Barbican
resource "openstack_keymanager_container_v1" "federation_cert" {
  name = "federation_tls_certificate"
  type = "certificate"
  
  secret_refs {
    name       = "certificate"
    secret_ref = openstack_keymanager_secret_v1.federation_cert_secret.secret_ref
  }
  
  secret_refs {
    name       = "private_key"
    secret_ref = openstack_keymanager_secret_v1.federation_key_secret.secret_ref
  }
}

resource "openstack_keymanager_secret_v1" "federation_cert_secret" {
  name                 = "federation_certificate"
  payload              = var.federation_certificate
  payload_content_type = "text/plain"
  secret_type         = "certificate"
  
  metadata = {
    purpose = "federation_tls"
  }
}

resource "openstack_keymanager_secret_v1" "federation_key_secret" {
  name                 = "federation_private_key"
  payload              = var.federation_private_key
  payload_content_type = "text/plain"
  secret_type         = "private"
  
  metadata = {
    purpose = "federation_tls"
  }
}

# Data sources for existing resources
data "openstack_identity_project_v3" "default_domain" {
  domain_id = "default"
  name      = "Default"
}

data "vault_generic_secret" "aws_config" {
  path = "secret/cloud-federation/aws"
}

data "vault_generic_secret" "azure_config" {
  path = "secret/cloud-federation/azure"
}

# Monitoring and Alerting for Federation
resource "openstack_compute_instance_v2" "federation_monitor" {
  name              = "federation-monitor-${var.environment}"
  image_name        = var.monitor_image_name
  flavor_name       = var.monitor_flavor_name
  key_pair          = var.key_pair_name
  security_groups   = [openstack_networking_secgroup_v2.federation_secgroup.name]
  availability_zone = var.availability_zone

  network {
    uuid = openstack_networking_network_v2.federation_network.id
  }

  user_data = base64encode(templatefile("${path.module}/templates/monitor-init.sh", {
    vault_address    = var.vault_address
    environment     = var.environment
    federation_providers = var.federation_providers
  }))

  tags = var.tags
}

# Floating IP for external access
resource "openstack_networking_floatingip_v2" "federation_monitor_fip" {
  pool = var.external_network_name
  
  tags = var.tags
}

resource "openstack_compute_floatingip_associate_v2" "federation_monitor_fip_associate" {
  floating_ip = openstack_networking_floatingip_v2.federation_monitor_fip.address
  instance_id = openstack_compute_instance_v2.federation_monitor.id
}
