# Enterprise Security, Identity, and Secrets Management
# Comprehensive security implementation with HSM, SSO, and Zero Trust

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.20"
    }
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
    boundary = {
      source  = "hashicorp/boundary"
      version = "~> 1.1"
    }
  }
}

# Enterprise SSO Configuration
# Keystone Federation with OIDC/SAML
resource "openstack_identity_project_v3" "federation_projects" {
  for_each = var.federation_projects
  
  name        = each.key
  description = each.value.description
  domain_id   = data.openstack_identity_domain_v3.default.id
  
  tags = [
    "environment:${var.environment}",
    "cost_center:${each.value.cost_center}",
    "sso_enabled:true"
  ]
}

# OIDC Identity Provider Configuration
resource "openstack_identity_provider_v3" "okta" {
  name        = "okta-${var.environment}"
  description = "Okta OIDC Identity Provider"
  enabled     = true
  
  remote_ids = [var.okta_issuer_url]
  
  tags = [
    "provider:okta",
    "protocol:oidc"
  ]
}

# SAML Identity Provider for Azure AD
resource "openstack_identity_provider_v3" "azure_ad" {
  name        = "azure-ad-${var.environment}"
  description = "Azure AD SAML Identity Provider"
  enabled     = true
  
  remote_ids = [var.azure_ad_entity_id]
  
  tags = [
    "provider:azure_ad",
    "protocol:saml"
  ]
}

# Identity Mapping for Role Assignment
resource "openstack_identity_mapping_v3" "okta_mapping" {
  mapping_id = "okta-role-mapping"
  
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
            id = data.openstack_identity_group_v3.developers.id
          }
        }
      ]
      remote = [
        {
          type = "openstack_user"
        },
        {
          type = "openstack_groups"
          any_one_of = ["developers", "engineers"]
        }
      ]
    },
    {
      local = [
        {
          user = {
            name = "{0}"
          }
        },
        {
          group = {
            id = data.openstack_identity_group_v3.admins.id
          }
        }
      ]
      remote = [
        {
          type = "openstack_user"
        },
        {
          type = "openstack_groups"
          any_one_of = ["administrators", "platform-team"]
        }
      ]
    }
  ])
}

# Federation Protocol Configuration
resource "openstack_identity_protocol_v3" "oidc" {
  protocol_id    = "oidc"
  identity_provider_id = openstack_identity_provider_v3.okta.name
  mapping_id     = openstack_identity_mapping_v3.okta_mapping.mapping_id
}

resource "openstack_identity_protocol_v3" "saml" {
  protocol_id    = "saml2"
  identity_provider_id = openstack_identity_provider_v3.azure_ad.name
  mapping_id     = "azure-ad-mapping"
}

# SCIM Configuration for User Lifecycle Management
resource "okta_app_oauth" "openstack_federation" {
  label       = "OpenStack Federation ${title(var.environment)}"
  type        = "service"
  status      = "ACTIVE"
  
  grant_types = ["authorization_code", "refresh_token"]
  redirect_uris = [
    "https://keystone.${var.domain}/v3/auth/OS-FEDERATION/identity_providers/okta-${var.environment}/protocols/oidc/auth"
  ]
  
  response_types = ["code"]
  
  issuer_mode = "ORG_URL"
  
  groups_claim {
    type        = "FILTER"
    filter_type = "REGEX"
    name        = "groups"
    value       = ".*"
  }
}

# SCIM Application for User Provisioning
resource "okta_app_saml" "openstack_scim" {
  label     = "OpenStack SCIM ${title(var.environment)}"
  status    = "ACTIVE"
  
  sso_url          = "https://keystone.${var.domain}/v3/auth/OS-FEDERATION/identity_providers/okta-${var.environment}/protocols/saml2/auth"
  recipient        = "https://keystone.${var.domain}/v3/auth/OS-FEDERATION/identity_providers/okta-${var.environment}/protocols/saml2/auth"
  destination      = "https://keystone.${var.domain}/v3/auth/OS-FEDERATION/identity_providers/okta-${var.environment}/protocols/saml2/auth"
  audience         = "https://keystone.${var.domain}"
  
  subject_name_id_template = "$${user.userName}"
  subject_name_id_format   = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  
  response_signed   = true
  assertion_signed  = true
  signature_algorithm = "RSA_SHA256"
  digest_algorithm    = "SHA256"
  
  attribute_statements {
    type      = "GROUP"
    name      = "groups"
    namespace = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
  }
}

# AWS IAM Role Mapping for Cross-Cloud Access
resource "aws_iam_role" "openstack_federation" {
  for_each = var.openstack_projects
  
  name = "OpenStackFederation-${each.key}-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.openstack.arn
        }
        Condition = {
          StringEquals = {
            "${aws_iam_openid_connect_provider.openstack.url}:sub" = "project:${each.key}"
            "${aws_iam_openid_connect_provider.openstack.url}:aud" = "aws"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# OpenID Connect Provider for OpenStack
resource "aws_iam_openid_connect_provider" "openstack" {
  url = "https://keystone.${var.domain}/v3/auth/OS-FEDERATION/websso"
  
  client_id_list = ["aws"]
  
  thumbprint_list = [var.keystone_cert_thumbprint]
  
  tags = local.common_tags
}

# GCP Workload Identity for OpenStack Federation
resource "google_iam_workload_identity_pool" "openstack" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = "openstack-federation-${var.environment}"
  display_name              = "OpenStack Federation Pool"
  description               = "Workload Identity Pool for OpenStack Federation"
}

resource "google_iam_workload_identity_pool_provider" "openstack" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.openstack.workload_identity_pool_id
  workload_identity_pool_provider_id = "openstack-oidc"
  display_name                       = "OpenStack OIDC Provider"
  
  attribute_mapping = {
    "google.subject"     = "assertion.sub"
    "attribute.project"  = "assertion.project"
    "attribute.user"     = "assertion.user"
  }
  
  oidc {
    issuer_uri = "https://keystone.${var.domain}/v3/auth/OS-FEDERATION"
    allowed_audiences = ["gcp"]
  }
}

# HSM-Backed Secrets with Barbican and Castellan
resource "openstack_keymanager_secret_v1" "hsm_root_key" {
  name         = "hsm-root-key-${var.environment}"
  algorithm    = "aes"
  bit_length   = 256
  mode         = "cbc"
  secret_type  = "symmetric"
  
  # HSM backend configuration via Castellan
  metadata = {
    hsm_backend     = "pkcs11"
    hsm_slot_id     = var.hsm_slot_id
    castellan_type  = "hsm"
    rotation_policy = "90days"
    backup_required = "true"
  }
}

# Vault as System of Record for Secrets
resource "vault_mount" "federation" {
  path        = "federation"
  type        = "kv-v2"
  description = "Federation secrets store"
  
  options = {
    version = "2"
  }
}

# PKI Mount for Short-Lived Certificates
resource "vault_mount" "pki_root" {
  path                      = "pki-root"
  type                      = "pki"
  description               = "Root CA for federation"
  default_lease_ttl_seconds = 3600    # 1 hour
  max_lease_ttl_seconds     = 8760 * 3600  # 1 year
}

resource "vault_mount" "pki_intermediate" {
  path                      = "pki-intermediate"
  type                      = "pki"
  description               = "Intermediate CA for services"
  default_lease_ttl_seconds = 3600    # 1 hour
  max_lease_ttl_seconds     = 720 * 3600   # 30 days
}

# PKI Root CA Configuration
resource "vault_pki_secret_backend_root_cert" "federation" {
  depends_on = [vault_mount.pki_root]
  
  backend = vault_mount.pki_root.path
  type    = "internal"
  
  common_name          = "Federation Root CA"
  ttl                  = "87600h"  # 10 years
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  
  ou           = "Platform Engineering"
  organization = var.organization_name
  country      = var.country_code
  locality     = var.locality
  province     = var.province
}

# PKI Intermediate CA
resource "vault_pki_secret_backend_intermediate_cert_request" "federation" {
  depends_on = [vault_mount.pki_intermediate]
  
  backend = vault_mount.pki_intermediate.path
  type    = "internal"
  
  common_name = "Federation Intermediate CA"
  key_type    = "rsa"
  key_bits    = 4096
  
  ou           = "Platform Engineering"
  organization = var.organization_name
  country      = var.country_code
  locality     = var.locality
  province     = var.province
}

resource "vault_pki_secret_backend_root_sign_intermediate" "federation" {
  depends_on = [vault_pki_secret_backend_root_cert.federation]
  
  backend = vault_mount.pki_root.path
  
  csr         = vault_pki_secret_backend_intermediate_cert_request.federation.csr
  common_name = "Federation Intermediate CA"
  
  exclude_cn_from_sans = true
  max_path_length      = 1
  ttl                  = "43800h"  # 5 years
}

# AWS STS Role for Short-Lived Credentials
resource "vault_aws_secret_backend" "federation" {
  access_key = var.vault_aws_access_key
  secret_key = var.vault_aws_secret_key
  region     = var.aws_region
  
  default_lease_ttl_seconds = 3600   # 1 hour
  max_lease_ttl_seconds     = 7200   # 2 hours
}

resource "vault_aws_secret_backend_role" "burst_role" {
  backend = vault_aws_secret_backend.federation.path
  name    = "burst-role"
  
  credential_type = "assumed_role"
  role_arns       = [aws_iam_role.burst_controller.arn]
  
  default_sts_ttl = 3600  # 1 hour
  max_sts_ttl     = 7200  # 2 hours
}

# Automatic Key Rotation Policy
resource "vault_pki_secret_backend_role" "service_certs" {
  backend = vault_mount.pki_intermediate.path
  name    = "service-certificates"
  
  ttl     = "24h"
  max_ttl = "72h"
  
  allow_localhost    = true
  allow_bare_domains = false
  allow_subdomains   = true
  allow_glob_domains = false
  
  allowed_domains = [
    "*.${var.domain}",
    "*.federation.local",
    "*.openstack.local"
  ]
  
  country                = [var.country_code]
  locality               = [var.locality]
  organization           = [var.organization_name]
  ou                     = ["Platform Engineering"]
  generate_lease         = true
  no_store               = false
  require_cn             = true
  policy_identifiers     = ["1.3.6.1.4.1.311.21.8.8.3.3"]  # Extended Validation
  
  ext_key_usage = [
    "ServerAuth",
    "ClientAuth"
  ]
  
  key_type = "rsa"
  key_bits = 2048
}

# Zero Trust Network Controls
# mTLS Configuration for Service-to-Service Communication
resource "vault_pki_secret_backend_config_urls" "intermediate" {
  backend                 = vault_mount.pki_intermediate.path
  issuing_certificates    = ["https://vault.${var.domain}/v1/pki-intermediate/ca"]
  crl_distribution_points = ["https://vault.${var.domain}/v1/pki-intermediate/crl"]
}

# OPA/Gatekeeper Policies for Cluster and VM Posture
resource "kubernetes_manifest" "admission_policy" {
  manifest = {
    apiVersion = "templates.gatekeeper.sh/v1beta1"
    kind       = "ConstraintTemplate"
    metadata = {
      name = "requiredsecuritycontext"
      namespace = "gatekeeper-system"
    }
    spec = {
      crd = {
        spec = {
          names = {
            kind = "RequiredSecurityContext"
          }
          validation = {
            properties = {
              requiredSecurityContext = {
                type = "object"
                properties = {
                  runAsNonRoot = {
                    type = "boolean"
                  }
                  readOnlyRootFilesystem = {
                    type = "boolean"
                  }
                  allowPrivilegeEscalation = {
                    type = "boolean"
                  }
                }
              }
            }
          }
        }
      }
      targets = [
        {
          target = "admission.k8s.gatekeeper.sh"
          rego = templatefile("${path.module}/policies/security-context.rego", {
            environment = var.environment
          })
        }
      ]
    }
  }
}

# Boundary Configuration for Just-in-Time Access
resource "boundary_scope" "federation" {
  scope_id                 = "global"
  name                     = "federation-${var.environment}"
  description              = "Federation boundary scope"
  auto_create_admin_role   = true
  auto_create_default_role = true
}

resource "boundary_host_catalog_static" "federation" {
  name        = "federation-hosts"
  description = "Federation infrastructure hosts"
  scope_id    = boundary_scope.federation.id
}

resource "boundary_host_static" "openstack_controllers" {
  for_each = var.openstack_controllers
  
  name            = "openstack-controller-${each.key}"
  description     = "OpenStack controller ${each.key}"
  address         = each.value.ip
  host_catalog_id = boundary_host_catalog_static.federation.id
}

resource "boundary_target" "openstack_ssh" {
  type         = "tcp"
  name         = "openstack-ssh-access"
  description  = "SSH access to OpenStack controllers"
  scope_id     = boundary_scope.federation.id
  default_port = 22
  
  host_source_ids = [
    for host in boundary_host_static.openstack_controllers : host.id
  ]
}

# Compliance by Design - CIS/NIST Controls
resource "vault_policy" "compliance" {
  name = "compliance-policy-${var.environment}"
  
  policy = templatefile("${path.module}/policies/compliance.hcl", {
    environment = var.environment
  })
}

# Audit Log Configuration
resource "vault_audit" "compliance_audit" {
  type = "file"
  
  options = {
    file_path = "/vault/logs/audit.log"
    log_raw   = false
    hmac_accessor = true
    mode     = "0600"
    format   = "json"
  }
}

# Security Scanning Integration
resource "aws_inspector_assessment_template" "federation" {
  name       = "federation-security-assessment-${var.environment}"
  target_arn = aws_inspector_assessment_target.federation.arn
  duration   = 3600  # 1 hour
  
  rules_package_arns = [
    "arn:aws:inspector:${var.aws_region}:316112463485:rulespackage/0-R01qwB5Q",  # Security Best Practices
    "arn:aws:inspector:${var.aws_region}:316112463485:rulespackage/0-gEjTy7T7",  # Network Reachability
    "arn:aws:inspector:${var.aws_region}:316112463485:rulespackage/0-rExsr2X8",  # Runtime Behavior Analysis
    "arn:aws:inspector:${var.aws_region}:316112463485:rulespackage/0-gBONHN9h"   # Common Vulnerabilities
  ]
  
  tags = local.common_tags
}

# Data sources
data "openstack_identity_domain_v3" "default" {
  name = "Default"
}

data "openstack_identity_group_v3" "developers" {
  name = "developers"
}

data "openstack_identity_group_v3" "admins" {
  name = "administrators"
}

# Outputs
output "sso_configuration" {
  description = "SSO and federation configuration"
  value = {
    okta_app_id     = okta_app_oauth.openstack_federation.id
    azure_app_id    = okta_app_saml.openstack_scim.id
    keystone_idp    = openstack_identity_provider_v3.okta.name
    aws_oidc_arn    = aws_iam_openid_connect_provider.openstack.arn
    gcp_pool_id     = google_iam_workload_identity_pool.openstack.name
  }
}

output "secrets_management" {
  description = "Secrets management configuration"
  value = {
    vault_mount        = vault_mount.federation.path
    pki_root_mount     = vault_mount.pki_root.path
    pki_int_mount      = vault_mount.pki_intermediate.path
    barbican_secret_id = openstack_keymanager_secret_v1.hsm_root_key.id
  }
  sensitive = true
}

output "zero_trust_config" {
  description = "Zero Trust security configuration"
  value = {
    boundary_scope = boundary_scope.federation.id
    boundary_target = boundary_target.openstack_ssh.id
    compliance_policy = vault_policy.compliance.name
  }
}
