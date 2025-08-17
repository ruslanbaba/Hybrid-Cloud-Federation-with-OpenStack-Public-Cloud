# Enterprise Security Policies for Hybrid Cloud Federation
# Zero-trust security model with comprehensive compliance

package hybrid.federation.security

import future.keywords.in

# Default deny all actions
default allow = false
default allow_cross_cloud_access = false
default allow_data_transfer = false

# Security policy configuration
security_policies := {
    "encryption_required": true,
    "multi_factor_auth_required": true,
    "certificate_validation_required": true,
    "network_segmentation_required": true,
    "audit_logging_required": true,
    "data_classification_required": true,
    "vulnerability_scanning_required": true
}

# Compliance frameworks configuration
compliance_frameworks := {
    "SOC2": {
        "enabled": true,
        "requirements": [
            "encryption_at_rest",
            "encryption_in_transit", 
            "access_logging",
            "user_access_controls",
            "incident_response"
        ]
    },
    "PCI_DSS": {
        "enabled": true,
        "requirements": [
            "network_segmentation",
            "strong_cryptography",
            "access_controls",
            "vulnerability_management",
            "monitoring"
        ]
    },
    "GDPR": {
        "enabled": true,
        "requirements": [
            "data_encryption",
            "data_portability",
            "right_to_deletion",
            "consent_management",
            "data_minimization"
        ]
    },
    "HIPAA": {
        "enabled": false,
        "requirements": [
            "data_encryption",
            "access_controls",
            "audit_logging",
            "business_associate_agreements"
        ]
    }
}

# Allow federation access with proper authentication
allow {
    input.action == "federate_identity"
    valid_authentication
    valid_authorization
    security_controls_validated
    compliance_requirements_met
}

# Allow cross-cloud access with security validation
allow_cross_cloud_access {
    input.action == "cross_cloud_access"
    valid_federation_token
    destination_cloud_approved
    network_security_validated
    data_classification_appropriate
}

# Allow data transfer with encryption and compliance
allow_data_transfer {
    input.action == "transfer_data"
    data_encrypted_in_transit
    data_encrypted_at_rest
    transfer_authorized
    compliance_data_handling_met
}

# Authentication validation
valid_authentication {
    input.auth.method in ["saml", "oidc", "oauth2"]
    input.auth.multi_factor == true
    token_not_expired
    issuer_trusted
}

token_not_expired {
    input.auth.expires_at > time.now_ns()
}

issuer_trusted {
    input.auth.issuer in data.trusted_issuers
}

# Authorization validation
valid_authorization {
    user_has_required_roles
    action_permitted_for_user
    resource_access_allowed
}

user_has_required_roles {
    required_roles := action_role_mapping[input.action]
    user_roles := {role | role := input.user.roles[_]}
    required_roles_set := {role | role := required_roles[_]}
    count(required_roles_set - user_roles) == 0
}

action_role_mapping := {
    "federate_identity": ["federation_user", "authenticated"],
    "cross_cloud_access": ["burst_user", "federation_user"],
    "transfer_data": ["data_transfer_user", "federation_user"],
    "scale_out": ["burst_user", "cloud_operator"],
    "scale_in": ["burst_user", "cloud_operator"],
    "cost_monitoring": ["cost_monitor", "federation_admin"],
    "policy_management": ["policy_admin", "federation_admin"]
}

action_permitted_for_user {
    input.action in data.user_permissions[input.user.id]
}

resource_access_allowed {
    input.resource.classification in allowed_classifications_for_user
}

allowed_classifications_for_user := {
    "public", "internal"
} {
    "standard_user" in input.user.roles
} else := {
    "public", "internal", "confidential"
} {
    "privileged_user" in input.user.roles
} else := {
    "public", "internal", "confidential", "restricted"
} {
    "admin_user" in input.user.roles
} else := {"public"}

# Security controls validation
security_controls_validated {
    encryption_requirements_met
    network_security_requirements_met
    access_control_requirements_met
    monitoring_requirements_met
}

encryption_requirements_met {
    security_policies.encryption_required == true
    input.security.encryption_at_rest == true
    input.security.encryption_in_transit == true
    input.security.encryption_algorithm in approved_encryption_algorithms
}

approved_encryption_algorithms := {
    "AES-256-GCM",
    "ChaCha20-Poly1305", 
    "RSA-4096",
    "ECDSA-P384",
    "Ed25519"
}

network_security_requirements_met {
    security_policies.network_segmentation_required == true
    input.network.security_groups_enabled == true
    input.network.firewall_rules_applied == true
    input.network.intrusion_detection_enabled == true
    no_public_access_to_sensitive_resources
}

no_public_access_to_sensitive_resources {
    input.resource.classification != "public"
    "0.0.0.0/0" not in input.network.allowed_cidrs
}

access_control_requirements_met {
    input.access_control.rbac_enabled == true
    input.access_control.principle_of_least_privilege == true
    input.access_control.session_timeout <= 3600  # 1 hour max
    input.access_control.concurrent_sessions <= 3
}

monitoring_requirements_met {
    security_policies.audit_logging_required == true
    input.monitoring.audit_logging_enabled == true
    input.monitoring.security_monitoring_enabled == true
    input.monitoring.anomaly_detection_enabled == true
}

# Compliance requirements validation
compliance_requirements_met {
    soc2_requirements_met
    pci_dss_requirements_met
    gdpr_requirements_met
}

soc2_requirements_met {
    not compliance_frameworks.SOC2.enabled
} else {
    compliance_frameworks.SOC2.enabled
    encryption_requirements_met
    access_control_requirements_met
    monitoring_requirements_met
    incident_response_plan_exists
}

pci_dss_requirements_met {
    not compliance_frameworks.PCI_DSS.enabled
} else {
    compliance_frameworks.PCI_DSS.enabled
    network_security_requirements_met
    strong_cryptography_implemented
    vulnerability_management_active
}

gdpr_requirements_met {
    not compliance_frameworks.GDPR.enabled
} else {
    compliance_frameworks.GDPR.enabled
    data_protection_measures_implemented
    consent_management_active
    data_portability_supported
}

# Federation-specific security checks
valid_federation_token {
    input.federation.token_type in ["SAML", "JWT", "OAuth2"]
    input.federation.token_signature_valid == true
    input.federation.token_audience_valid == true
    input.federation.token_scope_sufficient == true
}

destination_cloud_approved {
    input.destination.provider in approved_cloud_providers
    input.destination.region in approved_regions[input.destination.provider]
    input.destination.compliance_certified == true
}

approved_cloud_providers := {"aws", "gcp", "azure", "openstack"}

approved_regions := {
    "aws": ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1"],
    "gcp": ["us-central1", "us-east1", "europe-west1", "europe-west3"],
    "azure": ["eastus", "westus2", "westeurope", "northeurope"],
    "openstack": ["regionone", "region-west", "region-east"]
}

network_security_validated {
    input.network.vpn_enabled == true
    input.network.transit_encryption == true
    input.network.network_acls_configured == true
    input.network.ddos_protection_enabled == true
}

# Data security and classification
data_encrypted_in_transit {
    input.data.encryption_in_transit == true
    input.data.tls_version >= "1.3"
    input.data.certificate_validation == true
}

data_encrypted_at_rest {
    input.data.encryption_at_rest == true
    input.data.key_management == "vault"
    input.data.key_rotation_enabled == true
}

data_classification_appropriate {
    input.data.classification in ["public", "internal", "confidential", "restricted"]
    classification_handling_requirements_met
}

classification_handling_requirements_met {
    input.data.classification == "public"
} else {
    input.data.classification == "internal"
    internal_data_requirements_met
} else {
    input.data.classification == "confidential"
    confidential_data_requirements_met
} else {
    input.data.classification == "restricted"
    restricted_data_requirements_met
}

internal_data_requirements_met {
    input.data.access_logging == true
    input.data.backup_encrypted == true
}

confidential_data_requirements_met {
    internal_data_requirements_met
    input.data.multi_factor_auth_required == true
    input.data.data_loss_prevention_enabled == true
}

restricted_data_requirements_met {
    confidential_data_requirements_met
    input.data.geographic_restrictions_enforced == true
    input.data.privileged_access_management == true
    input.data.continuous_monitoring == true
}

# Security violations and alerts
violations[violation] {
    not valid_authentication
    violation := {
        "type": "authentication_failure",
        "message": "Invalid or insufficient authentication",
        "severity": "high",
        "action": "block",
        "remediation": "Verify authentication method and credentials"
    }
}

violations[violation] {
    not encryption_requirements_met
    violation := {
        "type": "encryption_violation",
        "message": "Encryption requirements not met",
        "severity": "critical",
        "action": "block",
        "remediation": "Enable encryption at rest and in transit"
    }
}

violations[violation] {
    not compliance_requirements_met
    violation := {
        "type": "compliance_violation",
        "message": "Compliance framework requirements not satisfied",
        "severity": "high",
        "action": "block",
        "remediation": "Review and implement required compliance controls"
    }
}

violations[violation] {
    input.action == "cross_cloud_access"
    input.destination.provider not in approved_cloud_providers
    violation := {
        "type": "unauthorized_destination",
        "message": sprintf("Access to provider %s not authorized", [input.destination.provider]),
        "severity": "medium",
        "action": "block",
        "remediation": "Use approved cloud providers only"
    }
}

# Helper functions for additional validations
incident_response_plan_exists {
    data.security.incident_response.plan_exists == true
    data.security.incident_response.contact_list_current == true
    data.security.incident_response.procedures_tested == true
}

strong_cryptography_implemented {
    input.security.encryption_algorithm in approved_encryption_algorithms
    input.security.key_length >= 256
    input.security.certificate_authority_trusted == true
}

vulnerability_management_active {
    input.security.vulnerability_scanning_enabled == true
    input.security.patch_management_enabled == true
    input.security.security_updates_current == true
}

data_protection_measures_implemented {
    input.data.anonymization_available == true
    input.data.pseudonymization_available == true
    input.data.deletion_capabilities == true
}

consent_management_active {
    input.data.consent_tracking_enabled == true
    input.data.consent_withdrawal_available == true
    input.data.consent_granular == true
}

data_portability_supported {
    input.data.export_capabilities == true
    input.data.standard_formats_supported == true
    input.data.automated_export_available == true
}

transfer_authorized {
    input.transfer.authorization_granted == true
    input.transfer.purpose_documented == true
    input.transfer.retention_period_specified == true
}

compliance_data_handling_met {
    data_residency_requirements_met
    cross_border_transfer_authorized
    data_processing_agreements_in_place
}

data_residency_requirements_met {
    input.data.classification == "public"
} else {
    input.destination.country in approved_countries
    input.destination.adequacy_decision == true
}

approved_countries := {
    "US", "CA", "GB", "DE", "FR", "NL", "SE", "NO", "DK", "FI", 
    "CH", "AU", "NZ", "JP", "SG", "KR"
}

cross_border_transfer_authorized {
    input.source.country == input.destination.country
} else {
    input.transfer.legal_basis in ["adequacy_decision", "standard_contractual_clauses", "binding_corporate_rules"]
    input.transfer.data_protection_assessment_completed == true
}

data_processing_agreements_in_place {
    input.transfer.dpa_signed == true
    input.transfer.processor_certified == true
    input.transfer.subprocessor_agreements_current == true
}
