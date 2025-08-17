# Enterprise Hybrid Cloud Federation - OPA Policies
# Cost Management and Compliance Enforcement

package hybrid.federation.cost

import future.keywords.in

# Default deny for cost-related actions
default allow_burst = false
default allow_scale_out = false

# Cost thresholds configuration
cost_thresholds := {
    "monthly_budget_usd": 50000,
    "daily_budget_usd": 1667,  # Monthly / 30
    "hourly_budget_usd": 69,   # Daily / 24
    "burst_cost_limit_per_hour": 500,
    "instance_cost_threshold": 2.0
}

# Cloud provider cost multipliers (relative to baseline)
cloud_cost_multipliers := {
    "aws": 1.0,      # Baseline
    "gcp": 0.95,     # 5% cheaper
    "azure": 1.05,   # 5% more expensive
    "openstack": 0.3 # 70% cheaper (private cloud)
}

# Allow burst if within cost limits
allow_burst {
    input.action == "scale_out"
    input.estimated_cost_per_hour <= cost_thresholds.burst_cost_limit_per_hour
    current_monthly_spend + projected_additional_cost <= cost_thresholds.monthly_budget_usd
    security_compliance_check
}

# Calculate projected additional cost
projected_additional_cost := input.instance_count * input.cost_per_hour * hours_remaining_in_month

# Get current monthly spend from monitoring data
current_monthly_spend := data.cost_monitoring.current_month_total

# Calculate hours remaining in current month
hours_remaining_in_month := (days_in_month - day_of_month) * 24 + (24 - hour_of_day)

# Security compliance check
security_compliance_check {
    input.security_validated == true
    input.provider in allowed_providers
    instance_meets_security_requirements
}

# Allowed cloud providers based on compliance
allowed_providers := {"aws", "gcp", "azure"} {
    data.compliance.frameworks["SOC2"] == true
} else := {"aws"} {
    data.compliance.frameworks["PCI_DSS"] == true
} else := {"aws", "gcp"} {
    data.compliance.frameworks["GDPR"] == true
} else := {"aws", "gcp", "azure"}

# Instance security requirements
instance_meets_security_requirements {
    input.instance_spec.encryption_at_rest == true
    input.instance_spec.encryption_in_transit == true
    count(input.instance_spec.security_groups) > 0
    input.instance_spec.patch_management_enabled == true
}

# Cost optimization recommendations
cost_optimization_suggestions[suggestion] {
    input.provider == provider
    provider_cost := cloud_cost_multipliers[provider]
    cheaper_provider := [p | p := provider_options[_]; cloud_cost_multipliers[p] < provider_cost][0]
    suggestion := sprintf("Consider using %s instead of %s for %.0f%% cost savings", [
        cheaper_provider, 
        provider, 
        (provider_cost - cloud_cost_multipliers[cheaper_provider]) / provider_cost * 100
    ])
}

provider_options := ["aws", "gcp", "azure"]

# Violations and alerts
violations[violation] {
    input.estimated_cost_per_hour > cost_thresholds.burst_cost_limit_per_hour
    violation := {
        "type": "cost_limit_exceeded",
        "message": sprintf("Estimated cost $%.2f/hour exceeds limit $%.2f/hour", [
            input.estimated_cost_per_hour,
            cost_thresholds.burst_cost_limit_per_hour
        ]),
        "severity": "high",
        "action": "block"
    }
}

violations[violation] {
    current_monthly_spend > cost_thresholds.monthly_budget_usd * 0.9
    violation := {
        "type": "budget_warning",
        "message": sprintf("Monthly spend $%.2f approaching budget limit $%.2f", [
            current_monthly_spend,
            cost_thresholds.monthly_budget_usd
        ]),
        "severity": "medium",
        "action": "alert"
    }
}

violations[violation] {
    not security_compliance_check
    violation := {
        "type": "security_violation",
        "message": "Security requirements not met for burst instance",
        "severity": "critical",
        "action": "block"
    }
}

# Audit logging requirements
audit_required {
    input.action in ["scale_out", "scale_in", "terminate"]
    input.estimated_cost_per_hour > 1.0
}

audit_metadata := {
    "timestamp": time.now_ns(),
    "user": input.user,
    "action": input.action,
    "provider": input.provider,
    "cost_impact": input.estimated_cost_per_hour,
    "compliance_frameworks": data.compliance.frameworks,
    "policy_version": "1.0.0"
} {
    audit_required
}
