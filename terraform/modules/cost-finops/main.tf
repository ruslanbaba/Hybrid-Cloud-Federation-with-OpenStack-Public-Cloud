# Advanced Cost Management & FinOps Platform
# Chargeback, Right-sizing, Carbon-aware placement

terraform {
  required_providers {
    cloudcustodian = {
      source  = "cloud-custodian/custodian"
      version = "~> 0.6"
    }
  }
}

# Cost Allocation and Tagging Strategy
locals {
  cost_allocation_tags = {
    CostCenter    = var.cost_center
    Department    = var.department
    Project       = var.project_name
    Environment   = var.environment
    Owner         = var.owner
    Application   = "federation"
    Service       = "hybrid-cloud"
    BillingCode   = var.billing_code
    CarbonTracked = "true"
  }
}

# OpenStack Project Cost Tracking
resource "openstack_identity_project_v3" "cost_tracked_projects" {
  for_each = var.cost_tracked_projects
  
  name        = each.key
  description = each.value.description
  domain_id   = data.openstack_identity_domain_v3.default.id
  
  tags = [
    "cost_center:${each.value.cost_center}",
    "department:${each.value.department}",
    "budget_limit:${each.value.budget_limit}",
    "billing_model:${each.value.billing_model}",
    "cost_tracking:enabled"
  ]
}

# Cost Allocation Quota Management
resource "openstack_compute_quotaset_v2" "project_quotas" {
  for_each = var.cost_tracked_projects
  
  project_id                = openstack_identity_project_v3.cost_tracked_projects[each.key].id
  cores                     = each.value.quota_cores
  instances                 = each.value.quota_instances
  ram                       = each.value.quota_ram_mb
  volumes                   = each.value.quota_volumes
  snapshots                 = each.value.quota_snapshots
  gigabytes                 = each.value.quota_volume_gb
  floating_ips              = each.value.quota_floating_ips
  security_groups           = each.value.quota_security_groups
  security_group_rules      = each.value.quota_security_group_rules
  networks                  = each.value.quota_networks
  subnets                   = each.value.quota_subnets
  routers                   = each.value.quota_routers
  ports                     = each.value.quota_ports
}

# AWS Cost Budgets with Alerts
resource "aws_budgets_budget" "federation_monthly" {
  for_each = var.aws_cost_budgets
  
  name         = "federation-${each.key}-${var.environment}"
  budget_type  = "COST"
  limit_amount = each.value.limit_amount
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  
  time_period_start = formatdate("YYYY-MM-01_00:00", timestamp())
  
  cost_filters {
    tag {
      key = "Environment"
      values = [var.environment]
    }
    
    tag {
      key = "Project"
      values = [var.project_name]
    }
    
    tag {
      key = "CostCenter"
      values = [each.value.cost_center]
    }
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_email_addresses = each.value.notification_emails
    subscriber_sns_topic_arns   = [aws_sns_topic.cost_alerts.arn]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = each.value.notification_emails
    subscriber_sns_topic_arns   = [aws_sns_topic.cost_alerts.arn]
  }
  
  tags = local.cost_allocation_tags
}

# GCP Billing Budgets
resource "google_billing_budget" "federation" {
  for_each = var.gcp_billing_budgets
  
  billing_account = var.gcp_billing_account
  display_name    = "Federation ${each.key} Budget - ${title(var.environment)}"
  
  budget_filter {
    projects = ["projects/${var.gcp_project_id}"]
    
    labels = {
      environment = var.environment
      project     = var.project_name
      cost_center = each.value.cost_center
    }
  }
  
  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(each.value.limit_amount)
    }
  }
  
  threshold_rules {
    threshold_percent = 0.8
    spend_basis       = "CURRENT_SPEND"
  }
  
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "FORECASTED_SPEND"
  }
  
  all_updates_rule {
    monitoring_notification_channels = [
      google_monitoring_notification_channel.cost_alerts.name
    ]
    
    pubsub_topic                     = google_pubsub_topic.cost_alerts.id
    disable_default_iam_recipients   = false
  }
}

# Cloud Custodian for Cost Optimization
resource "kubernetes_namespace" "cloud_custodian" {
  metadata {
    name = "cloud-custodian"
    labels = {
      "app.kubernetes.io/name" = "cloud-custodian"
      "environment"            = var.environment
    }
  }
}

resource "kubernetes_config_map" "custodian_policies" {
  metadata {
    name      = "custodian-policies"
    namespace = kubernetes_namespace.cloud_custodian.metadata[0].name
  }
  
  data = {
    "aws-policies.yml" = templatefile("${path.module}/policies/aws-custodian.yml", {
      environment = var.environment
      cost_center = var.cost_center
      max_instance_age_days = 30
      idle_threshold_days = 7
      snapshot_retention_days = 90
    })
    
    "gcp-policies.yml" = templatefile("${path.module}/policies/gcp-custodian.yml", {
      environment = var.environment
      project_id  = var.gcp_project_id
    })
    
    "azure-policies.yml" = templatefile("${path.module}/policies/azure-custodian.yml", {
      environment = var.environment
      subscription_id = var.azure_subscription_id
    })
  }
}

resource "helm_release" "cloud_custodian" {
  name       = "cloud-custodian"
  chart      = "${path.module}/charts/cloud-custodian"
  namespace  = kubernetes_namespace.cloud_custodian.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/custodian-values.yaml", {
      environment = var.environment
      aws_region  = var.aws_region
      gcp_project = var.gcp_project_id
      azure_subscription = var.azure_subscription_id
      schedule = "0 */6 * * *"  # Every 6 hours
    })
  ]
}

# OpenStack Usage Collection
resource "openstack_compute_instance_v2" "usage_collector" {
  name              = "usage-collector-${var.environment}"
  image_id          = data.openstack_images_image_v2.ubuntu.id
  flavor_id         = data.openstack_compute_flavor_v2.small.id
  key_pair          = openstack_compute_keypair_v2.usage_collector.name
  security_groups   = [openstack_networking_secgroup_v2.usage_collector.name]
  
  network {
    name = var.management_network_name
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/usage-collector-init.sh", {
    environment        = var.environment
    prometheus_endpoint = var.prometheus_endpoint
    influxdb_endpoint  = var.influxdb_endpoint
    collection_interval = 300  # 5 minutes
  }))
  
  metadata = {
    cost_tracking = "enabled"
    service_type  = "monitoring"
    billing_model = "utility"
  }
  
  tags = [
    "service:usage_collection",
    "cost_tracking:enabled"
  ]
}

# Right-sizing Recommendations Engine
resource "aws_lambda_function" "rightsizing_analyzer" {
  filename         = "rightsizing_analyzer.zip"
  function_name    = "federation-rightsizing-analyzer-${var.environment}"
  role            = aws_iam_role.lambda_rightsizing.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.rightsizing_analyzer.output_base64sha256
  runtime         = "python3.11"
  timeout         = 900  # 15 minutes
  memory_size     = 2048
  
  environment {
    variables = {
      PROMETHEUS_URL     = var.prometheus_endpoint
      OPENSTACK_ENDPOINT = var.openstack_endpoint
      AWS_REGION         = var.aws_region
      GCP_PROJECT        = var.gcp_project_id
      UTILIZATION_THRESHOLD = "20"  # 20% utilization threshold
      ANALYSIS_PERIOD_DAYS  = "14"  # 2 weeks analysis
      COST_SAVINGS_THRESHOLD = "50" # Minimum $50 monthly savings
    }
  }
  
  tags = local.cost_allocation_tags
}

# EventBridge for Right-sizing Schedule
resource "aws_cloudwatch_event_rule" "rightsizing_schedule" {
  name                = "federation-rightsizing-${var.environment}"
  description         = "Weekly right-sizing analysis"
  schedule_expression = "cron(0 6 ? * SUN *)"  # Every Sunday at 6 AM
  
  tags = local.cost_allocation_tags
}

resource "aws_cloudwatch_event_target" "rightsizing_target" {
  rule      = aws_cloudwatch_event_rule.rightsizing_schedule.name
  target_id = "RightsizingAnalysisTarget"
  arn       = aws_lambda_function.rightsizing_analyzer.arn
}

# GitHub Actions for Automated Right-sizing PRs
resource "github_repository_file" "rightsizing_workflow" {
  repository          = var.gitops_repo_name
  branch              = "main"
  file                = ".github/workflows/rightsizing-automation.yml"
  commit_message      = "Add automated right-sizing workflow"
  commit_author       = "terraform-automation"
  commit_email        = var.automation_email
  overwrite_on_create = true
  
  content = templatefile("${path.module}/templates/rightsizing-workflow.yml", {
    environment = var.environment
  })
}

# Carbon-Aware Placement Engine
resource "kubernetes_namespace" "carbon_optimizer" {
  metadata {
    name = "carbon-optimizer"
    labels = {
      "app.kubernetes.io/name" = "carbon-optimizer"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "carbon_optimizer" {
  name       = "carbon-optimizer"
  chart      = "${path.module}/charts/carbon-optimizer"
  namespace  = kubernetes_namespace.carbon_optimizer.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/carbon-optimizer-values.yaml", {
      environment = var.environment
      carbon_api_url = var.carbon_intensity_api_url
      update_interval = 300  # 5 minutes
      placement_weight = 0.3  # 30% weight for carbon in placement decisions
    })
  ]
}

# Carbon Intensity Tracking
resource "aws_lambda_function" "carbon_tracker" {
  filename         = "carbon_tracker.zip"
  function_name    = "federation-carbon-tracker-${var.environment}"
  role            = aws_iam_role.lambda_carbon_tracker.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.carbon_tracker.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512
  
  environment {
    variables = {
      CARBON_API_URL     = var.carbon_intensity_api_url
      PROMETHEUS_URL     = var.prometheus_endpoint
      REGIONS            = jsonencode(var.carbon_tracked_regions)
      CARBON_BUDGET_KG   = var.monthly_carbon_budget_kg
    }
  }
  
  tags = local.cost_allocation_tags
}

# Carbon Tracking Schedule
resource "aws_cloudwatch_event_rule" "carbon_tracking" {
  name                = "federation-carbon-tracking-${var.environment}"
  description         = "Track carbon intensity every 15 minutes"
  schedule_expression = "rate(15 minutes)"
  
  tags = local.cost_allocation_tags
}

resource "aws_cloudwatch_event_target" "carbon_tracking_target" {
  rule      = aws_cloudwatch_event_rule.carbon_tracking.name
  target_id = "CarbonTrackingTarget"
  arn       = aws_lambda_function.carbon_tracker.arn
}

# Carbon Budget Alerts
resource "aws_cloudwatch_metric_alarm" "carbon_budget_warning" {
  alarm_name          = "federation-carbon-budget-warning-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CarbonBudgetUtilization"
  namespace           = "Federation/Carbon"
  period              = "3600"  # 1 hour
  statistic           = "Average"
  threshold           = "80"    # 80% of budget
  alarm_description   = "Carbon budget utilization warning"
  alarm_actions       = [aws_sns_topic.carbon_alerts.arn]
  
  dimensions = {
    Environment = var.environment
  }
  
  tags = local.cost_allocation_tags
}

# Cost Optimization Recommendations Database
resource "aws_dynamodb_table" "cost_recommendations" {
  name           = "federation-cost-recommendations-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "recommendation_id"
  range_key      = "timestamp"
  
  attribute {
    name = "recommendation_id"
    type = "S"
  }
  
  attribute {
    name = "timestamp"
    type = "S"
  }
  
  attribute {
    name = "resource_id"
    type = "S"
  }
  
  attribute {
    name = "potential_savings"
    type = "N"
  }
  
  global_secondary_index {
    name            = "ResourceIndex"
    hash_key        = "resource_id"
    range_key       = "timestamp"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "SavingsIndex"
    hash_key        = "potential_savings"
    range_key       = "timestamp"
    projection_type = "ALL"
  }
  
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  tags = local.cost_allocation_tags
}

# Chargeback Report Generator
resource "aws_lambda_function" "chargeback_reporter" {
  filename         = "chargeback_reporter.zip"
  function_name    = "federation-chargeback-reporter-${var.environment}"
  role            = aws_iam_role.lambda_chargeback.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.chargeback_reporter.output_base64sha256
  runtime         = "python3.11"
  timeout         = 900  # 15 minutes
  memory_size     = 1024
  
  environment {
    variables = {
      OPENSTACK_ENDPOINT    = var.openstack_endpoint
      AWS_COST_EXPLORER_API = "true"
      GCP_BILLING_API       = "true"
      AZURE_CONSUMPTION_API = "true"
      S3_REPORTS_BUCKET     = aws_s3_bucket.cost_reports.bucket
      REPORT_FREQUENCY      = "monthly"
      INCLUDE_PROJECTIONS   = "true"
    }
  }
  
  tags = local.cost_allocation_tags
}

# Monthly Chargeback Report Schedule
resource "aws_cloudwatch_event_rule" "chargeback_monthly" {
  name                = "federation-chargeback-monthly-${var.environment}"
  description         = "Generate monthly chargeback reports"
  schedule_expression = "cron(0 8 1 * ? *)"  # First day of month at 8 AM
  
  tags = local.cost_allocation_tags
}

resource "aws_cloudwatch_event_target" "chargeback_monthly_target" {
  rule      = aws_cloudwatch_event_rule.chargeback_monthly.name
  target_id = "ChargebackMonthlyTarget"
  arn       = aws_lambda_function.chargeback_reporter.arn
}

# Cost Reports S3 Bucket
resource "aws_s3_bucket" "cost_reports" {
  bucket = "federation-cost-reports-${var.environment}-${random_id.bucket_suffix.hex}"
  
  tags = local.cost_allocation_tags
}

resource "aws_s3_bucket_public_access_block" "cost_reports" {
  bucket = aws_s3_bucket.cost_reports.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cost_reports" {
  bucket = aws_s3_bucket.cost_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cost_reports" {
  bucket = aws_s3_bucket.cost_reports.id
  
  rule {
    id     = "cost_reports_lifecycle"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 2555  # 7 years retention
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Cost Dashboard for Grafana
resource "grafana_dashboard" "cost_management" {
  config_json = templatefile("${path.module}/dashboards/cost-management.json", {
    environment = var.environment
    aws_region  = var.aws_region
    gcp_project = var.gcp_project_id
  })
  
  folder = grafana_folder.finops.id
}

resource "grafana_dashboard" "carbon_tracking" {
  config_json = templatefile("${path.module}/dashboards/carbon-tracking.json", {
    environment = var.environment
    carbon_budget = var.monthly_carbon_budget_kg
  })
  
  folder = grafana_folder.finops.id
}

resource "grafana_folder" "finops" {
  title = "FinOps ${title(var.environment)}"
}

# SNS Topics for Alerts
resource "aws_sns_topic" "cost_alerts" {
  name = "federation-cost-alerts-${var.environment}"
  
  tags = local.cost_allocation_tags
}

resource "aws_sns_topic" "carbon_alerts" {
  name = "federation-carbon-alerts-${var.environment}"
  
  tags = local.cost_allocation_tags
}

# GCP Monitoring for Cost Alerts
resource "google_monitoring_notification_channel" "cost_alerts" {
  display_name = "Federation Cost Alerts ${title(var.environment)}"
  type         = "email"
  
  labels = {
    email_address = var.cost_alert_email
  }
}

resource "google_pubsub_topic" "cost_alerts" {
  name = "federation-cost-alerts-${var.environment}"
  
  labels = {
    environment = var.environment
    service     = "cost-management"
  }
}

# Random ID for unique resource names
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Data sources
data "openstack_images_image_v2" "ubuntu" {
  name        = "Ubuntu 20.04 LTS"
  most_recent = true
}

data "openstack_compute_flavor_v2" "small" {
  name = "m1.small"
}

data "openstack_identity_domain_v3" "default" {
  name = "Default"
}

data "archive_file" "rightsizing_analyzer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/rightsizing_analyzer"
  output_path = "rightsizing_analyzer.zip"
}

data "archive_file" "carbon_tracker" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/carbon_tracker"
  output_path = "carbon_tracker.zip"
}

data "archive_file" "chargeback_reporter" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/chargeback_reporter"
  output_path = "chargeback_reporter.zip"
}

# Outputs
output "cost_tracking_config" {
  description = "Cost tracking and allocation configuration"
  value = {
    openstack_projects = {
      for k, v in openstack_identity_project_v3.cost_tracked_projects : k => v.id
    }
    aws_budgets = {
      for k, v in aws_budgets_budget.federation_monthly : k => v.id
    }
    gcp_budgets = {
      for k, v in google_billing_budget.federation : k => v.name
    }
    cost_reports_bucket = aws_s3_bucket.cost_reports.bucket
  }
}

output "finops_automation" {
  description = "FinOps automation configuration"
  value = {
    rightsizing_function = aws_lambda_function.rightsizing_analyzer.function_name
    carbon_tracker_function = aws_lambda_function.carbon_tracker.function_name
    chargeback_function = aws_lambda_function.chargeback_reporter.function_name
    custodian_namespace = kubernetes_namespace.cloud_custodian.metadata[0].name
    carbon_optimizer_namespace = kubernetes_namespace.carbon_optimizer.metadata[0].name
  }
}

output "cost_alerts" {
  description = "Cost alerting configuration"
  value = {
    aws_cost_alerts_topic = aws_sns_topic.cost_alerts.arn
    aws_carbon_alerts_topic = aws_sns_topic.carbon_alerts.arn
    gcp_notification_channel = google_monitoring_notification_channel.cost_alerts.name
    carbon_budget_alarm = aws_cloudwatch_metric_alarm.carbon_budget_warning.arn
  }
}
