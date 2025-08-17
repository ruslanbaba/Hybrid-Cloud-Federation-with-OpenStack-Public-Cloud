# Advanced Observability & AIOps Platform
# OpenTelemetry, SLOs, Error Budgets, Automated Triage

terraform {
  required_providers {
    opentelemetry = {
      source  = "open-telemetry/opentelemetry"
      version = "~> 0.4"
    }
    grafana = {
      source  = "grafana/grafana"
      version = "~> 2.9"
    }
    pagerduty = {
      source  = "pagerduty/pagerduty"
      version = "~> 3.8"
    }
  }
}

# OpenTelemetry Collector Configuration
resource "kubernetes_namespace" "otel_system" {
  metadata {
    name = "opentelemetry-system"
    labels = {
      "app.kubernetes.io/name" = "opentelemetry"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "opentelemetry_operator" {
  name       = "opentelemetry-operator"
  repository = "https://open-telemetry.github.io/opentelemetry-helm-charts"
  chart      = "opentelemetry-operator"
  namespace  = kubernetes_namespace.otel_system.metadata[0].name
  version    = "0.47.0"
  
  values = [
    templatefile("${path.module}/templates/otel-operator-values.yaml", {
      environment = var.environment
    })
  ]
}

# OpenTelemetry Collector for OpenStack Services
resource "kubernetes_manifest" "otel_collector_openstack" {
  manifest = {
    apiVersion = "opentelemetry.io/v1alpha1"
    kind       = "OpenTelemetryCollector"
    metadata = {
      name      = "openstack-collector"
      namespace = kubernetes_namespace.otel_system.metadata[0].name
    }
    spec = {
      mode = "daemonset"
      
      config = templatefile("${path.module}/configs/otel-openstack-config.yaml", {
        prometheus_endpoint = var.prometheus_endpoint
        jaeger_endpoint     = var.jaeger_endpoint
        loki_endpoint       = var.loki_endpoint
        tempo_endpoint      = var.tempo_endpoint
        mimir_endpoint      = var.mimir_endpoint
        environment         = var.environment
        openstack_endpoints = var.openstack_service_endpoints
      })
      
      env = [
        {
          name = "KUBE_NODE_NAME"
          valueFrom = {
            fieldRef = {
              apiVersion = "v1"
              fieldPath  = "spec.nodeName"
            }
          }
        },
        {
          name = "OTEL_RESOURCE_ATTRIBUTES"
          value = "service.name=openstack-federation,service.version=${var.openstack_version},deployment.environment=${var.environment}"
        }
      ]
      
      ports = [
        {
          name = "prometheus"
          port = 8888
          protocol = "TCP"
        },
        {
          name = "jaeger-grpc"
          port = 14250
          protocol = "TCP"
        },
        {
          name = "jaeger-thrift"
          port = 14268
          protocol = "TCP"
        }
      ]
      
      resources = {
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
        requests = {
          cpu    = "100m"
          memory = "128Mi"
        }
      }
      
      volumeMounts = [
        {
          name      = "varlogpods"
          mountPath = "/var/log/pods"
          readOnly  = true
        },
        {
          name      = "varlibdockercontainers"
          mountPath = "/var/lib/docker/containers"
          readOnly  = true
        }
      ]
      
      volumes = [
        {
          name = "varlogpods"
          hostPath = {
            path = "/var/log/pods"
          }
        },
        {
          name = "varlibdockercontainers"
          hostPath = {
            path = "/var/lib/docker/containers"
          }
        }
      ]
    }
  }
  
  depends_on = [helm_release.opentelemetry_operator]
}

# OpenTelemetry Collector for Burst Workloads
resource "kubernetes_manifest" "otel_collector_burst" {
  manifest = {
    apiVersion = "opentelemetry.io/v1alpha1"
    kind       = "OpenTelemetryCollector"
    metadata = {
      name      = "burst-collector"
      namespace = kubernetes_namespace.otel_system.metadata[0].name
    }
    spec = {
      mode = "deployment"
      replicas = 3
      
      config = templatefile("${path.module}/configs/otel-burst-config.yaml", {
        aws_region          = var.aws_region
        gcp_project         = var.gcp_project_id
        azure_subscription  = var.azure_subscription_id
        prometheus_endpoint = var.prometheus_endpoint
        tempo_endpoint      = var.tempo_endpoint
        environment         = var.environment
      })
      
      env = [
        {
          name = "AWS_REGION"
          value = var.aws_region
        },
        {
          name = "GCP_PROJECT_ID"
          value = var.gcp_project_id
        },
        {
          name = "AZURE_SUBSCRIPTION_ID"
          value = var.azure_subscription_id
        }
      ]
      
      resources = {
        limits = {
          cpu    = "2"
          memory = "4Gi"
        }
        requests = {
          cpu    = "200m"
          memory = "256Mi"
        }
      }
    }
  }
  
  depends_on = [helm_release.opentelemetry_operator]
}

# Prometheus for Metrics Collection
resource "helm_release" "prometheus_stack" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = "monitoring"
  create_namespace = true
  version    = "56.8.0"
  
  values = [
    templatefile("${path.module}/templates/prometheus-stack-values.yaml", {
      environment                = var.environment
      retention_size            = var.prometheus_retention_size
      retention_days            = var.prometheus_retention_days
      storage_class             = var.prometheus_storage_class
      grafana_admin_password    = var.grafana_admin_password
      alertmanager_slack_url    = var.alertmanager_slack_url
      pagerduty_service_key     = var.pagerduty_service_key
      openstack_exporter_config = var.openstack_exporter_config
    })
  ]
  
  set_sensitive {
    name  = "grafana.adminPassword"
    value = var.grafana_admin_password
  }
}

# Tempo for Distributed Tracing
resource "helm_release" "tempo" {
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  namespace  = "monitoring"
  version    = "1.7.1"
  
  values = [
    templatefile("${path.module}/templates/tempo-values.yaml", {
      environment    = var.environment
      storage_bucket = aws_s3_bucket.tempo_traces.bucket
      retention_days = var.tempo_retention_days
    })
  ]
}

# Loki for Log Aggregation
resource "helm_release" "loki" {
  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"
  namespace  = "monitoring"
  version    = "5.41.4"
  
  values = [
    templatefile("${path.module}/templates/loki-values.yaml", {
      environment    = var.environment
      storage_bucket = aws_s3_bucket.loki_logs.bucket
      retention_days = var.loki_retention_days
    })
  ]
}

# Mimir for Long-term Metrics Storage
resource "helm_release" "mimir" {
  name       = "mimir"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "mimir-distributed"
  namespace  = "monitoring"
  version    = "5.1.3"
  
  values = [
    templatefile("${path.module}/templates/mimir-values.yaml", {
      environment     = var.environment
      storage_bucket  = aws_s3_bucket.mimir_metrics.bucket
      retention_days  = var.mimir_retention_days
      compactor_replicas = 3
      ingester_replicas  = 6
    })
  ]
}

# SLO and Error Budget Configuration
resource "kubernetes_config_map" "slo_definitions" {
  metadata {
    name      = "slo-definitions"
    namespace = "monitoring"
  }
  
  data = {
    "federation-slos.yaml" = templatefile("${path.module}/configs/slo-definitions.yaml", {
      environment = var.environment
      slos = {
        api_availability = {
          objective = 99.9
          window    = "30d"
          indicator = "up{job=\"federation-api\"}"
        }
        api_latency = {
          objective = 95
          threshold = "100ms"
          window    = "30d"
          indicator = "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"federation-api\"}[5m]))"
        }
        burst_time_to_serve = {
          objective = 99
          threshold = "300s"
          window    = "7d"
          indicator = "histogram_quantile(0.99, rate(burst_deployment_duration_seconds_bucket[5m]))"
        }
        data_pipeline_lag = {
          objective = 95
          threshold = "60s"
          window    = "24h"
          indicator = "kafka_consumer_lag_sum{job=\"data-pipeline\"}"
        }
        cross_cloud_network_latency = {
          objective = 99
          threshold = "50ms"
          window    = "24h"
          indicator = "histogram_quantile(0.99, rate(network_latency_seconds_bucket[5m]))"
        }
      }
    })
  }
}

# Sloth for SLO Management
resource "helm_release" "sloth" {
  name       = "sloth"
  repository = "https://slok.github.io/sloth"
  chart      = "sloth"
  namespace  = "monitoring"
  version    = "0.11.0"
  
  values = [
    templatefile("${path.module}/templates/sloth-values.yaml", {
      environment = var.environment
    })
  ]
}

# Error Budget Alerts
resource "kubernetes_manifest" "error_budget_alerts" {
  manifest = {
    apiVersion = "monitoring.coreos.com/v1"
    kind       = "PrometheusRule"
    metadata = {
      name      = "error-budget-alerts"
      namespace = "monitoring"
      labels = {
        prometheus = "kube-prometheus"
        role       = "alert-rules"
      }
    }
    spec = {
      groups = [
        {
          name = "federation.error-budget"
          rules = [
            {
              alert = "ErrorBudgetCritical"
              expr  = "slo_error_budget_remaining < 0.1"
              for   = "5m"
              labels = {
                severity = "critical"
                team     = "platform"
              }
              annotations = {
                summary     = "Error budget critically low for {{ $labels.service }}"
                description = "Error budget for {{ $labels.service }} is below 10% ({{ $value | humanizePercentage }})"
                runbook_url = "https://runbooks.${var.domain_name}/error-budget-critical"
              }
            },
            {
              alert = "ErrorBudgetWarning"
              expr  = "slo_error_budget_remaining < 0.3"
              for   = "10m"
              labels = {
                severity = "warning"
                team     = "platform"
              }
              annotations = {
                summary     = "Error budget low for {{ $labels.service }}"
                description = "Error budget for {{ $labels.service }} is below 30% ({{ $value | humanizePercentage }})"
                runbook_url = "https://runbooks.${var.domain_name}/error-budget-warning"
              }
            }
          ]
        }
      ]
    }
  }
}

# PagerDuty Integration
resource "pagerduty_service" "federation" {
  name                    = "Federation Platform ${title(var.environment)}"
  description             = "Federation platform monitoring and alerting"
  auto_resolve_timeout    = 14400  # 4 hours
  acknowledgement_timeout = 600    # 10 minutes
  escalation_policy       = pagerduty_escalation_policy.federation.id
  alert_creation          = "create_alerts_and_incidents"
  
  incident_urgency_rule {
    type = "constant"
    urgency = "high"
  }
}

resource "pagerduty_escalation_policy" "federation" {
  name      = "Federation Escalation Policy ${title(var.environment)}"
  num_loops = 2
  
  rule {
    escalation_delay_in_minutes = 10
    
    target {
      type = "schedule_reference"
      id   = pagerduty_schedule.platform_team.id
    }
  }
  
  rule {
    escalation_delay_in_minutes = 15
    
    target {
      type = "schedule_reference"
      id   = pagerduty_schedule.sre_team.id
    }
  }
}

resource "pagerduty_schedule" "platform_team" {
  name      = "Platform Team Schedule ${title(var.environment)}"
  time_zone = var.timezone
  
  layer {
    name                         = "Platform Engineers"
    start                        = "2024-01-01T09:00:00+00:00"
    rotation_virtual_start       = "2024-01-01T09:00:00+00:00"
    rotation_turn_length_seconds = 604800  # 1 week
    
    users = var.platform_team_users
  }
}

resource "pagerduty_schedule" "sre_team" {
  name      = "SRE Team Schedule ${title(var.environment)}"
  time_zone = var.timezone
  
  layer {
    name                         = "Site Reliability Engineers"
    start                        = "2024-01-01T09:00:00+00:00"
    rotation_virtual_start       = "2024-01-01T09:00:00+00:00"
    rotation_turn_length_seconds = 604800  # 1 week
    
    users = var.sre_team_users
  }
}

# AlertManager PagerDuty Integration
resource "kubernetes_secret" "pagerduty_config" {
  metadata {
    name      = "pagerduty-config"
    namespace = "monitoring"
  }
  
  data = {
    "pagerduty.yml" = base64encode(templatefile("${path.module}/configs/pagerduty.yml", {
      service_key = pagerduty_service.federation.id
      routing_key = var.pagerduty_routing_key
    }))
  }
}

# Automated Triage and Remediation
resource "kubernetes_namespace" "automation" {
  metadata {
    name = "automation"
    labels = {
      "app.kubernetes.io/name" = "automation"
      "environment"            = var.environment
    }
  }
}

# Event-Driven Remediation Engine
resource "helm_release" "remediation_engine" {
  name       = "remediation-engine"
  chart      = "${path.module}/charts/remediation-engine"
  namespace  = kubernetes_namespace.automation.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/remediation-engine-values.yaml", {
      environment       = var.environment
      webhook_url       = var.remediation_webhook_url
      slack_token       = var.slack_token
      runbook_base_url  = "https://runbooks.${var.domain_name}"
      vault_addr        = var.vault_addr
    })
  ]
}

# Automated Runbooks as Code
resource "kubernetes_config_map" "runbooks" {
  metadata {
    name      = "automated-runbooks"
    namespace = kubernetes_namespace.automation.metadata[0].name
  }
  
  data = {
    "disk-space-cleanup.py"     = file("${path.module}/runbooks/disk-space-cleanup.py")
    "service-restart.py"        = file("${path.module}/runbooks/service-restart.py")
    "scale-deployment.py"       = file("${path.module}/runbooks/scale-deployment.py")
    "clear-cache.py"           = file("${path.module}/runbooks/clear-cache.py")
    "database-connection-fix.py" = file("${path.module}/runbooks/database-connection-fix.py")
    "network-connectivity-check.py" = file("${path.module}/runbooks/network-connectivity-check.py")
  }
}

# Postmortem Automation
resource "aws_lambda_function" "postmortem_generator" {
  filename         = "postmortem_generator.zip"
  function_name    = "federation-postmortem-generator-${var.environment}"
  role            = aws_iam_role.lambda_postmortem.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.postmortem_generator.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 1024
  
  environment {
    variables = {
      PROMETHEUS_URL    = var.prometheus_endpoint
      GRAFANA_URL       = var.grafana_endpoint
      LOKI_URL          = var.loki_endpoint
      GIT_REPO_URL      = var.gitops_repo_url
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      JIRA_URL          = var.jira_url
      JIRA_TOKEN        = var.jira_token
    }
  }
  
  tags = local.common_tags
}

# EventBridge for Incident Response
resource "aws_cloudwatch_event_rule" "incident_triggered" {
  name        = "federation-incident-triggered-${var.environment}"
  description = "Trigger postmortem automation when incident is resolved"
  
  event_pattern = jsonencode({
    source = ["pagerduty"]
    detail-type = ["Incident Status Changed"]
    detail = {
      status = ["resolved"]
      service = {
        name = [pagerduty_service.federation.name]
      }
    }
  })
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "postmortem_automation" {
  rule      = aws_cloudwatch_event_rule.incident_triggered.name
  target_id = "PostmortemAutomation"
  arn       = aws_lambda_function.postmortem_generator.arn
}

# Grafana Dashboards for Observability
resource "grafana_dashboard" "federation_overview" {
  config_json = templatefile("${path.module}/dashboards/federation-overview.json", {
    environment = var.environment
  })
  
  folder = grafana_folder.federation.id
}

resource "grafana_dashboard" "slo_dashboard" {
  config_json = templatefile("${path.module}/dashboards/slo-dashboard.json", {
    environment = var.environment
  })
  
  folder = grafana_folder.federation.id
}

resource "grafana_dashboard" "burst_analytics" {
  config_json = templatefile("${path.module}/dashboards/burst-analytics.json", {
    environment = var.environment
  })
  
  folder = grafana_folder.federation.id
}

resource "grafana_dashboard" "cost_analytics" {
  config_json = templatefile("${path.module}/dashboards/cost-analytics.json", {
    environment = var.environment
  })
  
  folder = grafana_folder.federation.id
}

resource "grafana_folder" "federation" {
  title = "Federation ${title(var.environment)}"
}

# S3 Buckets for Observability Data
resource "aws_s3_bucket" "tempo_traces" {
  bucket = "federation-tempo-traces-${var.environment}-${random_id.bucket_suffix.hex}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket" "loki_logs" {
  bucket = "federation-loki-logs-${var.environment}-${random_id.bucket_suffix.hex}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket" "mimir_metrics" {
  bucket = "federation-mimir-metrics-${var.environment}-${random_id.bucket_suffix.hex}"
  
  tags = local.common_tags
}

# Bucket Lifecycle Configuration
resource "aws_s3_bucket_lifecycle_configuration" "tempo_lifecycle" {
  bucket = aws_s3_bucket.tempo_traces.id
  
  rule {
    id     = "traces_lifecycle"
    status = "Enabled"
    
    expiration {
      days = var.tempo_retention_days
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "loki_lifecycle" {
  bucket = aws_s3_bucket.loki_logs.id
  
  rule {
    id     = "logs_lifecycle"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = var.loki_retention_days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "mimir_lifecycle" {
  bucket = aws_s3_bucket.mimir_metrics.id
  
  rule {
    id     = "metrics_lifecycle"
    status = "Enabled"
    
    transition {
      days          = 60
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 180
      storage_class = "GLACIER"
    }
    
    expiration {
      days = var.mimir_retention_days
    }
  }
}

# Random ID for unique bucket names
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Data sources
data "archive_file" "postmortem_generator" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/postmortem_generator"
  output_path = "postmortem_generator.zip"
}

# Outputs
output "observability_stack" {
  description = "Observability stack configuration"
  value = {
    prometheus_endpoint = "http://prometheus.monitoring.svc.cluster.local:9090"
    grafana_endpoint    = "http://grafana.monitoring.svc.cluster.local:3000"
    tempo_endpoint      = "http://tempo.monitoring.svc.cluster.local:3100"
    loki_endpoint       = "http://loki.monitoring.svc.cluster.local:3100"
    mimir_endpoint      = "http://mimir.monitoring.svc.cluster.local:8080"
    alertmanager_endpoint = "http://alertmanager.monitoring.svc.cluster.local:9093"
  }
}

output "slo_configuration" {
  description = "SLO and error budget configuration"
  value = {
    slo_config_map     = kubernetes_config_map.slo_definitions.metadata[0].name
    sloth_namespace    = "monitoring"
    error_budget_rules = "error-budget-alerts"
  }
}

output "automation_config" {
  description = "Automation and remediation configuration"
  value = {
    remediation_namespace = kubernetes_namespace.automation.metadata[0].name
    runbooks_config_map   = kubernetes_config_map.runbooks.metadata[0].name
    postmortem_function   = aws_lambda_function.postmortem_generator.function_name
  }
}

output "pagerduty_integration" {
  description = "PagerDuty integration details"
  value = {
    service_id        = pagerduty_service.federation.id
    escalation_policy = pagerduty_escalation_policy.federation.id
    platform_schedule = pagerduty_schedule.platform_team.id
    sre_schedule      = pagerduty_schedule.sre_team.id
  }
}
