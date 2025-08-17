# Developer Experience Platform
# One-click preview environments, platform contracts, golden paths

terraform {
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 5.34"
    }
  }
}

# Developer Experience Namespace
resource "kubernetes_namespace" "developer_experience" {
  metadata {
    name = "developer-experience"
    labels = {
      "app.kubernetes.io/name" = "developer-experience"
      "environment"            = var.environment
    }
  }
}

# Preview Environment Controller
resource "helm_release" "preview_environments" {
  name       = "preview-environments"
  chart      = "${path.module}/charts/preview-environments"
  namespace  = kubernetes_namespace.developer_experience.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/preview-env-values.yaml", {
      environment = var.environment
      openstack_endpoint = var.openstack_endpoint
      aws_region = var.aws_region
      gcp_project = var.gcp_project_id
      domain_suffix = var.preview_domain_suffix
      max_preview_envs = var.max_preview_environments
      preview_ttl_hours = var.preview_ttl_hours
      burst_to_cloud_threshold = 0.8
    })
  ]
}

# GitHub App for PR Integration
resource "github_app" "preview_environments" {
  count = var.create_github_app ? 1 : 0
  
  name         = "Federation Preview Environments ${title(var.environment)}"
  description  = "Automated preview environment management for federation platform"
  homepage_url = "https://federation.${var.domain_name}"
  
  webhook_url    = "https://preview-controller.${var.domain_name}/webhook"
  webhook_secret = var.github_webhook_secret
  
  events = [
    "pull_request",
    "pull_request_review",
    "issue_comment",
    "push"
  ]
  
  permissions = {
    contents       = "read"
    pull_requests  = "write"
    issues         = "write"
    statuses       = "write"
    deployments    = "write"
    checks         = "write"
    metadata       = "read"
  }
}

# Preview Environment Template Repository
resource "github_repository" "preview_templates" {
  name        = "federation-preview-templates"
  description = "Template repository for federation preview environments"
  visibility  = "private"
  
  template {
    owner                = var.github_organization
    repository           = "preview-template-base"
    include_all_branches = false
  }
  
  pages {
    source {
      branch = "main"
      path   = "/docs"
    }
  }
  
  topics = [
    "federation",
    "preview-environments", 
    "infrastructure",
    "templates"
  ]
}

# Preview Environment Workflows
resource "github_repository_file" "preview_create_workflow" {
  repository          = github_repository.preview_templates.name
  branch              = "main"
  file                = ".github/workflows/preview-create.yml"
  commit_message      = "Add preview environment creation workflow"
  commit_author       = "terraform-automation"
  commit_email        = var.automation_email
  overwrite_on_create = true
  
  content = templatefile("${path.module}/templates/preview-create-workflow.yml", {
    environment = var.environment
    openstack_project_template = var.openstack_project_template
    aws_account_id = var.aws_account_id
    gcp_project_template = var.gcp_project_template
  })
}

resource "github_repository_file" "preview_destroy_workflow" {
  repository          = github_repository.preview_templates.name
  branch              = "main"
  file                = ".github/workflows/preview-destroy.yml"
  commit_message      = "Add preview environment cleanup workflow"
  commit_author       = "terraform-automation"
  commit_email        = var.automation_email
  overwrite_on_create = true
  
  content = templatefile("${path.module}/templates/preview-destroy-workflow.yml", {
    environment = var.environment
    cleanup_retention_days = var.preview_cleanup_retention_days
  })
}

# Golden Path Templates
resource "kubernetes_config_map" "golden_path_templates" {
  metadata {
    name      = "golden-path-templates"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    "microservice-template.yaml" = templatefile("${path.module}/golden-paths/microservice.yaml", {
      environment = var.environment
    })
    
    "api-gateway-template.yaml" = templatefile("${path.module}/golden-paths/api-gateway.yaml", {
      environment = var.environment
    })
    
    "data-pipeline-template.yaml" = templatefile("${path.module}/golden-paths/data-pipeline.yaml", {
      environment = var.environment
    })
    
    "ml-workload-template.yaml" = templatefile("${path.module}/golden-paths/ml-workload.yaml", {
      environment = var.environment
    })
    
    "batch-job-template.yaml" = templatefile("${path.module}/golden-paths/batch-job.yaml", {
      environment = var.environment
    })
  }
}

# Platform Contracts and Standards
resource "kubernetes_config_map" "platform_contracts" {
  metadata {
    name      = "platform-contracts"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    "service-contract.yaml" = templatefile("${path.module}/contracts/service-contract.yaml", {
      environment = var.environment
      slo_availability_target = 99.9
      slo_latency_p95_ms = 100
      slo_error_rate_percent = 0.1
    })
    
    "deployment-contract.yaml" = templatefile("${path.module}/contracts/deployment-contract.yaml", {
      environment = var.environment
      required_labels = var.required_service_labels
      required_annotations = var.required_service_annotations
    })
    
    "security-contract.yaml" = templatefile("${path.module}/contracts/security-contract.yaml", {
      environment = var.environment
      security_scan_required = true
      vulnerability_threshold = "HIGH"
      compliance_frameworks = ["SOC2", "ISO27001"]
    })
    
    "observability-contract.yaml" = templatefile("${path.module}/contracts/observability-contract.yaml", {
      environment = var.environment
      metrics_required = true
      tracing_required = true
      logging_structured = true
    })
  }
}

# Developer Portal (Backstage)
resource "helm_release" "backstage" {
  name       = "backstage"
  repository = "https://backstage.github.io/charts"
  chart      = "backstage"
  namespace  = kubernetes_namespace.developer_experience.metadata[0].name
  version    = "1.8.0"
  
  values = [
    templatefile("${path.module}/templates/backstage-values.yaml", {
      environment = var.environment
      github_token = var.github_token
      gitlab_token = var.gitlab_token
      openstack_endpoint = var.openstack_endpoint
      domain_name = var.domain_name
      auth_provider = var.auth_provider
      catalog_locations = var.backstage_catalog_locations
    })
  ]
  
  set_sensitive {
    name  = "backstage.app.auth.github.clientSecret"
    value = var.github_oauth_client_secret
  }
  
  set_sensitive {
    name  = "backstage.app.integrations.github.token"
    value = var.github_token
  }
}

# Service Catalog for Self-Service
resource "kubernetes_config_map" "service_catalog" {
  metadata {
    name      = "service-catalog"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    "catalog-info.yaml" = templatefile("${path.module}/catalog/catalog-info.yaml", {
      environment = var.environment
      organization = var.github_organization
      domain_name = var.domain_name
    })
    
    "systems.yaml" = templatefile("${path.module}/catalog/systems.yaml", {
      environment = var.environment
      systems = var.platform_systems
    })
    
    "components.yaml" = templatefile("${path.module}/catalog/components.yaml", {
      environment = var.environment
      components = var.platform_components
    })
    
    "apis.yaml" = templatefile("${path.module}/catalog/apis.yaml", {
      environment = var.environment
      apis = var.platform_apis
    })
    
    "resources.yaml" = templatefile("${path.module}/catalog/resources.yaml", {
      environment = var.environment
      resources = var.platform_resources
    })
  }
}

# Developer Scorecards
resource "kubernetes_config_map" "developer_scorecards" {
  metadata {
    name      = "developer-scorecards"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    "scorecard-config.yaml" = templatefile("${path.module}/scorecards/scorecard-config.yaml", {
      environment = var.environment
      scorecard_categories = {
        code_quality = {
          weight = 25
          checks = [
            "has_unit_tests",
            "has_integration_tests", 
            "code_coverage_above_80",
            "sonarqube_quality_gate_passed"
          ]
        }
        security = {
          weight = 30
          checks = [
            "security_scan_passed",
            "no_critical_vulnerabilities",
            "secrets_not_hardcoded",
            "container_image_signed"
          ]
        }
        observability = {
          weight = 20
          checks = [
            "has_metrics",
            "has_structured_logging",
            "has_distributed_tracing",
            "has_health_checks"
          ]
        }
        reliability = {
          weight = 15
          checks = [
            "has_slo_definition",
            "has_error_budget",
            "has_runbook",
            "has_disaster_recovery_plan"
          ]
        }
        documentation = {
          weight = 10
          checks = [
            "has_readme",
            "has_api_documentation",
            "has_architecture_decision_records",
            "has_deployment_documentation"
          ]
        }
      }
    })
  }
}

# Automated Scorecard Evaluation
resource "kubernetes_manifest" "scorecard_evaluator" {
  manifest = {
    apiVersion = "batch/v1"
    kind       = "CronJob"
    metadata = {
      name      = "scorecard-evaluator"
      namespace = kubernetes_namespace.developer_experience.metadata[0].name
    }
    spec = {
      schedule = "0 6 * * 1"  # Every Monday at 6 AM
      jobTemplate = {
        spec = {
          template = {
            spec = {
              containers = [
                {
                  name  = "scorecard-evaluator"
                  image = "federation/scorecard-evaluator:${var.scorecard_evaluator_image_tag}"
                  env = [
                    {
                      name = "GITHUB_TOKEN"
                      valueFrom = {
                        secretKeyRef = {
                          name = "github-credentials"
                          key  = "token"
                        }
                      }
                    },
                    {
                      name = "SONARQUBE_URL"
                      value = var.sonarqube_url
                    },
                    {
                      name = "BACKSTAGE_API_URL"
                      value = "http://backstage:7007/api"
                    }
                  ]
                  command = ["/bin/sh", "-c", "python3 /app/evaluate-scorecards.py"]
                }
              ]
              restartPolicy = "OnFailure"
            }
          }
        }
      }
    }
  }
}

# Peak Hour Migration Controller
resource "kubernetes_deployment" "peak_hour_controller" {
  metadata {
    name      = "peak-hour-controller"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
    labels = {
      app = "peak-hour-controller"
    }
  }
  
  spec {
    replicas = 1
    
    selector {
      match_labels = {
        app = "peak-hour-controller"
      }
    }
    
    template {
      metadata {
        labels = {
          app = "peak-hour-controller"
        }
      }
      
      spec {
        container {
          name  = "controller"
          image = "federation/peak-hour-controller:${var.peak_hour_controller_image_tag}"
          
          env {
            name  = "OPENSTACK_ENDPOINT"
            value = var.openstack_endpoint
          }
          
          env {
            name  = "AWS_REGION"
            value = var.aws_region
          }
          
          env {
            name  = "GCP_PROJECT"
            value = var.gcp_project_id
          }
          
          env {
            name  = "PEAK_HOURS_START"
            value = var.peak_hours_start
          }
          
          env {
            name  = "PEAK_HOURS_END"
            value = var.peak_hours_end
          }
          
          env {
            name  = "MIGRATION_THRESHOLD"
            value = "85"  # 85% capacity
          }
          
          env {
            name  = "AUTO_MIGRATE_ENABLED"
            value = "true"
          }
          
          port {
            container_port = 8080
            name          = "http"
          }
          
          resources {
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
          }
          
          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }
          
          readiness_probe {
            http_get {
              path = "/readyz"
              port = "http"
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }
        }
        
        service_account_name = kubernetes_service_account.peak_hour_controller.metadata[0].name
      }
    }
  }
}

# Service Account for Peak Hour Controller
resource "kubernetes_service_account" "peak_hour_controller" {
  metadata {
    name      = "peak-hour-controller"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
}

resource "kubernetes_cluster_role" "peak_hour_controller" {
  metadata {
    name = "peak-hour-controller"
  }
  
  rule {
    api_groups = [""]
    resources  = ["pods", "services", "namespaces"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
  
  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "replicasets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
  
  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["ingresses"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
}

resource "kubernetes_cluster_role_binding" "peak_hour_controller" {
  metadata {
    name = "peak-hour-controller"
  }
  
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.peak_hour_controller.metadata[0].name
  }
  
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.peak_hour_controller.metadata[0].name
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
}

# Developer CLI Tools
resource "kubernetes_config_map" "cli_tools_config" {
  metadata {
    name      = "cli-tools-config"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    "fed-cli-config.yaml" = templatefile("${path.module}/cli/fed-cli-config.yaml", {
      environment = var.environment
      openstack_endpoint = var.openstack_endpoint
      aws_region = var.aws_region
      gcp_project = var.gcp_project_id
      default_preview_ttl = var.preview_ttl_hours
    })
    
    "aliases.sh" = templatefile("${path.module}/cli/aliases.sh", {
      environment = var.environment
    })
    
    "completions.sh" = file("${path.module}/cli/completions.sh")
  }
}

# Documentation Generator
resource "kubernetes_manifest" "docs_generator" {
  manifest = {
    apiVersion = "batch/v1"
    kind       = "CronJob"
    metadata = {
      name      = "docs-generator"
      namespace = kubernetes_namespace.developer_experience.metadata[0].name
    }
    spec = {
      schedule = "0 2 * * *"  # Daily at 2 AM
      jobTemplate = {
        spec = {
          template = {
            spec = {
              containers = [
                {
                  name  = "docs-generator"
                  image = "federation/docs-generator:${var.docs_generator_image_tag}"
                  env = [
                    {
                      name = "GITHUB_TOKEN"
                      valueFrom = {
                        secretKeyRef = {
                          name = "github-credentials"
                          key  = "token"
                        }
                      }
                    },
                    {
                      name = "DOCS_REPO_URL"
                      value = var.docs_repository_url
                    },
                    {
                      name = "API_ENDPOINTS"
                      value = jsonencode(var.api_endpoints_for_docs)
                    }
                  ]
                  command = ["/bin/sh", "-c", "python3 /app/generate-docs.py"]
                }
              ]
              restartPolicy = "OnFailure"
            }
          }
        }
      }
    }
  }
}

# Team Dashboards
resource "grafana_dashboard" "team_productivity" {
  config_json = templatefile("${path.module}/dashboards/team-productivity.json", {
    environment = var.environment
    github_organization = var.github_organization
  })
  
  folder = grafana_folder.developer_experience.id
}

resource "grafana_dashboard" "preview_environments" {
  config_json = templatefile("${path.module}/dashboards/preview-environments.json", {
    environment = var.environment
    max_preview_envs = var.max_preview_environments
  })
  
  folder = grafana_folder.developer_experience.id
}

resource "grafana_folder" "developer_experience" {
  title = "Developer Experience ${title(var.environment)}"
}

# Slack Integration for Developer Notifications
resource "kubernetes_secret" "slack_credentials" {
  metadata {
    name      = "slack-credentials"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    webhook_url = base64encode(var.slack_webhook_url)
    bot_token   = base64encode(var.slack_bot_token)
  }
}

# GitHub Credentials Secret
resource "kubernetes_secret" "github_credentials" {
  metadata {
    name      = "github-credentials"
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
  }
  
  data = {
    token = base64encode(var.github_token)
    app_id = base64encode(var.github_app_id)
    private_key = base64encode(var.github_app_private_key)
  }
}

# Outputs
output "developer_experience_config" {
  description = "Developer experience platform configuration"
  value = {
    namespace = kubernetes_namespace.developer_experience.metadata[0].name
    preview_environments = {
      controller_installed = true
      max_environments = var.max_preview_environments
      ttl_hours = var.preview_ttl_hours
      domain_suffix = var.preview_domain_suffix
    }
    backstage = {
      installed = true
      url = "https://backstage.${var.domain_name}"
    }
    golden_paths = {
      microservice = "microservice-template.yaml"
      api_gateway = "api-gateway-template.yaml"
      data_pipeline = "data-pipeline-template.yaml"
      ml_workload = "ml-workload-template.yaml"
      batch_job = "batch-job-template.yaml"
    }
    platform_contracts = {
      service_contract = "service-contract.yaml"
      deployment_contract = "deployment-contract.yaml"
      security_contract = "security-contract.yaml"
      observability_contract = "observability-contract.yaml"
    }
  }
}

output "github_integration" {
  description = "GitHub integration configuration"
  value = {
    app_created = var.create_github_app ? true : false
    app_id = var.create_github_app ? github_app.preview_environments[0].id : null
    template_repo = github_repository.preview_templates.name
    workflows_configured = true
  }
}

output "peak_hour_migration" {
  description = "Peak hour migration configuration"
  value = {
    controller_deployed = true
    peak_hours_start = var.peak_hours_start
    peak_hours_end = var.peak_hours_end
    migration_threshold = "85%"
    auto_migrate_enabled = true
  }
}
