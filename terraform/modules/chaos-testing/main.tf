# Chaos Engineering & Resilience Testing Platform
# Comprehensive fault injection, GameDay automation, synthetic testing

terraform {
  required_providers {
    chaos = {
      source  = "chaostoolkit/chaostoolkit"
      version = "~> 0.3"
    }
    litmus = {
      source  = "litmuschaos/litmus"
      version = "~> 3.8"
    }
  }
}

# Chaos Engineering Namespace
resource "kubernetes_namespace" "chaos_engineering" {
  metadata {
    name = "chaos-engineering"
    labels = {
      "app.kubernetes.io/name" = "chaos-engineering"
      "environment"            = var.environment
      "chaos.alpha.kubernetes.io/experiment" = "true"
    }
  }
}

# LitmusChaos Operator Installation
resource "helm_release" "litmus" {
  name       = "litmus"
  repository = "https://litmuschaos.github.io/litmus-helm"
  chart      = "litmus"
  namespace  = kubernetes_namespace.chaos_engineering.metadata[0].name
  version    = "3.8.0"
  
  values = [
    templatefile("${path.module}/templates/litmus-values.yaml", {
      environment = var.environment
      portal_enabled = true
      auth_enabled = true
      chaos_center_scope = "cluster"
    })
  ]
}

# Chaos Toolkit Operator
resource "helm_release" "chaos_toolkit" {
  name       = "chaos-toolkit"
  chart      = "${path.module}/charts/chaos-toolkit"
  namespace  = kubernetes_namespace.chaos_engineering.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/chaos-toolkit-values.yaml", {
      environment = var.environment
      openstack_endpoint = var.openstack_endpoint
      aws_region = var.aws_region
      gcp_project = var.gcp_project_id
    })
  ]
}

# Burst Path Chaos Experiments
resource "kubernetes_manifest" "burst_path_chaos_experiments" {
  for_each = var.burst_chaos_experiments
  
  manifest = {
    apiVersion = "litmuschaos.io/v1alpha1"
    kind       = "ChaosExperiment"
    metadata = {
      name      = "burst-${each.key}-experiment"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
      labels = {
        name    = "burst-${each.key}-experiment"
        app.kubernetes.io/part-of = "litmus"
        app.kubernetes.io/component = "chaosexperiment"
        chaos-type = "burst-path"
      }
    }
    spec = {
      definition = {
        scope = "Namespaced"
        permissions = [
          {
            apiGroups = [""]
            resources = ["pods", "services", "nodes", "secrets", "configmaps"]
            verbs     = ["create", "delete", "get", "list", "patch", "update", "deletecollection"]
          },
          {
            apiGroups = ["extensions", "apps"]
            resources = ["deployments", "replicasets"]
            verbs     = ["list", "get", "patch", "update"]
          }
        ]
        image = "litmuschaos/litmus-ansible-runner:${var.litmus_version}"
        imagePullPolicy = "Always"
        args = ["/bin/bash", "-c", "ansible-playbook ./experiments/burst/${each.key}/test.yml -i /etc/ansible/hosts -v"]
        command = ["sh", "-c"]
        
        env = [
          {
            name = "ANSIBLE_STDOUT_CALLBACK"
            value = "default"
          },
          {
            name = "TOTAL_CHAOS_DURATION"
            value = tostring(each.value.duration_seconds)
          },
          {
            name = "CHAOS_INTERVAL"
            value = tostring(each.value.interval_seconds)
          },
          {
            name = "TARGET_CONTAINER"
            value = each.value.target_container
          },
          {
            name = "BURST_SCENARIO"
            value = each.key
          },
          {
            name = "OPENSTACK_ENDPOINT"
            value = var.openstack_endpoint
          },
          {
            name = "AWS_REGION"
            value = var.aws_region
          }
        ]
        
        labels = {
          experiment = "burst-${each.key}"
          app.kubernetes.io/part-of = "litmus"
        }
      }
    }
  }
}

# VPN Tunnel Chaos - Kill VPN Connections
resource "kubernetes_manifest" "vpn_tunnel_chaos" {
  manifest = {
    apiVersion = "litmuschaos.io/v1alpha1"
    kind       = "ChaosExperiment"
    metadata = {
      name      = "vpn-tunnel-disruption"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
      labels = {
        name = "vpn-tunnel-disruption"
        app.kubernetes.io/part-of = "litmus"
        chaos-type = "network"
      }
    }
    spec = {
      definition = {
        scope = "Cluster"
        permissions = [
          {
            apiGroups = [""]
            resources = ["pods", "nodes"]
            verbs     = ["list", "get", "create", "delete", "patch"]
          }
        ]
        image = "litmuschaos/ansible-runner:${var.litmus_version}"
        args = ["/bin/bash", "-c", "ansible-playbook ./experiments/network/vpn-tunnel-kill.yml -i /etc/ansible/hosts -v"]
        command = ["sh", "-c"]
        
        env = [
          {
            name = "TOTAL_CHAOS_DURATION"
            value = "300"  # 5 minutes
          },
          {
            name = "TUNNEL_ENDPOINTS"
            value = jsonencode(var.vpn_tunnel_endpoints)
          },
          {
            name = "RECOVERY_TIMEOUT"
            value = "120"  # 2 minutes max recovery time
          }
        ]
      }
    }
  }
}

# BGP Session Chaos - Drop BGP Sessions
resource "kubernetes_manifest" "bgp_session_chaos" {
  manifest = {
    apiVersion = "litmuschaos.io/v1alpha1"
    kind       = "ChaosExperiment"
    metadata = {
      name      = "bgp-session-disruption"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
      labels = {
        name = "bgp-session-disruption"
        app.kubernetes.io/part-of = "litmus"
        chaos-type = "network"
      }
    }
    spec = {
      definition = {
        scope = "Cluster"
        permissions = [
          {
            apiGroups = [""]
            resources = ["pods", "nodes"]
            verbs     = ["list", "get", "create", "delete", "patch"]
          }
        ]
        image = "litmuschaos/ansible-runner:${var.litmus_version}"
        args = ["/bin/bash", "-c", "ansible-playbook ./experiments/network/bgp-session-drop.yml -i /etc/ansible/hosts -v"]
        command = ["sh", "-c"]
        
        env = [
          {
            name = "TOTAL_CHAOS_DURATION"
            value = "180"  # 3 minutes
          },
          {
            name = "BGP_PEERS"
            value = jsonencode(var.bgp_peer_ips)
          },
          {
            name = "LOCAL_ASN"
            value = var.local_asn
          }
        ]
      }
    }
  }
}

# Route Corruption Chaos
resource "kubernetes_manifest" "route_corruption_chaos" {
  manifest = {
    apiVersion = "litmuschaos.io/v1alpha1"
    kind       = "ChaosExperiment"
    metadata = {
      name      = "route-corruption"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
      labels = {
        name = "route-corruption"
        app.kubernetes.io/part-of = "litmus"
        chaos-type = "network"
      }
    }
    spec = {
      definition = {
        scope = "Cluster"
        permissions = [
          {
            apiGroups = [""]
            resources = ["pods", "nodes"]
            verbs     = ["list", "get", "create", "delete", "patch"]
          }
        ]
        image = "litmuschaos/network-chaos:${var.litmus_version}"
        args = ["/bin/bash", "-c", "./route-corruption.sh"]
        command = ["sh", "-c"]
        
        env = [
          {
            name = "TOTAL_CHAOS_DURATION"
            value = "240"  # 4 minutes
          },
          {
            name = "TARGET_ROUTES"
            value = jsonencode(var.critical_routes)
          },
          {
            name = "CORRUPTION_TYPE"
            value = "blackhole"  # or "redirect"
          }
        ]
      }
    }
  }
}

# Secrets Rotation Chaos
resource "kubernetes_manifest" "secrets_rotation_chaos" {
  manifest = {
    apiVersion = "litmuschaos.io/v1alpha1"
    kind       = "ChaosExperiment"
    metadata = {
      name      = "unexpected-key-rotation"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
      labels = {
        name = "unexpected-key-rotation"
        app.kubernetes.io/part-of = "litmus"
        chaos-type = "security"
      }
    }
    spec = {
      definition = {
        scope = "Namespaced"
        permissions = [
          {
            apiGroups = [""]
            resources = ["secrets"]
            verbs     = ["list", "get", "create", "delete", "patch", "update"]
          }
        ]
        image = "litmuschaos/vault-chaos:${var.litmus_version}"
        args = ["/bin/bash", "-c", "python3 /tmp/rotate-secrets.py"]
        command = ["sh", "-c"]
        
        env = [
          {
            name = "VAULT_ADDR"
            value = var.vault_addr
          },
          {
            name = "ROTATION_TARGETS"
            value = jsonencode(var.rotation_target_secrets)
          },
          {
            name = "CHAOS_DURATION"
            value = "120"  # 2 minutes
          }
        ]
      }
    }
  }
}

# Synthetic Burst Drills for CI
resource "kubernetes_manifest" "synthetic_burst_drill" {
  manifest = {
    apiVersion = "litmuschaos.io/v1alpha1"
    kind       = "ChaosEngine"
    metadata = {
      name      = "synthetic-burst-drill"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
    }
    spec = {
      appinfo = {
        appns    = "burst-controller"
        applabel = "app=burst-controller"
        appkind  = "deployment"
      }
      chaosServiceAccount = kubernetes_service_account.chaos_runner.metadata[0].name
      monitoring          = true
      jobCleanUpPolicy    = "retain"
      
      experiments = [
        {
          name = "burst-capacity-stress"
          spec = {
            components = {
              env = [
                {
                  name  = "TOTAL_CHAOS_DURATION"
                  value = "600"  # 10 minutes
                },
                {
                  name  = "BURST_THRESHOLD"
                  value = "85"   # Trigger at 85% capacity
                },
                {
                  name  = "TARGET_REPLICAS"
                  value = "20"   # Scale to 20 replicas
                },
                {
                  name  = "CHAOS_MONKEY_MODE"
                  value = "true"
                }
              ]
            }
          }
        }
      ]
    }
  }
}

# GameDay Automation Platform
resource "kubernetes_namespace" "gameday" {
  metadata {
    name = "gameday"
    labels = {
      "app.kubernetes.io/name" = "gameday"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "gameday_platform" {
  name       = "gameday-platform"
  chart      = "${path.module}/charts/gameday-platform"
  namespace  = kubernetes_namespace.gameday.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/gameday-values.yaml", {
      environment = var.environment
      slack_webhook_url = var.gameday_slack_webhook
      email_notifications = var.gameday_email_list
      slo_breach_threshold = 0.95  # 95% SLO threshold
      auto_rollback_enabled = true
    })
  ]
}

# Scheduled GameDay Events
resource "kubernetes_manifest" "monthly_gameday" {
  manifest = {
    apiVersion = "batch/v1"
    kind       = "CronJob"
    metadata = {
      name      = "monthly-gameday"
      namespace = kubernetes_namespace.gameday.metadata[0].name
    }
    spec = {
      schedule = "0 10 15 * *"  # 15th of every month at 10 AM
      jobTemplate = {
        spec = {
          template = {
            spec = {
              containers = [
                {
                  name  = "gameday-runner"
                  image = "federation/gameday-runner:${var.gameday_image_tag}"
                  env = [
                    {
                      name = "GAMEDAY_TYPE"
                      value = "full_federation_test"
                    },
                    {
                      name = "ENVIRONMENT"
                      value = var.environment
                    },
                    {
                      name = "SLO_MONITOR_ENABLED"
                      value = "true"
                    },
                    {
                      name = "AUTO_ROLLBACK_ENABLED"
                      value = "true"
                    }
                  ]
                  command = ["/bin/sh", "-c", "python3 /app/gameday-runner.py"]
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

# Resilience Testing as CI
resource "github_repository_file" "chaos_ci_workflow" {
  repository          = var.gitops_repo_name
  branch              = "main"
  file                = ".github/workflows/chaos-testing.yml"
  commit_message      = "Add chaos testing CI workflow"
  commit_author       = "terraform-automation"
  commit_email        = var.automation_email
  overwrite_on_create = true
  
  content = templatefile("${path.module}/templates/chaos-ci-workflow.yml", {
    environment = var.environment
    chaos_namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
    litmus_version = var.litmus_version
  })
}

# Chaos Monitoring and Observability
resource "kubernetes_manifest" "chaos_prometheus_rules" {
  manifest = {
    apiVersion = "monitoring.coreos.com/v1"
    kind       = "PrometheusRule"
    metadata = {
      name      = "chaos-engineering-alerts"
      namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
      labels = {
        prometheus = "kube-prometheus"
        role       = "alert-rules"
      }
    }
    spec = {
      groups = [
        {
          name = "chaos.experiments"
          rules = [
            {
              alert = "ChaosExperimentFailed"
              expr  = "increase(litmus_experiment_failed_total[5m]) > 0"
              for   = "0m"
              labels = {
                severity = "warning"
                team     = "platform"
              }
              annotations = {
                summary     = "Chaos experiment {{ $labels.experiment }} failed"
                description = "Chaos experiment {{ $labels.experiment }} in namespace {{ $labels.namespace }} has failed"
                runbook_url = "https://runbooks.${var.domain_name}/chaos-experiment-failure"
              }
            },
            {
              alert = "ChaosExperimentTimeout"
              expr  = "increase(litmus_experiment_timeout_total[10m]) > 0"
              for   = "0m"
              labels = {
                severity = "critical"
                team     = "platform"
              }
              annotations = {
                summary     = "Chaos experiment {{ $labels.experiment }} timed out"
                description = "Chaos experiment {{ $labels.experiment }} in namespace {{ $labels.namespace }} has timed out"
                runbook_url = "https://runbooks.${var.domain_name}/chaos-experiment-timeout"
              }
            },
            {
              alert = "SLOBreachDuringChaos"
              expr  = "slo_error_budget_remaining < 0.05 and on() litmus_experiment_running == 1"
              for   = "1m"
              labels = {
                severity = "critical"
                team     = "platform"
              }
              annotations = {
                summary     = "SLO breach detected during chaos experiment"
                description = "Error budget critically low ({{ $value | humanizePercentage }}) during active chaos experiment"
                runbook_url = "https://runbooks.${var.domain_name}/slo-breach-during-chaos"
              }
            }
          ]
        }
      ]
    }
  }
}

# Chaos Service Account with RBAC
resource "kubernetes_service_account" "chaos_runner" {
  metadata {
    name      = "chaos-runner"
    namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
  }
}

resource "kubernetes_cluster_role" "chaos_runner" {
  metadata {
    name = "chaos-runner"
  }
  
  rule {
    api_groups = [""]
    resources  = ["pods", "services", "nodes", "secrets", "configmaps", "events"]
    verbs      = ["create", "delete", "get", "list", "patch", "update", "watch"]
  }
  
  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs      = ["get", "list", "patch", "update"]
  }
  
  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies"]
    verbs      = ["create", "delete", "get", "list", "patch", "update"]
  }
  
  rule {
    api_groups = ["litmuschaos.io"]
    resources  = ["chaosengines", "chaosexperiments", "chaosresults"]
    verbs      = ["create", "delete", "get", "list", "patch", "update", "watch"]
  }
}

resource "kubernetes_cluster_role_binding" "chaos_runner" {
  metadata {
    name = "chaos-runner"
  }
  
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.chaos_runner.metadata[0].name
  }
  
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.chaos_runner.metadata[0].name
    namespace = kubernetes_namespace.chaos_engineering.metadata[0].name
  }
}

# Fault Library Database
resource "aws_dynamodb_table" "fault_library" {
  name           = "federation-fault-library-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "fault_id"
  
  attribute {
    name = "fault_id"
    type = "S"
  }
  
  attribute {
    name = "category"
    type = "S"
  }
  
  attribute {
    name = "severity"
    type = "S"
  }
  
  global_secondary_index {
    name     = "CategoryIndex"
    hash_key = "category"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name     = "SeverityIndex"
    hash_key = "severity"
    projection_type = "ALL"
  }
  
  tags = local.common_tags
}

# Populate Fault Library
resource "aws_dynamodb_table_item" "fault_library_items" {
  for_each = var.fault_library_definitions
  
  table_name = aws_dynamodb_table.fault_library.name
  hash_key   = aws_dynamodb_table.fault_library.hash_key
  
  item = jsonencode({
    fault_id = {
      S = each.key
    }
    name = {
      S = each.value.name
    }
    description = {
      S = each.value.description
    }
    category = {
      S = each.value.category
    }
    severity = {
      S = each.value.severity
    }
    blast_radius = {
      S = each.value.blast_radius
    }
    recovery_time = {
      N = tostring(each.value.recovery_time_seconds)
    }
    automation_script = {
      S = each.value.automation_script
    }
    prerequisites = {
      SS = each.value.prerequisites
    }
    expected_impact = {
      S = each.value.expected_impact
    }
    rollback_procedure = {
      S = each.value.rollback_procedure
    }
    last_tested = {
      S = each.value.last_tested
    }
    success_criteria = {
      SS = each.value.success_criteria
    }
  })
}

# Chaos Automation Scripts Storage
resource "aws_s3_bucket" "chaos_scripts" {
  bucket = "federation-chaos-scripts-${var.environment}-${random_id.chaos_suffix.hex}"
  
  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "chaos_scripts" {
  bucket = aws_s3_bucket.chaos_scripts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Upload Chaos Scripts
resource "aws_s3_object" "chaos_scripts" {
  for_each = fileset("${path.module}/scripts", "**/*")
  
  bucket = aws_s3_bucket.chaos_scripts.bucket
  key    = each.value
  source = "${path.module}/scripts/${each.value}"
  etag   = filemd5("${path.module}/scripts/${each.value}")
  
  tags = local.common_tags
}

# Random ID for unique resource names
resource "random_id" "chaos_suffix" {
  byte_length = 4
}

# Outputs
output "chaos_engineering_config" {
  description = "Chaos engineering platform configuration"
  value = {
    chaos_namespace    = kubernetes_namespace.chaos_engineering.metadata[0].name
    gameday_namespace  = kubernetes_namespace.gameday.metadata[0].name
    litmus_installed   = true
    chaos_toolkit_installed = true
    fault_library_table = aws_dynamodb_table.fault_library.name
    chaos_scripts_bucket = aws_s3_bucket.chaos_scripts.bucket
  }
}

output "chaos_experiments" {
  description = "Available chaos experiments"
  value = {
    burst_experiments = [
      for k, v in kubernetes_manifest.burst_path_chaos_experiments : k
    ]
    network_experiments = [
      "vpn-tunnel-disruption",
      "bgp-session-disruption", 
      "route-corruption"
    ]
    security_experiments = [
      "unexpected-key-rotation"
    ]
  }
}

output "gameday_automation" {
  description = "GameDay automation configuration"
  value = {
    platform_installed = true
    monthly_schedule   = "0 10 15 * *"
    slo_monitoring     = true
    auto_rollback      = true
  }
}
