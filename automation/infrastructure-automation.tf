# Comprehensive Infrastructure Automation for Hybrid Cloud Federation
# Handles deployment, scaling, monitoring, and lifecycle management

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    kubectl = {
      source  = "alekc/kubectl"
      version = "~> 2.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.84"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

# GitOps Automation with ArgoCD
resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  version    = "5.46.7"
  namespace  = "argocd"
  create_namespace = true

  values = [
    yamlencode({
      global = {
        domain = var.argocd_domain
      }
      
      server = {
        replicas = 3
        
        config = {
          "application.instanceLabelKey" = "argocd.argoproj.io/instance"
          "server.rbac.log.enforce.enable" = "true"
          "exec.enabled" = "false"
          "admin.enabled" = "true"
          "timeout.reconciliation" = "180s"
          "timeout.hard.reconciliation" = "0s"
          
          # OIDC configuration for SSO
          "oidc.config" = yamlencode({
            name = "Vault OIDC"
            issuer = "https://vault.federation.local/v1/identity/oidc"
            clientId = "$oidc.vault.clientId"
            clientSecret = "$oidc.vault.clientSecret"
            requestedScopes = ["openid", "profile", "email", "groups"]
            requestedIDTokenClaims = {
              groups = {
                essential = true
              }
            }
          })
          
          # Repository credentials
          "repositories" = yamlencode([
            {
              url = var.gitops_repo_url
              name = "federation-config"
              type = "git"
              sshPrivateKeySecret = {
                name = "argocd-repo-creds"
                key = "sshPrivateKey"
              }
            }
          ])
        }
        
        ingress = {
          enabled = true
          ingressClassName = "istio"
          annotations = {
            "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
            "nginx.ingress.kubernetes.io/ssl-passthrough" = "true"
            "nginx.ingress.kubernetes.io/backend-protocol" = "GRPC"
          }
          hosts = [var.argocd_domain]
          tls = [{
            secretName = "argocd-server-tls"
            hosts = [var.argocd_domain]
          }]
        }
        
        metrics = {
          enabled = true
          serviceMonitor = {
            enabled = true
            namespace = "monitoring"
          }
        }
      }
      
      controller = {
        replicas = 3
        
        metrics = {
          enabled = true
          serviceMonitor = {
            enabled = true
            namespace = "monitoring"
          }
        }
        
        # Performance tuning
        env = [
          {
            name = "ARGOCD_CONTROLLER_REPLICAS"
            value = "3"
          },
          {
            name = "ARGOCD_CONTROLLER_PARALLELISM_LIMIT"
            value = "20"
          },
          {
            name = "ARGOCD_CONTROLLER_STATUS_PROCESSORS"
            value = "40"
          },
          {
            name = "ARGOCD_CONTROLLER_OPERATION_PROCESSORS"
            value = "20"
          }
        ]
      }
      
      repoServer = {
        replicas = 3
        
        metrics = {
          enabled = true
          serviceMonitor = {
            enabled = true
            namespace = "monitoring"
          }
        }
        
        # Enable Helm and Kustomize support
        env = [
          {
            name = "ARGOCD_EXEC_TIMEOUT"
            value = "300s"
          },
          {
            name = "ARGOCD_REPO_SERVER_PARALLELISM_LIMIT"
            value = "10"
          }
        ]
        
        # Plugin support for custom tools
        volumes = [
          {
            name = "custom-tools"
            emptyDir = {}
          }
        ]
        
        volumeMounts = [
          {
            name = "custom-tools"
            mountPath = "/custom-tools"
          }
        ]
        
        initContainers = [
          {
            name = "download-tools"
            image = "curlimages/curl:8.4.0"
            command = ["sh", "-c"]
            args = [
              "curl -L https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.2.1/kustomize_v5.2.1_linux_amd64.tar.gz | tar -xz -C /custom-tools && chmod +x /custom-tools/kustomize"
            ]
            volumeMounts = [
              {
                name = "custom-tools"
                mountPath = "/custom-tools"
              }
            ]
          }
        ]
      }
      
      redis = {
        enabled = true
        metrics = {
          enabled = true
          serviceMonitor = {
            enabled = true
            namespace = "monitoring"
          }
        }
      }
      
      # External secret management
      configs = {
        secret = {
          createSecret = false
        }
      }
    })
  ]
  
  depends_on = [
    kubernetes_namespace.argocd,
    kubernetes_secret.argocd_secret
  ]
}

# ArgoCD namespace and RBAC
resource "kubernetes_namespace" "argocd" {
  metadata {
    name = "argocd"
    labels = {
      "istio-injection" = "enabled"
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit" = "restricted"
      "pod-security.kubernetes.io/warn" = "restricted"
    }
  }
}

# ArgoCD secret for external secret management
resource "kubernetes_secret" "argocd_secret" {
  metadata {
    name      = "argocd-secret"
    namespace = "argocd"
    labels = {
      "app.kubernetes.io/name" = "argocd-secret"
      "app.kubernetes.io/part-of" = "argocd"
    }
  }

  type = "Opaque"

  data = {
    "admin.password" = bcrypt(var.argocd_admin_password)
    "server.secretkey" = base64encode(random_password.argocd_server_secret.result)
    "oidc.vault.clientSecret" = var.vault_oidc_client_secret
  }
}

resource "random_password" "argocd_server_secret" {
  length  = 32
  special = true
}

# Repository credentials secret
resource "kubernetes_secret" "argocd_repo_creds" {
  metadata {
    name      = "argocd-repo-creds"
    namespace = "argocd"
    labels = {
      "argocd.argoproj.io/secret-type" = "repository"
    }
  }

  type = "Opaque"

  data = {
    type = "git"
    url = var.gitops_repo_url
    sshPrivateKey = var.gitops_ssh_private_key
  }
}

# ArgoCD Applications for Federation Components
resource "kubectl_manifest" "federation_apps" {
  for_each = {
    "federation-controller" = {
      path = "applications/federation-controller"
      automated = true
      selfHeal = true
    }
    "observability" = {
      path = "applications/observability"
      automated = true
      selfHeal = true
    }
    "security" = {
      path = "applications/security"
      automated = false
      selfHeal = false
    }
    "networking" = {
      path = "applications/networking"
      automated = true
      selfHeal = true
    }
    "workload-management" = {
      path = "applications/workload-management"
      automated = true
      selfHeal = true
    }
  }

  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind = "Application"
    metadata = {
      name = each.key
      namespace = "argocd"
      finalizers = ["resources-finalizer.argocd.argoproj.io"]
    }
    spec = {
      project = "federation"
      source = {
        repoURL = var.gitops_repo_url
        targetRevision = "HEAD"
        path = each.value.path
      }
      destination = {
        server = "https://kubernetes.default.svc"
        namespace = "federation-system"
      }
      syncPolicy = each.value.automated ? {
        automated = {
          prune = true
          selfHeal = each.value.selfHeal
          allowEmpty = false
        }
        syncOptions = [
          "CreateNamespace=true",
          "PrunePropagationPolicy=foreground",
          "PruneLast=true"
        ]
        retry = {
          limit = 5
          backoff = {
            duration = "5s"
            factor = 2
            maxDuration = "3m"
          }
        }
      } : null
    }
  })

  depends_on = [helm_release.argocd]
}

# ArgoCD Project for Federation
resource "kubectl_manifest" "federation_project" {
  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind = "AppProject"
    metadata = {
      name = "federation"
      namespace = "argocd"
    }
    spec = {
      description = "Hybrid Cloud Federation Project"
      
      sourceRepos = [
        var.gitops_repo_url,
        "https://helm.releases.hashicorp.com",
        "https://prometheus-community.github.io/helm-charts",
        "https://grafana.github.io/helm-charts",
        "https://istio-release.storage.googleapis.com/charts",
        "https://kubernetes-sigs.github.io/external-dns/"
      ]
      
      destinations = [
        {
          namespace = "*"
          server = "https://kubernetes.default.svc"
        }
      ]
      
      clusterResourceWhitelist = [
        {
          group = "*"
          kind = "*"
        }
      ]
      
      namespaceResourceWhitelist = [
        {
          group = "*"
          kind = "*"
        }
      ]
      
      roles = [
        {
          name = "admin"
          description = "Admin access to federation project"
          policies = [
            "p, proj:federation:admin, applications, *, federation/*, allow",
            "p, proj:federation:admin, repositories, *, *, allow",
            "p, proj:federation:admin, certificates, *, *, allow"
          ]
          groups = ["federation:admins"]
        },
        {
          name = "developer"
          description = "Developer access to federation project"
          policies = [
            "p, proj:federation:developer, applications, get, federation/*, allow",
            "p, proj:federation:developer, applications, sync, federation/*, allow"
          ]
          groups = ["federation:developers"]
        }
      ]
    }
  })

  depends_on = [helm_release.argocd]
}

# Terraform State Automation and Management
resource "aws_s3_bucket" "terraform_state" {
  count  = var.enable_terraform_state_management ? 1 : 0
  bucket = var.terraform_state_bucket
  
  tags = {
    Name        = "Terraform State"
    Environment = var.environment
    Purpose     = "Infrastructure State Management"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  count  = var.enable_terraform_state_management ? 1 : 0
  bucket = aws_s3_bucket.terraform_state[0].id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "terraform_state" {
  count  = var.enable_terraform_state_management ? 1 : 0
  bucket = aws_s3_bucket.terraform_state[0].id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.terraform_state[0].arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_kms_key" "terraform_state" {
  count       = var.enable_terraform_state_management ? 1 : 0
  description = "KMS key for Terraform state encryption"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_dynamodb_table" "terraform_state_lock" {
  count          = var.enable_terraform_state_management ? 1 : 0
  name           = "${var.terraform_state_bucket}-lock"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = "Terraform State Lock"
    Environment = var.environment
  }
}

# Infrastructure Monitoring and Alerting Automation
resource "helm_release" "prometheus_operator" {
  name       = "kube-prometheus-stack"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = "51.2.0"
  namespace  = "monitoring"
  create_namespace = true

  values = [
    yamlencode({
      prometheus = {
        prometheusSpec = {
          retention = "30d"
          storageSpec = {
            volumeClaimTemplate = {
              spec = {
                storageClassName = var.storage_class
                accessModes = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "100Gi"
                  }
                }
              }
            }
          }
          
          additionalScrapeConfigs = [
            {
              job_name = "federation-controller"
              static_configs = [{
                targets = ["federation-controller.federation-system.svc.cluster.local:8080"]
              }]
              metrics_path = "/metrics"
              scrape_interval = "30s"
            },
            {
              job_name = "openstack-exporter"
              static_configs = [{
                targets = ["openstack-exporter.openstack.svc.cluster.local:9180"]
              }]
              scrape_interval = "60s"
            },
            {
              job_name = "aws-cloudwatch"
              ec2_sd_configs = [{
                region = var.aws_region
                port = 9100
              }]
              relabel_configs = [
                {
                  source_labels = ["__meta_ec2_tag_Environment"]
                  target_label = "environment"
                },
                {
                  source_labels = ["__meta_ec2_tag_Project"]
                  target_label = "project"
                }
              ]
            }
          ]
          
          ruleSelector = {
            matchLabels = {
              prometheus = "kube-prometheus"
              role = "alert-rules"
            }
          }
        }
      }
      
      grafana = {
        enabled = true
        adminPassword = var.grafana_admin_password
        
        persistence = {
          enabled = true
          storageClassName = var.storage_class
          size = "10Gi"
        }
        
        sidecar = {
          dashboards = {
            enabled = true
            searchNamespace = "ALL"
          }
          datasources = {
            enabled = true
          }
        }
        
        additionalDataSources = [
          {
            name = "Loki"
            type = "loki"
            url = "http://loki.monitoring.svc.cluster.local:3100"
            access = "proxy"
          },
          {
            name = "Jaeger"
            type = "jaeger"
            url = "http://jaeger-query.monitoring.svc.cluster.local:16686"
            access = "proxy"
          }
        ]
        
        dashboardProviders = {
          "dashboardproviders.yaml" = {
            apiVersion = 1
            providers = [
              {
                name = "federation"
                orgId = 1
                folder = "Federation"
                type = "file"
                disableDeletion = false
                updateIntervalSeconds = 30
                options = {
                  path = "/var/lib/grafana/dashboards/federation"
                }
              }
            ]
          }
        }
      }
      
      alertmanager = {
        alertmanagerSpec = {
          storage = {
            volumeClaimTemplate = {
              spec = {
                storageClassName = var.storage_class
                accessModes = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "10Gi"
                  }
                }
              }
            }
          }
        }
        
        config = {
          global = {
            slack_api_url = var.slack_webhook_url
          }
          
          route = {
            group_by = ["alertname", "cluster", "service"]
            group_wait = "10s"
            group_interval = "10s"
            repeat_interval = "1h"
            receiver = "web.hook"
            
            routes = [
              {
                match = {
                  alertname = "Watchdog"
                }
                receiver = "null"
              },
              {
                match = {
                  severity = "critical"
                }
                receiver = "critical-alerts"
                group_wait = "0s"
                repeat_interval = "5m"
              }
            ]
          }
          
          receivers = [
            {
              name = "null"
            },
            {
              name = "web.hook"
              slack_configs = [
                {
                  channel = "#federation-alerts"
                  title = "Federation Alert"
                  text = "{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}"
                }
              ]
            },
            {
              name = "critical-alerts"
              slack_configs = [
                {
                  channel = "#federation-critical"
                  title = "CRITICAL: Federation Alert"
                  text = "{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}"
                }
              ]
              webhook_configs = [
                {
                  url = var.pagerduty_webhook_url
                }
              ]
            }
          ]
        }
      }
    })
  ]
}

# Custom Federation Monitoring Rules
resource "kubectl_manifest" "federation_monitoring_rules" {
  yaml_body = yamlencode({
    apiVersion = "monitoring.coreos.com/v1"
    kind = "PrometheusRule"
    metadata = {
      name = "federation-monitoring"
      namespace = "monitoring"
      labels = {
        prometheus = "kube-prometheus"
        role = "alert-rules"
      }
    }
    spec = {
      groups = [
        {
          name = "federation.rules"
          rules = [
            {
              alert = "FederationControllerDown"
              expr = "up{job=\"federation-controller\"} == 0"
              for = "5m"
              labels = {
                severity = "critical"
              }
              annotations = {
                summary = "Federation controller is down"
                description = "The federation controller has been down for more than 5 minutes"
              }
            },
            {
              alert = "CloudConnectivityLoss"
              expr = "federation_cloud_connectivity == 0"
              for = "2m"
              labels = {
                severity = "critical"
              }
              annotations = {
                summary = "Lost connectivity to cloud {{ $labels.cloud }}"
                description = "Connectivity to {{ $labels.cloud }} has been lost for more than 2 minutes"
              }
            },
            {
              alert = "WorkloadFailureRate"
              expr = "rate(federation_workload_failures_total[5m]) > 0.1"
              for = "10m"
              labels = {
                severity = "warning"
              }
              annotations = {
                summary = "High workload failure rate"
                description = "Workload failure rate is {{ $value }} failures per second"
              }
            },
            {
              alert = "NetworkLatencyHigh"
              expr = "federation_network_latency_seconds > 0.5"
              for = "15m"
              labels = {
                severity = "warning"
              }
              annotations = {
                summary = "High network latency between clouds"
                description = "Network latency between {{ $labels.source }} and {{ $labels.target }} is {{ $value }}s"
              }
            }
          ]
        }
      ]
    }
  })
  
  depends_on = [helm_release.prometheus_operator]
}

# Automated Backup System
resource "kubernetes_cron_job" "federation_backup" {
  metadata {
    name      = "federation-backup"
    namespace = "federation-system"
  }

  spec {
    schedule = "0 2 * * *"  # Daily at 2 AM
    
    job_template {
      metadata {
        labels = {
          app = "federation-backup"
        }
      }
      
      spec {
        template {
          metadata {
            labels = {
              app = "federation-backup"
            }
          }
          
          spec {
            service_account_name = "federation-backup"
            restart_policy = "OnFailure"
            
            container {
              name  = "backup"
              image = "federation/backup-tool:latest"
              
              command = ["/bin/sh"]
              args = [
                "-c",
                "fed-cli backup create --all --retention 30d && fed-cli backup verify"
              ]
              
              env {
                name = "BACKUP_STORAGE_BUCKET"
                value = var.backup_storage_bucket
              }
              
              env {
                name = "BACKUP_ENCRYPTION_KEY"
                value_from {
                  secret_key_ref {
                    name = "backup-encryption"
                    key = "key"
                  }
                }
              }
              
              volume_mount {
                name       = "backup-config"
                mount_path = "/etc/backup"
              }
              
              resources {
                requests = {
                  cpu    = "500m"
                  memory = "1Gi"
                }
                limits = {
                  cpu    = "2"
                  memory = "4Gi"
                }
              }
            }
            
            volume {
              name = "backup-config"
              config_map {
                name = "federation-backup-config"
              }
            }
          }
        }
      }
    }
  }
}

# Service Account for Backup Operations
resource "kubernetes_service_account" "federation_backup" {
  metadata {
    name      = "federation-backup"
    namespace = "federation-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.federation_backup_role.arn
    }
  }
}

resource "kubernetes_cluster_role_binding" "federation_backup" {
  metadata {
    name = "federation-backup"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }

  subject {
    kind      = "ServiceAccount"
    name      = "federation-backup"
    namespace = "federation-system"
  }
}

# AWS IAM Role for Backup
resource "aws_iam_role" "federation_backup_role" {
  name = "federation-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = var.eks_oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${var.eks_oidc_provider}:sub" = "system:serviceaccount:federation-system:federation-backup"
            "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "federation_backup_policy" {
  name = "federation-backup-policy"
  role = aws_iam_role.federation_backup_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.backup_storage_bucket}",
          "arn:aws:s3:::${var.backup_storage_bucket}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Infrastructure as Code Pipeline
resource "kubernetes_config_map" "terraform_automation" {
  metadata {
    name      = "terraform-automation"
    namespace = "federation-system"
  }

  data = {
    "plan.sh" = <<-EOF
      #!/bin/bash
      set -e
      
      # Initialize Terraform
      terraform init -backend-config="bucket=${var.terraform_state_bucket}" \
                     -backend-config="key=federation/terraform.tfstate" \
                     -backend-config="region=${var.aws_region}" \
                     -backend-config="dynamodb_table=${var.terraform_state_bucket}-lock"
      
      # Plan changes
      terraform plan -out=tfplan -var-file=environments/${var.environment}.tfvars
      
      # Save plan for review
      terraform show -json tfplan > tfplan.json
      
      # Upload plan to S3 for review
      aws s3 cp tfplan.json s3://${var.terraform_state_bucket}/plans/$(date +%Y%m%d-%H%M%S)-plan.json
    EOF
    
    "apply.sh" = <<-EOF
      #!/bin/bash
      set -e
      
      # Download approved plan
      aws s3 cp s3://${var.terraform_state_bucket}/plans/approved-plan.json tfplan.json
      
      # Apply changes
      terraform apply tfplan
      
      # Update ArgoCD applications if needed
      if [ "$UPDATE_ARGOCD" == "true" ]; then
        kubectl patch application federation-controller -n argocd --type='merge' -p='{"spec":{"source":{"targetRevision":"HEAD"}}}'
      fi
    EOF
  }
}

# Output automation information
output "argocd_server_url" {
  value = "https://${var.argocd_domain}"
  description = "ArgoCD server URL for GitOps management"
}

output "grafana_url" {
  value = "http://grafana.monitoring.svc.cluster.local:3000"
  description = "Grafana dashboard URL"
}

output "prometheus_url" {
  value = "http://prometheus-operated.monitoring.svc.cluster.local:9090"
  description = "Prometheus server URL"
}

output "backup_schedule" {
  value = "Daily at 2:00 AM UTC"
  description = "Automated backup schedule"
}

output "terraform_state_bucket" {
  value = var.enable_terraform_state_management ? aws_s3_bucket.terraform_state[0].bucket : null
  description = "S3 bucket for Terraform state"
}

# Variables
variable "argocd_domain" {
  description = "Domain for ArgoCD server"
  type        = string
  default     = "argocd.federation.local"
}

variable "argocd_admin_password" {
  description = "Admin password for ArgoCD"
  type        = string
  sensitive   = true
}

variable "gitops_repo_url" {
  description = "Git repository URL for GitOps"
  type        = string
}

variable "gitops_ssh_private_key" {
  description = "SSH private key for Git repository access"
  type        = string
  sensitive   = true
}

variable "vault_oidc_client_secret" {
  description = "Vault OIDC client secret for ArgoCD SSO"
  type        = string
  sensitive   = true
}

variable "enable_terraform_state_management" {
  description = "Enable automated Terraform state management"
  type        = bool
  default     = true
}

variable "terraform_state_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
}

variable "backup_storage_bucket" {
  description = "S3 bucket for backup storage"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts"
  type        = string
  sensitive   = true
}

variable "pagerduty_webhook_url" {
  description = "PagerDuty webhook URL for critical alerts"
  type        = string
  sensitive   = true
}

variable "grafana_admin_password" {
  description = "Admin password for Grafana"
  type        = string
  sensitive   = true
}
EOF
