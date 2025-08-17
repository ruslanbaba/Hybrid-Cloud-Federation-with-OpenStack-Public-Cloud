# Platform Operations & Delivery Pipeline
# GitOps, Golden Images, Change Management, Control Plane Upgrades

terraform {
  required_providers {
    argocd = {
      source  = "oboukili/argocd"
      version = "~> 6.0"
    }
    flux = {
      source  = "fluxcd/flux"
      version = "~> 1.2"
    }
    atlantis = {
      source  = "runatlantis/atlantis"
      version = "~> 0.24"
    }
  }
}

# ArgoCD Configuration for GitOps
resource "kubernetes_namespace" "argocd" {
  metadata {
    name = "argocd"
    labels = {
      "app.kubernetes.io/name" = "argocd"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  namespace  = kubernetes_namespace.argocd.metadata[0].name
  version    = "5.46.8"
  
  values = [
    templatefile("${path.module}/templates/argocd-values.yaml", {
      domain         = var.domain_name
      environment    = var.environment
      tls_cert_arn   = var.argocd_tls_cert_arn
      sso_client_id  = var.argocd_sso_client_id
      sso_client_secret = var.argocd_sso_client_secret
      rbac_policy    = file("${path.module}/configs/argocd-rbac.csv")
    })
  ]
  
  depends_on = [kubernetes_namespace.argocd]
}

# ArgoCD Application for OpenStack Resources
resource "argocd_application" "openstack_federation" {
  metadata {
    name      = "openstack-federation-${var.environment}"
    namespace = kubernetes_namespace.argocd.metadata[0].name
    labels = {
      environment = var.environment
      service     = "openstack"
    }
  }
  
  spec {
    project = argocd_project.federation.metadata[0].name
    
    source {
      repo_url        = var.gitops_repo_url
      path            = "openstack/${var.environment}"
      target_revision = "main"
      
      helm {
        value_files = [
          "values.yaml",
          "values-${var.environment}.yaml"
        ]
        
        parameter {
          name  = "global.environment"
          value = var.environment
        }
        
        parameter {
          name  = "openstack.endpoint"
          value = var.openstack_endpoint
        }
        
        parameter {
          name  = "federation.enabled"
          value = "true"
        }
      }
    }
    
    destination {
      server    = "https://kubernetes.default.svc"
      namespace = "openstack-system"
    }
    
    sync_policy {
      automated {
        prune       = true
        self_heal   = true
        allow_empty = false
      }
      
      sync_options = [
        "CreateNamespace=true",
        "PrunePropagationPolicy=foreground",
        "PruneLast=true"
      ]
      
      retry {
        limit = 5
        backoff {
          duration     = "30s"
          max_duration = "2m"
          factor       = 2
        }
      }
    }
    
    ignore_difference {
      group         = "apps"
      kind          = "Deployment"
      json_pointers = ["/spec/replicas"]
    }
  }
}

# ArgoCD Application for AWS Resources
resource "argocd_application" "aws_federation" {
  metadata {
    name      = "aws-federation-${var.environment}"
    namespace = kubernetes_namespace.argocd.metadata[0].name
    labels = {
      environment = var.environment
      service     = "aws"
    }
  }
  
  spec {
    project = argocd_project.federation.metadata[0].name
    
    source {
      repo_url        = var.gitops_repo_url
      path            = "aws/${var.environment}"
      target_revision = "main"
      
      kustomize {
        name_prefix = "${var.environment}-"
        name_suffix = "-federation"
        
        common_labels = {
          environment = var.environment
          managed_by  = "argocd"
        }
        
        images = [
          "burst-controller=federation/burst-controller:${var.controller_image_tag}"
        ]
      }
    }
    
    destination {
      server    = "https://kubernetes.default.svc"
      namespace = "aws-system"
    }
    
    sync_policy {
      automated {
        prune       = true
        self_heal   = true
        allow_empty = false
      }
      
      sync_options = [
        "CreateNamespace=true",
        "ServerSideApply=true"
      ]
    }
  }
}

# ArgoCD Project for Federation
resource "argocd_project" "federation" {
  metadata {
    name      = "federation-${var.environment}"
    namespace = kubernetes_namespace.argocd.metadata[0].name
    labels = {
      environment = var.environment
    }
  }
  
  spec {
    description  = "Federation project for ${var.environment}"
    source_repos = [var.gitops_repo_url]
    
    destination {
      server     = "https://kubernetes.default.svc"
      namespace  = "openstack-system"
    }
    
    destination {
      server     = "https://kubernetes.default.svc"
      namespace  = "aws-system"
    }
    
    destination {
      server     = "https://kubernetes.default.svc"
      namespace  = "gcp-system"
    }
    
    destination {
      server     = "https://kubernetes.default.svc"
      namespace  = "azure-system"
    }
    
    cluster_resource_whitelist {
      group = "*"
      kind  = "*"
    }
    
    namespace_resource_whitelist {
      group = "*"
      kind  = "*"
    }
    
    orphaned_resources {
      warn = true
    }
    
    role {
      name = "admin"
      policies = [
        "p, proj:federation-${var.environment}:admin, applications, *, federation-${var.environment}/*, allow",
        "p, proj:federation-${var.environment}:admin, repositories, *, *, allow",
        "p, proj:federation-${var.environment}:admin, clusters, *, *, allow"
      ]
      groups = ["platform-team", "sre-team"]
    }
    
    role {
      name = "developer"
      policies = [
        "p, proj:federation-${var.environment}:developer, applications, get, federation-${var.environment}/*, allow",
        "p, proj:federation-${var.environment}:developer, applications, sync, federation-${var.environment}/*, allow"
      ]
      groups = ["developers"]
    }
  }
}

# Flux Configuration for Alternative GitOps
resource "kubernetes_namespace" "flux_system" {
  metadata {
    name = "flux-system"
    labels = {
      "app.kubernetes.io/name" = "flux"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "flux" {
  count = var.enable_flux ? 1 : 0
  
  name       = "flux"
  repository = "https://fluxcd-community.github.io/helm-charts"
  chart      = "flux2"
  namespace  = kubernetes_namespace.flux_system.metadata[0].name
  version    = "2.11.0"
  
  values = [
    templatefile("${path.module}/templates/flux-values.yaml", {
      git_url     = var.gitops_repo_url
      git_branch  = "main"
      git_path    = "clusters/${var.environment}"
      environment = var.environment
    })
  ]
}

# Atlantis for Terraform PR-based Planning
resource "kubernetes_namespace" "atlantis" {
  metadata {
    name = "atlantis"
    labels = {
      "app.kubernetes.io/name" = "atlantis"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "atlantis" {
  name       = "atlantis"
  repository = "https://runatlantis.github.io/helm-charts"
  chart      = "atlantis"
  namespace  = kubernetes_namespace.atlantis.metadata[0].name
  version    = "4.18.0"
  
  values = [
    templatefile("${path.module}/templates/atlantis-values.yaml", {
      github_token    = var.github_token
      github_webhook_secret = var.github_webhook_secret
      domain_name     = var.domain_name
      environment     = var.environment
      vault_addr      = var.vault_addr
      aws_region      = var.aws_region
      tf_version      = var.terraform_version
    })
  ]
  
  set_sensitive {
    name  = "github.token"
    value = var.github_token
  }
  
  set_sensitive {
    name  = "github.secret"
    value = var.github_webhook_secret
  }
}

# Atlantis Repository Configuration
resource "kubernetes_config_map" "atlantis_repos" {
  metadata {
    name      = "atlantis-repos"
    namespace = kubernetes_namespace.atlantis.metadata[0].name
  }
  
  data = {
    "repos.yaml" = templatefile("${path.module}/configs/atlantis-repos.yaml", {
      repo_url        = var.gitops_repo_url
      apply_requirements = ["approved", "mergeable"]
      allowed_overrides  = ["workflow", "apply_requirements"]
      allowed_workflows  = ["federation"]
    })
  }
}

# Golden Image Pipeline with Packer
resource "aws_codebuild_project" "golden_images" {
  name         = "federation-golden-images-${var.environment}"
  description  = "Build golden images for federation"
  service_role = aws_iam_role.codebuild_golden_images.arn
  
  artifacts {
    type = "CODEPIPELINE"
  }
  
  environment {
    compute_type                = "BUILD_GENERAL1_MEDIUM"
    image                      = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                       = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode            = true
    
    environment_variable {
      name  = "ENVIRONMENT"
      value = var.environment
    }
    
    environment_variable {
      name  = "OPENSTACK_ENDPOINT"
      value = var.openstack_endpoint
    }
    
    environment_variable {
      name  = "AWS_REGION"
      value = var.aws_region
    }
    
    environment_variable {
      name  = "GCP_PROJECT"
      value = var.gcp_project_id
    }
    
    environment_variable {
      name  = "VAULT_ADDR"
      value = var.vault_addr
    }
  }
  
  source {
    type = "CODEPIPELINE"
    buildspec = templatefile("${path.module}/configs/golden-images-buildspec.yml", {
      environment = var.environment
    })
  }
  
  tags = local.common_tags
}

# CodePipeline for Golden Images
resource "aws_codepipeline" "golden_images" {
  name     = "federation-golden-images-${var.environment}"
  role_arn = aws_iam_role.codepipeline_golden_images.arn
  
  artifact_store {
    location = aws_s3_bucket.pipeline_artifacts.bucket
    type     = "S3"
    
    encryption_key {
      id   = aws_kms_key.pipeline.arn
      type = "KMS"
    }
  }
  
  stage {
    name = "Source"
    
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["SourceOutput"]
      
      configuration = {
        S3Bucket    = aws_s3_bucket.golden_images_source.bucket
        S3ObjectKey = "source.zip"
      }
    }
  }
  
  stage {
    name = "CVE_Scan"
    
    action {
      name             = "CVE_Security_Scan"
      category         = "Test"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["SourceOutput"]
      output_artifacts = ["CVEScanOutput"]
      version          = "1"
      
      configuration = {
        ProjectName = aws_codebuild_project.cve_scan.name
      }
    }
  }
  
  stage {
    name = "Build_Images"
    
    action {
      name             = "Build_OpenStack_Image"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["CVEScanOutput"]
      output_artifacts = ["OpenStackOutput"]
      version          = "1"
      
      configuration = {
        ProjectName = aws_codebuild_project.golden_images.name
        EnvironmentVariables = jsonencode([
          {
            name  = "TARGET_PLATFORM"
            value = "openstack"
          }
        ])
      }
    }
    
    action {
      name             = "Build_AWS_AMI"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["CVEScanOutput"]
      output_artifacts = ["AWSOutput"]
      version          = "1"
      
      configuration = {
        ProjectName = aws_codebuild_project.golden_images.name
        EnvironmentVariables = jsonencode([
          {
            name  = "TARGET_PLATFORM"
            value = "aws"
          }
        ])
      }
    }
    
    action {
      name             = "Build_GCP_Image"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["CVEScanOutput"]
      output_artifacts = ["GCPOutput"]
      version          = "1"
      
      configuration = {
        ProjectName = aws_codebuild_project.golden_images.name
        EnvironmentVariables = jsonencode([
          {
            name  = "TARGET_PLATFORM"
            value = "gcp"
          }
        ])
      }
    }
  }
  
  stage {
    name = "Compliance_Check"
    
    action {
      name             = "CIS_Compliance_Scan"
      category         = "Test"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["OpenStackOutput", "AWSOutput", "GCPOutput"]
      output_artifacts = ["ComplianceOutput"]
      version          = "1"
      
      configuration = {
        ProjectName = aws_codebuild_project.compliance_scan.name
      }
    }
  }
  
  stage {
    name = "Deploy"
    
    action {
      name            = "Deploy_to_Registry"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeBuild"
      input_artifacts = ["ComplianceOutput"]
      version         = "1"
      
      configuration = {
        ProjectName = aws_codebuild_project.image_promotion.name
      }
    }
  }
  
  tags = local.common_tags
}

# CVE Scanning Project
resource "aws_codebuild_project" "cve_scan" {
  name         = "federation-cve-scan-${var.environment}"
  description  = "CVE scanning for golden images"
  service_role = aws_iam_role.codebuild_cve_scan.arn
  
  artifacts {
    type = "CODEPIPELINE"
  }
  
  environment {
    compute_type = "BUILD_GENERAL1_MEDIUM"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
    
    environment_variable {
      name  = "CVE_DATABASE_URL"
      value = var.cve_database_url
    }
    
    environment_variable {
      name  = "SEVERITY_THRESHOLD"
      value = "HIGH"
    }
  }
  
  source {
    type = "CODEPIPELINE"
    buildspec = file("${path.module}/configs/cve-scan-buildspec.yml")
  }
  
  tags = local.common_tags
}

# Compliance Scanning Project
resource "aws_codebuild_project" "compliance_scan" {
  name         = "federation-compliance-scan-${var.environment}"
  description  = "CIS compliance scanning for images"
  service_role = aws_iam_role.codebuild_compliance_scan.arn
  
  artifacts {
    type = "CODEPIPELINE"
  }
  
  environment {
    compute_type = "BUILD_GENERAL1_MEDIUM"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
    
    environment_variable {
      name  = "CIS_BENCHMARK_VERSION"
      value = "1.1.0"
    }
    
    environment_variable {
      name  = "COMPLIANCE_STANDARDS"
      value = "CIS,NIST-800-53,ISO-27001"
    }
  }
  
  source {
    type = "CODEPIPELINE"
    buildspec = file("${path.module}/configs/compliance-scan-buildspec.yml")
  }
  
  tags = local.common_tags
}

# Image Promotion Project
resource "aws_codebuild_project" "image_promotion" {
  name         = "federation-image-promotion-${var.environment}"
  description  = "Promote golden images to registries"
  service_role = aws_iam_role.codebuild_image_promotion.arn
  
  artifacts {
    type = "CODEPIPELINE"
  }
  
  environment {
    compute_type = "BUILD_GENERAL1_MEDIUM"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
    
    environment_variable {
      name  = "GLANCE_ENDPOINT"
      value = var.openstack_glance_endpoint
    }
    
    environment_variable {
      name  = "ECR_REGISTRY"
      value = var.aws_ecr_registry
    }
    
    environment_variable {
      name  = "GCR_REGISTRY"
      value = var.gcp_gcr_registry
    }
  }
  
  source {
    type = "CODEPIPELINE"
    buildspec = file("${path.module}/configs/image-promotion-buildspec.yml")
  }
  
  tags = local.common_tags
}

# Change Management with Evidence
resource "kubernetes_namespace" "change_management" {
  metadata {
    name = "change-management"
    labels = {
      "app.kubernetes.io/name" = "change-management"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "change_tracker" {
  name       = "change-tracker"
  chart      = "${path.module}/charts/change-tracker"
  namespace  = kubernetes_namespace.change_management.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/change-tracker-values.yaml", {
      git_repo        = var.gitops_repo_url
      cmdb_endpoint   = var.cmdb_endpoint
      vault_addr      = var.vault_addr
      sbom_generator  = "syft"
      environment     = var.environment
    })
  ]
}

# Control Plane Blue/Green Upgrade System
resource "openstack_compute_instance_v2" "control_plane_blue" {
  count = var.control_plane_blue_count
  
  name              = "control-plane-blue-${count.index + 1}-${var.environment}"
  image_id          = var.openstack_control_plane_image_id
  flavor_id         = var.openstack_control_plane_flavor_id
  key_pair          = openstack_compute_keypair_v2.control_plane.name
  security_groups   = [openstack_networking_secgroup_v2.control_plane.name]
  availability_zone = element(var.availability_zones, count.index)
  
  network {
    name = var.control_plane_network_name
  }
  
  metadata = {
    deployment_slot    = "blue"
    control_plane_role = "active"
    upgrade_group      = "control-plane"
    backup_enabled     = "true"
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/control-plane-init.sh", {
    deployment_slot = "blue"
    environment     = var.environment
    vault_addr      = var.vault_addr
    consul_addr     = var.consul_addr
  }))
  
  tags = [
    "deployment:blue",
    "role:control_plane",
    "environment:${var.environment}"
  ]
}

resource "openstack_compute_instance_v2" "control_plane_green" {
  count = var.control_plane_green_count
  
  name              = "control-plane-green-${count.index + 1}-${var.environment}"
  image_id          = var.openstack_control_plane_image_id
  flavor_id         = var.openstack_control_plane_flavor_id
  key_pair          = openstack_compute_keypair_v2.control_plane.name
  security_groups   = [openstack_networking_secgroup_v2.control_plane.name]
  availability_zone = element(var.availability_zones, count.index)
  
  network {
    name = var.control_plane_network_name
  }
  
  metadata = {
    deployment_slot    = "green"
    control_plane_role = "standby"
    upgrade_group      = "control-plane"
    backup_enabled     = "true"
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/control-plane-init.sh", {
    deployment_slot = "green"
    environment     = var.environment
    vault_addr      = var.vault_addr
    consul_addr     = var.consul_addr
  }))
  
  tags = [
    "deployment:green",
    "role:control_plane",
    "environment:${var.environment}"
  ]
}

# Zuul CI/CD for OpenStack Control Plane Upgrades
resource "kubernetes_namespace" "zuul" {
  metadata {
    name = "zuul"
    labels = {
      "app.kubernetes.io/name" = "zuul"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "zuul" {
  name       = "zuul"
  chart      = "${path.module}/charts/zuul"
  namespace  = kubernetes_namespace.zuul.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/zuul-values.yaml", {
      git_repo     = var.openstack_repo_url
      ansible_galaxy = var.ansible_galaxy_url
      environment  = var.environment
      scheduler_count = 3
      executor_count  = 5
      merger_count    = 2
    })
  ]
}

# Ansible Automation Platform for Control Plane Management
resource "kubernetes_config_map" "ansible_playbooks" {
  metadata {
    name      = "ansible-control-plane-playbooks"
    namespace = kubernetes_namespace.zuul.metadata[0].name
  }
  
  data = {
    "upgrade-control-plane.yml" = file("${path.module}/playbooks/upgrade-control-plane.yml")
    "blue-green-switch.yml"     = file("${path.module}/playbooks/blue-green-switch.yml")
    "canary-api-check.yml"      = file("${path.module}/playbooks/canary-api-check.yml")
    "rollback-control-plane.yml" = file("${path.module}/playbooks/rollback-control-plane.yml")
  }
}

# Load Balancer for Control Plane Blue/Green
resource "openstack_lb_loadbalancer_v2" "control_plane_lb" {
  name          = "control-plane-lb-${var.environment}"
  vip_subnet_id = var.control_plane_lb_subnet_id
  
  tags = [
    "service:control_plane_lb",
    "environment:${var.environment}"
  ]
}

resource "openstack_lb_pool_v2" "control_plane_blue" {
  name        = "control-plane-blue-pool"
  protocol    = "HTTPS"
  lb_method   = "ROUND_ROBIN"
  loadbalancer_id = openstack_lb_loadbalancer_v2.control_plane_lb.id
}

resource "openstack_lb_pool_v2" "control_plane_green" {
  name        = "control-plane-green-pool"
  protocol    = "HTTPS"
  lb_method   = "ROUND_ROBIN"
  loadbalancer_id = openstack_lb_loadbalancer_v2.control_plane_lb.id
}

# Health Monitors for Blue/Green Pools
resource "openstack_lb_monitor_v2" "control_plane_blue_monitor" {
  name           = "control-plane-blue-monitor"
  type           = "HTTPS"
  delay          = 30
  timeout        = 10
  max_retries    = 3
  url_path       = "/healthcheck"
  expected_codes = "200"
  pool_id        = openstack_lb_pool_v2.control_plane_blue.id
}

resource "openstack_lb_monitor_v2" "control_plane_green_monitor" {
  name           = "control-plane-green-monitor"
  type           = "HTTPS"
  delay          = 30
  timeout        = 10
  max_retries    = 3
  url_path       = "/healthcheck"
  expected_codes = "200"
  pool_id        = openstack_lb_pool_v2.control_plane_green.id
}

# Control Plane Members
resource "openstack_lb_member_v2" "control_plane_blue_members" {
  count = length(openstack_compute_instance_v2.control_plane_blue)
  
  pool_id       = openstack_lb_pool_v2.control_plane_blue.id
  address       = openstack_compute_instance_v2.control_plane_blue[count.index].access_ip_v4
  protocol_port = 443
  weight        = var.blue_deployment_active ? 100 : 0
}

resource "openstack_lb_member_v2" "control_plane_green_members" {
  count = length(openstack_compute_instance_v2.control_plane_green)
  
  pool_id       = openstack_lb_pool_v2.control_plane_green.id
  address       = openstack_compute_instance_v2.control_plane_green[count.index].access_ip_v4
  protocol_port = 443
  weight        = var.blue_deployment_active ? 0 : 100
}

# Drift Detection with Terraform Cloud/Enterprise
resource "tfe_workspace" "federation" {
  name                          = "federation-${var.environment}"
  organization                  = var.tfe_organization
  description                   = "Federation infrastructure for ${var.environment}"
  auto_apply                    = false
  file_triggers_enabled         = true
  queue_all_runs               = false
  speculative_enabled          = true
  structured_run_output_enabled = true
  
  terraform_version = var.terraform_version
  
  working_directory = "terraform/${var.environment}"
  
  vcs_repo {
    identifier     = var.gitops_repo_full_name
    branch         = "main"
    oauth_token_id = var.vcs_oauth_token_id
  }
  
  tag_names = [
    "federation",
    "infrastructure",
    var.environment
  ]
}

# Drift Detection Schedule
resource "tfe_run_trigger" "drift_detection" {
  workspace_id    = tfe_workspace.federation.id
  sourceable_id   = var.drift_detection_workspace_id
  sourceable_type = "workspace"
}

# Outputs
output "gitops_configuration" {
  description = "GitOps configuration details"
  value = {
    argocd_namespace    = kubernetes_namespace.argocd.metadata[0].name
    atlantis_namespace  = kubernetes_namespace.atlantis.metadata[0].name
    flux_namespace      = kubernetes_namespace.flux_system.metadata[0].name
    zuul_namespace      = kubernetes_namespace.zuul.metadata[0].name
  }
}

output "golden_images_pipeline" {
  description = "Golden images pipeline configuration"
  value = {
    codepipeline_name   = aws_codepipeline.golden_images.name
    codebuild_projects = [
      aws_codebuild_project.golden_images.name,
      aws_codebuild_project.cve_scan.name,
      aws_codebuild_project.compliance_scan.name,
      aws_codebuild_project.image_promotion.name
    ]
  }
}

output "control_plane_blue_green" {
  description = "Control plane blue/green deployment configuration"
  value = {
    blue_instances  = [for instance in openstack_compute_instance_v2.control_plane_blue : instance.id]
    green_instances = [for instance in openstack_compute_instance_v2.control_plane_green : instance.id]
    load_balancer_id = openstack_lb_loadbalancer_v2.control_plane_lb.id
    active_deployment = var.blue_deployment_active ? "blue" : "green"
  }
}

output "change_management" {
  description = "Change management configuration"
  value = {
    change_tracker_namespace = kubernetes_namespace.change_management.metadata[0].name
    tfe_workspace_id        = tfe_workspace.federation.id
  }
}
