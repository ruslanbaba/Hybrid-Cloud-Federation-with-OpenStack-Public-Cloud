# Smart Workload Placement & Autoscaling Engine
# Policy-driven scheduling, predictive scaling, spot/preemptible strategy, K8s federation

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.50"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

# Policy-Driven Scheduler Configuration
resource "openstack_compute_flavor_v2" "policy_flavors" {
  for_each = var.workload_policies
  
  name      = "policy-${each.key}-${var.environment}"
  ram       = each.value.memory_mb
  vcpus     = each.value.vcpus
  disk      = each.value.disk_gb
  is_public = true
  
  extra_specs = {
    "hw:cpu_policy"             = each.value.cpu_policy
    "hw:cpu_thread_policy"      = each.value.cpu_thread_policy
    "hw:numa_nodes"             = each.value.numa_nodes
    "quota:cpu_shares"          = each.value.cpu_shares
    "quota:memory_shares"       = each.value.memory_shares
    "aggregate_instance_extra_specs:slo_tier" = each.value.slo_tier
    "aggregate_instance_extra_specs:cost_tier" = each.value.cost_tier
    "aggregate_instance_extra_specs:carbon_zone" = each.value.carbon_zone
    "aggregate_instance_extra_specs:data_residency" = each.value.data_residency
    "placement:scheduler_hints" = jsonencode({
      slo_requirements    = each.value.slo_requirements
      cost_optimization   = each.value.cost_optimization
      data_gravity        = each.value.data_gravity
      residency_requirements = each.value.residency_requirements
      carbon_awareness    = each.value.carbon_awareness
    })
  }
  
  tags = [
    "policy:${each.key}",
    "slo:${each.value.slo_tier}",
    "cost:${each.value.cost_tier}",
    "carbon:${each.value.carbon_zone}"
  ]
}

# Host Aggregates for Policy-Based Placement
resource "openstack_compute_aggregate_v2" "slo_aggregates" {
  for_each = var.slo_tiers
  
  name = "slo-${each.key}-${var.environment}"
  zone = "nova:slo-${each.key}"
  
  hosts = each.value.compute_hosts
  
  metadata = {
    slo_tier           = each.key
    latency_target_ms  = each.value.latency_target_ms
    throughput_target  = each.value.throughput_target
    availability_sla   = each.value.availability_sla
    burst_capable      = each.value.burst_capable
    cost_multiplier    = each.value.cost_multiplier
  }
}

# Cost-Optimized Aggregates
resource "openstack_compute_aggregate_v2" "cost_aggregates" {
  for_each = var.cost_tiers
  
  name = "cost-${each.key}-${var.environment}"
  zone = "nova:cost-${each.key}"
  
  hosts = each.value.compute_hosts
  
  metadata = {
    cost_tier          = each.key
    cost_per_hour      = each.value.cost_per_hour
    preemptible        = each.value.preemptible
    spot_eligible      = each.value.spot_eligible
    savings_target     = each.value.savings_target
  }
}

# Carbon-Aware Aggregates
resource "openstack_compute_aggregate_v2" "carbon_aggregates" {
  for_each = var.carbon_zones
  
  name = "carbon-${each.key}-${var.environment}"
  zone = "nova:carbon-${each.key}"
  
  hosts = each.value.compute_hosts
  
  metadata = {
    carbon_zone        = each.key
    carbon_intensity   = each.value.carbon_intensity_gco2_kwh
    renewable_percent  = each.value.renewable_percent
    green_hours        = jsonencode(each.value.green_hours)
    carbon_budget      = each.value.carbon_budget_kg
  }
}

# Data Residency Aggregates
resource "openstack_compute_aggregate_v2" "residency_aggregates" {
  for_each = var.residency_zones
  
  name = "residency-${each.key}-${var.environment}"
  zone = "nova:residency-${each.key}"
  
  hosts = each.value.compute_hosts
  
  metadata = {
    residency_zone     = each.key
    jurisdiction       = each.value.jurisdiction
    compliance_standards = jsonencode(each.value.compliance_standards)
    data_sovereignty   = each.value.data_sovereignty
    encryption_required = each.value.encryption_required
  }
}

# Custom Scheduler Filter for Policy-Based Placement
resource "openstack_compute_service_v2" "policy_scheduler" {
  binary = "nova-scheduler"
  host   = "policy-scheduler-${var.environment}"
  
  metadata = {
    scheduler_filters = jsonencode([
      "RetryFilter",
      "AvailabilityZoneFilter",
      "ComputeFilter",
      "ComputeCapabilitiesFilter",
      "ImagePropertiesFilter",
      "ServerGroupAntiAffinityFilter",
      "ServerGroupAffinityFilter",
      "SLOAffinityFilter",
      "CostOptimizationFilter",
      "CarbonAwarenessFilter",
      "DataResidencyFilter",
      "DataGravityFilter"
    ])
    
    scheduler_weights = jsonencode({
      "ram_weight_multiplier"     = 1.0
      "disk_weight_multiplier"    = 1.0
      "io_ops_weight_multiplier"  = 1.0
      "slo_weight_multiplier"     = 2.0
      "cost_weight_multiplier"    = 1.5
      "carbon_weight_multiplier"  = 1.2
      "locality_weight_multiplier" = 1.8
    })
  }
}

# Predictive Autoscaling with Event Bus
resource "aws_kinesis_stream" "demand_forecasting" {
  name             = "federation-demand-forecasting-${var.environment}"
  shard_count      = 3
  retention_period = 168  # 7 days
  
  shard_level_metrics = [
    "IncomingRecords",
    "OutgoingRecords"
  ]
  
  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.federation.arn
  
  tags = local.common_tags
}

# Lambda Function for Demand Prediction
resource "aws_lambda_function" "demand_predictor" {
  filename         = "demand_predictor.zip"
  function_name    = "federation-demand-predictor-${var.environment}"
  role            = aws_iam_role.lambda_demand_predictor.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.demand_predictor.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 1024
  
  environment {
    variables = {
      KINESIS_STREAM = aws_kinesis_stream.demand_forecasting.name
      OPENSTACK_ENDPOINT = var.openstack_endpoint
      PREDICTION_HORIZON = "3600"  # 1 hour
      MODEL_TYPE = "ARIMA"
    }
  }
  
  tags = local.common_tags
}

# EventBridge Rule for Demand Forecasting
resource "aws_cloudwatch_event_rule" "demand_forecasting" {
  name                = "federation-demand-forecasting-${var.environment}"
  description         = "Trigger demand forecasting every 15 minutes"
  schedule_expression = "rate(15 minutes)"
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "demand_forecasting" {
  rule      = aws_cloudwatch_event_rule.demand_forecasting.name
  target_id = "DemandForecastingTarget"
  arn       = aws_lambda_function.demand_predictor.arn
}

# Pre-warming Lambda for Capacity Management
resource "aws_lambda_function" "capacity_prewarmer" {
  filename         = "capacity_prewarmer.zip"
  function_name    = "federation-capacity-prewarmer-${var.environment}"
  role            = aws_iam_role.lambda_prewarmer.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.capacity_prewarmer.output_base64sha256
  runtime         = "python3.11"
  timeout         = 900  # 15 minutes
  memory_size     = 2048
  
  environment {
    variables = {
      OPENSTACK_ENDPOINT = var.openstack_endpoint
      AWS_REGION = var.aws_region
      GCP_PROJECT = var.gcp_project_id
      AZURE_SUBSCRIPTION = var.azure_subscription_id
      PREWARM_THRESHOLD = "0.7"  # 70% predicted utilization
      SCALE_FACTOR = "1.2"       # 20% buffer
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.prewarming_dlq.arn
  }
  
  tags = local.common_tags
}

# Spot/Preemptible Instance Strategy
resource "openstack_compute_instance_v2" "spot_workers" {
  count = var.spot_instance_count
  
  name              = "spot-worker-${count.index + 1}-${var.environment}"
  image_id          = data.openstack_images_image_v2.worker_image.id
  flavor_id         = openstack_compute_flavor_v2.policy_flavors["cost-optimized"].id
  key_pair          = openstack_compute_keypair_v2.workers.name
  security_groups   = [openstack_networking_secgroup_v2.workers.name]
  availability_zone = var.spot_availability_zone
  
  network {
    name = data.openstack_networking_network_v2.workers.name
  }
  
  # Spot instance metadata
  metadata = {
    spot_instance     = "true"
    preemptible       = "true"
    interruption_handler = "enabled"
    checkpoint_enabled = "true"
    workload_tier     = "batch"
    cost_optimization = "aggressive"
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/spot-worker-init.sh", {
    checkpoint_interval = 300  # 5 minutes
    workload_type      = "batch"
    interrupt_handler  = "/opt/spot-interrupt-handler.sh"
  }))
  
  tags = [
    "instance_type:spot",
    "cost_tier:optimized",
    "workload:batch"
  ]
}

# AWS Auto Scaling for Spot Instances
resource "aws_autoscaling_group" "spot_workers" {
  name                = "federation-spot-workers-${var.environment}"
  vpc_zone_identifier = data.aws_subnets.private.ids
  target_group_arns   = [aws_lb_target_group.burst_workers.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  min_size         = 0
  max_size         = var.max_spot_instances
  desired_capacity = var.desired_spot_instances
  
  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.spot_workers.id
        version           = "$Latest"
      }
      
      override {
        instance_type = "m5.large"
      }
      override {
        instance_type = "m5.xlarge"
      }
      override {
        instance_type = "c5.large"
      }
    }
    
    instances_distribution {
      on_demand_base_capacity                  = 1
      on_demand_percentage_above_base_capacity = 0
      spot_allocation_strategy                 = "diversified"
      spot_instance_pools                      = 3
      spot_max_price                          = var.spot_max_price
    }
  }
  
  tag {
    key                 = "Name"
    value               = "federation-spot-worker-${var.environment}"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "InstanceType"
    value               = "spot"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "WorkloadTier"
    value               = "burst"
    propagate_at_launch = true
  }
}

# Launch Template for Spot Instances
resource "aws_launch_template" "spot_workers" {
  name_prefix   = "federation-spot-${var.environment}-"
  image_id      = data.aws_ami.worker_ami.id
  instance_type = "m5.large"
  key_name      = aws_key_pair.workers.key_name
  
  vpc_security_group_ids = [aws_security_group.workers.id]
  
  user_data = base64encode(templatefile("${path.module}/templates/aws-spot-worker-init.sh", {
    environment = var.environment
    cluster_name = "federation-cluster"
    spot_interruption_handler = true
  }))
  
  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price = var.spot_max_price
      spot_instance_type = "one-time"
    }
  }
  
  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "federation-spot-worker-${var.environment}"
      InstanceType = "spot"
    })
  }
}

# Kubernetes Federation with Magnum
resource "openstack_containerinfra_cluster_v1" "k8s_primary" {
  name                = "k8s-primary-${var.environment}"
  cluster_template_id = openstack_containerinfra_clustertemplate_v1.k8s_template.id
  master_count        = 3
  node_count          = var.k8s_primary_node_count
  keypair             = openstack_compute_keypair_v2.k8s.name
  
  labels = {
    "cloud_provider_enabled"     = "true"
    "auto_healing_enabled"       = "true"
    "auto_scaling_enabled"       = "true"
    "monitoring_enabled"         = "true"
    "federation_enabled"         = "true"
    "multi_cloud_bursting"       = "true"
    "cluster_autoscaler_enabled" = "true"
    "kube_tag"                   = "v1.28.2"
  }
  
  tags = [
    "cluster:primary",
    "federation:enabled",
    "environment:${var.environment}"
  ]
}

resource "openstack_containerinfra_cluster_v1" "k8s_burst" {
  name                = "k8s-burst-${var.environment}"
  cluster_template_id = openstack_containerinfra_clustertemplate_v1.k8s_template.id
  master_count        = 1
  node_count          = var.k8s_burst_node_count
  keypair             = openstack_compute_keypair_v2.k8s.name
  
  labels = {
    "cloud_provider_enabled"     = "true"
    "auto_healing_enabled"       = "true"
    "auto_scaling_enabled"       = "true"
    "monitoring_enabled"         = "true"
    "federation_enabled"         = "true"
    "burst_cluster"              = "true"
    "cluster_autoscaler_enabled" = "true"
    "kube_tag"                   = "v1.28.2"
    "burst_only"                 = "true"
  }
  
  tags = [
    "cluster:burst",
    "federation:enabled",
    "environment:${var.environment}"
  ]
}

# Kubernetes Cluster Template
resource "openstack_containerinfra_clustertemplate_v1" "k8s_template" {
  name                = "federation-k8s-template-${var.environment}"
  image               = data.openstack_containerinfra_clustertemplate_v1.k8s_image.image
  coe                 = "kubernetes"
  flavor              = data.openstack_compute_flavor_v2.k8s_node.name
  master_flavor       = data.openstack_compute_flavor_v2.k8s_master.name
  dns_nameserver      = var.dns_nameserver
  docker_volume_size  = 50
  server_type         = "vm"
  network_driver      = "calico"
  volume_driver       = "cinder"
  
  labels = {
    "auto_healing_enabled"       = "true"
    "auto_scaling_enabled"       = "true"
    "cloud_provider_enabled"     = "true"
    "monitoring_enabled"         = "true"
    "ingress_controller"         = "nginx"
    "cluster_autoscaler_enabled" = "true"
    "calico_ipv4pool"           = var.k8s_pod_cidr
  }
  
  tags = [
    "template:kubernetes",
    "federation:ready"
  ]
}

# EKS Cluster for Multi-Cloud Federation
resource "aws_eks_cluster" "federation" {
  name     = "federation-eks-${var.environment}"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.28"
  
  vpc_config {
    subnet_ids              = data.aws_subnets.private.ids
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.eks_public_access_cidrs
  }
  
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }
  
  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]
  
  tags = merge(local.common_tags, {
    Name = "federation-eks-${var.environment}"
    "kubernetes.io/cluster/federation-eks-${var.environment}" = "owned"
  })
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_service_policy,
  ]
}

# EKS Node Group with Mixed Instance Types
resource "aws_eks_node_group" "federation" {
  cluster_name    = aws_eks_cluster.federation.name
  node_group_name = "federation-nodes-${var.environment}"
  node_role_arn   = aws_iam_role.eks_node_group.arn
  subnet_ids      = data.aws_subnets.private.ids
  
  capacity_type = "SPOT"
  
  scaling_config {
    desired_size = var.eks_desired_nodes
    max_size     = var.eks_max_nodes
    min_size     = var.eks_min_nodes
  }
  
  instance_types = ["m5.large", "m5.xlarge", "c5.large", "c5.xlarge"]
  
  remote_access {
    ec2_ssh_key = aws_key_pair.workers.key_name
    source_security_group_ids = [aws_security_group.eks_remote_access.id]
  }
  
  labels = {
    "cluster"     = "federation"
    "environment" = var.environment
    "node-type"   = "spot"
    "burst-capable" = "true"
  }
  
  taint {
    key    = "burst-workload"
    value  = "true"
    effect = "NO_SCHEDULE"
  }
  
  tags = merge(local.common_tags, {
    Name = "federation-eks-nodes-${var.environment}"
    "kubernetes.io/cluster/federation-eks-${var.environment}" = "owned"
  })
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry_policy,
  ]
}

# GKE Cluster for Multi-Cloud Federation
resource "google_container_cluster" "federation" {
  name     = "federation-gke-${var.environment}"
  location = var.gcp_region
  
  remove_default_node_pool = true
  initial_node_count       = 1
  
  network    = google_compute_network.federation.name
  subnetwork = google_compute_subnetwork.gke.name
  
  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_ipv4_cidr_block  = var.gke_cluster_cidr
    services_ipv4_cidr_block = var.gke_services_cidr
  }
  
  workload_identity_config {
    workload_pool = "${var.gcp_project_id}.svc.id.goog"
  }
  
  cluster_autoscaling {
    enabled = true
    resource_limits {
      resource_type = "cpu"
      minimum       = 1
      maximum       = 100
    }
    resource_limits {
      resource_type = "memory"
      minimum       = 2
      maximum       = 400
    }
  }
  
  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
    cluster_autoscaling {
      enabled = true
    }
  }
  
  network_policy {
    enabled = true
  }
  
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = var.gke_master_cidr
  }
  
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}

# GKE Node Pool with Preemptible Instances
resource "google_container_node_pool" "federation_preemptible" {
  name       = "federation-preemptible-${var.environment}"
  location   = var.gcp_region
  cluster    = google_container_cluster.federation.name
  node_count = var.gke_preemptible_node_count
  
  autoscaling {
    min_node_count = 0
    max_node_count = var.gke_max_preemptible_nodes
  }
  
  node_config {
    preemptible  = true
    machine_type = "e2-medium"
    
    metadata = {
      disable-legacy-endpoints = "true"
      burst-workload = "true"
    }
    
    labels = {
      cluster = "federation"
      environment = var.environment
      node-type = "preemptible"
      burst-capable = "true"
    }
    
    taint {
      key    = "burst-workload"
      value  = "true"
      effect = "NO_SCHEDULE"
    }
    
    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
  
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# Cluster API for Cross-Cloud Management
resource "helm_release" "cluster_api" {
  name             = "cluster-api"
  repository       = "https://kubernetes-sigs.github.io/cluster-api-operator"
  chart            = "cluster-api-operator"
  namespace        = "cluster-api-system"
  create_namespace = true
  version          = "0.8.0"
  
  values = [
    templatefile("${path.module}/templates/cluster-api-values.yaml", {
      openstack_cluster = openstack_containerinfra_cluster_v1.k8s_primary.name
      aws_cluster       = aws_eks_cluster.federation.name
      gcp_cluster       = google_container_cluster.federation.name
      environment       = var.environment
    })
  ]
  
  depends_on = [
    openstack_containerinfra_cluster_v1.k8s_primary,
    aws_eks_cluster.federation,
    google_container_cluster.federation
  ]
}

# ExternalDNS for Cross-Cloud Service Discovery
resource "helm_release" "external_dns" {
  name             = "external-dns"
  repository       = "https://kubernetes-sigs.github.io/external-dns"
  chart            = "external-dns"
  namespace        = "external-dns"
  create_namespace = true
  version          = "1.13.1"
  
  values = [
    templatefile("${path.module}/templates/external-dns-values.yaml", {
      aws_region     = var.aws_region
      gcp_project    = var.gcp_project_id
      domain_name    = var.domain_name
      environment    = var.environment
    })
  ]
}

# Data sources
data "openstack_images_image_v2" "worker_image" {
  name        = "Fedora CoreOS"
  most_recent = true
}

data "openstack_networking_network_v2" "workers" {
  name = "workers-network-${var.environment}"
}

data "openstack_containerinfra_clustertemplate_v1" "k8s_image" {
  name = "kubernetes-v1.28.2"
}

data "openstack_compute_flavor_v2" "k8s_node" {
  name = "m1.medium"
}

data "openstack_compute_flavor_v2" "k8s_master" {
  name = "m1.large"
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.federation.id]
  }
  
  tags = {
    Type = "private"
  }
}

data "aws_ami" "worker_ami" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amazon-linux-2-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "archive_file" "demand_predictor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/demand_predictor"
  output_path = "demand_predictor.zip"
}

data "archive_file" "capacity_prewarmer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/capacity_prewarmer"
  output_path = "capacity_prewarmer.zip"
}

# Outputs
output "policy_scheduler_config" {
  description = "Policy-driven scheduler configuration"
  value = {
    flavors = {
      for k, v in openstack_compute_flavor_v2.policy_flavors : k => v.id
    }
    aggregates = {
      slo = {
        for k, v in openstack_compute_aggregate_v2.slo_aggregates : k => v.id
      }
      cost = {
        for k, v in openstack_compute_aggregate_v2.cost_aggregates : k => v.id
      }
      carbon = {
        for k, v in openstack_compute_aggregate_v2.carbon_aggregates : k => v.id
      }
      residency = {
        for k, v in openstack_compute_aggregate_v2.residency_aggregates : k => v.id
      }
    }
  }
}

output "predictive_scaling_config" {
  description = "Predictive scaling configuration"
  value = {
    kinesis_stream_name = aws_kinesis_stream.demand_forecasting.name
    predictor_function  = aws_lambda_function.demand_predictor.function_name
    prewarmer_function  = aws_lambda_function.capacity_prewarmer.function_name
  }
}

output "kubernetes_federation" {
  description = "Kubernetes federation cluster information"
  value = {
    openstack_cluster_id = openstack_containerinfra_cluster_v1.k8s_primary.id
    aws_cluster_name     = aws_eks_cluster.federation.name
    gcp_cluster_name     = google_container_cluster.federation.name
    cluster_api_namespace = "cluster-api-system"
  }
}

output "spot_preemptible_config" {
  description = "Spot and preemptible instance configuration"
  value = {
    openstack_spot_count = length(openstack_compute_instance_v2.spot_workers)
    aws_asg_name        = aws_autoscaling_group.spot_workers.name
    gcp_node_pool_name  = google_container_node_pool.federation_preemptible.name
  }
}
