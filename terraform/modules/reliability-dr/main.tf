# Enterprise Reliability & Disaster Recovery Configuration
# Active/Active bursting with global DNS failover

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.50"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Multi-Region OpenStack Configuration
locals {
  openstack_regions = {
    primary = {
      region = "RegionOne"
      endpoint = var.openstack_primary_endpoint
      priority = 100
      weight = 70
    }
    secondary = {
      region = "RegionTwo"
      endpoint = var.openstack_secondary_endpoint
      priority = 200
      weight = 30
    }
  }
  
  public_cloud_regions = {
    aws_primary = {
      provider = "aws"
      region = "us-east-1"
      priority = 300
      weight = 0  # Only activated during burst
    }
    gcp_primary = {
      provider = "gcp"
      region = "us-central1"
      priority = 400
      weight = 0
    }
    azure_primary = {
      provider = "azure"
      region = "East US"
      priority = 500
      weight = 0
    }
  }
}

# Global DNS with Health-Based Failover (OpenStack Designate)
resource "openstack_dns_zone_v2" "federation_global" {
  name        = "federation.global."
  description = "Global federation DNS zone with health-based routing"
  type        = "PRIMARY"
  
  attributes = {
    routing_policy = "geo_health"
  }
  
  tags = local.common_tags
}

# Primary Region DNS Record
resource "openstack_dns_recordset_v2" "primary_region" {
  zone_id = openstack_dns_zone_v2.federation_global.id
  name    = "api.federation.global."
  type    = "A"
  ttl     = 60
  
  records = [data.openstack_networking_floatingip_v2.primary_lb.address]
  
  # Health check configuration
  metadata = {
    health_check_url      = "https://${data.openstack_networking_floatingip_v2.primary_lb.address}/health"
    health_check_interval = "30"
    health_check_timeout  = "10"
    failure_threshold     = "3"
    weight               = local.openstack_regions.primary.weight
    priority             = local.openstack_regions.primary.priority
  }
}

# Secondary Region DNS Record
resource "openstack_dns_recordset_v2" "secondary_region" {
  zone_id = openstack_dns_zone_v2.federation_global.id
  name    = "api.federation.global."
  type    = "A"
  ttl     = 60
  
  records = [data.openstack_networking_floatingip_v2.secondary_lb.address]
  
  metadata = {
    health_check_url      = "https://${data.openstack_networking_floatingip_v2.secondary_lb.address}/health"
    health_check_interval = "30"
    health_check_timeout  = "10"
    failure_threshold     = "3"
    weight               = local.openstack_regions.secondary.weight
    priority             = local.openstack_regions.secondary.priority
  }
}

# AWS Route 53 Health Checks and Failover
resource "aws_route53_health_check" "openstack_primary" {
  fqdn                            = data.openstack_networking_floatingip_v2.primary_lb.address
  port                            = 443
  type                            = "HTTPS"
  resource_path                   = "/health"
  failure_threshold               = 3
  request_interval                = 30
  insufficient_data_health_status = "Failure"
  
  tags = merge(local.common_tags, {
    Name = "OpenStack Primary Health Check"
    Region = "RegionOne"
  })
}

resource "aws_route53_health_check" "openstack_secondary" {
  fqdn                            = data.openstack_networking_floatingip_v2.secondary_lb.address
  port                            = 443
  type                            = "HTTPS"
  resource_path                   = "/health"
  failure_threshold               = 3
  request_interval                = 30
  insufficient_data_health_status = "Failure"
  
  tags = merge(local.common_tags, {
    Name = "OpenStack Secondary Health Check"
    Region = "RegionTwo"
  })
}

# Route 53 Hosted Zone for Global DNS
resource "aws_route53_zone" "federation_global" {
  name = "federation.global"
  
  tags = local.common_tags
}

# Weighted routing with health checks
resource "aws_route53_record" "primary_weighted" {
  zone_id = aws_route53_zone.federation_global.zone_id
  name    = "api.federation.global"
  type    = "A"
  ttl     = 60
  
  weighted_routing_policy {
    weight = local.openstack_regions.primary.weight
  }
  
  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.openstack_primary.id
  records         = [data.openstack_networking_floatingip_v2.primary_lb.address]
}

resource "aws_route53_record" "secondary_weighted" {
  zone_id = aws_route53_zone.federation_global.zone_id
  name    = "api.federation.global"
  type    = "A"
  ttl     = 60
  
  weighted_routing_policy {
    weight = local.openstack_regions.secondary.weight
  }
  
  set_identifier  = "secondary"
  health_check_id = aws_route53_health_check.openstack_secondary.id
  records         = [data.openstack_networking_floatingip_v2.secondary_lb.address]
}

# Cross-Cloud State Continuity - Glance Multi-Store Configuration
resource "openstack_images_image_v2" "golden_images" {
  for_each = var.golden_images
  
  name             = each.value.name
  image_source_url = each.value.source_url
  container_format = "bare"
  disk_format      = "qcow2"
  
  # Multi-store configuration
  stores = ["swift", "s3", "gcs"]
  
  properties = {
    os_type           = each.value.os_type
    os_version        = each.value.os_version
    architecture      = each.value.architecture
    backup_location   = "s3://federation-images-backup/${each.key}"
    gcs_backup        = "gs://federation-images-gcs/${each.key}"
    replication_policy = "async"
    rpo_minutes       = "15"
    rto_minutes       = "5"
  }
  
  tags = [
    "environment:${var.environment}",
    "backup:enabled",
    "replication:multi-cloud"
  ]
}

# Cinder Volume Replication Configuration
resource "openstack_blockstorage_volume_type_v3" "replicated" {
  name        = "replicated-ssd"
  description = "SSD volumes with cross-cloud replication"
  
  extra_specs = {
    "volume_backend_name"           = "ceph-ssd"
    "replication_enabled"           = "True"
    "replication:type"              = "async"
    "replication:rpo_minutes"       = "30"
    "replication:rto_minutes"       = "10"
    "replication:target_backend"    = "aws-ebs"
    "replication:secondary_backend" = "gcp-pd"
  }
}

# Aurora Global Database for Cross-Region Replication
resource "aws_rds_global_cluster" "federation" {
  global_cluster_identifier = "federation-global-${var.environment}"
  engine                    = "aurora-mysql"
  engine_version            = "8.0.mysql_aurora.3.02.0"
  database_name             = "federation"
  deletion_protection       = true
  
  tags = local.common_tags
}

resource "aws_rds_cluster" "primary" {
  cluster_identifier     = "federation-primary-${var.environment}"
  global_cluster_identifier = aws_rds_global_cluster.federation.id
  engine                 = aws_rds_global_cluster.federation.engine
  engine_version         = aws_rds_global_cluster.federation.engine_version
  database_name          = aws_rds_global_cluster.federation.database_name
  
  backup_retention_period = 7
  preferred_backup_window = "03:00-04:00"
  backup_window          = "03:00-04:00"
  
  kms_key_id        = aws_kms_key.federation.arn
  storage_encrypted = true
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.federation.name
  
  tags = local.common_tags
}

resource "aws_rds_cluster" "secondary" {
  provider = aws.secondary
  
  cluster_identifier        = "federation-secondary-${var.environment}"
  global_cluster_identifier = aws_rds_global_cluster.federation.id
  engine                    = aws_rds_global_cluster.federation.engine
  engine_version            = aws_rds_global_cluster.federation.engine_version
  
  kms_key_id        = aws_kms_key.federation_secondary.arn
  storage_encrypted = true
  
  vpc_security_group_ids = [aws_security_group.rds_secondary.id]
  db_subnet_group_name   = aws_db_subnet_group.federation_secondary.name
  
  tags = local.common_tags
}

# Masakari Configuration for Instance HA
resource "openstack_compute_service_v2" "masakari" {
  binary  = "nova-compute"
  host    = "masakari-host"
  disabled_reason = "Masakari Instance HA Service"
  
  # Masakari segment configuration
  metadata = {
    masakari_segment_id = "auto-recovery-segment"
    recovery_method     = "auto"
    failure_detection   = "libvirt"
    notification_driver = "masakari"
  }
}

# Senlin Cluster Autoscaling Policies
resource "openstack_clustering_profile_v1" "burst_profile" {
  name = "burst-worker-profile"
  spec = jsonencode({
    type    = "os.nova.server"
    version = "1.0"
    properties = {
      flavor    = "m1.large"
      image     = data.openstack_images_image_v2.ubuntu.id
      networks  = [{ network = data.openstack_networking_network_v2.burst_network.id }]
      user_data = base64encode(templatefile("${path.module}/templates/burst-node-init.sh", {
        cluster_type = "burst"
        environment  = var.environment
      }))
      metadata = {
        burst_enabled = "true"
        auto_scaling  = "true"
      }
    }
  })
}

resource "openstack_clustering_cluster_v1" "burst_cluster" {
  name            = "burst-cluster-${var.environment}"
  profile_id      = openstack_clustering_profile_v1.burst_profile.id
  desired_capacity = 3
  min_size        = 1
  max_size        = 20
  timeout         = 3600
  
  metadata = {
    burst_threshold = "80"
    scale_cooldown  = "300"
  }
}

resource "openstack_clustering_policy_v1" "scaling_policy" {
  name = "burst-scaling-policy"
  spec = jsonencode({
    type    = "senlin.policy.scaling"
    version = "1.0"
    properties = {
      event         = "CLUSTER_SCALE_OUT"
      adjustment = {
        type          = "CHANGE_IN_CAPACITY"
        number        = 2
        min_step      = 1
        best_effort   = true
        cooldown      = 300
      }
    }
  })
}

# Nova Cells v2 Configuration for Control Plane Scaling
resource "openstack_compute_aggregate_v2" "cell1" {
  name = "cell1-${var.environment}"
  zone = "nova:cell1"
  
  hosts = var.cell1_compute_hosts
  
  metadata = {
    cell_name    = "cell1"
    cell_type    = "compute"
    burst_enabled = "true"
  }
}

resource "openstack_compute_aggregate_v2" "cell2" {
  name = "cell2-${var.environment}"
  zone = "nova:cell2"
  
  hosts = var.cell2_compute_hosts
  
  metadata = {
    cell_name     = "cell2"
    cell_type     = "burst"
    burst_enabled = "true"
    burst_priority = "high"
  }
}

# Backup-as-Code with OpenStack Freezer
resource "openstack_objectstorage_container_v1" "backup_container" {
  name = "federation-backups-${var.environment}"
  
  metadata = {
    backup_policy    = "daily"
    retention_days   = "30"
    encryption       = "true"
    replication      = "cross-cloud"
  }
}

# AWS Backup Configuration
resource "aws_backup_vault" "federation" {
  name        = "federation-backup-vault-${var.environment}"
  kms_key_arn = aws_kms_key.backup.arn
  
  tags = local.common_tags
}

resource "aws_backup_plan" "federation" {
  name = "federation-backup-plan-${var.environment}"
  
  rule {
    rule_name         = "daily_backups"
    target_vault_name = aws_backup_vault.federation.name
    schedule          = "cron(0 5 ? * * *)"  # Daily at 5 AM UTC
    
    start_window      = 480  # 8 hours
    completion_window = 10080  # 7 days
    
    recovery_point_tags = merge(local.common_tags, {
      BackupType = "Automated"
      Schedule   = "Daily"
    })
    
    lifecycle {
      cold_storage_after = 30
      delete_after       = 365
    }
    
    copy_action {
      destination_vault_arn = aws_backup_vault.federation_secondary.arn
      
      lifecycle {
        cold_storage_after = 30
        delete_after       = 365
      }
    }
  }
  
  rule {
    rule_name         = "continuous_backups"
    target_vault_name = aws_backup_vault.federation.name
    schedule          = "cron(0 */6 ? * * *)"  # Every 6 hours
    
    recovery_point_tags = merge(local.common_tags, {
      BackupType = "Continuous"
      RPO        = "6hours"
    })
    
    lifecycle {
      delete_after = 7
    }
  }
  
  tags = local.common_tags
}

# Backup Selection for Tagged Resources
resource "aws_backup_selection" "federation" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "federation-backup-selection"
  plan_id      = aws_backup_plan.federation.id
  
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "Required"
  }
  
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Environment"
    value = var.environment
  }
}

# Automated Failover Runbooks
resource "aws_ssm_document" "failover_runbook" {
  name          = "FederationFailoverRunbook"
  document_type = "Automation"
  document_format = "YAML"
  
  content = templatefile("${path.module}/runbooks/failover-automation.yaml", {
    environment = var.environment
    region     = var.aws_region
  })
  
  tags = local.common_tags
}

# DR Testing Automation
resource "aws_events_rule" "dr_testing" {
  name                = "federation-dr-testing-${var.environment}"
  description         = "Trigger DR testing monthly"
  schedule_expression = "cron(0 6 1 * ? *)"  # First day of month at 6 AM
  
  tags = local.common_tags
}

resource "aws_events_target" "dr_testing" {
  rule      = aws_events_rule.dr_testing.name
  target_id = "TriggerDRTesting"
  arn       = aws_ssm_document.failover_runbook.arn
  role_arn  = aws_iam_role.dr_automation.arn
  
  input = jsonencode({
    test_mode = true
    environment = var.environment
    rto_target_minutes = 10
    rpo_target_minutes = 15
  })
}

# Data sources for existing resources
data "openstack_networking_floatingip_v2" "primary_lb" {
  description = "Primary region load balancer floating IP"
}

data "openstack_networking_floatingip_v2" "secondary_lb" {
  description = "Secondary region load balancer floating IP"
}

data "openstack_images_image_v2" "ubuntu" {
  name        = "Ubuntu 20.04 LTS"
  most_recent = true
}

data "openstack_networking_network_v2" "burst_network" {
  name = "burst-network-${var.environment}"
}

# Outputs for integration
output "global_dns_zone" {
  description = "Global DNS zone for federation"
  value = {
    openstack = openstack_dns_zone_v2.federation_global.name
    aws       = aws_route53_zone.federation_global.name
  }
}

output "backup_configuration" {
  description = "Backup configuration details"
  value = {
    openstack_container = openstack_objectstorage_container_v1.backup_container.name
    aws_vault          = aws_backup_vault.federation.name
    backup_plan        = aws_backup_plan.federation.name
  }
}

output "ha_configuration" {
  description = "High availability configuration"
  value = {
    masakari_enabled = true
    senlin_cluster   = openstack_clustering_cluster_v1.burst_cluster.name
    nova_cells       = [
      openstack_compute_aggregate_v2.cell1.name,
      openstack_compute_aggregate_v2.cell2.name
    ]
  }
}
