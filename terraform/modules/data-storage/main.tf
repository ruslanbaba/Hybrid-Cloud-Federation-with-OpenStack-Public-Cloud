# Advanced Data & Storage Strategy
# Data gravity controls, Glance multi-store, Cinder multi-attach, Manila shared filesystems

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.50"
    }
  }
}

# Data Classification and Governance
locals {
  data_classifications = {
    hot = {
      access_frequency = "daily"
      latency_requirement = "low"
      availability_requirement = "99.9"
      backup_frequency = "hourly"
      encryption_required = true
      residency_enforcement = true
    }
    warm = {
      access_frequency = "weekly"
      latency_requirement = "medium"
      availability_requirement = "99.5"
      backup_frequency = "daily"
      encryption_required = true
      residency_enforcement = false
    }
    cold = {
      access_frequency = "monthly"
      latency_requirement = "high"
      availability_requirement = "99.0"
      backup_frequency = "weekly"
      encryption_required = true
      residency_enforcement = false
    }
  }
  
  residency_zones = {
    eu_strict = {
      jurisdiction = "EU"
      compliance_standards = ["GDPR", "DPA"]
      allowed_regions = ["eu-west-1", "eu-central-1"]
      data_sovereignty = true
    }
    us_standard = {
      jurisdiction = "US"
      compliance_standards = ["SOC2", "HIPAA"]
      allowed_regions = ["us-east-1", "us-west-2"]
      data_sovereignty = false
    }
    global_flexible = {
      jurisdiction = "Global"
      compliance_standards = ["ISO27001"]
      allowed_regions = ["*"]
      data_sovereignty = false
    }
  }
}

# Glance Multi-Store Configuration
resource "openstack_images_image_v2" "federation_images" {
  for_each = var.federation_images
  
  name             = each.value.name
  image_source_url = each.value.source_url
  container_format = "bare"
  disk_format      = "qcow2"
  visibility       = each.value.visibility
  
  # Multi-store backend configuration
  stores = ["swift", "ceph", "s3", "gcs"]
  
  properties = {
    os_type              = each.value.os_type
    os_version           = each.value.os_version
    architecture         = each.value.architecture
    hw_disk_bus         = each.value.disk_bus
    hw_scsi_model       = each.value.scsi_model
    hw_qemu_guest_agent = each.value.qemu_guest_agent
    
    # Data classification and governance
    data_classification  = each.value.data_classification
    residency_zone      = each.value.residency_zone
    retention_policy    = each.value.retention_policy
    backup_policy       = each.value.backup_policy
    
    # Multi-store replication
    swift_store_config  = jsonencode({
      container         = "federation-images"
      large_object_size = "5368709120"  # 5GB
      large_object_chunk_size = "524288000"  # 500MB
    })
    
    ceph_store_config = jsonencode({
      pool              = "federation-images"
      chunk_size        = "8388608"  # 8MB
      stripe_unit       = "4194304"  # 4MB
      stripe_count      = "2"
    })
    
    s3_store_config = jsonencode({
      bucket           = aws_s3_bucket.glance_images.bucket
      storage_class    = each.value.data_classification == "hot" ? "STANDARD" : 
                        each.value.data_classification == "warm" ? "STANDARD_IA" : "GLACIER"
      server_side_encryption = "aws:kms"
      kms_key_id      = aws_kms_key.glance_images.arn
    })
    
    gcs_store_config = jsonencode({
      bucket          = google_storage_bucket.glance_images.name
      storage_class   = each.value.data_classification == "hot" ? "STANDARD" :
                       each.value.data_classification == "warm" ? "NEARLINE" : "COLDLINE"
    })
    
    # Async replication configuration
    replication_enabled = "true"
    replication_targets = jsonencode([
      {
        store = "s3"
        priority = 1
        sync_mode = "async"
        rpo_minutes = 15
      },
      {
        store = "gcs"
        priority = 2
        sync_mode = "async"
        rpo_minutes = 30
      }
    ])
  }
  
  # Image signing for verification
  signing_enabled = true
  signature_hash_method = "SHA-256"
  signature_key_type = "RSA-PSS"
  
  tags = [
    "data_classification:${each.value.data_classification}",
    "residency_zone:${each.value.residency_zone}",
    "multi_store:enabled",
    "signed:true"
  ]
}

# S3 Backend for Glance Multi-Store
resource "aws_s3_bucket" "glance_images" {
  bucket = "federation-glance-images-${var.environment}-${random_id.storage_suffix.hex}"
  
  tags = merge(local.common_tags, {
    Service = "glance-multistore"
    DataType = "images"
  })
}

resource "aws_s3_bucket_versioning" "glance_images" {
  bucket = aws_s3_bucket.glance_images.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "glance_images" {
  bucket = aws_s3_bucket.glance_images.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.glance_images.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "glance_images" {
  bucket = aws_s3_bucket.glance_images.id
  
  rule {
    id     = "image_lifecycle"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }
    
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# GCS Backend for Glance Multi-Store
resource "google_storage_bucket" "glance_images" {
  name          = "federation-glance-images-${var.environment}-${random_id.storage_suffix.hex}"
  location      = var.gcp_region
  storage_class = "STANDARD"
  
  versioning {
    enabled = true
  }
  
  encryption {
    default_kms_key_name = google_kms_crypto_key.glance_images.id
  }
  
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }
  
  labels = {
    environment = var.environment
    service     = "glance-multistore"
    data_type   = "images"
  }
}

# Cinder Multi-Attach Volume Types
resource "openstack_blockstorage_volume_type_v3" "multi_attach_ssd" {
  name        = "multi-attach-ssd-${var.environment}"
  description = "SSD volumes with multi-attach capability"
  
  extra_specs = {
    "volume_backend_name"     = "ceph-ssd"
    "multiattach"            = "True"
    "replication_enabled"    = "True"
    "replication:type"       = "async"
    "rbd:exclusive_cinder_pool" = "False"
    
    # Performance characteristics
    "volume_type"            = "ssd"
    "iops_per_gb"           = "10"
    "throughput_per_gb"     = "125"  # MB/s
    
    # Cross-cloud replication
    "replication:aws_ebs"    = "True"
    "replication:gcp_pd"     = "True"
    "replication:azure_disk" = "True"
    
    # Data residency controls
    "data_residency"         = "flexible"
    "encryption_required"    = "True"
    "backup_required"        = "True"
  }
  
  tags = [
    "multi_attach:enabled",
    "replication:cross_cloud",
    "performance:high"
  ]
}

resource "openstack_blockstorage_volume_type_v3" "multi_attach_hdd" {
  name        = "multi-attach-hdd-${var.environment}"
  description = "HDD volumes with multi-attach capability for shared storage"
  
  extra_specs = {
    "volume_backend_name"     = "ceph-hdd"
    "multiattach"            = "True"
    "replication_enabled"    = "True"
    "replication:type"       = "async"
    
    # Performance characteristics
    "volume_type"            = "hdd"
    "iops_per_gb"           = "3"
    "throughput_per_gb"     = "40"   # MB/s
    
    # Cost optimization
    "cost_tier"             = "standard"
    "backup_frequency"      = "daily"
    
    # Data lifecycle
    "auto_tiering"          = "True"
    "cold_storage_days"     = "90"
  }
  
  tags = [
    "multi_attach:enabled",
    "cost:optimized",
    "tier:standard"
  ]
}

# Shared Storage Volumes for Legacy Applications
resource "openstack_blockstorage_volume_v3" "shared_app_storage" {
  for_each = var.shared_storage_volumes
  
  name                 = "shared-${each.key}-${var.environment}"
  size                 = each.value.size_gb
  volume_type          = each.value.performance_tier == "high" ? 
                        openstack_blockstorage_volume_type_v3.multi_attach_ssd.name : 
                        openstack_blockstorage_volume_type_v3.multi_attach_hdd.name
  availability_zone    = each.value.availability_zone
  multiattach          = true
  
  metadata = {
    application         = each.value.application
    data_classification = each.value.data_classification
    residency_zone     = each.value.residency_zone
    backup_policy      = each.value.backup_policy
    shared_mount       = "true"
    filesystem_type    = each.value.filesystem_type
  }
  
  tags = [
    "shared_storage:enabled",
    "application:${each.value.application}",
    "data_class:${each.value.data_classification}"
  ]
}

# Manila Shared Filesystems for Cross-Cloud Access
resource "openstack_sharedfilesystem_sharenetwork_v2" "federation_network" {
  name        = "federation-share-network-${var.environment}"
  description = "Shared filesystem network for federation"
  
  neutron_net_id    = data.openstack_networking_network_v2.shared_storage.id
  neutron_subnet_id = data.openstack_networking_subnet_v2.shared_storage.id
  
  security_service_ids = [
    openstack_sharedfilesystem_securityservice_v2.active_directory.id
  ]
}

resource "openstack_sharedfilesystem_securityservice_v2" "active_directory" {
  name        = "federation-ad-security-${var.environment}"
  description = "Active Directory security service for shared filesystems"
  type        = "active_directory"
  
  dns_ip      = var.ad_dns_ip
  domain      = var.ad_domain
  user        = var.ad_service_user
  password    = var.ad_service_password
  server      = var.ad_server_ip
  
  tags = [
    "auth_type:active_directory",
    "service:manila"
  ]
}

resource "openstack_sharedfilesystem_sharetype_v2" "nfs_ha" {
  name                    = "nfs-ha-${var.environment}"
  description             = "High-availability NFS shares"
  driver_handles_share_servers = false
  
  extra_specs = {
    "share_backend_name"        = "cephfs-nfs"
    "snapshot_support"          = "True"
    "create_share_from_snapshot_support" = "True"
    "revert_to_snapshot_support" = "True"
    "mount_snapshot_support"    = "True"
    
    # High availability configuration
    "replication_type"          = "readable"
    "replication_domain"        = "cephfs"
    "availability_zones"        = "nova:zone1,nova:zone2,nova:zone3"
    
    # Performance tuning
    "dedupe"                   = "True"
    "compression"              = "True"
    "thin_provisioning"        = "True"
    
    # Cross-cloud capabilities
    "cloud_sync_enabled"       = "True"
    "aws_efs_integration"      = "True"
    "gcp_filestore_integration" = "True"
    "azure_files_integration"  = "True"
  }
  
  tags = [
    "protocol:nfs",
    "ha:enabled",
    "cross_cloud:enabled"
  ]
}

resource "openstack_sharedfilesystem_sharetype_v2" "cephfs_native" {
  name                    = "cephfs-native-${var.environment}"
  description             = "Native CephFS shares with kernel client"
  driver_handles_share_servers = false
  
  extra_specs = {
    "share_backend_name"    = "cephfs-native"
    "snapshot_support"      = "True"
    "cephfs_protocol_helper" = "CEPHFS"
    
    # Native CephFS features
    "cephfs_enable_snapshots" = "True"
    "cephfs_snapshot_clone_support" = "True"
    "cephfs_subvolume_group" = "federation"
    
    # Performance optimization
    "cephfs_volume_mode"    = "0755"
    "cephfs_data_isolated"  = "True"
    "cephfs_ganesha_enabled" = "False"
  }
  
  tags = [
    "protocol:cephfs",
    "native:enabled",
    "performance:optimized"
  ]
}

# Shared Filesystems for Applications
resource "openstack_sharedfilesystem_share_v2" "application_shares" {
  for_each = var.application_shares
  
  name             = "app-share-${each.key}-${var.environment}"
  description      = "Shared filesystem for ${each.key} application"
  share_proto      = each.value.protocol
  size             = each.value.size_gb
  share_type       = each.value.protocol == "CEPHFS" ? 
                    openstack_sharedfilesystem_sharetype_v2.cephfs_native.name :
                    openstack_sharedfilesystem_sharetype_v2.nfs_ha.name
  share_network_id = openstack_sharedfilesystem_sharenetwork_v2.federation_network.id
  availability_zone = each.value.availability_zone
  
  metadata = {
    application         = each.key
    data_classification = each.value.data_classification
    backup_enabled      = each.value.backup_enabled
    cache_warming       = each.value.cache_warming_enabled
    cross_cloud_sync    = each.value.cross_cloud_sync
    residency_zone     = each.value.residency_zone
  }
  
  tags = [
    "application:${each.key}",
    "protocol:${lower(each.value.protocol)}",
    "data_class:${each.value.data_classification}"
  ]
}

# Share Access Rules for Security
resource "openstack_sharedfilesystem_share_access_v2" "application_access" {
  for_each = var.application_shares
  
  share_id     = openstack_sharedfilesystem_share_v2.application_shares[each.key].id
  access_type  = "ip"
  access_to    = each.value.allowed_cidr
  access_level = each.value.access_level
  
  metadata = {
    description = "Access rule for ${each.key} application"
    created_by  = "terraform"
  }
}

# AWS EFS for Cross-Cloud Shared Storage
resource "aws_efs_file_system" "federation_shared" {
  creation_token   = "federation-shared-${var.environment}"
  performance_mode = "generalPurpose"
  availability_zone_name = var.aws_single_az ? var.aws_primary_az : null
  
  encryption = true
  kms_key_id = aws_kms_key.efs.arn
  
  lifecycle_policy {
    transition_to_ia                    = "AFTER_30_DAYS"
    transition_to_primary_storage_class = "AFTER_1_ACCESS"
  }
  
  lifecycle_policy {
    transition_to_archive = "AFTER_90_DAYS"
  }
  
  tags = merge(local.common_tags, {
    Name = "federation-shared-${var.environment}"
    Service = "cross-cloud-storage"
  })
}

resource "aws_efs_mount_target" "federation_shared" {
  for_each = toset(var.aws_private_subnet_ids)
  
  file_system_id  = aws_efs_file_system.federation_shared.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

# GCP Filestore for Cross-Cloud Integration
resource "google_filestore_instance" "federation_shared" {
  name     = "federation-shared-${var.environment}"
  location = var.gcp_zone
  tier     = "STANDARD"
  
  file_shares {
    capacity_gb = var.gcp_filestore_capacity_gb
    name        = "federation_share"
    
    nfs_export_options {
      ip_ranges   = [var.gcp_vpc_cidr]
      access_mode = "READ_WRITE"
      squash_mode = "NO_ROOT_SQUASH"
    }
  }
  
  networks {
    network = google_compute_network.federation.name
    modes   = ["MODE_IPV4"]
  }
  
  labels = {
    environment = var.environment
    service     = "cross-cloud-storage"
    tier        = "standard"
  }
}

# Data Gravity Control Engine
resource "kubernetes_namespace" "data_gravity" {
  metadata {
    name = "data-gravity"
    labels = {
      "app.kubernetes.io/name" = "data-gravity"
      "environment"            = var.environment
    }
  }
}

resource "helm_release" "data_gravity_controller" {
  name       = "data-gravity-controller"
  chart      = "${path.module}/charts/data-gravity-controller"
  namespace  = kubernetes_namespace.data_gravity.metadata[0].name
  
  values = [
    templatefile("${path.module}/templates/data-gravity-values.yaml", {
      environment = var.environment
      openstack_endpoint = var.openstack_endpoint
      aws_region = var.aws_region
      gcp_project = var.gcp_project_id
      data_locality_weight = 0.4
      cache_warming_enabled = true
      async_replication_rpo = 300  # 5 minutes
    })
  ]
}

# Cache Warming Service for Burst Scenarios
resource "aws_lambda_function" "cache_warmer" {
  filename         = "cache_warmer.zip"
  function_name    = "federation-cache-warmer-${var.environment}"
  role            = aws_iam_role.lambda_cache_warmer.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.cache_warmer.output_base64sha256
  runtime         = "python3.11"
  timeout         = 900  # 15 minutes
  memory_size     = 2048
  
  environment {
    variables = {
      OPENSTACK_GLANCE_ENDPOINT = var.openstack_glance_endpoint
      AWS_S3_BUCKET            = aws_s3_bucket.glance_images.bucket
      GCS_BUCKET               = google_storage_bucket.glance_images.name
      EFS_MOUNT_POINT          = "/mnt/efs"
      CACHE_WARMING_THRESHOLD  = "0.8"  # Start warming at 80% capacity
      PREDICTION_HORIZON       = "1800" # 30 minutes
    }
  }
  
  vpc_config {
    subnet_ids         = var.aws_private_subnet_ids
    security_group_ids = [aws_security_group.cache_warmer.id]
  }
  
  tags = local.common_tags
}

# Async Replication Monitor
resource "aws_lambda_function" "replication_monitor" {
  filename         = "replication_monitor.zip"
  function_name    = "federation-replication-monitor-${var.environment}"
  role            = aws_iam_role.lambda_replication_monitor.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.replication_monitor.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512
  
  environment {
    variables = {
      PROMETHEUS_ENDPOINT = var.prometheus_endpoint
      RPO_TARGET_MINUTES  = "15"
      RTO_TARGET_MINUTES  = "5"
      ALERT_WEBHOOK_URL   = var.replication_alert_webhook
    }
  }
  
  tags = local.common_tags
}

# Replication Monitoring Schedule
resource "aws_cloudwatch_event_rule" "replication_monitoring" {
  name                = "federation-replication-monitoring-${var.environment}"
  description         = "Monitor data replication status"
  schedule_expression = "rate(5 minutes)"
  
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "replication_monitoring_target" {
  rule      = aws_cloudwatch_event_rule.replication_monitoring.name
  target_id = "ReplicationMonitoringTarget"
  arn       = aws_lambda_function.replication_monitor.arn
}

# KMS Keys for Encryption
resource "aws_kms_key" "glance_images" {
  description             = "KMS key for Glance images encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = local.common_tags
}

resource "aws_kms_key" "efs" {
  description             = "KMS key for EFS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = local.common_tags
}

resource "google_kms_key_ring" "federation" {
  name     = "federation-${var.environment}"
  location = var.gcp_region
}

resource "google_kms_crypto_key" "glance_images" {
  name     = "glance-images"
  key_ring = google_kms_key_ring.federation.id
  
  rotation_period = "7776000s"  # 90 days
  
  lifecycle {
    prevent_destroy = true
  }
}

# Random ID for unique storage names
resource "random_id" "storage_suffix" {
  byte_length = 4
}

# Data sources
data "openstack_networking_network_v2" "shared_storage" {
  name = "shared-storage-network-${var.environment}"
}

data "openstack_networking_subnet_v2" "shared_storage" {
  name = "shared-storage-subnet-${var.environment}"
}

data "archive_file" "cache_warmer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/cache_warmer"
  output_path = "cache_warmer.zip"
}

data "archive_file" "replication_monitor" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/replication_monitor"
  output_path = "replication_monitor.zip"
}

# Outputs
output "data_storage_config" {
  description = "Data and storage configuration"
  value = {
    glance_multistore = {
      s3_bucket  = aws_s3_bucket.glance_images.bucket
      gcs_bucket = google_storage_bucket.glance_images.name
      images     = {
        for k, v in openstack_images_image_v2.federation_images : k => v.id
      }
    }
    
    cinder_volumes = {
      multi_attach_ssd = openstack_blockstorage_volume_type_v3.multi_attach_ssd.name
      multi_attach_hdd = openstack_blockstorage_volume_type_v3.multi_attach_hdd.name
      shared_volumes   = {
        for k, v in openstack_blockstorage_volume_v3.shared_app_storage : k => v.id
      }
    }
    
    manila_shares = {
      share_network = openstack_sharedfilesystem_sharenetwork_v2.federation_network.id
      nfs_type      = openstack_sharedfilesystem_sharetype_v2.nfs_ha.name
      cephfs_type   = openstack_sharedfilesystem_sharetype_v2.cephfs_native.name
      app_shares    = {
        for k, v in openstack_sharedfilesystem_share_v2.application_shares : k => v.id
      }
    }
    
    cross_cloud_storage = {
      aws_efs_id = aws_efs_file_system.federation_shared.id
      gcp_filestore_name = google_filestore_instance.federation_shared.name
    }
  }
}

output "data_gravity_control" {
  description = "Data gravity control configuration"
  value = {
    controller_namespace = kubernetes_namespace.data_gravity.metadata[0].name
    cache_warmer_function = aws_lambda_function.cache_warmer.function_name
    replication_monitor = aws_lambda_function.replication_monitor.function_name
  }
}

output "encryption_keys" {
  description = "Encryption key configuration"
  value = {
    aws_glance_kms_key = aws_kms_key.glance_images.arn
    aws_efs_kms_key    = aws_kms_key.efs.arn
    gcp_glance_key     = google_kms_crypto_key.glance_images.id
  }
  sensitive = true
}
