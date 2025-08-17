# Advanced Networking & Performance Configuration
# BGP, BGPVPN, WireGuard, Service-aware traffic steering, eBPF observability

terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.50"
    }
    wireguard = {
      source  = "OJFord/wireguard"
      version = "~> 0.3"
    }
  }
}

# BGP Configuration for Route Propagation
resource "openstack_bgp_speaker_v2" "federation_speaker" {
  name                = "federation-bgp-speaker-${var.environment}"
  ip_version          = 4
  local_as            = var.local_asn
  advertise_floating_ip_host_routes = true
  advertise_tenant_networks = true
  
  tags = [
    "environment:${var.environment}",
    "service:bgp",
    "routing:federation"
  ]
}

# BGP Peer Configuration for Public Cloud Connectivity
resource "openstack_bgp_peer_v2" "aws_peer" {
  name        = "aws-transit-gateway-peer"
  peer_ip     = var.aws_transit_gateway_bgp_ip
  remote_as   = var.aws_asn
  auth_type   = "md5"
  password    = var.bgp_auth_password
  
  tags = [
    "provider:aws",
    "type:transit_gateway"
  ]
}

resource "openstack_bgp_peer_v2" "gcp_peer" {
  name        = "gcp-cloud-router-peer"
  peer_ip     = var.gcp_cloud_router_bgp_ip
  remote_as   = var.gcp_asn
  auth_type   = "md5"
  password    = var.bgp_auth_password
  
  tags = [
    "provider:gcp",
    "type:cloud_router"
  ]
}

resource "openstack_bgp_peer_v2" "azure_peer" {
  name        = "azure-vpn-gateway-peer"
  peer_ip     = var.azure_vpn_gateway_bgp_ip
  remote_as   = var.azure_asn
  auth_type   = "md5"
  password    = var.bgp_auth_password
  
  tags = [
    "provider:azure",
    "type:vpn_gateway"
  ]
}

# Associate BGP Peers with Speaker
resource "openstack_bgp_peer_associate_v2" "aws_association" {
  bgp_speaker_id = openstack_bgp_speaker_v2.federation_speaker.id
  bgp_peer_id    = openstack_bgp_peer_v2.aws_peer.id
}

resource "openstack_bgp_peer_associate_v2" "gcp_association" {
  bgp_speaker_id = openstack_bgp_speaker_v2.federation_speaker.id
  bgp_peer_id    = openstack_bgp_peer_v2.gcp_peer.id
}

resource "openstack_bgp_peer_associate_v2" "azure_association" {
  bgp_speaker_id = openstack_bgp_speaker_v2.federation_speaker.id
  bgp_peer_id    = openstack_bgp_peer_v2.azure_peer.id
}

# BGPVPN Configuration for L3VPN Services
resource "openstack_bgpvpn_v2" "federation_l3vpn" {
  name = "federation-l3vpn-${var.environment}"
  type = "l3"
  
  route_distinguishers = [
    "${var.local_asn}:${var.rd_base + 1}",
    "${var.local_asn}:${var.rd_base + 2}"
  ]
  
  import_targets = [
    "${var.local_asn}:${var.rt_base + 1}",
    "${var.aws_asn}:${var.rt_base + 1}",
    "${var.gcp_asn}:${var.rt_base + 1}",
    "${var.azure_asn}:${var.rt_base + 1}"
  ]
  
  export_targets = [
    "${var.local_asn}:${var.rt_base + 1}"
  ]
  
  tags = [
    "service:l3vpn",
    "environment:${var.environment}",
    "multi_cloud:true"
  ]
}

# Network Association with BGPVPN
resource "openstack_bgpvpn_network_associate_v2" "federation_networks" {
  for_each = var.federation_networks
  
  bgpvpn_id  = openstack_bgpvpn_v2.federation_l3vpn.id
  network_id = each.value.network_id
}

# WireGuard VPN Configuration for Low-Latency Encrypted Links
resource "wireguard_asymmetric_key" "federation_server" {
  for_each = var.wireguard_endpoints
}

resource "openstack_compute_instance_v2" "wireguard_gateway" {
  for_each = var.wireguard_endpoints
  
  name              = "wireguard-gateway-${each.key}-${var.environment}"
  image_id          = data.openstack_images_image_v2.ubuntu_focal.id
  flavor_id         = data.openstack_compute_flavor_v2.wireguard.id
  key_pair          = openstack_compute_keypair_v2.wireguard.name
  security_groups   = [openstack_networking_secgroup_v2.wireguard.name]
  availability_zone = each.value.availability_zone
  
  network {
    name = each.value.network_name
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/wireguard-setup.sh", {
    private_key    = wireguard_asymmetric_key.federation_server[each.key].private_key
    public_key     = wireguard_asymmetric_key.federation_server[each.key].public_key
    listen_port    = each.value.listen_port
    peers          = each.value.peers
    allowed_ips    = each.value.allowed_ips
    endpoint_ip    = each.value.endpoint_ip
  }))
  
  tags = [
    "service:wireguard",
    "gateway:${each.key}",
    "environment:${var.environment}"
  ]
}

# WireGuard Security Group
resource "openstack_networking_secgroup_v2" "wireguard" {
  name        = "wireguard-gateways-${var.environment}"
  description = "Security group for WireGuard gateways"
  
  tags = [
    "service:wireguard",
    "component:security_group"
  ]
}

resource "openstack_networking_secgroup_rule_v2" "wireguard_udp" {
  for_each = var.wireguard_endpoints
  
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = each.value.listen_port
  port_range_max    = each.value.listen_port
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.wireguard.id
  description       = "WireGuard UDP traffic for ${each.key}"
}

# AWS Transit Gateway Configuration
resource "aws_ec2_transit_gateway" "federation" {
  description                     = "Federation Transit Gateway"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"
  dns_support                     = "enable"
  vpn_ecmp_support               = "enable"
  
  tags = merge(local.common_tags, {
    Name = "federation-tgw-${var.environment}"
    Service = "networking"
  })
}

# VPN Connection to OpenStack
resource "aws_vpn_connection" "openstack" {
  customer_gateway_id = aws_customer_gateway.openstack.id
  transit_gateway_id  = aws_ec2_transit_gateway.federation.id
  type               = "ipsec.1"
  static_routes_only = false
  
  tags = merge(local.common_tags, {
    Name = "openstack-vpn-${var.environment}"
  })
}

resource "aws_customer_gateway" "openstack" {
  bgp_asn    = var.local_asn
  ip_address = var.openstack_public_ip
  type       = "ipsec.1"
  
  tags = merge(local.common_tags, {
    Name = "openstack-cgw-${var.environment}"
  })
}

# GCP Cloud Router and VPN
resource "google_compute_router" "federation" {
  name    = "federation-router-${var.environment}"
  region  = var.gcp_region
  network = google_compute_network.federation.id
  
  bgp {
    asn            = var.gcp_asn
    advertise_mode = "CUSTOM"
    
    advertised_groups = ["ALL_SUBNETS"]
    
    advertised_ip_ranges {
      range       = var.openstack_cidr
      description = "OpenStack networks"
    }
  }
}

resource "google_compute_vpn_gateway" "federation" {
  name    = "federation-vpn-gateway-${var.environment}"
  network = google_compute_network.federation.id
  region  = var.gcp_region
}

resource "google_compute_vpn_tunnel" "openstack" {
  name          = "openstack-tunnel-${var.environment}"
  peer_ip       = var.openstack_public_ip
  shared_secret = var.vpn_shared_secret
  
  target_vpn_gateway = google_compute_vpn_gateway.federation.id
  
  depends_on = [
    google_compute_forwarding_rule.fr_esp,
    google_compute_forwarding_rule.fr_udp500,
    google_compute_forwarding_rule.fr_udp4500,
  ]
  
  router = google_compute_router.federation.id
}

# Service-Aware Traffic Steering with Global Load Balancer
resource "openstack_lb_loadbalancer_v2" "global_lb" {
  name          = "global-federation-lb-${var.environment}"
  vip_subnet_id = data.openstack_networking_subnet_v2.lb_subnet.id
  
  tags = [
    "service:global_load_balancer",
    "environment:${var.environment}",
    "tier:edge"
  ]
}

# Global Anycast VIP Pool
resource "openstack_lb_pool_v2" "global_anycast" {
  name        = "global-anycast-pool"
  protocol    = "HTTP"
  lb_method   = "LEAST_CONNECTIONS"
  loadbalancer_id = openstack_lb_loadbalancer_v2.global_lb.id
  
  persistence {
    type        = "HTTP_COOKIE"
    cookie_name = "federation_session"
  }
}

# Health Monitor for Latency-Aware Routing
resource "openstack_lb_monitor_v2" "latency_health" {
  name           = "latency-health-monitor"
  type           = "HTTP"
  delay          = 10
  timeout        = 5
  max_retries    = 3
  url_path       = "/health/latency"
  expected_codes = "200"
  pool_id        = openstack_lb_pool_v2.global_anycast.id
  
  # Custom health check for latency measurement
  http_method = "GET"
  
  admin_state_up = true
}

# Member pools for different regions and providers
resource "openstack_lb_member_v2" "openstack_primary" {
  pool_id       = openstack_lb_pool_v2.global_anycast.id
  address       = var.openstack_primary_endpoint_ip
  protocol_port = 443
  weight        = 100
  
  monitor_address = var.openstack_primary_endpoint_ip
  monitor_port    = 443
  
  tags = [
    "provider:openstack",
    "region:primary",
    "priority:high"
  ]
}

resource "openstack_lb_member_v2" "openstack_secondary" {
  pool_id       = openstack_lb_pool_v2.global_anycast.id
  address       = var.openstack_secondary_endpoint_ip
  protocol_port = 443
  weight        = 50
  backup        = true
  
  tags = [
    "provider:openstack",
    "region:secondary",
    "priority:medium"
  ]
}

# AWS Application Load Balancer for Cross-Cloud Routing
resource "aws_lb" "federation_alb" {
  name               = "federation-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets           = data.aws_subnets.public.ids
  
  enable_deletion_protection = true
  enable_http2              = true
  
  tags = local.common_tags
}

# Target Group for OpenStack endpoints
resource "aws_lb_target_group" "openstack" {
  name     = "openstack-targets-${var.environment}"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = data.aws_vpc.federation.id
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = local.common_tags
}

# Listener with latency-based routing rules
resource "aws_lb_listener" "federation" {
  load_balancer_arn = aws_lb.federation_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.federation.arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.openstack.arn
  }
}

# Blue/Green Deployment for Burst Pathway
resource "aws_lb_target_group" "burst_blue" {
  name     = "burst-blue-${var.environment}"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = data.aws_vpc.federation.id
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 15
    matcher             = "200"
    path                = "/health/burst"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = merge(local.common_tags, {
    DeploymentSlot = "blue"
    Service        = "burst"
  })
}

resource "aws_lb_target_group" "burst_green" {
  name     = "burst-green-${var.environment}"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = data.aws_vpc.federation.id
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 15
    matcher             = "200"
    path                = "/health/burst"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = merge(local.common_tags, {
    DeploymentSlot = "green"
    Service        = "burst"
  })
}

# eBPF Observability Configuration
resource "openstack_compute_instance_v2" "ebpf_collectors" {
  count = var.ebpf_collector_count
  
  name              = "ebpf-collector-${count.index + 1}-${var.environment}"
  image_id          = data.openstack_images_image_v2.ebpf_image.id
  flavor_id         = data.openstack_compute_flavor_v2.monitoring.id
  key_pair          = openstack_compute_keypair_v2.monitoring.name
  security_groups   = [openstack_networking_secgroup_v2.monitoring.name]
  
  network {
    name = data.openstack_networking_network_v2.monitoring.name
  }
  
  user_data = base64encode(templatefile("${path.module}/templates/ebpf-collector.sh", {
    prometheus_endpoint = var.prometheus_endpoint
    grafana_endpoint   = var.grafana_endpoint
    environment        = var.environment
    collector_id       = count.index + 1
  }))
  
  tags = [
    "service:ebpf_collector",
    "monitoring:network",
    "observability:l4_l7"
  ]
}

# Network SLA Configuration
resource "openstack_networking_qos_policy_v2" "sla_policy" {
  name        = "federation-sla-policy-${var.environment}"
  description = "QoS policy for federation SLA enforcement"
  shared      = true
  
  tags = [
    "service:qos",
    "sla:enforced"
  ]
}

resource "openstack_networking_qos_bandwidth_limit_rule_v2" "burst_bandwidth" {
  qos_policy_id  = openstack_networking_qos_policy_v2.sla_policy.id
  max_kbps       = var.burst_max_bandwidth_kbps
  max_burst_kbps = var.burst_max_burst_kbps
  direction      = "egress"
}

resource "openstack_networking_qos_dscp_marking_rule_v2" "priority_marking" {
  qos_policy_id = openstack_networking_qos_policy_v2.sla_policy.id
  dscp_mark     = 46  # EF (Expedited Forwarding)
}

# Network SLO Monitoring
resource "aws_cloudwatch_metric_alarm" "network_latency" {
  alarm_name          = "federation-network-latency-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "100"  # 100ms threshold
  alarm_description   = "This metric monitors federation network latency"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    LoadBalancer = aws_lb.federation_alb.arn_suffix
  }
  
  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "packet_loss" {
  alarm_name          = "federation-packet-loss-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetConnectionErrorCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors federation packet loss"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    LoadBalancer = aws_lb.federation_alb.arn_suffix
  }
  
  tags = local.common_tags
}

# Data sources
data "openstack_images_image_v2" "ubuntu_focal" {
  name        = "Ubuntu 20.04 LTS"
  most_recent = true
}

data "openstack_images_image_v2" "ebpf_image" {
  name        = "Ubuntu eBPF Collector"
  most_recent = true
}

data "openstack_compute_flavor_v2" "wireguard" {
  name = "m1.small"
}

data "openstack_compute_flavor_v2" "monitoring" {
  name = "m1.medium"
}

data "openstack_networking_subnet_v2" "lb_subnet" {
  name = "lb-subnet-${var.environment}"
}

data "openstack_networking_network_v2" "monitoring" {
  name = "monitoring-network-${var.environment}"
}

data "aws_vpc" "federation" {
  tags = {
    Name = "federation-vpc-${var.environment}"
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.federation.id]
  }
  
  tags = {
    Type = "public"
  }
}

# Outputs
output "bgp_configuration" {
  description = "BGP and routing configuration"
  value = {
    bgp_speaker_id = openstack_bgp_speaker_v2.federation_speaker.id
    bgpvpn_id      = openstack_bgpvpn_v2.federation_l3vpn.id
    aws_tgw_id     = aws_ec2_transit_gateway.federation.id
    gcp_router_id  = google_compute_router.federation.id
  }
}

output "wireguard_gateways" {
  description = "WireGuard gateway configuration"
  value = {
    for k, v in openstack_compute_instance_v2.wireguard_gateway : k => {
      instance_id = v.id
      public_key  = wireguard_asymmetric_key.federation_server[k].public_key
    }
  }
  sensitive = true
}

output "load_balancer_config" {
  description = "Global load balancer configuration"
  value = {
    openstack_lb_id    = openstack_lb_loadbalancer_v2.global_lb.id
    aws_alb_arn        = aws_lb.federation_alb.arn
    blue_target_group  = aws_lb_target_group.burst_blue.arn
    green_target_group = aws_lb_target_group.burst_green.arn
  }
}

output "network_slo_monitoring" {
  description = "Network SLO monitoring configuration"
  value = {
    latency_alarm = aws_cloudwatch_metric_alarm.network_latency.arn
    packet_loss_alarm = aws_cloudwatch_metric_alarm.packet_loss.arn
    qos_policy_id = openstack_networking_qos_policy_v2.sla_policy.id
  }
}
