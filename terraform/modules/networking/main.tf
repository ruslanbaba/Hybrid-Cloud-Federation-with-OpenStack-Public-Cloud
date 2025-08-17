# Multi-Cloud Networking Configuration
# Enterprise-grade VPN, Transit Gateway, and BGP setup

# VPN Gateway Configuration for OpenStack to AWS
resource "aws_vpn_gateway" "federation_vgw" {
  vpc_id          = aws_vpc.federation_vpc.id
  amazon_side_asn = var.aws_bgp_asn

  tags = merge(local.common_tags, {
    Name = "federation-vpn-gateway"
    Purpose = "hybrid-cloud-federation"
  })
}

resource "aws_customer_gateway" "openstack_cgw" {
  bgp_asn    = var.openstack_bgp_asn
  ip_address = var.openstack_public_ip
  type       = "ipsec.1"
  
  tags = merge(local.common_tags, {
    Name = "openstack-customer-gateway"
    Location = "openstack-datacenter"
  })
}

resource "aws_vpn_connection" "openstack_to_aws" {
  vpn_gateway_id      = aws_vpn_gateway.federation_vgw.id
  customer_gateway_id = aws_customer_gateway.openstack_cgw.id
  type                = "ipsec.1"
  static_routes_only  = false

  tags = merge(local.common_tags, {
    Name = "openstack-aws-vpn"
    Tunnel = "primary"
  })
}

# Transit Gateway for multi-cloud connectivity
resource "aws_ec2_transit_gateway" "federation_tgw" {
  description                     = "Transit Gateway for hybrid cloud federation"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"
  dns_support                    = "enable"
  multicast_support             = "disable"
  amazon_side_asn               = var.aws_transit_gateway_asn

  tags = merge(local.common_tags, {
    Name = "federation-transit-gateway"
    Purpose = "multi-cloud-routing"
  })
}

# VPC attachments to Transit Gateway
resource "aws_ec2_transit_gateway_vpc_attachment" "federation_vpc_attachment" {
  subnet_ids         = aws_subnet.federation_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.federation_tgw.id
  vpc_id            = aws_vpc.federation_vpc.id
  
  dns_support                                    = "enable"
  ipv6_support                                  = "disable"
  appliance_mode_support                        = "disable"
  transit_gateway_default_route_table_association = "enable"
  transit_gateway_default_route_table_propagation = "enable"

  tags = merge(local.common_tags, {
    Name = "federation-vpc-attachment"
  })
}

# VPN attachment to Transit Gateway
resource "aws_ec2_transit_gateway_vpn_attachment" "openstack_vpn_attachment" {
  vpn_connection_id  = aws_vpn_connection.openstack_to_aws.id
  transit_gateway_id = aws_ec2_transit_gateway.federation_tgw.id

  tags = merge(local.common_tags, {
    Name = "openstack-vpn-attachment"
  })
}

# Route Tables for precise routing control
resource "aws_ec2_transit_gateway_route_table" "federation_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.federation_tgw.id

  tags = merge(local.common_tags, {
    Name = "federation-route-table"
    Purpose = "hybrid-routing"
  })
}

# Routes for OpenStack networks
resource "aws_ec2_transit_gateway_route" "openstack_routes" {
  count = length(var.openstack_cidrs)
  
  destination_cidr_block         = var.openstack_cidrs[count.index]
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpn_attachment.openstack_vpn_attachment.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.federation_rt.id
}

# Cross-region peering for multi-region setup
resource "aws_ec2_transit_gateway_peering_attachment" "cross_region_peering" {
  count = length(var.peer_regions)

  peer_region             = var.peer_regions[count.index]
  peer_transit_gateway_id = var.peer_transit_gateway_ids[count.index]
  transit_gateway_id      = aws_ec2_transit_gateway.federation_tgw.id

  tags = merge(local.common_tags, {
    Name = "federation-cross-region-${var.peer_regions[count.index]}"
    PeerRegion = var.peer_regions[count.index]
  })
}

# Security Groups for federation traffic
resource "aws_security_group" "federation_sg" {
  name_prefix = "federation-network-"
  vpc_id      = aws_vpc.federation_vpc.id
  description = "Security group for federation network traffic"

  # OpenStack HTTPS API access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.openstack_cidrs
    description = "HTTPS from OpenStack"
  }

  # VPN traffic
  ingress {
    from_port   = 500
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = [var.openstack_public_ip_cidr]
    description = "IKE for VPN"
  }

  ingress {
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = [var.openstack_public_ip_cidr]
    description = "IPSec NAT-T for VPN"
  }

  # BGP traffic
  ingress {
    from_port   = 179
    to_port     = 179
    protocol    = "tcp"
    cidr_blocks = var.openstack_cidrs
    description = "BGP from OpenStack"
  }

  # Inter-cloud federation traffic
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = concat(var.openstack_cidrs, var.gcp_cidrs, var.azure_cidrs)
    description = "Federation controller API"
  }

  # Monitoring and metrics
  ingress {
    from_port   = 9090
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = var.monitoring_cidrs
    description = "Prometheus metrics"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "federation-security-group"
    Purpose = "network-security"
  })
}

# Network ACLs for additional security layer
resource "aws_network_acl" "federation_nacl" {
  vpc_id     = aws_vpc.federation_vpc.id
  subnet_ids = aws_subnet.federation_private[*].id

  # Ingress rules
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    from_port  = 443
    to_port    = 443
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  ingress {
    rule_no    = 110
    protocol   = "tcp"
    from_port  = 80
    to_port    = 80
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  ingress {
    rule_no    = 120
    protocol   = "tcp"
    from_port  = 22
    to_port    = 22
    cidr_block = var.management_cidr
    action     = "allow"
  }

  # VPN protocols
  ingress {
    rule_no    = 130
    protocol   = "udp"
    from_port  = 500
    to_port    = 500
    cidr_block = var.openstack_public_ip_cidr
    action     = "allow"
  }

  ingress {
    rule_no    = 140
    protocol   = "udp"
    from_port  = 4500
    to_port    = 4500
    cidr_block = var.openstack_public_ip_cidr
    action     = "allow"
  }

  # Egress rules
  egress {
    rule_no    = 100
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  tags = merge(local.common_tags, {
    Name = "federation-nacl"
    Purpose = "network-acl"
  })
}

# Google Cloud VPN setup
resource "google_compute_vpn_gateway" "federation_gcp_gateway" {
  name    = "federation-vpn-gateway"
  network = google_compute_network.federation_network.id
  region  = var.gcp_region

  depends_on = [google_compute_network.federation_network]
}

resource "google_compute_address" "federation_gcp_vpn_ip" {
  name   = "federation-vpn-ip"
  region = var.gcp_region
}

resource "google_compute_vpn_tunnel" "federation_gcp_tunnel" {
  name          = "federation-vpn-tunnel"
  peer_ip       = aws_vpn_connection.openstack_to_aws.tunnel1_address
  shared_secret = aws_vpn_connection.openstack_to_aws.tunnel1_preshared_key
  
  target_vpn_gateway = google_compute_vpn_gateway.federation_gcp_gateway.id
  ike_version       = 2

  local_traffic_selector  = ["0.0.0.0/0"]
  remote_traffic_selector = ["0.0.0.0/0"]

  depends_on = [
    google_compute_forwarding_rule.federation_gcp_esp,
    google_compute_forwarding_rule.federation_gcp_udp500,
    google_compute_forwarding_rule.federation_gcp_udp4500,
  ]
}

# GCP Forwarding rules for VPN
resource "google_compute_forwarding_rule" "federation_gcp_esp" {
  name        = "federation-esp"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.federation_gcp_vpn_ip.address
  target      = google_compute_vpn_gateway.federation_gcp_gateway.id
}

resource "google_compute_forwarding_rule" "federation_gcp_udp500" {
  name        = "federation-udp500"
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.federation_gcp_vpn_ip.address
  target      = google_compute_vpn_gateway.federation_gcp_gateway.id
}

resource "google_compute_forwarding_rule" "federation_gcp_udp4500" {
  name        = "federation-udp4500"
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.federation_gcp_vpn_ip.address
  target      = google_compute_vpn_gateway.federation_gcp_gateway.id
}

# Azure Virtual Network Gateway
resource "azurerm_virtual_network_gateway" "federation_azure_gateway" {
  name                = "federation-vpn-gateway"
  location            = azurerm_resource_group.federation.location
  resource_group_name = azurerm_resource_group.federation.name

  type     = "Vpn"
  vpn_type = "RouteBased"
  sku      = "VpnGw2"

  ip_configuration {
    public_ip_address_id          = azurerm_public_ip.federation_azure_gateway_ip.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.federation_azure_gateway_subnet.id
  }

  vpn_client_configuration {
    address_space = ["10.254.0.0/24"]
    
    vpn_client_protocols = ["OpenVPN", "IkeV2"]

    vpn_auth_types = ["Certificate"]

    root_certificate {
      name             = "federation-root-cert"
      public_cert_data = var.azure_vpn_root_certificate
    }
  }

  tags = local.common_tags
}

resource "azurerm_public_ip" "federation_azure_gateway_ip" {
  name                = "federation-gateway-ip"
  location            = azurerm_resource_group.federation.location
  resource_group_name = azurerm_resource_group.federation.name
  allocation_method   = "Static"
  sku                = "Standard"

  tags = local.common_tags
}

# BGP Configuration for dynamic routing
resource "aws_ec2_transit_gateway_route_table_association" "federation_bgp_association" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpn_attachment.openstack_vpn_attachment.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.federation_rt.id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "federation_bgp_propagation" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpn_attachment.openstack_vpn_attachment.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.federation_rt.id
}

# Cloud Router for GCP BGP
resource "google_compute_router" "federation_gcp_router" {
  name    = "federation-cloud-router"
  region  = var.gcp_region
  network = google_compute_network.federation_network.id

  bgp {
    asn               = var.gcp_bgp_asn
    advertise_mode    = "CUSTOM"
    advertised_groups = ["ALL_SUBNETS"]

    advertised_ip_ranges {
      range = var.gcp_vpc_cidr
    }
  }
}

# BGP session for GCP
resource "google_compute_router_peer" "federation_gcp_bgp_peer" {
  name                      = "federation-bgp-peer"
  router                    = google_compute_router.federation_gcp_router.name
  region                    = var.gcp_region
  peer_ip_address          = "169.254.1.1"
  peer_asn                 = var.openstack_bgp_asn
  advertised_route_priority = 100
  interface                = google_compute_router_interface.federation_gcp_interface.name
}

resource "google_compute_router_interface" "federation_gcp_interface" {
  name       = "federation-interface"
  router     = google_compute_router.federation_gcp_router.name
  region     = var.gcp_region
  ip_range   = "169.254.1.2/30"
  vpn_tunnel = google_compute_vpn_tunnel.federation_gcp_tunnel.name
}

# Route monitoring and health checks
resource "aws_route53_health_check" "vpn_tunnel_health" {
  count                           = 2
  fqdn                           = "tunnel${count.index + 1}.federation.local"
  port                           = 443
  type                           = "HTTPS"
  resource_path                  = "/health"
  failure_threshold              = 3
  request_interval               = 30
  insufficient_data_health_status = "Failure"

  tags = merge(local.common_tags, {
    Name = "VPN Tunnel ${count.index + 1} Health Check"
    Tunnel = "tunnel${count.index + 1}"
  })
}

# CloudWatch alarms for network monitoring
resource "aws_cloudwatch_metric_alarm" "vpn_tunnel_state" {
  count = 2

  alarm_name          = "federation-vpn-tunnel-${count.index + 1}-down"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TunnelState"
  namespace           = "AWS/VPN"
  period              = "60"
  statistic           = "Maximum"
  threshold           = "1"
  alarm_description   = "This metric monitors VPN tunnel ${count.index + 1} state"
  alarm_actions       = [aws_sns_topic.federation_alerts.arn]

  dimensions = {
    VpnId   = aws_vpn_connection.openstack_to_aws.id
    TunnelIpAddress = count.index == 0 ? aws_vpn_connection.openstack_to_aws.tunnel1_address : aws_vpn_connection.openstack_to_aws.tunnel2_address
  }

  tags = local.common_tags
}

# Network performance monitoring
resource "aws_cloudwatch_metric_alarm" "network_latency" {
  alarm_name          = "federation-network-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NetworkLatency"
  namespace           = "AWS/VPN"
  period              = "300"
  statistic           = "Average"
  threshold           = "150"  # 150ms threshold
  alarm_description   = "This metric monitors network latency across federation"
  alarm_actions       = [aws_sns_topic.federation_alerts.arn]

  tags = local.common_tags
}

# DNS configuration for service discovery
resource "aws_route53_zone" "federation_private" {
  name = "federation.local"

  vpc {
    vpc_id = aws_vpc.federation_vpc.id
  }

  tags = merge(local.common_tags, {
    Name = "Federation Private DNS Zone"
    Purpose = "service-discovery"
  })
}

# DNS records for federation services
resource "aws_route53_record" "burst_controller" {
  zone_id = aws_route53_zone.federation_private.zone_id
  name    = "burst-controller.federation.local"
  type    = "A"
  ttl     = 300
  records = [aws_instance.burst_controller.private_ip]
}

resource "aws_route53_record" "monitoring" {
  zone_id = aws_route53_zone.federation_private.zone_id
  name    = "monitoring.federation.local"
  type    = "A"
  ttl     = 300
  records = [aws_instance.monitoring.private_ip]
}

# Output network configuration
output "network_configuration" {
  description = "Network configuration for federation"
  value = {
    aws = {
      vpc_id              = aws_vpc.federation_vpc.id
      transit_gateway_id  = aws_ec2_transit_gateway.federation_tgw.id
      vpn_connection_id   = aws_vpn_connection.openstack_to_aws.id
      tunnel_addresses    = [
        aws_vpn_connection.openstack_to_aws.tunnel1_address,
        aws_vpn_connection.openstack_to_aws.tunnel2_address
      ]
    }
    gcp = {
      network_name       = google_compute_network.federation_network.name
      vpn_gateway_name   = google_compute_vpn_gateway.federation_gcp_gateway.name
      external_ip        = google_compute_address.federation_gcp_vpn_ip.address
    }
    azure = {
      virtual_network_id = azurerm_virtual_network.federation.id
      gateway_id         = azurerm_virtual_network_gateway.federation_azure_gateway.id
      public_ip          = azurerm_public_ip.federation_azure_gateway_ip.ip_address
    }
    dns_zone = aws_route53_zone.federation_private.zone_id
  }
  sensitive = true
}
