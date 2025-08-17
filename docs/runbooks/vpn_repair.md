# VPN Repair Runbook

## Overview
This runbook provides comprehensive procedures for diagnosing and repairing VPN connectivity issues in the hybrid cloud federation platform.

## Emergency Contacts
- **Network Team Lead**: network-team@company.com
- **On-Call Network Engineer**: +1-555-NETWORK
- **Platform Team**: platform-team@company.com
- **Security Team**: security@company.com

## VPN Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   OpenStack     │    │      AWS        │    │      GCP        │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ WireGuard   │◄┼────┼►│Transit      │◄┼────┼►│Cloud        │ │
│ │ Gateway     │ │    │ │Gateway      │ │    │ │Router       │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ StrongSwan  │ │    │ │VPN Gateway  │ │    │ │VPN Gateway  │ │
│ │ IPsec       │◄┼────┼►│             │◄┼────┼►│             │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Common VPN Issues and Solutions

### Issue 1: WireGuard Tunnel Down

**Symptoms:**
- WireGuard interface not responding
- No traffic flow between clouds
- Connection timeouts

**Diagnostic Commands:**
```bash
# Check WireGuard status
sudo wg show
sudo wg show wg0

# Check interface status
ip addr show wg0
ip route show table main | grep wg0

# Check systemd service
sudo systemctl status wg-quick@wg0
sudo journalctl -u wg-quick@wg0 -f
```

**Repair Procedures:**

1. **Interface Reset**
   ```bash
   # Stop WireGuard interface
   sudo wg-quick down wg0
   
   # Check for process conflicts
   sudo netstat -tulpn | grep :51820
   sudo pkill -f wireguard
   
   # Restart interface
   sudo wg-quick up wg0
   
   # Verify connectivity
   ping -c 3 <remote-endpoint-ip>
   ```

2. **Configuration Validation**
   ```bash
   # Check WireGuard config
   sudo cat /etc/wireguard/wg0.conf
   
   # Validate configuration syntax
   sudo wg-quick save wg0
   
   # Test with temporary config
   sudo wg setconf wg0 <(wg-quick strip wg0)
   ```

3. **Key Rotation (if needed)**
   ```bash
   # Generate new keypair
   wg genkey | tee privatekey | wg pubkey > publickey
   
   # Update Vault with new keys
   vault kv put secret/federation/wireguard \
     private_key=@privatekey \
     public_key=@publickey
   
   # Update peer configurations
   fed-cli vpn update-keys --provider all
   ```

### Issue 2: IPsec/StrongSwan Tunnel Failure

**Symptoms:**
- StrongSwan service failures
- IKE negotiation errors
- ESP packet drops

**Diagnostic Commands:**
```bash
# Check StrongSwan status
sudo systemctl status strongswan
sudo ipsec status
sudo ipsec statusall

# Check logs
sudo journalctl -u strongswan -f
tail -f /var/log/charon.log

# Verify configurations
sudo ipsec listcerts
sudo ipsec listsecrets
```

**Repair Procedures:**

1. **Service Recovery**
   ```bash
   # Restart StrongSwan
   sudo systemctl restart strongswan
   
   # Reload configuration
   sudo ipsec reload
   
   # Re-establish connections
   sudo ipsec up aws-tunnel
   sudo ipsec up gcp-tunnel
   
   # Check connection status
   sudo ipsec status
   ```

2. **Certificate Issues**
   ```bash
   # Check certificate validity
   sudo ipsec listcerts | grep -A 5 -B 5 "not after"
   
   # Renew certificates via Vault
   vault write pki-intermediate/issue/vpn-certs \
     common_name="vpn.federation.local" \
     ttl="8760h"
   
   # Update StrongSwan certificates
   sudo cp /tmp/new-cert.pem /etc/ipsec.d/certs/
   sudo cp /tmp/new-key.pem /etc/ipsec.d/private/
   sudo ipsec reload
   ```

3. **IKE Troubleshooting**
   ```bash
   # Enable debug logging
   sudo ipsec stroke loglevel ike 2
   sudo ipsec stroke loglevel net 2
   
   # Monitor IKE exchanges
   sudo tcpdump -i eth0 -n port 500 or port 4500
   
   # Check NAT traversal
   sudo ipsec stroke loglevel ike 3
   ```

### Issue 3: AWS Transit Gateway Issues

**Symptoms:**
- Route propagation failures
- Attachment state issues
- Cross-VPC connectivity problems

**Diagnostic Commands:**
```bash
# Check Transit Gateway status
aws ec2 describe-transit-gateways \
  --transit-gateway-ids tgw-xxxxxxxxx

# Check attachments
aws ec2 describe-transit-gateway-attachments \
  --filters "Name=transit-gateway-id,Values=tgw-xxxxxxxxx"

# Check route tables
aws ec2 describe-transit-gateway-route-tables \
  --transit-gateway-route-table-ids tgw-rtb-xxxxxxxxx
```

**Repair Procedures:**

1. **Attachment Recovery**
   ```bash
   # Check attachment state
   aws ec2 describe-transit-gateway-vpc-attachments \
     --transit-gateway-attachment-ids tgw-attach-xxxxxxxxx
   
   # Recreate attachment if needed
   aws ec2 create-transit-gateway-vpc-attachment \
     --transit-gateway-id tgw-xxxxxxxxx \
     --vpc-id vpc-xxxxxxxxx \
     --subnet-ids subnet-xxxxxxxxx
   ```

2. **Route Table Fixes**
   ```bash
   # Check current routes
   aws ec2 search-transit-gateway-routes \
     --transit-gateway-route-table-id tgw-rtb-xxxxxxxxx \
     --filters "Name=state,Values=active"
   
   # Add missing routes
   aws ec2 create-route \
     --route-table-id rtb-xxxxxxxxx \
     --destination-cidr-block 10.0.0.0/16 \
     --transit-gateway-id tgw-xxxxxxxxx
   ```

### Issue 4: Network Performance Issues

**Symptoms:**
- High latency between clouds
- Packet loss
- Bandwidth limitations

**Diagnostic Tools:**
```bash
# Network performance testing
fed-cli network benchmark \
  --source openstack \
  --target aws \
  --duration 60s

# MTU path discovery
tracepath <remote-ip>
ping -M do -s 1472 <remote-ip>

# Bandwidth testing
iperf3 -c <remote-host> -t 30 -i 5
```

**Performance Optimization:**

1. **MTU Optimization**
   ```bash
   # Check current MTU
   ip link show | grep mtu
   
   # Optimize for VPN overhead
   sudo ip link set dev wg0 mtu 1420
   
   # Update persistent configuration
   echo "MTU = 1420" >> /etc/wireguard/wg0.conf
   ```

2. **TCP Optimization**
   ```bash
   # Optimize TCP settings for WAN
   cat >> /etc/sysctl.conf << EOF
   net.core.rmem_max = 134217728
   net.core.wmem_max = 134217728
   net.ipv4.tcp_rmem = 4096 87380 134217728
   net.ipv4.tcp_wmem = 4096 65536 134217728
   net.ipv4.tcp_congestion_control = bbr
   EOF
   
   sudo sysctl -p
   ```

## Automated Repair Scripts

**VPN Health Monitor:**
```bash
#!/bin/bash
# vpn-health-monitor.sh

VPN_ENDPOINTS=(
  "10.0.1.1:openstack-wg"
  "10.1.1.1:aws-tgw" 
  "10.2.1.1:gcp-vpn"
)

LOG_FILE="/var/log/vpn-health.log"
ALERT_WEBHOOK="https://alerts.federation.local/webhook"

check_vpn_health() {
  local endpoint=$1
  local name=$2
  
  if ping -c 3 -W 5 $endpoint >/dev/null 2>&1; then
    echo "$(date): $name - OK" >> $LOG_FILE
    return 0
  else
    echo "$(date): $name - FAILED" >> $LOG_FILE
    return 1
  fi
}

repair_wireguard() {
  echo "$(date): Attempting WireGuard repair" >> $LOG_FILE
  sudo wg-quick down wg0
  sleep 5
  sudo wg-quick up wg0
  sleep 10
}

repair_strongswan() {
  echo "$(date): Attempting StrongSwan repair" >> $LOG_FILE
  sudo ipsec restart
  sleep 15
  sudo ipsec up aws-tunnel
  sudo ipsec up gcp-tunnel
}

send_alert() {
  local message=$1
  curl -X POST $ALERT_WEBHOOK \
    -H "Content-Type: application/json" \
    -d "{\"text\":\"VPN Alert: $message\"}"
}

# Main health check loop
for endpoint_info in "${VPN_ENDPOINTS[@]}"; do
  IFS=':' read -r endpoint name <<< "$endpoint_info"
  
  if ! check_vpn_health $endpoint $name; then
    send_alert "$name connectivity failed"
    
    case $name in
      *wg*)
        repair_wireguard
        ;;
      *ipsec*|*strongswan*)
        repair_strongswan
        ;;
    esac
    
    # Recheck after repair
    sleep 30
    if check_vpn_health $endpoint $name; then
      send_alert "$name connectivity restored"
    else
      send_alert "$name repair failed - manual intervention required"
    fi
  fi
done
```

**Certificate Renewal Script:**
```bash
#!/bin/bash
# cert-renewal.sh

VAULT_ADDR="https://vault.federation.local"
CERT_PATH="/etc/ipsec.d/certs"
KEY_PATH="/etc/ipsec.d/private"
LOG_FILE="/var/log/cert-renewal.log"

renew_certificates() {
  echo "$(date): Starting certificate renewal" >> $LOG_FILE
  
  # Authenticate to Vault
  vault auth -method=kubernetes role=cert-renewal
  
  # Request new certificates
  vault write pki-intermediate/issue/vpn-certs \
    common_name="vpn.federation.local" \
    alt_names="vpn-openstack.federation.local,vpn-aws.federation.local" \
    ttl="8760h" \
    format="pem" > /tmp/new-certs.json
  
  # Extract certificates
  jq -r '.data.certificate' /tmp/new-certs.json > /tmp/new-cert.pem
  jq -r '.data.private_key' /tmp/new-certs.json > /tmp/new-key.pem
  jq -r '.data.ca_chain[]' /tmp/new-certs.json > /tmp/new-ca.pem
  
  # Backup old certificates
  sudo cp $CERT_PATH/cert.pem $CERT_PATH/cert.pem.bak
  sudo cp $KEY_PATH/key.pem $KEY_PATH/key.pem.bak
  
  # Install new certificates
  sudo cp /tmp/new-cert.pem $CERT_PATH/cert.pem
  sudo cp /tmp/new-key.pem $KEY_PATH/key.pem
  sudo cp /tmp/new-ca.pem $CERT_PATH/ca.pem
  
  # Set permissions
  sudo chmod 644 $CERT_PATH/cert.pem
  sudo chmod 600 $KEY_PATH/key.pem
  sudo chmod 644 $CERT_PATH/ca.pem
  
  # Reload StrongSwan
  sudo ipsec reload
  
  # Clean up
  rm -f /tmp/new-*
  
  echo "$(date): Certificate renewal completed" >> $LOG_FILE
}

# Check certificate expiry
CERT_EXPIRY=$(openssl x509 -in $CERT_PATH/cert.pem -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_UNTIL_EXPIRY=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

if [ $DAYS_UNTIL_EXPIRY -lt 30 ]; then
  echo "Certificate expires in $DAYS_UNTIL_EXPIRY days, renewing..." >> $LOG_FILE
  renew_certificates
else
  echo "Certificate valid for $DAYS_UNTIL_EXPIRY days" >> $LOG_FILE
fi
```

## Monitoring and Alerting

**Key Metrics:**
- VPN tunnel status (up/down)
- Packet loss percentage
- Round-trip time (RTT)
- Throughput (Mbps)
- Certificate expiry dates

**Alert Thresholds:**
- VPN tunnel down > 30 seconds
- Packet loss > 1%
- RTT > 100ms
- Certificate expiry < 30 days

**Grafana Queries:**
```promql
# VPN tunnel status
up{job="vpn-monitoring"}

# Packet loss rate
(increase(vpn_packets_dropped_total[5m]) / increase(vpn_packets_total[5m])) * 100

# Round-trip time
vpn_rtt_milliseconds

# Certificate expiry days
(vpn_cert_expiry_timestamp - time()) / 86400
```

## Testing and Validation

**Monthly VPN Tests:**
```bash
# Full connectivity test
fed-cli vpn test --comprehensive

# Performance benchmark
fed-cli network benchmark --all-paths --duration 300s

# Failover test
fed-cli vpn failover-test --primary wg0 --backup ipsec0
```

**Security Validation:**
```bash
# Verify encryption
tcpdump -i wg0 -c 10 -x

# Test certificate validation
openssl s_client -connect vpn.federation.local:443 -verify 5

# Audit VPN configurations
fed-cli security audit --component vpn
```

---

**Last Updated:** August 16, 2025  
**Version:** 2.0  
**Next Review:** September 15, 2025
