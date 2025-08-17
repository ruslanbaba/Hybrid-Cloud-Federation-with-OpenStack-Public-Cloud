# Burst Failover Runbook

## Overview
This runbook provides step-by-step procedures for handling burst failover scenarios in the hybrid cloud federation platform.

## Emergency Contacts
- **Platform Team Lead**: platform-team@company.com
- **On-Call Engineer**: +1-555-ONCALL
- **Security Team**: security@company.com
- **Incident Commander**: incident-commander@company.com

## Prerequisites
- Access to federation platform dashboards
- kubectl access to all clusters
- Vault authentication tokens
- Cloud provider CLI tools configured

## Burst Failover Scenarios

### Scenario 1: OpenStack Capacity Exhaustion

**Symptoms:**
- High resource utilization (>80%) in OpenStack
- Failed instance launches
- Slow API responses from Nova/Neutron

**Immediate Actions:**
```bash
# 1. Check current capacity
fed-cli capacity check --provider openstack
kubectl get nodes -o wide

# 2. Verify burst controller status
kubectl get pods -n burst-controller -l app=burst-controller
kubectl logs -n burst-controller deployment/burst-controller --tail=50

# 3. Manual burst trigger if automatic fails
fed-cli burst trigger --source openstack --target aws --workload-type web
```

**Detailed Procedure:**

1. **Assessment Phase (5 minutes)**
   ```bash
   # Check OpenStack resource usage
   openstack quota show
   openstack hypervisor stats show
   openstack server list --status ERROR

   # Check Kubernetes node status
   kubectl get nodes
   kubectl describe node | grep -A 10 "Allocated resources"
   
   # Verify networking
   fed-cli network status --provider openstack
   ```

2. **Burst Initiation (10 minutes)**
   ```bash
   # Identify workloads for migration
   fed-cli workload list --provider openstack --status running
   
   # Prioritize workloads (critical first)
   fed-cli workload prioritize --criteria "tier=critical"
   
   # Initiate burst to AWS
   fed-cli burst start \
     --source openstack \
     --target aws \
     --workload-count 10 \
     --instance-type m5.large
   
   # Monitor migration progress
   watch "fed-cli burst status"
   ```

3. **Validation Phase (15 minutes)**
   ```bash
   # Verify workloads are running in AWS
   aws ec2 describe-instances --filters "Name=tag:BurstMigration,Values=true"
   
   # Check application health
   fed-cli health check --provider aws --burst-only
   
   # Verify networking connectivity
   fed-cli network test --source openstack --target aws
   
   # Monitor application metrics
   curl -s "http://prometheus.federation.local/api/v1/query?query=up{job='burst-workloads'}"
   ```

**Rollback Procedure:**
```bash
# If burst fails, rollback to OpenStack
fed-cli burst rollback --burst-id <BURST_ID>

# Scale down non-critical workloads in OpenStack
fed-cli workload scale --provider openstack --tier non-critical --replicas 0

# Emergency capacity expansion (if available)
fed-cli capacity expand --provider openstack --nodes 5
```

### Scenario 2: Network Connectivity Issues

**Symptoms:**
- Cross-cloud networking failures
- VPN tunnel down
- BGP routing issues

**Immediate Actions:**
```bash
# 1. Check VPN status
fed-cli vpn status --all

# 2. Verify BGP routing
fed-cli bgp status --provider all

# 3. Test connectivity
fed-cli network ping --source openstack --target aws
```

**Detailed Network Troubleshooting:**

1. **VPN Diagnostics**
   ```bash
   # Check WireGuard tunnels
   sudo wg show
   
   # Verify IPsec tunnels (if using StrongSwan)
   sudo ipsec status
   sudo ipsec statusall
   
   # Check tunnel traffic
   sudo tcpdump -i wg0 -nn
   ```

2. **BGP Troubleshooting**
   ```bash
   # Check BGP sessions
   kubectl exec -n networking deployment/bgp-speaker -- vtysh -c "show bgp summary"
   
   # Verify routes
   kubectl exec -n networking deployment/bgp-speaker -- vtysh -c "show ip route bgp"
   
   # Check BGP neighbors
   kubectl exec -n networking deployment/bgp-speaker -- vtysh -c "show bgp neighbors"
   ```

3. **AWS Transit Gateway**
   ```bash
   # Check TGW status
   aws ec2 describe-transit-gateways
   
   # Verify route tables
   aws ec2 describe-transit-gateway-route-tables
   
   # Check VPN connections
   aws ec2 describe-vpn-connections
   ```

### Scenario 3: Authentication Failures

**Symptoms:**
- Keystone federation errors
- AWS STS assume role failures
- Vault authentication issues

**Immediate Actions:**
```bash
# 1. Check Vault status
vault status
vault auth list

# 2. Verify Keystone federation
openstack federation protocol list
openstack federation identity provider list

# 3. Test cross-cloud authentication
fed-cli auth test --provider all
```

## Monitoring and Alerting

**Key Metrics to Monitor:**
- Resource utilization across all clouds
- Network latency between providers
- Application response times
- Error rates during burst operations

**Alert Thresholds:**
- OpenStack CPU utilization > 80%
- Network latency > 100ms
- Failed burst attempts > 3 in 5 minutes
- Authentication failures > 5 in 1 minute

**Grafana Dashboards:**
- Burst Operations Overview: `https://grafana.federation.local/d/burst-ops`
- Network Health: `https://grafana.federation.local/d/network-health`
- Authentication Status: `https://grafana.federation.local/d/auth-status`

## Post-Incident Actions

1. **Documentation**
   ```bash
   # Generate incident report
   fed-cli incident report --start-time "2025-08-16T10:00:00Z" --end-time "2025-08-16T12:00:00Z"
   
   # Export logs for analysis
   fed-cli logs export --timerange "last 4 hours" --format json
   ```

2. **Capacity Planning**
   ```bash
   # Analyze resource trends
   fed-cli analytics capacity --provider openstack --days 30
   
   # Generate scaling recommendations
   fed-cli recommend scaling --provider openstack
   ```

3. **Update Runbooks**
   - Document lessons learned
   - Update escalation procedures
   - Refine monitoring thresholds

## Automation Scripts

**Quick Burst Script:**
```bash
#!/bin/bash
# quick-burst.sh
PROVIDER_SOURCE=${1:-openstack}
PROVIDER_TARGET=${2:-aws}
WORKLOAD_COUNT=${3:-5}

echo "Initiating emergency burst from $PROVIDER_SOURCE to $PROVIDER_TARGET"
fed-cli burst trigger \
  --source $PROVIDER_SOURCE \
  --target $PROVIDER_TARGET \
  --workload-count $WORKLOAD_COUNT \
  --priority high \
  --timeout 300

echo "Monitoring burst progress..."
while true; do
  STATUS=$(fed-cli burst status --format json | jq -r '.status')
  if [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]]; then
    break
  fi
  sleep 10
done

echo "Burst operation completed with status: $STATUS"
```

**Health Check Script:**
```bash
#!/bin/bash
# health-check.sh
echo "=== Federation Platform Health Check ==="

# Check all providers
for provider in openstack aws gcp azure; do
  echo "Checking $provider..."
  fed-cli health check --provider $provider
done

# Check networking
echo "Checking network connectivity..."
fed-cli network test --all

# Check authentication
echo "Checking authentication..."
fed-cli auth test --all

echo "=== Health Check Complete ==="
```

## Communication Templates

**Incident Notification:**
```
SUBJECT: [CRITICAL] Burst Failover Initiated - Federation Platform

INCIDENT: Burst failover from OpenStack to AWS initiated due to capacity constraints
TIME: {{ .timestamp }}
IMPACT: Workload migration in progress, temporary performance degradation possible
ACTIONS: Engineering team investigating, burst controller active
ETA: Resolution expected within 30 minutes
UPDATES: Monitor #platform-incidents channel for updates
```

**Resolution Notification:**
```
SUBJECT: [RESOLVED] Burst Failover Complete - Federation Platform

RESOLUTION: Burst failover completed successfully
WORKLOADS MIGRATED: {{ .workload_count }} workloads moved to AWS
DURATION: {{ .duration }} minutes
NEXT STEPS: Monitoring performance, planning capacity expansion
POST-MORTEM: Scheduled for {{ .postmortem_date }}
```

## Testing and Validation

**Monthly Burst Drill:**
```bash
# Scheduled burst testing
fed-cli gameday schedule \
  --scenario burst-failover \
  --date "first monday of month" \
  --duration 60m \
  --participants platform-team,sre-team
```

**Performance Benchmarks:**
- Burst initiation time: < 5 minutes
- Workload migration time: < 2 minutes per workload
- Network convergence time: < 30 seconds
- Application recovery time: < 60 seconds

---

**Last Updated:** August 16, 2025  
**Version:** 2.1  
**Next Review:** September 15, 2025
