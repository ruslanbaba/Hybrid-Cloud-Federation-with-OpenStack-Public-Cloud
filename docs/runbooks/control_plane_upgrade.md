# Control Plane Upgrade Runbook

## Overview
This runbook provides step-by-step procedures for upgrading the hybrid cloud federation control plane components, including Kubernetes clusters, OpenStack services, and federation controllers across all cloud environments.

## Emergency Contacts
- **Platform Team Lead**: platform@company.com
- **On-Call Platform Engineer**: +1-555-PLATFORM
- **SRE Team**: sre@company.com
- **Architecture Team**: architecture@company.com

## Upgrade Components Matrix

| Component | Current Version | Target Version | Upgrade Method | Downtime | Rollback Time |
|-----------|----------------|----------------|----------------|----------|---------------|
| Kubernetes | v1.28.x | v1.29.x | Rolling | None | 30 min |
| OpenStack | Yoga | Zed | Blue/Green | 2 hours | 1 hour |
| Istio | 1.18.x | 1.19.x | Canary | None | 15 min |
| Vault | 1.14.x | 1.15.x | Blue/Green | 5 min | 10 min |
| ETCD | 3.5.x | 3.5.y | Rolling | None | 20 min |
| Federation Controller | v2.1.x | v2.2.x | Canary | None | 5 min |

## Pre-Upgrade Requirements

### System Health Check
```bash
#!/bin/bash
# pre-upgrade-health-check.sh

echo "=== Pre-Upgrade Health Check ==="

# Check cluster health
kubectl get nodes -o wide
kubectl get pods --all-namespaces | grep -v Running | grep -v Completed

# Check control plane components
kubectl get componentstatuses

# Check ETCD health
kubectl exec -n kube-system etcd-master-0 -- etcdctl endpoint health \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Check federation controller health
fed-cli status --all-clouds

# Check OpenStack services
openstack service list --long
openstack compute service list
openstack network agent list

# Check storage health
kubectl get pv,pvc --all-namespaces
openstack volume service list

# Check networking
kubectl get networkpolicies --all-namespaces
openstack router list
openstack port list --device-owner network:router_gateway

# Check workload distribution
fed-cli workload status --detailed

echo "=== Health Check Complete ==="
```

### Backup Procedures
```bash
#!/bin/bash
# pre-upgrade-backup.sh

BACKUP_DIR="/backup/upgrade-$(date +%Y%m%d-%H%M%S)"
mkdir -p $BACKUP_DIR

echo "Starting comprehensive backup process..."

# ETCD Backup
kubectl exec -n kube-system etcd-master-0 -- etcdctl snapshot save /tmp/etcd-backup.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

kubectl cp kube-system/etcd-master-0:/tmp/etcd-backup.db $BACKUP_DIR/etcd-backup.db

# Kubernetes Resources
kubectl get all --all-namespaces -o yaml > $BACKUP_DIR/k8s-resources.yaml
kubectl get crd -o yaml > $BACKUP_DIR/crds.yaml
kubectl get secrets --all-namespaces -o yaml > $BACKUP_DIR/secrets.yaml
kubectl get configmaps --all-namespaces -o yaml > $BACKUP_DIR/configmaps.yaml

# Vault Backup
vault operator backup $BACKUP_DIR/vault-backup.snap

# OpenStack Database Backup
mysql-dump --all-databases --routines --triggers > $BACKUP_DIR/openstack-db.sql

# Federation Controller Configuration
fed-cli config export --all > $BACKUP_DIR/federation-config.yaml

# Terraform State Backup
cp -r /terraform/state $BACKUP_DIR/terraform-state

echo "Backup completed: $BACKUP_DIR"
echo "Backup size: $(du -sh $BACKUP_DIR)"
```

## Kubernetes Control Plane Upgrade

### Master Node Upgrade (Rolling)
```bash
#!/bin/bash
# k8s-master-upgrade.sh

TARGET_VERSION="1.29.8"
MASTERS=("master-0" "master-1" "master-2")

upgrade_master_node() {
  local node=$1
  
  echo "Upgrading master node: $node"
  
  # Drain node
  kubectl drain $node --ignore-daemonsets --delete-emptydir-data --force
  
  # SSH to node and upgrade
  ssh $node << EOF
    # Update package repository
    sudo apt-get update
    
    # Upgrade kubeadm
    sudo apt-mark unhold kubeadm
    sudo apt-get install -y kubeadm=$TARGET_VERSION-00
    sudo apt-mark hold kubeadm
    
    # Verify kubeadm version
    kubeadm version
    
    # Upgrade control plane
    sudo kubeadm upgrade plan
    
    if [ "$node" == "master-0" ]; then
      # First master - upgrade cluster
      sudo kubeadm upgrade apply v$TARGET_VERSION -y
    else
      # Other masters - upgrade node
      sudo kubeadm upgrade node
    fi
    
    # Upgrade kubelet and kubectl
    sudo apt-mark unhold kubelet kubectl
    sudo apt-get install -y kubelet=$TARGET_VERSION-00 kubectl=$TARGET_VERSION-00
    sudo apt-mark hold kubelet kubectl
    
    # Restart kubelet
    sudo systemctl daemon-reload
    sudo systemctl restart kubelet
EOF
  
  # Wait for node to be ready
  kubectl wait --for=condition=Ready node/$node --timeout=300s
  
  # Uncordon node
  kubectl uncordon $node
  
  echo "Master node $node upgraded successfully"
}

# Upgrade masters one by one
for master in "${MASTERS[@]}"; do
  upgrade_master_node $master
  
  # Wait between upgrades
  sleep 120
  
  # Verify cluster health
  kubectl get nodes
  kubectl get pods -n kube-system | grep -v Running
done

echo "All master nodes upgraded to $TARGET_VERSION"
```

### Worker Node Upgrade
```bash
#!/bin/bash
# k8s-worker-upgrade.sh

TARGET_VERSION="1.29.8"
WORKERS=($(kubectl get nodes --no-headers | grep -v master | awk '{print $1}'))

upgrade_worker_node() {
  local node=$1
  
  echo "Upgrading worker node: $node"
  
  # Drain node
  kubectl drain $node --ignore-daemonsets --delete-emptydir-data --force
  
  # SSH to node and upgrade
  ssh $node << EOF
    # Update package repository
    sudo apt-get update
    
    # Upgrade kubeadm
    sudo apt-mark unhold kubeadm
    sudo apt-get install -y kubeadm=$TARGET_VERSION-00
    sudo apt-mark hold kubeadm
    
    # Upgrade node
    sudo kubeadm upgrade node
    
    # Upgrade kubelet and kubectl
    sudo apt-mark unhold kubelet kubectl
    sudo apt-get install -y kubelet=$TARGET_VERSION-00 kubectl=$TARGET_VERSION-00
    sudo apt-mark hold kubelet kubectl
    
    # Restart kubelet
    sudo systemctl daemon-reload
    sudo systemctl restart kubelet
EOF
  
  # Wait for node to be ready
  kubectl wait --for=condition=Ready node/$node --timeout=300s
  
  # Uncordon node
  kubectl uncordon $node
  
  echo "Worker node $node upgraded successfully"
}

# Upgrade workers in batches to maintain capacity
BATCH_SIZE=3
for ((i=0; i<${#WORKERS[@]}; i+=BATCH_SIZE)); do
  echo "Upgrading worker batch: ${WORKERS[@]:$i:$BATCH_SIZE}"
  
  # Upgrade batch in parallel
  for ((j=0; j<BATCH_SIZE && i+j<${#WORKERS[@]}; j++)); do
    upgrade_worker_node "${WORKERS[$i+$j]}" &
  done
  
  # Wait for batch to complete
  wait
  
  # Verify cluster health
  kubectl get nodes
  kubectl top nodes
  
  echo "Batch completed, waiting before next batch..."
  sleep 60
done

echo "All worker nodes upgraded to $TARGET_VERSION"
```

## OpenStack Services Upgrade

### OpenStack Control Plane Upgrade (Blue/Green)
```bash
#!/bin/bash
# openstack-upgrade.sh

SOURCE_RELEASE="yoga"
TARGET_RELEASE="zed"
SERVICES=("keystone" "glance" "nova" "neutron" "cinder" "heat" "horizon")

# Create new environment for target release
create_target_environment() {
  echo "Creating target environment for $TARGET_RELEASE"
  
  # Deploy new OpenStack environment
  cd /opt/openstack-ansible
  git checkout stable/$TARGET_RELEASE
  
  # Update configuration for new release
  cp -r /etc/openstack_deploy /etc/openstack_deploy_$TARGET_RELEASE
  
  # Update inventory for blue/green deployment
  ansible-playbook playbooks/os-greenfield-setup.yml \
    -e target_release=$TARGET_RELEASE \
    -e source_release=$SOURCE_RELEASE
  
  # Deploy new services alongside existing ones
  ansible-playbook playbooks/setup-everything.yml \
    -e openstack_release=$TARGET_RELEASE \
    -e deployment_mode=blue_green
}

# Database migration
migrate_databases() {
  echo "Migrating databases for $TARGET_RELEASE"
  
  for service in "${SERVICES[@]}"; do
    echo "Migrating $service database..."
    
    # Run database migrations
    ansible-playbook playbooks/os-$service-install.yml \
      -e openstack_release=$TARGET_RELEASE \
      -e db_migrate_only=true \
      --tags db_migrate
  done
}

# Service validation
validate_services() {
  echo "Validating $TARGET_RELEASE services"
  
  # Set environment for new release
  source /opt/openstack/$TARGET_RELEASE/admin-openrc
  
  # Test each service
  openstack token issue
  openstack image list
  openstack server list
  openstack network list
  openstack volume list
  
  # Run tempest tests
  cd /opt/tempest
  tempest run --regex "^tempest\.api\.identity.*test_tokens"
  tempest run --regex "^tempest\.api\.compute.*test_list_servers"
  tempest run --regex "^tempest\.api\.network.*test_list_networks"
}

# Traffic switchover
switchover_traffic() {
  echo "Switching traffic to $TARGET_RELEASE"
  
  # Update load balancer configuration
  ansible-playbook playbooks/haproxy-config.yml \
    -e backend_release=$TARGET_RELEASE
  
  # Update DNS records
  ansible-playbook playbooks/dns-update.yml \
    -e target_environment=$TARGET_RELEASE
  
  # Restart HAProxy
  ansible-playbook playbooks/restart-haproxy.yml
}

# Execute upgrade process
echo "Starting OpenStack upgrade from $SOURCE_RELEASE to $TARGET_RELEASE"

create_target_environment
migrate_databases
validate_services

# Pause for manual verification
echo "Services deployed and validated. Press Enter to switch traffic..."
read -p "Continue with traffic switchover? (yes/no): " confirm

if [ "$confirm" == "yes" ]; then
  switchover_traffic
  echo "Traffic switched to $TARGET_RELEASE"
  
  # Final validation
  validate_services
  
  echo "OpenStack upgrade completed successfully"
else
  echo "Traffic switchover cancelled. New environment available for testing."
fi
```

## Istio Service Mesh Upgrade

### Istio Canary Upgrade
```bash
#!/bin/bash
# istio-upgrade.sh

CURRENT_VERSION="1.18.2"
TARGET_VERSION="1.19.1"

# Download and install new Istio version
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$TARGET_VERSION sh -
cd istio-$TARGET_VERSION
export PATH=$PWD/bin:$PATH

# Install new revision
istioctl install --set values.pilot.env.EXTERNAL_ISTIOD=false \
  --set revision=$TARGET_VERSION \
  --set values.pilot.env.PILOT_ENABLE_WORKLOAD_ENTRY_AUTOREGISTRATION=true

# Verify installation
kubectl get pods -n istio-system -l app=istiod
kubectl get pods -n istio-system -l istio.io/rev=$TARGET_VERSION

# Label namespace for canary deployment
kubectl label namespace production istio.io/rev=$TARGET_VERSION --overwrite
kubectl label namespace production istio-injection-

# Restart workloads to pick up new sidecars
kubectl rollout restart deployment -n production

# Wait for rollout to complete
kubectl rollout status deployment -n production --timeout=600s

# Validate new version
istioctl proxy-config cluster -n production <pod-name>
istioctl version

# Remove old revision after validation
kubectl delete service -n istio-system -l istio.io/rev=$CURRENT_VERSION
kubectl delete deployment -n istio-system -l istio.io/rev=$CURRENT_VERSION
istioctl uninstall --revision $CURRENT_VERSION

echo "Istio upgrade from $CURRENT_VERSION to $TARGET_VERSION completed"
```

## Vault Upgrade

### Vault Blue/Green Upgrade
```bash
#!/bin/bash
# vault-upgrade.sh

CURRENT_VERSION="1.14.8"
TARGET_VERSION="1.15.2"
VAULT_NAMESPACE="vault-system"

# Create new Vault deployment
upgrade_vault() {
  echo "Upgrading Vault from $CURRENT_VERSION to $TARGET_VERSION"
  
  # Scale down current Vault (prepare for blue/green)
  kubectl scale statefulset vault -n $VAULT_NAMESPACE --replicas=0
  
  # Update Vault image
  kubectl patch statefulset vault -n $VAULT_NAMESPACE \
    -p='{"spec":{"template":{"spec":{"containers":[{"name":"vault","image":"vault:'$TARGET_VERSION'"}]}}}}'
  
  # Scale up with new version
  kubectl scale statefulset vault -n $VAULT_NAMESPACE --replicas=3
  
  # Wait for pods to be ready
  kubectl wait --for=condition=Ready pod -l app=vault -n $VAULT_NAMESPACE --timeout=300s
  
  # Unseal Vault with existing keys
  VAULT_PODS=$(kubectl get pods -n $VAULT_NAMESPACE -l app=vault -o jsonpath='{.items[*].metadata.name}')
  
  for pod in $VAULT_PODS; do
    echo "Unsealing $pod..."
    kubectl exec -n $VAULT_NAMESPACE $pod -- vault operator unseal $UNSEAL_KEY_1
    kubectl exec -n $VAULT_NAMESPACE $pod -- vault operator unseal $UNSEAL_KEY_2
    kubectl exec -n $VAULT_NAMESPACE $pod -- vault operator unseal $UNSEAL_KEY_3
  done
  
  # Verify Vault health
  kubectl exec -n $VAULT_NAMESPACE vault-0 -- vault status
  kubectl exec -n $VAULT_NAMESPACE vault-0 -- vault auth list
  
  echo "Vault upgrade completed successfully"
}

# Backup Vault data before upgrade
kubectl exec -n $VAULT_NAMESPACE vault-0 -- vault operator backup /tmp/vault-backup-$(date +%Y%m%d).snap

# Perform upgrade
upgrade_vault

# Test Vault functionality
kubectl exec -n $VAULT_NAMESPACE vault-0 -- vault kv get secret/test
```

## Federation Controller Upgrade

### Canary Deployment
```bash
#!/bin/bash
# federation-controller-upgrade.sh

CURRENT_VERSION="v2.1.3"
TARGET_VERSION="v2.2.0"
NAMESPACE="federation-system"

# Deploy canary version
deploy_canary() {
  echo "Deploying federation controller canary: $TARGET_VERSION"
  
  # Create canary deployment
  kubectl patch deployment federation-controller -n $NAMESPACE \
    -p='{"spec":{"template":{"metadata":{"labels":{"version":"'$TARGET_VERSION'"}},"spec":{"containers":[{"name":"controller","image":"federation-controller:'$TARGET_VERSION'"}]}}}}'
  
  # Scale up canary deployment
  kubectl scale deployment federation-controller-canary -n $NAMESPACE --replicas=1
  
  # Wait for canary to be ready
  kubectl wait --for=condition=Available deployment/federation-controller-canary -n $NAMESPACE --timeout=300s
}

# Traffic splitting
configure_traffic_split() {
  echo "Configuring traffic split: 90% stable, 10% canary"
  
  # Update VirtualService for traffic splitting
  kubectl apply -f - << EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: federation-controller
  namespace: $NAMESPACE
spec:
  hosts:
  - federation-controller
  http:
  - match:
    - headers:
        canary:
          exact: "true"
    route:
    - destination:
        host: federation-controller
        subset: canary
  - route:
    - destination:
        host: federation-controller
        subset: stable
      weight: 90
    - destination:
        host: federation-controller
        subset: canary
      weight: 10
EOF
}

# Validation and promotion
validate_and_promote() {
  echo "Validating canary deployment..."
  
  # Run validation tests
  fed-cli validate --endpoint=http://federation-controller-canary:8080
  
  # Check metrics
  prometheus_query="rate(http_requests_total{service=\"federation-controller-canary\"}[5m])"
  ERROR_RATE=$(curl -s "http://prometheus:9090/api/v1/query?query=$prometheus_query" | jq '.data.result[0].value[1]')
  
  if (( $(echo "$ERROR_RATE < 0.01" | bc -l) )); then
    echo "Canary validation successful. Promoting to 100%..."
    
    # Full promotion
    kubectl patch deployment federation-controller -n $NAMESPACE \
      -p='{"spec":{"template":{"spec":{"containers":[{"name":"controller","image":"federation-controller:'$TARGET_VERSION'"}]}}}}'
    
    # Scale down canary
    kubectl scale deployment federation-controller-canary -n $NAMESPACE --replicas=0
    
    echo "Federation controller upgrade completed successfully"
  else
    echo "Canary validation failed. Rolling back..."
    kubectl scale deployment federation-controller-canary -n $NAMESPACE --replicas=0
    exit 1
  fi
}

# Execute canary upgrade
deploy_canary
configure_traffic_split
sleep 300  # Monitor for 5 minutes
validate_and_promote
```

## Post-Upgrade Validation

### Comprehensive System Test
```bash
#!/bin/bash
# post-upgrade-validation.sh

echo "=== Post-Upgrade Validation ==="

# Test Kubernetes cluster
echo "Testing Kubernetes functionality..."
kubectl get nodes
kubectl get pods --all-namespaces | grep -v Running | grep -v Completed
kubectl create namespace test-upgrade
kubectl run test-pod --image=nginx --restart=Never -n test-upgrade
kubectl wait --for=condition=Ready pod/test-pod -n test-upgrade --timeout=60s
kubectl delete namespace test-upgrade

# Test OpenStack services
echo "Testing OpenStack services..."
source /opt/openstack/admin-openrc
openstack token issue
openstack image list
openstack flavor list
openstack network list

# Test federation controller
echo "Testing federation controller..."
fed-cli status --all-clouds
fed-cli workload create test-workload --image nginx --replicas 2
fed-cli workload delete test-workload

# Test service mesh
echo "Testing Istio service mesh..."
kubectl exec -n istio-system deployment/istiod -- pilot-discovery version
istioctl proxy-status

# Test storage
echo "Testing storage..."
kubectl get storageclass
openstack volume type list

# Test networking
echo "Testing networking..."
kubectl get networkpolicies --all-namespaces
openstack security group list

# Performance benchmarks
echo "Running performance benchmarks..."
fed-cli benchmark --duration 30s

echo "=== Validation Complete ==="
```

## Rollback Procedures

### Emergency Rollback Script
```bash
#!/bin/bash
# emergency-rollback.sh

COMPONENT=$1
BACKUP_DIR=$2

case $COMPONENT in
  "kubernetes")
    echo "Rolling back Kubernetes..."
    # Restore ETCD
    kubectl scale deployment --all -n kube-system --replicas=0
    etcdctl snapshot restore $BACKUP_DIR/etcd-backup.db
    systemctl restart etcd
    ;;
    
  "openstack")
    echo "Rolling back OpenStack..."
    # Switch back to previous environment
    ansible-playbook playbooks/haproxy-config.yml -e backend_release=yoga
    ansible-playbook playbooks/restart-haproxy.yml
    ;;
    
  "vault")
    echo "Rolling back Vault..."
    kubectl patch statefulset vault -n vault-system \
      -p='{"spec":{"template":{"spec":{"containers":[{"name":"vault","image":"vault:1.14.8"}]}}}}'
    ;;
    
  "federation")
    echo "Rolling back Federation Controller..."
    kubectl rollout undo deployment/federation-controller -n federation-system
    ;;
    
  *)
    echo "Unknown component: $COMPONENT"
    exit 1
    ;;
esac

echo "Rollback completed for $COMPONENT"
```

## Monitoring and Alerting

### Upgrade Monitoring Dashboard
```yaml
# upgrade-monitoring.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: upgrade-dashboard
  namespace: monitoring
data:
  dashboard.json: |
    {
      "dashboard": {
        "title": "Control Plane Upgrade Monitoring",
        "panels": [
          {
            "title": "Component Versions",
            "type": "stat",
            "targets": [
              {
                "expr": "kubernetes_build_info",
                "legendFormat": "Kubernetes {{version}}"
              },
              {
                "expr": "vault_version_info", 
                "legendFormat": "Vault {{version}}"
              }
            ]
          },
          {
            "title": "Upgrade Progress",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(upgrade_operations_total[5m])",
                "legendFormat": "{{component}} upgrade rate"
              }
            ]
          },
          {
            "title": "Error Rate During Upgrade",
            "type": "graph", 
            "targets": [
              {
                "expr": "rate(http_requests_total{code!~\"2..\"}[5m])",
                "legendFormat": "Error rate"
              }
            ]
          }
        ]
      }
    }
```

### Upgrade Alerts
```yaml
groups:
- name: upgrade-alerts
  rules:
  - alert: UpgradeInProgress
    expr: upgrade_in_progress == 1
    for: 0m
    labels:
      severity: info
    annotations:
      summary: "Control plane upgrade in progress"
      
  - alert: UpgradeFailed
    expr: upgrade_failed == 1
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Control plane upgrade failed"
      description: "Upgrade of {{ $labels.component }} has failed"
      
  - alert: HighErrorRateDuringUpgrade
    expr: rate(http_requests_total{code!~\"2..\"}[5m]) > 0.05
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate during upgrade"
```

## Maintenance Windows

### Scheduled Upgrade Windows
- **Monthly Patches**: First Saturday of each month, 2:00-6:00 AM UTC
- **Minor Upgrades**: Quarterly, during scheduled maintenance windows
- **Major Upgrades**: Bi-annually, with extended maintenance windows

### Communication Template
```
Subject: Scheduled Control Plane Upgrade - [DATE]

Dear Users,

We will be performing a scheduled upgrade of the hybrid cloud federation platform:

Date: [DATE]
Time: [TIME] - [TIME] UTC
Duration: [ESTIMATED_DURATION]
Impact: [IMPACT_DESCRIPTION]

Components being upgraded:
- Kubernetes: [OLD_VERSION] → [NEW_VERSION]
- OpenStack: [OLD_VERSION] → [NEW_VERSION]
- Istio: [OLD_VERSION] → [NEW_VERSION]

Expected improvements:
- [FEATURE_1]
- [SECURITY_UPDATE_1]
- [PERFORMANCE_IMPROVEMENT_1]

Please plan accordingly and contact the platform team if you have any concerns.

Platform Team
```

---

**Last Updated:** August 16, 2025  
**Version:** 2.0  
**Next Review:** September 15, 2025  
**Upgrade Schedule:** Available in maintenance calendar
