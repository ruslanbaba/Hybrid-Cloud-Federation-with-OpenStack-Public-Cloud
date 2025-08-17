# Key Rotation Runbook

## Overview
This runbook provides comprehensive procedures for rotating cryptographic keys across all components of the hybrid cloud federation platform, including service accounts, certificates, encryption keys, and authentication tokens.

## Emergency Contacts
- **Security Team Lead**: security@company.com
- **On-Call Security Engineer**: +1-555-SECURITY
- **Platform Team**: platform-team@company.com
- **Compliance Officer**: compliance@company.com

## Key Rotation Schedule

| Component | Rotation Frequency | Lead Time | Automation |
|-----------|-------------------|-----------|------------|
| Service Account Keys | 90 days | 7 days | Automated |
| TLS Certificates | 90 days | 14 days | Automated |
| API Keys | 60 days | 3 days | Semi-automated |
| Database Encryption Keys | 1 year | 30 days | Manual |
| Root CA | 5 years | 90 days | Manual |
| Vault Unseal Keys | Annual | 60 days | Manual |
| SSH Host Keys | 180 days | 7 days | Automated |

## Pre-Rotation Checklist

- [ ] Verify all backup systems are operational
- [ ] Check monitoring and alerting systems
- [ ] Notify stakeholder teams 48 hours in advance
- [ ] Prepare rollback procedures
- [ ] Test rotation in staging environment
- [ ] Schedule maintenance windows
- [ ] Update change management tickets

## Service Account Key Rotation

### AWS IAM Keys

**Automated Process:**
```bash
#!/bin/bash
# aws-key-rotation.sh

AWS_ACCOUNTS=("prod-123456789" "staging-987654321")
SERVICE_USERS=("federation-service" "monitoring-service" "backup-service")

rotate_aws_keys() {
  local account=$1
  local username=$2
  
  echo "Rotating keys for $username in account $account"
  
  # Assume role in target account
  aws sts assume-role \
    --role-arn "arn:aws:iam::$account:role/KeyRotationRole" \
    --role-session-name "key-rotation-$(date +%s)"
  
  # Get current access keys
  CURRENT_KEYS=$(aws iam list-access-keys --user-name $username --query 'AccessKeyMetadata[*].AccessKeyId' --output text)
  
  # Create new access key
  NEW_KEY=$(aws iam create-access-key --user-name $username)
  NEW_ACCESS_KEY=$(echo $NEW_KEY | jq -r '.AccessKey.AccessKeyId')
  NEW_SECRET_KEY=$(echo $NEW_KEY | jq -r '.AccessKey.SecretAccessKey')
  
  # Store new key in Vault
  vault kv put secret/aws/$account/$username \
    access_key="$NEW_ACCESS_KEY" \
    secret_key="$NEW_SECRET_KEY" \
    rotation_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  
  # Update External Secrets Operator
  kubectl patch secretstore aws-secret-store -n federation-system \
    --type='merge' \
    -p="{\"spec\":{\"provider\":{\"aws\":{\"auth\":{\"secretRef\":{\"accessKeyIDSecretRef\":{\"name\":\"aws-credentials\",\"key\":\"access-key-id\"},\"secretAccessKeySecretRef\":{\"name\":\"aws-credentials\",\"key\":\"secret-access-key\"}}}}}}}"
  
  # Wait for propagation
  echo "Waiting 60 seconds for key propagation..."
  sleep 60
  
  # Test new key
  export AWS_ACCESS_KEY_ID=$NEW_ACCESS_KEY
  export AWS_SECRET_ACCESS_KEY=$NEW_SECRET_KEY
  
  if aws sts get-caller-identity >/dev/null 2>&1; then
    echo "New key validated successfully"
    
    # Delete old keys
    for old_key in $CURRENT_KEYS; do
      aws iam delete-access-key --user-name $username --access-key-id $old_key
      echo "Deleted old key: $old_key"
    done
  else
    echo "New key validation failed! Rolling back..."
    aws iam delete-access-key --user-name $username --access-key-id $NEW_ACCESS_KEY
    exit 1
  fi
}

# Rotate keys for all accounts and users
for account in "${AWS_ACCOUNTS[@]}"; do
  for user in "${SERVICE_USERS[@]}"; do
    rotate_aws_keys $account $user
    sleep 30  # Rate limiting
  done
done
```

### GCP Service Account Keys

**Automated Process:**
```bash
#!/bin/bash
# gcp-key-rotation.sh

GCP_PROJECTS=("federation-prod" "federation-staging")
SERVICE_ACCOUNTS=("federation-sa@federation-prod.iam.gserviceaccount.com" "monitoring-sa@federation-prod.iam.gserviceaccount.com")

rotate_gcp_keys() {
  local project=$1
  local sa_email=$2
  
  echo "Rotating keys for $sa_email in project $project"
  
  # Set project context
  gcloud config set project $project
  
  # Create new service account key
  NEW_KEY_FILE="/tmp/new-sa-key-$(date +%s).json"
  gcloud iam service-accounts keys create $NEW_KEY_FILE \
    --iam-account=$sa_email
  
  # Extract key details
  KEY_ID=$(jq -r '.private_key_id' $NEW_KEY_FILE)
  
  # Store new key in Vault
  vault kv put secret/gcp/$project/$(echo $sa_email | cut -d@ -f1) \
    service_account_key=@$NEW_KEY_FILE \
    key_id="$KEY_ID" \
    rotation_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  
  # Update Kubernetes secret
  kubectl create secret generic gcp-credentials \
    --from-file=key.json=$NEW_KEY_FILE \
    --namespace=federation-system \
    --dry-run=client -o yaml | kubectl apply -f -
  
  # Test new key
  export GOOGLE_APPLICATION_CREDENTIALS=$NEW_KEY_FILE
  if gcloud auth application-default print-access-token >/dev/null 2>&1; then
    echo "New key validated successfully"
    
    # List and delete old keys (keep latest 2)
    OLD_KEYS=$(gcloud iam service-accounts keys list \
      --iam-account=$sa_email \
      --format="value(name)" \
      --filter="keyType:USER_MANAGED" | head -n -2)
    
    for old_key in $OLD_KEYS; do
      if [ ! -z "$old_key" ]; then
        gcloud iam service-accounts keys delete $old_key \
          --iam-account=$sa_email \
          --quiet
        echo "Deleted old key: $old_key"
      fi
    done
  else
    echo "New key validation failed!"
    exit 1
  fi
  
  # Clean up temp file
  rm -f $NEW_KEY_FILE
}

# Rotate keys for all projects and service accounts
for project in "${GCP_PROJECTS[@]}"; do
  for sa in "${SERVICE_ACCOUNTS[@]}"; do
    rotate_gcp_keys $project $sa
    sleep 30
  done
done
```

## TLS Certificate Rotation

### Vault PKI Certificate Rotation

**Semi-Automated Process:**
```bash
#!/bin/bash
# cert-rotation.sh

VAULT_ADDR="https://vault.federation.local"
CERT_ROLES=("server-certs" "client-certs" "vpn-certs")
NAMESPACES=("federation-system" "monitoring" "security")

rotate_certificates() {
  local role=$1
  local namespace=$2
  
  echo "Rotating certificates for role: $role in namespace: $namespace"
  
  # Authenticate to Vault
  vault auth -method=kubernetes role=cert-manager
  
  # Issue new certificate
  CERT_RESPONSE=$(vault write pki-intermediate/issue/$role \
    common_name="$role.federation.local" \
    alt_names="$role.svc.cluster.local,$role.$namespace.svc.cluster.local" \
    ttl="2160h" \
    format="pem")
  
  # Extract certificate components
  echo "$CERT_RESPONSE" | jq -r '.data.certificate' > /tmp/cert.pem
  echo "$CERT_RESPONSE" | jq -r '.data.private_key' > /tmp/key.pem
  echo "$CERT_RESPONSE" | jq -r '.data.ca_chain[]' > /tmp/ca.pem
  
  # Create/update Kubernetes secret
  kubectl create secret tls $role-tls \
    --cert=/tmp/cert.pem \
    --key=/tmp/key.pem \
    --namespace=$namespace \
    --dry-run=client -o yaml | kubectl apply -f -
  
  # Add CA certificate to secret
  kubectl patch secret $role-tls -n $namespace \
    -p="{\"data\":{\"ca.crt\":\"$(base64 -w 0 /tmp/ca.pem)\"}}"
  
  # Restart deployments using the certificate
  kubectl rollout restart deployment -n $namespace -l cert-rotation=true
  
  # Verify certificate installation
  kubectl get secret $role-tls -n $namespace -o jsonpath='{.data.tls\.crt}' | \
    base64 -d | openssl x509 -noout -dates
  
  # Clean up temp files
  rm -f /tmp/cert.pem /tmp/key.pem /tmp/ca.pem
  
  echo "Certificate rotation completed for $role"
}

# Rotate certificates for all roles and namespaces
for role in "${CERT_ROLES[@]}"; do
  for namespace in "${NAMESPACES[@]}"; do
    rotate_certificates $role $namespace
    sleep 15
  done
done
```

### Let's Encrypt Certificate Rotation

**Automated via cert-manager:**
```yaml
# cert-manager-automation.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: federation-api-cert
  namespace: federation-system
spec:
  secretName: federation-api-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - api.federation.local
  - dashboard.federation.local
  duration: 2160h # 90 days
  renewBefore: 720h # 30 days before expiry
```

## Database Encryption Key Rotation

### PostgreSQL Encryption Keys

**Manual Process (High Risk):**
```bash
#!/bin/bash
# postgres-key-rotation.sh

DB_CLUSTERS=("federation-primary" "federation-replica")
BACKUP_LOCATION="/backup/postgres"

rotate_postgres_encryption() {
  local cluster=$1
  
  echo "Starting encryption key rotation for cluster: $cluster"
  
  # Step 1: Full backup before rotation
  kubectl exec -n postgres-operator $cluster-0 -- \
    pg_dump -h localhost -U postgres federation_db | \
    gzip > $BACKUP_LOCATION/$cluster-$(date +%Y%m%d-%H%M%S).sql.gz
  
  # Step 2: Generate new encryption key
  NEW_KEY=$(openssl rand -hex 32)
  
  # Step 3: Store new key in Vault
  vault kv put secret/postgres/$cluster/encryption \
    key="$NEW_KEY" \
    rotation_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    previous_rotation="$(vault kv get -field=rotation_date secret/postgres/$cluster/encryption 2>/dev/null || echo 'never')"
  
  # Step 4: Update PostgreSQL configuration
  kubectl patch postgresql $cluster -n postgres-operator --type='merge' \
    -p="{\"spec\":{\"parameters\":{\"data_encryption_key\":\"$NEW_KEY\"}}}"
  
  # Step 5: Trigger cluster restart
  kubectl patch postgresql $cluster -n postgres-operator \
    -p="{\"metadata\":{\"annotations\":{\"restart-$(date +%s)\":\"true\"}}}"
  
  # Step 6: Wait for cluster to be ready
  kubectl wait --for=condition=Ready pod -l postgres-operator.crunchydata.com/cluster=$cluster \
    -n postgres-operator --timeout=600s
  
  # Step 7: Verify database access
  kubectl exec -n postgres-operator $cluster-0 -- \
    psql -h localhost -U postgres -d federation_db -c "SELECT 1;"
  
  if [ $? -eq 0 ]; then
    echo "Database encryption key rotation completed successfully"
  else
    echo "Database access verification failed! Manual intervention required."
    exit 1
  fi
}

# Rotate encryption keys for all clusters
for cluster in "${DB_CLUSTERS[@]}"; do
  rotate_postgres_encryption $cluster
  sleep 300  # Wait 5 minutes between clusters
done
```

## API Key Rotation

### OpenStack Service Keys

**Semi-Automated Process:**
```bash
#!/bin/bash
# openstack-key-rotation.sh

OPENSTACK_SERVICES=("nova" "neutron" "cinder" "glance" "keystone")
CLOUDS=("openstack-prod" "openstack-staging")

rotate_openstack_keys() {
  local cloud=$1
  local service=$2
  
  echo "Rotating $service keys in $cloud"
  
  # Source OpenStack credentials
  source /opt/openstack/$cloud/admin-openrc
  
  # Create new service user (with suffix for identification)
  NEW_USER="${service}-svc-$(date +%Y%m%d)"
  NEW_PASSWORD=$(openssl rand -base64 32)
  
  openstack user create $NEW_USER \
    --password $NEW_PASSWORD \
    --project service \
    --description "Service account for $service ($(date +%Y-%m-%d))"
  
  # Assign necessary roles
  openstack role add --user $NEW_USER --project service admin
  openstack role add --user $NEW_USER --project service service
  
  # Store new credentials in Vault
  vault kv put secret/openstack/$cloud/$service \
    username="$NEW_USER" \
    password="$NEW_PASSWORD" \
    rotation_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  
  # Update External Secrets to use new credentials
  kubectl patch externalsecret openstack-$service-credentials \
    -n federation-system \
    --type='merge' \
    -p="{\"spec\":{\"data\":[{\"secretKey\":\"username\",\"remoteRef\":{\"key\":\"secret/openstack/$cloud/$service\",\"property\":\"username\"}},{\"secretKey\":\"password\",\"remoteRef\":{\"key\":\"secret/openstack/$cloud/$service\",\"property\":\"password\"}}]}}"
  
  # Wait for secret synchronization
  sleep 30
  
  # Test new credentials
  export OS_USERNAME=$NEW_USER
  export OS_PASSWORD=$NEW_PASSWORD
  
  if openstack token issue >/dev/null 2>&1; then
    echo "New credentials validated successfully"
    
    # Find and delete old service accounts (keep last 2)
    OLD_USERS=$(openstack user list --format value -c Name | \
      grep "^${service}-svc-" | head -n -2)
    
    for old_user in $OLD_USERS; do
      if [ ! -z "$old_user" ]; then
        openstack user delete $old_user
        echo "Deleted old user: $old_user"
      fi
    done
  else
    echo "New credentials validation failed!"
    openstack user delete $NEW_USER
    exit 1
  fi
}

# Rotate keys for all services and clouds
for cloud in "${CLOUDS[@]}"; do
  for service in "${OPENSTACK_SERVICES[@]}"; do
    rotate_openstack_keys $cloud $service
    sleep 60
  done
done
```

## SSH Host Key Rotation

**Automated Process:**
```bash
#!/bin/bash
# ssh-key-rotation.sh

HOSTS_FILE="/etc/ansible/hosts"
KEY_TYPES=("rsa" "ecdsa" "ed25519")

rotate_ssh_host_keys() {
  local hostname=$1
  
  echo "Rotating SSH host keys for: $hostname"
  
  # Backup existing keys
  ansible $hostname -m shell -a "tar -czf /tmp/ssh-keys-backup-$(date +%Y%m%d).tar.gz /etc/ssh/ssh_host_*"
  
  # Generate new host keys
  for key_type in "${KEY_TYPES[@]}"; do
    ansible $hostname -m shell -a "ssh-keygen -t $key_type -f /etc/ssh/ssh_host_${key_type}_key -N '' -q"
  done
  
  # Restart SSH service
  ansible $hostname -m systemd -a "name=ssh state=restarted"
  
  # Update known_hosts
  ssh-keyscan -t rsa,ecdsa,ed25519 $hostname > /tmp/new_known_hosts_$hostname
  
  # Store new host keys in Vault for reference
  for key_type in "${KEY_TYPES[@]}"; do
    PUB_KEY=$(ansible $hostname -m shell -a "cat /etc/ssh/ssh_host_${key_type}_key.pub" | grep -v "SUCCESS" | tail -1)
    vault kv put secret/ssh-host-keys/$hostname/$key_type \
      public_key="$PUB_KEY" \
      rotation_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  done
  
  echo "SSH host key rotation completed for $hostname"
}

# Get list of hosts from Ansible inventory
HOSTS=$(ansible-inventory --list | jq -r '.all.children | to_entries[] | .value.hosts[]?' | sort -u)

# Rotate keys for all hosts
for host in $HOSTS; do
  rotate_ssh_host_keys $host
  sleep 30
done

echo "All SSH host key rotations completed"
echo "Please update your known_hosts files with the new keys from /tmp/new_known_hosts_*"
```

## Vault Unseal Key Rotation

**Manual Process (Critical):**
```bash
#!/bin/bash
# vault-unseal-rotation.sh

VAULT_ADDR="https://vault.federation.local"
BACKUP_DIR="/secure-backup/vault"

echo "WARNING: This is a critical operation that requires multiple operators"
echo "Ensure you have at least 3 unseal key holders available"
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
  exit 1
fi

# Step 1: Backup current Vault data
vault operator backup $BACKUP_DIR/vault-backup-$(date +%Y%m%d-%H%M%S).snap

# Step 2: Initialize key rotation
echo "Initializing unseal key rotation..."
vault operator rekey -init -key-shares=5 -key-threshold=3

# The following steps require manual intervention with existing unseal keys
echo "Manual steps required:"
echo "1. Collect unseal keys from key holders"
echo "2. Run: vault operator rekey -key-share=<share1>"
echo "3. Repeat for threshold number of shares"
echo "4. Distribute new unseal keys to key holders"
echo "5. Test unsealing with new keys"
echo "6. Securely destroy old unseal keys"

# Generate recovery instructions
cat > $BACKUP_DIR/recovery-instructions-$(date +%Y%m%d).txt << EOF
Vault Unseal Key Rotation Recovery Instructions
Generated: $(date)

In case of issues during rotation:
1. Stop rotation: vault operator rekey -cancel
2. Restore from backup: vault operator restore $BACKUP_DIR/vault-backup-$(date +%Y%m%d-%H%M%S).snap
3. Contact security team immediately

New Key Distribution:
- Key Holder 1: security-lead@company.com
- Key Holder 2: platform-lead@company.com  
- Key Holder 3: cto@company.com
- Key Holder 4: devops-lead@company.com
- Key Holder 5: backup-operator@company.com

Next scheduled rotation: $(date -d "+1 year" +%Y-%m-%d)
EOF
```

## Post-Rotation Validation

**Comprehensive Testing:**
```bash
#!/bin/bash
# post-rotation-validation.sh

validate_aws_access() {
  echo "Validating AWS access..."
  aws sts get-caller-identity
  aws s3 ls
  echo "AWS validation: $?"
}

validate_gcp_access() {
  echo "Validating GCP access..."
  gcloud auth list
  gcloud projects list
  echo "GCP validation: $?"
}

validate_openstack_access() {
  echo "Validating OpenStack access..."
  openstack token issue
  openstack server list
  echo "OpenStack validation: $?"
}

validate_certificates() {
  echo "Validating certificates..."
  for cert in $(kubectl get certificates -A -o jsonpath='{.items[*].metadata.name}'); do
    kubectl describe certificate $cert | grep -E "(Ready|Status)"
  done
}

validate_database_access() {
  echo "Validating database access..."
  kubectl exec -n postgres-operator federation-primary-0 -- \
    psql -h localhost -U postgres -d federation_db -c "SELECT version();"
}

validate_ssh_access() {
  echo "Validating SSH access..."
  ansible all -m ping
}

# Run all validations
validate_aws_access
validate_gcp_access  
validate_openstack_access
validate_certificates
validate_database_access
validate_ssh_access

echo "Post-rotation validation completed"
```

## Monitoring and Alerting

**Key Rotation Metrics:**
```promql
# Certificate expiry monitoring
(cert_expiry_timestamp - time()) / 86400 < 30

# Key rotation success rate
rate(key_rotation_success_total[1h]) / rate(key_rotation_attempts_total[1h])

# Failed authentication attempts after rotation
rate(authentication_failures_total[5m]) > 10
```

**Alert Rules:**
```yaml
groups:
- name: key-rotation
  rules:
  - alert: CertificateExpiringSoon
    expr: (cert_expiry_timestamp - time()) / 86400 < 30
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: "Certificate expiring soon"
      description: "Certificate {{ $labels.cert_name }} expires in {{ $value }} days"
      
  - alert: KeyRotationFailed
    expr: increase(key_rotation_failures_total[1h]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Key rotation failed"
      description: "Key rotation failed for {{ $labels.component }}"
```

## Emergency Procedures

**Rollback Process:**
1. Stop all rotation processes
2. Restore previous keys from Vault backup
3. Update all service configurations
4. Restart affected services
5. Validate functionality
6. Investigate failure cause

**Incident Response:**
1. Immediately notify security team
2. Assess impact and affected systems
3. Implement emergency access if needed
4. Document all actions taken
5. Conduct post-incident review

---

**Last Updated:** August 16, 2025  
**Version:** 2.0  
**Next Review:** September 15, 2025  
**Key Rotation Schedule:** Available in security calendar
