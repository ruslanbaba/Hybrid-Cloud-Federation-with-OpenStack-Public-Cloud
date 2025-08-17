# Enterprise Makefile for Hybrid Cloud Federation
# Principal Engineer Level - Production-Ready Automation

.PHONY: help install validate deploy destroy test security-scan cost-analysis backup restore

# Default environment
ENV ?= staging
REGION ?= us-east-1
VAULT_ADDR ?= https://vault.federation.local

# Color codes for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
help: ## Display this help message
	@echo "$(BLUE)Enterprise Hybrid Cloud Federation - Management Interface$(NC)"
	@echo "$(BLUE)================================================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Usage:$(NC) make [target] [ENV=environment] [REGION=region]"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make deploy ENV=staging REGION=us-west-2"
	@echo "  make destroy ENV=staging"
	@echo "  make test ENV=production"
	@echo ""

# Prerequisites check
check-prerequisites: ## Check if all required tools are installed
	@echo "$(BLUE)Checking prerequisites...$(NC)"
	@command -v terraform >/dev/null 2>&1 || { echo "$(RED)Error: terraform is required$(NC)"; exit 1; }
	@command -v ansible >/dev/null 2>&1 || { echo "$(RED)Error: ansible is required$(NC)"; exit 1; }
	@command -v vault >/dev/null 2>&1 || { echo "$(RED)Error: vault CLI is required$(NC)"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "$(RED)Error: kubectl is required$(NC)"; exit 1; }
	@command -v aws >/dev/null 2>&1 || { echo "$(RED)Error: aws CLI is required$(NC)"; exit 1; }
	@command -v gcloud >/dev/null 2>&1 || { echo "$(RED)Error: gcloud CLI is required$(NC)"; exit 1; }
	@command -v az >/dev/null 2>&1 || { echo "$(RED)Error: az CLI is required$(NC)"; exit 1; }
	@echo "$(GREEN)All prerequisites satisfied$(NC)"

# Installation and setup
install: check-prerequisites ## Install and configure all dependencies
	@echo "$(BLUE)Installing dependencies and configuring environment...$(NC)"
	@./scripts/install-dependencies.sh
	@./scripts/setup-vault.sh
	@echo "$(GREEN)Installation completed$(NC)"

# Vault authentication
vault-auth: ## Authenticate with Vault using current credentials
	@echo "$(BLUE)Authenticating with Vault...$(NC)"
	@if [ -z "$(VAULT_TOKEN)" ]; then \
		vault auth -method=userpass username=$(USER) || \
		vault auth -method=aws || \
		vault auth -method=kubernetes; \
	else \
		vault auth -token=$(VAULT_TOKEN); \
	fi
	@echo "$(GREEN)Vault authentication successful$(NC)"

# Cloud authentication
auth-clouds: vault-auth ## Authenticate with all cloud providers
	@echo "$(BLUE)Authenticating with cloud providers...$(NC)"
	@./scripts/auth-aws.sh $(ENV)
	@./scripts/auth-gcp.sh $(ENV)  
	@./scripts/auth-azure.sh $(ENV)
	@./scripts/auth-openstack.sh $(ENV)
	@echo "$(GREEN)Cloud authentication completed$(NC)"

# Validation and testing
validate: check-prerequisites ## Validate all configurations and code
	@echo "$(BLUE)Validating configurations...$(NC)"
	@echo "$(YELLOW)Validating Terraform...$(NC)"
	@cd terraform && terraform fmt -check -recursive
	@cd terraform && find . -name "*.tf" -exec dirname {} \; | sort -u | while read dir; do \
		echo "Validating $$dir"; \
		(cd "$$dir" && terraform init -backend=false && terraform validate); \
	done
	
	@echo "$(YELLOW)Validating Ansible...$(NC)"
	@cd ansible && find . -name "*.yml" -o -name "*.yaml" | xargs ansible-playbook --syntax-check
	
	@echo "$(YELLOW)Validating OPA Policies...$(NC)"
	@opa fmt --diff policies/opa/
	@opa test policies/opa/
	
	@echo "$(YELLOW)Validating Go code...$(NC)"
	@cd controller/src && go mod tidy && go vet ./... && go test ./...
	
	@echo "$(GREEN)All validations passed$(NC)"

# Security scanning
security-scan: ## Run comprehensive security scans
	@echo "$(BLUE)Running security scans...$(NC)"
	@echo "$(YELLOW)Scanning for secrets...$(NC)"
	@trufflehog filesystem . --only-verified
	
	@echo "$(YELLOW)Scanning Terraform configurations...$(NC)"
	@checkov -d terraform/ --framework terraform
	
	@echo "$(YELLOW)Scanning container images...$(NC)"
	@if [ -f "controller/Dockerfile" ]; then \
		trivy config controller/; \
	fi
	
	@echo "$(YELLOW)Scanning dependencies...$(NC)"
	@cd controller/src && go list -json -deps ./... | nancy sleuth
	
	@echo "$(GREEN)Security scan completed$(NC)"

# Infrastructure deployment
terraform-init: auth-clouds ## Initialize Terraform with remote backend
	@echo "$(BLUE)Initializing Terraform for $(ENV) environment...$(NC)"
	@cd terraform && terraform init \
		-backend-config="environments/$(ENV)/backend.conf" \
		-backend-config="region=$(REGION)"

terraform-plan: terraform-init ## Generate Terraform execution plan
	@echo "$(BLUE)Generating Terraform plan for $(ENV)...$(NC)"
	@cd terraform && terraform plan \
		-var-file="environments/$(ENV)/terraform.tfvars" \
		-var="environment=$(ENV)" \
		-var="region=$(REGION)" \
		-out="$(ENV).tfplan"

terraform-apply: terraform-plan ## Apply Terraform configuration
	@echo "$(BLUE)Applying Terraform configuration for $(ENV)...$(NC)"
	@cd terraform && terraform apply "$(ENV).tfplan"
	@echo "$(GREEN)Infrastructure deployment completed$(NC)"

# Configuration management
ansible-configure: ## Configure services with Ansible
	@echo "$(BLUE)Configuring services with Ansible for $(ENV)...$(NC)"
	@cd ansible && ansible-playbook \
		-i inventory/$(ENV) \
		playbooks/main.yml \
		--extra-vars "environment=$(ENV) region=$(REGION)"
	@echo "$(GREEN)Service configuration completed$(NC)"

# Full deployment
deploy: validate terraform-apply ansible-configure ## Deploy complete federation infrastructure
	@echo "$(BLUE)Starting full deployment for $(ENV) environment...$(NC)"
	@./scripts/post-deploy-validation.sh $(ENV)
	@echo "$(GREEN)Deployment completed successfully!$(NC)"
	@echo "$(YELLOW)Federation endpoints:$(NC)"
	@cd terraform && terraform output -json federation_endpoints | jq -r '.[] | to_entries[] | "  \(.key): \(.value)"'

# Container builds
build-images: ## Build all container images
	@echo "$(BLUE)Building container images...$(NC)"
	@docker build -t federation-burst-controller:latest controller/
	@docker build -t federation-monitoring:latest monitoring/
	@docker build -t federation-networking:latest networking/
	@echo "$(GREEN)Container images built successfully$(NC)"

# Testing
test-unit: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	@cd controller/src && go test -v -race -coverprofile=coverage.out ./...
	@cd ansible && molecule test

test-integration: deploy ## Run integration tests
	@echo "$(BLUE)Running integration tests for $(ENV)...$(NC)"
	@cd tests/integration && python -m pytest -v --environment=$(ENV)

test-load: ## Run load tests
	@echo "$(BLUE)Running load tests...$(NC)"
	@cd tests/load && ./run-load-tests.sh $(ENV)

test: test-unit test-integration ## Run all tests

# Monitoring and observability
setup-monitoring: ## Setup monitoring dashboards
	@echo "$(BLUE)Setting up monitoring for $(ENV)...$(NC)"
	@cd monitoring && ./setup-grafana-dashboards.sh $(ENV)
	@cd monitoring && ./setup-prometheus-rules.sh $(ENV)
	@echo "$(GREEN)Monitoring setup completed$(NC)"

# Backup and restore
backup: auth-clouds ## Backup critical data and configurations
	@echo "$(BLUE)Creating backup for $(ENV) environment...$(NC)"
	@./scripts/backup.sh $(ENV) $(shell date +%Y%m%d_%H%M%S)
	@echo "$(GREEN)Backup completed$(NC)"

restore: auth-clouds ## Restore from backup
	@echo "$(BLUE)Restoring $(ENV) environment from backup...$(NC)"
	@if [ -z "$(BACKUP_ID)" ]; then \
		echo "$(RED)Error: BACKUP_ID is required. Usage: make restore ENV=staging BACKUP_ID=20231201_140000$(NC)"; \
		exit 1; \
	fi
	@./scripts/restore.sh $(ENV) $(BACKUP_ID)
	@echo "$(GREEN)Restore completed$(NC)"

# Cost analysis
cost-analysis: ## Generate cost analysis report
	@echo "$(BLUE)Generating cost analysis for $(ENV)...$(NC)"
	@cd terraform && terraform plan -var-file="environments/$(ENV)/terraform.tfvars" | \
		infracost breakdown --path - --format table
	@./scripts/cost-report.sh $(ENV)
	@echo "$(GREEN)Cost analysis completed$(NC)"

# Scaling operations
scale-out: ## Scale out burst capacity
	@echo "$(BLUE)Scaling out burst capacity for $(ENV)...$(NC)"
	@curl -X POST \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $(shell vault write -field=token auth/kubernetes/login role=burst-controller jwt=$(shell cat /var/run/secrets/kubernetes.io/serviceaccount/token))" \
		-d '{"provider":"aws","count":$(COUNT)}' \
		https://burst-controller.$(ENV).federation.local/api/v1/burst

scale-in: ## Scale in burst capacity
	@echo "$(BLUE)Scaling in burst capacity for $(ENV)...$(NC)"
	@curl -X DELETE \
		-H "Authorization: Bearer $(shell vault write -field=token auth/kubernetes/login role=burst-controller jwt=$(shell cat /var/run/secrets/kubernetes.io/serviceaccount/token))" \
		https://burst-controller.$(ENV).federation.local/api/v1/burst

# Compliance and governance
compliance-check: ## Run compliance validation
	@echo "$(BLUE)Running compliance checks for $(ENV)...$(NC)"
	@./scripts/compliance-check.sh $(ENV)
	@echo "$(GREEN)Compliance check completed$(NC)"

policy-update: ## Update OPA policies
	@echo "$(BLUE)Updating OPA policies...$(NC)"
	@kubectl apply -f policies/opa/ -n federation-system
	@echo "$(GREEN)Policies updated$(NC)"

# Maintenance operations
rotate-secrets: vault-auth ## Rotate all secrets and certificates
	@echo "$(BLUE)Rotating secrets for $(ENV)...$(NC)"
	@./scripts/rotate-secrets.sh $(ENV)
	@echo "$(GREEN)Secret rotation completed$(NC)"

update-certificates: ## Update TLS certificates
	@echo "$(BLUE)Updating certificates for $(ENV)...$(NC)"
	@./scripts/update-certificates.sh $(ENV)
	@echo "$(GREEN)Certificate update completed$(NC)"

# Cleanup operations
clean-terraform: ## Clean Terraform state and cache
	@echo "$(BLUE)Cleaning Terraform cache...$(NC)"
	@cd terraform && find . -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@cd terraform && find . -name "*.tfplan" -type f -delete
	@echo "$(GREEN)Terraform cleanup completed$(NC)"

clean-ansible: ## Clean Ansible cache
	@echo "$(BLUE)Cleaning Ansible cache...$(NC)"
	@rm -rf ansible/.ansible_cache
	@rm -rf ansible/retry_files
	@echo "$(GREEN)Ansible cleanup completed$(NC)"

clean: clean-terraform clean-ansible ## Clean all cache and temporary files
	@echo "$(GREEN)All cleanup completed$(NC)"

# Disaster recovery
disaster-recovery: ## Initiate disaster recovery procedures
	@echo "$(RED)Initiating disaster recovery for $(ENV)...$(NC)"
	@./scripts/disaster-recovery.sh $(ENV)
	@echo "$(GREEN)Disaster recovery procedures initiated$(NC)"

# Infrastructure destruction
destroy-confirm: ## Confirm destruction (safety check)
	@echo "$(RED)WARNING: This will destroy the $(ENV) environment!$(NC)"
	@echo "$(YELLOW)Type 'yes' to confirm destruction:$(NC)"
	@read confirmation && [ "$$confirmation" = "yes" ]

destroy: destroy-confirm terraform-init ## Destroy infrastructure (use with extreme caution)
	@echo "$(RED)Destroying $(ENV) environment...$(NC)"
	@cd terraform && terraform destroy \
		-var-file="environments/$(ENV)/terraform.tfvars" \
		-var="environment=$(ENV)" \
		-auto-approve
	@echo "$(RED)Environment $(ENV) has been destroyed$(NC)"

# Status and information
status: ## Display federation status
	@echo "$(BLUE)Federation Status for $(ENV):$(NC)"
	@echo ""
	@curl -s https://burst-controller.$(ENV).federation.local/api/v1/status | jq .
	@echo ""
	@kubectl get pods -n federation-system --field-selector=status.phase=Running
	@echo ""

endpoints: terraform-init ## Display all federation endpoints
	@echo "$(BLUE)Federation Endpoints for $(ENV):$(NC)"
	@cd terraform && terraform output -json federation_endpoints | jq -r '.[] | to_entries[] | "  \(.key): \(.value)"'

logs: ## Display recent logs
	@echo "$(BLUE)Recent logs for $(ENV):$(NC)"
	@kubectl logs -n federation-system -l app=burst-controller --tail=100
	@kubectl logs -n monitoring -l app=prometheus --tail=50

# Development helpers
dev-setup: ## Setup development environment
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@./scripts/dev-setup.sh
	@echo "$(GREEN)Development environment ready$(NC)"

format: ## Format all code
	@echo "$(BLUE)Formatting code...$(NC)"
	@cd terraform && terraform fmt -recursive
	@cd controller/src && go fmt ./...
	@cd ansible && find . -name "*.yml" -o -name "*.yaml" | xargs prettier --write
	@echo "$(GREEN)Code formatting completed$(NC)"

# Documentation
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@cd terraform && terraform-docs markdown table --output-file README.md .
	@cd controller/src && godoc -http=:6060 &
	@echo "$(GREEN)Documentation generated$(NC)"

# Version information
version: ## Display version information
	@echo "$(BLUE)Version Information:$(NC)"
	@echo "Terraform: $(shell terraform version -json | jq -r '.terraform_version')"
	@echo "Ansible: $(shell ansible --version | head -n1 | awk '{print $$2}')"
	@echo "Vault: $(shell vault version | head -n1 | awk '{print $$2}')"
	@echo "Kubectl: $(shell kubectl version --client -o json | jq -r '.clientVersion.gitVersion')"
	@echo "Federation: v1.0.0"

# Emergency procedures
emergency-stop: ## Emergency stop all services
	@echo "$(RED)EMERGENCY STOP: Stopping all federation services...$(NC)"
	@kubectl scale deployment --replicas=0 -n federation-system --all
	@echo "$(RED)All services stopped$(NC)"

emergency-start: ## Emergency start all services
	@echo "$(GREEN)EMERGENCY START: Starting all federation services...$(NC)"
	@kubectl scale deployment --replicas=1 -n federation-system --all
	@echo "$(GREEN)All services started$(NC)"
