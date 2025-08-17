package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	vaultapi "github.com/hashicorp/vault/api"
)

// AWSProvider implements CloudProvider for AWS
type AWSProvider struct {
	ec2Client     *ec2.Client
	pricingClient *pricing.Client
	vaultClient   *vaultapi.Client
	region        string
	credentials   *AWSCredentials
}

// AWSCredentials holds AWS authentication details
type AWSCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	AssumeRoleARN   string `json:"assume_role_arn"`
}

// NewAWSProvider creates a new AWS cloud provider
func NewAWSProvider(vaultClient *vaultapi.Client) (*AWSProvider, error) {
	// Get credentials from Vault
	credentials, err := getAWSCredentialsFromVault(vaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials: %v", err)
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-east-1"), // Default region, should be configurable
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Create service clients
	ec2Client := ec2.NewFromConfig(cfg)
	pricingClient := pricing.NewFromConfig(cfg)

	return &AWSProvider{
		ec2Client:     ec2Client,
		pricingClient: pricingClient,
		vaultClient:   vaultClient,
		region:        "us-east-1",
		credentials:   credentials,
	}, nil
}

// Name returns the provider name
func (p *AWSProvider) Name() string {
	return "aws"
}

// GetCapacity returns current AWS capacity information
func (p *AWSProvider) GetCapacity() (*CloudCapacity, error) {
	ctx := context.TODO()

	// Get running instances
	runningInstances, err := p.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
			{
				Name:   aws.String("tag:purpose"),
				Values: []string{"burst-workload"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %v", err)
	}

	// Calculate capacity based on running burst instances
	totalCPU := 0
	totalMemory := int64(0)
	
	for _, reservation := range runningInstances.Reservations {
		for _, instance := range reservation.Instances {
			// Map instance types to CPU/Memory (simplified)
			cpu, memory := p.getInstanceSpecs(string(instance.InstanceType))
			totalCPU += cpu
			totalMemory += memory
		}
	}

	// For AWS, we assume unlimited capacity for bursting
	// In practice, this would check service quotas and limits
	capacity := &CloudCapacity{
		TotalCPU:           totalCPU + 1000, // Assume 1000 vCPUs available
		AvailableCPU:       1000,           // Available for new instances
		TotalMemory:        totalMemory + (1000 * 4 * 1024 * 1024 * 1024), // 4GB per vCPU
		AvailableMemory:    1000 * 4 * 1024 * 1024 * 1024,
		UtilizationPercent: float64(totalCPU) / float64(totalCPU+1000) * 100,
	}

	return capacity, nil
}

// LaunchInstances launches new EC2 instances
func (p *AWSProvider) LaunchInstances(spec *InstanceSpec, count int) ([]*Instance, error) {
	ctx := context.TODO()

	// Get latest Amazon Linux 2 AMI
	imageID, err := p.getLatestAMI()
	if err != nil {
		return nil, fmt.Errorf("failed to get AMI: %v", err)
	}

	// Prepare launch template
	userData := p.generateUserData(spec)
	
	// Run instances
	result, err := p.ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId:          aws.String(imageID),
		InstanceType:     types.InstanceType(spec.InstanceType),
		MinCount:         aws.Int32(int32(count)),
		MaxCount:         aws.Int32(int32(count)),
		UserData:         aws.String(userData),
		SecurityGroupIds: spec.SecurityGroups,
		SubnetId:         aws.String(spec.Subnets[0]), // Use first subnet
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeInstance,
				Tags:         p.convertToEC2Tags(spec.Tags),
			},
		},
		IamInstanceProfile: &types.IamInstanceProfileSpecification{
			Name: aws.String("BurstWorkloadInstanceProfile"), // Pre-configured IAM role
		},
		Monitoring: &types.RunInstancesMonitoringEnabled{
			Enabled: aws.Bool(true),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run instances: %v", err)
	}

	// Convert to our instance format
	instances := make([]*Instance, 0, len(result.Instances))
	for _, ec2Instance := range result.Instances {
		instance := &Instance{
			ID:          *ec2Instance.InstanceId,
			Provider:    "aws",
			State:       string(ec2Instance.State.Name),
			LaunchTime:  *ec2Instance.LaunchTime,
			Tags:        p.convertFromEC2Tags(ec2Instance.Tags),
			CostPerHour: p.getInstanceCostPerHour(string(ec2Instance.InstanceType)),
		}

		if ec2Instance.PrivateIpAddress != nil {
			instance.IPAddress = *ec2Instance.PrivateIpAddress
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// TerminateInstances terminates specified EC2 instances
func (p *AWSProvider) TerminateInstances(instanceIDs []string) error {
	ctx := context.TODO()

	// Convert to AWS format
	awsInstanceIDs := make([]string, len(instanceIDs))
	copy(awsInstanceIDs, instanceIDs)

	_, err := p.ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: awsInstanceIDs,
	})
	if err != nil {
		return fmt.Errorf("failed to terminate instances: %v", err)
	}

	return nil
}

// GetCostPerHour returns the cost per hour for the default instance type
func (p *AWSProvider) GetCostPerHour() (float64, error) {
	// This would typically query AWS Pricing API
	// For now, return a mock value for t3.medium
	return 0.0416, nil // $0.0416/hour for t3.medium in us-east-1
}

// IsAvailable checks if the AWS provider is available
func (p *AWSProvider) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	// Simple health check - describe regions
	_, err := p.ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	return err == nil
}

// Helper methods

func (p *AWSProvider) getLatestAMI() (string, error) {
	ctx := context.TODO()

	// Get latest Amazon Linux 2 AMI
	result, err := p.ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"amazon"},
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{"amzn2-ami-hvm-*-x86_64-gp2"},
			},
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})
	if err != nil {
		return "", err
	}

	if len(result.Images) == 0 {
		return "", fmt.Errorf("no Amazon Linux 2 AMI found")
	}

	// Return the most recent AMI
	latestImage := result.Images[0]
	for _, image := range result.Images[1:] {
		if image.CreationDate != nil && latestImage.CreationDate != nil {
			latestTime, _ := time.Parse(time.RFC3339, *latestImage.CreationDate)
			currentTime, _ := time.Parse(time.RFC3339, *image.CreationDate)
			if currentTime.After(latestTime) {
				latestImage = image
			}
		}
	}

	return *latestImage.ImageId, nil
}

func (p *AWSProvider) generateUserData(spec *InstanceSpec) string {
	// Generate cloud-init user data for burst workload setup
	userData := `#!/bin/bash
yum update -y
yum install -y docker

# Start Docker service
systemctl start docker
systemctl enable docker

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Configure burst workload environment
mkdir -p /opt/burst-workload
cat > /opt/burst-workload/config.json << EOF
{
  "provider": "aws",
  "launched_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "purpose": "burst-workload",
  "controller_endpoint": "https://burst-controller.federation.local"
}
EOF

# Install monitoring agents
curl -sSL https://raw.githubusercontent.com/prometheus/node_exporter/master/node_exporter.sh | bash

# Signal successful initialization
curl -X POST https://burst-controller.federation.local/api/v1/instances/ready \
  -H "Content-Type: application/json" \
  -d '{"instance_id": "'$(curl -s http://169.254.169.254/latest/meta-data/instance-id)'", "provider": "aws"}'
`
	return userData
}

func (p *AWSProvider) convertToEC2Tags(tags map[string]string) []types.Tag {
	ec2Tags := make([]types.Tag, 0, len(tags))
	for key, value := range tags {
		ec2Tags = append(ec2Tags, types.Tag{
			Key:   aws.String(key),
			Value: aws.String(value),
		})
	}
	return ec2Tags
}

func (p *AWSProvider) convertFromEC2Tags(ec2Tags []types.Tag) map[string]string {
	tags := make(map[string]string)
	for _, tag := range ec2Tags {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}
	return tags
}

func (p *AWSProvider) getInstanceSpecs(instanceType string) (int, int64) {
	// Simplified mapping of instance types to CPU cores and memory (bytes)
	specs := map[string]struct {
		cpu    int
		memory int64
	}{
		"t3.micro":   {1, 1 * 1024 * 1024 * 1024},
		"t3.small":   {1, 2 * 1024 * 1024 * 1024},
		"t3.medium":  {2, 4 * 1024 * 1024 * 1024},
		"t3.large":   {2, 8 * 1024 * 1024 * 1024},
		"t3.xlarge":  {4, 16 * 1024 * 1024 * 1024},
		"t3.2xlarge": {8, 32 * 1024 * 1024 * 1024},
	}

	if spec, exists := specs[instanceType]; exists {
		return spec.cpu, spec.memory
	}

	// Default to t3.medium specs
	return 2, 4 * 1024 * 1024 * 1024
}

func (p *AWSProvider) getInstanceCostPerHour(instanceType string) float64 {
	// Simplified cost mapping (would typically use AWS Pricing API)
	costs := map[string]float64{
		"t3.micro":   0.0104,
		"t3.small":   0.0208,
		"t3.medium":  0.0416,
		"t3.large":   0.0832,
		"t3.xlarge":  0.1664,
		"t3.2xlarge": 0.3328,
	}

	if cost, exists := costs[instanceType]; exists {
		return cost
	}

	return 0.0416 // Default to t3.medium cost
}

func getAWSCredentialsFromVault(vaultClient *vaultapi.Client) (*AWSCredentials, error) {
	secret, err := vaultClient.Logical().Read("secret/cloud-federation/aws")
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no AWS credentials found in Vault")
	}

	credentials := &AWSCredentials{
		AccessKeyID:     getStringFromVault(secret.Data, "access_key_id"),
		SecretAccessKey: getStringFromVault(secret.Data, "secret_access_key"),
		SessionToken:    getStringFromVault(secret.Data, "session_token"),
		AssumeRoleARN:   getStringFromVault(secret.Data, "assume_role_arn"),
	}

	return credentials, nil
}

func getStringFromVault(data map[string]interface{}, key string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}
