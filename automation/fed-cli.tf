# Federation CLI Tool
# Comprehensive management interface for hybrid cloud federation operations

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    kubectl = {
      source  = "alekc/kubectl"
      version = "~> 2.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

# Build federation CLI
resource "docker_image" "fed_cli" {
  name = "federation-cli:latest"
  build {
    context    = "${path.module}/cli"
    dockerfile = "Dockerfile"
    build_args = {
      VERSION = var.cli_version
    }
  }
}

# CLI configuration
resource "kubernetes_config_map" "fed_cli_config" {
  metadata {
    name      = "fed-cli-config"
    namespace = "federation-system"
  }

  data = {
    "config.yaml" = yamlencode({
      clouds = {
        openstack = {
          auth_url    = var.openstack_auth_url
          region      = var.openstack_region
          api_version = "3"
        }
        aws = {
          region      = var.aws_region
          api_version = "2020-05-31"
        }
        gcp = {
          project = var.gcp_project
          region  = var.gcp_region
        }
        azure = {
          subscription_id = var.azure_subscription_id
          tenant_id      = var.azure_tenant_id
          region         = var.azure_region
        }
      }
      federation = {
        controller_endpoint = "https://federation-controller.federation-system.svc.cluster.local"
        api_version        = "v1"
        timeout           = "30s"
      }
      monitoring = {
        prometheus_url = var.prometheus_url
        grafana_url   = var.grafana_url
      }
      logging = {
        level = "info"
        format = "json"
      }
    })
  }
}

# CLI deployment (for scheduled operations)
resource "kubernetes_deployment" "fed_cli_scheduler" {
  metadata {
    name      = "fed-cli-scheduler"
    namespace = "federation-system"
    labels = {
      app = "fed-cli-scheduler"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "fed-cli-scheduler"
      }
    }

    template {
      metadata {
        labels = {
          app = "fed-cli-scheduler"
        }
      }

      spec {
        service_account_name = "fed-cli"

        container {
          name  = "scheduler"
          image = docker_image.fed_cli.name

          command = ["/bin/sh", "-c"]
          args = [
            "while true; do fed-cli scheduled-tasks run; sleep 300; done"
          ]

          env {
            name = "FED_CLI_CONFIG"
            value = "/etc/fed-cli/config.yaml"
          }

          volume_mount {
            name       = "config"
            mount_path = "/etc/fed-cli"
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }
        }

        volume {
          name = "config"
          config_map {
            name = kubernetes_config_map.fed_cli_config.metadata[0].name
          }
        }
      }
    }
  }
}

# Service account for CLI operations
resource "kubernetes_service_account" "fed_cli" {
  metadata {
    name      = "fed-cli"
    namespace = "federation-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.fed_cli_role.arn
    }
  }
}

# RBAC for CLI operations
resource "kubernetes_cluster_role" "fed_cli" {
  metadata {
    name = "fed-cli"
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "services", "configmaps", "secrets", "nodes"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies", "ingresses"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["federation.io"]
    resources  = ["*"]
    verbs      = ["*"]
  }

  rule {
    api_groups = ["metrics.k8s.io"]
    resources  = ["pods", "nodes"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_cluster_role_binding" "fed_cli" {
  metadata {
    name = "fed-cli"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.fed_cli.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.fed_cli.metadata[0].name
    namespace = "federation-system"
  }
}

# AWS IAM role for CLI
resource "aws_iam_role" "fed_cli_role" {
  name = "federation-cli-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = var.eks_oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${var.eks_oidc_provider}:sub" = "system:serviceaccount:federation-system:fed-cli"
            "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "fed_cli_policy" {
  name = "federation-cli-policy"
  role = aws_iam_role.fed_cli_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "ecs:*",
          "eks:*",
          "s3:*",
          "iam:PassRole",
          "cloudwatch:*",
          "logs:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# CLI Docker image build context
resource "local_file" "dockerfile" {
  filename = "${path.module}/cli/Dockerfile"
  content = <<EOF
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.version=$VERSION" -o fed-cli ./cmd/fed-cli

FROM alpine:3.18

RUN apk --no-cache add ca-certificates curl jq
WORKDIR /root/

COPY --from=builder /app/fed-cli /usr/local/bin/fed-cli

# Install additional tools
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

RUN curl -L https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -o /usr/local/bin/yq && \
    chmod +x /usr/local/bin/yq

ENTRYPOINT ["fed-cli"]
EOF
}

# CLI source code structure
resource "local_file" "main_go" {
  filename = "${path.module}/cli/cmd/fed-cli/main.go"
  content = <<EOF
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/federation/cli/pkg/commands"
	"github.com/federation/cli/pkg/config"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "fed-cli",
		Short: "Federation CLI for hybrid cloud management",
		Long:  "A comprehensive CLI tool for managing hybrid cloud federation across OpenStack, AWS, GCP, and Azure",
		Version: version,
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Add commands
	rootCmd.AddCommand(
		commands.NewStatusCommand(cfg),
		commands.NewWorkloadCommand(cfg),
		commands.NewNetworkCommand(cfg),
		commands.NewSecurityCommand(cfg),
		commands.NewMonitoringCommand(cfg),
		commands.NewBenchmarkCommand(cfg),
		commands.NewVPNCommand(cfg),
		commands.NewBackupCommand(cfg),
		commands.NewScheduledTasksCommand(cfg),
		commands.NewValidateCommand(cfg),
		commands.NewConfigCommand(cfg),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
EOF
}

# Go module definition
resource "local_file" "go_mod" {
  filename = "${path.module}/cli/go.mod"
  content = <<EOF
module github.com/federation/cli

go 1.21

require (
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.17.0
	k8s.io/client-go v0.28.3
	k8s.io/api v0.28.3
	k8s.io/apimachinery v0.28.3
	github.com/prometheus/client_golang v1.17.0
	github.com/aws/aws-sdk-go-v2 v1.21.0
	github.com/aws/aws-sdk-go-v2/config v1.18.45
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.120.0
	google.golang.org/api v0.149.0
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/gophercloud/gophercloud v1.7.0
	gopkg.in/yaml.v3 v3.0.1
)
EOF
}

# Status command implementation
resource "local_file" "status_command" {
  filename = "${path.module}/cli/pkg/commands/status.go"
  content = <<EOF
package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/federation/cli/pkg/config"
	"github.com/federation/cli/pkg/federation"
	"github.com/federation/cli/pkg/clouds"
)

func NewStatusCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show federation status across all clouds",
		Long:  "Display comprehensive status information for the hybrid cloud federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cfg, cmd.Flags())
		},
	}

	cmd.Flags().Bool("all-clouds", false, "Show status for all clouds")
	cmd.Flags().String("cloud", "", "Show status for specific cloud (openstack, aws, gcp, azure)")
	cmd.Flags().Bool("detailed", false, "Show detailed status information")

	return cmd
}

func runStatus(cfg *config.Config, flags *pflag.FlagSet) error {
	ctx := context.Background()
	
	allClouds, _ := flags.GetBool("all-clouds")
	cloud, _ := flags.GetString("cloud")
	detailed, _ := flags.GetBool("detailed")

	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "CLOUD\tSTATUS\tNODES\tWORKLOADS\tLAST_SYNC\tHEALTH")

	if cloud != "" {
		return showCloudStatus(ctx, w, cfg, fedClient, cloud, detailed)
	}

	if allClouds || cloud == "" {
		clouds := []string{"openstack", "aws", "gcp", "azure"}
		for _, cloudName := range clouds {
			if err := showCloudStatus(ctx, w, cfg, fedClient, cloudName, detailed); err != nil {
				fmt.Fprintf(os.Stderr, "Error getting status for %s: %v\n", cloudName, err)
			}
		}
	}

	return nil
}

func showCloudStatus(ctx context.Context, w *tabwriter.Writer, cfg *config.Config, fedClient *federation.Client, cloudName string, detailed bool) error {
	status, err := fedClient.GetCloudStatus(ctx, cloudName)
	if err != nil {
		fmt.Fprintf(w, "%s\tERROR\t-\t-\t-\t%v\n", cloudName, err)
		return nil
	}

	fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
		cloudName,
		status.Status,
		status.NodeCount,
		status.WorkloadCount,
		status.LastSync.Format(time.RFC3339),
		status.Health,
	)

	if detailed {
		fmt.Fprintf(w, "\tRegion: %s\n", status.Region)
		fmt.Fprintf(w, "\tAvailable Resources: CPU: %s, Memory: %s, Storage: %s\n",
			status.Resources.CPU, status.Resources.Memory, status.Resources.Storage)
		fmt.Fprintf(w, "\tNetwork Status: %s\n", status.NetworkStatus)
	}

	return nil
}
EOF
}

# Workload management command
resource "local_file" "workload_command" {
  filename = "${path.module}/cli/pkg/commands/workload.go"
  content = <<EOF
package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/federation/cli/pkg/config"
	"github.com/federation/cli/pkg/federation"
)

func NewWorkloadCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workload",
		Short: "Manage workloads across clouds",
		Long:  "Create, delete, scale, and manage workloads in the federation",
	}

	cmd.AddCommand(
		newWorkloadListCommand(cfg),
		newWorkloadCreateCommand(cfg),
		newWorkloadDeleteCommand(cfg),
		newWorkloadScaleCommand(cfg),
		newWorkloadMigrateCommand(cfg),
	)

	return cmd
}

func newWorkloadListCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all workloads",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listWorkloads(cfg)
		},
	}
}

func newWorkloadCreateCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new workload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			image, _ := cmd.Flags().GetString("image")
			replicas, _ := cmd.Flags().GetInt("replicas")
			clouds, _ := cmd.Flags().GetStringSlice("clouds")
			
			return createWorkload(cfg, name, image, replicas, clouds)
		},
	}

	cmd.Flags().String("image", "", "Container image for the workload")
	cmd.Flags().Int("replicas", 1, "Number of replicas")
	cmd.Flags().StringSlice("clouds", []string{}, "Target clouds for deployment")
	cmd.MarkFlagRequired("image")

	return cmd
}

func newWorkloadDeleteCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a workload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			return deleteWorkload(cfg, name)
		},
	}
}

func newWorkloadScaleCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scale <name>",
		Short: "Scale a workload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			replicas, _ := cmd.Flags().GetInt("replicas")
			return scaleWorkload(cfg, name, replicas)
		},
	}

	cmd.Flags().Int("replicas", 1, "New replica count")
	cmd.MarkFlagRequired("replicas")

	return cmd
}

func newWorkloadMigrateCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate <name>",
		Short: "Migrate a workload between clouds",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			fromCloud, _ := cmd.Flags().GetString("from")
			toCloud, _ := cmd.Flags().GetString("to")
			return migrateWorkload(cfg, name, fromCloud, toCloud)
		},
	}

	cmd.Flags().String("from", "", "Source cloud")
	cmd.Flags().String("to", "", "Destination cloud")
	cmd.MarkFlagRequired("from")
	cmd.MarkFlagRequired("to")

	return cmd
}

func listWorkloads(cfg *config.Config) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	workloads, err := fedClient.ListWorkloads(ctx)
	if err != nil {
		return fmt.Errorf("failed to list workloads: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "NAME\tIMAGE\tREPLICAS\tCLOUDS\tSTATUS\tAGE")

	for _, workload := range workloads {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
			workload.Name,
			workload.Image,
			workload.Replicas,
			strings.Join(workload.Clouds, ","),
			workload.Status,
			workload.Age,
		)
	}

	return nil
}

func createWorkload(cfg *config.Config, name, image string, replicas int, clouds []string) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	workload := &federation.Workload{
		Name:     name,
		Image:    image,
		Replicas: replicas,
		Clouds:   clouds,
	}

	if err := fedClient.CreateWorkload(ctx, workload); err != nil {
		return fmt.Errorf("failed to create workload: %w", err)
	}

	fmt.Printf("Workload %s created successfully\n", name)
	return nil
}

func deleteWorkload(cfg *config.Config, name string) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	if err := fedClient.DeleteWorkload(ctx, name); err != nil {
		return fmt.Errorf("failed to delete workload: %w", err)
	}

	fmt.Printf("Workload %s deleted successfully\n", name)
	return nil
}

func scaleWorkload(cfg *config.Config, name string, replicas int) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	if err := fedClient.ScaleWorkload(ctx, name, replicas); err != nil {
		return fmt.Errorf("failed to scale workload: %w", err)
	}

	fmt.Printf("Workload %s scaled to %d replicas\n", name, replicas)
	return nil
}

func migrateWorkload(cfg *config.Config, name, fromCloud, toCloud string) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	migration := &federation.WorkloadMigration{
		WorkloadName: name,
		FromCloud:    fromCloud,
		ToCloud:      toCloud,
	}

	if err := fedClient.MigrateWorkload(ctx, migration); err != nil {
		return fmt.Errorf("failed to migrate workload: %w", err)
	}

	fmt.Printf("Workload %s migration from %s to %s initiated\n", name, fromCloud, toCloud)
	return nil
}
EOF
}

# Network management command
resource "local_file" "network_command" {
  filename = "${path.module}/cli/pkg/commands/network.go"
  content = <<EOF
package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/federation/cli/pkg/config"
	"github.com/federation/cli/pkg/federation"
)

func NewNetworkCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage federation networking",
		Long:  "Network management and troubleshooting tools",
	}

	cmd.AddCommand(
		newNetworkStatusCommand(cfg),
		newNetworkBenchmarkCommand(cfg),
		newNetworkTopologyCommand(cfg),
		newNetworkTestCommand(cfg),
	)

	return cmd
}

func newNetworkStatusCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show network connectivity status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showNetworkStatus(cfg)
		},
	}
}

func newNetworkBenchmarkCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run network performance benchmarks",
		RunE: func(cmd *cobra.Command, args []string) error {
			source, _ := cmd.Flags().GetString("source")
			target, _ := cmd.Flags().GetString("target")
			duration, _ := cmd.Flags().GetDuration("duration")
			return runNetworkBenchmark(cfg, source, target, duration)
		},
	}

	cmd.Flags().String("source", "", "Source cloud")
	cmd.Flags().String("target", "", "Target cloud")
	cmd.Flags().Duration("duration", 30*time.Second, "Benchmark duration")

	return cmd
}

func newNetworkTopologyCommand(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "topology",
		Short: "Show network topology",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showNetworkTopology(cfg)
		},
	}
}

func newNetworkTestCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test network connectivity between clouds",
		RunE: func(cmd *cobra.Command, args []string) error {
			return testNetworkConnectivity(cfg)
		},
	}

	return cmd
}

func showNetworkStatus(cfg *config.Config) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	status, err := fedClient.GetNetworkStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get network status: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "CONNECTION\tSTATUS\tLATENCY\tBANDWIDTH\tPACKET_LOSS")

	for _, conn := range status.Connections {
		fmt.Fprintf(w, "%s -> %s\t%s\t%s\t%s\t%.2f%%\n",
			conn.Source,
			conn.Target,
			conn.Status,
			conn.Latency,
			conn.Bandwidth,
			conn.PacketLoss,
		)
	}

	return nil
}

func runNetworkBenchmark(cfg *config.Config, source, target string, duration time.Duration) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	benchmark := &federation.NetworkBenchmark{
		Source:   source,
		Target:   target,
		Duration: duration,
	}

	fmt.Printf("Running network benchmark from %s to %s for %s...\n", source, target, duration)
	
	result, err := fedClient.RunNetworkBenchmark(ctx, benchmark)
	if err != nil {
		return fmt.Errorf("failed to run network benchmark: %w", err)
	}

	fmt.Printf("Benchmark Results:\n")
	fmt.Printf("  Latency: %s (min: %s, max: %s, avg: %s)\n",
		result.Latency.Current, result.Latency.Min, result.Latency.Max, result.Latency.Avg)
	fmt.Printf("  Bandwidth: %s (upload: %s, download: %s)\n",
		result.Bandwidth.Total, result.Bandwidth.Upload, result.Bandwidth.Download)
	fmt.Printf("  Packet Loss: %.2f%%\n", result.PacketLoss)
	fmt.Printf("  Jitter: %s\n", result.Jitter)

	return nil
}

func showNetworkTopology(cfg *config.Config) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	topology, err := fedClient.GetNetworkTopology(ctx)
	if err != nil {
		return fmt.Errorf("failed to get network topology: %w", err)
	}

	fmt.Println("Network Topology:")
	fmt.Println("================")
	
	for _, cloud := range topology.Clouds {
		fmt.Printf("\n%s:\n", cloud.Name)
		fmt.Printf("  Regions: %v\n", cloud.Regions)
		fmt.Printf("  VPC/VNet: %s\n", cloud.VPC)
		fmt.Printf("  Subnets: %v\n", cloud.Subnets)
		fmt.Printf("  Gateways: %v\n", cloud.Gateways)
		
		if len(cloud.Connections) > 0 {
			fmt.Printf("  Connections:\n")
			for _, conn := range cloud.Connections {
				fmt.Printf("    -> %s (%s)\n", conn.Target, conn.Type)
			}
		}
	}

	return nil
}

func testNetworkConnectivity(cfg *config.Config) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	fmt.Println("Testing network connectivity...")
	
	result, err := fedClient.TestNetworkConnectivity(ctx)
	if err != nil {
		return fmt.Errorf("failed to test network connectivity: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "TEST\tSOURCE\tTARGET\tSTATUS\tDETAILS")

	for _, test := range result.Tests {
		status := "PASS"
		if test.Failed {
			status = "FAIL"
		}
		
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			test.Name,
			test.Source,
			test.Target,
			status,
			test.Details,
		)
	}

	if result.Failed {
		fmt.Fprintf(os.Stderr, "\nSome connectivity tests failed. Check network configuration.\n")
		return fmt.Errorf("connectivity tests failed")
	}

	fmt.Println("\nAll connectivity tests passed!")
	return nil
}
EOF
}

# Benchmark command
resource "local_file" "benchmark_command" {
  filename = "${path.module}/cli/pkg/commands/benchmark.go"
  content = <<EOF
package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/federation/cli/pkg/config"
	"github.com/federation/cli/pkg/federation"
)

func NewBenchmarkCommand(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Run performance benchmarks",
		Long:  "Run comprehensive performance benchmarks across the federation",
		RunE: func(cmd *cobra.Command, args []string) error {
			duration, _ := cmd.Flags().GetDuration("duration")
			clouds, _ := cmd.Flags().GetStringSlice("clouds")
			return runBenchmark(cfg, duration, clouds)
		},
	}

	cmd.Flags().Duration("duration", 60*time.Second, "Benchmark duration")
	cmd.Flags().StringSlice("clouds", []string{}, "Clouds to benchmark (empty = all)")

	return cmd
}

func runBenchmark(cfg *config.Config, duration time.Duration, clouds []string) error {
	ctx := context.Background()
	fedClient := federation.NewClient(cfg.Federation.ControllerEndpoint)
	
	benchmark := &federation.BenchmarkRequest{
		Duration: duration,
		Clouds:   clouds,
		Tests: []string{
			"workload-scheduling",
			"network-performance",
			"storage-io",
			"api-latency",
			"failover-time",
		},
	}

	fmt.Printf("Running comprehensive benchmark for %s...\n", duration)
	
	result, err := fedClient.RunBenchmark(ctx, benchmark)
	if err != nil {
		return fmt.Errorf("failed to run benchmark: %w", err)
	}

	fmt.Printf("\nBenchmark Results:\n")
	fmt.Printf("==================\n")
	
	fmt.Printf("Workload Scheduling:\n")
	fmt.Printf("  Average Time: %s\n", result.WorkloadScheduling.AverageTime)
	fmt.Printf("  Success Rate: %.2f%%\n", result.WorkloadScheduling.SuccessRate)
	
	fmt.Printf("\nNetwork Performance:\n")
	fmt.Printf("  Inter-cloud Latency: %s\n", result.NetworkPerformance.InterCloudLatency)
	fmt.Printf("  Bandwidth: %s\n", result.NetworkPerformance.Bandwidth)
	fmt.Printf("  Packet Loss: %.2f%%\n", result.NetworkPerformance.PacketLoss)
	
	fmt.Printf("\nStorage I/O:\n")
	fmt.Printf("  Read IOPS: %d\n", result.StorageIO.ReadIOPS)
	fmt.Printf("  Write IOPS: %d\n", result.StorageIO.WriteIOPS)
	fmt.Printf("  Latency: %s\n", result.StorageIO.Latency)
	
	fmt.Printf("\nAPI Latency:\n")
	fmt.Printf("  Federation API: %s\n", result.APILatency.Federation)
	fmt.Printf("  Cloud APIs: %s\n", result.APILatency.CloudAPIs)
	
	fmt.Printf("\nFailover Performance:\n")
	fmt.Printf("  Detection Time: %s\n", result.FailoverTime.Detection)
	fmt.Printf("  Recovery Time: %s\n", result.FailoverTime.Recovery)
	fmt.Printf("  Total Time: %s\n", result.FailoverTime.Total)

	return nil
}
EOF
}

# Configuration management
resource "local_file" "config_go" {
  filename = "${path.module}/cli/pkg/config/config.go"
  content = <<EOF
package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Clouds     CloudsConfig     `mapstructure:"clouds"`
	Federation FederationConfig `mapstructure:"federation"`
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

type CloudsConfig struct {
	OpenStack OpenStackConfig `mapstructure:"openstack"`
	AWS       AWSConfig       `mapstructure:"aws"`
	GCP       GCPConfig       `mapstructure:"gcp"`
	Azure     AzureConfig     `mapstructure:"azure"`
}

type OpenStackConfig struct {
	AuthURL    string `mapstructure:"auth_url"`
	Region     string `mapstructure:"region"`
	APIVersion string `mapstructure:"api_version"`
}

type AWSConfig struct {
	Region     string `mapstructure:"region"`
	APIVersion string `mapstructure:"api_version"`
}

type GCPConfig struct {
	Project string `mapstructure:"project"`
	Region  string `mapstructure:"region"`
}

type AzureConfig struct {
	SubscriptionID string `mapstructure:"subscription_id"`
	TenantID      string `mapstructure:"tenant_id"`
	Region        string `mapstructure:"region"`
}

type FederationConfig struct {
	ControllerEndpoint string `mapstructure:"controller_endpoint"`
	APIVersion        string `mapstructure:"api_version"`
	Timeout           string `mapstructure:"timeout"`
}

type MonitoringConfig struct {
	PrometheusURL string `mapstructure:"prometheus_url"`
	GrafanaURL    string `mapstructure:"grafana_url"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	
	// Configuration file locations
	viper.AddConfigPath("/etc/fed-cli/")
	viper.AddConfigPath("$HOME/.fed-cli/")
	viper.AddConfigPath(".")
	
	// Environment variable override
	if configPath := os.Getenv("FED_CLI_CONFIG"); configPath != "" {
		viper.SetConfigFile(configPath)
	}
	
	// Set defaults
	setDefaults()
	
	// Read configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

func setDefaults() {
	viper.SetDefault("federation.api_version", "v1")
	viper.SetDefault("federation.timeout", "30s")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	viper.SetConfigFile(path)
	return viper.WriteConfig()
}
EOF
}

# Output CLI information
output "cli_image" {
  value = docker_image.fed_cli.name
  description = "Federation CLI Docker image name"
}

output "cli_commands" {
  value = {
    status     = "fed-cli status --all-clouds"
    workload   = "fed-cli workload list"
    network    = "fed-cli network status"
    benchmark  = "fed-cli benchmark --duration 60s"
    security   = "fed-cli security scan"
    vpn        = "fed-cli vpn status"
    backup     = "fed-cli backup create"
    validate   = "fed-cli validate --all"
  }
  description = "Common federation CLI commands"
}

output "cli_config_path" {
  value = "/etc/fed-cli/config.yaml"
  description = "CLI configuration file path in containers"
}
EOF
