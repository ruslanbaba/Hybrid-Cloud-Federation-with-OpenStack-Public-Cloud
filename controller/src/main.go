package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// BurstController manages workload bursting across clouds
type BurstController struct {
	config          *Config
	prometheusClient v1.API
	vaultClient     *vaultapi.Client
	k8sClient       kubernetes.Interface
	cloudProviders  map[string]CloudProvider
	metrics         *Metrics
	mu              sync.RWMutex
	lastBurstCheck  time.Time
}

// Config holds controller configuration
type Config struct {
	Port                  int    `json:"port"`
	BurstThreshold       float64 `json:"burst_threshold"`
	ScaleInThreshold     float64 `json:"scale_in_threshold"`
	PrometheusURL        string `json:"prometheus_url"`
	VaultAddress         string `json:"vault_address"`
	OpenStackEndpoint    string `json:"openstack_endpoint"`
	CheckInterval        time.Duration `json:"check_interval"`
	CooldownPeriod       time.Duration `json:"cooldown_period"`
	MaxBurstInstances    int    `json:"max_burst_instances"`
	PreferredCloudOrder  []string `json:"preferred_cloud_order"`
	SecurityEnabled      bool   `json:"security_enabled"`
	CostOptimizationEnabled bool `json:"cost_optimization_enabled"`
}

// CloudProvider interface for multi-cloud operations
type CloudProvider interface {
	Name() string
	GetCapacity() (*CloudCapacity, error)
	LaunchInstances(spec *InstanceSpec, count int) ([]*Instance, error)
	TerminateInstances(instanceIDs []string) error
	GetCostPerHour() (float64, error)
	IsAvailable() bool
}

// CloudCapacity represents available resources
type CloudCapacity struct {
	TotalCPU      int     `json:"total_cpu"`
	AvailableCPU  int     `json:"available_cpu"`
	TotalMemory   int64   `json:"total_memory"`
	AvailableMemory int64 `json:"available_memory"`
	UtilizationPercent float64 `json:"utilization_percent"`
}

// InstanceSpec defines instance requirements
type InstanceSpec struct {
	CPUCores    int               `json:"cpu_cores"`
	MemoryGB    int               `json:"memory_gb"`
	ImageID     string            `json:"image_id"`
	InstanceType string           `json:"instance_type"`
	SecurityGroups []string       `json:"security_groups"`
	Subnets     []string          `json:"subnets"`
	Tags        map[string]string `json:"tags"`
}

// Instance represents a compute instance
type Instance struct {
	ID           string            `json:"id"`
	Provider     string            `json:"provider"`
	State        string            `json:"state"`
	IPAddress    string            `json:"ip_address"`
	LaunchTime   time.Time         `json:"launch_time"`
	Tags         map[string]string `json:"tags"`
	CostPerHour  float64           `json:"cost_per_hour"`
}

// BurstDecision represents a scaling decision
type BurstDecision struct {
	Action           string    `json:"action"` // scale_out, scale_in, no_action
	TargetProvider   string    `json:"target_provider"`
	InstanceCount    int       `json:"instance_count"`
	Reason           string    `json:"reason"`
	Timestamp        time.Time `json:"timestamp"`
	EstimatedCost    float64   `json:"estimated_cost"`
	SecurityValidated bool     `json:"security_validated"`
}

// Metrics for monitoring and observability
type Metrics struct {
	burstDecisions prometheus.Counter
	instancesLaunched prometheus.CounterVec
	instancesTerminated prometheus.CounterVec
	cloudUtilization prometheus.GaugeVec
	burstLatency prometheus.HistogramVec
	costPerHour prometheus.GaugeVec
}

func main() {
	log.Println("Starting Enterprise Hybrid Cloud Federation Burst Controller")

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize controller
	controller, err := NewBurstController(config)
	if err != nil {
		log.Fatalf("Failed to initialize burst controller: %v", err)
	}

	// Start background monitoring
	go controller.startMonitoring()

	// Start HTTP server
	router := setupRoutes(controller)
	log.Printf("Starting server on port %d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), router))
}

// NewBurstController creates a new burst controller instance
func NewBurstController(config *Config) (*BurstController, error) {
	// Initialize Prometheus client
	promClient, err := api.NewClient(api.Config{
		Address: config.PrometheusURL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus client: %v", err)
	}

	// Initialize Vault client
	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = config.VaultAddress
	vaultClient, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}

	// Initialize Kubernetes client
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes config: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	// Initialize metrics
	metrics := initializeMetrics()

	// Initialize cloud providers
	cloudProviders := make(map[string]CloudProvider)
	
	// Register cloud providers based on configuration
	if awsProvider, err := NewAWSProvider(vaultClient); err == nil {
		cloudProviders["aws"] = awsProvider
	}
	if gcpProvider, err := NewGCPProvider(vaultClient); err == nil {
		cloudProviders["gcp"] = gcpProvider
	}
	if azureProvider, err := NewAzureProvider(vaultClient); err == nil {
		cloudProviders["azure"] = azureProvider
	}

	return &BurstController{
		config:          config,
		prometheusClient: v1.NewAPI(promClient),
		vaultClient:     vaultClient,
		k8sClient:       k8sClient,
		cloudProviders:  cloudProviders,
		metrics:         metrics,
		lastBurstCheck:  time.Now(),
	}, nil
}

// startMonitoring runs the main monitoring loop
func (bc *BurstController) startMonitoring() {
	ticker := time.NewTicker(bc.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Since(bc.lastBurstCheck) >= bc.config.CooldownPeriod {
				if err := bc.evaluateAndExecuteBurst(); err != nil {
					log.Printf("Error during burst evaluation: %v", err)
				}
				bc.lastBurstCheck = time.Now()
			}
		}
	}
}

// evaluateAndExecuteBurst checks if bursting is needed and executes it
func (bc *BurstController) evaluateAndExecuteBurst() error {
	// Get OpenStack utilization
	utilization, err := bc.getOpenStackUtilization()
	if err != nil {
		return fmt.Errorf("failed to get OpenStack utilization: %v", err)
	}

	log.Printf("Current OpenStack utilization: %.2f%%", utilization)

	// Update metrics
	bc.metrics.cloudUtilization.WithLabelValues("openstack").Set(utilization)

	// Make burst decision
	decision := bc.makeBurstDecision(utilization)
	
	// Execute decision if action is required
	if decision.Action != "no_action" {
		if err := bc.executeBurstDecision(decision); err != nil {
			return fmt.Errorf("failed to execute burst decision: %v", err)
		}
		bc.metrics.burstDecisions.Inc()
	}

	return nil
}

// makeBurstDecision determines what action to take based on utilization
func (bc *BurstController) makeBurstDecision(utilization float64) *BurstDecision {
	decision := &BurstDecision{
		Timestamp: time.Now(),
		SecurityValidated: bc.config.SecurityEnabled,
	}

	if utilization >= bc.config.BurstThreshold {
		// Scale out to public cloud
		targetProvider := bc.selectOptimalProvider()
		instanceCount := bc.calculateRequiredInstances(utilization)
		
		decision.Action = "scale_out"
		decision.TargetProvider = targetProvider
		decision.InstanceCount = instanceCount
		decision.Reason = fmt.Sprintf("OpenStack utilization %.2f%% exceeds threshold %.2f%%", 
			utilization, bc.config.BurstThreshold)
		
		if provider, exists := bc.cloudProviders[targetProvider]; exists {
			if cost, err := provider.GetCostPerHour(); err == nil {
				decision.EstimatedCost = cost * float64(instanceCount)
			}
		}
	} else if utilization <= bc.config.ScaleInThreshold {
		// Scale in from public cloud
		decision.Action = "scale_in"
		decision.Reason = fmt.Sprintf("OpenStack utilization %.2f%% below scale-in threshold %.2f%%", 
			utilization, bc.config.ScaleInThreshold)
	} else {
		decision.Action = "no_action"
		decision.Reason = "Utilization within normal range"
	}

	return decision
}

// selectOptimalProvider chooses the best cloud provider for bursting
func (bc *BurstController) selectOptimalProvider() string {
	// Check preferred order and availability
	for _, provider := range bc.config.PreferredCloudOrder {
		if cloudProvider, exists := bc.cloudProviders[provider]; exists {
			if cloudProvider.IsAvailable() {
				// Check cost if optimization is enabled
				if bc.config.CostOptimizationEnabled {
					if cost, err := cloudProvider.GetCostPerHour(); err == nil {
						log.Printf("Provider %s cost per hour: $%.4f", provider, cost)
					}
				}
				return provider
			}
		}
	}

	// Fallback to first available provider
	for name, provider := range bc.cloudProviders {
		if provider.IsAvailable() {
			return name
		}
	}

	return "aws" // Default fallback
}

// calculateRequiredInstances determines how many instances to launch
func (bc *BurstController) calculateRequiredInstances(utilization float64) int {
	// Simple calculation based on over-threshold percentage
	overThreshold := utilization - bc.config.BurstThreshold
	instanceCount := int((overThreshold / 10.0) + 1) // 1 instance per 10% over threshold
	
	if instanceCount > bc.config.MaxBurstInstances {
		instanceCount = bc.config.MaxBurstInstances
	}
	
	return instanceCount
}

// executeBurstDecision carries out the scaling action
func (bc *BurstController) executeBurstDecision(decision *BurstDecision) error {
	start := time.Now()
	defer func() {
		bc.metrics.burstLatency.WithLabelValues(decision.Action).Observe(time.Since(start).Seconds())
	}()

	log.Printf("Executing burst decision: %s to %s (%d instances) - %s", 
		decision.Action, decision.TargetProvider, decision.InstanceCount, decision.Reason)

	switch decision.Action {
	case "scale_out":
		return bc.scaleOut(decision)
	case "scale_in":
		return bc.scaleIn(decision)
	}

	return nil
}

// scaleOut launches new instances in the target cloud
func (bc *BurstController) scaleOut(decision *BurstDecision) error {
	provider, exists := bc.cloudProviders[decision.TargetProvider]
	if !exists {
		return fmt.Errorf("provider %s not found", decision.TargetProvider)
	}

	// Define instance specification
	spec := &InstanceSpec{
		CPUCores:     2,
		MemoryGB:     4,
		InstanceType: "t3.medium", // Default, should be configurable
		Tags: map[string]string{
			"purpose":     "burst-workload",
			"source":      "openstack-federation",
			"launched-by": "burst-controller",
			"launched-at": time.Now().Format(time.RFC3339),
		},
	}

	// Launch instances
	instances, err := provider.LaunchInstances(spec, decision.InstanceCount)
	if err != nil {
		return fmt.Errorf("failed to launch instances: %v", err)
	}

	// Update metrics
	bc.metrics.instancesLaunched.WithLabelValues(decision.TargetProvider).Add(float64(len(instances)))

	log.Printf("Successfully launched %d instances in %s", len(instances), decision.TargetProvider)
	return nil
}

// scaleIn terminates instances from public clouds
func (bc *BurstController) scaleIn(decision *BurstDecision) error {
	// Implementation for scaling in burst instances
	// This would identify and terminate burst instances based on tags
	log.Printf("Scaling in burst instances (implementation needed)")
	return nil
}

// getOpenStackUtilization retrieves current OpenStack cluster utilization
func (bc *BurstController) getOpenStackUtilization() (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Query Prometheus for OpenStack CPU utilization
	query := `(1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100`
	result, warnings, err := bc.prometheusClient.Query(ctx, query, time.Now())
	if err != nil {
		return 0, err
	}

	if len(warnings) > 0 {
		log.Printf("Prometheus warnings: %v", warnings)
	}

	// Parse result (simplified - would need proper vector parsing)
	// This is a mock implementation
	return 75.0, nil // Mock value for demonstration
}

// initializeMetrics sets up Prometheus metrics
func initializeMetrics() *Metrics {
	return &Metrics{
		burstDecisions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "burst_decisions_total",
			Help: "Total number of burst decisions made",
		}),
		instancesLaunched: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "instances_launched_total",
			Help: "Total number of instances launched per provider",
		}, []string{"provider"}),
		instancesTerminated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "instances_terminated_total",
			Help: "Total number of instances terminated per provider",
		}, []string{"provider"}),
		cloudUtilization: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cloud_utilization_percent",
			Help: "Current utilization percentage per cloud provider",
		}, []string{"provider"}),
		burstLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "burst_action_duration_seconds",
			Help: "Time taken to execute burst actions",
		}, []string{"action"}),
		costPerHour: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cloud_cost_per_hour_usd",
			Help: "Cost per hour for cloud providers",
		}, []string{"provider"}),
	}
}

// setupRoutes configures HTTP routes
func setupRoutes(controller *BurstController) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "timestamp": time.Now()})
	})

	// Metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API routes
	api := router.Group("/api/v1")
	{
		api.GET("/status", controller.getStatus)
		api.GET("/providers", controller.getProviders)
		api.POST("/burst", controller.manualBurst)
		api.GET("/decisions", controller.getRecentDecisions)
	}

	return router
}

// HTTP handlers
func (bc *BurstController) getStatus(c *gin.Context) {
	utilization, _ := bc.getOpenStackUtilization()
	
	status := gin.H{
		"controller": gin.H{
			"version":     "1.0.0",
			"uptime":      time.Since(bc.lastBurstCheck),
			"last_check":  bc.lastBurstCheck,
		},
		"openstack": gin.H{
			"utilization": utilization,
			"threshold":   bc.config.BurstThreshold,
		},
		"providers": len(bc.cloudProviders),
	}
	
	c.JSON(200, status)
}

func (bc *BurstController) getProviders(c *gin.Context) {
	providers := make(map[string]interface{})
	
	for name, provider := range bc.cloudProviders {
		capacity, _ := provider.GetCapacity()
		cost, _ := provider.GetCostPerHour()
		
		providers[name] = gin.H{
			"available": provider.IsAvailable(),
			"capacity":  capacity,
			"cost_per_hour": cost,
		}
	}
	
	c.JSON(200, providers)
}

func (bc *BurstController) manualBurst(c *gin.Context) {
	var request struct {
		Provider string `json:"provider"`
		Count    int    `json:"count"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	
	decision := &BurstDecision{
		Action:         "scale_out",
		TargetProvider: request.Provider,
		InstanceCount:  request.Count,
		Reason:         "Manual burst request",
		Timestamp:      time.Now(),
	}
	
	if err := bc.executeBurstDecision(decision); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(200, decision)
}

func (bc *BurstController) getRecentDecisions(c *gin.Context) {
	// Mock implementation - would store recent decisions in memory or database
	decisions := []BurstDecision{
		{
			Action:        "scale_out",
			TargetProvider: "aws",
			InstanceCount: 2,
			Reason:        "Utilization exceeded threshold",
			Timestamp:     time.Now().Add(-1 * time.Hour),
		},
	}
	
	c.JSON(200, decisions)
}

// loadConfig loads configuration from environment variables and files
func loadConfig() (*Config, error) {
	config := &Config{
		Port:                    getEnvInt("PORT", 8080),
		BurstThreshold:         getEnvFloat("BURST_THRESHOLD", 80.0),
		ScaleInThreshold:       getEnvFloat("SCALE_IN_THRESHOLD", 20.0),
		PrometheusURL:          getEnvString("PROMETHEUS_URL", "http://prometheus:9090"),
		VaultAddress:           getEnvString("VAULT_ADDRESS", "http://vault:8200"),
		OpenStackEndpoint:      getEnvString("OPENSTACK_ENDPOINT", ""),
		CheckInterval:          getEnvDuration("CHECK_INTERVAL", 30*time.Second),
		CooldownPeriod:         getEnvDuration("COOLDOWN_PERIOD", 5*time.Minute),
		MaxBurstInstances:      getEnvInt("MAX_BURST_INSTANCES", 10),
		PreferredCloudOrder:    []string{"aws", "gcp", "azure"},
		SecurityEnabled:        getEnvBool("SECURITY_ENABLED", true),
		CostOptimizationEnabled: getEnvBool("COST_OPTIMIZATION_ENABLED", true),
	}

	return config, nil
}

// Utility functions for environment variables
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
