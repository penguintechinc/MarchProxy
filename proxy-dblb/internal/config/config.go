package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds the DBLB configuration
type Config struct {
	// Server settings
	GRPCAddr    string `mapstructure:"grpc_addr"`
	GRPCPort    int    `mapstructure:"grpc_port"`
	MetricsAddr string `mapstructure:"metrics_addr"`

	// Manager connection
	ManagerURL      string `mapstructure:"manager_url"`
	ClusterAPIKey   string `mapstructure:"cluster_api_key"`
	RegistrationURL string `mapstructure:"registration_url"`

	// Database routing
	Routes []RouteConfig `mapstructure:"routes"`

	// Connection pooling
	MaxConnectionsPerRoute int           `mapstructure:"max_connections_per_route"`
	ConnectionIdleTimeout  time.Duration `mapstructure:"connection_idle_timeout"`
	ConnectionMaxLifetime  time.Duration `mapstructure:"connection_max_lifetime"`

	// Rate limiting
	EnableRateLimiting    bool    `mapstructure:"enable_rate_limiting"`
	DefaultConnectionRate float64 `mapstructure:"default_connection_rate"`
	DefaultQueryRate      float64 `mapstructure:"default_query_rate"`

	// Security
	EnableSQLInjectionDetection bool `mapstructure:"enable_sql_injection_detection"`
	BlockSuspiciousQueries      bool `mapstructure:"block_suspicious_queries"`

	// Observability
	EnableTracing    bool    `mapstructure:"enable_tracing"`
	JaegerEndpoint   string  `mapstructure:"jaeger_endpoint"`
	TraceSampleRate  float64 `mapstructure:"trace_sample_rate"`
	MetricsNamespace string  `mapstructure:"metrics_namespace"`

	// Licensing
	LicenseKey    string `mapstructure:"license_key"`
	LicenseServer string `mapstructure:"license_server"`
	ReleaseMode   bool   `mapstructure:"release_mode"`
}

// RouteConfig defines a database route configuration
type RouteConfig struct {
	Name           string  `mapstructure:"name"`
	Protocol       string  `mapstructure:"protocol"` // mysql, postgresql, mongodb, redis, mssql
	ListenPort     int     `mapstructure:"listen_port"`
	BackendHost    string  `mapstructure:"backend_host"`
	BackendPort    int     `mapstructure:"backend_port"`
	MaxConnections int     `mapstructure:"max_connections"`
	ConnectionRate float64 `mapstructure:"connection_rate"` // connections per second
	QueryRate      float64 `mapstructure:"query_rate"`      // queries per second
	EnableAuth     bool    `mapstructure:"enable_auth"`
	Username       string  `mapstructure:"username"`
	Password       string  `mapstructure:"password"`
	EnableSSL      bool    `mapstructure:"enable_ssl"`
	HealthCheckSQL string  `mapstructure:"health_check_sql"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	// Set defaults
	viper.SetDefault("grpc_addr", "0.0.0.0")
	viper.SetDefault("grpc_port", 50052)
	viper.SetDefault("metrics_addr", ":7002")
	viper.SetDefault("manager_url", "http://api-server:8000")

	// Connection pooling defaults
	viper.SetDefault("max_connections_per_route", 100)
	viper.SetDefault("connection_idle_timeout", 5*time.Minute)
	viper.SetDefault("connection_max_lifetime", 30*time.Minute)

	// Rate limiting defaults
	viper.SetDefault("enable_rate_limiting", true)
	viper.SetDefault("default_connection_rate", 100.0) // 100 connections per second
	viper.SetDefault("default_query_rate", 1000.0)     // 1000 queries per second

	// Security defaults
	viper.SetDefault("enable_sql_injection_detection", true)
	viper.SetDefault("block_suspicious_queries", true)

	// Observability defaults
	viper.SetDefault("enable_tracing", false)
	viper.SetDefault("trace_sample_rate", 0.1)
	viper.SetDefault("metrics_namespace", "marchproxy_dblb")

	// Licensing defaults
	viper.SetDefault("license_server", "https://license.penguintech.io")
	viper.SetDefault("release_mode", false)

	// Load config file if provided
	if configPath != "" {
		viper.SetConfigFile(configPath)
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Environment variables take precedence
	viper.AutomaticEnv()
	viper.SetEnvPrefix("MARCHPROXY_DBLB")

	// Unmarshal config
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Override from environment if set
	if apiKey := os.Getenv("CLUSTER_API_KEY"); apiKey != "" {
		cfg.ClusterAPIKey = apiKey
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.GRPCPort <= 0 || c.GRPCPort > 65535 {
		return fmt.Errorf("invalid grpc_port: must be 1-65535")
	}

	if c.MaxConnectionsPerRoute <= 0 {
		return fmt.Errorf("max_connections_per_route must be > 0")
	}

	if c.ConnectionIdleTimeout <= 0 {
		return fmt.Errorf("connection_idle_timeout must be > 0")
	}

	if c.ConnectionMaxLifetime <= 0 {
		return fmt.Errorf("connection_max_lifetime must be > 0")
	}

	if c.EnableRateLimiting {
		if c.DefaultConnectionRate <= 0 {
			return fmt.Errorf("default_connection_rate must be > 0")
		}
		if c.DefaultQueryRate <= 0 {
			return fmt.Errorf("default_query_rate must be > 0")
		}
	}

	// Validate routes
	for i, route := range c.Routes {
		if err := route.Validate(); err != nil {
			return fmt.Errorf("route %d (%s): %w", i, route.Name, err)
		}
	}

	return nil
}

// Validate validates a route configuration
func (r *RouteConfig) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}

	validProtocols := map[string]bool{
		"mysql":      true,
		"postgresql": true,
		"mongodb":    true,
		"redis":      true,
		"mssql":      true,
	}

	if !validProtocols[r.Protocol] {
		return fmt.Errorf("invalid protocol: %s (must be one of: mysql, postgresql, mongodb, redis, mssql)", r.Protocol)
	}

	if r.ListenPort <= 0 || r.ListenPort > 65535 {
		return fmt.Errorf("invalid listen_port: must be 1-65535")
	}

	if r.BackendHost == "" {
		return fmt.Errorf("backend_host is required")
	}

	if r.BackendPort <= 0 || r.BackendPort > 65535 {
		return fmt.Errorf("invalid backend_port: must be 1-65535")
	}

	if r.MaxConnections <= 0 {
		r.MaxConnections = 100 // default
	}

	if r.ConnectionRate <= 0 {
		r.ConnectionRate = 100.0 // default
	}

	if r.QueryRate <= 0 {
		r.QueryRate = 1000.0 // default
	}

	return nil
}

// IsEnterpriseFeatureEnabled checks if an enterprise feature is enabled
func (c *Config) IsEnterpriseFeatureEnabled(feature string) bool {
	// In release mode, check license
	if c.ReleaseMode {
		// TODO: Validate with license server
		return c.LicenseKey != ""
	}
	// In development mode, all features available
	return true
}
