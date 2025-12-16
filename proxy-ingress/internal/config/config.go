package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	ProxyType    string `mapstructure:"proxy_type"`
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	TLSPort      int    `mapstructure:"tls_port"`
	MetricsPort  int    `mapstructure:"metrics_port"`
	HealthPort   int    `mapstructure:"health_port"`
	LogLevel     string `mapstructure:"log_level"`
	LogPath      string `mapstructure:"log_path"`
	ConfigPath   string `mapstructure:"config_path"`
	CertPath     string `mapstructure:"cert_path"`

	EnableEBPF       bool   `mapstructure:"enable_ebpf"`
	EnableXDP        bool   `mapstructure:"enable_xdp"`
	XDPInterface     string `mapstructure:"xdp_interface"`
	EnableDPDK       bool   `mapstructure:"enable_dpdk"`
	DPDKPorts        string `mapstructure:"dpdk_ports"`
	EnableAFXDP      bool   `mapstructure:"enable_af_xdp"`
	EnableSRIOV      bool   `mapstructure:"enable_sriov"`
	HardwareOffload  bool   `mapstructure:"hardware_offload"`

	EnableMTLS           bool   `mapstructure:"mtls_enabled"`
	MTLSRequireClientCert bool  `mapstructure:"mtls_require_client_cert"`
	MTLSServerCertPath   string `mapstructure:"mtls_server_cert_path"`
	MTLSServerKeyPath    string `mapstructure:"mtls_server_key_path"`
	MTLSClientCAPath     string `mapstructure:"mtls_client_ca_path"`

	Manager struct {
		URL        string `mapstructure:"url"`
		APIKey     string `mapstructure:"api_key"`
		ProxyID    string `mapstructure:"proxy_id"`
		ClusterID  string `mapstructure:"cluster_id"`
		RetryCount int    `mapstructure:"retry_count"`
		Timeout    int    `mapstructure:"timeout"`
	} `mapstructure:"manager"`

	RateLimit struct {
		RequestsPerSecond int `mapstructure:"requests_per_second"`
		BurstSize         int `mapstructure:"burst_size"`
		MaxConnections    int `mapstructure:"max_connections"`
	} `mapstructure:"rate_limit"`

	LoadBalancing struct {
		Algorithm string   `mapstructure:"algorithm"`
		Backends  []string `mapstructure:"backends"`
	} `mapstructure:"load_balancing"`

	Routing struct {
		Rules []RoutingRule `mapstructure:"rules"`
	} `mapstructure:"routing"`

	Cache struct {
		Enabled    bool `mapstructure:"enabled"`
		TTL        int  `mapstructure:"ttl"`
		MaxSize    int  `mapstructure:"max_size"`
		MaxMemory  int  `mapstructure:"max_memory"`
	} `mapstructure:"cache"`

	Security struct {
		EnableDDoSProtection bool     `mapstructure:"enable_ddos_protection"`
		AllowedIPs           []string `mapstructure:"allowed_ips"`
		BlockedIPs           []string `mapstructure:"blocked_ips"`
		MaxRequestSize       int64    `mapstructure:"max_request_size"`
		TimeoutSeconds       int      `mapstructure:"timeout_seconds"`
	} `mapstructure:"security"`
}

type RoutingRule struct {
	Host     string `mapstructure:"host"`
	Path     string `mapstructure:"path"`
	Backend  string `mapstructure:"backend"`
	Priority int    `mapstructure:"priority"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/app/configs")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	viper.SetEnvPrefix("PROXY")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logrus.Warn("Config file not found, using defaults and environment variables")
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("proxy_type", "ingress")
	viper.SetDefault("host", "0.0.0.0")
	viper.SetDefault("port", 80)
	viper.SetDefault("tls_port", 443)
	viper.SetDefault("metrics_port", 8082)
	viper.SetDefault("health_port", 8083)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_path", "/app/logs")
	viper.SetDefault("config_path", "/app/configs")
	viper.SetDefault("cert_path", "/app/certs")

	viper.SetDefault("enable_ebpf", true)
	viper.SetDefault("enable_xdp", false)
	viper.SetDefault("xdp_interface", "eth0")
	viper.SetDefault("enable_dpdk", false)
	viper.SetDefault("enable_af_xdp", false)
	viper.SetDefault("enable_sriov", false)
	viper.SetDefault("hardware_offload", false)

	viper.SetDefault("mtls_enabled", getEnvBool("MTLS_ENABLED", true))
	viper.SetDefault("mtls_require_client_cert", true)
	viper.SetDefault("mtls_server_cert_path", getEnv("MTLS_SERVER_CERT_PATH", "/app/certs/ingress-server.crt"))
	viper.SetDefault("mtls_server_key_path", getEnv("MTLS_SERVER_KEY_PATH", "/app/certs/ingress-server.key"))
	viper.SetDefault("mtls_client_ca_path", getEnv("MTLS_CLIENT_CA_PATH", "/app/certs/client-ca-bundle.crt"))

	viper.SetDefault("manager.url", getEnv("MANAGER_URL", "http://manager:8000"))
	viper.SetDefault("manager.api_key", getEnv("CLUSTER_API_KEY", ""))
	viper.SetDefault("manager.proxy_id", getEnv("PROXY_ID", ""))
	viper.SetDefault("manager.cluster_id", getEnv("CLUSTER_ID", "default"))
	viper.SetDefault("manager.retry_count", 3)
	viper.SetDefault("manager.timeout", 30)

	viper.SetDefault("rate_limit.requests_per_second", 1000)
	viper.SetDefault("rate_limit.burst_size", 2000)
	viper.SetDefault("rate_limit.max_connections", 10000)

	viper.SetDefault("load_balancing.algorithm", "round_robin")
	viper.SetDefault("load_balancing.backends", []string{})

	viper.SetDefault("cache.enabled", true)
	viper.SetDefault("cache.ttl", 300)
	viper.SetDefault("cache.max_size", 1000)
	viper.SetDefault("cache.max_memory", 100)

	viper.SetDefault("security.enable_ddos_protection", true)
	viper.SetDefault("security.allowed_ips", []string{})
	viper.SetDefault("security.blocked_ips", []string{})
	viper.SetDefault("security.max_request_size", 10*1024*1024)
	viper.SetDefault("security.timeout_seconds", 30)
}

func validateConfig(config *Config) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}

	if config.TLSPort <= 0 || config.TLSPort > 65535 {
		return fmt.Errorf("invalid TLS port: %d", config.TLSPort)
	}

	if config.MetricsPort <= 0 || config.MetricsPort > 65535 {
		return fmt.Errorf("invalid metrics port: %d", config.MetricsPort)
	}

	if config.HealthPort <= 0 || config.HealthPort > 65535 {
		return fmt.Errorf("invalid health port: %d", config.HealthPort)
	}

	if _, err := logrus.ParseLevel(config.LogLevel); err != nil {
		return fmt.Errorf("invalid log level: %s", config.LogLevel)
	}

	if net.ParseIP(config.Host) == nil && config.Host != "0.0.0.0" {
		return fmt.Errorf("invalid host: %s", config.Host)
	}

	if config.EnableMTLS {
		if config.MTLSServerCertPath == "" {
			return fmt.Errorf("mTLS server certificate path required when mTLS is enabled")
		}
		if config.MTLSServerKeyPath == "" {
			return fmt.Errorf("mTLS server key path required when mTLS is enabled")
		}
		if config.MTLSClientCAPath == "" && config.MTLSRequireClientCert {
			return fmt.Errorf("mTLS client CA path required when client certificates are required")
		}
	}

	validAlgorithms := map[string]bool{
		"round_robin":      true,
		"least_connections": true,
		"weighted_round_robin": true,
		"ip_hash": true,
	}
	if !validAlgorithms[config.LoadBalancing.Algorithm] {
		return fmt.Errorf("invalid load balancing algorithm: %s", config.LoadBalancing.Algorithm)
	}

	if config.Manager.APIKey == "" {
		return fmt.Errorf("cluster API key is required")
	}

	return nil
}

func (c *Config) GetTLSConfig() (*tls.Config, error) {
	if !c.EnableMTLS {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.MTLSServerCertPath, c.MTLSServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}

	if c.MTLSRequireClientCert && c.MTLSClientCAPath != "" {
		clientCAs, err := loadClientCAs(c.MTLSClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CAs: %w", err)
		}
		tlsConfig.ClientCAs = clientCAs
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

func (c *Config) GetManagerTimeout() time.Duration {
	return time.Duration(c.Manager.Timeout) * time.Second
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func loadClientCAs(caPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return caCertPool, nil
}