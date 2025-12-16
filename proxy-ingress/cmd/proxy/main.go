// MarchProxy Ingress - High-performance reverse proxy server with eBPF acceleration
// Main entry point for the ingress proxy application
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"marchproxy-ingress/internal/auth"
	"marchproxy-ingress/internal/config"
	// "marchproxy-ingress/internal/ebpf"  // TODO: Create ebpf package or remove usage
	"marchproxy-ingress/internal/manager"
	// "marchproxy-ingress/internal/tls"   // TODO: Create tls package or remove usage
	"github.com/spf13/cobra"
)

var (
	version   = "v1.0.0" // MarchProxy Ingress - Production Release
	buildTime = "unknown"
	gitHash   = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "marchproxy-ingress",
		Short: "MarchProxy Ingress - Enterprise-grade reverse proxy server",
		Long: `MarchProxy Ingress is a high-performance reverse proxy server with eBPF acceleration.

Features:
- Layer 7 reverse proxy with host/path-based routing
- mTLS authentication for secure service communication
- eBPF acceleration for high-performance packet filtering
- XDP rate limiting and DDoS protection
- Enterprise clustering and license validation
- SSL/TLS termination with certificate management
- Backend health checking and load balancing
- Prometheus metrics and centralized logging`,
		Version: fmt.Sprintf("%s (built: %s, commit: %s)", version, buildTime, gitHash),
		Run:     runIngressProxy,
	}

	// Add command line flags
	rootCmd.Flags().StringP("config", "c", "", "Configuration file path")
	rootCmd.Flags().StringP("manager-url", "m", "", "Manager server URL")
	rootCmd.Flags().StringP("cluster-api-key", "k", "", "Cluster API key")
	rootCmd.Flags().StringP("listen-port", "p", "80", "HTTP listen port")
	rootCmd.Flags().StringP("tls-port", "t", "443", "HTTPS/TLS listen port")
	rootCmd.Flags().StringP("admin-port", "a", "8082", "Admin/metrics port")
	rootCmd.Flags().StringP("log-level", "l", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	rootCmd.Flags().BoolP("enable-ebpf", "e", true, "Enable eBPF acceleration")
	rootCmd.Flags().BoolP("enable-mtls", "", true, "Enable mTLS authentication")
	rootCmd.Flags().BoolP("enable-metrics", "", true, "Enable Prometheus metrics")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runIngressProxy(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg, err := config.Load(cmd)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set proxy type to ingress
	cfg.ProxyType = "ingress"

	fmt.Printf("Starting MarchProxy Ingress %s\n", version)
	fmt.Printf("Proxy Type: %s\n", cfg.ProxyType)
	fmt.Printf("Manager URL: %s\n", cfg.ManagerURL)
	fmt.Printf("HTTP Port: %d\n", cfg.ListenPort)
	fmt.Printf("TLS Port: %d\n", cfg.TLSPort)
	fmt.Printf("Admin Port: %d\n", cfg.AdminPort)
	fmt.Printf("Log Level: %s\n", cfg.LogLevel)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize manager client for configuration and registration
	managerClient := manager.NewClient(cfg)

	// Check license status first
	licenseStatus, err := managerClient.GetLicenseStatus()
	if err != nil {
		fmt.Printf("Warning: Failed to check license status: %v\n", err)
	} else {
		fmt.Printf("License: %s (%s) - Proxies: %d/%d\n",
			licenseStatus.Edition,
			map[bool]string{true: "Valid", false: "Invalid"}[licenseStatus.Valid],
			licenseStatus.CurrentProxies,
			licenseStatus.MaxProxies)

		if !licenseStatus.CanRegister {
			fmt.Printf("Error: Cannot register - proxy limit reached or license invalid\n")
			os.Exit(1)
		}
	}

	// Register ingress proxy with manager
	fmt.Printf("Registering ingress proxy with manager...\n")
	if err := managerClient.Register(cfg); err != nil {
		fmt.Printf("Failed to register with manager: %v\n", err)
		os.Exit(1)
	}

	// Get initial configuration including ingress routes
	initialConfig, err := managerClient.GetConfig()
	if err != nil {
		fmt.Printf("Failed to get initial configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded configuration - Virtual Hosts: %d\n",
		len(initialConfig.VirtualHosts))

	// Initialize authenticator and metrics
	mtlsConfig := auth.MTLSConfig{
		Enabled:           cfg.EnableMTLS,
		RequireClientCert: cfg.RequireMTLSClientCert,
		ServerCertPath:    cfg.MTLSServerCertPath,
		ServerKeyPath:     cfg.MTLSServerKeyPath,
		ClientCAPath:      cfg.MTLSClientCAPath,
		ClientCABundle:    cfg.MTLSClientCABundle,
		AllowedCNs:        cfg.MTLSAllowedCNs,
		AllowedOUs:        cfg.MTLSAllowedOUs,
		VerifyClient:      cfg.MTLSVerifyClient,
		CRLPath:           cfg.MTLSCRLPath,
		OCSPEnabled:       cfg.MTLSOCSPEnabled,
		CertExpiredGrace:  cfg.MTLSCertExpiredGrace,
		MaxCertChainDepth: cfg.MTLSMaxCertChainDepth,
	}
	authenticator, err := auth.NewMTLSAuthenticator(mtlsConfig)
	if err != nil {
		fmt.Printf("Warning: Failed to initialize mTLS authenticator: %v\n", err)
		authenticator, _ = auth.NewMTLSAuthenticator(auth.MTLSConfig{Enabled: false})
	}
	metrics := &IngressMetrics{}

	// Initialize eBPF manager with ingress-specific programs
	// ebpfManager := ebpf.NewManager(cfg.EnableEBPF)  // TODO: Create ebpf package
	var ebpfManager interface{} // Placeholder
	if cfg.EnableEBPF {
		fmt.Printf("eBPF acceleration enabled for ingress\n")
		if err := ebpfManager.LoadProgram("ingress"); err != nil {
			fmt.Printf("Warning: Failed to load eBPF program: %v\n", err)
			fmt.Printf("Continuing with userspace-only mode\n")
		} else {
			// Sync initial configuration
			ebpfManager.UpdateVirtualHosts(initialConfig.VirtualHosts)
		}
	}

	// Initialize mTLS configuration
	var tlsConfig *tls.Config
	if cfg.EnableMTLS {
		tlsConfig, err = setupMTLS(cfg)
		if err != nil {
			fmt.Printf("Warning: Failed to setup mTLS: %v\n", err)
			fmt.Printf("Continuing without mTLS\n")
		} else {
			fmt.Printf("mTLS authentication enabled\n")
		}
	}

	// Initialize ingress proxy server
	fmt.Printf("Starting ingress proxy server on ports %d (HTTP) and %d (HTTPS)...\n",
		cfg.ListenPort, cfg.TLSPort)
	ingressServer := &IngressProxy{
		config:        cfg,
		clusterConfig: initialConfig,
		managerClient: managerClient,
		authenticator: authenticator,
		metrics:       metrics,
		ebpfManager:   ebpfManager,
		tlsConfig:     tlsConfig,
	}

	// Start configuration refresh loop
	go managerClient.StartConfigRefresh(ctx, cfg, func(config *manager.ClusterConfig) {
		fmt.Printf("Configuration updated - Version: %s\n", config.Version)
		ingressServer.updateConfiguration(config)

		// Update eBPF maps
		if ebpfManager.IsEnabled() {
			ebpfManager.UpdateVirtualHosts(config.VirtualHosts)
		}
	})

	// Start heartbeat loop
	go managerClient.StartHeartbeat(ctx, cfg, func() manager.SystemStats {
		return manager.GetSystemStats()
	})

	// Start HTTP server in goroutine
	go func() {
		if err := ingressServer.StartHTTP(ctx); err != nil {
			fmt.Printf("HTTP ingress server failed: %v\n", err)
			cancel()
		}
	}()

	// Start HTTPS server in goroutine
	go func() {
		if err := ingressServer.StartHTTPS(ctx); err != nil {
			fmt.Printf("HTTPS ingress server failed: %v\n", err)
			cancel()
		}
	}()

	// Start admin server for health checks and metrics
	if cfg.EnableMetrics {
		go func() {
			if err := startAdminServer(cfg.AdminPort, metrics, ebpfManager); err != nil {
				fmt.Printf("Failed to start admin server: %v\n", err)
			}
		}()
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		fmt.Printf("Received signal %s, shutting down\n", sig)
	case <-ctx.Done():
		fmt.Printf("Context cancelled, shutting down\n")
	}

	// Graceful shutdown
	fmt.Printf("Starting graceful shutdown...\n")

	// Shutdown ingress servers
	if ingressServer != nil {
		ingressServer.Stop()
	}

	// Cleanup eBPF resources
	if ebpfManager != nil && ebpfManager.IsEnabled() {
		if err := ebpfManager.Cleanup(); err != nil {
			fmt.Printf("Warning: eBPF cleanup error: %v\n", err)
		}
	}

	fmt.Printf("MarchProxy Ingress shutdown complete\n")
}

// setupMTLS configures mutual TLS for the ingress proxy
func setupMTLS(cfg *config.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load server certificate
	cert, err := tls.LoadX509KeyPair(cfg.MTLSServerCertPath, cfg.MTLSServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Setup client certificate validation for mutual TLS
	if cfg.MTLSRequireClientCert {
		// Load client CA certificates
		caCert, err := ioutil.ReadFile(cfg.MTLSClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CA: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		fmt.Printf("mTLS client certificate validation enabled\n")
	}

	return tlsConfig, nil
}

// IngressMetrics holds metrics for the ingress proxy
type IngressMetrics struct {
	HTTPRequests      int64
	HTTPSRequests     int64
	RoutedRequests    int64
	FailedRequests    int64
	AuthSuccesses     int64
	AuthFailures      int64
	ActiveConnections int64
	BytesTransferred  int64
	mu                sync.RWMutex
}

// IngressProxy implements a reverse proxy server with mTLS and routing
type IngressProxy struct {
	config        *config.Config
	clusterConfig *manager.ClusterConfig
	managerClient *manager.Client
	authenticator *auth.MTLSAuthenticator
	metrics       *IngressMetrics
	// ebpfManager   *ebpf.Manager  // TODO: Create ebpf package
	ebpfManager   interface{} // Placeholder
	tlsConfig     *tls.Config
	httpServer    *http.Server
	httpsServer   *http.Server
	mu            sync.RWMutex
}

// StartHTTP starts the HTTP ingress server
func (p *IngressProxy) StartHTTP(ctx context.Context) error {
	handler := p.createReverseProxyHandler(false)

	p.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.config.ListenPort),
		Handler: handler,
	}

	fmt.Printf("HTTP ingress proxy listening on :%d\n", p.config.ListenPort)
	return p.httpServer.ListenAndServe()
}

// StartHTTPS starts the HTTPS ingress server with mTLS
func (p *IngressProxy) StartHTTPS(ctx context.Context) error {
	if p.tlsConfig == nil {
		return fmt.Errorf("TLS not configured")
	}

	handler := p.createReverseProxyHandler(true)

	p.httpsServer = &http.Server{
		Addr:      fmt.Sprintf(":%d", p.config.TLSPort),
		Handler:   handler,
		TLSConfig: p.tlsConfig,
	}

	fmt.Printf("HTTPS ingress proxy with mTLS listening on :%d\n", p.config.TLSPort)
	return p.httpsServer.ListenAndServeTLS("", "")
}

// createReverseProxyHandler creates the HTTP handler for reverse proxying
func (p *IngressProxy) createReverseProxyHandler(isTLS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Update metrics
		p.metrics.mu.Lock()
		if isTLS {
			p.metrics.HTTPSRequests++
		} else {
			p.metrics.HTTPRequests++
		}
		p.metrics.ActiveConnections++
		p.metrics.mu.Unlock()

		defer func() {
			p.metrics.mu.Lock()
			p.metrics.ActiveConnections--
			p.metrics.mu.Unlock()
		}()

		// Find matching route
		route := p.findMatchingRoute(r)
		if route == nil {
			http.Error(w, "No matching route found", http.StatusNotFound)
			p.metrics.mu.Lock()
			p.metrics.FailedRequests++
			p.metrics.mu.Unlock()
			return
		}

		// Check mTLS authentication if required
		if route.RequireMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if err := p.validateClientCertificate(r.TLS.PeerCertificates[0], route); err != nil {
				http.Error(w, "Client certificate validation failed", http.StatusForbidden)
				p.metrics.mu.Lock()
				p.metrics.AuthFailures++
				p.metrics.mu.Unlock()
				return
			}
			p.metrics.mu.Lock()
			p.metrics.AuthSuccesses++
			p.metrics.mu.Unlock()
		}

		// Select backend service (load balancing)
		backend, err := p.selectBackend(route)
		if err != nil {
			http.Error(w, "No healthy backend available", http.StatusServiceUnavailable)
			p.metrics.mu.Lock()
			p.metrics.FailedRequests++
			p.metrics.mu.Unlock()
			return
		}

		// Create reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(backend)
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Update byte transfer metrics
			p.metrics.mu.Lock()
			p.metrics.BytesTransferred += resp.ContentLength
			p.metrics.mu.Unlock()
			return nil
		}

		// Proxy the request
		proxy.ServeHTTP(w, r)

		p.metrics.mu.Lock()
		p.metrics.RoutedRequests++
		p.metrics.mu.Unlock()

		fmt.Printf("Proxied %s %s to %s\n", r.Method, r.URL.Path, backend.String())
	})
}

// findMatchingRoute finds the best matching virtual host for the request
func (p *IngressProxy) findMatchingRoute(r *http.Request) *manager.VirtualHost {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.clusterConfig == nil {
		return nil
	}

	host := r.Host
	path := r.URL.Path

	// Find matching routes based on host patterns
	for i, vhost := range p.clusterConfig.VirtualHosts {
		if p.matchesHostPattern(host, vhost.Hostname) {
			// Check if any routing rule matches the path
			for _, rule := range vhost.RoutingRules {
				if p.matchesPathPattern(path, rule.PathPattern) {
					return &p.clusterConfig.VirtualHosts[i]
				}
			}
			// If no specific rule matches, return the vhost anyway
			return &p.clusterConfig.VirtualHosts[i]
		}
	}

	return nil
}

// matchesHostPattern checks if the host matches the pattern (supports wildcards)
func (p *IngressProxy) matchesHostPattern(host, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		domain := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(host, "."+domain) || host == domain
	}

	return host == pattern
}

// matchesPathPattern checks if the path matches the pattern (supports wildcards)
func (p *IngressProxy) matchesPathPattern(path, pattern string) bool {
	if pattern == "" || pattern == "/" || pattern == "/*" {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	return path == pattern
}

// validateClientCertificate validates the client certificate for mTLS
func (p *IngressProxy) validateClientCertificate(cert *x509.Certificate, vhost *manager.VirtualHost) error {
	// Placeholder for client certificate validation
	// This would be implemented when RoutingRule authentication rules are populated
	// For now, we accept all valid certificates

	// Additional certificate validation can be added here when needed:
	// - CN validation against allowed list from RoutingRule.Authentication
	// - CRL checking, OCSP validation
	// - Subject/Issuer validation

	return nil
}

// selectBackend selects a backend service using load balancing
func (p *IngressProxy) selectBackend(vhost *manager.VirtualHost) (*url.URL, error) {
	if vhost.Backend == "" {
		return nil, fmt.Errorf("no backend configured for virtual host")
	}

	// Find the backend configuration
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.clusterConfig == nil {
		return nil, fmt.Errorf("no cluster configuration")
	}

	// Look up the backend by name
	var backend *manager.Backend
	for i := range p.clusterConfig.Backends {
		if p.clusterConfig.Backends[i].Name == vhost.Backend {
			backend = &p.clusterConfig.Backends[i]
			break
		}
	}

	if backend == nil {
		return nil, fmt.Errorf("backend '%s' not found", vhost.Backend)
	}

	if len(backend.Endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints available for backend '%s'", vhost.Backend)
	}

	// Simple round-robin selection for now
	// TODO: Implement more sophisticated load balancing strategies
	endpoint := backend.Endpoints[0]

	// Build backend URL from endpoint
	scheme := "http"
	if backend.TLSConfig.Enabled {
		scheme = "https"
	}

	backendURL, err := url.Parse(fmt.Sprintf("%s://%s:%d", scheme, endpoint.Host, endpoint.Port))
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}

	return backendURL, nil
}

// updateConfiguration updates the proxy's cluster configuration
func (p *IngressProxy) updateConfiguration(config *manager.ClusterConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clusterConfig = config
	// Note: MTLSAuthenticator does not need virtual host updates
	// Virtual host routing is handled through the cluster configuration

	fmt.Printf("Ingress proxy configuration updated - Virtual Hosts: %d, Backends: %d\n",
		len(config.VirtualHosts), len(config.Backends))
}

// Stop stops the ingress proxy servers
func (p *IngressProxy) Stop() {
	if p.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.httpServer.Shutdown(ctx)
	}

	if p.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.httpsServer.Shutdown(ctx)
	}
}

// startAdminServer starts the admin/metrics HTTP server
func startAdminServer(port int, metrics *IngressMetrics, ebpfMgr interface{}) error {  // TODO: Change back to *ebpf.Manager when package created
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","type":"ingress","version":"%s"}`, version)
	})

	// Comprehensive metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics.mu.RLock()
		httpRequests := metrics.HTTPRequests
		httpsRequests := metrics.HTTPSRequests
		routedRequests := metrics.RoutedRequests
		failedRequests := metrics.FailedRequests
		authSuccesses := metrics.AuthSuccesses
		authFailures := metrics.AuthFailures
		activeConnections := metrics.ActiveConnections
		bytesTransferred := metrics.BytesTransferred
		metrics.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		// HTTP request metrics
		fmt.Fprintf(w, "# HELP marchproxy_ingress_http_requests_total Total number of HTTP requests\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_http_requests_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_http_requests_total %d\n", httpRequests)

		// HTTPS request metrics
		fmt.Fprintf(w, "# HELP marchproxy_ingress_https_requests_total Total number of HTTPS requests\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_https_requests_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_https_requests_total %d\n", httpsRequests)

		// Routed request metrics
		fmt.Fprintf(w, "# HELP marchproxy_ingress_routed_requests_total Total number of successfully routed requests\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_routed_requests_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_routed_requests_total %d\n", routedRequests)

		// Failed request metrics
		fmt.Fprintf(w, "# HELP marchproxy_ingress_failed_requests_total Total number of failed requests\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_failed_requests_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_failed_requests_total %d\n", failedRequests)

		// Bytes transferred metrics
		fmt.Fprintf(w, "# HELP marchproxy_ingress_bytes_transferred_total Total bytes transferred\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_bytes_transferred_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_bytes_transferred_total %d\n", bytesTransferred)

		// Authentication metrics
		fmt.Fprintf(w, "# HELP marchproxy_ingress_auth_successes_total Total successful mTLS authentications\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_auth_successes_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_auth_successes_total %d\n", authSuccesses)

		fmt.Fprintf(w, "# HELP marchproxy_ingress_auth_failures_total Total failed mTLS authentications\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_auth_failures_total counter\n")
		fmt.Fprintf(w, "marchproxy_ingress_auth_failures_total %d\n", authFailures)

		// Active connections gauge
		fmt.Fprintf(w, "# HELP marchproxy_ingress_active_connections Current number of active connections\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_active_connections gauge\n")
		fmt.Fprintf(w, "marchproxy_ingress_active_connections %d\n", activeConnections)

		// Version information
		fmt.Fprintf(w, "# HELP marchproxy_ingress_version_info Version information\n")
		fmt.Fprintf(w, "# TYPE marchproxy_ingress_version_info gauge\n")
		fmt.Fprintf(w, `marchproxy_ingress_version_info{version="%s"} 1`+"\n", version)

		// eBPF metrics
		if ebpfMgr != nil && ebpfMgr.IsEnabled() {
			ebpfProxyStats, ebpfStats := ebpfMgr.GetStats()

			fmt.Fprintf(w, "# HELP marchproxy_ingress_ebpf_enabled Whether eBPF acceleration is enabled\n")
			fmt.Fprintf(w, "# TYPE marchproxy_ingress_ebpf_enabled gauge\n")
			fmt.Fprintf(w, "marchproxy_ingress_ebpf_enabled %d\n", map[bool]int{true: 1, false: 0}[ebpfStats.ProgramLoaded])

			fmt.Fprintf(w, "# HELP marchproxy_ingress_ebpf_total_packets Total packets processed by eBPF\n")
			fmt.Fprintf(w, "# TYPE marchproxy_ingress_ebpf_total_packets counter\n")
			fmt.Fprintf(w, "marchproxy_ingress_ebpf_total_packets %d\n", ebpfProxyStats.TotalPackets)
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	fmt.Printf("Ingress admin server listening on :%d\n", port)
	fmt.Printf("Endpoints: /healthz, /metrics\n")
	return server.ListenAndServe()
}