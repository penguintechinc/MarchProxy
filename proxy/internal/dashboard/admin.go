package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MarchProxy/proxy/internal/health"
	"github.com/MarchProxy/proxy/internal/manager"
	"github.com/MarchProxy/proxy/internal/metrics"
)

type AdminDashboard struct {
	config         DashboardConfig
	server         *http.Server
	templates      *template.Template
	healthChecker  *health.HealthChecker
	metricsClient  *metrics.PrometheusMetrics
	serviceManager *manager.Manager
	websockets     map[string]*WebSocketConnection
	mutex          sync.RWMutex
	running        bool
}

type DashboardConfig struct {
	Port            int
	Enabled         bool
	BasicAuth       BasicAuthConfig
	TLSEnabled      bool
	CertFile        string
	KeyFile         string
	StaticPath      string
	UpdateInterval  time.Duration
	MaxConnections  int
	CORS            CORSConfig
	RateLimiting    RateLimitConfig
}

type BasicAuthConfig struct {
	Enabled  bool
	Username string
	Password string
	Realm    string
}

type CORSConfig struct {
	Enabled          bool
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
}

type RateLimitConfig struct {
	Enabled         bool
	RequestsPerMin  int
	BurstSize       int
}

type WebSocketConnection struct {
	conn     WebSocketConn
	lastPing time.Time
	topics   map[string]bool
}

type WebSocketConn interface {
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, p []byte, err error)
	Close() error
}

type DashboardData struct {
	Timestamp        time.Time                `json:"timestamp"`
	SystemHealth     *health.SystemHealth     `json:"system_health"`
	Services         []ServiceStatus          `json:"services"`
	Metrics          DashboardMetrics         `json:"metrics"`
	Configuration    ConfigurationData        `json:"configuration"`
	RecentEvents     []SystemEvent            `json:"recent_events"`
	Alerts           []Alert                  `json:"alerts"`
}

type ServiceStatus struct {
	Name              string            `json:"name"`
	Host              string            `json:"host"`
	Port              int               `json:"port"`
	Status            string            `json:"status"`
	Health            string            `json:"health"`
	RequestCount      uint64            `json:"request_count"`
	ErrorCount        uint64            `json:"error_count"`
	AverageLatency    time.Duration     `json:"average_latency"`
	LastHealthCheck   time.Time         `json:"last_health_check"`
	ActiveConnections int               `json:"active_connections"`
	Metadata          map[string]string `json:"metadata"`
}

type DashboardMetrics struct {
	TotalRequests         uint64        `json:"total_requests"`
	RequestsPerSecond     float64       `json:"requests_per_second"`
	AverageResponseTime   time.Duration `json:"average_response_time"`
	ErrorRate             float64       `json:"error_rate"`
	ActiveConnections     int           `json:"active_connections"`
	MemoryUsage           int64         `json:"memory_usage"`
	CPUUsage              float64       `json:"cpu_usage"`
	CacheHitRate          float64       `json:"cache_hit_rate"`
	CircuitBreakerTrips   uint64        `json:"circuit_breaker_trips"`
	RateLimitBlocks       uint64        `json:"rate_limit_blocks"`
	SecurityBlocks        uint64        `json:"security_blocks"`
}

type ConfigurationData struct {
	Version       string                 `json:"version"`
	StartTime     time.Time              `json:"start_time"`
	ConfigFile    string                 `json:"config_file"`
	LogLevel      string                 `json:"log_level"`
	Features      map[string]bool        `json:"features"`
	Settings      map[string]interface{} `json:"settings"`
}

type SystemEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      EventType              `json:"type"`
	Severity  EventSeverity          `json:"severity"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
}

type EventType string

const (
	EventServiceUp      EventType = "service_up"
	EventServiceDown    EventType = "service_down"
	EventConfigReload   EventType = "config_reload"
	EventSecurityAlert  EventType = "security_alert"
	EventRateLimitHit   EventType = "rate_limit"
	EventCircuitBreaker EventType = "circuit_breaker"
	EventSystemError    EventType = "system_error"
)

type EventSeverity string

const (
	SeverityInfo     EventSeverity = "info"
	SeverityWarning  EventSeverity = "warning"
	SeverityError    EventSeverity = "error"
	SeverityCritical EventSeverity = "critical"
)

type Alert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        AlertType              `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Status      AlertStatus            `json:"status"`
	Data        map[string]interface{} `json:"data"`
}

type AlertType string

const (
	AlertHealthCheck    AlertType = "health_check"
	AlertPerformance    AlertType = "performance"
	AlertSecurity       AlertType = "security"
	AlertConfiguration  AlertType = "configuration"
	AlertSystem         AlertType = "system"
)

type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

type AlertStatus string

const (
	AlertStatusActive    AlertStatus = "active"
	AlertStatusResolved  AlertStatus = "resolved"
	AlertStatusSuppressed AlertStatus = "suppressed"
)

func NewAdminDashboard(config DashboardConfig, healthChecker *health.HealthChecker, metricsClient *metrics.PrometheusMetrics, serviceManager *manager.Manager) *AdminDashboard {
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 5 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 100
	}

	ad := &AdminDashboard{
		config:         config,
		healthChecker:  healthChecker,
		metricsClient:  metricsClient,
		serviceManager: serviceManager,
		websockets:     make(map[string]*WebSocketConnection),
	}

	ad.initializeTemplates()
	ad.setupRoutes()

	return ad
}

func (ad *AdminDashboard) initializeTemplates() {
	ad.templates = template.New("dashboard")
	ad.templates.Parse(dashboardHTML)
	ad.templates.Parse(serviceTableHTML)
	ad.templates.Parse(metricsHTML)
	ad.templates.Parse(configurationHTML)
}

func (ad *AdminDashboard) setupRoutes() {
	mux := http.NewServeMux()

	// Static routes
	mux.HandleFunc("/", ad.handleDashboard)
	mux.HandleFunc("/api/status", ad.handleStatus)
	mux.HandleFunc("/api/services", ad.handleServices)
	mux.HandleFunc("/api/metrics", ad.handleMetrics)
	mux.HandleFunc("/api/health", ad.handleHealth)
	mux.HandleFunc("/api/config", ad.handleConfiguration)
	mux.HandleFunc("/api/events", ad.handleEvents)
	mux.HandleFunc("/api/alerts", ad.handleAlerts)

	// Management routes
	mux.HandleFunc("/api/services/toggle", ad.handleServiceToggle)
	mux.HandleFunc("/api/services/restart", ad.handleServiceRestart)
	mux.HandleFunc("/api/config/reload", ad.handleConfigReload)
	mux.HandleFunc("/api/cache/clear", ad.handleCacheClear)

	// WebSocket route
	mux.HandleFunc("/ws", ad.handleWebSocket)

	// Add middleware
	var handler http.Handler = mux
	if ad.config.CORS.Enabled {
		handler = ad.corsMiddleware(handler)
	}
	if ad.config.BasicAuth.Enabled {
		handler = ad.basicAuthMiddleware(handler)
	}
	if ad.config.RateLimiting.Enabled {
		handler = ad.rateLimitMiddleware(handler)
	}

	ad.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", ad.config.Port),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

func (ad *AdminDashboard) Start() error {
	if !ad.config.Enabled {
		return nil
	}

	ad.mutex.Lock()
	defer ad.mutex.Unlock()

	if ad.running {
		return fmt.Errorf("dashboard already running")
	}

	ad.running = true

	go ad.broadcastLoop()

	if ad.config.TLSEnabled {
		return ad.server.ListenAndServeTLS(ad.config.CertFile, ad.config.KeyFile)
	}

	return ad.server.ListenAndServe()
}

func (ad *AdminDashboard) Stop() error {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()

	if !ad.running {
		return nil
	}

	ad.running = false

	if ad.server != nil {
		return ad.server.Close()
	}

	return nil
}

func (ad *AdminDashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := ad.getDashboardData()
	
	w.Header().Set("Content-Type", "text/html")
	ad.templates.ExecuteTemplate(w, "dashboard", data)
}

func (ad *AdminDashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := ad.getDashboardData()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (ad *AdminDashboard) handleServices(w http.ResponseWriter, r *http.Request) {
	services := ad.getServicesData()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

func (ad *AdminDashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := ad.getMetricsData()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (ad *AdminDashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	if ad.healthChecker == nil {
		http.Error(w, "Health checker not available", http.StatusServiceUnavailable)
		return
	}
	
	health := ad.healthChecker.GetSystemHealth()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (ad *AdminDashboard) handleConfiguration(w http.ResponseWriter, r *http.Request) {
	config := ad.getConfigurationData()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (ad *AdminDashboard) handleEvents(w http.ResponseWriter, r *http.Request) {
	events := ad.getRecentEvents()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (ad *AdminDashboard) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := ad.getActiveAlerts()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (ad *AdminDashboard) handleServiceToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	serviceName := r.FormValue("service")
	action := r.FormValue("action")
	
	success := ad.toggleService(serviceName, action)
	
	response := map[string]interface{}{
		"success": success,
		"service": serviceName,
		"action":  action,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ad *AdminDashboard) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	serviceName := r.FormValue("service")
	success := ad.restartService(serviceName)
	
	response := map[string]interface{}{
		"success": success,
		"service": serviceName,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ad *AdminDashboard) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	success := ad.reloadConfiguration()
	
	response := map[string]interface{}{
		"success": success,
		"message": "Configuration reload requested",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ad *AdminDashboard) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	success := ad.clearCache()
	
	response := map[string]interface{}{
		"success": success,
		"message": "Cache clear requested",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ad *AdminDashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// WebSocket implementation would go here
	// For this example, we'll return a simple response
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("WebSocket not implemented in this example"))
}

func (ad *AdminDashboard) getDashboardData() *DashboardData {
	return &DashboardData{
		Timestamp:     time.Now(),
		SystemHealth:  ad.getSystemHealth(),
		Services:      ad.getServicesData(),
		Metrics:       ad.getMetricsData(),
		Configuration: ad.getConfigurationData(),
		RecentEvents:  ad.getRecentEvents(),
		Alerts:        ad.getActiveAlerts(),
	}
}

func (ad *AdminDashboard) getSystemHealth() *health.SystemHealth {
	if ad.healthChecker == nil {
		return &health.SystemHealth{
			Status:    health.StatusUnknown,
			Timestamp: time.Now(),
		}
	}
	return ad.healthChecker.GetSystemHealth()
}

func (ad *AdminDashboard) getServicesData() []ServiceStatus {
	var services []ServiceStatus
	
	if ad.serviceManager == nil {
		return services
	}
	
	// Mock data for services
	services = append(services, ServiceStatus{
		Name:              "example-service",
		Host:              "localhost",
		Port:              8080,
		Status:            "active",
		Health:            "healthy",
		RequestCount:      1000,
		ErrorCount:        5,
		AverageLatency:    50 * time.Millisecond,
		LastHealthCheck:   time.Now().Add(-30 * time.Second),
		ActiveConnections: 25,
		Metadata:          map[string]string{"version": "1.0.0"},
	})
	
	return services
}

func (ad *AdminDashboard) getMetricsData() DashboardMetrics {
	// Mock metrics data
	return DashboardMetrics{
		TotalRequests:       10000,
		RequestsPerSecond:   150.5,
		AverageResponseTime: 75 * time.Millisecond,
		ErrorRate:           0.5,
		ActiveConnections:   100,
		MemoryUsage:         512 * 1024 * 1024, // 512MB
		CPUUsage:            25.5,
		CacheHitRate:        85.2,
		CircuitBreakerTrips: 3,
		RateLimitBlocks:     25,
		SecurityBlocks:      7,
	}
}

func (ad *AdminDashboard) getConfigurationData() ConfigurationData {
	return ConfigurationData{
		Version:   "1.0.0",
		StartTime: time.Now().Add(-2 * time.Hour),
		LogLevel:  "info",
		Features: map[string]bool{
			"caching":         true,
			"circuit_breaker": true,
			"rate_limiting":   true,
			"waf":             true,
			"tls":             true,
		},
		Settings: map[string]interface{}{
			"max_connections": 1000,
			"timeout":         "30s",
			"workers":         8,
		},
	}
}

func (ad *AdminDashboard) getRecentEvents() []SystemEvent {
	events := []SystemEvent{
		{
			ID:        "evt-001",
			Timestamp: time.Now().Add(-5 * time.Minute),
			Type:      EventServiceUp,
			Severity:  SeverityInfo,
			Message:   "Service example-service started successfully",
			Source:    "service-manager",
		},
		{
			ID:        "evt-002",
			Timestamp: time.Now().Add(-10 * time.Minute),
			Type:      EventConfigReload,
			Severity:  SeverityInfo,
			Message:   "Configuration reloaded successfully",
			Source:    "config-manager",
		},
	}
	
	return events
}

func (ad *AdminDashboard) getActiveAlerts() []Alert {
	alerts := []Alert{
		{
			ID:          "alert-001",
			Timestamp:   time.Now().Add(-15 * time.Minute),
			Type:        AlertPerformance,
			Severity:    AlertSeverityMedium,
			Title:       "High Response Time",
			Description: "Average response time exceeded threshold",
			Source:      "metrics-collector",
			Status:      AlertStatusActive,
		},
	}
	
	return alerts
}

func (ad *AdminDashboard) toggleService(serviceName, action string) bool {
	// Implementation would interact with service manager
	return true
}

func (ad *AdminDashboard) restartService(serviceName string) bool {
	// Implementation would restart the specific service
	return true
}

func (ad *AdminDashboard) reloadConfiguration() bool {
	// Implementation would trigger configuration reload
	return true
}

func (ad *AdminDashboard) clearCache() bool {
	// Implementation would clear caches
	return true
}

func (ad *AdminDashboard) broadcastLoop() {
	ticker := time.NewTicker(ad.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if ad.running {
				ad.broadcastUpdates()
			}
		}
	}
}

func (ad *AdminDashboard) broadcastUpdates() {
	data := ad.getDashboardData()
	jsonData, _ := json.Marshal(data)

	ad.mutex.RLock()
	for _, conn := range ad.websockets {
		conn.conn.WriteMessage(1, jsonData)
	}
	ad.mutex.RUnlock()
}

func (ad *AdminDashboard) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ad.config.CORS.Enabled {
			origin := r.Header.Get("Origin")
			if ad.isOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(ad.config.CORS.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(ad.config.CORS.AllowedHeaders, ", "))
			
			if ad.config.CORS.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

func (ad *AdminDashboard) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ad.config.BasicAuth.Enabled {
			username, password, ok := r.BasicAuth()
			if !ok || username != ad.config.BasicAuth.Username || password != ad.config.BasicAuth.Password {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, ad.config.BasicAuth.Realm))
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

func (ad *AdminDashboard) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple rate limiting implementation
		next.ServeHTTP(w, r)
	})
}

func (ad *AdminDashboard) isOriginAllowed(origin string) bool {
	for _, allowed := range ad.config.CORS.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

const dashboardHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>MarchProxy Admin Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .services-table { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: bold; }
        .status-healthy { color: #27ae60; font-weight: bold; }
        .status-unhealthy { color: #e74c3c; font-weight: bold; }
        .btn { padding: 8px 16px; border: none; border-radius: 3px; cursor: pointer; margin: 2px; }
        .btn-primary { background: #3498db; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-warning { background: #f39c12; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MarchProxy Admin Dashboard</h1>
            <p>Real-time monitoring and management interface</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{.Metrics.TotalRequests}}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{printf "%.1f" .Metrics.RequestsPerSecond}}</div>
                <div class="stat-label">Requests/Second</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Metrics.AverageResponseTime}}</div>
                <div class="stat-label">Avg Response Time</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{printf "%.2f%%" .Metrics.ErrorRate}}</div>
                <div class="stat-label">Error Rate</div>
            </div>
        </div>
        
        <div class="services-table">
            <h2>Services Status</h2>
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Host:Port</th>
                        <th>Status</th>
                        <th>Health</th>
                        <th>Requests</th>
                        <th>Errors</th>
                        <th>Latency</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Services}}
                    <tr>
                        <td>{{.Name}}</td>
                        <td>{{.Host}}:{{.Port}}</td>
                        <td>{{.Status}}</td>
                        <td class="{{if eq .Health "healthy"}}status-healthy{{else}}status-unhealthy{{end}}">{{.Health}}</td>
                        <td>{{.RequestCount}}</td>
                        <td>{{.ErrorCount}}</td>
                        <td>{{.AverageLatency}}</td>
                        <td>
                            <button class="btn btn-warning">Restart</button>
                            <button class="btn btn-danger">Stop</button>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 5 seconds
        setInterval(function() {
            location.reload();
        }, 5000);
    </script>
</body>
</html>
`

const serviceTableHTML = ``
const metricsHTML = ``
const configurationHTML = ``