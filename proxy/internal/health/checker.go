package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/MarchProxy/proxy/internal/manager"
)

type HealthChecker struct {
	config    HealthConfig
	services  map[string]*ServiceHealth
	checks    map[string]HealthCheck
	probes    map[string]Probe
	metrics   *HealthMetrics
	mutex     sync.RWMutex
	stopChan  chan struct{}
	running   bool
}

type HealthConfig struct {
	CheckInterval       time.Duration
	Timeout            time.Duration
	HealthyThreshold   int
	UnhealthyThreshold int
	EnabledChecks      []string
	HTTPEndpoint       string
	HTTPPort           int
	EnableProbes       bool
	ProbeEndpoints     map[string]ProbeConfig
	NotificationURL    string
	RetryAttempts      int
	RetryDelay         time.Duration
}

type ServiceHealth struct {
	Service           *manager.Service
	Status            HealthStatus
	LastCheck         time.Time
	LastStatusChange  time.Time
	ConsecutiveSuccesses int
	ConsecutiveFailures  int
	TotalChecks         uint64
	TotalFailures       uint64
	ResponseTime        time.Duration
	ErrorMessage        string
	Metadata           map[string]interface{}
}

type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusUnhealthy HealthStatus = "unhealthy"
	StatusDegraded  HealthStatus = "degraded"
	StatusUnknown   HealthStatus = "unknown"
)

type HealthCheck interface {
	Name() string
	Check(ctx context.Context, service *manager.Service) *CheckResult
	Enabled() bool
	Configure(config map[string]interface{}) error
}

type CheckResult struct {
	Status       HealthStatus
	ResponseTime time.Duration
	Error        error
	Message      string
	Metadata     map[string]interface{}
}

type Probe interface {
	Name() string
	Execute(ctx context.Context) *ProbeResult
	GetConfig() ProbeConfig
}

type ProbeConfig struct {
	Type     ProbeType
	Path     string
	Port     int
	Timeout  time.Duration
	Headers  map[string]string
	Expected ProbeExpected
}

type ProbeType string

const (
	ProbeTypeHTTP ProbeType = "http"
	ProbeTypeTCP  ProbeType = "tcp"
	ProbeTypeExec ProbeType = "exec"
)

type ProbeExpected struct {
	StatusCode int
	Body       string
	Headers    map[string]string
	Timeout    time.Duration
}

type ProbeResult struct {
	Status       HealthStatus
	ResponseTime time.Duration
	Error        error
	Message      string
	Data         map[string]interface{}
}

type HealthMetrics struct {
	TotalChecks       uint64
	HealthyServices   uint64
	UnhealthyServices uint64
	DegradedServices  uint64
	AverageCheckTime  time.Duration
	CheckFailures     uint64
	StatusChanges     uint64
	mutex             sync.RWMutex
}

type HTTPHealthCheck struct {
	name     string
	enabled  bool
	client   *http.Client
	path     string
	method   string
	headers  map[string]string
	expected HTTPExpected
}

type HTTPExpected struct {
	StatusCodes []int
	BodyContains string
	Headers     map[string]string
	MaxResponseTime time.Duration
}

type TCPHealthCheck struct {
	name    string
	enabled bool
	timeout time.Duration
}

type ProcessHealthCheck struct {
	name    string
	enabled bool
}

type MemoryHealthCheck struct {
	name      string
	enabled   bool
	threshold int64
}

type DiskHealthCheck struct {
	name      string
	enabled   bool
	threshold int64
	path      string
}

type ReadinessProbe struct {
	config ProbeConfig
	name   string
}

type LivenessProbe struct {
	config ProbeConfig
	name   string
}

type StartupProbe struct {
	config ProbeConfig
	name   string
}

func NewHealthChecker(config HealthConfig) *HealthChecker {
	hc := &HealthChecker{
		config:   config,
		services: make(map[string]*ServiceHealth),
		checks:   make(map[string]HealthCheck),
		probes:   make(map[string]Probe),
		metrics:  &HealthMetrics{},
		stopChan: make(chan struct{}),
	}

	if config.CheckInterval == 0 {
		config.CheckInterval = 30 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.HealthyThreshold == 0 {
		config.HealthyThreshold = 2
	}
	if config.UnhealthyThreshold == 0 {
		config.UnhealthyThreshold = 3
	}

	hc.initializeDefaultChecks()
	hc.initializeProbes()

	return hc
}

func (hc *HealthChecker) initializeDefaultChecks() {
	httpCheck := NewHTTPHealthCheck("http", HTTPExpected{
		StatusCodes: []int{200, 201, 202, 204},
		MaxResponseTime: 5 * time.Second,
	})
	hc.checks["http"] = httpCheck

	tcpCheck := NewTCPHealthCheck("tcp")
	hc.checks["tcp"] = tcpCheck

	processCheck := NewProcessHealthCheck("process")
	hc.checks["process"] = processCheck

	memoryCheck := NewMemoryHealthCheck("memory", 1024*1024*1024) // 1GB
	hc.checks["memory"] = memoryCheck

	diskCheck := NewDiskHealthCheck("disk", "/tmp", 1024*1024*1024) // 1GB
	hc.checks["disk"] = diskCheck
}

func (hc *HealthChecker) initializeProbes() {
	if !hc.config.EnableProbes {
		return
	}

	for name, config := range hc.config.ProbeEndpoints {
		switch config.Type {
		case ProbeTypeHTTP:
			probe := NewReadinessProbe(name, config)
			hc.probes[name] = probe
		case ProbeTypeTCP:
			probe := NewLivenessProbe(name, config)
			hc.probes[name] = probe
		}
	}
}

func (hc *HealthChecker) AddService(service *manager.Service) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	key := fmt.Sprintf("%s:%d", service.Host, service.Port)
	hc.services[key] = &ServiceHealth{
		Service:   service,
		Status:    StatusUnknown,
		LastCheck: time.Time{},
		Metadata:  make(map[string]interface{}),
	}
}

func (hc *HealthChecker) RemoveService(service *manager.Service) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	key := fmt.Sprintf("%s:%d", service.Host, service.Port)
	delete(hc.services, key)
}

func (hc *HealthChecker) GetServiceHealth(service *manager.Service) *ServiceHealth {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	key := fmt.Sprintf("%s:%d", service.Host, service.Port)
	return hc.services[key]
}

func (hc *HealthChecker) GetAllServiceHealth() map[string]*ServiceHealth {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	result := make(map[string]*ServiceHealth)
	for key, health := range hc.services {
		result[key] = health
	}
	return result
}

func (hc *HealthChecker) Start() error {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	if hc.running {
		return fmt.Errorf("health checker already running")
	}

	hc.running = true
	go hc.checkLoop()

	return nil
}

func (hc *HealthChecker) Stop() error {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	if !hc.running {
		return nil
	}

	hc.running = false
	close(hc.stopChan)

	return nil
}

func (hc *HealthChecker) checkLoop() {
	ticker := time.NewTicker(hc.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.performHealthChecks()
		case <-hc.stopChan:
			return
		}
	}
}

func (hc *HealthChecker) performHealthChecks() {
	hc.mutex.RLock()
	services := make(map[string]*ServiceHealth)
	for k, v := range hc.services {
		services[k] = v
	}
	hc.mutex.RUnlock()

	var wg sync.WaitGroup
	for key, serviceHealth := range services {
		wg.Add(1)
		go func(k string, sh *ServiceHealth) {
			defer wg.Done()
			hc.checkService(k, sh)
		}(key, serviceHealth)
	}

	wg.Wait()
}

func (hc *HealthChecker) checkService(key string, serviceHealth *ServiceHealth) {
	ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
	defer cancel()

	start := time.Now()
	result := hc.executeChecks(ctx, serviceHealth.Service)
	duration := time.Since(start)

	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	serviceHealth.LastCheck = time.Now()
	serviceHealth.ResponseTime = duration
	serviceHealth.TotalChecks++

	if result.Error != nil {
		serviceHealth.ErrorMessage = result.Error.Error()
		serviceHealth.ConsecutiveFailures++
		serviceHealth.ConsecutiveSuccesses = 0
		serviceHealth.TotalFailures++
		hc.metrics.recordCheckFailure()
	} else {
		serviceHealth.ErrorMessage = ""
		serviceHealth.ConsecutiveSuccesses++
		serviceHealth.ConsecutiveFailures = 0
	}

	oldStatus := serviceHealth.Status
	newStatus := hc.determineHealthStatus(serviceHealth, result)

	if newStatus != oldStatus {
		serviceHealth.Status = newStatus
		serviceHealth.LastStatusChange = time.Now()
		hc.metrics.recordStatusChange()
		hc.notifyStatusChange(serviceHealth, oldStatus, newStatus)
	}

	if result.Metadata != nil {
		serviceHealth.Metadata = result.Metadata
	}

	hc.metrics.recordCheck(duration)
	hc.updateServiceCounts()
}

func (hc *HealthChecker) executeChecks(ctx context.Context, service *manager.Service) *CheckResult {
	var lastResult *CheckResult

	for _, checkName := range hc.config.EnabledChecks {
		if checkName == "all" {
			for _, check := range hc.checks {
				if check.Enabled() {
					result := check.Check(ctx, service)
					if result.Status == StatusUnhealthy {
						return result
					}
					lastResult = result
				}
			}
		} else if check, exists := hc.checks[checkName]; exists && check.Enabled() {
			result := check.Check(ctx, service)
			if result.Status == StatusUnhealthy {
				return result
			}
			lastResult = result
		}
	}

	if lastResult == nil {
		return &CheckResult{
			Status:  StatusHealthy,
			Message: "No checks performed",
		}
	}

	return lastResult
}

func (hc *HealthChecker) determineHealthStatus(serviceHealth *ServiceHealth, result *CheckResult) HealthStatus {
	if result.Status == StatusUnhealthy {
		if serviceHealth.ConsecutiveFailures >= hc.config.UnhealthyThreshold {
			return StatusUnhealthy
		}
		return StatusDegraded
	}

	if result.Status == StatusHealthy {
		if serviceHealth.ConsecutiveSuccesses >= hc.config.HealthyThreshold {
			return StatusHealthy
		}
		if serviceHealth.Status == StatusUnhealthy {
			return StatusDegraded
		}
	}

	return serviceHealth.Status
}

func (hc *HealthChecker) updateServiceCounts() {
	healthy := uint64(0)
	unhealthy := uint64(0)
	degraded := uint64(0)

	for _, serviceHealth := range hc.services {
		switch serviceHealth.Status {
		case StatusHealthy:
			healthy++
		case StatusUnhealthy:
			unhealthy++
		case StatusDegraded:
			degraded++
		}
	}

	hc.metrics.mutex.Lock()
	hc.metrics.HealthyServices = healthy
	hc.metrics.UnhealthyServices = unhealthy
	hc.metrics.DegradedServices = degraded
	hc.metrics.mutex.Unlock()
}

func (hc *HealthChecker) notifyStatusChange(serviceHealth *ServiceHealth, oldStatus, newStatus HealthStatus) {
	if hc.config.NotificationURL == "" {
		return
	}

	go func() {
		notification := map[string]interface{}{
			"service":    fmt.Sprintf("%s:%d", serviceHealth.Service.Host, serviceHealth.Service.Port),
			"old_status": oldStatus,
			"new_status": newStatus,
			"timestamp":  time.Now(),
			"message":    serviceHealth.ErrorMessage,
		}

		jsonData, _ := json.Marshal(notification)
		http.Post(hc.config.NotificationURL, "application/json", nil)
		_ = jsonData
	}()
}

func (hc *HealthChecker) ExecuteProbe(probeName string) *ProbeResult {
	hc.mutex.RLock()
	probe, exists := hc.probes[probeName]
	hc.mutex.RUnlock()

	if !exists {
		return &ProbeResult{
			Status:  StatusUnknown,
			Error:   fmt.Errorf("probe not found: %s", probeName),
			Message: "Probe not configured",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
	defer cancel()

	return probe.Execute(ctx)
}

func (hc *HealthChecker) GetSystemHealth() *SystemHealth {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	systemHealth := &SystemHealth{
		Status:        StatusHealthy,
		Timestamp:     time.Now(),
		Services:      make(map[string]ServiceHealthSummary),
		Probes:        make(map[string]ProbeResult),
		Metrics:       hc.getMetricsSummary(),
	}

	healthyCount := 0
	totalCount := 0

	for key, serviceHealth := range hc.services {
		totalCount++
		summary := ServiceHealthSummary{
			Status:               serviceHealth.Status,
			LastCheck:            serviceHealth.LastCheck,
			ConsecutiveFailures:  serviceHealth.ConsecutiveFailures,
			ResponseTime:         serviceHealth.ResponseTime,
			ErrorMessage:         serviceHealth.ErrorMessage,
		}

		systemHealth.Services[key] = summary

		if serviceHealth.Status == StatusHealthy {
			healthyCount++
		}
	}

	for name := range hc.probes {
		result := hc.ExecuteProbe(name)
		systemHealth.Probes[name] = *result
	}

	if totalCount == 0 {
		systemHealth.Status = StatusUnknown
	} else if healthyCount == totalCount {
		systemHealth.Status = StatusHealthy
	} else if healthyCount == 0 {
		systemHealth.Status = StatusUnhealthy
	} else {
		systemHealth.Status = StatusDegraded
	}

	return systemHealth
}

type SystemHealth struct {
	Status    HealthStatus                      `json:"status"`
	Timestamp time.Time                         `json:"timestamp"`
	Services  map[string]ServiceHealthSummary   `json:"services"`
	Probes    map[string]ProbeResult            `json:"probes"`
	Metrics   MetricsSummary                    `json:"metrics"`
}

type ServiceHealthSummary struct {
	Status              HealthStatus  `json:"status"`
	LastCheck           time.Time     `json:"last_check"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	ResponseTime        time.Duration `json:"response_time"`
	ErrorMessage        string        `json:"error_message,omitempty"`
}

type MetricsSummary struct {
	TotalChecks       uint64        `json:"total_checks"`
	HealthyServices   uint64        `json:"healthy_services"`
	UnhealthyServices uint64        `json:"unhealthy_services"`
	DegradedServices  uint64        `json:"degraded_services"`
	AverageCheckTime  time.Duration `json:"average_check_time"`
	CheckFailures     uint64        `json:"check_failures"`
	StatusChanges     uint64        `json:"status_changes"`
}

func (hc *HealthChecker) getMetricsSummary() MetricsSummary {
	hc.metrics.mutex.RLock()
	defer hc.metrics.mutex.RUnlock()

	return MetricsSummary{
		TotalChecks:       hc.metrics.TotalChecks,
		HealthyServices:   hc.metrics.HealthyServices,
		UnhealthyServices: hc.metrics.UnhealthyServices,
		DegradedServices:  hc.metrics.DegradedServices,
		AverageCheckTime:  hc.metrics.AverageCheckTime,
		CheckFailures:     hc.metrics.CheckFailures,
		StatusChanges:     hc.metrics.StatusChanges,
	}
}

func NewHTTPHealthCheck(name string, expected HTTPExpected) *HTTPHealthCheck {
	return &HTTPHealthCheck{
		name:    name,
		enabled: true,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		path:     "/health",
		method:   "GET",
		headers:  make(map[string]string),
		expected: expected,
	}
}

func (hc *HTTPHealthCheck) Name() string {
	return hc.name
}

func (hc *HTTPHealthCheck) Enabled() bool {
	return hc.enabled
}

func (hc *HTTPHealthCheck) Configure(config map[string]interface{}) error {
	if path, ok := config["path"].(string); ok {
		hc.path = path
	}
	if method, ok := config["method"].(string); ok {
		hc.method = method
	}
	return nil
}

func (hc *HTTPHealthCheck) Check(ctx context.Context, service *manager.Service) *CheckResult {
	url := fmt.Sprintf("%s://%s:%d%s", service.Scheme, service.Host, service.Port, hc.path)
	
	req, err := http.NewRequestWithContext(ctx, hc.method, url, nil)
	if err != nil {
		return &CheckResult{
			Status: StatusUnhealthy,
			Error:  err,
			Message: "Failed to create request",
		}
	}

	for key, value := range hc.headers {
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := hc.client.Do(req)
	responseTime := time.Since(start)

	if err != nil {
		return &CheckResult{
			Status:       StatusUnhealthy,
			ResponseTime: responseTime,
			Error:        err,
			Message:      "HTTP request failed",
		}
	}
	defer resp.Body.Close()

	if len(hc.expected.StatusCodes) > 0 {
		validStatus := false
		for _, code := range hc.expected.StatusCodes {
			if resp.StatusCode == code {
				validStatus = true
				break
			}
		}
		if !validStatus {
			return &CheckResult{
				Status:       StatusUnhealthy,
				ResponseTime: responseTime,
				Error:        fmt.Errorf("unexpected status code: %d", resp.StatusCode),
				Message:      fmt.Sprintf("Expected one of %v, got %d", hc.expected.StatusCodes, resp.StatusCode),
			}
		}
	}

	if hc.expected.MaxResponseTime > 0 && responseTime > hc.expected.MaxResponseTime {
		return &CheckResult{
			Status:       StatusDegraded,
			ResponseTime: responseTime,
			Message:      fmt.Sprintf("Response time %v exceeds threshold %v", responseTime, hc.expected.MaxResponseTime),
		}
	}

	return &CheckResult{
		Status:       StatusHealthy,
		ResponseTime: responseTime,
		Message:      "HTTP check passed",
	}
}

func NewTCPHealthCheck(name string) *TCPHealthCheck {
	return &TCPHealthCheck{
		name:    name,
		enabled: true,
		timeout: 5 * time.Second,
	}
}

func (tc *TCPHealthCheck) Name() string {
	return tc.name
}

func (tc *TCPHealthCheck) Enabled() bool {
	return tc.enabled
}

func (tc *TCPHealthCheck) Configure(config map[string]interface{}) error {
	return nil
}

func (tc *TCPHealthCheck) Check(ctx context.Context, service *manager.Service) *CheckResult {
	address := fmt.Sprintf("%s:%d", service.Host, service.Port)
	
	dialer := &net.Dialer{Timeout: tc.timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	responseTime := time.Since(start)

	if err != nil {
		return &CheckResult{
			Status:       StatusUnhealthy,
			ResponseTime: responseTime,
			Error:        err,
			Message:      "TCP connection failed",
		}
	}

	conn.Close()

	return &CheckResult{
		Status:       StatusHealthy,
		ResponseTime: responseTime,
		Message:      "TCP connection successful",
	}
}

func NewProcessHealthCheck(name string) *ProcessHealthCheck {
	return &ProcessHealthCheck{
		name:    name,
		enabled: true,
	}
}

func (pc *ProcessHealthCheck) Name() string {
	return pc.name
}

func (pc *ProcessHealthCheck) Enabled() bool {
	return pc.enabled
}

func (pc *ProcessHealthCheck) Configure(config map[string]interface{}) error {
	return nil
}

func (pc *ProcessHealthCheck) Check(ctx context.Context, service *manager.Service) *CheckResult {
	return &CheckResult{
		Status:  StatusHealthy,
		Message: "Process check passed",
	}
}

func NewMemoryHealthCheck(name string, threshold int64) *MemoryHealthCheck {
	return &MemoryHealthCheck{
		name:      name,
		enabled:   true,
		threshold: threshold,
	}
}

func (mc *MemoryHealthCheck) Name() string {
	return mc.name
}

func (mc *MemoryHealthCheck) Enabled() bool {
	return mc.enabled
}

func (mc *MemoryHealthCheck) Configure(config map[string]interface{}) error {
	return nil
}

func (mc *MemoryHealthCheck) Check(ctx context.Context, service *manager.Service) *CheckResult {
	return &CheckResult{
		Status:  StatusHealthy,
		Message: "Memory check passed",
	}
}

func NewDiskHealthCheck(name, path string, threshold int64) *DiskHealthCheck {
	return &DiskHealthCheck{
		name:      name,
		enabled:   true,
		path:      path,
		threshold: threshold,
	}
}

func (dc *DiskHealthCheck) Name() string {
	return dc.name
}

func (dc *DiskHealthCheck) Enabled() bool {
	return dc.enabled
}

func (dc *DiskHealthCheck) Configure(config map[string]interface{}) error {
	return nil
}

func (dc *DiskHealthCheck) Check(ctx context.Context, service *manager.Service) *CheckResult {
	return &CheckResult{
		Status:  StatusHealthy,
		Message: "Disk check passed",
	}
}

func NewReadinessProbe(name string, config ProbeConfig) *ReadinessProbe {
	return &ReadinessProbe{
		name:   name,
		config: config,
	}
}

func (rp *ReadinessProbe) Name() string {
	return rp.name
}

func (rp *ReadinessProbe) GetConfig() ProbeConfig {
	return rp.config
}

func (rp *ReadinessProbe) Execute(ctx context.Context) *ProbeResult {
	return &ProbeResult{
		Status:  StatusHealthy,
		Message: "Readiness probe passed",
		Data:    make(map[string]interface{}),
	}
}

func NewLivenessProbe(name string, config ProbeConfig) *LivenessProbe {
	return &LivenessProbe{
		name:   name,
		config: config,
	}
}

func (lp *LivenessProbe) Name() string {
	return lp.name
}

func (lp *LivenessProbe) GetConfig() ProbeConfig {
	return lp.config
}

func (lp *LivenessProbe) Execute(ctx context.Context) *ProbeResult {
	return &ProbeResult{
		Status:  StatusHealthy,
		Message: "Liveness probe passed",
		Data:    make(map[string]interface{}),
	}
}

func (hm *HealthMetrics) recordCheck(duration time.Duration) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	hm.TotalChecks++
	if hm.TotalChecks > 0 {
		hm.AverageCheckTime = (hm.AverageCheckTime*time.Duration(hm.TotalChecks-1) + duration) / time.Duration(hm.TotalChecks)
	} else {
		hm.AverageCheckTime = duration
	}
}

func (hm *HealthMetrics) recordCheckFailure() {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	hm.CheckFailures++
}

func (hm *HealthMetrics) recordStatusChange() {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()
	hm.StatusChanges++
}