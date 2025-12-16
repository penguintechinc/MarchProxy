package middleware

import (
	// "context"  // Unused
	"fmt"
	"net/http"
	// "reflect"  // Unused
	"sort"
	"strings"  // Added - was missing
	"sync"
	"time"

	"marchproxy-egress/internal/manager"
)

// Pipeline manages middleware execution order and context
type Pipeline struct {
	middlewares []Middleware
	plugins     map[string]Plugin
	config      *PipelineConfig
	stats       *PipelineStats
	hooks       *Hooks
	mu          sync.RWMutex
}

// Middleware represents a middleware component
type Middleware interface {
	Name() string
	Priority() int
	ProcessRequest(req *http.Request, ctx *MiddlewareContext) error
	ProcessResponse(resp *http.Response, ctx *MiddlewareContext) error
	Enabled() bool
}

// Plugin represents a custom plugin
type Plugin interface {
	Name() string
	Version() string
	Initialize(config map[string]interface{}) error
	Execute(req *http.Request, resp *http.Response, ctx *MiddlewareContext) error
	Cleanup() error
	Health() error
}

// MiddlewareContext holds context information for middleware processing
type MiddlewareContext struct {
	Request       *http.Request
	Response      *http.Response
	Service       *manager.Service
	Variables     map[string]interface{}
	Metadata      map[string]interface{}
	Errors        []error
	StartTime     time.Time
	ProcessingTime time.Duration
	RetryCount    int
	AbortPipeline bool
	SkipCount     int
}

// SetData sets a value in the context variables
func (ctx *MiddlewareContext) SetData(key string, value interface{}) {
	if ctx.Variables == nil {
		ctx.Variables = make(map[string]interface{})
	}
	ctx.Variables[key] = value
}

// GetData retrieves a value from the context variables
func (ctx *MiddlewareContext) GetData(key string) interface{} {
	if ctx.Variables == nil {
		return nil
	}
	return ctx.Variables[key]
}

// HasData checks if a key exists in the context variables
func (ctx *MiddlewareContext) HasData(key string) bool {
	if ctx.Variables == nil {
		return false
	}
	_, exists := ctx.Variables[key]
	return exists
}

// PipelineConfig holds pipeline configuration
type PipelineConfig struct {
	MaxMiddlewares   int
	DefaultTimeout   time.Duration
	EnableStats      bool
	StatsInterval    time.Duration
	EnableHooks      bool
	EnablePlugins    bool
	PluginDirectory  string
	MaxRetries       int
	RetryDelay       time.Duration
	EnableProfiling  bool
	EnableTracing    bool
}

// PipelineStats holds pipeline execution statistics
type PipelineStats struct {
	TotalRequests        uint64
	ProcessedRequests    uint64
	FailedRequests       uint64
	AverageLatency       time.Duration
	MiddlewareLatencies  map[string]time.Duration
	PluginLatencies      map[string]time.Duration
	ErrorCounts          map[string]uint64
	SuccessCounts        map[string]uint64
	LastUpdate           time.Time
}

// Hooks allows custom hooks at various pipeline stages
type Hooks struct {
	BeforeProcessing []HookFunc
	AfterProcessing  []HookFunc
	OnError          []ErrorHookFunc
	OnSuccess        []HookFunc
	mu               sync.RWMutex
}

// HookFunc represents a standard hook function
type HookFunc func(*MiddlewareContext) error

// ErrorHookFunc represents an error hook function
type ErrorHookFunc func(*MiddlewareContext, error) error

// Built-in middleware implementations

// LoggingMiddleware logs request/response information
type LoggingMiddleware struct {
	enabled bool
	format  string
	level   LogLevel
}

// AuthenticationMiddleware handles request authentication
type AuthenticationMiddleware struct {
	enabled     bool
	schemes     []AuthScheme
	validators  map[string]AuthValidator
	headerName  string
	cookieName  string
}

// RateLimitMiddleware implements rate limiting
type RateLimitMiddleware struct {
	enabled    bool
	limiters   map[string]*RateLimiter
	defaultRPS int
	burstSize  int
}

// CompressionMiddleware handles content compression
type CompressionMiddleware struct {
	enabled      bool
	algorithms   []CompressionAlgorithm
	minSize      int
	contentTypes []string
}

// CacheMiddleware handles response caching
type CacheMiddleware struct {
	enabled   bool
	store     CacheStore
	ttl       time.Duration
	varyBy    []string
	excludes  []string
}

// SecurityMiddleware adds security headers and policies
type SecurityMiddleware struct {
	enabled         bool
	headers         map[string]string
	policies        []SecurityPolicy
	blockMalicious  bool
}

// MetricsMiddleware collects detailed metrics
type MetricsMiddleware struct {
	enabled    bool
	collector  MetricsCollector
	labels     []string
	histograms map[string]Histogram
}

// ValidationMiddleware validates requests
type ValidationMiddleware struct {
	enabled   bool
	schemas   map[string]ValidationSchema
	validator RequestValidator
}

// TransformMiddleware transforms requests/responses
type TransformMiddleware struct {
	enabled      bool
	transformers map[string]Transformer
	rules        []TransformRule
}

// CircuitBreakerMiddleware implements circuit breaker pattern
type CircuitBreakerMiddleware struct {
	enabled  bool
	breakers map[string]*CircuitBreaker
	config   *CircuitBreakerConfig
}

// Supporting types and interfaces

type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

type AuthScheme int

const (
	AuthBasic AuthScheme = iota
	AuthBearer
	AuthJWT
	AuthAPIKey
	AuthOAuth2
)

type AuthValidator interface {
	Validate(token string, req *http.Request) (*AuthResult, error)
}

type AuthResult struct {
	Valid    bool
	UserID   string
	Roles    []string
	Claims   map[string]interface{}
	ExpireAt time.Time
}

type RateLimiter struct {
	limit     int
	window    time.Duration
	requests  map[string][]time.Time
	mu        sync.RWMutex
}

type CompressionAlgorithm int

const (
	CompressionGzip CompressionAlgorithm = iota
	CompressionBrotli
	CompressionZstd
	CompressionDeflate
)

type CacheStore interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte, ttl time.Duration) error
	Delete(key string) error
	Exists(key string) bool
	Clear() error
}

type SecurityPolicy interface {
	Apply(req *http.Request, resp *http.Response) error
	Validate(req *http.Request) error
}

type MetricsCollector interface {
	Counter(name string, labels map[string]string) Counter
	Histogram(name string, labels map[string]string) Histogram
	Gauge(name string, labels map[string]string) Gauge
}

type Counter interface {
	Inc()
	Add(float64)
}

type Histogram interface {
	Observe(float64)
}

type Gauge interface {
	Set(float64)
	Inc()
	Dec()
}

type ValidationSchema interface {
	Validate(data interface{}) error
	GetErrors() []ValidationError
}

type ValidationError struct {
	Field   string
	Message string
	Code    string
}

type RequestValidator interface {
	ValidateHeaders(req *http.Request) error
	ValidateBody(req *http.Request) error
	ValidateParameters(req *http.Request) error
}

type Transformer interface {
	Transform(data interface{}) (interface{}, error)
	CanTransform(contentType string) bool
}

type TransformRule struct {
	Pattern     string
	Transformer string
	Condition   string
	Priority    int
}

type CircuitBreaker struct {
	state         CircuitState
	failures      int
	requests      int
	lastFailure   time.Time
	nextAttempt   time.Time
	config        *CircuitBreakerConfig
	mu            sync.RWMutex
}

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

type CircuitBreakerConfig struct {
	FailureThreshold int
	RecoveryTimeout  time.Duration
	TestRequests     int
	SuccessThreshold int
}

// NewPipeline creates a new middleware pipeline
func NewPipeline(config *PipelineConfig) *Pipeline {
	if config == nil {
		config = &PipelineConfig{
			MaxMiddlewares:  50,
			DefaultTimeout:  time.Second * 30,
			EnableStats:     true,
			StatsInterval:   time.Minute,
			EnableHooks:     true,
			EnablePlugins:   true,
			MaxRetries:      3,
			RetryDelay:      time.Millisecond * 100,
			EnableProfiling: true,
			EnableTracing:   true,
		}
	}

	pipeline := &Pipeline{
		middlewares: make([]Middleware, 0),
		plugins:     make(map[string]Plugin),
		config:      config,
		stats: &PipelineStats{
			MiddlewareLatencies: make(map[string]time.Duration),
			PluginLatencies:     make(map[string]time.Duration),
			ErrorCounts:         make(map[string]uint64),
			SuccessCounts:       make(map[string]uint64),
			LastUpdate:          time.Now(),
		},
		hooks: &Hooks{
			BeforeProcessing: make([]HookFunc, 0),
			AfterProcessing:  make([]HookFunc, 0),
			OnError:          make([]ErrorHookFunc, 0),
			OnSuccess:        make([]HookFunc, 0),
		},
	}

	// Start statistics collection if enabled
	if config.EnableStats {
		go pipeline.statsCollector()
	}

	return pipeline
}

// AddMiddleware adds a middleware to the pipeline
func (p *Pipeline) AddMiddleware(middleware Middleware) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.middlewares) >= p.config.MaxMiddlewares {
		return fmt.Errorf("maximum middlewares limit reached: %d", p.config.MaxMiddlewares)
	}

	// Check for duplicate middleware
	for _, existing := range p.middlewares {
		if existing.Name() == middleware.Name() {
			return fmt.Errorf("middleware already exists: %s", middleware.Name())
		}
	}

	p.middlewares = append(p.middlewares, middleware)

	// Sort middlewares by priority (highest first)
	sort.Slice(p.middlewares, func(i, j int) bool {
		return p.middlewares[i].Priority() > p.middlewares[j].Priority()
	})

	fmt.Printf("Middleware: Added '%s' with priority %d\n", middleware.Name(), middleware.Priority())
	return nil
}

// RemoveMiddleware removes a middleware from the pipeline
func (p *Pipeline) RemoveMiddleware(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, middleware := range p.middlewares {
		if middleware.Name() == name {
			p.middlewares = append(p.middlewares[:i], p.middlewares[i+1:]...)
			fmt.Printf("Middleware: Removed '%s'\n", name)
			return nil
		}
	}

	return fmt.Errorf("middleware not found: %s", name)
}

// AddPlugin adds a custom plugin to the pipeline
func (p *Pipeline) AddPlugin(plugin Plugin, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.config.EnablePlugins {
		return fmt.Errorf("plugins are disabled")
	}

	if _, exists := p.plugins[plugin.Name()]; exists {
		return fmt.Errorf("plugin already exists: %s", plugin.Name())
	}

	// Initialize plugin
	if err := plugin.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", plugin.Name(), err)
	}

	p.plugins[plugin.Name()] = plugin
	fmt.Printf("Middleware: Added plugin '%s' version %s\n", plugin.Name(), plugin.Version())
	return nil
}

// ProcessRequest processes a request through the middleware pipeline
func (p *Pipeline) ProcessRequest(req *http.Request, service *manager.Service) (*MiddlewareContext, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ctx := &MiddlewareContext{
		Request:   req,
		Service:   service,
		Variables: make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Errors:    make([]error, 0),
		StartTime: time.Now(),
	}

	p.stats.TotalRequests++

	// Execute before processing hooks
	if p.config.EnableHooks {
		for _, hook := range p.hooks.BeforeProcessing {
			if err := hook(ctx); err != nil {
				p.executeErrorHooks(ctx, err)
				return ctx, err
			}
		}
	}

	// Process through middlewares
	for _, middleware := range p.middlewares {
		if !middleware.Enabled() {
			continue
		}

		if ctx.AbortPipeline {
			break
		}

		start := time.Now()
		
		if err := middleware.ProcessRequest(req, ctx); err != nil {
			latency := time.Since(start)
			p.stats.MiddlewareLatencies[middleware.Name()] = latency
			p.stats.ErrorCounts[middleware.Name()]++
			
			ctx.Errors = append(ctx.Errors, err)
			
			// Execute error hooks
			if p.config.EnableHooks {
				for _, errorHook := range p.hooks.OnError {
					if hookErr := errorHook(ctx, err); hookErr != nil {
						ctx.Errors = append(ctx.Errors, hookErr)
					}
				}
			}
			
			// Decide whether to continue or abort
			if ctx.AbortPipeline {
				p.stats.FailedRequests++
				return ctx, err
			}
		} else {
			latency := time.Since(start)
			p.stats.MiddlewareLatencies[middleware.Name()] = latency
			p.stats.SuccessCounts[middleware.Name()]++
		}
	}

	// Process through plugins
	if p.config.EnablePlugins {
		for _, plugin := range p.plugins {
			start := time.Now()
			
			if err := plugin.Execute(req, nil, ctx); err != nil {
				latency := time.Since(start)
				p.stats.PluginLatencies[plugin.Name()] = latency
				ctx.Errors = append(ctx.Errors, err)
			} else {
				latency := time.Since(start)
				p.stats.PluginLatencies[plugin.Name()] = latency
			}
		}
	}

	ctx.ProcessingTime = time.Since(ctx.StartTime)
	
	if len(ctx.Errors) == 0 {
		p.stats.ProcessedRequests++
		
		// Execute success hooks
		if p.config.EnableHooks {
			for _, successHook := range p.hooks.OnSuccess {
				successHook(ctx)
			}
		}
	} else {
		p.stats.FailedRequests++
	}

	return ctx, nil
}

// ProcessResponse processes a response through the middleware pipeline
func (p *Pipeline) ProcessResponse(resp *http.Response, ctx *MiddlewareContext) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ctx.Response = resp

	// Process through middlewares in reverse order
	for i := len(p.middlewares) - 1; i >= 0; i-- {
		middleware := p.middlewares[i]
		
		if !middleware.Enabled() {
			continue
		}

		start := time.Now()
		
		if err := middleware.ProcessResponse(resp, ctx); err != nil {
			latency := time.Since(start)
			p.stats.MiddlewareLatencies[middleware.Name()] += latency
			p.stats.ErrorCounts[middleware.Name()]++
			ctx.Errors = append(ctx.Errors, err)
		} else {
			latency := time.Since(start)
			p.stats.MiddlewareLatencies[middleware.Name()] += latency
		}
	}

	// Process through plugins
	if p.config.EnablePlugins {
		for _, plugin := range p.plugins {
			start := time.Now()
			
			if err := plugin.Execute(ctx.Request, resp, ctx); err != nil {
				latency := time.Since(start)
				p.stats.PluginLatencies[plugin.Name()] += latency
				ctx.Errors = append(ctx.Errors, err)
			} else {
				latency := time.Since(start)
				p.stats.PluginLatencies[plugin.Name()] += latency
			}
		}
	}

	// Execute after processing hooks
	if p.config.EnableHooks {
		for _, hook := range p.hooks.AfterProcessing {
			if err := hook(ctx); err != nil {
				ctx.Errors = append(ctx.Errors, err)
			}
		}
	}

	return nil
}

// executeErrorHooks executes error hooks
func (p *Pipeline) executeErrorHooks(ctx *MiddlewareContext, err error) {
	if !p.config.EnableHooks {
		return
	}

	for _, errorHook := range p.hooks.OnError {
		if hookErr := errorHook(ctx, err); hookErr != nil {
			ctx.Errors = append(ctx.Errors, hookErr)
		}
	}
}

// AddBeforeHook adds a before processing hook
func (p *Pipeline) AddBeforeHook(hook HookFunc) {
	p.hooks.mu.Lock()
	defer p.hooks.mu.Unlock()
	p.hooks.BeforeProcessing = append(p.hooks.BeforeProcessing, hook)
}

// AddAfterHook adds an after processing hook
func (p *Pipeline) AddAfterHook(hook HookFunc) {
	p.hooks.mu.Lock()
	defer p.hooks.mu.Unlock()
	p.hooks.AfterProcessing = append(p.hooks.AfterProcessing, hook)
}

// AddErrorHook adds an error hook
func (p *Pipeline) AddErrorHook(hook ErrorHookFunc) {
	p.hooks.mu.Lock()
	defer p.hooks.mu.Unlock()
	p.hooks.OnError = append(p.hooks.OnError, hook)
}

// AddSuccessHook adds a success hook
func (p *Pipeline) AddSuccessHook(hook HookFunc) {
	p.hooks.mu.Lock()
	defer p.hooks.mu.Unlock()
	p.hooks.OnSuccess = append(p.hooks.OnSuccess, hook)
}

// statsCollector collects pipeline statistics
func (p *Pipeline) statsCollector() {
	ticker := time.NewTicker(p.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.collectStatistics()
		}
	}
}

// collectStatistics collects and updates pipeline statistics
func (p *Pipeline) collectStatistics() {
	p.mu.Lock()
	defer p.mu.Unlock()

	_ = p.stats.TotalRequests  // totalRequests declared but not used
	processedRequests := p.stats.ProcessedRequests

	// Calculate average latency
	if processedRequests > 0 {
		totalLatency := time.Duration(0)
		for _, latency := range p.stats.MiddlewareLatencies {
			totalLatency += latency
		}
		if len(p.stats.MiddlewareLatencies) > 0 {
			p.stats.AverageLatency = totalLatency / time.Duration(len(p.stats.MiddlewareLatencies))
		}
	}

	p.stats.LastUpdate = time.Now()
}

// Built-in middleware implementations

// LoggingMiddleware implementation
func NewLoggingMiddleware(format string, level LogLevel) *LoggingMiddleware {
	return &LoggingMiddleware{
		enabled: true,
		format:  format,
		level:   level,
	}
}

func (lm *LoggingMiddleware) Name() string {
	return "logging"
}

func (lm *LoggingMiddleware) Priority() int {
	return 1000 // High priority for logging
}

func (lm *LoggingMiddleware) ProcessRequest(req *http.Request, ctx *MiddlewareContext) error {
	if !lm.enabled {
		return nil
	}

	// Log request information
	fmt.Printf("Request: %s %s from %s\n", req.Method, req.URL.Path, req.RemoteAddr)
	ctx.Variables["request_logged"] = true
	return nil
}

func (lm *LoggingMiddleware) ProcessResponse(resp *http.Response, ctx *MiddlewareContext) error {
	if !lm.enabled {
		return nil
	}

	// Log response information
	duration := time.Since(ctx.StartTime)
	fmt.Printf("Response: %d in %v\n", resp.StatusCode, duration)
	return nil
}

func (lm *LoggingMiddleware) Enabled() bool {
	return lm.enabled
}

// AuthenticationMiddleware implementation
func NewAuthenticationMiddleware(schemes []AuthScheme) *AuthenticationMiddleware {
	return &AuthenticationMiddleware{
		enabled:    true,
		schemes:    schemes,
		validators: make(map[string]AuthValidator),
		headerName: "Authorization",
		cookieName: "auth_token",
	}
}

func (am *AuthenticationMiddleware) Name() string {
	return "authentication"
}

func (am *AuthenticationMiddleware) Priority() int {
	return 900 // High priority for security
}

func (am *AuthenticationMiddleware) ProcessRequest(req *http.Request, ctx *MiddlewareContext) error {
	if !am.enabled {
		return nil
	}

	// Extract and validate authentication token
	token := am.extractToken(req)
	if token == "" {
		return fmt.Errorf("authentication token not found")
	}

	// Validate token
	result, err := am.validateToken(token, req)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("invalid authentication token")
	}

	// Store authentication result in context
	ctx.Variables["auth_result"] = result
	ctx.Variables["user_id"] = result.UserID
	ctx.Variables["user_roles"] = result.Roles

	return nil
}

func (am *AuthenticationMiddleware) ProcessResponse(resp *http.Response, ctx *MiddlewareContext) error {
	return nil // No response processing needed
}

func (am *AuthenticationMiddleware) Enabled() bool {
	return am.enabled
}

func (am *AuthenticationMiddleware) extractToken(req *http.Request) string {
	// Try header first
	authHeader := req.Header.Get(am.headerName)
	if authHeader != "" {
		// Extract token from "Bearer <token>" format
		parts := strings.Fields(authHeader)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Try cookie
	if cookie, err := req.Cookie(am.cookieName); err == nil {
		return cookie.Value
	}

	return ""
}

func (am *AuthenticationMiddleware) validateToken(token string, req *http.Request) (*AuthResult, error) {
	// Simplified validation - in practice would use actual validators
	return &AuthResult{
		Valid:  true,
		UserID: "user123",
		Roles:  []string{"user"},
		Claims: make(map[string]interface{}),
	}, nil
}

// GetStats returns pipeline statistics
func (p *Pipeline) GetStats() *PipelineStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := *p.stats
	return &stats
}

// GetMiddlewares returns all registered middlewares
func (p *Pipeline) GetMiddlewares() []Middleware {
	p.mu.RLock()
	defer p.mu.RUnlock()

	middlewares := make([]Middleware, len(p.middlewares))
	copy(middlewares, p.middlewares)
	return middlewares
}

// GetPlugins returns all registered plugins
func (p *Pipeline) GetPlugins() map[string]Plugin {
	p.mu.RLock()
	defer p.mu.RUnlock()

	plugins := make(map[string]Plugin)
	for name, plugin := range p.plugins {
		plugins[name] = plugin
	}
	return plugins
}

// Cleanup cleans up all plugins and resources
func (p *Pipeline) Cleanup() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errors []error

	// Cleanup plugins
	for name, plugin := range p.plugins {
		if err := plugin.Cleanup(); err != nil {
			errors = append(errors, fmt.Errorf("plugin %s cleanup failed: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cleanup errors: %v", errors)
	}

	fmt.Printf("Middleware: Pipeline cleanup complete\n")
	return nil
}