package circuitbreaker

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"marchproxy-egress/internal/manager"
	"marchproxy-egress/internal/middleware"
)

type CircuitBreakerMiddleware struct {
	serviceBreaker *ServiceCircuitBreaker
	config         Config
	enabled        bool
}

func NewCircuitBreakerMiddleware(config Config) *CircuitBreakerMiddleware {
	return &CircuitBreakerMiddleware{
		serviceBreaker: NewServiceCircuitBreaker(config),
		config:        config,
		enabled:       true,
	}
}

func (cbm *CircuitBreakerMiddleware) Name() string {
	return "circuit-breaker"
}

func (cbm *CircuitBreakerMiddleware) Priority() int {
	return 200
}

func (cbm *CircuitBreakerMiddleware) ProcessRequest(req *http.Request, ctx *middleware.MiddlewareContext) error {
	if !cbm.enabled {
		return nil
	}

	if ctx.Service == nil {
		return fmt.Errorf("no service available for circuit breaker")
	}

	breaker := cbm.serviceBreaker.GetBreaker(ctx.Service)
	
	ctx.SetData("circuit_breaker", breaker)
	ctx.SetData("circuit_breaker_start_time", time.Now())
	
	state := breaker.State()
	if state == StateOpen {
		ctx.SetData("circuit_breaker_rejected", true)
		return &CircuitBreakerError{
			Service: ctx.Service,
			State:   state,
			Err:     ErrCircuitBreakerOpen,
		}
	}

	return nil
}

func (cbm *CircuitBreakerMiddleware) ProcessResponse(resp *http.Response, ctx *middleware.MiddlewareContext) error {
	if !cbm.enabled {
		return nil
	}

	breaker, ok := ctx.GetData("circuit_breaker").(*CircuitBreaker)
	if !ok {
		return nil
	}

	startTime, ok := ctx.GetData("circuit_breaker_start_time").(time.Time)
	if ok {
		duration := time.Since(startTime)
		breaker.updateResponseTime(duration)
	}

	isSuccess := resp != nil && resp.StatusCode < 500
	if !isSuccess && resp != nil {
		ctx.SetData("circuit_breaker_failure", true)
		ctx.SetData("circuit_breaker_status_code", resp.StatusCode)
	}

	return nil
}

func (cbm *CircuitBreakerMiddleware) ProcessError(err error, ctx *middleware.MiddlewareContext) error {
	if !cbm.enabled {
		return err
	}

	_, ok := ctx.GetData("circuit_breaker").(*CircuitBreaker)
	if !ok {
		return err
	}

	ctx.SetData("circuit_breaker_error", err)
	
	if cbm.config.FallbackFunc != nil && !ctx.HasData("circuit_breaker_rejected") {
		fallbackResult, fallbackErr := cbm.config.FallbackFunc(context.Background(), err)
		if fallbackErr == nil {
			ctx.SetData("circuit_breaker_fallback_result", fallbackResult)
			ctx.SetData("circuit_breaker_fallback_used", true)
			return nil
		}
	}

	return err
}

func (cbm *CircuitBreakerMiddleware) Enabled() bool {
	return cbm.enabled
}

func (cbm *CircuitBreakerMiddleware) Enable() {
	cbm.enabled = true
}

func (cbm *CircuitBreakerMiddleware) Disable() {
	cbm.enabled = false
}

func (cbm *CircuitBreakerMiddleware) GetServiceBreaker() *ServiceCircuitBreaker {
	return cbm.serviceBreaker
}

func (cbm *CircuitBreakerMiddleware) GetMetrics() map[string]BreakerMetrics {
	breakers := cbm.serviceBreaker.GetAllBreakers()
	metrics := make(map[string]BreakerMetrics)
	
	for name, breaker := range breakers {
		metrics[name] = breaker.GetMetrics()
	}
	
	return metrics
}

type CircuitBreakerError struct {
	Service *manager.Service
	State   State
	Err     error
}

func (cbe *CircuitBreakerError) Error() string {
	return fmt.Sprintf("circuit breaker for service %s:%d is %s: %v", 
		cbe.Service.Host, cbe.Service.Port, cbe.State, cbe.Err)
}

func (cbe *CircuitBreakerError) Unwrap() error {
	return cbe.Err
}

type CircuitBreakerProxy struct {
	serviceBreaker *ServiceCircuitBreaker
	client         *http.Client
	config         Config
}

func NewCircuitBreakerProxy(config Config) *CircuitBreakerProxy {
	return &CircuitBreakerProxy{
		serviceBreaker: NewServiceCircuitBreaker(config),
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
	}
}

func (cbp *CircuitBreakerProxy) ExecuteRequest(service *manager.Service, req *http.Request) (*http.Response, error) {
	return cbp.serviceBreaker.ExecuteRequestWithContext(req.Context(), service, func(ctx context.Context) (interface{}, error) {
		reqCopy := req.Clone(ctx)
		reqCopy.URL.Scheme = service.Scheme
		reqCopy.URL.Host = fmt.Sprintf("%s:%d", service.Host, service.Port)
		reqCopy.RequestURI = ""
		
		return cbp.client.Do(reqCopy)
	})
}

func (cbp *CircuitBreakerProxy) GetBreaker(service *manager.Service) *CircuitBreaker {
	return cbp.serviceBreaker.GetBreaker(service)
}

func (cbp *CircuitBreakerProxy) GetAllBreakers() map[string]*CircuitBreaker {
	return cbp.serviceBreaker.GetAllBreakers()
}

func (cbp *CircuitBreakerProxy) ResetAll() {
	cbp.serviceBreaker.ResetAll()
}

func DefaultCircuitBreakerConfig() Config {
	return Config{
		Name:                   "default",
		MaxRequests:           10,
		Interval:              60 * time.Second,
		Timeout:               30 * time.Second,
		ReadyToTrip:           defaultReadyToTrip,
		IsSuccessful:          defaultIsSuccessful,
		MaxConcurrentRequests: 100,
		RequestVolumeThreshold: 20,
		SleepWindow:           5 * time.Second,
		ErrorPercentThreshold: 50.0,
		OnStateChange: func(name string, from State, to State) {
			fmt.Printf("Circuit breaker %s changed from %s to %s\n", name, from, to)
		},
		FallbackFunc: func(ctx context.Context, err error) (interface{}, error) {
			resp := &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     make(http.Header),
				Body:       http.NoBody,
			}
			resp.Header.Set("Content-Type", "application/json")
			resp.Header.Set("X-Circuit-Breaker", "fallback")
			return resp, nil
		},
	}
}

func AdvancedCircuitBreakerConfig() Config {
	config := DefaultCircuitBreakerConfig()
	config.MaxRequests = 5
	config.Interval = 30 * time.Second
	config.Timeout = 10 * time.Second
	config.MaxConcurrentRequests = 50
	config.RequestVolumeThreshold = 10
	config.SleepWindow = 10 * time.Second
	config.ErrorPercentThreshold = 30.0
	
	config.ReadyToTrip = func(counts Counts) bool {
		return counts.Requests >= 10 && counts.ErrorRate() >= 30.0
	}
	
	config.ShouldTrip = func(counts Counts) bool {
		return counts.ConsecutiveFailures >= 3 || 
			   (counts.Requests >= 10 && counts.ErrorRate() >= 50.0)
	}
	
	return config
}

func CustomCircuitBreakerConfig(
	maxRequests uint32,
	interval time.Duration,
	timeout time.Duration,
	errorThreshold float64,
	sleepWindow time.Duration,
) Config {
	config := DefaultCircuitBreakerConfig()
	config.MaxRequests = maxRequests
	config.Interval = interval
	config.Timeout = timeout
	config.ErrorPercentThreshold = errorThreshold
	config.SleepWindow = sleepWindow
	
	config.ReadyToTrip = func(counts Counts) bool {
		return counts.Requests >= 5 && counts.ErrorRate() >= errorThreshold
	}
	
	return config
}