package circuitbreaker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"marchproxy-egress/internal/manager"
)

var (
	ErrCircuitBreakerOpen     = errors.New("circuit breaker is open")
	ErrCircuitBreakerTimeout  = errors.New("circuit breaker timeout")
	ErrTooManyRequests        = errors.New("too many requests")
	ErrServiceUnavailable     = errors.New("service unavailable")
)

type State int32

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF_OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

type Config struct {
	Name                    string
	MaxRequests             uint32
	Interval                time.Duration
	Timeout                 time.Duration
	ReadyToTrip             ReadyToTripFunc
	OnStateChange          StateChangeFunc
	IsSuccessful           IsSuccessfulFunc
	ShouldTrip             ShouldTripFunc
	FallbackFunc           FallbackFunc
	MaxConcurrentRequests   uint32
	RequestVolumeThreshold  uint32
	SleepWindow            time.Duration
	ErrorPercentThreshold   float64
}

type ReadyToTripFunc func(counts Counts) bool
type StateChangeFunc func(name string, from State, to State)
type IsSuccessfulFunc func(err error) bool
type ShouldTripFunc func(counts Counts) bool
type FallbackFunc func(ctx context.Context, err error) (interface{}, error)

type Counts struct {
	Requests             uint32
	TotalSuccesses       uint32
	TotalFailures        uint32
	ConsecutiveSuccesses uint32
	ConsecutiveFailures  uint32
}

func (c *Counts) onRequest() {
	atomic.AddUint32(&c.Requests, 1)
}

func (c *Counts) onSuccess() {
	atomic.AddUint32(&c.TotalSuccesses, 1)
	atomic.AddUint32(&c.ConsecutiveSuccesses, 1)
	atomic.StoreUint32(&c.ConsecutiveFailures, 0)
}

func (c *Counts) onFailure() {
	atomic.AddUint32(&c.TotalFailures, 1)
	atomic.AddUint32(&c.ConsecutiveFailures, 1)
	atomic.StoreUint32(&c.ConsecutiveSuccesses, 0)
}

func (c *Counts) clear() {
	atomic.StoreUint32(&c.Requests, 0)
	atomic.StoreUint32(&c.TotalSuccesses, 0)
	atomic.StoreUint32(&c.TotalFailures, 0)
	atomic.StoreUint32(&c.ConsecutiveSuccesses, 0)
	atomic.StoreUint32(&c.ConsecutiveFailures, 0)
}

func (c *Counts) ErrorRate() float64 {
	requests := atomic.LoadUint32(&c.Requests)
	if requests == 0 {
		return 0.0
	}
	failures := atomic.LoadUint32(&c.TotalFailures)
	return float64(failures) / float64(requests) * 100
}

type CircuitBreaker struct {
	name          string
	maxRequests   uint32
	interval      time.Duration
	timeout       time.Duration
	readyToTrip   ReadyToTripFunc
	isSuccessful  IsSuccessfulFunc
	onStateChange StateChangeFunc
	fallbackFunc  FallbackFunc

	mutex      sync.RWMutex
	state      State
	generation uint64
	counts     Counts
	expiry     time.Time

	maxConcurrentRequests  uint32
	currentRequests       int64
	requestVolumeThreshold uint32
	sleepWindow           time.Duration
	errorPercentThreshold  float64

	stats Statistics
}

type Statistics struct {
	TotalRequests        uint64
	TotalSuccesses      uint64
	TotalFailures       uint64
	TotalTimeouts       uint64
	TotalFallbacks      uint64
	TotalRejections     uint64
	StateChanges        uint64
	LastStateChange     time.Time
	AverageResponseTime time.Duration
	
	responseTimes sync.Map
}

func NewCircuitBreaker(config Config) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:                   config.Name,
		maxRequests:           config.MaxRequests,
		interval:              config.Interval,
		timeout:               config.Timeout,
		readyToTrip:           config.ReadyToTrip,
		isSuccessful:          config.IsSuccessful,
		onStateChange:         config.OnStateChange,
		fallbackFunc:          config.FallbackFunc,
		maxConcurrentRequests: config.MaxConcurrentRequests,
		requestVolumeThreshold: config.RequestVolumeThreshold,
		sleepWindow:           config.SleepWindow,
		errorPercentThreshold: config.ErrorPercentThreshold,
		state:                 StateClosed,
		expiry:                time.Now().Add(config.Interval),
	}

	if cb.maxRequests == 0 {
		cb.maxRequests = 1
	}
	if cb.interval <= 0 {
		cb.interval = 60 * time.Second
	}
	if cb.timeout <= 0 {
		cb.timeout = 60 * time.Second
	}
	if cb.readyToTrip == nil {
		cb.readyToTrip = defaultReadyToTrip
	}
	if cb.isSuccessful == nil {
		cb.isSuccessful = defaultIsSuccessful
	}
	if cb.maxConcurrentRequests == 0 {
		cb.maxConcurrentRequests = 100
	}
	if cb.requestVolumeThreshold == 0 {
		cb.requestVolumeThreshold = 20
	}
	if cb.sleepWindow <= 0 {
		cb.sleepWindow = 5 * time.Second
	}
	if cb.errorPercentThreshold == 0 {
		cb.errorPercentThreshold = 50.0
	}

	return cb
}

func defaultReadyToTrip(counts Counts) bool {
	return counts.ConsecutiveFailures > 5
}

func defaultIsSuccessful(err error) bool {
	return err == nil
}

func (cb *CircuitBreaker) Name() string {
	return cb.name
}

func (cb *CircuitBreaker) State() State {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	now := time.Now()
	state, _ := cb.currentState(now)
	return state
}

func (cb *CircuitBreaker) Counts() Counts {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return cb.counts
}

func (cb *CircuitBreaker) Execute(req func() (interface{}, error)) (interface{}, error) {
	generation, err := cb.beforeRequest()
	if err != nil {
		if cb.fallbackFunc != nil {
			atomic.AddUint64(&cb.stats.TotalFallbacks, 1)
			return cb.fallbackFunc(context.Background(), err)
		}
		return nil, err
	}

	defer func() {
		atomic.AddInt64(&cb.currentRequests, -1)
	}()

	start := time.Now()
	result, err := req()
	duration := time.Since(start)

	cb.updateResponseTime(duration)
	cb.afterRequest(generation, cb.isSuccessful(err))

	return result, err
}

func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, req func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	generation, err := cb.beforeRequest()
	if err != nil {
		if cb.fallbackFunc != nil {
			atomic.AddUint64(&cb.stats.TotalFallbacks, 1)
			return cb.fallbackFunc(ctx, err)
		}
		return nil, err
	}

	defer func() {
		atomic.AddInt64(&cb.currentRequests, -1)
	}()

	done := make(chan struct{})
	var result interface{}
	var reqErr error

	go func() {
		defer close(done)
		start := time.Now()
		result, reqErr = req(ctx)
		duration := time.Since(start)
		cb.updateResponseTime(duration)
	}()

	select {
	case <-done:
		cb.afterRequest(generation, cb.isSuccessful(reqErr))
		return result, reqErr
	case <-ctx.Done():
		atomic.AddUint64(&cb.stats.TotalTimeouts, 1)
		cb.afterRequest(generation, false)
		return nil, ctx.Err()
	case <-time.After(cb.timeout):
		atomic.AddUint64(&cb.stats.TotalTimeouts, 1)
		cb.afterRequest(generation, false)
		return nil, ErrCircuitBreakerTimeout
	}
}

func (cb *CircuitBreaker) beforeRequest() (uint64, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)

	if state == StateOpen {
		atomic.AddUint64(&cb.stats.TotalRejections, 1)
		return generation, ErrCircuitBreakerOpen
	}

	if state == StateHalfOpen && cb.counts.Requests >= cb.maxRequests {
		atomic.AddUint64(&cb.stats.TotalRejections, 1)
		return generation, ErrTooManyRequests
	}

	if cb.maxConcurrentRequests > 0 {
		current := atomic.LoadInt64(&cb.currentRequests)
		if current >= int64(cb.maxConcurrentRequests) {
			atomic.AddUint64(&cb.stats.TotalRejections, 1)
			return generation, ErrTooManyRequests
		}
	}

	atomic.AddInt64(&cb.currentRequests, 1)
	cb.counts.onRequest()
	atomic.AddUint64(&cb.stats.TotalRequests, 1)

	return generation, nil
}

func (cb *CircuitBreaker) afterRequest(before uint64, success bool) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)
	if generation != before {
		return
	}

	if success {
		cb.onSuccess(state, now)
		atomic.AddUint64(&cb.stats.TotalSuccesses, 1)
	} else {
		cb.onFailure(state, now)
		atomic.AddUint64(&cb.stats.TotalFailures, 1)
	}
}

func (cb *CircuitBreaker) onSuccess(state State, now time.Time) {
	cb.counts.onSuccess()

	if state == StateHalfOpen {
		cb.setState(StateClosed, now)
	}
}

func (cb *CircuitBreaker) onFailure(state State, now time.Time) {
	cb.counts.onFailure()

	switch state {
	case StateClosed:
		if cb.readyToTrip(cb.counts) {
			cb.setState(StateOpen, now)
		}
	case StateHalfOpen:
		cb.setState(StateOpen, now)
	}
}

func (cb *CircuitBreaker) currentState(now time.Time) (State, uint64) {
	switch cb.state {
	case StateClosed:
		if !cb.expiry.IsZero() && cb.expiry.Before(now) {
			cb.toNewGeneration(now)
		}
	case StateOpen:
		if cb.expiry.Before(now) {
			cb.setState(StateHalfOpen, now)
		}
	}
	return cb.state, cb.generation
}

func (cb *CircuitBreaker) setState(state State, now time.Time) {
	if cb.state == state {
		return
	}

	prev := cb.state
	cb.state = state

	cb.toNewGeneration(now)

	if cb.onStateChange != nil {
		cb.onStateChange(cb.name, prev, state)
	}

	atomic.AddUint64(&cb.stats.StateChanges, 1)
	cb.stats.LastStateChange = now
}

func (cb *CircuitBreaker) toNewGeneration(now time.Time) {
	cb.generation++
	cb.counts.clear()

	var zero time.Time
	switch cb.state {
	case StateClosed:
		if cb.interval == 0 {
			cb.expiry = zero
		} else {
			cb.expiry = now.Add(cb.interval)
		}
	case StateOpen:
		cb.expiry = now.Add(cb.sleepWindow)
	default:
		cb.expiry = zero
	}
}

func (cb *CircuitBreaker) updateResponseTime(duration time.Duration) {
	cb.stats.responseTimes.Store(time.Now().UnixNano(), duration)
	
	var total time.Duration
	var count int64
	cb.stats.responseTimes.Range(func(key, value interface{}) bool {
		if d, ok := value.(time.Duration); ok {
			total += d
			count++
		}
		return true
	})
	
	if count > 0 {
		cb.stats.AverageResponseTime = total / time.Duration(count)
	}
	
	cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
	cb.stats.responseTimes.Range(func(key, value interface{}) bool {
		if timestamp, ok := key.(int64); ok && timestamp < cutoff {
			cb.stats.responseTimes.Delete(key)
		}
		return true
	})
}

func (cb *CircuitBreaker) Statistics() Statistics {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return cb.stats
}

func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.toNewGeneration(time.Now())
	cb.setState(StateClosed, time.Now())
}

type ServiceCircuitBreaker struct {
	breakers map[string]*CircuitBreaker
	mutex    sync.RWMutex
	config   Config
}

func NewServiceCircuitBreaker(config Config) *ServiceCircuitBreaker {
	return &ServiceCircuitBreaker{
		breakers: make(map[string]*CircuitBreaker),
		config:   config,
	}
}

func (scb *ServiceCircuitBreaker) GetBreaker(service *manager.Service) *CircuitBreaker {
	key := service.IPFQDN
	
	scb.mutex.RLock()
	breaker, exists := scb.breakers[key]
	scb.mutex.RUnlock()
	
	if exists {
		return breaker
	}
	
	scb.mutex.Lock()
	defer scb.mutex.Unlock()
	
	if breaker, exists := scb.breakers[key]; exists {
		return breaker
	}
	
	config := scb.config
	config.Name = key
	breaker = NewCircuitBreaker(config)
	scb.breakers[key] = breaker
	
	return breaker
}

func (scb *ServiceCircuitBreaker) ExecuteRequest(service *manager.Service, req func() (interface{}, error)) (interface{}, error) {
	breaker := scb.GetBreaker(service)
	return breaker.Execute(req)
}

func (scb *ServiceCircuitBreaker) ExecuteRequestWithContext(ctx context.Context, service *manager.Service, req func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	breaker := scb.GetBreaker(service)
	return breaker.ExecuteWithContext(ctx, req)
}

func (scb *ServiceCircuitBreaker) GetAllBreakers() map[string]*CircuitBreaker {
	scb.mutex.RLock()
	defer scb.mutex.RUnlock()
	
	result := make(map[string]*CircuitBreaker)
	for key, breaker := range scb.breakers {
		result[key] = breaker
	}
	return result
}

func (scb *ServiceCircuitBreaker) RemoveBreaker(service *manager.Service) {
	key := service.IPFQDN
	
	scb.mutex.Lock()
	defer scb.mutex.Unlock()
	
	delete(scb.breakers, key)
}

func (scb *ServiceCircuitBreaker) ResetAll() {
	scb.mutex.Lock()
	defer scb.mutex.Unlock()
	
	for _, breaker := range scb.breakers {
		breaker.Reset()
	}
}

func (scb *ServiceCircuitBreaker) GetStatistics() map[string]Statistics {
	scb.mutex.RLock()
	defer scb.mutex.RUnlock()
	
	result := make(map[string]Statistics)
	for key, breaker := range scb.breakers {
		result[key] = breaker.Statistics()
	}
	return result
}

type BreakerMetrics struct {
	Name                 string        `json:"name"`
	State                string        `json:"state"`
	TotalRequests        uint64        `json:"total_requests"`
	TotalSuccesses       uint64        `json:"total_successes"`
	TotalFailures        uint64        `json:"total_failures"`
	TotalTimeouts        uint64        `json:"total_timeouts"`
	TotalFallbacks       uint64        `json:"total_fallbacks"`
	TotalRejections      uint64        `json:"total_rejections"`
	StateChanges         uint64        `json:"state_changes"`
	LastStateChange      time.Time     `json:"last_state_change"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
	ErrorRate           float64       `json:"error_rate"`
	CurrentRequests     int64         `json:"current_requests"`
}

func (cb *CircuitBreaker) GetMetrics() BreakerMetrics {
	stats := cb.Statistics()
	counts := cb.Counts()
	
	return BreakerMetrics{
		Name:                 cb.name,
		State:                cb.State().String(),
		TotalRequests:        stats.TotalRequests,
		TotalSuccesses:       stats.TotalSuccesses,
		TotalFailures:        stats.TotalFailures,
		TotalTimeouts:        stats.TotalTimeouts,
		TotalFallbacks:       stats.TotalFallbacks,
		TotalRejections:      stats.TotalRejections,
		StateChanges:         stats.StateChanges,
		LastStateChange:      stats.LastStateChange,
		AverageResponseTime:  stats.AverageResponseTime,
		ErrorRate:           counts.ErrorRate(),
		CurrentRequests:     atomic.LoadInt64(&cb.currentRequests),
	}
}