package ratelimit

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrQuotaExceeded     = errors.New("quota exceeded")
	ErrTooManyRequests   = errors.New("too many requests")
	ErrBlocked           = errors.New("client blocked")
)

type RateLimiter struct {
	config        RateLimiterConfig
	limiters      map[string]*ClientLimiter
	globalLimiter *rate.Limiter
	ipBlocklist   *IPBlocklist
	ddosDetector  *DDoSDetector
	quotaManager  *QuotaManager
	metrics       *RateLimitMetrics
	mutex         sync.RWMutex
}

type RateLimiterConfig struct {
	GlobalLimit          rate.Limit
	GlobalBurst          int
	PerIPLimit           rate.Limit
	PerIPBurst           int
	PerUserLimit         rate.Limit
	PerUserBurst         int
	PerAPIKeyLimit       rate.Limit
	PerAPIKeyBurst       int
	WindowSize           time.Duration
	CleanupInterval      time.Duration
	EnableDDoSProtection bool
	DDoSThreshold        int
	DDoSWindow           time.Duration
	EnableQuotas         bool
	QuotaPeriod          time.Duration
	BlocklistEnabled     bool
	BlockDuration        time.Duration
	CustomLimits         map[string]LimitConfig
	RateLimitHeaders     bool
	BackoffStrategy      BackoffStrategy
}

type LimitConfig struct {
	Limit  rate.Limit
	Burst  int
	Quota  int64
	Window time.Duration
}

type ClientLimiter struct {
	limiter       *rate.Limiter
	lastAccess    time.Time
	requestCount  int64
	violations    int
	blocked       bool
	blockedUntil  time.Time
	customLimits  map[string]*rate.Limiter
}

type IPBlocklist struct {
	blocked       map[string]BlockedEntry
	whitelist     map[string]bool
	mutex         sync.RWMutex
	blockDuration time.Duration
}

type BlockedEntry struct {
	IP           string
	Reason       string
	BlockedAt    time.Time
	BlockedUntil time.Time
	Permanent    bool
}

type DDoSDetector struct {
	requests      map[string]*RequestPattern
	threshold     int
	window        time.Duration
	mutex         sync.RWMutex
	alerts        []DDoSAlert
	mitigations   []MitigationRule
}

type RequestPattern struct {
	IP            string
	Count         int
	FirstRequest  time.Time
	LastRequest   time.Time
	Endpoints     map[string]int
	UserAgents    map[string]int
	Suspicious    bool
}

type DDoSAlert struct {
	Timestamp    time.Time
	IP           string
	RequestCount int
	Pattern      string
	Severity     AlertSeverity
	Mitigated    bool
}

type AlertSeverity int

const (
	SeverityLow AlertSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type MitigationRule struct {
	Name        string
	Condition   MitigationCondition
	Action      MitigationAction
	Priority    int
	Enabled     bool
}

type MitigationCondition func(pattern *RequestPattern) bool
type MitigationAction func(ip string) error

type QuotaManager struct {
	quotas map[string]*Quota
	mutex  sync.RWMutex
	period time.Duration
}

type Quota struct {
	Limit        int64
	Used         int64
	ResetAt      time.Time
	WarningLevel float64
}

type RateLimitMetrics struct {
	TotalRequests        uint64
	AllowedRequests      uint64
	BlockedRequests      uint64
	QuotaExceeded        uint64
	DDoSAttacksDetected  uint64
	DDoSAttacksMitigated uint64
	UniqueClients        uint64
	BlockedIPs           uint64
	AverageRequestRate   float64
	PeakRequestRate      float64
	mutex                sync.RWMutex
}

type BackoffStrategy interface {
	CalculateDelay(violations int) time.Duration
	ShouldBlock(violations int) bool
}

type ExponentialBackoff struct {
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	Multiplier    float64
	BlockThreshold int
}

func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		config:   config,
		limiters: make(map[string]*ClientLimiter),
		metrics:  &RateLimitMetrics{},
	}

	if config.GlobalLimit > 0 {
		rl.globalLimiter = rate.NewLimiter(config.GlobalLimit, config.GlobalBurst)
	}

	if config.BlocklistEnabled {
		rl.ipBlocklist = NewIPBlocklist(config.BlockDuration)
	}

	if config.EnableDDoSProtection {
		rl.ddosDetector = NewDDoSDetector(config.DDoSThreshold, config.DDoSWindow)
		rl.setupDefaultMitigations()
	}

	if config.EnableQuotas {
		rl.quotaManager = NewQuotaManager(config.QuotaPeriod)
	}

	if config.BackoffStrategy == nil {
		rl.config.BackoffStrategy = &ExponentialBackoff{
			BaseDelay:      1 * time.Second,
			MaxDelay:       1 * time.Minute,
			Multiplier:     2.0,
			BlockThreshold: 10,
		}
	}

	go rl.startCleanup()

	return rl
}

func (rl *RateLimiter) Allow(r *http.Request) error {
	rl.metrics.recordRequest()

	clientID := rl.extractClientID(r)

	if rl.ipBlocklist != nil {
		ip := rl.extractIP(r)
		if rl.ipBlocklist.IsBlocked(ip) {
			rl.metrics.recordBlocked()
			return ErrBlocked
		}
	}

	if rl.globalLimiter != nil {
		if !rl.globalLimiter.Allow() {
			rl.metrics.recordBlocked()
			rl.recordViolation(clientID)
			return ErrRateLimitExceeded
		}
	}

	limiter := rl.getOrCreateLimiter(clientID)
	
	if limiter.blocked && time.Now().Before(limiter.blockedUntil) {
		rl.metrics.recordBlocked()
		return ErrBlocked
	}

	endpoint := r.URL.Path
	if customLimiter := rl.getCustomLimiter(limiter, endpoint); customLimiter != nil {
		if !customLimiter.Allow() {
			rl.metrics.recordBlocked()
			rl.recordViolation(clientID)
			return ErrRateLimitExceeded
		}
	} else {
		if !limiter.limiter.Allow() {
			rl.metrics.recordBlocked()
			rl.recordViolation(clientID)
			return ErrRateLimitExceeded
		}
	}

	if rl.config.EnableQuotas {
		if err := rl.checkQuota(clientID); err != nil {
			rl.metrics.recordQuotaExceeded()
			return err
		}
	}

	if rl.config.EnableDDoSProtection {
		ip := rl.extractIP(r)
		if rl.ddosDetector.IsSuspicious(ip, r) {
			rl.metrics.recordDDoSDetected()
			if rl.ddosDetector.ShouldMitigate(ip) {
				rl.ipBlocklist.Block(ip, "DDoS attack detected", 1*time.Hour)
				rl.metrics.recordDDoSMitigated()
				return ErrBlocked
			}
		}
	}

	limiter.lastAccess = time.Now()
	limiter.requestCount++
	
	rl.metrics.recordAllowed()

	return nil
}

func (rl *RateLimiter) extractClientID(r *http.Request) string {
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "apikey:" + apiKey
	}

	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return "user:" + userID
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.Split(auth, " ")
		if len(parts) == 2 {
			return "auth:" + parts[1][:min(16, len(parts[1]))]
		}
	}

	return "ip:" + rl.extractIP(r)
}

func (rl *RateLimiter) extractIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (rl *RateLimiter) getOrCreateLimiter(clientID string) *ClientLimiter {
	rl.mutex.RLock()
	limiter, exists := rl.limiters[clientID]
	rl.mutex.RUnlock()

	if exists {
		return limiter
	}

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if limiter, exists := rl.limiters[clientID]; exists {
		return limiter
	}

	var limit rate.Limit
	var burst int

	if strings.HasPrefix(clientID, "apikey:") && rl.config.PerAPIKeyLimit > 0 {
		limit = rl.config.PerAPIKeyLimit
		burst = rl.config.PerAPIKeyBurst
	} else if strings.HasPrefix(clientID, "user:") && rl.config.PerUserLimit > 0 {
		limit = rl.config.PerUserLimit
		burst = rl.config.PerUserBurst
	} else {
		limit = rl.config.PerIPLimit
		burst = rl.config.PerIPBurst
	}

	limiter = &ClientLimiter{
		limiter:      rate.NewLimiter(limit, burst),
		lastAccess:   time.Now(),
		customLimits: make(map[string]*rate.Limiter),
	}

	rl.limiters[clientID] = limiter
	rl.metrics.incrementUniqueClients()

	return limiter
}

func (rl *RateLimiter) getCustomLimiter(limiter *ClientLimiter, endpoint string) *rate.Limiter {
	if config, exists := rl.config.CustomLimits[endpoint]; exists {
		if customLimiter, exists := limiter.customLimits[endpoint]; exists {
			return customLimiter
		}
		
		customLimiter := rate.NewLimiter(config.Limit, config.Burst)
		limiter.customLimits[endpoint] = customLimiter
		return customLimiter
	}
	return nil
}

func (rl *RateLimiter) recordViolation(clientID string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if limiter, exists := rl.limiters[clientID]; exists {
		limiter.violations++
		
		if rl.config.BackoffStrategy.ShouldBlock(limiter.violations) {
			delay := rl.config.BackoffStrategy.CalculateDelay(limiter.violations)
			limiter.blocked = true
			limiter.blockedUntil = time.Now().Add(delay)
			
			if rl.ipBlocklist != nil && strings.HasPrefix(clientID, "ip:") {
				ip := strings.TrimPrefix(clientID, "ip:")
				rl.ipBlocklist.Block(ip, "Rate limit violations", delay)
			}
		}
	}
}

func (rl *RateLimiter) checkQuota(clientID string) error {
	if rl.quotaManager == nil {
		return nil
	}

	quota := rl.quotaManager.GetQuota(clientID)
	if quota == nil {
		quota = rl.quotaManager.CreateQuota(clientID, 10000)
	}

	if !quota.HasRemaining() {
		return ErrQuotaExceeded
	}

	quota.Use(1)
	return nil
}

func (rl *RateLimiter) GetRateLimitHeaders(clientID string) map[string]string {
	headers := make(map[string]string)
	
	if !rl.config.RateLimitHeaders {
		return headers
	}

	rl.mutex.RLock()
	limiter, exists := rl.limiters[clientID]
	rl.mutex.RUnlock()

	if !exists {
		return headers
	}

	limit := limiter.limiter.Limit()
	burst := limiter.limiter.Burst()
	
	headers["X-RateLimit-Limit"] = strconv.Itoa(int(limit))
	headers["X-RateLimit-Burst"] = strconv.Itoa(burst)
	headers["X-RateLimit-Remaining"] = strconv.Itoa(burst - int(limiter.requestCount))
	
	if limiter.blocked {
		headers["X-RateLimit-Reset"] = strconv.FormatInt(limiter.blockedUntil.Unix(), 10)
		headers["Retry-After"] = strconv.Itoa(int(time.Until(limiter.blockedUntil).Seconds()))
	}

	return headers
}

func (rl *RateLimiter) startCleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	for id, limiter := range rl.limiters {
		if now.Sub(limiter.lastAccess) > rl.config.WindowSize {
			delete(rl.limiters, id)
		}
	}
}

func (rl *RateLimiter) setupDefaultMitigations() {
	rl.ddosDetector.AddMitigation(MitigationRule{
		Name:     "high-rate-block",
		Priority: 1,
		Enabled:  true,
		Condition: func(pattern *RequestPattern) bool {
			return pattern.Count > rl.config.DDoSThreshold*2
		},
		Action: func(ip string) error {
			rl.ipBlocklist.Block(ip, "DDoS: High request rate", 24*time.Hour)
			return nil
		},
	})

	rl.ddosDetector.AddMitigation(MitigationRule{
		Name:     "suspicious-pattern-throttle",
		Priority: 2,
		Enabled:  true,
		Condition: func(pattern *RequestPattern) bool {
			return pattern.Suspicious && pattern.Count > rl.config.DDoSThreshold
		},
		Action: func(ip string) error {
			rl.ipBlocklist.Block(ip, "DDoS: Suspicious pattern", 1*time.Hour)
			return nil
		},
	})
}

func NewIPBlocklist(blockDuration time.Duration) *IPBlocklist {
	bl := &IPBlocklist{
		blocked:       make(map[string]BlockedEntry),
		whitelist:     make(map[string]bool),
		blockDuration: blockDuration,
	}
	
	go bl.startCleanup()
	return bl
}

func (bl *IPBlocklist) Block(ip string, reason string, duration time.Duration) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()

	if bl.whitelist[ip] {
		return
	}

	bl.blocked[ip] = BlockedEntry{
		IP:           ip,
		Reason:       reason,
		BlockedAt:    time.Now(),
		BlockedUntil: time.Now().Add(duration),
		Permanent:    false,
	}
}

func (bl *IPBlocklist) IsBlocked(ip string) bool {
	bl.mutex.RLock()
	defer bl.mutex.RUnlock()

	if bl.whitelist[ip] {
		return false
	}

	entry, exists := bl.blocked[ip]
	if !exists {
		return false
	}

	if !entry.Permanent && time.Now().After(entry.BlockedUntil) {
		return false
	}

	return true
}

func (bl *IPBlocklist) Whitelist(ip string) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()
	
	bl.whitelist[ip] = true
	delete(bl.blocked, ip)
}

func (bl *IPBlocklist) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bl.cleanup()
	}
}

func (bl *IPBlocklist) cleanup() {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()

	now := time.Now()
	for ip, entry := range bl.blocked {
		if !entry.Permanent && now.After(entry.BlockedUntil) {
			delete(bl.blocked, ip)
		}
	}
}

func NewDDoSDetector(threshold int, window time.Duration) *DDoSDetector {
	dd := &DDoSDetector{
		requests:    make(map[string]*RequestPattern),
		threshold:   threshold,
		window:      window,
		alerts:      make([]DDoSAlert, 0),
		mitigations: make([]MitigationRule, 0),
	}
	
	go dd.startCleanup()
	return dd
}

func (dd *DDoSDetector) IsSuspicious(ip string, r *http.Request) bool {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	pattern, exists := dd.requests[ip]
	if !exists {
		pattern = &RequestPattern{
			IP:           ip,
			Count:        1,
			FirstRequest: time.Now(),
			LastRequest:  time.Now(),
			Endpoints:    make(map[string]int),
			UserAgents:   make(map[string]int),
		}
		dd.requests[ip] = pattern
	} else {
		pattern.Count++
		pattern.LastRequest = time.Now()
	}

	pattern.Endpoints[r.URL.Path]++
	pattern.UserAgents[r.UserAgent()]++

	if time.Since(pattern.FirstRequest) < dd.window {
		rate := float64(pattern.Count) / time.Since(pattern.FirstRequest).Seconds()
		if rate > float64(dd.threshold) {
			pattern.Suspicious = true
			dd.createAlert(pattern)
			return true
		}
	}

	if len(pattern.Endpoints) > 100 {
		pattern.Suspicious = true
		return true
	}

	if len(pattern.UserAgents) > 10 {
		pattern.Suspicious = true
		return true
	}

	return false
}

func (dd *DDoSDetector) ShouldMitigate(ip string) bool {
	dd.mutex.RLock()
	defer dd.mutex.RUnlock()

	pattern, exists := dd.requests[ip]
	if !exists {
		return false
	}

	for _, rule := range dd.mitigations {
		if rule.Enabled && rule.Condition(pattern) {
			rule.Action(ip)
			return true
		}
	}

	return false
}

func (dd *DDoSDetector) AddMitigation(rule MitigationRule) {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()
	dd.mitigations = append(dd.mitigations, rule)
}

func (dd *DDoSDetector) createAlert(pattern *RequestPattern) {
	severity := SeverityLow
	if pattern.Count > dd.threshold*5 {
		severity = SeverityCritical
	} else if pattern.Count > dd.threshold*3 {
		severity = SeverityHigh
	} else if pattern.Count > dd.threshold*2 {
		severity = SeverityMedium
	}

	alert := DDoSAlert{
		Timestamp:    time.Now(),
		IP:           pattern.IP,
		RequestCount: pattern.Count,
		Pattern:      "high-rate",
		Severity:     severity,
		Mitigated:    false,
	}

	dd.alerts = append(dd.alerts, alert)
}

func (dd *DDoSDetector) startCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		dd.cleanup()
	}
}

func (dd *DDoSDetector) cleanup() {
	dd.mutex.Lock()
	defer dd.mutex.Unlock()

	now := time.Now()
	for ip, pattern := range dd.requests {
		if now.Sub(pattern.LastRequest) > dd.window {
			delete(dd.requests, ip)
		}
	}

	if len(dd.alerts) > 1000 {
		dd.alerts = dd.alerts[len(dd.alerts)-1000:]
	}
}

func NewQuotaManager(period time.Duration) *QuotaManager {
	return &QuotaManager{
		quotas: make(map[string]*Quota),
		period: period,
	}
}

func (qm *QuotaManager) CreateQuota(clientID string, limit int64) *Quota {
	qm.mutex.Lock()
	defer qm.mutex.Unlock()

	quota := &Quota{
		Limit:        limit,
		Used:         0,
		ResetAt:      time.Now().Add(qm.period),
		WarningLevel: 0.8,
	}

	qm.quotas[clientID] = quota
	return quota
}

func (qm *QuotaManager) GetQuota(clientID string) *Quota {
	qm.mutex.RLock()
	defer qm.mutex.RUnlock()

	quota, exists := qm.quotas[clientID]
	if !exists {
		return nil
	}

	if time.Now().After(quota.ResetAt) {
		quota.Used = 0
		quota.ResetAt = time.Now().Add(qm.period)
	}

	return quota
}

func (q *Quota) HasRemaining() bool {
	return q.Used < q.Limit
}

func (q *Quota) Use(amount int64) {
	q.Used += amount
}

func (q *Quota) GetRemaining() int64 {
	return q.Limit - q.Used
}

func (q *Quota) IsWarning() bool {
	return float64(q.Used) >= float64(q.Limit)*q.WarningLevel
}

func (eb *ExponentialBackoff) CalculateDelay(violations int) time.Duration {
	delay := eb.BaseDelay
	for i := 1; i < violations; i++ {
		delay = time.Duration(float64(delay) * eb.Multiplier)
		if delay > eb.MaxDelay {
			return eb.MaxDelay
		}
	}
	return delay
}

func (eb *ExponentialBackoff) ShouldBlock(violations int) bool {
	return violations >= eb.BlockThreshold
}

func (rm *RateLimitMetrics) recordRequest() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.TotalRequests++
}

func (rm *RateLimitMetrics) recordAllowed() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.AllowedRequests++
}

func (rm *RateLimitMetrics) recordBlocked() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.BlockedRequests++
}

func (rm *RateLimitMetrics) recordQuotaExceeded() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.QuotaExceeded++
}

func (rm *RateLimitMetrics) recordDDoSDetected() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.DDoSAttacksDetected++
}

func (rm *RateLimitMetrics) recordDDoSMitigated() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.DDoSAttacksMitigated++
}

func (rm *RateLimitMetrics) incrementUniqueClients() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.UniqueClients++
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}