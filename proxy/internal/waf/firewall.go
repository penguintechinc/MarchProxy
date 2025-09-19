package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrRequestBlocked    = errors.New("request blocked by WAF")
	ErrSQLInjection      = errors.New("SQL injection detected")
	ErrXSSAttack         = errors.New("XSS attack detected")
	ErrPathTraversal     = errors.New("path traversal detected")
	ErrCommandInjection  = errors.New("command injection detected")
	ErrSuspiciousPayload = errors.New("suspicious payload detected")
)

type WAF struct {
	config          WAFConfig
	rules           *RuleEngine
	anomalyDetector *AnomalyDetector
	geoBlocker      *GeoBlocker
	ipReputation    *IPReputation
	requestAnalyzer *RequestAnalyzer
	responseFilter  *ResponseFilter
	metrics         *WAFMetrics
	logger          *SecurityLogger
	mutex           sync.RWMutex
}

type WAFConfig struct {
	Enabled                bool
	Mode                   WAFMode
	RuleSetVersion         string
	CustomRules            []Rule
	AnomalyThreshold       int
	BlockingScore          int
	ParanoiaLevel          int
	MaxRequestBodySize     int64
	MaxFileUploadSize      int64
	AllowedMethods         []string
	AllowedContentTypes    []string
	BlockedCountries       []string
	AllowedCountries       []string
	EnableGeoBlocking      bool
	EnableIPReputation     bool
	EnableAnomalyDetection bool
	EnableRequestLogging   bool
	EnableResponseFiltering bool
	SensitiveDataMasking   bool
	RateLimitPerIP         int
	BlockDuration          time.Duration
}

type WAFMode string

const (
	ModeDetection WAFMode = "detection"
	ModePrevention WAFMode = "prevention"
	ModeBypass    WAFMode = "bypass"
)

type Rule struct {
	ID          string
	Name        string
	Description string
	Category    RuleCategory
	Severity    RuleSeverity
	Pattern     *regexp.Regexp
	Action      RuleAction
	Score       int
	Tags        []string
	Enabled     bool
}

type RuleCategory string

const (
	CategorySQLInjection     RuleCategory = "sql_injection"
	CategoryXSS              RuleCategory = "xss"
	CategoryPathTraversal    RuleCategory = "path_traversal"
	CategoryCommandInjection RuleCategory = "command_injection"
	CategoryXMLInjection     RuleCategory = "xml_injection"
	CategoryLDAPInjection    RuleCategory = "ldap_injection"
	CategoryProtocolAttack   RuleCategory = "protocol_attack"
	CategoryApplicationAttack RuleCategory = "application_attack"
)

type RuleSeverity int

const (
	SeverityCritical RuleSeverity = 5
	SeverityHigh     RuleSeverity = 4
	SeverityMedium   RuleSeverity = 3
	SeverityLow      RuleSeverity = 2
	SeverityInfo     RuleSeverity = 1
)

type RuleAction string

const (
	ActionBlock    RuleAction = "block"
	ActionAllow    RuleAction = "allow"
	ActionLog      RuleAction = "log"
	ActionRedirect RuleAction = "redirect"
	ActionChallenge RuleAction = "challenge"
)

type RuleEngine struct {
	rules       map[string]*Rule
	rulesByCategory map[RuleCategory][]*Rule
	compiledPatterns map[string]*regexp.Regexp
	mutex       sync.RWMutex
}

type AnomalyDetector struct {
	baseline    *TrafficBaseline
	threshold   int
	window      time.Duration
	patterns    map[string]*AnomalyPattern
	mutex       sync.RWMutex
}

type TrafficBaseline struct {
	RequestRate     float64
	AverageSize     int64
	CommonPaths     map[string]int
	CommonHeaders   map[string]int
	CommonUserAgents map[string]int
}

type AnomalyPattern struct {
	Pattern     string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	Suspicious  bool
}

type GeoBlocker struct {
	allowedCountries map[string]bool
	blockedCountries map[string]bool
	geoDatabase      GeoDatabase
	mutex            sync.RWMutex
}

type GeoDatabase interface {
	GetCountry(ip string) (string, error)
	GetCity(ip string) (string, error)
	GetASN(ip string) (string, error)
}

type IPReputation struct {
	reputationDB map[string]*IPReputationData
	providers    []ReputationProvider
	cache        *ReputationCache
	mutex        sync.RWMutex
}

type IPReputationData struct {
	IP         string
	Score      int
	Categories []string
	Threats    []string
	LastUpdate time.Time
	Blocked    bool
}

type ReputationProvider interface {
	GetReputation(ip string) (*IPReputationData, error)
	UpdateReputation(ip string, data *IPReputationData) error
}

type ReputationCache struct {
	data  map[string]*IPReputationData
	ttl   time.Duration
	mutex sync.RWMutex
}

type RequestAnalyzer struct {
	inspectors []RequestInspector
	sanitizer  *PayloadSanitizer
	decoder    *PayloadDecoder
	metrics    *AnalyzerMetrics
}

type RequestInspector interface {
	Inspect(req *http.Request, body []byte) (*InspectionResult, error)
	Name() string
}

type InspectionResult struct {
	Passed      bool
	Score       int
	Violations  []Violation
	Metadata    map[string]interface{}
}

type Violation struct {
	Rule        string
	Category    RuleCategory
	Severity    RuleSeverity
	Description string
	Evidence    string
	Location    string
}

type PayloadSanitizer struct {
	rules []SanitizationRule
}

type SanitizationRule struct {
	Pattern     *regexp.Regexp
	Replacement string
	Category    string
}

type PayloadDecoder struct {
	decoders map[string]Decoder
}

type Decoder interface {
	Decode(data []byte) ([]byte, error)
	CanDecode(data []byte) bool
}

type ResponseFilter struct {
	rules    []ResponseRule
	masker   *DataMasker
	injector *HeaderInjector
}

type ResponseRule struct {
	ID       string
	Match    ResponseMatcher
	Action   ResponseAction
	Priority int
}

type ResponseMatcher func(resp *http.Response, body []byte) bool
type ResponseAction func(resp *http.Response, body []byte) ([]byte, error)

type DataMasker struct {
	patterns map[string]*regexp.Regexp
	masks    map[string]string
}

type HeaderInjector struct {
	headers map[string]string
}

type SecurityLogger struct {
	loggers  []SecurityLogWriter
	buffer   *LogBuffer
	mutex    sync.Mutex
}

type SecurityLogWriter interface {
	Write(entry *SecurityLogEntry) error
	Flush() error
}

type SecurityLogEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	RequestID    string                 `json:"request_id"`
	ClientIP     string                 `json:"client_ip"`
	Method       string                 `json:"method"`
	Path         string                 `json:"path"`
	UserAgent    string                 `json:"user_agent"`
	Action       string                 `json:"action"`
	Score        int                    `json:"score"`
	Violations   []Violation            `json:"violations"`
	ResponseCode int                    `json:"response_code"`
	Duration     time.Duration          `json:"duration"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type LogBuffer struct {
	entries  []*SecurityLogEntry
	maxSize  int
	mutex    sync.Mutex
}

type WAFMetrics struct {
	TotalRequests       uint64
	BlockedRequests     uint64
	AllowedRequests     uint64
	SQLInjectionBlocked uint64
	XSSBlocked          uint64
	PathTraversalBlocked uint64
	CommandInjectionBlocked uint64
	AnomaliesDetected   uint64
	GeoBlocked          uint64
	ReputationBlocked   uint64
	FalsePositives      uint64
	AverageLatency      time.Duration
	mutex               sync.RWMutex
}

func NewWAF(config WAFConfig) *WAF {
	waf := &WAF{
		config:  config,
		metrics: &WAFMetrics{},
	}

	waf.rules = NewRuleEngine()
	waf.initializeDefaultRules()

	if config.EnableAnomalyDetection {
		waf.anomalyDetector = NewAnomalyDetector(config.AnomalyThreshold)
	}

	if config.EnableGeoBlocking {
		waf.geoBlocker = NewGeoBlocker(config.AllowedCountries, config.BlockedCountries)
	}

	if config.EnableIPReputation {
		waf.ipReputation = NewIPReputation()
	}

	waf.requestAnalyzer = NewRequestAnalyzer()
	waf.responseFilter = NewResponseFilter(config.SensitiveDataMasking)

	if config.EnableRequestLogging {
		waf.logger = NewSecurityLogger()
	}

	for _, rule := range config.CustomRules {
		waf.rules.AddRule(&rule)
	}

	return waf
}

func (waf *WAF) ProcessRequest(req *http.Request) error {
	if !waf.config.Enabled || waf.config.Mode == ModeBypass {
		return nil
	}

	start := time.Now()
	defer waf.updateMetrics(start)

	waf.metrics.recordRequest()

	body, err := waf.readRequestBody(req)
	if err != nil {
		return err
	}

	clientIP := waf.extractClientIP(req)

	if waf.config.EnableGeoBlocking {
		if blocked, country := waf.geoBlocker.IsBlocked(clientIP); blocked {
			waf.metrics.recordGeoBlocked()
			waf.logSecurityEvent(req, "geo_blocked", country)
			return waf.handleBlocking(req, ErrRequestBlocked)
		}
	}

	if waf.config.EnableIPReputation {
		if reputation := waf.ipReputation.GetReputation(clientIP); reputation != nil && reputation.Blocked {
			waf.metrics.recordReputationBlocked()
			waf.logSecurityEvent(req, "reputation_blocked", reputation.Score)
			return waf.handleBlocking(req, ErrRequestBlocked)
		}
	}

	result := waf.analyzeRequest(req, body)
	
	if result.Score >= waf.config.BlockingScore {
		waf.recordViolations(result.Violations)
		waf.logSecurityEvent(req, "blocked", result)
		return waf.handleBlocking(req, waf.getBlockingError(result))
	}

	if waf.config.EnableAnomalyDetection {
		if waf.anomalyDetector.IsAnomalous(req, body) {
			waf.metrics.recordAnomalyDetected()
			waf.logSecurityEvent(req, "anomaly_detected", nil)
			
			if waf.config.Mode == ModePrevention {
				return waf.handleBlocking(req, ErrSuspiciousPayload)
			}
		}
	}

	waf.metrics.recordAllowed()
	return nil
}

func (waf *WAF) analyzeRequest(req *http.Request, body []byte) *InspectionResult {
	result := &InspectionResult{
		Passed:     true,
		Score:      0,
		Violations: []Violation{},
		Metadata:   make(map[string]interface{}),
	}

	waf.inspectHeaders(req, result)
	waf.inspectPath(req, result)
	waf.inspectQueryParams(req, result)
	waf.inspectBody(body, result)
	waf.inspectCookies(req, result)

	inspectorResult, _ := waf.requestAnalyzer.Analyze(req, body)
	if inspectorResult != nil {
		result.Score += inspectorResult.Score
		result.Violations = append(result.Violations, inspectorResult.Violations...)
	}

	return result
}

func (waf *WAF) inspectHeaders(req *http.Request, result *InspectionResult) {
	for name, values := range req.Header {
		for _, value := range values {
			waf.checkForViolations(value, "header:"+name, result)
		}
	}
}

func (waf *WAF) inspectPath(req *http.Request, result *InspectionResult) {
	path := req.URL.Path
	
	if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
		result.Violations = append(result.Violations, Violation{
			Rule:        "path_traversal",
			Category:    CategoryPathTraversal,
			Severity:    SeverityCritical,
			Description: "Path traversal attempt detected",
			Evidence:    path,
			Location:    "path",
		})
		result.Score += 10
	}

	waf.checkForViolations(path, "path", result)
}

func (waf *WAF) inspectQueryParams(req *http.Request, result *InspectionResult) {
	for key, values := range req.URL.Query() {
		for _, value := range values {
			waf.checkForViolations(value, "query:"+key, result)
		}
	}
}

func (waf *WAF) inspectBody(body []byte, result *InspectionResult) {
	if len(body) == 0 {
		return
	}

	if len(body) > int(waf.config.MaxRequestBodySize) {
		result.Violations = append(result.Violations, Violation{
			Rule:        "body_size_limit",
			Category:    CategoryProtocolAttack,
			Severity:    SeverityMedium,
			Description: "Request body exceeds size limit",
			Evidence:    fmt.Sprintf("size: %d bytes", len(body)),
			Location:    "body",
		})
		result.Score += 5
	}

	bodyStr := string(body)
	waf.checkForViolations(bodyStr, "body", result)
}

func (waf *WAF) inspectCookies(req *http.Request, result *InspectionResult) {
	for _, cookie := range req.Cookies() {
		waf.checkForViolations(cookie.Value, "cookie:"+cookie.Name, result)
	}
}

func (waf *WAF) checkForViolations(input string, location string, result *InspectionResult) {
	violations := waf.rules.Check(input, location)
	for _, violation := range violations {
		result.Violations = append(result.Violations, violation)
		result.Score += violation.Severity.Score()
	}
}

func (waf *WAF) readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, waf.config.MaxRequestBodySize))
	if err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func (waf *WAF) extractClientIP(req *http.Request) string {
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	return strings.Split(req.RemoteAddr, ":")[0]
}

func (waf *WAF) handleBlocking(req *http.Request, err error) error {
	if waf.config.Mode == ModeDetection {
		return nil
	}
	return err
}

func (waf *WAF) getBlockingError(result *InspectionResult) error {
	if len(result.Violations) == 0 {
		return ErrRequestBlocked
	}

	switch result.Violations[0].Category {
	case CategorySQLInjection:
		return ErrSQLInjection
	case CategoryXSS:
		return ErrXSSAttack
	case CategoryPathTraversal:
		return ErrPathTraversal
	case CategoryCommandInjection:
		return ErrCommandInjection
	default:
		return ErrRequestBlocked
	}
}

func (waf *WAF) recordViolations(violations []Violation) {
	for _, violation := range violations {
		switch violation.Category {
		case CategorySQLInjection:
			waf.metrics.recordSQLInjectionBlocked()
		case CategoryXSS:
			waf.metrics.recordXSSBlocked()
		case CategoryPathTraversal:
			waf.metrics.recordPathTraversalBlocked()
		case CategoryCommandInjection:
			waf.metrics.recordCommandInjectionBlocked()
		}
	}
	waf.metrics.recordBlocked()
}

func (waf *WAF) logSecurityEvent(req *http.Request, action string, data interface{}) {
	if waf.logger == nil {
		return
	}

	entry := &SecurityLogEntry{
		Timestamp: time.Now(),
		ClientIP:  waf.extractClientIP(req),
		Method:    req.Method,
		Path:      req.URL.Path,
		UserAgent: req.UserAgent(),
		Action:    action,
		Metadata:  make(map[string]interface{}),
	}

	if result, ok := data.(*InspectionResult); ok {
		entry.Score = result.Score
		entry.Violations = result.Violations
	}

	waf.logger.Log(entry)
}

func (waf *WAF) updateMetrics(start time.Time) {
	duration := time.Since(start)
	waf.metrics.mutex.Lock()
	defer waf.metrics.mutex.Unlock()

	count := waf.metrics.TotalRequests
	if count > 0 {
		waf.metrics.AverageLatency = 
			(waf.metrics.AverageLatency*time.Duration(count-1) + duration) / 
			time.Duration(count)
	} else {
		waf.metrics.AverageLatency = duration
	}
}

func (waf *WAF) initializeDefaultRules() {
	sqlInjectionPatterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|eval).*?(from|into|where|table|database)`,
		`(?i)(;|--|#|\/\*|\*\/|xp_|sp_|0x)`,
		`(?i)(benchmark|sleep|waitfor|pg_sleep)\s*\(`,
	}

	xssPatterns := []string{
		`(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>`,
		`(?i)(javascript|vbscript|onload|onerror|onmouseover|onclick)\s*[:=]`,
		`(?i)<\s*(iframe|frame|embed|object|applet|meta|link|style|form|input)`,
	}

	commandInjectionPatterns := []string{
		`(?i)(\||;|&|>|<|\$\(|\`|\\n|\\r)`,
		`(?i)(wget|curl|nc|netcat|telnet|ssh|ftp|scp|rsync)`,
		`(?i)(bash|sh|cmd|powershell|python|perl|ruby|php)`,
	}

	for _, pattern := range sqlInjectionPatterns {
		waf.rules.AddRule(&Rule{
			ID:          fmt.Sprintf("sql_%d", len(waf.rules.rules)),
			Name:        "SQL Injection Detection",
			Category:    CategorySQLInjection,
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(pattern),
			Action:      ActionBlock,
			Score:       10,
			Enabled:     true,
		})
	}

	for _, pattern := range xssPatterns {
		waf.rules.AddRule(&Rule{
			ID:          fmt.Sprintf("xss_%d", len(waf.rules.rules)),
			Name:        "XSS Detection",
			Category:    CategoryXSS,
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(pattern),
			Action:      ActionBlock,
			Score:       8,
			Enabled:     true,
		})
	}

	for _, pattern := range commandInjectionPatterns {
		waf.rules.AddRule(&Rule{
			ID:          fmt.Sprintf("cmd_%d", len(waf.rules.rules)),
			Name:        "Command Injection Detection",
			Category:    CategoryCommandInjection,
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(pattern),
			Action:      ActionBlock,
			Score:       10,
			Enabled:     true,
		})
	}
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:            make(map[string]*Rule),
		rulesByCategory:  make(map[RuleCategory][]*Rule),
		compiledPatterns: make(map[string]*regexp.Regexp),
	}
}

func (re *RuleEngine) AddRule(rule *Rule) {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	re.rules[rule.ID] = rule
	re.rulesByCategory[rule.Category] = append(re.rulesByCategory[rule.Category], rule)
	
	if rule.Pattern != nil {
		re.compiledPatterns[rule.ID] = rule.Pattern
	}
}

func (re *RuleEngine) Check(input string, location string) []Violation {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	var violations []Violation

	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}

		if rule.Pattern != nil && rule.Pattern.MatchString(input) {
			violations = append(violations, Violation{
				Rule:        rule.ID,
				Category:    rule.Category,
				Severity:    rule.Severity,
				Description: rule.Description,
				Evidence:    input[:min(100, len(input))],
				Location:    location,
			})
		}
	}

	return violations
}

func NewAnomalyDetector(threshold int) *AnomalyDetector {
	return &AnomalyDetector{
		threshold: threshold,
		window:    5 * time.Minute,
		patterns:  make(map[string]*AnomalyPattern),
		baseline: &TrafficBaseline{
			CommonPaths:      make(map[string]int),
			CommonHeaders:    make(map[string]int),
			CommonUserAgents: make(map[string]int),
		},
	}
}

func (ad *AnomalyDetector) IsAnomalous(req *http.Request, body []byte) bool {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()

	score := 0

	if float64(len(body)) > ad.baseline.AverageSize*3 {
		score += 2
	}

	path := req.URL.Path
	if _, exists := ad.baseline.CommonPaths[path]; !exists && len(ad.baseline.CommonPaths) > 100 {
		score += 1
	}

	userAgent := req.UserAgent()
	if _, exists := ad.baseline.CommonUserAgents[userAgent]; !exists && len(ad.baseline.CommonUserAgents) > 50 {
		score += 1
	}

	return score >= ad.threshold
}

func NewGeoBlocker(allowed []string, blocked []string) *GeoBlocker {
	gb := &GeoBlocker{
		allowedCountries: make(map[string]bool),
		blockedCountries: make(map[string]bool),
	}

	for _, country := range allowed {
		gb.allowedCountries[country] = true
	}

	for _, country := range blocked {
		gb.blockedCountries[country] = true
	}

	return gb
}

func (gb *GeoBlocker) IsBlocked(ip string) (bool, string) {
	country := "US"

	if len(gb.allowedCountries) > 0 {
		if !gb.allowedCountries[country] {
			return true, country
		}
	}

	if gb.blockedCountries[country] {
		return true, country
	}

	return false, country
}

func NewIPReputation() *IPReputation {
	return &IPReputation{
		reputationDB: make(map[string]*IPReputationData),
		cache:        NewReputationCache(1 * time.Hour),
	}
}

func (ipr *IPReputation) GetReputation(ip string) *IPReputationData {
	ipr.mutex.RLock()
	defer ipr.mutex.RUnlock()

	if data := ipr.cache.Get(ip); data != nil {
		return data
	}

	if data, exists := ipr.reputationDB[ip]; exists {
		return data
	}

	return nil
}

func NewReputationCache(ttl time.Duration) *ReputationCache {
	return &ReputationCache{
		data: make(map[string]*IPReputationData),
		ttl:  ttl,
	}
}

func (rc *ReputationCache) Get(ip string) *IPReputationData {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	if data, exists := rc.data[ip]; exists {
		if time.Since(data.LastUpdate) < rc.ttl {
			return data
		}
	}

	return nil
}

func NewRequestAnalyzer() *RequestAnalyzer {
	return &RequestAnalyzer{
		inspectors: []RequestInspector{},
		sanitizer:  NewPayloadSanitizer(),
		decoder:    NewPayloadDecoder(),
		metrics:    &AnalyzerMetrics{},
	}
}

func (ra *RequestAnalyzer) Analyze(req *http.Request, body []byte) (*InspectionResult, error) {
	result := &InspectionResult{
		Passed:     true,
		Score:      0,
		Violations: []Violation{},
		Metadata:   make(map[string]interface{}),
	}

	for _, inspector := range ra.inspectors {
		inspResult, err := inspector.Inspect(req, body)
		if err != nil {
			continue
		}

		result.Score += inspResult.Score
		result.Violations = append(result.Violations, inspResult.Violations...)
	}

	return result, nil
}

func NewPayloadSanitizer() *PayloadSanitizer {
	return &PayloadSanitizer{
		rules: []SanitizationRule{},
	}
}

func NewPayloadDecoder() *PayloadDecoder {
	return &PayloadDecoder{
		decoders: make(map[string]Decoder),
	}
}

func NewResponseFilter(enableMasking bool) *ResponseFilter {
	rf := &ResponseFilter{
		rules:    []ResponseRule{},
		injector: NewHeaderInjector(),
	}

	if enableMasking {
		rf.masker = NewDataMasker()
	}

	return rf
}

func NewDataMasker() *DataMasker {
	return &DataMasker{
		patterns: map[string]*regexp.Regexp{
			"ssn":    regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			"cc":     regexp.MustCompile(`\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),
			"email":  regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		},
		masks: map[string]string{
			"ssn":   "XXX-XX-XXXX",
			"cc":    "XXXX-XXXX-XXXX-XXXX",
			"email": "****@****.***",
		},
	}
}

func NewHeaderInjector() *HeaderInjector {
	return &HeaderInjector{
		headers: map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"X-XSS-Protection":       "1; mode=block",
		},
	}
}

func NewSecurityLogger() *SecurityLogger {
	return &SecurityLogger{
		loggers: []SecurityLogWriter{},
		buffer:  NewLogBuffer(1000),
	}
}

func (sl *SecurityLogger) Log(entry *SecurityLogEntry) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	sl.buffer.Add(entry)

	for _, logger := range sl.loggers {
		logger.Write(entry)
	}
}

func NewLogBuffer(maxSize int) *LogBuffer {
	return &LogBuffer{
		entries: make([]*SecurityLogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (lb *LogBuffer) Add(entry *SecurityLogEntry) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.entries) >= lb.maxSize {
		lb.entries = lb.entries[1:]
	}

	lb.entries = append(lb.entries, entry)
}

func (s RuleSeverity) Score() int {
	return int(s) * 2
}

func (wm *WAFMetrics) recordRequest() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.TotalRequests++
}

func (wm *WAFMetrics) recordBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.BlockedRequests++
}

func (wm *WAFMetrics) recordAllowed() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.AllowedRequests++
}

func (wm *WAFMetrics) recordSQLInjectionBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.SQLInjectionBlocked++
}

func (wm *WAFMetrics) recordXSSBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.XSSBlocked++
}

func (wm *WAFMetrics) recordPathTraversalBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.PathTraversalBlocked++
}

func (wm *WAFMetrics) recordCommandInjectionBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.CommandInjectionBlocked++
}

func (wm *WAFMetrics) recordAnomalyDetected() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.AnomaliesDetected++
}

func (wm *WAFMetrics) recordGeoBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.GeoBlocked++
}

func (wm *WAFMetrics) recordReputationBlocked() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	wm.ReputationBlocked++
}

type AnalyzerMetrics struct {
	RequestsAnalyzed uint64
	ViolationsFound  uint64
	AverageScore     float64
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}