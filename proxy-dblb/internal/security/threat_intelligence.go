package security

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// ThreatIntelConfig configures the threat intelligence engine
type ThreatIntelConfig struct {
	Enabled            bool             `json:"enabled" yaml:"enabled"`
	UpdateInterval     time.Duration    `json:"update_interval" yaml:"update_interval"`
	MaxConcurrentFeeds int              `json:"max_concurrent_feeds" yaml:"max_concurrent_feeds"`
	Feeds              map[string]*Feed `json:"feeds" yaml:"feeds"`
	AutoBlock          AutoBlockConfig  `json:"auto_block" yaml:"auto_block"`
	RetentionDays      int              `json:"retention_days" yaml:"retention_days"`
}

// Feed represents a threat intelligence feed
type Feed struct {
	Name       string            `json:"name" yaml:"name"`
	Type       string            `json:"type" yaml:"type"` // json, csv
	URL        string            `json:"url" yaml:"url"`
	APIKey     string            `json:"api_key" yaml:"api_key"`
	Headers    map[string]string `json:"headers" yaml:"headers"`
	Enabled    bool              `json:"enabled" yaml:"enabled"`
	UpdateFreq time.Duration     `json:"update_freq" yaml:"update_freq"`
	Timeout    time.Duration     `json:"timeout" yaml:"timeout"`
	Fields     map[string]string `json:"fields" yaml:"fields"` // Field mapping
}

// AutoBlockConfig configures automatic blocking
type AutoBlockConfig struct {
	Enabled             bool          `json:"enabled" yaml:"enabled"`
	ConfidenceThreshold float64       `json:"confidence_threshold" yaml:"confidence_threshold"`
	Categories          []string      `json:"categories" yaml:"categories"`
	BlockDuration       time.Duration `json:"block_duration" yaml:"block_duration"`
}

// ThreatIndicator represents a single threat
type ThreatIndicator struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // ip, domain, url, hash
	Value      string                 `json:"value"`
	Confidence float64                `json:"confidence"`
	Severity   string                 `json:"severity"` // low, medium, high, critical
	Categories []string               `json:"categories"`
	Sources    []string               `json:"sources"`
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
	Blocked    bool                   `json:"blocked"`
	BlockedAt  *time.Time             `json:"blocked_at,omitempty"`
	Tags       []string               `json:"tags"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ThreatIntelligenceEngine manages threat feeds and indicators
type ThreatIntelligenceEngine struct {
	config        *ThreatIntelConfig
	redis         *redis.Client
	logger        *logrus.Logger
	indicators    map[string]*ThreatIndicator
	ipThreats     map[string]*ThreatIndicator
	domainThreats map[string]*ThreatIndicator
	feedStats     map[string]*FeedStats
	httpClient    *http.Client
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// FeedStats tracks feed update statistics
type FeedStats struct {
	TotalUpdates      int       `json:"total_updates"`
	SuccessfulUpdates int       `json:"successful_updates"`
	FailedUpdates     int       `json:"failed_updates"`
	LastUpdateTime    time.Time `json:"last_update_time"`
	TotalIndicators   int       `json:"total_indicators"`
	LastHash          string    `json:"last_hash"`
}

// NewThreatIntelligenceEngine creates a new threat intelligence engine
func NewThreatIntelligenceEngine(config *ThreatIntelConfig, redisClient *redis.Client, logger *logrus.Logger) *ThreatIntelligenceEngine {
	ctx, cancel := context.WithCancel(context.Background())

	engine := &ThreatIntelligenceEngine{
		config:        config,
		redis:         redisClient,
		logger:        logger,
		indicators:    make(map[string]*ThreatIndicator),
		ipThreats:     make(map[string]*ThreatIndicator),
		domainThreats: make(map[string]*ThreatIndicator),
		feedStats:     make(map[string]*FeedStats),
		ctx:           ctx,
		cancel:        cancel,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Initialize feed stats
	for feedID := range config.Feeds {
		engine.feedStats[feedID] = &FeedStats{}
	}

	// Load existing data from Redis
	engine.loadFromRedis()

	// Start background processes
	go engine.feedUpdateLoop()
	go engine.cleanupLoop()

	logger.WithFields(logrus.Fields{
		"feeds":      len(config.Feeds),
		"auto_block": config.AutoBlock.Enabled,
	}).Info("Threat Intelligence Engine initialized")

	return engine
}

// feedUpdateLoop periodically updates all feeds
func (tie *ThreatIntelligenceEngine) feedUpdateLoop() {
	if tie.config.UpdateInterval == 0 {
		tie.config.UpdateInterval = 1 * time.Hour
	}

	ticker := time.NewTicker(tie.config.UpdateInterval)
	defer ticker.Stop()

	// Initial update
	tie.updateAllFeeds()

	for {
		select {
		case <-tie.ctx.Done():
			return
		case <-ticker.C:
			tie.updateAllFeeds()
		}
	}
}

// updateAllFeeds updates all configured feeds
func (tie *ThreatIntelligenceEngine) updateAllFeeds() {
	for feedID, feed := range tie.config.Feeds {
		if !feed.Enabled {
			continue
		}

		go func(id string, f *Feed) {
			if err := tie.updateFeed(id, f); err != nil {
				tie.logger.WithFields(logrus.Fields{
					"feed":  id,
					"error": err,
				}).Error("Failed to update threat feed")

				tie.mu.Lock()
				tie.feedStats[id].FailedUpdates++
				tie.mu.Unlock()
			}
		}(feedID, feed)
	}
}

// updateFeed fetches and processes a single feed
func (tie *ThreatIntelligenceEngine) updateFeed(feedID string, feed *Feed) error {
	timeout := feed.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(tie.ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if feed.APIKey != "" {
		req.Header.Set("X-API-Key", feed.APIKey)
	}
	for key, value := range feed.Headers {
		req.Header.Set(key, value)
	}

	resp, err := tie.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check if content changed
	newHash := fmt.Sprintf("%x", md5.Sum(body))
	tie.mu.RLock()
	oldHash := tie.feedStats[feedID].LastHash
	tie.mu.RUnlock()

	if oldHash == newHash {
		tie.logger.WithField("feed", feedID).Debug("Feed content unchanged")
		return nil
	}

	// Parse feed
	indicators, err := tie.parseFeed(feedID, feed, body)
	if err != nil {
		return fmt.Errorf("failed to parse feed: %w", err)
	}

	// Process indicators
	newCount := 0
	for _, indicator := range indicators {
		if tie.processIndicator(indicator) {
			newCount++
		}
	}

	// Update stats
	tie.mu.Lock()
	stats := tie.feedStats[feedID]
	stats.TotalUpdates++
	stats.SuccessfulUpdates++
	stats.LastUpdateTime = time.Now()
	stats.TotalIndicators = len(indicators)
	stats.LastHash = newHash
	tie.mu.Unlock()

	tie.logger.WithFields(logrus.Fields{
		"feed":           feedID,
		"total":          len(indicators),
		"new_indicators": newCount,
	}).Info("Updated threat feed")

	return nil
}

// parseFeed parses feed data based on type
func (tie *ThreatIntelligenceEngine) parseFeed(feedID string, feed *Feed, data []byte) ([]*ThreatIndicator, error) {
	switch feed.Type {
	case "json":
		return tie.parseJSONFeed(feedID, feed, data)
	case "csv":
		return tie.parseCSVFeed(feedID, feed, data)
	default:
		return nil, fmt.Errorf("unsupported feed type: %s", feed.Type)
	}
}

// parseJSONFeed parses JSON format feeds
func (tie *ThreatIntelligenceEngine) parseJSONFeed(feedID string, feed *Feed, data []byte) ([]*ThreatIndicator, error) {
	var rawData []map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, err
	}

	var indicators []*ThreatIndicator
	for _, item := range rawData {
		indicator := tie.mapToIndicator(feedID, feed.Fields, item)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

// parseCSVFeed parses CSV format feeds
func (tie *ThreatIntelligenceEngine) parseCSVFeed(feedID string, feed *Feed, data []byte) ([]*ThreatIndicator, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, nil
	}

	headers := strings.Split(lines[0], ",")
	var indicators []*ThreatIndicator

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) != len(headers) {
			continue
		}

		item := make(map[string]interface{})
		for j, header := range headers {
			item[strings.TrimSpace(header)] = strings.TrimSpace(fields[j])
		}

		indicator := tie.mapToIndicator(feedID, feed.Fields, item)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

// mapToIndicator converts raw data to ThreatIndicator
func (tie *ThreatIntelligenceEngine) mapToIndicator(feedID string, fieldMap map[string]string, item map[string]interface{}) *ThreatIndicator {
	getValue := func(key string) string {
		if mapped, ok := fieldMap[key]; ok {
			key = mapped
		}
		if val, ok := item[key]; ok {
			return fmt.Sprintf("%v", val)
		}
		return ""
	}

	indicatorType := getValue("type")
	value := getValue("value")

	if indicatorType == "" || value == "" {
		return nil
	}

	confidence := 0.5
	if confStr := getValue("confidence"); confStr != "" {
		fmt.Sscanf(confStr, "%f", &confidence)
	}

	indicator := &ThreatIndicator{
		ID:         fmt.Sprintf("%s_%s_%x", feedID, indicatorType, md5.Sum([]byte(value))),
		Type:       strings.ToLower(indicatorType),
		Value:      strings.ToLower(strings.TrimSpace(value)),
		Confidence: confidence,
		Severity:   getValue("severity"),
		Sources:    []string{feedID},
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       []string{},
		Metadata:   item,
	}

	if categories := getValue("categories"); categories != "" {
		indicator.Categories = strings.Split(categories, ",")
	}

	return indicator
}

// processIndicator adds or updates an indicator
func (tie *ThreatIntelligenceEngine) processIndicator(indicator *ThreatIndicator) bool {
	tie.mu.Lock()
	defer tie.mu.Unlock()

	// Check for existing indicator
	if existing, ok := tie.indicators[indicator.ID]; ok {
		existing.LastSeen = time.Now()
		existing.Sources = mergeStrings(existing.Sources, indicator.Sources)
		return false
	}

	// Store new indicator
	tie.indicators[indicator.ID] = indicator

	switch indicator.Type {
	case "ip":
		tie.ipThreats[indicator.Value] = indicator
	case "domain":
		tie.domainThreats[indicator.Value] = indicator
	}

	// Auto-block if configured
	if tie.config.AutoBlock.Enabled && indicator.Confidence >= tie.config.AutoBlock.ConfidenceThreshold {
		indicator.Blocked = true
		now := time.Now()
		indicator.BlockedAt = &now

		if tie.config.AutoBlock.BlockDuration > 0 {
			expires := now.Add(tie.config.AutoBlock.BlockDuration)
			indicator.ExpiresAt = &expires
		}
	}

	// Store in Redis
	tie.storeInRedis(indicator)

	return true
}

// storeInRedis persists an indicator to Redis
func (tie *ThreatIntelligenceEngine) storeInRedis(indicator *ThreatIndicator) {
	if tie.redis == nil {
		return
	}

	data, err := json.Marshal(indicator)
	if err != nil {
		return
	}

	key := fmt.Sprintf("dblb:threat:%s", indicator.ID)
	expiration := time.Duration(tie.config.RetentionDays) * 24 * time.Hour
	if expiration == 0 {
		expiration = 30 * 24 * time.Hour // Default 30 days
	}

	tie.redis.Set(tie.ctx, key, data, expiration)
}

// loadFromRedis loads existing indicators from Redis
func (tie *ThreatIntelligenceEngine) loadFromRedis() {
	if tie.redis == nil {
		return
	}

	keys, err := tie.redis.Keys(tie.ctx, "dblb:threat:*").Result()
	if err != nil {
		tie.logger.WithError(err).Error("Failed to load threat data from Redis")
		return
	}

	loaded := 0
	for _, key := range keys {
		data, err := tie.redis.Get(tie.ctx, key).Result()
		if err != nil {
			continue
		}

		var indicator ThreatIndicator
		if err := json.Unmarshal([]byte(data), &indicator); err != nil {
			continue
		}

		tie.mu.Lock()
		tie.indicators[indicator.ID] = &indicator
		switch indicator.Type {
		case "ip":
			tie.ipThreats[indicator.Value] = &indicator
		case "domain":
			tie.domainThreats[indicator.Value] = &indicator
		}
		tie.mu.Unlock()

		loaded++
	}

	tie.logger.WithField("count", loaded).Info("Loaded threat indicators from Redis")
}

// cleanupLoop removes expired indicators
func (tie *ThreatIntelligenceEngine) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-tie.ctx.Done():
			return
		case <-ticker.C:
			tie.cleanup()
		}
	}
}

// cleanup removes expired indicators
func (tie *ThreatIntelligenceEngine) cleanup() {
	tie.mu.Lock()
	defer tie.mu.Unlock()

	now := time.Now()
	expired := 0

	for id, indicator := range tie.indicators {
		if indicator.ExpiresAt != nil && now.After(*indicator.ExpiresAt) {
			delete(tie.indicators, id)

			switch indicator.Type {
			case "ip":
				delete(tie.ipThreats, indicator.Value)
			case "domain":
				delete(tie.domainThreats, indicator.Value)
			}

			expired++
		}
	}

	if expired > 0 {
		tie.logger.WithField("count", expired).Info("Cleaned up expired threat indicators")
	}
}

// IsIPThreat checks if an IP is a known threat
func (tie *ThreatIntelligenceEngine) IsIPThreat(ip string) bool {
	tie.mu.RLock()
	defer tie.mu.RUnlock()

	if indicator, ok := tie.ipThreats[strings.ToLower(ip)]; ok {
		if indicator.ExpiresAt == nil || time.Now().Before(*indicator.ExpiresAt) {
			return true
		}
	}
	return false
}

// IsDomainThreat checks if a domain is a known threat
func (tie *ThreatIntelligenceEngine) IsDomainThreat(domain string) bool {
	tie.mu.RLock()
	defer tie.mu.RUnlock()

	if indicator, ok := tie.domainThreats[strings.ToLower(domain)]; ok {
		if indicator.ExpiresAt == nil || time.Now().Before(*indicator.ExpiresAt) {
			return true
		}
	}
	return false
}

// GetThreat returns a threat indicator by value
func (tie *ThreatIntelligenceEngine) GetThreat(value string) *ThreatIndicator {
	tie.mu.RLock()
	defer tie.mu.RUnlock()

	value = strings.ToLower(value)

	if indicator, ok := tie.ipThreats[value]; ok {
		return indicator
	}
	if indicator, ok := tie.domainThreats[value]; ok {
		return indicator
	}
	return nil
}

// AddCustomThreat manually adds a threat indicator
func (tie *ThreatIntelligenceEngine) AddCustomThreat(indicatorType, value string, confidence float64, categories []string) error {
	indicator := &ThreatIndicator{
		ID:         fmt.Sprintf("manual_%s_%x", indicatorType, md5.Sum([]byte(value))),
		Type:       indicatorType,
		Value:      strings.ToLower(value),
		Confidence: confidence,
		Severity:   "medium",
		Categories: categories,
		Sources:    []string{"manual"},
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       []string{"manual"},
		Metadata:   make(map[string]interface{}),
	}

	tie.processIndicator(indicator)

	tie.logger.WithFields(logrus.Fields{
		"type":  indicatorType,
		"value": value,
	}).Info("Added custom threat indicator")

	return nil
}

// RemoveThreat removes a threat indicator
func (tie *ThreatIntelligenceEngine) RemoveThreat(value string) bool {
	tie.mu.Lock()
	defer tie.mu.Unlock()

	value = strings.ToLower(value)

	// Find and remove from appropriate map
	if indicator, ok := tie.ipThreats[value]; ok {
		delete(tie.indicators, indicator.ID)
		delete(tie.ipThreats, value)
		return true
	}

	if indicator, ok := tie.domainThreats[value]; ok {
		delete(tie.indicators, indicator.ID)
		delete(tie.domainThreats, value)
		return true
	}

	return false
}

// GetStats returns threat intelligence statistics
func (tie *ThreatIntelligenceEngine) GetStats() map[string]interface{} {
	tie.mu.RLock()
	defer tie.mu.RUnlock()

	return map[string]interface{}{
		"total_indicators": len(tie.indicators),
		"ip_threats":       len(tie.ipThreats),
		"domain_threats":   len(tie.domainThreats),
		"feed_stats":       tie.feedStats,
	}
}

// Close shuts down the threat intelligence engine
func (tie *ThreatIntelligenceEngine) Close() error {
	tie.cancel()
	tie.logger.Info("Threat Intelligence Engine stopped")
	return nil
}

// mergeStrings merges two string slices, removing duplicates
func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))

	for _, v := range a {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	for _, v := range b {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}

	return result
}
