package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// User represents a database user
type User struct {
	Username     string     `json:"username" yaml:"username"`
	PasswordHash string     `json:"password_hash" yaml:"password_hash"`
	APIKey       string     `json:"api_key" yaml:"api_key"`
	Enabled      bool       `json:"enabled" yaml:"enabled"`
	RequireTLS   bool       `json:"require_tls" yaml:"require_tls"`
	RateLimit    int        `json:"rate_limit" yaml:"rate_limit"` // Requests per second
	AllowedIPs   []string   `json:"allowed_ips" yaml:"allowed_ips"`
	ExpiresAt    *time.Time `json:"expires_at" yaml:"expires_at"`
	CreatedAt    time.Time  `json:"created_at" yaml:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" yaml:"updated_at"`
}

// Permission represents database access permissions
type Permission struct {
	Username  string     `json:"username" yaml:"username"`
	Database  string     `json:"database" yaml:"database"` // "*" for all
	Table     string     `json:"table" yaml:"table"`       // "*" for all
	Actions   []string   `json:"actions" yaml:"actions"`   // read, write, admin, *
	TimeLimit *time.Time `json:"time_limit" yaml:"time_limit"`
}

// Manager handles authentication and authorization
type Manager struct {
	redis       *redis.Client
	logger      *logrus.Logger
	users       map[string]*User
	permissions map[string]*Permission
	mu          sync.RWMutex
	cachePrefix string
}

// NewManager creates a new auth manager
func NewManager(redisClient *redis.Client, logger *logrus.Logger) *Manager {
	return &Manager{
		redis:       redisClient,
		logger:      logger,
		users:       make(map[string]*User),
		permissions: make(map[string]*Permission),
		cachePrefix: "dblb:auth:",
	}
}

// AddUser adds a user to the manager
func (m *Manager) AddUser(user *User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.Username] = user
}

// GetUser retrieves a user by username
func (m *Manager) GetUser(username string) (*User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, ok := m.users[username]
	return user, ok
}

// AddPermission adds a permission to the manager
func (m *Manager) AddPermission(perm *Permission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.permissions[perm.Username] = perm
}

// GetPermission retrieves permissions for a user
func (m *Manager) GetPermission(username string) (*Permission, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	perm, ok := m.permissions[username]
	return perm, ok
}

// Authenticate verifies user credentials for database access
func (m *Manager) Authenticate(ctx context.Context, username, database, dbType string) bool {
	return m.AuthenticateWithIP(ctx, username, database, dbType, "")
}

// AuthenticateWithIP verifies user credentials with IP validation
func (m *Manager) AuthenticateWithIP(ctx context.Context, username, database, dbType, clientIP string) bool {
	cacheKey := fmt.Sprintf("%s%s:%s:%s:%s", m.cachePrefix, dbType, username, database, clientIP)

	// Check cache first
	if m.redis != nil {
		cached, err := m.redis.Get(ctx, cacheKey).Result()
		if err == nil {
			return cached == "allowed"
		}
	}

	user, ok := m.GetUser(username)
	if !ok || !user.Enabled {
		m.logger.WithFields(logrus.Fields{
			"username": username,
		}).Warn("Authentication failed: user not found or disabled")
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	// Check account expiration
	if user.ExpiresAt != nil && time.Now().After(*user.ExpiresAt) {
		m.logger.WithFields(logrus.Fields{
			"username": username,
		}).Warn("Authentication failed: user account expired")
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	// Check IP whitelist if configured
	if len(user.AllowedIPs) > 0 && clientIP != "" {
		if !m.isIPAllowed(clientIP, user.AllowedIPs) {
			m.logger.WithFields(logrus.Fields{
				"username": username,
				"ip":       clientIP,
			}).Warn("Authentication failed: IP not in whitelist")
			m.cacheAuthResult(ctx, cacheKey, false)
			return false
		}
	}

	perm, ok := m.GetPermission(username)
	if !ok {
		m.logger.WithFields(logrus.Fields{
			"username": username,
		}).Warn("Authentication failed: no permissions found")
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	// Check database access
	if perm.Database != "*" && perm.Database != database {
		m.logger.WithFields(logrus.Fields{
			"username": username,
			"database": database,
		}).Warn("Authentication failed: database access denied")
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	// Check permission expiration
	if perm.TimeLimit != nil && time.Now().After(*perm.TimeLimit) {
		m.logger.WithFields(logrus.Fields{
			"username": username,
			"database": database,
		}).Warn("Authentication failed: database access expired")
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	m.cacheAuthResult(ctx, cacheKey, true)
	return true
}

// Authorize checks if a user can perform an action
func (m *Manager) Authorize(ctx context.Context, username, database, table string, isWrite bool) bool {
	cacheKey := fmt.Sprintf("%sauthz:%s:%s:%s:%t", m.cachePrefix, username, database, table, isWrite)

	// Check cache first
	if m.redis != nil {
		cached, err := m.redis.Get(ctx, cacheKey).Result()
		if err == nil {
			return cached == "allowed"
		}
	}

	perm, ok := m.GetPermission(username)
	if !ok {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	if perm.Database != "*" && perm.Database != database {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	if table != "" && perm.Table != "*" && perm.Table != table {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	action := "read"
	if isWrite {
		action = "write"
	}

	for _, allowedAction := range perm.Actions {
		if allowedAction == action || allowedAction == "*" {
			m.cacheAuthResult(ctx, cacheKey, true)
			return true
		}
	}

	m.cacheAuthResult(ctx, cacheKey, false)
	return false
}

// cacheAuthResult caches authentication/authorization results
func (m *Manager) cacheAuthResult(ctx context.Context, key string, allowed bool) {
	if m.redis == nil {
		return
	}

	value := "denied"
	if allowed {
		value = "allowed"
	}

	m.redis.Set(ctx, key, value, 5*time.Minute)
}

// HashPassword creates a SHA256 hash of a password
func (m *Manager) HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ValidatePassword checks if password matches user's stored hash
func (m *Manager) ValidatePassword(username, password string) bool {
	user, ok := m.GetUser(username)
	if !ok {
		return false
	}

	return user.PasswordHash == m.HashPassword(password)
}

// ValidateAPIKey authenticates using an API key
func (m *Manager) ValidateAPIKey(ctx context.Context, apiKey, database, dbType string) (string, bool) {
	if apiKey == "" {
		return "", false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for username, user := range m.users {
		if user.APIKey == apiKey && user.Enabled {
			// Check if user can access this database
			if m.AuthenticateWithIP(ctx, username, database, dbType, "") {
				m.logger.WithFields(logrus.Fields{
					"username": username,
				}).Info("API key authentication successful")
				return username, true
			}
		}
	}

	if len(apiKey) > 8 {
		m.logger.WithFields(logrus.Fields{
			"key_prefix": apiKey[:8] + "...",
		}).Warn("API key authentication failed")
	}
	return "", false
}

// GenerateAPIKey creates a new random API key
func (m *Manager) GenerateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// isIPAllowed checks if an IP is in the allowed list
func (m *Manager) isIPAllowed(clientIP string, allowedIPs []string) bool {
	for _, allowedIP := range allowedIPs {
		if strings.Contains(allowedIP, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(allowedIP)
			if err != nil {
				continue
			}
			ip := net.ParseIP(clientIP)
			if ip != nil && network.Contains(ip) {
				return true
			}
		} else {
			// Direct IP match
			if clientIP == allowedIP {
				return true
			}
		}
	}
	return false
}

// CheckTLSRequired returns whether user requires TLS
func (m *Manager) CheckTLSRequired(username string) bool {
	user, ok := m.GetUser(username)
	if !ok {
		return false
	}
	return user.RequireTLS
}

// GetUserRateLimit returns rate limit for a user
func (m *Manager) GetUserRateLimit(username string) int {
	user, ok := m.GetUser(username)
	if !ok {
		return 0
	}
	return user.RateLimit
}

// CheckRateLimit verifies if user is within rate limits
func (m *Manager) CheckRateLimit(ctx context.Context, username string) bool {
	user, ok := m.GetUser(username)
	if !ok || user.RateLimit <= 0 {
		return true // No rate limit
	}

	if m.redis == nil {
		return true
	}

	key := fmt.Sprintf("%srate:%s", m.cachePrefix, username)
	current, err := m.redis.Get(ctx, key).Int()
	if err != nil {
		current = 0
	}

	if current >= user.RateLimit {
		m.logger.WithFields(logrus.Fields{
			"username": username,
			"limit":    user.RateLimit,
			"current":  current,
		}).Warn("Rate limit exceeded")
		return false
	}

	// Increment counter with 1-second TTL
	pipe := m.redis.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, time.Second)
	pipe.Exec(ctx)

	return true
}

// SyncUsersFromRedis loads users from Redis
func (m *Manager) SyncUsersFromRedis(ctx context.Context) error {
	if m.redis == nil {
		return nil
	}

	usersData, err := m.redis.Get(ctx, m.cachePrefix+"manager:users").Result()
	if err != nil {
		return err
	}

	var users map[string]*User
	if err := json.Unmarshal([]byte(usersData), &users); err != nil {
		return err
	}

	m.mu.Lock()
	m.users = users
	m.mu.Unlock()

	m.logger.WithField("count", len(users)).Info("Synced users from Redis")
	return nil
}

// SyncPermissionsFromRedis loads permissions from Redis
func (m *Manager) SyncPermissionsFromRedis(ctx context.Context) error {
	if m.redis == nil {
		return nil
	}

	permsData, err := m.redis.Get(ctx, m.cachePrefix+"manager:permissions").Result()
	if err != nil {
		return err
	}

	var perms map[string]*Permission
	if err := json.Unmarshal([]byte(permsData), &perms); err != nil {
		return err
	}

	m.mu.Lock()
	m.permissions = perms
	m.mu.Unlock()

	m.logger.WithField("count", len(perms)).Info("Synced permissions from Redis")
	return nil
}

// PublishUsersToRedis saves users to Redis for other services
func (m *Manager) PublishUsersToRedis(ctx context.Context) error {
	if m.redis == nil {
		return nil
	}

	m.mu.RLock()
	data, err := json.Marshal(m.users)
	m.mu.RUnlock()

	if err != nil {
		return err
	}

	return m.redis.Set(ctx, m.cachePrefix+"manager:users", data, 0).Err()
}

// PublishPermissionsToRedis saves permissions to Redis
func (m *Manager) PublishPermissionsToRedis(ctx context.Context) error {
	if m.redis == nil {
		return nil
	}

	m.mu.RLock()
	data, err := json.Marshal(m.permissions)
	m.mu.RUnlock()

	if err != nil {
		return err
	}

	return m.redis.Set(ctx, m.cachePrefix+"manager:permissions", data, 0).Err()
}

// ClearAuthCache clears all authentication cache entries
func (m *Manager) ClearAuthCache(ctx context.Context) error {
	if m.redis == nil {
		return nil
	}

	keys, err := m.redis.Keys(ctx, m.cachePrefix+"*").Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return m.redis.Del(ctx, keys...).Err()
	}
	return nil
}

// GetStats returns authentication statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"users_count":       len(m.users),
		"permissions_count": len(m.permissions),
	}
}
