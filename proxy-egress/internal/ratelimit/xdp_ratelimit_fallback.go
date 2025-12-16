// +build !xdp

package ratelimit

import (
	"fmt"
	"net"

	"marchproxy-egress/internal/logging"
	"marchproxy-egress/internal/metrics"
)

// XDPRateLimiter fallback implementation for systems without XDP support
type XDPRateLimiter struct {
	logger  logging.Logger
	metrics metrics.Collector
}

// NewXDPRateLimiter creates a new fallback XDP rate limiter
func NewXDPRateLimiter(logger logging.Logger, metricsCollector metrics.Collector) *XDPRateLimiter {
	logger.Warn("XDP support not available, rate limiting will be disabled")
	return &XDPRateLimiter{
		logger:  logger,
		metrics: metricsCollector,
	}
}

// LoadProgram is a no-op in fallback mode
func (rl *XDPRateLimiter) LoadProgram(programPath string) error {
	return fmt.Errorf("XDP not supported in this build")
}

// AttachToInterface is a no-op in fallback mode
func (rl *XDPRateLimiter) AttachToInterface(interfaceName string) error {
	return fmt.Errorf("XDP not supported in this build")
}

// DetachFromInterface is a no-op in fallback mode
func (rl *XDPRateLimiter) DetachFromInterface(interfaceName string) error {
	return fmt.Errorf("XDP not supported in this build")
}

// UpdateConfig is a no-op in fallback mode
func (rl *XDPRateLimiter) UpdateConfig(config *RateLimiterConfig) error {
	rl.logger.Warn("XDP rate limiting not available, configuration ignored")
	return nil
}

// SetEnterpriseLicense is a no-op in fallback mode
func (rl *XDPRateLimiter) SetEnterpriseLicense(enabled bool) error {
	return nil
}

// GetStats returns empty stats in fallback mode
func (rl *XDPRateLimiter) GetStats() (*RateLimitMetrics, error) {
	return &RateLimitMetrics{}, nil
}

// GetIPState returns nil in fallback mode
func (rl *XDPRateLimiter) GetIPState(ip net.IP) (*ClientLimiter, error) {
	return nil, fmt.Errorf("XDP not supported in this build")
}

// ClearIPState is a no-op in fallback mode
func (rl *XDPRateLimiter) ClearIPState(ip net.IP) error {
	return fmt.Errorf("XDP not supported in this build")
}

// Close is a no-op in fallback mode
func (rl *XDPRateLimiter) Close() error {
	return nil
}

// IsEnabled always returns false in fallback mode
func (rl *XDPRateLimiter) IsEnabled() bool {
	return false
}

// GetAttachedInterfaces returns empty list in fallback mode
func (rl *XDPRateLimiter) GetAttachedInterfaces() []string {
	return []string{}
}

// GetConfig returns nil in fallback mode
func (rl *XDPRateLimiter) GetConfig() *RateLimiterConfig {
	return nil
}