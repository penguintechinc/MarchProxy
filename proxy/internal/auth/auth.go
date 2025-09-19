package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/penguintech/marchproxy/internal/manager"
)

// AuthType represents the type of authentication
type AuthType string

const (
	AuthTypeBase64 AuthType = "base64"
	AuthTypeJWT    AuthType = "jwt"
	AuthTypeNone   AuthType = "none"
)

// BasicJWTClaims represents basic JWT token claims for service authentication
type BasicJWTClaims struct {
	ServiceID int    `json:"service_id"`
	ServiceName string `json:"service_name"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// Authenticator handles authentication for proxy connections
type Authenticator struct {
	services map[int]*manager.Service
}

// NewAuthenticator creates a new authenticator with service configuration
func NewAuthenticator(services []manager.Service) *Authenticator {
	serviceMap := make(map[int]*manager.Service)
	for i := range services {
		serviceMap[services[i].ID] = &services[i]
	}
	
	return &Authenticator{
		services: serviceMap,
	}
}

// AuthenticateService authenticates a service using the provided credentials
func (a *Authenticator) AuthenticateService(serviceID int, token string) error {
	service, exists := a.services[serviceID]
	if !exists {
		return fmt.Errorf("service %d not found", serviceID)
	}
	
	switch AuthType(service.AuthType) {
	case AuthTypeBase64:
		return a.validateBase64Token(service, token)
	case AuthTypeJWT:
		return a.validateJWTToken(service, token)
	case AuthTypeNone:
		return nil // No authentication required
	default:
		return fmt.Errorf("unsupported auth type: %s", service.AuthType)
	}
}

// validateBase64Token validates a Base64 encoded token
func (a *Authenticator) validateBase64Token(service *manager.Service, token string) error {
	if service.AuthToken == "" {
		return fmt.Errorf("no Base64 token configured for service %s", service.Name)
	}
	
	// Simple constant-time comparison
	expectedToken := service.AuthToken
	if len(token) != len(expectedToken) {
		return fmt.Errorf("invalid token length for service %s", service.Name)
	}
	
	// Use HMAC for constant-time comparison
	h1 := hmac.New(sha256.New, []byte("comparison"))
	h1.Write([]byte(token))
	mac1 := h1.Sum(nil)
	
	h2 := hmac.New(sha256.New, []byte("comparison"))
	h2.Write([]byte(expectedToken))
	mac2 := h2.Sum(nil)
	
	if !hmac.Equal(mac1, mac2) {
		return fmt.Errorf("invalid Base64 token for service %s", service.Name)
	}
	
	return nil
}

// validateJWTToken validates a JWT token using the simplified JWT validation
func (a *Authenticator) validateJWTToken(service *manager.Service, token string) error {
	if service.JWTSecret == "" {
		return fmt.Errorf("no JWT secret configured for service %s", service.Name)
	}

	// Use the simplified JWT validation from jwt.go
	_, err := ValidateJWTToken(token, service.JWTSecret, service.ID)
	if err != nil {
		return fmt.Errorf("JWT validation failed for service %s: %w", service.Name, err)
	}

	return nil
}


// UpdateServices updates the authenticator with new service configuration
func (a *Authenticator) UpdateServices(services []manager.Service) {
	serviceMap := make(map[int]*manager.Service)
	for i := range services {
		serviceMap[services[i].ID] = &services[i]
	}
	
	a.services = serviceMap
}

// GetServiceAuthType returns the authentication type for a service
func (a *Authenticator) GetServiceAuthType(serviceID int) (AuthType, error) {
	service, exists := a.services[serviceID]
	if !exists {
		return AuthTypeNone, fmt.Errorf("service %d not found", serviceID)
	}
	
	return AuthType(service.AuthType), nil
}

// GenerateJWTToken generates a JWT token for testing purposes
func (a *Authenticator) GenerateJWTToken(serviceID int) (string, error) {
	service, exists := a.services[serviceID]
	if !exists {
		return "", fmt.Errorf("service %d not found", serviceID)
	}

	if service.JWTSecret == "" {
		return "", fmt.Errorf("no JWT secret configured for service %s", service.Name)
	}

	// Default expiry duration
	expiryDuration := time.Hour
	if service.JWTExpiry > 0 {
		expiryDuration = time.Duration(service.JWTExpiry) * time.Second
	}

	// Use the simplified JWT generation from jwt.go
	return GenerateJWTToken(service.ID, service.Name, service.JWTSecret, expiryDuration)
}