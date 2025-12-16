package auth

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestBase64TokenValidation tests Base64 token authentication without external dependencies
func TestBase64TokenValidation(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		validTokens []string
		expected    bool
	}{
		{
			name:        "Valid token",
			token:       "dGVzdC10b2tlbi0xMjM=", // base64 encoded "test-token-123"
			validTokens: []string{"dGVzdC10b2tlbi0xMjM=", "b3RoZXItdG9rZW4="},
			expected:    true,
		},
		{
			name:        "Invalid token",
			token:       "aW52YWxpZC10b2tlbg==", // base64 encoded "invalid-token"
			validTokens: []string{"dGVzdC10b2tlbi0xMjM=", "b3RoZXItdG9rZW4="},
			expected:    false,
		},
		{
			name:        "Empty token",
			token:       "",
			validTokens: []string{"dGVzdC10b2tlbi0xMjM="},
			expected:    false,
		},
		{
			name:        "Malformed base64",
			token:       "not-base64!@#",
			validTokens: []string{"dGVzdC10b2tlbi0xMjM="},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateBase64Token(tt.token, tt.validTokens)
			if result != tt.expected {
				t.Errorf("validateBase64Token() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestJWTTokenValidation tests JWT token authentication without external dependencies
func TestJWTTokenValidation(t *testing.T) {
	secret := "test-secret-key-for-jwt-validation"

	// Create a valid JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"service_id":   1,
		"service_name": "test-service",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour).Unix(),
	})

	validTokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Create an expired token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"service_id":   1,
		"service_name": "test-service",
		"iat":          time.Now().Add(-2 * time.Hour).Unix(),
		"exp":          time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	})

	expiredTokenString, err := expiredToken.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create expired test token: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		secret    string
		expected  bool
		expectErr bool
	}{
		{
			name:      "Valid JWT token",
			token:     validTokenString,
			secret:    secret,
			expected:  true,
			expectErr: false,
		},
		{
			name:      "Invalid secret",
			token:     validTokenString,
			secret:    "wrong-secret",
			expected:  false,
			expectErr: true,
		},
		{
			name:      "Expired token",
			token:     expiredTokenString,
			secret:    secret,
			expected:  false,
			expectErr: true,
		},
		{
			name:      "Malformed token",
			token:     "invalid.jwt.token",
			secret:    secret,
			expected:  false,
			expectErr: true,
		},
		{
			name:      "Empty token",
			token:     "",
			secret:    secret,
			expected:  false,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateJWTToken(tt.token, tt.secret)

			if tt.expectErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("validateJWTToken() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestExtractTokenFromRequest tests token extraction from HTTP headers
func TestExtractTokenFromRequest(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedToken  string
		expectedScheme string
		expectError    bool
	}{
		{
			name:           "Bearer token",
			authHeader:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedScheme: "Bearer",
			expectError:    false,
		},
		{
			name:           "Basic token",
			authHeader:     "Basic dGVzdDp0b2tlbg==",
			expectedToken:  "dGVzdDp0b2tlbg==",
			expectedScheme: "Basic",
			expectError:    false,
		},
		{
			name:           "No space separator",
			authHeader:     "BearereyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken:  "",
			expectedScheme: "",
			expectError:    true,
		},
		{
			name:           "Empty header",
			authHeader:     "",
			expectedToken:  "",
			expectedScheme: "",
			expectError:    true,
		},
		{
			name:           "Only scheme",
			authHeader:     "Bearer",
			expectedToken:  "",
			expectedScheme: "",
			expectError:    true,
		},
		{
			name:           "Multiple spaces",
			authHeader:     "Bearer   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedScheme: "Bearer",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, token, err := extractTokenFromHeader(tt.authHeader)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if scheme != tt.expectedScheme {
				t.Errorf("extractTokenFromHeader() scheme = %v, want %v", scheme, tt.expectedScheme)
			}
			if token != tt.expectedToken {
				t.Errorf("extractTokenFromHeader() token = %v, want %v", token, tt.expectedToken)
			}
		})
	}
}

// Helper functions that would be implemented in the actual auth package

func validateBase64Token(token string, validTokens []string) bool {
	if token == "" {
		return false
	}

	// Try to decode the token to ensure it's valid base64
	_, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	// Check if token is in the list of valid tokens
	for _, validToken := range validTokens {
		if token == validToken {
			return true
		}
	}
	return false
}

func validateJWTToken(tokenString, secret string) (bool, error) {
	if tokenString == "" {
		return false, jwt.ErrTokenMalformed
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}

func extractTokenFromHeader(authHeader string) (string, string, error) {
	if authHeader == "" {
		return "", "", jwt.ErrTokenMalformed
	}

	// Split by space to separate scheme and token
	parts := make([]string, 0, 2)
	current := ""

	for _, char := range authHeader {
		if char == ' ' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	if len(parts) != 2 {
		return "", "", jwt.ErrTokenMalformed
	}

	return parts[0], parts[1], nil
}

// TestServiceConfiguration tests service configuration validation
func TestServiceConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		config    ServiceConfig
		expectErr bool
	}{
		{
			name: "Valid token-based service",
			config: ServiceConfig{
				ID:       1,
				Name:     "test-service",
				AuthType: "token",
				Token:    "dGVzdC10b2tlbg==",
			},
			expectErr: false,
		},
		{
			name: "Valid JWT-based service",
			config: ServiceConfig{
				ID:        2,
				Name:      "jwt-service",
				AuthType:  "jwt",
				JWTSecret: "secret-key-123",
			},
			expectErr: false,
		},
		{
			name: "Invalid auth type",
			config: ServiceConfig{
				ID:       3,
				Name:     "invalid-service",
				AuthType: "oauth",
			},
			expectErr: true,
		},
		{
			name: "Missing token for token auth",
			config: ServiceConfig{
				ID:       4,
				Name:     "no-token-service",
				AuthType: "token",
			},
			expectErr: true,
		},
		{
			name: "Missing JWT secret for JWT auth",
			config: ServiceConfig{
				ID:       5,
				Name:     "no-jwt-service",
				AuthType: "jwt",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServiceConfig(tt.config)

			if tt.expectErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// ServiceConfig represents a service configuration for testing
type ServiceConfig struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	AuthType  string `json:"auth_type"`
	Token     string `json:"token,omitempty"`
	JWTSecret string `json:"jwt_secret,omitempty"`
}

func validateServiceConfig(config ServiceConfig) error {
	if config.Name == "" {
		return jwt.ErrTokenMalformed
	}

	switch config.AuthType {
	case "token":
		if config.Token == "" {
			return jwt.ErrTokenMalformed
		}
	case "jwt":
		if config.JWTSecret == "" {
			return jwt.ErrTokenMalformed
		}
	default:
		return jwt.ErrTokenMalformed
	}

	return nil
}