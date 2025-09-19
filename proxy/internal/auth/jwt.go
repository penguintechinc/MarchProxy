package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token expired")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrMissingToken      = errors.New("missing token")
	ErrInvalidClaims     = errors.New("invalid claims")
)

// JWTClaims represents the JWT claims structure from manager
type JWTClaims struct {
	ServiceID   int    `json:"service_id"`
	ServiceName string `json:"service_name"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	jwt.RegisteredClaims
}

// Valid validates the claims (required by jwt.Claims interface)
func (c JWTClaims) Valid() error {
	if c.ExpiresAt > 0 && time.Now().Unix() > c.ExpiresAt {
		return ErrTokenExpired
	}
	return nil
}

// ValidateJWTToken validates a JWT token using the provided secret
// This is called by the proxy with service configuration from manager
func ValidateJWTToken(tokenString, secret string, expectedServiceID int) (*JWTClaims, error) {
	if secret == "" {
		return nil, fmt.Errorf("no JWT secret provided")
	}

	// Parse token with claims
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, ErrTokenExpired
			}
			if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, ErrInvalidSignature
			}
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	// Validate service ID matches
	if claims.ServiceID != expectedServiceID {
		return nil, fmt.Errorf("service ID mismatch: expected %d, got %d", expectedServiceID, claims.ServiceID)
	}

	// Additional expiration check (redundant but explicit)
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// GenerateJWTToken generates a JWT token for testing/development
func GenerateJWTToken(serviceID int, serviceName, secret string, expiryDuration time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("no JWT secret provided")
	}

	now := time.Now().Unix()
	expiry := now + int64(expiryDuration.Seconds())

	claims := JWTClaims{
		ServiceID:   serviceID,
		ServiceName: serviceName,
		IssuedAt:    now,
		ExpiresAt:   expiry,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Unix(now, 0)),
			ExpiresAt: jwt.NewNumericDate(time.Unix(expiry, 0)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingToken
	}

	// Remove "Bearer " prefix if present
	const bearerPrefix = "Bearer "
	if strings.HasPrefix(authHeader, bearerPrefix) {
		return strings.TrimSpace(authHeader[len(bearerPrefix):]), nil
	}

	// Return the header value as-is if no Bearer prefix
	return strings.TrimSpace(authHeader), nil
}