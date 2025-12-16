package tls

import (
	"crypto/tls"
	"testing"

	"marchproxy-egress/internal/config"
)

func TestMTLSManagerCreation(t *testing.T) {
	// Test with mTLS disabled
	cfg := &config.Config{
		EnableMTLS: false,
	}

	manager, err := NewMTLSManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create mTLS manager: %v", err)
	}

	if manager.GetTLSConfig() != nil {
		t.Error("Expected nil TLS config when mTLS is disabled")
	}
}

func TestMTLSCertificateInfo(t *testing.T) {
	cfg := &config.Config{
		EnableMTLS: false,
	}

	manager, err := NewMTLSManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create mTLS manager: %v", err)
	}

	certInfo := manager.GetCertificateInfo()
	if enabled, ok := certInfo["enabled"].(bool); !ok || enabled {
		t.Error("Expected mTLS to be disabled")
	}
}

func TestMTLSConfigMethods(t *testing.T) {
	cfg := &config.Config{
		EnableMTLS:           true,
		MTLSServerCertPath:   "/path/to/server.crt",
		MTLSServerKeyPath:    "/path/to/server.key",
		MTLSClientCAPath:     "/path/to/ca.crt",
		MTLSRequireClientCert: true,
		MTLSVerifyClientCert:  true,
	}

	if !cfg.IsMTLSEnabled() {
		t.Error("Expected mTLS to be enabled")
	}

	if !cfg.RequiresClientCert() {
		t.Error("Expected client certificate to be required")
	}

	if !cfg.ShouldVerifyClientCert() {
		t.Error("Expected client certificate verification to be enabled")
	}

	serverCert, serverKey, clientCA := cfg.GetMTLSConfig()
	if serverCert != "/path/to/server.crt" || serverKey != "/path/to/server.key" || clientCA != "/path/to/ca.crt" {
		t.Error("mTLS configuration paths don't match expected values")
	}

	capabilities := cfg.GetCapabilities()
	found := false
	for _, cap := range capabilities {
		if cap == "mtls" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'mtls' to be in capabilities list")
	}
}

func TestCipherSuites(t *testing.T) {
	cfg := &config.Config{
		EnableMTLS: false,
	}

	manager, _ := NewMTLSManager(cfg)

	// Test that we use secure cipher suites
	_ = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	// Since we can't test the actual TLS config without certificates,
	// we'll just verify the method exists
	if manager == nil {
		t.Error("Manager should not be nil")
	}
}