package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type MTLSAuthenticator struct {
	config      MTLSConfig
	tlsConfig   *tls.Config
	certPool    *x509.CertPool
	metrics     *MTLSMetrics
	mutex       sync.RWMutex
	initialized bool
}

type MTLSConfig struct {
	Enabled            bool
	RequireClientCert  bool
	ServerCertPath     string
	ServerKeyPath      string
	ClientCAPath       string
	ClientCABundle     []string
	AllowedCNs         []string
	AllowedOUs         []string
	VerifyClient       bool
	CRLPath            string
	OCSPEnabled        bool
	CertExpiredGrace   time.Duration
	MaxCertChainDepth  int
	CustomVerifyFunc   func(*x509.Certificate) error
}

type MTLSMetrics struct {
	SuccessfulAuths     uint64
	FailedAuths         uint64
	ExpiredCerts        uint64
	RevokedCerts        uint64
	InvalidCerts        uint64
	ClientCertMissing   uint64
	CAValidationErrors  uint64
	CertChainTooLong    uint64
	CustomValidationErr uint64
	AverageLatency      time.Duration
	mutex               sync.RWMutex
}

type MTLSMetricsSnapshot struct {
	SuccessfulAuths     uint64
	FailedAuths         uint64
	ExpiredCerts        uint64
	RevokedCerts        uint64
	InvalidCerts        uint64
	ClientCertMissing   uint64
	CAValidationErrors  uint64
	CertChainTooLong    uint64
	CustomValidationErr uint64
	AverageLatency      time.Duration
}

type ClientCertInfo struct {
	Subject            string
	Issuer             string
	CommonName         string
	OrganizationalUnit []string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	IsExpired          bool
	IsCA               bool
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []string
}

func NewMTLSAuthenticator(config MTLSConfig) (*MTLSAuthenticator, error) {
	if !config.Enabled {
		return &MTLSAuthenticator{
			config:      config,
			metrics:     &MTLSMetrics{},
			initialized: false,
		}, nil
	}

	auth := &MTLSAuthenticator{
		config:  config,
		metrics: &MTLSMetrics{},
	}

	if err := auth.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize mTLS authenticator: %w", err)
	}

	return auth, nil
}

func (m *MTLSAuthenticator) initialize() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.config.Enabled {
		m.initialized = true
		return nil
	}

	if m.config.ServerCertPath == "" || m.config.ServerKeyPath == "" {
		return fmt.Errorf("server certificate and key paths are required")
	}

	cert, err := tls.LoadX509KeyPair(m.config.ServerCertPath, m.config.ServerKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	m.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   false,
	}

	if m.config.RequireClientCert {
		if err := m.loadClientCAs(); err != nil {
			return fmt.Errorf("failed to load client CAs: %w", err)
		}
		m.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		m.tlsConfig.ClientCAs = m.certPool
	} else {
		m.tlsConfig.ClientAuth = tls.NoClientCert
	}

	if m.config.VerifyClient {
		m.tlsConfig.VerifyPeerCertificate = m.verifyClientCertificate
	}

	m.initialized = true
	logrus.Info("mTLS authenticator initialized successfully")
	return nil
}

func (m *MTLSAuthenticator) loadClientCAs() error {
	m.certPool = x509.NewCertPool()

	if m.config.ClientCAPath != "" {
		caCert, err := os.ReadFile(m.config.ClientCAPath)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate file: %w", err)
		}

		if !m.certPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		logrus.Infof("Loaded CA certificate from %s", m.config.ClientCAPath)
	}

	for i, caData := range m.config.ClientCABundle {
		if !m.certPool.AppendCertsFromPEM([]byte(caData)) {
			return fmt.Errorf("failed to parse CA certificate bundle entry %d", i)
		}
		logrus.Infof("Loaded CA certificate from bundle entry %d", i)
	}

	if len(m.certPool.Subjects()) == 0 {
		return fmt.Errorf("no valid CA certificates found")
	}

	return nil
}

func (m *MTLSAuthenticator) GetTLSConfig() *tls.Config {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if !m.initialized || !m.config.Enabled {
		return nil
	}

	return m.tlsConfig.Clone()
}

func (m *MTLSAuthenticator) AuthenticateRequest(r *http.Request) (*ClientCertInfo, error) {
	start := time.Now()
	defer m.updateMetrics(start)

	if !m.config.Enabled {
		return nil, nil
	}

	if !m.config.RequireClientCert {
		return nil, nil
	}

	if r.TLS == nil {
		m.metrics.recordFailure()
		return nil, fmt.Errorf("TLS connection required")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		m.metrics.recordClientCertMissing()
		return nil, fmt.Errorf("client certificate required")
	}

	clientCert := r.TLS.PeerCertificates[0]
	certInfo := m.extractCertInfo(clientCert)

	if err := m.validateClientCertificate(clientCert, r.TLS.PeerCertificates); err != nil {
		m.metrics.recordFailure()
		return certInfo, err
	}

	m.metrics.recordSuccess()
	return certInfo, nil
}

func (m *MTLSAuthenticator) verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		m.metrics.recordClientCertMissing()
		return fmt.Errorf("no client certificate provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		m.metrics.recordInvalidCert()
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	if len(verifiedChains) > 0 && len(verifiedChains[0]) > m.config.MaxCertChainDepth {
		m.metrics.recordCertChainTooLong()
		return fmt.Errorf("certificate chain too long: %d (max %d)", len(verifiedChains[0]), m.config.MaxCertChainDepth)
	}

	return m.validateClientCertificate(cert, nil)
}

func (m *MTLSAuthenticator) validateClientCertificate(cert *x509.Certificate, chain []*x509.Certificate) error {
	if time.Now().After(cert.NotAfter) {
		if m.config.CertExpiredGrace > 0 && time.Since(cert.NotAfter) <= m.config.CertExpiredGrace {
			logrus.Warnf("Accepting expired certificate within grace period: %s", cert.Subject)
		} else {
			m.metrics.recordExpiredCert()
			return fmt.Errorf("client certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
		}
	}

	if time.Now().Before(cert.NotBefore) {
		m.metrics.recordInvalidCert()
		return fmt.Errorf("client certificate not yet valid until %s", cert.NotBefore.Format(time.RFC3339))
	}

	if len(m.config.AllowedCNs) > 0 {
		allowed := false
		for _, allowedCN := range m.config.AllowedCNs {
			if cert.Subject.CommonName == allowedCN {
				allowed = true
				break
			}
		}
		if !allowed {
			m.metrics.recordInvalidCert()
			return fmt.Errorf("client certificate CN '%s' not in allowed list", cert.Subject.CommonName)
		}
	}

	if len(m.config.AllowedOUs) > 0 {
		allowed := false
		for _, certOU := range cert.Subject.OrganizationalUnit {
			for _, allowedOU := range m.config.AllowedOUs {
				if certOU == allowedOU {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			m.metrics.recordInvalidCert()
			return fmt.Errorf("client certificate OU not in allowed list")
		}
	}

	if m.config.CustomVerifyFunc != nil {
		if err := m.config.CustomVerifyFunc(cert); err != nil {
			m.metrics.recordCustomValidationError()
			return fmt.Errorf("custom certificate validation failed: %w", err)
		}
	}

	return nil
}

func (m *MTLSAuthenticator) extractCertInfo(cert *x509.Certificate) *ClientCertInfo {
	return &ClientCertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		CommonName:         cert.Subject.CommonName,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsExpired:          time.Now().After(cert.NotAfter),
		IsCA:               cert.IsCA,
		KeyUsage:           cert.KeyUsage,
		ExtKeyUsage:        cert.ExtKeyUsage,
		DNSNames:           cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
	}
}

func (m *MTLSAuthenticator) Reload() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.config.Enabled {
		return nil
	}

	logrus.Info("Reloading mTLS configuration")

	cert, err := tls.LoadX509KeyPair(m.config.ServerCertPath, m.config.ServerKeyPath)
	if err != nil {
		return fmt.Errorf("failed to reload server certificate: %w", err)
	}

	m.tlsConfig.Certificates = []tls.Certificate{cert}

	if m.config.RequireClientCert {
		if err := m.loadClientCAs(); err != nil {
			return fmt.Errorf("failed to reload client CAs: %w", err)
		}
		m.tlsConfig.ClientCAs = m.certPool
	}

	logrus.Info("mTLS configuration reloaded successfully")
	return nil
}

func (m *MTLSAuthenticator) GetMetrics() MTLSMetricsSnapshot {
	m.metrics.mutex.RLock()
	defer m.metrics.mutex.RUnlock()
	return MTLSMetricsSnapshot{
		SuccessfulAuths:     m.metrics.SuccessfulAuths,
		FailedAuths:         m.metrics.FailedAuths,
		ExpiredCerts:        m.metrics.ExpiredCerts,
		RevokedCerts:        m.metrics.RevokedCerts,
		InvalidCerts:        m.metrics.InvalidCerts,
		ClientCertMissing:   m.metrics.ClientCertMissing,
		CAValidationErrors:  m.metrics.CAValidationErrors,
		CertChainTooLong:    m.metrics.CertChainTooLong,
		CustomValidationErr: m.metrics.CustomValidationErr,
		AverageLatency:      m.metrics.AverageLatency,
	}
}

func (m *MTLSAuthenticator) updateMetrics(start time.Time) {
	duration := time.Since(start)
	m.metrics.mutex.Lock()
	defer m.metrics.mutex.Unlock()

	totalRequests := m.metrics.SuccessfulAuths + m.metrics.FailedAuths
	if totalRequests > 0 {
		m.metrics.AverageLatency = (m.metrics.AverageLatency*time.Duration(totalRequests-1) + duration) / time.Duration(totalRequests)
	} else {
		m.metrics.AverageLatency = duration
	}
}

func (m *MTLSMetrics) recordSuccess() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.SuccessfulAuths++
}

func (m *MTLSMetrics) recordFailure() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.FailedAuths++
}

func (m *MTLSMetrics) recordExpiredCert() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.ExpiredCerts++
	m.FailedAuths++
}

func (m *MTLSMetrics) recordRevokedCert() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.RevokedCerts++
	m.FailedAuths++
}

func (m *MTLSMetrics) recordInvalidCert() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.InvalidCerts++
	m.FailedAuths++
}

func (m *MTLSMetrics) recordClientCertMissing() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.ClientCertMissing++
	m.FailedAuths++
}

func (m *MTLSMetrics) recordCAValidationError() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.CAValidationErrors++
	m.FailedAuths++
}

func (m *MTLSMetrics) recordCertChainTooLong() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.CertChainTooLong++
	m.FailedAuths++
}

func (m *MTLSMetrics) recordCustomValidationError() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.CustomValidationErr++
	m.FailedAuths++
}