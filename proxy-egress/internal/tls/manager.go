package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

type TLSManager struct {
	config           TLSConfig
	certificates     map[string]*tls.Certificate
	clientCAs        *x509.CertPool
	rootCAs          *x509.CertPool
	ocspCache        *OCSPCache
	sessionCache     *SessionCache
	certRotator      *CertificateRotator
	mutex            sync.RWMutex
	metrics          *TLSMetrics
	acmeManager      *ACMEManager
}

type TLSConfig struct {
	EnableTLS              bool
	EnableMTLS             bool
	CertFile               string
	KeyFile                string
	CAFile                 string
	ClientCAFile           string
	Certificates           map[string]CertificateConfig
	MinVersion             uint16
	MaxVersion             uint16
	CipherSuites           []uint16
	CurvePreferences       []tls.CurveID
	PreferServerCiphers    bool
	SessionTicketsDisabled bool
	SessionCacheSize       int
	ClientAuth             tls.ClientAuthType
	EnableOCSP             bool
	OCSPStapling           bool
	EnableACME             bool
	ACMEDirectory          string
	ACMEEmail              string
	AutoCertDomains        []string
	CertRotationInterval   time.Duration
	EnableHSTS             bool
	HSTSMaxAge             time.Duration
	HSTSIncludeSubdomains  bool
	HSTSPreload            bool
}

type CertificateConfig struct {
	CertFile    string
	KeyFile     string
	Domains     []string
	NotBefore   time.Time
	NotAfter    time.Time
	AutoRenew   bool
	RenewBefore time.Duration
}

type OCSPCache struct {
	responses map[string]*OCSPResponse
	mutex     sync.RWMutex
	ttl       time.Duration
}

type OCSPResponse struct {
	Response   []byte
	NextUpdate time.Time
	Status     int
}

type SessionCache struct {
	sessions map[string]*SessionData
	mutex    sync.RWMutex
	maxSize  int
	ttl      time.Duration
}

type SessionData struct {
	SessionID   []byte
	Certificate []byte
	CreatedAt   time.Time
	LastUsed    time.Time
	UseCount    int
}

type CertificateRotator struct {
	manager       *TLSManager
	interval      time.Duration
	renewBefore   time.Duration
	stopChan      chan struct{}
	running       bool
	mutex         sync.Mutex
}

type ACMEManager struct {
	directory    string
	email        string
	domains      []string
	client       ACMEClient
	challenges   map[string]string
	mutex        sync.RWMutex
}

type ACMEClient interface {
	Register(email string) error
	ObtainCertificate(domains []string) (*tls.Certificate, error)
	RenewCertificate(cert *tls.Certificate) (*tls.Certificate, error)
	GetChallenge(domain string) (string, error)
	CompleteChallenge(domain string, token string) error
}

type TLSMetrics struct {
	Handshakes          uint64
	HandshakeErrors     uint64
	ClientCertProvided  uint64
	ClientCertValid     uint64
	ClientCertInvalid   uint64
	OCSPRequests        uint64
	OCSPCacheHits       uint64
	SessionResumptions  uint64
	CertRotations       uint64
	ACMECertObtained    uint64
	ACMECertRenewed     uint64
	mutex               sync.RWMutex
}

func NewTLSManager(config TLSConfig) (*TLSManager, error) {
	tm := &TLSManager{
		config:       config,
		certificates: make(map[string]*tls.Certificate),
		metrics:      &TLSMetrics{},
	}

	if err := tm.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize TLS manager: %w", err)
	}

	return tm, nil
}

func (tm *TLSManager) initialize() error {
	if tm.config.CertFile != "" && tm.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tm.config.CertFile, tm.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		tm.certificates["default"] = &cert
	}

	for name, certConfig := range tm.config.Certificates {
		cert, err := tls.LoadX509KeyPair(certConfig.CertFile, certConfig.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate %s: %w", name, err)
		}
		tm.certificates[name] = &cert
		
		for _, domain := range certConfig.Domains {
			tm.certificates[domain] = &cert
		}
	}

	if tm.config.CAFile != "" {
		tm.rootCAs = x509.NewCertPool()
	}

	if tm.config.EnableMTLS && tm.config.ClientCAFile != "" {
		tm.clientCAs = x509.NewCertPool()
	}

	if tm.config.EnableOCSP {
		tm.ocspCache = NewOCSPCache(24 * time.Hour)
	}

	if tm.config.SessionCacheSize > 0 {
		tm.sessionCache = NewSessionCache(tm.config.SessionCacheSize, 24*time.Hour)
	}

	if tm.config.CertRotationInterval > 0 {
		tm.certRotator = NewCertificateRotator(tm, tm.config.CertRotationInterval)
		tm.certRotator.Start()
	}

	if tm.config.EnableACME {
		tm.acmeManager = NewACMEManager(
			tm.config.ACMEDirectory,
			tm.config.ACMEEmail,
			tm.config.AutoCertDomains,
		)
		
		if err := tm.acmeManager.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize ACME manager: %w", err)
		}
	}

	return nil
}

func (tm *TLSManager) GetTLSConfig() *tls.Config {
	config := &tls.Config{
		GetCertificate:         tm.getCertificate,
		GetClientCertificate:   tm.getClientCertificate,
		VerifyPeerCertificate:  tm.verifyPeerCertificate,
		MinVersion:             tm.config.MinVersion,
		MaxVersion:             tm.config.MaxVersion,
		CipherSuites:           tm.config.CipherSuites,
		CurvePreferences:       tm.config.CurvePreferences,
		PreferServerCipherSuites: tm.config.PreferServerCiphers,
		SessionTicketsDisabled: tm.config.SessionTicketsDisabled,
	}

	if tm.config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}

	if tm.config.MaxVersion == 0 {
		config.MaxVersion = tls.VersionTLS13
	}

	if len(tm.config.CipherSuites) == 0 {
		config.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}
	}

	if tm.config.EnableMTLS {
		config.ClientAuth = tm.config.ClientAuth
		if config.ClientAuth == 0 {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
		config.ClientCAs = tm.clientCAs
	}

	if tm.rootCAs != nil {
		config.RootCAs = tm.rootCAs
	}

	// SessionCache was removed from crypto/tls in Go 1.23+
	// if tm.sessionCache != nil {
	//	config.SessionCache = tm.sessionCache
	// }

	return config
}

func (tm *TLSManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tm.metrics.recordHandshake()

	serverName := hello.ServerName
	if serverName == "" {
		serverName = "default"
	}

	tm.mutex.RLock()
	cert, exists := tm.certificates[serverName]
	tm.mutex.RUnlock()

	if exists {
		if tm.shouldRotateCertificate(cert) {
			newCert, err := tm.rotateCertificate(serverName)
			if err == nil {
				cert = newCert
			}
		}
		return cert, nil
	}

	if tm.config.EnableACME && tm.acmeManager != nil {
		cert, err := tm.acmeManager.GetOrObtainCertificate(serverName)
		if err == nil {
			tm.mutex.Lock()
			tm.certificates[serverName] = cert
			tm.mutex.Unlock()
			tm.metrics.recordACMEObtained()
			return cert, nil
		}
	}

	tm.mutex.RLock()
	defaultCert, exists := tm.certificates["default"]
	tm.mutex.RUnlock()

	if exists {
		return defaultCert, nil
	}

	tm.metrics.recordHandshakeError()
	return nil, errors.New("no certificate available")
}

func (tm *TLSManager) getClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	for _, cert := range tm.certificates {
		if tm.certificateMatchesRequest(cert, info) {
			return cert, nil
		}
	}

	return nil, errors.New("no suitable client certificate")
}

func (tm *TLSManager) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		tm.metrics.recordClientCertInvalid()
		return errors.New("no client certificate provided")
	}

	tm.metrics.recordClientCertProvided()

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		tm.metrics.recordClientCertInvalid()
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if tm.config.EnableOCSP {
		if err := tm.verifyOCSP(cert); err != nil {
			tm.metrics.recordClientCertInvalid()
			return fmt.Errorf("OCSP verification failed: %w", err)
		}
	}

	if err := tm.verifyCustomRules(cert); err != nil {
		tm.metrics.recordClientCertInvalid()
		return err
	}

	tm.metrics.recordClientCertValid()
	return nil
}

func (tm *TLSManager) shouldRotateCertificate(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	renewBefore := 30 * 24 * time.Hour
	for _, config := range tm.config.Certificates {
		if config.RenewBefore > 0 {
			renewBefore = config.RenewBefore
			break
		}
	}

	return time.Until(x509Cert.NotAfter) < renewBefore
}

func (tm *TLSManager) rotateCertificate(serverName string) (*tls.Certificate, error) {
	if tm.config.EnableACME && tm.acmeManager != nil {
		oldCert := tm.certificates[serverName]
		newCert, err := tm.acmeManager.RenewCertificate(oldCert)
		if err != nil {
			return nil, err
		}

		tm.mutex.Lock()
		tm.certificates[serverName] = newCert
		tm.mutex.Unlock()

		tm.metrics.recordCertRotation()
		tm.metrics.recordACMERenewed()

		return newCert, nil
	}

	return nil, errors.New("certificate rotation not available")
}

func (tm *TLSManager) certificateMatchesRequest(cert *tls.Certificate, info *tls.CertificateRequestInfo) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	for _, acceptedCA := range info.AcceptableCAs {
		if x509Cert.Issuer.String() == string(acceptedCA) {
			return true
		}
	}

	return false
}

func (tm *TLSManager) verifyOCSP(cert *x509.Certificate) error {
	tm.metrics.recordOCSPRequest()

	if tm.ocspCache != nil {
		if response := tm.ocspCache.Get(cert.SerialNumber.String()); response != nil {
			tm.metrics.recordOCSPCacheHit()
			if response.Status == 0 {
				return nil
			}
			return fmt.Errorf("certificate revoked: OCSP status %d", response.Status)
		}
	}

	return nil
}

func (tm *TLSManager) verifyCustomRules(cert *x509.Certificate) error {
	now := time.Now()
	
	if now.Before(cert.NotBefore) {
		return errors.New("certificate not yet valid")
	}
	
	if now.After(cert.NotAfter) {
		return errors.New("certificate expired")
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate not valid for digital signature")
	}

	return nil
}

func (tm *TLSManager) GenerateSelfSignedCertificate(hosts []string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"MarchProxy"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, nil
}

func NewOCSPCache(ttl time.Duration) *OCSPCache {
	oc := &OCSPCache{
		responses: make(map[string]*OCSPResponse),
		ttl:       ttl,
	}
	
	go oc.startCleanup()
	return oc
}

func (oc *OCSPCache) Get(serial string) *OCSPResponse {
	oc.mutex.RLock()
	defer oc.mutex.RUnlock()
	
	response, exists := oc.responses[serial]
	if !exists {
		return nil
	}
	
	if time.Now().After(response.NextUpdate) {
		return nil
	}
	
	return response
}

func (oc *OCSPCache) Set(serial string, response *OCSPResponse) {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	oc.responses[serial] = response
}

func (oc *OCSPCache) startCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		oc.cleanup()
	}
}

func (oc *OCSPCache) cleanup() {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	
	now := time.Now()
	for serial, response := range oc.responses {
		if now.After(response.NextUpdate) {
			delete(oc.responses, serial)
		}
	}
}

func NewSessionCache(maxSize int, ttl time.Duration) *SessionCache {
	return &SessionCache{
		sessions: make(map[string]*SessionData),
		maxSize:  maxSize,
		ttl:      ttl,
	}
}

func (sc *SessionCache) Get(sessionKey string) ([]byte, bool) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	
	session, exists := sc.sessions[sessionKey]
	if !exists {
		return nil, false
	}
	
	if time.Since(session.CreatedAt) > sc.ttl {
		return nil, false
	}
	
	session.LastUsed = time.Now()
	session.UseCount++
	
	return session.SessionID, true
}

func (sc *SessionCache) Put(sessionKey string, cs *tls.ConnectionState) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	
	if len(sc.sessions) >= sc.maxSize {
		sc.evictOldest()
	}
	
	sc.sessions[sessionKey] = &SessionData{
		SessionID:   []byte(sessionKey),
		CreatedAt:   time.Now(),
		LastUsed:    time.Now(),
		UseCount:    1,
	}
}

func (sc *SessionCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, session := range sc.sessions {
		if oldestTime.IsZero() || session.LastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = session.LastUsed
		}
	}
	
	if oldestKey != "" {
		delete(sc.sessions, oldestKey)
	}
}

func NewCertificateRotator(manager *TLSManager, interval time.Duration) *CertificateRotator {
	return &CertificateRotator{
		manager:     manager,
		interval:    interval,
		renewBefore: 30 * 24 * time.Hour,
		stopChan:    make(chan struct{}),
	}
}

func (cr *CertificateRotator) Start() {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()
	
	if cr.running {
		return
	}
	
	cr.running = true
	go cr.run()
}

func (cr *CertificateRotator) Stop() {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()
	
	if !cr.running {
		return
	}
	
	cr.running = false
	close(cr.stopChan)
}

func (cr *CertificateRotator) run() {
	ticker := time.NewTicker(cr.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cr.checkAndRotateCertificates()
		case <-cr.stopChan:
			return
		}
	}
}

func (cr *CertificateRotator) checkAndRotateCertificates() {
	cr.manager.mutex.RLock()
	certificates := make(map[string]*tls.Certificate)
	for k, v := range cr.manager.certificates {
		certificates[k] = v
	}
	cr.manager.mutex.RUnlock()
	
	for name, cert := range certificates {
		if cr.manager.shouldRotateCertificate(cert) {
			cr.manager.rotateCertificate(name)
		}
	}
}

func NewACMEManager(directory, email string, domains []string) *ACMEManager {
	return &ACMEManager{
		directory:  directory,
		email:      email,
		domains:    domains,
		challenges: make(map[string]string),
	}
}

func (am *ACMEManager) Initialize() error {
	return nil
}

func (am *ACMEManager) GetOrObtainCertificate(domain string) (*tls.Certificate, error) {
	return nil, errors.New("ACME not implemented in this example")
}

func (am *ACMEManager) RenewCertificate(cert *tls.Certificate) (*tls.Certificate, error) {
	return nil, errors.New("ACME renewal not implemented in this example")
}

func (tm *TLSMetrics) recordHandshake() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.Handshakes++
}

func (tm *TLSMetrics) recordHandshakeError() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.HandshakeErrors++
}

func (tm *TLSMetrics) recordClientCertProvided() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.ClientCertProvided++
}

func (tm *TLSMetrics) recordClientCertValid() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.ClientCertValid++
}

func (tm *TLSMetrics) recordClientCertInvalid() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.ClientCertInvalid++
}

func (tm *TLSMetrics) recordOCSPRequest() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.OCSPRequests++
}

func (tm *TLSMetrics) recordOCSPCacheHit() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.OCSPCacheHits++
}

func (tm *TLSMetrics) recordSessionResumption() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.SessionResumptions++
}

func (tm *TLSMetrics) recordCertRotation() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.CertRotations++
}

func (tm *TLSMetrics) recordACMEObtained() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.ACMECertObtained++
}

func (tm *TLSMetrics) recordACMERenewed() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.ACMECertRenewed++
}