package pool

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
)

// SQLPool manages database/sql connections for database protocols
type SQLPool struct {
	db          *sql.DB
	protocol    string
	dsn         string
	maxConns    int
	maxIdle     int
	maxLifetime time.Duration
	logger      *logrus.Logger
	mu          sync.RWMutex
}

// NewSQLPool creates a new SQL connection pool
func NewSQLPool(protocol, dsn string, maxConns int, logger *logrus.Logger) (*SQLPool, error) {
	// Determine driver based on protocol
	driver := protocol
	if protocol == "galera" {
		driver = "mysql"
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns / 2)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	pool := &SQLPool{
		db:          db,
		protocol:    protocol,
		dsn:         dsn,
		maxConns:    maxConns,
		maxIdle:     maxConns / 2,
		maxLifetime: 30 * time.Minute,
		logger:      logger,
	}

	logger.WithFields(logrus.Fields{
		"protocol":  protocol,
		"max_conns": maxConns,
		"max_idle":  pool.maxIdle,
		"driver":    driver,
	}).Info("SQL connection pool created")

	return pool, nil
}

// Get retrieves a connection from the pool
func (p *SQLPool) Get() (*sql.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}

	return conn, nil
}

// GetWithContext retrieves a connection from the pool with context
func (p *SQLPool) GetWithContext(ctx context.Context) (*sql.Conn, error) {
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection: %w", err)
	}

	return conn, nil
}

// Close closes the connection pool
func (p *SQLPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		p.logger.WithField("protocol", p.protocol).Info("Closing SQL connection pool")
		return p.db.Close()
	}

	return nil
}

// GetDB returns the underlying sql.DB for advanced operations
func (p *SQLPool) GetDB() *sql.DB {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.db
}

// Ping checks if the database is accessible
func (p *SQLPool) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// Stats returns pool statistics
func (p *SQLPool) Stats() sql.DBStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.db.Stats()
}

// SetMaxOpenConns sets the maximum number of open connections
func (p *SQLPool) SetMaxOpenConns(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = n
	p.db.SetMaxOpenConns(n)
}

// SetMaxIdleConns sets the maximum number of idle connections
func (p *SQLPool) SetMaxIdleConns(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxIdle = n
	p.db.SetMaxIdleConns(n)
}

// SetConnMaxLifetime sets the maximum lifetime of connections
func (p *SQLPool) SetConnMaxLifetime(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxLifetime = d
	p.db.SetConnMaxLifetime(d)
}
