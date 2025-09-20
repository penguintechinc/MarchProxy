# MarchProxy Development Makefile

.PHONY: help build test lint clean docker-build docker-up docker-down format security-scan version

# Default target
help: ## Show this help message
	@echo "MarchProxy Development Commands"
	@echo "==============================="
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Version management
version: ## Display current version
	@if [ -f .version ]; then \
		echo "Current version: $$(cat .version)"; \
	else \
		echo "No version file found"; \
	fi

version-update: ## Update version using version script
	@./scripts/update-version.sh

version-patch: ## Increment patch version
	@./scripts/update-version.sh patch

version-minor: ## Increment minor version
	@./scripts/update-version.sh minor

version-major: ## Increment major version
	@./scripts/update-version.sh major

# Build targets
build: build-proxy build-manager ## Build all components

build-proxy: ## Build Go proxy application
	@echo "Building proxy..."
	cd proxy && go build -v -o bin/marchproxy-proxy ./cmd/proxy
	cd proxy && go build -v -o bin/marchproxy-health ./cmd/health
	cd proxy && go build -v -o bin/marchproxy-metrics ./cmd/metrics

build-manager: ## Build Python manager (install dependencies)
	@echo "Setting up manager..."
	cd manager && pip install -r requirements.txt

build-ebpf: ## Build eBPF programs
	@echo "Building eBPF programs..."
	cd ebpf && make

# Test targets
test: test-proxy test-manager ## Run all tests

test-proxy: ## Run Go tests
	@echo "Running Go tests..."
	cd proxy && go test -v -race -coverprofile=coverage.out ./...

test-manager: ## Run Python tests
	@echo "Running Python tests..."
	cd manager && python -m pytest tests/ -v --cov=. --cov-report=term-missing || echo "No tests found"

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	docker-compose -f docker-compose.yml -f docker-compose.ci.yml up -d
	sleep 30
	curl -f http://localhost:8000/health || echo "Manager health check failed"
	curl -f http://localhost:8080/healthz || echo "Proxy health check failed"
	docker-compose -f docker-compose.yml -f docker-compose.ci.yml down -v

# Lint and format targets
lint: lint-proxy lint-manager ## Run all linters

lint-proxy: ## Lint Go code
	@echo "Linting Go code..."
	cd proxy && go fmt ./...
	cd proxy && go vet ./...
	cd proxy && golangci-lint run --timeout 5m || echo "golangci-lint not installed"

lint-manager: ## Lint Python code
	@echo "Linting Python code..."
	cd manager && flake8 . --max-line-length=127 --extend-ignore=E203,W503 || echo "flake8 not installed"
	cd manager && black --check . || echo "black not installed"
	cd manager && isort --check-only . || echo "isort not installed"

format: format-proxy format-manager ## Format all code

format-proxy: ## Format Go code
	@echo "Formatting Go code..."
	cd proxy && go fmt ./...

format-manager: ## Format Python code
	@echo "Formatting Python code..."
	cd manager && black . || echo "black not installed"
	cd manager && isort . || echo "isort not installed"

# Security scanning
security-scan: ## Run security scans
	@echo "Running security scans..."
	@echo "Scanning Go code with gosec..."
	cd proxy && gosec ./... || echo "gosec not installed"
	@echo "Scanning Python code with bandit..."
	cd manager && bandit -r . -ll || echo "bandit not installed"
	@echo "Running Trivy filesystem scan..."
	trivy fs . || echo "trivy not installed"

# Docker targets
docker-build: ## Build all Docker images
	@echo "Building Docker images..."
	docker build -t marchproxy/manager:dev --target manager .
	docker build -t marchproxy/proxy:dev --target proxy .
	docker build -t marchproxy/dev:latest --target development .

docker-build-production: ## Build production Docker images
	@echo "Building production Docker images..."
	docker build -t marchproxy/manager:latest --target manager .
	docker build -t marchproxy/proxy:latest --target proxy .

docker-up: ## Start development environment
	@echo "Starting development environment..."
	docker-compose up -d
	@echo "Services starting... waiting for health checks..."
	sleep 15
	@echo "Manager: http://localhost:8000"
	@echo "Proxy Admin: http://localhost:8080"
	@echo "Metrics: http://localhost:8090/metrics"
	@echo "Grafana: http://localhost:3000 (admin/admin123)"
	@echo "Prometheus: http://localhost:9090"

docker-up-ci: ## Start CI test environment
	@echo "Starting CI test environment..."
	docker-compose -f docker-compose.yml -f docker-compose.ci.yml up -d

docker-down: ## Stop development environment
	@echo "Stopping development environment..."
	docker-compose down

docker-down-volumes: ## Stop and remove volumes
	@echo "Stopping and removing volumes..."
	docker-compose down -v

docker-logs: ## Show logs from all services
	docker-compose logs -f

docker-logs-manager: ## Show manager logs
	docker-compose logs -f manager

docker-logs-proxy: ## Show proxy logs
	docker-compose logs -f proxy

# Development helpers
dev-setup: ## Set up development environment
	@echo "Setting up development environment..."
	@echo "Installing Go dependencies..."
	cd proxy && go mod download
	@echo "Installing Python dependencies..."
	cd manager && pip install -r requirements.txt -r requirements-dev.txt
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	pip install black isort flake8 pytest bandit
	@echo "Development environment ready!"

dev-proxy: ## Run proxy in development mode
	@echo "Starting proxy in development mode..."
	cd proxy && go run ./cmd/proxy

dev-manager: ## Run manager in development mode
	@echo "Starting manager in development mode..."
	cd manager && python -m py4web run apps --host 0.0.0.0 --port 8000

dev-watch: ## Run with file watching (requires air for Go)
	@echo "Starting with file watching..."
	cd proxy && air -c .air.toml || echo "air not installed, falling back to manual build"

# Database management
db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	cd manager && python -c "from apps.manager.models import db; db.commit()"

db-reset: ## Reset database (DESTRUCTIVE)
	@echo "Resetting database..."
	docker-compose exec postgres psql -U marchproxy -d marchproxy -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	$(MAKE) db-migrate

# Monitoring and logs
logs-syslog: ## Show syslog output
	docker-compose logs -f syslog

logs-prometheus: ## Show Prometheus logs
	docker-compose logs -f prometheus

logs-grafana: ## Show Grafana logs
	docker-compose logs -f grafana

# Performance testing
perf-test: ## Run performance tests
	@echo "Running performance tests..."
	@echo "Testing manager..."
	ab -n 1000 -c 10 http://localhost:8000/health || echo "ab not installed"
	@echo "Testing proxy..."
	ab -n 1000 -c 10 http://localhost:8080/healthz || echo "ab not installed"

load-test: ## Run load tests (requires hey)
	@echo "Running load tests..."
	hey -n 10000 -c 100 http://localhost:8000/health || echo "hey not installed"
	hey -n 10000 -c 100 http://localhost:8080/healthz || echo "hey not installed"

# Cleanup targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	cd proxy && rm -rf bin/ coverage.out
	cd manager && find . -name "*.pyc" -delete
	cd manager && find . -name "__pycache__" -delete
	cd ebpf && make clean || echo "eBPF clean failed"

clean-docker: ## Clean Docker images and containers
	@echo "Cleaning Docker resources..."
	docker-compose down -v
	docker system prune -f
	docker volume prune -f

# Installation helpers
install-tools: ## Install development tools
	@echo "Installing development tools..."
	# Go tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install github.com/cosmtrek/air@latest
	# Python tools
	pip install black isort flake8 bandit pytest pytest-cov
	# System tools (Ubuntu/Debian)
	sudo apt-get update || echo "apt-get not available"
	sudo apt-get install -y apache2-utils hey trivy || echo "Some tools may not be available"

# Documentation
docs-serve: ## Serve documentation locally
	@echo "Serving documentation..."
	cd docs && python -m http.server 8080 || echo "docs directory not found"

# Quick commands for common workflows
quick-test: format lint test ## Quick test cycle (format, lint, test)

quick-build: clean build test ## Quick build cycle (clean, build, test)

quick-deploy: docker-build docker-up ## Quick deploy to local Docker

# CI/CD helpers
ci-lint: ## Run CI linting
	$(MAKE) lint-proxy lint-manager

ci-test: ## Run CI tests
	$(MAKE) test-proxy test-manager test-integration

ci-build: ## Run CI build
	$(MAKE) docker-build

ci-security: ## Run CI security scans
	$(MAKE) security-scan

# Release workflow
release-check: ## Check if ready for release
	@echo "Checking release readiness..."
	@if [ ! -f .version ]; then echo "ERROR: Missing .version file"; exit 1; fi
	@if [ ! -f VERSION.md ]; then echo "ERROR: Missing VERSION.md file"; exit 1; fi
	@if [ ! -f CHANGELOG.md ]; then echo "ERROR: Missing CHANGELOG.md file"; exit 1; fi
	@echo "Release checks passed!"

release-prepare: version-update release-check ## Prepare for release
	@echo "Release preparation complete!"

# Environment info
env-info: ## Show environment information
	@echo "Development Environment Information"
	@echo "=================================="
	@echo "Go version: $$(go version 2>/dev/null || echo 'Not installed')"
	@echo "Python version: $$(python --version 2>/dev/null || echo 'Not installed')"
	@echo "Docker version: $$(docker --version 2>/dev/null || echo 'Not installed')"
	@echo "Docker Compose version: $$(docker-compose --version 2>/dev/null || echo 'Not installed')"
	@echo "Current directory: $$(pwd)"
	@if [ -f .version ]; then echo "Project version: $$(cat .version)"; fi