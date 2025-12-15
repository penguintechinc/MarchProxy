# MarchProxy Development Standards

This document outlines development standards, code quality requirements, and best practices for all MarchProxy components.

## Table of Contents

1. [Code Quality Standards](#code-quality-standards)
2. [Python Standards (Manager)](#python-standards-manager)
3. [Go Standards (Proxy Services)](#go-standards-proxy-services)
4. [Docker Standards](#docker-standards)
5. [Testing Requirements](#testing-requirements)
6. [Security Standards](#security-standards)
7. [CI/CD Standards](#cicd-standards)
8. [Documentation Standards](#documentation-standards)
9. [Git Workflow](#git-workflow)

---

## Code Quality Standards

### Universal Requirements

All code must meet these requirements regardless of language:

- **No warnings from linters** - All code must pass linting without warnings
- **Proper error handling** - All errors must be handled appropriately
- **Type safety** - Type hints/declarations required for all functions
- **Comments for complexity** - Complex logic must have explanatory comments
- **Constants for magic numbers** - No hardcoded values in code
- **Input validation** - All external inputs must be validated
- **No dead code** - Unused functions, variables, imports must be removed
- **No TODO placeholders** - All temporary code must be completed or removed

### Code Organization

- **Single responsibility** - Each function/class handles one concern
- **Clear naming** - Variables and functions have descriptive names
- **Consistent formatting** - Code style is consistent throughout
- **Appropriate abstraction** - Functions are properly decomposed
- **DRY principle** - No duplicate code or logic

---

## Python Standards (Manager)

### Framework & Tools

- **Framework**: py4web with pydal ORM (mandatory)
- **Python Version**: 3.12+ (3.13 preferred)
- **Package Manager**: pip with requirements.txt
- **Type Checking**: mypy with type hints

### Code Style

**Formatting & Linting**:
- black: Code formatting (line length: 100)
- isort: Import sorting
- flake8: Linting (ignore E203, W503)
- mypy: Type checking with strict mode

**PEP Compliance**:
- PEP 8: Style guide
- PEP 257: Docstring conventions
- PEP 484: Type hints

### File Organization

```
manager/
├── apps/
│   ├── __init__.py
│   ├── models.py      # pydal models and schemas
│   ├── routes.py      # API endpoints
│   ├── auth.py        # Authentication and authorization
│   └── utils.py       # Utility functions
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_models.py
│   └── test_routes.py
├── requirements.txt     # Production dependencies
├── requirements-dev.txt # Development dependencies
└── Dockerfile
```

### Dependency Management

**requirements.txt** (production):
```
py4web>=1.0.0
pydal>=20.11.1
flask-security-too>=5.0.0
sqlalchemy>=2.0.0
```

**requirements-dev.txt** (development):
```
-r requirements.txt
pytest>=7.0.0
pytest-cov>=4.0.0
black==23.0.0
isort==5.12.0
flake8==6.0.0
mypy==1.0.0
bandit==1.7.0
safety==2.3.0
```

### Testing Requirements

- **Minimum coverage**: 80% code coverage
- **Test types**: Unit tests only (mocked external dependencies)
- **Framework**: pytest with fixtures
- **Mocking**: unittest.mock for external services
- **Database**: SQLite in-memory for tests

### Security Requirements

- **Input validation**: All API inputs validated
- **SQL injection prevention**: Use pydal parameterized queries
- **XSS prevention**: HTML escaping in templates
- **CSRF protection**: py4web built-in protection
- **Password hashing**: bcrypt via Flask-Security-Too
- **Environment variables**: All secrets via environment

---

## Go Standards (Proxy Services)

### Framework & Tools

- **Go Version**: 1.23+ (1.24 preferred)
- **Package Manager**: go mod
- **Module Name**: github.com/penguintechinc/marchproxy
- **Linting**: golangci-lint
- **Security**: gosec

### Code Style

**Formatting & Linting**:
- gofmt: Standard Go formatter (enforced)
- go vet: Built-in Go analysis
- golangci-lint: Comprehensive linting
  - Includes: staticcheck, gosec, ineffassign, misspell, etc.

**Conventions**:
- CamelCase for exported identifiers
- snake_case for unexported identifiers
- Receiver names short (1-2 characters)
- Error handling: `if err != nil { return err }`

### File Organization

```
proxy-egress/
├── cmd/
│   └── proxy/
│       └── main.go          # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go        # Configuration parsing
│   ├── proxy/
│   │   ├── listener.go      # Network listeners
│   │   ├── handler.go       # Connection handlers
│   │   └── ebpf.go          # eBPF programs
│   ├── health/
│   │   └── health.go        # Health check endpoints
│   └── metrics/
│       └── metrics.go       # Prometheus metrics
├── tests/
│   ├── integration_test.go
│   └── performance_test.go
├── go.mod
├── go.sum
├── Dockerfile
└── .golangci.yml            # golangci-lint config
```

### Dependency Management

**go.mod**:
```go
module github.com/penguintechinc/marchproxy

go 1.24

require (
    github.com/prometheus/client_golang v1.18.0
    golang.org/x/sys v0.14.0
)
```

### Testing Requirements

- **Minimum coverage**: 80% code coverage
- **Test types**: Unit and integration tests
- **Framework**: Go testing package (no external test framework)
- **Benchmarks**: Included for performance-critical code
- **Mocking**: Manual mocking or interfaces
- **Race detection**: All tests run with `-race` flag

### Security Requirements

- **Input validation**: Validate all external inputs
- **Command execution**: Use exec.Command safely
- **Network security**: TLS 1.2 minimum
- **Dependency auditing**: Regular go mod audit checks
- **gosec scanning**: Run before commits

---

## Docker Standards

### Base Images

**ALWAYS use Debian variants** for all container images (no Alpine):
- Use Debian release codenames: `bookworm`, `trixie`, `bullseye`
- Examples of correct base images:
  - **Go**: `golang:1.24-bookworm`, `golang:1.24-trixie`
  - **Python**: `python:3.12-bookworm`, `python:3.12-slim`
  - **Node.js**: `node:20-bookworm-slim`, `node:22-bookworm`
  - **Runtime**: `debian:bookworm-slim`, `debian:12-slim`
- **NEVER use Alpine images** (`*-alpine`) due to musl libc compatibility issues

### Approved Languages and Versions

- **Python**: 3.12+ only
- **Go**: 1.23.x or 1.24.x only (use 1.24 for latest features)
- **Node.js**: 20.x or 22.x LTS only
- **NO Rust, C++, or other languages** unless explicitly approved

### Health Check Requirements

**ALWAYS use native language health checks** instead of curl/wget:
- This reduces image size and eliminates unnecessary dependencies
- Health checks should use the application's own binary or runtime

**Examples**:
```dockerfile
# Go containers - implement --healthcheck flag in the binary
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["./app", "--healthcheck"]

# Python containers - use urllib from standard library
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

# Node.js containers - use http module from standard library
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "const http = require('http'); http.get('http://localhost:3000/', (res) => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1));"
```

### Multi-Stage Builds

All Dockerfiles must use multi-stage builds:

```dockerfile
# Build stage
FROM golang:1.24-bookworm AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -o app ./cmd/main.go

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/app /usr/local/bin/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/app", "--healthcheck"]
CMD ["app"]
```

### Build Arguments

- `VERSION`: Passed during build for embedding
- `BUILD_DATE`: Build timestamp
- `VCS_REF`: Git commit SHA

### Scanning

- **Hadolint**: Dockerfile linting
- **Trivy**: Container image scanning
- **No vulnerabilities**: High and critical vulnerabilities not allowed

---

## Testing Requirements

### Test Structure

**Unit Tests**:
- Test individual functions in isolation
- Mock all external dependencies
- Cover normal, error, and edge cases
- Fast execution (< 1 second per test)

**Integration Tests**:
- Test component interactions
- Use real containers/services where needed
- Slower execution acceptable (< 30 seconds per test)
- Marked with build tags

**Performance Tests**:
- Benchmark critical paths
- Track performance metrics
- Part of CI/CD pipeline

### Coverage Requirements

- **Minimum**: 80% code coverage
- **Target**: 90%+ code coverage
- **Exception**: Generated code, vendor code excluded
- **Tracking**: Coverage reports uploaded to Codecov

### Running Tests Locally

```bash
# Python (Manager)
cd manager
pytest tests/ -v --cov=apps --cov-report=term-missing

# Go (Proxy services)
cd proxy-egress
go test -v -race -coverprofile=coverage.out ./...
```

---

## Security Standards

### Dependency Management

- **Regular audits**: Weekly security audits
  - Python: `safety check`, `pip-audit`
  - Go: `govulncheck`, `go mod audit`
  - Vulnerability reports uploaded to GitHub

- **Update policy**:
  - Critical vulnerabilities: Fix within 24 hours
  - High vulnerabilities: Fix within 1 week
  - Medium vulnerabilities: Fix within 2 weeks
  - Low vulnerabilities: Fix within 1 month

### Secrets Management

**Never commit**:
- Passwords or API keys
- Private certificates
- Database credentials
- OAuth tokens

**Use instead**:
- GitHub Secrets for CI/CD
- Environment variables at runtime
- HashiCorp Vault for production
- Infisical for shared secrets

### Code Scanning

All code must pass security scanning:

**Python**:
- bandit: Security issue detection
- safety: Dependency vulnerability check
- pip-audit: Alternative dependency auditing

**Go**:
- gosec: Security issue detection
- govulncheck: Vulnerability checks
- staticcheck: Code analysis (via golangci-lint)

**Multi-language**:
- Semgrep: Pattern-based security scanning
- CodeQL: GitHub code analysis (if configured)

### Network Security

- **TLS**: TLS 1.2 minimum, TLS 1.3 preferred
- **Certificates**: Validated for all HTTPS connections
- **mTLS**: Mutual TLS for service-to-service
- **No self-signed**: Production uses trusted CAs

---

## CI/CD Standards

### Workflow Requirements

All CI/CD workflows must:

1. **Path Filters**: Monitor `.version` and relevant component directories
2. **Version Detection**: Extract version from `.version` file
3. **Epoch64 Timestamps**: Generate for development builds
4. **Parallel Jobs**: Run linting and security scans in parallel
5. **Artifact Preservation**: Keep scan results for analysis
6. **Artifact Upload**: Upload to GitHub for visibility

### Build Naming Conventions

**Image Tags Generated Automatically**:

| Branch Type | Build Type | Tag Format | Example |
|-------------|-----------|-----------|---------|
| feature/* | development | `alpha-<epoch64>` | `alpha-1734001234` |
| develop | development | `alpha-<epoch64>` | `alpha-1734001234` |
| main | development | `beta-<epoch64>` | `beta-1734001234` |
| main | after version change | `v<VERSION>-beta` | `v1.2.3-beta` |
| git tag (v*) | release | `v<VERSION>` | `v1.2.3` |
| git tag (v*) | release | `latest` | `latest` |

### Linting Gates

Workflows enforce linting at earliest stage:

**Python (Manager)**:
- flake8: Code style and correctness
- black: Code formatting
- isort: Import sorting
- mypy: Type checking

**Go (Proxy services)**:
- golangci-lint: Comprehensive linting
- gosec: Security scanning
- go fmt: Code formatting (enforced)
- go vet: Built-in analysis

**Docker**:
- hadolint: Dockerfile linting
- trivy: Container image scanning

### Security Scanning

All workflows include comprehensive security scanning:

**Dependency Scanning**:
- Python: bandit, safety, pip-audit
- Go: govulncheck, gosec
- Reports in GitHub artifacts

**Code Scanning**:
- bandit (Python)
- gosec (Go)
- Semgrep (multi-language)
- Results in SARIF format

**Container Scanning**:
- Trivy for image vulnerabilities
- Hadolint for Dockerfile issues
- Results uploaded to GitHub Security tab

### Version Management

**Version File (.version)**:
- Location: Repository root
- Format: `vX.Y.Z` or `vX.Y.Z.EPOCH64`
- Updates: Manual edit and commit
- Triggers: All workflows on change

**Update Process**:
```bash
# Update version
echo "v1.2.3" > .version

# Commit
git add .version
git commit -m "Bump version to v1.2.3"

# Push triggers build with new version tags
git push origin develop
```

**Release Process**:
```bash
# Create release
git tag v1.2.3
git push origin v1.2.3

# This triggers release workflow that:
# 1. Validates version
# 2. Builds final images
# 3. Creates GitHub release
# 4. Tags with vX.Y.Z and latest
```

### Caching Strategy

All workflows implement GitHub Actions caching:

**Go**:
- Cache: `~/.cache/go-build`, `~/go/pkg/mod`
- Key: `go-${{ hashFiles('**/go.sum') }}`

**Python**:
- Cache: `~/.cache/pip`
- Key: `pip-${{ hashFiles('**/requirements.txt') }}`

**Docker**:
- Cache: `type=gha` (GitHub Actions cache)
- Saves: Build layers for reuse
- Benefit: 50%+ reduction in build time

### Multi-Architecture Builds

Services build for three architectures:

- `linux/amd64` - Intel/AMD 64-bit
- `linux/arm64` - ARM 64-bit (Apple Silicon, Graviton)
- `linux/arm/v7` - ARM 32-bit (Raspberry Pi)

Uses `docker buildx` for parallel builds across platforms.

### Environment-Specific Builds

**Pull Requests**:
- Build images without pushing
- Test container validity
- Security scans run
- No registry push

**Main Branch**:
- Build and push to registry
- Tag with `beta-<epoch64>`
- Security scans run
- Available for staging

**Releases (git tags)**:
- Build and push to registry
- Tag with `v<VERSION>` and `latest`
- Create GitHub release
- Promoted to production

---

## Documentation Standards

### Code Documentation

**Docstrings Required**:
- Python: PEP 257 ("""Triple quoted""")
- Go: Exported functions (start with name)

**Python Example**:
```python
def validate_service_name(name: str) -> bool:
    """Validate service name format.

    Args:
        name: Service name to validate

    Returns:
        True if name is valid, False otherwise

    Raises:
        ValueError: If name is empty
    """
```

**Go Example**:
```go
// ValidateServiceName validates the service name format.
func ValidateServiceName(name string) (bool, error) {
    // Implementation
}
```

### File Documentation

**README.md in each directory**:
- Purpose of component
- Quick start instructions
- Key files explanation
- Development setup

**doc_strings.md for complex logic**:
- Algorithm explanation
- Design decisions
- Performance considerations
- References to papers/articles

### API Documentation

- Endpoint specifications in code comments
- Request/response format documentation
- Error code documentation
- Example requests and responses

### Workflow Documentation

- See `docs/WORKFLOWS.md` for comprehensive documentation
- Update when adding new workflows
- Include trigger conditions
- Document any manual intervention needed

---

## Git Workflow

### Branch Naming

- Feature branches: `feature/<description>` (e.g., `feature/add-metrics`)
- Bug fixes: `bugfix/<description>` (e.g., `bugfix/fix-panic`)
- Release branches: `release/v<VERSION>` (e.g., `release/v1.2.3`)
- Hotfix branches: `hotfix/<description>` (e.g., `hotfix/critical-security`)

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Type**: feat, fix, docs, style, refactor, test, chore
**Scope**: manager, proxy, proxy-egress, proxy-ingress
**Subject**: Imperative, lowercase, no period
**Body**: Explain what and why (not how)
**Footer**: Close issues (#123)

**Example**:
```
feat(manager): add service validation API

Add endpoint /api/v1/services/validate for validating
service configurations before deployment.

Closes #456
```

### Code Review Requirements

- Minimum 1 approval required
- All checks must pass (linting, tests, security)
- No merge conflicts
- Branch up-to-date with target

### Pre-Commit Checklist

Before committing code:

- [ ] Code passes all linters
- [ ] Tests pass locally
- [ ] No hardcoded secrets
- [ ] No debug statements
- [ ] Security scans clean
- [ ] Docstrings added for new functions
- [ ] Updated relevant documentation
- [ ] No console.log or print statements
- [ ] No TODO comments (complete or remove)
- [ ] Code coverage maintained (80%+ minimum)

---

**Last Updated**: 2025-12-11
**Version**: 1.0.0
**Maintained by**: MarchProxy Team
