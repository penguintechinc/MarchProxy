# Contributing to MarchProxy

Thank you for your interest in contributing to MarchProxy! This guide will help you get started with contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Getting Started

### Prerequisites

- Git
- Docker and Docker Compose
- Go 1.21+ (for proxy development)
- Python 3.9+ (for manager development)
- Node.js 18+ (for frontend development)
- PostgreSQL 13+ (for local development)
- Redis 6+ (for caching)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/marchproxy.git
   cd marchproxy
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/marchproxy/marchproxy.git
   ```

## Development Environment

### Quick Setup with Docker

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Install development dependencies
./scripts/setup-dev.sh

# Run tests
./test/run_tests.sh --all
```

### Manual Setup

#### Manager (Python/py4web)

```bash
cd manager

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Start development server
python3 -m py4web run apps
```

#### Proxy (Go)

```bash
cd proxy

# Install dependencies
go mod download

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/sast-scan/cmd/gosec@latest

# Build proxy
go build -o proxy ./cmd/proxy

# Run tests
go test ./...
```

### Database Setup

```bash
# Start PostgreSQL
docker run -d \
  --name marchproxy-dev-postgres \
  -e POSTGRES_DB=marchproxy_dev \
  -e POSTGRES_USER=marchproxy \
  -e POSTGRES_PASSWORD=devpassword \
  -p 5432:5432 \
  postgres:15

# Run migrations
cd manager
python3 migrate.py
```

## Contributing Process

### 1. Create an Issue

Before starting work, create an issue describing:
- The problem you're solving
- Your proposed solution
- Any breaking changes

### 2. Create a Branch

```bash
# Update main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Follow our [coding standards](#coding-standards)
- Write tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add new authentication method

- Implement OAuth2 authentication
- Add tests for OAuth2 flow
- Update API documentation
- Closes #123"
```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Maintenance tasks

Examples:
```
feat(auth): add SAML authentication support
fix(proxy): resolve memory leak in connection pooling
docs(api): update REST API documentation
test(manager): add unit tests for cluster management
```

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

## Coding Standards

### Go Code Standards

We follow standard Go conventions plus additional rules:

```bash
# Format code
go fmt ./...

# Run linter
golangci-lint run

# Check for security issues
gosec ./...

# Run tests with coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

#### Go Style Guidelines

- Use `gofmt` for formatting
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use meaningful variable names
- Write godoc comments for public APIs
- Handle errors explicitly
- Use context for cancellation and timeouts

Example:
```go
// Package proxy provides high-performance network proxying capabilities
// with support for multiple protocols and advanced features.
package proxy

// Server represents a proxy server instance that handles incoming
// connections and forwards them to configured backends.
type Server struct {
    config   *Config
    listener net.Listener
    metrics  *Metrics
}

// Start starts the proxy server and begins accepting connections.
// It returns an error if the server fails to start.
func (s *Server) Start(ctx context.Context) error {
    if s.listener == nil {
        return fmt.Errorf("listener not configured")
    }

    // Implementation...
    return nil
}
```

### Python Code Standards

We follow PEP 8 plus additional rules:

```bash
# Format code
black manager/

# Sort imports
isort manager/

# Check style
flake8 manager/

# Type checking
mypy manager/

# Security checks
bandit -r manager/
```

#### Python Style Guidelines

- Use `black` for formatting
- Follow PEP 8 style guide
- Use type hints
- Write docstrings for functions and classes
- Use meaningful variable names
- Handle exceptions appropriately

Example:
```python
"""MarchProxy manager authentication module.

This module provides authentication and authorization functionality
for the MarchProxy management interface.
"""

from typing import Optional, Dict, Any
import bcrypt
import jwt


class AuthenticationManager:
    """Manages user authentication and session handling.

    The AuthenticationManager provides methods for user login,
    logout, password validation, and JWT token management.
    """

    def __init__(self, jwt_secret: str, token_expiry: int = 3600) -> None:
        """Initialize the authentication manager.

        Args:
            jwt_secret: Secret key for JWT token signing
            token_expiry: Token expiration time in seconds
        """
        self.jwt_secret = jwt_secret
        self.token_expiry = token_expiry

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user with username and password.

        Args:
            username: The username to authenticate
            password: The password to verify

        Returns:
            User information dict if authentication succeeds, None otherwise

        Raises:
            AuthenticationError: If authentication fails due to system error
        """
        # Implementation...
        pass
```

### Frontend Code Standards (if applicable)

- Use TypeScript for type safety
- Follow React/Vue.js best practices
- Use ESLint and Prettier
- Write component tests

## Testing Guidelines

### Test Structure

```
test/
├── unit/                 # Unit tests
│   ├── manager_test.py   # Manager unit tests
│   └── proxy_test.go     # Proxy unit tests
├── integration/          # Integration tests
│   └── integration_test.py
├── load/                 # Performance tests
│   └── load_test.py
├── security/             # Security tests
│   └── security_test.py
└── run_tests.sh         # Test runner
```

### Writing Tests

#### Go Tests

```go
func TestServerStart(t *testing.T) {
    tests := []struct {
        name    string
        config  *Config
        wantErr bool
    }{
        {
            name:    "valid config",
            config:  &Config{ListenAddr: ":8080"},
            wantErr: false,
        },
        {
            name:    "invalid config",
            config:  &Config{},
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            server := NewServer(tt.config)
            err := server.Start(context.Background())

            if (err != nil) != tt.wantErr {
                t.Errorf("Server.Start() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

#### Python Tests

```python
import unittest
from unittest.mock import Mock, patch
from manager.auth import AuthenticationManager


class TestAuthenticationManager(unittest.TestCase):
    """Test cases for AuthenticationManager."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth_manager = AuthenticationManager(
            jwt_secret="test-secret",
            token_expiry=3600
        )

    def test_authenticate_user_success(self):
        """Test successful user authentication."""
        with patch('manager.auth.verify_password') as mock_verify:
            mock_verify.return_value = True

            result = self.auth_manager.authenticate_user("testuser", "password")

            self.assertIsNotNone(result)
            self.assertEqual(result['username'], "testuser")

    def test_authenticate_user_failure(self):
        """Test failed user authentication."""
        with patch('manager.auth.verify_password') as mock_verify:
            mock_verify.return_value = False

            result = self.auth_manager.authenticate_user("testuser", "wrong")

            self.assertIsNone(result)
```

### Test Coverage

Maintain high test coverage:
- **Unit tests**: >90% coverage
- **Integration tests**: Cover all major workflows
- **Security tests**: Cover all attack vectors
- **Performance tests**: Verify performance requirements

```bash
# Check Go coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Check Python coverage
coverage run -m pytest manager/tests/
coverage report -m
coverage html
```

## Documentation

### Code Documentation

- **Go**: Use godoc comments for all public APIs
- **Python**: Use docstrings following PEP 257
- **API**: Use OpenAPI 3.0 specifications
- **Architecture**: Update diagrams and documentation

### Documentation Types

1. **Code comments**: Explain complex logic
2. **API documentation**: REST API endpoints
3. **User guides**: Installation and configuration
4. **Developer docs**: Architecture and contributing
5. **Security docs**: Security model and practices

### Documentation Standards

```python
def create_service(self, service_data: Dict[str, Any]) -> int:
    """Create a new service in the specified cluster.

    This method creates a new service with the provided configuration
    and assigns it to the specified cluster. The service will be
    available for mapping creation after successful creation.

    Args:
        service_data: Dictionary containing service configuration with
            required keys: name, ip_fqdn, cluster_id, auth_type

    Returns:
        The ID of the newly created service

    Raises:
        ValidationError: If service_data is invalid
        ClusterNotFoundError: If specified cluster doesn't exist
        ServiceExistsError: If service name already exists in cluster

    Example:
        >>> manager = ServiceManager()
        >>> service_id = manager.create_service({
        ...     'name': 'web-backend',
        ...     'ip_fqdn': 'backend.example.com',
        ...     'cluster_id': 1,
        ...     'auth_type': 'jwt'
        ... })
        >>> print(f"Created service with ID: {service_id}")
    """
```

## Pull Request Guidelines

### PR Requirements

1. **Description**: Clear description of changes
2. **Tests**: All tests pass
3. **Documentation**: Updated as needed
4. **No breaking changes**: Unless discussed in issue
5. **Linear history**: Rebase before merging

### PR Template

```markdown
## Description
Brief description of the changes and why they're needed.

## Changes Made
- [ ] Added new feature X
- [ ] Fixed bug Y
- [ ] Updated documentation

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Breaking Changes
List any breaking changes and migration steps.

## Related Issues
Closes #123
Related to #456

## Screenshots (if applicable)
Include screenshots for UI changes.
```

### Review Process

1. **Automated checks**: All CI checks must pass
2. **Code review**: At least one maintainer approval
3. **Security review**: For security-related changes
4. **Performance review**: For performance-critical changes

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version numbers
2. Update CHANGELOG.md
3. Run all tests
4. Create release PR
5. Tag release
6. Build and push images
7. Update documentation
8. Announce release

### Version Update

```bash
# Update version
./scripts/update-version.sh minor

# Create release branch
git checkout -b release/v1.2.0

# Update changelog
vim CHANGELOG.md

# Commit changes
git commit -m "chore: prepare release v1.2.0"

# Create PR
gh pr create --title "Release v1.2.0" --body "Release notes..."
```

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Discord**: Real-time chat with maintainers
- **Email**: security@marchproxy.io for security issues

### Maintainer Response Time

- **Bug reports**: 2-3 business days
- **Feature requests**: 1 week
- **Security issues**: 24 hours
- **Pull requests**: 3-5 business days

### Becoming a Maintainer

Regular contributors who demonstrate:
- High-quality code contributions
- Good understanding of the codebase
- Helpful community participation
- Alignment with project values

May be invited to become maintainers.

## License

By contributing to MarchProxy, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](../../LICENSE).

For Enterprise licensing questions, contact [enterprise@marchproxy.io](mailto:enterprise@marchproxy.io).

---

Thank you for contributing to MarchProxy! 🚀