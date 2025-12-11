# Claude Code Context for MarchProxy

## Project Overview
MarchProxy is a two-container application suite for managing egress traffic in a data center environment to the internet. Available in two tiers: Community (open source) and Enterprise (licensed).

### Product Tiers
- **Community (Open Source)**: Free, maximum 3 proxy servers, single default cluster, basic authentication
- **Enterprise (Licensed)**: Licensed via license.penguintech.io, unlimited proxies based on license, multi-cluster support, SAML/SCIM/OAuth2

### Architecture Components
1. **Manager**: Python/py4web management server with pydal ORM, PostgreSQL database, web UI
2. **Proxy**: High-performance Go/eBPF proxy with optional hardware acceleration (DPDK, XDP, AF_XDP, SR-IOV)

## Key Project Files
- `.REQUIREMENTS`: Original project requirements (git ignored)
- `.PLAN`: Detailed development plan based on requirements (git ignored) 
- `.TODO`: Comprehensive todo list for tracking progress (git ignored)
- `.version`: Current version number (vMajor.Minor.Patch.Build format)
- `VERSION.md`: Versioning system documentation and history
- `CLAUDE.md`: This context file for Claude Code sessions

## Development Context

### Architecture Components
- **Manager Container**: py4web + pydal + PostgreSQL for configuration management
- **Proxy Container**: Go + eBPF + optional hardware acceleration for packet forwarding
- **Database**: PostgreSQL (default), configurable via ENV to any pydal-supported DB
- **Licensing**: Integration with license.penguintech.io for Enterprise features
- **Clustering**: Multi-cluster support with separate API keys (Enterprise)

### Key Features
- **Service Management**: Service-to-service mapping with cluster isolation
- **Protocol Support**: TCP, UDP, ICMP, HTTPS (WebSockets), HTTP3/QUIC
- **Authentication**: 2FA, SAML, SCIM, OAuth2 (Enterprise), Base64 tokens OR JWT (mutually exclusive)
- **Port Configuration**: Single, ranges, comma-separated lists  
- **Role-based Access**: Administrator and Service-owner roles with cluster assignments
- **TLS Management**: Infisical, HashiCorp Vault integration, or direct upload
- **Monitoring**: /healthz and /metrics endpoints, UDP syslog logging

### Performance Architecture
Multi-tier packet processing for maximum performance:
1. **Hardware Acceleration**: DPDK (kernel bypass), XDP (driver-level), AF_XDP (zero-copy), SR-IOV (virtualization)
2. **eBPF Fast-path**: Programmable kernel-level packet filtering
3. **Go Application Logic**: Complex rule processing and application features
4. **Standard Networking**: Traditional kernel socket processing

### Security Features
- **Authentication**: 2FA, SAML, SCIM, OAuth2 integration (Enterprise)
- **API Security**: Cluster-specific API keys via py4web native system
- **Service Authentication**: Base64 tokens OR JWT with rotation capability
- **License Enforcement**: Proxy count limits based on Community (3) vs Enterprise tiers
- **Role-based Access**: User assignments to clusters and services

### Logging and Observability
- **Health Checks**: /healthz endpoints for both manager and proxy
- **Metrics**: Prometheus /metrics endpoints with comprehensive stats
- **Centralized Logging**: UDP syslog with per-cluster configuration
- **Log Types**: Authentication logs, netflow logs, debug logs (configurable per cluster)

## Development Workflow
1. Track progress in `.TODO` file
2. Reference `.PLAN` for architectural guidance
3. Use `.REQUIREMENTS` for original specifications
4. Update this file when adding significant context

## Critical TODO Management Rule
🔥 **MANDATORY TODO SYNCHRONIZATION** 🔥
- `.TODO` file is the single source of truth for project progress
- **ALWAYS** update `.TODO` file when completing tasks or changing status
- Mark items as `[x]` when completed, `[ ]` when pending
- Add new discovered tasks to appropriate phases
- **NEVER** mark tasks complete in TODO without updating `.TODO` file
- Sync TodoWrite status with `.TODO` file status regularly
- If `.TODO` exists, it MUST be kept current and accurate

## Current Status
Project fully planned with comprehensive documentation architecture. Ready to begin implementation following the 8-phase development plan.

### Development Phases
1. **Foundation Setup**: Project structure, containerization, database schema
2. **Manager Implementation**: Authentication, licensing, clustering, API endpoints
3. **Proxy Core Development**: Go proxy, registration, protocol handling
4. **eBPF Integration**: Packet filtering and fast-path processing
5. **Advanced Network Acceleration**: DPDK, XDP, AF_XDP, SR-IOV (optional)
6. **Advanced Features**: WebSockets, QUIC/HTTP3, advanced routing
7. **Production Readiness**: Testing, security hardening, deployment
8. **Documentation**: Comprehensive docs/ folder and README.md

## Important Commands
- **Database**: PostgreSQL (configurable via ENV to any pydal-supported DB)
- **Manager Framework**: py4web with pydal ORM and native API key system
- **Proxy Language**: Go with eBPF and optional hardware acceleration
- **Testing**: TBD based on project structure (will be defined during Phase 1)
- **Linting**: TBD based on project structure (will be defined during Phase 1)

## py4web Documentation and Research
- **Official Documentation**: https://py4web.com/_documentation
- **Always research py4web native features before implementing custom solutions**
- **Leverage py4web's built-in authentication, user management, and API systems**
- **Use py4web's native decorators, validators, and utilities wherever possible**
- **Priority order: py4web native → pydal features → custom implementation**

## Input Validation and Security Requirements
- **ALL fields and inputs MUST have appropriate validators**
- **Use pydal's built-in validators (IS_EMAIL, IS_STRONG, IS_IN_SET, etc.)**
- **Implement input sanitization for XSS prevention**
- **Validate data types, lengths, and formats at database and API levels**
- **Use py4web's native form validation and error handling**
- **Never trust client-side input - always validate server-side**
- **Implement CSRF protection using py4web's native features**

## Key Environment Variables
- `CLUSTER_API_KEY`: Cluster-specific API key for proxy registration (Docker ENV)
- `DATABASE_URL`: Database connection string for manager
- `LICENSE_KEY`: Enterprise license key (format: PENG-XXXX-XXXX-XXXX-XXXX-ABCD)

## Critical Development Rules

### Development Philosophy: Safe, Stable, and Feature-Complete

**NEVER take shortcuts or the "easy route" - ALWAYS prioritize safety, stability, and feature completeness**

#### Core Principles
- **No Quick Fixes**: Resist quick workarounds or partial solutions
- **Complete Features**: Fully implemented with proper error handling and validation
- **Safety First**: Security, data integrity, and fault tolerance are non-negotiable
- **Stable Foundations**: Build on solid, tested components
- **Future-Proof Design**: Consider long-term maintainability and scalability
- **No Technical Debt**: Address issues properly the first time

#### Red Flags (Never Do These)
- Skipping input validation "just this once"
- Hardcoding credentials or configuration
- Ignoring error returns or exceptions
- Commenting out failing tests to make CI pass
- Deploying without proper testing
- Using deprecated or unmaintained dependencies
- Implementing partial features with "TODO" placeholders
- Bypassing security checks for convenience
- Assuming data is valid without verification
- Leaving debug code or backdoors in production

#### Quality Checklist Before Completion
- All error cases handled properly
- Unit tests cover all code paths
- Integration tests verify component interactions
- Security requirements fully implemented
- Performance meets acceptable standards
- Documentation complete and accurate
- Code review standards met
- No hardcoded secrets or credentials
- Logging and monitoring in place
- Build passes in containerized environment
- No security vulnerabilities in dependencies
- Edge cases and boundary conditions tested

### Git Workflow
- **NEVER commit automatically** unless explicitly requested by the user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- Always use feature branches for development
- Require pull request reviews for main branch
- Automated testing must pass before merge

### Local State Management (Crash Recovery)
- **ALWAYS maintain local .PLAN and .TODO files** for crash recovery
- **Keep .PLAN file updated** with current implementation plans and progress
- **Keep .TODO file updated** with task lists and completion status
- **Update these files in real-time** as work progresses
- **Add to .gitignore**: Both .PLAN and .TODO files must be in .gitignore
- **File format**: Use simple text format for easy recovery
- **Automatic recovery**: Upon restart, check for existing files to resume work

### Dependency Security Requirements
- **ALWAYS check for Dependabot alerts** before every commit
- **Monitor vulnerabilities via Socket.dev** for all dependencies
- **Mandatory security scanning** before any dependency changes
- **Fix all security alerts immediately** - no commits with outstanding vulnerabilities
- **Regular security audits**: `npm audit`, `go mod audit`, `safety check`

### Linting & Code Quality Requirements
- **ALL code must pass linting** before commit - no exceptions
- **Python**: flake8, black, isort, mypy (type checking), bandit (security)
- **JavaScript/TypeScript**: ESLint, Prettier
- **Go**: golangci-lint (includes staticcheck, gosec, etc.)
- **Docker**: hadolint
- **YAML**: yamllint
- **Shell**: shellcheck
- **CodeQL**: All code must pass CodeQL security analysis
- **PEP Compliance**: Python code must follow PEP 8, PEP 257 (docstrings), PEP 484 (type hints)

### Build & Deployment Requirements
- **NEVER mark tasks as completed until successful build verification**
- All Go and Python builds MUST be executed within Docker containers
- Use containerized builds for local development and CI/CD pipelines
- Build failures must be resolved before task completion

### Documentation Standards
- **README.md**: Keep as overview and pointer to comprehensive docs/ folder
- **docs/ folder**: Create comprehensive documentation for all aspects
- **RELEASE_NOTES.md**: Maintain in docs/ folder, prepend new version releases to top
- Update CLAUDE.md when adding significant context
- **Build status badges**: Always include in README.md
- **ASCII art**: Include catchy, project-appropriate ASCII art in README
- **Company homepage**: Point to www.penguintech.io
- **License**: All projects use Limited AGPL3 with preamble for fair use

### File Size Limits
- **Maximum file size**: 25,000 characters for ALL code and markdown files
- **Split large files**: Decompose into modules, libraries, or separate documents
- **CLAUDE.md exception**: Maximum 39,000 characters (only exception to 25K rule)
- **Documentation strategy**: Create detailed documentation in `docs/` folder and link to them from CLAUDE.md
- **User approval required**: ALWAYS ask user permission before splitting CLAUDE.md files

## PenguinTech License Server Integration

All projects integrate with the centralized PenguinTech License Server at `https://license.penguintech.io` for feature gating and enterprise functionality.

**IMPORTANT: License enforcement is ONLY enabled when project is marked as release-ready**
- Development phase: All features available, no license checks
- Release phase: License validation required, feature gating active

**License Key Format**: `PENG-XXXX-XXXX-XXXX-XXXX-ABCD`

**Core Endpoints**:
- `POST /api/v2/validate` - Validate license
- `POST /api/v2/features` - Check feature entitlements
- `POST /api/v2/keepalive` - Report usage statistics

**Environment Variables**:
```bash
# License configuration
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD
LICENSE_SERVER_URL=https://license.penguintech.io
PRODUCT_NAME=marchproxy

# Release mode (enables license enforcement)
RELEASE_MODE=false  # Development (default)
RELEASE_MODE=true   # Production (explicitly set)
```

## WaddleAI Integration (Optional)

For projects requiring AI capabilities, integrate with WaddleAI located at `~/code/WaddleAI`.

**When to Use WaddleAI:**
- Natural language processing (NLP)
- Machine learning model inference
- AI-powered features and automation
- Intelligent data analysis

**Integration Pattern:**
- WaddleAI runs as separate microservice container
- Communicate via REST API or gRPC
- Environment variable configuration for API endpoints
- License-gate AI features as enterprise functionality

## Version Management System

**Format**: `vMajor.Minor.Patch.build`
- **Major**: Breaking changes, API changes, removed features
- **Minor**: Significant new features and functionality additions
- **Patch**: Minor updates, bug fixes, security patches
- **Build**: Epoch64 timestamp of build time

**Update Commands**:
```bash
./scripts/update-version.sh          # Update build timestamp only
./scripts/update-version.sh patch    # Increment patch version
./scripts/update-version.sh minor    # Increment minor version
./scripts/update-version.sh major    # Increment major version
```

## Notes for Claude
- Always refer to `.PLAN` and `.TODO` for current project state and comprehensive task tracking
- Focus on performance, security, and scalability requirements
- Maintain stateless proxy design for horizontal scaling
- Prioritize multi-tier performance: Hardware acceleration → eBPF → Go → Standard networking
- Consider Community (3 proxies max) vs Enterprise (unlimited) licensing implications
- Use py4web native functions wherever possible (API keys, authentication, etc.)
- Implement proper cluster isolation for Enterprise multi-cluster deployments
- Follow comprehensive documentation standards for all code

## Critical Implementation Rule
🚨 **NOTHING IS CONSIDERED COMPLETE UNTIL IT HAS A SUCCESSFUL TEST BUILD** 🚨
- Every component must build successfully before marking tasks as completed
- Docker containers must build without errors
- Go applications must compile cleanly (`go build`, `go test`)
- Python applications must start without import or syntax errors
- Database migrations must run successfully
- All health check endpoints must respond correctly
- Integration tests must pass before considering a phase complete
- If builds fail, tasks remain in "in_progress" status until fixed

## Additional Version Notes
- Use `./scripts/update-version.sh` to update versions
- Build number automatically set to current epoch timestamp
- Update after any significant code changes
- Check VERSION.md for version history and guidelines
- Version must be embedded in applications and API responses
- Docker images tagged with full version for dev, without epoch for releases

## CI/CD Pipeline Overview

### Workflow Structure

MarchProxy uses GitHub Actions with service-specific CI/CD pipelines:

**Three Main Services**:
1. **Manager** (Python/py4web) - Workflow: `manager-ci.yml`
2. **Proxy Egress** (Go) - Workflow: `proxy-ci.yml`
3. **Proxy Ingress** (Go) - Workflow: `proxy-ingress-ci.yml`

**Combined Build**: `build-and-test.yml` for coordinated builds

### Build Pipeline Stages

1. **Lint Stage** - Code quality checks (fail fast)
   - Python: flake8, black, isort, mypy
   - Go: golangci-lint, gosec, go fmt, go vet
   - Fails immediately on linting errors

2. **Test Stage** - Unit tests with mocked dependencies
   - Python: pytest with 80%+ coverage requirement
   - Go: go test -race with 80%+ coverage requirement
   - Tests must pass before proceeding to build

3. **Build Stage** - Multi-architecture Docker builds
   - Platforms: linux/amd64, linux/arm64, linux/arm/v7
   - Tags: Automatic based on branch/version
   - Caching: GitHub Actions cache for 50%+ speedup

4. **Security Scan Stage** - Comprehensive vulnerability scanning
   - Dependency scanning: govulncheck, safety, pip-audit
   - Code scanning: gosec, bandit, Semgrep
   - Container scanning: Trivy
   - Results uploaded to GitHub Security tab

### Automatic Versioning & Image Tagging

**Version Detection**:
- Reads `.version` file at workflow start
- Extracts semantic version (X.Y.Z)
- Generates epoch64 timestamp for build tracking

**Image Tags**:
- **Development**: `alpha-<epoch64>` (feature/develop), `beta-<epoch64>` (main)
- **Version Release**: `v<X.Y.Z>-alpha/beta` when .version changes
- **Production**: `v<X.Y.Z>`, `latest` on git tags
- **PR Builds**: `pr-<number>` + `<branch>-<sha>`

### Version Release Workflow

1. **Update Version**:
   ```bash
   echo "v1.2.3" > .version
   git add .version && git commit -m "Release v1.2.3"
   git push origin develop
   ```

2. **Automatic Pre-Release**:
   - `version-release.yml` triggers
   - Creates GitHub pre-release: `v1.2.3-pre`
   - Builds all services with version tags

3. **Final Release** (Optional):
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```
   - Creates production release
   - Tags final images with `v1.2.3` and `latest`

### Key Features

**Path Filters**: Workflows only trigger on changes to relevant code
- Manager: Changes to `manager/` or `.version`
- Proxy: Changes to `proxy*/` or `.version`
- All workflows triggered by `.version` changes

**Security First**: All workflows include security scanning
- Bandit/gosec for code vulnerabilities
- safety/govulncheck for dependencies
- Trivy for container images
- Results in GitHub Security tab

**Performance Optimized**: Multi-level caching and parallelization
- GitHub Actions cache for dependencies
- Parallel job execution
- Multi-arch builds reduce time via buildx

**Comprehensive Testing**:
- 80%+ code coverage minimum
- Unit tests with mocked dependencies
- Integration tests for critical paths
- Performance benchmarks included

### Documentation

Complete CI/CD documentation available:
- **docs/WORKFLOWS.md** - Complete workflow reference
  - Trigger conditions and path filters
  - Build service specifications
  - Naming conventions
  - Troubleshooting guide
  - Local workflow testing

- **docs/STANDARDS.md** - Development standards with CI/CD section
  - Code quality requirements
  - Language-specific standards
  - Security standards
  - Testing requirements
  - Git workflow guidelines