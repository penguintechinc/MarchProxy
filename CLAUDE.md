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

## Critical Git Rules for Claude
⚠️ **IMPORTANT GIT RESTRICTIONS** ⚠️
- **NEVER run `git commit` unless explicitly asked by the user**
- **NEVER EVER run `git push` under any circumstances**
- Claude can use `git status`, `git diff`, `git log` for information gathering
- Claude can add files to staging with `git add` if needed for status checks
- Only commit when user explicitly requests it
- Never push to remote repositories

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

## Versioning System (vMajor.Minor.Patch.EpochTimestamp)
📌 **Version Format**: `vMajor.Minor.Patch.EpochTimestamp` (e.g., v0.1.0.1757706313)

### When to Update Version:
- **Major**: Breaking changes (API changes, schema migrations, removed features)
- **Minor**: New features and significant functionality additions
- **Patch**: Bug fixes, security patches, minor improvements
- **Build**: Unix epoch timestamp (automatic chronological ordering and uniqueness)

### Version Update Rules for Claude:
- Use `./scripts/update-version.sh` to update versions
- Build number automatically set to current epoch timestamp
- Update after any significant code changes
- Check VERSION.md for version history and guidelines
- Version must be embedded in applications and API responses
- Docker images tagged with full version for dev, without epoch for releases

### Version Script Usage:
```bash
./scripts/update-version.sh          # Update build timestamp only
./scripts/update-version.sh patch    # Increment patch version  
./scripts/update-version.sh minor    # Increment minor version
./scripts/update-version.sh major    # Increment major version
./scripts/update-version.sh 1 2 3    # Set specific version
```