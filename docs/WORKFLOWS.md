# MarchProxy CI/CD Workflows Documentation

## Table of Contents

1. [Overview](#overview)
2. [Workflow Architecture](#workflow-architecture)
3. [Build Services](#build-services)
4. [Naming Conventions](#naming-conventions)
5. [Path Filter Requirements](#path-filter-requirements)
6. [Workflow Triggers](#workflow-triggers)
7. [Security Scanning](#security-scanning)
8. [Version Release Workflow](#version-release-workflow)
9. [Build Optimization](#build-optimization)
10. [Troubleshooting](#troubleshooting)

---

## Overview

MarchProxy uses GitHub Actions for continuous integration and deployment (CI/CD). The CI/CD pipeline ensures code quality, security, and reliability across all three main services:

- **Manager** (Python/py4web) - Management server with web UI and API
- **Proxy** (Go) - High-performance egress proxy with eBPF support
- **Proxy-Ingress** (Go) - Reverse proxy variant with ingress routing

Each service has dedicated workflows that handle:
- Code linting and formatting checks
- Unit testing with mocked dependencies
- Security scanning (dependencies, code vulnerabilities, container images)
- Multi-architecture Docker builds (AMD64, ARM64, ARM v7)
- Automated versioning with epoch64 timestamps
- Pre-release creation on version changes

**Philosophy**: Workflows are optimized for **speed, reliability, and security**. Path filters ensure workflows only run when relevant files change.

---

## Workflow Architecture

### Pipeline Structure

Each service follows this standardized pipeline:

```
┌──────────────┐
│ Lint Stage   │ (Fail fast on code quality issues)
└───────┬──────┘
        │
        ▼
┌──────────────┐
│ Test Stage   │ (Unit tests only, mocked dependencies)
└───────┬──────┘
        │
        ▼
┌──────────────────────┐
│ Build & Push Stage   │ (Docker image build for multi-arch)
└───────┬──────────────┘
        │
        ▼
┌──────────────────────┐
│ Security Scan Stage  │ (Trivy, gosec, bandit scanning)
└──────────────────────┘
```

### Job Dependencies

- **Lint** → Runs immediately on push/PR (fail fast principle)
- **Test** → Requires lint to pass
- **Build** → Requires both lint and test to pass
- **Security Scan** → Runs in parallel with build stage

### Service-Specific Workflows

| Service | Workflow File | Trigger Directory | Output Format |
|---------|---------------|-------------------|---------------|
| Manager | `manager-ci.yml` | `manager/` | Docker image |
| Proxy Egress | `proxy-ci.yml` | `proxy-egress/` | Docker image |
| Proxy Ingress | `proxy-ingress-ci.yml` | `proxy-ingress/` | Docker image |
| Combined Build | `build-and-test.yml` | `proxy/`, `manager/` | Multi-service images |

---

## Build Services

### Manager Service (Python)

**Location**: `manager/` directory
**Dockerfile**: `manager/Dockerfile`
**Architecture Support**: linux/amd64, linux/arm64, linux/arm/v7

**Build Steps**:
1. Lint with flake8, black, isort, mypy
2. Security scan with bandit, safety, pip-audit
3. Unit tests with pytest
4. Docker image build and push

**Environment Variables**:
- `REGISTRY`: Container registry (default: ghcr.io)
- `IMAGE_NAME`: Docker image name (default: ghcr.io/marchproxy/manager)
- `PYTHON_VERSION`: Python version (default: 3.12)

### Proxy Services (Go)

**Egress Proxy Location**: `proxy-egress/` directory
**Ingress Proxy Location**: `proxy-ingress/` directory
**Architecture Support**: linux/amd64, linux/arm64, linux/arm/v7

**Build Steps**:
1. Lint with golangci-lint
2. Security scan with gosec, govulncheck
3. Unit tests with go test
4. Docker image build and push

**Environment Variables**:
- `REGISTRY`: Container registry (default: ghcr.io)
- `IMAGE_NAME`: Docker image name (default: ghcr.io/marchproxy/proxy-egress or proxy-ingress)
- `GO_VERSION`: Go version (default: 1.21, 1.22 for combined builds)

---

## Naming Conventions

### Docker Image Tags

Image tags are generated automatically based on branch, version file, and build type:

#### Development Builds (alpha/beta with epoch64)
- **Feature/develop branches**: `alpha-<epoch64>`
  - Example: `alpha-1734001234`
  - Used for development and testing
  - Includes current epoch64 timestamp

- **Main branch**: `beta-<epoch64>`
  - Example: `beta-1734001234`
  - Staging-ready build with timestamp
  - Pre-release quality

#### Version-Based Tags (when .version file changes)
- **Feature/develop branches**: `v<VERSION>-alpha`
  - Example: `v1.2.3-alpha`
  - Corresponds to new version release candidate

- **Main branch**: `v<VERSION>-beta`
  - Example: `v1.2.3-beta`
  - Corresponds to version for beta testing

#### Release Tags (git tags)
- **Git tags (v*)**: `v<VERSION>` + `latest`
  - Example: `v1.2.3`, `latest`
  - Triggered by git tag creation
  - Used for production releases

#### Additional Metadata Tags
- Pull request builds: `pr-<pr-number>`
- Commit-based builds: `<branch>-<short-sha>`
- Default branch: `latest` (on release tags only)

### Version File Format

**Location**: `.version` file in repository root
**Format**: `vX.Y.Z` or `vX.Y.Z.EPOCH64`
- `X` = Major version (breaking changes)
- `Y` = Minor version (new features)
- `Z` = Patch version (bug fixes)
- `EPOCH64` = Optional build timestamp (auto-generated)

**Example**:
```
v1.2.3
v1.2.3.1734001234
```

---

## Path Filter Requirements

All workflows include path filters to ensure they only trigger on relevant changes. This optimizes CI/CD resource usage.

### Global Path Triggers

All workflows monitor `.version` file and workflow file itself:

```yaml
paths:
  - '.version'  # Version changes trigger all workflows
  - '.github/workflows/<workflow-name>.yml'  # Self-triggering
```

### Service-Specific Paths

| Service | Monitored Paths |
|---------|-----------------|
| Manager | `manager/**`, `.version` |
| Proxy Egress | `proxy-egress/**`, `.version` |
| Proxy Ingress | `proxy-ingress/**`, `.version` |
| Combined | `proxy/**`, `manager/**`, `.version` |
| Lint/Format | `manager/**`, `proxy/**`, `proxy-egress/**`, `proxy-ingress/**`, `.version` |
| Security | `manager/**`, `proxy/**`, `proxy-egress/**`, `proxy-ingress/**`, `.version` |

### Pull Request Paths

Pull request workflows only trigger on `main` branch with path filters applied. This prevents unnecessary runs for unrelated changes.

---

## Workflow Triggers

### On Push

Workflows trigger when:
1. Code changes in monitored directories
2. `.version` file changes (ensures all builds trigger on version updates)
3. Workflow file itself changes
4. Specific branch patterns: `main`, `develop`, `feature/*`, `release/*`

### On Pull Request

Pull request workflows trigger:
1. Only on `main` and `develop` branches
2. With same path filters as push workflows
3. Can be manually triggered via `workflow_dispatch`

### Scheduled Triggers

Security workflows run on a schedule:
- **Daily**: Security scans run at 2 AM UTC
- Manual trigger: Via `workflow_dispatch` input

---

## Security Scanning

### Integrated Scanning

All workflows include security scanning at multiple stages:

#### Dependency Scanning
- **Python**: bandit, safety, pip-audit
- **Go**: govulncheck, gosec
- Runs in security-scan job

#### Code Quality Scanning
- **Python**: flake8, black, isort, mypy (type checking)
- **Go**: golangci-lint, go vet, go fmt
- Runs in lint-and-test job

#### Container Scanning
- **Trivy**: Scans Docker images for vulnerabilities
- **Hadolint**: Lints Dockerfiles
- Runs after image build

#### Static Analysis
- **bandit**: Python security linting
- **gosec**: Go security scanning
- **Semgrep**: Multi-language SAST scanning

### Security Scan Artifacts

All security scan results are uploaded to GitHub:
- SARIF files for CodeQL analysis
- JSON reports for each scanner
- Summary reports in artifacts

---

## Version Release Workflow

### Automatic Pre-Release on Version Change

When `.version` file is updated:

1. **version-release.yml** workflow triggers
2. Reads `.version` file content
3. Checks if version differs from previous (git)
4. Creates GitHub pre-release with:
   - Release tag: `v<VERSION>`
   - Release notes auto-generated
   - Pre-release flag set to `true`

### Manual Release

Releases can be created manually via:
```bash
git tag v1.2.3
git push origin v1.2.3
```

This triggers:
1. **release.yml** workflow
2. Builds and pushes final images
3. Creates GitHub release (non-pre-release)
4. Tags images with `v1.2.3` and `latest`

### Version Update Process

To update version:

```bash
# Update version file
echo "v1.2.3" > .version

# Commit and push
git add .version
git commit -m "Release v1.2.3"
git push origin develop  # or main for release

# version-release.yml automatically creates pre-release
# Later, create final release with git tag
git tag v1.2.3
git push origin v1.2.3
```

---

## Build Optimization

### Caching Strategy

All workflows implement GitHub Actions caching for performance:

**Docker Images**:
- Uses GitHub Actions cache for Docker layers
- Cache key: Go/Python version + dependency hashes
- Significantly reduces build time (50%+ improvement)

**Dependencies**:
- **Go**: `.cache/go-build` and `go/pkg/mod` cached
- **Python**: pip packages cached in `~/.cache/pip`
- **Docker**: Layer cache via `type=gha`

### Multi-Architecture Builds

Manager and Proxy services build for three architectures:

```
Platforms:
  - linux/amd64    (Intel/AMD 64-bit)
  - linux/arm64    (ARM 64-bit, Apple Silicon, Graviton)
  - linux/arm/v7   (ARM 32-bit, Raspberry Pi)
```

Build times:
- Single-arch: ~5-10 minutes
- Multi-arch: ~15-25 minutes (parallel)

---

## Troubleshooting

### Common Issues

#### 1. Workflow Not Triggering

**Symptom**: Push to branch doesn't trigger workflow

**Causes**:
- Path filters don't match changed files
- Branch not in trigger list
- Workflow file syntax error

**Solution**:
```bash
# Check changed paths
git diff HEAD~1 --name-only

# Verify path filters in workflow match
# Edit .version or workflow file to force trigger
```

#### 2. Build Fails in Workflow but Works Locally

**Symptom**: Local build succeeds, GitHub Actions build fails

**Causes**:
- Environment differences (OS, tools, caches)
- Missing secrets or credentials
- Docker layer caching issues

**Solution**:
```bash
# Clear caches
# In GitHub: Settings > Actions > Clear all workflows

# Run with Docker locally
docker build -t test:latest .

# Check for hardcoded paths or environment assumptions
```

#### 3. Image Not Pushed to Registry

**Symptom**: Build succeeds but image not in container registry

**Causes**:
- Not logged into registry
- Registry credentials invalid
- Pull request (not pushed to registry by design)

**Solution**:
- Check GitHub secrets: `GITHUB_TOKEN` must be set
- Verify workflow runs on non-PR: `if: github.event_name != 'pull_request'`
- Manual push: `docker push <image>`

#### 4. Version Detection Fails

**Symptom**: Version shows as `0.0.0` instead of actual version

**Causes**:
- `.version` file missing
- `.version` has whitespace issues
- Version format incorrect

**Solution**:
```bash
# Check .version file
cat .version

# Fix format
echo "v1.2.3" > .version
echo "v1.2.3.1734001234" > .version  # with epoch
```

### Debug Commands

Enable workflow debug logging in GitHub Actions:
1. Go to repository Settings > Secrets and Variables > Actions
2. Add secret: `ACTIONS_STEP_DEBUG=true`
3. Re-run workflow for detailed logs

### Manual Workflow Execution

Trigger workflow manually:
```bash
# Via GitHub CLI
gh workflow run build-and-test.yml --ref main

# Via GitHub Web UI
1. Actions tab
2. Select workflow
3. "Run workflow" button
```

---

## Security Considerations

### Secrets Management

All workflows use GitHub secrets for credentials:
- `GITHUB_TOKEN`: Auto-injected, no action needed
- Custom secrets: Define in repository settings

**Do NOT**:
- Hardcode credentials in workflows
- Log secrets in output
- Commit `.env` files

### Code Review Workflow

All changes to workflows should be code reviewed:
1. Create feature branch
2. Modify workflow file
3. Create pull request
4. Security and syntax review required
5. Merge to main/develop

### Access Control

- Workflows can only access `GITHUB_TOKEN` by default
- Additional secrets require explicit environment configuration
- Deployments use separate `environment:` specifications for approval gates

---

## Integration with Development

### Local Testing of Workflows

Test workflow changes locally before pushing:

```bash
# Use act (GitHub Actions locally)
# https://github.com/nektos/act

act push -j lint-and-test

# Or build Docker image locally
docker build -f manager/Dockerfile -t manager:test .
```

### Continuous Development

During active development:
1. Push to `develop` branch (triggers alpha builds)
2. Test alpha builds in staging
3. Create PR against `main` for code review
4. Merge to `main` (triggers beta builds)
5. Tag release (triggers final builds and release)

### Adding New Workflow Files

When adding new workflows:
1. Follow existing naming pattern: `<component>-*.yml`
2. Include path filters for `.version` and workflow file
3. Add appropriate security scanning steps
4. Document in this file
5. Submit for code review

---

**Last Updated**: 2025-12-11
**Maintained by**: MarchProxy Team
