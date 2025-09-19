#!/bin/bash

# MarchProxy Test Runner
# Copyright (C) 2025 MarchProxy Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$PROJECT_ROOT/test"
REPORTS_DIR="$TEST_DIR/reports"
COVERAGE_DIR="$REPORTS_DIR/coverage"

# Create reports directory
mkdir -p "$REPORTS_DIR" "$COVERAGE_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    MarchProxy Test Suite Runner       ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Parse command line arguments
RUN_UNIT=true
RUN_INTEGRATION=false
RUN_LOAD=false
RUN_SECURITY=false
RUN_ALL=false
VERBOSE=false
COVERAGE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit)
            RUN_UNIT=true
            shift
            ;;
        --integration)
            RUN_INTEGRATION=true
            shift
            ;;
        --load)
            RUN_LOAD=true
            shift
            ;;
        --security)
            RUN_SECURITY=true
            shift
            ;;
        --all)
            RUN_ALL=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --coverage)
            COVERAGE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --unit         Run unit tests (default)"
            echo "  --integration  Run integration tests"
            echo "  --load         Run load tests"
            echo "  --security     Run security tests"
            echo "  --all          Run all test suites"
            echo "  --verbose, -v  Verbose output"
            echo "  --coverage     Generate coverage reports"
            echo "  --help, -h     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                     # Run unit tests only"
            echo "  $0 --all              # Run all test suites"
            echo "  $0 --unit --coverage  # Run unit tests with coverage"
            echo "  $0 --integration -v   # Run integration tests verbosely"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# If --all is specified, enable all test types
if [ "$RUN_ALL" = true ]; then
    RUN_UNIT=true
    RUN_INTEGRATION=true
    RUN_LOAD=true
    RUN_SECURITY=true
fi

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
TEST_SUITES_RUN=0

# Function to run unit tests
run_unit_tests() {
    echo -e "${YELLOW}Running Unit Tests...${NC}"
    echo "======================================"

    local test_failed=false

    # Python unit tests for manager
    if [ -f "$TEST_DIR/unit/manager_test.py" ]; then
        echo -e "${BLUE}Running Manager unit tests...${NC}"
        cd "$PROJECT_ROOT"

        if [ "$COVERAGE" = true ]; then
            python3 -m pytest "$TEST_DIR/unit/manager_test.py" \
                --cov=manager \
                --cov-report=html:"$COVERAGE_DIR/manager" \
                --cov-report=xml:"$COVERAGE_DIR/manager.xml" \
                --junit-xml="$REPORTS_DIR/manager_unit_tests.xml" \
                -v || test_failed=true
        else
            python3 "$TEST_DIR/unit/manager_test.py" || test_failed=true
        fi
    fi

    # Go unit tests for proxy
    if [ -f "$TEST_DIR/unit/proxy_test.go" ]; then
        echo -e "${BLUE}Running Proxy unit tests...${NC}"
        cd "$PROJECT_ROOT/proxy"

        if [ "$COVERAGE" = true ]; then
            go test -v -coverprofile="$COVERAGE_DIR/proxy.out" \
                -covermode=count \
                ../test/unit/proxy_test.go || test_failed=true

            # Generate HTML coverage report
            go tool cover -html="$COVERAGE_DIR/proxy.out" \
                -o "$COVERAGE_DIR/proxy.html"
        else
            go test -v ../test/unit/proxy_test.go || test_failed=true
        fi
    fi

    if [ "$test_failed" = true ]; then
        echo -e "${RED}❌ Unit tests failed${NC}"
        ((FAILED_TESTS++))
    else
        echo -e "${GREEN}✅ Unit tests passed${NC}"
        ((PASSED_TESTS++))
    fi

    ((TEST_SUITES_RUN++))
    echo ""
}

# Function to run integration tests
run_integration_tests() {
    echo -e "${YELLOW}Running Integration Tests...${NC}"
    echo "======================================"

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is required for integration tests${NC}"
        ((FAILED_TESTS++))
        ((TEST_SUITES_RUN++))
        return
    fi

    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}❌ docker-compose is required for integration tests${NC}"
        ((FAILED_TESTS++))
        ((TEST_SUITES_RUN++))
        return
    fi

    local test_failed=false

    echo -e "${BLUE}Starting integration test environment...${NC}"
    cd "$PROJECT_ROOT"

    # Start services with docker-compose
    docker-compose -f docker-compose.yml up -d || {
        echo -e "${RED}❌ Failed to start integration test environment${NC}"
        test_failed=true
    }

    if [ "$test_failed" = false ]; then
        # Wait for services to be ready
        echo "Waiting for services to be ready..."
        sleep 30

        # Run integration tests
        python3 "$TEST_DIR/integration/integration_test.py" || test_failed=true

        # Stop services
        docker-compose -f docker-compose.yml down
    fi

    if [ "$test_failed" = true ]; then
        echo -e "${RED}❌ Integration tests failed${NC}"
        ((FAILED_TESTS++))
    else
        echo -e "${GREEN}✅ Integration tests passed${NC}"
        ((PASSED_TESTS++))
    fi

    ((TEST_SUITES_RUN++))
    echo ""
}

# Function to run load tests
run_load_tests() {
    echo -e "${YELLOW}Running Load Tests...${NC}"
    echo "======================================"

    local test_failed=false

    # Check if required Python packages are available
    python3 -c "import aiohttp, matplotlib, pandas" 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Installing required packages for load testing...${NC}"
        pip3 install aiohttp matplotlib pandas || {
            echo -e "${RED}❌ Failed to install required packages${NC}"
            test_failed=true
        }
    }

    if [ "$test_failed" = false ]; then
        echo -e "${BLUE}Running load tests (this may take several minutes)...${NC}"
        cd "$TEST_DIR/load"

        # Run load tests with reasonable parameters for CI
        python3 load_test.py \
            --test all \
            --users 10 \
            --requests 20 \
            --duration 30 || test_failed=true

        # Move reports to reports directory
        if [ -f "load_test_report.html" ]; then
            mv load_test_report.html "$REPORTS_DIR/"
        fi
        if [ -f "load_test_charts.png" ]; then
            mv load_test_charts.png "$REPORTS_DIR/"
        fi
    fi

    if [ "$test_failed" = true ]; then
        echo -e "${RED}❌ Load tests failed${NC}"
        ((FAILED_TESTS++))
    else
        echo -e "${GREEN}✅ Load tests passed${NC}"
        ((PASSED_TESTS++))
    fi

    ((TEST_SUITES_RUN++))
    echo ""
}

# Function to run security tests
run_security_tests() {
    echo -e "${YELLOW}Running Security Tests...${NC}"
    echo "======================================"

    local test_failed=false

    echo -e "${BLUE}Running security test suite...${NC}"
    python3 "$TEST_DIR/security/security_test.py" || test_failed=true

    # Run additional security checks if tools are available
    if command -v bandit &> /dev/null; then
        echo -e "${BLUE}Running Bandit security linter...${NC}"
        bandit -r "$PROJECT_ROOT/manager" \
            -f json -o "$REPORTS_DIR/bandit_report.json" || true
        bandit -r "$PROJECT_ROOT/manager" || true
    fi

    if command -v safety &> /dev/null; then
        echo -e "${BLUE}Checking for known security vulnerabilities...${NC}"
        safety check --json --output "$REPORTS_DIR/safety_report.json" || true
        safety check || true
    fi

    if [ "$test_failed" = true ]; then
        echo -e "${RED}❌ Security tests failed${NC}"
        ((FAILED_TESTS++))
    else
        echo -e "${GREEN}✅ Security tests passed${NC}"
        ((PASSED_TESTS++))
    fi

    ((TEST_SUITES_RUN++))
    echo ""
}

# Function to generate final report
generate_report() {
    echo -e "${BLUE}Generating Test Report...${NC}"
    echo "======================================"

    local report_file="$REPORTS_DIR/test_summary.html"

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MarchProxy Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; color: #333; }
        .summary { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .passed { color: #4CAF50; font-weight: bold; }
        .failed { color: #F44336; font-weight: bold; }
        .metric { display: inline-block; margin: 10px 20px; }
        .metric-value { font-size: 1.5em; font-weight: bold; }
        .metric-label { color: #666; }
        ul { list-style-type: none; padding-left: 0; }
        li { padding: 5px 0; }
        .file-link { color: #2196F3; text-decoration: none; }
        .file-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MarchProxy Test Report</h1>
        <p>Generated on: $(date)</p>
    </div>

    <div class="summary">
        <h2>Test Summary</h2>
        <div class="metric">
            <div class="metric-value">$TEST_SUITES_RUN</div>
            <div class="metric-label">Test Suites Run</div>
        </div>
        <div class="metric">
            <div class="metric-value passed">$PASSED_TESTS</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric">
            <div class="metric-value failed">$FAILED_TESTS</div>
            <div class="metric-label">Failed</div>
        </div>
    </div>

    <h2>Generated Reports</h2>
    <ul>
EOF

    # Add links to generated reports
    for report in "$REPORTS_DIR"/*.{html,xml,json,png} 2>/dev/null; do
        if [ -f "$report" ]; then
            local filename=$(basename "$report")
            echo "        <li><a href=\"$filename\" class=\"file-link\">$filename</a></li>" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF
    </ul>

    <h2>Coverage Reports</h2>
    <ul>
EOF

    # Add links to coverage reports
    for coverage_report in "$COVERAGE_DIR"/*.html 2>/dev/null; do
        if [ -f "$coverage_report" ]; then
            local filename=$(basename "$coverage_report")
            local relative_path="coverage/$filename"
            echo "        <li><a href=\"$relative_path\" class=\"file-link\">$filename</a></li>" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF
    </ul>
</body>
</html>
EOF

    echo -e "${GREEN}✅ Test report generated: $report_file${NC}"
}

# Main execution
echo "Project Root: $PROJECT_ROOT"
echo "Test Directory: $TEST_DIR"
echo "Reports Directory: $REPORTS_DIR"
echo ""

# Run selected test suites
if [ "$RUN_UNIT" = true ]; then
    run_unit_tests
fi

if [ "$RUN_INTEGRATION" = true ]; then
    run_integration_tests
fi

if [ "$RUN_LOAD" = true ]; then
    run_load_tests
fi

if [ "$RUN_SECURITY" = true ]; then
    run_security_tests
fi

# Generate final report
generate_report

# Print final summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}           Test Summary                 ${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Test Suites Run: $TEST_SUITES_RUN"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}💥 Some tests failed!${NC}"
    exit 1
fi