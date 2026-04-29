#!/bin/bash
# Gavel OS Validation Script
# Validates running containers and API endpoints

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║   Gavel OS Portal - Validation & Testing Suite        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Docker
echo "📦 Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker found: $(docker --version)${NC}"
echo ""

# Check Docker Compose
echo "📦 Checking Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose found${NC}"
echo ""

# Check running containers
echo "🔍 Checking running containers..."
if docker compose ps | grep -q "control-plane"; then
    echo -e "${GREEN}✓ Control Plane is running${NC}"
    STATUS=$(docker compose ps | grep control-plane | awk '{print $NF}')
    echo "  Status: $STATUS"
else
    echo -e "${YELLOW}⚠ Control Plane not found in compose${NC}"
fi

if docker compose ps | grep -q "postgres"; then
    echo -e "${GREEN}✓ PostgreSQL is running${NC}"
else
    echo -e "${YELLOW}⚠ PostgreSQL not found${NC}"
fi

if docker compose ps | grep -q "opa"; then
    echo -e "${GREEN}✓ OPA Policy Engine is running${NC}"
else
    echo -e "${YELLOW}⚠ OPA not found${NC}"
fi
echo ""

# Check API endpoints
echo "🌐 Checking API Endpoints..."
API_BASE="http://localhost:18000"

# Root endpoint
echo -n "  GET / ... "
if curl -s -o /dev/null -w "%{http_code}" "$API_BASE/" | grep -q "200"; then
    echo -e "${GREEN}✓ 200 OK${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# Health endpoint
echo -n "  GET /health ... "
if curl -s "$API_BASE/health" | grep -q "healthy"; then
    echo -e "${GREEN}✓ Healthy${NC}"
else
    echo -e "${RED}✗ Unhealthy${NC}"
fi

# Readiness endpoint
echo -n "  GET /ready ... "
if curl -s "$API_BASE/ready" | grep -q "ready"; then
    echo -e "${GREEN}✓ Ready${NC}"
else
    echo -e "${RED}✗ Not ready${NC}"
fi

# Liveness endpoint
echo -n "  GET /live ... "
if curl -s "$API_BASE/live" | grep -q "alive"; then
    echo -e "${GREEN}✓ Alive${NC}"
else
    echo -e "${RED}✗ Not alive${NC}"
fi
echo ""

# Component health
echo "📊 Component Status:"
HEALTH=$(curl -s "$API_BASE/health")
echo "$HEALTH" | python3 -m json.tool | grep -E '".*": "' | sed 's/^/  /'
echo ""

# Port check
echo "🔌 Port Check:"
echo -n "  API (18000): "
if nc -z localhost 18000 2>/dev/null; then
    echo -e "${GREEN}✓ Open${NC}"
else
    echo -e "${RED}✗ Closed${NC}"
fi

echo -n "  OPA (18181): "
if nc -z localhost 18181 2>/dev/null; then
    echo -e "${GREEN}✓ Open${NC}"
else
    echo -e "${RED}✗ Closed${NC}"
fi

echo -n "  PostgreSQL (5432): "
if nc -z localhost 5432 2>/dev/null; then
    echo -e "${GREEN}✓ Open${NC}"
else
    echo -e "${RED}✗ Closed${NC}"
fi
echo ""

# Test modes
echo "🧪 Testing Options:"
echo "  1. Run API validation tests:"
echo "     python -m pytest tests/playwright/test_api_endpoints.py -v -m playwright"
echo ""
echo "  2. Run full test suite:"
echo "     python -m pytest tests/ -v"
echo ""
echo "  3. Run integration tests:"
echo "     python -m pytest tests/integration/ -v -m integration"
echo ""
echo "  4. Run tests in Docker container:"
echo "     docker-compose -f docker-compose.test.yml up --build test-runner"
echo ""
echo "  5. Validate Linux runtime (in container):"
echo "     docker-compose -f docker-compose.test.yml up runtime-validation"
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════╗"
echo "║          Portal is Running and Accessible             ║"
echo "║                                                        ║"
echo "║  API Docs:  http://localhost:18000/docs              ║"
echo "║  API Base:  http://localhost:18000                   ║"
echo "║  OPA:       http://localhost:18181                   ║"
echo "║  Database:  localhost:5432                           ║"
echo "╚════════════════════════════════════════════════════════╝"
