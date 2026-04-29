# Escalation Workflows & Health Checks Implementation

**Date:** April 2026  
**Phase:** Next-Phase Implementation (completed)

---

## Summary

This document describes the implementation of escalation workflows, health checks, and circuit breaker resilience for Gavel OS control plane.

Three major features were implemented:

1. **Escalation Workflows** - Database-backed tool proposal approval chains
2. **Health Check Service** - System dependency monitoring with component status
3. **Circuit Breaker Pattern** - Resilience against cascading OPA failures

---

## 1. Escalation Workflows

### Overview

Tool proposals that require approval are managed through escalation workflows. When SRP VerdictEngine returns ESCALATE, a new escalation record is created and approvers are notified.

### Service API

**EscalationService** (control-plane/service/escalation_service.py):

- create_escalation() - Create new escalation with ticket number
- approve_escalation() - Record approval/denial decision  
- get_escalation_status() - Query escalation with approval history
- get_pending_escalations() - List pending escalations for tenant
- auto_deny_expired() - Background task for deadline enforcement

### HTTP Endpoints

**Escalation Routes** (control-plane/api/routes/escalations.py):

- POST /escalations/{escalation_id}/approve - Record approval/denial
- GET /escalations/{escalation_id} - Get escalation status
- GET /escalations - List pending escalations for tenant

All endpoints use TenantContext for tenant isolation.

### Database Schema

Three tables created in 003_create_escalation_tables.sql:

- escalations: Escalation records with status and deadline
- escalation_approvals: Approval decisions from reviewers
- escalation_approvers: Users authorized to approve per tenant

---

## 2. Health Check Service

### Overview

The health check service provides visibility into system component status, enabling monitoring, alerting, and graceful degradation.

### Service API

**HealthCheckService** (control-plane/service/health_check.py):

- check_opa_health() - Check OPA availability including circuit breaker
- check_db_health() - Check database connectivity
- get_system_health() - Overall system health status

### HTTP Endpoints

**Health Routes** (control-plane/api/routes/health.py):

- GET /health - Overall system health (returns 503 if degraded)
- GET /health/opa - OPA-specific health including circuit breaker state
- GET /health/db - Database-specific health

Health response includes component status, messages, and circuit breaker state.

---

## 3. Circuit Breaker Pattern

### Overview

The circuit breaker prevents cascading failures when OPA becomes unreliable. It tracks consecutive failures and temporarily "opens" to fail-closed rather than hammering a struggling service.

### States

- CLOSED: Normal operation
- OPEN: Rejecting requests after N failures  
- HALF_OPEN: Testing recovery after timeout

### Implementation

**CircuitBreaker** (control-plane/sentinel/circuit_breaker.py):

- Configurable failure threshold (default: 5)
- Configurable recovery timeout (default: 60 seconds)
- Automatic state transitions
- Status reporting for monitoring

### Integration in OPA Engine

All OPA requests protected by circuit breaker. Configuration via environment:

- OPA_CB_FAILURE_THRESHOLD: Failures before opening (default: 5)
- OPA_CB_RECOVERY_TIMEOUT: Seconds before testing recovery (default: 60)

---

## Testing

### Unit Tests (21 passing)

Existing tests cover OPA engine, audit ledger chaining, and Pydantic models.

### Integration Tests (new)

TestEscalationWorkflows:
- Create escalation, complete approval workflow, list pending, auto-deny expired

TestHealthChecks:
- Service creation, OPA health, database health, aggregate status

TestCircuitBreaker:
- Initialization, success, failure threshold, status retrieval

TestOPAEngineResilience:
- Circuit breaker integration, status reporting

---

## Deployment

1. Run migrations: 002_add_tenancy.sql, 003_create_escalation_tables.sql
2. Set environment variables for circuit breaker thresholds
3. Initialize EscalationService and HealthCheckService in app startup
4. Register routes: /escalations/*, /health/*
5. Configure notification backend
6. Set up monitoring on health endpoints
7. Test escalation workflow with sample data

---

## Files Summary

Core:
- control-plane/service/escalation_service.py
- control-plane/service/health_check.py
- control-plane/sentinel/circuit_breaker.py
- control-plane/api/routes/escalations.py
- control-plane/api/routes/health.py
- control-plane/models/escalation.py

Tests:
- tests/integration/test_external_endpoints.py
- tests/integration/test_health_and_resilience.py

Database:
- control-plane/db/migrations/002_add_tenancy.sql
- control-plane/db/migrations/003_create_escalation_tables.sql

---

## Key Features

✅ Tool Proposal Escalations - Approval chains for high-risk operations
✅ System Observability - Health checks for all components
✅ Resilience - Circuit breaker prevents cascade failures
✅ Multi-Tenancy - Tenant isolation across all workflows
✅ Comprehensive Testing - Unit and integration tests
