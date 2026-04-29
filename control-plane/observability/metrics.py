"""OpenTelemetry metrics for Gavel."""

from typing import Optional

from opentelemetry import metrics

# Get the global meter
_meter = metrics.get_meter(__name__)


class OPAMetrics:
    """Metrics for OPA policy engine."""

    def __init__(self):
        self.query_duration = _meter.create_histogram(
            name="opa.query.duration_ms",
            description="OPA query execution duration in milliseconds",
            unit="ms",
        )
        self.query_count = _meter.create_counter(
            name="opa.queries.total",
            description="Total number of OPA queries",
            unit="1",
        )
        self.query_errors = _meter.create_counter(
            name="opa.queries.errors",
            description="Number of OPA query errors",
            unit="1",
        )

    def record_query(self, duration_ms: float, success: bool, policy: str = "unknown"):
        """Record OPA query metrics."""
        self.query_count.add(1, {"policy": policy})
        self.query_duration.record(duration_ms, {"policy": policy})
        if not success:
            self.query_errors.add(1, {"policy": policy})


class AuditMetrics:
    """Metrics for audit ledger operations."""

    def __init__(self):
        self.write_duration = _meter.create_histogram(
            name="audit.write.duration_ms",
            description="Audit ledger write duration in milliseconds",
            unit="ms",
        )
        self.write_count = _meter.create_counter(
            name="audit.writes.total",
            description="Total number of audit ledger writes",
            unit="1",
        )
        self.write_errors = _meter.create_counter(
            name="audit.writes.errors",
            description="Number of audit ledger write errors",
            unit="1",
        )

    def record_write(self, duration_ms: float, success: bool, event_type: str = "unknown"):
        """Record audit write metrics."""
        self.write_count.add(1, {"event_type": event_type})
        self.write_duration.record(duration_ms, {"event_type": event_type})
        if not success:
            self.write_errors.add(1, {"event_type": event_type})


class VerdictMetrics:
    """Metrics for policy verdict decisions."""

    def __init__(self):
        self.verdict_count = _meter.create_counter(
            name="verdict.total",
            description="Total verdicts issued",
            unit="1",
        )
        self.verdict_by_result = _meter.create_counter(
            name="verdict.by_result",
            description="Verdicts broken down by result (allow/deny/escalate)",
            unit="1",
        )

    def record_verdict(self, verdict: str, policy: str = "unknown"):
        """Record verdict decision."""
        self.verdict_count.add(1, {"policy": policy})
        self.verdict_by_result.add(1, {"verdict": verdict, "policy": policy})


class EscalationMetrics:
    """Metrics for escalation workflow."""

    def __init__(self):
        self.escalation_count = _meter.create_counter(
            name="escalation.created",
            description="Number of escalations created",
            unit="1",
        )
        self.approval_count = _meter.create_counter(
            name="escalation.approvals",
            description="Number of escalation approvals",
            unit="1",
        )
        self.denial_count = _meter.create_counter(
            name="escalation.denials",
            description="Number of escalation denials",
            unit="1",
        )
        self.time_to_approval = _meter.create_histogram(
            name="escalation.approval_time_seconds",
            description="Time from escalation creation to approval in seconds",
            unit="s",
        )

    def record_escalation_created(self, escalation_type: str = "unknown"):
        """Record escalation creation."""
        self.escalation_count.add(1, {"type": escalation_type})

    def record_approval(self, approval_time_seconds: float, escalation_type: str = "unknown"):
        """Record escalation approval."""
        self.approval_count.add(1, {"type": escalation_type})
        self.time_to_approval.record(approval_time_seconds, {"type": escalation_type})

    def record_denial(self, escalation_type: str = "unknown"):
        """Record escalation denial."""
        self.denial_count.add(1, {"type": escalation_type})


# Global metric instances
opa_metrics = OPAMetrics()
audit_metrics = AuditMetrics()
verdict_metrics = VerdictMetrics()
escalation_metrics = EscalationMetrics()
