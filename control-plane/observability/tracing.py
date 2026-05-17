"""OpenTelemetry tracing setup for Gavel."""

import os

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
except ImportError:
    OTLPSpanExporter = None

# Get the global tracer provider
_tracer_provider: TracerProvider | None = None


def initialize_tracing(
    service_name: str = "gavel-control-plane",
    otel_exporter_otlp_endpoint: str | None = None,
) -> trace.TracerProvider:
    """Initialize OpenTelemetry tracing with OTLP exporter."""
    global _tracer_provider

    if _tracer_provider is not None:
        return _tracer_provider

    # Get endpoint from environment or parameter
    endpoint = otel_exporter_otlp_endpoint or os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "grpc://localhost:4317",  # Default to local Jaeger
    )

    # Create TracerProvider
    tracer_provider = TracerProvider()

    # Add OTLP exporter
    try:
        if OTLPSpanExporter is None:
            raise RuntimeError("OTLP exporter package is not installed or is incompatible")
        otlp_exporter = OTLPSpanExporter(endpoint=endpoint)
        tracer_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
    except Exception as e:
        # If OTLP export fails, continue without it
        print(f"Warning: Failed to initialize OTLP exporter: {e}")

    # Set as global tracer provider
    trace.set_tracer_provider(tracer_provider)
    _tracer_provider = tracer_provider

    return tracer_provider


def get_tracer(name: str) -> trace.Tracer:
    """Get a tracer for a specific module."""
    return trace.get_tracer(name)


class TracingContext:
    """Context manager for creating spans."""

    def __init__(self, tracer: trace.Tracer, name: str, attributes: dict | None = None):
        self.tracer = tracer
        self.name = name
        self.attributes = attributes or {}
        self.span = None

    def __enter__(self):
        """Start a span."""
        self.span = self.tracer.start_span(self.name)
        if self.attributes:
            for key, value in self.attributes.items():
                self.span.set_attribute(key, value)
        return self.span

    def __exit__(self, exc_type, exc_val, exc_tb):
        """End the span."""
        if exc_type:
            self.span.set_attribute("error", True)
            self.span.set_attribute("error.type", exc_type.__name__)
            if exc_val:
                self.span.set_attribute("error.message", str(exc_val))
        self.span.end()
