"""
setup.py — OpenTelemetry Instrumentation Config

Configures the global TracerProvider, sets up the OTLP Exporter
(e.g., Jaeger/Datadog), and provides a helper to instrument the
FastAPI application and its backing services.
"""

import logging
import os

# Note: asyncpg and redis instrumentors need to be called on their respective connection pools
from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

logger = logging.getLogger("sentinel.telemetry")


def setup_telemetry(app: FastAPI, service_name: str = "sentinel-recipe-engine"):
    """
    Initializes OpenTelemetry tracing for the application.
    """
    env = os.getenv("ENV", "development")
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

    # 1. Resource defines the entity producing telemetry
    resource = Resource.create({SERVICE_NAME: service_name, "deployment.environment": env})

    # 2. Configure the Global Tracer Provider
    provider = TracerProvider(resource=resource)

    # 3. Add Exporters
    if env == "production" or os.getenv("ENABLE_OTLP", "false").lower() == "true":
        # Export to Jaeger / OTEL Collector
        _insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "false").lower() == "true"
        otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=_insecure)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        logger.info("OpenTelemetry OTLP Exporter enabled targeting %s", otlp_endpoint)
    else:
        # Development fallback: don't dump to stdout to avoid log noise
        logger.info("OpenTelemetry Console Exporter disabled intentionally to reduce noise")

    # Set as the global provider used by all instrumentors
    trace.set_tracer_provider(provider)

    # 4. Configure Prometheus Metrics Exporter
    try:
        reader = PrometheusMetricReader()
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)
        logger.info("OpenTelemetry Prometheus Exporter enabled")
    except Exception as e:
        logger.warning("Failed to setup Prometheus Exporter: %s", e)

    # 4. Instrument Frameworks
    FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor().instrument()

    # Optional extensions based on what is available in the environment
    try:
        from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor

        AsyncPGInstrumentor().instrument()
    except ImportError:
        logger.warning("AsyncPG instrumentor not available")

    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor

        RedisInstrumentor().instrument()
    except ImportError:
        logger.warning("Redis instrumentor not available")

    try:
        from opentelemetry.instrumentation.logging import LoggingInstrumentor

        LoggingInstrumentor().instrument(set_logging_format=True)
    except ImportError:
        logger.warning("Logging instrumentor not available")

    logger.info("OpenTelemetry instrumented FastAPI, HTTPX, Postgres, Redis, and Logging")
