FROM python:3.13-slim AS base

WORKDIR /app

# System deps for cryptography and asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user — create keys directory with correct ownership before switching
RUN useradd -r -u 1001 -g root gavel && \
    mkdir -p /tmp/gavel-keys && \
    mkdir -p /tmp/gavel-grpc-dev && \
    chown -R gavel:root /app
USER gavel

EXPOSE 8000 50051

# Use the new main.py from Phase 1-3 implementation
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
