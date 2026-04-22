FROM python:3.11-slim AS base

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
    mkdir -p /app/auth/keys && \
    chown -R gavel:root /app
USER gavel

EXPOSE 8000 50051

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
