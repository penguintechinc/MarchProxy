# MarchProxy API Server Dockerfile
# Multi-stage build for FastAPI + Go xDS server

# Stage 1: Build Python dependencies
FROM python:3.11-slim as python-builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Development stage
FROM python:3.11-slim AS development

LABEL maintainer="MarchProxy Contributors"
LABEL description="MarchProxy API Server - Development"

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=python-builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY app/ ./app/

# Create non-root user
RUN useradd -m -u 1000 marchproxy && \
    chown -R marchproxy:marchproxy /app

# Expose ports
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

# Start FastAPI with uvicorn in reload mode
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Stage 3: Production stage
FROM python:3.11-slim AS production

LABEL maintainer="MarchProxy Contributors"
LABEL description="MarchProxy API Server - FastAPI Backend"

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=python-builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY app/ ./app/

# Create non-root user (for future use)
RUN useradd -m -u 1000 marchproxy && \
    chown -R marchproxy:marchproxy /app

# Run as root to access installed packages
# In production, use a service account with proper permissions

# Expose ports
# 8000: FastAPI REST API
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

# Start FastAPI with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
