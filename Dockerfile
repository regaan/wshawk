# WSHawk - Professional WebSocket Security Scanner
# Multi-stage build for smaller image size

FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY setup.py pyproject.toml README.md ./
COPY wshawk/ ./wshawk/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Final stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies for Playwright (optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/wshawk* /usr/local/bin/

# Create non-root user
RUN useradd -m -u 1000 wshawk && \
    chown -R wshawk:wshawk /app

USER wshawk

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wshawk --help || exit 1

# Default command
ENTRYPOINT ["wshawk"]
CMD ["--help"]

# Labels (OpenContainers standard for GitHub Container Registry)
LABEL maintainer="Regaan"
LABEL description="WSHawk - Professional WebSocket Security Scanner with Defensive Validation"
LABEL version="4.0.0"
LABEL org.opencontainers.image.source="https://github.com/regaan/wshawk"
LABEL org.opencontainers.image.description="Professional WebSocket security scanner with real vulnerability verification, defensive validation, and CVSS scoring"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.title="WSHawk"
LABEL org.opencontainers.image.vendor="Regaan"
LABEL org.opencontainers.image.url="https://github.com/regaan/wshawk"
LABEL org.opencontainers.image.documentation="https://github.com/regaan/wshawk/blob/main/README.md"
