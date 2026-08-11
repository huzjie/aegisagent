# syntax=docker/dockerfile:1.7

# ── Stage 1: Builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .[all]

COPY aegis/ ./aegis/
RUN pip install --no-cache-dir --prefix=/install .

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="AegisAgent Contributors"
LABEL org.opencontainers.image.title="AegisAgent"
LABEL org.opencontainers.image.description="AI Agent Runtime Security Gateway"
LABEL org.opencontainers.image.version="1.0.0"

# Security: no new privileges, non-root user
RUN groupadd -r aegis && useradd -r -g aegis -s /sbin/nologin aegis \
    && mkdir -p /etc/aegis /var/log/aegis /var/lib/aegis \
    && chown -R aegis:aegis /etc/aegis /var/log/aegis /var/lib/aegis

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=aegis:aegis aegis/ /opt/aegis/aegis/
COPY --chown=aegis:aegis pyproject.toml /opt/aegis/

WORKDIR /opt/aegis

USER aegis

EXPOSE 8901 8902

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8901/health')" || exit 1

ENTRYPOINT ["python", "-m", "aegis.cli"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8901"]
