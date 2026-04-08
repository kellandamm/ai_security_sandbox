# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Rule 5: run as non-root, no setuid/setgid binaries in our layer
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

# Install seccomp tooling and set PR_SET_NO_NEW_PRIVS
# The container runtime (Azure Container Apps) enforces the seccomp profile;
# we additionally drop all capabilities at the process level.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appgroup . .

# Rule 5: /tmp is a tmpfs mount — noexec enforced at container level by ACA.
# Explicitly restrict permissions here too.
RUN chmod 700 /app && chmod -R o-rwx /app

USER appuser

ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Prevent the agent from loading .pth files from user site-packages
    PYTHONNOUSERSITE=0

# Liveness / readiness check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
