FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SNIPER_HOST=0.0.0.0 \
    SNIPER_PORT=8787 \
    SNIPER_ALLOW_REMOTE=1 \
    SNIPER_DATA_DIR=/var/lib/sniper \
    SNIPER_AUDIT_KEY_FILE=/var/lib/sniper-integrity/audit.key \
    SNIPER_AUTH_FIELD_KEY_FILE=/var/lib/sniper-secrets/auth-field-keys.json

WORKDIR /app

# Git is required for the bounded local history profile.
RUN apt-get update && apt-get install -y --no-install-recommends git libseccomp2 openssl && rm -rf /var/lib/apt/lists/*

# Authentication field encryption is a mandatory runtime capability.
# The exact dependency version is shared by source and container profiles.
COPY requirements-runtime.lock ./
RUN pip install --no-cache-dir --disable-pip-version-check --no-deps -r requirements-runtime.lock \
    && python -c "import cryptography; assert cryptography.__version__ == '41.0.7'"

# Create a non‑root user to run the application
RUN addgroup --system sniper && \
    adduser --system --ingroup sniper --home /app sniper

# Copy project sources into the image. Every top-level Python module is
# copied so newly added modules (including lazily imported auditors) can never
# drift out of an explicit allowlist. Tests live under tests/ and are excluded;
# secrets, databases and caches are filtered by .dockerignore.
COPY core/ ./core/
COPY docs/ ./docs/
COPY exporter/ ./exporter/
COPY monitoring/ ./monitoring/
COPY plugins/ ./plugins/
COPY rules/ ./rules/
COPY vendor/ ./vendor/
COPY static/ ./static/
COPY templates/nuclei/ ./templates/nuclei/
COPY *.py ./
COPY taint_js_bridge.cjs ./

# Create the data directory and give ownership to the non‑root user
# Denetim anahtarı ve çapaları veritabanı biriminden ayrı, kalıcı bir birimde durur.
RUN mkdir -p /var/lib/sniper /var/lib/sniper-integrity /var/lib/sniper-secrets \
    && chown -R sniper:sniper /app /var/lib/sniper /var/lib/sniper-integrity /var/lib/sniper-secrets \
    && chmod 0700 /var/lib/sniper /var/lib/sniper-integrity /var/lib/sniper-secrets \
    && chmod 0700 /app/plugins/user && chmod 0600 /app/plugins/user/*.py

USER sniper
EXPOSE 8787
VOLUME ["/var/lib/sniper", "/var/lib/sniper-integrity", "/var/lib/sniper-secrets"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=3)" || exit 1

CMD ["python", "server.py"]
