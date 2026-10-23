FROM python:3.12-slim AS community-runtime

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
    && python -m pip check \
    && python -c "import cffi, cryptography, pycparser; assert cryptography.__version__ == '50.0.2'"

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
RUN mkdir -p /app/projects /var/lib/sniper /var/lib/sniper-integrity /var/lib/sniper-secrets \
    && chown -R sniper:sniper /app /var/lib/sniper /var/lib/sniper-integrity /var/lib/sniper-secrets \
    && chmod 0700 /app/projects /var/lib/sniper /var/lib/sniper-integrity /var/lib/sniper-secrets \
    && chmod 0700 /app/plugins/user && chmod 0600 /app/plugins/user/*.py

USER sniper
EXPOSE 8787
VOLUME ["/var/lib/sniper", "/var/lib/sniper-integrity", "/var/lib/sniper-secrets"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=3)" || exit 1

CMD ["python", "server.py"]

# Optional five-engine image. The acceptance gate is deliberately the first
# instruction in this target: selecting it without an explicit acknowledgement
# fails before any third-party artifact is requested. The locked installer
# verifies every complete archive and never executes an installed scanner.
FROM community-runtime AS community-tools
ARG SNIPER_ACCEPT_THIRD_PARTY_LICENSES=0
RUN test "$SNIPER_ACCEPT_THIRD_PARTY_LICENSES" = "1" || \
    (echo "Third-party license acceptance is required for the community-tools target." >&2; exit 64)
COPY COMMUNITY-TOOLS.lock.json ./COMMUNITY-TOOLS.lock.json
COPY scripts/install-community-tools ./scripts/install-community-tools
RUN python scripts/install-community-tools \
    --profile local \
    --install-dir /app/runtimes \
    --accept-third-party-licenses

# Keep this stage last: plain `docker build .` and the default Compose file
# remain the network-minimal core image and never download optional engines.
FROM community-runtime AS community-core
