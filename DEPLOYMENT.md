# Sniper Community local deployment

Sniper Community is designed to run from a reviewed source checkout on a local
machine. The web service binds to `127.0.0.1:8787` by default. Use a dedicated
data directory and do not point a new checkout at an existing production
database.

The Community source distribution intentionally does not include commercial
packaging, customer-bound licensing, private installers, or native-binary
delivery tooling. Replace the source tree only after reviewing a new archive
and verifying its published SHA-256 digest and
`COMMUNITY-SOURCE-MANIFEST.sha256`.

## Source checkout

Python 3.12 is the tested interpreter. Create an isolated environment and
install the exact runtime dependency lock:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-runtime.lock
python3 .github/scripts/validate-community-release.py --scan-release-tree
python3 scripts/sniper-mcp --help
```

Start the loopback web service with a new data directory:

```bash
export SNIPER_DATA_DIR="$PWD/.local-data"
python3 server.py
```

The source checkout is not a system installer. Keep application source and
data backups separate. The local web backup action uses SQLite's online backup
API; recovery remains an explicit operator procedure and is never started by
the MCP server.

## Container deployment

Docker deployment is optional. Every published port in the checked-in Compose
file is bound to loopback.

```bash
./scripts/build.sh
./scripts/deploy.sh
```

`scripts/deploy.sh` creates a mode-`0600` `.env` file with a random local
Grafana password when one does not already exist. It does not print the
password. The local endpoints are:

- Sniper: `http://127.0.0.1:8787`
- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:9090`

Stop the containers without deleting named data volumes:

```bash
docker compose --profile monitoring down
```

Do not add `--volumes` unless the stored application and monitoring data are
intentionally being deleted.

## Remote access

Do not publish port 8787 on all interfaces. For remote administration, enable
Sniper authentication first and use an authenticated tunnel or a reviewed TLS
reverse proxy. The Compose acknowledgement exists only because the container
listens on its internal interface while the host publishes it on
`127.0.0.1`; it is not transport encryption and must not be copied to a public
bind.

Additional Host header names require `SNIPER_ALLOWED_HOSTS`. Treat remote MCP
model access separately: the MCP process uses stdio, but its host application
may send source excerpts and findings to a model provider.

## Data and secrets

Container state is split across the `sniper_data`, `sniper_integrity`, and
`sniper_secrets` volumes. Authentication field keys are outside the main
SQLite volume. Back up the field-key volume together with `auth.db`; encrypted
TOTP fields cannot be recovered without the matching key.

User plugins are executable Python and remain disabled by default. Enable only
reviewed, locally owned plugin files that are not group/world writable.

## Offline verification

The Community release gate and source assembler are offline. They do not start
scanners or open a database:

```bash
python3 .github/scripts/validate-community-release.py
python3 scripts/build-community-source.py \
  --output /ABSOLUTE/PATH/TO/sniper-community-source
python3 .github/scripts/validate-community-release.py \
  --root /ABSOLUTE/PATH/TO/sniper-community-source --scan-release-tree
```

The final command checks the manifest, rejects runtime state and private build
metadata, and fails if excluded delivery implementation is reintroduced.

## External-target safety

Run active tools only against systems you own or are explicitly authorized to
assess. Verify target identity, written scope, timing, rate limits, data
handling, and stop conditions before approving the exact MCP action plan.
