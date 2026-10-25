# Sniper Community local deployment

Sniper Community is designed to run from a reviewed source checkout on a local
machine. The web service binds to `127.0.0.1:8787` by default. Use a dedicated
data directory and do not point a new checkout at an existing production
database.

## Platform support

| Host path | Community v1 status |
| --- | --- |
| Linux ARM64 | Supported and release-tested for the native source setup and five locked optional engines |
| Linux x86-64 | Locked artifacts are provided; GitHub CI validates the source/container path |
| macOS native (Apple Silicon) | Supported and real-host verified for the native source setup (`--core-only`: `.venv`, built-in SAST/SCA/IaC analyzers, MCP, CLI, and loopback web interface); optional third-party Linux engine binaries run via the verified Docker Desktop profile below |
| macOS Apple Silicon + Docker Desktop | Supported and real-host verified for the five-engine Linux container profile (`./scripts/deploy-community-tools --accept-third-party-licenses`) |
| Windows native / WSL2 / Docker Desktop | Supported via `--core-only` native source setup (`python3 scripts/setup-community --core-only`), WSL2, or Docker Desktop Linux container profiles (`community-core` and license-gated `community-tools`) |

The default container runs the Sniper web application and does not bundle the five separately licensed optional
engines. The distinct `community-tools` build target installs exactly the five Linux artifacts in
`COMMUNITY-TOOLS.lock.json` after an explicit license acknowledgement. Linux-specific isolation profiles such as
bubblewrap/seccomp do not become native Windows or macOS capabilities merely because a Linux container is used.

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
python3 .github/scripts/validate-community-release.py
sha256sum --check COMMUNITY-SOURCE-MANIFEST.sha256
python3 scripts/sniper-mcp --help
```

The plain validator is appropriate for a Git checkout, which also contains
`.git` and may contain local caches. Use `--scan-release-tree` only on a freshly
assembled source directory as shown under **Source release assembly** below;
that stricter mode rejects every unlisted runtime artifact.

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

Plain `docker build .` and the default Compose build select `community-core` and never download optional engines.
To build the five-engine image after reviewing the licenses recorded in `COMMUNITY-TOOLS.lock.json`, run:

```bash
python3 scripts/build-community-tools-image --accept-third-party-licenses --dry-run
python3 scripts/build-community-tools-image --accept-third-party-licenses
```

The dry run prints the exact Compose plan without calling Docker or the network. The real command combines
`docker-compose.yml` with `docker-compose.tools.yml`, selects `community-tools`, verifies every downloaded archive
against its locked SHA-256, and does not execute a scanner. Omitting the acknowledgement fails before an optional
artifact is requested. Start that image with the same explicit gate:

```bash
SNIPER_ACCEPT_THIRD_PARTY_LICENSES=1 docker compose \
  -f docker-compose.yml -f docker-compose.tools.yml up -d sniper
```

Both profiles retain the loopback-only `127.0.0.1:8787` host publication and the same named data volumes. Docker
Desktop/WSL2 supplies a Linux container runtime; it does not turn the source installer or optional engines into native
Windows/macOS binaries.

Docker Desktop on Windows (PowerShell), core profile:

```powershell
docker compose up -d sniper
```

Docker Desktop on Windows (PowerShell), explicit five-engine profile:

```powershell
$env:SNIPER_ACCEPT_THIRD_PARTY_LICENSES = "1"
docker compose -f docker-compose.yml -f docker-compose.tools.yml up -d sniper
```

Docker Desktop on macOS or Docker from WSL2 uses the same Compose files from a POSIX shell:

```bash
docker compose up -d sniper
SNIPER_ACCEPT_THIRD_PARTY_LICENSES=1 docker compose \
  -f docker-compose.yml -f docker-compose.tools.yml up -d sniper
```

Review `COMMUNITY-TOOLS.lock.json` before setting the acknowledgement. The exact host run remains operator evidence;
the release gate validates the plans, merged Compose model, architecture mapping, and fail-closed acknowledgement.

### Verified macOS five-engine path

On Apple Silicon with Docker Desktop running, use the checked-in helper from the repository root after reviewing the
five separate open-source licenses in `COMMUNITY-TOOLS.lock.json`:

```bash
./scripts/deploy-community-tools --accept-third-party-licenses
```

This builds the digest-locked `community-tools` image, starts only Sniper on `127.0.0.1:8787`, and fails unless the
Nuclei loopback, Trivy local secret, Gitleaks, TruffleHog filesystem, and Opengrep local-code profiles all pass their
runtime prechecks. The helper creates a mode-`0600` `.env` with a random Grafana password only when that file is absent;
it never replaces an existing `.env`. It does not start monitoring or run a scan. The five binaries do not supply
Nuclei's separate broad template catalog, Trivy's offline vulnerability database, or the other prerequisite-dependent
tools; those profiles continue to show unavailable until their own verified inputs exist.

Docker Desktop can be denied macOS Documents/Downloads bind mounts even when the terminal can read those folders.
Instead of broadening Docker's filesystem access, explicitly copy one chosen project into the persistent
`sniper_projects` volume:

```bash
./scripts/import-community-project /absolute/path/to/project --name project-name
```

Then enter `/app/projects/project-name` in Sniper's local-project forms. The copy can include sensitive source files,
so choose the directory deliberately. Import never changes the Mac original and refuses to overwrite an existing
project name. The project copy persists across container restarts and `docker compose down`; include this volume in
your data handling and backups. This is a source snapshot, not a live sync. Re-import under a new name after source
changes, or use a Docker Desktop file-sharing bind mount only after explicitly granting that folder access.

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
