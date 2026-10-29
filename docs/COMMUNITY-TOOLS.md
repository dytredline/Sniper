# Community tool installation

Sniper's built-in analyzers, report parsers, MCP server, CLI, and local web interface are part of the source tree.
Selected third-party local executors are installed separately so their licenses, platform artifacts, and SHA-256
digests remain explicit.

On Linux ARM64 or x86-64, install the rootless local profile from the repository root:

```bash
python3 scripts/install-community-tools --profile local --accept-third-party-licenses
```

For a new checkout, `python3 scripts/setup-community --accept-third-party-licenses` also creates `.venv`, installs
`requirements-runtime.lock`, invokes this tool installer, and verifies the two documented command-line entrypoints.
It does not start the server or execute a scanner. Prepared offline Python wheels and tool artifacts can be supplied
with `--wheelhouse` and `--tool-cache-dir`.

The source core can be prepared without optional tools on Linux, or experimentally on macOS, with
`python3 scripts/setup-community --core-only`. Native Windows is intentionally rejected; use WSL2 or Docker Desktop's
Linux-container path. For an optional seven-engine container image, review the same lock-file licenses and run
`python3 scripts/build-community-tools-image --accept-third-party-licenses`; see `DEPLOYMENT.md` for the exact profile
and evidence boundary.

The command downloads only artifacts listed in `COMMUNITY-TOOLS.lock.json`, verifies each complete artifact before
extracting its declared executable, and never executes a scanner. It installs into the ignored `runtimes/` directory;
Sniper discovers the files, records their hashes, and still requires the normal local-input or target-authorization
approval before a scan. Re-running the command verifies the recorded install rather than silently replacing files.

The local profile contains Nuclei, Trivy, Gitleaks, TruffleHog, Opengrep, Syft, and Grype. The installed Nuclei binary works with
Sniper's checked-in pinned loopback template; the authorized broad HTTP workflow still requires its separately pinned
catalog. The installed Trivy binary enables configuration profiles; vulnerability profiles still require a separately
pinned offline database. Syft can produce a local manifest-only SBOM after installation; Grype vulnerability matching
also requires the separately pinned offline database documented by its readiness result. Each upstream license is recorded in the lock file and remains applicable. Review and accept
those terms before using the flag above.

For the separately downloaded official `nuclei-templates` v10.5.0 tag archive, the checked-in catalog builder verifies
the archive SHA-256, extracts only regular HTTP YAML files, rejects duplicate template IDs and symlinks, and creates
deterministic read-only pin/index manifests. It never updates an existing destination in place:

```bash
python3 scripts/install_nuclei_catalog.py \
  --archive /ABSOLUTE/PATH/nuclei-templates-v10.5.0.tar.gz \
  --destination /ABSOLUTE/PATH/runtimes/nuclei-templates-v10.5.0
```

The accepted archive SHA-256 is `80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41`.
The resulting catalog contains 11,655 templates; broad execution remains subject to the existing target authorization
and explicit approval workflow.

This command does not bundle commercial or service-hosted products. Burp Suite Professional requires a PortSwigger
license; GitHub CodeQL and Dependabot follow GitHub's terms; SSL Labs is a remote service. ZAP, Joern, browser
automation, Nmap, k6, full offline vulnerability databases, and other host-constrained profiles have additional
runtime or isolation requirements and must remain unavailable in the UI until their readiness checks pass. A missing
or unverified engine is never presented as installed merely because its report importer exists.

For an air-gapped installation, pre-download the exact lock-file assets on an authorized connected machine, place
them in one directory, and pass `--cache-dir /ABSOLUTE/PATH`. The same SHA-256 checks apply and no fallback artifact is
accepted.
