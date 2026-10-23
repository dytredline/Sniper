# Changelog

All notable changes to Sniper Community are recorded here. The project follows semantic versioning for public
Community releases.

## Sniper Community 1.0.0 — 2026-10-24

- Added local-first source, configuration, dependency, container, and report workflows.
- Added the stdio MCP interface with expiring, single-use, human-confirmed MCP action plans.
- Added the loopback web interface and manual command-line entrypoints.
- Added deterministic Community source assembly with SHA-256 manifests and fail-closed release validation.
- Added a one-command rootless setup plus a SHA-256-locked installer for the supported local third-party tool profile.
- Added a Linux core-only setup, an experimental macOS core-only source path, and a fail-closed Windows-native
  refusal with WSL2/Docker guidance.
- Added separate `community-core` and license-gated `community-tools` container targets for Docker Desktop/WSL2;
  the optional target installs exactly the five SHA-256-locked engines and never executes them during the build.
- Added Japanese, Simplified Chinese, and Korean interface language packs with English fallback and desktop/mobile
  CJK layout contracts.
- Added CodeQL, pinned GitHub Actions, dependency locks, Compose validation, and container-image CI.
- Published the Community source under Apache-2.0 while keeping private delivery implementation outside this
  repository.

Security fixes are described after coordinated disclosure. Reports still under embargo are never added here.
