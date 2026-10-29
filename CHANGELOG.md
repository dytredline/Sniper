# Changelog

All notable changes to Sniper Community are recorded here. The project follows semantic versioning for public
Community releases.

## Unreleased

## Sniper Community 1.1.0 — 2026-10-29

- Expanded authorization review across supported Rails inheritance, Spring and ASP.NET routes, and GraphQL
  resolvers; added bounded multi-repository trust graphs for CI artifacts, webhooks, services, and dependency lineage.
- Added reviewable fuzz-target generation and bounded local runtimes for supported C/C++, Rust, Go, Python, Java,
  and JavaScript/TypeScript targets, plus memory-safety and runtime-evidence correlation improvements.
- Added local supply-chain, OCI provenance, Kubernetes, migration, protocol, archive/symlink, and binary-hardening
  checks, together with Syft/Grype integration and seven-tool Linux Community profiles.
- Added Community MCP tools for local response comparison, authorization matrices, token sequencing, traffic
  decoding, GHSA/OpenVEX preparation, and bounty-readiness review. Every advertised tool now declares its MCP
  read-only, destructive, idempotent, and open-world effects.
- Hardened deterministic source assembly so Git worktree pointer files are excluded before they can be read or
  copied, and the assembled-tree validator rejects any manifest-listed `.git` artifact.
- Added GitHub OIDC provenance attestation for tagged source archives while preserving SHA-256 release checksums.
- Verified both the macOS Apple Silicon native `--core-only` source setup and the macOS Apple Silicon + Docker Desktop
  setup path for the five license-gated local engines, with health/readiness checks, persistent project volume, and
  end-to-end local SAST audit verification.
- Added an explicit project-import command for macOS folders that Docker Desktop cannot bind-mount, without changing
  the original project or accepting an existing target name.
- Fixed the local Nuclei template invocation so the pinned Nuclei binary recognizes the verified template while
  preserving the open-file identity check; added a real-binary regression test.
- Clarified IDOR (CWE-639), missing-authorization (CWE-862), and authorized manual penetration-testing support across
  the public README, AI discovery index, use cases, capability map, and localized introductions, with validation
  guidance for separate test identities, roles, and synthetic objects.
- Added benefit-led discovery highlights for supported injection/data-flow analysis, secrets and privacy, software
  supply chain, containers and infrastructure, risk prioritization, reporting, and AI/CLI/web workflows.
- Added multilingual AI-assisted release-preflight guidance for mobile store submissions, website/API launches, and
  release pull requests.

## Sniper Community 1.0.0 — 2026-10-24

- Added local-first source, configuration, dependency, container, and report workflows.
- Added the stdio MCP interface with expiring, single-use, human-confirmed MCP action plans.
- Added the loopback web interface and manual command-line entrypoints.
- Added deterministic Community source assembly with SHA-256 manifests and fail-closed release validation.
- Added a one-command rootless setup plus a SHA-256-locked installer for the supported local third-party tool profile.
- Added a Linux, macOS, and Windows core-only source setup plus WSL2/Docker Desktop guidance for the five-engine Linux container profile.
- Added separate `community-core` and license-gated `community-tools` container targets for Docker Desktop/WSL2;
  the optional target installs exactly the five SHA-256-locked engines and never executes them during the build.
- Added Japanese, Simplified Chinese, and Korean interface language packs with English fallback and desktop/mobile
  CJK layout contracts.
- Added CodeQL, pinned GitHub Actions, dependency locks, Compose validation, and container-image CI.
- Published the Community source under Apache-2.0 while keeping private delivery implementation outside this
  repository.

Security fixes are described after coordinated disclosure. Reports still under embargo are never added here.
