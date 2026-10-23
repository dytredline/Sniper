# Contributing to Sniper Community

Thank you for helping improve defensive application security.

## Before opening a change

1. Use an issue or discussion for substantial behavior changes.
2. Keep one change focused and preserve existing public CLI, API, database, and report contracts unless the change
   explicitly migrates them.
3. Add a test that fails on the old behavior and passes on the new behavior. Include a safe control and an edge case.
4. Never run tests against an external target unless you own it or have explicit written authorization. Repository
   tests must use local fixtures, temporary directories, or loopback-only services.

Do not commit credentials, tokens, private keys, production data, customer identifiers, local databases, generated
evidence, or machine-specific absolute paths.

## Local checks

Run the Community publication gate after documentation or metadata changes:

```bash
python3 .github/scripts/validate-community-release.py
```

Run the full local test launcher before proposing a product change:

```bash
python3 scripts/run_all_tests.py
```

If an optional pinned tool is unavailable, state exactly which tests were skipped and why. Do not report a skipped
integration as passing.

## Pull requests

Describe the observable behavior, risk, tests actually run, and remaining limitations. Keep generated caches and
runtime data out of the change. Reviews may request a smaller diff, a regression test, or independent reproduction.

By submitting a contribution intentionally for inclusion in Sniper Community, you agree that it is licensed on an
**Apache-2.0 inbound=outbound** basis, unless you explicitly state otherwise before it is accepted. You must have the
right to submit the contribution and must preserve applicable third-party copyright and license notices.

## Security issues

Do not file exploitable details publicly. Follow [SECURITY.md](SECURITY.md) and send the report through GitHub
Private Vulnerability Reporting for review by the named Security Maintainer.
