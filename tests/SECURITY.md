# Security-sensitive test code

Some tests must reproduce an unsafe pattern so Sniper can prove that it detects
the pattern. This code is confined to the test suite:

- `test_dast_runtime_engine.py`, `test_dast_runtime_ssrf.py`, and `test_runtime_proof_open_redirect.py` start
  ephemeral servers on `127.0.0.1`. Their reflected CORS and redirect headers
  are intentional targets for bounded runtime-proof tests; they are never
  registered as application routes.
- `test_project_analyzer.py` writes a synthetic token into a temporary project
  and proves that the resulting report does not retain the token.
- `test_triage_context_round26.py` writes synthetic credentials into a
  temporary project and proves that every exported context masks them.
- `fixtures/README.md` documents the intentionally vulnerable static-analysis
  corpora under `tests/fixtures/`.

A code-scanning alert in one of these test-only patterns may be closed as
**used in tests** only after its call path, loopback/temporary-directory
boundary, and the corresponding positive and negative assertions have been
verified. Application, packaging, and build code are outside this exception.
