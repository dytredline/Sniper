# Security test fixtures

The files under `opengrep_rules/` and `taint_bench/` deliberately contain
vulnerable source snippets. They are data inputs for Sniper's static-analysis
tests; they are not imported by the application, exposed by the web server, or
executed as services.

- `tests/test_opengrep_rulepack.py` copies `opengrep_rules/` to a temporary
  directory and verifies that every positive sample is detected while every
  negative sample remains clean.
- `tests/test_taint_cache.py` reads the Python `taint_bench/` files as strings
  and compares cached and uncached analysis results.
- `tests/test_taint_flow.py` uses the same benchmark corpus to measure detector
  precision and recall when the optional maintainer benchmark helper is
  present.

Code-scanning findings whose locations are inside these two directories are
therefore expected test signals. They may be closed as **used in tests** only
after confirming that the finding points to one of these fixtures and not to
application or build code. Findings elsewhere still require individual review.
