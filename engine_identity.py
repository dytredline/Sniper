"""Release ve olcum hattinin paylastigi deterministik analiz motoru kimligi."""
from __future__ import annotations

import hashlib
from pathlib import Path


ENGINE_FILES = (
    "engine_identity.py", "project_analyzer.py", "secret_intelligence_auditor.py", "scan_scope.py",
    "c_build.py", "eval_metrics.py", "quality_gate.py", "ground_truth_review.py", "finding_tracking.py",
    "api_spec_routes.py", "authz_routes.py", "monorepo.py", "project_progress.py", "threat_model.py",
    "safe_file_read.py", "project_tree.py", "finding_limits.py", "legacy_basis.py", "scanner.py", "semgrep_active.py",
    "os_versions.py", "storage.py", "taint_js_bridge.cjs", "vendor/babel-parser/index.js",
)
ENGINE_FILE_GLOBS = (
    "taint_*.py", "iac_*.py", "dependency_*.py", "container_*.py",
    "memsafety_*.py", "asan_*.py", "joern_*.py", "osv_*.py",
)
ENGINE_RULE_GLOBS = (
    "rules/taint/*.json", "rules/iac/*.json", "rules/joern/*.sc",
    "rules/opengrep/*.yaml", "rules/opengrep/*.yml",
)


def engine_digest(app_root: Path) -> str:
    """Motor kaynaklari ve bildirimsel kurallarin tam SHA-256 ozeti."""
    app_root = Path(app_root)
    digest = hashlib.sha256()
    relative_paths = set(ENGINE_FILES)
    for pattern in (*ENGINE_FILE_GLOBS, *ENGINE_RULE_GLOBS):
        for path in sorted(app_root.glob(pattern)):
            if path.is_file():
                relative_paths.add(path.relative_to(app_root).as_posix())
    for relative in sorted(relative_paths):
        path = app_root / relative
        if path.is_file():
            digest.update(relative.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def engine_fingerprint(app_root: Path) -> str:
    """Motor ozeti icin API ve raporlarda kullanilan 16 haneli kimlik."""
    return engine_digest(app_root)[:16]
