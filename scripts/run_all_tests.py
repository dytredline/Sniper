#!/usr/bin/env python3
"""Run every Sniper test suite with one command.

* unittest modules run one process per module (the global HTTP rate limiter and
  module-level state are not shared between modules), in parallel;
* modules written for pytest (``import pytest`` or bare ``def test_`` functions
  without a ``unittest.TestCase``) run with pytest and the runtime dependencies;
* ``tests/*.mjs`` run with ``node --test``.

pytest is looked up in this order: ``$SNIPER_PYTEST_PYTHON``, the current
interpreter, then the offline test venv ``~/.local/state/sniper-test-venv``.
Exit status is non-zero when any suite fails or a required runner is missing.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

APP_ROOT = Path(__file__).resolve().parents[1]
TESTS = APP_ROOT / "tests"
DEFAULT_VENV_PYTHON = Path.home() / ".local" / "state" / "sniper-test-venv" / "bin" / "python"


def _is_pytest_module(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"^\s*(import pytest|from pytest\b)", text, re.M):
        return True
    has_case = "unittest.TestCase" in text or re.search(r"class \w+\((?:unittest\.)?\w*TestCase\)", text)
    return bool(re.search(r"^def test_\w+\(", text, re.M)) and not has_case


def _pytest_python() -> str | None:
    candidates = [os.environ.get("SNIPER_PYTEST_PYTHON", ""), sys.executable, str(DEFAULT_VENV_PYTHON)]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen or not Path(candidate).exists():
            continue
        seen.add(candidate)
        probe = subprocess.run(
            [candidate, "-c", "import pytest, cryptography, packaging, yaml"],
            capture_output=True,
        )
        if probe.returncode == 0:
            return candidate
    return None


def _run_unittest(module: str) -> tuple[str, int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", f"tests.{module}"],
        cwd=APP_ROOT,
        capture_output=True,
        text=True,
        timeout=900,
    )
    return module, proc.returncode, proc.stdout + proc.stderr


def _summarize_unittest(output: str) -> tuple[int, int, int]:
    ran = re.search(r"Ran (\d+) tests?", output)
    total = int(ran.group(1)) if ran else 0
    failures = errors = 0
    failed = re.search(r"FAILED \(([^)]*)\)", output)
    if failed:
        counts = dict((k, int(v)) for k, v in re.findall(r"(\w+)=(\d+)", failed.group(1)))
        failures, errors = counts.get("failures", 0), counts.get("errors", 0)
    return total, failures, errors


def _summarize_node(output: str) -> dict[str, str]:
    """Accept the TAP summary prefixes emitted by supported Node 22 and newer runtimes."""
    return {
        key: value
        for key, value in re.findall(r"^(?:#|ℹ)\s+(tests|pass|fail)\s+(\d+)", output, re.M)
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sniper: tüm test paketlerini tek komutla çalıştırır.")
    parser.add_argument("--jobs", type=int, default=max(2, (os.cpu_count() or 4) // 2))
    parser.add_argument("--skip-node", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="Başarısız modüllerin çıktısını yazdır.")
    args = parser.parse_args(argv)

    # Denetim anahtarı/çapaları kullanıcının ~/.config/sniper dizinine değil geçici dizine yazılsın.
    integrity_tmp = tempfile.TemporaryDirectory(prefix="sniper-test-integrity-")
    os.chmod(integrity_tmp.name, 0o700)
    os.environ.setdefault("SNIPER_AUDIT_KEY_FILE", str(Path(integrity_tmp.name) / "audit.key"))
    os.environ.setdefault("SNIPER_AUDIT_ANCHOR_DIR", str(Path(integrity_tmp.name) / "audit-anchors"))

    modules = sorted(path for path in TESTS.glob("test_*.py"))
    pytest_modules = [path for path in modules if _is_pytest_module(path)]
    unittest_modules = [path.stem for path in modules if path not in pytest_modules]
    ok = True

    print(f"[unittest] {len(unittest_modules)} modül, {args.jobs} paralel süreç")
    totals = [0, 0, 0]
    failed_modules: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for module, code, output in pool.map(_run_unittest, unittest_modules):
            total, failures, errors = _summarize_unittest(output)
            totals[0] += total
            totals[1] += failures
            totals[2] += errors
            if code != 0:
                failed_modules.append((module, output))
    print(f"[unittest] test={totals[0]} başarısız={totals[1]} hata={totals[2]}")
    for module, output in failed_modules:
        ok = False
        print(f"  BAŞARISIZ: {module}")
        if args.verbose:
            print(output[-4000:])

    if pytest_modules:
        python = _pytest_python()
        if python is None:
            ok = False
            print("[pytest] pytest ve runtime bağımlılıklarını birlikte içeren Python bulunamadı. "
                  "Aynı venv içine requirements-runtime.lock ve requirements-test.lock kurun.")
        else:
            print(f"[pytest] {len(pytest_modules)} modül ({python})")
            proc = subprocess.run(
                [python, "-m", "pytest", "-p", "no:cacheprovider", "-q", *[str(p.relative_to(APP_ROOT)) for p in pytest_modules]],
                cwd=APP_ROOT, capture_output=True, text=True, timeout=1800,
            )
            lines = [line for line in (proc.stdout + proc.stderr).strip().splitlines() if line.strip()]
            print(f"[pytest] {lines[-1] if lines else 'çıktı yok'}")
            if proc.returncode != 0:
                ok = False
                if args.verbose:
                    print(proc.stdout[-6000:])

    mjs = sorted(str(p.relative_to(APP_ROOT)) for p in TESTS.glob("*.mjs"))
    if mjs and not args.skip_node:
        node = os.environ.get("SNIPER_NODE_BINARY") or shutil.which("node")
        if not node:
            ok = False
            print("[node] node bulunamadı (SNIPER_NODE_BINARY ile belirtilebilir).")
        else:
            proc = subprocess.run([node, "--test", *mjs], cwd=APP_ROOT, capture_output=True, text=True, timeout=1800)
            summary = _summarize_node(proc.stdout)
            print(f"[node] test={summary.get('tests', '?')} geçti={summary.get('pass', '?')} başarısız={summary.get('fail', '?')}")
            if proc.returncode != 0:
                ok = False
                if args.verbose:
                    print((proc.stdout + proc.stderr)[-6000:])

    print("SONUÇ:", "TÜMÜ GEÇTİ" if ok else "BAŞARISIZLIK VAR")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
