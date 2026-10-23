#!/usr/bin/env python3
"""Büyük proje stres testi: sentetik N dosyalık (varsayılan 50.000) çok dilli bir monorepo üretir, proje analizini
çalıştırır ve süre, tepe bellek (RSS), ilerleme olayı sayısı, alt proje sayısı ve (isteğe bağlı süre bütçesiyle)
kısmi sonuç bilgisini JSON olarak yazar. Ağ yok; yalnız verilen geçici dizine yazar.

Kullanım:
  python3 scripts/stress_project_analysis.py --dir /yol/gecici --files 50000 [--time-budget 60] [--keep]
Dizin ev dizini altında olmalı (proje yolu kuralı). Varsayılan: ~/.cache/sniper-stress-<pid> (sonda silinir).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import sys
import time

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))

TEMPLATES = {
    ".py": "import os\n\ndef handler_{i}(value):\n    total = 0\n    for item in range({n}):\n        total += item * value\n    return total\n",
    ".js": "export function handler{i}(value) {{\n  let total = 0;\n  for (let i = 0; i < {n}; i++) total += i * value;\n  return total;\n}}\n",
    ".go": "package svc\n\nfunc Handler{i}(value int) int {{\n\ttotal := 0\n\tfor i := 0; i < {n}; i++ {{\n\t\ttotal += i * value\n\t}}\n\treturn total\n}}\n",
    ".java": "package svc;\n\npublic class Handler{i} {{\n  public int run(int value) {{\n    int total = 0;\n    for (int i = 0; i < {n}; i++) total += i * value;\n    return total;\n  }}\n}}\n",
}
# Gerçekçi olsun diye her 500 dosyada bir doğrulanabilir açık (komut enjeksiyonu) eklenir.
VULN = 'import os\nfrom flask import request\n\ndef run_{i}():\n    os.system("ping " + request.args["h"])\n'


def generate(root: Path, files: int, packages: int = 50) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"private": True, "workspaces": ["packages/*"]}), encoding="utf-8")
    suffixes = list(TEMPLATES)
    per_package = max(1, files // packages)
    written = 1  # kök package.json
    for p in range(packages):
        pkg = root / "packages" / f"pkg{p:03d}"
        (pkg / "src").mkdir(parents=True, exist_ok=True)
        (pkg / "package.json").write_text(json.dumps({"name": f"pkg{p:03d}", "version": "1.0.0"}), encoding="utf-8")
        written += 1
        for i in range(per_package):
            if written >= files:
                return
            suffix = suffixes[(p + i) % len(suffixes)]
            index = p * per_package + i
            text = VULN.format(i=index) if suffix == ".py" and index % 500 == 0 else TEMPLATES[suffix].format(i=index, n=index % 97 + 3)
            sub = pkg / "src" / f"d{i // 200:03d}"
            sub.mkdir(exist_ok=True)
            (sub / f"f{index}{suffix}").write_text(text, encoding="utf-8")
            written += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--files", type=int, default=50_000)
    parser.add_argument("--dir", default=str(Path.home() / ".cache" / f"sniper-stress-{os.getpid()}"))
    parser.add_argument("--time-budget", type=float, default=0.0, help="SNIPER_PROJECT_TIME_BUDGET_SECONDS (0 = sınırsız)")
    parser.add_argument("--keep", action="store_true", help="Sentetik projeyi silme")
    args = parser.parse_args()
    base = Path(args.dir).expanduser()
    project = base / "monorepo"
    if project.exists():
        print(f"Hedef zaten var, üzerine yazılmaz: {project}", file=sys.stderr)
        return 2
    if args.time_budget > 0:
        os.environ["SNIPER_PROJECT_TIME_BUDGET_SECONDS"] = str(args.time_budget)
    import project_analyzer
    import project_progress
    import scan_scope

    started = time.monotonic()
    generate(project, args.files)
    generated_seconds = time.monotonic() - started
    events: list[dict] = []
    scope = scan_scope.parse_scope({"max_files": 50_000, "max_total_mb": 1000})
    started = time.monotonic()
    error = None
    result = None
    try:
        with project_progress.reporting(events.append):
            result = project_analyzer.analyze_project(str(project), allowed_roots=(base,), scope=scope, max_files=50_000)
    except project_analyzer.ProjectRejected as exc:
        error = str(exc)
    seconds = time.monotonic() - started
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    report = {
        "files_requested": args.files,
        "generate_seconds": round(generated_seconds, 1),
        "analyze_seconds": round(seconds, 1),
        "peak_rss_mb": round(peak_mb, 1),
        "progress_events": len(events),
        "last_progress": events[-1] if events else None,
        "error": error,
    }
    if result is not None:
        report.update({
            "file_count": result["file_count"],
            "bytes_scanned": result["bytes_scanned"],
            "finding_counts": result["finding_counts"],
            "verified_flows": sum(1 for f in result["findings"] if str(f.get("title", "")).startswith("Doğrulanmış veri akışı")),
            "subprojects": (result.get("subprojects") or {}).get("count"),
            "partial": result.get("partial"),
            "warnings": result["warnings"][:3],
        })
    print(json.dumps(report, ensure_ascii=False, indent=1))
    if not args.keep:
        shutil.rmtree(project, ignore_errors=True)  # yalnız bu betiğin oluşturduğu proje dizini silinir
        try:
            base.rmdir()  # boşsa (varsayılan geçici dizin)
        except OSError:
            pass
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
