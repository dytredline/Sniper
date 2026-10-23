#!/usr/bin/env python3
"""Sniper ölçüm hattı: açıklı/olgun proje setleri, zemin gerçeği, CodeQL karşılaştırması, kıyaslar ve regresyon.

Yapılandırma (JSON; göreli yollar yapılandırma dosyasına göre, ``@app/`` ölçülen Sniper kopyasına göre;
``~`` ve ``$DEĞİŞKEN`` açılır)::

    {"name": "standart",
     "node": {"binary": "/yol/node", "sha256": "…" | "sha256_file": "/yol/node.sha256"},
     "sets": [
       {"name": "heldout5", "kind": "vulnerable", "root": "…/heldout5", "projects": ["Pixi", …],
        "ground_truth": "…/ground_truth.v1.json", "codeql_sarif_dir": "…/cq-heldout5"},
       {"name": "set1", "kind": "vulnerable", "root": "…/heldout", "projects": [...], "codeql_sarif_dir": "…"},
       {"name": "olgun", "kind": "benign", "root": "…/benign", "baseline": "docs/olcum/fp-corpus-baseline-20261020.json"}],
     "benchmarks": {"taint_benchmark": true, "owasp_python": {"path": "…/BenchmarkPython", "splits": ["all", "odd", "even"]}}}

Sonuç ``--history-dir`` / ``$SNIPER_EVAL_HISTORY_DIR`` / ``$SNIPER_DATA_DIR/eval-history`` altına yazılır ve aynı
yapılandırma adının önceki çalıştırmasıyla karşılaştırılır. Çıkış kodu: 0 sorun yok, 1 regresyon, 2 yapılandırma hatası.
Kaynak satır içeriği hiçbir çıktıya yazılmaz; ölçülen projelerin kodu çalıştırılmaz.

Kullanım: python3 scripts/eval_pipeline.py --config ölçüm.json [--label r13] [--only heldout5] [--no-write] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import warnings

APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

import eval_metrics as em  # noqa: E402
import ground_truth_review  # noqa: E402

ENGINE_FILES = ("project_analyzer.py", "taint_flow.py", "taint_js_ast.py", "taint_js_views.py", "taint_angular.py",
                "secret_intelligence_auditor.py", "scan_scope.py", "memsafety_c.py", "memsafety_clang.py",
                "c_build.py")
QUALITY_GATE_KEYS = frozenset({"min_projects", "min_labels", "min_recall", "min_precision", "max_errors"})


def _resolve(value: str | None, base: Path) -> Path | None:
    if not value:
        return None
    if str(value).startswith("@app/"):  # ölçülen Sniper kopyasına göre (ör. temel çizgi dosyası)
        return APP_ROOT / str(value)[5:]
    path = Path(os.path.expandvars(os.path.expanduser(str(value))))
    return path if path.is_absolute() else (base / path)


def _quality_gate(raw: object, set_name: str) -> dict[str, int | float] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or not raw or set(raw) - QUALITY_GATE_KEYS:
        raise em.EvalError(f"{set_name}: quality_gate yalnız {', '.join(sorted(QUALITY_GATE_KEYS))} alanlarını içermeli.")
    gate: dict[str, int | float] = {}
    for key, value in raw.items():
        if key in {"min_projects", "min_labels", "max_errors"}:
            if type(value) is not int or value < 0 or (key != "max_errors" and value < 1):
                raise em.EvalError(f"{set_name}: quality_gate.{key} geçersiz.")
            gate[key] = value
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= float(value) <= 1:
                raise em.EvalError(f"{set_name}: quality_gate.{key} 0 ile 1 arasında olmalı.")
            gate[key] = float(value)
    return gate


def load_config(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise em.EvalError(f"Yapılandırma okunamadı: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("sets"), list) or not raw["sets"]:
        raise em.EvalError("Yapılandırma en az bir set içermeli ('sets').")
    base = path.resolve().parent
    sets = []
    for item in raw["sets"]:
        name = str(item.get("name", ""))
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", name):
            raise em.EvalError(f"Geçersiz set adı: {name!r}")
        kind = item.get("kind", "vulnerable")
        if kind not in {"vulnerable", "benign", "sca"}:
            raise em.EvalError(f"{name}: kind 'vulnerable', 'benign' veya 'sca' olmalı.")
        root = _resolve(item.get("root"), base)
        if root is None or not root.is_dir():
            raise em.EvalError(f"{name}: kök dizin yok: {root}")
        projects = item.get("projects")
        if projects is None:
            projects = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))
        sets.append({
            "name": name, "kind": kind, "root": root, "projects": [str(p) for p in projects],
            "ground_truth": _resolve(item.get("ground_truth"), base),
            "codeql_sarif_dir": _resolve(item.get("codeql_sarif_dir"), base),
            "baseline": _resolve(item.get("baseline"), base),
            "review_manifest": _resolve(item.get("review_manifest"), base),
            "require_blinded_ground_truth": item.get("require_blinded_ground_truth") is True,
            "quality_gate": _quality_gate(item.get("quality_gate"), name),
        })
    node = raw.get("node") or {}
    sha = node.get("sha256")
    if not sha and node.get("sha256_file"):
        sha_path = _resolve(node["sha256_file"], base)
        sha = sha_path.read_text().split()[0] if sha_path and sha_path.is_file() else None
    benchmarks = raw.get("benchmarks") or {}
    owasp = benchmarks.get("owasp_python")
    if isinstance(owasp, dict):
        owasp = {"path": _resolve(owasp.get("path"), base), "splits": list(owasp.get("splits") or ["all"])}
    return {"name": str(raw.get("name") or path.stem), "sets": sets,
            "node": {"binary": str(_resolve(node.get("binary"), base)) if node.get("binary") else None, "sha256": sha},
            "benchmarks": {"taint_benchmark": bool(benchmarks.get("taint_benchmark")), "owasp_python": owasp}}


def engine_fingerprint() -> str:
    digest = hashlib.sha256()
    for name in ENGINE_FILES:
        path = APP_ROOT / name
        if path.is_file():
            digest.update(name.encode() + b"\0" + path.read_bytes())
    for path in sorted((APP_ROOT / "rules" / "taint").glob("*.json")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()[:16]


def _fp_key(finding: dict) -> str:
    flow = finding.get("taint_flow") or {}
    return (f"{finding.get('reference')}|{finding.get('file')}:{finding.get('line')}|{flow.get('source_label')}|"
            f"{flow.get('source')}→{flow.get('sink')}")


def run_sca_set(spec: dict, log) -> dict:
    """10. set: bağımlılık açığı (SCA) kümesi — paket@sürüm düzeyi duyarlılık (eval_metrics.score_sca)."""
    gt = em.load_sca_ground_truth(spec["ground_truth"])
    projects: dict[str, dict] = {}
    findings: dict[str, list[dict]] = {}
    statuses = set()
    started_set = time.monotonic()
    for project in spec["projects"]:
        started = time.monotonic()
        try:
            rows, status = em.sniper_sca_findings(str(spec["root"] / project), spec["root"])
        except Exception as exc:  # ölçüm aracı: hata regresyon olarak raporlanır
            projects[project] = {"error": f"{type(exc).__name__}: {str(exc)[:160]}"}
            log(f"== {spec['name']}/{project}: HATA {projects[project]['error']}")
            continue
        statuses.add(status)
        findings[project] = rows
        projects[project] = {"seconds": round(time.monotonic() - started, 1), "findings": len(rows), "status": status}
        log(f"== {spec['name']}/{project}: {projects[project]['seconds']}s durum={status} bulgu={len(rows)}")
    scored = em.score_sca(gt, findings)
    return {"kind": "sca", "root": str(spec["root"]), "projects": projects,
            "seconds": round(time.monotonic() - started_set, 1), "ground_truth": str(spec["ground_truth"]),
            "verified": scored, "sca_status": sorted(statuses)}


def validate_ground_truth_contract(spec: dict) -> dict | None:
    if not spec.get("require_blinded_ground_truth"):
        return None
    if not spec.get("ground_truth") or not spec.get("review_manifest"):
        raise em.EvalError(f"{spec.get('name')}: kör ground-truth için ground_truth ve review_manifest gerekli.")
    try:
        return ground_truth_review.validate_bundle(
            spec["root"], spec["review_manifest"], spec["ground_truth"], require_attestation=True,
        )
    except ground_truth_review.GroundTruthReviewError as exc:
        raise em.EvalError(f"{spec.get('name')}: {exc}") from exc


def run_set(spec: dict, log) -> dict:
    review_contract = validate_ground_truth_contract(spec)
    import project_analyzer

    if spec["kind"] == "sca":
        return run_sca_set(spec, log)

    gt = em.load_ground_truth(spec["ground_truth"]) if spec["ground_truth"] else None
    projects: dict[str, dict] = {}
    verified_items: list[tuple] = []
    all_items: list[tuple] = []
    benign_keys: dict[str, list[str]] = {}
    started_set = time.monotonic()
    for project in spec["projects"]:
        started = time.monotonic()
        try:
            report = project_analyzer.analyze_project(str(spec["root"] / project), allowed_roots=(spec["root"],))
        except Exception as exc:  # ölçüm aracı: hata regresyon olarak raporlanır
            projects[project] = {"error": f"{type(exc).__name__}: {str(exc)[:160]}"}
            log(f"== {spec['name']}/{project}: HATA {projects[project]['error']}")
            continue
        findings = report["findings"]
        verified = [f for f in findings if em.is_verified_flow(f)]
        projects[project] = {
            "seconds": round(time.monotonic() - started, 1), "file_count": report.get("file_count"),
            "findings": len(findings), "verified_flows": len(verified),
            "second_order_flows": sum(1 for f in findings if em.is_second_order_flow(f)),
        }
        verified_items += em.sniper_items(project, findings, verified_only=True)
        all_items += em.sniper_items(project, findings, verified_only=False)
        if spec["kind"] == "benign":
            benign_keys[project] = sorted(_fp_key(f) for f in findings if f.get("taint_flow"))
        log(f"== {spec['name']}/{project}: {projects[project]['seconds']}s dosya={report.get('file_count')} "
            f"bulgu={len(findings)} doğrulanmış={len(verified)}")
    result = {"kind": spec["kind"], "root": str(spec["root"]), "projects": projects,
              "seconds": round(time.monotonic() - started_set, 1),
              "ground_truth": str(spec["ground_truth"]) if spec["ground_truth"] else None,
              "verified": em.score_items(gt, verified_items)}
    if review_contract is not None:
        result["ground_truth_review"] = review_contract
    if gt is not None:
        result["all_class_findings"] = {k: v for k, v in em.score_items(gt, all_items).items()
                                        if k in {"findings", "tp", "total", "fn", "recall", "missed_classes"}}
    if spec["kind"] == "benign":
        result["flow_keys"] = benign_keys
        if spec["baseline"] and spec["baseline"].is_file():
            baseline = json.loads(spec["baseline"].read_text(encoding="utf-8"))
            result["new_flows_vs_baseline"] = sorted(
                f"{project}: {key}" for project, keys in benign_keys.items()
                for key in sorted(set(keys) - set(baseline.get(project, []))))
    if spec["codeql_sarif_dir"] and spec["codeql_sarif_dir"].is_dir():
        cq = em.codeql_items(spec["codeql_sarif_dir"], spec["projects"])
        quiet = [row for row in cq if row[4] not in em.CODEQL_NOISY_RULES]
        if gt is not None:
            scored = em.score_items(gt, cq)
            result["codeql"] = {k: scored[k] for k in ("findings", "tp", "total", "fn", "recall", "found", "missed_classes")}
            result["codeql"]["unmatched_non_noisy"] = sum(
                1 for row in scored["unmatched"] if row["tag"] not in em.CODEQL_NOISY_RULES)
            # Sniper'ın kaçırıp CodeQL'in bulduğu zemin gerçeği kayıtları (geliştirme önceliği için).
            sniper_found = result["verified"]["found"]
            result["codeql"]["only_codeql"] = sorted(
                f"{project}#{index}" for project, indexes in scored["found"].items()
                for index in indexes if index not in sniper_found.get(project, []))
        else:
            result["codeql"] = {"findings": len(quiet), **em.agreement(verified_items, quiet)}
    return result


def evaluate_quality_gate(spec: dict, result: dict) -> dict | None:
    """Bir set için mutlak kabul eşiklerini değerlendir; geçmiş karşılaştırmasına bağlı değildir."""
    gate = spec.get("quality_gate")
    if not gate:
        return None
    projects = result.get("projects") if isinstance(result.get("projects"), dict) else {}
    scored = result.get("verified") if isinstance(result.get("verified"), dict) else {}
    actuals: dict[str, int | float | None] = {
        "projects": sum(1 for row in projects.values() if isinstance(row, dict) and "error" not in row),
        "labels": scored.get("total"),
        "recall": scored.get("recall"),
        "precision": scored.get("precision"),
        "errors": sum(1 for row in projects.values() if not isinstance(row, dict) or "error" in row),
    }
    mapping = {
        "min_projects": ("projects", ">="), "min_labels": ("labels", ">="),
        "min_recall": ("recall", ">="), "min_precision": ("precision", ">="),
        "max_errors": ("errors", "<="),
    }
    checks = []
    for key in sorted(gate):
        metric, operator = mapping[key]
        actual, threshold = actuals[metric], gate[key]
        passed = actual is not None and (actual >= threshold if operator == ">=" else actual <= threshold)
        checks.append({"metric": metric, "operator": operator, "threshold": threshold,
                       "actual": actual, "passed": passed})
    failures = [dict(row) for row in checks if not row["passed"]]
    return {"passed": not failures, "checks": checks, "failures": failures}


_TAINT_RE = re.compile(r"\|\s*(\d+)/(\d+)/(\d+)\s+P=([\d.]+)\s+R=([\d.]+)\s*$")
_OWASP_RE = re.compile(r"ORTALAMA PUAN \(Youden\) = ([\d.]+)")


def run_benchmarks(spec: dict, env: dict, log) -> dict:
    out: dict[str, dict] = {}
    if spec.get("taint_benchmark"):
        proc = subprocess.run([sys.executable, str(APP_ROOT / "scripts" / "taint_benchmark.py")], cwd=APP_ROOT, env=env,
                              capture_output=True, text=True, timeout=1800, check=False)
        line = (proc.stdout.strip().splitlines() or [""])[-1]
        match = _TAINT_RE.search(line)
        out["taint_benchmark"] = ({"correct": int(match.group(1)), "fn": int(match.group(2)), "fp": int(match.group(3)),
                                   "precision": float(match.group(4)), "recall": float(match.group(5))}
                                  if match else {"error": f"çıktı çözümlenemedi (kod {proc.returncode})"})
        log(f"== kıyas taint: {out['taint_benchmark']}")
    owasp = spec.get("owasp_python")
    if owasp and owasp.get("path"):
        for split in owasp["splits"]:
            proc = subprocess.run([sys.executable, str(APP_ROOT / "scripts" / "owasp_benchmark_python.py"), str(owasp["path"]),
                                   "--split", split], cwd=APP_ROOT, env=env, capture_output=True, text=True, timeout=1800, check=False)
            match = _OWASP_RE.search(proc.stdout)
            out[f"owasp_python_{split}"] = {"score": float(match.group(1))} if match else {"error": f"kod {proc.returncode}"}
            log(f"== kıyas OWASP {split}: {out[f'owasp_python_{split}']}")
    return out


def format_report(record: dict) -> str:
    lines = [f"# Ölçüm {record['label']} ({record['created_at']}, motor {record['engine']})"]
    for name, data in record["sets"].items():
        v = data["verified"]
        if "tp" in v:
            prec = f"{v['precision']:.2f}" if v.get("precision") is not None else "—"
            lines.append(f"## {name}: doğrulanmış akış TP {v['tp']}/{v['total']} (duyarlılık {v['recall']:.2f}), "
                         f"kesinlik {prec} (yanlış {v['false_positives']}, sınıflandırılmamış {v['unclassified']})")
            for project, row in v["per_project"].items():
                lines.append(f"   {project:40} {row['tp']:3}/{row['total']}")
            if v["missed_classes"]:
                lines.append("   kaçan sınıflar: " + ", ".join(f"{k} {n}" for k, n in v["missed_classes"].items()))
            if data.get("kind") == "sca":
                lines.append(f"   SCA kimlik eşleşmesi {v.get('id_match')}, ürün durumu {','.join(data.get('sca_status') or [])}")
            if "all_class_findings" in data:
                a = data["all_class_findings"]
                lines.append(f"   tüm sınıf bulguları: TP {a['tp']}/{a['total']}")
        else:
            lines.append(f"## {name} ({data['kind']}): doğrulanmış akış {v['findings']}")
        if data.get("new_flows_vs_baseline") is not None:
            lines.append(f"   temel çizgiye göre yeni akış: {len(data['new_flows_vs_baseline'])}")
        gate = data.get("quality_gate")
        if gate:
            lines.append("   KALİTE KAPISI: " + ("GEÇTİ" if gate["passed"] else "KALDI"))
        cq = data.get("codeql")
        if cq:
            if "tp" in cq:
                lines.append(f"   CodeQL: TP {cq['tp']}/{cq['total']}, eşleşmeyen (gürültülü kurallar hariç) "
                             f"{cq['unmatched_non_noisy']}, yalnız CodeQL'in bulduğu {len(cq['only_codeql'])}")
            else:
                lines.append(f"   CodeQL örtüşme: ikisi {cq['both']}, yalnız Sniper {cq['only_sniper']}, yalnız CodeQL {cq['only_codeql']}")
    if record.get("benchmarks"):
        lines.append("## kıyaslar: " + json.dumps(record["benchmarks"], ensure_ascii=False))
    if record.get("class_precision"):
        lines.append("## sınıf kesinliği: " + ", ".join(
            f"{cls} {row['precision']:.2f} (n={row['judged']})" for cls, row in record["class_precision"].items()
            if row.get("precision") is not None))
    for title, rows in (("REGRESYON", record["regressions"]), ("uyarı", record["warnings"])):
        for row in rows:
            lines.append(f"{title}: " + json.dumps(row, ensure_ascii=False))
    lines.append("SONUÇ: " + ("REGRESYON VAR" if record["regressions"] else "regresyon yok"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sniper ölçüm hattı")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--label", default="")
    parser.add_argument("--only", action="append", default=[], help="Yalnız bu set(ler)")
    parser.add_argument("--history-dir", type=Path)
    parser.add_argument("--compare-to", type=Path, help="Karşılaştırılacak geçmiş dosyası (varsayılan: aynı adlı son çalıştırma)")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--no-benchmarks", action="store_true")
    parser.add_argument("--fail-on-slowdown", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    # Ölçülen projelerin kaynak kodunu ayrıştırırken çıkan Python uyarıları (ör. kaçış dizisi) ölçümle ilgisiz.
    warnings.filterwarnings("ignore", category=SyntaxWarning)
    try:
        config = load_config(args.config)
    except em.EvalError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return 2
    env = dict(os.environ)
    if config["node"]["binary"]:
        env["SNIPER_NODE_BINARY"] = config["node"]["binary"]
        os.environ["SNIPER_NODE_BINARY"] = config["node"]["binary"]
    if config["node"]["sha256"]:
        env["SNIPER_NODE_SHA256"] = config["node"]["sha256"]
        os.environ["SNIPER_NODE_SHA256"] = config["node"]["sha256"]
    log = (lambda message: print(message, file=sys.stderr, flush=True)) if args.json else (lambda message: print(message, flush=True))
    sets = {}
    try:
        for spec in config["sets"]:
            if args.only and spec["name"] not in args.only:
                continue
            result = run_set(spec, log)
            gate = evaluate_quality_gate(spec, result)
            if gate is not None:
                result["quality_gate"] = gate
            sets[spec["name"]] = result
    except em.EvalError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return 2
    benchmarks = {} if args.no_benchmarks or args.only else run_benchmarks(config["benchmarks"], env, log)
    now = time.time()
    record = {
        "format": em.HISTORY_FORMAT, "config_name": config["name"] + (":" + ",".join(sorted(args.only)) if args.only else ""),
        "label": args.label or engine_fingerprint(), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "created_epoch": now, "engine": engine_fingerprint(), "sets": sets, "benchmarks": benchmarks,
        "class_precision": em.class_precision(sets),
    }
    history = args.history_dir or em.history_dir()
    previous = em.read_history(args.compare_to) if args.compare_to else em.previous_record(history, record["config_name"])
    record["compared_to"] = (previous or {}).get("file")
    record["regressions"], record["warnings"] = em.compare_records(record, previous)
    for name, result in sets.items():
        gate = result.get("quality_gate")
        if gate and not gate["passed"]:
            record["regressions"].append({"type": "quality_gate_failed", "set": name,
                                          "failures": gate["failures"]})
    if not args.no_write and history is not None:
        path = em.write_history(record, history)
        record["file"] = path.name
        em.write_history(record, history, target=path)  # dosya adı aynı kayda eklendi
    print(json.dumps(em.summarize(record), ensure_ascii=False, indent=1) if args.json else format_report(record))
    slow = args.fail_on_slowdown and any(w["type"] == "slowdown" for w in record["warnings"])
    return 1 if record["regressions"] or slow else 0


if __name__ == "__main__":
    raise SystemExit(main())
