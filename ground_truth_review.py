"""Motor çıktısı görülmeden hazırlanmış ground-truth paketleri için kaynak manifesti ve doğrulama.

Hazırlama yalnız kaynak yollarını, satır sayılarını ve SHA-256 değerlerini okur; Sniper analiz motorunu içe aktarmaz
ve çalıştırmaz. Etiketleme ayrı bir insan adımıdır. Değerlendirme hattı, açıkça istendiğinde kaynakların etiketleme
sonrasında değişmediğini ve insan körleme beyanını bu modülle doğrular.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable

import eval_metrics

LEGACY_MANIFEST_FORMAT = "sniper-ground-truth-review/1"
MANIFEST_FORMAT = "sniper-ground-truth-review/2"
SOURCE_PROFILES = {
    "c_cpp": frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}),
    "python": frozenset({".py", ".pyi"}),
    "javascript_typescript": frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}),
    "jvm": frozenset({".java", ".kt", ".kts"}),
    "dotnet": frozenset({".cs"}),
    "go": frozenset({".go"}),
    "ruby": frozenset({".rb"}),
    "php": frozenset({".php", ".phtml"}),
    "rust": frozenset({".rs"}),
}
SOURCE_SUFFIXES = SOURCE_PROFILES["c_cpp"]  # v1 uyumluluğu ve varsayılan profil
MAX_FILES = 10_000
MAX_BYTES = 200_000_000
_PROJECT = re.compile(r"[A-Za-z0-9._-]{1,120}\Z")
_ISO_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


class GroundTruthReviewError(ValueError):
    """Kaynak manifesti, etiket veya körleme beyanı geçersiz."""


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    if not path.parent.is_dir() or path.is_symlink():
        raise GroundTruthReviewError("Çıktı dizini yok veya çıktı sembolik bağ.")
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _source_profiles(values: Iterable[str] | None) -> tuple[list[str], frozenset[str]]:
    profiles = [str(value) for value in (values if values is not None else ("c_cpp",))]
    if not profiles or len(profiles) != len(set(profiles)) or any(value not in SOURCE_PROFILES for value in profiles):
        raise GroundTruthReviewError("Kaynak profilleri benzersiz ve desteklenen dillerden seçilmeli.")
    profiles.sort()
    return profiles, frozenset(suffix for profile in profiles for suffix in SOURCE_PROFILES[profile])


def _project_files(root: Path, name: str, suffixes: frozenset[str]) -> list[dict[str, Any]]:
    if not _PROJECT.fullmatch(name):
        raise GroundTruthReviewError(f"Geçersiz proje adı: {name!r}")
    project = root / name
    if not project.is_dir() or project.is_symlink():
        raise GroundTruthReviewError(f"Proje dizini yok veya sembolik bağ: {name}")
    rows, total = [], 0
    for path in sorted(project.rglob("*")):
        if path.is_symlink():
            raise GroundTruthReviewError(f"Kaynak kümesinde sembolik bağ var: {name}/{path.relative_to(project)}")
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        raw = path.read_bytes()
        total += len(raw)
        if len(rows) >= MAX_FILES or total > MAX_BYTES:
            raise GroundTruthReviewError("Kaynak manifesti sınırı aşıldı.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GroundTruthReviewError(f"Kaynak UTF-8 değil: {name}/{path.relative_to(project)}") from exc
        rows.append({"file": path.relative_to(project).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(),
                     "bytes": len(raw), "lines": len(text.splitlines())})
    if not rows:
        raise GroundTruthReviewError(f"Seçilen profillerde kaynak bulunamadı: {name}")
    return rows


def source_manifest(root: str | Path, projects: Iterable[str], *,
                    source_profiles: Iterable[str] | None = None) -> dict[str, Any]:
    root_path = Path(root).resolve(strict=True)
    names = list(projects)
    if not names or len(names) != len(set(names)):
        raise GroundTruthReviewError("En az bir benzersiz proje adı gerekli.")
    profiles, suffixes = _source_profiles(source_profiles)
    return {
        "format": MANIFEST_FORMAT,
        "prepared_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "preparation": "source-only-no-engine-output",
        "root_name": root_path.name,
        "source_profiles": profiles,
        "projects": {name: _project_files(root_path, name, suffixes) for name in names},
    }


def prepare_bundle(root: str | Path, projects: Iterable[str], manifest_path: str | Path,
                   ground_truth_path: str | Path, *,
                   source_profiles: Iterable[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = source_manifest(root, projects, source_profiles=source_profiles)
    template = {
        "format": eval_metrics.GT_FORMAT,
        "meta": {"review_protocol": MANIFEST_FORMAT},
        "projects": {name: [] for name in manifest["projects"]},
        "adjudicated": {},
    }
    _write_json(Path(manifest_path), manifest)
    _write_json(Path(ground_truth_path), template)
    return manifest, template


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GroundTruthReviewError(f"{label} okunamadı.") from exc
    if not isinstance(value, dict):
        raise GroundTruthReviewError(f"{label} nesne olmalı.")
    return value


def validate_bundle(root: str | Path, manifest_path: str | Path, ground_truth_path: str | Path, *,
                    require_attestation: bool = True) -> dict[str, Any]:
    root_path = Path(root).resolve(strict=True)
    manifest_file = Path(manifest_path)
    manifest = _load(manifest_file, "Kaynak manifesti")
    manifest_format = manifest.get("format")
    if manifest_format not in {LEGACY_MANIFEST_FORMAT, MANIFEST_FORMAT} \
            or manifest.get("preparation") != "source-only-no-engine-output" \
            or not isinstance(manifest.get("projects"), dict):
        raise GroundTruthReviewError("Kaynak manifesti biçimi geçersiz.")
    if not isinstance(manifest.get("prepared_at"), str) or not _ISO_UTC.fullmatch(manifest["prepared_at"]):
        raise GroundTruthReviewError("Kaynak manifestinin UTC hazırlama zamanı geçersiz.")
    if manifest_format == LEGACY_MANIFEST_FORMAT:
        current = {
            "format": LEGACY_MANIFEST_FORMAT,
            "prepared_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "preparation": "source-only-no-engine-output",
            "root_name": root_path.name,
            "projects": {name: _project_files(root_path, name, SOURCE_SUFFIXES)
                         for name in manifest["projects"].keys()},
        }
        profiles = ["c_cpp"]
    else:
        raw_profiles = manifest.get("source_profiles")
        if not isinstance(raw_profiles, list):
            raise GroundTruthReviewError("Kaynak profilleri eksik veya geçersiz.")
        profiles, _suffixes = _source_profiles(raw_profiles)
        current = source_manifest(root_path, manifest["projects"].keys(), source_profiles=profiles)
    current.pop("prepared_at", None)
    expected = dict(manifest)
    expected.pop("prepared_at", None)
    if current != expected:
        raise GroundTruthReviewError("Kaynak kümesi etiketleme manifestinden sonra değişmiş.")
    try:
        gt = eval_metrics.normalize_ground_truth(_load(Path(ground_truth_path), "Ground truth"))
    except eval_metrics.EvalError as exc:
        raise GroundTruthReviewError(str(exc)) from exc
    if set(gt["projects"]) != set(manifest["projects"]):
        raise GroundTruthReviewError("Ground-truth proje listesi kaynak manifestiyle eşleşmiyor.")

    files_by_project = {
        project: {row["file"]: row for row in rows}
        for project, rows in manifest["projects"].items()
    }
    counts: Counter[str] = Counter()
    for project, items in gt["projects"].items():
        for item in items:
            pure = PurePosixPath(item["file"])
            row = files_by_project[project].get(item["file"])
            start, end = item["lines"]
            if pure.is_absolute() or ".." in pure.parts or row is None:
                raise GroundTruthReviewError(f"Etiket kaynak manifestinde olmayan dosyaya bağlı: {project}/{item['file']}")
            if start < 1 or end < start or end > row["lines"]:
                raise GroundTruthReviewError(f"Etiket satır aralığı dosya dışında: {project}/{item['file']}")
            for alt_file, alt_start, alt_end in item.get("alt", []):
                alt_row = files_by_project[project].get(alt_file)
                if alt_row is None or alt_start < 1 or alt_end < alt_start or alt_end > alt_row["lines"]:
                    raise GroundTruthReviewError(f"Alternatif etiket konumu geçersiz: {project}/{alt_file}")
            counts[item["class"]] += 1

    if require_attestation:
        attestation = gt.get("meta", {}).get("blinded_review")
        if not isinstance(attestation, dict) or attestation.get("prepared_before_analysis") is not True \
                or attestation.get("independent_of_engine_output") is not True \
                or not isinstance(attestation.get("reviewer"), str) or not attestation["reviewer"].strip() \
                or not isinstance(attestation.get("reviewed_at"), str) or not _ISO_UTC.fullmatch(attestation["reviewed_at"]) \
                or attestation.get("source_manifest_sha256") != file_sha256(manifest_file):
            raise GroundTruthReviewError("Bağımsız insan körleme beyanı eksik veya kaynak manifestiyle eşleşmiyor.")
    return {"format": manifest_format, "project_count": len(gt["projects"]),
            "source_file_count": sum(len(rows) for rows in manifest["projects"].values()),
            "label_count": sum(counts.values()), "classes": dict(sorted(counts.items())),
            "source_profiles": profiles,
            "source_manifest_sha256": file_sha256(manifest_file)}
