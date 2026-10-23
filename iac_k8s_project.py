"""Düz Kubernetes manifestleri için proje geneli kaynak ilişkileri."""
from __future__ import annotations

import os
from pathlib import Path
import stat

import iac_engine
import iac_yaml

MAX_FILES = 3000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 30_000_000


def scan_tree(root: Path, skip_dirs: set[str]) -> iac_engine.ProjectResults:
    root = Path(root)
    docs: list[iac_yaml.LDict] = []
    total = 0
    count = 0
    limitations: set[str] = set()
    exhausted = False
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories
                                if name.casefold() not in skip_dirs and not (Path(current) / name).is_symlink())
        for name in sorted(names):
            if not name.casefold().endswith((".yaml", ".yml")):
                continue
            path = Path(current) / name
            try:
                info = os.stat(path, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_size > MAX_FILE_BYTES:
                limitations.add("file-bytes")
                continue
            if count >= MAX_FILES or total + info.st_size > MAX_TOTAL_BYTES:
                limitations.add("file" if count >= MAX_FILES else "total-bytes")
                exhausted = True
                break
            # Bütçe her okuma adayında tüketilir. YAML'ın Kubernetes belgesi çıkmaması, sınırsız sayıda
            # sıradan YAML dosyasının okunmasına izin vermemeli.
            count += 1
            total += info.st_size
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            # Helm/kustomize parçalarında ilişki kesin değildir; dosya başına motor bunları ayrıca inceler.
            if "{{" in text or "apiVersion" not in text or "kind" not in text:
                continue
            try:
                parsed = list(iac_engine._k8s_docs(iac_yaml.load_all(text)))
            except iac_yaml.YamlError:
                continue
            rel = path.relative_to(root).as_posix()
            for doc in parsed:
                doc._sniper_rel = rel
                docs.append(doc)
        if exhausted:
            break
    results = iac_engine.ProjectResults()
    for doc, line, resource in iac_engine.k8s_relationships(docs):
        rel = getattr(doc, "_sniper_rel", "")
        if not rel:
            continue
        collector = iac_engine._Collector("kubernetes")
        collector.add("SNP-IAC-K8S-016", line, resource)
        target = results.setdefault(rel, iac_engine.IacResult("kubernetes"))
        target.findings.extend(collector.result.findings)
    return results.mark_incomplete(*sorted(limitations)) if limitations else results
