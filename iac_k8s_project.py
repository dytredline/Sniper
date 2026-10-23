"""Düz Kubernetes manifestleri için proje geneli kaynak ilişkileri."""
from __future__ import annotations

from pathlib import Path

import iac_engine
import iac_yaml
from project_tree import ProjectTree, ProjectTreeError

MAX_FILES = 3000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 30_000_000


def scan_tree(
    root: Path,
    skip_dirs: set[str],
    *,
    project_tree: ProjectTree | None = None,
) -> iac_engine.ProjectResults:
    root = Path(root)
    docs: list[iac_yaml.LDict] = []
    total = 0
    count = 0
    limitations: set[str] = set()
    tree = project_tree.duplicate() if project_tree is not None else ProjectTree(root)
    try:
        with tree:
            for observed in tree.iter_files(skip_dirs=skip_dirs, reject_unsafe=False):
                if not observed.name.casefold().endswith((".yaml", ".yml")):
                    continue
                if observed.size > MAX_FILE_BYTES:
                    limitations.add("file-bytes")
                    continue
                if count >= MAX_FILES:
                    limitations.add("file")
                    break
                # Bütçe her okuma adayında tüketilir. YAML'ın Kubernetes belgesi çıkmaması,
                # sınırsız sayıda sıradan YAML dosyasının okunmasına izin vermemeli.
                count += 1
                try:
                    raw = tree.read_bytes(observed, MAX_FILE_BYTES, allow_empty=True)
                except ProjectTreeError:
                    limitations.add("file-read")
                    continue
                if total + len(raw) > MAX_TOTAL_BYTES:
                    limitations.add("total-bytes")
                    break
                total += len(raw)
                try:
                    text = raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    continue
                # Helm/kustomize parçalarında ilişki kesin değildir; dosya başına motor bunları ayrıca inceler.
                if "{{" in text or "apiVersion" not in text or "kind" not in text:
                    continue
                try:
                    parsed = list(iac_engine._k8s_docs(iac_yaml.load_all(text)))
                except iac_yaml.YamlError:
                    continue
                rel = observed.path.as_posix()
                for doc in parsed:
                    doc._sniper_rel = rel
                    docs.append(doc)
    except ProjectTreeError:
        limitations.add("file-read")
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
