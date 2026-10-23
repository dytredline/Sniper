from __future__ import annotations

import re
import os
from pathlib import Path


def build_nuclei_http_args(
    binary: Path,
    catalog_root: Path,
    target_url: str,
    output_path: Path,
    template_ids: list[str] | None = None,
    include_excluded: bool = False,
    selected_template_paths: dict[str, Path] | None = None,
) -> list[str]:
    """
    Build deterministic subprocess.argv list for a Nuclei HTTP scan.

    Contract:
    - template_ids=[] or None → broad mode (no -id)
    - non-empty template_ids → narrow mode via -id id1 -id id2 ...
    - Never use profiles/recommended.yml
    - Always include required privacy/safety flags
    - No shell; pure list argv
    - Do not validate URL, filesystem, or auth; caller must have done so.
    """
    # Normalize and validate template_ids early
    ids = template_ids if template_ids is not None else []

    # Enforce: max 1000 elements, no duplicates, all ASCII, valid format
    if len(ids) > 1000:
        raise ValueError("template_ids en fazla 1000 öğe içerebilir")
    seen = set()
    id_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    for eid in ids:
        if not isinstance(eid, str) or not eid:
            raise ValueError("her template_id boş olmayan bir metin olmalı")
        if not id_pattern.fullmatch(eid):
            raise ValueError(f"geçersiz template_id biçimi: {eid}")
        if eid in seen:
            raise ValueError(f"yinelenen template_id: {eid}")
        seen.add(eid)

    # Validate selected_template_paths when include_excluded is True and IDs non-empty
    # Reject selected_template_paths otherwise (fail-closed)
    if include_excluded and ids:
        if selected_template_paths is None:
            raise ValueError("include_excluded=True ve template_ids boş değilse selected_template_paths verilmeli")
        # Validate selected_template_paths structure and contents
        if not isinstance(selected_template_paths, dict):
            raise ValueError("selected_template_paths bir sözlük olmalı")
        if set(selected_template_paths.keys()) != set(ids):
            raise ValueError("selected_template_paths anahtarları template_ids ile birebir eşleşmeli")
        base_http = catalog_root / "http"
        try:
            base_http_resolved = base_http.resolve()
        except OSError:
            raise ValueError(f"catalog_root/http yolu çözümlenemiyor: {catalog_root / 'http'}")
        resolved_paths = []
        for eid in ids:
            path = selected_template_paths[eid]
            if not isinstance(path, Path):
                raise ValueError(f"selected_template_paths[{eid!r}] bir Path olmalı, {type(path).__name__} verildi")
            # Check absolute on original path before resolving
            if not path.is_absolute():
                raise ValueError(f"{eid!r} kimliğinin şablon yolu mutlak olmalı: {path}")
            # Check no symlinks in original path or original ancestors below catalog_root/http
            # Walk up from original path to base_http and check each component BEFORE resolving
            current = path
            while True:
                if current.is_symlink():
                    raise ValueError(f"{eid!r} kimliğinin şablon yolu veya bir üst dizini sembolik bağ: {path}")
                try:
                    parent = current.parent
                except RuntimeError:
                    break
                if parent == current:
                    break
                current = parent
                if current == base_http:
                    break
            # After reaching base_http or root, check lexical relative_to
            try:
                path.relative_to(base_http)
            except ValueError:
                raise ValueError(f"{eid!r} kimliğinin şablon yolu catalog_root/http altında değil: {path}")
            # Now resolve and validate
            try:
                resolved = path.resolve()
            except OSError:
                raise ValueError(f"{eid!r} kimliğinin şablon yolu çözümlenemiyor: {path}")
            # Must be .yaml or .yml (check raw suffix before resolving)
            if path.suffix not in (".yaml", ".yml"):
                raise ValueError(f"{eid!r} kimliğinin şablon yolu .yaml veya .yml uzantılı olmalı: {path}")
            # Must be a regular file
            if not resolved.is_file():
                raise ValueError(f"{eid!r} kimliğinin şablon yolu normal bir dosya olmalı: {path}")
            # Confirm containment under resolved catalog_root/http
            try:
                resolved.relative_to(base_http_resolved)
            except ValueError:
                raise ValueError(f"{eid!r} kimliğinin şablon yolu catalog_root/http altında değil: {path}")
            resolved_paths.append(resolved)
    elif selected_template_paths is not None:
        raise ValueError("include_excluded=False veya template_ids boşken selected_template_paths verilmemeli")

    # Base CLI
    args = [
        str(binary),
        "-u", target_url,
        "-o", str(output_path),
        "-jsonl", "-silent", "-nc", "-or", "-ot", "-duc", "-ni", "-dr",
        "-no-stdin", "-pt", "http", "-dut", "-lna", "-c", "1", "-rl", "1",
        "-timeout", "5", "-retries", "0",
    ]

    if ids:
        # Narrow mode
        if selected_template_paths is not None:
            # Full narrow: use -t and -it with exact resolved paths, no -id, no -t ROOT/http, no -it ROOT/http
            for eid in ids:
                path = selected_template_paths[eid]
                resolved = path.resolve()
                args.extend(("-t", str(resolved), "-it", str(resolved)))
        else:
            # Standard narrow: use -id for each id, plus -t ROOT/http, -it ROOT/http if include_excluded
            args.extend(("-t", str(catalog_root / "http")))
            for eid in ids:
                args.extend(("-id", eid))
            if include_excluded:
                args.extend(("-it", str(catalog_root / "http")))
    else:
        # Broad mode
        args.extend(("-t", str(catalog_root / "http")))
        if include_excluded:
            args.extend(("-it", str(catalog_root / "http")))

    return args
