from __future__ import annotations

import hashlib
import json
import os
import pathlib
from typing import Dict, Set, Tuple


# Constants per spec
EXPECTED_INDEX_VERSION = "v10.5.0"
HTTP_PREFIX = "http"
YAML_SUFFIXES = (".yaml", ".yml")
MIN_ID_LENGTH = 1
MAX_ID_LENGTH = 128
MAX_IDS = 1000
MIN_ID_FIRST_CHAR_ALLOWED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
ID_CHAR_SET = set(MIN_ID_FIRST_CHAR_ALLOWED + "._-")


def _is_ascii_alpha_num_plus_underscore_dot_hyphen(s: str) -> bool:
    """Return True if s matches [A-Za-z0-9][A-Za-z0-9._-]{0,127}"""
    if not s:
        return False
    if len(s) > MAX_ID_LENGTH:
        return False
    if s[0] not in MIN_ID_FIRST_CHAR_ALLOWED:
        return False
    return all(c in ID_CHAR_SET for c in s)


def _verify_no_symlink(path: pathlib.Path, base: pathlib.Path) -> None:
    """Ensure no symlink in path components from base down to path"""
    current = path
    while True:
        if current.is_symlink():
            raise ValueError(f"Çözümlenen yolda sembolik bağ bulundu: {current}")
        if current == base or current == current.parent:
            break
        current = current.parent


def _verify_no_dotdot(path: pathlib.Path) -> None:
    """Ensure resolved path has no '..' in its normalized relative form to base"""
    if '..' in str(path):
        raise ValueError(f"Yol '..' içeriyor: {path}")


def _verify_yaml_under_http(path: pathlib.Path, catalog_root: pathlib.Path) -> None:
    """Ensure path is under catalog_root/http, is .yaml/.yml, and no absolute path components"""
    try:
        rel = path.relative_to(catalog_root)
    except ValueError:
        raise ValueError(f"{path} yolu catalog_root {catalog_root} altında değil")

    parts = rel.parts
    if len(parts) < 2 or parts[0] != HTTP_PREFIX:
        raise ValueError(f"Yol '{HTTP_PREFIX}/' altında olmalı: {path}")

    if not parts[-1].endswith(YAML_SUFFIXES):
        raise ValueError(f"Yol .yaml veya .yml ile bitmeli: {path}")


def _verify_path_content_sha256(file_path: pathlib.Path, expected_sha256: str) -> None:
    """Compute SHA256 of file contents and compare to expected"""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    computed = sha.hexdigest()
    if computed != expected_sha256:
        raise ValueError(f"{file_path} için SHA256 uyuşmuyor: {expected_sha256} bekleniyordu, {computed} hesaplandı")


def _validate_index_content(
    data: dict,
    expected_index_sha256: str,
    count_expected: int,
) -> None:
    # Validate version
    if data.get("version") != EXPECTED_INDEX_VERSION:
        raise ValueError(f"Dizin sürümü {EXPECTED_INDEX_VERSION} olmalı, {data.get('version')!r} verildi")

    # Validate top-level keys exist and have expected names
    required_keys = {"version", "count", "paths_and_hashes", "scope", "sha256"}
    if not isinstance(data, dict) or set(data.keys()) != required_keys:
        raise ValueError(f"Dizin tam olarak {required_keys} anahtarlarını içermeli")

    # Validate count
    count_actual = data.get("count")
    if not isinstance(count_actual, int) or count_actual != count_expected:
        raise ValueError(f"Dizin sayısı {count_expected} olmalı, {count_actual} verildi")

    # Validate sha256 field — *not* used as trusted anchor, only format check
    index_sha = data.get("sha256")
    if not isinstance(index_sha, str) or len(index_sha) != 64:
        raise ValueError(f"Index.sha256 64 karakterlik onaltılık metin olmalı")

    # Validate paths_and_hashes structure
    rows = data.get("paths_and_hashes")
    if not isinstance(rows, list):
        raise ValueError("paths_and_hashes bir liste olmalı")
    if len(rows) != count_expected:
        raise ValueError(f"paths_and_hashes uzunluğu ({len(rows)}) sayıyla ({count_actual}) eşleşmiyor")

    seen_paths = set()
    seen_hashes = set()
    for i, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError(f"{i}. satır 2 metinden oluşan bir liste olmalı: {row!r}")
        rel_path, sha256 = row
        if not all(isinstance(x, str) for x in row):
            raise ValueError(f"{i}. satırın öğeleri metin olmalı: {row!r}")

        if rel_path in seen_paths:
            raise ValueError(f"Yinelenen göreli yol: {rel_path}")
        seen_paths.add(rel_path)

        if sha256 in seen_hashes:
            raise ValueError(f"Yinelenen SHA256: {sha256}")
        seen_hashes.add(sha256)

        # Path must be relative POSIX (no backslashes, no absolute)
        if rel_path.startswith('/') or rel_path.startswith('\\'):
            raise ValueError(f"Göreli yol POSIX olmalı (başta eğik çizgi olmadan): {rel_path}")
        if '\\' in rel_path:
            raise ValueError(f"Göreli yol POSIX ayırıcıları kullanmalı: {rel_path}")

        # Validate SHA256 format
        if len(sha256) != 64:
            raise ValueError(f"SHA256 64 karakterlik onaltılık olmalı: {sha256}")


def verify_http_catalog(
    root: pathlib.Path,
    pin_path: pathlib.Path,
    expected_pin_sha256: str,
    expected_count: int,
    mapping_sha256: str,
) -> dict:
    # Validate inputs per contract
    if not isinstance(root, pathlib.Path):
        root = pathlib.Path(root)
    if not isinstance(pin_path, pathlib.Path):
        pin_path = pathlib.Path(pin_path)

    # Require absolute non-symlink root and pin file
    if not root.is_absolute():
        raise ValueError("root mutlak olmalı")
    if root.is_symlink():
        raise ValueError("root sembolik bağ olmamalı")
    if not root.is_dir():
        raise ValueError("root bir dizin olmalı")

    if not pin_path.is_absolute():
        raise ValueError("pin_path mutlak olmalı")
    if pin_path.is_symlink():
        raise ValueError("pin_path sembolik bağ olmamalı")
    if not pin_path.is_file():
        raise ValueError("pin_path bir dosya olmalı")

    # Pin file bytes must match expected_pin_sha256 before JSON parsing
    try:
        pin_bytes = pin_path.read_bytes()
    except OSError as e:
        raise ValueError(f"Sabitleme dosyası {pin_path} okunamadı: {e}")

    if hashlib.sha256(pin_bytes).hexdigest() != expected_pin_sha256.lower():
        raise ValueError(f"Sabitleme SHA256 değeri uyuşmuyor: {expected_pin_sha256} bekleniyordu, {hashlib.sha256(pin_bytes).hexdigest()} hesaplandı")

    # Parse JSON strictly
    try:
        pin_data = json.loads(pin_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Sabitleme dosyası geçerli JSON değil: {e}")

    # Validate pin content (including counts, versions, rows)
    _validate_index_content(pin_data, expected_pin_sha256.lower(), expected_count)

    # Build expected set: all listed YAMLs from paths_and_hashes + mapping.yml
    http_dir = root / HTTP_PREFIX
    if not http_dir.is_absolute():
        raise RuntimeError("root/http mutlak olmalı")
    if http_dir.is_symlink():
        raise ValueError("root/http sembolik bağ olmamalı")
    if not http_dir.is_dir():
        raise ValueError("root/http bir dizin olmalı")

    # Map relative paths to expected hashes from pin
    pin_map: Dict[str, str] = {}
    for rel_path, sha256 in pin_data["paths_and_hashes"]:
        pin_map[rel_path] = sha256

    # Add mapping.yml if not present in pin_map (per spec: include pinned extra_data)
    mapping_rel = os.path.join(HTTP_PREFIX, "technologies", "wappalyzer-mapping.yml")
    if mapping_rel not in pin_map:
        # According to spec, mapping.yml is pinned separately
        pin_map[mapping_rel] = mapping_sha256

    # Enumerate all .yaml/.yml files under root/http/ without following symlinks
    actual_files: Set[pathlib.Path] = set()
    for dirpath, dirnames, filenames in os.walk(http_dir, followlinks=False):
        dirpath = pathlib.Path(dirpath)
        # Reject symlinks in directories
        for dn in list(dirnames):
            d = dirpath / dn
            if d.is_symlink():
                raise ValueError(f"Katalog altında sembolik bağlı dizin bulundu: {d}")
        for fn in filenames:
            if fn.endswith(YAML_SUFFIXES):
                full_path = dirpath / fn
                if full_path.is_symlink():
                    raise ValueError(f"Katalog altında sembolik bağlı dosya bulundu: {full_path}")
                if not full_path.is_file():
                    raise ValueError(f"Katalog altında dosya olmayan girdi: {full_path}")
                actual_files.add(full_path)

    # Expected full paths: join each pin_map key with root
    expected_paths: Set[pathlib.Path] = set()
    for rel_path in pin_map.keys():
        full_path = root / rel_path
        if not full_path.is_absolute():
            raise RuntimeError(f"Çözümlenen yol mutlak değil: {full_path}")
        expected_paths.add(full_path)

    # Compare sets
    if actual_files != expected_paths:
        missing = expected_paths - actual_files
        extra = actual_files - expected_paths
        raise ValueError(
            f"Dosya kümesi uyuşmuyor: eksik={len(missing)}, fazla={len(extra)}; "
            f"eksik={missing}, fazla={extra}"
        )

    # Verify all content hashes (including mapping.yml)
    for rel_path, expected_hash in pin_map.items():
        full_path = root / rel_path
        try:
            _verify_path_content_sha256(full_path, expected_hash)
        except ValueError as ve:
            raise ValueError(f"{rel_path} için SHA256 doğrulaması başarısız oldu: {ve}") from ve

    # Final checks on each file path: symlink-free relative to root, no dotdot
    for full_path in expected_paths:
        try:
            _verify_no_symlink(full_path, root)
            _verify_no_dotdot(full_path)
            _verify_yaml_under_http(full_path, root)
        except ValueError as ve:
            raise ValueError(f"{full_path} için yol doğrulaması başarısız oldu: {ve}") from ve

    # Return sanitized status
    return {
        "status": "ok",
        "template_count": expected_count,
        "pin_sha256": expected_pin_sha256.lower(),
    }
