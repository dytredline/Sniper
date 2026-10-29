import hashlib
import json
import os
import pathlib
from typing import List, Dict


# Constants per spec
EXPECTED_INDEX_VERSION = "v10.5.0"
MIN_ID_LENGTH = 1
MAX_ID_LENGTH = 128
MAX_IDS = 1000
MIN_ID_FIRST_CHAR_ALLOWED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
ID_CHAR_SET = set(MIN_ID_FIRST_CHAR_ALLOWED + "._-")

HTTP_PREFIX = "http"
YAML_SUFFIXES = (".yaml", ".yml")


def _is_ascii_alpha_num_plus_underscore_dot_hyphen(s: str) -> bool:
    """Return True if s matches [A-Za-z0-9][A-Za-z0-9._-]{0,127}"""
    if not s:
        return False
    if len(s) > MAX_ID_LENGTH:
        return False
    if s[0] not in MIN_ID_FIRST_CHAR_ALLOWED:
        return False
    return all(c in ID_CHAR_SET for c in s)


def _verify_symlink_free(path: pathlib.Path, base: pathlib.Path) -> None:
    """Ensure no symlink in path components from base down to path"""
    # Walk upwards from path to base, checking each component is not a symlink
    current = path
    while True:
        if current.is_symlink():
            raise ValueError(f"Çözümlenen yolda sembolik bağ bulundu: {current}")
        if current == base or current == current.parent:
            break
        current = current.parent


def _verify_no_dotdot(path: pathlib.Path) -> None:
    """Ensure resolved path has no '..' in its normalized relative form to base"""
    # Pathlib already normalizes, so check raw path segments contain no '..'
    # But spec says 'no ..' in relative path: check both raw and resolved
    if '..' in str(path):
        raise ValueError(f"Yol '..' içeriyor: {path}")


def _verify_yaml_under_http(path: pathlib.Path, catalog_root: pathlib.Path) -> None:
    """Ensure path is under catalog_root/http, is YAML, and no absolute path components."""
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
    required_keys = {"version", "count", "sha256", "ids_paths_hashes"}
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

    # Validate ids_paths_hashes structure
    rows = data.get("ids_paths_hashes")
    if not isinstance(rows, list):
        raise ValueError("ids_paths_hashes bir liste olmalı")
    if len(rows) != count_expected:
        raise ValueError(f"ids_paths_hashes uzunluğu ({len(rows)}) sayıyla ({count_expected}) eşleşmiyor")

    seen_ids = set()
    seen_paths = set()
    for i, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 3:
            raise ValueError(f"{i}. satır 3 metinden oluşan bir liste olmalı: {row!r}")
        template_id, rel_path, sha256 = row
        if not all(isinstance(x, str) for x in row):
            raise ValueError(f"{i}. satırın öğeleri metin olmalı: {row!r}")

        # Duplicates
        if template_id in seen_ids:
            raise ValueError(f"Yinelenen template-id: {template_id}")
        seen_ids.add(template_id)

        if rel_path in seen_paths:
            raise ValueError(f"Yinelenen yol: {rel_path}")
        seen_paths.add(rel_path)

        # Path must be relative POSIX (no backslashes, no absolute)
        if rel_path.startswith('/') or rel_path.startswith('\\'):
            raise ValueError(f"Göreli yol POSIX olmalı (başta eğik çizgi olmadan): {rel_path}")
        if '\\' in rel_path:
            raise ValueError(f"Göreli yol POSIX ayırıcıları kullanmalı: {rel_path}")

        # Validate SHA256 format
        if len(sha256) != 64:
            raise ValueError(f"SHA256 64 karakterlik onaltılık olmalı: {sha256}")


def resolve_http_template_paths(
    catalog_root: pathlib.Path,
    requested_ids: List[str],
    expected_index_sha256: str,
) -> Dict[str, pathlib.Path]:
    # Validate inputs per contract
    if not isinstance(catalog_root, pathlib.Path):
        catalog_root = pathlib.Path(catalog_root)
    if not catalog_root.is_absolute():
        raise ValueError("catalog_root mutlak olmalı")
    if catalog_root.is_symlink():
        raise ValueError("catalog_root sembolik bağ olmamalı")
    if not catalog_root.is_dir():
        raise ValueError("catalog_root bir dizin olmalı")

    index_path = catalog_root / "SNIPER-HTTP-ID-INDEX.json"
    if not index_path.is_absolute():
        raise ValueError("Dizin yolu mutlak olmalı (catalog_root mutlak)")
    if index_path.is_symlink():
        raise ValueError("Dizin yolu sembolik bağ olmamalı")

    # Validate index bytes SHA-256 against expected_index_sha256 (trusted anchor)
    try:
        index_bytes = index_path.read_bytes()
    except FileNotFoundError:
        raise ValueError(f"Dizin dosyası bulunamadı: {index_path}")
    except OSError as e:
        raise ValueError(f"Dizin okunamadı: {e}")

    if hashlib.sha256(index_bytes).hexdigest() != expected_index_sha256:
        raise ValueError(f"Dizin SHA256 değeri uyuşmuyor: {expected_index_sha256} bekleniyordu")

    # Parse JSON strictly
    try:
        index_data = json.loads(index_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Dizin geçerli JSON değil: {e}")

    # Validate index content (including counts, versions, rows)
    _validate_index_content(index_data, expected_index_sha256, len(index_data.get("ids_paths_hashes", [])))

    # Build ID->(path, sha256) map from index
    row_map: Dict[str, tuple] = {}
    for template_id, rel_path, file_sha256 in index_data["ids_paths_hashes"]:
        row_map[template_id] = (rel_path, file_sha256)

    # Validate requested_ids
    if not isinstance(requested_ids, list) or not requested_ids:
        raise ValueError("requested_ids boş olmayan bir liste olmalı")
    if len(requested_ids) > MAX_IDS:
        raise ValueError(f"requested_ids azami {MAX_IDS} sayısını aşıyor")

    seen_req = set()
    for rid in requested_ids:
        if not isinstance(rid, str) or not _is_ascii_alpha_num_plus_underscore_dot_hyphen(rid):
            raise ValueError(f"Geçersiz istenen kimlik: {rid!r}")
        if rid in seen_req:
            raise ValueError(f"Yinelenen istenen kimlik: {rid}")
        seen_req.add(rid)
        if rid not in row_map:
            raise ValueError(f"Bilinmeyen istenen kimlik: {rid}")

    # Resolve paths — row paths already contain http/ prefix
    results: Dict[str, pathlib.Path] = {}
    http_root = catalog_root / HTTP_PREFIX
    if not http_root.is_absolute():
        raise RuntimeError("catalog_root/http mutlak olmalı")
    if http_root.is_symlink():
        raise ValueError("catalog_root/http sembolik bağ olmamalı")

    for rid in requested_ids:
        rel_path_str, expected_sha = row_map[rid]
        # Construct full path directly under catalog_root using the relative path from the index
        full_path = catalog_root / rel_path_str

        # Sanitize and validate path components
        if not full_path.is_absolute():
            # Should be absolute because catalog_root is absolute
            raise RuntimeError("Göreli yol çözümlemesi mutlak olmayan bir yol üretti")
        if full_path.is_symlink():
            raise ValueError(f"Çözümlenen şablon sembolik bağ: {full_path}")
        if not full_path.is_file():
            raise ValueError(f"Çözümlenen yol normal bir dosya değil: {full_path}")

        # Enforce symlink-free and containment
        try:
            _verify_symlink_free(full_path, catalog_root)
            _verify_no_dotdot(full_path)
            _verify_yaml_under_http(full_path, catalog_root)
        except ValueError as ve:
            raise ValueError(f"{rid} için geçersiz yol: {ve}") from ve

        # Final containment under catalog_root/http is implicit from construction

        # Validate content integrity
        try:
            _verify_path_content_sha256(full_path, expected_sha)
        except ValueError as ve:
            raise ValueError(f"{rid} için SHA256 uyuşmuyor: {ve}") from ve

        results[rid] = full_path

    return results
