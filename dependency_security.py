from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import socket
import subprocess
import tomllib
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from project_analyzer import ProjectRejected, validate_project_path

from safe_file_read import read_bytes_bounded


MAX_REPORT_BYTES = 8_000_000
MAX_COMPONENTS = 20_000
MAX_FINDINGS = 50_000
MAX_MAVEN_MODELS = 64
MAX_MAVEN_RESOLVED_CHARS = 4_000
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


class DependencySecurityError(ValueError):
    pass


def _clean(value: Any, maximum: int = 4_000) -> str:
    text = str(value or "").strip()
    return text[:maximum]


def _package_url(ecosystem: str, name: str, version: str) -> str:
    import urllib.parse
    types = {
        "pypi": "pypi",
        "npm": "npm",
        "golang": "golang",
        "go": "golang",
        "cargo": "cargo",
        "crates.io": "cargo",
        "maven": "maven",
        "gradle": "maven",
        "rubygems": "gem",
        "gem": "gem",
        "packagist": "composer",
        "composer": "composer",
        "pub": "pub",
        "cocoapods": "cocoapods",
        "pod": "cocoapods",
        "swift": "swift",
        "swifturl": "swift",
        "nuget": "nuget",
        "hex": "hex",
    }
    package_type = types.get(ecosystem.casefold(), "generic")
    encoded_name = name.replace(" ", "%20")
    if package_type == "npm" and name.startswith("@"):
        encoded_name = encoded_name.replace("@", "%40", 1)
    if version:
        encoded_version = urllib.parse.quote(version, safe="")
        return f"pkg:{package_type}/{encoded_name}@{encoded_version}"
    return f"pkg:{package_type}/{encoded_name}"


def _split_requirement(value: str) -> tuple[str, str] | None:
    line = value.strip()
    if not line or line.startswith(("#", "-", "http://", "https://", "git+")):
        return None
    line = line.split(" #", 1)[0].split(";", 1)[0].strip()
    line = line.split(" --", 1)[0].strip()
    line = line.rstrip("\\").strip()  # 18. tur: satır devamı ("pkg==1.0 \\" + --hash satırları) sürümü düşürmesin
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(?:===|==)\s*([^,\s]+)$", line)
    if match:
        return match.group(1), match.group(2)
    match = re.match(r"^([A-Za-z0-9_.-]+)", line)
    return (match.group(1), "") if match else None


def _python_components(root: Path) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    requirements = root / "requirements.txt"
    if requirements.is_symlink():
        raise DependencySecurityError("requirements.txt bir simge bağlantısı olamaz.")
    if requirements.is_file() and requirements.stat().st_size > 1_000_000:
        raise DependencySecurityError("requirements.txt boyut sınırını aşıyor.")
    if requirements.is_file() and requirements.stat().st_size <= 1_000_000:
        try:
            text = requirements.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            raise DependencySecurityError(f"requirements.txt decode hatası: {e}") from e
        if text.startswith("\ufeff"):
            text = text[1:]
        for line in text.splitlines():
            parsed = _split_requirement(line)
            if parsed:
                name, version = parsed
                result.append({"name": name, "version": version, "ecosystem": "PyPI", "manifest": "requirements.txt"})
    pyproject = root / "pyproject.toml"
    if pyproject.is_symlink():
        raise DependencySecurityError("pyproject.toml bir simge bağlantısı olamaz.")
    if pyproject.is_file() and pyproject.stat().st_size > 1_000_000:
        raise DependencySecurityError("pyproject.toml boyut sınırını aşıyor.")
    if pyproject.is_file() and pyproject.stat().st_size <= 1_000_000:
        raw_pyproject = read_bytes_bounded(pyproject, 1_000_000, allow_empty=True)
        if raw_pyproject is None:
            raise DependencySecurityError("pyproject.toml güvenli biçimde okunamadı.")
        try:
            content = raw_pyproject.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DependencySecurityError("pyproject.toml geçerli UTF-8 değil.") from exc
        try:
            document = tomllib.loads(content)
        except (OSError, tomllib.TOMLDecodeError, RecursionError) as exc:
            raise DependencySecurityError("pyproject.toml geçerli TOML değil.") from exc
        project = document.get("project", {})
        if not isinstance(project, dict):
            raise DependencySecurityError("pyproject.toml project alanı bir nesne olmalıdır.")
        deps = project.get("dependencies")
        if deps is None:
            deps = []
        if not isinstance(deps, list):
            raise DependencySecurityError("pyproject.toml project.dependencies bir dizi olmalıdır.")
        for idx, value in enumerate(deps):
            if not isinstance(value, str):
                raise DependencySecurityError(f"pyproject.toml project.dependencies[{idx}] bir string olmalıdır.")
            parsed = _split_requirement(value)
            if parsed:
                name, version = parsed
                result.append({"name": name, "version": version, "ecosystem": "PyPI", "manifest": "pyproject.toml"})
        opt_deps = project.get("optional-dependencies")
        if opt_deps is not None:
            if not isinstance(opt_deps, dict):
                raise DependencySecurityError("pyproject.toml project.optional-dependencies bir nesne olmalıdır.")
            for group_name, group_value in opt_deps.items():
                if not isinstance(group_value, list):
                    raise DependencySecurityError(f"pyproject.toml project.optional-dependencies[{group_name}] bir dizi olmalıdır.")
                for idx, value in enumerate(group_value):
                    if not isinstance(value, str):
                        raise DependencySecurityError(f"pyproject.toml project.optional-dependencies[{group_name}][{idx}] bir string olmalıdır.")
                    parsed = _split_requirement(value)
                    if parsed:
                        name, version = parsed
                        result.append({"name": name, "version": version, "ecosystem": "PyPI", "manifest": "pyproject.toml"})
    result.extend(_poetry_components(root))
    return result


def _poetry_components(root: Path) -> list[dict[str, str]]:
    lockfile = root / "poetry.lock"
    if lockfile.is_symlink():
        raise DependencySecurityError("poetry.lock bir simge bağlantısı olamaz.")
    if not lockfile.is_file():
        return []
    size = lockfile.stat().st_size
    if size > MAX_REPORT_BYTES:
        raise DependencySecurityError("poetry.lock boyut sınırını aşıyor.")
    try:
        content = lockfile.read_text(encoding="utf-8", errors="strict")
        document = tomllib.loads(content)
    except OSError as exc:
        raise DependencySecurityError("poetry.lock okunamadı.") from exc
    except UnicodeDecodeError as exc:
        raise DependencySecurityError("poetry.lock geçerli UTF-8 değil.") from exc
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise DependencySecurityError("poetry.lock geçerli TOML değil.") from exc
    if not isinstance(document, dict):
        raise DependencySecurityError("poetry.lock kökü bir TOML nesnesi olmalıdır.")
    result: list[dict[str, str]] = []
    packages = document.get("package", [])
    if not isinstance(packages, list):
        raise DependencySecurityError("poetry.lock package alanı bir dizi şemasına uymuyor.")
    seen: set[tuple[str, str]] = set()
    for item in packages:
        if not isinstance(item, dict):
            raise DependencySecurityError("poetry.lock package şeması geçersiz: her öğe bir nesne olmalıdır.")
        raw_name = item.get("name")
        raw_version = item.get("version")
        if raw_name is None:
            raise DependencySecurityError("poetry.lock package name alanı eksik.")
        if not isinstance(raw_name, str):
            raise DependencySecurityError("poetry.lock package name alanı geçersiz: bir string olmalıdır.")
        name = _clean(raw_name)
        if not name:
            raise DependencySecurityError("poetry.lock package name alanı eksik veya boş.")
        # Güvenli ASCII dağıtım adı doğrulaması: PyPA name grammar
        # Regex: baş/son harf/rakam, iç ASCII harf/rakam/dot/underscore/hyphen
        import re
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]|[A-Za-z0-9]', raw_name):
            raise DependencySecurityError("poetry.lock package name alanı güvenli ASCII değil.")
        if ".." in name or "/" in name or "\\" in name:
            raise DependencySecurityError("poetry.lock package name alanı geçersiz: yol ayracı içeremez.")
        if raw_version is None:
            raise DependencySecurityError("poetry.lock package version alanı eksik.")
        if isinstance(raw_version, (int, float)):
            raise DependencySecurityError("poetry.lock package version bir string olmalıdır.")
        if not isinstance(raw_version, str):
            raise DependencySecurityError("poetry.lock package version bir string olmalıdır.")
        version = _clean(raw_version)
        if not version:
            raise DependencySecurityError("poetry.lock package version boş olamaz.")
        key = (name.casefold(), version.casefold())
        if key not in seen:
            seen.add(key)
            result.append({"name": name, "version": version, "ecosystem": "PyPI", "manifest": "poetry.lock"})
        if len(result) > MAX_COMPONENTS:
            break
    return result



PIPFILE_LOCK_NAME = "Pipfile.lock"
# Varsayılan (genel) PyPI dizinleri; bunlar için PURL'e repository_url eklenmez.
_PIPFILE_DEFAULT_PYPI_HOSTS = frozenset({"pypi.org", "www.pypi.org", "pypi.python.org"})
# VCS / yerel yol kayıtları: PyPI sürüm kimliği yoktur, bileşen olarak üretilmez.
_PIPFILE_NON_REGISTRY_KEYS = ("git", "hg", "svn", "bzr", "path", "file")
_PIPFILE_EXACT_PIN = re.compile(r"==\s*([A-Za-z0-9](?:[A-Za-z0-9._+!-]*[A-Za-z0-9])?)")
_PYPA_DIST_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


def _pep503_normalize(name: str) -> str:
    """PEP 503 ad normalizasyonu: küçük harf, -_. dizileri tek '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_regular_file_bytes(root: Path, filename: str, limit: int = MAX_REPORT_BYTES) -> bytes | None:
    """Kök dizindeki dosyayı tek bir tanıtıcı üzerinden güvenli okur.

    O_NOFOLLOW son bileşendeki sembolik bağı açılış anında reddeder; tür ve
    boyut kontrolü os.fstat ile aynı tanıtıcı üzerinde yapılır; okuma da
    limit+1 bayt ile sınırlandığından fstat sonrası büyüme yakalanır.
    Dosya yoksa None döner.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(root / filename, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise DependencySecurityError(f"{filename} bir simge bağlantısı olamaz.") from exc
        raise DependencySecurityError(f"{filename} okunamadı.") from exc
    try:
        try:
            file_stat = os.fstat(fd)
        except OSError as exc:
            raise DependencySecurityError(f"{filename} okunamadı.") from exc
        if not stat.S_ISREG(file_stat.st_mode):
            raise DependencySecurityError(f"{filename} normal bir dosya olmalıdır.")
        if file_stat.st_size > limit:
            raise DependencySecurityError(f"{filename} boyut sınırını aşıyor.")
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(fd, min(1 << 20, limit + 1 - total))
            except OSError as exc:
                raise DependencySecurityError(f"{filename} okunamadı.") from exc
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise DependencySecurityError(f"{filename} boyut sınırını aşıyor.")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _pipfile_repository_url(raw_url: str) -> str:
    """Özel index adresini PURL repository_url niteleyicisi için temizler.

    Kimlik bilgisi (user:pass@), sorgu dizgesi ve parça (#) atılır.
    """
    try:
        parts = urllib.parse.urlsplit(raw_url.strip())
        port = parts.port
    except ValueError as exc:
        raise DependencySecurityError("Pipfile.lock _meta.sources url alanı geçerli bir adres değil.") from exc
    scheme = parts.scheme.casefold()
    host = (parts.hostname or "").casefold()
    if scheme not in {"http", "https"} or not host:
        raise DependencySecurityError("Pipfile.lock _meta.sources url alanı http(s) bir dizin adresi olmalıdır.")
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    path = parts.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def _pipfile_sources(document: dict[str, Any]) -> dict[str, str]:
    meta = document.get("_meta")
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        raise DependencySecurityError("Pipfile.lock _meta alanı bir nesne olmalıdır.")
    sources = meta.get("sources")
    if sources is None:
        return {}
    if not isinstance(sources, list):
        raise DependencySecurityError("Pipfile.lock _meta.sources alanı bir dizi olmalıdır.")
    result: dict[str, str] = {}
    for source in sources:
        if not isinstance(source, dict):
            raise DependencySecurityError("Pipfile.lock _meta.sources öğeleri nesne olmalıdır.")
        name = source.get("name")
        url = source.get("url")
        if not isinstance(name, str) or not name.strip() or not isinstance(url, str) or not url.strip():
            raise DependencySecurityError("Pipfile.lock _meta.sources öğesi name ve url string alanları içermelidir.")
        if name in result:
            raise DependencySecurityError("Pipfile.lock _meta.sources içinde yinelenen kaynak adı var.")
        result[name] = url
    return result


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Yinelenen JSON anahtarı")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError("JSON dışı sabit: " + value)


def _pipfile_lock_inventory(root: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Pipfile.lock (pipenv JSON) envanteri: (bileşenler, atlanan kayıtlar)."""
    raw = _read_regular_file_bytes(root, PIPFILE_LOCK_NAME)
    if raw is None:
        return [], []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencySecurityError("Pipfile.lock geçerli UTF-8 değil.") from exc
    if text.startswith("﻿"):
        text = text[1:]
    try:
        document = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_json_object_without_duplicates,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise DependencySecurityError("Pipfile.lock geçersiz JSON.") from exc
    if not isinstance(document, dict):
        raise DependencySecurityError("Pipfile.lock kökü bir JSON nesnesi olmalıdır.")
    sources = _pipfile_sources(document)
    components: dict[tuple[str, str, str], dict[str, str]] = {}
    skipped: list[dict[str, str]] = []
    for section in ("default", "develop"):
        packages = document.get(section)
        if packages is None:
            continue
        if not isinstance(packages, dict):
            raise DependencySecurityError(f"Pipfile.lock {section} alanı bir nesne olmalıdır.")
        for raw_name in sorted(packages):
            entry = packages[raw_name]
            if not _PYPA_DIST_NAME.fullmatch(raw_name):
                raise DependencySecurityError("Pipfile.lock paket adı güvenli ASCII değil.")
            if not isinstance(entry, dict):
                raise DependencySecurityError("Pipfile.lock paket kaydı bir nesne olmalıdır.")

            def skip(reason: str) -> None:
                skipped.append({"manifest": PIPFILE_LOCK_NAME, "section": section, "name": raw_name, "reason": reason})
                if len(skipped) > MAX_COMPONENTS:
                    raise DependencySecurityError("Bağımlılık sayısı güvenli sınırı aşıyor.")

            if any(key in entry for key in _PIPFILE_NON_REGISTRY_KEYS) or entry.get("editable") is True:
                skip("vcs_or_local_path")
                continue
            if "version" not in entry:
                skip("version_missing")
                continue
            raw_version = entry["version"]
            if not isinstance(raw_version, str):
                raise DependencySecurityError("Pipfile.lock paket version alanı bir string olmalıdır.")
            pin = raw_version.strip()
            if not pin:
                raise DependencySecurityError("Pipfile.lock paket version alanı boş olamaz.")
            if pin == "==" or (pin.startswith("==") and not pin[2:].strip()):
                skip("version_pin_empty")
                continue
            match = _PIPFILE_EXACT_PIN.fullmatch(pin)
            if not match:
                skip("version_not_pinned")
                continue
            version = _clean(match.group(1))
            normalized = _pep503_normalize(raw_name)
            purl = _package_url("PyPI", normalized, version)
            index = entry.get("index")
            if index is not None:
                if not isinstance(index, str) or not index:
                    raise DependencySecurityError("Pipfile.lock paket index alanı bir string olmalıdır.")
                if index not in sources:
                    raise DependencySecurityError("Pipfile.lock paketi _meta.sources içinde tanımsız bir index kaynağına başvuruyor.")
                repository_url = _pipfile_repository_url(sources[index])
                host = (urllib.parse.urlsplit(repository_url).hostname or "").casefold()
                if host not in _PIPFILE_DEFAULT_PYPI_HOSTS:
                    purl += "?repository_url=" + urllib.parse.quote(repository_url, safe="/:")
            key = (normalized, version, purl)
            if key in components:
                continue  # default bölümü önce işlenir; aynı kayıt develop'ta tekrar ederse zorunlu kalır.
            component = {
                "name": raw_name,
                "version": version,
                "ecosystem": "PyPI",
                "manifest": PIPFILE_LOCK_NAME,
                "purl": purl,
            }
            if section == "develop":
                component["scope"] = "optional"
            components[key] = component
            if len(components) > MAX_COMPONENTS:
                raise DependencySecurityError("Bağımlılık sayısı güvenli sınırı aşıyor.")
    return list(components.values()), skipped


def _pipfile_lock_components(root: Path) -> list[dict[str, str]]:
    return _pipfile_lock_inventory(root)[0]


_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+")  # eski paketlerde büyük harf olabilir (JSONStream)


def _npm_components(root: Path) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for filename in ("package-lock.json", "npm-shrinkwrap.json"):
        result.extend(_npm_lock_components(root, filename))
    return result


def _npm_lock_components(root: Path, filename: str) -> list[dict[str, str]]:
    """package-lock.json / npm-shrinkwrap.json: lockfileVersion 2–3 ``packages`` haritası, yoksa v1 ``dependencies``
    ağacı (18. tur). Yerel/git/URL kaynakları sürüm sayılmaz."""
    lockfile = root / filename
    if lockfile.is_symlink():
        raise DependencySecurityError(f"{filename} bir simge bağlantısı olamaz.")
    if not lockfile.is_file():
        return []
    if lockfile.stat().st_size > MAX_REPORT_BYTES:
        raise DependencySecurityError(f"{filename} boyut sınırını aşıyor.")
    try:
        content = lockfile.read_bytes()
        try:
            document = json.loads(content.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError("JSON dışı sabit: " + x)))
        except UnicodeDecodeError as exc:
            raise DependencySecurityError(f"{filename} geçerli UTF-8 değil.") from exc
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise DependencySecurityError(f"{filename} geçersiz JSON.") from exc
    except OSError as exc:
        raise DependencySecurityError(f"{filename} okunamadı.") from exc
    if not isinstance(document, dict):
        raise DependencySecurityError(f"{filename} kökü bir JSON nesnesi olmalıdır.")
    result: list[dict[str, str]] = []
    packages = document.get("packages")
    if packages is None or (isinstance(packages, dict) and not packages):
        legacy = document.get("dependencies")
        if isinstance(legacy, dict):
            return _npm_v1_components(legacy, filename)
        if packages is None:
            raise DependencySecurityError(f"{filename} packages alanı bir nesne olmalıdır.")
    if not isinstance(packages, dict):
        raise DependencySecurityError(f"{filename} packages alanı bir nesne olmalıdır.")
    for path, item in packages.items():
        if not isinstance(path, str):
            raise DependencySecurityError(f"{filename} packages keys bir string olmalıdır.")
        if not isinstance(item, dict):
            raise DependencySecurityError(f"{filename} packages değerleri nesneler olmalıdır.")
        raw_version = item.get("version")
        if raw_version is None:
            continue
        if not isinstance(raw_version, str):
            raise DependencySecurityError(f"{filename} package.version bir string olmalıdır.")
        if not raw_version.strip():
            raise DependencySecurityError(f"{filename} package.version boş olamaz.")
        if path == "" or item.get("link") is True:
            continue
        explicit_name = item.get("name")
        if explicit_name is not None:
            if not isinstance(explicit_name, str) or not explicit_name:
                raise DependencySecurityError(f"{filename} package.name geçersiz bir string olmalıdır.")
            safe_name = _clean(explicit_name)
            if safe_name in {".", ".."} or safe_name.startswith(("/", "..")) or ".." in safe_name:
                raise DependencySecurityError(f"{filename} package.name güvenli ASCII formu değil.")
            if not _NPM_NAME.fullmatch(safe_name):
                raise DependencySecurityError(f"{filename} package.name güvenli ASCII formu değil.")
        else:
            safe_name = None
        if "node_modules/" not in path:
            continue  # çalışma alanı (workspace) paketinin kendisi: kayıt defteri bileşeni değil
        fallback_name = path.rsplit("node_modules/", 1)[-1]
        if fallback_name in {".", ".."} or fallback_name.startswith(("/", "..")) or ".." in fallback_name:
            raise DependencySecurityError("fallback path güvenli ASCII formu değil.")
        if not _NPM_NAME.fullmatch(fallback_name):
            raise DependencySecurityError("fallback path güvenli ASCII formu değil.")
        name = safe_name or fallback_name
        version = _clean(raw_version)
        if version.startswith(("file:", "link:", "git", "http:", "https:")):
            continue
        component = {"name": name, "version": version, "ecosystem": "npm", "manifest": filename}
        if item.get("dev") is True:
            # npm'in kendi hesapladığı "yalnız geliştirme" işareti (üretim kurulumuna girmez); aynı paket başka bir
            # konumda zorunlu görünüyorsa discover_inventory kapsamı düşürür (Pipfile.lock develop ile aynı kural).
            component["scope"] = "optional"
        result.append(component)
    return result


def _npm_v1_components(tree: dict[str, Any], filename: str) -> list[dict[str, str]]:
    """lockfileVersion 1: iç içe ``dependencies`` ağacı (yinelemeli değil, açık yığınla; derinlik/sayı sınırlı)."""
    result: list[dict[str, str]] = []
    stack: list[tuple[dict[str, Any], int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > 64:
            continue
        for name, item in node.items():
            if not isinstance(name, str) or not isinstance(item, dict):
                continue
            version = item.get("version")
            if (isinstance(version, str) and version.strip() and _NPM_NAME.fullmatch(name) and ".." not in name
                    and not version.startswith(("file:", "link:", "git", "http:", "https:", "github:"))
                    and item.get("bundled") is not True):
                component = {"name": name, "version": _clean(version), "ecosystem": "npm", "manifest": filename}
                if item.get("dev") is True:
                    component["scope"] = "optional"
                result.append(component)
                if len(result) > MAX_COMPONENTS:
                    raise DependencySecurityError("Bağımlılık sayısı güvenli sınırı aşıyor.")
            children = item.get("dependencies")
            if isinstance(children, dict):
                stack.append((children, depth + 1))
    return result


def _read_manifest_text(root: Path, filename: str) -> str | None:
    manifest = root / filename
    if manifest.is_symlink():
        raise DependencySecurityError(f"{filename} bir simge bağlantısı olamaz.")
    if not manifest.is_file():
        return None
    try:
        size = manifest.stat().st_size
    except OSError as exc:
        raise DependencySecurityError(f"{filename} okunamadı.") from exc
    if size > MAX_REPORT_BYTES:
        raise DependencySecurityError(f"{filename} boyut sınırını aşıyor.")
    try:
        text = manifest.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DependencySecurityError(f"{filename} geçerli UTF-8 değil.") from exc
    except OSError as exc:
        raise DependencySecurityError(f"{filename} okunamadı.") from exc
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def _go_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "go.mod")
    if text is None:
        return []
    result: list[dict[str, str]] = []
    replaces = _go_replaces(text)
    in_require_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require") and line[7:].strip().startswith("("):
            in_require_block = True
            inner = line.split("(", 1)[1].strip()
            if inner.endswith(")"):
                in_require_block = False
                inner = inner[:-1].strip()
            if not inner:
                continue
            line = inner
        elif in_require_block and line.startswith(")"):
            in_require_block = False
            continue
        elif line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require_block:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        mod_path = _clean(parts[0])
        version = _clean(parts[1]).lstrip("v")
        if not mod_path or not version or ".." in mod_path or mod_path.startswith("/"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9._/~+-]+", mod_path):
            continue
        target = replaces.get((mod_path, version)) or replaces.get((mod_path, ""))
        if target is not None:
            if target == ("", ""):
                continue  # yerel dizine yönlendirilen modül: kayıt defteri bileşeni değil
            mod_path, version = target
        result.append({"name": mod_path, "version": version, "ecosystem": "Golang", "manifest": "go.mod"})
        if len(result) > MAX_COMPONENTS:
            break
    result.extend(_go_sum_components(root, {item["name"] for item in result}))
    return result


def _go_replaces(text: str) -> dict[tuple[str, str], tuple[str, str]]:
    """go.mod ``replace`` yönergeleri (18. tur): (modül, [sürüm]) → (yeni modül, sürüm); yerel yol → ("", "")."""
    out: dict[tuple[str, str], tuple[str, str]] = {}
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("replace") and line[7:].strip().startswith("("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue
        if line.startswith("replace "):
            line = line[len("replace "):].strip()
        elif not in_block:
            continue
        if "=>" not in line:
            continue
        left, right = (part.split() for part in line.split("=>", 1))
        if not left or not right:
            continue
        key = (left[0], left[1].lstrip("v") if len(left) > 1 else "")
        if right[0].startswith((".", "/")):
            out[key] = ("", "")
        elif len(right) > 1 and re.fullmatch(r"[A-Za-z0-9._/~+-]+", right[0]) and ".." not in right[0]:
            out[key] = (right[0], right[1].lstrip("v"))
        if len(out) > 1000:
            break
    return out


def _go_sum_components(root: Path, declared: set[str]) -> list[dict[str, str]]:
    """go.sum (18. tur): go.mod'da olmayan geçişli modüller (Go < 1.17 modülleri bunları go.mod'a yazmaz).
    Yalnız içerik özeti olan satırlar (``/go.mod`` olmayan) ve modül başına en yüksek sürüm (MVS yaklaşımı)."""
    text = _read_manifest_text(root, "go.sum")
    if text is None:
        return []
    from osv_offline import compare_semver

    best: dict[str, str] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) != 3 or parts[1].endswith("/go.mod") or not parts[2].startswith("h1:"):
            continue
        mod_path, version = parts[0], parts[1].lstrip("v").replace("+incompatible", "")
        if mod_path in declared or not re.fullmatch(r"[A-Za-z0-9._/~+-]+", mod_path) or ".." in mod_path:
            continue
        if not re.match(r"\d", version):
            continue
        current = best.get(mod_path)
        if current is None or compare_semver(version, current) > 0:
            best[mod_path] = version
    return [{"name": name, "version": best[name], "ecosystem": "Golang", "manifest": "go.sum"}
            for name in sorted(best)][:MAX_COMPONENTS]


def _cargo_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "Cargo.lock")
    if text is None:
        return []
    try:
        document = tomllib.loads(text)
    except (OSError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise DependencySecurityError("Cargo.lock geçerli TOML değil.") from exc
    if not isinstance(document, dict):
        raise DependencySecurityError("Cargo.lock kökü bir TOML nesnesi olmalıdır.")
    packages = document.get("package", [])
    if not isinstance(packages, list):
        raise DependencySecurityError("Cargo.lock package alanı bir dizi olmalıdır.")
    result: list[dict[str, str]] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        raw_name = item.get("name")
        raw_version = item.get("version")
        if not isinstance(raw_name, str) or not isinstance(raw_version, str):
            continue
        name = _clean(raw_name)
        version = _clean(raw_version)
        if not name or not version or ".." in name or "/" in name or "\\" in name:
            continue
        result.append({"name": name, "version": version, "ecosystem": "cargo", "manifest": "Cargo.lock"})
        if len(result) > MAX_COMPONENTS:
            break
    return result


def _pnpm_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "pnpm-lock.yaml")
    if text is None:
        return []
    result: list[dict[str, str]] = []
    in_packages = False
    for raw_line in text.splitlines():
        comment_stripped = raw_line.split(" #", 1)[0].rstrip()
        if not comment_stripped.strip() or comment_stripped.lstrip().startswith("#"):
            continue
        indent = len(comment_stripped) - len(comment_stripped.lstrip(" "))
        stripped = comment_stripped.strip()
        if indent == 0:
            in_packages = stripped == "packages:"
            continue
        if not in_packages or indent not in (2, 4) or not stripped.endswith(":"):
            continue
        key = stripped[:-1].strip().strip("'\"")
        if key.startswith("/"):
            key = key[1:]
        key = key.split("(", 1)[0].strip()
        if not key:
            continue
        at_index = key.rfind("@")
        if at_index > 0:
            name = _clean(key[:at_index])
            version = _clean(key[at_index + 1:])
        else:
            slash_index = key.rfind("/")
            if slash_index <= 0:
                continue
            name = _clean(key[:slash_index])
            version = _clean(key[slash_index + 1:])
        if not name or not version or ".." in name or name.startswith("/"):
            continue
        if not re.fullmatch(r"(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+", name):
            continue
        result.append({"name": name, "version": version, "ecosystem": "npm", "manifest": "pnpm-lock.yaml"})
        if len(result) > MAX_COMPONENTS:
            break
    return result


def _yarn_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "yarn.lock")
    if text is None:
        return []
    result: list[dict[str, str]] = []
    current_name: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if indent == 0 and stripped.endswith(":"):
            header = stripped[:-1].split(",", 1)[0].strip().strip("'\"")
            if header == "__metadata":
                current_name = None
                continue
            at_idx = header.find("@", 1) if header.startswith("@") else header.find("@")
            candidate = _clean(header[:at_idx]) if at_idx > 0 else ""
            if candidate and ".." not in candidate and re.fullmatch(r"(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+", candidate):
                current_name = candidate
            else:
                current_name = None
        elif indent > 0 and current_name:
            match = re.match(r'^version(?::)?\s+"?([^"\s]+)"?$', stripped)
            if match:
                version = _clean(match.group(1))
                if version:
                    result.append({"name": current_name, "version": version, "ecosystem": "npm", "manifest": "yarn.lock"})
                current_name = None
                if len(result) > MAX_COMPONENTS:
                    break
    return result


def _maven_parse(directory: Path, filename: str = "pom.xml"):
    import xml.etree.ElementTree as ET

    text = _read_manifest_text(directory, filename)
    if text is None:
        return None
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise DependencySecurityError(f"{filename} güvenli olmayan XML DTD/ENTITY içeriyor.")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise DependencySecurityError(f"{filename} geçerli XML değil.") from exc


def _mtag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _mchild(elem: Any, name: str) -> Any:
    return next((c for c in elem if _mtag(c.tag) == name), None) if elem is not None else None


def _mtext(elem: Any, name: str) -> str:
    child = _mchild(elem, name)
    return (child.text or "").strip() if child is not None and child.text else ""


_MAVEN_PROP = re.compile(r"\$\{([^}]{1,200})\}")


def _maven_resolve(value: str, props: dict[str, str]) -> str:
    if len(value) > MAX_MAVEN_RESOLVED_CHARS:
        return "${sniper.unresolved}"
    seen: set[str] = set()
    for _ in range(6):  # iç içe özellikler (${a} → ${b} → 1.2); döngüye karşı sınırlı
        if "${" not in value:
            break
        if value in seen:
            break
        seen.add(value)
        resolved = _MAVEN_PROP.sub(lambda m: props.get(m.group(1).strip(), m.group(0)), value)
        if len(resolved) > MAX_MAVEN_RESOLVED_CHARS:
            return "${sniper.unresolved}"
        value = resolved
    return value


def _maven_effective_gav(xml_root: Any, props: dict[str, str]) -> tuple[str, str, str]:
    """Return the effective model coordinates after local/inherited property interpolation."""
    if xml_root is None:
        return "", "", ""
    group = props.get("project.groupId", "") or _mtext(xml_root, "groupId")
    artifact = props.get("project.artifactId", "") or _mtext(xml_root, "artifactId")
    version = props.get("project.version", "") or _mtext(xml_root, "version")
    return tuple(_maven_resolve(value, props) for value in (group, artifact, version))


def _maven_repository() -> Path | None:
    """Yalnız açıkça yapılandırılan çevrimdışı Maven deposunu kabul et.

    Kullanıcının ``~/.m2`` dizini kendiliğinden okunmaz. Depo ve POM yolu sembolik bağ olamaz; bu, proje taramasının
    yapılandırılmış depo dışına taşmasını engeller.
    """
    raw = os.environ.get("SNIPER_MAVEN_REPOSITORY", "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            return None
        return candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _maven_repo_pom(group: str, artifact: str, version: str) -> tuple[Path, str] | None:
    repo = _maven_repository()
    group, artifact, version = (_clean(x, 300) for x in (group, artifact, version))
    token = re.compile(r"[A-Za-z0-9_.+-]+")
    if repo is None or not token.fullmatch(group) or not token.fullmatch(artifact) or not token.fullmatch(version) \
            or any(".." in x for x in (group, artifact, version)):
        return None
    relative = Path(*group.split(".")) / artifact / version / f"{artifact}-{version}.pom"
    candidate = repo / relative
    try:
        current = repo
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return None
        if not candidate.is_file() or candidate.stat().st_size > 1_000_000:
            return None
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(repo):
            return None
        return resolved.parent, resolved.name
    except (OSError, RuntimeError, ValueError):
        return None


def _maven_model(directory: Path, project_root: Path, depth: int = 0, *, filename: str = "pom.xml",
                 visited: set[Path] | None = None,
                 model_budget: list[int] | None = None) -> tuple[Any, dict[str, str], dict[str, str]]:
    """POM modeli: özellikler ve yönetilen sürümler.

    Proje içi ``relativePath`` üst POM'ları ile, yalnız ``SNIPER_MAVEN_REPOSITORY`` altında bulunan üst POM ve
    import edilmiş BOM dosyaları en çok beş düzey okunur. Ağ ve örtük kullanıcı depoları kullanılmaz.
    """
    # [okunan model, kısmi model]; ikinci hücre eski tek-hücreli özel çağrılarla uyumluluk için isteğe bağlıdır.
    model_budget = [0, 0] if model_budget is None else model_budget
    try:
        model_path = (directory / filename).resolve(strict=True)
    except (OSError, RuntimeError):
        return None, {}, {}
    visited = set() if visited is None else set(visited)
    if model_path in visited:
        return None, {}, {}
    if depth > 5:
        if len(model_budget) < 2:
            model_budget.append(1)
        else:
            model_budget[1] = 1
        return None, {}, {}
    if model_budget[0] >= MAX_MAVEN_MODELS:
        if len(model_budget) < 2:
            model_budget.append(1)
        else:
            model_budget[1] = 1
        return None, {}, {}
    model_budget[0] += 1
    visited.add(model_path)
    xml_root = _maven_parse(directory, filename)
    if xml_root is None:
        return None, {}, {}
    props: dict[str, str] = {}
    managed: dict[str, str] = {}
    parent = _mchild(xml_root, "parent")
    if parent is not None and depth >= 5:
        if len(model_budget) < 2:
            model_budget.append(1)
        else:
            model_budget[1] = 1
    if parent is not None and depth < 5:
        relative_node = _mchild(parent, "relativePath")
        rel = _mtext(parent, "relativePath") if relative_node is not None else "../pom.xml"
        parent_models: list[tuple[Path, str]] = []
        candidate = directory / rel if rel else None
        try:
            if candidate is not None and candidate.is_dir():
                candidate /= "pom.xml"
            lexical_file = Path(os.path.abspath(candidate)) if candidate is not None else None
            project_resolved = project_root.resolve(strict=True)
            lexical_inside = bool(lexical_file is not None and lexical_file.is_relative_to(project_resolved))
            if lexical_inside and lexical_file is not None:
                current = project_resolved
                for part in lexical_file.relative_to(project_resolved).parts:
                    current /= part
                    if current.is_symlink():
                        lexical_inside = False
                        break
            resolved_file = candidate.resolve(strict=True) if candidate is not None else None
            inside = bool(lexical_inside and resolved_file is not None and resolved_file.is_relative_to(project_resolved)
                          and resolved_file != model_path and resolved_file.is_file())
        except (AttributeError, OSError, RuntimeError, ValueError):
            inside = False
        if inside and resolved_file is not None:
            parent_models.append((resolved_file.parent, resolved_file.name))
        repository_parent = _maven_repo_pom(_mtext(parent, "groupId"), _mtext(parent, "artifactId"),
                                            _mtext(parent, "version"))
        if repository_parent is not None and repository_parent not in parent_models:
            parent_models.append(repository_parent)
        expected_parent = (_mtext(parent, "groupId"), _mtext(parent, "artifactId"), _mtext(parent, "version"))
        for parent_model in parent_models:
            try:
                _proot, pprops, pmanaged = _maven_model(parent_model[0], project_root, depth + 1,
                                                        filename=parent_model[1], visited=visited,
                                                        model_budget=model_budget)
            except DependencySecurityError:
                continue
            effective_parent = _maven_effective_gav(_proot, pprops)
            if effective_parent != expected_parent:
                continue
            props.update(pprops)
            managed.update(pmanaged)
            break
        pversion = _mtext(parent, "version")
        if pversion:
            props.update({"project.parent.version": pversion, "parent.version": pversion})
        if _mtext(parent, "groupId"):
            props.update({"project.parent.groupId": _mtext(parent, "groupId"),
                          "parent.groupId": _mtext(parent, "groupId")})
        if _mtext(parent, "artifactId"):
            props.update({"project.parent.artifactId": _mtext(parent, "artifactId"),
                          "parent.artifactId": _mtext(parent, "artifactId")})
    own_version = _mtext(xml_root, "version") or props.get("project.parent.version", "")
    own_group = _mtext(xml_root, "groupId") or props.get("project.parent.groupId", "")
    own_artifact = _mtext(xml_root, "artifactId")
    # Raw aliases are visible while local properties are read. Effective aliases are written below once the
    # model's own properties have been loaded (for example version=${revision}).
    if own_version:
        props.update({"project.version": own_version, "pom.version": own_version, "version": own_version})
    if own_group:
        props.update({"project.groupId": own_group, "pom.groupId": own_group})
    if own_artifact:
        props.update({"project.artifactId": own_artifact, "pom.artifactId": own_artifact})
    for elem in xml_root:
        if _mtag(elem.tag) == "properties":
            for child in elem:
                if child.text and child.text.strip():
                    props[_mtag(child.tag)] = child.text.strip()
    effective_group = _maven_resolve(own_group, props)
    effective_artifact = _maven_resolve(own_artifact, props)
    effective_version = _maven_resolve(own_version, props)
    if effective_group:
        props.update({"project.groupId": effective_group, "pom.groupId": effective_group})
    if effective_artifact:
        props.update({"project.artifactId": effective_artifact, "pom.artifactId": effective_artifact})
    if effective_version:
        props.update({"project.version": effective_version, "pom.version": effective_version,
                      "version": effective_version})
    management = _mchild(xml_root, "dependencyManagement")
    deps = _mchild(management, "dependencies")
    imported_managed: dict[str, str] = {}
    local_managed: dict[str, str] = {}
    for dep in (deps if deps is not None else []):
        if _mtag(dep.tag) != "dependency":
            continue
        ga = f"{_maven_resolve(_mtext(dep, 'groupId'), props)}:{_maven_resolve(_mtext(dep, 'artifactId'), props)}"
        raw_version = _mtext(dep, "version")
        version = _maven_resolve(raw_version, props)
        dep_type = _maven_resolve(_mtext(dep, "type"), props)
        dep_scope = _maven_resolve(_mtext(dep, "scope"), props)
        if dep_type == "pom" and dep_scope == "import" and version and "${" not in version:
            if depth >= 5:
                if len(model_budget) < 2:
                    model_budget.append(1)
                else:
                    model_budget[1] = 1
                continue
            bom = _maven_repo_pom(_maven_resolve(_mtext(dep, "groupId"), props),
                                  _maven_resolve(_mtext(dep, "artifactId"), props), version)
            if bom is not None:
                try:
                    _broot, bprops, bmanaged = _maven_model(bom[0], project_root, depth + 1,
                                                            filename=bom[1], visited=visited,
                                                            model_budget=model_budget)
                    expected_bom = (_maven_resolve(_mtext(dep, "groupId"), props),
                                    _maven_resolve(_mtext(dep, "artifactId"), props), version)
                    effective_bom = _maven_effective_gav(_broot, bprops)
                    if effective_bom != expected_bom:
                        continue
                    # Birden çok BOM aynı GAV'ı yönetirse Maven ilk importu seçer. Çocuk POM'daki doğrudan
                    # dependencyManagement kayıtları ise bildirim sırasından bağımsız olarak BOM'ların önündedir.
                    # BOM özellikleri içe aktaran projenin özellik tablosuna taşınmaz. Her yönetilen sürüm kendi
                    # BOM etkin modeli içinde somutlaştırılır; aynı isimli iki BOM özelliği birbirine sızamaz.
                    for key, value in bmanaged.items():
                        frozen = _maven_resolve(value, bprops)
                        imported_managed.setdefault(
                            key, frozen if "${" not in frozen else "${sniper.unresolved}"
                        )
                except DependencySecurityError:
                    pass
            continue
        if raw_version:
            # Üst POM'daki özellik şablonunu erken somutlaştırma. Maven etkin modeli çocuk özellikleri üst
            # özelliklerinin üzerine kurduktan sonra interpolasyon yapar; ``${lib.version}`` bu nedenle çocukta
            # geçerli biçimde ezilebilir. BOM içe aktarma sınırında ise değer kendi etkin modelinde dondurulur.
            local_managed[ga] = raw_version
    managed.update(imported_managed)
    managed.update(local_managed)
    return xml_root, props, managed


def _maven_components(root: Path, project_root: Path | None = None,
                      warnings: list[str] | None = None) -> list[dict[str, str]]:
    budget = [0, 0]
    xml_root, props, managed = _maven_model(root, project_root or root, model_budget=budget)
    if budget[1] and warnings is not None:
        warning = (f"Maven etkin model bütçesi ({MAX_MAVEN_MODELS}) veya derinlik sınırı aşıldı; "
                   "bağımlılık envanteri kısmi.")
        if warning not in warnings:
            warnings.append(warning)
    if xml_root is None:
        return []
    result: list[dict[str, str]] = []
    # dependencyManagement sürüm seçer; kendi başına kurulu bir bağımlılık bildirmez. Yalnız proje düzeyindeki
    # doğrudan dependencies kayıtları envantere girer. Böylece BOM ve salt yönetilen paketler SBOM/OSV'de yanlış
    # pozitif bileşene dönüşmez.
    dependencies = _mchild(xml_root, "dependencies")
    for elem in (dependencies if dependencies is not None else []):
        if _mtag(elem.tag) != "dependency":
            continue
        group_id = _clean(_maven_resolve(_mtext(elem, "groupId"), props))
        artifact_id = _clean(_maven_resolve(_mtext(elem, "artifactId"), props))
        if not group_id or not artifact_id:
            continue
        if ".." in group_id or ".." in artifact_id or "/" in group_id or "/" in artifact_id:
            continue
        raw_version = _mtext(elem, "version") or managed.get(f"{group_id}:{artifact_id}", "")
        version = _maven_resolve(raw_version, props)
        version = _clean(version)
        if "${" in version or version.startswith(("[", "(")):
            version = ""  # çözülemeyen özellik ya da sürüm aralığı: somut sürüm değil
        component = {"name": f"{group_id}:{artifact_id}", "version": version, "ecosystem": "Maven", "manifest": "pom.xml"}
        if _mtext(elem, "scope") == "test":
            component["scope"] = "optional"
        result.append(component)
        if len(result) > MAX_COMPONENTS:
            break
    return result


def _ruby_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "Gemfile.lock")
    if text is None:
        return []
    result: list[dict[str, str]] = []
    in_gem = False
    in_specs = False
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if indent == 0:
            in_gem = stripped == "GEM"
            in_specs = False
            continue
        if in_gem and indent == 2:
            in_specs = stripped == "specs:"
            continue
        if in_gem and in_specs and indent == 4:
            match = re.match(r"^([A-Za-z0-9_.-]+)\s+\(([0-9][A-Za-z0-9_.-]*)\)$", stripped)
            if match:
                name = _clean(match.group(1))
                version = _clean(match.group(2))
                if name and version and ".." not in name:
                    result.append({"name": name, "version": version, "ecosystem": "RubyGems", "manifest": "Gemfile.lock"})
                    if len(result) > MAX_COMPONENTS:
                        break
    return result


def _composer_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "composer.lock")
    if text is None:
        return []
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise DependencySecurityError("composer.lock geçersiz JSON.") from exc
    if not isinstance(document, dict):
        raise DependencySecurityError("composer.lock kökü bir JSON nesnesi olmalıdır.")
    result: list[dict[str, str]] = []
    for section in ("packages", "packages-dev"):
        items = document.get(section, [])
        if items is None:
            continue
        if not isinstance(items, list):
            raise DependencySecurityError(f"composer.lock {section} alanı bir dizi olmalıdır.")
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_name = item.get("name")
            raw_version = item.get("version")
            if not isinstance(raw_name, str) or not isinstance(raw_version, str):
                continue
            name = _clean(raw_name)
            version = _clean(raw_version).lstrip("v")
            if not name or not version or ".." in name or name.startswith("/"):
                continue
            result.append({"name": name, "version": version, "ecosystem": "Packagist", "manifest": "composer.lock"})
            if len(result) > MAX_COMPONENTS:
                break
    return result


def _pubspec_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "pubspec.lock")
    if text is None:
        return []
    result: list[dict[str, str]] = []
    in_packages = False
    current_pkg: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if indent == 0:
            in_packages = stripped == "packages:"
            current_pkg = None
            continue
        if not in_packages:
            continue
        if indent == 2 and stripped.endswith(":"):
            candidate = _clean(stripped[:-1].strip().strip("'\""))
            if candidate and ".." not in candidate and re.fullmatch(r"[A-Za-z0-9_.-]+", candidate):
                current_pkg = candidate
            else:
                current_pkg = None
        elif indent >= 4 and current_pkg:
            match = re.match(r'^version:\s*"?([^"\s]+)"?$', stripped)
            if match:
                version = _clean(match.group(1))
                if version:
                    result.append({"name": current_pkg, "version": version, "ecosystem": "Pub", "manifest": "pubspec.lock"})
                current_pkg = None
                if len(result) > MAX_COMPONENTS:
                    break
    return result


def _gradle_components(root: Path) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    lock_text = _read_manifest_text(root, "gradle.lockfile")
    if lock_text is not None:
        for raw_line in lock_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coord = line.split("=", 1)[0].strip()
            parts = coord.split(":")
            if len(parts) >= 3:
                group_id = _clean(parts[0])
                artifact_id = _clean(parts[1])
                version = _clean(parts[2])
                if (
                    group_id
                    and artifact_id
                    and version
                    and ".." not in group_id
                    and ".." not in artifact_id
                    and "/" not in group_id
                    and "/" not in artifact_id
                ):
                    result.append({
                        "name": f"{group_id}:{artifact_id}",
                        "version": version,
                        "ecosystem": "Maven",
                        "manifest": "gradle.lockfile",
                    })
                    if len(result) > MAX_COMPONENTS:
                        return result

    variables = _gradle_variables(root)
    seen: set[tuple[str, str]] = set()
    for gradle_file in ("build.gradle", "build.gradle.kts"):
        g_text = _read_manifest_text(root, gradle_file)
        if g_text is None:
            continue
        code = _GRADLE_COMMENT.sub("", g_text)
        coords = [(m.group(1), m.group(2), m.group(3)) for m in _GRADLE_COORD.finditer(code)]
        coords += [(m.group(1), m.group(2), m.group(3)) for m in _GRADLE_MAP.finditer(code)]
        for group_id, artifact_id, raw_version in coords:
            version = _gradle_resolve(raw_version, variables)
            if not re.match(r"\d", version) or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", version) or version.endswith("+"):
                continue  # aralık (1.+), çözülemeyen değişken ya da dinamik sürüm: somut değil
            ga = f"{_clean(group_id)}:{_clean(artifact_id)}"
            if ".." in ga or "/" in ga or (ga, version) in seen:
                continue
            seen.add((ga, version))
            result.append({"name": ga, "version": version, "ecosystem": "Maven", "manifest": gradle_file})
            if len(result) > MAX_COMPONENTS:
                return result
    result.extend(_gradle_catalog_components(root))
    return result


# 18. tur: Gradle bağımlılıkları yapılandırma adından bağımsız bulunur — 'g:a:v' koordinat dizgeleri (çok satırlı
# "compile \\ 'a:b:1', 'c:d:2'" listeleri dahil) ve group:/name:/version: harita gösterimi; $değişkenler çözülür.
_GRADLE_COMMENT = re.compile(r"/\*.*?\*/|(?<![:\"'])//[^\n]*", re.S)
_GRADLE_COORD = re.compile(r"""['"]([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([^'"\s:@]{1,120})(?::[A-Za-z0-9_.\-]+)?(?:@[A-Za-z0-9]+)?['"]""")
_GRADLE_MAP = re.compile(r"""group\s*[:=]\s*['"]([A-Za-z0-9_.\-]+)['"]\s*,\s*name\s*[:=]\s*['"]([A-Za-z0-9_.\-]+)['"]\s*,\s*version\s*[:=]\s*['"]([^'"]{1,120})['"]""")
_GRADLE_VAR = re.compile(r"""(?:\b(?:def|val|var|ext\.)\s*)?\b([A-Za-z_][A-Za-z0-9_.]{0,80})\s*=\s*['"]([0-9][A-Za-z0-9_.+-]{0,80})['"]""")
_GRADLE_EXTRA = re.compile(r"""(?:extra\[|set\()\s*['"]([A-Za-z_][A-Za-z0-9_.]{0,80})['"]\s*[\],]\s*=?\s*['"]([0-9][A-Za-z0-9_.+-]{0,80})['"]""")


def _gradle_variables(root: Path) -> dict[str, str]:
    """Sürüm değişkenleri: build.gradle(.kts) / settings içindeki def/val/ext atamaları ve gradle.properties."""
    out: dict[str, str] = {}
    props = _read_manifest_text(root, "gradle.properties")
    for line in (props or "").splitlines():
        if "=" in line and not line.lstrip().startswith(("#", "!")):
            key, value = (part.strip() for part in line.split("=", 1))
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,80}", key) and re.fullmatch(r"[0-9][A-Za-z0-9_.+-]{0,80}", value):
                out[key] = value
    for filename in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        text = _read_manifest_text(root, filename)
        for m in _GRADLE_VAR.finditer(text or ""):
            out.setdefault(m.group(1).rsplit(".", 1)[-1], m.group(2))
            out.setdefault(m.group(1), m.group(2))
        for m in _GRADLE_EXTRA.finditer(text or ""):
            out.setdefault(m.group(1), m.group(2))
    return out


def _gradle_resolve(value: str, variables: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        key = m.group(1) or m.group(2)
        return variables.get(key, variables.get(key.rsplit(".", 1)[-1], m.group(0)))
    return re.sub(r"\$\{([A-Za-z0-9_.]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, value)


def _gradle_catalog_components(root: Path) -> list[dict[str, str]]:
    """Gradle sürüm kataloğu gradle/libs.versions.toml: [libraries] girdileri (module / group+name; version ya da
    version.ref). Yalnız somut sürümler."""
    catalog_dir = root / "gradle"
    if catalog_dir.is_symlink() or not catalog_dir.is_dir():
        return []
    text = _read_manifest_text(catalog_dir, "libs.versions.toml")
    if text is None:
        return []
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise DependencySecurityError("gradle/libs.versions.toml geçerli TOML değil.") from exc
    versions = document.get("versions") if isinstance(document.get("versions"), dict) else {}
    libraries = document.get("libraries") if isinstance(document.get("libraries"), dict) else {}

    def version_of(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            if isinstance(value.get("ref"), str):
                return version_of(versions.get(value["ref"]))
            for key in ("strictly", "require", "prefer"):
                if isinstance(value.get(key), str):
                    return value[key]
        return ""

    result: list[dict[str, str]] = []
    for entry in libraries.values():
        group = name = version = ""
        if isinstance(entry, str) and entry.count(":") >= 2:
            group, name, version = entry.split(":")[:3]
        elif isinstance(entry, dict):
            module = entry.get("module")
            if isinstance(module, str) and ":" in module:
                group, name = module.split(":", 1)
            else:
                group, name = str(entry.get("group") or ""), str(entry.get("name") or "")
            version = version_of(entry.get("version"))
        if not (group and name and re.match(r"\d", version or "")) or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", version) \
                or version.endswith("+"):
            continue
        ga = f"{_clean(group)}:{_clean(name)}"
        if ".." in ga or "/" in ga:
            continue
        result.append({"name": ga, "version": version, "ecosystem": "Maven", "manifest": "gradle/libs.versions.toml"})
        if len(result) > MAX_COMPONENTS:
            break
    return result


def _uv_lock_components(root: Path) -> list[dict[str, str]]:
    """uv.lock (TOML): yalnız kayıt defterinden gelen paketler (yerel/git/editable kaynaklar atlanır)."""
    text = _read_manifest_text(root, "uv.lock")
    if text is None:
        return []
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise DependencySecurityError("uv.lock geçerli TOML değil.") from exc
    packages = document.get("package", []) if isinstance(document, dict) else []
    if not isinstance(packages, list):
        raise DependencySecurityError("uv.lock package alanı bir dizi olmalıdır.")
    result: list[dict[str, str]] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        if not isinstance(source, dict) or "registry" not in source:
            continue
        name, version = item.get("name"), item.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not _PYPA_DIST_NAME.fullmatch(name):
            continue
        result.append({"name": _clean(name), "version": _clean(version), "ecosystem": "PyPI", "manifest": "uv.lock"})
        if len(result) > MAX_COMPONENTS:
            break
    return result


_NUGET_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}")
_NUGET_VERSION = re.compile(r"\[?\s*(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?)\s*\]?")


def _safe_xml(text: str, filename: str):
    import xml.etree.ElementTree as ET
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise DependencySecurityError(f"{filename} güvenli olmayan XML DTD/ENTITY içeriyor.")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise DependencySecurityError(f"{filename} geçerli XML değil.") from exc


def _nuget_components(root: Path) -> list[dict[str, str]]:
    """NuGet (18. tur): packages.lock.json, kökteki *.csproj/*.fsproj/*.vbproj PackageReference,
    Directory.Packages.props (merkezi sürüm) ve packages.config. Yalnız tek, somut sürümler."""
    result: list[dict[str, str]] = []

    def add(name: Any, version: Any, manifest: str) -> None:
        if not isinstance(name, str) or not isinstance(version, str) or not _NUGET_NAME.fullmatch(name.strip()):
            return
        match = _NUGET_VERSION.fullmatch(version.strip())
        if not match:
            return
        result.append({"name": name.strip(), "version": match.group(1), "ecosystem": "NuGet", "manifest": manifest})

    lock_text = _read_manifest_text(root, "packages.lock.json")
    if lock_text is not None:
        try:
            document = json.loads(lock_text)
        except (ValueError, RecursionError) as exc:
            raise DependencySecurityError("packages.lock.json geçerli JSON değil.") from exc
        frameworks = document.get("dependencies") if isinstance(document, dict) else None
        if isinstance(frameworks, dict):
            for packages in frameworks.values():
                if not isinstance(packages, dict):
                    continue
                for name, entry in packages.items():
                    if isinstance(entry, dict) and entry.get("type") != "Project":
                        add(name, entry.get("resolved"), "packages.lock.json")
    central: dict[str, str] = {}
    props = _read_manifest_text(root, "Directory.Packages.props")
    if props is not None:
        for element in _safe_xml(props, "Directory.Packages.props").iter():
            if element.tag.rsplit("}", 1)[-1] == "PackageVersion":
                name, version = element.get("Include"), element.get("Version")
                if isinstance(name, str) and isinstance(version, str):
                    central[name.strip().casefold()] = version
    try:
        project_files = sorted(p.name for p in root.iterdir()
                               if p.suffix in (".csproj", ".fsproj", ".vbproj") and p.is_file() and not p.is_symlink())
    except OSError:
        project_files = []
    for filename in project_files[:20]:
        text = _read_manifest_text(root, filename)
        if text is None:
            continue
        for element in _safe_xml(text, filename).iter():
            if element.tag.rsplit("}", 1)[-1] != "PackageReference":
                continue
            name = element.get("Include") or element.get("Update")
            version = element.get("Version")
            if version is None:
                child = next((c for c in element if c.tag.rsplit("}", 1)[-1] == "Version"), None)
                version = (child.text or "").strip() if child is not None else None
            if version is None and isinstance(name, str):
                version = central.get(name.strip().casefold())
            add(name, version, filename)
    config = _read_manifest_text(root, "packages.config")
    if config is not None:
        for element in _safe_xml(config, "packages.config").iter():
            if element.tag.rsplit("}", 1)[-1] == "package":
                add(element.get("id"), element.get("version"), "packages.config")
    return result[: MAX_COMPONENTS + 1]


def _cocoapods_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "Podfile.lock")
    if text is None:
        return []
    result: list[dict[str, str]] = []
    in_pods = False
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if indent == 0:
            in_pods = stripped == "PODS:"
            continue
        if not in_pods or indent != 2 or not stripped.startswith("- "):
            continue
        entry = stripped[2:].rstrip(":").strip().strip("'\"")
        match = re.match(r"^([A-Za-z0-9_./+-]+)\s+\(([0-9][A-Za-z0-9_.-]*)\)$", entry)
        if match:
            name = _clean(match.group(1))
            version = _clean(match.group(2))
            if name and version and ".." not in name and not name.startswith("/"):
                result.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "CocoaPods",
                    "manifest": "Podfile.lock",
                })
                if len(result) > MAX_COMPONENTS:
                    break
    return result


def _swiftpm_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "Package.resolved")
    if text is None:
        return []
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise DependencySecurityError("Package.resolved geçersiz JSON.") from exc
    if not isinstance(document, dict):
        raise DependencySecurityError("Package.resolved kökü bir JSON nesnesi olmalıdır.")
    pins = document.get("pins")
    if pins is None and isinstance(document.get("object"), dict):
        pins = document["object"].get("pins")
    if pins is None:
        return []
    if not isinstance(pins, list):
        raise DependencySecurityError("Package.resolved pins alanı bir dizi olmalıdır.")
    result: list[dict[str, str]] = []
    for item in pins:
        if not isinstance(item, dict):
            continue
        raw_name = item.get("package") or item.get("identity")
        if not isinstance(raw_name, str) or not raw_name.strip():
            loc = item.get("location") or item.get("repositoryURL")
            if isinstance(loc, str) and loc.strip():
                tail = loc.strip().rstrip("/").rsplit("/", 1)[-1]
                if tail.endswith(".git"):
                    tail = tail[:-4]
                raw_name = tail
        if not isinstance(raw_name, str) or not raw_name.strip():
            continue
        state = item.get("state")
        raw_version = ""
        if isinstance(state, dict):
            ver_candidate = state.get("version") or state.get("branch") or state.get("revision") or ""
            if isinstance(ver_candidate, str):
                raw_version = ver_candidate.strip().lstrip("v")
        name = _clean(raw_name)
        version = _clean(raw_version)
        if not name or not version or ".." in name or "/" in name or "\\" in name:
            continue
        result.append({
            "name": name,
            "version": version,
            "ecosystem": "SwiftURL",
            "manifest": "Package.resolved",
        })
        if len(result) > MAX_COMPONENTS:
            break
    return result


# ---------------------------------------------------------------------------
# 18. tur: gerçek dünya manifest çeşitliliği (ek Python/npm kaynakları, alt dizinler, hoşgörülü mod)
# ---------------------------------------------------------------------------
_REQ_FILE = re.compile(
    r"(?i)^(?:requirements|reqs?)(?:[-_.][A-Za-z0-9_.-]*)?\.(?:txt|lock)$"
    r"|^[A-Za-z0-9_.-]*[-_]requirements\.(?:txt|lock)$"
)
_EXACT_PY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9_.+!-]*)$")
MAX_REQUIREMENT_FILES = 50


def _requirements_scope(path: Path) -> str | None:
    tokens = {part for part in re.split(r"[-_.]+", path.stem.casefold()) if part}
    return "optional" if tokens & {"dev", "development", "test", "tests"} else None


def _requirement_lines(text: str) -> list[str]:
    """Satır devamlarını (sonda \\) birleştirir; yorumları atar."""
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        lines.append(buffer + stripped)
        buffer = ""
    if buffer:
        lines.append(buffer)
    return lines


def _requirements_extra_components(root: Path, project_root: Path | None = None) -> list[dict[str, str]]:
    """requirements*.txt|lock / *-requirements.txt|lock ve ``-r``/``-c`` içermeleri (proje kökü dışına
    çıkmadan, en çok 50 dosya). Kök requirements.txt'nin satırları ayrıca _python_components'ta okunur; tekrar
    discover_inventory'de tekilleşir."""
    project_root = (project_root or root).resolve()
    queue: list[Path] = []
    try:
        queue += sorted(p for p in root.iterdir() if p.is_file() and not p.is_symlink() and _REQ_FILE.match(p.name))
        sub = root / "requirements"
        if sub.is_dir() and not sub.is_symlink():
            queue += sorted(
                p for p in sub.iterdir()
                if p.is_file() and not p.is_symlink() and p.suffix.casefold() in {".txt", ".lock"}
            )
    except OSError:
        return []
    seen: set[Path] = set()
    result: list[dict[str, str]] = []
    while queue and len(seen) < MAX_REQUIREMENT_FILES:
        path = queue.pop(0)
        try:
            real = path.resolve()
        except (OSError, RuntimeError):
            continue
        if real in seen or not real.is_relative_to(project_root) or path.is_symlink():
            continue
        seen.add(real)
        text = _read_manifest_text(path.parent, path.name)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
        for line in _requirement_lines(text):
            stripped = line.strip()
            include = re.match(r"^(?:-r|--requirement|-c|--constraint)[\s=]+(\S+)", stripped)
            if include:
                queue.append(path.parent / include.group(1))
                continue
            parsed = _split_requirement(stripped)
            if parsed and parsed[1]:
                item = {"name": parsed[0], "version": parsed[1], "ecosystem": "PyPI", "manifest": rel}
                scope = _requirements_scope(path)
                if scope is not None:
                    item["scope"] = scope
                result.append(item)
                if len(result) > MAX_COMPONENTS:
                    return result
    return result


def _pdm_lock_components(root: Path) -> list[dict[str, str]]:
    text = _read_manifest_text(root, "pdm.lock")
    if text is None:
        return []
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise DependencySecurityError("pdm.lock geçerli TOML değil.") from exc
    result: list[dict[str, str]] = []
    for item in document.get("package", []) if isinstance(document.get("package"), list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("version"), str) \
                and _PYPA_DIST_NAME.fullmatch(item["name"]) and "path" not in item and "git" not in item:
            result.append({"name": item["name"], "version": _clean(item["version"]), "ecosystem": "PyPI",
                           "manifest": "pdm.lock"})
    return result[: MAX_COMPONENTS + 1]


def _setup_components(root: Path) -> list[dict[str, str]]:
    """setup.py / setup.cfg ve pyproject [tool.poetry] içindeki KESİN sabitlemeler (==, ===, Poetry'de çıplak sürüm).
    setup.py çalıştırılmaz; yalnız tırnaklı 'paket==1.2' dizgeleri okunur."""
    result: list[dict[str, str]] = []
    setup_py = _read_manifest_text(root, "setup.py")
    for m in re.finditer(r"""['"]([^'"\n]{1,200})['"]""", setup_py or ""):
        exact = _EXACT_PY.match(m.group(1).split(";", 1)[0].strip())
        if exact:
            result.append({"name": exact.group(1), "version": exact.group(2), "ecosystem": "PyPI", "manifest": "setup.py"})
    setup_cfg = _read_manifest_text(root, "setup.cfg")
    for line in (setup_cfg or "").splitlines():
        exact = _EXACT_PY.match(line.split("#", 1)[0].split(";", 1)[0].strip())
        if exact:
            result.append({"name": exact.group(1), "version": exact.group(2), "ecosystem": "PyPI", "manifest": "setup.cfg"})
    pyproject = _read_manifest_text(root, "pyproject.toml")
    if pyproject:
        try:
            document = tomllib.loads(pyproject)
        except RecursionError as exc:
            raise DependencySecurityError("pyproject.toml geçerli TOML değil.") from exc
        except tomllib.TOMLDecodeError:
            document = {}
        poetry = ((document.get("tool") or {}).get("poetry") or {}) if isinstance(document.get("tool"), dict) else {}
        tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
        groups = poetry.get("group") if isinstance(poetry.get("group"), dict) else {}
        tables += [g.get("dependencies") for g in groups.values() if isinstance(g, dict)]
        for table in tables:
            if not isinstance(table, dict):
                continue
            for name, spec in table.items():
                version = spec.get("version") if isinstance(spec, dict) else spec
                if name.casefold() == "python" or not isinstance(version, str):
                    continue
                version = version.strip().lstrip("=").strip()
                if _PYPA_DIST_NAME.fullmatch(name) and re.fullmatch(r"\d[A-Za-z0-9_.+!-]*", version):
                    result.append({"name": name, "version": version, "ecosystem": "PyPI", "manifest": "pyproject.toml"})
    return result[: MAX_COMPONENTS + 1]


_NPM_LOCK_FILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
_SEMVER_IDENTIFIER = r"(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER_TEXT = (
    rf"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    rf"(?:-({_SEMVER_IDENTIFIER}(?:\.{_SEMVER_IDENTIFIER})*))?"
    rf"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
_SEMVER_RE = re.compile(rf"^[=v]?{_SEMVER_TEXT}$")
_NPM_EXACT = re.compile(rf"^[=v]?({_SEMVER_TEXT})$")
_NPM_PARTIAL = re.compile(
    r"^[v=]?(0|[1-9]\d*|[xX*])(?:\.(0|[1-9]\d*|[xX*]))?(?:\.(0|[1-9]\d*|[xX*]))?$"
)


def _semver_parts(value: str) -> tuple[tuple[int, int, int], str | None] | None:
    match = _SEMVER_RE.fullmatch(value.strip())
    return ((int(match.group(1)), int(match.group(2)), int(match.group(3))), match.group(4)) if match else None


def _semver_core(value: str) -> tuple[int, int, int] | None:
    parsed = _semver_parts(value)
    return parsed[0] if parsed else None


def _semver_compare(left: tuple[tuple[int, int, int], str | None],
                    right: tuple[tuple[int, int, int], str | None]) -> int:
    """SemVer precedence comparison; build metadata is already omitted by ``_semver_parts``."""
    if left[0] != right[0]:
        return -1 if left[0] < right[0] else 1
    left_pre, right_pre = left[1], right[1]
    if left_pre is None or right_pre is None:
        return 0 if left_pre is right_pre else (1 if left_pre is None else -1)
    left_ids, right_ids = left_pre.split("."), right_pre.split(".")
    for lvalue, rvalue in zip(left_ids, right_ids):
        if lvalue == rvalue:
            continue
        lnum, rnum = lvalue.isdigit(), rvalue.isdigit()
        if lnum and rnum:
            return -1 if int(lvalue) < int(rvalue) else 1
        if lnum != rnum:
            return -1 if lnum else 1
        return -1 if lvalue < rvalue else 1
    return (len(left_ids) > len(right_ids)) - (len(left_ids) < len(right_ids))


def _npm_partial_bounds(value: str) -> tuple[tuple[int, int, int], tuple[int, int, int] | None, bool] | None:
    """Return a stable lower bound, exclusive upper bound, and whether the token is fully concrete."""
    match = _NPM_PARTIAL.fullmatch(value.strip())
    if not match:
        return None
    raw = list(match.groups())
    wildcard = next((index for index, item in enumerate(raw) if item is None or item.casefold() == "x" or item == "*"), 3)
    if any(item is not None and item.casefold() not in {"x"} and item != "*"
           for item in raw[wildcard + 1:]):
        return None
    if wildcard == 0:  # bare * / x is deliberately too broad for manifest-only inventory
        return ((0, 0, 0), None, False)
    values = [int(item) if item is not None and item.casefold() != "x" and item != "*" else 0 for item in raw]
    lower = (values[0], values[1], values[2])
    if wildcard >= 3:
        return lower, None, True
    upper = (values[0] + 1, 0, 0) if wildcard == 1 else (values[0], values[1] + 1, 0)
    return lower, upper, False


def _npm_range_contains(spec: str, version: str) -> bool:
    """Bounded npm SemVer subset used only to validate a concrete local ``node_modules`` version."""
    actual_semver = _semver_parts(version)
    wanted = spec.strip()
    if actual_semver is None or not wanted or len(wanted) > 1_000 \
            or wanted.casefold() in {"*", "x", "latest", "next"}:
        return False
    exact_semver = _semver_parts(wanted)
    if exact_semver is not None:
        return _semver_compare(actual_semver, exact_semver) == 0

    branches = wanted.split("||")
    if not branches or len(branches) > 8 or any(not branch.strip() for branch in branches):
        return False

    def branch_matches(branch: str) -> bool | None:
        prerelease_cores: set[tuple[int, int, int]] = set()
        comparisons: list[bool] = []
        # node-semver karşılaştırıcı ile sürüm arasında boşluğa izin verir (``>= 1.2.3``). Yalnız sayı/wildcard
        # ile başlayan sınırı birleştir; serbest metni kabul eden genel bir yeniden yazım yapma.
        branch = re.sub(r"(?<!\S)(<=|>=|<|>|=)\s+(?=[v=]?[0-9xX*])", r"\1", branch)
        hyphen = re.fullmatch(r"\s*(\S+)\s+-\s+(\S+)\s*", branch)
        if hyphen:
            low_parts, high_parts = _semver_parts(hyphen.group(1)), _semver_parts(hyphen.group(2))
            low_partial, high_partial = _npm_partial_bounds(hyphen.group(1)), _npm_partial_bounds(hyphen.group(2))
            if low_parts is None and low_partial is None or high_parts is None and high_partial is None:
                return None
            low = low_parts or (low_partial[0], None)
            if low[1] is not None:
                prerelease_cores.add(low[0])
            comparisons.append(_semver_compare(actual_semver, low) >= 0)
            if high_parts is not None:
                if high_parts[1] is not None:
                    prerelease_cores.add(high_parts[0])
                comparisons.append(_semver_compare(actual_semver, high_parts) <= 0)
            elif high_partial[1] is not None:
                comparisons.append(actual_semver[0] < high_partial[1])
            else:
                comparisons.append(actual_semver[0] == high_partial[0])
        else:
            terms = branch.replace(",", " ").split()
            if not terms or len(terms) > 12:
                return None
            for term in terms:
                if term.startswith(("^", "~")):
                    raw_base = term[1:]
                    base_semver = _semver_parts(raw_base)
                    # Ön sürüm caret/tilde aralıkları, sabit bir yerel sürümü manifest kanıtına dönüştürülmeden
                    # önce tam node-semver doğrulaması gerektirir. Bu sınırlı ayrıştırıcı güvenli biçimde atlar.
                    if base_semver is not None and base_semver[1] is not None:
                        return None
                    partial = _npm_partial_bounds(raw_base) if base_semver is None else None
                    if base_semver is None and partial is None:
                        return None
                    base = base_semver[0] if base_semver is not None else partial[0]
                    if term.startswith("^"):
                        if base[0]:
                            upper = (base[0] + 1, 0, 0)
                        elif base[1]:
                            upper = (0, base[1] + 1, 0)
                        elif base_semver is not None:
                            upper = (0, 0, base[2] + 1)
                        else:
                            # Missing components are npm wildcards.  In particular ``^0`` spans
                            # the whole 0.x line while ``^0.0`` spans the 0.0.x line.
                            upper = partial[1]
                    else:
                        # ``~1`` means 1.x, ``~1.2`` means 1.2.x and a complete
                        # ``~1.2.3`` advances only the minor line.
                        upper = ((base[0], base[1] + 1, 0) if base_semver is not None
                                 else partial[1])
                    if upper is None:
                        return None
                    comparisons.extend((actual_semver[0] >= base, actual_semver[0] < upper))
                    continue
                match = re.fullmatch(r"(<=|>=|<|>|=)?(.+)", term)
                if not match:
                    return None
                op, raw_bound = match.group(1) or "=", match.group(2)
                bound_semver = _semver_parts(raw_bound)
                if bound_semver is not None:
                    if bound_semver[1] is not None:
                        prerelease_cores.add(bound_semver[0])
                    compared = _semver_compare(actual_semver, bound_semver)
                    comparisons.append({"=": compared == 0, ">": compared > 0, ">=": compared >= 0,
                                        "<": compared < 0, "<=": compared <= 0}[op])
                    continue
                partial = _npm_partial_bounds(raw_bound)
                if partial is None or partial[2] or partial[1] is None:
                    return None
                # npm treats omitted components as wildcards.  Comparator direction decides
                # which edge of that wildcard interval is inclusive: ``>1.2`` starts at
                # 1.3.0, while ``<=1.2`` includes the complete 1.2.x line.
                if op == "=":
                    comparisons.extend((actual_semver[0] >= partial[0], actual_semver[0] < partial[1]))
                elif op == ">=":
                    comparisons.append(actual_semver[0] >= partial[0])
                elif op == ">":
                    comparisons.append(actual_semver[0] >= partial[1])
                elif op == "<":
                    comparisons.append(actual_semver[0] < partial[0])
                else:  # <=
                    comparisons.append(actual_semver[0] < partial[1])
        if actual_semver[1] is not None and actual_semver[0] not in prerelease_cores:
            return False
        return all(comparisons)

    results = [branch_matches(branch.strip()) for branch in branches]
    return all(result is not None for result in results) and any(results)


def _local_npm_component(root: Path, name: str, requested: str) -> dict[str, str] | None:
    parts = name.split("/")
    if not parts or len(parts) > 2 or any(not p or p in {".", ".."} for p in parts):
        return None
    package_dir = root / "node_modules"
    if package_dir.is_symlink():
        return None
    for part in parts:
        package_dir /= part
        if package_dir.is_symlink():
            return None
    manifest = package_dir / "package.json"
    try:
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 1_000_000:
            return None
        document = json.loads(manifest.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None
    version = document.get("version") if isinstance(document, dict) else None
    if document.get("name") != name or not isinstance(version, str) or not _npm_range_contains(requested, version):
        return None
    return {"name": name, "version": version, "ecosystem": "npm",
            "manifest": manifest.relative_to(root).as_posix(), "requested_range": requested}


def _package_json_components(root: Path, counters: dict[str, int] | None = None) -> list[dict[str, str]]:
    """Kilit yoksa kesin sürümleri, aralıklar için de doğrulanmış yerel kurulum sürümünü kullan."""
    if any((root / name).exists() for name in _NPM_LOCK_FILES):
        return []
    text = _read_manifest_text(root, "package.json")
    if text is None:
        return []
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise DependencySecurityError("package.json geçerli JSON değil.") from exc
    if not isinstance(document, dict):
        return []
    result: list[dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = document.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str) or not isinstance(spec, str) or not _NPM_NAME.fullmatch(name) or ".." in name:
                continue
            exact = _NPM_EXACT.match(spec.strip())
            if not exact:
                component = _local_npm_component(root, name, spec.strip())
                if component is not None:
                    if section == "devDependencies":
                        component["scope"] = "optional"
                    result.append(component)
                    continue
                if counters is not None:
                    counters["npm_ranges_skipped"] = counters.get("npm_ranges_skipped", 0) + 1
                continue
            component = {"name": name, "version": exact.group(1), "ecosystem": "npm", "manifest": "package.json"}
            if section == "devDependencies":
                component["scope"] = "optional"
            result.append(component)
    return result[: MAX_COMPONENTS + 1]


_HEX_TUPLE_KIND_RE = re.compile(r"^\{\s*:([A-Za-z_][A-Za-z0-9_!?]*)")
_HEX_TUPLE_PREFIX_RE = re.compile(
    r'''^\{\s*:hex\s*,\s*(?::([A-Za-z0-9_.-]+)|:\"([A-Za-z0-9_.-]+)\"|"([A-Za-z0-9_.-]+)")'''
    r'''\s*,\s*"([^"\\\s]{1,200})"\s*(?:,|\})'''
)


def _elixir_balanced_tuple_end(text: str, start: int) -> int | None:
    """Find a tuple's closing byte without evaluating Elixir syntax.

    mix.lock tails contain nested lists, tuples and maps. This scanner only proves balanced delimiters and quoted
    strings; package identity still comes from the fixed ``:hex`` prefix grammar below.
    """
    pairs = {"}": "{", "]": "[", ")": "("}
    stack: list[str] = []
    quote = ""
    escaped = False
    comment = False
    for index in range(start, len(text)):
        char = text[index]
        if comment:
            if char == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "#":
            comment = True
        elif char in "{[(":
            stack.append(char)
        elif char in "}])":
            if not stack or stack[-1] != pairs[char]:
                return None
            stack.pop()
            if not stack:
                return index + 1
    return None


def _hex_components(root: Path) -> list[dict[str, str]]:
    """mix.lock içindeki yalnız ``:hex`` tuple'larını veri olarak ayrıştır; Elixir kodu çalıştırılmaz."""
    text = _read_manifest_text(root, "mix.lock")
    if text is None:
        return []
    document = text.strip()
    if not document.startswith("%{"):
        raise DependencySecurityError("mix.lock geçerli bir Elixir map belgesi değil.")
    root_start = text.find("{", 0, text.find("%{") + 2)
    root_end = _elixir_balanced_tuple_end(text, root_start)
    if root_end is None or text[root_end:].strip():
        raise DependencySecurityError("mix.lock dengeli bir Elixir map belgesi değil.")
    entries: dict[str, dict[str, str]] = {}
    entry_count = 0
    cursor = root_start + 1
    map_end = root_end - 1

    def skip_trivia(index: int) -> int:
        while index < map_end:
            if text[index].isspace():
                index += 1
                continue
            if text[index] == "#":
                newline = text.find("\n", index + 1, map_end)
                index = map_end if newline < 0 else newline + 1
                continue
            break
        return index

    while True:
        cursor = skip_trivia(cursor)
        if cursor >= map_end:
            break
        match = re.match(r'''"([A-Za-z0-9_.-]+)"[ \t]*(?::|=>)[ \t]*(\{)''', text[cursor:map_end])
        if match is None:
            raise DependencySecurityError("mix.lock geçerli bir üst düzey kilit kaydı içermiyor.")
        entry_count += 1
        if entry_count > MAX_COMPONENTS:
            raise DependencySecurityError("mix.lock kayıt sayısı güvenli sınırı aşıyor.")
        lock_name = match.group(1)
        tuple_start = cursor + match.start(2)
        tuple_end = _elixir_balanced_tuple_end(text, tuple_start)
        if tuple_end is None or tuple_end > map_end:
            raise DependencySecurityError("mix.lock dengeli bir tuple haritası değil.")
        tuple_text = text[tuple_start:tuple_end]
        cursor = skip_trivia(tuple_end)
        if cursor < map_end:
            if text[cursor] != ",":
                raise DependencySecurityError("mix.lock üst düzey kayıt ayıracı eksik.")
            cursor += 1
        kind = _HEX_TUPLE_KIND_RE.match(tuple_text)
        if kind is None:
            raise DependencySecurityError("mix.lock geçerli bir kilit tuple'ı içermiyor.")
        if kind.group(1) != "hex":
            # Elixir map semantiği: yinelenen anahtarda son değer geçerlidir. Son değer git/path ise önceki Hex
            # kaydı da artık etkin değildir.
            entries.pop(lock_name, None)
            continue
        prefix = _HEX_TUPLE_PREFIX_RE.match(tuple_text)
        if prefix is None:
            raise DependencySecurityError("mix.lock geçerli bir Hex kilit tuple'ı içermiyor.")
        package_name = next((value for value in prefix.groups()[:3] if value), "")
        version = prefix.group(4)
        # mix.lock somut SemVer taşır; npm'in gevşek ``v``/``=`` bildirim önekleri Hex kilidinde geçerli değildir.
        if package_name and ".." not in package_name and re.fullmatch(_SEMVER_TEXT, version) is not None:
            entries.pop(lock_name, None)
            entries[lock_name] = {"name": package_name, "version": version,
                                  "ecosystem": "Hex", "manifest": "mix.lock"}
        else:
            entries.pop(lock_name, None)
    return list(entries.values())


_MANIFEST_NAMES = frozenset({
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "setup.py",
    "setup.cfg", "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "go.mod",
    "go.sum", "Cargo.lock", "pom.xml", "gradle.lockfile", "build.gradle", "build.gradle.kts", "Gemfile.lock",
    "composer.lock", "pubspec.lock", "Podfile.lock", "Package.resolved", "packages.config", "packages.lock.json",
    "Directory.Packages.props", "mix.lock",
})
MAX_MANIFEST_DIRS = 300
MAX_WALK_DIRS = 20_000
MAX_MANIFEST_DEPTH = 8


def _is_manifest_dir(filenames: list[str]) -> bool:
    return any(name in _MANIFEST_NAMES or name.endswith((".csproj", ".fsproj", ".vbproj")) or _REQ_FILE.match(name)
               for name in filenames)


def _manifest_dirs(root: Path, warnings: list[str]) -> list[Path]:
    """Kök altındaki manifest içeren alt dizinler (monorepo, çok modüllü Maven/Gradle, servisler). Sembolik bağ
    izlenmez; varsayılan atlanan dizinler (node_modules, vendor, test, build …) ve gizli dizinler girilmez."""
    import scan_scope

    skip = {name.casefold() for name in scan_scope.DEFAULT_SKIP_DIRS}
    found: list[Path] = []
    visited = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        depth = len(current.relative_to(root).parts)
        eligible_dirs = sorted(d for d in dirnames if d.casefold() not in skip and not d.startswith(".")
                               and not (current / d).is_symlink())
        if depth >= MAX_MANIFEST_DEPTH and eligible_dirs:
            warning = f"Bağımlılık envanteri: manifest dizini derinlik sınırında ({MAX_MANIFEST_DEPTH}) durduruldu."
            if warning not in warnings:
                warnings.append(warning)
            dirnames[:] = []
        else:
            dirnames[:] = eligible_dirs
        visited += 1
        if visited > MAX_WALK_DIRS:
            warnings.append(f"Bağımlılık envanteri: {MAX_WALK_DIRS} dizinden sonra alt dizin taraması durduruldu.")
            break
        if depth and _is_manifest_dir(filenames):
            found.append(current)
            if len(found) >= MAX_MANIFEST_DIRS:
                warnings.append(f"Bağımlılık envanteri: en çok {MAX_MANIFEST_DIRS} manifest dizini okundu.")
                break
    return found


def _directory_inventory(directory: Path, project_root: Path, *, strict: bool, warnings: list[str],
                         counters: dict[str, int]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    rel = directory.relative_to(project_root).as_posix() if directory != project_root else ""
    parsers: list[Any] = [
        _python_components, _uv_lock_components, _pdm_lock_components, _setup_components,
        lambda d: _requirements_extra_components(d, project_root),
        _npm_components, _pnpm_components, _yarn_components, lambda d: _package_json_components(d, counters),
        _go_components, _cargo_components,
        lambda d: _maven_components(d, project_root, warnings), _gradle_components,
        _ruby_components, _composer_components, _pubspec_components, _cocoapods_components, _swiftpm_components,
        _hex_components,
        _nuget_components,
    ]
    components: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    try:
        pip_components, pip_skipped = _pipfile_lock_inventory(directory)
        components += pip_components
        skipped += pip_skipped
    except DependencySecurityError as exc:
        if strict:
            raise
        warnings.append(f"{rel or '.'}: {exc}")
    for parser in parsers:
        try:
            components += parser(directory)
        except DependencySecurityError as exc:
            if strict:
                raise
            warnings.append(f"{rel or '.'}: {exc}")
        except (OSError, ValueError, RecursionError, TypeError, AttributeError) as exc:
            if strict:
                raise
            warnings.append(f"{rel or '.'}: manifest okunamadı ({type(exc).__name__}).")
    if rel:
        for component in components:
            component["manifest"] = f"{rel}/{component['manifest']}"
        for item in skipped:
            item["manifest"] = f"{rel}/{item.get('manifest', '')}"
    return components, skipped


def discover_inventory(
    project_path: str, *, allowed_roots: tuple[Path, ...] | None = None, lenient: bool = False,
    warnings: list[str] | None = None, recursive: bool = True,
) -> tuple[Path, list[dict[str, str]], list[dict[str, str]]]:
    """Bileşenleri ve bileşen olarak üretilmeyen (atlanan) kilit kayıtlarını döndürür.

    Kök dizindeki bozuk manifest varsayılan olarak hata verir (önceki sözleşme). 18. tur: alt dizinlerdeki
    manifestler de okunur (monorepo/çok modüllü projeler) ve oradaki hatalar yalnız ``warnings`` listesine düşer;
    ``lenient=True`` kökteki hataları da uyarıya çevirir (çevrimdışı SCA taraması)."""
    try:
        root = validate_project_path(project_path, allowed_roots)
    except ProjectRejected as exc:
        raise DependencySecurityError(str(exc)) from exc
    warnings = warnings if warnings is not None else []
    counters: dict[str, int] = {}
    all_components, skipped = _directory_inventory(root, root, strict=not lenient, warnings=warnings, counters=counters)
    if recursive:
        for directory in _manifest_dirs(root, warnings):
            sub_components, sub_skipped = _directory_inventory(directory, root, strict=False, warnings=warnings,
                                                               counters=counters)
            all_components += sub_components
            skipped += sub_skipped
            if len(all_components) > MAX_COMPONENTS * 2:
                warnings.append("Bağımlılık envanteri: bileşen sınırına ulaşıldı; kalan alt dizinler okunmadı.")
                break
    if counters.get("npm_ranges_skipped"):
        warnings.append(f"package.json: kilit dosyası olmayan {counters['npm_ranges_skipped']} aralıklı sürüm "
                        "güvenli yerel kurulumla doğrulanamadığı için denetlenmedi.")
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for component in all_components:
        key = (component["ecosystem"].casefold(), component["name"].casefold(), component["version"])
        previous = unique.get(key)
        if previous is not None:
            # İlk görülen (kök ya da en sığ) manifest korunur; aynı paket başka bir kaynakta zorunlu görünüyorsa
            # geliştirme kapsamı düşürülür (Pipfile.lock develop / npm dev ile aynı kural).
            if previous.get("scope") != component.get("scope"):
                previous = {k: v for k, v in previous.items() if k != "scope"}
            component = previous
        unique[key] = component
        if len(unique) > MAX_COMPONENTS:
            if not lenient:
                raise DependencySecurityError("Bağımlılık sayısı güvenli sınırı aşıyor.")
            warnings.append("Bağımlılık envanteri: bileşen sınırı aşıldı; fazlası atlandı.")
            break
    # Sürümsüz kayıt, aynı ad için somut sürüm de varsa gereksizdir (pom.xml'de yönetilen + alt modülde sürümlü vb.)
    versioned = {(k[0], k[1]) for k, v in unique.items() if v["version"]}
    components = [unique[key] for key in sorted(unique) if unique[key]["version"] or (key[0], key[1]) not in versioned]
    return root, components, skipped


def discover_components(project_path: str, *, allowed_roots: tuple[Path, ...] | None = None) -> tuple[Path, list[dict[str, str]]]:
    root, components, _skipped = discover_inventory(project_path, allowed_roots=allowed_roots)
    return root, components


def generate_cyclonedx_sbom(project_path: str, *, allowed_roots: tuple[Path, ...] | None = None) -> dict[str, Any]:
    root, components, skipped = discover_inventory(project_path, allowed_roots=allowed_roots)
    try:  # yerel lisans üst verisi (ağ yok); okunamazsa SBOM lisanssız üretilir
        import license_compliance

        license_map = license_compliance.component_license_map(root, components)
    except Exception:  # noqa: BLE001
        license_compliance, license_map = None, {}
    cyclonedx_components = []
    for component in components:
        purl = component.get("purl") or _package_url(component["ecosystem"], component["name"], component["version"])
        item: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": component["name"],
            "purl": purl,
            "properties": [{"name": "sniper:manifest", "value": component["manifest"]}],
        }
        if component["version"]:
            item["version"] = component["version"]
        if component.get("scope") == "optional":
            item["scope"] = "optional"
            item["properties"].append({"name": "sniper:dependency-section", "value": "develop"})
        if license_map:
            info = license_map.get(license_compliance.component_key(component["ecosystem"], component["name"], component["version"]))
            licenses = license_compliance.cyclonedx_licenses(info)
            if licenses:
                item["licenses"] = licenses
        cyclonedx_components.append(item)
    # 20. tur: araç bilgisi ve kilit dosyalarındaki bağımlılık ağacı (deterministik; zaman damgası indirmede eklenir)
    try:
        from version import __version__ as tool_version
    except Exception:  # noqa: BLE001
        tool_version = ""
    metadata: dict[str, Any] = {
        "tools": [{"vendor": "Sniper", "name": "sniper-sbom", "version": str(tool_version)}],
        "component": {"type": "application", "name": root.name, "bom-ref": "sniper-root"},
    }
    try:
        import sbom_formats

        edges, direct, _used = sbom_formats.dependency_graph(root, components)
        dependencies = sbom_formats.cyclonedx_dependencies(cyclonedx_components, edges, direct)
    except Exception:  # noqa: BLE001 — ilişki çıkarılamazsa SBOM ilişkisiz üretilir
        dependencies = None
    hashed: Any = cyclonedx_components
    if skipped:
        metadata["properties"] = [{"name": "sniper:skipped-dependency-count", "value": str(len(skipped))}] + [
            {
                "name": "sniper:skipped-dependency",
                "value": f"{entry['manifest']}|{entry['section']}|{entry['name']}|{entry['reason']}",
            }
            for entry in skipped
        ]
        hashed = {"components": cyclonedx_components, "skipped": skipped}
    canonical = json.dumps(hashed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"sniper:{root}:{hashlib.sha256(canonical.encode()).hexdigest()}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": cyclonedx_components,
        **({"dependencies": dependencies} if dependencies else {}),
    }


def _safe_report_path(value: str, allowed_roots: tuple[Path, ...] | None = None) -> Path:
    raw = value.strip()
    if not raw or len(raw) > 1_024:
        raise DependencySecurityError("Geçerli bir yerel rapor dosyası girin.")
    try:
        path = Path(raw).expanduser()
    except (OSError, RuntimeError) as exc:
        raise DependencySecurityError("Rapor dosyası bulunamadı veya okunamıyor.") from exc
    if path.is_symlink():
        raise DependencySecurityError("Rapor yolu normal bir dosya olmalıdır.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DependencySecurityError("Rapor dosyası bulunamadı veya okunamıyor.") from exc
    if not resolved.is_file():
        raise DependencySecurityError("Rapor yolu normal bir dosya olmalıdır.")
    roots = allowed_roots if allowed_roots is not None else (Path.home().resolve(), Path("/media").resolve(), Path("/mnt").resolve())
    if not any(resolved != root and root in resolved.parents for root in roots):
        raise DependencySecurityError("Rapor yalnızca kullanıcı dizini veya bağlı yerel diskten okunabilir.")
    size = resolved.stat().st_size
    if size <= 0 or size > MAX_REPORT_BYTES:
        raise DependencySecurityError("Rapor boş veya 8 MB boyut sınırını aşıyor.")
    return resolved


def load_report(path_value: str, *, allowed_roots: tuple[Path, ...] | None = None) -> tuple[Path, dict[str, Any]]:
    import json
    import os
    import stat
    from pathlib import Path
    from typing import Any

    from dependency_security import DependencySecurityError

    MAX_REPORT_BYTES = 8_000_000
    path = _safe_report_path(path_value, allowed_roots)

    class VerifiedDocument(dict):
        _verified_sha256: str
        _verified_mtime_ns: int

    # Secure file opening: walk all directory components with O_DIRECTORY | O_NOFOLLOW
    # to detect parent directory symlink swaps after validation, then open file with O_NOFOLLOW
    dir_fds: list[int] = []
    try:
        # Get absolute path without resolving symlinks
        if path.is_absolute():
            abs_path = path
        else:
            abs_path = Path.cwd() / path

        parts = abs_path.parts

        if len(parts) < 2:
            raise DependencySecurityError("Dosya geçerli bir regular dosya olamaz.")

        # Walk each parent directory component with O_DIRECTORY | O_NOFOLLOW
        # Open with dir_fd chaining: each dir opens relative to previous parent fd
        base_fd = os.open(str(Path(parts[0])), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        dir_fds.append(base_fd)

        for i in range(1, len(parts) - 1):
            # Open each directory component RELATIVE to the previously opened parent descriptor
            dir_path = parts[i]
            try:
                fd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fds[-1])
                dir_fds.append(fd)
            except OSError as exc:
                if exc.errno == 40:  # ELOOP - symlink detected in parent
                    raise DependencySecurityError("Dosya geçerli bir regular dosya olamaz.") from exc
                if exc.errno in (20, 13):  # ENOTDIR, EACCES
                    raise DependencySecurityError("Dosya okunamadı: izin veya yol hatası.") from exc
                raise DependencySecurityError("Dosya geçerli bir regular dosya olamaz.") from exc

        # Open final file component RELATIVE to the verified parent descriptor
        final_name = parts[-1]
        try:
            fd = os.open(final_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fds[-1])
        except OSError as exc:
            if exc.errno == 40:  # ELOOP - symlink detected
                raise DependencySecurityError("Dosya geçerli bir regular dosya olamaz.") from exc
            if exc.errno in (20, 13):  # ENOTDIR, EACCES
                raise DependencySecurityError("Dosya okunamadı: izin veya yol hatası.") from exc
            raise DependencySecurityError("Dosya geçerli bir regular dosya olamaz.") from exc
        except ValueError:
            raise DependencySecurityError("Dosya geçerli bir regular dosya olamaz.")

        try:
            # Verify the opened fd is a regular file (not FIFO/socket/device)
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise DependencySecurityError("Dosya bir regular dosya değil.")
            initial_size = file_stat.st_size
            if initial_size > MAX_REPORT_BYTES:
                raise DependencySecurityError("Dosya boyut sınırı aşıyor.")

            # Read complete FD until EOF with 8MB upper bound, handle short reads
            raw_bytes = b""
            remaining = MAX_REPORT_BYTES
            while remaining > 0:
                try:
                    chunk = os.read(fd, remaining)
                    if not chunk:
                        break
                    raw_bytes += chunk
                    remaining -= len(chunk)
                except OSError as exc:
                    raise DependencySecurityError("Dosya okuma hatası.") from exc

            # Detect post-fstat growth: file grew beyond initial size after fstat
            try:
                final_pos = os.lseek(fd, 0, os.SEEK_END)
            except OSError as exc:
                raise DependencySecurityError("Dosya okuma hatası.") from exc

            if final_pos > initial_size:
                raise DependencySecurityError("Dosya fstat sonrası büyüme tespit edildi.")

            if final_pos > MAX_REPORT_BYTES:
                raise DependencySecurityError("Dosya boyut sınırı aşıyor.")

            if remaining == MAX_REPORT_BYTES and len(raw_bytes) == 0:
                raise DependencySecurityError("Dosya boş veya okunamadı.")

            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DependencySecurityError("Rapor geçerli UTF-8 JSON değil.") from exc

            try:
                def object_pairs_hook(pairs):
                    seen = set()
                    for key, value in pairs:
                        if key in seen:
                            raise ValueError("Yinelenen anahtar bulundu")
                        seen.add(key)
                    return dict(pairs)
                parsed = json.loads(text, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("JSON dışı sabit: " + x)), object_pairs_hook=object_pairs_hook, strict=True)
            except (json.JSONDecodeError, ValueError, RecursionError) as exc:
                raise DependencySecurityError("Rapor geçerli UTF-8 JSON değil.") from exc

            # Require dict root BEFORE wrapping in VerifiedDocument
            if not isinstance(parsed, dict):
                raise DependencySecurityError("Raporun kökü bir JSON nesnesi olmalıdır.")

            document = VerifiedDocument(parsed)

            import hashlib
            document._verified_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            document._verified_mtime_ns = file_stat.st_mtime_ns
        finally:
            os.close(fd)

    finally:
        for fd in dir_fds:
            os.close(fd)

    return path, document


def detect_report_source(document: dict[str, Any]) -> str:
    has_trivy = isinstance(document.get("Results"), list)
    has_osv = isinstance(document.get("results"), list)
    if has_trivy and has_osv:
        raise DependencySecurityError("Rapor hem Trivy hem de OSV şemasına sahip; çakışan şema tespit edildi.")
    if has_trivy:
        return "trivy"
    if has_osv:
        return "osv"
    raise DependencySecurityError("Rapor Trivy veya OSV şemasına uymuyor.")


def _references(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    refs: list[str] = []
    for item in value:
        candidate = item.get("url") if isinstance(item, dict) else item
        if not isinstance(candidate, str):
            continue
        text = _clean(candidate, 1_000)
        if text:
            if text not in refs:
                refs.append(text)
            if len(refs) >= 50:
                break
    return refs


def parse_trivy(document: dict[str, Any], project_path: str) -> list[dict[str, Any]]:
    results = document.get("Results")
    if not isinstance(results, list):
        raise DependencySecurityError("Trivy raporunda Results dizisi yok.")
    findings: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise DependencySecurityError("Trivy Results dizisinde geçersiz öğe bulundu.")
        target = _clean(result.get("Target"), 1_000)
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise DependencySecurityError("Trivy Vulnerabilities alanı bir dizi olmalıdır.")
        for item in vulnerabilities or []:
            if not isinstance(item, dict):
                raise DependencySecurityError("Trivy Vulnerabilities dizisinde geçersiz öğe bulundu.")
            vulnerability_id = _clean(item.get("VulnerabilityID"), 160)
            package = _clean(item.get("PkgName"), 500)
            installed = _clean(item.get("InstalledVersion"), 240)
            if not vulnerability_id or not package:
                continue
            severity = _clean(item.get("Severity"), 20).casefold()
            findings.append({
                "project_path": project_path,
                "package_name": package,
                "installed_version": installed,
                "vulnerability_id": vulnerability_id,
                "severity": severity if severity in SEVERITIES else "unknown",
                "fixed_version": _clean(item.get("FixedVersion"), 500),
                "source": "trivy",
                "title": _clean(item.get("Title"), 500) or vulnerability_id,
                "summary": _clean(item.get("Description"), 8_000),
                "references": _references(item.get("References")),
                "target": target,
            })
            if len(findings) > MAX_FINDINGS:
                raise DependencySecurityError("Bulgu sayısı güvenli sınırı aşıyor.")
    return findings


MALICIOUS_TITLE = "Kötü amaçlı paket"
MALICIOUS_CWE = "CWE-506"
MALICIOUS_RECOMMENDATION = (
    "Bu paket sürümü OpenSSF kötü amaçlı paket veritabanında kayıtlı (açık değil, zararlı kod). Derhal kaldırın ve "
    "kilit dosyasından çıkarın; paketin kurulduğu makinelerde ve CI'da kullanılan kimlik bilgilerini, belirteçleri ve "
    "anahtarları döndürün; etkilenen sistemleri (kurulum betikleri, ağ bağlantıları, kalıcılık) inceleyin. Sürüm "
    "yükseltmek yeterli değildir.")


def is_malicious_vulnerability(vulnerability: dict[str, Any]) -> bool:
    """OSV kaydı kötü amaçlı paket mi? Kimlik/takma ad MAL- ya da birleşik kayıtta ``database_specific.malicious``."""
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("malicious") is True:
        return True
    import osv_offline  # döngüsüz: osv_offline bu modülü yalnız işlev içinde içe aktarır

    return osv_offline.is_malicious_record(vulnerability)


def is_malicious_finding(finding: dict[str, Any]) -> bool:
    """Kayıtlı bağımlılık bulgusu kötü amaçlı paket mi (veritabanında ayrı sütun yok: kimlik öneki/başlık)."""
    return (finding.get("malicious") is True or str(finding.get("vulnerability_id") or "").startswith("MAL-")
            or str(finding.get("title") or "").startswith(MALICIOUS_TITLE + ":"))


def _osv_severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    value = database_specific.get("severity") if isinstance(database_specific, dict) else ""
    severity = _clean(value, 20).casefold()
    return severity if severity in SEVERITIES else "unknown"


def _osv_fixed_version(vulnerability: dict[str, Any]) -> str:
    versions: list[str] = []
    for affected in vulnerability.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for range_item in affected.get("ranges") or []:
            if not isinstance(range_item, dict):
                continue
            for event in range_item.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    versions.append(_clean(event["fixed"], 240))
    return ", ".join(dict.fromkeys(filter(None, versions)))[:500]


def parse_osv(document: dict[str, Any], project_path: str) -> list[dict[str, Any]]:
    results = document.get("results")
    if not isinstance(results, list):
        raise DependencySecurityError("OSV raporunda results dizisi yok.")
    findings: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise DependencySecurityError("OSV raporunda bir sonuç nesnesi bir sözlük olmalı.")
        packages = result.get("packages")
        if packages is None:
            raise DependencySecurityError("OSV raporunda packages alanı null olamaz.")
        if not isinstance(packages, list):
            raise DependencySecurityError("OSV raporunda packages alanı bir liste olmalı.")
        if not isinstance(packages, list):
            raise DependencySecurityError("OSV raporunda packages alanı bir liste olmalı.")
        for package_entry in packages:
            if not isinstance(package_entry, dict):
                raise DependencySecurityError("OSV raporunda packages listesi bir sözlük içermelidir.")
            package = package_entry.get("package")
            if not isinstance(package, dict):
                raise DependencySecurityError("OSV raporunda package alanı bir sözlük olmalıdır.")
            name = _clean(package.get("name"), 500)
            version = _clean(package.get("version"), 240)
            ecosystem = _clean(package.get("ecosystem"), 100)
            vulnerabilities = package_entry.get("vulnerabilities")
            if vulnerabilities is None:
                raise DependencySecurityError("OSV raporunda vulnerabilities alanı null olamaz.")
            if not isinstance(vulnerabilities, list):
                raise DependencySecurityError("OSV raporunda vulnerabilities alanı bir liste olmalı.")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise DependencySecurityError("OSV raporunda vulnerabilities listesi bir sözlük içermelidir.")
                vulnerability_id = _clean(vulnerability.get("id"), 160)
                if not name or not vulnerability_id:
                    raise DependencySecurityError("OSV raporunda package adı veya vulnerability ID eksik veya boş.")
                if is_malicious_vulnerability(vulnerability):
                    # 20. tur: kötü amaçlı paket (OpenSSF MAL-) — açık değil; yükseltme değil kaldırma gerekir.
                    findings.append({
                        "project_path": project_path,
                        "package_name": name,
                        "installed_version": version,
                        "vulnerability_id": vulnerability_id,
                        "severity": "critical",
                        "fixed_version": _osv_fixed_version(vulnerability),  # çoğu MAL- kaydında yok (tüm sürümler)
                        "source": "osv",
                        "title": _clean(f"{MALICIOUS_TITLE}: {name} {version}", 500),
                        "summary": _clean(MALICIOUS_RECOMMENDATION + "\n\n" + str(vulnerability.get("summary") or "")
                                          + "\n" + str(vulnerability.get("details") or ""), 8_000),
                        "references": _references(vulnerability.get("references")),
                        "target": ecosystem,
                        "malicious": True,
                        "cwe": MALICIOUS_CWE,
                    })
                    if len(findings) > MAX_FINDINGS:
                        raise DependencySecurityError("Bulgu sayısı güvenli sınırı aşıyor.")
                    continue
                findings.append({
                    "project_path": project_path,
                    "package_name": name,
                    "installed_version": version,
                    "vulnerability_id": vulnerability_id,
                    "severity": _osv_severity(vulnerability),
                    "fixed_version": _osv_fixed_version(vulnerability),
                    "source": "osv",
                    "title": _clean(vulnerability.get("summary"), 500) or vulnerability_id,
                    "summary": _clean(vulnerability.get("details"), 8_000),
                    "references": _references(vulnerability.get("references")),
                    "target": ecosystem,
                })
                if len(findings) > MAX_FINDINGS:
                    raise DependencySecurityError("Bulgu sayısı güvenli sınırı aşıyor.")
    return findings


def source_timestamp(document: dict[str, Any], fallback_path: Path) -> str:
    metadata = document.get("Metadata")
    candidates = [document.get("created_at"), document.get("timestamp")]
    if isinstance(metadata, dict):
        candidates.extend((metadata.get("Date"), metadata.get("UpdatedAt")))
    for value in candidates:
        if isinstance(value, str) and value.strip():
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    continue
                try:
                    return parsed.astimezone(timezone.utc).isoformat()
                except OverflowError:
                    continue
            except ValueError:
                continue
    verified_sha256 = getattr(document, "_verified_sha256", None)
    verified_mtime_ns = getattr(document, "_verified_mtime_ns", None)
    if verified_sha256 is None or verified_mtime_ns is None:
        raise DependencySecurityError("load_report FD metadata: _verified_sha256 ve _verified_mtime_ns gerekli.")
    return datetime.fromtimestamp(verified_mtime_ns / 1e9, timezone.utc).isoformat()


def import_report(path_value: str, project_path: str, source: str = "auto", *, allowed_roots: tuple[Path, ...] | None = None) -> dict[str, Any]:
    project_root, _ = discover_components(project_path, allowed_roots=allowed_roots)
    path, document = load_report(path_value, allowed_roots=allowed_roots)
    selected = detect_report_source(document) if source == "auto" else source.casefold()
    if selected not in {"trivy", "osv"}:
        raise DependencySecurityError("Kaynak yalnızca auto, trivy veya osv olabilir.")
    findings = parse_trivy(document, str(project_root)) if selected == "trivy" else parse_osv(document, str(project_root))
    verified_sha256 = getattr(document, "_verified_sha256", None)
    if not verified_sha256:
        raise DependencySecurityError("load_report: _verified_sha256 bekleniyor.")
    raw_hash = verified_sha256
    return {
        "source": selected,
        "source_path": str(path),
        "source_timestamp": source_timestamp(document, path),
        "document_hash": raw_hash,
        "project_path": str(project_root),
        "findings": findings,
    }


def query_osv_batch_via_tor(components: list[dict[str, str]], *, proxy: str = "socks5h://127.0.0.1:9050", timeout: int = 45) -> dict[str, Any]:
    if not re.fullmatch(r"socks5h://127\.0\.0\.1:\d{1,5}$", proxy) or not (1 <= int(proxy.rsplit(":", 1)[1]) <= 65535):
        raise DependencySecurityError("OSV çevrimiçi sorgusu yalnızca yerel Tor SOCKS vekiliyle kullanılabilir.")

    if len(components) > 1000:
        raise DependencySecurityError("OSV sorgusu için maksimum 1000 bileşen desteklenir. 1000'den fazla bileşen tespit edildi.")

    try:
        port_str = proxy.rsplit(":", 1)[1]
        port = int(port_str)
        if port < 1 or port > 65535:
            raise ValueError("Port aralık dışında")
    except (OSError, ValueError, IndexError) as exc:
        raise DependencySecurityError("Tor SOCKS hizmetine ulaşılamadı; doğrudan ağa geçilmedi.") from exc

    if len(components) == 0:
        return {"results": []}

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    except (OSError, ValueError) as exc:
        raise DependencySecurityError("Tor SOCKS hizmetine ulaşılamadı; doğrudan ağa geçilmedi.") from exc

    queries = []
    for component in components:
        from osv_offline import osv_ecosystem  # envanter adı → OSV adı (Golang → Go, cargo → crates.io)
        package = {"name": component["name"], "ecosystem": osv_ecosystem(component["ecosystem"]) or component["ecosystem"]}
        query: dict[str, Any] = {"package": package}
        if component.get("version"):
            query["version"] = component["version"]
        queries.append(query)

    payload = json.dumps({"queries": queries}, separators=(",", ":"))
    # Gövde argv yerine stdin'den gider: 1000 bileşenlik bir sorgu komut satırı
    # uzunluk sınırını (E2BIG) aşabilir ve argv /proc üzerinden diğer süreçlere görünür.
    # --disable (-q) kullanıcının ~/.curlrc dosyasının vekil/ayar enjekte etmesini engeller.
    try:
        process = subprocess.run(
            ["curl", "--disable", "--silent", "--show-error", "--fail", "--max-time", str(timeout),
             "--proxy", proxy, "--header", "Content-Type: application/json", "--data-binary", "@-",
             "https://api.osv.dev/v1/querybatch"],
            input=payload, capture_output=True, text=True, timeout=timeout + 5, check=False,
        )
    except subprocess.TimeoutExpired:
        raise DependencySecurityError("Tor üzerinden OSV isteği zaman aşımına uğradı ve doğrudan yedekleme gerçekleşmedi.") from None
    if process.returncode != 0:
        raise DependencySecurityError("Tor üzerinden OSV sorgusu başarısız.")

    if len(process.stdout.encode("utf-8")) > MAX_REPORT_BYTES:
        raise DependencySecurityError("OSV yanıtı boyut sınırı aşıldı.")
    try:
        response = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise DependencySecurityError("OSV geçersiz JSON döndürdü.") from exc

    if not isinstance(response, dict) or not isinstance(response.get("results"), list):
        raise DependencySecurityError("OSV yanıt şeması geçersiz.")

    results = response["results"]

    if len(results) != len(queries):
        raise DependencySecurityError(f"OSV yanıtı eksik: {len(queries)} sorgu yapıldı ancak {len(results)} sonuç döndü.")

    for i, result in enumerate(results):
        if not isinstance(result, dict):
            raise DependencySecurityError(f"OSV yanıtı geçersiz: {i}. sonuç bir nesne değil.")
        if "vulns" in result and not isinstance(result["vulns"], list):
            raise DependencySecurityError(f"OSV yanıtı geçersiz: {i}. 'vulns' alanı bir liste olmalıdır.")
        if result.get("next_page_token"):
            raise DependencySecurityError(f"OSV yanıtı eksik: {i}. sonuç için 'next_page_token' var, bu tamamlanmamış bir sayfalama anlamına gelir.")

    return response


_REACHABILITY_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    "target",
    "vendor",
}

_REACHABILITY_SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".jsp",
    ".cs",
    ".cshtml",
    ".razor",
    ".vb",
    ".fs",
    ".erb",
    ".rake",
    ".phtml",
    ".swift",
    ".dart",
    ".m",
    ".mm",
}

_PACKAGE_IMPORT_ALIASES: dict[str, set[str]] = {
    "pyyaml": {"yaml", "pyyaml"},
    "pillow": {"pil", "pillow"},
    "beautifulsoup4": {"bs4", "beautifulsoup4"},
    "scikit-learn": {"sklearn", "scikit_learn"},
    "python-dateutil": {"dateutil", "python_dateutil"},
    "pyjwt": {"jwt", "pyjwt"},
    "cryptography": {"cryptography"},
    "opencv-python": {"cv2", "opencv_python"},
    "attrs": {"attr", "attrs"},
    "pyopenssl": {"openssl", "pyopenssl"},
    # 20. tur: içe aktarma adı paket adından farklı yaygın PyPI paketleri
    "djangorestframework": {"rest_framework"},
    "djangorestframework-simplejwt": {"rest_framework_simplejwt"},
    "django-cors-headers": {"corsheaders"},
    "django-filter": {"django_filters"},
    "django-environ": {"environ"},
    "python-dotenv": {"dotenv"},
    "python-jose": {"jose"},
    "python-magic": {"magic"},
    "python-multipart": {"multipart"},
    "pymongo": {"pymongo", "bson", "gridfs"},
    "protobuf": {"google.protobuf"},
    "pycryptodome": {"crypto"},
    "pycryptodomex": {"cryptodome"},
    "pycrypto": {"crypto"},
    "mysqlclient": {"mysqldb"},
    "psycopg2-binary": {"psycopg2"},
    "opencv-python-headless": {"cv2"},
    "scikit-image": {"skimage"},
    "msgpack-python": {"msgpack"},
    "ruamel.yaml": {"ruamel"},
    "google-auth": {"google.auth"},
}


_GENERIC_JVM_SEGMENTS = {"core", "common", "commons", "api", "util", "utils", "base", "impl", "parent", "all", "bom",
                         "starter", "client", "server", "lib", "java", "jvm", "kotlin", "plugin", "spi", "web"}
# Grup kimliğinden çıkarılamayan yaygın Java paket önekleri (artefakt → içe aktarma önekleri)
_MAVEN_PACKAGE_PREFIXES: dict[str, tuple[str, ...]] = {
    "com.fasterxml.jackson.core:jackson-databind": ("com.fasterxml.jackson.databind",),
    "com.fasterxml.jackson.core:jackson-core": ("com.fasterxml.jackson.core",),
    "org.yaml:snakeyaml": ("org.yaml.snakeyaml",),
    "commons-collections:commons-collections": ("org.apache.commons.collections",),
    "org.apache.commons:commons-collections4": ("org.apache.commons.collections4",),
    "commons-io:commons-io": ("org.apache.commons.io",),
    "commons-fileupload:commons-fileupload": ("org.apache.commons.fileupload",),
    "commons-beanutils:commons-beanutils": ("org.apache.commons.beanutils",),
    "commons-codec:commons-codec": ("org.apache.commons.codec",),
    "commons-lang:commons-lang": ("org.apache.commons.lang",),
    "org.apache.commons:commons-lang3": ("org.apache.commons.lang3",),
    "org.apache.commons:commons-text": ("org.apache.commons.text",),
    "org.apache.commons:commons-compress": ("org.apache.commons.compress",),
    "com.google.guava:guava": ("com.google.common",),
    "com.google.code.gson:gson": ("com.google.gson",),
    "com.thoughtworks.xstream:xstream": ("com.thoughtworks.xstream",),
    "mysql:mysql-connector-java": ("com.mysql",),
    "com.mysql:mysql-connector-j": ("com.mysql",),
    "org.postgresql:postgresql": ("org.postgresql",),
    "com.h2database:h2": ("org.h2",),
    "org.apache.tomcat.embed:tomcat-embed-core": ("org.apache.catalina", "org.apache.tomcat", "org.apache.coyote"),
    "ch.qos.logback:logback-classic": ("ch.qos.logback.classic",),
    "ch.qos.logback:logback-core": ("ch.qos.logback.core",),
    "org.apache.logging.log4j:log4j-core": ("org.apache.logging.log4j",),
    "org.apache.logging.log4j:log4j-api": ("org.apache.logging.log4j",),
    "log4j:log4j": ("org.apache.log4j",),
    "org.bouncycastle:bcprov-jdk15on": ("org.bouncycastle",),
    "io.jsonwebtoken:jjwt": ("io.jsonwebtoken",),
    "com.alibaba:fastjson": ("com.alibaba.fastjson",),
    "org.dom4j:dom4j": ("org.dom4j",),
    "dom4j:dom4j": ("org.dom4j",),
    "org.jsoup:jsoup": ("org.jsoup",),
    "org.mybatis:mybatis": ("org.apache.ibatis",),
}
# Grup öneki → içe aktarma önekleri (Spring, Netty vb. birçok artefakt aynı kökü paylaşır)
_MAVEN_GROUP_PREFIXES: dict[str, tuple[str, ...]] = {
    "org.springframework": ("org.springframework",),
    "io.netty": ("io.netty",),
    "org.hibernate": ("org.hibernate",),
    "org.eclipse.jetty": ("org.eclipse.jetty",),
}


def _candidate_import_names(
    pkg_name: str,
    cargo_aliases: dict[str, set[str]] | None = None,
) -> set[str]:
    cleaned = pkg_name.strip()
    if not cleaned:
        return set()
    lower = cleaned.casefold()
    candidates: set[str] = {lower, lower.replace("-", "_"), lower.replace("-", "")}
    if lower in _PACKAGE_IMPORT_ALIASES:
        candidates.update(_PACKAGE_IMPORT_ALIASES[lower])
    if cargo_aliases:
        package_forms = {lower, lower.replace("-", "_"), lower.replace("_", "-")}
        for package, aliases in cargo_aliases.items():
            canonical_forms = {
                package.casefold(),
                package.casefold().replace("-", "_"),
                package.casefold().replace("_", "-"),
            }
            if package_forms & canonical_forms:
                candidates.update(alias.casefold() for alias in aliases)
    if ":" in lower:
        group, artifact = lower.split(":", 1)
        candidates.add(artifact)
        candidates.add(artifact.replace("-", "_"))
        candidates.add(artifact.replace("-", "."))
        candidates.add(artifact.replace("-", ""))
        candidates.add(group)
        candidates.add(f"{group}.{artifact.replace('-', '')}")
        group_tail = group.rsplit(".", 1)[-1]
        # 20. tur: "core", "common" gibi genel son parçalar başka kütüphanelerin içe aktarmalarıyla çakışıyordu.
        if len(group_tail) >= 3 and group_tail not in {"com", "org", "net", "io", "dev", "app"} | _GENERIC_JVM_SEGMENTS:
            candidates.add(group_tail)
        # 20. tur: Java paket öneki çoğu kütüphanede grup ya da grup ebeveyni + artefakt son parçası
        # (com.fasterxml.jackson.core:jackson-databind → com.fasterxml.jackson.databind).
        parent = group.rsplit(".", 1)[0] if group.count(".") >= 2 else ""
        tail = artifact.rsplit("-", 1)[-1]
        if parent and tail and tail not in _GENERIC_JVM_SEGMENTS and len(tail) >= 3:
            candidates.add(f"{parent}.{tail}")
            candidates.add(f"{group}.{tail}")
        candidates.update(_MAVEN_PACKAGE_PREFIXES.get(lower, ()))
        if "." not in group and artifact.startswith("commons-") and len(artifact) > len("commons-") + 1:
            # Apache Commons eski grupları (commons-httpclient:commons-httpclient → org.apache.commons.httpclient)
            candidates.add("org.apache.commons." + artifact[len("commons-"):].replace("-", ""))
        for prefix, packages in _MAVEN_GROUP_PREFIXES.items():
            if group == prefix or group.startswith(prefix + "."):
                candidates.update(packages)
    if "/" in lower and not lower.startswith("@") and "." in lower.split("/", 1)[0]:
        # Go modülü (golang.org/x/net): yalnız modül yolu; alan adı kökü ("golang.org") ya da son parça ("net")
        # başka modüllerin içe aktarmalarıyla eşleşip yanlış kullanım üretirdi. Alt paketler ayrıca eşleşir.
        return {lower}
    if "/" in lower and not lower.startswith("@"):
        head = lower.split("/", 1)[0]
        tail = lower.rsplit("/", 1)[-1]
        candidates.add(head)
        candidates.add(tail)
        candidates.add(tail.replace("-", "_"))
        candidates.add(tail.replace("-", ""))
    if "-" in lower and ":" not in lower and "/" not in lower:
        candidates.add(lower.replace("-", "/"))  # Ruby: net-http → require "net/http"
    return {c for c in candidates if c}


def _extract_line_imports(line: str, ext: str) -> set[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return set()
    if stripped.startswith("#") and ext not in {".m", ".mm"}:
        return set()
    found: set[str] = set()
    if ext == ".py":
        m_from = re.match(r"^from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\b", stripped)
        if m_from:
            mod = m_from.group(1).casefold()
            found.add(mod)
            found.add(mod.split(".", 1)[0])
        m_imp = re.match(r"^import\s+(.+)$", stripped)
        if m_imp:
            for part in m_imp.group(1).split(","):
                token = part.strip().split(" as ", 1)[0].strip().casefold()
                if token and re.fullmatch(r"[a-z_][a-z0-9_.]*", token):
                    found.add(token)
                    found.add(token.split(".", 1)[0])
    elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".dart"}:
        for m in re.finditer(r"""(?:from|import)\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)""", stripped):
            spec = (m.group(1) or m.group(2) or "").strip()
            if spec.startswith("package:"):
                spec = spec[len("package:"):]
            if not spec or spec.startswith(".") or spec.startswith("dart:"):
                continue
            low = spec.casefold()
            found.add(low)
            if low.startswith("@"):
                parts = low.split("/")
                if len(parts) >= 2:
                    found.add(f"{parts[0]}/{parts[1]}")
            else:
                found.add(low.split("/", 1)[0])
    elif ext == ".go":
        for m in re.finditer(r'"([A-Za-z0-9._/~+-]+)"', stripped):
            spec = m.group(1).strip().casefold()
            if spec:
                found.add(spec)
                found.add(spec.rsplit("/", 1)[-1])
    elif ext in {".rs", ".php", ".phtml"}:
        m_use = re.match(r"^use\s+(?:function\s+|const\s+)?([A-Za-z0-9_:\\]+)", stripped)
        if m_use:
            raw = m_use.group(1).strip("\\").casefold()
            found.add(raw)
            first = re.split(r"::|\\", raw)[0]
            if first:
                found.add(first)
            if ext != ".rs":  # 20. tur: PHP ad alanı önekleri (composer autoload ad alanlarıyla eşleşir)
                parts = raw.split("\\")
                for i in range(2, min(len(parts), 6)):
                    found.add("\\".join(parts[:i]))
        if ext == ".rs":
            m_ext = re.match(r"^extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)", stripped)
            if m_ext:
                found.add(m_ext.group(1).casefold())
        else:
            for m in re.finditer(r"(?:new\s+|[\s(=,])\\([A-Z][A-Za-z0-9_]*(?:\\[A-Z][A-Za-z0-9_]*)+)", stripped):
                parts = m.group(1).casefold().split("\\")
                for i in range(1, min(len(parts), 6) + 1):
                    found.add("\\".join(parts[:i]))
    elif ext in {".cs", ".cshtml", ".razor", ".vb", ".fs"}:
        m_cs = re.match(r"^(?:global\s+)?@?(?:using|Imports|open)\s+(?:static\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?([A-Za-z_][A-Za-z0-9_.]*)", stripped)
        if m_cs:
            imp = m_cs.group(1).rstrip(".").casefold()
            parts = imp.split(".")
            for i in range(1, min(len(parts) + 1, 7)):
                found.add(".".join(parts[:i]))
    elif ext in {".rb", ".erb", ".rake"}:
        for m in re.finditer(r"""require\s*\(?['"]([^'"]+)['"]\)?""", stripped):
            spec = m.group(1).strip().casefold()
            if spec:
                found.add(spec)
                found.add(spec.split("/", 1)[0])
    elif ext in {".java", ".kt", ".kts", ".scala", ".groovy", ".jsp"}:
        imports = []
        m_jvm = re.match(r"^import\s+(?:static\s+)?([A-Za-z0-9_.]+)", stripped)
        if m_jvm:
            imports.append(m_jvm.group(1))
        if ext == ".jsp":  # <%@ page import="a.b.C, d.e.*" %>
            for m in re.finditer(r"""import\s*=\s*["']([^"']+)["']""", stripped):
                imports.extend(x.strip() for x in m.group(1).split(","))
        for raw_imp in imports:
            imp = raw_imp.rstrip(".*").rstrip(".").casefold()
            if not re.fullmatch(r"[a-z0-9_.]+", imp):
                continue
            found.add(imp)
            parts = imp.split(".")
            for i in range(1, min(len(parts) + 1, 6)):
                found.add(".".join(parts[:i]))
                found.update(parts[:i])
    elif ext == ".swift":
        m_swift = re.match(
            r"^(?:@[A-Za-z_][A-Za-z0-9_]*\s+)*import\s+(?:(?:struct|class|enum|protocol|func|var|let|typealias)\s+)?([A-Za-z_][A-Za-z0-9_.]*)",
            stripped,
        )
        if m_swift:
            mod = m_swift.group(1).casefold()
            found.add(mod)
            found.add(mod.split(".", 1)[0])
    elif ext in {".m", ".mm"}:
        m_objc_hdr = re.match(r'^#import\s*<([A-Za-z0-9_+-]+)/', stripped)
        if m_objc_hdr:
            found.add(m_objc_hdr.group(1).casefold())
        m_objc_mod = re.match(r"^@import\s+([A-Za-z_][A-Za-z0-9_.]*)", stripped)
        if m_objc_mod:
            mod = m_objc_mod.group(1).casefold()
            found.add(mod)
            found.add(mod.split(".", 1)[0])
    return found


def analyze_vulnerability_reachability(
    project_path: str,
    *,
    findings: list[dict[str, Any]] | None = None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    import os

    try:
        root = validate_project_path(project_path, allowed_roots)
    except ProjectRejected as exc:
        raise DependencySecurityError(str(exc)) from exc

    import_index: dict[str, list[dict[str, Any]]] = {}
    scanned_files_count = 0
    seen_suffixes: set[str] = set()  # 20. tur: ekosistem kaynağı var mı ("kullanılmıyor" demek için gerekli)

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            d for d in directories
            if d.casefold() not in _REACHABILITY_SKIP_DIRS and not (Path(current) / d).is_symlink()
        )
        for filename in sorted(files):
            fpath = Path(current) / filename
            if fpath.is_symlink() or not fpath.is_file():
                continue
            ext = fpath.suffix.casefold()
            if ext not in _REACHABILITY_SOURCE_EXTENSIONS:
                continue
            try:
                if fpath.stat().st_size > 1_000_000:
                    continue
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned_files_count += 1
            seen_suffixes.add(ext)
            rel_path = str(fpath.relative_to(root))
            for line_no, raw_line in enumerate(content.splitlines(), start=1):
                for ident in _extract_line_imports(raw_line, ext):
                    sites = import_index.setdefault(ident, [])
                    if len(sites) < 25:
                        sites.append({"file": rel_path, "line": line_no})

    target_entries: list[dict[str, Any]]
    if findings:
        target_entries = list(findings)
    else:
        _, discovered = discover_components(project_path, allowed_roots=allowed_roots)
        target_entries = list(discovered)

    items: list[dict[str, Any]] = []
    reachable_count = 0

    # Sembol düzeyi (açıklı fonksiyon kullanılıyor mu): dependency_reachability; ağ yok, yalnız okuma.
    import dependency_reachability as dr

    package_names = {
        str(e.get("package_name") or e.get("name") or "").strip()
        for e in target_entries if isinstance(e, dict)
    } - {""}
    package_aliases: dict[str, set[str]] = {}
    if package_names:
        alias_owners: dict[str, set[str]] = {}
        for alias_map in (
            dr.cargo_dependency_aliases(root, _REACHABILITY_SKIP_DIRS),
            dr.npm_dependency_aliases(root, _REACHABILITY_SKIP_DIRS),
        ):
            for package, aliases in alias_map.items():
                for alias in aliases:
                    alias_owners.setdefault(alias, set()).add(package)
        for alias, owners in alias_owners.items():
            if len(owners) == 1:
                package_aliases.setdefault(next(iter(owners)), set()).add(alias)

    def import_candidates(name: str) -> set[str]:
        return _candidate_import_names(name, package_aliases)

    hints: set[str] = set()
    for name in package_names:
        hints |= import_candidates(name)
    usage = (dr.build_usage_index(root, _REACHABILITY_SKIP_DIRS, packages_hint=hints, packages=package_names)
             if package_names else dr.UsageIndex())
    # Kodda içe aktarılan paketler (yükleyici → sürücü ilişkisi için)
    used_packages = {
        name.casefold() for name in set(package_names) | set(dr.LOADER_PACKAGES)
        if usage.for_package(import_candidates(name))
        or any(import_index.get(cand) for cand in import_candidates(name))
    }
    offline_osv = dr.OfflineOSV()
    direct_names = dr.direct_dependencies(root, _REACHABILITY_SKIP_DIRS) if package_names else set()
    verdict_counts = {key: 0 for key in dr.VERDICT_LABELS}
    # 20. tur: PHP composer autoload ad alanları ve Ruby Bundler.require (Gemfile'daki gem'ler açılışta yüklenir)
    php_namespaces = dr.composer_namespaces(root) if package_names else {}
    bundler_loaded = dr.bundler_autorequired(root) if package_names else {}
    npm_tools = dr.npm_tool_mentions(root, package_names) if package_names else {}
    cli_tools = dr.cli_tool_mentions(root, package_names, _REACHABILITY_SKIP_DIRS) if package_names else {}
    jvm_tokens: dict[str, set[str]] = {}
    for name in package_names:
        if ":" in name:  # Maven: JDBC adresi/sürücü sınıfı ya da en az iki parçalı paket öneki yapılandırmada
            toks = {t for t in import_candidates(name) if t.count(".") >= 1 and ":" not in t and len(t) >= 6}
            toks |= set(dr.JDBC_SCHEMES.get(name.casefold(), ()))
            if toks:
                jvm_tokens[name.casefold()] = toks
    jvm_config = dr.jvm_config_mentions(root, jvm_tokens, _REACHABILITY_SKIP_DIRS) if jvm_tokens else {}
    usage_counts = {key: 0 for key in dr.USAGE_LABELS}

    for entry in target_entries:
        if not isinstance(entry, dict):
            continue
        pkg_name = str(entry.get("package_name") or entry.get("name") or "").strip()
        if not pkg_name:
            continue
        candidates = import_candidates(pkg_name)
        ecosystem = dr.normalize_ecosystem(entry.get("target") or entry.get("ecosystem"))
        if not ecosystem:
            ecosystem = ("maven" if ":" in pkg_name else "go" if dr.is_go_module(pkg_name) else "")
        if pkg_name.casefold() in php_namespaces:
            # composer.lock autoload ad alanı bilinen paket: satıcı öneki ("guzzlehttp") aynı satıcının başka paketlerinin
            # kullanımını bu pakete yazdırmasın — yalnız kendi ad alanları ve paket adı.
            candidates = {pkg_name.casefold()} | php_namespaces[pkg_name.casefold()]
        matched_sites: list[dict[str, Any]] = []
        seen_sites: set[tuple[str, int]] = set()
        index_keys = set(candidates)
        if dr.is_go_module(pkg_name):  # alt paket içe aktarmaları (golang.org/x/net/html) modülün kullanımıdır
            low = pkg_name.strip().casefold()
            index_keys |= {k for k in import_index if k.startswith(low + "/")}
        for cand in sorted(index_keys):
            for site in import_index.get(cand, ()):
                key = (site["file"], site["line"])
                if key not in seen_sites:
                    seen_sites.add(key)
                    matched_sites.append(site)
                    if len(matched_sites) >= 10:
                        break
            if len(matched_sites) >= 10:
                break
        is_reachable = len(matched_sites) > 0
        if is_reachable:
            reachable_count += 1
        item_out = dict(entry)
        item_out.setdefault("package_name", pkg_name)
        item_out["reachable"] = is_reachable
        item_out["reachability_status"] = (
            "reachable_in_source" if is_reachable else "not_imported_in_source"
        )
        item_out["call_sites"] = matched_sites
        uses = usage.for_package(candidates)
        imported = is_reachable or bool(uses)
        indirect = None if imported else dr.indirect_use(pkg_name, usage, used_packages)
        if not imported and indirect is None and ecosystem in {"rubygems", ""} and pkg_name.casefold() in bundler_loaded:
            indirect = dict(bundler_loaded[pkg_name.casefold()])
        if not imported and indirect is None and ecosystem in {"npm", ""} and pkg_name.casefold() in npm_tools:
            indirect = dict(npm_tools[pkg_name.casefold()])
        if not imported and indirect is None and pkg_name.casefold() in jvm_config:
            indirect = dict(jvm_config[pkg_name.casefold()])
        if not imported and indirect is None and ecosystem in {"pypi", "npm", "rubygems", ""} \
                and pkg_name.casefold() in cli_tools:
            indirect = dict(cli_tools[pkg_name.casefold()])
        key = pkg_name.casefold().replace("_", "-")
        direct = (key in direct_names or pkg_name.casefold() in direct_names) if direct_names else None
        item_out["reachability"] = dr.assess_item(item_out, candidates, uses, imported, offline_osv, indirect, direct,
                                                  classpath=ecosystem in dr.CLASSPATH_ECOSYSTEMS)
        verdict_counts[item_out["reachability"]["verdict"]] += 1
        suffixes = dr.ECOSYSTEM_SOURCE_SUFFIXES.get(ecosystem)
        analyzable = bool(seen_suffixes & suffixes) if suffixes else scanned_files_count > 0
        state = dr.usage_state(imported or indirect is not None, direct, analyzable)
        usage_counts[state] += 1
        evidence = matched_sites[:5] or list(item_out["reachability"].get("evidence") or [])[:5]
        item_out["usage"] = {"state": state, "label": dr.USAGE_LABELS[state], "ecosystem": ecosystem,
                             "evidence": evidence}
        item_out["reachability"]["usage"] = state
        item_out["priority"] = dr.priority(item_out, item_out["reachability"], state)
        items.append(item_out)
    offline_osv.close()
    prioritized = sorted(items, key=dr.priority_sort_key)
    by_score = sorted(items, key=dr.priority_order_key)
    tier_counts = {tier: 0 for tier in dr.PRIORITY_TIERS}
    for it in items:
        tier_counts[it["priority"]["tier"]] += 1

    return {
        "format": "sniper-vulnerability-reachability-v1",
        "symbol_analysis": {
            "engines": sorted(usage.engine),
            "verdict_counts": verdict_counts,
            "verdict_labels": dict(dr.VERDICT_LABELS),
            "downgraded_count": sum(
                1 for it in items if it["reachability"]["effective_severity"] != it["reachability"]["base_severity"]
            ),
            "priority_order": [
                {"package_name": it.get("package_name"), "vulnerability_id": it.get("vulnerability_id") or it.get("id"),
                 "effective_severity": it["reachability"]["effective_severity"], "verdict": it["reachability"]["verdict"]}
                for it in prioritized
            ][:200],
        },
        # 20. tur: "önce bunları düzelt" sırası (puan: önem × erişilebilirlik × düzeltme × doğrudan/dolaylı)
        "priority": {
            "tiers": tier_counts,
            "tier_labels": dict(dr.PRIORITY_TIERS),
            "usage_counts": usage_counts,
            "usage_labels": dict(dr.USAGE_LABELS),
            "order": [
                {"package_name": it.get("package_name"), "installed_version": it.get("installed_version", ""),
                 "vulnerability_id": it.get("vulnerability_id") or it.get("id"), "score": it["priority"]["score"],
                 "tier": it["priority"]["tier"], "usage": it["usage"]["state"],
                 "verdict": it["reachability"]["verdict"], "fixed_version": it.get("fixed_version", ""),
                 "evidence": it["usage"]["evidence"][:2]}
                for it in by_score
            ][:200],
        },
        "project_path": str(root),
        "project_name": root.name,
        "scanned_source_files": scanned_files_count,
        "total_evaluated": len(items),
        "reachable_count": reachable_count,
        "transitive_only_count": len(items) - reachable_count,
        "items": items,
    }



def offline_vulnerability_findings(project_path: str, *, allowed_roots: tuple[Path, ...] | None = None) -> list[dict[str, Any]]:
    """Çevrimdışı (yerel OSV, çok ekosistem) paket düzeyi açık listesi — ölçüm ve dışa aktarım sözleşmesi:
    ``[{"ecosystem", "name", "version", "ids": [kimlik ve takma adlar]}]``. Kaydetmez; ağ kullanmaz."""
    import osv_offline

    _root, components, _skipped = discover_inventory(project_path, allowed_roots=allowed_roots, lenient=True)
    result = osv_offline.match_components(components)
    rows: list[dict[str, Any]] = []
    for res in result["document"].get("results", []):
        for entry in res.get("packages", []):
            package = entry.get("package") or {}
            ids: set[str] = set()
            for vuln in entry.get("vulnerabilities") or []:
                if vuln.get("id"):
                    ids.add(str(vuln["id"]))
                ids.update(str(a) for a in (vuln.get("aliases") or []) if a)
            if ids:
                rows.append({"ecosystem": package.get("ecosystem", ""), "name": package.get("name", ""),
                             "version": package.get("version", ""), "ids": sorted(ids)})
    return rows
