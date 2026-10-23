"""Opt-in loader and result boundary for locally trusted Sniper plugins.

Güvenlik modeli:
* Dosya izinleri asla "düzeltilmez" (chmod yok). Eklenti dizini ve dosyaları
  süreç UID'sine ait olmalı, grup/diğerleri tarafından yazılabilir olmamalıdır;
  aksi halde reddedilir ve nedeni hatalar listesine yazılır.
* Sembolik bağlar izlenmez (lstat + O_NOFOLLOW); dosya fd üzerinden fstat ile
  doğrulanır ve yükleme fd'den okunan içerikle yapılır (TOCTOU yok).
* Yerleşik eklentiler sabit SHA-256 listesiyle doğrulanır. Diğer (kullanıcı)
  eklentileri yalnız ayrı bir açık izinle yüklenir: SNIPER_ENABLE_USER_PLUGINS=1
  (isteğe bağlı daraltma: SNIPER_USER_PLUGIN_ALLOWLIST=a.py,b.py) ya da
  PluginManager(..., allow_user_plugins=True, user_plugin_allowlist=[...]).
* Her eklenti tarama çağrısı süre sınırlı bir daemon iş parçacığında çalışır.
"""

from __future__ import annotations

import hashlib
import importlib.abc
import importlib.util
import os
from pathlib import Path
import stat
import threading
from types import MappingProxyType, ModuleType
from typing import Any, Iterable

from plugins.base_plugin import BasePlugin


MAX_PLUGIN_FILES = 64
MAX_PLUGIN_BYTES = 256_000
MAX_FINDINGS_PER_PLUGIN = 100
MAX_ERRORS = 100
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
# Tek bir eklenti tarama çağrısının (scan + bulgu doğrulama) üst süresi; sabittir.
PLUGIN_SCAN_TIMEOUT_SECONDS = 30.0
# Yükleme (modül kodu + PLUGIN/create_plugin), initialize() ve cleanup() için süre sınırları.
PLUGIN_LOAD_TIMEOUT_SECONDS = 10.0
PLUGIN_LIFECYCLE_TIMEOUT_SECONDS = 10.0


class PluginTimeout(Exception):
    """Eklenti yaşam döngüsü çağrısı süre sınırını aştı."""


def _call_with_timeout(label: str, func: Any, timeout: float) -> Any:
    """``func``'ı süre sınırlı bir daemon iş parçacığında çalıştırır.

    Python iş parçacıkları zorla durdurulamaz: süre aşılırsa iş parçacığı arka planda kalır,
    sonucu yok sayılır ve :class:`PluginTimeout` yükseltilir (çağıran eklentiyi devre dışı bırakır).
    """
    outcome: dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome["result"] = func()
        except BaseException as exc:  # iş parçacığı dışına sızmasın
            outcome["error"] = exc

    worker = threading.Thread(target=runner, name=f"sniper-plugin-{label[:40]}", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise PluginTimeout(f"zaman aşımı ({timeout:g} sn)")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")
USER_PLUGINS_ENV = "SNIPER_ENABLE_USER_PLUGINS"
USER_PLUGIN_ALLOWLIST_ENV = "SNIPER_USER_PLUGIN_ALLOWLIST"

# Sniper ile gelen yerleşik eklentilerin (plugins/user/) sabit SHA-256 özetleri.
# Bir yerleşik eklenti değiştirilirse bu liste de bilinçli olarak güncellenmelidir;
# uyuşmayan içerik yüklenmez.
BUILTIN_PLUGIN_SHA256: MappingProxyType = MappingProxyType(
    {
        "api_surface_target_advisor.py": "3aa73f92b9a03fcd178a5f21000a3fd21440f5e3ac10eb5ecc0e37b61d2d4ab7",
        "cross_origin_isolation_advisor.py": "bf68c18fb9493b3e5a32b1c4336ebe588e388c14fb2c7b05cbaf9cb95f0b62eb",
        "ip_literal_target_advisor.py": "3cb852f9940a2396af4ee4fa624fbb9345104185580ccaadda4a21f502c2372e",
        "zero_trust_transport_advisor.py": "631196095f3978bea318076e87016a21dea034347f88074fa9b3276ad53bf984",
    }
)

_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH


class _VerifiedSourceLoader(importlib.abc.SourceLoader):
    """Önceden doğrulanmış (hash ve izin denetiminden geçmiş) kaynak baytlarını sunar."""

    def __init__(self, source: bytes, origin: str) -> None:
        self._source = source
        self._origin = origin

    def get_filename(self, fullname: str) -> str:
        return self._origin

    def get_data(self, path: str) -> bytes:
        if path != self._origin:
            raise OSError("Beklenmeyen eklenti verisi isteği.")
        return self._source

    def path_stats(self, path: str) -> dict:
        raise OSError("Bayt önbelleği kullanılmaz.")

    def set_data(self, path: str, data: bytes, *, _mode: int = 0o666) -> None:
        return None


class PluginManager:
    def __init__(
        self,
        directory: Path,
        *,
        enabled: bool = False,
        config: dict[str, dict[str, Any]] | None = None,
        allow_user_plugins: bool | None = None,
        user_plugin_allowlist: Iterable[str] | None = None,
    ) -> None:
        self.directory = directory.resolve()
        self.enabled = enabled
        self.config = config or {}
        # None => ortam değişkeninden (SNIPER_ENABLE_USER_PLUGINS=1) okunur.
        self.allow_user_plugins = allow_user_plugins
        self.user_plugin_allowlist = (
            frozenset(user_plugin_allowlist) if user_plugin_allowlist is not None else None
        )
        self._plugins: dict[str, BasePlugin] = {}
        self._errors: list[str] = []
        self._hung_scans: dict[str, threading.Thread] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ izinler
    def user_plugins_allowed(self) -> bool:
        if self.allow_user_plugins is not None:
            return bool(self.allow_user_plugins)
        return os.getenv(USER_PLUGINS_ENV, "0") == "1"

    def _user_allowlist(self) -> frozenset[str] | None:
        if self.user_plugin_allowlist is not None:
            return self.user_plugin_allowlist
        raw = os.getenv(USER_PLUGIN_ALLOWLIST_ENV, "").strip()
        if not raw:
            return None
        return frozenset(item.strip() for item in raw.split(",") if item.strip())

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._errors.append(message)
            self._errors = self._errors[-MAX_ERRORS:]

    # ------------------------------------------------------------------ yükleme
    def reload(self) -> None:
        with self._lock:
            self._errors = []
            for plugin_name, plugin in self._plugins.items():
                try:
                    _call_with_timeout(f"{plugin_name}-cleanup", plugin.cleanup, PLUGIN_LIFECYCLE_TIMEOUT_SECONDS)
                except PluginTimeout:
                    self._errors.append(f"{plugin_name}: cleanup() zaman aşımı; eklenti bırakıldı.")
                except Exception:
                    pass
            self._plugins = {}
            self._hung_scans = {}
            if not self.enabled:
                return
            try:
                dir_fd = self._open_plugin_directory()
            except Exception as exc:
                self._errors.append(f"Eklenti dizini: {type(exc).__name__}: {str(exc)[:180]}")
                return
            try:
                self._load_from_directory(dir_fd)
            finally:
                os.close(dir_fd)

    def _open_plugin_directory(self) -> int:
        # Yalnız yoksa oluşturulur; mevcut dizinin izinleri asla değiştirilmez.
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            dir_fd = os.open(self.directory, flags)
        except OSError as exc:
            raise PermissionError(
                "Eklenti dizini açılamadı (sembolik bağ veya erişilemez dizin); eklentiler yüklenmedi."
            ) from exc
        try:
            details = os.fstat(dir_fd)
            if not stat.S_ISDIR(details.st_mode):
                raise PermissionError("Eklenti yolu bir dizin değil; eklentiler yüklenmedi.")
            if details.st_uid != os.geteuid():
                raise PermissionError(
                    "Eklenti dizininin sahibi bu süreç kullanıcısı değil; eklentiler yüklenmedi."
                )
            if details.st_mode & _WRITABLE_BY_OTHERS:
                raise PermissionError(
                    "Eklenti dizini grup veya diğer kullanıcılarca yazılabilir; eklentiler yüklenmedi. "
                    "İzni elle 0700 yapın (Sniper izinleri kendisi değiştirmez)."
                )
        except BaseException:
            os.close(dir_fd)
            raise
        return dir_fd

    def _load_from_directory(self, dir_fd: int) -> None:
        names = sorted(
            name for name in os.listdir(dir_fd) if name.endswith(".py") and not name.startswith("_")
        )
        if len(names) > MAX_PLUGIN_FILES:
            self._errors.append(f"En fazla {MAX_PLUGIN_FILES} eklenti dosyası yüklenebilir.")
            names = names[:MAX_PLUGIN_FILES]
        user_allowed = self.user_plugins_allowed()
        allowlist = self._user_allowlist()
        skipped_user: list[str] = []
        for name in names:
            builtin = name in BUILTIN_PLUGIN_SHA256
            if not builtin:
                if not user_allowed:
                    skipped_user.append(name)
                    continue
                if allowlist is not None and name not in allowlist:
                    self._errors.append(f"{name}: kullanıcı eklentisi izin listesinde değil; yüklenmedi.")
                    continue
            try:
                source = self._read_plugin_source(dir_fd, name)
                digest = hashlib.sha256(source).hexdigest()
                if builtin and digest != BUILTIN_PLUGIN_SHA256[name]:
                    raise PermissionError(
                        "Yerleşik eklenti bütünlük denetimi başarısız (SHA-256 uyuşmuyor); yüklenmedi."
                    )
                plugin = _call_with_timeout(
                    f"{name}-load", lambda: self._load_source(name, source, digest, builtin=builtin),
                    PLUGIN_LOAD_TIMEOUT_SECONDS,
                )
                plugin_name = plugin.info.name.strip()
                if not plugin_name or len(plugin_name) > 80:
                    raise ValueError("Eklenti adı boş veya çok uzun.")
                if plugin_name in self._plugins:
                    raise ValueError(f"Yinelenen eklenti adı: {plugin_name}")
                settings = dict(self.config.get(plugin_name, {}))
                _call_with_timeout(
                    f"{plugin_name}-init", lambda: plugin.initialize(settings), PLUGIN_LIFECYCLE_TIMEOUT_SECONDS
                )
                self._plugins[plugin_name] = plugin
            except Exception as exc:
                self._errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:180]}")
        if skipped_user:
            listed = ", ".join(skipped_user[:5]) + (" …" if len(skipped_user) > 5 else "")
            self._errors.append(
                f"{len(skipped_user)} kullanıcı eklentisi yüklenmedi ({listed}): yalnız yerleşik eklentiler "
                f"etkin; kullanıcı eklentileri için ayrı açık izin ({USER_PLUGINS_ENV}=1) gerekir."
            )

    @staticmethod
    def _check_owner_and_mode(details: os.stat_result) -> None:
        if details.st_mode & _WRITABLE_BY_OTHERS:
            raise PermissionError("Grup veya diğer kullanıcılarca yazılabilen eklenti reddedildi.")
        if details.st_uid != os.geteuid():
            raise PermissionError("Eklenti dosyasının sahibi bu süreç kullanıcısı değil; reddedildi.")

    def _read_plugin_source(self, dir_fd: int, name: str) -> bytes:
        if "/" in name or name in {".", ".."} or not name.endswith(".py"):
            raise ValueError("Eklenti yolu izin verilen dizinin dışında.")
        before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise PermissionError("Sembolik bağ olan eklenti atlandı (bağlar izlenmez).")
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Eklenti normal bir dosya değil.")
        self._check_owner_and_mode(before)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, dir_fd=dir_fd)
        except OSError as exc:
            raise PermissionError("Eklenti dosyası güvenli biçimde açılamadı (O_NOFOLLOW).") from exc
        try:
            details = os.fstat(fd)
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("Eklenti normal bir dosya değil.")
            if (details.st_dev, details.st_ino) != (before.st_dev, before.st_ino):
                raise PermissionError("Eklenti dosyası denetim sırasında değişti; reddedildi.")
            self._check_owner_and_mode(details)
            if details.st_size > MAX_PLUGIN_BYTES:
                raise ValueError("Eklenti dosyası boyut sınırını aşıyor.")
            chunks: list[bytes] = []
            remaining = MAX_PLUGIN_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            source = b"".join(chunks)
            if len(source) > MAX_PLUGIN_BYTES:
                raise ValueError("Eklenti dosyası boyut sınırını aşıyor.")
            return source
        finally:
            os.close(fd)

    def _load_source(self, name: str, source: bytes, digest: str, *, builtin: bool) -> BasePlugin:
        stem = name[:-3]
        origin = str(self.directory / name)
        kind = "builtin" if builtin else "user"
        module_name = f"sniper_{kind}_plugin_{stem}_{digest[:16]}"
        # Kod, doğrulanan fd'den okunan baytlardan yüklenir; yol yeniden açılmaz.
        loader = _VerifiedSourceLoader(source, origin)
        spec = importlib.util.spec_from_loader(module_name, loader=loader, origin=origin)
        if spec is None:
            raise ImportError("Eklenti modülü açılamadı.")
        module = importlib.util.module_from_spec(spec)
        module.__file__ = origin
        loader.exec_module(module)
        return self._plugin_from_module(module)

    @staticmethod
    def _plugin_from_module(module: ModuleType) -> BasePlugin:
        candidate = getattr(module, "PLUGIN", None)
        if candidate is None:
            factory = getattr(module, "create_plugin", None)
            if not callable(factory):
                raise ValueError("PLUGIN nesnesi veya create_plugin() fabrikası gerekli.")
            candidate = factory()
        if not isinstance(candidate, BasePlugin):
            raise TypeError("Eklenti BasePlugin sınıfından türemelidir.")
        return candidate

    # ------------------------------------------------------------------ tarama
    def scan_all(self, target: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        with self._lock:
            plugins = list(self._plugins.items())
        for name, plugin in plugins:
            with self._lock:
                hung = self._hung_scans.get(name)
                if hung is not None:
                    if hung.is_alive():
                        self._record_error(
                            f"{name} tarama hatası: önceki çağrı zaman aşımından sonra hâlâ sürüyor; eklenti atlandı."
                        )
                        continue
                    del self._hung_scans[name]
            outcome = self._run_plugin_scan(name, plugin, target)
            if outcome is None:
                continue
            plugin_findings, original_count = outcome
            if original_count > MAX_FINDINGS_PER_PLUGIN:
                self._record_error(
                    f"{name}: bulgu sayısı {original_count} > {MAX_FINDINGS_PER_PLUGIN} ve kesildi."
                )
            findings.extend(plugin_findings)
        return findings

    def _run_plugin_scan(
        self, name: str, plugin: BasePlugin, target: str
    ) -> tuple[list[dict[str, Any]], int] | None:
        """Eklentiyi süre sınırlı bir daemon iş parçacığında çalıştırır; hata/zaman aşımında None."""
        outcome: dict[str, Any] = {}

        def runner() -> None:
            try:
                rows = plugin.scan(target)
                if not isinstance(rows, list):
                    raise TypeError("scan() bir liste döndürmelidir.")
                validated = [self._validated_finding(name, row) for row in rows[:MAX_FINDINGS_PER_PLUGIN]]
                outcome["result"] = (validated, len(rows))
            except BaseException as exc:  # iş parçacığı dışına sızmasın
                outcome["error"] = exc

        timeout = float(PLUGIN_SCAN_TIMEOUT_SECONDS)
        worker = threading.Thread(target=runner, name=f"sniper-plugin-{name[:40]}", daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            with self._lock:
                self._hung_scans[name] = worker
            self._record_error(
                f"{name} tarama hatası: zaman aşımı ({timeout:g} sn); sonuç yok sayıldı."
            )
            return None
        if "error" in outcome:
            self._record_error(f"{name} tarama hatası: {type(outcome['error']).__name__}")
            return None
        if "result" not in outcome:
            self._record_error(f"{name} tarama hatası: sonuç üretilmedi")
            return None
        return outcome["result"]

    @staticmethod
    def _validated_finding(plugin_name: str, row: Any) -> dict[str, Any]:
        if not isinstance(row, dict):
            raise TypeError("Her eklenti bulgusu bir nesne olmalıdır.")
        severity = str(row.get("severity", "info")).strip().lower()
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError("Geçersiz bulgu önem derecesi.")
        import hashlib
        # title ilk kontrol edilir, boştansa hiçbir sonraki alan işlenmez (kurulu davranış)
        title_val = str(row.get("title", "")).strip()[:240]
        if not title_val:
            raise ValueError("title alanı zorunludur.")
        # title geçerse description kontrol edilir, boştansa evidence ve sonrası işlenmez
        description_val = str(row.get("description", "")).strip()[:4000]
        if not description_val:
            raise ValueError("description alanı zorunludur.")
        # title/description kontrollerinden SONRA evidence ve sonraki alanlar işlenir
        evidence_val = str(row.get("evidence", "")).strip()[:4000]
        recommendation_val = str(row.get("recommendation", "")).strip()[:4000]
        reference_val = str(row.get("reference", "")).strip()[:500]
        # raw_id erişimi ve truthiness kararı category str() çağrısından ÖNCE, bir kez
        raw_id = row.get("id")
        if raw_id:
            # Truthy açık ID: category dönüşümünden ÖNCE bir kez str() yap
            finding_id = str(raw_id)[:160]
            # Zaten yakalanan category_str değerini kullan
            category_str_for_return = str(row.get("category", "plugin"))[:120]
        else:
            # Fallback: raw_id false, category bir kez yakala
            category_val = str(row.get("category", "plugin"))[:120]
            combined = f"{len(plugin_name)}:{plugin_name}|{len(title_val)}:{title_val}|{len(evidence_val)}:{evidence_val}|{len(category_val)}:{category_val}|{len(reference_val)}:{reference_val}"
            finding_id = f"plugin-{hashlib.sha256(combined.encode('utf-8')).hexdigest()[:40]}"
            category_str_for_return = category_val
        # Zaten yakalanan değerleri kullan
        required = {
            "title": title_val,
            "description": description_val,
            "evidence": evidence_val,
            "recommendation": recommendation_val,
            "reference": reference_val,
        }
        return {
            "id": finding_id[:160],
            "severity": severity,
            "category": category_str_for_return,
            **required,
            "owasp": str(row.get("owasp", ""))[:160],
            "cwe": str(row.get("cwe", ""))[:32],
            "detection": "trusted-local-plugin",
            "confidence": str(row.get("confidence", "medium"))[:20],
            "plugin": plugin_name,
        }

    def public_status(self) -> dict[str, Any]:
        with self._lock:
            plugins = [plugin.info.public_dict() for plugin in self._plugins.values()]
            errors = list(self._errors[-20:])
        return {
            "enabled": self.enabled,
            "user_plugins_allowed": self.user_plugins_allowed(),
            "loaded": len(plugins),
            "plugins": plugins,
            "errors": errors,
        }

    @property
    def loaded_count(self) -> int:
        with self._lock:
            return len(self._plugins)
