"""Sniper öz sağlık raporu (salt okunur).

Disk ve veri dizini, veritabanı boyutu ve ``PRAGMA quick_check``, en son veritabanı yedeğinin yaşı, çevrimdışı OSV
veritabanı tazeliği, servis çalışma/otomatik başlama durumu, zamanlanmış taramaların son durumu, iş kuyruğu birikmesi, denetim zinciri, araç pinleri,
sürüm/güncelleme durumu ve giriş güvenliği (giriş açık mı, yöneticilerde TOTP, ilk parola dosyası) denetlenir.

Rapor hiçbir şeyi silmez, değiştirmez ya da düzeltmez; yalnız durum ve öneri döndürür. Pahalı denetimler
(araç pinlerinin SHA-256'sı, ``quick_check``) süreç içinde önbelleğe alınır. Günlük denetim ``daily_check`` ile
zamanlayıcıdan çağrılır; sorun varsa (yeni sorun ya da 24 saattir süren sorun) bildirim merkezine düşer.
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

FORMAT = "sniper-system-health-v1"
STATE_FILE = "system-health-state.json"
STATUS_ORDER = {"ok": 0, "info": 0, "unknown": 1, "warn": 2, "fail": 3}
STATUS_LABELS = {"ok": "Tamam", "info": "Bilgi", "unknown": "Bilinmiyor", "warn": "Uyarı", "fail": "Sorun"}
THRESHOLDS = {
    "disk_free_warn_pct": 15.0, "disk_free_fail_pct": 5.0,
    "db_warn_mb": 2048.0, "data_warn_mb": 20480.0,
    "backup_warn_days": 7.0, "backup_fail_days": 30.0, "backup_count_warn": 30, "backup_warn_mb": 1024.0,
    "osv_warn_hours": 24.0 * 8, "osv_fail_hours": 24.0 * 31,
    "queue_warn": 10, "queue_age_warn_minutes": 60.0,
}
INITIAL_PASSWORD_FILE = Path(".config") / "sniper" / "ilk-yonetici-parolasi.txt"
CHECK_INTERVAL_SECONDS = 24 * 3600
REMIND_SECONDS = 24 * 3600
_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_LOCK = threading.Lock()
FAILED_SCHEDULE_STATES = {"failed", "expired", "interrupted", "submit_failed", "invalid_frequency", "cancelled"}


def _cached(key: str, ttl: float, compute: Callable[[], Any], refresh: bool = False) -> Any:
    now = time.monotonic()
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and not refresh and now - hit[0] < ttl:
            return hit[1]
    value = compute()
    with _CACHE_LOCK:
        _CACHE[key] = (now, value)
    return value


def _check(check_id: str, label: str, status: str, value: str, detail: str = "", recommendation: str = "") -> dict[str, Any]:
    return {"id": check_id, "label": label, "status": status, "status_label": STATUS_LABELS[status],
            "value": value, "detail": detail, "recommendation": recommendation}


def _mb(size: float) -> str:
    return f"{size / 1048576:.1f} MB"


def _dir_size(path: Path, limit: int = 50_000) -> tuple[int, bool]:
    total, seen = 0, 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            seen += 1
            if seen > limit:
                return total, True
            try:
                info = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            total += info.st_size
    return total, False


def _age_text(seconds: float) -> str:
    if seconds < 3600:
        return f"{max(0, int(seconds // 60))} dk"
    if seconds < 172_800:
        return f"{seconds / 3600:.1f} sa"
    return f"{seconds / 86400:.1f} gün"


# ---------------------------------------------------------------------------
# Tek tek denetimler
# ---------------------------------------------------------------------------
def check_disk(data_dir: Path) -> list[dict[str, Any]]:
    out = []
    try:
        usage = shutil.disk_usage(data_dir)
        free_pct = usage.free / usage.total * 100 if usage.total else 0.0
        status = ("fail" if free_pct < THRESHOLDS["disk_free_fail_pct"]
                  else "warn" if free_pct < THRESHOLDS["disk_free_warn_pct"] else "ok")
        out.append(_check("disk_free", "Disk boş alanı", status, f"%{free_pct:.1f} boş ({usage.free / 1073741824:.1f} GB)",
                          "Veri dizininin bulunduğu dosya sistemi.",
                          "" if status == "ok" else "Eski rapor/yedekleri gözden geçirin ya da diski genişletin; Sniper "
                                                    "kendiliğinden hiçbir şey silmez."))
    except OSError:
        out.append(_check("disk_free", "Disk boş alanı", "unknown", "okunamadı"))
    size, truncated = _dir_size(data_dir)
    status = "warn" if size / 1048576 > THRESHOLDS["data_warn_mb"] else "ok"
    out.append(_check("data_dir", "Veri dizini boyutu", status, _mb(size) + (" (en az)" if truncated else ""),
                      str(data_dir), "Eski yedekleri arşivleyin." if status != "ok" else ""))
    return out


def check_database(data_dir: Path, *, refresh: bool = False) -> list[dict[str, Any]]:
    db = data_dir / "sniper.db"
    if not db.is_file():
        return [_check("database", "Veritabanı", "unknown", "sniper.db yok", str(db))]
    size = sum((data_dir / name).stat().st_size for name in ("sniper.db", "sniper.db-wal", "sniper.db-shm")
               if (data_dir / name).is_file())

    def quick_check() -> str:
        try:
            connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
            try:
                rows = connection.execute("PRAGMA quick_check(5)").fetchall()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            return f"hata: {type(exc).__name__}"
        return "ok" if rows == [("ok",)] else "; ".join(str(r[0]) for r in rows)[:300]

    result = _cached(f"quick_check:{db}", 900, quick_check, refresh)
    status = "fail" if result != "ok" else ("warn" if size / 1048576 > THRESHOLDS["db_warn_mb"] else "ok")
    return [_check("database", "Veritabanı bütünlüğü ve boyutu", status, f"{_mb(size)} · quick_check: {result}",
                   "Salt okunur PRAGMA quick_check (15 dk önbellek).",
                   "Bütünlük hatasında servisi durdurup en son yedekten geri dönmeyi değerlendirin (documented Community recovery procedure --rollback "
                   "ya da DB yedeği)." if result != "ok" else
                   ("Veritabanı büyük; eski analizleri arşivlemeyi düşünün." if status == "warn" else ""))]


def _backup_times(data_dir: Path, app_root: Path | None) -> list[tuple[float, str]]:
    found: list[tuple[float, str]] = []
    try:
        for path in data_dir.glob("sniper.db.bak*"):
            if path.is_file() and not path.is_symlink():
                found.append((path.stat().st_mtime, path.name))
    except OSError:
        pass
    if app_root is not None:
        try:
            import community_release_info

            for item in community_release_info.list_backups(Path(app_root).parent / "backups"):
                if item.get("has_db") and item.get("created_at"):
                    try:
                        moment = dt.datetime.fromisoformat(str(item["created_at"]).replace("Z", "+00:00")).timestamp()
                    except ValueError:
                        continue
                    found.append((moment, str(item.get("id"))))
        except Exception:  # noqa: BLE001
            pass
    return sorted(found, reverse=True)


def check_backups(data_dir: Path, app_root: Path | None, now: float) -> list[dict[str, Any]]:
    backups = _backup_times(data_dir, app_root)
    if not backups:
        return [_check("db_backup", "Veritabanı yedeği", "warn", "yedek bulunamadı", "",
                       "Tutarlı yedek alın: sqlite3 sniper.db \".backup sniper.db.bak-<tarih>\" (güncelleme aracı her "
                       "güncellemede otomatik yedek alır).")]
    newest, name = backups[0]
    age = now - newest
    days = age / 86400
    status = "fail" if days > THRESHOLDS["backup_fail_days"] else "warn" if days > THRESHOLDS["backup_warn_days"] else "ok"
    return [_check("db_backup", "En son veritabanı yedeği", status, f"{_age_text(age)} önce", f"{name} · toplam {len(backups)} yedek",
                   "" if status == "ok" else "Yeni bir tutarlı veritabanı yedeği alın.")]


def check_backup_storage(data_dir: Path, environ: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Birikmiş gevşek DB yedekleri (sayı, boyut), başkalarınca okunabilen yedek ve döndürme politikası durumu."""
    import data_retention

    summary = data_retention.backup_summary(data_dir)
    out: list[dict[str, Any]] = []
    try:
        policy = data_retention.load_policy(environ if environ is not None else {"SNIPER_DATA_DIR": str(data_dir)})
        rotation = "açık" if policy["enabled"] else "kapalı"
    except Exception:  # noqa: BLE001
        policy, rotation = None, "bilinmiyor"
    heavy = summary["count"] > THRESHOLDS["backup_count_warn"] or summary["bytes"] > THRESHOLDS["backup_warn_mb"] * 1024 * 1024
    status = "warn" if heavy and not (policy and policy["enabled"]) else "info"
    out.append(_check("db_backup_storage", "Birikmiş veritabanı yedekleri", status,
                      f"{summary['count']} yedek · {_mb(summary['bytes'])} · döndürme {rotation}",
                      f"{summary['named']} etiketli (elle alınmış) yedek varsayılan döndürmede korunur.",
                      "İşlem geçmişi › Saklama ve yedekler bölümünden önizleyip döndürmeyi açın." if status == "warn" else ""))
    if summary["world_readable"]:
        names = summary["world_readable"]
        out.append(_check("db_backup_permissions", "Yedek dosya izinleri", "warn",
                          f"{len(names)} yedek başkalarınca okunabilir", ", ".join(names[:5]) + (" …" if len(names) > 5 else ""),
                          "Bu yedeklerin izinlerini 0600 yapın (chmod 600); Sniper izinleri kendisi değiştirmez."))
    return out


def check_osv(now_dt: dt.datetime) -> list[dict[str, Any]]:
    try:
        import osv_db_refresh

        info = osv_db_refresh.status("npm", now=now_dt)
    except Exception as exc:  # noqa: BLE001
        return [_check("osv_db", "Çevrimdışı OSV veritabanı", "unknown", type(exc).__name__)]
    if info.get("status") != "present":
        return [_check("osv_db", "Çevrimdışı OSV veritabanı", "warn", "yok",
                       "Bağımlılık açıkları çevrimdışı denetlenemez.",
                       "scripts/osv_refresh.py ile indirin ya da sniper-osv-refresh.timer'ı etkinleştirin.")]
    if info.get("signature_valid") is False:
        return [_check("osv_db", "Çevrimdışı OSV veritabanı", "fail", "imza doğrulanamadı",
                       "Manifest HMAC'i uyuşmuyor.", "OSV veritabanını yeniden indirin.")]
    age_hours = info.get("age_hours")
    if age_hours is None:
        return [_check("osv_db", "Çevrimdışı OSV veritabanı", "unknown", "yaş okunamadı")]
    status = ("fail" if age_hours > THRESHOLDS["osv_fail_hours"]
              else "warn" if age_hours > THRESHOLDS["osv_warn_hours"] else "ok")
    return [_check("osv_db", "Çevrimdışı OSV veritabanı tazeliği", status, f"{_age_text(age_hours * 3600)} önce",
                   f"nesil {info.get('generation') or '?'}",
                   "" if status == "ok" else "OSV veritabanını tazeleyin (zamanlayıcı çalışıyor mu kontrol edin).")]


def check_osv_ecosystems(now_dt: dt.datetime) -> list[dict[str, Any]]:
    """18. tur: npm dışındaki ekosistemlerin çevrimdışı OSV veritabanları (PyPI, Go, Maven …)."""
    try:
        import osv_offline

        items = [i for i in osv_offline.database_status(now=now_dt) if i.get("ecosystem") != "npm"]
    except Exception as exc:  # noqa: BLE001
        return [_check("osv_db_ecosystems", "Çevrimdışı OSV (diğer ekosistemler)", "unknown", type(exc).__name__)]
    ok = [i["ecosystem"] for i in items if i.get("status") == "ok"]
    stale = [i["ecosystem"] for i in items if i.get("status") == "stale"]
    untrusted = [i["ecosystem"] for i in items if i.get("status") == "untrusted"]
    missing = [i["ecosystem"] for i in items if i.get("status") == "missing"]
    if untrusted:
        return [_check("osv_db_ecosystems", "Çevrimdışı OSV (diğer ekosistemler)", "fail",
                       f"doğrulanamayan: {', '.join(untrusted)}", "Manifest imzası ya da arşiv özeti uyuşmuyor.",
                       "scripts/osv_refresh.py ile ilgili ekosistemleri yeniden indirin.")]
    if not ok and not stale:
        return [_check("osv_db_ecosystems", "Çevrimdışı OSV (diğer ekosistemler)", "info", "yok",
                       "Python/Java/Go/Ruby/PHP/Rust/.NET bağımlılıkları çevrimdışı denetlenemez.",
                       "scripts/osv_refresh.py (varsayılan liste) ile indirin.")]
    status = "warn" if stale else "ok"
    detail = f"güncel: {', '.join(ok) or '-'}" + (f"; bayat: {', '.join(stale)}" if stale else "")
    return [_check("osv_db_ecosystems", "Çevrimdışı OSV (diğer ekosistemler)", status,
                   f"{len(ok)}/{len(items)} güncel", detail + (f"; eksik: {', '.join(missing)}" if missing else ""),
                   "" if status == "ok" else "OSV veritabanlarını tazeleyin (zamanlayıcı çalışıyor mu kontrol edin).")]


# ---------------------------------------------------------------------------
# 21. tur: OSV ekosistem tazeliği (ekosistem başına), malware önbelleği, lisans önbellekleri, OSV zamanlayıcısı
# ---------------------------------------------------------------------------
def osv_freshness_items(now_dt: dt.datetime, root: Path | None = None) -> list[dict[str, Any]]:
    """Ekosistem başına manifest yaşı ve imza durumu (arşiv özeti hesaplanmaz; ucuz)."""
    import osv_db_refresh

    out: list[dict[str, Any]] = []
    for ecosystem in osv_db_refresh.known_ecosystems(root):
        try:
            info = osv_db_refresh.status(ecosystem, root=root, now=now_dt)
        except Exception as exc:  # noqa: BLE001
            out.append({"ecosystem": ecosystem, "state": "unknown", "detail": type(exc).__name__})
            continue
        age = info.get("age_hours")
        if info.get("status") != "present":
            state = "missing"
        elif info.get("signature_valid") is False:
            state = "untrusted"
        elif not isinstance(age, (int, float)):
            state = "unknown"
        elif age > THRESHOLDS["osv_fail_hours"]:
            state = "fail"
        elif age > THRESHOLDS["osv_warn_hours"]:
            state = "stale"
        else:
            state = "ok"
        out.append({"ecosystem": ecosystem, "state": state, "age_hours": age, "sha256": info.get("sha256"),
                    "retrieved_utc": info.get("retrieved_utc")})
    return out


def check_osv_freshness(now_dt: dt.datetime, root: Path | None = None, *, refresh: bool = False) -> list[dict[str, Any]]:
    try:
        items = _cached(f"osv_fresh:{root}", 600, lambda: osv_freshness_items(now_dt, root), refresh)
    except Exception as exc:  # noqa: BLE001
        return [_check("osv_freshness", "OSV ekosistem tazeliği", "unknown", type(exc).__name__)]
    if not items:
        return [_check("osv_freshness", "OSV ekosistem tazeliği", "info", "ekosistem yok",
                       "Çevrimdışı OSV veritabanı indirilmemiş.", "scripts/osv_refresh.py ile indirin.")]
    bad = [i for i in items if i["state"] in {"fail", "untrusted"}]
    stale = [i for i in items if i["state"] == "stale"]
    missing = [i for i in items if i["state"] in {"missing", "unknown"}]
    status = "fail" if bad else "warn" if stale or missing else "ok"

    def text(item: dict[str, Any]) -> str:
        age = item.get("age_hours")
        label = {"ok": "", "stale": " bayat", "fail": " çok eski", "untrusted": " imza yok", "missing": " yok",
                 "unknown": " ?"}[item["state"]]
        return f"{item['ecosystem']} {_age_text(age * 3600) if isinstance(age, (int, float)) else '-'}{label}".strip()

    ok_count = sum(1 for i in items if i["state"] == "ok")
    check = _check("osv_freshness", "OSV ekosistem tazeliği", status, f"{ok_count}/{len(items)} güncel",
                   "; ".join(text(i) for i in items),
                   "" if status == "ok" else "sniper-osv-refresh.timer'ı ya da scripts/osv_refresh.py'yi kontrol edin.")
    check["items"] = [{k: i.get(k) for k in ("ecosystem", "state", "age_hours", "retrieved_utc")} for i in items]
    return [check]


def check_malware_cache(data_dir: Path, now_dt: dt.datetime, root: Path | None = None) -> list[dict[str, Any]]:
    """osv_offline malware dizini disk önbelleği (data/cache/osv-malware-*.json): güncel / eski arşivlere ait."""
    cache = Path(data_dir) / "cache"
    try:
        files = sorted(p for p in cache.glob("osv-malware-*.json") if p.is_file() and not p.is_symlink()) \
            if cache.is_dir() and not cache.is_symlink() else []
    except OSError as exc:
        return [_check("malware_cache", "Kötü amaçlı paket dizini önbelleği", "unknown", type(exc).__name__)]
    try:
        current = {str(i.get("sha256") or "")[:32] for i in _cached(f"osv_fresh:{root}", 600,
                                                                     lambda: osv_freshness_items(now_dt, root))}
    except Exception:  # noqa: BLE001
        current = set()
    stale = [p for p in files if p.stem[len("osv-malware-"):] not in current]
    size = sum(p.stat().st_size for p in files)
    value = f"{len(files) - len(stale)} güncel, {len(stale)} eski ({_mb(size)})" if files else "henüz yok"
    detail = ("Arşiv özetine bağlı; ilk proje analizinde kurulur, iş kuyruğu alt süreçleri yeniden taramaz."
              if files else "İlk proje analizinde ya da tedarik zinciri denetiminde kurulur.")
    return [_check("malware_cache", "Kötü amaçlı paket dizini önbelleği", "info", value, detail,
                   "Eski arşivlere ait önbellekler saklama politikasındaki 'Önbellekler' kategorisiyle temizlenebilir."
                   if stale else "")]


def check_license_caches() -> list[dict[str, Any]]:
    """Lisans uyumu için okunan yerel paket önbellekleri (salt okunur; ağ yok)."""
    try:
        import license_compliance

        home = license_compliance._cache_home()
        if home is None:
            return [_check("license_caches", "Lisans önbellek okuması", "info", "kapalı",
                           "SNIPER_LICENSE_CACHE_HOME boş: yalnız proje dosyalarından lisans okunur.")]
        roots = license_compliance._CacheReader(home).roots
    except Exception as exc:  # noqa: BLE001
        return [_check("license_caches", "Lisans önbellek okuması", "unknown", type(exc).__name__)]
    found = [kind for kind, paths in sorted(roots.items()) if paths]
    return [_check("license_caches", "Lisans önbellek okuması", "info",
                   f"{len(found)} önbellek okunabiliyor" if found else "okunabilir önbellek yok",
                   ("Okunan: " + ", ".join(found)) if found else
                   "Maven ~/.m2, Cargo, NuGet, Go modül ve gem önbellekleri bulunamadı; bilinmeyen lisanslar 'inceleme'.")]


def _systemctl_show(unit: str, props: tuple[str, ...]) -> dict[str, str] | None:
    import shutil
    import subprocess

    if os.environ.get("SNIPER_HEALTH_SYSTEMCTL", "1") == "0":
        return None  # testler ve systemd'siz kurulumlar
    exe = shutil.which("systemctl")
    if not exe:
        return None
    try:
        proc = subprocess.run([exe, "--user", "show", unit, *[f"--property={p}" for p in props]],
                              capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition("=")
        if key in props:
            out[key] = value.strip()
    return out


def check_service_autostart(*,
                            show: Callable[[str, tuple[str, ...]], dict[str, str] | None] | None = None,
                            refresh: bool = False) -> list[dict[str, Any]]:
    """Ana kullanıcı servisinin çalıştığını ve oturum açılışında kalıcı olarak başlayacağını salt okunur denetle."""
    show = show or _systemctl_show
    state = _cached("sniper_service", 300, lambda: show(
        "sniper.service", ("LoadState", "ActiveState", "SubState", "UnitFileState")), refresh)
    if state is None:
        return [_check("sniper_service", "Sniper servisi ve otomatik başlatma", "unknown", "systemd okunamadı",
                       "systemctl --user durumu bu ortamda kullanılamıyor.")]
    loaded = state.get("LoadState") or "?"
    active = state.get("ActiveState") or "?"
    sub = state.get("SubState") or "?"
    enabled = state.get("UnitFileState") or "?"
    value = f"{active}/{sub} · otomatik başlatma {enabled}"
    if loaded in {"masked", "not-found", "error"} or enabled == "masked":
        return [_check("sniper_service", "Sniper servisi ve otomatik başlatma", "fail", value,
                       f"birim yükleme durumu: {loaded}", "Kullanıcı servisinin kurulumunu ve maskelenme durumunu inceleyin.")]
    if active != "active":
        return [_check("sniper_service", "Sniper servisi ve otomatik başlatma", "fail", value,
                       f"birim yükleme durumu: {loaded}", "systemctl --user status sniper.service ile servis hatasını inceleyin.")]
    if enabled != "enabled":
        return [_check("sniper_service", "Sniper servisi ve otomatik başlatma", "warn", value,
                       "Servis şu anda çalışıyor ancak sonraki kullanıcı oturumunda otomatik başlamayabilir.",
                       "systemctl --user enable sniper.service")]
    return [_check("sniper_service", "Sniper servisi ve otomatik başlatma", "ok", value)]


def check_osv_timer(now_dt: dt.datetime, root: Path | None = None, *,
                    show: Callable[[str, tuple[str, ...]], dict[str, str] | None] | None = None,
                    refresh: bool = False) -> list[dict[str, Any]]:
    """sniper-osv-refresh zamanlayıcısının son çalışması (systemd'den salt okunur; yoksa manifest zaman damgası)."""
    show = show or _systemctl_show
    service = _cached("osv_timer_service", 600, lambda: show(
        "sniper-osv-refresh.service", ("Result", "ExecMainStatus", "ExecMainExitTimestamp", "ActiveState")), refresh)
    timer = _cached("osv_timer_timer", 600, lambda: show(
        "sniper-osv-refresh.timer", ("ActiveState", "LastTriggerUSec", "NextElapseUSecRealtime")), refresh)
    if service is None or timer is None:
        try:
            import osv_db_refresh

            base = (root or osv_db_refresh.default_root()).expanduser()
            stamps = [p.stat().st_mtime for p in base.glob("*-OFFLINE-DB-MANIFEST-v2.json") if p.is_file()]
        except OSError:
            stamps = []
        if not stamps:
            return [_check("osv_timer", "OSV yenileme zamanlayıcısı", "unknown", "systemd okunamadı",
                           "systemctl --user kullanılamıyor ve manifest bulunamadı.")]
        age = now_dt.timestamp() - max(stamps)
        status = "warn" if age > THRESHOLDS["osv_warn_hours"] * 3600 else "info"
        return [_check("osv_timer", "OSV yenileme zamanlayıcısı", status, f"son manifest {_age_text(age)} önce",
                       "systemd durumu okunamadı; en yeni manifest dosyasının zamanı gösteriliyor.")]
    result = service.get("Result") or "?"
    exit_status = service.get("ExecMainStatus") or "?"
    last_trigger = timer.get("LastTriggerUSec") or ""
    next_run = timer.get("NextElapseUSecRealtime") or ""
    active = timer.get("ActiveState") or "?"
    if active != "active":
        status, recommendation = "warn", "systemctl --user enable --now sniper-osv-refresh.timer"
    elif result not in {"success", ""} or exit_status not in {"0", "", "?"}:
        status, recommendation = "fail", "journalctl --user -u sniper-osv-refresh.service ile son çalışmayı inceleyin."
    else:
        status, recommendation = "ok", ""
    return [_check("osv_timer", "OSV yenileme zamanlayıcısı", status,
                   f"zamanlayıcı {active}, son sonuç {result} (çıkış {exit_status})",
                   f"son tetik: {last_trigger or 'hiç'}; sonraki: {next_run or '-'}", recommendation)]


def check_schedules(environ: dict[str, str] | None) -> list[dict[str, Any]]:
    try:
        import scheduler

        data = scheduler.load(environ)
    except Exception as exc:  # noqa: BLE001
        return [_check("schedules", "Zamanlanmış taramalar", "unknown", type(exc).__name__)]
    enabled = [s for s in data.get("schedules") or [] if s.get("enabled")]
    if not enabled:
        return [_check("schedules", "Zamanlanmış taramalar", "info", "etkin plan yok")]
    failed = [s for s in enabled if s.get("last_status") in FAILED_SCHEDULE_STATES]
    status = "warn" if failed else "ok"
    detail = "; ".join(f"{s.get('name') or s.get('id')}: {s.get('last_status')}" for s in failed[:5])
    return [_check("schedules", "Zamanlanmış taramaların son durumu", status,
                   f"{len(enabled)} etkin plan · {len(failed)} başarısız", detail,
                   "İşler panelinden başarısız işin ayrıntısına bakın." if failed else "")]


def check_jobs(jobs: list[dict[str, Any]] | None, stats: dict[str, Any] | None) -> list[dict[str, Any]]:
    if jobs is None or stats is None:
        return [_check("job_queue", "İş kuyruğu", "unknown", "bu süreçte iş kuyruğu yok")]
    queued = int(stats.get("queued") or 0)
    oldest_minutes = 0.0
    now = dt.datetime.now(dt.timezone.utc)
    for job in jobs:
        if job.get("state") != "queued" or not job.get("created_at"):
            continue
        try:
            created = dt.datetime.fromisoformat(str(job["created_at"]).replace("Z", "+00:00"))
        except ValueError:
            continue
        oldest_minutes = max(oldest_minutes, (now - created).total_seconds() / 60)
    status = "warn" if queued >= THRESHOLDS["queue_warn"] or oldest_minutes > THRESHOLDS["queue_age_warn_minutes"] else "ok"
    return [_check("job_queue", "İş kuyruğu birikmesi", status,
                   f"{queued} bekleyen · {int(stats.get('running') or 0)} çalışan / {int(stats.get('workers') or 0)} işçi",
                   f"en eski bekleyen {oldest_minutes:.0f} dk" if queued else "",
                   "Takılı işleri İşler panelinden iptal edin." if status != "ok" else "")]


def check_audit_chain(store: Any) -> list[dict[str, Any]]:
    if store is None:
        return [_check("audit_chain", "Denetim zinciri", "unknown", "depo yok")]
    try:
        result = store.verify_audit_chain()
    except Exception as exc:  # noqa: BLE001
        return [_check("audit_chain", "Denetim zinciri", "unknown", type(exc).__name__)]
    ok = bool(result.get("verified")) and not result.get("integrity_problems")
    return [_check("audit_chain", "Denetim kaydı zinciri", "ok" if ok else "fail",
                   f"{int(result.get('event_count') or 0)} kayıt · {result.get('integrity') or '?'}",
                   "" if ok else f"ilk bozuk kayıt: {result.get('first_broken_id')}; "
                                 + "; ".join(str(p) for p in (result.get("integrity_problems") or [])[:3]),
                   "" if ok else "Denetim kaydı değiştirilmiş olabilir: veritabanı yedekleriyle karşılaştırın, olayı inceleyin.")]


def _pin_states() -> list[dict[str, Any]]:
    from tool_pins import PINS, TREE_PINS, pin_status, tree_pin_status

    try:
        from semgrep_active import active_engine

        engine, engine_binary = active_engine()[:2]
    except Exception:  # noqa: BLE001
        engine, engine_binary = "opengrep", None
    states = []
    for tool in PINS:
        try:
            if tool in ("semgrep", "opengrep"):
                if tool != engine:
                    continue  # yalnız etkin desen motoru (hazırlık raporuyla aynı)
                states.append(pin_status(tool, engine_binary))
                continue
            states.append(pin_status(tool))
        except Exception as exc:  # noqa: BLE001
            states.append({"tool": tool, "state": "unavailable", "reason_code": type(exc).__name__})
    for name in TREE_PINS:
        try:
            states.append(tree_pin_status(name))
        except Exception as exc:  # noqa: BLE001
            states.append({"tool": name, "state": "unavailable", "reason_code": type(exc).__name__})
    return states


def check_pins(*, refresh: bool = False, pin_states: Callable[[], list[dict[str, Any]]] | None = None) -> list[dict[str, Any]]:
    try:
        states = _cached("pins", 3600, pin_states or _pin_states, refresh)
    except Exception as exc:  # noqa: BLE001
        return [_check("tool_pins", "Araç pinleri", "unknown", type(exc).__name__)]
    mismatch = [s["tool"] for s in states if s.get("state") == "mismatch"]
    missing = [s["tool"] for s in states if s.get("state") in {"unavailable", "unpinned"}]
    pinned = sum(1 for s in states if s.get("state") == "pinned")
    status = "fail" if mismatch else ("info" if missing else "ok")
    detail = ("SHA-256 uyuşmuyor: " + ", ".join(mismatch)) if mismatch else (
        ("kurulu değil / sabitlenmemiş: " + ", ".join(missing)) if missing else "")
    return [_check("tool_pins", "Araç ikilileri (SHA-256 pinleri)", status, f"{pinned}/{len(states)} doğrulandı", detail,
                   "Uyuşmayan ikili çalıştırılmaz; aracı resmi kaynaktan yeniden kurun ve pini doğrulayın." if mismatch else "")]


def check_version(app_root: Path | None, data_dir: Path, running_release: Any) -> list[dict[str, Any]]:
    if app_root is None:
        return []
    try:
        import community_release_info

        info = community_release_info.system_version_payload(app_root, data_dir, running_release=running_release)
    except Exception as exc:  # noqa: BLE001
        return [_check("version", "Sürüm", "unknown", type(exc).__name__)]
    release = info.get("release") or {}
    value = release.get("version") or f"{info.get('product_version') or '?'} (paketsiz kurulum)"
    last = info.get("last_update") or {}
    if info.get("restart_pending"):
        return [_check("version", "Sürüm ve güncelleme", "warn", value,
                       f"yeni sürüm {info.get('installed_version')} kurulu, servis henüz yeniden başlatılmadı",
                       "Servisi yeniden başlatın (systemctl --user restart sniper.service).")]
    if last.get("status") in {"unhealthy", "failed", "rolled_back"}:
        return [_check("version", "Sürüm ve güncelleme", "warn", value,
                       f"son güncelleme: {last.get('action')} · {last.get('status')}",
                       "Güncelleme günlüğünü inceleyin; paket doğrulaması ve sağlık denetimi neden başarısız oldu?")]
    signature = release.get("signature")
    detail = f"imza: {signature}" if signature else ""
    return [_check("version", "Sürüm ve güncelleme", "ok" if release else "info", value, detail)]


def check_auth(data_dir: Path, home: Path | None) -> list[dict[str, Any]]:
    out = []
    try:
        import auth

        manager = auth.AuthManager(data_dir)
        enabled = manager.enabled()
        users = manager.list_users() if manager.path.is_file() else []
    except Exception as exc:  # noqa: BLE001
        return [_check("auth", "Giriş", "unknown", type(exc).__name__)]
    if not enabled:
        out.append(_check("auth", "Arayüz girişi", "warn", "kapalı",
                          "Sniper yalnız yerel/tünel erişimiyle korunuyor.",
                          "Girişi açın: cli_reports.py users create-admin --username <ad>."))
    else:
        admins = [u for u in users if u.get("role") == "admin" and not u.get("disabled")]
        without = [u["username"] for u in admins if not u.get("totp_enabled")]
        out.append(_check("auth", "Arayüz girişi ve iki adımlı doğrulama", "warn" if without else "ok",
                          f"açık · {len(users)} kullanıcı · {len(admins)} yönetici",
                          ("TOTP kapalı yönetici: " + ", ".join(without)) if without else "tüm yöneticilerde TOTP açık",
                          "Yönetici hesaplarında iki adımlı doğrulamayı (TOTP) açın." if without else ""))
    initial = (home or Path.home()) / INITIAL_PASSWORD_FILE
    if initial.exists():
        out.append(_check("initial_password", "İlk yönetici parola dosyası", "warn", "duruyor", str(initial),
                          "İlk girişte parolayı değiştirin ve bu dosyayı silin (Sniper dosyayı kendisi silmez)."))
    return out


# ---------------------------------------------------------------------------
# Rapor ve günlük denetim
# ---------------------------------------------------------------------------
def build_report(*, data_dir: Path, app_root: Path | None = None, store: Any = None,
                 jobs: list[dict[str, Any]] | None = None, job_stats: dict[str, Any] | None = None,
                 running_release: Any = None, environ: dict[str, str] | None = None, home: Path | None = None,
                 refresh: bool = False, now: dt.datetime | None = None,
                 pin_states: Callable[[], list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    data_dir = Path(data_dir)
    checks: list[dict[str, Any]] = []
    for producer in (
        lambda: check_disk(data_dir),
        lambda: check_database(data_dir, refresh=refresh),
        lambda: check_backups(data_dir, app_root, now.timestamp()),
        lambda: check_backup_storage(data_dir, environ),
        lambda: check_osv(now),
        lambda: _cached("osv_ecosystems", 900, lambda: check_osv_ecosystems(now), refresh),  # arşiv özetleri pahalı
        lambda: check_osv_freshness(now, refresh=refresh),
        lambda: check_service_autostart(refresh=refresh),
        lambda: check_osv_timer(now, refresh=refresh),
        lambda: check_malware_cache(data_dir, now),
        lambda: check_license_caches(),
        lambda: check_schedules(environ),
        lambda: check_jobs(jobs, job_stats),
        lambda: check_audit_chain(store),
        lambda: check_pins(refresh=refresh, pin_states=pin_states),
        lambda: check_version(app_root, data_dir, running_release),
        lambda: check_auth(data_dir, home),
    ):
        try:
            checks.extend(producer())
        except Exception as exc:  # noqa: BLE001 — tek denetim hatası raporu düşürmez
            checks.append(_check("internal", "İç denetim hatası", "unknown", type(exc).__name__))
    overall = max((c["status"] for c in checks), key=STATUS_ORDER.__getitem__, default="unknown")
    if overall == "info":
        overall = "ok"
    counts = {status: sum(1 for c in checks if c["status"] == status) for status in STATUS_LABELS}
    return {
        "format": FORMAT,
        "generated_at": now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "overall": overall,
        "overall_label": STATUS_LABELS[overall],
        "counts": counts,
        "checks": checks,
        "read_only": True,
        "note": "Salt okunur rapor: Sniper hiçbir dosyayı silmez ya da düzeltmez; yalnız öneri verir.",
    }


def problems(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in report.get("checks") or [] if c["status"] in {"warn", "fail"}]


def notify_if_needed(report: dict[str, Any], *, environ: dict[str, str] | None = None,
                     now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Yeni sorun çıktıysa ya da sorun 24 saattir sürüyorsa bildirim üretir; durum veri dizininde tutulur."""
    import notifications
    import ops_files

    now = now or dt.datetime.now(dt.timezone.utc)
    current = problems(report)
    signature = sorted(f"{c['id']}:{c['status']}" for c in current)
    decision: dict[str, Any] = {}

    def change(state: Any) -> dict[str, Any]:
        state = state if isinstance(state, dict) else {}
        previous = set(state.get("signature") or [])
        last = state.get("last_notified_at")
        try:
            last_ts = dt.datetime.fromisoformat(str(last).replace("Z", "+00:00")).timestamp() if last else None
        except ValueError:
            last_ts = None
        new = [item for item in signature if item not in previous]
        remind = bool(signature) and (last_ts is None or now.timestamp() - last_ts >= REMIND_SECONDS)
        decision["send"] = bool(signature) and (bool(new) or remind)
        state["signature"] = signature
        state["last_check_at"] = now.isoformat()
        if decision["send"]:
            state["last_notified_at"] = now.isoformat()
        return state

    ops_files.update_json(STATE_FILE, dict, change, environ)
    if not decision.get("send"):
        return None
    worst = "high" if any(c["status"] == "fail" for c in current) else "medium"
    return notifications.emit(
        "system_health", worst, f"Sniper öz sağlık: {len(current)} sorun",
        "Öz sağlık panosunda uyarı/sorun var; ayrıntı İşlem geçmişi › Sistem sağlığı kartında.",
        details=[f"{c['label']}: {c['value']}" for c in current[:10]],
        data={"checks": [c["id"] for c in current]}, now=now, environ=environ)


def daily_check(build: Callable[[], dict[str, Any]], *, environ: dict[str, str] | None = None,
                now: dt.datetime | None = None, interval: float = CHECK_INTERVAL_SECONDS) -> dict[str, Any] | None:
    """Zamanlayıcıdan her turda çağrılır; son denetimden ``interval`` geçmediyse hiçbir şey yapmaz."""
    import ops_files

    now = now or dt.datetime.now(dt.timezone.utc)
    state = ops_files.read_json(STATE_FILE, dict, environ)
    last = state.get("last_check_at") if isinstance(state, dict) else None
    if last:
        try:
            if now.timestamp() - dt.datetime.fromisoformat(str(last)).timestamp() < interval:
                return None
        except ValueError:
            pass
    report = build()
    notify_if_needed(report, environ=environ, now=now)
    return report
