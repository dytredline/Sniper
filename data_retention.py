"""Veri saklama politikası, veritabanı yedek döndürme ve elle yedek alma (17. tur, W3-OPS).

İlkeler:
* Varsayılan KAPALI. Politika kapalıyken de önizleme (kuru çalıştırma) yapılabilir; silme yalnız politika açıkken,
  yönetici onayıyla ve önizlemede gösterilen planla birebir aynı plan için (``plan_id``) yapılır.
* Denetim zinciri (``audit_log``) ve bulgu takibi tabloları hiçbir koşulda silinmez. Silinen her şey kategori başına
  denetim kaydına yazılır.
* Veri dizinindeki gevşek yedekler (``sniper.db.bak-*``, ``auth.db.bak-*``): son N + günlük + haftalık saklanır, en yeni
  yedek her zaman kalır. Etiketli/elle alınmış yedekler (ör. ``-claude-r16``, ``-pre-restore``) yalnız
  ``include_named`` açıkça seçilirse kapsama girer; ``-ui``/``-auto`` etiketli ve etiketsiz yedekler "yönetilen" sayılır.
* Güncelleme yedekleri (``<önek>/backups/<kimlik>``) burada yalnız listelenir; onları ``documented Community recovery procedure`` döndürür.
* Geri yükleme yalnız komut satırından: ``documented Community recovery procedure --restore-db <yedek>`` (gevşek yedek) ya da
  ``documented Community recovery procedure --rollback <kimlik> --with-db`` (güncelleme yedeği).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any, Callable

import ops_files

FORMAT = "sniper-retention-v1"
POLICY_FILE = "retention-policy.json"
STATE_FILE = "retention-state.json"
LOCK_NAME = "retention"
MANAGED_LABELS = frozenset({"ui", "auto"})
SIDECAR_SUFFIXES = ("-shm", "-wal", "-journal")
_BACKUP_RE = re.compile(r"^(sniper|auth)\.db\.bak(?:-(\d{8}T\d{4}(?:\d{2})?))?(?:-([A-Za-z0-9._-]{1,80}))?$")
_JOB_RE = re.compile(r"^job_[0-9a-f]{8,64}\.json$")
_TMP_RE = re.compile(r"^\..+\.tmp$")
RECENT_GRACE_SECONDS = 3600  # son 1 saatte oluşan dosya hiçbir kategoride silinmez
MAX_LISTED = 2000

DEFAULT_POLICY: dict[str, Any] = {
    "enabled": False,
    "auto_daily": False,
    "backups": {"keep_last": 10, "keep_daily": 7, "keep_weekly": 4, "include_named": False},
    "project_audits": {"enabled": False, "older_than_days": 365, "keep_per_project": 20},
    "notifications": {"enabled": True, "read_older_than_days": 90},
    "jobs": {"enabled": True, "older_than_days": 30},
    "temp": {"enabled": True, "older_than_days": 7},
    # 21. tur: yeniden üretilebilir önbellekler (kötü amaçlı paket dizini, konteyner OSV dizini, PDF iş dizinleri,
    # LSP önbelleği). Politikanın kendisi kapalıyken olduğu gibi, bu kategori de varsayılan kapalıdır.
    "caches": {"enabled": False, "older_than_days": 30},
}
_INT_LIMITS = {
    ("backups", "keep_last"): (1, 500), ("backups", "keep_daily"): (0, 365), ("backups", "keep_weekly"): (0, 260),
    ("project_audits", "older_than_days"): (30, 3650), ("project_audits", "keep_per_project"): (1, 1000),
    ("notifications", "read_older_than_days"): (1, 3650), ("jobs", "older_than_days"): (1, 3650),
    ("temp", "older_than_days"): (1, 365), ("caches", "older_than_days"): (1, 365),
}
CATEGORY_LABELS = {
    "backups": "Veritabanı yedekleri", "project_audits": "Eski proje analizleri", "notifications": "Okunmuş bildirimler",
    "jobs": "Bitmiş iş kayıtları", "temp": "Geçici dosyalar ve önbellek",
    "caches": "Önbellekler (kötü amaçlı paket dizini, konteyner OSV dizini, PDF iş dizinleri, LSP)",
}
_MALWARE_CACHE_RE = re.compile(r"^osv-malware-([0-9a-f]{32})\.json$")
_INDEX_CACHE_RE = re.compile(r"^[a-z0-9-]+-([0-9a-f]{16})\.json\.gz$")
_PDF_DIR_RE = re.compile(r"^pdf-[A-Za-z0-9_]{1,64}$")


class RetentionError(ValueError):
    """Geçersiz politika ya da yürütülemeyen plan."""


# ---------------------------------------------------------------------------
# Politika
# ---------------------------------------------------------------------------
def _copy_default() -> dict[str, Any]:
    return json.loads(json.dumps(DEFAULT_POLICY))


def validate_policy(raw: Any) -> dict[str, Any]:
    """Kısmi politika kabul eder (eksik alanlar varsayılandan); bilinmeyen alan ve aralık dışı değer reddedilir."""
    if not isinstance(raw, dict):
        raise RetentionError("Politika bir nesne olmalı.")
    policy = _copy_default()
    for key, value in raw.items():
        if key not in policy:
            raise RetentionError(f"Bilinmeyen politika alanı: {key}")
        if key in ("enabled", "auto_daily"):
            if type(value) is not bool:
                raise RetentionError(f"{key} true/false olmalı.")
            policy[key] = value
            continue
        if not isinstance(value, dict):
            raise RetentionError(f"{key} bir nesne olmalı.")
        for sub, sub_value in value.items():
            if sub not in policy[key]:
                raise RetentionError(f"Bilinmeyen alan: {key}.{sub}")
            if sub in ("enabled", "include_named"):
                if type(sub_value) is not bool:
                    raise RetentionError(f"{key}.{sub} true/false olmalı.")
            else:
                low, high = _INT_LIMITS[(key, sub)]
                if type(sub_value) is not int or not low <= sub_value <= high:
                    raise RetentionError(f"{key}.{sub} {low}–{high} arası tam sayı olmalı.")
            policy[key][sub] = sub_value
    return policy


def load_policy(environ: dict[str, str] | None = None) -> dict[str, Any]:
    raw = ops_files.read_json(POLICY_FILE, _copy_default, environ)
    try:
        return validate_policy(raw)
    except RetentionError:
        return _copy_default()  # bozuk dosya: güvenli varsayılan (kapalı)


def save_policy(raw: Any, environ: dict[str, str] | None = None) -> dict[str, Any]:
    policy = validate_policy(raw)
    ops_files.update_json(POLICY_FILE, _copy_default, lambda _old: policy, environ)
    return policy


# ---------------------------------------------------------------------------
# Yedek keşfi
# ---------------------------------------------------------------------------
def _parse_stamp(text: str | None) -> float | None:
    if not text:
        return None
    # Biçim uzunluğa göre seçilir: strptime %H%M%S'yi tek haneli alanlarla da eşler ("T2358" → 23:05:08 olurdu).
    fmt = {15: "%Y%m%dT%H%M%S", 13: "%Y%m%dT%H%M"}.get(len(text))
    if fmt is None or not text[:8].isdigit() or not text[9:].isdigit():
        return None
    try:
        return time.mktime(time.strptime(text, fmt))  # yerel saat (yedek adları `date` ile yerel üretilir)
    except ValueError:
        return None


def _regular(path: Path) -> os.stat_result | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return info if stat.S_ISREG(info.st_mode) else None


def list_db_backups(data_dir: Path) -> list[dict[str, Any]]:
    """Veri dizinindeki gevşek DB yedekleri (yeniden eskiye). Yan dosyalar (-shm/-wal/-journal) ana yedeğe bağlanır."""
    data_dir = Path(data_dir)
    try:
        names = sorted(p.name for p in data_dir.iterdir())
    except OSError:
        return []
    name_set = set(names)
    out: list[dict[str, Any]] = []
    for name in names:
        if name.endswith(SIDECAR_SUFFIXES) and name.rsplit("-", 1)[0] in name_set:
            continue  # yan dosya: ana yedekle birlikte sayılır
        match = _BACKUP_RE.match(name)
        if not match:
            continue
        info = _regular(data_dir / name)
        if info is None:
            continue
        kind, stamp_text, label = match.groups()
        sidecars = [n for n in (name + s for s in SIDECAR_SUFFIXES) if n in name_set and _regular(data_dir / n)]
        size = info.st_size + sum((_regular(data_dir / n) or info).st_size for n in sidecars)
        created = _parse_stamp(stamp_text) or info.st_mtime
        out.append({
            "name": name, "kind": kind, "label": label or "", "created_epoch": created,
            "created_at": dt.datetime.fromtimestamp(created, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "bytes": size, "sidecars": sidecars,
            "named": bool(label) and label not in MANAGED_LABELS,
            "world_readable": bool(info.st_mode & 0o044),
            "mode": oct(info.st_mode & 0o777),
        })
    out.sort(key=lambda item: item["created_epoch"], reverse=True)
    return out[:MAX_LISTED]


def backup_summary(data_dir: Path) -> dict[str, Any]:
    backups = list_db_backups(data_dir)
    return {
        "count": len(backups), "bytes": sum(b["bytes"] for b in backups),
        "named": sum(1 for b in backups if b["named"]), "world_readable": [b["name"] for b in backups if b["world_readable"]],
        "newest_epoch": max((b["created_epoch"] for b in backups if b["kind"] == "sniper"), default=None),
    }


def select_backup_deletions(backups: list[dict[str, Any]], rules: dict[str, Any], now: float) -> list[dict[str, Any]]:
    """Son N + günlük (son D gün, gün başına en yeni) + haftalık (son W ISO haftası) saklanır; tür başına en yeni hep kalır."""
    doomed: list[dict[str, Any]] = []
    for kind in ("sniper", "auth"):
        items = sorted((b for b in backups if b["kind"] == kind), key=lambda b: b["created_epoch"], reverse=True)
        if not items:
            continue
        keep = {items[0]["name"]}  # en yeni yedek (etiketli olsa bile) asla silinmez
        candidates = [b for b in items if rules.get("include_named") or not b["named"]]
        keep.update(b["name"] for b in candidates[: rules["keep_last"]])
        today = dt.date.fromtimestamp(now)
        days_seen: set[dt.date] = set()
        weeks_seen: set[tuple[int, int]] = set()
        for b in candidates:  # yeniden eskiye: gün/hafta başına ilk görülen en yenidir
            day = dt.date.fromtimestamp(b["created_epoch"])
            if rules["keep_daily"] and (today - day).days < rules["keep_daily"] and day not in days_seen:
                days_seen.add(day)
                keep.add(b["name"])
            week = day.isocalendar()[:2]
            if rules["keep_weekly"] and (today - day).days < rules["keep_weekly"] * 7 and week not in weeks_seen:
                weeks_seen.add(week)
                keep.add(b["name"])
        for b in candidates:
            if b["name"] in keep or now - b["created_epoch"] < RECENT_GRACE_SECONDS:
                continue
            doomed.append({"name": b["name"], "kind": kind, "label": b["label"], "bytes": b["bytes"],
                           "created_at": b["created_at"], "sidecars": b["sidecars"]})
    return doomed


# ---------------------------------------------------------------------------
# Diğer kategoriler
# ---------------------------------------------------------------------------
def _iso_epoch(text: Any) -> float | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _notification_deletions(rules: dict[str, Any], now: float, environ: dict[str, str] | None) -> list[dict[str, Any]]:
    data = ops_files.read_json("notifications.json", lambda: {"items": []}, environ)
    items = data.get("items") if isinstance(data, dict) and isinstance(data.get("items"), list) else []
    limit = now - rules["read_older_than_days"] * 86400
    out = []
    for item in items:
        created = _iso_epoch(item.get("created_at")) if isinstance(item, dict) else None
        if isinstance(item, dict) and item.get("read") and created is not None and created < limit and item.get("id"):
            out.append({"id": str(item["id"]), "created_at": item.get("created_at"), "event": item.get("event")})
    return out


def _job_deletions(data_dir: Path, rules: dict[str, Any], now: float) -> list[dict[str, Any]]:
    directory = data_dir / "jobs"
    if directory.is_symlink() or not directory.is_dir():
        return []
    final = {"succeeded", "failed", "cancelled", "expired", "interrupted"}
    limit = now - rules["older_than_days"] * 86400
    out = []
    for path in sorted(directory.iterdir())[:MAX_LISTED * 5]:
        info = _regular(path)
        if info is None or not _JOB_RE.match(path.name) or info.st_size > 50_000_000:
            continue
        try:
            record = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        finished = record.get("finished_epoch") if isinstance(record, dict) else None
        if not isinstance(record, dict) or record.get("state") not in final or not isinstance(finished, (int, float)):
            continue  # çalışan/kuyrukta ya da bitiş zamanı bilinmeyen iş korunur
        if finished < limit and now - info.st_mtime >= RECENT_GRACE_SECONDS:
            out.append({"name": path.name, "state": record.get("state"), "bytes": info.st_size})
    return out


def _temp_deletions(data_dir: Path, rules: dict[str, Any], now: float) -> list[dict[str, Any]]:
    """Veri dizini ve taint-cache içindeki eski atomik yazım artıkları (``.*.tmp``) ve önbellek dosyaları."""
    limit = now - rules["older_than_days"] * 86400
    out = []
    for directory, pattern in ((data_dir, _TMP_RE), (data_dir / "taint-cache", re.compile(r"^[0-9a-f]{64}\.json$|^\..+\.tmp$"))):
        if directory.is_symlink() or not directory.is_dir():
            continue
        for path in sorted(directory.iterdir())[:MAX_LISTED * 5]:
            info = _regular(path)
            if info is None or not pattern.match(path.name) or info.st_mtime >= limit:
                continue
            out.append({"name": path.relative_to(data_dir).as_posix(), "bytes": info.st_size})
    return out


def _current_osv_shas(osv_root: Path | None) -> set[str] | None:
    """Güncel OSV arşivlerinin SHA-256 değerleri (manifestlerden). Okunamazsa None: o önbellekler silinmez."""
    try:
        import osv_db_refresh

        shas = set()
        for ecosystem in osv_db_refresh.known_ecosystems(osv_root):
            info = osv_db_refresh.status(ecosystem, root=osv_root)
            if info.get("status") == "present" and isinstance(info.get("sha256"), str):
                shas.add(info["sha256"])
        return shas
    except Exception:  # noqa: BLE001 — güvenli taraf: hiçbir şeyi silme
        return None


def cache_bases(data_dir: Path, environ: dict[str, str] | None = None) -> dict[str, Path]:
    """Önbellek kategorisinin kökleri. Silme yalnız bu köklerin içinde ve yalnız sıradan dosya/dizin üzerinde yapılır."""
    env = os.environ if environ is None else environ
    raw_osv = str(env.get("SNIPER_OSV_DB_ROOT", "") or "").strip()
    osv = Path(raw_osv).expanduser() if raw_osv else Path.home() / ".local" / "state" / "sniper" / "osv-db"
    xdg = str(env.get("XDG_CACHE_HOME", "") or "").strip()
    lsp = (Path(xdg) if xdg else Path.home() / ".cache") / "sniper-lsp"
    return {"data": Path(data_dir), "osv": osv, "lsp": lsp}


def _cache_deletions(data_dir: Path, rules: dict[str, Any], now: float,
                     environ: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Yeniden üretilebilir önbellekler:
    * ``data/cache/osv-malware-*.json`` ve OSV kökündeki ``index-cache/*.json.gz``: yalnız güncel arşivlerle EŞLEŞMEYENLER
      (eski nesillere ait); güncel arşivler okunamazsa hiçbiri.
    * ``data/sandbox-runs/pdf-*``: çökmeden kalan PDF iş dizinleri (süreden eski).
    * LSP önbelleği (``~/.cache/sniper-lsp``): süreden eski dosyalar."""
    bases = cache_bases(data_dir, environ)
    limit = now - rules["older_than_days"] * 86400
    grace = now - RECENT_GRACE_SECONDS
    out: list[dict[str, Any]] = []
    shas = _current_osv_shas(bases["osv"])
    if shas is not None:
        prefixes32 = {sha[:32] for sha in shas}
        prefixes16 = {sha[:16] for sha in shas}
        for base, sub, pattern, prefixes, kind in (
            ("data", "cache", _MALWARE_CACHE_RE, prefixes32, "malware_cache"),
            ("osv", "index-cache", _INDEX_CACHE_RE, prefixes16, "container_index"),
        ):
            directory = bases[base] / sub
            if directory.is_symlink() or not directory.is_dir():
                continue
            for path in sorted(directory.iterdir())[:MAX_LISTED]:
                match = pattern.match(path.name)
                info = _regular(path)
                if not match or info is None or match.group(1) in prefixes or info.st_mtime >= grace:
                    continue
                out.append({"name": f"{base}:{sub}/{path.name}", "kind": kind, "bytes": info.st_size})
    runs = bases["data"] / "sandbox-runs"
    if runs.is_dir() and not runs.is_symlink():
        for path in sorted(runs.iterdir())[:MAX_LISTED]:
            try:
                info = path.lstat()
            except OSError:
                continue
            if not _PDF_DIR_RE.match(path.name) or not stat.S_ISDIR(info.st_mode) or info.st_mtime >= limit:
                continue
            size = 0
            for child in path.rglob("*"):
                try:
                    child_info = child.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(child_info.st_mode):
                    size += child_info.st_size
            out.append({"name": f"data:sandbox-runs/{path.name}", "kind": "pdf_workdir", "bytes": size, "dir": True})
    lsp = bases["lsp"]
    if lsp.is_dir() and not lsp.is_symlink():
        count = 0
        for current, directories, files in os.walk(lsp, followlinks=False):
            directories[:] = sorted(d for d in directories if not (Path(current) / d).is_symlink())
            for name in sorted(files):
                path = Path(current) / name
                info = _regular(path)
                if info is None or info.st_mtime >= limit:
                    continue
                out.append({"name": f"lsp:{path.relative_to(lsp).as_posix()}", "kind": "lsp_cache",
                            "bytes": info.st_size})
                count += 1
                if count >= MAX_LISTED:
                    break
            if count >= MAX_LISTED:
                break
    return out


def _remove_cache_item(data_dir: Path, item: dict[str, Any], environ: dict[str, str] | None = None) -> bool:
    """``taban:göreli`` adlı önbellek öğesini kökün içinde sil (dizinlerde sembolik bağ izlenmez)."""
    base_name, _, rel = str(item.get("name") or "").partition(":")
    bases = cache_bases(data_dir, environ)
    if base_name not in bases or not rel or ".." in Path(rel).parts:
        return False
    base = bases[base_name]
    if not item.get("dir"):
        return _unlink_inside(base, rel)
    import shutil

    path = base / rel
    try:
        if path.is_symlink() or not path.is_dir():
            return False
        if not str(path.resolve(strict=True)).startswith(str(base.resolve()) + os.sep):
            return False
        shutil.rmtree(path)
        return True
    except OSError:
        return False


def _audit_deletions(db_path: Path, rules: dict[str, Any], now: float) -> list[dict[str, Any]]:
    """Eski proje analizleri: süreden eski + proje başına son K dışında + bulgu takibinin başvurmadığı analizler."""
    if not Path(db_path).is_file():
        return []
    limit = dt.datetime.fromtimestamp(now - rules["older_than_days"] * 86400, dt.timezone.utc).isoformat()
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "project_audits" not in tables:
            return []
        protected: set[str] = set()
        if "tracked_findings" in tables:
            for row in con.execute("SELECT first_audit_id, last_audit_id, fixed_audit_id FROM tracked_findings"):
                protected.update(value for value in row if value)
        if "project_audit_tracking" in tables:
            for row in con.execute("SELECT base_audit_id FROM project_audit_tracking WHERE base_audit_id IS NOT NULL"):
                protected.add(row[0])
        rows = con.execute(
            "SELECT id, project_path, created_at, length(findings_json) + length(summary_json) FROM project_audits "
            "ORDER BY project_path, created_at DESC").fetchall()
    finally:
        con.close()
    out, seen = [], {}
    for audit_id, project, created, size in rows:
        rank = seen.get(project, 0)
        seen[project] = rank + 1
        if rank < rules["keep_per_project"] or created >= limit or audit_id in protected:
            continue
        out.append({"id": audit_id, "project": Path(project).name, "created_at": created, "bytes": int(size or 0)})
    return out


# ---------------------------------------------------------------------------
# Plan ve yürütme
# ---------------------------------------------------------------------------
def _plan_id(categories: dict[str, list[dict[str, Any]]]) -> str:
    keys = {name: sorted(str(item.get("name") or item.get("id")) for item in items) for name, items in categories.items()}
    return hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()[:32]


def build_plan(data_dir: Path, *, policy: dict[str, Any] | None = None, now: float | None = None,
               environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Kuru çalıştırma: hiçbir şey silinmez; ne silineceğini ve neden korunduğunu döndürür."""
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    policy = policy or load_policy(environ)
    categories: dict[str, list[dict[str, Any]]] = {}
    categories["backups"] = select_backup_deletions(list_db_backups(data_dir), policy["backups"], now)
    categories["project_audits"] = (_audit_deletions(data_dir / "sniper.db", policy["project_audits"], now)
                                    if policy["project_audits"]["enabled"] else [])
    try:
        categories["notifications"] = (_notification_deletions(policy["notifications"], now, environ)
                                       if policy["notifications"]["enabled"] else [])
    except ops_files.OpsStoreError:
        categories["notifications"] = []
    categories["jobs"] = _job_deletions(data_dir, policy["jobs"], now) if policy["jobs"]["enabled"] else []
    categories["temp"] = _temp_deletions(data_dir, policy["temp"], now) if policy["temp"]["enabled"] else []
    categories["caches"] = (_cache_deletions(data_dir, policy["caches"], now, environ)
                            if policy["caches"]["enabled"] else [])
    summary = {name: {"label": CATEGORY_LABELS[name], "count": len(items),
                      "bytes": sum(int(item.get("bytes") or 0) for item in items)} for name, items in categories.items()}
    return {
        "format": FORMAT, "dry_run": True, "plan_id": _plan_id(categories), "policy": policy,
        "enabled": policy["enabled"], "categories": categories, "summary": summary,
        "total": {"count": sum(s["count"] for s in summary.values()), "bytes": sum(s["bytes"] for s in summary.values())},
        "backups": backup_summary(data_dir),
        "never_deleted": ["audit_log (denetim zinciri)", "bulgu takibi tabloları", "en yeni yedek",
                          "etiketli yedekler (include_named kapalıyken)", "son 1 saatte oluşan dosyalar"],
    }


def _unlink_inside(data_dir: Path, rel: str) -> bool:
    path = (data_dir / rel)
    try:
        resolved_parent = path.parent.resolve(strict=True)
        base = data_dir.resolve()
        # 22. tur güvenlik: düz önek karşılaştırması "/x/data" ile "/x/data-eski"yi aynı sayıyordu; ayırıcıyla denetle.
        if resolved_parent != base and base not in resolved_parent.parents:
            return False
        if _regular(path) is None:
            return False
        path.unlink()
        return True
    except OSError:
        return False


def _delete_audits(db_path: Path, ids: list[str]) -> int:
    if not ids:
        return 0
    con = sqlite3.connect(db_path, timeout=30)
    try:
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("BEGIN IMMEDIATE")
        deleted = 0
        for audit_id in ids:  # tek tek, sabit sorgu (dinamik IN listesi yok)
            deleted += con.execute("DELETE FROM project_audits WHERE id = ?", (audit_id,)).rowcount
        con.commit()
        return deleted
    finally:
        con.close()


def execute_plan(data_dir: Path, plan_id: str, *, log: Callable[[str, str, dict[str, Any]], None],
                 policy: dict[str, Any] | None = None, now: float | None = None,
                 environ: dict[str, str] | None = None, automatic: bool = False) -> dict[str, Any]:
    """Planı yeniden hesaplar; önizlemedeki ``plan_id`` ile aynı değilse hiçbir şey silmez (RetentionError)."""
    data_dir = Path(data_dir)
    policy = policy or load_policy(environ)
    if not policy["enabled"]:
        raise RetentionError("Saklama politikası kapalı; önce politikayı etkinleştirin (önizleme her zaman yapılabilir).")
    with ops_files._locked(data_dir / LOCK_NAME):
        plan = build_plan(data_dir, policy=policy, now=now, environ=environ)
        if plan["plan_id"] != plan_id:
            raise RetentionError("Plan önizlemeden sonra değişti; yeniden önizleyip onaylayın.")
        done: dict[str, Any] = {}
        cats = plan["categories"]
        removed = []
        for item in cats["backups"]:
            if _unlink_inside(data_dir, item["name"]):
                removed.append(item["name"])
                for sidecar in item["sidecars"]:
                    _unlink_inside(data_dir, sidecar)
        done["backups"] = removed
        if removed:
            log("data_retention.backups_deleted", "retention", {"names": removed, "automatic": automatic,
                                                               "bytes": sum(i["bytes"] for i in cats["backups"] if i["name"] in removed)})
        ids = [item["id"] for item in cats["project_audits"]]
        done["project_audits"] = _delete_audits(data_dir / "sniper.db", ids)
        if ids:
            log("data_retention.project_audits_deleted", "retention", {"ids": ids, "deleted": done["project_audits"],
                                                                      "automatic": automatic})
        doomed = {item["id"] for item in cats["notifications"]}
        if doomed:
            def change(data: Any) -> Any:
                if isinstance(data, dict) and isinstance(data.get("items"), list):
                    data["items"] = [i for i in data["items"] if not (isinstance(i, dict) and i.get("id") in doomed)]
                return data
            ops_files.update_json("notifications.json", lambda: {"items": []}, change, environ)
            log("data_retention.notifications_deleted", "retention", {"count": len(doomed), "automatic": automatic})
        done["notifications"] = len(doomed)
        jobs = [item["name"] for item in cats["jobs"] if _unlink_inside(data_dir, f"jobs/{item['name']}")]
        if jobs:
            log("data_retention.jobs_deleted", "retention", {"names": jobs, "automatic": automatic})
        done["jobs"] = jobs
        temp = [item["name"] for item in cats["temp"] if _unlink_inside(data_dir, item["name"])]
        if temp:
            log("data_retention.temp_deleted", "retention", {"count": len(temp), "automatic": automatic})
        done["temp"] = len(temp)
        caches = [item["name"] for item in cats.get("caches", []) if _remove_cache_item(data_dir, item, environ)]
        if caches:
            log("data_retention.caches_deleted", "retention", {"count": len(caches), "automatic": automatic,
                                                              "kinds": sorted({i["kind"] for i in cats["caches"]
                                                                               if i["name"] in caches})})
        done["caches"] = len(caches)
        state = {"last_run_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                 "automatic": automatic, "plan_id": plan_id, "freed_bytes": plan["total"]["bytes"]}
        try:
            ops_files.update_json(STATE_FILE, dict, lambda _old: state, environ)
        except ops_files.OpsStoreError:
            pass
    return {"executed": True, "plan_id": plan_id, "deleted": done, "freed_bytes": plan["total"]["bytes"]}


def daily_auto(data_dir: Path, *, log: Callable[[str, str, dict[str, Any]], None],
               environ: dict[str, str] | None = None, now: float | None = None) -> dict[str, Any] | None:
    """Zamanlayıcı bakım kancası: yalnız politika açık VE auto_daily seçiliyse, günde en çok bir kez çalışır."""
    try:
        policy = load_policy(environ)
    except ops_files.OpsStoreError:
        return None
    if not (policy["enabled"] and policy["auto_daily"]):
        return None
    now = time.time() if now is None else now
    try:
        state = ops_files.read_json(STATE_FILE, dict, environ)
    except ops_files.OpsStoreError:
        return None
    last = _iso_epoch(state.get("last_run_at")) if isinstance(state, dict) else None
    if last is not None and now - last < 23 * 3600:
        return None
    plan = build_plan(data_dir, policy=policy, now=now, environ=environ)
    if plan["total"]["count"] == 0:
        ops_files.update_json(STATE_FILE, dict, lambda _old: {"last_run_at": dt.datetime.fromtimestamp(now, dt.timezone.utc)
                                                               .isoformat().replace("+00:00", "Z"), "automatic": True,
                                                               "plan_id": plan["plan_id"], "freed_bytes": 0}, environ)
        return {"executed": False, "reason": "silinecek bir şey yok"}
    return execute_plan(data_dir, plan["plan_id"], log=log, policy=policy, now=now, environ=environ, automatic=True)


# ---------------------------------------------------------------------------
# Elle yedek alma
# ---------------------------------------------------------------------------
def take_backup(data_dir: Path, *, label: str = "ui") -> dict[str, Any]:
    """``sniper.db`` (ve varsa ``auth.db``) için SQLite çevrimiçi yedek API'siyle tutarlı kopya + integrity_check."""
    import community_release_info

    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", label):
        raise RetentionError("Geçersiz yedek etiketi.")
    data_dir = Path(data_dir)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
    created = []
    with ops_files._locked(data_dir / LOCK_NAME):
        for kind in ("sniper", "auth"):
            source = data_dir / f"{kind}.db"
            if _regular(source) is None:
                if kind == "sniper":
                    raise RetentionError("Canlı veritabanı bulunamadı.")
                continue
            target = data_dir / f"{kind}.db.bak-{stamp}-{label}"
            if target.exists() or target.is_symlink():
                raise RetentionError("Aynı adla yedek zaten var; bir saniye sonra yeniden deneyin.")
            try:
                result = community_release_info.backup_database(source, target)
            except Exception as exc:  # noqa: BLE001 — yarım yedek bırakma
                try:
                    target.unlink()
                except OSError:
                    pass
                raise RetentionError(f"Yedek alınamadı: {exc}") from exc
            created.append({"name": target.name, "kind": kind, "sha256": result["sha256"],
                            "integrity": result["integrity"], "bytes": target.stat().st_size})
    return {"created": created, "restore_hint": f"python3 scripts/documented Community recovery procedure --restore-db {created[0]['name']}"}


def restore_db_backup(data_dir: Path, name: str) -> dict[str, Any]:
    """CLI geri yükleme (documented Community recovery procedure --restore-db): önce güvenlik yedeği (``-pre-restore``), sonra çevrimiçi yedek API'siyle
    geri yazma ve integrity_check. Arayüzden çağrılmaz."""
    import community_release_info

    data_dir = Path(data_dir)
    match = _BACKUP_RE.match(name or "")
    if not match or "/" in name or _regular(data_dir / name) is None:
        raise RetentionError("Yedek bulunamadı (liste: documented Community recovery procedure --list-db-backups).")
    kind = match.group(1)
    live = data_dir / f"{kind}.db"
    source = data_dir / name
    check = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        result = check.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        check.close()
    if result != "ok":
        raise RetentionError(f"Yedek bütünlük denetiminden geçmedi: {result}")
    safety = None
    if _regular(live) is not None:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
        safety = data_dir / f"{kind}.db.bak-{stamp}-pre-restore"
        community_release_info.backup_database(live, safety)
    community_release_info.restore_database(source, live)
    return {"restored": name, "kind": kind, "safety_backup": safety.name if safety else None}
