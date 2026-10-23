"""Zamanlanmış yerel taramalar (Sniper süreci içinde; systemd zamanlayıcısı kurulmaz).

* Kayıt ``$SNIPER_DATA_DIR/schedules.json`` (0600, flock, atomik). Her değişiklik API'de ``confirm: true`` ister ve
  denetim kaydına yazılır.
* Yalnız yerel proje yolu taramaları zamanlanabilir (``SCAN_TYPES``); uzak hedefli araçlar (nuclei, nmap, ZAP vb.)
  listede yoktur.
* Sıklık: ``hourly [MM]``, ``daily HH:MM``, ``weekly <gün> HH:MM`` ya da 5 alanlı cron (dakika saat gün ay haftagünü).
  Varsayılan saat dilimi Europe/Istanbul; ``timezone`` ile değiştirilebilir.
* Tek arka plan iş parçacığı; işler mevcut iş kuyruğuna (job_queue) gönderilir. Aynı planın önceki işi hâlâ
  sıradaysa/çalışıyorsa yeni çalıştırma atlanır. Servis kapalıyken kaçırılan çalıştırmalar açılışta en çok bir kez
  telafi edilir (sonraki zaman şimdiden itibaren hesaplanır).
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import re
import secrets
import threading
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import ops_files

FILE_NAME = "schedules.json"
DEFAULT_TIMEZONE = "Europe/Istanbul"
MAX_SCHEDULES = 50
TICK_SECONDS = 20.0
PERIODIC_SECONDS = 3600.0  # son tarih denetimi saatte bir (bildirim bulgu/aşama başına bir kez)
_ID_RE = re.compile(r"sch_[0-9a-f]{12}\Z")
_NAME_RE = re.compile(r"[\w .,:()/+\-]{0,80}\Z", re.UNICODE)
_BASE_REF_RE = re.compile(r"(?!-)[A-Za-z0-9._/~^@{}\-]{1,120}\Z")
ACTIVE_JOB_STATES = frozenset({"queued", "running"})


class ScheduleError(ValueError):
    """Geçersiz plan, sıklık ya da işlem."""


# ---------------------------------------------------------------------------
# Tarama türleri (yalnız yerel proje yolu)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScanType:
    key: str
    label: str
    route: str
    confirm_local: bool = False
    uses_scope: bool = False
    changed_only: bool = False
    # 21. tur: hedef türü ve iş gövdesindeki alan. Plan kaydında hedef her zaman ``project_path`` alanında tutulur
    # (geriye uyum); gövdeye ``target_field`` adıyla yazılır. project → dizin, image → imaj dosyası/rootfs,
    # sbom → SBOM dosyası. Yol doğrulaması hedef türüne göre (izinli kökler) sunucuda yapılır.
    target_kind: str = "project"
    target_field: str = "project_path"
    confirm_field: str = "confirm_local"


TARGET_LABELS = {
    "project": ("Yerel proje yolu", "/home/community-user/proje"),
    "image": ("Yerel imaj dosyası ya da rootfs dizini", "/home/community-user/imajlar/uygulama.tar"),
    "sbom": ("Yerel SBOM dosyası (CycloneDX/SPDX)", "/home/community-user/sbom/uygulama.cdx.json"),
    "directory": ("Kök dizin (altındaki tüm depolar)", "/home/community-user/projeler"),
}


SCAN_TYPES: dict[str, ScanType] = {
    item.key: item for item in (
        ScanType("project_audit", "Proje analizi", "/api/project-audits", uses_scope=True),
        ScanType("project_changed", "Proje analizi — yalnız değişenler (git)", "/api/project-audits", changed_only=True),
        ScanType("dependency_sbom", "Bağımlılık envanteri (CycloneDX SBOM)", "/api/dependency-security/sbom"),
        ScanType("dependency_osv", "Bağımlılık güvenliği (OSV-Scanner, çevrimdışı)", "/api/tool-runs/osv-scanner-local", confirm_local=True),
        ScanType("secrets_gitleaks", "Sır taraması (gitleaks)", "/api/tool-runs/gitleaks", confirm_local=True),
        ScanType("secrets_trufflehog", "Sır taraması (TruffleHog dosya sistemi)", "/api/tool-runs/trufflehog-filesystem", confirm_local=True),
        # 21. tur: çevrimdışı çok ekosistemli SCA, konteyner imajı / rootfs ve SBOM dosyası taramaları
        ScanType("dependency_offline", "Bağımlılık açıkları (çevrimdışı OSV, tüm ekosistemler)",
                 "/api/dependency-security/offline-scan", confirm_local=True),
        ScanType("container_image", "Konteyner imajı / rootfs taraması", "/api/container-images",
                 target_kind="image", target_field="image_path"),
        ScanType("sbom_file", "SBOM dosyası taraması (çevrimdışı OSV)", "/api/dependency-security/sbom-scan",
                 confirm_local=True, target_kind="sbom", target_field="sbom_path", confirm_field="confirm"),
        # 25. tur: kök dizindeki tüm depolar (keşif + proje analizi + çevrimdışı SCA; değişmeyen commit atlanır).
        # Sunucu bu türü iş kuyruğuna doğrudan toplu tarama yürütücüsü olarak gönderir (bulk_scan.py).
        ScanType("bulk_repos", "Toplu depo taraması (kök dizindeki tüm depolar)", "/api/bulk-scans",
                 target_kind="directory", target_field="root"),
    )
}
SCAN_ROUTES = frozenset(item.route for item in SCAN_TYPES.values())


def _changed_scan_supported() -> bool:
    import scan_scope
    return "changed_only" in getattr(scan_scope, "_ALLOWED_KEYS", ())


def available_scan_types() -> list[dict[str, Any]]:
    out = []
    for item in SCAN_TYPES.values():
        if item.changed_only and not _changed_scan_supported():
            continue
        target_label, placeholder = TARGET_LABELS[item.target_kind]
        out.append({"key": item.key, "label": item.label, "uses_scope": item.uses_scope, "base_ref": item.changed_only,
                    "target_kind": item.target_kind, "target_label": target_label, "target_placeholder": placeholder})
    return out


def job_request(schedule: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Planın iş kuyruğuna gidecek (rota, gövde) çifti."""
    item = SCAN_TYPES[schedule["scan_type"]]
    payload: dict[str, Any] = {item.target_field: schedule["project_path"]}
    if item.confirm_local:
        payload[item.confirm_field] = True
    if item.uses_scope and schedule.get("scope"):
        payload["scope"] = schedule["scope"]
    if item.changed_only:
        payload["scope"] = {"changed_only": True, "base_ref": schedule.get("base_ref") or "HEAD~1"}
    return item.route, payload


# ---------------------------------------------------------------------------
# Sıklık
# ---------------------------------------------------------------------------
_DAYS = {
    "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
    "paz": 0, "pzt": 1, "sal": 2, "çar": 3, "car": 3, "per": 4, "cum": 5, "cmt": 6,
}
_FIELDS = (("dakika", 0, 59), ("saat", 0, 23), ("gün", 1, 31), ("ay", 1, 12), ("haftagünü", 0, 7))


@dataclass(frozen=True)
class CronSpec:
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = pazar
    day_any: bool
    weekday_any: bool
    text: str

    def matches(self, moment: dt.datetime) -> bool:
        if moment.minute not in self.minutes or moment.hour not in self.hours or moment.month not in self.months:
            return False
        return self._day_ok(moment)

    def _day_ok(self, moment: dt.datetime) -> bool:
        weekday = (moment.weekday() + 1) % 7
        day_hit = moment.day in self.days
        weekday_hit = weekday in self.weekdays
        if self.day_any and self.weekday_any:
            return True
        if self.day_any:
            return weekday_hit
        if self.weekday_any:
            return day_hit
        return day_hit or weekday_hit  # cron: ikisi de kısıtlıysa VEYA


def _parse_field(text: str, name: str, low: int, high: int) -> tuple[frozenset[int], bool]:
    values: set[int] = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            if not step_text.isdigit() or int(step_text) < 1:
                raise ScheduleError(f"Geçersiz {name} adımı.")
            step = int(step_text)
        if part == "*":
            start, end = low, high
        elif "-" in part:
            a, b = part.split("-", 1)
            if not (a.isdigit() and b.isdigit()):
                raise ScheduleError(f"Geçersiz {name} aralığı.")
            start, end = int(a), int(b)
        elif part.isdigit():
            start = end = int(part)
            if step != 1:
                end = high
        else:
            raise ScheduleError(f"Geçersiz {name} değeri: {part!r}.")
        if not (low <= start <= high and low <= end <= high and start <= end):
            raise ScheduleError(f"{name} {low}–{high} aralığında olmalı.")
        values.update(range(start, end + 1, step))
    if name == "haftagünü" and 7 in values:
        values.discard(7)
        values.add(0)
    return frozenset(values), text == "*"


def _hhmm(text: str) -> tuple[int, int]:
    match = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", text)
    if not match:
        raise ScheduleError("Saat HH:MM biçiminde olmalı (ör. 03:00).")
    return int(match.group(1)), int(match.group(2))


def parse_frequency(text: Any) -> CronSpec:
    """``hourly [MM]`` | ``daily HH:MM`` | ``weekly <gün> HH:MM`` | 5 alanlı cron."""
    if not isinstance(text, str) or not text.strip() or len(text) > 100:
        raise ScheduleError("Sıklık gerekli (ör. 'daily 03:00', 'weekly mon 02:30', 'hourly 15' ya da cron).")
    raw = " ".join(text.strip().casefold().split())
    parts = raw.split(" ")
    if parts[0] in {"hourly", "@hourly", "saatlik"}:
        minute = parts[1] if len(parts) > 1 else "0"
        if len(parts) > 2 or not minute.isdigit() or int(minute) > 59:
            raise ScheduleError("Saatlik sıklık: 'hourly' ya da 'hourly MM' (0–59).")
        cron = f"{int(minute)} * * * *"
    elif parts[0] in {"daily", "@daily", "günlük", "gunluk"}:
        if len(parts) > 2:
            raise ScheduleError("Günlük sıklık: 'daily HH:MM'.")
        hour, minute = _hhmm(parts[1]) if len(parts) == 2 else (0, 0)
        cron = f"{minute} {hour} * * *"
    elif parts[0] in {"weekly", "@weekly", "haftalık", "haftalik"}:
        if len(parts) != 3 or parts[1] not in _DAYS:
            raise ScheduleError("Haftalık sıklık: 'weekly <gün> HH:MM' (gün: mon..sun ya da pzt..paz).")
        hour, minute = _hhmm(parts[2])
        cron = f"{minute} {hour} * * {_DAYS[parts[1]]}"
    elif len(parts) == 5:
        cron = raw
    else:
        raise ScheduleError("Sıklık tanınmadı: 'hourly', 'daily HH:MM', 'weekly <gün> HH:MM' ya da 5 alanlı cron.")
    fields = cron.split(" ")
    parsed = [_parse_field(value, name, low, high) for value, (name, low, high) in zip(fields, _FIELDS)]
    return CronSpec(
        minutes=parsed[0][0], hours=parsed[1][0], days=parsed[2][0], months=parsed[3][0], weekdays=parsed[4][0],
        day_any=parsed[2][1], weekday_any=parsed[4][1], text=cron,
    )


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ScheduleError(f"Bilinmeyen saat dilimi: {name}") from exc


def next_run(spec: CronSpec, after: dt.datetime, tz: ZoneInfo) -> dt.datetime:
    """``after``'dan (hariç) sonraki ilk eşleşen dakika (UTC, saniyesiz)."""
    local = after.astimezone(tz).replace(second=0, microsecond=0, tzinfo=None) + dt.timedelta(minutes=1)
    limit = local + dt.timedelta(days=366 * 5)
    while local < limit:
        if local.month not in spec.months:
            local = (local.replace(day=1, hour=0, minute=0) + dt.timedelta(days=32)).replace(day=1)
            continue
        if not spec._day_ok(local):
            local = local.replace(hour=0, minute=0) + dt.timedelta(days=1)
            continue
        if local.hour not in spec.hours:
            local = local.replace(minute=0) + dt.timedelta(hours=1)
            continue
        if local.minute not in spec.minutes:
            local += dt.timedelta(minutes=1)
            continue
        return local.replace(tzinfo=tz).astimezone(dt.timezone.utc)
    raise ScheduleError("Sıklık hiçbir zaman eşleşmiyor.")


# ---------------------------------------------------------------------------
# Kayıt
# ---------------------------------------------------------------------------
def _default() -> dict[str, Any]:
    return {"format": 1, "timezone": DEFAULT_TIMEZONE, "schedules": []}


def _normalize(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("schedules"), list):
        return _default()
    data.setdefault("timezone", DEFAULT_TIMEZONE)
    return data


def _iso(moment: dt.datetime | None) -> str | None:
    return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") if moment else None


def _parse_iso(text: Any) -> dt.datetime | None:
    if not isinstance(text, str):
        return None
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def load(environ: dict[str, str] | None = None) -> dict[str, Any]:
    return _normalize(ops_files.read_json(FILE_NAME, _default, environ))


def timezone_name(environ: dict[str, str] | None = None) -> str:
    try:
        return load(environ).get("timezone") or DEFAULT_TIMEZONE
    except ops_files.OpsStoreError:
        return DEFAULT_TIMEZONE


def _validate_fields(fields: dict[str, Any], current: dict[str, Any] | None, validate_path: Callable[[str], str]) -> dict[str, Any]:
    allowed = {"name", "project_path", "scan_type", "scope", "frequency", "enabled", "base_ref"}
    unknown = set(fields) - allowed
    if unknown:
        raise ScheduleError("Bilinmeyen alan: " + ", ".join(sorted(unknown)))
    out = dict(current or {})
    if "name" in fields or current is None:
        name = fields.get("name", "")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise ScheduleError("Ad en çok 80 karakter; harf, rakam ve sınırlı noktalama.")
        out["name"] = name.strip()
    if "scan_type" in fields or current is None:
        scan_type = fields.get("scan_type", "project_audit")
        if scan_type not in {item["key"] for item in available_scan_types()}:
            raise ScheduleError("Bu tarama türü zamanlanamaz (yalnız yerel proje yolu taramaları).")
        out["scan_type"] = scan_type
    kind = SCAN_TYPES[out["scan_type"]].target_kind
    kind_changed = current is not None and "scan_type" in fields and \
        SCAN_TYPES.get(current.get("scan_type", ""), SCAN_TYPES["project_audit"]).target_kind != kind
    if "project_path" in fields or current is None or kind_changed:
        path = fields.get("project_path", out.get("project_path"))
        if not isinstance(path, str) or not path.strip():
            raise ScheduleError("Hedef yol gerekli." if kind != "project" else "Proje yolu gerekli.")
        # Proje türleri eski tek argümanlı doğrulayıcıyla; imaj/SBOM hedefleri tür bilgisiyle doğrulanır.
        out["project_path"] = validate_path(path) if kind == "project" else validate_path(path, kind)
    if "frequency" in fields or current is None:
        spec = parse_frequency(fields.get("frequency"))
        out["frequency"] = " ".join(str(fields["frequency"]).split())
        out["cron"] = spec.text
    if "scope" in fields:
        scope = fields["scope"]
        if scope is not None:
            import scan_scope
            try:
                parsed = scan_scope.parse_scope(scope)
            except scan_scope.ScopeError as exc:
                raise ScheduleError(str(exc)) from exc
            if getattr(parsed, "skipped_only", False):
                raise ScheduleError("'Yalnız atlananlar' modu zamanlanamaz (tek seferlik ek taramadır).")
        out["scope"] = scope
    if "base_ref" in fields:
        ref = fields["base_ref"]
        if ref is not None and (not isinstance(ref, str) or not _BASE_REF_RE.fullmatch(ref) or ".." in ref):
            raise ScheduleError("Geçersiz git tabanı (ör. HEAD~1, origin/main).")
        out["base_ref"] = ref
    if "enabled" in fields or current is None:
        enabled = fields.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ScheduleError("enabled true/false olmalı.")
        out["enabled"] = enabled
    if not SCAN_TYPES[out["scan_type"]].uses_scope:
        out.pop("scope", None)
    if not SCAN_TYPES[out["scan_type"]].changed_only:
        out.pop("base_ref", None)
    return out


def apply_action(action: str, payload: dict[str, Any], *, validate_path: Callable[[str], str],
                 now: dt.datetime | None = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """create | update | delete | enable | disable | timezone. Sonuç: {"schedule"/"timezone", "data"}."""
    now = now or dt.datetime.now(dt.timezone.utc)
    result: dict[str, Any] = {}

    def change(data: Any) -> dict[str, Any]:
        data = _normalize(data)
        tz = zone(data["timezone"])
        schedules: list[dict[str, Any]] = data["schedules"]
        if action == "timezone":
            name = payload.get("timezone")
            if not isinstance(name, str):
                raise ScheduleError("timezone gerekli (ör. Europe/Istanbul).")
            tz = zone(name)
            data["timezone"] = name
            for item in schedules:
                item["next_run_at"] = _iso(next_run(parse_frequency_cron(item), now, tz)) if item.get("enabled") else None
            result["timezone"] = name
            return data
        if action == "create":
            if len(schedules) >= MAX_SCHEDULES:
                raise ScheduleError(f"En çok {MAX_SCHEDULES} plan tanımlanabilir.")
            fields = _validate_fields(payload.get("schedule") or {}, None, validate_path)
            item = {
                "id": "sch_" + secrets.token_hex(6), **fields,
                "created_at": _iso(now), "updated_at": _iso(now), "last_run_at": None, "last_job_id": None,
                "last_status": None, "last_finished_at": None, "run_count": 0,
            }
            item["next_run_at"] = _iso(next_run(parse_frequency_cron(item), now, tz)) if item["enabled"] else None
            schedules.append(item)
            result["schedule"] = item
            return data
        schedule_id = payload.get("id")
        if not isinstance(schedule_id, str) or not _ID_RE.fullmatch(schedule_id):
            raise ScheduleError("Geçerli plan kimliği gerekli.")
        index = next((i for i, item in enumerate(schedules) if item.get("id") == schedule_id), None)
        if index is None:
            raise ScheduleError("Plan bulunamadı.")
        item = schedules[index]
        if action == "delete":
            schedules.pop(index)
            result["schedule"] = item
            return data
        if action in {"enable", "disable"}:
            fields = {"enabled": action == "enable"}
        elif action == "update":
            fields = payload.get("schedule") or {}
        else:
            raise ScheduleError("Geçersiz işlem.")
        updated = _validate_fields(fields, item, validate_path)
        updated["updated_at"] = _iso(now)
        updated["next_run_at"] = _iso(next_run(parse_frequency_cron(updated), now, tz)) if updated["enabled"] else None
        schedules[index] = updated
        result["schedule"] = updated
        return data

    data = ops_files.update_json(FILE_NAME, _default, change, environ)
    result["data"] = data
    return result


def parse_frequency_cron(item: dict[str, Any]) -> CronSpec:
    return parse_frequency(item.get("cron") or item.get("frequency"))


def public(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "timezone": data.get("timezone") or DEFAULT_TIMEZONE,
        "schedules": data.get("schedules") or [],
        "scan_types": available_scan_types(),
        "max_schedules": MAX_SCHEDULES,
    }


# ---------------------------------------------------------------------------
# Çalıştırıcı
# ---------------------------------------------------------------------------
class Scheduler:
    """``submit(plan) -> iş kimliği`` ve ``job_state(iş kimliği) -> durum`` ile iş kuyruğuna bağlanır."""

    def __init__(
        self,
        *,
        submit: Callable[[dict[str, Any]], str],
        job_state: Callable[[str], str | None],
        log: Callable[[str, str, dict[str, Any]], None] | None = None,
        clock: Callable[[], dt.datetime] | None = None,
        environ: dict[str, str] | None = None,
        maintenance: Callable[[], Any] | None = None,
        periodic: Callable[[dt.datetime], Any] | None = None,
        periodic_interval: float = PERIODIC_SECONDS,
    ) -> None:
        self.submit = submit
        # Her turdan sonra çağrılan bakım kancası (ör. günlük öz sağlık denetimi; kendi aralığını kendisi tutar).
        self.maintenance = maintenance
        # Plan dışı dönemsel denetim (ör. bulgu son tarihi hatırlatmaları); hata zamanlayıcıyı durdurmaz.
        self.periodic = periodic
        self.periodic_interval = periodic_interval
        self._last_periodic: dt.datetime | None = None
        self.job_state = job_state
        self.log = log or (lambda *_args: None)
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.environ = environ
        self._stop = threading.Event()
        self._lock = threading.Lock()  # tick ve elle çalıştırma aynı anda plan kaydını yazmasın

    # -- tek plan çalıştırma ---------------------------------------------------
    def _run(self, item: dict[str, Any], now: dt.datetime, *, reason: str) -> dict[str, Any]:
        previous = item.get("last_job_id")
        if previous and self.job_state(previous) in ACTIVE_JOB_STATES:
            item["last_status"] = "skipped_overlap"
            self.log("schedule.skipped", item["id"], {"reason": "overlap", "job_id": previous, "trigger": reason})
            return {"id": item["id"], "status": "skipped_overlap", "job_id": previous}
        try:
            job_id = self.submit(item)
        except Exception as exc:  # kuyruk dolu / aynı hedefte elle başlatılmış iş vb.
            status = "skipped_duplicate" if type(exc).__name__ == "DuplicateJob" else "submit_failed"
            item["last_status"] = status
            item["last_error"] = type(exc).__name__
            self.log("schedule.skipped", item["id"], {"reason": status, "error": type(exc).__name__, "trigger": reason})
            return {"id": item["id"], "status": status}
        item.update(last_run_at=_iso(now), last_job_id=job_id, last_status="submitted", last_finished_at=None,
                    run_count=int(item.get("run_count") or 0) + 1)
        item.pop("last_error", None)
        self.log("schedule.run", item["id"], {"job_id": job_id, "trigger": reason, "scan_type": item.get("scan_type")})
        return {"id": item["id"], "status": "submitted", "job_id": job_id, "trigger": reason}

    def tick(self) -> list[dict[str, Any]]:
        """Zamanı gelen etkin planları bir kez çalıştır; kaçırılan çalıştırmalar en çok bir kez telafi edilir."""
        now = self.clock()
        results: list[dict[str, Any]] = []

        def change(data: Any) -> dict[str, Any]:
            data = _normalize(data)
            tz = zone(data["timezone"])
            for item in data["schedules"]:
                if not item.get("enabled"):
                    continue
                try:
                    spec = parse_frequency_cron(item)
                except ScheduleError:
                    item["enabled"] = False
                    item["last_status"] = "invalid_frequency"
                    continue
                due = _parse_iso(item.get("next_run_at"))
                if due is None:
                    item["next_run_at"] = _iso(next_run(spec, now, tz))
                    continue
                if due > now:
                    continue
                missed = (now - due).total_seconds() > max(120.0, 3 * TICK_SECONDS)
                results.append(self._run(item, now, reason="catch_up" if missed else "schedule"))
                item["next_run_at"] = _iso(next_run(spec, now, tz))  # birden çok kaçırılan zaman tek çalıştırmaya iner
            return data

        with self._lock:
            ops_files.update_json(FILE_NAME, _default, change, self.environ)
        self._run_periodic(now)
        return results

    def _run_periodic(self, now: dt.datetime) -> None:
        if self.periodic is None:
            return
        if self._last_periodic is not None and (now - self._last_periodic).total_seconds() < self.periodic_interval:
            return
        self._last_periodic = now
        try:
            self.periodic(now)
        except Exception:  # denetim hatası planları etkilemez
            import traceback
            traceback.print_exc()

    def run_now(self, schedule_id: str) -> dict[str, Any]:
        now = self.clock()
        outcome: dict[str, Any] = {}

        def change(data: Any) -> dict[str, Any]:
            data = _normalize(data)
            item = next((s for s in data["schedules"] if s.get("id") == schedule_id), None)
            if item is None:
                raise ScheduleError("Plan bulunamadı.")
            outcome.update(self._run(item, now, reason="manual"))
            return data

        with self._lock:
            ops_files.update_json(FILE_NAME, _default, change, self.environ)
        return outcome

    def on_job_finished(self, job_id: str, state: str, finished_at: str | None) -> dict[str, Any] | None:
        """İş bitince ilgili planın son durumunu güncelle; plan varsa kopyasını döndür."""
        found: dict[str, Any] = {}

        def change(data: Any) -> dict[str, Any]:
            data = _normalize(data)
            for item in data["schedules"]:
                if item.get("last_job_id") == job_id:
                    item["last_status"] = state
                    item["last_finished_at"] = finished_at
                    found.update(item)
            return data

        with self._lock:
            ops_files.update_json(FILE_NAME, _default, change, self.environ)
        return found or None

    # -- iş parçacığı ----------------------------------------------------------
    def loop(self, interval: float = TICK_SECONDS) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # zamanlayıcı hiçbir koşulda servisi düşürmez
                import traceback
                traceback.print_exc()
            if self.maintenance is not None:
                try:
                    self.maintenance()
                except Exception:  # bakım hatası zamanlayıcıyı durdurmaz
                    import traceback
                    traceback.print_exc()
            self._stop.wait(interval)

    def start(self, interval: float = TICK_SECONDS) -> threading.Thread:
        thread = threading.Thread(target=self.loop, args=(interval,), name="sniper-scheduler", daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self._stop.set()

