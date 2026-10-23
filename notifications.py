"""Yerel bildirimler: tarama sonuçlarından olay üretir ve yapılandırılmış kanallara iletir.

Olaylar: ``new_findings`` (önceki tam analize göre yeni, eşik ve üstü önemde bulgu), ``fixed_findings`` (önceki
analizde olup artık görünmeyen bulgular), ``scan_failed`` (iş kuyruğundaki tarama başarısız/süre aşımı).

Kanallar:
* ``center`` — arayüz içi bildirim merkezi (her zaman açık; ``$SNIPER_DATA_DIR/notifications.json``, en çok 500).
* ``desktop`` — ``notify-send`` varsa ve oturum masaüstü/D-Bus ortamı varsa; yoksa sessizce atlanır.
* ``smtp`` — yalnız kullanıcı yapılandırırsa (varsayılan kapalı). Parola ayrı dosyada (0600) tutulur; API
  yanıtlarına, günlüğe ve denetim kaydına asla yazılmaz (yalnız ``password_set``).
* ``webhook`` — yalnız geri döngü (127.0.0.0/8, ::1) ya da özel ağ (RFC 1918, fc00::/7) adresine; yerel bağlantı
  (169.254/16, metadata) ve dış adresler reddedilir, yönlendirme izlenmez.

Sessiz saatlerde dış kanallar (masaüstü, SMTP, webhook) susturulur; merkez her zaman kaydeder. Kritik olaylar
isteğe bağlı olarak sessiz saatleri deler.

"Yeni/düzelen bulgu" tespiti tek bir fonksiyonun (``project_audit_changes``) arkasındadır; kalıcı bulgu takibi
(finding_tracking) birleştiğinde yalnız bu fonksiyon değiştirilir.
"""
from __future__ import annotations

import datetime as dt
from email.message import EmailMessage
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import smtplib
import socket
import ssl
from pathlib import Path
import subprocess
from typing import Any, Callable
from urllib.parse import urlsplit

import ops_files

CENTER_FILE = "notifications.json"
SETTINGS_FILE = "notification-settings.json"
SMTP_PASSWORD_FILE = "notification-smtp-password"
MAX_CENTER_ITEMS = 500
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
EVENT_TYPES = ("new_findings", "fixed_findings", "scan_failed", "system_health", "finding_assigned", "finding_due",
               "analysis_finished", "sla_breach", "risk_expired",
               # 21. tur: bağımlılık güvenliği / konteyner / lisans / çevrimdışı OSV tazeliği
               "malicious_package", "sca_fix_first", "container_critical", "license_forbidden", "osv_db_stale")
DEDUPE_FILE = "notification-dedupe.json"  # olay başına "görüldü" anahtarları (aynı bulgu tekrar bildirilmez)
MAX_DEDUPE_PER_EVENT = 5000
OSV_STALE_DAYS = 7
MAX_DUE_DAYS_BEFORE = 30
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}\Z")
_HOST_RE = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?\Z")
_TIME_RE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)\Z")
_ID_RE = re.compile(r"ntf_[0-9a-f]{16}\Z")


class NotificationError(ValueError):
    """Geçersiz bildirim ayarı."""


# ---------------------------------------------------------------------------
# Ayarlar
# ---------------------------------------------------------------------------
def default_settings() -> dict[str, Any]:
    return {
        "format": 1,
        "events": {
            "new_findings": {"enabled": True, "min_severity": "high"},
            "fixed_findings": {"enabled": True},
            "scan_failed": {"enabled": True},
            "system_health": {"enabled": True},  # öz sağlık panosu: yeni sorun ya da 24 saattir süren sorun
            # 16. tur: bulgu atanınca ve son tarih yaklaşınca/geçince (bulgu başına, aşama başına bir kez).
            "finding_assigned": {"enabled": True},
            "finding_due": {"enabled": True, "days_before": 2},
            # 17. tur: arka planda (iş kuyruğu) başlatılan proje analizi bitti; sayfa kapalı olsa da haber verir.
            "analysis_finished": {"enabled": True},
            # 17. tur: SLA süresi geçen (elle son tarihi olmayan) etkin bulgular ve süresi dolan risk kabulleri.
            "sla_breach": {"enabled": True},
            "risk_expired": {"enabled": True},
            # 21. tur: kötü amaçlı paket her zaman kritik ve sessiz saatleri aşar (kanal kısıtlaması yok); diğerleri
            # bulgu/paket başına bir kez (notification-dedupe.json), OSV tazeliği günde en çok bir kez.
            "malicious_package": {"enabled": True},
            "sca_fix_first": {"enabled": True},
            "container_critical": {"enabled": True},
            "license_forbidden": {"enabled": True},
            "osv_db_stale": {"enabled": True},
        },
        "channels": {
            "desktop": {"enabled": False},
            "smtp": {"enabled": False, "host": "", "port": 587, "security": "starttls", "username": "",
                     "from_addr": "", "to": []},
            "webhook": {"enabled": False, "url": ""},
        },
        "quiet_hours": {"enabled": False, "start": "22:00", "end": "08:00", "allow_critical": True},
    }


def _merge(base: dict[str, Any], extra: Any) -> dict[str, Any]:
    out = json.loads(json.dumps(base))
    if isinstance(extra, dict):
        for key, value in extra.items():
            if key in out and isinstance(out[key], dict) and isinstance(value, dict):
                out[key] = _merge(out[key], value)
            elif key in out:
                out[key] = value
    return out


def load_settings(environ: dict[str, str] | None = None) -> dict[str, Any]:
    return _merge(default_settings(), ops_files.read_json(SETTINGS_FILE, default_settings, environ))


def _password_path(environ: dict[str, str] | None = None):
    return ops_files.data_dir(environ) / SMTP_PASSWORD_FILE


def _password(environ: dict[str, str] | None = None) -> str | None:
    path = _password_path(environ)
    try:
        if path.is_symlink():
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        value = handle.read(1025).decode("utf-8", errors="replace").rstrip("\n")
    return value or None


def public_settings(environ: dict[str, str] | None = None) -> dict[str, Any]:
    settings = load_settings(environ)
    settings["channels"]["smtp"]["password_set"] = _password(environ) is not None
    settings["desktop_available"] = desktop_available()
    return settings


def _check_time(text: Any, name: str) -> str:
    if not isinstance(text, str) or not _TIME_RE.fullmatch(text):
        raise NotificationError(f"{name} HH:MM biçiminde olmalı.")
    return text


def _clean_header(text: str) -> str:
    return text.replace("\r", " ").replace("\n", " ")


def validate_settings(raw: Any) -> dict[str, Any]:
    """Tam ya da kısmi ayar nesnesini doğrula ve varsayılanla birleştir."""
    if not isinstance(raw, dict):
        raise NotificationError("settings bir JSON nesnesi olmalı.")
    allowed = {"events", "channels", "quiet_hours", "format", "desktop_available"}
    if set(raw) - allowed:
        raise NotificationError("Bilinmeyen ayar: " + ", ".join(sorted(set(raw) - allowed)))
    merged = _merge(default_settings(), raw)
    for name, event in merged["events"].items():
        if not isinstance(event.get("enabled"), bool):
            raise NotificationError(f"events.{name}.enabled true/false olmalı.")
    if merged["events"]["new_findings"].get("min_severity") not in SEVERITY_ORDER:
        raise NotificationError("min_severity low/medium/high/critical olmalı.")
    days_before = merged["events"]["finding_due"].get("days_before")
    if type(days_before) is not int or not 0 <= days_before <= MAX_DUE_DAYS_BEFORE:
        raise NotificationError(f"finding_due.days_before 0–{MAX_DUE_DAYS_BEFORE} arası tam sayı olmalı.")
    channels = merged["channels"]
    for name in ("desktop", "smtp", "webhook"):
        if not isinstance(channels[name].get("enabled"), bool):
            raise NotificationError(f"channels.{name}.enabled true/false olmalı.")
    smtp = channels["smtp"]
    if smtp["security"] not in {"starttls", "ssl", "none"}:
        raise NotificationError("SMTP güvenliği starttls, ssl veya none olmalı.")
    if type(smtp["port"]) is not int or not 1 <= smtp["port"] <= 65535:
        raise NotificationError("SMTP portu 1–65535 olmalı.")
    for key in ("host", "username", "from_addr"):
        if not isinstance(smtp[key], str) or len(smtp[key]) > 254:
            raise NotificationError(f"SMTP {key} metin olmalı.")
        smtp[key] = _clean_header(smtp[key].strip())
    if not isinstance(smtp["to"], list) or len(smtp["to"]) > 10 or not all(isinstance(x, str) for x in smtp["to"]):
        raise NotificationError("SMTP alıcıları en çok 10 adreslik liste olmalı.")
    smtp["to"] = [_clean_header(x.strip()) for x in smtp["to"] if x.strip()]
    if smtp["enabled"]:
        if not _HOST_RE.fullmatch(smtp["host"]):
            raise NotificationError("SMTP sunucusu gerekli (ad ya da IP).")
        if not _EMAIL_RE.fullmatch(smtp["from_addr"]) or not smtp["to"] or not all(_EMAIL_RE.fullmatch(x) for x in smtp["to"]):
            raise NotificationError("Geçerli gönderen ve en az bir alıcı e-posta adresi gerekli.")
    webhook = channels["webhook"]
    if not isinstance(webhook["url"], str) or len(webhook["url"]) > 500:
        raise NotificationError("Webhook adresi metin olmalı.")
    if webhook["enabled"] or webhook["url"]:
        validate_webhook_url(webhook["url"])
    quiet = merged["quiet_hours"]
    if not isinstance(quiet.get("enabled"), bool) or not isinstance(quiet.get("allow_critical"), bool):
        raise NotificationError("quiet_hours.enabled/allow_critical true/false olmalı.")
    _check_time(quiet["start"], "Sessiz saat başlangıcı")
    _check_time(quiet["end"], "Sessiz saat bitişi")
    merged["format"] = 1
    return merged


def save_settings(raw: Any, *, smtp_password: Any = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Ayarları kaydet. ``smtp_password``: None → değişmez, "" → silinir, metin → 0600 dosyaya yazılır."""
    settings = validate_settings(raw)
    if smtp_password is not None:
        if not isinstance(smtp_password, str) or len(smtp_password) > 1024 or "\n" in smtp_password or "\r" in smtp_password:
            raise NotificationError("SMTP parolası en çok 1024 karakterlik tek satır olmalı.")
        path = _password_path(environ)
        if smtp_password:
            ops_files.write_private(path, smtp_password.encode("utf-8"))
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    ops_files.update_json(SETTINGS_FILE, default_settings, lambda _old: settings, environ)
    return public_settings(environ)


# ---------------------------------------------------------------------------
# Kanallar
# ---------------------------------------------------------------------------
def _allowed_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _allowed_ip(str(ip.ipv4_mapped))
    return ip.is_loopback or ip.is_private


def validate_webhook_url(url: str) -> tuple[str, str, int, str, list[str]]:
    """(şema, ana makine, port, yol, izinli IP'ler). Dış ya da yerel bağlantı adresleri reddedilir."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise NotificationError("Webhook adresi kimlik bilgisi içermeyen http(s) adresi olmalı.")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise NotificationError("Webhook ana makinesi çözümlenemedi.") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses or not all(_allowed_ip(addr) for addr in addresses):
        raise NotificationError("Webhook yalnız yerel (127.0.0.1/::1) ya da özel ağ adresine gönderilebilir; dış adresler reddedilir.")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return parts.scheme, host, port, path, addresses


def desktop_available() -> bool:
    env = os.environ
    return bool(shutil.which("notify-send")) and bool(
        env.get("DISPLAY") or env.get("WAYLAND_DISPLAY") or env.get("DBUS_SESSION_BUS_ADDRESS"))


def _send_desktop(item: dict[str, Any]) -> str:
    if not desktop_available():
        return "unavailable"
    urgency = "critical" if item["severity"] == "critical" else "normal"
    try:
        result = subprocess.run(
            [shutil.which("notify-send") or "notify-send", "--app-name=Sniper", f"--urgency={urgency}", "--",
             item["title"][:200], item["message"][:600]],
            capture_output=True, timeout=5, check=False, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"failed:{type(exc).__name__}"
    return "sent" if result.returncode == 0 else "failed:exit"


def _send_smtp(item: dict[str, Any], config: dict[str, Any], environ: dict[str, str] | None,
               smtp_factory: Callable[..., Any] | None = None) -> str:
    message = EmailMessage()
    message["Subject"] = _clean_header("[Sniper] " + item["title"])[:200]
    message["From"] = config["from_addr"]
    message["To"] = ", ".join(config["to"])
    message.set_content(item["message"] + "\n\n" + "\n".join(item.get("details") or []) +
                        "\n\nBu ileti yerel Sniper kurulumunuzdan gönderildi.")
    password = _password(environ)
    try:
        if smtp_factory is not None:
            client = smtp_factory(config["host"], config["port"])
        elif config["security"] == "ssl":
            client = smtplib.SMTP_SSL(config["host"], config["port"], timeout=10, context=ssl.create_default_context())
        else:
            client = smtplib.SMTP(config["host"], config["port"], timeout=10)
        with client:
            if config["security"] == "starttls":
                client.starttls(context=ssl.create_default_context())
            if config["username"] and password:
                client.login(config["username"], password)
            client.send_message(message)
    except Exception as exc:  # parola ya da sunucu yanıtı asla dışarı yazılmaz; yalnız hata sınıfı
        return f"failed:{type(exc).__name__}"
    return "sent"


def _send_webhook(item: dict[str, Any], url: str) -> str:
    try:
        scheme, host, port, path, addresses = validate_webhook_url(url)
    except NotificationError:
        return "failed:rejected_address"
    body = json.dumps({"source": "sniper", **{k: item[k] for k in ("id", "created_at", "event", "severity", "title", "message", "data")}},
                      ensure_ascii=False).encode("utf-8")
    try:
        if scheme == "http":
            # Çözümlenen (doğrulanmış) adrese bağlan: DNS yeniden bağlama ile dış adrese kaçamaz.
            conn = http.client.HTTPConnection(addresses[0], port, timeout=5)
        else:
            conn = http.client.HTTPSConnection(host, port, timeout=5, context=ssl.create_default_context())
        conn.request("POST", path, body=body, headers={"Host": host if port in (80, 443) else f"{host}:{port}",
                                                      "Content-Type": "application/json", "User-Agent": "Sniper-notify/1"})
        status = conn.getresponse().status
        conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return f"failed:{type(exc).__name__}"
    return "sent" if 200 <= status < 300 else f"failed:http_{status}"  # 3xx yönlendirmeleri izlenmez


def _in_quiet_hours(quiet: dict[str, Any], now: dt.datetime, tz_name: str) -> bool:
    if not quiet.get("enabled"):
        return False
    from zoneinfo import ZoneInfo
    try:
        local = now.astimezone(ZoneInfo(tz_name))
    except Exception:
        local = now
    minutes = local.hour * 60 + local.minute
    sh, sm = map(int, quiet["start"].split(":"))
    eh, em = map(int, quiet["end"].split(":"))
    start, end = sh * 60 + sm, eh * 60 + em
    if start == end:
        return False
    return start <= minutes < end if start < end else (minutes >= start or minutes < end)


# ---------------------------------------------------------------------------
# Merkez ve gönderim
# ---------------------------------------------------------------------------
def _center_default() -> dict[str, Any]:
    return {"format": 1, "items": []}


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def emit(event: str, severity: str, title: str, message: str, *, details: list[str] | None = None,
         data: dict[str, Any] | None = None, now: dt.datetime | None = None, force: bool = False,
         environ: dict[str, str] | None = None, smtp_factory: Callable[..., Any] | None = None,
         bypass_quiet: bool = False) -> dict[str, Any] | None:
    """Olayı merkeze kaydet ve etkin dış kanallara gönder. Olay türü kapalıysa (``force`` değilse) None.
    ``bypass_quiet``: sessiz saatlerde de gönderilir (kötü amaçlı paket gibi acil olaylar)."""
    settings = load_settings(environ)
    if not force and not settings["events"].get(event, {}).get("enabled", False):
        return None
    now = now or dt.datetime.now(dt.timezone.utc)
    item: dict[str, Any] = {
        "id": "ntf_" + secrets.token_hex(8), "created_at": _iso(now), "event": event,
        "severity": severity if severity in SEVERITY_ORDER else "medium", "title": title[:200],
        "message": message[:1000], "details": [str(x)[:300] for x in (details or [])[:10]], "data": data or {},
        "read": False, "channels": {"center": "stored"},
    }
    import scheduler
    quiet = _in_quiet_hours(settings["quiet_hours"], now, scheduler.timezone_name(environ))
    if quiet and item["severity"] == "critical" and settings["quiet_hours"].get("allow_critical"):
        quiet = False
    if bypass_quiet:
        quiet = False
    channels = settings["channels"]
    for name, sender in (
        ("desktop", lambda: _send_desktop(item)),
        ("smtp", lambda: _send_smtp(item, channels["smtp"], environ, smtp_factory)),
        ("webhook", lambda: _send_webhook(item, channels["webhook"]["url"])),
    ):
        if not channels[name].get("enabled"):
            continue
        item["channels"][name] = "quiet_hours" if quiet else sender()

    def change(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            data = _center_default()
        data["items"].insert(0, item)
        del data["items"][MAX_CENTER_ITEMS:]
        return data

    ops_files.update_json(CENTER_FILE, _center_default, change, environ)
    return item


def list_items(*, unread_only: bool = False, limit: int = 100, environ: dict[str, str] | None = None) -> dict[str, Any]:
    data = ops_files.read_json(CENTER_FILE, _center_default, environ)
    items = data.get("items") if isinstance(data, dict) and isinstance(data.get("items"), list) else []
    unread = sum(1 for item in items if not item.get("read"))
    if unread_only:
        items = [item for item in items if not item.get("read")]
    return {"items": items[: max(1, min(limit, MAX_CENTER_ITEMS))], "unread": unread, "total": len(items)}


def mark_read(ids: Any, environ: dict[str, str] | None = None) -> int:
    """``ids``: "all" ya da kimlik listesi. Okundu işaretlenen sayıyı döndür."""
    if ids != "all" and (not isinstance(ids, list) or len(ids) > 500 or not all(isinstance(x, str) and _ID_RE.fullmatch(x) for x in ids)):
        raise NotificationError("ids 'all' ya da bildirim kimliği listesi olmalı.")
    wanted = None if ids == "all" else set(ids)
    count = 0

    def change(data: Any) -> dict[str, Any]:
        nonlocal count
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            return _center_default()
        for item in data["items"]:
            if not item.get("read") and (wanted is None or item.get("id") in wanted):
                item["read"] = True
                count += 1
        return data

    ops_files.update_json(CENTER_FILE, _center_default, change, environ)
    return count


# ---------------------------------------------------------------------------
# Olay üreticileri
# ---------------------------------------------------------------------------
def _is_partial(audit: dict[str, Any]) -> bool:
    scope = audit.get("scope") if isinstance(audit.get("scope"), dict) else {}
    return bool(scope.get("skipped_only") or scope.get("changed_only") or audit.get("base_audit_id"))


def _previous_full_audit_id(store: Any, audit: dict[str, Any]) -> str | None:
    with store._connect() as db:
        rows = db.execute(
            "SELECT id FROM project_audits WHERE project_path = ? AND id != ? ORDER BY rowid DESC LIMIT 20",
            (audit["project_path"], audit["id"]),
        ).fetchall()
    for row in rows:
        candidate = store.get_project_audit(row[0])
        if candidate and not _is_partial(candidate):
            return candidate["id"]
    return None


def project_audit_changes(store: Any, audit: dict[str, Any]) -> dict[str, Any]:
    """Yeni ve düzelen bulgular (önceki TAM analize göre basit fark).

    Birleştirmede kalıcı bulgu takibi (finding_tracking) varsa yalnız bu fonksiyon onun "yeni/düzeldi" sonucuna
    geçirilir. Kısmi taramalarda (yalnız atlananlar / yalnız değişenler / ek tarama) düzelen bulgu üretilmez.
    """
    from project_audit_diff import compare_project_audits

    baseline = _previous_full_audit_id(store, audit)
    if baseline is None:
        return {"baseline_id": None, "new": [], "fixed": [], "first_audit": True}
    tracked = _tracked_changes(store, audit)
    if tracked is not None:
        return {"baseline_id": baseline, **tracked, "first_audit": False}
    diff = compare_project_audits(store, baseline, audit["id"])
    new = list(diff.get("new_findings") or [])
    fixed = [] if _is_partial(audit) else list(diff.get("resolved_findings") or [])
    return {"baseline_id": baseline, "new": new, "fixed": fixed, "first_audit": False}


def _tracked_changes(store: Any, audit: dict[str, Any]) -> dict[str, Any] | None:
    """Kalıcı bulgu takibi (finding_tracking) varsa yeni/düzelen bulgular oradan: satır kaymasına dayanıklı eşleme,
    bastırılmış (yanlış alarm / risk kabulü) bulgular yeni sayılmaz. Takip kaydı yoksa ``None`` (basit farka düşülür)."""
    getter = getattr(store, "get_project_audit", None)
    detail = getter(audit["id"]) if getter else None
    if not detail or not detail.get("tracking"):
        return None
    new = [f for f in detail.get("findings") or []
           if (f.get("tracking") or {}).get("is_new") and not f["tracking"].get("suppressed")]
    fixed: list[dict[str, Any]] = []
    lister = getattr(store, "list_tracked_findings", None)
    if lister and not _is_partial(audit) and detail["tracking"].get("fixed_count"):
        fixed = [item for item in lister(detail["project_path"], {"fixed"}, 5000) if item.get("fixed_audit_id") == audit["id"]]
    return {"new": new, "fixed": fixed}


def _line(finding: dict[str, Any]) -> str:
    where = finding.get("file") or "proje geneli"
    if finding.get("line"):
        where = f"{where}:{finding['line']}"
    return f"[{finding.get('severity', '?')}] {finding.get('title', '')} — {where}"


def on_project_audit_created(store: Any, audit: dict[str, Any], *, environ: dict[str, str] | None = None,
                             now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Proje analizi kaydedildikten sonra (elle ya da zamanlanmış) olayları üret."""
    settings = load_settings(environ)
    changes = project_audit_changes(store, audit)
    emitted: list[dict[str, Any]] = []
    name = audit.get("project_name") or audit.get("project_path") or "proje"
    threshold = SEVERITY_ORDER[settings["events"]["new_findings"].get("min_severity", "high")]
    if changes["first_audit"]:
        # İlk analiz: önceki yok; eşik üstü tüm bulgular "yeni" sayılır.
        candidates = [f for f in audit.get("findings") or []
                      if (f.get("triage") or {}).get("disposition") not in {"false_positive", "risk_accepted"}]
    else:
        candidates = changes["new"]
    serious = [f for f in candidates if SEVERITY_ORDER.get(f.get("severity"), 0) >= threshold]
    if serious:
        top = max(serious, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 0))["severity"]
        counts = {sev: sum(1 for f in serious if f.get("severity") == sev) for sev in ("critical", "high", "medium", "low")}
        summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
        item = emit("new_findings", top, f"{name}: {len(serious)} yeni önemli bulgu",
                    f"{'İlk analiz' if changes['first_audit'] else 'Önceki analize göre'} yeni bulgular ({summary}).",
                    details=[_line(f) for f in serious[:10]],
                    data={"audit_id": audit["id"], "baseline_id": changes["baseline_id"], "project_path": audit.get("project_path"),
                          "counts": counts}, now=now, environ=environ)
        if item:
            emitted.append(item)
    if changes["fixed"]:
        item = emit("fixed_findings", "low", f"{name}: {len(changes['fixed'])} bulgu düzeldi",
                    "Önceki analizde görülen bulgular bu analizde yok.",
                    details=[_line(f) for f in changes["fixed"][:10]],
                    data={"audit_id": audit["id"], "baseline_id": changes["baseline_id"], "project_path": audit.get("project_path")},
                    now=now, environ=environ)
        if item:
            emitted.append(item)
    try:
        emitted.extend(on_audit_categories(audit, environ=environ, now=now))
    except ops_files.OpsStoreError:
        raise
    except Exception:  # noqa: BLE001 — ek olay hatası analiz bildirimini düşürmez
        import traceback
        traceback.print_exc()
    return emitted


def on_scan_failed(route: str, job_id: str, state: str, *, schedule: dict[str, Any] | None = None,
                   environ: dict[str, str] | None = None, now: dt.datetime | None = None) -> dict[str, Any] | None:
    label = {"failed": "başarısız oldu", "expired": "süre sınırını aştı", "cancelled": "iptal edildi",
             "interrupted": "yarıda kaldı"}.get(state, state)
    source = f"Zamanlanmış tarama “{schedule.get('name') or schedule.get('id')}”" if schedule else "Tarama"
    return emit("scan_failed", "medium", f"{source} {label}",
                f"{route} işi ({job_id}) {label}. Ayrıntılar işler panelinde ve sunucu günlüğünde.",
                data={"job_id": job_id, "route": route, "state": state,
                      "schedule_id": schedule.get("id") if schedule else None,
                      "project_path": schedule.get("project_path") if schedule else None},
                now=now, environ=environ)


def on_project_analysis_finished(job_id: str, label: str | None, result: Any, *, environ: dict[str, str] | None = None,
                                 now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Arka plan proje analizi tamamlandı (kullanıcı başlattı; planlı taramalar hariç)."""
    result = result if isinstance(result, dict) else {}
    name = str(result.get("project_name") or label or "Proje")[:120]
    counts = result.get("finding_counts") if isinstance(result.get("finding_counts"), dict) else {}
    labels = {"critical": "kritik", "high": "yüksek", "medium": "orta", "low": "düşük"}
    parts = [f"{int(counts.get(key) or 0)} {label}" for key, label in labels.items() if counts.get(key)]
    message = f"{name} analizi tamamlandı" + (f" ({', '.join(parts)})." if parts else " (bulgu yok).")
    return emit("analysis_finished", "low", f"Proje analizi tamamlandı: {name}", message,
                data={"job_id": job_id, "audit_id": result.get("id"), "project_name": name},
                now=now, environ=environ)


def send_test(environ: dict[str, str] | None = None, smtp_factory: Callable[..., Any] | None = None) -> dict[str, Any]:
    item = emit("test", "low", "Sniper test bildirimi", "Bildirim kanalları bu iletiyle sınandı.", force=True,
                environ=environ, smtp_factory=smtp_factory)
    assert item is not None
    return item


# ---------------------------------------------------------------------------
# Bulgu atama ve son tarih (16. tur)
# ---------------------------------------------------------------------------
def _notify_severity(severity: Any) -> str:
    return severity if severity in SEVERITY_ORDER else "low"


def on_finding_assigned(item: dict[str, Any], *, actor: dict[str, Any] | None = None, environ: dict[str, str] | None = None,
                        now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Bulgu bir kişiye atandığında (kaldırmada bildirim yok)."""
    name = item.get("assignee_name") or ""
    if not name:
        return None
    by = f" ({actor.get('username')} tarafından)" if actor and actor.get("username") else ""
    return emit("finding_assigned", _notify_severity(item.get("severity")), f"Bulgu atandı: {name}",
                f"{item.get('title', '')}{by}.", details=[_line(item)],
                data={"tracked_id": item.get("id"), "project_path": item.get("project_path"),
                      "assignee_id": item.get("assignee_id"), "assignee_name": name, "due_date": item.get("due_date")},
                now=now, environ=environ)


def check_due_dates(store: Any, *, now: dt.datetime | None = None, environ: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Zamanlayıcıdan (saatlik) çağrılır: son tarihi geçen ve yaklaşan etkin bulgular için toplu hatırlatma.
    Aynı bulgu, aynı tarih ve aşama (yaklaşıyor/geçti) için yalnız bir kez bildirilir."""
    settings = load_settings(environ)
    event = settings["events"].get("finding_due", {})
    if not event.get("enabled", False):
        return []
    import scheduler

    moment = now or dt.datetime.now(dt.timezone.utc)
    today = moment.astimezone(scheduler.zone(scheduler.timezone_name(environ))).date()
    candidates = store.tracked_due_candidates(today, int(event.get("days_before", 2)))
    emitted: list[dict[str, Any]] = []
    for stage, title, message in (
        ("overdue", "{n} bulgunun son tarihi geçti", "Son tarihi geçen etkin bulgular (sorumlu · son tarih)."),
        ("soon", "{n} bulgunun son tarihi yaklaşıyor", "Son tarihi {d} gün içinde dolacak etkin bulgular."),
    ):
        group = [item for item in candidates if item["stage"] == stage]
        if not group:
            continue
        top = max(group, key=lambda item: SEVERITY_ORDER.get(item.get("severity"), 0)).get("severity")
        details = [f"{_line(item)} · {item.get('assignee_name') or 'sorumlu yok'} · {item.get('due_date')}" for item in group[:10]]
        notice = emit("finding_due", _notify_severity(top), title.format(n=len(group)),
                      message.format(d=int(event.get("days_before", 2))), details=details,
                      data={"stage": stage, "tracked_ids": [item["id"] for item in group[:50]]}, now=now, environ=environ)
        if notice:
            emitted.append(notice)
            store.mark_tracked_due_notices([(item["id"], item["notice"]) for item in group])
    return emitted


def check_sla(store: Any, *, now: dt.datetime | None = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Zamanlayıcıdan (saatlik) çağrılır (17. tur):

    * Bitiş tarihi gelen risk kabulleri bildirim ayarından bağımsız olarak yeniden açılır (durum değişikliği politika
      gereğidir); ``risk_expired`` olayı açıksa bildirim üretilir.
    * Elle son tarihi olmayan etkin bulgulardan SLA süresi geçenler (her SLA günü için bir kez) ``sla_breach`` olayıyla
      toplu bildirilir.
    """
    import portfolio
    import scheduler

    moment = now or dt.datetime.now(dt.timezone.utc)
    today = moment.astimezone(scheduler.zone(scheduler.timezone_name(environ))).date()
    policy, _custom = portfolio.load_policy(environ)
    out: dict[str, Any] = {"expired": [], "breached": [], "notices": []}
    expired = store.expire_risk_acceptances(today)
    out["expired"] = expired
    if expired:
        top = max(expired, key=lambda item: SEVERITY_ORDER.get(item.get("severity"), 0)).get("severity")
        notice = emit("risk_expired", _notify_severity(top), f"{len(expired)} risk kabulünün süresi doldu",
                      "Süresi dolan risk kabulleri yeniden açıldı; yeniden değerlendirin.",
                      details=[f"{_line(item)} · bitiş {item.get('expired_on')}" for item in expired[:10]],
                      data={"tracked_ids": [item["id"] for item in expired[:50]]}, now=now, environ=environ)
        if notice:
            out["notices"].append(notice)
    settings = load_settings(environ)
    if settings["events"].get("sla_breach", {}).get("enabled", False):
        breached = store.sla_breach_candidates(policy, today)
        out["breached"] = breached
        if breached:
            top = max(breached, key=lambda item: SEVERITY_ORDER.get(item.get("severity"), 0)).get("severity")
            notice = emit("sla_breach", _notify_severity(top), f"{len(breached)} bulgu SLA süresini aştı",
                          "SLA süresi geçen etkin bulgular (önem · SLA son günü · sorumlu).",
                          details=[f"{_line(item)} · SLA {item.get('sla_due')} · {item.get('assignee_name') or 'sorumlu yok'}"
                                   for item in breached[:10]],
                          data={"tracked_ids": [item["id"] for item in breached[:50]]}, now=now, environ=environ)
            if notice:
                out["notices"].append(notice)
                store.mark_sla_notices([(item["id"], item["notice"]) for item in breached])
    return out



# ---------------------------------------------------------------------------
# 21. tur: bağımlılık güvenliği, konteyner, lisans ve OSV tazeliği olayları
# ---------------------------------------------------------------------------
MALICIOUS_TITLE_PREFIX = "Kötü amaçlı paket"
LICENSE_FORBIDDEN_PREFIX = "Bağımlılık lisansı politika gereği yasak"
CONTAINER_CATEGORIES = frozenset({"container_os", "container_lang"})
_SUPPRESSED = frozenset({"false_positive", "risk_accepted"})


def _dedupe_default() -> dict[str, Any]:
    return {"format": 1, "events": {}, "daily": {}}


def _first_seen(event: str, keys: list[str], *, now: dt.datetime | None = None,
                environ: dict[str, str] | None = None) -> list[str]:
    """Daha önce bildirilmemiş anahtarları döndürür ve kaydeder (olay başına en çok MAX_DEDUPE_PER_EVENT; en eskiler
    düşer). Aynı bulgu her taramada yeniden bildirilmez."""
    if not keys:
        return []
    stamp = _iso(now or dt.datetime.now(dt.timezone.utc))
    fresh: list[str] = []

    def change(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict) or not isinstance(data.get("events"), dict):
            data = _dedupe_default()
        seen = data["events"].get(event)
        seen = seen if isinstance(seen, dict) else {}
        for key in dict.fromkeys(keys):
            if key not in seen:
                fresh.append(key)
                seen[key] = stamp
        if len(seen) > MAX_DEDUPE_PER_EVENT:
            for old in sorted(seen, key=lambda k: (seen[k], k))[:len(seen) - MAX_DEDUPE_PER_EVENT]:
                seen.pop(old, None)
        data["events"][event] = seen
        return data

    ops_files.update_json(DEDUPE_FILE, _dedupe_default, change, environ)
    return fresh


def _once_per_day(name: str, day: str, *, environ: dict[str, str] | None = None) -> bool:
    """Günlük işaret: ``name`` bu gün için ilk kez mi? (kaydeder)"""
    decision = {"first": False}

    def change(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict) or not isinstance(data.get("events"), dict):
            data = _dedupe_default()
        daily = data.get("daily") if isinstance(data.get("daily"), dict) else {}
        if daily.get(name) != day:
            daily[name] = day
            decision["first"] = True
        data["daily"] = daily
        return data

    ops_files.update_json(DEDUPE_FILE, _dedupe_default, change, environ)
    return decision["first"]


def _event_enabled(event: str, environ: dict[str, str] | None) -> bool:
    return bool(load_settings(environ)["events"].get(event, {}).get("enabled", False))


def is_malicious(finding: dict[str, Any]) -> bool:
    """Kötü amaçlı paket bulgusu (proje analizi tedarik zinciri, konteyner dil paketi, SBOM, bağımlılık kaydı)."""
    vuln = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
    ids = (str(finding.get("vulnerability_id") or ""), str(finding.get("reference") or ""), str(vuln.get("id") or ""))
    return (finding.get("malicious") is True or any(i.startswith("MAL-") for i in ids)
            or str(finding.get("title") or "").startswith(MALICIOUS_TITLE_PREFIX)
            or (finding.get("category") == "supply_chain" and finding.get("cwe") == "CWE-506"))


def _suppressed(finding: dict[str, Any]) -> bool:
    triage = finding.get("triage") if isinstance(finding.get("triage"), dict) else {}
    tracking = finding.get("tracking") if isinstance(finding.get("tracking"), dict) else {}
    return triage.get("disposition") in _SUPPRESSED or bool(tracking.get("suppressed"))


def _key(scope: str, finding: dict[str, Any]) -> str:
    """Kararlı bulgu anahtarı: proje + kategori + başlık (paket/sürüm/kimlik başlıkta) + dosya."""
    return "|".join((scope, str(finding.get("category") or ""), str(finding.get("title") or "")[:200],
                     str(finding.get("file") or "")))


def on_audit_categories(audit: dict[str, Any], *, environ: dict[str, str] | None = None,
                        now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Kaydedilen analiz (proje, konteyner, SBOM) için kötü amaçlı paket, kritik konteyner ve yasak lisans olayları.
    Bastırılmış (yanlış alarm / risk kabulü) bulgular ve daha önce bildirilenler atlanır."""
    findings = [f for f in audit.get("findings") or [] if isinstance(f, dict) and not _suppressed(f)]
    if not findings:
        return []
    scope = str(audit.get("project_path") or audit.get("project_name") or audit.get("id") or "")
    name = audit.get("project_name") or Path(scope).name or "analiz"
    base = {"audit_id": audit.get("id"), "project_path": audit.get("project_path"),
            "audit_kind": audit.get("audit_kind") or "project"}
    out: list[dict[str, Any]] = []
    groups = (
        ("malicious_package", [f for f in findings if is_malicious(f)]),
        ("container_critical", [f for f in findings if f.get("category") in CONTAINER_CATEGORIES
                                and f.get("severity") == "critical" and not is_malicious(f)]),
        ("license_forbidden", [f for f in findings if f.get("category") == "license"
                               and str(f.get("title") or "").startswith(LICENSE_FORBIDDEN_PREFIX)
                               and f.get("severity") in {"high", "critical"}]),
    )
    for event, items in groups:
        if not items or not _event_enabled(event, environ):
            continue
        by_key = {_key(scope, f): f for f in items}
        fresh = [by_key[k] for k in _first_seen(event, list(by_key), now=now, environ=environ)]
        if not fresh:
            continue
        if event == "malicious_package":
            item = emit(event, "critical", f"{name}: {len(fresh)} kötü amaçlı paket bulundu",
                        "Kötü amaçlı paketler derhal kaldırılmalı; kimlik bilgileri döndürülmeli ve paketin kurulduğu "
                        "sistemler incelenmeli (sürüm yükseltmek yetmez).",
                        details=[_line(f) for f in fresh[:10]], data={**base, "count": len(fresh)},
                        now=now, environ=environ, bypass_quiet=True)
        elif event == "container_critical":
            item = emit(event, "critical", f"{name}: {len(fresh)} yeni kritik konteyner açığı",
                        "İmajdaki kritik işletim sistemi / dil paketi açıkları. Temel imajı güncelleyip yeniden derleyin.",
                        details=[_line(f) for f in fresh[:10]], data={**base, "count": len(fresh)},
                        now=now, environ=environ)
        else:
            item = emit(event, "high", f"{name}: politika gereği yasak lisans",
                        "Bağımlılıklarda lisans politikasının yasakladığı lisans bulundu (geliştirme bağımlılıkları "
                        "hariç).", details=[_line(f) for f in fresh[:10]], data={**base, "count": len(fresh)},
                        now=now, environ=environ)
        if item:
            out.append(item)
    return out


def on_dependency_scan(project_path: str, findings: list[dict[str, Any]], priority: dict[str, Any] | None, *,
                       environ: dict[str, str] | None = None, now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Çevrimdışı bağımlılık taraması (elle ya da zamanlanmış) sonrası: kötü amaçlı paketler (hemen, kritik) ve yeni
    "Önce düzelt" katmanındaki SCA bulguları (paket+sürüm+kimlik başına bir kez)."""
    name = Path(str(project_path)).name or "proje"
    out: list[dict[str, Any]] = []
    malicious = [f for f in findings or [] if isinstance(f, dict) and is_malicious(f)]
    if malicious and _event_enabled("malicious_package", environ):
        by_key = {"|".join((str(project_path), str(f.get("package_name")), str(f.get("installed_version")),
                            str(f.get("vulnerability_id")))): f for f in malicious}
        fresh = [by_key[k] for k in _first_seen("malicious_package", list(by_key), now=now, environ=environ)]
        if fresh:
            item = emit("malicious_package", "critical", f"{name}: {len(fresh)} kötü amaçlı bağımlılık",
                        "Kötü amaçlı paketler derhal kaldırılmalı; kimlik bilgileri döndürülmeli ve paketin kurulduğu "
                        "sistemler incelenmeli (sürüm yükseltmek yetmez).",
                        details=[f"{f.get('package_name')} {f.get('installed_version')} — {f.get('vulnerability_id')}"
                                 for f in fresh[:10]],
                        data={"project_path": project_path, "count": len(fresh)}, now=now, environ=environ,
                        bypass_quiet=True)
            if item:
                out.append(item)
    order = (priority or {}).get("order") if isinstance(priority, dict) else None
    fix_first = [o for o in order or [] if isinstance(o, dict) and o.get("tier") == "fix_first"]
    if fix_first and _event_enabled("sca_fix_first", environ):
        by_key = {"|".join((str(project_path), str(o.get("package_name")), str(o.get("installed_version")),
                            str(o.get("vulnerability_id")))): o for o in fix_first}
        fresh = [by_key[k] for k in _first_seen("sca_fix_first", list(by_key), now=now, environ=environ)]
        if fresh:
            item = emit("sca_fix_first", "high", f"{name}: {len(fresh)} yeni 'Önce düzelt' bağımlılık açığı",
                        "Önceliklendirme (önem × erişilebilirlik × düzeltme × doğrudan) en üst katmana koydu.",
                        details=[f"{o.get('package_name')} {o.get('installed_version')} — {o.get('vulnerability_id')}"
                                 f" (puan {o.get('score')}" + (f", düzeltme ≥ {o['fixed_version']}" if o.get("fixed_version") else "")
                                 + ")" for o in fresh[:10]],
                        data={"project_path": project_path, "count": len(fresh)}, now=now, environ=environ)
            if item:
                out.append(item)
    return out


def check_osv_stale(*, now: dt.datetime | None = None, environ: dict[str, str] | None = None,
                    status_fn: Callable[[], list[dict[str, Any]]] | None = None) -> dict[str, Any] | None:
    """Zamanlayıcıdan (saatlik) çağrılır; günde en çok bir kez: 7 günden eski çevrimdışı OSV ekosistemleri."""
    if not _event_enabled("osv_db_stale", environ):
        return None
    moment = now or dt.datetime.now(dt.timezone.utc)
    import scheduler

    day = moment.astimezone(scheduler.zone(scheduler.timezone_name(environ))).date().isoformat()
    if not _once_per_day("osv_db_stale", day, environ=environ):
        return None
    items = status_fn() if status_fn else osv_status_light(now=moment)
    stale = [i for i in items if i.get("status") == "present" and isinstance(i.get("age_hours"), (int, float))
             and i["age_hours"] > OSV_STALE_DAYS * 24]
    if not stale:
        return None
    stale.sort(key=lambda i: (-i["age_hours"], i.get("ecosystem") or ""))
    return emit("osv_db_stale", "medium", f"{len(stale)} çevrimdışı OSV veritabanı {OSV_STALE_DAYS} günden eski",
                "Yeni açıklar ve kötü amaçlı paket kayıtları eksik olabilir. sniper-osv-refresh.timer'ı ya da "
                "scripts/osv_refresh.py'yi kontrol edin.",
                details=[f"{i['ecosystem']}: {round(i['age_hours'] / 24, 1)} gün" for i in stale[:10]],
                data={"ecosystems": [i["ecosystem"] for i in stale]}, now=now, environ=environ)


def osv_status_light(*, now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Ekosistem başına manifest yaşı (arşiv özeti hesaplanmaz; ucuz). İmza ayrıca doğrulanır."""
    import osv_db_refresh

    out = []
    for ecosystem in osv_db_refresh.known_ecosystems():
        try:
            out.append(osv_db_refresh.status(ecosystem, now=now))
        except Exception as exc:  # noqa: BLE001
            out.append({"ecosystem": ecosystem, "status": "error", "detail": type(exc).__name__})
    return out
