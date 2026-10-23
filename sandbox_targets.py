"""Sniper içinden yönetilen yalıtılmış test hedefleri, kapsam seçenekleri ve yük profilleri.

Ayarlar ``$SNIPER_DATA_DIR/sandbox-targets.json`` dosyasında (0600, flock, atomik yazım) tutulur.

Kapsam seçenekleri (her biri bağımsız açılıp kapanır):
  * ``local``            — 127.0.0.1 portları (varsayılan açık).
  * ``critical``         — Sniper'ın kendi portu ve kritik yerel servisler (LLM, SSH tüneli, ssh, VNC); varsayılan
                           kapalı; açıkken bu portlar (uyarıyla) eklenebilir.
  * ``remote_verified``  — yalnız sahipliği doğrulanmış alan adları (varsayılan kapalı). IP hedefi kabul edilmez.
    Sniper rastgele belirteç üretir; kullanıcı belirteci ``https://<alan>/.well-known/sniper-verify/<id>`` dosyasına
    ya da ``_sniper-verify.<alan>`` TXT kaydına koyar ve tek "Doğrula" ile Sniper önce dosyayı, sonra TXT'yi dener.
    Doğrulanmış hedef kalıcıdır; arka planda REVERIFY_SECONDS aralıkla yalnız doğrulanmış alanlara, yalnız aynı
    .well-known yoluna/TXT kaydına yeniden doğrulama yapılır; başarısız olursa hedef yeniden doğrulanana dek çalışmaz.
Tüm değişiklikler API'de tek ``confirm: true`` onayıyla yapılır ve denetim kaydına yazılır (server.py).

Yük profilleri: Hafif (1 VU, 10 sn), Orta (10 VU, 1 dk), Yoğun (50 VU, 5 dk) ve kullanıcı tanımlı Özel profiller
(mutlak üst sınırlar: HARD_LIMITS). Kritik yerel servislerde varsayılan profil Hafif'tir.
Dosya hiç yoksa yerel hedeflerin başlangıç değeri ``SNIPER_K6_ALLOWED_PORTS`` / ``SNIPER_SCHEMATHESIS_ALLOWED_PORTS``.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

TOOLS = ("k6", "schemathesis", "playwright", "runtime_proof")
REMOTE_TOOLS = frozenset({"k6", "schemathesis", "playwright"})
PORT_ENVS = {"k6": "SNIPER_K6_ALLOWED_PORTS", "schemathesis": "SNIPER_SCHEMATHESIS_ALLOWED_PORTS",
             "runtime_proof": "SNIPER_RUNTIME_PROOF_ALLOWED_PORTS"}
SCOPES = ("local", "critical", "remote_verified")
DEFAULT_SCOPES = {"local": True, "critical": False, "remote_verified": False}
# Kritik yerel servisler: Sniper, LLM (llama-server), SSH ters tüneli, ssh, VNC. Engellenmez; ayrı onay ister.
CRITICAL_PORTS = frozenset({8787, 18090, 20129, 22, 5901})
BUILTIN_PRESETS = {
    "hafif": {"vus": 1, "duration_s": 10, "label": "Hafif"},
    "orta": {"vus": 10, "duration_s": 60, "label": "Orta"},
    "yogun": {"vus": 50, "duration_s": 300, "label": "Yoğun"},
}
DEFAULT_CUSTOM_PRESETS = {"ozel": {"vus": 5, "duration_s": 30, "label": "Özel"}}
HARD_LIMITS = {"vus": 200, "duration_s": 600, "st_max_time_s": 600, "st_max_examples": 200}
DEFAULT_ST_LIMITS = {"st_max_time_s": 120, "st_max_examples": 25}
MAX_TARGETS = 32
MAX_CUSTOM_PRESETS = 10
MAX_PENDING = 16
PENDING_TTL = 7 * 24 * 3600
REVERIFY_SECONDS = 24 * 3600
FILE_NAME = "sandbox-targets.json"
_LABEL_RE = re.compile(r"[\w .,:()/+-]{0,64}\Z", re.UNICODE)
_PRESET_RE = re.compile(r"[a-z0-9_-]{1,32}\Z")
_TOKEN_ID_RE = re.compile(r"[a-f0-9]{32}\Z")


def _is_remote_hostname(host: str) -> bool:
    if not 4 <= len(host) <= 253:
        return False
    labels = host.split(".")
    if len(labels) < 2 or not 2 <= len(labels[-1]) <= 63 or any(char not in "abcdefghijklmnopqrstuvwxyz" for char in labels[-1]):
        return False
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-"
    edge = "abcdefghijklmnopqrstuvwxyz0123456789"
    return all(
        1 <= len(label) <= 63
        and label[0] in edge
        and label[-1] in edge
        and all(char in allowed for char in label)
        for label in labels[:-1]
    )


class TargetError(ValueError):
    """Geçersiz hedef, kapsam, profil ya da sınır."""


class ScopeDisabled(TargetError):
    """Hedefin kapsam seçeneği kapalı."""


class VerificationFailed(TargetError):
    """Sahiplik doğrulaması başarısız."""


CRITICAL_WARNING = ("Uyarı: bu port kritik bir yerel servise ait (Sniper, LLM, SSH tüneli, ssh veya VNC). Yük testi bu "
                    "servisi yavaşlatabilir ya da durdurabilir.")


# ---------------------------------------------------------------------------
# Okuma / yazma
# ---------------------------------------------------------------------------
def critical_ports(environ: dict[str, str] | None = None) -> frozenset[int]:
    env = os.environ if environ is None else environ
    ports = set(CRITICAL_PORTS)
    if env.get("SNIPER_PORT", "").isdigit():
        ports.add(int(env["SNIPER_PORT"]))
    return frozenset(ports)


def _env(environ: dict[str, str] | None) -> dict[str, str]:
    return dict(os.environ if environ is None else environ)


def _path(environ: dict[str, str]) -> Path:
    text = environ.get("SNIPER_DATA_DIR", "")
    path = Path(text)
    if not text or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise TargetError("Sniper veri dizini yapılandırılmamış.")
    return path / FILE_NAME


def _port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise TargetError("Port 1–65535 aralığında bir tam sayı olmalı.")
    return value


def _tools(value: object) -> list[str]:
    tools = list(TOOLS) if value is None else value
    if not isinstance(tools, list) or not tools or any(t not in TOOLS for t in tools):
        raise TargetError("Araç listesi yalnız k6, schemathesis, playwright ve/veya runtime_proof içerebilir.")
    return sorted(set(tools))


def _remote_tools(value: object) -> list[str]:
    """Uzak hedeflerde yalnız ağ test araçları; runtime_proof kesinlikle loopback içindir."""
    tools = sorted(REMOTE_TOOLS) if value is None else _tools(value)
    if "runtime_proof" in tools:
        raise TargetError("Çalışma zamanı kanıtı yalnız loopback hedeflerde kullanılabilir.")
    return tools


def _label(value: object) -> str:
    if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
        raise TargetError("Etiket en çok 64 karakter; harf, rakam ve sınırlı noktalama.")
    return value


def remote_host(value: object) -> str:
    """Yalnız alan adı (IP değişmezi değil), küçük harf, en az bir nokta."""
    if not isinstance(value, str):
        raise TargetError("Geçersiz alan adı.")
    host = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        raise TargetError("IP adresi uzak hedef olamaz; sahipliği doğrulanabilen bir alan adı girin.")
    except ValueError:
        pass
    if not _is_remote_hostname(host) or host.endswith((".local", ".localhost", ".internal", ".lan", ".home")) \
            or host == "localhost":
        raise TargetError("Geçersiz ya da yerel ağa ait alan adı.")
    return host


def _env_seed(environ: dict[str, str]) -> list[dict]:
    seeded: dict[int, set[str]] = {}
    for tool, key in PORT_ENVS.items():
        for part in environ.get(key, "").split(","):
            part = part.strip()
            if re.fullmatch(r"[1-9][0-9]{0,4}", part) and int(part) <= 65535:
                seeded.setdefault(int(part), set()).add(tool)
    critical = critical_ports(environ)
    # Kritik portlar ortamdan sessizce gelmez (ayrı onay gerekir).
    return [{"id": f"local:{port}", "kind": "local", "host": "127.0.0.1", "port": port, "scheme": "http",
             "tools": sorted(tools), "label": "ortam başlangıç değeri", "added_at": 0, "critical": False}
            for port, tools in sorted(seeded.items()) if port not in critical][:MAX_TARGETS]


def _clean_target(item: object, critical: frozenset[int]) -> dict | None:
    if not isinstance(item, dict):
        return None
    try:
        port = _port(item.get("port"))
        tools = _tools(item.get("tools"))
        label = _label(item.get("label", ""))
    except TargetError:
        return None
    added = item.get("added_at") if type(item.get("added_at")) is int else 0
    if item.get("kind") == "local":
        if port in critical and item.get("critical") is not True:
            return None  # kritik port yalnız onayla eklenmiş kayıttan gelir (elle düzenlemeye karşı)
        return {"id": f"local:{port}", "kind": "local", "host": "127.0.0.1", "port": port, "scheme": "http",
                "tools": tools, "label": label, "added_at": added, "critical": port in critical}
    if item.get("kind") == "remote":
        try:
            host = remote_host(item.get("host"))
        except TargetError:
            return None
        verification = item.get("verification")
        if item.get("scheme") not in ("http", "https") or not isinstance(verification, dict) \
                or type(verification.get("verified_at")) is not int \
                or verification.get("method") not in ("http", "dns") \
                or not _TOKEN_ID_RE.fullmatch(str(verification.get("token_id", ""))):
            return None
        failed = verification.get("failed_at")
        remote_tools = [tool for tool in tools if tool in REMOTE_TOOLS]
        if not remote_tools:
            return None
        return {"id": f"remote:{host}:{port}", "kind": "remote", "host": host, "port": port,
                "scheme": item["scheme"], "tools": remote_tools, "label": label, "added_at": added, "critical": False,
                "verification": {**{k: verification.get(k) for k in
                                    ("method", "token_id", "verified_at", "evidence_sha256", "token")},
                                 "failed_at": failed if type(failed) is int else None}}
    return None


def _clean_preset(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    vus, duration = value.get("vus"), value.get("duration_s")
    if type(vus) is not int or type(duration) is not int or not 1 <= vus <= HARD_LIMITS["vus"] \
            or not 1 <= duration <= HARD_LIMITS["duration_s"]:
        return None
    label = value.get("label", "")
    return {"vus": vus, "duration_s": duration, "label": label if isinstance(label, str) and _LABEL_RE.fullmatch(label) else ""}


def _default_settings(environ: dict[str, str]) -> dict:
    return {"version": 2, "scopes": dict(DEFAULT_SCOPES), "targets": _env_seed(environ), "pending": [],
            "presets": {k: dict(v) for k, v in DEFAULT_CUSTOM_PRESETS.items()}, "limits": dict(DEFAULT_ST_LIMITS)}


def _clean(raw: object, environ: dict[str, str]) -> dict:
    settings = _default_settings(environ)
    if not isinstance(raw, dict):
        return settings
    scopes = raw.get("scopes")
    if isinstance(scopes, dict):
        settings["scopes"] = {k: scopes.get(k) is True if k in scopes else DEFAULT_SCOPES[k] for k in SCOPES}
    critical = critical_ports(environ)
    targets, seen = [], set()
    for item in (raw.get("targets") if isinstance(raw.get("targets"), list) else [])[:MAX_TARGETS]:
        cleaned = _clean_target(item, critical)
        if cleaned and cleaned["id"] not in seen:
            seen.add(cleaned["id"])
            targets.append(cleaned)
    settings["targets"] = targets if isinstance(raw.get("targets"), list) else settings["targets"]
    now = int(time.time())
    pending = []
    for item in (raw.get("pending") if isinstance(raw.get("pending"), list) else [])[:MAX_PENDING]:
        if isinstance(item, dict) and _TOKEN_ID_RE.fullmatch(str(item.get("id", ""))) \
                and isinstance(item.get("token"), str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", item["token"]) \
                and type(item.get("expires_at")) is int and item["expires_at"] > now:
            try:
                pending.append({"id": item["id"], "token": item["token"], "host": remote_host(item.get("host")),
                                "port": _port(item.get("port")), "scheme": item.get("scheme") if item.get("scheme") in ("http", "https") else "https",
                                "tools": _tools(item.get("tools")), "label": _label(item.get("label", "")),
                                "created_at": int(item.get("created_at", 0)) if type(item.get("created_at")) is int else 0,
                                "expires_at": item["expires_at"]})
            except TargetError:
                continue
    settings["pending"] = pending
    presets = {}
    for name, value in (raw.get("presets") if isinstance(raw.get("presets"), dict) else {}).items():
        cleaned = _clean_preset(value)
        if isinstance(name, str) and _PRESET_RE.fullmatch(name) and name not in BUILTIN_PRESETS and cleaned:
            presets[name] = cleaned
    if isinstance(raw.get("presets"), dict):
        settings["presets"] = dict(list(presets.items())[:MAX_CUSTOM_PRESETS])
    limits = raw.get("limits") if isinstance(raw.get("limits"), dict) else {}
    for key in DEFAULT_ST_LIMITS:
        value = limits.get(key)
        if type(value) is int and 1 <= value <= HARD_LIMITS[key]:
            settings["limits"][key] = value
    return settings


def read_settings(environ: dict[str, str] | None = None) -> dict:
    env = _env(environ)
    path = _path(env)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return _default_settings(env)
    except OSError as exc:
        raise TargetError("Test hedefi ayarları okunamadı.") from exc
    with os.fdopen(fd, "rb") as handle:
        meta = os.fstat(handle.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o022 \
                or meta.st_size > 262144:
            raise TargetError("Test hedefi ayarları güvenli değil.")
        try:
            raw = json.loads(handle.read())
        except ValueError:
            raw = {"targets": []}
    return _clean(raw, env)


def _save(path: Path, settings: dict) -> None:
    data = json.dumps(settings, ensure_ascii=False, indent=1).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".sandbox-targets-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _update(environ: dict[str, str] | None, change) -> dict:
    env = _env(environ)
    path = _path(env)
    lock_fd = os.open(path.parent / (FILE_NAME + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        settings = read_settings(env)
        result = change(settings)
        _save(path, settings)
        return result
    finally:
        os.close(lock_fd)


# ---------------------------------------------------------------------------
# Kapsam, yerel hedefler, profiller, sınırlar
# ---------------------------------------------------------------------------
def set_scope(scope: object, enabled: object, environ: dict[str, str] | None = None) -> dict:
    if scope not in SCOPES or type(enabled) is not bool:
        raise TargetError("Kapsam: local, critical veya remote_verified; enabled: true/false.")

    def change(settings: dict) -> dict:
        settings["scopes"][scope] = enabled
        return dict(settings["scopes"])

    return _update(environ, change)


def add_local_target(port: object, tools: object = None, label: object = "",
                     environ: dict[str, str] | None = None) -> dict:
    env = _env(environ)
    port = _port(port)
    tool_list, text = _tools(tools), _label(label)
    critical = port in critical_ports(env)

    def change(settings: dict) -> dict:
        if not settings["scopes"]["local"]:
            raise ScopeDisabled("'Yerel portlar' kapsam seçeneği kapalı.")
        if critical and not settings["scopes"]["critical"]:
            raise ScopeDisabled("Bu port kritik bir yerel servise ait; önce 'Kritik yerel servisler' seçeneğini açın.")
        entry = {"id": f"local:{port}", "kind": "local", "host": "127.0.0.1", "port": port, "scheme": "http",
                 "tools": tool_list, "label": text, "added_at": int(time.time()), "critical": critical}
        rest = [t for t in settings["targets"] if t["id"] != entry["id"]]
        if len(rest) >= MAX_TARGETS:
            raise TargetError(f"En çok {MAX_TARGETS} hedef tanımlanabilir.")
        settings["targets"] = sorted(rest + [entry], key=lambda t: t["id"])
        return entry

    return _update(env, change)


def set_target_tools(target_id: object, tools: object, environ: dict[str, str] | None = None) -> dict:
    """Kayıtlı hedefin izinli araçlarını değiştir (kapsam ve doğrulama aynen kalır)."""
    if not isinstance(target_id, str) or len(target_id) > 300:
        raise TargetError("Geçersiz hedef kimliği.")
    tool_list = _tools(tools)

    def change(settings: dict) -> dict:
        for entry in settings["targets"]:
            if entry["id"] == target_id:
                if entry["kind"] == "remote" and "runtime_proof" in tool_list:
                    raise TargetError("Çalışma zamanı kanıtı yalnız loopback hedeflerde kullanılabilir.")
                entry["tools"] = tool_list
                return public_target(entry)
        raise TargetError("Hedef bulunamadı.")

    return _update(environ, change)


def remove_target(target_id: object, environ: dict[str, str] | None = None) -> bool:
    if not isinstance(target_id, str) or len(target_id) > 300:
        raise TargetError("Geçersiz hedef kimliği.")

    def change(settings: dict) -> bool:
        kept = [t for t in settings["targets"] if t["id"] != target_id]
        removed = len(kept) != len(settings["targets"])
        settings["targets"] = kept
        return removed

    return _update(environ, change)


def presets(environ: dict[str, str] | None = None) -> dict[str, dict]:
    try:
        custom = read_settings(environ)["presets"]
    except TargetError:
        custom = {}
    return {**{k: dict(v, builtin=True) for k, v in BUILTIN_PRESETS.items()},
            **{k: dict(v, builtin=False) for k, v in custom.items()}}


def set_preset(name: object, vus: object, duration_s: object, label: object = "",
               environ: dict[str, str] | None = None) -> dict:
    if not isinstance(name, str) or not _PRESET_RE.fullmatch(name) or name in BUILTIN_PRESETS:
        raise TargetError("Profil adı küçük harf/rakam/-/_ (en çok 32); hazır profiller (hafif/orta/yogun) değiştirilemez.")
    preset = _clean_preset({"vus": vus, "duration_s": duration_s, "label": label})
    if preset is None:
        raise TargetError(f"VU 1–{HARD_LIMITS['vus']}, süre 1–{HARD_LIMITS['duration_s']} sn olmalı.")

    def change(settings: dict) -> dict:
        if name not in settings["presets"] and len(settings["presets"]) >= MAX_CUSTOM_PRESETS:
            raise TargetError(f"En çok {MAX_CUSTOM_PRESETS} özel profil tanımlanabilir.")
        settings["presets"][name] = preset
        return preset

    return _update(environ, change)


def remove_preset(name: object, environ: dict[str, str] | None = None) -> bool:
    if name in BUILTIN_PRESETS:
        raise TargetError("Hazır profiller kaldırılamaz.")

    def change(settings: dict) -> bool:
        return settings["presets"].pop(name, None) is not None

    return _update(environ, change)


def set_limits(values: object, environ: dict[str, str] | None = None) -> dict[str, int]:
    if not isinstance(values, dict) or not values or set(values) - set(DEFAULT_ST_LIMITS):
        raise TargetError("Sınırlar: " + ", ".join(sorted(DEFAULT_ST_LIMITS)))
    for key, value in values.items():
        if type(value) is not int or not 1 <= value <= HARD_LIMITS[key]:
            raise TargetError(f"{key} 1–{HARD_LIMITS[key]} aralığında bir tam sayı olmalı.")

    def change(settings: dict) -> dict:
        settings["limits"].update(values)
        return dict(settings["limits"])

    return _update(environ, change)


# ---------------------------------------------------------------------------
# Uzak hedef sahiplik doğrulaması (yalnız kullanıcı başlatınca)
# ---------------------------------------------------------------------------
def start_verification(host: object, port: object = 443, scheme: object = "https", tools: object = None,
                       label: object = "", environ: dict[str, str] | None = None) -> dict:
    host = remote_host(host)
    port = _port(port)
    if scheme not in ("http", "https"):
        raise TargetError("Şema http veya https olmalı.")
    tool_list, text = _remote_tools(tools), _label(label)
    now = int(time.time())
    item = {"id": secrets.token_hex(16), "token": secrets.token_urlsafe(32), "host": host, "port": port,
            "scheme": scheme, "tools": tool_list, "label": text, "created_at": now, "expires_at": now + PENDING_TTL}

    def change(settings: dict) -> dict:
        if not settings["scopes"]["remote_verified"]:
            raise ScopeDisabled("'Sahipliği doğrulanmış uzak hedefler' kapsam seçeneği kapalı.")
        settings["pending"] = [p for p in settings["pending"] if not (p["host"] == host and p["port"] == port)]
        if len(settings["pending"]) >= MAX_PENDING:
            raise TargetError("Çok fazla bekleyen doğrulama.")
        settings["pending"].append(item)
        return item

    _update(environ, change)
    return {**item, **instructions(item)}


def instructions(item: dict) -> dict:
    return {"http_url": f"https://{item['host']}/.well-known/sniper-verify/{item['id']}",
            "http_body": item["token"],
            "dns_name": f"_sniper-verify.{item['host']}", "dns_value": f"sniper-verify={item['token']}"}


def fetch_http_token(host: str, token_id: str, timeout: float = 5.0) -> bytes:
    """https://<alan>/.well-known/sniper-verify/<id>: TLS doğrulamalı, yönlendirme yok, en çok 4 KB."""
    import http.client
    import ssl
    conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ssl.create_default_context())
    try:
        conn.request("GET", f"/.well-known/sniper-verify/{token_id}",
                     headers={"Host": host, "User-Agent": "Sniper-ownership-verification", "Connection": "close"})
        response = conn.getresponse()
        if response.status != 200:
            raise VerificationFailed(f"HTTP doğrulama yanıtı {response.status} (yönlendirme izlenmez).")
        return response.read(4097)
    except OSError as exc:
        raise VerificationFailed("HTTP doğrulama dosyasına ulaşılamadı.") from exc
    finally:
        conn.close()


def _dns_query_txt(name: str, timeout: float = 4.0) -> list[str]:
    """Sistem çözücüsüne (resolv.conf'taki ilk sunucu) tek UDP TXT sorgusu; yalnız standart kütüphane."""
    import socket
    import struct
    server = "127.0.0.53"
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                server = parts[1]
                break
    except OSError:
        pass
    ident = secrets.randbits(16)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    packet = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 16, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    rid, flags, qd, an = struct.unpack(">HHHH", data[:8])
    if rid != ident or flags & 0x000F:
        return []
    offset = 12

    def skip_name(pos: int) -> int:
        while True:
            length = data[pos]
            if length == 0:
                return pos + 1
            if length & 0xC0 == 0xC0:
                return pos + 2
            pos += 1 + length

    for _ in range(qd):
        offset = skip_name(offset) + 4
    texts = []
    for _ in range(an):
        offset = skip_name(offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == 16:
            parts, pos = [], 0
            while pos < len(rdata):
                size = rdata[pos]
                parts.append(rdata[pos + 1:pos + 1 + size].decode("utf-8", "replace"))
                pos += 1 + size
            texts.append("".join(parts))
    return texts


def _probe_ownership(host: str, token_id: str, token: str, http_fetch, dns_txt) -> tuple[str, bytes] | None:
    """Önce .well-known dosyası, sonra TXT kaydı; bulunan yöntem ve kanıt baytları."""
    try:
        body = http_fetch(host, token_id)
        if isinstance(body, bytes) and len(body) <= 4096 and body.strip() == token.encode():
            return "http", body
    except (VerificationFailed, OSError):
        pass
    try:
        records = dns_txt(f"_sniper-verify.{host}")
    except (OSError, ValueError, IndexError):
        records = []
    if f"sniper-verify={token}" in records:
        return "dns", "\n".join(sorted(records)).encode()[:4096]
    return None


def check_verification(verification_id: object, *, environ: dict[str, str] | None = None,
                       http_fetch=None, dns_txt=None) -> dict:
    """Tek "Doğrula": kullanıcı başlatınca sahiplik denetimi; başarılıysa hedef doğrulanmış olarak eklenir/yenilenir."""
    http_fetch = http_fetch or fetch_http_token
    dns_txt = dns_txt or _dns_query_txt
    if not isinstance(verification_id, str) or not _TOKEN_ID_RE.fullmatch(verification_id):
        raise TargetError("Geçersiz doğrulama kimliği.")
    settings = read_settings(environ)
    if not settings["scopes"]["remote_verified"]:
        raise ScopeDisabled("'Sahipliği doğrulanmış uzak hedefler' kapsam seçeneği kapalı.")
    item = next((p for p in settings["pending"] if p["id"] == verification_id), None)
    if item is None:
        existing = next((t for t in settings["targets"] if t["kind"] == "remote"
                         and t["verification"].get("token_id") == verification_id), None)
        if existing is None:
            raise TargetError("Bekleyen doğrulama bulunamadı ya da süresi doldu.")
        item = {"id": verification_id, "token": existing["verification"].get("token", ""), "host": existing["host"],
                "port": existing["port"], "scheme": existing["scheme"], "tools": existing["tools"],
                "label": existing["label"]}
    found = _probe_ownership(item["host"], item["id"], item["token"], http_fetch, dns_txt)
    if found is None:
        raise VerificationFailed("Belirteç ne .well-known dosyasında ne de TXT kaydında bulundu.")
    method, evidence = found
    now = int(time.time())
    entry = {"id": f"remote:{item['host']}:{item['port']}", "kind": "remote", "host": item["host"], "port": item["port"],
             "scheme": item["scheme"], "tools": item["tools"], "label": item["label"], "added_at": now,
             "critical": False, "verification": {"method": method, "token_id": item["id"], "verified_at": now,
                                                  "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                                                  "token": item["token"], "failed_at": None}}

    def change(settings: dict) -> dict:
        settings["pending"] = [p for p in settings["pending"] if p["id"] != verification_id]
        rest = [t for t in settings["targets"] if t["id"] != entry["id"]]
        if len(rest) >= MAX_TARGETS:
            raise TargetError(f"En çok {MAX_TARGETS} hedef tanımlanabilir.")
        settings["targets"] = sorted(rest + [entry], key=lambda t: t["id"])
        return entry

    _update(environ, change)
    return public_target(entry)


def reverify_due(environ: dict[str, str] | None = None, *, now: int | None = None, http_fetch=None,
                 dns_txt=None) -> list[dict]:
    """Arka plan yeniden doğrulaması: yalnız doğrulanmış uzak alanlara, yalnız aynı .well-known yolu / TXT kaydı.

    Sonuç her hedef için {id, ok, method, evidence_sha256}; başarısızlıkta hedef ``failed_at`` ile işaretlenir ve
    yeniden doğrulanana dek çalıştırılmaz.
    """
    now = int(time.time()) if now is None else now
    http_fetch = http_fetch or fetch_http_token
    dns_txt = dns_txt or _dns_query_txt
    try:
        settings = read_settings(environ)
    except TargetError:
        return []
    if not settings["scopes"]["remote_verified"]:
        return []
    due = [t for t in settings["targets"] if t["kind"] == "remote"
           and now - t["verification"]["verified_at"] >= REVERIFY_SECONDS]
    results = []
    for target in due:
        verification = target["verification"]
        found = _probe_ownership(target["host"], verification["token_id"], verification.get("token") or "",
                                 http_fetch, dns_txt)
        results.append({"id": target["id"], "ok": found is not None, "method": found[0] if found else None,
                        "evidence_sha256": hashlib.sha256(found[1]).hexdigest() if found else None})
    if results:
        outcome = {r["id"]: r for r in results}

        def change(settings: dict) -> None:
            for target in settings["targets"]:
                result = outcome.get(target["id"])
                if result is None:
                    continue
                if result["ok"]:
                    target["verification"].update(verified_at=now, method=result["method"],
                                                  evidence_sha256=result["evidence_sha256"], failed_at=None)
                else:
                    target["verification"]["failed_at"] = now

        _update(environ, change)
    return results


# ---------------------------------------------------------------------------
# Çalıştırma için hedef çözümü
# ---------------------------------------------------------------------------
def parse_target_url(target: object) -> tuple[str, str, int]:
    if not isinstance(target, str) or len(target) > 300:
        raise TargetError("Geçersiz hedef.")
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or parts.username or parts.password or parts.path not in ("", "/") \
            or parts.query or parts.fragment or not parts.hostname:
        raise TargetError("Hedef yalnız şema://ana-makine[:port] olmalı.")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetError("Geçersiz port.") from exc
    return parts.scheme, parts.hostname.lower(), port


def resolve_run_target(tool: str, target: object, environ: dict[str, str] | None = None) -> dict:
    """Hedef listede, araca açık ve kapsamı açık olmalı; uzak hedefin doğrulaması güncel olmalı."""
    scheme, host, port = parse_target_url(target)
    settings = read_settings(environ)
    if host == "127.0.0.1":
        if scheme != "http":
            raise TargetError("Yerel hedefler http://127.0.0.1:PORT biçimindedir.")
        target_id = f"local:{port}"
    else:
        target_id = f"remote:{remote_host(host)}:{port}"
    entry = next((t for t in settings["targets"] if t["id"] == target_id and t["scheme"] == scheme), None)
    if entry is None or tool not in entry["tools"]:
        raise TargetError("Hedef, bu araç için izinli test hedefleri listesinde değil.")
    scopes = settings["scopes"]
    if entry["kind"] == "local" and not scopes["local"]:
        raise ScopeDisabled("'Yerel portlar' kapsam seçeneği kapalı.")
    if entry["critical"] and not scopes["critical"]:
        raise ScopeDisabled("'Kritik yerel servisler' kapsam seçeneği kapalı.")
    if entry["kind"] == "remote":
        if not scopes["remote_verified"]:
            raise ScopeDisabled("'Sahipliği doğrulanmış uzak hedefler' kapsam seçeneği kapalı.")
        if entry["verification"].get("failed_at"):
            raise ScopeDisabled("Periyodik sahiplik doğrulaması başarısız oldu; 'Doğrula' ile yeniden doğrulayın.")
    return {"id": entry["id"], "kind": entry["kind"], "host": entry["host"], "port": entry["port"],
            "scheme": entry["scheme"], "critical": entry["critical"]}


def resolve_preset(name: object, target: dict, environ: dict[str, str] | None = None) -> dict:
    if name is None:
        name = "hafif" if target.get("critical") else "orta"
    table = presets(environ)
    if not isinstance(name, str) or name not in table:
        raise TargetError("Bilinmeyen yük profili.")
    preset = table[name]
    return {"name": name, "vus": preset["vus"], "duration_s": preset["duration_s"]}


def public_target(entry: dict) -> dict:
    result = {k: v for k, v in entry.items() if k != "verification"}
    if entry.get("kind") == "remote":
        verification = entry["verification"]
        result["verification"] = {k: verification.get(k) for k in ("method", "verified_at", "evidence_sha256", "failed_at")}
        result["reverify_due_at"] = verification.get("verified_at", 0) + REVERIFY_SECONDS
    return result


def status(environ: dict[str, str] | None = None) -> dict:
    env = _env(environ)
    try:
        settings, error = read_settings(env), ""
    except TargetError as exc:
        settings, error = _default_settings(env), str(exc)
    return {"local_host": "127.0.0.1", "scopes": settings["scopes"],
            "targets": [public_target(t) for t in settings["targets"]],
            "pending_verifications": [{k: p[k] for k in ("id", "host", "port", "scheme", "expires_at")}
                                      for p in settings["pending"]],
            "presets": presets(env), "limits": settings["limits"], "hard_limits": dict(HARD_LIMITS),
            "critical_ports": sorted(critical_ports(env)), "critical_warning": CRITICAL_WARNING,
            "reverify_seconds": REVERIFY_SECONDS, "max_targets": MAX_TARGETS, "tools": list(TOOLS), "error": error}
