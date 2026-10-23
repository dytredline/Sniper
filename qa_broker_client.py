"""Host QA aracısına (sniper-qa-broker) sınırlı istemci.

Aracı yalnız iki sabit, parametresiz sentetik işlemi (k6, schemathesis) kendi
fikstürüne karşı çalıştırır; kullanıcı hedefi, URL, imaj veya argüman almaz.
Bu modül varsayılan olarak kapalıdır (SNIPER_QA_BROKER=1 ile açılır), soketin
sahibini/grubunu/iznini ve karşı sürecin UID'sini (SO_PEERCRED) doğrular, tek
satır istek gönderir ve yanıtı şemaya göre süzer. Ham çıktı yalnız ANSI/denetim
karakterlerinden arındırılmış kısa bir kuyruk olarak döner.
"""
from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import uuid
from pathlib import Path

SOCKET_PATH = Path("/run/sniper-qa-broker/request.sock")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
BROKER_USER = "sniper-qa-broker"
CLIENT_GROUP = "sniper-qa-client"
OPERATIONS = ("k6", "schemathesis")
RESPONSE_MAX = 16384
TIMEOUT_SECONDS = 45.0
OUTPUT_TAIL = 2000
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_RESULT_KEYS = {"operation", "exit_code", "fixture_hits", "passed", "output"}


class QABrokerUnavailable(RuntimeError):
    """Aracı kapalı, yapılandırılmamış veya kimliği doğrulanamadı."""


class QABrokerBusy(RuntimeError):
    """Başka bir aracı isteği sürüyor."""


class QABrokerError(RuntimeError):
    """Aracı isteği başarısız oldu veya yanıt geçersiz."""


def _enabled() -> bool:
    return os.environ.get("SNIPER_QA_BROKER") == "1"


def _visible_id(real: int, map_path: str, overflow_path: str) -> int:
    """Ana makine kimliğinin bu sürecin kullanıcı ad alanındaki karşılığı.

    systemd kullanıcı servisleri (ProtectSystem/PrivateTmp…) yalnız kendi UID'sini eşleyen bir ad alanında
    çalışır; eşlenmemiş kimlikler çekirdekte overflow kimliği (65534) olarak görünür.
    """
    try:
        with open(map_path, encoding="ascii") as handle:
            for line in handle:
                inside, outside, count = (int(part) for part in line.split())
                if outside <= real < outside + count:
                    return inside + (real - outside)
        with open(overflow_path, encoding="ascii") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError) as exc:
        raise QABrokerUnavailable("namespace_map_unreadable") from exc


def _identities() -> tuple[int, int]:
    try:
        uid, gid = pwd.getpwnam(BROKER_USER).pw_uid, grp.getgrnam(CLIENT_GROUP).gr_gid
    except KeyError as exc:
        raise QABrokerUnavailable("host_identity_missing") from exc
    return (_visible_id(uid, "/proc/self/uid_map", "/proc/sys/kernel/overflowuid"),
            _visible_id(gid, "/proc/self/gid_map", "/proc/sys/kernel/overflowgid"))


def _check_socket(path: Path, broker_uid: int, client_gid: int) -> None:
    try:
        meta = os.lstat(path)
    except FileNotFoundError as exc:
        raise QABrokerUnavailable("broker_socket_missing") from exc
    except OSError as exc:
        raise QABrokerUnavailable("broker_socket_unreadable") from exc
    if not stat.S_ISSOCK(meta.st_mode):
        raise QABrokerUnavailable("broker_socket_not_socket")
    if meta.st_uid != broker_uid or meta.st_gid != client_gid or stat.S_IMODE(meta.st_mode) != 0o660:
        raise QABrokerUnavailable("broker_socket_identity_mismatch")
    try:
        parent = os.lstat(path.parent)
    except OSError as exc:
        raise QABrokerUnavailable("broker_socket_unreadable") from exc
    if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
        raise QABrokerUnavailable("broker_socket_parent_writable")
    # Ad alanında aracı kimliği overflow (65534) görünebilir; o zaman sahte soket konamadığını ayrıca
    # kanıtla: üst dizin bizim değil ve bu süreç oraya yazamaz.
    if not _parent_is_foreign(path.parent, parent):
        raise QABrokerUnavailable("broker_socket_parent_writable")


def _parent_is_foreign(directory: Path, meta: os.stat_result) -> bool:
    return meta.st_uid != os.getuid() and not os.access(directory, os.W_OK)


def status(path: Path = SOCKET_PATH) -> dict:
    """Soket açmadan, yalnız yerel kimlik/izin denetimi."""
    result = {"enabled": _enabled(), "socket_ok": False, "socket_access": False, "reason": ""}
    try:
        broker_uid, client_gid = _identities()
        _check_socket(path, broker_uid, client_gid)
        result["socket_ok"] = True
        # Grup üyeliği ya da aracının soket ACL'si (user:<istemci>:rw) erişim verir.
        result["socket_access"] = os.access(path, os.R_OK | os.W_OK)
    except QABrokerUnavailable as exc:
        result["reason"] = str(exc)
    if not result["reason"]:
        if not result["enabled"]:
            result["reason"] = "disabled"
        elif not result["socket_access"]:
            result["reason"] = "no_socket_access"
        else:
            result["reason"] = "ready"
    return result


def _lock(data_dir: Path) -> int:
    path = data_dir / "qa-broker.lock"
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise QABrokerUnavailable("lock_unavailable") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise QABrokerBusy("busy")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, QABrokerBusy) as exc:
        os.close(fd)
        raise QABrokerBusy("busy") from exc
    return fd


def _clean_output(text: str) -> str:
    text = _CONTROL.sub("", _ANSI.sub("", text))
    return text[-OUTPUT_TAIL:]


def _parse(raw: bytes, operation: str) -> dict:
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise QABrokerError("invalid_response") from exc
    if not isinstance(value, dict):
        raise QABrokerError("invalid_response")
    if set(value) == {"passed", "error"} and value["passed"] is False and isinstance(value["error"], str):
        error = value["error"] if re.fullmatch(r"[A-Za-z]{1,64}", value["error"]) else "Error"
        return {"format": "sniper-qa-broker-v1", "operation": operation, "passed": False, "error": error}
    if set(value) != _RESULT_KEYS or value["operation"] != operation:
        raise QABrokerError("invalid_response")
    exit_code, hits, passed, output = value["exit_code"], value["fixture_hits"], value["passed"], value["output"]
    if (not isinstance(passed, bool) or not isinstance(output, str)
            or not (exit_code is None or (isinstance(exit_code, int) and not isinstance(exit_code, bool)))
            or not isinstance(hits, int) or isinstance(hits, bool) or hits < 0):
        raise QABrokerError("invalid_response")
    return {
        "format": "sniper-qa-broker-v1",
        "operation": operation,
        "passed": passed and exit_code == 0 and hits > 0,
        "exit_code": exit_code,
        "fixture_hits": hits,
        "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
        "output_tail": _clean_output(output),
    }


def _exchange(operation: str, path: Path) -> bytes:
    """Kimlik denetimleri + tek istek/yanıt. Ham yanıt baytlarını döndürür."""
    broker_uid, client_gid = _identities()
    _check_socket(path, broker_uid, client_gid)
    if not os.access(path, os.R_OK | os.W_OK):
        raise QABrokerUnavailable("no_socket_access")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(TIMEOUT_SECONDS)
        try:
            client.connect(str(path))
        except OSError as exc:
            raise QABrokerUnavailable("broker_connect_failed") from exc
        creds = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, peer_uid, _ = struct.unpack("3i", creds)
        if peer_uid != broker_uid:
            raise QABrokerUnavailable("broker_peer_identity_mismatch")
        try:
            client.sendall((json.dumps({"operation": operation}) + "\n").encode())
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > RESPONSE_MAX:
                    raise QABrokerError("response_too_large")
                chunks.append(chunk)
        except (OSError, TimeoutError) as exc:
            raise QABrokerError("broker_io_failed") from exc
    raw = b"".join(chunks)
    if not raw:
        # Aracı UID uyuşmazlığında yanıtsız kapatır.
        raise QABrokerUnavailable("broker_rejected_client")
    return raw


def _in_user_namespace() -> bool:
    try:
        with open("/proc/self/uid_map", encoding="ascii") as handle:
            return handle.read().split() != ["0", "0", "4294967295"]
    except OSError:
        return False


def _launch_mode() -> str:
    """Servis sandbox'ı (ProtectSystem/PrivateTmp/ProtectHome) kullanıcı yöneticisinde ayrıcalıksız bir kullanıcı
    ad alanı açar; Ubuntu'nun unprivileged_userns AppArmor profili ad alanı dışındaki aracı soketine connect()'i
    reddeder ("disconnected path"). Bu durumda istek, ad alanı açmayan kısıtlı geçici bir kullanıcı biriminde
    yapılır (joern_active.launch_mode ile aynı yaklaşım). SNIPER_QA_BROKER_LAUNCH=direct|systemd-run."""
    value = os.environ.get("SNIPER_QA_BROKER_LAUNCH", "")
    if value in {"direct", "systemd-run"}:
        return value
    return "systemd-run" if _in_user_namespace() and SYSTEMD_RUN.is_file() else "direct"


def _unit_command(unit: str, operation: str) -> list[str]:
    return [
        str(SYSTEMD_RUN), "--user", "--wait", "--collect", "--pipe", "--quiet", "--unit=" + unit,
        # Yalnız ad alanı gerektirmeyen kısıtlar (seccomp/cgroup): bağlantı ad alanı dışında kurulmalı.
        "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes", "-p", "LockPersonality=yes",
        "-p", "RestrictRealtime=yes", "-p", "RestrictAddressFamilies=AF_UNIX",
        "-p", "MemoryMax=128M", "-p", "TasksMax=16", "-p", "CPUQuota=50%",
        "-p", f"RuntimeMaxSec={int(TIMEOUT_SECONDS) + 10}",
        "-E", "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3", "-I", str(Path(__file__).resolve()), "--exchange", operation, str(SOCKET_PATH),
    ]


def _exchange_via_unit(operation: str, runner=subprocess.run) -> bytes:
    unit = "sniper-qa-probe-" + uuid.uuid4().hex[:20]
    finished = False
    try:
        try:
            completed = runner(
                _unit_command(unit, operation), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS + 20, close_fds=True, check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                     "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise QABrokerError("probe_unit_failed") from exc
        finished = True
    finally:
        if not finished:
            subprocess.run([str(SYSTEMCTL), "--user", "stop", unit], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
    stdout = completed.stdout or b""
    if len(stdout) > RESPONSE_MAX:
        raise QABrokerError("response_too_large")
    if completed.returncode == 0:
        return stdout
    lines = (completed.stderr or b"").decode("ascii", "replace").strip().splitlines()
    reason = lines[-1] if lines and re.fullmatch(r"[a-z_]{1,64}", lines[-1]) else "probe_unit_failed"
    if completed.returncode == 3:
        raise QABrokerUnavailable(reason)
    raise QABrokerError(reason)


def run_qa_broker_probe(operation: object, *, path: Path = SOCKET_PATH) -> dict:
    if operation not in OPERATIONS:
        raise ValueError("Geçersiz QA işlemi")
    if not _enabled():
        raise QABrokerUnavailable("disabled")
    data_text = os.environ.get("SNIPER_DATA_DIR", "")
    data_dir = Path(data_text)
    if not data_text or not data_dir.is_absolute() or data_dir.is_symlink() or not data_dir.is_dir():
        raise QABrokerUnavailable("data_dir_invalid")
    via_unit = path == SOCKET_PATH and _launch_mode() == "systemd-run"
    lock_fd = _lock(data_dir)
    try:
        raw = _exchange_via_unit(operation) if via_unit else _exchange(operation, path)
        return _parse(raw, operation)
    finally:
        os.close(lock_fd)


def _helper_main(argv: list[str]) -> int:
    """Geçici birim içinde: yalnız sabit soket ve sabit işlem; ham yanıt stdout'a."""
    if len(argv) != 3 or argv[0] != "--exchange" or argv[1] not in OPERATIONS or argv[2] != str(SOCKET_PATH):
        sys.stderr.write("invalid_helper_arguments\n")
        return 4
    try:
        sys.stdout.buffer.write(_exchange(argv[1], SOCKET_PATH))
        return 0
    except QABrokerUnavailable as exc:
        sys.stderr.write(f"{exc}\n")
        return 3
    except QABrokerError as exc:
        sys.stderr.write(f"{exc}\n")
        return 4


if __name__ == "__main__":
    sys.exit(_helper_main(sys.argv[1:]))
