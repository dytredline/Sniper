"""Docker'sız, root'suz yalıtılmış araç çalıştırma: bubblewrap + tek hedefe TCP aktarıcı.

Katmanlar:
1. Arayan (Sniper): girdiyi ve hedefi (sandbox_targets: liste, kapsam, doğrulama) denetler, veri dizininde özel bir
   iş dizini hazırlar, yardımcıyı başlatır. Servis sandbox'ı ayrıcalıksız kullanıcı ad alanındaysa (systemd kullanıcı
   birimi + Ubuntu ``unprivileged_userns`` AppArmor profili) bwrap orada çalışamaz; yardımcı ad alanı açmayan kısıtlı
   geçici bir kullanıcı biriminde başlatılır (qa_broker_client / joern_active ile aynı yaklaşım).
2. Yardımcı (``--helper``): hedefi listeden yeniden doğrular; uzak hedefin adını bir kez, yalnız genel (global) tek
   bir IP'ye çözer; pinli bwrap ve araç ikilisini doğrular; iş dizinindeki Unix soketinde yalnız o IP:port'a TCP
   aktarıcısı açar; süre/bağlantı/bayt sınırlarını uygular.
3. Sandbox (bwrap): ayrı user/pid/net/ipc/uts/cgroup ad alanları, iç içe userns kapalı, yetenek yok (yalnız <1024
   portta, sandbox'ın kendi ağ ad alanında bağlanmak için CAP_NET_BIND_SERVICE), ortam temiz; yalnız /usr, /etc/ssl
   (salt-okunur), /job, /out, /relay, sabit /etc/hosts ve doğrulanmış araç baytları görünür. Ağ ad alanında yalnız
   ``lo`` vardır: araç başka bir porta/adrese ulaşamaz; tek yol aktarıcıdır (sandbox_inner.py). Uzak alan adı
   sandbox'ta /etc/hosts ile 127.0.0.1'e bağlanır; TLS uçtan uca (aktarıcı yalnız TCP baytı taşır).
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
INNER = APP_DIR / "sandbox_inner.py"
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
TOOLS = ("k6", "schemathesis", "playwright")
DRIVER = APP_DIR / "sandbox_playwright_driver.cjs"
AUTHORIZED_DRIVER = APP_DIR / "playwright_authorized_driver.cjs"
PASS_ENV = ("SNIPER_DATA_DIR", "SNIPER_PORT", "SNIPER_K6_ALLOWED_PORTS", "SNIPER_SCHEMATHESIS_ALLOWED_PORTS")
MAX_TIMEOUT = 900
MAX_SPEC_BYTES = 65536
MAX_OUTPUT_FILE = 2_000_000
LOG_LIMIT = 65536


class SandboxUnavailable(RuntimeError):
    """Sandbox çalışma zamanı (bwrap, araç, hedef) kullanılamıyor."""


class SandboxBusy(RuntimeError):
    """Aynı araç için başka bir yalıtılmış çalıştırma sürüyor."""


class SandboxExecutionError(RuntimeError):
    """Yalıtılmış çalıştırma başarısız oldu."""


# ---------------------------------------------------------------------------
# Hedef
# ---------------------------------------------------------------------------
def check_target(tool: str, target_url: object, environ: dict[str, str] | None = None) -> dict:
    """Liste + kapsam + doğrulama (sandbox_targets). Hata: ValueError (TargetError alt sınıfı)."""
    import sandbox_targets
    return sandbox_targets.resolve_run_target(tool, target_url, environ)


def check_authorized_target(tool: str, target_url: object) -> dict:
    """One-run target confirmed by the caller; no persistent registry lookup."""
    from authorized_tool_targets import parse_authorized_target
    return parse_authorized_target(tool, target_url)


def _check_target_mode(tool: str, target_url: object, target_mode: str) -> dict:
    if target_mode == "registered":
        return check_target(tool, target_url)
    if target_mode == "authorized":
        if tool not in {"k6", "schemathesis"}:
            raise ValueError("Geçersiz yetkili araç profili.")
        return check_authorized_target(tool, target_url)
    if target_mode == "playwright-authorized":
        if tool != "playwright":
            raise ValueError("Geçersiz yetkili araç profili.")
        from playwright_authorized import normalize_authorized_target
        return normalize_authorized_target(target_url)
    raise ValueError("Geçersiz hedef doğrulama kipi.")


def resolve_remote(host: str, port: int, resolver=socket.getaddrinfo) -> str:
    """Uzak alan adını bir kez çöz; her adres genel (global) olmalı, ilk adres kullanılır (DNS yeniden bağlamaya karşı)."""
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SandboxUnavailable("uzak_ad_cozulemedi") from exc
    addresses = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global or address.is_multicast:
            raise SandboxUnavailable("uzak_ad_ozel_adrese_cozuldu")
        addresses.append(str(address))
    if not addresses:
        raise SandboxUnavailable("uzak_ad_cozulemedi")
    return addresses[0]


def resolve_authorized_host(host: str, port: int, resolver=socket.getaddrinfo) -> str:
    """Resolve a run-confirmed hostname once and reject unusable destinations.

    Private, link-local and public unicast addresses remain eligible because
    authorization is asserted per run.  Multicast and unspecified addresses
    are not valid TCP targets.
    """
    if host == "localhost":
        return "127.0.0.1"
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SandboxUnavailable("yetkili_ad_cozulemedi") from exc
    addresses: list[str] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError as exc:
            raise SandboxUnavailable("yetkili_ad_cozulemedi") from exc
        if address.is_multicast or address.is_unspecified:
            raise SandboxUnavailable("yetkili_ad_kullanilamaz")
        addresses.append(str(address))
    if not addresses:
        raise SandboxUnavailable("yetkili_ad_cozulemedi")
    # Prefer IPv4: the relay listener in the sandbox is deliberately IPv4.
    return next((value for value in addresses if ":" not in value), addresses[0])


def resolve_authorized(host: str, port: int, resolver=socket.getaddrinfo) -> str:
    """Playwright yetkili hedefini bir kez çöz ve aktarıcıyı o adrese sabitle."""
    try:
        literal = ipaddress.ip_address(host)
        infos = [(None, None, None, None, (str(literal), port))]
    except ValueError:
        try:
            infos = resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise SandboxUnavailable("yetkili_hedef_cozulemedi") from exc
    addresses: list[str] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError, TypeError):
            continue
        if address.is_unspecified or address.is_multicast:
            raise SandboxUnavailable("yetkili_hedef_adresi_gecersiz")
        addresses.append(str(address))
    if not addresses:
        raise SandboxUnavailable("yetkili_hedef_cozulemedi")
    return addresses[0]


def require_authorized_renderer_sandbox(browser_dir: Path) -> Path:
    """İç içe userns kapalıyken Chromium'un setuid sandbox önkoşulunu doğrula."""
    helper = browser_dir / "chrome-sandbox"
    try:
        info = os.lstat(helper)
    except OSError as exc:
        raise SandboxUnavailable("chromium_setuid_sandbox_missing") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or not info.st_mode & stat.S_ISUID or not info.st_mode & stat.S_IXUSR):
        raise SandboxUnavailable("chromium_setuid_sandbox_invalid")
    return helper


# ---------------------------------------------------------------------------
# Çalışma zamanı doğrulaması
# ---------------------------------------------------------------------------
def open_bwrap():
    from tool_pins import open_pinned
    from verified_exec import VerificationError
    try:
        return open_pinned("bwrap")
    except VerificationError as exc:
        raise SandboxUnavailable("bwrap_" + exc.reason) from exc


def open_k6():
    from tool_pins import open_pinned
    from verified_exec import VerificationError
    try:
        return open_pinned("k6")
    except VerificationError as exc:
        raise SandboxUnavailable("k6_" + exc.reason) from exc


def open_node():
    from tool_pins import open_pinned
    from verified_exec import VerificationError
    try:
        return open_pinned("node")
    except VerificationError as exc:
        raise SandboxUnavailable("node_" + exc.reason) from exc


def _root_owned_dir(path: Path) -> None:
    """Bağlanacak dizin root'a ait ve kimse tarafından (bu süreç dahil) yazılamaz olmalı."""
    from verified_exec import _namespaced_root_owned
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or os.access(path, os.W_OK):
        raise SandboxUnavailable("chromium_dizini_guvensiz")
    if info.st_uid != 0 and not _namespaced_root_owned(str(path / "."), info):
        raise SandboxUnavailable("chromium_dizini_guvensiz")


def chromium_dir() -> Path:
    """Pinli Chromium ikilisini doğrular; tarayıcı dosyalarının bulunduğu (root'a ait) dizini döndürür."""
    from tool_pins import configured_binary, open_pinned
    from verified_exec import VerificationError
    try:
        with open_pinned("chromium"):
            pass
    except VerificationError as exc:
        raise SandboxUnavailable("chromium_" + exc.reason) from exc
    directory = Path(configured_binary("chromium") or "").parent
    _root_owned_dir(directory)
    _root_owned_dir(directory.parent)
    return directory


def playwright_core_dir() -> Path:
    from tool_pins import verified_tree
    from verified_exec import VerificationError
    try:
        return verified_tree("playwright-core")
    except (VerificationError, OSError) as exc:
        raise SandboxUnavailable("playwright_core_" + getattr(exc, "reason", "okunamadi")) from exc


def schemathesis_venv() -> Path:
    from schemathesis_active import SchemathesisUnavailable, _checked_executable
    try:
        exe = _checked_executable()
    except SchemathesisUnavailable as exc:
        raise SandboxUnavailable("schemathesis_runtime") from exc
    venv = exe.parent.parent
    if not (venv / "pyvenv.cfg").is_file() or venv.is_symlink():
        raise SandboxUnavailable("schemathesis_runtime")
    return venv


# ---------------------------------------------------------------------------
# Arayan taraf
# ---------------------------------------------------------------------------
def _in_user_namespace() -> bool:
    try:
        with open("/proc/self/uid_map", encoding="ascii") as handle:
            return handle.read().split() != ["0", "0", "4294967295"]
    except OSError:
        return False


def launch_mode() -> str:
    value = os.environ.get("SNIPER_SANDBOX_LAUNCH", "")
    if value in {"direct", "systemd-run"}:
        return value
    return "systemd-run" if _in_user_namespace() and SYSTEMD_RUN.is_file() else "direct"


def _data_dir() -> Path:
    text = os.environ.get("SNIPER_DATA_DIR", "")
    path = Path(text)
    if not text or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise SandboxUnavailable("veri_dizini")
    return path


def _private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise SandboxUnavailable("calisma_alani")
    path.mkdir(mode=0o700, exist_ok=True)
    meta = os.lstat(path)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise SandboxUnavailable("calisma_alani")
    return path


def _lock(tool: str, parent: Path) -> int:
    fd = os.open(parent / f"{tool}.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise SandboxBusy("mesgul") from exc
    return fd


def _write(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def read_output(work: Path, name: str, limit: int = MAX_OUTPUT_FILE) -> bytes | None:
    path = work / "out" / name
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        meta = os.fstat(handle.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise SandboxExecutionError("cikti_gecersiz")
        return handle.read(limit + 1)


def _helper_command(work: Path, unit: str, timeout: int, mode: str) -> list[str]:
    helper = ["/usr/bin/python3", "-I", str(APP_DIR / "tool_sandbox.py"), "--helper", str(work)]
    if mode == "direct":
        return helper
    command = [
        str(SYSTEMD_RUN), "--user", "--wait", "--collect", "--pipe", "--quiet", "--unit=" + unit,
        # Ad alanı açmayan kısıtlar: bwrap kendi ad alanlarını bu birimden kurar.
        "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes", "-p", "LockPersonality=yes",
        "-p", "RestrictRealtime=yes", "-p", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "-p", "MemoryMax=1536M", "-p", "TasksMax=512", "-p", "CPUQuota=200%",
        "-p", f"RuntimeMaxSec={timeout + 45}",
        "-E", "PYTHONDONTWRITEBYTECODE=1",
    ]
    for key in PASS_ENV:
        if key in os.environ:
            command += ["-E", f"{key}={os.environ[key]}"]
    return command + helper


def run_job(tool: str, target_url: str, *, argv: list[str], env: dict[str, str], timeout: int,
            files: dict[str, bytes], max_connections: int, max_bytes: int, reader=None,
            target_mode: str = "registered", authorized: bool = False) -> dict:
    """Yalıtılmış işi çalıştırır; yardımcının sonucunu (relay sayaçları, iç sonuç, ``parsed``) döndürür.

    ``reader(work)`` iş dizini silinmeden çağrılır."""
    if tool not in TOOLS:
        raise ValueError("Geçersiz araç.")
    if type(authorized) is not bool or (authorized and (tool != "playwright" or target_mode != "registered")):
        raise ValueError("Geçersiz yetkili araç profili.")
    if authorized:
        target_mode = "playwright-authorized"
    target = _check_target_mode(tool, target_url, target_mode)
    if not 5 <= timeout <= MAX_TIMEOUT:
        raise ValueError("Geçersiz süre.")
    parent = _private_dir(_data_dir() / "sandbox-runs")
    lock_fd = _lock(tool, parent)
    work: Path | None = None
    unit = "sniper-sandbox-" + uuid.uuid4().hex[:20]
    try:
        work = Path(tempfile.mkdtemp(prefix=f"{tool}-", dir=parent))
        for sub in ("job", "out", "relay"):
            (work / sub).mkdir(mode=0o700)
        for name, data in files.items():
            if not re.fullmatch(r"[a-z0-9_.-]{1,64}", name):
                raise ValueError("Geçersiz iş dosyası adı.")
            _write(work / "job" / name, data, 0o644)
        spec = {"tool": tool, "target_url": target_url, "target_mode": target_mode,
                "argv": argv, "env": env, "timeout": timeout,
                "max_connections": max_connections, "max_bytes": max_bytes}
        _write(work / "spec.json", json.dumps(spec).encode())
        mode = launch_mode()
        finished = False
        try:
            try:
                completed = subprocess.run(
                    _helper_command(work, unit, timeout, mode), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 60, close_fds=True,
                    check=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                         "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"),
                         **{k: os.environ[k] for k in PASS_ENV if k in os.environ}},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SandboxExecutionError("yardimci_basarisiz") from exc
            finished = True
        finally:
            if not finished and mode == "systemd-run":
                subprocess.run([str(SYSTEMCTL), "--user", "stop", unit], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
        if completed.returncode == 3:
            lines = completed.stderr.decode("ascii", "replace").strip().splitlines()
            reason = lines[-1] if lines and re.fullmatch(r"[a-z0-9_]{1,64}", lines[-1]) else "sandbox"
            raise SandboxUnavailable(reason)
        raw = read_output(work, "outer.json", 65536)
        if completed.returncode != 0 or raw is None:
            if os.environ.get("SNIPER_SANDBOX_DEBUG") == "1":
                sys.stderr.write(completed.stderr.decode("utf-8", "replace")[-3000:])
            raise SandboxExecutionError("yardimci_basarisiz")
        outer = json.loads(raw)
        if os.environ.get("SNIPER_SANDBOX_DEBUG") == "1":
            sys.stderr.write(json.dumps(outer) + "\n")
            sys.stderr.write((read_output(work, "tool.log", LOG_LIMIT) or b"").decode("utf-8", "replace")[-3000:])
        outer["target"] = {k: target[k] for k in ("id", "kind", "critical")}
        if target_mode != "registered":
            outer["target"]["normalized"] = target["normalized"]
        if reader is not None:
            outer["parsed"] = reader(work)
        return outer
    finally:
        try:
            if work is not None:
                shutil.rmtree(work, ignore_errors=True)
        finally:
            os.close(lock_fd)


# ---------------------------------------------------------------------------
# Yardımcı (geçici birimde ya da doğrudan alt süreç olarak)
# ---------------------------------------------------------------------------
class _Relay(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, connect_ip: str, port: int, max_connections: int, max_bytes: int) -> None:
        self.connect_ip = connect_ip
        self.target_port = port
        self.max_connections = max_connections
        self.max_bytes = max_bytes
        self.connections = 0
        self.refused = 0
        self.bytes = 0
        self.lock = threading.Lock()
        super().__init__(path, _RelayHandler)
        os.chmod(path, 0o600)

    def take(self, amount: int) -> bool:
        with self.lock:
            if self.bytes + amount > self.max_bytes:
                return False
            self.bytes += amount
            return True


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _Relay = self.server  # type: ignore[assignment]
        with server.lock:
            if server.connections >= server.max_connections:
                server.refused += 1
                return
            server.connections += 1
        try:
            upstream = socket.create_connection((server.connect_ip, server.target_port), timeout=5)
        except OSError:
            with server.lock:
                server.refused += 1
            return
        upstream.settimeout(60)
        self.request.settimeout(60)

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data or not server.take(len(data)):
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for sock, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
                    try:
                        sock.shutdown(how)
                    except OSError:
                        pass

        other = threading.Thread(target=pump, args=(upstream, self.request), daemon=True)
        other.start()
        pump(self.request, upstream)
        other.join(timeout=65)
        upstream.close()


def bwrap_argv(bwrap_fd: int, tool_binds: list[str], *, low_port: bool = False,
               seccomp_fd: int | None = None) -> list[str]:
    caps = ["--cap-drop", "ALL"] + (["--cap-add", "CAP_NET_BIND_SERVICE"] if low_port else [])
    if seccomp_fd is not None:
        caps += ["--seccomp", str(seccomp_fd)]
    return [
        f"/proc/self/fd/{bwrap_fd}",
        "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts", "--unshare-cgroup",
        "--disable-userns", "--die-with-parent", "--new-session", "--clearenv", *caps,
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/sbin", "/sbin", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--ro-bind-try", "/etc/ssl", "/etc/ssl", "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
        "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C.UTF-8",
        *tool_binds, "--chdir", "/tmp",
    ]


def hosts_file(name: str | None) -> bytes:
    lines = ["127.0.0.1 localhost"]
    if name:
        lines.append(f"127.0.0.1 {name}")
    return ("\n".join(lines) + "\n").encode("ascii")


def _fail(reason: str) -> int:
    sys.stderr.write(reason + "\n")
    return 3


def _data_fd(data: bytes, opened: list[int]) -> int:
    read_fd, write_fd = os.pipe()
    opened.append(read_fd)
    os.write(write_fd, data)
    os.close(write_fd)
    return read_fd


def _helper(work_text: str) -> int:
    work = Path(work_text)
    try:
        meta = os.lstat(work)
    except OSError:
        return _fail("is_dizini")
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        return _fail("is_dizini")
    spec_raw = (work / "spec.json").read_bytes()
    if len(spec_raw) > MAX_SPEC_BYTES:
        return _fail("is_tanimi")
    spec = json.loads(spec_raw)
    tool = spec.get("tool")
    if tool not in TOOLS:
        return _fail("is_tanimi")
    try:
        target_mode = spec.get("target_mode", "registered")
        target = _check_target_mode(tool, spec.get("target_url"), target_mode)
    except ValueError:
        return _fail("hedef_listede_degil" if target_mode == "registered" else "yetkili_hedef_gecersiz")
    timeout = int(spec["timeout"])
    if not 5 <= timeout <= MAX_TIMEOUT:
        return _fail("is_tanimi")
    port = target["port"]
    try:
        if target["kind"] in {"local", "loopback"}:
            connect_ip = "127.0.0.1"
        elif target_mode == "authorized":
            connect_ip = resolve_authorized_host(target["host"], port)
        elif target_mode == "playwright-authorized":
            connect_ip = resolve_authorized(target["host"], port)
        else:
            connect_ip = resolve_remote(target["host"], port)
    except SandboxUnavailable as exc:
        return _fail(str(exc))
    try:
        bwrap = open_bwrap()
    except SandboxUnavailable as exc:
        return _fail(str(exc))
    opened: list[int] = []
    try:
        inner_fd = os.open(INNER, os.O_RDONLY | os.O_NOFOLLOW)
        opened.append(inner_fd)
        inner_spec = {"listen_port": port, "argv": spec["argv"], "env": spec["env"], "timeout": timeout,
                      "log_limit": LOG_LIMIT}
        spec_fd = _data_fd(json.dumps(inner_spec).encode(), opened)
        mapped_host = target["host"] if target["kind"] not in {"local", "loopback"} else None
        hosts_fd = _data_fd(hosts_file(mapped_host), opened)
        nss_fd = _data_fd(b"hosts: files\n", opened)
        fds = [bwrap.fd, inner_fd, spec_fd, hosts_fd, nss_fd]
        binds = ["--dir", "/sbx", "--perms", "0444", "--ro-bind-data", str(inner_fd), "/sbx/inner.py",
                 "--perms", "0444", "--ro-bind-data", str(spec_fd), "/sbx/inner.json",
                 "--perms", "0444", "--ro-bind-data", str(hosts_fd), "/etc/hosts",
                 "--perms", "0444", "--ro-bind-data", str(nss_fd), "/etc/nsswitch.conf",
                 "--ro-bind", str(work / "job"), "/job", "--bind", str(work / "out"), "/out",
                 "--bind", str(work / "relay"), "/relay"]
        seccomp_fd = None
        if tool == "k6":
            try:
                k6 = open_k6()
            except SandboxUnavailable as exc:
                return _fail(str(exc))
            opened.append(k6.fd)
            fds.append(k6.fd)
            binds += ["--dir", "/opt/k6", "--perms", "0555", "--ro-bind-data", str(k6.fd), "/opt/k6/k6"]
        elif tool == "playwright":
            # Eski kayıtlı-hedef profilinde dış bwrap+seccomp sınırı Chromium iç sandbox'ının yerini alır.
            # Genel yetkili profil bu davranışı miras almaz: iç sandbox önkoşulu yoksa fail-closed kalır.
            import sandbox_seccomp
            try:
                node = open_node()
                browser_dir = chromium_dir()
                core_dir = playwright_core_dir()
                if target_mode == "playwright-authorized":
                    require_authorized_renderer_sandbox(browser_dir)
                program = sandbox_seccomp.build_filter()
            except SandboxUnavailable as exc:
                return _fail(str(exc))
            except sandbox_seccomp.SeccompUnsupported:
                return _fail("seccomp_desteklenmiyor")
            opened.append(node.fd)
            driver_fd = os.open(AUTHORIZED_DRIVER if target_mode == "playwright-authorized" else DRIVER,
                                os.O_RDONLY | os.O_NOFOLLOW)
            opened.append(driver_fd)
            seccomp_fd = _data_fd(program, opened)
            fds += [node.fd, driver_fd, seccomp_fd]
            binds += ["--dir", "/opt/node", "--perms", "0555", "--ro-bind-data", str(node.fd), "/opt/node/node",
                      "--perms", "0444", "--ro-bind-data", str(driver_fd), "/sbx/driver.cjs",
                      "--ro-bind", str(browser_dir), "/opt/chromium", "--ro-bind", str(core_dir), "/opt/playwright-core",
                      "--ro-bind-try", "/etc/fonts", "/etc/fonts", "--tmpfs", "/dev/shm"]
        else:
            try:
                venv = schemathesis_venv()
            except SandboxUnavailable as exc:
                return _fail(str(exc))
            binds += ["--ro-bind", str(venv), str(venv)]
        argv = bwrap_argv(bwrap.fd, binds, low_port=port < 1024, seccomp_fd=seccomp_fd) + \
            ["/usr/bin/python3", "-I", "/sbx/inner.py", "/sbx/inner.json"]
        # Göreli bağlama: Unix soket yolu 108 bayt sınırı iş dizininin uzunluğundan bağımsız olur.
        os.chdir(work / "relay")
        relay = _Relay("relay.sock", connect_ip, port, int(spec["max_connections"]), int(spec["max_bytes"]))
        thread = threading.Thread(target=relay.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        thread.start()
        started = time.monotonic()
        timed_out = False
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, pass_fds=tuple(fds), close_fds=True,
                                       start_new_session=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            try:
                _, err = process.communicate(timeout=timeout + 20)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
                _, err = process.communicate(timeout=10)
        finally:
            relay.shutdown()
            relay.server_close()
            thread.join(timeout=5)
        outer = {"bwrap_exit": process.returncode, "timed_out": timed_out,
                 "elapsed_s": round(time.monotonic() - started, 2),
                 "relay": {"connections": relay.connections, "refused": relay.refused, "bytes": relay.bytes,
                           "connect_ip": connect_ip},
                 "bwrap_error": (err or b"")[-300:].decode("utf-8", "replace") if process.returncode else ""}
        inner_raw = read_output(work, "inner.json", 4096)
        outer["inner"] = json.loads(inner_raw) if inner_raw else None
        _write(work / "out" / "outer.json", json.dumps(outer).encode())
        return 0
    finally:
        bwrap.close()
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    # python3 -I betik dizinini sys.path'e eklemez; yalnız uygulama dizini (pin/doğrulama modülleri) eklenir.
    sys.path.insert(0, str(APP_DIR))
    if len(sys.argv) == 3 and sys.argv[1] == "--helper":
        sys.exit(_helper(sys.argv[2]))
    sys.stderr.write("kullanim\n")
    sys.exit(4)
