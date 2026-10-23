"""Bounded k6 smoke for an explicitly approved host-loopback HTTP service.

Candidate only. A fixed, pinned k6 script talks to a container-local HTTP shim;
its only bridge to the host is a counted Unix relay. The service defaults off.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import socketserver
import struct
import stat
import subprocess
import tempfile
import threading
from pathlib import Path

from k6_relay_protocol import RelayGate, RelayReply, ProtocolError, parse_fixed_summary, MAX_FRAME_BYTES, MAX_TARGET_BODY_BYTES

DOCKER = Path('/usr/bin/docker')
IMAGE_ID = 'sha256:b3feeeea123d0d6315ec14f3d746b20c4abd4b29438e2486bbb96fd3d155e2d6'
PAYLOAD = Path(__file__).with_name('k6_payload')
PAYLOAD_PINS = {
    'fixed_k6_smoke_design.js': '34412c05b58c8339923a5a14b1f8b70fe9d1b12359f5b39574bc82ee0abe0c84',
    'k6_loopback_shim_v2': 'e07ddfe22a642d2333e8360db1e205be6496de9162015d90fd665c108941dce2',
}
CONTAINER_OWNERSHIP_LABEL = 'org.sniper.community.k6.local'
WORK_PARENT = Path.home() / '.local/state/sniper/k6-loopback'
TARGET_RE = re.compile(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z')
PATH_RE = re.compile(r'/(?:[A-Za-z0-9_-]+/?){1,8}\Z')
WALL_SECONDS = 30
RUN_LOCK = threading.Lock()

class K6Unavailable(RuntimeError):
    pass

class K6Busy(RuntimeError):
    pass

class K6ExecutionError(RuntimeError):
    pass


def _approved(target_url: object, path: object) -> tuple[int, str]:
    if type(target_url) is not str or not TARGET_RE.fullmatch(target_url):
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    port = int(TARGET_RE.fullmatch(target_url).group(1))
    try:
        server_port = int(os.environ.get('SNIPER_PORT', '8787'))
    except ValueError as exc:
        raise K6Unavailable("Onaylı loopback k6 çalıştırıcısı kullanılamıyor.") from exc
    if port > 65535 or port in {8765, server_port}:
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    if type(path) is not str or not PATH_RE.fullmatch(path) or '//' in path or len(path) > 128:
        raise ValueError("Geçersiz sınırlı yol.")
    raw = os.environ.get('SNIPER_K6_ALLOWED_PORTS', '')
    parts = raw.split(',') if raw else []
    if not parts or len(parts) > 32 or any(not re.fullmatch(r'[1-9][0-9]{0,4}', p) for p in parts):
        raise K6Unavailable("Onaylı loopback k6 çalıştırıcısı kullanılamıyor.")
    ports = [int(p) for p in parts]
    if any(p > 65535 for p in ports) or len(set(ports)) != len(ports):
        raise K6Unavailable("Onaylı loopback k6 çalıştırıcısı kullanılamıyor.")
    if port not in ports:
        raise ValueError("Geçersiz onaylı loopback hedefi.")
    return port, path


def _pinned_runtime() -> None:
    if os.getuid() == 0 or DOCKER.is_symlink() or not DOCKER.is_file() or not os.access(DOCKER, os.X_OK):
        raise K6Unavailable("Sabitlenmiş k6 çalışma zamanı kullanılamıyor.")
    if PAYLOAD.is_symlink() or not PAYLOAD.is_dir():
        raise K6Unavailable("Sabitlenmiş k6 çalışma zamanı kullanılamıyor.")
    for name, expected in PAYLOAD_PINS.items():
        item = PAYLOAD / name
        if item.is_symlink() or not item.is_file() or not stat.S_ISREG(item.stat(follow_symlinks=False).st_mode):
            raise K6Unavailable("Sabitlenmiş k6 çalışma zamanı kullanılamıyor.")
        if hashlib.sha256(item.read_bytes()).hexdigest() != expected:
            raise K6Unavailable("Sabitlenmiş k6 çalışma zamanı kullanılamıyor.")
    try:
        result = subprocess.run([str(DOCKER), 'image', 'inspect', IMAGE_ID, '--format', '{{.Id}} {{.Os}}/{{.Architecture}}'],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                                env={'PATH': '/usr/bin:/bin'}, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise K6Unavailable("Sabitlenmiş k6 çalışma zamanı kullanılamıyor.") from exc
    if result.returncode or result.stdout.strip() != (IMAGE_ID + ' linux/arm64').encode():
        raise K6Unavailable("Sabitlenmiş k6 çalışma zamanı kullanılamıyor.")


def _private_parent() -> Path:
    parent = WORK_PARENT
    if not parent.is_absolute() or parent.is_symlink():
        raise K6Unavailable("Özel k6 çalışma alanı kullanılamıyor.")
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
            raise OSError("güvensiz çalışma alanı")
    except OSError as exc:
        raise K6Unavailable("Özel k6 çalışma alanı kullanılamıyor.") from exc
    return parent


def _exact_read(sock, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ProtocolError("kesik Unix çerçevesi")
        out.extend(chunk)
    return bytes(out)


def _bind_unix(work: Path, handler):
    class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
    # /proc/self/fd keeps sockaddr_un short without process-global chdir in a
    # multithreaded HTTP server. The directory is a private 0700 run dir.
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        server = UnixServer(f'/proc/self/fd/{fd}/relay.sock', handler)
        try:
            os.chmod(work/'relay.sock', 0o600)
        except Exception:
            server.server_close()
            (work/'relay.sock').unlink(missing_ok=True)
            raise
        return server
    finally:
        os.close(fd)


def _docker_argv(work: Path, name: str, label: str) -> list[str]:
    return [str(DOCKER), 'run', '--rm', '--pull=never', '--network=none', '--read-only',
            '--user='+f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=256m', '--cpus=1',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m', '--cidfile', str(work/'container.cid'),
            '--label', CONTAINER_OWNERSHIP_LABEL+'='+label, '--name', name,
            '--mount', f'type=bind,source={PAYLOAD},target=/artifact,readonly',
            '--mount', f'type=bind,source={work},target=/work',
            '-e', 'HOME=/tmp', '--entrypoint', '/artifact/k6_loopback_shim_v2', IMAGE_ID]


def _complete_inventory(cid: str | None, name: str) -> bool:
    try:
        ps = subprocess.run([str(DOCKER), 'ps', '-a', '--no-trunc', '--format', '{{json .}}'],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=8,
                            env={'PATH': '/usr/bin:/bin'}, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise K6ExecutionError("Konteyner temizliği doğrulanamadı.") from exc
    if ps.returncode or len(ps.stdout) > 1024*1024:
        raise K6ExecutionError("Konteyner temizliği doğrulanamadı.")
    try:
        for raw in ps.stdout.splitlines():
            row = json.loads(raw)
            if type(row) is not dict or not re.fullmatch(r'[0-9a-f]{64}', row.get('ID', '')) or type(row.get('Names')) is not str:
                raise ValueError("envanter bozuk")
            if (cid and row['ID'] == cid) or name in [value.strip() for value in row['Names'].split(',')]:
                return False
    except (ValueError, TypeError) as exc:
        raise K6ExecutionError("Konteyner temizliği doğrulanamadı.") from exc
    return True


def _peer_is_owned_shim(sock: socket.socket, work: Path, name: str, label: str) -> bool:
    """Bind the Unix FD peer PID to this run's exact Docker container init.

    A host process with the same UID cannot claim the owned CID and init PID.
    Every uncertainty denies before the counted relay reaches the target.
    """
    if not hasattr(socket, 'SO_PEERCRED'):
        return False
    try:
        raw_creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        peer_pid, peer_uid, peer_gid = struct.unpack('3i', raw_creds)
        if peer_pid <= 0 or (peer_uid, peer_gid) != (os.getuid(), os.getgid()):
            return False
        cidfile = work / 'container.cid'
        if cidfile.is_symlink() or not cidfile.is_file():
            return False
        raw_cid = cidfile.read_bytes()
        if not re.fullmatch(rb'[0-9a-f]{64}\n?', raw_cid):
            return False
        cid = raw_cid.decode('ascii').strip()
        inspected = subprocess.run([str(DOCKER), 'inspect', '--type', 'container', cid],
                                   stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                                   env={'PATH': '/usr/bin:/bin'}, check=False)
        if inspected.returncode or len(inspected.stdout) > 65536:
            return False
        rows = json.loads(inspected.stdout)
        if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
            return False
        row = rows[0]
        return (row.get('Id') == cid and row.get('Image') == IMAGE_ID and
                row.get('Name') == '/' + name and
                row.get('HostConfig', {}).get('NetworkMode') == 'none' and
                row.get('Config', {}).get('User') == f'{os.getuid()}:{os.getgid()}' and
                row.get('Config', {}).get('Labels', {}).get(CONTAINER_OWNERSHIP_LABEL) == label and
                row.get('State', {}).get('Running') is True and
                type(row.get('State', {}).get('Pid')) is int and
                row['State']['Pid'] == peer_pid)
    except (OSError, ValueError, TypeError, IndexError, AttributeError, subprocess.TimeoutExpired):
        return False


def _cleanup_container(work: Path, name: str, label: str) -> None:
    cidfile = work/'container.cid'
    cid = None
    if cidfile.exists() or cidfile.is_symlink():
        if cidfile.is_symlink() or not stat.S_ISREG(cidfile.stat(follow_symlinks=False).st_mode):
            raise K6ExecutionError("Konteyner sahipliği doğrulanamadı.")
        raw = cidfile.read_bytes()
        if not re.fullmatch(rb'[0-9a-f]{64}\n?', raw):
            raise K6ExecutionError("Konteyner sahipliği doğrulanamadı.")
        cid = raw.decode('ascii').strip()
        try:
            inspected = subprocess.run([str(DOCKER), 'inspect', '--type', 'container', cid],
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=8,
                                       env={'PATH': '/usr/bin:/bin'}, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise K6ExecutionError("Konteyner sahipliği doğrulanamadı.") from exc
        if inspected.returncode == 0:
            try:
                records = json.loads(inspected.stdout)
                row = records[0] if type(records) is list and len(records) == 1 else None
                owned = (type(row) is dict and row.get('Id') == cid and row.get('Image') == IMAGE_ID
                         and row.get('Name') == '/'+name and row.get('HostConfig', {}).get('NetworkMode') == 'none'
                         and row.get('Config', {}).get('User') == f'{os.getuid()}:{os.getgid()}'
                         and row.get('Config', {}).get('Labels', {}).get(CONTAINER_OWNERSHIP_LABEL) == label)
            except (ValueError, TypeError, IndexError, AttributeError):
                owned = False
            if not owned:
                raise K6ExecutionError("Konteyner sahipliği doğrulanamadı.")
            try:
                removed = subprocess.run([str(DOCKER), 'rm', '-f', cid], stdin=subprocess.DEVNULL,
                                         capture_output=True, timeout=8, env={'PATH': '/usr/bin:/bin'}, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise K6ExecutionError("Konteyner temizliği doğrulanamadı.") from exc
            if removed.returncode:
                raise K6ExecutionError("Konteyner temizliği doğrulanamadı.")
    if not _complete_inventory(cid, name):
        raise K6ExecutionError("Konteyner temizliği doğrulanamadı.")


def _run(port: int, path: str) -> dict[str, object]:
    _pinned_runtime()
    if not RUN_LOCK.acquire(blocking=False):
        raise K6Busy("Sınırlı k6 duman testi meşgul.")
    work = None
    container_may_exist = False
    cleanup_verified = False
    try:
        work = Path(tempfile.mkdtemp(prefix='run-', dir=_private_parent()))
        os.chmod(work, 0o700)
        name = 'sniper-k6-'+work.name
        label = hashlib.sha256(os.urandom(32)).hexdigest()
        transport_count = 0
        transport_lock = threading.Lock()
        def transport() -> tuple[int, bytes]:
            nonlocal transport_count
            with transport_lock:
                transport_count += 1
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            try:
                conn.request('GET', path, headers={'Host': f'127.0.0.1:{port}', 'Connection': 'close'})
                response = conn.getresponse()
                body = response.read(MAX_TARGET_BODY_BYTES+1)
                return response.status, body
            finally:
                conn.close()
        gate = RelayGate(transport)
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                try:
                    if not _peer_is_owned_shim(self.request, work, name, label):
                        gate.failure = True
                        self.request.sendall(RelayReply(403).wire_frame())
                        return
                    n = int.from_bytes(_exact_read(self.request, 4), 'big')
                    if not 1 <= n <= MAX_FRAME_BYTES:
                        raise ProtocolError("çerçeve boyutu")
                    frame = n.to_bytes(4, 'big') + _exact_read(self.request, n)
                    reply = gate.handle_frame(frame)
                    self.request.sendall(reply.wire_frame())
                except Exception:
                    gate.failure = True
        relay = _bind_unix(work, Handler)
        thread = threading.Thread(target=relay.serve_forever, daemon=True)
        thread.start()
        docker_result = None
        teardown_errors = []
        try:
            pre = subprocess.run([str(DOCKER), 'ps', '-aq', '--filter', 'name=^/'+name+'$'],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=8,
                                 env={'PATH': '/usr/bin:/bin'}, check=False)
            if pre.returncode or pre.stdout.strip():
                raise K6Unavailable("Sınırlı k6 çalışma zamanı kullanılamıyor.")
            container_may_exist = True
            try:
                docker_result = subprocess.run(_docker_argv(work, name, label), stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=WALL_SECONDS,
                                               env={'PATH': '/usr/bin:/bin', 'HOME': str(work)}, check=False)
            except subprocess.TimeoutExpired as exc:
                raise K6ExecutionError("Sınırlı k6 duman testi başarısız oldu.") from exc
            except OSError as exc:
                raise K6Unavailable("Sınırlı k6 çalışma zamanı kullanılamıyor.") from exc
        finally:
            try:
                _cleanup_container(work, name, label)
                cleanup_verified = True
            except Exception as exc:
                teardown_errors.append(exc)
            for action in (relay.shutdown, relay.server_close,
                           lambda: thread.join(timeout=3),
                           lambda: (work/'relay.sock').unlink(missing_ok=True)):
                try:
                    action()
                except Exception as exc:
                    teardown_errors.append(exc)
            if teardown_errors:
                raise K6ExecutionError("Sınırlı k6 temizliği doğrulanamadı.") from teardown_errors[0]
        if docker_result is None or docker_result.returncode:
            raise K6ExecutionError("Sınırlı k6 duman testi başarısız oldu.")
        summary = work/'summary.json'
        if (summary.is_symlink() or not summary.is_file()
                or not stat.S_ISREG(summary.stat(follow_symlinks=False).st_mode)
                or summary.stat().st_size > 65536):
            raise K6ExecutionError("Sınırlı k6 duman testi başarısız oldu.")
        raw = summary.read_bytes()
        if transport_count != 3 or not gate.success_gate(fixture_requests=transport_count, raw_summary=raw):
            raise K6ExecutionError("Sınırlı k6 duman testi başarısız oldu.")
        try:
            parse_fixed_summary(raw)
        except ProtocolError as exc:
            raise K6ExecutionError("Sınırlı k6 duman testi başarısız oldu.") from exc
        return {'format':'k6-approved-loopback-smoke-v1', 'status':'completed', 'scope':'approved-loopback',
                'request_count':3, 'http_requests':3, 'checks_passed':3, 'checks_failed':0,
                'dropped_iterations':0, 'summary_sha256':hashlib.sha256(raw).hexdigest()}
    finally:
        # On ambiguous Docker cleanup, retain the private CID/label workspace so
        # an operator can verify ownership. Never delete the only cleanup proof.
        try:
            if work is not None and (not container_may_exist or cleanup_verified):
                shutil.rmtree(work)
        finally:
            RUN_LOCK.release()


def run_k6_loopback(target_url: object, path: object) -> dict[str, object]:
    """Run only three fixed GETs against one explicitly allowlisted local port."""
    port, safe_path = _approved(target_url, path)
    return _run(port, safe_path)
