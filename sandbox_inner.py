"""bwrap sandbox'ı içinde çalışan başlatıcı (yalnız /usr ve /job, /out, /relay görünür; ağ ad alanında yalnız lo).

127.0.0.1:<listen_port> üzerinde dinler; her TCP bağlantısını tek Unix soketine (/relay/relay.sock) aktarır.
Dışarıdaki yardımcı bu soketi yalnız izinli tek hedefe bağlar. Ardından aracı (k6/schemathesis) sabit argv ve
ortamla çalıştırır, çıktısını sınırlı olarak /out/tool.log'a yazar, sonucu /out/inner.json'a bırakır.
Standart kütüphane dışında bağımlılığı yoktur; python3 -I ile çalıştırılır.
"""
from __future__ import annotations

import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

RELAY_SOCKET = "/relay/relay.sock"
BUFFER = 65536


def _pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(BUFFER)
            if not data:
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


def _serve(listener: socket.socket, counter: list[int], stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            client, _ = listener.accept()
        except OSError:
            return
        counter[0] += 1
        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.settimeout(10)
            upstream.connect(RELAY_SOCKET)
            upstream.settimeout(None)
        except OSError:
            client.close()
            continue

        def run(a: socket.socket = client, b: socket.socket = upstream) -> None:
            left = threading.Thread(target=_pump, args=(a, b), daemon=True)
            left.start()
            _pump(b, a)
            left.join(timeout=5)
            a.close()
            b.close()

        threading.Thread(target=run, daemon=True).start()


def _run_tool(argv: list[str], env: dict[str, str], timeout: float, log_limit: int) -> tuple[int | None, bool]:
    process = subprocess.Popen(argv, env=env, cwd="/tmp", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, close_fds=True, start_new_session=True)
    assert process.stdout is not None
    written = 0
    selector = selectors.DefaultSelector()
    os.set_blocking(process.stdout.fileno(), False)
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    timed_out = False
    with open("/out/tool.log", "wb") as log:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fd, BUFFER)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if written < log_limit:
                    log.write(chunk[: log_limit - written])
                    written += len(chunk)
    selector.close()
    if timed_out:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        code = None
    process.stdout.close()
    return code, timed_out


def main(spec_path: str) -> int:
    with open(spec_path, encoding="utf-8") as handle:
        spec = json.load(handle)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(spec["listen_port"])))
    listener.listen(128)
    counter = [0]
    stop = threading.Event()
    threading.Thread(target=_serve, args=(listener, counter, stop), daemon=True).start()
    code, timed_out = _run_tool(list(spec["argv"]), dict(spec["env"]), float(spec["timeout"]), int(spec["log_limit"]))
    stop.set()
    listener.close()
    with open("/out/inner.json", "w", encoding="utf-8") as handle:
        json.dump({"exit_code": code, "timed_out": timed_out, "connections": counter[0]}, handle)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
