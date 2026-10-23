"""Saf Python iş kuyruğu rotalarını ayrı bir süreçte çalıştıran işçi.

Python iş parçacıkları zorla durdurulamadığı için (ör. büyük bir proje analizi) bu rotalar
iş kuyruğunda kendi süreç grubunda çalışır; iptal ve süre aşımı ``killpg`` ile gerçekten
durdurur. İşçi, canlı istekle aynı doğrulama/yürütme yolunu (``server._run_post_capture``)
kullanır; girdi stdin'den tek JSON nesnesi, çıktı stdout'a tek JSON nesnesidir.
"""

from __future__ import annotations

import json
import sys
import types

MAX_INPUT_BYTES = 512_000


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print(json.dumps({"status": 413, "body": {"error": "İş girdisi çok büyük."}}))
        return 0
    request = json.loads(raw)
    import server  # ağır içe aktarma: yalnız işçi süreçte

    fake_server = types.SimpleNamespace(server_port=int(request.get("server_port") or server.PORT))
    client = tuple(request.get("client_address") or ("127.0.0.1", 0))
    headers = [(str(k), str(v)) for k, v in request.get("headers", [])]
    import request_context
    actor = request.get("actor") if isinstance(request.get("actor"), dict) else None
    import contextlib
    import os
    import project_progress

    reporting = contextlib.nullcontext()
    raw_fd = os.environ.pop("SNIPER_PROGRESS_FD", "")
    if raw_fd.isdigit():
        try:
            os.fstat(int(raw_fd))  # ana sürecin verdiği boru ucu; yoksa ilerleme bildirilmez
            reporting = project_progress.reporting(project_progress.fd_writer(int(raw_fd)))
        except OSError:
            pass
    with request_context.acting_as(actor), reporting:  # iş, kuyruğa alan kullanıcının kimliğiyle (denetim kaydı)
        project_progress.report("start", force=True)
        status, body = server._run_post_capture(fake_server, client, headers, request["route"], request["payload"])
    sys.stdout.write(json.dumps({"status": status, "body": body}, ensure_ascii=False, default=str))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
