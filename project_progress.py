"""Proje analizi ilerleme bildirimi (aşama + yüzde).

Analiz kodu ``report(...)`` çağırır; etkin bir dinleyici yoksa çağrı hiçbir şey yapmaz (eşzamanlı API ve CLI
etkilenmez). İş kuyruğunda analiz ayrı süreçte (job_worker.py) çalışır: dinleyici ilerlemeyi bir boru üzerinden
satır satır JSON olarak ana sürece iletir; ana süreç işin ``progress`` alanını günceller.

Yüzde aşama ağırlıklarından hesaplanır: dosya yürüyüşü %0–5, dosya analizi %5–85, proje geneli adımlar
(yetki envanteri, lisans, tehdit modeli, alt projeler) %85–97, kayıt %97–100. Dosya aşamasında bildirim
kısıtlanır (en çok ~4/sn); aşama değişimi her zaman iletilir.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import time
from typing import Any, Callable

# aşama → (başlangıç yüzdesi, bitiş yüzdesi, Türkçe etiket)
STAGES: dict[str, tuple[float, float, str]] = {
    "queued": (0.0, 0.0, "Sırada bekliyor"),
    "start": (0.0, 1.0, "Başlatılıyor"),
    "walk": (1.0, 5.0, "Dosyalar listeleniyor"),
    "files": (5.0, 85.0, "Dosyalar analiz ediliyor"),
    "routes": (85.0, 88.0, "Rota yetki envanteri"),
    "licenses": (88.0, 91.0, "Lisans uyumu"),
    "threat": (91.0, 94.0, "Tehdit modeli"),
    "subprojects": (94.0, 97.0, "Alt projeler"),
    "saving": (97.0, 99.0, "Sonuç kaydediliyor"),
    "done": (100.0, 100.0, "Tamamlandı"),
}
MIN_INTERVAL = 0.25

_REPORTER: contextvars.ContextVar[Callable[[dict[str, Any]], None] | None] = contextvars.ContextVar(
    "sniper_project_progress", default=None)
_STATE: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("sniper_project_progress_state", default=None)


def percent(stage: str, done: int | None = None, total: int | None = None) -> float:
    start, end, _label = STAGES.get(stage, (0.0, 0.0, ""))
    if total and done is not None and total > 0:
        return round(start + (end - start) * min(1.0, max(0.0, done / total)), 1)
    return start


def snapshot(stage: str, done: int | None = None, total: int | None = None, detail: str = "") -> dict[str, Any]:
    data: dict[str, Any] = {"stage": stage, "label": STAGES.get(stage, (0, 0, stage))[2],
                            "percent": percent(stage, done, total)}
    if total is not None:
        data["done"] = int(done or 0)
        data["total"] = int(total)
    if detail:
        data["detail"] = str(detail)[:200]
    return data


def active() -> bool:
    return _REPORTER.get() is not None


def report(stage: str, done: int | None = None, total: int | None = None, detail: str = "", *, force: bool = False) -> None:
    """İlerlemeyi bildir. Aynı aşama içindeki sık çağrılar kısıtlanır; hata analizi asla durdurmaz."""
    reporter = _REPORTER.get()
    if reporter is None:
        return
    state = _STATE.get()
    now = time.monotonic()
    if state is not None and not force and state.get("stage") == stage and now - state.get("at", 0.0) < MIN_INTERVAL \
            and not (total and done is not None and done >= total):
        return
    if state is not None:
        state["stage"], state["at"] = stage, now
    try:
        reporter(snapshot(stage, done, total, detail))
    except Exception:  # noqa: BLE001 - ilerleme bildirimi analizi etkilemez
        pass


@contextlib.contextmanager
def reporting(callback: Callable[[dict[str, Any]], None]):
    """Bu bağlamda yapılan ``report`` çağrılarını ``callback``'e iletir."""
    token = _REPORTER.set(callback)
    state_token = _STATE.set({"stage": None, "at": 0.0})
    try:
        yield
    finally:
        _REPORTER.reset(token)
        _STATE.reset(state_token)


def fd_writer(fd: int) -> Callable[[dict[str, Any]], None]:
    """İş süreci tarafı: her ilerlemeyi borunun yazma ucuna tek satır JSON olarak yazar."""
    def write(data: dict[str, Any]) -> None:
        line = (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")
        if len(line) <= 4096:  # PIPE_BUF altında: satırlar bölünmeden yazılır
            os.write(fd, line)
    return write


def parse_line(raw: bytes) -> dict[str, Any] | None:
    """Ana süreç tarafı: borudan gelen satırı doğrula (yalnız bilinen alanlar, sınırlı boyut)."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("stage") not in STAGES:
        return None
    clean: dict[str, Any] = {"stage": data["stage"], "label": STAGES[data["stage"]][2]}
    value = data.get("percent")
    clean["percent"] = float(value) if isinstance(value, (int, float)) and 0 <= value <= 100 else percent(data["stage"])
    for key in ("done", "total"):
        if isinstance(data.get(key), int) and not isinstance(data.get(key), bool) and data[key] >= 0:
            clean[key] = data[key]
    if isinstance(data.get("detail"), str):
        clean["detail"] = data["detail"][:200]
    return clean
