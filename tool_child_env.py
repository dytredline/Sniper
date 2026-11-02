"""Dış tarama araçları için sır taşımayan, açıkça tanımlı alt süreç ortamı.

Servis ortamını kopyalamak; API anahtarları, bulut kimlik bilgileri, proxy URL'leri
ve Python/JVM enjeksiyon seçeneklerini güvenilmeyen girdiyi ayrıştıran üçüncü taraf
motorlara taşır. Bu yardımcı yalnız aracın çalışması için gereken sabit temel
değerleri ve çağıranın açıkça verdiği overrides alanlarını geçirir.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Mapping


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_BASE = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "NO_COLOR": "1",
    # Yerel/offline ve doğrudan soket kullanan araçlar ebeveyn proxy ayarlarını
    # miras almamalı; hedef kapsamı argüman/relay katmanında belirlenir.
    "HTTP_PROXY": "",
    "HTTPS_PROXY": "",
    "ALL_PROXY": "",
    "http_proxy": "",
    "https_proxy": "",
    "all_proxy": "",
    "NO_PROXY": "*",
    "no_proxy": "*",
}


def _text(value: str | os.PathLike[str], label: str) -> str:
    raw = os.fspath(value)
    if not raw or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ValueError(f"{label} güvenli bir ortam değeri değil")
    return raw


def isolated_tool_environment(
    *,
    home: str | os.PathLike[str],
    tmpdir: str | os.PathLike[str] | None = None,
    overrides: Mapping[str, str | os.PathLike[str]] | None = None,
) -> dict[str, str]:
    """Yeni bir araç ortamı üret; ebeveyn ``os.environ`` değerlerini kopyalama.

    ``overrides`` yalnız çağıranın araca gerçekten gereken HOME/cache/ürün
    anahtarlarını açıkça geçirmesi içindir. Tarama hedefi ve kapsam seçenekleri
    argv üzerinden aynen korunur.
    """

    clean = dict(_BASE)
    clean["HOME"] = _text(home, "HOME")
    clean["TMPDIR"] = _text(tmpdir if tmpdir is not None else home, "TMPDIR")
    for name, value in (overrides or {}).items():
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise ValueError("geçersiz ortam değişkeni adı")
        clean[name] = _text(value, name)
    return clean
