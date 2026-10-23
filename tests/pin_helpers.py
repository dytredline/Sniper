"""Testlerde sahte araç ikililerini operatör SHA-256 sabitlemesiyle kabul ettirir.

Üretimde sabitlenmemiş ikili çalıştırılmaz; testler sahte betiği yazdıktan sonra
``pin_test_binary`` ile o anki içeriğin SHA-256'sını ``SNIPER_<ARAÇ>_SHA256``
ortam değişkenine koyar. Değişken test sonunda eski değerine döner.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from tool_pins import PINS


def sha256_of(path: str | os.PathLike[str]) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pin_env(tool: str, path: str | os.PathLike[str]) -> dict[str, str]:
    return {PINS[tool].env_sha256: sha256_of(path)}


def pin_test_binary(case, tool: str, path: str | os.PathLike[str]) -> None:
    name = PINS[tool].env_sha256
    old = os.environ.get(name)
    os.environ[name] = sha256_of(path)

    def restore() -> None:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old

    case.addCleanup(restore)
