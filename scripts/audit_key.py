#!/usr/bin/env python3
"""Denetim günlüğü HMAC anahtarı yönetimi (anahtar baytları hiçbir zaman yazdırılmaz).

Kullanım:
  python3 scripts/audit_key.py init      # anahtar yoksa 0600/32 bayt oluşturur, çapa dizinini hazırlar
  python3 scripts/audit_key.py status    # anahtar durumu ve key_id parmak izi

Servis `ProtectHome=read-only` ile çalışıyorsa anahtarı servis değil bu komut oluşturmalı; servis
anahtarı yalnız okur, çapa dizini için ise systemd drop-in'inde `ReadWritePaths=` gerekir
(DEPLOYMENT.md).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit_integrity  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sniper denetim anahtarı yönetimi")
    parser.add_argument("command", choices=("init", "status"))
    args = parser.parse_args(argv)
    anchor_dir = audit_integrity.anchor_dir()
    if args.command == "init" and audit_integrity.load_key().status == "missing":
        signed = []
        for path in sorted(anchor_dir.glob("*.json")) if anchor_dir.is_dir() else []:
            try:
                if json.loads(path.read_text(encoding="utf-8")).get("key_id"):
                    signed.append(path.name)
            except (OSError, ValueError, AttributeError):
                continue
        if signed:
            print("Anahtar yok ama önceki bir anahtarla imzalanmış çapalar var; yeni anahtar üretmek eski "
                  "HMAC'li kayıtları doğrulanamaz kılar. Eski anahtarı geri yükleyin ya da bu çapaları "
                  f"bilinçli olarak arşivleyin: {', '.join(signed)}", file=sys.stderr)
            return 2
    state = audit_integrity.load_key(create=args.command == "init")
    anchor_ready = False
    if args.command == "init" and state.usable:
        anchor_ready = audit_integrity._ensure_private_dir(anchor_dir)
    else:
        anchor_ready = audit_integrity._dir_is_safe(anchor_dir)
    print(json.dumps({**state.public(), "anchor_dir": str(anchor_dir), "anchor_dir_ready": anchor_ready},
                     ensure_ascii=False, indent=2))
    return 0 if state.usable and anchor_ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
