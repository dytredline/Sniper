#!/usr/bin/env python3
"""OSV çevrimdışı veritabanını resmi OSV deposundan elle güncelle.

Kullanım:
  python3 scripts/osv_refresh.py                       # yapılandırılmış tüm ekosistemler (varsayılan: npm, PyPI,
                                                       # Go, Maven, RubyGems, crates.io, Packagist, NuGet, Pub, Hex)
  python3 scripts/osv_refresh.py --ecosystem PyPI --ecosystem Go
  python3 scripts/osv_refresh.py --status              # mevcut manifest, yaş ve imza durumu
  python3 scripts/osv_refresh.py --print-dropin        # systemd drop-in satırlarını yazdır

Varsayılan hedef ``~/.local/state/sniper/osv-db`` (``--root`` ya da ``SNIPER_OSV_DB_ROOT``).
Manifest yerel denetim anahtarıyla (scripts/audit_key.py init) imzalanırsa Sniper yeni veriyi yeniden
başlatma gerekmeden kabul eder; anahtar yoksa çıktıdaki ``manifest_sha256`` systemd'deki
``SNIPER_OSV_DB_MANIFEST_SHA256`` değerine yazılıp servis yeniden başlatılmalıdır.
OSV-Scanner profili 7 günden eski veriyi reddeder; haftalık çalıştırın.

Ekosistem listesi (18. tur): ``SNIPER_OSV_ECOSYSTEMS=npm,PyPI`` ya da ``<kök>/ecosystems.json``
(``{"ecosystems": ["npm", "PyPI"]}``); ikisi de yoksa varsayılan liste. Bir ekosistem başarısız olsa da
diğerleri güncellenir (çıkış kodu 1 olur).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import osv_db_refresh  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sniper OSV çevrimdışı veritabanı güncellemesi")
    parser.add_argument("--ecosystem", action="append",
                        help="OSV ekosistemi; tekrarlanabilir (varsayılan: yapılandırılmış liste)")
    parser.add_argument("--root", type=Path, help="Hedef dizin (varsayılan ~/.local/state/sniper/osv-db)")
    parser.add_argument("--max-bytes", type=int, default=None,
                        help="İndirme sınırı (bayt); verilmezse ekosisteme göre varsayılan")
    parser.add_argument("--status", action="store_true", help="İndirmeden mevcut durumu göster")
    parser.add_argument("--print-dropin", action="store_true", help="npm manifesti için systemd drop-in satırları")
    args = parser.parse_args(argv)
    root = args.root or osv_db_refresh.default_root()
    ecosystems = args.ecosystem or (osv_db_refresh.known_ecosystems(root) if args.status
                                    else osv_db_refresh.configured_ecosystems(root))

    if args.print_dropin:
        path = osv_db_refresh.manifest_path(root, "npm")
        print("[Service]")
        print(f"Environment=SNIPER_OSV_DB_MANIFEST={path}")
        print("# İmzalı manifestte SHA-256 pini isteğe bağlıdır; imzasız kullanımda --status çıktısındaki")
        print("# manifest_sha256 değerini SNIPER_OSV_DB_MANIFEST_SHA256= olarak ekleyin.")
        return 0

    exit_code = 0
    results = []
    for ecosystem in ecosystems:
        try:
            if args.status:
                results.append(osv_db_refresh.status(ecosystem, root=root))
            else:
                print(f"{ecosystem}: indiriliyor ve doğrulanıyor…", file=sys.stderr, flush=True)
                results.append(osv_db_refresh.refresh(ecosystem, root=root, max_bytes=args.max_bytes))
        except osv_db_refresh.OSVRefreshError as exc:
            exit_code = 1
            results.append({"status": "failed", "ecosystem": ecosystem, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - bir ekosistemin beklenmeyen hatası diğerlerini durdurmaz
            exit_code = 1
            results.append({"status": "failed", "ecosystem": ecosystem, "error": type(exc).__name__})
    print(json.dumps(results, ensure_ascii=False, indent=2))
    for result in results:
        if result.get("status") == "updated" and not result.get("manifest_signed"):
            print("Uyarı: manifest imzasız (denetim anahtarı yok). Sniper'ın kabul etmesi için "
                  "SNIPER_OSV_DB_MANIFEST_SHA256 değerini güncelleyip servisi yeniden başlatın.", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
