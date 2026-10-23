#!/bin/sh
# Sniper pre-commit kancası ÖRNEĞİ (yalnız yerel; ağ kullanmaz).
# Kurulum: bu dosyayı projenizde .git/hooks/pre-commit olarak kopyalayıp çalıştırılabilir yapın.
# Kaydedilmemiş (sahnelenmiş + çalışma ağacı) değişiklikleri HEAD ile karşılaştırır; yüksek ve üstü
# YENİ bulgu varsa commit'i durdurur. Atlamak için: git commit --no-verify
set -eu
SNIPER_APP="${SNIPER_APP:-$HOME/.local/share/sniper/app}"
ROOT="$(git rev-parse --show-toplevel)"
# HEAD yoksa (ilk commit) taban olarak boş ağaç kullanılamaz; ilk commit'te tarama atlanır.
git rev-parse --verify --quiet HEAD >/dev/null || exit 0
exec python3 "$SNIPER_APP/cli_reports.py" auto-scan "$ROOT" \
  --changed-since HEAD --fail-on high --no-store
