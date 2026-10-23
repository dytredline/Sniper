#!/bin/sh
# Sniper pre-commit kancası (çevrimdışı): yalnız hazırlanmış değişikliklerin getirdiği yeni bulgularda durdurur.
# Kurulum: cp pre-commit-sniper-gate.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Politika: depo kökünde .sniper-policy.json ("new_only": true önerilir).
set -eu
SNIPER_APP="${SNIPER_APP:-$HOME/.local/share/sniper/app}"
ROOT="$(git rev-parse --show-toplevel)"
python3 "$SNIPER_APP/cli_reports.py" ci "$ROOT" --baseline-ref HEAD --no-sca
# Çıkış kodu 1 (politika ihlali) commit'i durdurur; acil durumda: git commit --no-verify
