#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if ! docker info >/dev/null 2>&1; then
  echo "Docker API erişimi yok. Yerel Docker kurulumunu ve mevcut kullanıcı erişimini doğrulayın." >&2
  exit 1
fi

if [[ ! -f .env ]] || ! grep -q '^GRAFANA_ADMIN_PASSWORD=' .env; then
  python3 -c "import pathlib, secrets; p = pathlib.Path('.env'); p.write_text('GRAFANA_ADMIN_PASSWORD=' + secrets.token_urlsafe(24) + '\n', encoding='utf-8'); p.chmod(0o600)"
fi

docker compose --profile monitoring up --detach --build
docker compose --profile monitoring ps

for _ in $(seq 1 30); do
  if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=2)" 2>/dev/null; then
    echo "Sniper: http://127.0.0.1:8787"
    echo "  Community sürümü: $(tr -d '\n\r' < COMMUNITY_VERSION)"
    echo "Grafana: http://127.0.0.1:3000 (user: admin; password: local .env file)"
    echo "Prometheus: http://127.0.0.1:9090"
    exit 0
  fi
  sleep 1
done

echo "Sniper health check did not become ready." >&2
docker compose --profile monitoring logs --tail=80 sniper >&2
exit 1
