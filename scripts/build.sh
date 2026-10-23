#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if ! docker info >/dev/null 2>&1; then
  echo "Docker API erişimi yok. Yerel Docker kurulumunu ve mevcut kullanıcı erişimini doğrulayın." >&2
  exit 1
fi

VERSION=$(tr -d '\n\r' < COMMUNITY_VERSION)
echo "Building Sniper Community $VERSION..."

python3 .github/scripts/validate-community-release.py
python3 -m compileall -q core exporter plugins tests ./*.py
python3 -m unittest discover -s tests -v
GRAFANA_ADMIN_PASSWORD=validation-only docker compose --profile monitoring config --quiet
docker build --tag "sniper-community:${VERSION}" --build-arg VERSION="$VERSION" .

echo "Sniper Community $VERSION built and validated."
