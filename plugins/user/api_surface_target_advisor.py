"""Built-in trusted defensive plugin: API and management surface target path advisor."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from plugins.base_plugin import BasePlugin, PluginInfo

_SENSITIVE_SEGMENTS = frozenset({
    "api",
    "graphql",
    "v1",
    "v2",
    "v3",
    "swagger",
    "openapi",
    "admin",
    "actuator",
    "internal",
})


class ApiSurfaceTargetAdvisorPlugin(BasePlugin):
    """Advises schema, object-authorization, and rate-limit verification on API/management URL paths."""

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            "api-surface-target-advisor",
            "1.0.0",
            "Sniper Core",
            "Hedef URL yolunda API, GraphQL veya yönetim yüzeyi bulunduğunda şema ve oran sınırı denetim danışmanı",
        )

    def scan(self, target: str) -> list[dict[str, Any]]:
        raw = str(target or "").strip()
        if not raw:
            return []
        path = (urlsplit(raw).path or "/").lower()
        segments = [seg.strip() for seg in path.split("/") if seg.strip()]
        matched = [seg for seg in segments if seg in _SENSITIVE_SEGMENTS]
        if not matched:
            return []

        return [
            {
                "id": "plugin-api-surface-target-advisory",
                "severity": "info",
                "category": "api",
                "title": "Hedef yolda API veya yönetim yüzeyi tespit edildi",
                "description": (
                    "Hedef URL yolu doğrudan bir API, şema veya yönetim uç noktasına işaret ediyor; "
                    "bu yüzeylerde OpenAPI/GraphQL şema doğrulaması, BOLA/BFLA yetkilendirmesi ve "
                    "oran sınırlaması ayrıca doğrulanmalıdır."
                ),
                "evidence": f"Hedef yol: {path} (eşleşen segmentler: {', '.join(matched[:4])})",
                "recommendation": (
                    "Uç nokta için OpenAPI/GraphQL şema denetimini çalıştırın, kimlik doğrulama "
                    "zorunluluğunu ve istemci/IP bazlı oran sınırlarını doğrulayın."
                ),
                "reference": "OWASP WSTG-APIT-01",
                "owasp": "WSTG-APIT-01",
                "cwe": "CWE-200",
                "confidence": "medium",
            }
        ]


PLUGIN = ApiSurfaceTargetAdvisorPlugin()
