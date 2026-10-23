"""Built-in trusted defensive plugin: Zero-Trust transport layer and subdomain isolation advisor."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from plugins.base_plugin import BasePlugin, PluginInfo


class ZeroTrustTransportAdvisorPlugin(BasePlugin):
    """Deterministic passive target URL inspection for Zero-Trust transport hardening."""

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            "zero-trust-transport-advisor",
            "1.0.0",
            "Sniper Core",
            "Sıfır güven taşıma katmanı ve alt alan adı izolasyon kontrolü",
        )

    def scan(self, target: str) -> list[dict[str, Any]]:
        raw = str(target or "").strip()
        if not raw:
            return []
        parsed = urlsplit(raw)
        scheme = (parsed.scheme or "https").lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        effective_port = port if port is not None else (80 if scheme == "http" else 443)

        if scheme == "https" and effective_port == 443:
            return []

        return [
            {
                "id": "plugin-zero-trust-transport-advisory",
                "severity": "low",
                "category": "transport",
                "title": "Sıfır güven taşıma katmanı standart dışı kanal kullanıyor",
                "description": (
                    "Hedef URL şifrelenmemiş HTTP şeması veya standart dışı (443 olmayan) bir taşıma "
                    "portu kullanıyor; bu durum HSTS ve alt alan adı izolasyon politikalarını zayıflatabilir."
                ),
                "evidence": f"Hedef: {raw} (scheme={scheme}, port={effective_port})",
                "recommendation": (
                    "Tüm dış servisleri yalnızca HTTPS (port 443) üzerinden yayımlayın ve "
                    "HSTS includeSubDomains politikasını doğrulayın."
                ),
                "reference": "OWASP WSTG-CRYP-01",
                "owasp": "WSTG-CRYP-01",
                "cwe": "CWE-319",
                "confidence": "high",
            }
        ]


PLUGIN = ZeroTrustTransportAdvisorPlugin()
