"""Built-in trusted defensive plugin: Cross-Origin Isolation (COOP/COEP/CORP) target context advisor."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from plugins.base_plugin import BasePlugin, PluginInfo


class CrossOriginIsolationAdvisorPlugin(BasePlugin):
    """Inspects target URL scheme and port for cross-origin isolation context requirements."""

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            "cross-origin-isolation-advisor",
            "1.0.0",
            "Sniper Core",
            "Hedef URL şeması ve çapraz köken izolasyon (COOP/COEP/CORP) mimari denetim danışmanı",
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

        severity = "low" if scheme == "http" else "info"
        return [
            {
                "id": "plugin-coop-coep-scheme-advisory",
                "severity": severity,
                "category": "headers",
                "title": "Çapraz köken izolasyonu (COOP/COEP) güvenli bağlam gerektiriyor",
                "description": (
                    "Cross-Origin-Opener-Policy ve Cross-Origin-Embedder-Policy tarayıcı izolasyon "
                    "garantileri yalnızca güvenli (HTTPS / standart güvenilir köken) bağlamlarda etkinleşir."
                ),
                "evidence": f"Hedef: {raw} (scheme={scheme}, port={effective_port})",
                "recommendation": (
                    "Hedefi standart HTTPS (port 443) üzerinden sunun ve COOP: same-origin, "
                    "COEP: require-corp, CORP: same-origin başlıklarını etkinleştirin."
                ),
                "reference": "OWASP WSTG-CONF-07",
                "owasp": "WSTG-CONF-07",
                "cwe": "CWE-346",
                "confidence": "high",
            }
        ]


PLUGIN = CrossOriginIsolationAdvisorPlugin()
