"""Built-in trusted defensive plugin: IP-literal target SNI and virtual-host isolation advisor."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from plugins.base_plugin import BasePlugin, PluginInfo


class IpLiteralTargetAdvisorPlugin(BasePlugin):
    """Detects direct IP-literal targets where TLS SNI and origin concealment may be bypassed."""

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            "ip-literal-target-advisor",
            "1.0.0",
            "Sniper Core",
            "Doğrudan IP adresi hedefleri için SNI, TLS sertifika kapsamı ve sanal ana bilgisayar izolasyon danışmanı",
        )

    def scan(self, target: str) -> list[dict[str, Any]]:
        raw = str(target or "").strip()
        if not raw:
            return []
        hostname = (urlsplit(raw).hostname or "").strip()
        if not hostname:
            return []
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return []

        return [
            {
                "id": "plugin-ip-literal-target-advisory",
                "severity": "low",
                "category": "infrastructure",
                "title": "Doğrudan IP adresi üzerinden hedef erişimi",
                "description": (
                    "Hedef bir alan adı yerine doğrudan IP adresi ile tanımlanmış; doğrudan IP erişimi "
                    "TLS SNI yönlendirmesini, CDN/WAF korumasını ve sanal ana bilgisayar sınırlarını atlayabilir."
                ),
                "evidence": f"Hedef IP: {hostname} ({raw})",
                "recommendation": (
                    "Kaynak sunucuda doğrudan IP üzerinden gelen yetkisiz HTTP/HTTPS isteklerini "
                    "varsayılan sanal ana bilgisayarda reddedin ve sertifikaları alan adıyla sınırlandırın."
                ),
                "reference": "OWASP WSTG-INFR-03",
                "owasp": "WSTG-INFR-03",
                "cwe": "CWE-297",
                "confidence": "high",
            }
        ]


PLUGIN = IpLiteralTargetAdvisorPlugin()
