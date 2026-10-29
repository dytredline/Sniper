from __future__ import annotations

import hashlib
import json
from typing import Any


CATEGORY_ALIASES: dict[str, set[str]] = {
    "information": {"information", "disclosure"},
    "configuration": {
        "configuration",
        "headers",
        "cors",
        "docker",
        "kubernetes",
        "iac",
        "ci_cd",
        "container",
        "web_hardening",
        "cloud_iam",
        "host_cis",
        "zero_trust",
        "desktop_security",
    },
    "headers": {"headers", "configuration", "client", "web_hardening"},
    "cors": {"cors", "configuration", "client", "api"},
    "container": {"container", "docker", "kubernetes", "infrastructure", "configuration"},
    "web_hardening": {"web_hardening", "configuration", "headers", "client", "server"},
    "identity": {"identity", "auth", "authentication", "cloud_iam", "zero_trust"},
    "auth": {"auth", "identity", "authentication", "mobile_auth", "cloud_iam", "zero_trust"},
    "authentication": {"authentication", "auth", "identity", "mobile_auth", "cloud_iam", "zero_trust"},
    "authz": {"authz", "authorization", "database_rls", "cloud_iam", "zero_trust"},
    "authorization": {"authorization", "authz", "database_rls", "cloud_iam", "zero_trust"},
    "session": {"session", "auth"},
    "input": {"input", "code", "command_data", "data_query", "ai_llm", "iot_firmware"},
    "command_data": {"command_data", "input", "server", "code", "ai_llm", "iot_firmware"},
    "data_query": {"data_query", "input", "server", "code", "database_rls"},
    "ssrf": {"ssrf", "server", "api", "input"},
    "server": {"server", "code", "command_data", "data_query", "ssrf", "ai_llm"},
    "errors": {"errors", "logging"},
    "crypto": {"crypto", "cryptography", "transport", "secrets", "mobile_crypto", "zero_trust"},
    "transport": {"transport", "crypto", "cryptography", "mobile_network", "zero_trust"},
    "secrets": {"secrets", "data", "crypto", "data_protection", "mobile_crypto", "ai_llm"},
    "privacy": {"privacy", "data", "data_protection", "mobile_privacy", "ai_llm"},
    "data": {"data", "data_protection", "privacy", "secrets", "mobile_storage", "mobile_privacy", "database_rls", "ai_llm"},
    "business": {"business", "web3"},
    "client": {"client", "headers", "cors", "browser_extension", "desktop_security"},
    "api": {"api", "ssrf", "cors"},
    "infrastructure": {"infrastructure", "docker", "kubernetes", "iac", "container", "cloud_iam", "host_cis", "zero_trust"},
    "components": {"components", "supplychain", "supply_chain", "dependencies", "license", "ai_llm"},
    "supplychain": {"supplychain", "supply_chain", "dependencies", "ci_cd", "components", "ai_llm"},
    "availability": {"availability", "dos_resilience"},
    "logging": {"logging", "errors"},
    "controlled": {"controlled"},
    "ai_llm": {"ai_llm", "input", "command_data", "data", "privacy", "secrets", "supplychain", "components"},
    "database_rls": {"database_rls", "authorization", "authz", "data", "data_query"},
    "cloud_iam": {"cloud_iam", "authorization", "authz", "identity", "auth", "authentication", "infrastructure", "configuration"},
    "zero_trust": {"zero_trust", "transport", "crypto", "authentication", "authorization", "infrastructure", "configuration"},
    "browser_extension": {"browser_extension", "client", "configuration", "privacy", "data"},
    "desktop_security": {"desktop_security", "client", "configuration", "command_data"},
    "web3": {"web3", "business", "crypto", "authorization"},
    "iot_firmware": {"iot_firmware", "command_data", "input", "crypto", "configuration"},
    "host_cis": {"host_cis", "configuration", "infrastructure", "authorization"},
    "dos_resilience": {"dos_resilience", "availability", "configuration"},
    "mobile_auth": {"mobile_auth", "auth", "authentication", "mobile_security"},
    "mobile_crypto": {"mobile_crypto", "crypto", "cryptography", "secrets", "mobile_security"},
    "mobile_storage": {"mobile_storage", "data", "data_protection", "mobile_security"},
    "mobile_privacy": {"mobile_privacy", "privacy", "data", "mobile_security"},
    "mobile_network": {"mobile_network", "transport", "crypto", "infrastructure", "mobile_security"},
    "mobile_resilience": {"mobile_resilience", "configuration", "business", "mobile_security"},
    "mobile_security": {
        "mobile_security",
        "mobile",
        "configuration",
        "session",
        "authentication",
        "cryptography",
        "data_protection",
        "client",
        "supply_chain",
        "crypto",
        "data",
        "supplychain",
        "mobile_auth",
        "mobile_crypto",
        "mobile_storage",
        "mobile_privacy",
        "mobile_network",
        "mobile_resilience",
    },
}

_CATEGORY_ALIASES = CATEGORY_ALIASES


FRAMEWORK_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "OWASP-TOP10-2021",
        "name": "OWASP Top 10 (2021)",
        "version": "2021",
        "requirements": (
            {
                "id": "A01:2021",
                "title": "Bozuk Erişim Kontrolü (Broken Access Control)",
                "categories": ("authorization", "authz", "cors", "client"),
                "cwes": ("CWE-862", "CWE-639", "CWE-942", "CWE-285", "CWE-22", "CWE-284", "CWE-863", "CWE-915"),
            },
            {
                "id": "A02:2021",
                "title": "Kriptografik Hatalar (Cryptographic Failures)",
                "categories": ("crypto", "transport", "data", "secrets", "mobile_crypto"),
                "cwes": ("CWE-319", "CWE-320", "CWE-326", "CWE-327", "CWE-798", "CWE-295", "CWE-328", "CWE-330", "CWE-338"),
            },
            {
                "id": "A03:2021",
                "title": "Enjeksiyon (Injection)",
                "categories": ("input", "server", "command_data", "data_query"),
                "cwes": ("CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-77", "CWE-90", "CWE-95", "CWE-113", "CWE-134", "CWE-643", "CWE-917", "CWE-943", "CWE-1336"),
            },
            {
                "id": "A04:2021",
                "title": "Güvensiz Tasarım (Insecure Design)",
                "categories": ("business", "controlled", "privacy"),
                "cwes": ("CWE-200", "CWE-602"),
            },
            {
                "id": "A05:2021",
                "title": "Güvenlik Yanlış Yapılandırması (Security Misconfiguration)",
                "categories": ("configuration", "headers", "infrastructure", "container", "web_hardening"),
                "cwes": ("CWE-16", "CWE-693", "CWE-250", "CWE-489", "CWE-611", "CWE-732", "CWE-1021"),
            },
            {
                "id": "A06:2021",
                "title": "Savunmasız ve Güncel Olmayan Bileşenler (Vulnerable and Outdated Components)",
                "categories": ("supplychain", "components"),
                "cwes": ("CWE-1104", "CWE-1395", "CWE-506"),
            },
            {
                "id": "A07:2021",
                "title": "Kimlik Doğrulama Hataları (Identification and Authentication Failures)",
                "categories": ("identity", "authentication", "auth", "session", "mobile_auth"),
                "cwes": ("CWE-287", "CWE-523", "CWE-614", "CWE-384", "CWE-306", "CWE-307", "CWE-347", "CWE-798"),
            },
            {
                "id": "A08:2021",
                "title": "Yazılım ve Veri Bütünlüğü Hataları (Software and Data Integrity Failures)",
                "categories": ("supplychain", "components"),
                "cwes": ("CWE-829", "CWE-502", "CWE-347", "CWE-353", "CWE-494", "CWE-506"),
            },
            {
                "id": "A09:2021",
                "title": "Güvenlik Günlükleme ve İzleme Hataları (Security Logging and Monitoring Failures)",
                "categories": ("logging", "errors"),
                "cwes": ("CWE-209", "CWE-532", "CWE-778", "CWE-117"),
            },
            {
                "id": "A10:2021",
                "title": "Sunucu Taraflı İstek Sahteciliği (Server-Side Request Forgery - SSRF)",
                "categories": ("ssrf", "server", "api"),
                "cwes": ("CWE-918",),
            },
        ),
    },
    {
        "id": "OWASP-ASVS-4.0.3",
        "name": "OWASP ASVS v4.0.3",
        "version": "4.0.3",
        "requirements": (
            {
                "id": "V1",
                "title": "Mimari, Tasarım ve Tehdit Modelleme",
                "categories": ("information", "business", "controlled"),
                "cwes": ("CWE-200",),
            },
            {
                "id": "V2",
                "title": "Kimlik Doğrulama Doğrulama Gereksinimleri",
                "categories": ("identity", "authentication", "auth"),
                "cwes": ("CWE-523", "CWE-598", "CWE-287"),
            },
            {
                "id": "V3",
                "title": "Oturum Yönetimi Doğrulama Gereksinimleri",
                "categories": ("session",),
                "cwes": ("CWE-614", "CWE-384"),
            },
            {
                "id": "V4",
                "title": "Erişim Kontrolü Doğrulama Gereksinimleri",
                "categories": ("authorization", "authz"),
                "cwes": ("CWE-862", "CWE-639"),
            },
            {
                "id": "V5",
                "title": "Doğrulama, Temizleme ve Kodlama",
                "categories": ("input", "server", "client", "command_data", "data_query"),
                "cwes": ("CWE-79", "CWE-89", "CWE-78"),
            },
            {
                "id": "V6",
                "title": "Saklanan Kriptografi ve Anahtar Yönetimi",
                "categories": ("crypto", "secrets"),
                "cwes": ("CWE-320", "CWE-327"),
            },
            {
                "id": "V7",
                "title": "Hata İşleme ve Günlükleme",
                "categories": ("errors", "logging"),
                "cwes": ("CWE-209", "CWE-778"),
            },
            {
                "id": "V8",
                "title": "Veri Koruma ve Sır/Mahremiyet Hijyeni",
                "categories": ("data", "privacy", "secrets"),
                "cwes": ("CWE-200", "CWE-798"),
            },
            {
                "id": "V9",
                "title": "İletişim ve TLS Güvenliği",
                "categories": ("crypto", "transport", "infrastructure"),
                "cwes": ("CWE-319", "CWE-295"),
            },
            {
                "id": "V13",
                "title": "API ve Web Servisleri Doğrulama Gereksinimleri",
                "categories": ("api", "availability", "ssrf"),
                "cwes": ("CWE-942", "CWE-770"),
            },
            {
                "id": "V14",
                "title": "Yapılandırma ve Tedarik Zinciri Doğrulama Gereksinimleri",
                "categories": ("configuration", "supplychain", "components", "headers"),
                "cwes": ("CWE-693", "CWE-829"),
            },
        ),
    },
    {
        "id": "PCI-DSS-4.0",
        "name": "PCI-DSS v4.0",
        "version": "4.0",
        "requirements": (
            {
                "id": "Req 4.2.1",
                "title": "Güçlü Kriptografi ve Aktarım Katmanı (TLS) Güvenliği",
                "categories": ("crypto", "transport"),
                "cwes": ("CWE-319", "CWE-320", "CWE-326", "CWE-327"),
            },
            {
                "id": "Req 6.2.4",
                "title": "Güvenli Kodlama, Enjeksiyon ve Sunucu/İstemci Girdi Koruması",
                "categories": ("input", "server", "client", "business", "command_data", "data_query"),
                "cwes": ("CWE-79", "CWE-89", "CWE-78", "CWE-918", "CWE-693"),
            },
            {
                "id": "Req 6.3.1/6.3.2",
                "title": "SBOM, Bağımlılık Envanteri ve Tedarik Zinciri Zafiyet Yönetimi",
                "categories": ("supplychain", "components"),
                "cwes": ("CWE-829", "CWE-1104", "CWE-1395"),
            },
            {
                "id": "Req 6.4.1",
                "title": "Halka Açık Web Uygulamaları ve API Koruması",
                "categories": ("api", "configuration", "availability", "headers", "cors"),
                "cwes": ("CWE-942", "CWE-16", "CWE-200"),
            },
            {
                "id": "Req 8.3.1",
                "title": "Kimlik Yönetimi, Kimlik Doğrulama, Yetkilendirme ve Oturum Güvenliği",
                "categories": ("identity", "authentication", "authorization", "session", "auth", "authz"),
                "cwes": ("CWE-287", "CWE-523", "CWE-614", "CWE-862"),
            },
            {
                "id": "Req 10.2.1",
                "title": "Denetim İzi, Hata İşleme ve Güvenlik Günlükleme",
                "categories": ("logging", "errors"),
                "cwes": ("CWE-209", "CWE-778", "CWE-532"),
            },
            {
                "id": "Req 11.3.1",
                "title": "Altyapı, Keşif Yüzeyi ve Kontrollü Güvenlik Doğrulaması",
                "categories": ("information", "infrastructure", "data", "controlled", "container"),
                "cwes": ("CWE-200", "CWE-798"),
            },
        ),
    },
    {
        "id": "ISO-27001-2022",
        "name": "ISO/IEC 27001:2022",
        "version": "2022",
        "requirements": (
            {
                "id": "A.8.9",
                "title": "Yapılandırma Yönetimi ve Güvenlik Başlıkları",
                "categories": ("configuration", "information", "headers"),
                "cwes": ("CWE-16", "CWE-693"),
            },
            {
                "id": "A.8.15",
                "title": "Günlükleme, İzleme ve Hata Sızıntısının Önlenmesi",
                "categories": ("logging", "errors"),
                "cwes": ("CWE-209", "CWE-778"),
            },
            {
                "id": "A.8.20",
                "title": "Ağ, Konteyner ve Bulut Altyapısı Güvenliği",
                "categories": ("infrastructure", "availability", "container"),
                "cwes": ("CWE-16", "CWE-250"),
            },
            {
                "id": "A.8.21",
                "title": "Ağ ve API Servislerinin Güvenliği",
                "categories": ("api", "client", "cors"),
                "cwes": ("CWE-942", "CWE-285"),
            },
            {
                "id": "A.8.24",
                "title": "Kriptografi Kullanımı ve Anahtar/Sır Korunması",
                "categories": ("crypto", "data", "secrets", "transport"),
                "cwes": ("CWE-319", "CWE-320", "CWE-798"),
            },
            {
                "id": "A.8.25",
                "title": "Güvenli Geliştirme Yaşam Döngüsü ve Tedarik Zinciri",
                "categories": ("supplychain", "controlled", "components"),
                "cwes": ("CWE-829", "CWE-1395"),
            },
            {
                "id": "A.8.26",
                "title": "Uygulama Kimlik Doğrulama, Yetkilendirme ve Oturum Gereksinimleri",
                "categories": ("identity", "authentication", "authorization", "session", "business", "auth", "authz"),
                "cwes": ("CWE-523", "CWE-614", "CWE-862"),
            },
            {
                "id": "A.8.28",
                "title": "Güvenli Kodlama ve Sunucu/Girdi Doğrulama",
                "categories": ("input", "server", "command_data", "data_query", "ssrf"),
                "cwes": ("CWE-79", "CWE-89", "CWE-918"),
            },
        ),
    },
    {
        "id": "OWASP-MASVS-2.1.0",
        "name": "OWASP MASVS v2.1.0 & Mobile Top 10 (2024)",
        "version": "2.1.0",
        "requirements": (
            {
                "id": "MASVS-STORAGE-1",
                "title": "Hassas verilerin güvenli yerel depolanması (M9)",
                "categories": ("data", "data_protection", "mobile_storage", "mobile_security"),
                "cwes": ("CWE-312", "CWE-530", "CWE-532"),
            },
            {
                "id": "MASVS-CRYPTO-1",
                "title": "Güçlü kriptografi ve gömülü sırların önlenmesi (M1/M10)",
                "categories": ("crypto", "cryptography", "mobile_crypto", "mobile_security"),
                "cwes": ("CWE-798", "CWE-327", "CWE-338"),
            },
            {
                "id": "MASVS-AUTH-1",
                "title": "Güvenli kimlik doğrulama ve kriptografik biyometri (M3)",
                "categories": ("authentication", "session", "mobile_auth", "mobile_security"),
                "cwes": ("CWE-287", "CWE-347", "CWE-602"),
            },
            {
                "id": "MASVS-NETWORK-1",
                "title": "Şifreli iletişim, ATS/Cleartext yasağı ve SSL Pinning (M5)",
                "categories": ("crypto", "transport", "infrastructure", "mobile_network", "mobile_security"),
                "cwes": ("CWE-319", "CWE-295"),
            },
            {
                "id": "MASVS-PLATFORM-1",
                "title": "IPC, Deep Link, WebView ve ekran izolasyonu (M4/M8)",
                "categories": ("client", "configuration", "mobile_security"),
                "cwes": ("CWE-749", "CWE-939", "CWE-200", "CWE-1021"),
            },
            {
                "id": "MASVS-CODE-1",
                "title": "Mobil tedarik zinciri, SDK güvenliği ve asgari izin (M2)",
                "categories": ("supplychain", "supply_chain", "components", "mobile_security"),
                "cwes": ("CWE-250", "CWE-1104"),
            },
            {
                "id": "MASVS-RESILIENCE-1",
                "title": "Tersine mühendislik direnci, debuggable/R8 ve IAP bütünlüğü (M7)",
                "categories": ("configuration", "business", "mobile_resilience", "mobile_security"),
                "cwes": ("CWE-489", "CWE-693", "CWE-602"),
            },
            {
                "id": "MASVS-PRIVACY-1",
                "title": "Cihaz tanımlayıcıları, BLE ve kullanıcı gizliliği (M6)",
                "categories": ("data", "privacy", "mobile_privacy", "mobile_security"),
                "cwes": ("CWE-200", "CWE-359"),
            },
        ),
    },
    {
        "id": "KVKK-TEKNIK",
        "name": "KVKK Kişisel Verileri Koruma Kurumu — Veri Güvenliği Teknik Tedbirler Rehberi",
        "version": "2024",
        "requirements": (
            {
                "id": "KVKK-T01",
                "title": "Yetki Matrisi, Yetki Kontrolü ve Erişim Yönetimi",
                "categories": ("auth", "authz", "session", "mobile_auth", "identity", "authentication", "authorization"),
                "cwes": ("CWE-287", "CWE-523", "CWE-614", "CWE-862"),
            },
            {
                "id": "KVKK-T02",
                "title": "Erişim Logları ve Kullanıcı Hareketlerinin Kayıt Altına Alınması",
                "categories": ("logging", "errors"),
                "cwes": ("CWE-209", "CWE-532", "CWE-778"),
            },
            {
                "id": "KVKK-T03",
                "title": "Şifreleme, Kriptografik Anahtar Yönetimi ve Aktarım Güvenliği",
                "categories": ("crypto", "transport", "secrets", "mobile_crypto"),
                "cwes": ("CWE-319", "CWE-320", "CWE-326", "CWE-327", "CWE-798"),
            },
            {
                "id": "KVKK-T04",
                "title": "Sızma Testi, Zafiyet Taraması ve Uygulama Güvenliği Doğrulaması",
                "categories": ("command_data", "data_query", "ssrf", "components", "web_hardening", "input", "server"),
                "cwes": ("CWE-79", "CWE-89", "CWE-78", "CWE-918"),
            },
            {
                "id": "KVKK-T05",
                "title": "Veri Maskeleme, Veri Kaybı Önleme (DLP) ve Yedekleme Güvenliği",
                "categories": ("privacy", "data", "mobile_storage", "mobile_privacy"),
                "cwes": ("CWE-200", "CWE-312", "CWE-359", "CWE-530"),
            },
            {
                "id": "KVKK-T06",
                "title": "Ağ Güvenliği, Güvenlik Duvarı ve Bulut/Konteyner İzolasyonu",
                "categories": ("headers", "cors", "container", "supplychain", "infrastructure", "mobile_network", "configuration"),
                "cwes": ("CWE-16", "CWE-250", "CWE-693", "CWE-942"),
            },
        ),
    },
    {
        "id": "GDPR-EU",
        "name": "EU GDPR — Article 25 & Article 32 Data Protection & Security of Processing",
        "version": "2016/679",
        "requirements": (
            {
                "id": "GDPR-ART25",
                "title": "Data Protection by Design and by Default (Tasarımdan İtibaren Veri Koruma)",
                "categories": ("privacy", "headers", "mobile_privacy", "data", "configuration"),
                "cwes": ("CWE-200", "CWE-359", "CWE-693"),
            },
            {
                "id": "GDPR-ART32-1A",
                "title": "Pseudonymisation and Encryption of Personal Data (Şifreleme ve Maskeleme)",
                "categories": ("crypto", "transport", "secrets", "mobile_crypto", "mobile_storage", "data"),
                "cwes": ("CWE-312", "CWE-319", "CWE-327", "CWE-798"),
            },
            {
                "id": "GDPR-ART32-1B",
                "title": "Ongoing Confidentiality, Integrity, Availability and Resilience (Gizlilik ve Bütünlük)",
                "categories": ("auth", "authz", "session", "cors", "container", "infrastructure", "authentication", "authorization"),
                "cwes": ("CWE-287", "CWE-614", "CWE-862", "CWE-942"),
            },
            {
                "id": "GDPR-ART32-1D",
                "title": "Regular Testing, Assessing and Evaluating Effectiveness (Düzenli Güvenlik Testi)",
                "categories": ("command_data", "data_query", "ssrf", "components", "supplychain", "input", "server"),
                "cwes": ("CWE-79", "CWE-89", "CWE-918", "CWE-1104"),
            },
            {
                "id": "GDPR-ART33",
                "title": "Personal Data Breach Notification & Audit Trail Readiness (İhlal Tespiti ve İzlenebilirlik)",
                "categories": ("logging", "errors"),
                "cwes": ("CWE-209", "CWE-532", "CWE-778"),
            },
        ),
    },
    {
        "id": "EU-DORA",
        "name": "EU DORA — Digital Operational Resilience Act 2022/2554",
        "version": "2022/2554",
        "requirements": (
            {
                "id": "DORA-ART9",
                "title": "Protection and Prevention — ICT Systems, Protocols and Tools Security",
                "categories": ("auth", "session", "crypto", "transport", "headers", "container", "authentication", "configuration"),
                "cwes": ("CWE-16", "CWE-287", "CWE-319", "CWE-693"),
            },
            {
                "id": "DORA-ART10",
                "title": "Detection — Anomalous Activities and ICT Incident Monitoring",
                "categories": ("logging", "errors"),
                "cwes": ("CWE-209", "CWE-778"),
            },
            {
                "id": "DORA-ART24",
                "title": "General Requirements for Threat-Led Penetration Testing (TLPT) & Application Testing",
                "categories": ("command_data", "data_query", "ssrf", "web_hardening", "mobile_resilience", "input", "server"),
                "cwes": ("CWE-79", "CWE-89", "CWE-918", "CWE-489"),
            },
            {
                "id": "DORA-ART28",
                "title": "General Principles for Sound Management of ICT Third-Party Risk (Supply Chain)",
                "categories": ("components", "supplychain"),
                "cwes": ("CWE-829", "CWE-1104", "CWE-1395"),
            },
        ),
    },
    {
        "id": "EU-NIS2",
        "name": "EU NIS2 Directive — Directive 2022/2555 Article 21",
        "version": "2022/2555",
        "requirements": (
            {
                "id": "NIS2-21-2A",
                "title": "Policies on Risk Analysis and Information System Security",
                "categories": ("headers", "cors", "container", "infrastructure", "configuration"),
                "cwes": ("CWE-16", "CWE-250", "CWE-693", "CWE-942"),
            },
            {
                "id": "NIS2-21-2D",
                "title": "Supply Chain Security Including Security-Related Aspects Concerning Suppliers",
                "categories": ("components", "supplychain"),
                "cwes": ("CWE-829", "CWE-1104", "CWE-1395"),
            },
            {
                "id": "NIS2-21-2E",
                "title": "Security in Network and Information Systems Acquisition, Development and Maintenance",
                "categories": ("command_data", "data_query", "ssrf", "web_hardening", "input", "server"),
                "cwes": ("CWE-79", "CWE-89", "CWE-78", "CWE-918"),
            },
            {
                "id": "NIS2-21-2H",
                "title": "Policies and Procedures Regarding the Use of Cryptography and Encryption",
                "categories": ("crypto", "transport", "secrets", "mobile_crypto", "data"),
                "cwes": ("CWE-319", "CWE-320", "CWE-327", "CWE-798"),
            },
            {
                "id": "NIS2-21-2J",
                "title": "Use of Multi-Factor Authentication, Continuous Authentication and Secured Communications",
                "categories": ("auth", "session", "mobile_auth", "mobile_network", "authentication"),
                "cwes": ("CWE-287", "CWE-319", "CWE-523", "CWE-614"),
            },
        ),
    },
)

_CLAUSE_INDEX: dict[str, dict[str, Any]] = {
    req["id"]: {
        **req,
        "framework_id": fw["id"],
        "framework_name": fw["name"],
    }
    for fw in FRAMEWORK_DEFINITIONS
    for req in fw["requirements"]
}


def _is_false_positive(finding: dict[str, Any]) -> bool:
    triage = finding.get("triage")
    if isinstance(triage, dict) and str(triage.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(finding.get("disposition") or "").strip().lower() == "false_positive":
        return True
    if str(finding.get("status") or "").strip().lower() in {"resolved", "closed", "false_positive"}:
        return True
    tracking = finding.get("tracking")
    if isinstance(tracking, dict) and str(tracking.get("status") or "").strip().lower() in {"resolved", "closed", "false_positive"}:
        return True
    return False


def _expanded_categories(categories: tuple[str, ...]) -> set[str]:
    expanded: set[str] = set()
    for cat in categories:
        key = cat.lower()
        expanded.add(key)
        expanded.update(CATEGORY_ALIASES.get(key, set()))
        expanded.update(_CATEGORY_ALIASES.get(key, set()))
    return expanded


def _finding_cwes(finding: dict[str, Any]) -> set[str]:
    cwes: set[str] = set()
    for key in ("cwe", "cwe_id", "reference"):
        val = finding.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            cwes.add(f"CWE-{val}")
            continue
        raw = str(val or "").upper()
        if raw.strip().isdigit() and int(raw.strip()) > 0:
            cwes.add(f"CWE-{int(raw.strip())}")
            continue
        for token in (
            raw.replace(",", " ")
            .replace(";", " ")
            .replace("·", " ")
            .replace("/", " ")
            .replace("(", " ")
            .replace(")", " ")
            .split()
        ):
            if token.startswith("CWE-") and len(token) > 4:
                cwes.add(token)
    return cwes


def _finding_matches_requirement(
    finding: dict[str, Any],
    req: dict[str, Any],
    fw_id: str,
    cat_set: set[str],
    cwe_set: set[str],
) -> bool:
    req_id = str(req.get("id") or "").strip().upper()
    f_masvs = str(finding.get("masvs_id") or finding.get("masvs") or "").strip().upper()
    f_cat = str(finding.get("category") or "").strip().lower()
    f_cwes = _finding_cwes(finding)

    if fw_id == "OWASP-MASVS-2.1.0":
        if f_masvs:
            return req_id == f_masvs or req_id.startswith(f_masvs + "-") or f_masvs.startswith(req_id)
        if f_cwes:
            return bool(f_cwes & cwe_set)
        return f_cat in cat_set

    if f_cwes & cwe_set:
        return True
    if f_cat in {"mobile_security", "mobile"} and (f_cwes or f_masvs):
        masvs_cat_map = {
            "MASVS-STORAGE": "data",
            "MASVS-CRYPTO": "crypto",
            "MASVS-AUTH": "authentication",
            "MASVS-NETWORK": "crypto",
            "MASVS-PLATFORM": "client",
            "MASVS-CODE": "supplychain",
            "MASVS-RESILIENCE": "configuration",
            "MASVS-PRIVACY": "data",
        }
        mapped_cat = masvs_cat_map.get(f_masvs.split("-1")[0], "")
        if mapped_cat and mapped_cat in cat_set:
            return True
        return False
    return f_cat in cat_set


def _collect_open_findings(
    engagement: dict[str, Any] | None,
    project_audit: dict[str, Any] | None,
    scan: dict[str, Any] | None = None,
    dependency_report: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    if isinstance(engagement, dict):
        for list_key in ("findings",):
            raw = engagement.get(list_key)
            if isinstance(raw, list):
                collected.extend(f for f in raw if isinstance(f, dict) and not _is_false_positive(f))
        latest_scan = engagement.get("latest_scan")
        if isinstance(latest_scan, dict):
            scan_findings = latest_scan.get("findings")
            if isinstance(scan_findings, list):
                collected.extend(f for f in scan_findings if isinstance(f, dict) and not _is_false_positive(f))
    if isinstance(scan, dict):
        scan_findings = scan.get("findings")
        if isinstance(scan_findings, list):
            collected.extend(f for f in scan_findings if isinstance(f, dict) and not _is_false_positive(f))
    if isinstance(project_audit, dict):
        pa_findings = project_audit.get("findings")
        if isinstance(pa_findings, list):
            collected.extend(f for f in pa_findings if isinstance(f, dict) and not _is_false_positive(f))
    if isinstance(dependency_report, dict):
        dep_findings = dependency_report.get("findings") or dependency_report.get("vulnerabilities")
        if isinstance(dep_findings, list):
            for df in dep_findings:
                if isinstance(df, dict) and not _is_false_positive(df):
                    collected.append({**df, "category": df.get("category") or "supplychain"})
    if isinstance(mobile_audit, dict):
        ma_findings = mobile_audit.get("findings")
        if isinstance(ma_findings, list):
            collected.extend(f for f in ma_findings if isinstance(f, dict) and not _is_false_positive(f))
    return collected


def build_compliance_crosswalk(
    *,
    engagement: dict[str, Any] | None = None,
    project_audit: dict[str, Any] | None = None,
    scan: dict[str, Any] | None = None,
    dependency_report: dict[str, Any] | None = None,
    mobile_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tests: list[dict[str, Any]] = []
    has_scan_or_audit = False
    if isinstance(engagement, dict):
        raw_tests = engagement.get("tests")
        if isinstance(raw_tests, list):
            tests = [t for t in raw_tests if isinstance(t, dict)]
        if isinstance(engagement.get("latest_scan"), dict):
            has_scan_or_audit = True
    if isinstance(scan, dict) and scan:
        has_scan_or_audit = True
    if isinstance(project_audit, dict) and project_audit:
        has_scan_or_audit = True
    if isinstance(dependency_report, dict) and dependency_report:
        has_scan_or_audit = True
    if isinstance(mobile_audit, dict) and mobile_audit:
        has_scan_or_audit = True

    open_findings = _collect_open_findings(
        engagement,
        project_audit,
        scan=scan,
        dependency_report=dependency_report,
        mobile_audit=mobile_audit,
    )

    frameworks_list: list[dict[str, Any]] = []
    total_compliant = 0
    total_non_compliant = 0
    total_needs_review = 0
    total_not_assessed = 0

    for fw in FRAMEWORK_DEFINITIONS:
        fw_reqs: list[dict[str, Any]] = []
        fw_compliant = 0
        fw_non_compliant = 0
        fw_needs_review = 0
        fw_not_assessed = 0

        for req in fw["requirements"]:
            cat_set = _expanded_categories(req["categories"])
            test_cats = tuple(c for c in req["categories"] if not c.startswith("mobile_")) or req["categories"]
            test_cat_set = _expanded_categories(test_cats)
            cwe_set = {c.upper() for c in req.get("cwes", ())}

            matching_tests = [
                t for t in tests
                if str(t.get("category") or "").strip().lower() in test_cat_set
            ]
            matching_findings = [
                f for f in open_findings
                if _finding_matches_requirement(f, req, fw["id"], cat_set, cwe_set)
            ]

            failed_tests = [t for t in matching_tests if str(t.get("status") or "").lower() == "failed"]
            review_tests = [t for t in matching_tests if str(t.get("status") or "").lower() == "needs_review"]
            passed_tests = [t for t in matching_tests if str(t.get("status") or "").lower() == "passed"]

            if failed_tests or matching_findings:
                status = "non_compliant"
                fw_non_compliant += 1
                total_non_compliant += 1
            elif review_tests:
                status = "needs_review"
                fw_needs_review += 1
                total_needs_review += 1
            elif passed_tests or has_scan_or_audit:
                status = "compliant"
                fw_compliant += 1
                total_compliant += 1
            else:
                status = "not_assessed"
                fw_not_assessed += 1
                total_not_assessed += 1

            fw_reqs.append(
                {
                    "id": req["id"],
                    "title": req["title"],
                    "status": status,
                    "mapped_categories": list(req["categories"]),
                    "open_finding_count": len(matching_findings),
                    "failed_test_count": len(failed_tests),
                    "passed_test_count": len(passed_tests),
                }
            )

        req_total = len(fw_reqs)
        fw_percent = round((fw_compliant / req_total) * 100) if req_total else 0
        frameworks_list.append(
            {
                "id": fw["id"],
                "name": fw["name"],
                "version": fw["version"],
                "readiness_percent": fw_percent,
                "compliant_count": fw_compliant,
                "non_compliant_count": fw_non_compliant,
                "needs_review_count": fw_needs_review,
                "not_assessed_count": fw_not_assessed,
                "requirements": fw_reqs,
                "clauses": fw_reqs,
            }
        )

    grand_total = total_compliant + total_non_compliant + total_needs_review + total_not_assessed
    overall_percent = round((total_compliant / grand_total) * 100) if grand_total else 0

    return {
        "format": "sniper-compliance-crosswalk-v1",
        "engagement_id": str(engagement.get("id") or "") if isinstance(engagement, dict) else "",
        "project_audit_id": str(project_audit.get("id") or "") if isinstance(project_audit, dict) else "",
        "scan_id": str(scan.get("id") or "") if isinstance(scan, dict) else "",
        "framework_count": len(frameworks_list),
        "frameworks": frameworks_list,
        "overall_readiness_percent": overall_percent,
        "non_compliant_count": total_non_compliant,
        "compliant_count": total_compliant,
        "needs_review_count": total_needs_review,
        "not_assessed_count": total_not_assessed,
    }


def generate_regulatory_attestation_bundle(audit: dict[str, Any]) -> dict[str, Any]:
    findings = (audit.get("findings") if isinstance(audit, dict) else []) or []
    regime_defs: list[tuple[str, str, set[str]]] = [
        (
            "EU_AI_ACT_2024",
            "EU AI Act — Madde 15 (Siber Güvenlik, Sağlamlık ve Veri Yönetişimi)",
            {"CWE-77", "CWE-502", "CWE-359", "CWE-1336"},
        ),
        (
            "EU_DORA_2025",
            "AB DORA — Madde 6 & 9 (Finansal BİT Dayanıklılığı, Atomik İşlem ve Kriptografi)",
            {"CWE-362", "CWE-327", "CWE-295", "CWE-319"},
        ),
        (
            "PCI_DSS_V4_0",
            "PCI-DSS v4.0 — Gereksinim 6.2.4 & 6.3.2 (Güvenli Yazılım ve Tedarik Zinciri)",
            {"CWE-89", "CWE-78", "CWE-427", "CWE-506", "CWE-829", "CWE-639"},
        ),
        (
            "ISO_27001_2022",
            "ISO/IEC 27001:2022 — Ek A.8.25 & A.8.28 (Güvenli Kodlama ve Erişim Kontrolü)",
            {"CWE-284", "CWE-287", "CWE-732", "CWE-862", "CWE-915"},
        ),
        (
            "NIST_SSDF_SP800_218",
            "NIST SP 800-218 (SSDF) — PW.4 / PW.7 / RV.1 (Statik Analiz ve Zafiyet Giderimi)",
            {"CWE-787", "CWE-190", "CWE-416", "CWE-22", "CWE-918"},
        ),
    ]
    regimes: dict[str, dict[str, Any]] = {}
    for regime_id, title, cwe_set in regime_defs:
        matched = [
            {
                "title": str(f.get("title") or ""),
                "cwe": str(f.get("cwe") or ""),
                "severity": str(f.get("severity") or "high"),
                "file": str(f.get("file") or f.get("path") or ""),
                "line": int(f.get("line", 1) or 1),
            }
            for f in findings
            if isinstance(f, dict) and not _is_false_positive(f) and bool(_finding_cwes(f) & cwe_set)
        ]
        status = "FAIL_WITH_GAPS" if matched else "PASS"
        regimes[regime_id] = {
            "id": regime_id,
            "title": title,
            "status": status,
            "gap_count": len(matched),
            "mapped_cwes": sorted(cwe_set),
            "findings": matched,
        }
    serialized = json.dumps(regimes, sort_keys=True, ensure_ascii=False).encode("utf-8")
    attestation_sha256 = hashlib.sha256(serialized).hexdigest()
    return {
        "format": "sniper-regulatory-attestation-bundle/1",
        "attestation_sha256": attestation_sha256,
        "regime_count": len(regimes),
        "regimes": regimes,
    }
