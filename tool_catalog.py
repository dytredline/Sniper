from __future__ import annotations

import os
from pathlib import Path
from methodology import CATEGORIES, TEST_CATALOG


TOOLS = [
    {
        "id": "sniper-baseline", "name": "Sniper Temel Tarama", "kind": "Yerleşik pasif DAST",
        "license": "Yerleşik", "execution": "Sniper içinde güvenli",
        "summary": "TLS, HTTP başlıkları, çerezler ve dönen sayfa üzerinde düşük etkili kontroller.",
        "url": "https://owasp.org/www-project-web-security-testing-guide/",
        "formats": ["HTML", "JSON", "SARIF"],
    },
    {
        "id": "sniper-code-analysis", "name": "Sniper Kod ve Veri Akışı Analizi",
        "kind": "Yerleşik SAST (fonksiyonlar ve dosyalar arası taint)",
        "license": "Yerleşik", "execution": "Sniper içinde güvenli",
        "summary": "Python ve JS/TS projelerinde istek girdisinin SQL, komut, eval, HTML, yol, SSRF, "
                   "serileştirme ve yönlendirme hedeflerine ulaşıp ulaşmadığını izler; CodeQL tarzı akış yolu (SARIF codeFlows) üretir.",
        "url": "https://owasp.org/www-community/Source_Code_Analysis_Tools",
        "formats": ["JSON", "SARIF (codeFlows)", "HTML"],
    },
    {
        "id": "sniper-auditors", "name": "Sniper Yerleşik Denetçiler", "kind": "Yerleşik yapılandırma ve kod denetimleri",
        "license": "Yerleşik", "execution": "Sniper içinde güvenli",
        "summary": "Sır, gizlilik, günlük bütünlüğü, ReDoS, zero-trust/mesh, bulut IAM, protokol, kimlik doğrulama, "
                   "kripto/PQC, mobil, tedarik zinciri ve CVSS 4.0/SSVC önceliklendirme denetimleri; ağ erişimi yok.",
        "url": "https://owasp.org/www-project-application-security-verification-standard/",
        "formats": ["JSON", "Bulgu", "CVSS 3.1/4.0"],
    },
    {
        "id": "owasp-zap", "name": "OWASP ZAP", "kind": "DAST ve web proxy",
        "license": "Açık kaynak", "execution": "Harici; sonuç Sniper'a kaydedilir",
        "summary": "Web/API keşfi, kimlik doğrulamalı gezinme, pasif ve yapılandırılabilir aktif tarama.",
        "url": "https://www.zaproxy.org/docs/automate/automation-framework/",
        "formats": ["HTML", "JSON", "XML"],
    },
    {
        "id": "burp-suite", "name": "Burp Suite Professional", "kind": "DAST ve manuel proxy",
        "license": "Ticari", "execution": "Harici; sonuç Sniper'a kaydedilir",
        "summary": "Oturumlu tarama, web/API yüzey haritalama ve uzman odaklı manuel test iş akışı.",
        "url": "https://portswigger.net/burp/documentation/scanner",
        "formats": ["HTML", "XML"],
    },
    {
        "id": "semgrep", "name": "Semgrep / Opengrep", "kind": "SAST, sır ve tedarik zinciri",
        "license": "Açık kaynak (Opengrep LGPL-2.1) + ticari", "execution": "Kaynak kodu/CI üzerinde harici",
        "summary": "Kaynak kodu kusurları, veri akışları ve sırlar. Yerel motor SHA-256 ile sabitlenmiş Opengrep; "
                   "Sniper'ın kendi kural paketi (Python, JS/TS, Go, Java) ile dosya içi fonksiyonlar arası veri akışı izlenir.",
        "url": "https://semgrep.dev/docs/workflows/overview",
        "formats": ["JSON", "SARIF"],
    },
    {
        "id": "joern", "name": "Joern (derin analiz)", "kind": "SAST — C/C++, Java, Kotlin, PHP, Go, Ruby, C# veri akışı (Code Property Graph)",
        "license": "Apache-2.0", "execution": "Yerel, sabitli JDK ile isteğe bağlı",
        "summary": "C/C++, Java/Kotlin, PHP, Go, Ruby ve C# projelerinde dış girdinin komut, SQL, dosya yolu, biçim dizgisi, "
                   "bellek kopyalama, serileştirme, SSRF, XSS, yönlendirme, XXE, ifade değerlendirme ve LDAP hedeflerine dosyalar arası ulaşıp ulaşmadığını "
                   "Joern'ün veri akışı motoruyla izler; adım adım SARIF codeFlows üretir.",
        "url": "https://joern.io/",
        "formats": ["JSON", "SARIF (codeFlows)"],
    },
    {
        "id": "codeql", "name": "GitHub CodeQL", "kind": "SAST",
        "license": "GitHub koşullarına bağlı", "execution": "Kaynak kodu/CI üzerinde harici",
        "summary": "Kod tabanında güvenlik sorguları ve veri akışı analizi.",
        "url": "https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql",
        "formats": ["SARIF"],
    },
    {
        "id": "trivy", "name": "Trivy", "kind": "SCA, IaC, sır ve imaj tarama",
        "license": "Açık kaynak", "execution": "Depo/CI üzerinde harici",
        "summary": "Bağımlılık açıkları, IaC yanlış yapılandırmaları, container imajları ve sırlar.",
        "url": "https://trivy.dev/docs/latest/scanner/misconfiguration/",
        "formats": ["JSON", "SARIF", "SBOM"],
    },
    {
        "id": "osv-scanner", "name": "OSV-Scanner", "kind": "Bağımlılık analizi",
        "license": "Açık kaynak", "execution": "Açık onaylı çevrimdışı yerel npm kilit dosyası veya harici",
        "summary": "Kilit dosyaları ve proje bağımlılıklarını OSV açık veritabanıyla eşleştirir.",
        "url": "https://google.github.io/osv-scanner/",
        "formats": ["JSON", "SARIF"],
    },
    {
        "id": "schemathesis", "name": "Schemathesis", "kind": "Şema tabanlı API testi",
        "license": "Açık kaynak", "execution": "Sentetik loopback fixture için açık onaylı sınırlı yerel smoke veya harici",
        "summary": "OpenAPI veya GraphQL şemasından özellik tabanlı API testleri üretir.",
        "url": "https://schemathesis.readthedocs.io/en/stable/",
        "formats": ["JUnit", "HAR", "CLI özeti"],
    },
    {
        "id": "testssl", "name": "testssl.sh / SSLyze", "kind": "TLS yapılandırma testi",
        "license": "Açık kaynak", "execution": "Harici düşük etkili ağ testi",
        "summary": "TLS sürümü, şifre takımları, sertifika ve protokol yapılandırmasını ayrıntılı inceler.",
        "url": "https://testssl.sh/",
        "formats": ["JSON", "CSV", "HTML"],
    },
    {
        "id": "nmap", "name": "Nmap", "kind": "Ağ ve servis envanteri",
        "license": "Açık kaynak", "execution": "Harici, kapsamla sınırlandırılmış",
        "summary": "Açık servisleri ve mümkün olduğunda servis/sürüm bilgilerini envantere alır.",
        "url": "https://nmap.org/book/vscan.html",
        "formats": ["XML", "Normal"],
    },
    {
        "id": "nuclei", "name": "Nuclei", "kind": "Şablon tabanlı web denetimi",
        "license": "Açık kaynak", "execution": "Yerel ve ayrıca izinli hedef profilleri",
        "summary": "Yerel loopback ve ayrı yetkilendirilmiş HTTP hedeflerinde şablon taraması; kayıtlı JSONL özetini içe alır.",
        "url": "https://github.com/projectdiscovery/nuclei", "formats": ["JSONL"],
    },
    {
        "id": "gitleaks", "name": "Gitleaks", "kind": "Yerel sır taraması",
        "license": "Açık kaynak", "execution": "Açık yerel girdi onayıyla",
        "summary": "Yerel proje dosyalarının sınırlandırılmış kopyasında sır taraması ve kayıtlı rapor özeti.",
        "url": "https://github.com/gitleaks/gitleaks", "formats": ["JSON"],
    },
    {
        "id": "trufflehog", "name": "TruffleHog", "kind": "Yerel sır taraması",
        "license": "Açık kaynak", "execution": "Açık yerel girdi onayıyla",
        "summary": "Yerel dosya sistemi veya Git geçmişi profilleri; doğrulama yapmadan maskeli özet.",
        "url": "https://github.com/trufflesecurity/trufflehog", "formats": ["JSONL"],
    },
    {
        "id": "npm-audit", "name": "npm audit", "kind": "Bağımlılık analizi",
        "license": "Açık kaynak", "execution": "Yerel girdi ve npm kayıt servisi için ayrı onayla",
        "summary": "Yerel package-lock kopyasının resmî npm danışma servisiyle toplu zafiyet eşleştirmesi.",
        "url": "https://docs.npmjs.com/cli/commands/npm-audit", "formats": ["JSON"],
    },
    {
        "id": "dependabot", "name": "Dependabot", "kind": "Bağımlılık uyarıları",
        "license": "GitHub koşullarına bağlı", "execution": "Yalnız kayıtlı rapor özeti",
        "summary": "Kaydedilmiş Dependabot uyarılarını özetler; Sniper Dependabot taraması başlatmaz.",
        "url": "https://docs.github.com/en/code-security/dependabot", "formats": ["JSON"],
    },
    {
        "id": "ssllabs", "name": "SSL Labs", "kind": "TLS raporu",
        "license": "Harici hizmet", "execution": "Yalnız kayıtlı rapor özeti",
        "summary": "Kaydedilmiş SSL Labs ana makine raporunu özetler; canlı TLS testi başlatmaz.",
        "url": "https://www.ssllabs.com/ssltest/", "formats": ["JSON"],
    },
    {
        "id": "openssl", "name": "OpenSSL", "kind": "Sertifika raporu",
        "license": "Açık kaynak", "execution": "Açık onaylı yerel TLS ve kayıtlı rapor özeti",
        "summary": "Sabitlenmiş CA ile yalnız 127.0.0.1 TLS eşini doğrular; kayıtlı X.509 raporlarını ayrıca özetler.",
        "url": "https://www.openssl.org/docs/", "formats": ["JSON"],
    },
    {
        "id": "browser-tests", "name": "Playwright / tarayıcı geliştirici araçları", "kind": "İstemci ve akış testi",
        "license": "Açık kaynak / yerleşik", "execution": "Sentetik hesaplarla test ortamında",
        "summary": "Rol, oturum, istemci depolama ve iş akışlarını tekrar edilebilir tarayıcı senaryolarıyla doğrular.",
        "url": "https://playwright.dev/docs/intro",
        "formats": ["JSON", "JUnit", "HTML", "Ekran görüntüsü"],
    },
    {
        "id": "k6", "name": "Grafana k6", "kind": "Performans ve dayanıklılık",
        "license": "Açık kaynak + bulut", "execution": "Yalnız staging/laboratuvar",
        "summary": "SLO eşikleriyle kontrollü performans ve dayanıklılık senaryoları.",
        "url": "https://grafana.com/docs/k6/latest/testing-guides/automated-performance-testing/",
        "formats": ["JSON", "JUnit", "Özet"],
    },
    {
        "id": "siem-review", "name": "SIEM ve günlük incelemesi", "kind": "Kayıt ve olay müdahalesi",
        "license": "Kurulu sisteme bağlı", "execution": "Savunma ortamında sorgu/kanıt",
        "summary": "Uygulama, WAF, kimlik ve altyapı günlüklerinin üretildiğini ve alarmların çalıştığını doğrular.",
        "url": "https://owasp.org/www-project-application-security-verification-standard/",
        "formats": ["ECS JSONL kanıt özeti", "Maskeli kanıt", "Ekran görüntüsü", "Kayıt hash'i"],
    },
    {
        "id": "expert-review", "name": "Uzman manuel incelemesi", "kind": "İş mantığı ve tasarım",
        "license": "İnsan doğrulaması", "execution": "Sniper çalışma alanında yönlendirmeli",
        "summary": "Araçların güvenilir biçimde anlayamadığı rol, iş kuralı, tasarım ve etki kontrolleri.",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/README",
        "formats": ["Not", "Maskeli kanıt", "Bulgu"],
    },
]


# These are available workflows, not a claim that a binary, target authorization,
# or scan window is currently ready. Keep routes tied to server.py handlers.
CAPABILITY_WORKFLOWS = {
    "sniper-baseline": [("built_in", "Yerleşik temel tarama", ("/api/scans",))],
    "sniper-code-analysis": [
        ("built_in", "Proje kod ve veri akışı analizi", ("/api/project-audits",)),
        ("built_in", "Analiz karşılaştırma", ("/api/project-audits/diff",)),
    ],
    "sniper-auditors": [
        ("built_in", "Satır içi / proje kod denetçileri", (
            "/api/secret-intelligence/audit", "/api/privacy-dataflow/audit", "/api/host-hardening/audit",
            "/api/dos-resilience/audit", "/api/audit-logging/audit", "/api/browser-extension-pwa/audit",
            "/api/zero-trust-mesh/audit", "/api/business-logic/audit", "/api/database-security/audit",
            "/api/crypto-cbom-pqc/audit", "/api/web3-iot-security/audit", "/api/ai-llm-security/audit",
            "/api/cloud-iam-security/audit", "/api/protocol-security/audit", "/api/auth-protocol/audit",
            "/api/openapi-security/audit", "/api/desktop-security/audit", "/api/supply-chain-slsa/audit",
            "/api/mobile-security/audit-manifest", "/api/web-infra/dns-email-audit",
        )),
        ("built_in", "Önceliklendirme, tehdit modeli ve korelasyon", (
            "/api/cvss-ssvc/prioritize", "/api/threat-model/generate", "/api/attack-paths/correlate",
            "/api/blue-team/synthesize-rules",
        )),
    ],
    "owasp-zap": [
        ("local", "Yerel pasif profil", ("/api/tool-runs/zap-self-passive",)),
        ("authorized", "İnsan onaylı serbest hedef, kayıtlı hedef, seçili kapsam spider ve site-aktif profilleri", (
            "/api/tool-runs/zap-authorized",
            "/api/tool-runs/zap-target-active",
            "/api/tool-runs/zap-target-spider",
            "/api/tool-runs/zap-target-spider-scope",
            "/api/tool-runs/zap-site-active",
        )),
        ("report_import", "Kaydedilmiş rapor ve AF plan özeti", (
            "/api/tool-reports/zap/summary",
            "/api/tool-plans/zap-af/preview",
        )),
    ],
    "burp-suite": [(
        "report_import",
        "Kaydedilmiş site haritası, handoff manifest ve Logger CSV özeti",
        (
            "/api/tool-reports/burp-sitemap/summary",
            "/api/tool-reports/burp-sitemap/handoff-manifest",
            "/api/tool-reports/burp-logger-csv/summary",
        ),
    )],
    "semgrep": [
        ("local", "Yerel kod profili (sabitli Opengrep)", ("/api/tool-runs/semgrep",)),
        ("report_import", "Kaydedilmiş JSON rapor, kural envanteri ve TLS doğrulama filtresi", (
            "/api/tool-reports/semgrep-native-json/summary",
            "/api/tool-reports/semgrep/rulepack-inventory",
            "/api/tool-reports/semgrep/tls-verify-filter",
        )),
    ],
    "joern": [
        ("local", "Yerel derin veri akışı analizi (C/C++, Java, Kotlin, PHP, Go, Ruby, C#)", ("/api/tool-runs/joern-deep",)),
    ],
    "codeql": [
        ("report_import", "Kaydedilmiş CodeQL SARIF özeti", ("/api/tool-reports/sarif/summary",)),
        ("external", "Harici CodeQL analizi", ()),
    ],
    "trivy": [
        ("local", "Yerel zafiyet (Python/npm/Go/Cargo/pnpm/Yarn/Maven/Ruby), sır, imaj ve IaC profilleri", (
            "/api/tool-runs/trivy-vulnerability", "/api/tool-runs/trivy-npm-vulnerability",
            "/api/tool-runs/trivy-go-mod-vulnerability", "/api/tool-runs/trivy-cargo-lock-vulnerability",
            "/api/tool-runs/trivy-pnpm-vulnerability", "/api/tool-runs/trivy-yarn-vulnerability",
            "/api/tool-runs/trivy-maven-vulnerability", "/api/tool-runs/trivy-ruby-vulnerability",
            "/api/tool-runs/trivy-image-archive-vulnerability", "/api/tool-runs/trivy-secret",
            "/api/tool-runs/trivy-dockerfile-config", "/api/tool-runs/trivy-terraform-config",
            "/api/tool-runs/trivy-terraform-config-batch",
            "/api/tool-runs/trivy-kubernetes-config", "/api/tool-runs/trivy-kubernetes-config-batch",
        )),
        ("report_import", "Kaydedilmiş JSON rapor ve çevrimdışı DB tazelik özeti", (
            "/api/tool-reports/trivy-native-json/summary",
            "/api/tool-reports/trivy/db-freshness",
        )),
    ],
    "osv-scanner": [
        ("report_import", "Kaydedilmiş OSV SARIF özeti", ("/api/tool-reports/sarif/summary",)),
        ("external", "Harici OSV-Scanner analizi", ()),
        ("local", "Açık onaylı çevrimdışı yerel npm kilit dosyası analizi", ("/api/tool-runs/osv-scanner-local",)),
    ],
    "schemathesis": [
        ("report_import", "Kaydedilmiş JUnit XML özeti", ("/api/tool-reports/schemathesis-junit/summary",)),
        ("local", "Açık onaylı sentetik loopback fixture smoke", ("/api/tool-runs/schemathesis-local",)),
        ("local", "Operatörün izin verdiği yerel API için sınırlandırılmış GET testi", ("/api/tool-runs/schemathesis-loopback",)),
        ("external", "Harici Schemathesis API testi", ()),
    ],
    "testssl": [
        ("local", "Yalnız loopback TLS profilleri", ("/api/tool-runs/testssl-protocols", "/api/tool-runs/testssl-full")),
        ("authorized", "Her çalıştırmada insan onaylı, tek IP'ye sabitlenmiş doğrudan TLS profili", (
            "/api/tool-runs/testssl-authorized",
        )),
        ("report_import", "Kaydedilmiş rapor ve sınır sözleşmesi özeti", (
            "/api/tool-reports/testssl/summary",
            "/api/tool-reports/testssl/boundary-contract",
        )),
    ],
    "nmap": [
        ("authorized", "İzinli TCP ve servis parmak izi profilleri", (
            "/api/nmap/tcp-scan",
            "/api/nmap/service-fingerprint",
        )),
        ("report_import", "Kaydedilmiş rapor özeti", ("/api/tool-reports/nmap/summary",)),
    ],
    "nuclei": [
        ("local", "Yerel loopback profili", ("/api/tool-runs/nuclei-loopback",)),
        ("authorized", "İzinli HTTP hedef işi", ("/api/nuclei/http-scans",)),
        ("report_import", "Kaydedilmiş JSONL rapor ve doğrulama kapsamı özeti", (
            "/api/tool-reports/nuclei-jsonl/summary",
            "/api/tool-reports/nuclei/verification-coverage",
        )),
    ],
    "gitleaks": [
        ("local", "Yerel dosya ve Git geçmişi profilleri", (
            "/api/tool-runs/gitleaks",
            "/api/tool-runs/gitleaks-git-history",
        )),
        ("report_import", "Kaydedilmiş rapor özeti", ("/api/tool-reports/gitleaks/summary",)),
    ],
    "trufflehog": [
        ("local", "Yerel dosya ve Git geçmişi profilleri", (
            "/api/tool-runs/trufflehog-filesystem", "/api/tool-runs/trufflehog-git-history")),
        ("report_import", "Kaydedilmiş rapor ve sır doğrulama paketi özeti", (
            "/api/tool-reports/trufflehog/summary",
            "/api/tool-runs/secret-bundle/validate",
        )),
    ],
    "npm-audit": [
        ("local", "Yerel kilit dosyası ve resmî npm kayıt servisi (iki ayrı onay)", ("/api/tool-runs/npm-audit-local",)),
        ("report_import", "Kaydedilmiş rapor ve salt-okunur düzeltme planı özeti", (
            "/api/tool-reports/npm-audit/summary",
            "/api/tool-reports/dependency-remediation-plan",
        )),
    ],
    "dependabot": [(
        "report_import",
        "Kaydedilmiş uyarı ve çevrimdışı senkronizasyon özeti",
        ("/api/tool-reports/dependabot/summary", "/api/tool-reports/dependabot/offline-sync"),
    )],
    "ssllabs": [(
        "report_import",
        "Kaydedilmiş ana makine raporu ve önbellek sözleşmesi",
        ("/api/tool-reports/ssllabs-host/summary", "/api/tool-reports/ssllabs/cache-contract"),
    )],
    "openssl": [
        ("local", "Açık onaylı loopback TLS sertifika doğrulaması", ("/api/tool-runs/openssl-x509-loopback",)),
        ("report_import", "Kaydedilmiş X.509 raporları", (
            "/api/tool-reports/openssl-x509/summary", "/api/tool-reports/openssl-x509/batch-summary")),
    ],
    "browser-tests": [
        ("report_import", "Kaydedilmiş Playwright JSON özeti", ("/api/tool-reports/playwright-json/summary",)),
        ("external", "Harici tarayıcı testi", ()),
    ],
    "k6": [
        ("report_import", "Kaydedilmiş klasik handleSummary JSON özeti", ("/api/tool-reports/k6-summary-json/summary",)),
        ("report_import", "Kaydedilmiş machine-readable v1 JSON özeti", ("/api/tool-reports/k6-machine-summary-v1/summary",)),
        ("external", "Harici k6 performans testi", ()),
    ],
    "siem-review": [
        ("report_import", "Kaydedilmiş ECS JSONL kanıt özeti", ("/api/tool-reports/siem-ecs-ndjson/summary",)),
        ("external", "Harici savunma incelemesi", ()),
    ],
    "expert-review": [("manual", "Uzman manuel incelemesi", ())],
}


# MCP'nin serbest HTTP(S) hedef onay kaydı için sunabildiği ağ odaklı araçlar. Bu liste bir aracın kurulu,
# çalışmaya hazır veya hedefte yetkili olduğu iddiası değildir; yalnız insan onaylı dispatch makbuzunda seçilebilen
# ürün kataloğudur. Mevcut araç rotaları ve gövdeleri bu katalog tarafından değiştirilmez.
MCP_AUTHORIZED_HTTP_TOOL_IDS = (
    "owasp-zap", "burp-suite", "schemathesis", "testssl", "nmap", "nuclei",
    "ssllabs", "openssl", "browser-tests", "k6",
)
MCP_AUTHORIZED_HTTP_JOB_TOOL_IDS = frozenset(
    set(MCP_AUTHORIZED_HTTP_TOOL_IDS) - {"burp-suite"}
)


def mcp_authorized_target_tools() -> list[dict[str, object]]:
    """Serbest hedef onay planında seçilebilen, kaynak kataloglu ağ araçlarını döndür."""
    by_id = {tool["id"]: tool for tool in TOOLS}
    rows: list[dict[str, object]] = []
    for tool_id in MCP_AUTHORIZED_HTTP_TOOL_IDS:
        tool = by_id[tool_id]
        workflows = CAPABILITY_WORKFLOWS[tool_id]
        rows.append({
            "tool_id": tool_id,
            "label": tool["name"],
            "workflow_modes": sorted({mode for mode, _label, _routes in workflows}),
            "dispatch_mode": (
                "job" if tool_id in MCP_AUTHORIZED_HTTP_JOB_TOOL_IDS else "manual_handoff"
            ),
        })
    return rows


CATEGORY_TOOLING = {
    "information": ("Hibrit", ["sniper-baseline", "owasp-zap", "burp-suite", "nmap", "expert-review"], "Kapsam envanteri ve uygulama akışları"),
    "configuration": ("Yüksek otomasyon", ["sniper-baseline", "owasp-zap", "burp-suite", "nmap", "nuclei", "testssl", "ssllabs", "openssl", "trivy", "sniper-auditors"], "URL, DNS, altyapı veya IaC erişimi"),
    "identity": ("Uzman destekli", ["burp-suite", "owasp-zap", "browser-tests", "expert-review"], "Sentetik kullanıcı ve kayıt/davet akışları"),
    "authentication": ("Hibrit", ["burp-suite", "owasp-zap", "browser-tests", "expert-review", "sniper-auditors"], "Sentetik hesap, MFA ve kurtarma senaryoları"),
    "authorization": ("Uzman destekli", ["burp-suite", "browser-tests", "schemathesis", "expert-review"], "En az iki rol, iki kullanıcı ve sentetik nesneler"),
    "session": ("Hibrit", ["sniper-baseline", "burp-suite", "owasp-zap", "browser-tests"], "Sentetik oturumlar ve güvenli test verisi"),
    "input": ("Yüksek otomasyon", ["burp-suite", "owasp-zap", "semgrep", "codeql", "schemathesis", "expert-review", "sniper-code-analysis", "joern"], "Kapsamlı giriş noktaları ve kaynak kodu/API şeması"),
    "server": ("Hibrit", ["burp-suite", "owasp-zap", "semgrep", "codeql", "expert-review", "sniper-code-analysis", "joern"], "Staging, kaynak kodu ve kontrollü test uçları"),
    "errors": ("Hibrit", ["burp-suite", "owasp-zap", "schemathesis", "expert-review"], "Sentetik hata senaryoları ve günlük erişimi"),
    "crypto": ("Yüksek otomasyon", ["sniper-baseline", "testssl", "ssllabs", "openssl", "burp-suite", "semgrep", "codeql", "sniper-auditors"], "TLS uçları ve tercihen kaynak kodu"),
    "data": ("Uzman destekli", ["burp-suite", "owasp-zap", "semgrep", "trivy", "expert-review", "sniper-code-analysis", "sniper-auditors"], "Veri sınıflandırması, sentetik veri ve kaynak kodu"),
    "business": ("Manuel ağırlıklı", ["burp-suite", "browser-tests", "expert-review"], "Beklenen iş kuralları ve sentetik işlemler"),
    "client": ("Hibrit", ["sniper-baseline", "owasp-zap", "burp-suite", "browser-tests", "semgrep", "sniper-code-analysis"], "Tarayıcı akışları ve istemci kaynak kodu"),
    "api": ("Yüksek otomasyon", ["burp-suite", "owasp-zap", "schemathesis", "semgrep", "expert-review", "sniper-code-analysis", "sniper-auditors"], "OpenAPI/GraphQL şeması ve sentetik yetkilendirme"),
    "infrastructure": ("Yüksek otomasyon", ["nmap", "testssl", "trivy", "sniper-baseline", "expert-review", "sniper-auditors"], "Kapsam içi ana makineler, DNS ve IaC"),
    "supplychain": ("Yüksek otomasyon", ["osv-scanner", "trivy", "semgrep", "npm-audit", "dependabot", "gitleaks", "trufflehog", "codeql", "expert-review", "sniper-auditors"], "Depo, kilit dosyaları, SBOM ve CI"),
    "availability": ("Staging gerekli", ["k6", "expert-review", "sniper-auditors"], "Staging/lab, SLO ve gözlemlenebilirlik"),
    "logging": ("Savunma sistemi gerekli", ["siem-review", "semgrep", "expert-review", "sniper-auditors", "sniper-code-analysis"], "Uygulama/WAF/kimlik günlükleri ve alarm erişimi"),
    "controlled": ("Harici kanıt", ["k6", "burp-suite", "siem-review", "expert-review"], "Sentetik hesap veya staging; Sniper yalnız maskeli sonucu kaydeder"),
}


def _binary_presence(tool_id: str) -> str:
    """Return 'detected', 'not_found', or 'not_applicable' for CLI tool IDs."""
    cli_tools = {"nmap", "semgrep", "trivy"}
    if tool_id not in cli_tools:
        return "not_applicable"
    try:
        # Use shutil.which to detect presence in PATH without executing
        import shutil
        path = shutil.which(tool_id)
        if path is None:
            return "not_found"
        # Ensure the found path is executable
        if os.access(path, os.X_OK):
            return "detected"
        return "not_found"
    except Exception:
        return "not_found"


def tooling_payload() -> dict:
    tool_index = {tool["id"]: tool for tool in TOOLS}
    category_names = {slug: title for slug, title, _reference in CATEGORIES}
    categories = []
    for slug, title, reference in CATEGORIES:
        coverage, tool_ids, required_input = CATEGORY_TOOLING[slug]
        control_count = sum(1 for control in TEST_CATALOG if control["category"] == slug)
        categories.append({
            "slug": slug,
            "title": title,
            "reference": reference,
            "coverage": coverage,
            "control_count": control_count,
            "tool_ids": tool_ids,
            "required_input": required_input,
        })
    controls = []
    for control in TEST_CATALOG:
        coverage, tool_ids, required_input = CATEGORY_TOOLING[control["category"]]
        controls.append({
            "control_id": control["control_id"],
            "title": control["title"],
            "category": control["category"],
            "category_title": category_names[control["category"]],
            "coverage": coverage,
            "tool_ids": tool_ids,
            "required_input": required_input,
        })
    # Expose the source-backed workflow type separately from runtime readiness.
    tools_with_presence = []
    for tool in TOOLS:
        tool_copy = tool.copy()
        tool_copy["binary_presence"] = _binary_presence(tool["id"])
        workflows = CAPABILITY_WORKFLOWS[tool["id"]]
        tool_copy["workflows"] = [
            {"mode": mode, "label": label, "routes": list(routes)}
            for mode, label, routes in workflows
        ]
        tool_copy["execution"] = " · ".join(label for _mode, label, _routes in workflows)
        tools_with_presence.append(tool_copy)
    integrated_modes = {"built_in", "local", "authorized", "report_import"}
    integrated_count = sum(
        any(mode in integrated_modes for mode, _label, _routes in CAPABILITY_WORKFLOWS[tool["id"]])
        for tool in TOOLS
    )
    return {
        "summary": {
            "tool_count": len(TOOLS),
            "category_count": len(CATEGORIES),
            "control_count": len(TEST_CATALOG),
            "native_execution_count": sum(
                any(mode == "built_in" for mode, _label, _routes in CAPABILITY_WORKFLOWS[tool["id"]]) for tool in TOOLS
            ),
            "integrated_workflow_tool_count": integrated_count,
        },
        "tools": tools_with_presence,
        "categories": categories,
        "controls": controls,
        "policy": {
            "native": "Sniper düşük etkili yerleşik temel taramayı, ağ erişimi olmayan kod/veri akışı analizini ve yerleşik denetçileri kendisi çalıştırır. Yerel ve izinli araç profilleri ayrı uç noktalar üzerinden, gerekli onay ve çalışma zamanı koşullarıyla çalışır.",
            "external": "Rapor özeti tarama başlatmaz. Harici öneri, aracın Sniper'da çalıştırıldığı anlamına gelmez. Profilin listelenmesi ikilinin hazır veya hedefin yetkili olduğunu kanıtlamaz.",
            "completion": "Bir araç önerisi kontrolün tamamlandığı anlamına gelmez; sonuç uzman tarafından doğrulanır.",
        },
    }
