from __future__ import annotations

import re
from scanner import _finding, calculate_score, normalize_target
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups


DANGLING_CNAME_SUFFIXES: tuple[str, ...] = (
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "cloudapp.net",
    "trafficmanager.net",
    "fastly.net",
    "pantheonsite.io",
    "zendesk.com",
    "unbouncepages.com",
    "vercel.app",
    "netlify.app",
    "fly.dev",
    "onrender.com",
    "pages.dev",
    "surge.sh",
    "cargo.site",
    "ghost.io",
)

SENSITIVE_ROBOTS_PATHS: tuple[str, ...] = (
    "/admin",
    "/backup",
    "/.git",
    "/.env",
    "/config",
    "/debug",
    "/phpmyadmin",
    "/wp-admin",
    "/graphql",
    "/swagger",
    "/internal",
)

PRIVATE_JWK_FIELDS: tuple[str, ...] = ("d", "p", "q", "dp", "dq", "qi", "k")


def _controlled_finding(
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    reference: str,
    control_id: str,
) -> dict:
    item = _finding(
        severity,
        category,
        title,
        description,
        evidence,
        recommendation,
        reference,
    )
    item["control_id"] = control_id
    return item


def audit_dns_and_email_security(
    hostname: str,
    *,
    txt_records: list[str] | None = None,
    caa_records: list[str] | None = None,
    cname_target: str | None = None,
) -> dict:
    normalized = normalize_target(hostname)
    norm_host = normalized.hostname
    findings: list[dict] = []

    txt_list = [str(record).strip() for record in (txt_records or []) if str(record).strip()]
    caa_list = [str(record).strip() for record in (caa_records or []) if str(record).strip()]

    spf_records = [record for record in txt_list if record.lower().startswith("v=spf1")]
    if not spf_records:
        findings.append(
            _controlled_finding(
                "medium",
                "infrastructure",
                "SPF kaydı bulunamadı",
                "Alan adı için e-posta gönderici yetkilendirmesini tanımlayan SPF (v=spf1) TXT kaydı bulunamadı.",
                f"hostname={norm_host} · spf=(yok)",
                "Yetkili posta sunucularını belirten ve -all veya ~all ile biten bir SPF TXT kaydı yayımlayın.",
                "RFC 7208",
                "SNIPER-INFR-07",
            )
        )
    else:
        for spf in spf_records:
            tokens = [tok.strip().lower() for tok in spf.split() if tok.strip()]
            if "+all" in tokens or "all" in tokens:
                findings.append(
                    _controlled_finding(
                        "critical",
                        "infrastructure",
                        "SPF politikası tüm göndericilere izin veriyor (+all)",
                        "SPF kaydı +all mekanizması içeriyor; bu yapılandırma herhangi bir sunucunun alan adınız adına e-posta göndermesine izin verir.",
                        spf[:240],
                        "+all ifadesini kaldırın ve yalnızca yetkili göndericileri tanımlayarak kaydı -all veya ~all ile sonlandırın.",
                        "RFC 7208",
                        "SNIPER-INFR-07",
                    )
                )
            elif "?all" in tokens:
                findings.append(
                    _controlled_finding(
                        "medium",
                        "infrastructure",
                        "SPF politikası nötr (?all) bırakılmış",
                        "SPF kaydı ?all ile sonlandırılmış; yetkisiz göndericiler için reddetme veya işaretleme politikası uygulanmıyor.",
                        spf[:240],
                        "SPF politikasını geçiş sürecinde ~all (softfail), tam doğrulamada -all (fail) olarak sıkılaştırın.",
                        "RFC 7208",
                        "SNIPER-INFR-07",
                    )
                )

    dmarc_records = [record for record in txt_list if record.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(
            _controlled_finding(
                "medium",
                "infrastructure",
                "DMARC kaydı bulunamadı",
                "SPF ve DKIM hizalamasını denetleyen DMARC (v=DMARC1) TXT kaydı bulunamadı.",
                f"hostname={norm_host} · dmarc=(yok)",
                "_dmarc alt alan adında p=quarantine veya p=reject politikası içeren bir DMARC kaydı yayımlayın.",
                "RFC 7489",
                "SNIPER-INFR-07",
            )
        )
    else:
        for dmarc in dmarc_records:
            if re.search(r"(?:^|;)\s*p\s*=\s*none\s*(?:;|$)", dmarc, flags=re.IGNORECASE):
                findings.append(
                    _controlled_finding(
                        "low",
                        "infrastructure",
                        "DMARC politikası yalnız izleme modunda (p=none)",
                        "DMARC kaydı mevcut ancak p=none politikası sahte e-postaların teslimini engellemez.",
                        dmarc[:240],
                        "Raporları doğruladıktan sonra DMARC politikasını p=quarantine veya p=reject seviyesine yükseltin.",
                        "RFC 7489",
                        "SNIPER-INFR-07",
                    )
                )

    if not caa_list:
        findings.append(
            _controlled_finding(
                "low",
                "infrastructure",
                "DNS CAA sertifika otoritesi kısıtlaması yok",
                "Alan adı için hangi sertifika otoritelerinin (CA) TLS sertifikası üretebileceğini kısıtlayan DNS CAA kaydı bulunamadı.",
                f"hostname={norm_host} · caa=(yok)",
                "Yalnızca kullandığınız sertifika otoritelerine izin veren DNS CAA (issue / issuewild) kayıtları ekleyin.",
                "RFC 8659",
                "SNIPER-INFR-08",
            )
        )

    cname_clean = (cname_target or "").strip().rstrip(".").lower()
    if cname_clean and any(
        cname_clean == suffix or cname_clean.endswith("." + suffix)
        for suffix in DANGLING_CNAME_SUFFIXES
    ):
        findings.append(
            _controlled_finding(
                "high",
                "infrastructure",
                "Olası alt alan adı devralma (Subdomain Takeover) CNAME hedefi",
                "Alan adı CNAME kaydı, sahipsiz bırakıldığında üçüncü taraflarca kaydedilebilecek harici bir bulut/PaaS hizmetine işaret ediyor.",
                f"{norm_host} -> {cname_clean}",
                "Kullanılmayan CNAME DNS kayıtlarını derhal silin veya hedef bulut kaynağının sahipliğini doğrulayın.",
                "OWASP WSTG-CONF-10",
                "SNIPER-INFR-02",
            )
        )

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-dns-email-security-v1",
        "hostname": norm_host,
        "score": score,
        "grade": grade,
        "counts": counts,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-INFR-01",
            "SNIPER-INFR-02",
            "SNIPER-INFR-07",
            "SNIPER-INFR-08",
        ],
    }


def audit_discovery_and_identity_endpoints(
    target_url: str,
    *,
    robots_txt: str | None = None,
    openid_config: dict | None = None,
    jwks_doc: dict | None = None,
    graphql_response: dict | None = None,
    response_headers: dict[str, str] | None = None,
) -> dict:
    normalized = normalize_target(target_url)
    findings: list[dict] = []

    if robots_txt:
        exposed_paths: list[str] = []
        for raw_line in robots_txt.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            directive, value = line.split(":", 1)
            if directive.strip().lower() not in {"disallow", "allow"}:
                continue
            candidate_path = value.strip()
            if not candidate_path:
                continue
            lower_path = candidate_path.lower()
            if any(
                lower_path == sens or lower_path.startswith(sens + "/") or lower_path.startswith(sens + "?") or sens in lower_path
                for sens in SENSITIVE_ROBOTS_PATHS
            ):
                if candidate_path not in exposed_paths:
                    exposed_paths.append(candidate_path)
        if exposed_paths:
            findings.append(
                _controlled_finding(
                    "low",
                    "information",
                    "robots.txt içinde hassas dizin veya uç nokta ifşası",
                    "robots.txt dosyası yönetim, yedekleme veya yapılandırma yollarını açıkça listeliyor.",
                    ", ".join(exposed_paths[:8]),
                    "Hassas dizinleri robots.txt ile gizlemeye çalışmak yerine kimlik doğrulama ve ağ erişim kontrolleriyle koruyun.",
                    "OWASP WSTG-INFO-03",
                    "SNIPER-INFO-03",
                )
            )

    if isinstance(openid_config, dict) and openid_config:
        insecure_endpoints: list[str] = []
        for key, value in openid_config.items():
            if isinstance(value, str) and (key == "issuer" or key.endswith("_endpoint") or key.endswith("_uri")):
                if value.strip().lower().startswith("http://"):
                    insecure_endpoints.append(f"{key}={value.strip()[:120]}")
        if insecure_endpoints:
            findings.append(
                _controlled_finding(
                    "high",
                    "authentication",
                    "OpenID Connect yapılandırmasında şifrelenmemiş (HTTP) uç nokta",
                    "/.well-known/openid-configuration belgesinde HTTPS yerine HTTP kullanan uç noktalar tanımlanmış.",
                    ", ".join(insecure_endpoints[:5]),
                    "Tüm OpenID Connect ve OAuth 2.0 uç noktalarını yalnızca HTTPS üzerinden sunun.",
                    "OpenID Connect Core 1.0",
                    "SNIPER-AUTH-11",
                )
            )

        response_types = [str(rt).strip() for rt in openid_config.get("response_types_supported", []) if str(rt).strip()]
        implicit_types = [
            rt for rt in response_types
            if any(tok in {"token", "id_token"} for tok in rt.lower().split())
        ]
        if implicit_types:
            findings.append(
                _controlled_finding(
                    "medium",
                    "authentication",
                    "OpenID Connect implicit akışı etkin",
                    "OpenID Connect sağlayıcısı tarayıcı adres çubuğu/geçmişi üzerinden jeton sızıntısına açık olan implicit (token/id_token) yanıt türlerini destekliyor.",
                    "response_types_supported: " + ", ".join(implicit_types[:6]),
                    "Implicit akışını kapatın ve Authorization Code + PKCE (S256) akışını zorunlu kılın.",
                    "OAuth 2.0 Security Best Current Practice",
                    "SNIPER-AUTH-11",
                )
            )

        pkce_methods = [str(m).strip() for m in openid_config.get("code_challenge_methods_supported", []) if str(m).strip()]
        if "S256" not in pkce_methods:
            findings.append(
                _controlled_finding(
                    "medium",
                    "authentication",
                    "OpenID Connect PKCE (S256) desteği eksik",
                    "OpenID Connect yapılandırmasında S256 tabanlı PKCE doğrulama yöntemi ilan edilmemiş.",
                    f"code_challenge_methods_supported: {', '.join(pkce_methods) if pkce_methods else '(yok)'}",
                    "Yetkilendirme kodu攔 (interception) saldırılarını önlemek için PKCE S256 desteğini zorunlu kılın.",
                    "RFC 7636",
                    "SNIPER-AUTH-11",
                )
            )

        signing_algs = [str(alg).strip().lower() for alg in openid_config.get("id_token_signing_alg_values_supported", []) if str(alg).strip()]
        if "none" in signing_algs:
            findings.append(
                _controlled_finding(
                    "critical",
                    "authentication",
                    "OpenID Connect imzasız (alg=none) ID token kabul ediyor",
                    "id_token_signing_alg_values_supported listesinde 'none' algoritması bulunuyor; bu durum kimlik doğrulama atlatma riskine yol açar.",
                    "id_token_signing_alg_values_supported içinde 'none' mevcut",
                    "'none' algoritmasını derhal kaldırın ve yalnızca RS256/ES256 gibi güçlü asimetrik imzaları kabul edin.",
                    "OpenID Connect Core 1.0",
                    "SNIPER-AUTH-11",
                )
            )

        token_auth_methods = [
            str(m).strip().lower()
            for m in openid_config.get("token_endpoint_auth_methods_supported", [])
            if str(m).strip()
        ]
        weak_token_auth = [m for m in token_auth_methods if m in {"none", "client_secret_get"}]
        if weak_token_auth:
            findings.append(
                _controlled_finding(
                    "high",
                    "authentication",
                    "OpenID Connect token uç noktasında zayıf istemci kimlik doğrulama yöntemi (none / client_secret_get)",
                    "token_endpoint_auth_methods_supported içinde 'none' (kimlik doğrulamasız) veya 'client_secret_get' (URL sorgu dizgesinde istemci sırrı sızıntısı) yöntemine izin veriliyor.",
                    "token_endpoint_auth_methods_supported: " + ", ".join(weak_token_auth),
                    "Gizli istemciler için private_key_jwt veya tls_client_auth (en azından client_secret_basic/post + PKCE) zorunlu kılın; client_secret_get yöntemini kapatın.",
                    "OAuth 2.0 Security Best Current Practice",
                    "SNIPER-AUTH-11",
                )
            )

    if isinstance(jwks_doc, dict) and jwks_doc:
        key_entries = jwks_doc.get("keys")
        candidates = key_entries if isinstance(key_entries, list) else [jwks_doc]
        leaked_fields: set[str] = set()
        for entry in candidates:
            if isinstance(entry, dict):
                for field_name in PRIVATE_JWK_FIELDS:
                    if field_name in entry and entry[field_name] not in (None, ""):
                        leaked_fields.add(field_name)
        if leaked_fields:
            findings.append(
                _controlled_finding(
                    "critical",
                    "data",
                    "JWKS uç noktasında özel anahtar (private key) materyali sızıntısı",
                    "Genel JWKS belgesinde yalnızca açık anahtar parametreleri bulunması gerekirken özel/simetrik anahtar alanları tespit edildi.",
                    f"Sızan JWK alanları: {', '.join(sorted(leaked_fields))} · değerler kaydedilmedi",
                    "İlgili anahtarları derhal iptal edip döndürün (rotate) ve JWKS çıktısından özel anahtar alanlarını temizleyin.",
                    "RFC 7517",
                    "SNIPER-CRYP-06",
                )
            )

    if isinstance(graphql_response, dict) and graphql_response:
        data_obj = graphql_response.get("data")
        has_schema = (isinstance(data_obj, dict) and "__schema" in data_obj) or "__schema" in graphql_response
        if has_schema:
            findings.append(
                _controlled_finding(
                    "medium",
                    "information",
                    "GraphQL introspection (şema sorgulama) üretimde açık",
                    "GraphQL uç noktası __schema sorgusuna tam şema tanımıyla yanıt veriyor; bu durum tüm sorgu ve mutasyon yüzeyini açığa çıkarır.",
                    "GraphQL yanıtında __schema nesnesi döndürüldü",
                    "Üretim ortamında kimliği doğrulanmamış istemciler için GraphQL introspection özelliğini kapatın.",
                    "OWASP API8:2023",
                    "SNIPER-APIT-06",
                )
            )

    if response_headers is not None:
        hdrs = {str(k).lower(): str(v).strip() for k, v in response_headers.items()}
        acao = hdrs.get("access-control-allow-origin", "").strip().lower()
        acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
        if acao in {"*", "null"} and acac == "true":
            findings.append(
                _controlled_finding(
                    "critical",
                    "headers",
                    "CORS yapılandırmasında kimlik bilgileriyle (Allow-Credentials: true) joker veya null köken izni",
                    "Yanıt başlıklarında Access-Control-Allow-Credentials: true ile birlikte Access-Control-Allow-Origin: * veya null kullanılıyor; sanal çerçeve (sandboxed iframe) ve çapraz köken saldırılarıyla oturum verileri çalınabilir.",
                    f"Access-Control-Allow-Origin={acao}, Access-Control-Allow-Credentials={acac}",
                    "Kimlik bilgili CORS yanıtlarında yalnızca açıkça beyaz listeye alınmış tam HTTPS kökenlerine izin verin; 'null' ve '*' kökenlerini reddedin.",
                    "CWE-942",
                    "SNIPER-CONF-07",
                )
            )
        missing_isolation = [
            header_name
            for header_name in (
                "cross-origin-opener-policy",
                "cross-origin-embedder-policy",
                "cross-origin-resource-policy",
            )
            if not hdrs.get(header_name)
        ]
        if missing_isolation:
            findings.append(
                _controlled_finding(
                    "low",
                    "headers",
                    "Derin taramada çapraz köken izolasyon başlıkları eksik",
                    "Uygulama yanıtında spekülatif yan kanal ve çapraz köken kaynak sızıntılarını sınırlayan COOP/COEP/CORP başlıkları eksik.",
                    "Eksik başlıklar: " + ", ".join(missing_isolation),
                    "Uygulama uyumluluğuna göre Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy ve Cross-Origin-Resource-Policy başlıklarını tanımlayın.",
                    "OWASP Secure Headers Project",
                    "SNIPER-CONF-07",
                )
            )

    score, grade, counts = calculate_score(findings)
    return {
        "format": "sniper-web-discovery-deep-audit-v1",
        "target_url": normalized.url,
        "score": score,
        "grade": grade,
        "counts": counts,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-INFO-03",
            "SNIPER-AUTH-11",
            "SNIPER-CRYP-06",
            "SNIPER-APIT-06",
            "SNIPER-CONF-07",
        ],
    }
