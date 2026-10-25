from __future__ import annotations

import bisect
import hashlib
import math
from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from project_tree import ProjectTree
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


# Gizlilik ilkesi: bu modül hiçbir koşulda ham sır değerini döndürmez.
# Kanıt alanlarında yalnızca maskeli önizleme ve SHA-256 parmak izi bulunur.

MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
MAX_FINDINGS_PER_FILE = 200
MAX_GENERIC_LINE_CHARS = 4_000

SECRET_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-CRYP-04",
    "SNIPER-CRYP-06",
    "SNIPER-DATA-09",
]

SECRET_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".java",
    ".kt", ".rb", ".php", ".cs", ".rs", ".swift", ".env", ".ini", ".cfg",
    ".conf", ".toml", ".yaml", ".yml", ".json", ".xml", ".properties",
    ".tf", ".sh", ".ps1", ".pem", ".key",
}

SECRET_FILENAMES: set[str] = {
    ".env", ".npmrc", ".pypirc", ".netrc", "docker-compose.yml", "docker-compose.yaml",
}

CLIENT_BUNDLE_EXTENSIONS: set[str] = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".vue", ".svelte",
}

CONFIG_EXTENSIONS: set[str] = {
    ".env", ".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml", ".properties",
    ".sh", ".ps1", ".tf", ".npmrc", ".pypirc", ".netrc",
}

WEAK_JWT_SECRETS: set[str] = {
    "secret", "changeme", "change_me", "change-me", "password", "123456",
    "12345678", "jwtsecret", "jwt_secret", "jwt-secret", "mysecret", "my_secret",
    "supersecret", "super_secret", "secretkey", "secret_key", "secret-key",
    "your-256-bit-secret", "your_jwt_secret", "default", "key", "test", "dev",
    "development", "qwerty", "admin", "token", "s3cr3t",
}


# ---------------------------------------------------------------------------
# Sağlayıcı profilleri: (görünen ad, etki alanı / blast radius, rotasyon adımları)
# ---------------------------------------------------------------------------

_GIT_HISTORY_STEP = "Git geçmişinden git filter-repo (veya BFG) ile temizleyin ve tüm klonları yenileyin"

PROVIDER_PROFILES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "aws": (
        "AWS",
        "IAM kimliğinin tüm izinleri; S3/EC2/IAM erişimi olası",
        (
            "aws iam create-access-key ile yeni anahtar üretin",
            "Uygulama sırlarını güncelleyin",
            "aws iam update-access-key --status Inactive ile eski anahtarı devre dışı bırakın",
            "CloudTrail üzerinde eski anahtarın kullanımını inceleyin",
            "aws iam delete-access-key ile silin",
            "Git geçmişinden git filter-repo ile temizleyin",
        ),
    ),
    "github": (
        "GitHub",
        "Token kapsamına göre depo okuma/yazma, Actions sırları ve organizasyon ayarlarına erişim",
        (
            "GitHub > Settings > Developer settings üzerinden token'ı hemen iptal edin (revoke)",
            "En dar kapsamlı fine-grained token üretin ve son kullanma tarihi verin",
            "CI/CD ve uygulama sırlarını güncelleyin",
            "Organizasyon audit log'unda token kullanımını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "gitlab": (
        "GitLab",
        "Token kapsamına göre proje kaynak kodu, CI değişkenleri ve registry erişimi",
        (
            "GitLab > Preferences > Access Tokens üzerinden token'ı iptal edin",
            "Gerekli en dar kapsamla ve son kullanma tarihli yeni token üretin",
            "CI/CD değişkenlerini güncelleyin",
            "Audit events kayıtlarında token kullanımını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "stripe": (
        "Stripe",
        "Canlı ödeme alma, iade, müşteri ve kart meta verilerine tam API erişimi",
        (
            "Stripe Dashboard > Developers > API keys üzerinden anahtarı 'Roll key' ile yenileyin",
            "Mümkünse yalnızca gerekli izinlere sahip restricted key kullanın",
            "Sunucu tarafı sır deposunu güncelleyin",
            "Dashboard > Logs üzerinde yetkisiz API çağrılarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "stripe_test": (
        "Stripe",
        "Yalnızca test modu verileri; canlı ödeme etkisi yok ancak hesap yapısını açığa çıkarır",
        (
            "Stripe Dashboard üzerinden test anahtarını yenileyin",
            "Test anahtarlarını da ortam değişkeninden okuyun",
            _GIT_HISTORY_STEP,
        ),
    ),
    "slack": (
        "Slack",
        "Çalışma alanında mesaj okuma/gönderme, kanal ve kullanıcı bilgilerine erişim",
        (
            "api.slack.com/apps üzerinden token'ı iptal edip uygulamayı yeniden yükleyin",
            "Bot token kapsamlarını en aza indirin",
            "Workspace access log'larını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "slack_webhook": (
        "Slack",
        "Bağlı kanala sahte veya oltalama mesajı gönderilebilir",
        (
            "Slack uygulama ayarlarından Incoming Webhook URL'sini silip yeniden oluşturun",
            "Webhook URL'sini sır yöneticisinde saklayın",
            _GIT_HISTORY_STEP,
        ),
    ),
    "openai": (
        "OpenAI",
        "Ücretli model kullanımı (maliyet), dosya, asistan ve fine-tune verilerine erişim",
        (
            "platform.openai.com > API keys üzerinden anahtarı iptal edin",
            "Proje bazlı yeni anahtar üretip harcama limitleri tanımlayın",
            "Usage panelinde anormal tüketimi inceleyin",
            "Uygulama sırlarını güncelleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "anthropic": (
        "Anthropic",
        "Ücretli model kullanımı (maliyet) ve çalışma alanı verilerine erişim",
        (
            "console.anthropic.com > API Keys üzerinden anahtarı devre dışı bırakın",
            "Yeni anahtar üretip harcama limitlerini kontrol edin",
            "Usage raporlarında anormal tüketimi inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "google_api": (
        "Google API",
        "Anahtarın kısıtlanmadığı tüm Google API'lerinde kota ve fatura kullanımı",
        (
            "Google Cloud Console > APIs & Services > Credentials üzerinden anahtarı yeniden oluşturun",
            "HTTP referrer, IP ve API kısıtlamaları uygulayın",
            "Eski anahtarı silin",
            "Faturalama ve kota raporlarını inceleyin",
        ),
    ),
    "gcp_service_account": (
        "GCP Service Account",
        "Servis hesabına bağlı IAM rollerinin tüm yetkileri (GCS, BigQuery, Compute vb.)",
        (
            "gcloud iam service-accounts keys list ile sızan anahtarı belirleyin",
            "gcloud iam service-accounts keys delete ile anahtarı silin",
            "Mümkünse Workload Identity Federation ile anahtarsız kimliğe geçin",
            "Cloud Audit Logs üzerinde anahtar kullanımını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "azure_storage": (
        "Azure Storage",
        "Depolama hesabındaki tüm blob, kuyruk, tablo ve dosya verilerine tam okuma-yazma",
        (
            "az storage account keys renew ile anahtarı yenileyin",
            "Uygulamaları Managed Identity veya kısa ömürlü SAS kullanımına taşıyın",
            "Storage Analytics / erişim loglarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "twilio": (
        "Twilio",
        "SMS/arama gönderme (maliyet ve oltalama riski), mesaj geçmişine erişim",
        (
            "Twilio Console > API keys üzerinden anahtarı silin",
            "Yeni API key üretip sırları güncelleyin",
            "Usage ve mesaj loglarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "sendgrid": (
        "SendGrid",
        "Alan adınız adına e-posta gönderme (oltalama) ve kişi listelerine erişim",
        (
            "SendGrid > Settings > API Keys üzerinden anahtarı silin",
            "Yalnızca Mail Send izinli yeni anahtar üretin",
            "Activity feed üzerinde yetkisiz gönderimleri inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "mailgun": (
        "Mailgun",
        "Alan adınız adına e-posta gönderme ve gönderim loglarına erişim",
        (
            "Mailgun > API Security üzerinden anahtarı yenileyin",
            "Domain bazlı sending key kullanın",
            "Gönderim loglarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "telegram": (
        "Telegram Bot",
        "Bot adına mesaj okuma/gönderme ve botun bulunduğu sohbetlere erişim",
        (
            "@BotFather üzerinde /revoke komutu ile token'ı iptal edin",
            "Yeni token'ı sır yöneticisine kaydedin",
            "Webhook ayarlarını (getWebhookInfo) kontrol edin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "discord_webhook": (
        "Discord",
        "Bağlı kanala sahte veya oltalama mesajı gönderilebilir",
        (
            "Kanal ayarları > Entegrasyonlar > Webhook üzerinden webhook'u silip yeniden oluşturun",
            "Webhook URL'sini sır yöneticisinde saklayın",
            _GIT_HISTORY_STEP,
        ),
    ),
    "npm": (
        "npm",
        "Paket yayımlama yetkisi; tedarik zinciri saldırısı riski",
        (
            "npm token revoke ile token'ı iptal edin",
            "Granular access token ve 2FA zorunluluğu kullanın",
            "Son yayımlanan paket sürümlerini doğrulayın",
            _GIT_HISTORY_STEP,
        ),
    ),
    "pypi": (
        "PyPI",
        "Paket yayımlama yetkisi; tedarik zinciri saldırısı riski",
        (
            "pypi.org > Account settings > API tokens üzerinden token'ı silin",
            "Proje kapsamlı token veya Trusted Publishing (OIDC) kullanın",
            "Son yayımlanan sürümleri doğrulayın",
            _GIT_HISTORY_STEP,
        ),
    ),
    "shopify": (
        "Shopify",
        "Mağaza Admin API'si: sipariş, müşteri ve ürün verilerine erişim",
        (
            "Shopify uygulama ayarlarından erişim token'ını yeniden oluşturun",
            "Uygulama kapsamlarını en aza indirin",
            "Mağaza aktivite loglarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "cloudflare": (
        "Cloudflare",
        "DNS, WAF ve zone ayarlarını değiştirme; trafiği yönlendirme",
        (
            "Cloudflare > My Profile > API Tokens üzerinden token'ı 'Roll' veya silin",
            "Zone ve izin bazında kısıtlı token üretin",
            "Audit Logs üzerinde değişiklikleri inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "heroku": (
        "Heroku",
        "Uygulama, config var ve veritabanı eklentilerine tam erişim",
        (
            "heroku authorizations:revoke ile yetkiyi iptal edin",
            "heroku authorizations:create ile kapsamlı yeni token üretin",
            "Uygulama aktivite loglarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "digitalocean": (
        "DigitalOcean",
        "Droplet, veritabanı ve Spaces kaynaklarını oluşturma/silme",
        (
            "Control Panel > API > Tokens üzerinden token'ı silin",
            "Kapsamlı (scoped) yeni token üretin",
            "Security history kayıtlarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
    "vault": (
        "HashiCorp Vault",
        "Token politikalarına bağlı tüm sırlara erişim",
        (
            "vault token revoke ile token'ı iptal edin",
            "Kısa TTL'li token ve AppRole/OIDC kimlik doğrulaması kullanın",
            "Vault audit log'unda erişilen yolları inceleyin",
            "Erişilen sırları rotasyona alın",
        ),
    ),
    "private_key": (
        "Özel anahtar",
        "Anahtarın kullanıldığı TLS/SSH/imzalama kimliğinin taklit edilmesi",
        (
            "Yeni anahtar çifti üretin",
            "Sertifikayı CA üzerinden iptal edin veya SSH authorized_keys listesinden kaldırın",
            "Anahtarı sır yöneticisine / HSM'ye taşıyın",
            _GIT_HISTORY_STEP,
        ),
    ),
    "jwt": (
        "JWT",
        "Token süresi dolana kadar ilgili kullanıcı oturumunun taklit edilmesi",
        (
            "İmzalama anahtarını döndürerek eski token'ları geçersiz kılın",
            "Kısa ömürlü erişim token'ları kullanın",
            "Kaynak kodda sabit token tutmayın",
        ),
    ),
    "database_url": (
        "Veritabanı bağlantısı",
        "Veritabanındaki verilere kullanıcı yetkileri ölçüsünde okuma/yazma erişimi",
        (
            "Veritabanı kullanıcısının parolasını değiştirin (ALTER USER ... PASSWORD ...)",
            "Bağlantı dizesini ortam değişkeni veya sır yöneticisinden okuyun",
            "Veritabanı erişim loglarını inceleyin",
            "Ağ erişimini IP allowlist ile kısıtlayın",
            _GIT_HISTORY_STEP,
        ),
    ),
    "weak_jwt": (
        "JWT HMAC anahtarı",
        "Saldırgan geçerli imzalı token üreterek herhangi bir kullanıcı veya rol olarak oturum açabilir",
        (
            "En az 256 bit rastgele anahtar üretin: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\"",
            "Anahtarı ortam değişkeni veya sır yöneticisinden okuyun",
            "Anahtar değişince mevcut tüm token'lar geçersizleşir; kullanıcıları yeniden oturum açmaya yönlendirin",
            "Mümkünse RS256/EdDSA gibi asimetrik imzalamaya geçin",
        ),
    ),
    "generic": (
        "Genel sır",
        "Sırrın koruduğu sisteme yetkisiz erişim",
        (
            "Sırrı ilgili sistemde hemen iptal edip yenisini üretin",
            "Yeni sırrı ortam değişkeni veya sır yöneticisinden okuyun",
            "İlgili sistemin erişim loglarını inceleyin",
            _GIT_HISTORY_STEP,
        ),
    ),
}


# ---------------------------------------------------------------------------
# Sağlayıcı dedektörleri: (profil, regex, önem, sunucu tarafı sırrı mı)
# Sıra önemlidir: daha özgül kalıplar önce gelir; çakışan aralıklar atlanır.
# Tüm niceleyiciler sınırlıdır ve karakter sınıfları ayırıcıları dışlar
# (felaket düzeyinde geri izleme oluşmaz).
# ---------------------------------------------------------------------------

_PROVIDER_DETECTORS: list[tuple[str, re.Pattern[str], str, bool]] = [
    ("aws", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "critical", True),
    (
        "aws",
        re.compile(
            r"(?i)aws_?secret_?access_?key[\"']?\s*(?::=|=>|=|:)\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        "critical",
        True,
    ),
    ("github", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"), "critical", True),
    ("github", re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"), "critical", True),
    ("gitlab", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,64})(?![A-Za-z0-9_\-])"), "critical", True),
    ("stripe", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,247})\b"), "critical", True),
    ("stripe_test", re.compile(r"\b(sk_test_[0-9A-Za-z]{16,247})\b"), "low", True),
    ("slack_webhook", re.compile(
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{6,20}/B[A-Za-z0-9_]{6,20}/[A-Za-z0-9_]{20,40})"
    ), "high", True),
    ("slack", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,250})"), "high", True),
    ("anthropic", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,200})"), "critical", True),
    ("openai", re.compile(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,300})"), "critical", True),
    ("openai", re.compile(r"\b(sk-[A-Za-z0-9]{40,200})\b"), "critical", True),
    ("google_api", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), "high", False),
    ("azure_storage", re.compile(r"AccountKey=([A-Za-z0-9+/=]{40,100})"), "critical", True),
    ("twilio", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "high", True),
    ("sendgrid", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])"), "high", True),
    ("mailgun", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"), "high", True),
    ("telegram", re.compile(r"\b(\d{8,10}:[A-Za-z0-9_\-]{35})(?![A-Za-z0-9_\-])"), "high", True),
    ("discord_webhook", re.compile(
        r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_\-]{50,80})"
    ), "high", True),
    ("npm", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "critical", True),
    ("pypi", re.compile(r"\b(pypi-AgEI[A-Za-z0-9_\-]{50,300})"), "critical", True),
    ("shopify", re.compile(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), "critical", True),
    (
        "cloudflare",
        re.compile(
            r"(?i)\b(?:cf|cloudflare)_?(?:api_?)?(?:token|key)[\"']?\s*(?::=|=>|=|:)\s*[\"']?([A-Za-z0-9_\-]{37,40})(?![A-Za-z0-9_\-])"
        ),
        "high",
        True,
    ),
    (
        "heroku",
        re.compile(
            r"(?i)heroku[A-Za-z0-9_]{0,20}[\"']?\s*(?::=|=>|=|:)\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
        ),
        "high",
        True,
    ),
    ("heroku", re.compile(r"\b(HRKU-[A-Za-z0-9_\-]{20,80})"), "high", True),
    ("digitalocean", re.compile(r"\b(do[opr]_v1_[a-f0-9]{64})\b"), "critical", True),
    ("vault", re.compile(r"\b(hvs\.[A-Za-z0-9_\-]{24,200})"), "critical", True),
    (
        "private_key",
        re.compile(
            r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r"(?:[A-Za-z0-9+/=\s\\:,\-]{0,10000}?-----END [A-Z ]{0,24}PRIVATE KEY(?: BLOCK)?-----)?)"
        ),
        "critical",
        True,
    ),
    (
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_\-]{10,4000}\.eyJ[A-Za-z0-9_\-]{10,8000}\.[A-Za-z0-9_\-]{10,2000})(?![A-Za-z0-9_\-])"
        ),
        "medium",
        False,
    ),
    (
        "database_url",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://"
            r"[^\s:/@\"'<>]{0,128}:(?P<secret>[^\s@/\"'<>]{1,256})@[^\s/\"'<>:]{1,253}"
        ),
        "high",
        True,
    ),
]

_GCP_SA_MARKER_RE = re.compile(r"[\"']type[\"']\s*:\s*[\"']service_account[\"']")
_GCP_PRIVATE_KEY_RE = re.compile(r"[\"']private_key[\"']\s*:\s*[\"'](-----BEGIN[^\"']{20,8000})[\"']")

# Sağlayıcıya özgü kalıplar için dar yer tutucu listesi ("test" burada yok;
# sk_test_ gibi gerçek önekleri yanlışlıkla elemesin).
_PROVIDER_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|xxxx|your[_\-]|dummy|placeholder|redacted|<[^>]{0,64}>|\$\{|\{\{|\*\*\*)"
)

# Genel atama dedektörü için geniş yer tutucu listesi.
_GENERIC_PLACEHOLDER_RE = re.compile(
    r"(?i)(changeme|change_me|change-me|example|xxxx|your[_\-]|yourkey|dummy|test|sample|"
    r"placeholder|redacted|fake|lorem|insert|replace|todo|\*\*\*|<[^>]{0,64}>|\$\{|\{\{|%\(|"
    r"os\.environ|process\.env|getenv|env\()"
)

_DB_PASSWORD_PLACEHOLDERS: set[str] = {"password", "pass", "passwd", "secret", "pwd", "changeme"}
# 4 karakterden kısa bağlantı dizesi parolaları (u:p@, a:b@) örnek/yer tutucu kabul edilir.
_DB_PASSWORD_MIN_LEN = 4

# .js/.ts dosyası bu işaretlerden birini taşıyorsa Node sunucu kodudur, tarayıcı paketi değildir.
_SERVER_JS_RE = re.compile(
    r"""(?:\brequire\(\s*["'](?:node:)?(?:fs|child_process|net|tls|http|https|os|path|crypto|cluster|"""
    r"""worker_threads|express|koa|fastify|@hapi/hapi|pg|mysql2?|mongodb|mongoose|sequelize|redis|ioredis|"""
    r"""knex|typeorm|prisma|@prisma/client|sqlite3|better-sqlite3)["']\s*\)"""
    r"""|\bfrom\s+["'](?:node:[a-z_/]+|fs|child_process|express|koa|fastify|pg|mysql2?|mongodb|mongoose|"""
    r"""sequelize|typeorm|@prisma/client|knex)["']"""
    r"""|\bprocess\.env\b|\bmodule\.exports\b|^#!.*\bnode\b)""",
    re.M,
)

# Genel dedektör: parola özetleri sır değildir; örnek/belge dosyalarındaki değerler örnektir.
_PASSWORD_HASH_RE = re.compile(r"^(?:\$(?:argon2(?:id|i|d)?|2[abxy]|scrypt|pbkdf2(?:-sha\d+)?|[156])\$|pbkdf2_sha\d+\$|bcrypt\$)")
_GENERIC_EXTRA_PLACEHOLDER_RE = re.compile(
    r"(?i)fixme|change[_\-]?(?:me|it)|not[_\-]?a[_\-]?secret|no[_\-]?api[_\-]?key|"
    r"not[_\-]?used[_\-]?at[_\-]?runtime|build[_\-]?only"
)
_EXAMPLE_FILE_RE = re.compile(r"(?i)(?:\.(?:example|sample|template|dist|tmpl)$|(?:^|/)(?:docs?|docs_src)/)")

_GENERIC_NAME_HINT_RE = re.compile(
    r"(?i)(secret|token|api_?key|apikey|api-key|passwd|password|pwd|private_?key|"
    r"client_?secret|access_?key|auth_?key|credential)"
)
_GENERIC_NAME_EXCLUDE_RE = re.compile(
    r"(?i)(?:url|uri|endpoint|path|file|filename|name|field|label|type|length|len|regex|"
    r"pattern|placeholder|header|prompt|hint|message|msg|policy|expiry|expires|ttl|count|"
    r"id|prefix|format|min|max|required|enabled|validator|"
    r"(?:prompt|completion|total|max|input|output|cached|reasoning|num)[_\-]?tokens?|"
    r"token[_\-]?(?:count|usage|limit|budget)s?|"
    r"^no[_\-]?api[_\-]?key)$"
)
_GENERIC_ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.\-]{0,80})[\"']?\s*(?::=|=>|=|:)\s*"
    r"(?:[rbuRBUfF]{0,2}(?P<q>[\"'`])(?P<qv>[^\"'`\r\n]{16,512})(?P=q)"
    r"|(?P<uv>[A-Za-z0-9+/=_\-.~!@$%^&*]{16,512})(?=\s|$|[;,#]))"
)

_WEAK_JWT_ASSIGN_RE = re.compile(
    r"(?i)\b(?:jwt_?secret(?:_?key)?|jwt_?key|jwt_?signing_?key|secret_?key|token_?secret|signing_?key)"
    r"[\"'\]]{0,2}\s*(?::=|=>|=|:)\s*[rbuf]{0,2}(?P<q>[\"'`])(?P<v>[^\"'`\r\n]{0,512})(?P=q)"
)
_WEAK_JWT_CALL_RE = re.compile(
    r"\bjwt\.(?:encode|sign|decode|verify)\s*\(\s*[^,\n]{1,300},\s*[rbuf]{0,2}"
    r"(?P<q>[\"'`])(?P<v>[^\"'`\r\n]{0,512})(?P=q)"
)
_TEMPLATE_RE = re.compile(r"(\$\{|\{\{|%\(|<[^>]{0,64}>|os\.environ|process\.env|getenv)")


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def shannon_entropy(value: str) -> float:
    """Karakter başına Shannon entropisi (bit)."""
    if not isinstance(value, str) or not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _mask(value: str) -> str:
    if len(value) < 10:
        return "…"
    return f"{value[:4]}…{value[-2:]}"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _effective_ext(filename: str) -> str:
    name = Path(filename).name.lower()
    if name == ".env" or name.startswith(".env."):
        return ".env"
    if name in {".npmrc", ".pypirc", ".netrc"}:
        return name
    return Path(name).suffix.lower()


def _is_config_file(filename: str) -> bool:
    return _effective_ext(filename) in CONFIG_EXTENSIONS


def _is_secret_candidate(name: str) -> bool:
    lowered = name.lower()
    if lowered in SECRET_FILENAMES or lowered.startswith(".env."):
        return True
    return Path(lowered).suffix in SECRET_EXTENSIONS


def _line_starts(content: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\n", content))
    return starts


def _make_secret_finding(
    *,
    provider_key: str,
    value: str,
    filename: str,
    line: int,
    severity: str,
    control_id: str,
    cwe: str,
) -> dict[str, Any]:
    display, blast_radius, playbook = PROVIDER_PROFILES.get(provider_key, PROVIDER_PROFILES["generic"])
    masked = _mask(value)
    fingerprint = _fingerprint(value)
    entropy = round(shannon_entropy(value), 2)

    if control_id == "SNIPER-CRYP-06":
        title = "Zayıf veya tahmin edilebilir JWT HMAC imzalama anahtarı"
        description = (
            "JWT imzalama anahtarı kaynak kodda sabit ve zayıf (bilinen değer, 32 karakterden kısa "
            f"veya düşük entropili). Etki: {blast_radius}."
        )
        recommendation = (
            "En az 256 bit kriptografik rastgele anahtar kullanın, anahtarı sır yöneticisinden okuyun "
            "ve anahtarı döndürün."
        )
        reference = f"OWASP ASVS V3.5 / V6.4 · RFC 8725 · {cwe}"
    elif control_id == "SNIPER-DATA-09":
        title = f"İstemci paketinde sunucu tarafı {display} sırrı"
        description = (
            f"Tarayıcıya gönderilebilecek bir dosyada sunucu tarafında kalması gereken {display} sırrı "
            f"bulundu; paketi indiren herkes sırrı okuyabilir. Etki: {blast_radius}."
        )
        recommendation = (
            "Sırrı istemci kodundan kaldırın, çağrıyı sunucu tarafı bir proxy/uç nokta üzerinden yapın "
            "ve sırrı hemen döndürün."
        )
        reference = f"OWASP ASVS V14.3 / V6.4 · OWASP A02:2021 · {cwe}"
    else:
        title = f"Kaynakta gömülü {display} sırrı"
        description = (
            f"Kaynak veya yapılandırma dosyasında sabit kodlanmış {display} kimlik bilgisi bulundu. "
            f"Etki: {blast_radius}."
        )
        recommendation = (
            "Sırrı hemen döndürün (rotasyon), kaynak koddan kaldırın ve ortam değişkeni veya sır "
            "yöneticisinden (Vault, AWS Secrets Manager vb.) okuyun."
        )
        reference = f"OWASP ASVS V6.4 / V14.3 · OWASP A07:2021 · {cwe}"

    evidence = f"{filename}:{line} · sağlayıcı={display} · önizleme={masked} · sha256={fingerprint[:16]}"
    item = _finding(
        severity,
        "data",
        title,
        description,
        evidence,
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, fingerprint[:16]),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    item["provider"] = display
    item["provider_id"] = provider_key
    item["masked_preview"] = masked
    item["fingerprint_sha256"] = fingerprint
    item["entropy"] = entropy
    item["blast_radius"] = blast_radius
    item["rotation_playbook"] = list(playbook)
    return item


def _scan_secret_content(content: str, filename: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    spans: list[tuple[int, int]] = []
    line_starts = _line_starts(content)
    ext = _effective_ext(filename)
    is_client = ext in CLIENT_BUNDLE_EXTENSIONS and not (
        ext in {".js", ".mjs", ".cjs", ".ts"} and _SERVER_JS_RE.search(content)
    )
    is_config = _is_config_file(filename)

    def _overlaps(start: int, end: int) -> bool:
        return any(start < span_end and span_start < end for span_start, span_end in spans)

    def _record(
        provider_key: str,
        value: str,
        start: int,
        end: int,
        severity: str,
        server_side: bool,
        *,
        control_id: str = "SNIPER-CRYP-04",
        cwe: str = "CWE-798",
    ) -> None:
        if len(findings) >= MAX_FINDINGS_PER_FILE or not value:
            return
        if _overlaps(start, end):
            return
        spans.append((start, end))
        fingerprint = _fingerprint(value)
        if fingerprint in seen_fingerprints:
            return
        seen_fingerprints.add(fingerprint)
        if control_id == "SNIPER-CRYP-04" and is_client and server_side:
            control_id = "SNIPER-DATA-09"
        line = bisect.bisect_right(line_starts, start)
        findings.append(
            _make_secret_finding(
                provider_key=provider_key,
                value=value,
                filename=filename,
                line=line,
                severity=severity,
                control_id=control_id,
                cwe=cwe,
            )
        )

    # 1. GCP servis hesabı JSON (private_key alanı)
    if _GCP_SA_MARKER_RE.search(content):
        for match in _GCP_PRIVATE_KEY_RE.finditer(content):
            _record("gcp_service_account", match.group(1), match.start(1), match.end(1), "critical", True)

    # 2. Sağlayıcıya özgü kalıplar
    for provider_key, pattern, severity, server_side in _PROVIDER_DETECTORS:
        for match in pattern.finditer(content):
            group_name: str | int = "secret" if "secret" in pattern.groupindex else 1
            value = match.group(group_name)
            if not value:
                continue
            if provider_key == "database_url":
                lowered = value.lower()
                if (
                    lowered in _DB_PASSWORD_PLACEHOLDERS
                    or len(value) < _DB_PASSWORD_MIN_LEN
                    or value[:1] in {"$", "%", "{", "<"}
                    or _PROVIDER_PLACEHOLDER_RE.search(value)
                ):
                    continue
            elif provider_key not in {"private_key", "jwt"} and _PROVIDER_PLACEHOLDER_RE.search(value):
                continue
            _record(
                provider_key,
                value,
                match.start(group_name),
                match.end(group_name),
                severity,
                server_side,
            )

    # 3. Zayıf JWT HMAC anahtarı (SNIPER-CRYP-06)
    for pattern, allow_empty in ((_WEAK_JWT_ASSIGN_RE, False), (_WEAK_JWT_CALL_RE, True)):
        for match in pattern.finditer(content):
            raw_value = match.group("v")
            value = raw_value.strip()
            if not value and not allow_empty:
                continue
            if value and _TEMPLATE_RE.search(value):
                continue
            lowered = value.lower()
            weak = (
                lowered in WEAK_JWT_SECRETS
                or lowered.startswith("django-insecure-")
                or len(value) < 32
                or shannon_entropy(value) < 3.0
            )
            if not weak:
                continue
            start = match.start("v")
            end = max(match.end("v"), start + 1)
            # Boş anahtar için parmak izi tanımlı kalsın diye konum etiketli değer kullanılır.
            fingerprint_source = raw_value if raw_value else f"<empty-jwt-secret@{filename}:{start}>"
            _record(
                "weak_jwt",
                fingerprint_source,
                start,
                end,
                "high",
                True,
                control_id="SNIPER-CRYP-06",
                cwe="CWE-1391",
            )

    # 4. Genel yüksek entropili atama dedektörü (örnek/belge dosyalarında çalışmaz)
    generic_lines = () if _EXAMPLE_FILE_RE.search(filename.replace("\\", "/")) else line_starts
    for index, line_start in enumerate(generic_lines):
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            break
        line_end = line_starts[index + 1] if index + 1 < len(line_starts) else len(content)
        line_text = content[line_start:line_end]
        if len(line_text) > MAX_GENERIC_LINE_CHARS or not _GENERIC_NAME_HINT_RE.search(line_text):
            continue
        for match in _GENERIC_ASSIGN_RE.finditer(line_text):
            name = match.group("name")
            if not _GENERIC_NAME_HINT_RE.search(name) or _GENERIC_NAME_EXCLUDE_RE.search(name):
                continue
            if match.group("qv") is not None:
                group_name = "qv"
            elif match.group("uv") is not None and is_config:
                group_name = "uv"
            else:
                continue
            value = match.group(group_name)
            if (
                len(value) < 16
                or any(char.isspace() for char in value)
                or value.startswith(("/", "./", "~"))
                or "://" in value
                or _GENERIC_PLACEHOLDER_RE.search(value)
                or _GENERIC_EXTRA_PLACEHOLDER_RE.search(value)
                or _PASSWORD_HASH_RE.match(value)
                or len(set(value)) <= 3
                or shannon_entropy(value) < 3.5
            ):
                continue
            _record(
                "generic",
                value,
                line_start + match.start(group_name),
                line_start + match.end(group_name),
                "medium",
                True,
            )

    return findings


def _validate_inline(raw_content: str) -> None:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Sır taraması için kaynak içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")


def _summary(findings: list[dict[str, Any]]) -> tuple[list[str], int]:
    providers = sorted({str(item["provider"]) for item in findings})
    secret_count = len({str(item["fingerprint_sha256"]) for item in findings})
    return providers, secret_count


def audit_secrets_inline(
    raw_content: str,
    *,
    filename: str = "config.env",
) -> dict[str, Any]:
    _validate_inline(raw_content)
    if not isinstance(filename, str) or not filename.strip():
        filename = "config.env"
    clean_filename = filename.strip()
    findings = _scan_secret_content(raw_content, clean_filename)
    providers, secret_count = _summary(findings)
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-secret-intelligence-inline-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(SECRET_CONTROLS_EVALUATED),
        "providers_detected": providers,
        "secret_count": secret_count,
    }


@project_scan_scope
def audit_secrets_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    with ProjectTree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=SKIP_DIRS, reject_unsafe=False):
            if scanned_files >= MAX_PROJECT_FILES:
                break
            if not _is_secret_candidate(project_file.name):
                continue
            if project_file.size == 0 or project_file.size > MAX_INLINE_BYTES:
                continue
            content = tree.read_text(project_file, MAX_INLINE_BYTES, errors="replace")
            if not content.strip():
                continue
            rel_name = project_file.path.as_posix()
            scanned_files += 1
            findings.extend(_scan_secret_content(content, rel_name))

    providers, secret_count = _summary(findings)
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    return {
        "format": "sniper-secret-intelligence-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(SECRET_CONTROLS_EVALUATED),
        "providers_detected": providers,
        "secret_count": secret_count,
    }
