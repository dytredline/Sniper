"""Proje analizinden otomatik tehdit modeli: rota envanteri, veri akış diyagramı (DFD) ve STRIDE tehditleri.

Girdi, proje analizinin zaten okuduğu dosya metinleridir (``ThreatModelCollector.add``); kaynak kod ve sır değerleri
modele kopyalanmaz: yalnız rota yolu, işleyici adı, dosya:satır, kütüphane adı ve (literal) dış ana makine adı saklanır.

Model öğeleri:
* ``external`` — dış varlıklar (istemci, üçüncü taraf HTTP servisleri, e-posta, bulut servisleri)
* ``process``  — uygulama servisleri (bildirim dosyasına göre servis kökü; monorepo'da birden çok)
* ``store``    — veri depoları (SQL, NoSQL/önbellek, kuyruk, dosya sistemi, ortam değişkenleri/sırlar)
* ``flows``    — öğeler arası veri akışları; güven sınırını geçenler işaretli
* ``boundaries`` — güven sınırları (İnternet, veri katmanı, üçüncü taraflar, ana makine)
* ``threats``  — STRIDE tehditleri; mevcut bulgulara (CWE) bağlı olanlar "bulgu var", diğerleri "gözden geçirilecek"

Rota listesi birleştirme için basit tutulur: ``{method, path, handler, file, line, framework, service}``.
"""
from __future__ import annotations

import ast
import html
from pathlib import PurePosixPath
import re
from typing import Any, Iterable

MODEL_FORMAT = "sniper-threat-model-v1"
MAX_ROUTES = 400
MAX_HOSTS = 12

STRIDE_LABELS = {
    "S": "Kimlik sahteciliği (Spoofing)",
    "T": "Kurcalama (Tampering)",
    "R": "İnkâr (Repudiation)",
    "I": "Bilgi ifşası (Information disclosure)",
    "D": "Hizmet engelleme (Denial of service)",
    "E": "Yetki yükseltme (Elevation of privilege)",
}

# İçe aktarma kökü → (bileşen türü, görünen ad). Tür: framework | sql | nosql | cache | queue | cloud | http | email |
# auth | env | fs | template
_COMPONENTS: dict[str, tuple[str, str]] = {
    # web çatıları
    "flask": ("framework", "Flask"), "django": ("framework", "Django"), "fastapi": ("framework", "FastAPI"),
    "starlette": ("framework", "Starlette"), "quart": ("framework", "Quart"), "sanic": ("framework", "Sanic"),
    "falcon": ("framework", "Falcon"), "tornado": ("framework", "Tornado"), "bottle": ("framework", "Bottle"),
    "pyramid": ("framework", "Pyramid"), "connexion": ("framework", "Connexion"),
    "express": ("framework", "Express"), "koa": ("framework", "Koa"), "@koa/router": ("framework", "Koa"),
    "koa-router": ("framework", "Koa"), "fastify": ("framework", "Fastify"), "@nestjs/core": ("framework", "NestJS"),
    "@nestjs/common": ("framework", "NestJS"), "@hapi/hapi": ("framework", "hapi"), "hapi": ("framework", "hapi"),
    "restify": ("framework", "restify"), "next": ("framework", "Next.js"), "apollo-server": ("framework", "Apollo GraphQL"),
    "@apollo/server": ("framework", "Apollo GraphQL"), "graphene": ("framework", "Graphene GraphQL"),
    "strawberry": ("framework", "Strawberry GraphQL"), "ariadne": ("framework", "Ariadne GraphQL"),
    # SQL
    "sqlite3": ("sql", "SQLite"), "better-sqlite3": ("sql", "SQLite"), "psycopg2": ("sql", "PostgreSQL"),
    "psycopg": ("sql", "PostgreSQL"), "asyncpg": ("sql", "PostgreSQL"), "pg": ("sql", "PostgreSQL"),
    "pymysql": ("sql", "MySQL"), "mysqldb": ("sql", "MySQL"), "mysql": ("sql", "MySQL"), "mysql2": ("sql", "MySQL"),
    "aiomysql": ("sql", "MySQL"), "mssql": ("sql", "SQL Server"), "pyodbc": ("sql", "ODBC"), "oracledb": ("sql", "Oracle"),
    "cx_oracle": ("sql", "Oracle"), "sqlalchemy": ("sql", "SQLAlchemy"), "peewee": ("sql", "Peewee"),
    "tortoise": ("sql", "Tortoise ORM"), "sequelize": ("sql", "Sequelize"), "knex": ("sql", "Knex"),
    "typeorm": ("sql", "TypeORM"), "@prisma/client": ("sql", "Prisma"), "mikro-orm": ("sql", "MikroORM"),
    "django.db": ("sql", "Django ORM"),
    # NoSQL / önbellek / arama
    "pymongo": ("nosql", "MongoDB"), "motor": ("nosql", "MongoDB"), "mongoengine": ("nosql", "MongoDB"),
    "mongodb": ("nosql", "MongoDB"), "mongoose": ("nosql", "MongoDB"), "mongojs": ("nosql", "MongoDB"),
    "cassandra": ("nosql", "Cassandra"), "elasticsearch": ("nosql", "Elasticsearch"),
    "@elastic/elasticsearch": ("nosql", "Elasticsearch"), "couchbase": ("nosql", "Couchbase"),
    "redis": ("cache", "Redis"), "ioredis": ("cache", "Redis"), "aioredis": ("cache", "Redis"),
    "memcache": ("cache", "Memcached"), "pymemcache": ("cache", "Memcached"),
    # kuyruk
    "celery": ("queue", "Celery"), "kombu": ("queue", "AMQP"), "pika": ("queue", "RabbitMQ"),
    "aio_pika": ("queue", "RabbitMQ"), "amqplib": ("queue", "RabbitMQ"), "kafka": ("queue", "Kafka"),
    "confluent_kafka": ("queue", "Kafka"), "kafkajs": ("queue", "Kafka"), "bull": ("queue", "Bull"),
    "bullmq": ("queue", "BullMQ"), "rq": ("queue", "RQ"), "nats": ("queue", "NATS"),
    # bulut
    "boto3": ("cloud", "AWS"), "botocore": ("cloud", "AWS"), "aws-sdk": ("cloud", "AWS"), "@aws-sdk": ("cloud", "AWS"),
    "google.cloud": ("cloud", "Google Cloud"), "@google-cloud": ("cloud", "Google Cloud"), "azure": ("cloud", "Azure"),
    "@azure": ("cloud", "Azure"), "firebase_admin": ("cloud", "Firebase"), "firebase-admin": ("cloud", "Firebase"),
    "firebase": ("cloud", "Firebase"),
    # HTTP istemcileri (dış servis)
    "requests": ("http", "requests"), "httpx": ("http", "httpx"), "urllib3": ("http", "urllib3"),
    "urllib.request": ("http", "urllib"), "aiohttp.client": ("http", "aiohttp istemcisi"), "axios": ("http", "axios"),
    "node-fetch": ("http", "node-fetch"), "got": ("http", "got"), "superagent": ("http", "superagent"),
    "request": ("http", "request"), "needle": ("http", "needle"), "undici": ("http", "undici"),
    "pycurl": ("http", "pycurl"),
    # e-posta
    "smtplib": ("email", "SMTP"), "nodemailer": ("email", "SMTP (nodemailer)"), "flask_mail": ("email", "SMTP"),
    "sendgrid": ("email", "SendGrid"), "@sendgrid/mail": ("email", "SendGrid"),
    # kimlik doğrulama
    "flask_login": ("auth", "Flask-Login"), "flask_jwt_extended": ("auth", "Flask-JWT-Extended"),
    "django.contrib.auth": ("auth", "Django auth"), "fastapi.security": ("auth", "FastAPI security"),
    "passport": ("auth", "Passport"), "jsonwebtoken": ("auth", "JWT"), "jwt": ("auth", "JWT"), "jose": ("auth", "JOSE"),
    "express-session": ("auth", "Oturum (express-session)"), "cookie-session": ("auth", "Oturum (cookie-session)"),
    "bcrypt": ("auth", "bcrypt"), "bcryptjs": ("auth", "bcrypt"), "argon2": ("auth", "Argon2"),
    "passlib": ("auth", "passlib"), "authlib": ("auth", "Authlib"), "oauthlib": ("auth", "OAuth"),
    "@nestjs/passport": ("auth", "Passport"), "next-auth": ("auth", "NextAuth"), "flask_httpauth": ("auth", "HTTP auth"),
    "rest_framework.permissions": ("auth", "DRF izinleri"), "rest_framework_simplejwt": ("auth", "DRF JWT"),
    # ortam / sırlar
    "dotenv": ("env", "dotenv"), "decouple": ("env", "python-decouple"), "environ": ("env", "django-environ"),
    # dosya sistemi
    "fs": ("fs", "fs"), "fs/promises": ("fs", "fs"), "shutil": ("fs", "shutil"), "multer": ("fs", "Dosya yükleme (multer)"),
    "express-fileupload": ("fs", "Dosya yükleme"), "formidable": ("fs", "Dosya yükleme"),
    # günlük
    "logging": ("log", "logging"), "structlog": ("log", "structlog"), "loguru": ("log", "loguru"),
    "winston": ("log", "winston"), "pino": ("log", "pino"), "bunyan": ("log", "bunyan"), "morgan": ("log", "morgan"),
}

_STORE_LABELS = {
    "sql": "İlişkisel veritabanı", "nosql": "NoSQL / belge deposu", "cache": "Önbellek", "queue": "Mesaj kuyruğu",
    "fs": "Dosya sistemi", "env": "Ortam değişkenleri / sırlar",
}
_EXTERNAL_LABELS = {"http": "Üçüncü taraf HTTP servisleri", "email": "E-posta sunucusu", "cloud": "Bulut servisleri"}

# CWE → (öğe türü, STRIDE) eşlemesi
_CWE_THREATS: dict[str, tuple[tuple[str, str], ...]] = {}


def _cwes(*items: int) -> set[str]:
    return {str(i) for i in items}


_THREAT_TEMPLATES: list[dict[str, Any]] = [
    # İnternet → uygulama sınırı
    {"element": "client_flow", "stride": "S", "title": "İstemci kimliğinin taklidi / zayıf kimlik doğrulama",
     "cwes": _cwes(287, 306, 798, 522, 384, 613, 1004, 614, 521, 307, 640, 1275, 345, 347),
     "needs": "auth", "hint": "Kimlik doğrulama, oturum ve belirteç doğrulamasını gözden geçirin."},
    {"element": "client_flow", "stride": "T", "title": "İstek verisiyle kurcalama ve enjeksiyon",
     "cwes": _cwes(79, 80, 89, 943, 78, 77, 94, 95, 22, 23, 73, 611, 918, 601, 1321, 502, 1336, 917, 90, 643, 113, 74, 352, 434, 915),
     "hint": "Girdi doğrulama, çıktı kodlama ve parametreli sorguları doğrulayın."},
    {"element": "client_flow", "stride": "R", "title": "İşlemlerin izlenememesi (güvenlik günlüğü eksikliği)",
     "cwes": _cwes(117, 778, 223, 532), "needs": "log",
     "hint": "Kimlik doğrulama, yetki reddi ve kritik işlemler değiştirilemez biçimde günlüklenmeli."},
    {"element": "client_flow", "stride": "I", "title": "Yanıt, hata ve başlıklarla bilgi sızması",
     "cwes": _cwes(200, 209, 215, 548, 359, 312, 319, 1004, 942, 693, 1021, 16),
     "hint": "Hata ayrıntıları, CORS ve güvenlik başlıklarını gözden geçirin."},
    {"element": "client_flow", "stride": "D", "title": "Hizmet engelleme (ReDoS, sınırsız kaynak, oran sınırı yok)",
     "cwes": _cwes(1333, 400, 770, 799, 307, 409, 674, 1325),
     "hint": "Oran sınırı, istek boyutu ve düzenli ifade karmaşıklığını sınırlayın."},
    {"element": "client_flow", "stride": "E", "title": "Eksik yetki denetimi / nesne düzeyi yetki (IDOR)",
     "cwes": _cwes(862, 863, 639, 285, 269, 284, 266, 425),
     "hint": "Her rota ve nesne erişiminde yetki ve sahiplik denetimi olmalı."},
    # Süreç
    {"element": "process", "stride": "E", "title": "Kod/komut yürütme ve güvensiz seri çözme ile süreç ele geçirme",
     "cwes": _cwes(78, 77, 94, 95, 502, 917, 1336, 470, 829),
     "hint": "eval/exec, kabuk komutları, şablon derleme ve seri çözmeyi güvenilmeyen veriden ayırın."},
    {"element": "process", "stride": "T", "title": "Prototip kirletme / bellek içi durumun kurcalanması",
     "cwes": _cwes(1321, 915, 471), "hint": "Nesne birleştirmelerinde __proto__/constructor anahtarlarını engelleyin."},
    # Veri depoları
    {"element": "store:sql", "stride": "T", "title": "SQL enjeksiyonu ile verinin değiştirilmesi",
     "cwes": _cwes(89, 564, 566), "hint": "Parametreli sorgu / ORM kullanın; ham SQL birleştirmeyin."},
    {"element": "store:nosql", "stride": "T", "title": "NoSQL operatör enjeksiyonu",
     "cwes": _cwes(943, 1336), "hint": "Sorgu nesnelerine istek nesnesini doğrudan vermeyin; tür zorlayın."},
    {"element": "store:*", "stride": "I", "title": "Depolanan verinin ifşası (şifreleme, zayıf parola özeti)",
     "cwes": _cwes(311, 312, 256, 916, 327, 328, 759, 760, 261), "hint": "Hassas alanları şifreleyin; parola için KDF kullanın."},
    {"element": "store:fs", "stride": "T", "title": "Yol geçişi ve dosya yükleme ile dosya sisteminin kurcalanması",
     "cwes": _cwes(22, 23, 36, 73, 434, 59), "hint": "Dosya adlarını normalize edin, kök dizinle sınırlayın."},
    {"element": "store:env", "stride": "I", "title": "Sırların koda/günlüğe sızması",
     "cwes": _cwes(798, 522, 256, 532, 540, 547, 321), "hint": "Sırları gizli yönetimde tutun; günlüklere yazmayın."},
    # Dış servisler
    {"element": "external:http", "stride": "T", "title": "Sunucu taraflı istek sahteciliği (SSRF) ve uzak yanıta güven",
     "cwes": _cwes(918, 441, 20), "hint": "Giden istek hedeflerini izin listesiyle sınırlayın; uzak yanıtı doğrulayın."},
    {"element": "external:http", "stride": "S", "title": "TLS doğrulamasının kapatılması (sahte uç nokta)",
     "cwes": _cwes(295, 297, 599), "hint": "Sertifika ve ana makine adı doğrulamasını kapatmayın."},
    {"element": "external:*", "stride": "I", "title": "Üçüncü taraflara şifresiz/aşırı veri aktarımı",
     "cwes": _cwes(319, 201, 359), "hint": "Dış servislere yalnız gerekli veriyi, TLS üzerinden gönderin."},
]

_ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket", "options", "head"}
# Yalnız rota tanımı biçimleri: @x.route/@x.get(...) dekoratörleri, Django urlpatterns ve kayıt çağrıları.
_PY_ROUTE_HINT = re.compile(r"^\s*@[\w.]+\.(?:route|get|post|put|patch|delete|api_route|websocket|head|options)\s*\(|"
                            r"\burlpatterns\b|\bfrom\s+django\.(?:urls|conf\.urls)\s+import\b|"
                            r"\.(?:add_url_rule|add_route|add_get|add_post|add_put|add_delete|add_patch)\s*\(", re.M)
_JS_SERVER_HINT = re.compile(r"""require\(\s*['"](?:express|koa|@koa/router|koa-router|fastify|restify|@hapi/hapi)['"]\)|from\s+['"](?:express|koa|@koa/router|koa-router|fastify|restify|@hapi/hapi|@nestjs/common)['"]|\bRouter\s*\(""")
_JS_ROUTE_RE = re.compile(
    r"""(?<![\w$])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\.\s*(get|post|put|patch|delete|del|all|head|options|use)\s*\(\s*(['"`])([^'"`\n]{0,200})\3\s*(?:,\s*([^\n]{0,300}))?""")
_JS_ROUTE_CHAIN_RE = re.compile(r"""\.route\s*\(\s*(['"`])([^'"`\n]{0,200})\1\s*\)((?:\s*\.\s*(?:get|post|put|patch|delete|all)\s*\()+)""")
_JS_OWNER_BLOCKLIST = {"axios", "http", "https", "client", "request", "fetch", "$", "jquery", "api", "res", "req", "response",
                       "map", "cache", "headers", "params", "query", "session", "localstorage", "store", "config", "settings",
                       "this", "object", "array", "url", "searchparams", "formdata", "redis", "db", "knex"}
_NEST_CONTROLLER_RE = re.compile(r"""@Controller\s*\(\s*(?:['"`]([^'"`]*)['"`])?""")
_URL_HOST_RE = re.compile(r"""['"`]https?://([A-Za-z0-9.-]{3,253})(?::\d+)?[/'"`?]""")
_JS_IMPORT_LINE_RE = re.compile(r"""(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)|import\s+['"]([^'"]+)['"])""")
_PY_IMPORT_LINE_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))")
_ENV_RE = re.compile(r"\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\bgetenv\s*\(")
_FS_PY_RE = re.compile(r"\bopen\s*\([^)\n]*['\"][wa]b?\+?['\"]|\bos\.(?:remove|unlink|rename|makedirs)\s*\(|\.save\s*\(\s*os\.path\.join")
_FETCH_RE = re.compile(r"(?<![\w$.])fetch\s*\(")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "example.net"}
_MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "setup.py", "pipfile", "go.mod", "pom.xml",
              "build.gradle", "build.gradle.kts", "composer.json", "gemfile", "cargo.toml"}


def _openapi_path_key(text: str) -> str | None:
    """Parse one YAML path key without overlapping wildcard backtracking."""
    cursor = 0
    if cursor < len(text) and text[cursor] in "'\"":
        cursor += 1
    if cursor >= len(text) or text[cursor] != "/":
        return None
    start = cursor
    while cursor < len(text) and text[cursor] not in {"'", '"', ":"}:
        cursor += 1
    path = text[start:cursor]
    if cursor < len(text) and text[cursor] in "'\"":
        cursor += 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or text[cursor] != ":":
        return None
    cursor += 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    return path if cursor == len(text) else None


_NEST_ROUTE_METHODS = ("Get", "Post", "Put", "Patch", "Delete", "All", "Head", "Options")
_NEST_ROUTE_MODIFIERS = ("public", "private", "async")


def _iter_nest_routes(text: str):
    """Yield NestJS decorator routes with a forward-only source scan."""
    cursor = 0
    while (start := text.find("@", cursor)) >= 0:
        method = next((name for name in _NEST_ROUTE_METHODS if text.startswith(name, start + 1)), None)
        if method is None:
            cursor = start + 1
            continue
        pos = start + 1 + len(method)
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text) or text[pos] != "(":
            cursor = start + 1
            continue
        pos += 1
        while pos < len(text) and text[pos].isspace():
            pos += 1

        path = ""
        if pos < len(text) and text[pos] in "'\"`":
            pos += 1
            path_start = pos
            while pos < len(text) and text[pos] not in "'\"`":
                pos += 1
            if pos >= len(text):
                cursor = start + 1
                continue
            path = text[path_start:pos]
            pos += 1

        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text) or text[pos] != ")":
            cursor = start + 1
            continue
        pos += 1
        saw_newline = False
        while pos < len(text) and text[pos].isspace():
            saw_newline = saw_newline or text[pos] == "\n"
            pos += 1
        if not saw_newline:
            cursor = start + 1
            continue

        while True:
            modifier = next((name for name in _NEST_ROUTE_MODIFIERS if text.startswith(name, pos)), None)
            if modifier is None:
                break
            end = pos + len(modifier)
            if end >= len(text) or not text[end].isspace():
                break
            pos = end + 1
            while pos < len(text) and text[pos].isspace():
                pos += 1

        if pos >= len(text) or text[pos] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$":
            cursor = start + 1
            continue
        handler_start = pos
        pos += 1
        while pos < len(text) and (text[pos].isalnum() or text[pos] in "_$"):
            pos += 1
        yield start, method, path, text[handler_start:pos]
        cursor = pos


def _js_handler_name(rest: str) -> str:
    """Rota çağrısının son bağımsız değişkeni: tanıtıcı zinciri ise adı, satır içi fonksiyonsa "(anonim)"."""
    if not rest:
        return "?"
    depth, args, current = 0, [], ""
    for ch in rest:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
            continue
        current += ch
    args.append(current.strip())
    last = next((a for a in reversed(args) if a), "")
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", last):
        return last
    if last.startswith(("function", "async", "(")) or "=>" in last:
        return "(anonim)"
    named = re.match(r"([A-Za-z_$][\w$.]*)\s*\(", last)
    return named.group(1) + "()" if named else "?"


def _component_for(spec: str) -> tuple[str, str] | None:
    spec = spec.strip().casefold()
    if not spec or spec.startswith("."):
        return None
    if spec in _COMPONENTS:
        return _COMPONENTS[spec]
    parts = spec.split("/")
    if spec.startswith("@"):
        scoped = "/".join(parts[:2])
        if scoped in _COMPONENTS:
            return _COMPONENTS[scoped]
        if parts[0] in _COMPONENTS:
            return _COMPONENTS[parts[0]]
        return None
    if parts[0] in _COMPONENTS and len(parts) > 1 and parts[0] in {"fs"}:
        return _COMPONENTS[parts[0]]
    dotted = spec.split(".")
    for i in range(len(dotted), 0, -1):
        key = ".".join(dotted[:i])
        if key in _COMPONENTS:
            return _COMPONENTS[key]
    if parts[0] in _COMPONENTS:
        return _COMPONENTS[parts[0]]
    return None


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = _dotted(node.func)
        if inner:
            parts.append(inner + "()")
    return ".".join(reversed(parts))


_NO_TREE = object()  # add(): çağıran ağaç vermedi


def _parse_python(text: str) -> ast.Module | None:
    """Taranan kodun SyntaxWarning'leri (geçersiz kaçış vb.) günlüğü kirletmesin."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return ast.parse(text)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return None


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class ThreatModelCollector:
    """Proje analizi dosya döngüsünden beslenen hafif toplayıcı; çıktı yalnız meta veridir."""

    def __init__(self, project_name: str = "") -> None:
        self.project_name = project_name
        self.routes: list[dict[str, Any]] = []
        self.components: dict[str, dict[str, Any]] = {}  # "tür:ad" → {kind, label, files:set, services:set}
        self.hosts: dict[str, set[str]] = {}  # servis → literal dış ana makineler
        self.manifest_dirs: set[str] = set()
        self.secret_files = 0
        self.files_seen = 0
        self._file_services: dict[str, str] = {}

    # -- toplama ------------------------------------------------------------------
    def add(self, relpath: str, text: str | None, kind: str, py_tree: Any = _NO_TREE) -> None:
        """``py_tree``: çağıranın aynı metinden zaten ayrıştırdığı Python ağacı (ayrıştırılamadıysa None); verilirse
        rota çıkarımı yeniden ayrıştırmaz (19. tur hız)."""
        self._given_tree = py_tree
        rel = PurePosixPath(relpath)
        if kind == "secret_file":
            self.secret_files += 1
            self._component("env", ".env dosyası", relpath)
            return
        if text is None:
            return
        self.files_seen += 1
        name = rel.name.casefold()
        if name in _MANIFESTS:
            self.manifest_dirs.add(str(rel.parent))
        suffix = rel.suffix.casefold()
        if suffix in {".yaml", ".yml", ".json"} and ("openapi" in text[:4000] or "swagger" in text[:4000]) and "paths" in text:
            self._openapi(relpath, text, suffix)
            return
        if suffix == ".py":
            self._python(relpath, text)
        elif suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"}:
            if "/static/" in f"/{relpath}" or "/public/" in f"/{relpath}" or "/assets/" in f"/{relpath}":
                return  # istemci paketleri sunucu bileşeni değildir
            self._javascript(relpath, text)

    def _openapi(self, relpath: str, text: str, suffix: str) -> None:
        """OpenAPI/Swagger belgesindeki yollar (Connexion vb. yapılandırmayla bağlanan rotalar)."""
        methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        if suffix == ".json":
            import json

            try:
                doc = json.loads(text)
            except ValueError:
                return
            for path, item in (doc.get("paths") or {}).items() if isinstance(doc, dict) else []:
                if isinstance(item, dict):
                    for method, op in item.items():
                        if method in methods:
                            handler = op.get("operationId", "?") if isinstance(op, dict) else "?"
                            self._route(method, str(path), str(handler), relpath, 0, "openapi")
            return
        in_paths, path, path_indent, method, method_line = False, None, 0, None, 0
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()
            if indent == 0:
                in_paths = stripped.startswith("paths:")
                path = method = None
                continue
            if not in_paths:
                continue
            key = _openapi_path_key(stripped)
            if key is not None and (path is None or indent <= path_indent):
                if method:
                    self._route(method, path or "/", "?", relpath, method_line, "openapi")
                path, path_indent, method = key, indent, None
                continue
            m = re.match(r"(get|post|put|patch|delete|head|options)\s*:\s*$", stripped)
            if m and path is not None and indent > path_indent:
                if method:
                    self._route(method, path, "?", relpath, method_line, "openapi")
                method, method_line = m.group(1), line_no
                continue
            op = re.match(r"operationId\s*:\s*['\"]?([\w.]+)", stripped)
            if op and method:
                self._route(method, path or "/", op.group(1), relpath, method_line, "openapi")
                method = None
        if method:
            self._route(method, path or "/", "?", relpath, method_line, "openapi")

    def _component(self, kind: str, label: str, relpath: str) -> None:
        entry = self.components.setdefault(f"{kind}:{label}", {"kind": kind, "label": label, "files": set()})
        if len(entry["files"]) < 50:
            entry["files"].add(relpath)

    def _route(self, method: str, path: str, handler: str, relpath: str, line: int, framework: str) -> None:
        if len(self.routes) >= MAX_ROUTES:
            return
        self.routes.append({
            "method": method.upper()[:10], "path": path[:200] or "/", "handler": handler[:120],
            "file": relpath, "line": int(line), "framework": framework,
        })

    def _hosts(self, relpath: str, text: str) -> None:
        for match in _URL_HOST_RE.finditer(text):
            host = match.group(1).casefold().rstrip(".")
            if host in _LOCAL_HOSTS or host.endswith((".local", ".localhost", ".test", ".example")) or "." not in host:
                continue
            bucket = self.hosts.setdefault(relpath, set())
            if len(bucket) < MAX_HOSTS:
                bucket.add(host)

    def _python(self, relpath: str, text: str) -> None:
        uses_http = False
        for line in text.splitlines():
            if "import" not in line:
                continue
            match = _PY_IMPORT_LINE_RE.match(line)
            if not match:
                continue
            specs = [match.group(1)] if match.group(1) else [s.strip() for s in (match.group(2) or "").split(",")]
            for spec in specs:
                comp = _component_for(spec)
                if spec.startswith("aiohttp") and "ClientSession" in text:
                    comp = ("http", "aiohttp istemcisi")
                if comp:
                    self._component(comp[0], comp[1], relpath)
                    uses_http |= comp[0] == "http"
        if _ENV_RE.search(text):
            self._component("env", "Ortam değişkenleri", relpath)
        if _FS_PY_RE.search(text):
            self._component("fs", "Dosya yazma", relpath)
        if uses_http:
            self._hosts(relpath, text)
        if _PY_ROUTE_HINT.search(text):
            self._python_routes(relpath, text)

    def _python_routes(self, relpath: str, text: str) -> None:
        given = getattr(self, "_given_tree", _NO_TREE)
        tree = _parse_python(text) if given is _NO_TREE else given
        if tree is None:
            return
        modules: set[str] = set()
        for node in ast.walk(tree):  # içe aktarılan üst modüller (tek yürüyüş)
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        framework = next((f for f in ("fastapi", "flask", "quart", "sanic", "starlette", "aiohttp", "falcon", "django", "tornado", "bottle") if f in modules), "python")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
                        continue
                    attr = decorator.func.attr
                    if attr not in _ROUTE_DECORATORS or not _dotted(decorator.func.value):
                        continue
                    path = _const_str(decorator.args[0]) if decorator.args else None
                    if path is None:
                        path = next((_const_str(kw.value) for kw in decorator.keywords if kw.arg in {"path", "rule"}), None)
                    if path is None:
                        continue
                    methods = ["GET"] if attr in {"route", "api_route"} else [attr.upper()]
                    for kw in decorator.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                            listed = [_const_str(e) for e in kw.value.elts]
                            methods = [m for m in listed if m] or methods
                    for method in methods:
                        self._route(method, path, node.name, relpath, node.lineno, framework)
                # Falcon / Tornado sınıf yöntemleri: on_get / get(self, ...)
            elif isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name)):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
                args = node.args
                if name in {"path", "re_path", "url"} and len(args) >= 2 and _const_str(args[0]) is not None \
                        and (framework == "django" or "urlpatterns" in text or "django.urls" in text):
                    view = _dotted(args[1]) if not isinstance(args[1], ast.Call) else _dotted(args[1].func)
                    if view and view not in {"include"} and not view.startswith("include"):
                        self._route("ANY", "/" + str(_const_str(args[0])).lstrip("^/"), view, relpath, node.lineno, "django")
                elif name == "add_url_rule" and args and _const_str(args[0]) is not None:
                    view = next((_dotted(kw.value) for kw in node.keywords if kw.arg == "view_func"), "")
                    if not view and len(args) >= 3:
                        view = _dotted(args[2])
                    self._route("ANY", _const_str(args[0]) or "/", view or "?", relpath, node.lineno, framework)
                elif name == "add_route" and args:
                    if len(args) >= 3 and _const_str(args[0]) and _const_str(args[1]):  # aiohttp add_route(method, path, h)
                        self._route(_const_str(args[0]) or "ANY", _const_str(args[1]) or "/", _dotted(args[2]), relpath, node.lineno, framework)
                    elif _const_str(args[0]) is not None and len(args) >= 2:  # falcon add_route(path, resource)
                        target = _dotted(args[1].func) if isinstance(args[1], ast.Call) else _dotted(args[1])
                        self._route("ANY", _const_str(args[0]) or "/", target, relpath, node.lineno,
                                    "falcon" if "falcon" in modules or framework == "python" else framework)
                elif name in {"add_get", "add_post", "add_put", "add_patch", "add_delete"} and len(args) >= 2 and _const_str(args[0]):
                    self._route(name[4:], _const_str(args[0]) or "/", _dotted(args[1]), relpath, node.lineno, "aiohttp")

    def _javascript(self, relpath: str, text: str) -> None:
        uses_http = False
        for line in text.splitlines():
            if "require(" not in line and "import" not in line and " from " not in line:
                continue
            for match in _JS_IMPORT_LINE_RE.finditer(line):
                spec = match.group(1) or match.group(2) or match.group(3) or ""
                comp = _component_for(spec)
                if comp:
                    self._component(comp[0], comp[1], relpath)
                    uses_http |= comp[0] == "http"
        if _ENV_RE.search(text):
            self._component("env", "Ortam değişkenleri", relpath)
        if _FETCH_RE.search(text) and ("process.env" in text or _JS_SERVER_HINT.search(text) or "node-fetch" in text):
            self._component("http", "fetch", relpath)
            uses_http = True
        if uses_http:
            self._hosts(relpath, text)
        nest = "@Controller" in text
        if nest or _JS_SERVER_HINT.search(text) or _JS_ROUTE_RE.search(text):
            self._javascript_routes(relpath, text, nest)

    def _javascript_routes(self, relpath: str, text: str, nest: bool) -> None:
        framework = "express"
        for name in ("fastify", "koa", "hapi", "restify"):
            if re.search(rf"['\"](?:@koa/router|koa-router|{name}|@hapi/{name})['\"]", text):
                framework = name
                break
        line_starts = [0]
        for match in re.finditer("\n", text):
            line_starts.append(match.end())

        def line_of(offset: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= offset:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        for match in _JS_ROUTE_RE.finditer(text):
            owner, method, path, rest = match.group(1), match.group(2), match.group(4), match.group(5) or ""
            last = owner.rsplit(".", 1)[-1]
            if last.casefold() in _JS_OWNER_BLOCKLIST and not last.casefold().endswith(("router", "app")):
                continue
            if not (last.casefold() in {"app", "router", "server", "fastify", "route", "routes", "r", "api_router", "apirouter"}
                    or last.casefold().endswith(("router", "app", "routes"))):
                continue
            if not path.startswith(("/", "*")) and path != "":
                continue
            handler = _js_handler_name(rest)
            self._route("USE" if method == "use" else ("DELETE" if method == "del" else method), path, handler,
                        relpath, line_of(match.start()), framework)
        for match in _JS_ROUTE_CHAIN_RE.finditer(text):
            for method in re.findall(r"\.\s*(get|post|put|patch|delete|all)\s*\(", match.group(3)):
                self._route(method, match.group(2), "(zincir)", relpath, line_of(match.start()), framework)
        if nest:
            controller = _NEST_CONTROLLER_RE.search(text)
            prefix = "/" + (controller.group(1) or "").strip("/") if controller else ""
            for route_start, method, route_path, handler in _iter_nest_routes(text):
                path = "/".join(p for p in (prefix.rstrip("/"), route_path.strip("/")) if p) or "/"
                self._route(method, path if path.startswith("/") else "/" + path, handler, relpath,
                            line_of(route_start), "nestjs")

    # -- model --------------------------------------------------------------------
    def _service_of(self, relpath: str) -> str:
        if relpath in self._file_services:
            return self._file_services[relpath]
        parent = PurePosixPath(relpath).parent
        best = "."
        for candidate in [parent, *parent.parents]:
            if str(candidate) in self.manifest_dirs:
                best = str(candidate)
                break
        self._file_services[relpath] = best
        return best

    def build(self, findings: list[dict[str, Any]], *, partial: bool = False) -> dict[str, Any]:
        return build_model(self, findings, partial=partial)


def _finding_cwes(finding: dict[str, Any]) -> set[str]:
    text = " ".join(str(finding.get(key) or "") for key in ("reference", "cwe", "rule_id"))
    return set(re.findall(r"CWE-(\d+)", text))


def build_model(collector: ThreatModelCollector, findings: list[dict[str, Any]], *, partial: bool = False) -> dict[str, Any]:
    services: dict[str, dict[str, Any]] = {}

    def service(key: str) -> dict[str, Any]:
        if key not in services:
            label = collector.project_name if key == "." else key.rsplit("/", 1)[-1]
            services[key] = {"id": f"proc:{len(services) + 1}", "type": "process", "label": label or "Uygulama",
                             "path": key, "frameworks": set(), "routes": 0}
        return services[key]

    routes = []
    for route in collector.routes:
        key = collector._service_of(route["file"])
        svc = service(key)
        svc["routes"] += 1
        svc.setdefault("route_frameworks", set()).add(route["framework"])
        routes.append({**route, "service": svc["id"]})
    # Bileşenleri servislere bağla
    store_nodes: dict[str, dict[str, Any]] = {}
    external_nodes: dict[str, dict[str, Any]] = {}
    links: dict[tuple[str, str], dict[str, Any]] = {}
    auth_labels: set[str] = set()
    log_labels: set[str] = set()
    for entry in collector.components.values():
        kind, label = entry["kind"], entry["label"]
        for relpath in sorted(entry["files"]):
            svc = service(collector._service_of(relpath))
            if kind == "framework":
                svc["frameworks"].add(label)
            elif kind == "auth":
                auth_labels.add(label)
                svc.setdefault("auth", set()).add(label)
            elif kind == "log":
                log_labels.add(label)
            elif kind in _STORE_LABELS:
                node = store_nodes.setdefault(kind, {"id": f"store:{kind}", "type": "store", "kind": kind,
                                                     "label": _STORE_LABELS[kind], "technologies": set()})
                node["technologies"].add(label)
                links.setdefault((svc["id"], node["id"]), {"files": set()})["files"].add(relpath)
            elif kind in _EXTERNAL_LABELS:
                node = external_nodes.setdefault(kind, {"id": f"external:{kind}", "type": "external", "kind": kind,
                                                        "label": _EXTERNAL_LABELS[kind], "technologies": set(), "hosts": set()})
                node["technologies"].add(label)
                if kind == "http":
                    node["hosts"].update(collector.hosts.get(relpath, set()))
                links.setdefault((svc["id"], node["id"]), {"files": set()})["files"].add(relpath)
    if not services:
        service(".")
    client = None
    if routes or any(s["frameworks"] or s.get("route_frameworks") for s in services.values()):
        client = {"id": "external:client", "type": "external", "kind": "client", "label": "Kullanıcı / istemci (İnternet)"}

    flows: list[dict[str, Any]] = []

    def flow(src: str, dst: str, label: str, boundary: str | None, kind: str) -> dict[str, Any]:
        item = {"id": f"F{len(flows) + 1}", "from": src, "to": dst, "label": label, "boundary": boundary, "kind": kind,
                "finding_refs": []}
        flows.append(item)
        return item

    if client:
        for svc in services.values():
            if svc["routes"] or svc["frameworks"] or svc.get("route_frameworks"):
                flow(client["id"], svc["id"], f"HTTP istekleri ({svc['routes']} rota)" if svc["routes"] else "HTTP istekleri",
                     "internet", "client_flow")
    for (src, dst), meta in sorted(links.items()):
        node = store_nodes.get(dst.split(":", 1)[1]) if dst.startswith("store:") else external_nodes.get(dst.split(":", 1)[1])
        label = ", ".join(sorted(node["technologies"]))[:80] if node else ""
        boundary = "data" if dst.startswith("store:") and not dst.endswith(("fs", "env")) else (
            "host" if dst.startswith("store:") else "third_party")
        flow(src, dst, label, boundary, dst)

    boundaries = []
    used = {f["boundary"] for f in flows if f["boundary"]}
    for key, label in (("internet", "İnternet ↔ uygulama"), ("data", "Uygulama ↔ veri katmanı"),
                       ("third_party", "Uygulama ↔ üçüncü taraflar"), ("host", "Uygulama ↔ ana makine (dosya sistemi, ortam)")):
        if key in used:
            boundaries.append({"id": f"B:{key}", "label": label})

    # Tehditler
    cwe_index: dict[str, list[int]] = {}
    for idx, finding in enumerate(findings):
        for cwe in _finding_cwes(finding):
            cwe_index.setdefault(cwe, []).append(idx)
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threats: list[dict[str, Any]] = []
    element_targets: dict[str, list[str]] = {}
    for f in flows:
        if f["kind"] == "client_flow":
            element_targets.setdefault("client_flow", []).append(f["id"])
        elif f["to"].startswith("store:"):
            element_targets.setdefault(f["to"], []).append(f["id"])
            element_targets.setdefault("store:*", []).append(f["id"])
        elif f["to"].startswith("external:"):
            element_targets.setdefault(f["to"], []).append(f["id"])
            element_targets.setdefault("external:*", []).append(f["id"])
    process_ids = [s["id"] for s in services.values()]
    flow_by_id = {f["id"]: f for f in flows}
    for template in _THREAT_TEMPLATES:
        element = template["element"]
        targets = process_ids if element == "process" else element_targets.get(element, [])
        if not targets:
            continue
        refs = sorted({i for cwe in template["cwes"] for i in cwe_index.get(cwe, [])})
        status = "finding" if refs else "review"
        note = ""
        if template.get("needs") == "auth" and not auth_labels:
            note = "Kimlik doğrulama bileşeni tanınmadı; rotaların korunup korunmadığını doğrulayın."
        if template.get("needs") == "log" and not log_labels:
            note = "Güvenlik günlüğü kütüphanesi tanınmadı."
        top = max((findings[i].get("severity", "info") for i in refs), key=lambda s: severity_rank.get(s, 0), default=None)
        threat = {
            "id": f"T{len(threats) + 1:02d}", "stride": template["stride"], "stride_label": STRIDE_LABELS[template["stride"]],
            "element": targets[0] if len(targets) == 1 else element, "elements": targets[:20], "title": template["title"],
            "status": status, "status_label": "Bulgu var" if refs else "Gözden geçirilecek",
            "finding_refs": refs[:30], "finding_count": len(refs), "max_severity": top, "hint": template["hint"], "note": note,
        }
        threats.append(threat)
        for target in targets:
            if target in flow_by_id:
                bucket = flow_by_id[target]["finding_refs"]
                for i in refs:
                    if i not in bucket and len(bucket) < 50:
                        bucket.append(i)
    for f in flows:
        f["finding_refs"].sort()
        f["has_findings"] = bool(f["finding_refs"])

    nodes = []
    if client:
        nodes.append(client)
    for svc in services.values():
        known = {f.casefold() for f in svc["frameworks"]}
        for extra in svc.get("route_frameworks", ()):
            if extra.casefold() not in known and extra not in {"python", "openapi"}:
                svc["frameworks"].add(extra)
        nodes.append({"id": svc["id"], "type": "process", "label": svc["label"], "path": svc["path"],
                      "frameworks": sorted(svc["frameworks"]), "routes": svc["routes"], "auth": sorted(svc.get("auth", ()))})
    for node in store_nodes.values():
        nodes.append({**node, "technologies": sorted(node["technologies"])})
    for node in external_nodes.values():
        nodes.append({**node, "technologies": sorted(node["technologies"]), "hosts": sorted(node.get("hosts", ()))[:MAX_HOSTS]})
    stride_counts = {key: {"finding": 0, "review": 0} for key in STRIDE_LABELS}
    for threat in threats:
        stride_counts[threat["stride"]][threat["status"]] += 1
    return {
        "format": MODEL_FORMAT,
        "partial": partial,
        "nodes": nodes,
        "flows": flows,
        "boundaries": boundaries,
        "routes": sorted(routes, key=lambda r: (r["file"], r["line"], r["method"])),
        "route_count": len(routes),
        "routes_truncated": len(collector.routes) >= MAX_ROUTES,
        "threats": threats,
        "stride_counts": stride_counts,
        "auth_components": sorted(auth_labels),
        "secret_files": collector.secret_files,
        "notes": [
            "Model statik çıkarımdır; çalışma zamanı yapılandırması (ters vekil, ağ politikası) görülmez.",
            "Bulgu bağlantıları CWE eşlemesiyle yapılır; 'Gözden geçirilecek' tehditler için bulgu olmaması güvenli olduğu anlamına gelmez.",
        ] + (["Kısmi tarama (yalnız atlananlar/değişenler): model eksik olabilir."] if partial else []),
    }


# ---------------------------------------------------------------------------
# SVG çizimi (bağımlılıksız, çevrimdışı; tüm metinler kaçışlı)
# ---------------------------------------------------------------------------
def _wrap(text: str, width: int = 24, lines: int = 2) -> list[str]:
    words = str(text).split()
    out: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width and current:
            out.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
        if len(out) == lines:
            break
    if current and len(out) < lines:
        out.append(current)
    if len(out) == lines and sum(len(o) for o in out) < len(text) - 1:
        out[-1] = out[-1][: width - 1] + "…"
    return out or [""]


def render_svg(model: dict[str, Any]) -> str:
    nodes = model.get("nodes") or []
    flows = model.get("flows") or []
    columns = {
        0: [n for n in nodes if n.get("id") == "external:client"],
        1: [n for n in nodes if n.get("type") == "process"],
        2: [n for n in nodes if n.get("type") == "store"],
        3: [n for n in nodes if n.get("type") == "external" and n.get("id") != "external:client"],
    }
    box_w, box_h, gap_y, col_x = 190, 58, 26, {0: 20, 1: 270, 2: 520, 3: 770}
    if not columns[3]:
        col_x[2] = 560
    rows = max(1, *(len(v) for v in columns.values()))
    height = 70 + rows * (box_h + gap_y) + 30
    width = 990 if columns[3] else 780
    pos: dict[str, tuple[int, int]] = {}
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Veri akış diyagramı" class="threat-dfd" font-family="system-ui,sans-serif">',  # boyut CSS'te (.threat-dfd): CSP satır içi stili reddeder
        '<defs><marker id="dfd-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#475569"/></marker>'
        '<marker id="dfd-arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#dc2626"/></marker></defs>',
    ]
    headers = {0: "Dış varlık", 1: "Süreç (uygulama)", 2: "Veri depoları", 3: "Üçüncü taraflar"}
    for col, items in columns.items():
        if not items:
            continue
        x = col_x[col]
        parts.append(f'<text x="{x}" y="22" font-size="12" font-weight="700" fill="#334155">{html.escape(headers[col])}</text>')
        for row, node in enumerate(items):
            y = 40 + row * (box_h + gap_y)
            pos[node["id"]] = (x, y)
    # güven sınırları: İnternet sınırı istemci ile süreç arasında; veri/üçüncü taraf sınırları sütun çevresinde
    boundary_ids = {b["id"] for b in model.get("boundaries") or []}
    if "B:internet" in boundary_ids:
        parts.append(f'<line x1="235" y1="30" x2="235" y2="{height - 10}" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="6 5"/>'
                     f'<text x="240" y="{height - 14}" font-size="10" fill="#dc2626">güven sınırı: İnternet</text>')
    for col, bid, label in ((2, "B:data", "güven sınırı: veri katmanı"), (3, "B:third_party", "güven sınırı: üçüncü taraflar")):
        if columns[col] and (bid in boundary_ids or col == 2 and "B:host" in boundary_ids):
            x = col_x[col] - 12
            h = len(columns[col]) * (box_h + gap_y) + 8
            parts.append(f'<rect x="{x}" y="30" width="{box_w + 24}" height="{h}" rx="10" fill="none" stroke="#64748b" stroke-dasharray="6 5"/>'
                         f'<text x="{x + 6}" y="{30 + h + 13}" font-size="10" fill="#64748b">{html.escape(label)}</text>')
    # akışlar (kutulardan önce, altta kalsın)
    for f in flows:
        if f["from"] not in pos or f["to"] not in pos:
            continue
        (x1, y1), (x2, y2) = pos[f["from"]], pos[f["to"]]
        sx, sy = x1 + box_w, y1 + box_h / 2
        ex, ey = x2, y2 + box_h / 2
        color = "#dc2626" if f.get("has_findings") else "#475569"
        marker = "dfd-arrow-red" if f.get("has_findings") else "dfd-arrow"
        mx = (sx + ex) / 2
        parts.append(f'<path d="M{sx},{sy} C{mx},{sy} {mx},{ey} {ex - 2},{ey}" fill="none" stroke="{color}" '
                     f'stroke-width="{2 if f.get("has_findings") else 1.3}" marker-end="url(#{marker})"/>')
        label = f'{f["id"]}' + (f' · {len(f["finding_refs"])} bulgu' if f.get("has_findings") else "")
        parts.append(f'<text x="{mx - 30}" y="{(sy + ey) / 2 - 4}" font-size="10" fill="{color}">{html.escape(label)}</text>')
    for node in nodes:
        if node["id"] not in pos:
            continue
        x, y = pos[node["id"]]
        kind = node.get("type")
        sub = ""
        if kind == "process":
            sub = f'{node.get("routes", 0)} rota · ' + ", ".join(node.get("frameworks") or [])[:40]
        elif node.get("technologies"):
            sub = ", ".join(node["technologies"])
        if kind == "process":
            shape = f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="26" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>'
        elif kind == "store":
            shape = (f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" fill="#f0fdf4" stroke="none"/>'
                     f'<line x1="{x}" y1="{y}" x2="{x + box_w}" y2="{y}" stroke="#16a34a" stroke-width="1.5"/>'
                     f'<line x1="{x}" y1="{y + box_h}" x2="{x + box_w}" y2="{y + box_h}" stroke="#16a34a" stroke-width="1.5"/>')
        else:
            shape = f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" fill="#f8fafc" stroke="#475569" stroke-width="1.5"/>'
        parts.append(shape)
        for i, line in enumerate(_wrap(node.get("label", ""), 26, 1)):
            parts.append(f'<text x="{x + 10}" y="{y + 22 + i * 13}" font-size="12" font-weight="600" fill="#0f172a">{html.escape(line)}</text>')
        for i, line in enumerate(_wrap(sub, 32, 2)):
            parts.append(f'<text x="{x + 10}" y="{y + 38 + i * 12}" font-size="10" fill="#475569">{html.escape(line)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_html_section(model: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> str:
    """Rapor için bölüm: diyagram + tehdit tablosu + rota envanteri (ilk 50)."""
    if not isinstance(model, dict) or model.get("format") != MODEL_FORMAT:
        return ""
    findings = findings or []
    rows = []
    for threat in model.get("threats") or []:
        refs = threat.get("finding_refs") or []
        examples = []
        for i in refs[:3]:
            if 0 <= i < len(findings):
                f = findings[i]
                examples.append(f"{f.get('file', '')}:{f.get('line', '')} {f.get('title', '')}")
        detail = "; ".join(examples) or threat.get("note") or threat.get("hint", "")
        rows.append(
            f"<tr><td>{html.escape(threat['id'])}</td><td>{html.escape(threat['stride_label'])}</td>"
            f"<td>{html.escape(threat['title'])}</td><td>{html.escape(threat['status_label'])}"
            f"{' (' + str(threat['finding_count']) + ')' if threat['finding_count'] else ''}</td>"
            f"<td>{html.escape(detail[:300])}</td></tr>")
    route_rows = "".join(
        f"<tr><td>{html.escape(r['method'])}</td><td><code>{html.escape(r['path'])}</code></td><td>{html.escape(r['handler'])}</td>"
        f"<td><code>{html.escape(r['file'])}:{int(r['line'])}</code></td></tr>"
        for r in (model.get("routes") or [])[:50])
    more = model.get("route_count", 0) - min(50, model.get("route_count", 0))
    notes = "".join(f"<li>{html.escape(n)}</li>" for n in model.get("notes") or [])
    return (
        "<section><h2>Tehdit modeli (STRIDE)</h2>"
        + render_svg(model)
        + "<table><thead><tr><th>No</th><th>STRIDE</th><th>Tehdit</th><th>Durum</th><th>Ayrıntı</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
        + f"<h3>Rota envanteri ({int(model.get('route_count', 0))})</h3>"
        + ("<table><thead><tr><th>Yöntem</th><th>Yol</th><th>İşleyici</th><th>Konum</th></tr></thead><tbody>"
           + route_rows + "</tbody></table>" if route_rows else "<p>Rota bulunamadı.</p>")
        + (f"<p>… ve {more} rota daha.</p>" if more > 0 else "")
        + f"<ul>{notes}</ul></section>"
    )


def build_from_paths(root, files: Iterable[tuple[str, str | None, str]], findings: list[dict[str, Any]], *,
                     project_name: str = "", partial: bool = False) -> dict[str, Any]:
    """Önceden kaydedilmiş analizler için: (göreli yol, metin, tür) üçlülerinden model."""
    collector = ThreatModelCollector(project_name)
    for relpath, text, kind in files:
        collector.add(relpath, text, kind)
    return collector.build(findings, partial=partial)
