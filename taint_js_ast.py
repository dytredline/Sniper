"""JavaScript/TypeScript için AST tabanlı, fonksiyonlar ve dosyalar arası taint analizi.

Ayrıştırma, uygulamayla birlikte gelen ve SHA-256 ile sabitlenmiş ``@babel/parser``
(``vendor/babel-parser``) ile, yine hash'i sabitlenmiş Node (``SNIPER_NODE_BINARY`` +
``SNIPER_NODE_SHA256``) üzerinde ayrı bir süreçte yapılır. Node süreci yalnız ayrıştırır:
kod çalıştırmaz, ağ ve dosya yazımı kullanmaz; ``--disallow-code-generation-from-strings``
ve bellek sınırıyla, kendi süreç grubunda çalışır ve zaman aşımında öldürülür.

Node veya ayrıştırıcı kullanılamazsa çağıran (``taint_flow``) belirteç tabanlı motora düşer.
``SNIPER_TAINT_JS_ENGINE=tokens`` AST motorunu kapatır, ``=ast`` zorunlu kılar.

Analiz modeli Python motoruyla aynıdır (bkz. :mod:`taint_flow`): fonksiyon özetleri,
``require``/``import``/``module.exports``/``export`` ile dosyalar arası çözümleme, Express /
Koa / Fastify / NestJS işleyicileri, geri çağırma (callback) parametreleri, doğrulama
koşulları ve sonlanan dallar. Akışlar hedefin bulunduğu dosyaya raporlanır.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import select
import signal
import stat
import subprocess
import time
from typing import Any, Callable, Iterable

import taint_angular
import taint_flow as tf
import taint_js_views
import taint_models

APP_DIR = Path(__file__).resolve().parent
PARSER_PATH = APP_DIR / "vendor" / "babel-parser" / "index.js"
PARSER_SHA256 = "82d72e197e27bf909ae10ffc8d1a969aeb94fe96ec96c4e9cb685a0a8229e40c"
BRIDGE_PATH = APP_DIR / "taint_js_bridge.cjs"
BRIDGE_SHA256 = "fd95e94b1b7e87c01e560c86b41c3e6f03d00b0b1a5b613258fc79eb09304585"
PARSE_TIMEOUT = 20.0
PROJECT_PARSE_BUDGET = 240.0
NODE_HEAP_MB = 1536
MAX_BRIDGE_BYTES = 64_000

Node = dict[str, Any]
Taint = tf.Taint
_EMPTY = tf._EMPTY
_PARAM = tf._PARAM

_JS_EXTENSIONS = (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_REQUEST_ROOTS = frozenset({"req", "request"})
_CTX_ROOTS = frozenset({"ctx", "context"})
_REQUEST_MEMBERS = frozenset({
    "body", "query", "params", "headers", "cookies", "files", "file", "rawBody", "signedCookies",
    "fields", "url", "originalUrl", "path", "host", "hostname", "ip", "baseUrl", "nextUrl",
    "method", "protocol", "ips", "subdomains", "referrer",
})
_CTX_MEMBERS = frozenset({"query", "params", "headers", "cookies", "querystring", "url", "path", "href", "host"})
_BROWSER_SOURCES = {
    "location": frozenset({"hash", "search", "href", "pathname"}),
    "document": frozenset({"cookie", "URL", "documentURI", "referrer", "baseURI"}),
    "window": frozenset({"name"}),
}
# Angular ActivatedRoute: adres çubuğundan gelen sorgu/yol parametreleri ve parça.
_ANGULAR_ROUTE_MEMBERS = frozenset({"queryParams", "params", "queryParamMap", "paramMap", "fragment", "url"})
_FIXED_HOST_PREFIX_RE = re.compile(r"(?i)^(?:(?:https?:)?//[^/?#\s]+[/?#]|/(?![/\\]))")
_PROCESS_SPAWN_CALLS = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})
_NEST_PARAM_DECORATORS = frozenset({"Body", "Query", "Param", "Params", "Headers", "Req", "Request", "UploadedFile", "Cookies",
                                    # GraphQL: type-graphql @Arg/@Args, NestJS GraphQL @Args (istemci argümanları)
                                    "Arg", "Args"})
# Sunucusuz/GraphQL giriş noktaları (bkz. JsProject.collect_entrypoints).
_LAMBDA_EVENT_PARAMS = frozenset({"event", "evt", "e", "lambdaEvent", "awsEvent", "apiEvent"})
_LAMBDA_EVENT_TYPES = frozenset({
    "APIGatewayProxyEvent", "APIGatewayProxyEventV2", "APIGatewayProxyWithCognitoAuthorizerEvent", "APIGatewayEvent",
    "APIGatewayProxyEventV2WithJWTAuthorizer", "APIGatewayProxyWithLambdaAuthorizerEvent", "ALBEvent",
    "LambdaFunctionURLEvent", "HandlerEvent", "SQSEvent", "SNSEvent", "S3Event", "EventBridgeEvent",
})
_LAMBDA_HANDLER_TYPES = frozenset({
    "Handler", "APIGatewayProxyHandler", "APIGatewayProxyHandlerV2", "ALBHandler", "LambdaFunctionURLHandler",
    "SQSHandler", "SNSHandler", "S3Handler", "APIGatewayProxyHandlerV2WithJWTAuthorizer",
})
_LAMBDA_HANDLER_NAME_RE = re.compile(r"(?i)handler$")
_SERVERLESS_CONFIGS = frozenset({"serverless.yml", "serverless.yaml", "template.yaml", "template.yml"})
_SERVERLESS_HANDLER_RE = re.compile(r"""^\s*-?\s*[Hh]andler\s*:\s*['"]?([\w./@-]+)['"]?\s*(?:#.*)?$""", re.M)
_SAM_CODEURI_RE = re.compile(r"""^\s*CodeUri\s*:\s*['"]?([\w./@-]+)['"]?\s*(?:#.*)?$""", re.M)
_MAX_SERVERLESS_CONFIGS = 20
_GRAPHQL_ROOT_TYPES = frozenset({"Query", "Mutation", "Subscription"})
# Resolver haritalarını birleştiren çağrılar (graphql-tools/@graphql-tools/merge, graphql-compose …).
_RESOLVER_MERGE_CALLS = frozenset({"mergeResolvers", "mergeResolversSafe"})
# serverless.ts / CDK: yalnız bu dosya adlarında ya da `events` anahtarlı işlev nesnelerinde `handler:` okunur.
_SERVERLESS_TS_RE = re.compile(r"(?:^|/)serverless\.(?:[cm]?[jt]s)$")
_CDK_PACKAGES = frozenset({"aws-cdk-lib", "@aws-cdk/aws-lambda", "@aws-cdk/aws-lambda-nodejs", "aws-cdk"})
_CDK_FUNCTION_CLASSES = frozenset({"Function", "NodejsFunction", "DockerImageFunction"})
_JS_SOURCE_EXT_RE = re.compile(r"\.(?:[cm]?[jt]sx?)$")
_NEXT_PAGES_API_RE = re.compile(r"(?:^|/)(?:pages/|src/pages/)?api/")
_ROUTER_METHODS = frozenset({"get", "post", "put", "patch", "delete", "del", "all", "use", "options", "head", "route"})
_ROUTER_OBJECTS = frozenset({"app", "router", "server", "api", "routes", "route", "r", "fastify", "express", "apiRouter", "v1"})
_ITERATION_METHODS = frozenset({"forEach", "map", "filter", "find", "findLast", "some", "every", "flatMap", "then", "finally", "catch", "sort"})
# Geri çağrısı yalnız koşul/karşılaştırma döndüren yöntemler: sonuç öğeleri alıcıdan gelir, geri çağrının
# (ve yakaladığı ayarların) taint'i sonuca karışmaz (ör. items.filter(x => ayar.includes(x.tur))).
_PREDICATE_METHODS = frozenset({"filter", "find", "findLast", "some", "every", "sort"})
_FULL_SANITIZERS = frozenset({
    "parseInt", "parseFloat", "Number", "Boolean", "Math.floor", "Math.round", "Math.ceil", "Math.abs",
    "Number.parseInt", "Number.parseFloat", "isNaN", "Number.isInteger", "Array.isArray", "uuid.validate",
    "encodeURIComponent", "Date.parse",
})
_CLEAN_MEMBERS = frozenset({"length", "size", "byteLength", "includes", "startsWith", "endsWith", "indexOf", "test", "has", "lastIndexOf"})
_LOG_OBJECTS = frozenset({"logger", "log", "winston", "pino", "LOGGER", "Logger", "logging", "bunyan", "signale", "fastify.log", "this.logger"})
_LOG_METHODS = frozenset({"info", "warn", "warning", "error", "debug", "trace", "fatal", "verbose", "silly", "log", "notice", "critical"})
_SQL_METHODS = frozenset({
    "query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "queryRawUnsafe",
    "executeRawUnsafe", "whereRaw", "orderByRaw", "havingRaw", "joinRaw", "fromRaw", "selectRaw",
})
# İkinci derece (kayıtlı) veri: ORM/sürücü okumaları "stored" etiketli kaynaktır.
# 25. tur: ORM/sürücü yazımları (ilk argüman alan nesnesi)
_ORM_WRITE_METHODS = frozenset({"create", "update", "upsert", "insert", "insertOne", "insertMany", "updateOne",
                                "updateMany", "findOneAndUpdate", "findByIdAndUpdate", "build", "bulkCreate",
                                "createMany", "save"})
_ORM_READ_METHODS = frozenset({
    "findByPk", "findOne", "findAll", "findById", "findUnique", "findFirst", "findMany", "findAndCountAll",
    "findOneBy", "findBy", "findUniqueOrThrow", "findFirstOrThrow",
})
# Sonuç satırı döndüren sürücü çağrıları (sorgu kurucuları değil).
_DB_RESULT_METHODS = frozenset({"query", "execute"})
# XML ayrıştırıcıları: sonuçları dize ağacıdır (NoSQL işleci taşımaz).
_XML_PARSE_METHODS = frozenset({"parseStringPromise", "parseXml", "parseXmlString", "parseFromString", "text"})
_XML_PARSE_FUNCS = frozenset({"xml2js.parseString", "xml2js.parseStringPromise", "libxmljs.parseXml",
                              "libxmljs.parseXmlString", "libxmljs2.parseXml", "libxmljs2.parseXmlString"})
_SAFE_SQL_TAGS = frozenset({"sql", "SQL", "Prisma.sql", "sql.raw?"})
_TERMINATOR_CALLS = frozenset({"process.exit", "res.end", "next"})
_JS_VALIDATOR_RE = re.compile(r"^(?:is_?)?(?:valid|safe|allowed|permitted|whitelisted|allowlisted|trusted)|^validate|^check(?:Safe|Allowed)|^assert(?:Valid|Safe)", re.IGNORECASE)
_HTML_RE = re.compile(r"<[a-zA-Z/!]")


class JsParserUnavailable(Exception):
    pass


# ---------------------------------------------------------------------------
# Node köprüsü
# ---------------------------------------------------------------------------

def engine_mode() -> str:
    value = os.environ.get("SNIPER_TAINT_JS_ENGINE", "auto").strip().lower()
    return value if value in {"auto", "ast", "tokens"} else "auto"


def _open_pinned_node():
    """Merkezi SHA + sürüm kapısından geçen fd-bound Node çalışma zamanını aç."""
    from tool_pins import open_pinned
    from verified_exec import VerificationError
    try:
        return open_pinned("node")
    except VerificationError as exc:
        raise JsParserUnavailable(f"Node çalışma zamanı doğrulanamadı ({exc.reason}).") from exc


def _read_verified(path: Path, digest: str, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise JsParserUnavailable(f"{path.name} okunamadı.") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise JsParserUnavailable(f"{path.name} normal dosya değil.")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit or hashlib.sha256(data).hexdigest() != digest:
        raise JsParserUnavailable(f"{path.name} bütünlük doğrulaması başarısız.")
    return data


class NodeParser:
    """Tek bir Node sürecinde sırayla dosya ayrıştırır (satır başına bir JSON)."""

    def __init__(self) -> None:
        bridge = _read_verified(BRIDGE_PATH, BRIDGE_SHA256, MAX_BRIDGE_BYTES).decode("utf-8")
        node = _open_pinned_node()
        try:
            self.proc = subprocess.Popen(
                [
                    # --jitless: servis MemoryDenyWriteExecute=yes ile çalışır (V8 JIT W+X bellek ister).
                    node.argv0, "--jitless", "--disallow-code-generation-from-strings",
                    f"--max-old-space-size={NODE_HEAP_MB}", "-e", bridge, str(PARSER_PATH), PARSER_SHA256,
                ],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd="/", start_new_session=True,
                **node.popen_kwargs(
                    close_fds=True,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "NODE_OPTIONS": "", "NODE_PATH": ""},
                ),
            )
        except OSError as exc:
            raise JsParserUnavailable("Node süreci başlatılamadı.") from exc
        finally:
            node.close()
        self._counter = 0
        self._buffer = b""

    def _kill(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.close()
                self.proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if self.proc.poll() is None:
            self._kill()
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    def __enter__(self) -> "NodeParser":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _readline(self, deadline: float) -> bytes:
        assert self.proc.stdout is not None
        stream = self.proc.stdout.fileno()
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._kill()
                raise JsParserUnavailable("Ayrıştırma zaman aşımına uğradı.")
            ready, _, _ = select.select([stream], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(stream, 1 << 20)
            if not chunk:
                raise JsParserUnavailable("Ayrıştırıcı süreci beklenmedik biçimde kapandı.")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line

    def parse(self, name: str, text: str, timeout: float = PARSE_TIMEOUT) -> Node | None:
        if self.proc.poll() is not None:
            raise JsParserUnavailable("Ayrıştırıcı süreci çalışmıyor.")
        self._counter += 1
        request = json.dumps({"id": self._counter, "name": name, "text": text}) + "\n"
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(request.encode("utf-8", errors="surrogatepass"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise JsParserUnavailable("Ayrıştırıcıya yazılamadı.") from exc
        line = self._readline(time.monotonic() + timeout)
        try:
            response = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise JsParserUnavailable("Ayrıştırıcı yanıtı okunamadı.") from exc
        if response.get("id") != self._counter:
            raise JsParserUnavailable("Ayrıştırıcı yanıtı sırası bozuk.")
        ast = response.get("ast")
        return ast if isinstance(ast, dict) else None


def available() -> bool:
    if engine_mode() == "tokens":
        return False
    try:
        _read_verified(BRIDGE_PATH, BRIDGE_SHA256, MAX_BRIDGE_BYTES)
        # Hazırlık uçları süreç başlatmaz. Gerçek NodeParser kurulumu merkezi
        # open_pinned() kapısından geçerek sürümü ayrıca fail-closed doğrular.
        from tool_pins import pin_status
        if pin_status("node")["state"] != "pinned":
            return False
    except JsParserUnavailable:
        return False
    return True


# ---------------------------------------------------------------------------
# AST yardımcıları
# ---------------------------------------------------------------------------


def _t(node: Any) -> str:
    return node.get("type", "") if isinstance(node, dict) else ""


def _line(node: Any) -> int:
    return int(node.get("l", 0)) if isinstance(node, dict) else 0


def _key_name(node: Node) -> str:
    """Nesne/sınıf üyesi anahtarı (computed ise yalnız dize sabiti)."""
    key = node.get("key") or {}
    if node.get("computed"):
        return key.get("value", "") if _t(key) == "StringLiteral" else ""
    if _t(key) == "Identifier":
        return key.get("name", "")
    if _t(key) in {"StringLiteral", "NumericLiteral"}:
        return str(key.get("value", ""))
    if _t(key) == "PrivateName":
        return "#" + (key.get("id") or {}).get("name", "")
    return ""


def _chain(node: Any) -> list[str] | None:
    """a.b.c / this.x / a["b"] → ["a", "b", "c"]; çözülemezse None."""
    parts: list[str] = []
    current = node
    while _t(current) in {"MemberExpression", "OptionalMemberExpression"}:
        prop = current.get("property") or {}
        if current.get("computed"):
            if _t(prop) != "StringLiteral":
                return None
            parts.append(str(prop.get("value", "")))
        elif _t(prop) in {"Identifier", "PrivateName"}:
            parts.append(prop.get("name") or (prop.get("id") or {}).get("name", ""))
        else:
            return None
        current = current.get("object")
    if _t(current) == "Identifier":
        parts.append(current.get("name", ""))
    elif _t(current) == "ThisExpression":
        parts.append("this")
    else:
        return None
    parts.reverse()
    return parts


def _dotted(node: Any) -> str:
    chain = _chain(node)
    return ".".join(chain) if chain else (node.get("name", "") if _t(node) == "Identifier" else "")


def _callee_name(callee: Any) -> str:
    """Çağrı adı; ``a.b().c`` gibi zincirlerde ara çağrılar ``()`` ile gösterilir."""
    if _t(callee) in {"Identifier", "MemberExpression", "OptionalMemberExpression", "ThisExpression"}:
        name = _dotted(callee)
        if name:
            return name
    if _t(callee) in {"MemberExpression", "OptionalMemberExpression"} and not callee.get("computed"):
        inner = callee.get("object")
        prop = (callee.get("property") or {}).get("name", "")
        if _t(inner) in {"CallExpression", "OptionalCallExpression"}:
            base = _callee_name(inner.get("callee"))
            return f"{base or '_call_'}().{prop}" if prop else ""
        return f"_expr_.{prop}" if prop else ""
    return ""


def _is_function(node: Any) -> bool:
    return _t(node) in {"FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration", "ObjectMethod", "ClassMethod", "ClassPrivateMethod"}


def _router_arguments(
    values: Iterable[Any],
    array_resolver: Callable[[str], Node | None] | None = None,
) -> Iterable[Node]:
    """Flatten bounded, static Express handler arrays and spreads.

    Literal arrays are always safe to flatten.  The optional resolver is used
    by :class:`JsScope` for immutable module-level ``const`` arrays only; an
    unresolved spread/identifier remains opaque rather than being guessed.
    """
    stack = [(value, frozenset(), 0) for value in reversed(list(values)) if isinstance(value, dict)]
    emitted = 0
    while stack:
        value, seen, depth = stack.pop()
        if depth > 16 or emitted >= 256:
            return
        if _t(value) == "SpreadElement":
            argument = value.get("argument")
            if isinstance(argument, dict):
                stack.append((argument, seen, depth + 1))
            continue
        if _t(value) == "ArrayExpression":
            stack.extend(
                (item, seen, depth + 1)
                for item in reversed(value.get("elements") or [])
                if isinstance(item, dict)
            )
            continue
        if _t(value) == "Identifier" and array_resolver is not None:
            name = value.get("name", "")
            resolved = None if not name or name in seen else array_resolver(name)
            if resolved is not None:
                stack.append((resolved, seen | {name}, depth + 1))
                continue
        emitted += 1
        yield value


def _string_value(node: Any) -> str | None:
    if _t(node) == "StringLiteral":
        return str(node.get("value", ""))
    if _t(node) == "TemplateLiteral" and not node.get("expressions"):
        return "".join(((q.get("value") or {}).get("cooked") or "") for q in node.get("quasis", []))
    return None


def _children(node: Any) -> Iterable[Node]:
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in {"type", "l"}:
            continue
        if isinstance(value, dict) and "type" in value:
            yield value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "type" in item:
                    yield item


def _unsafe_recursive_merge(node: Node, qual: str) -> bool:
    """Kendini çağıran, anahtar koruması olmayan ``hedef[k] = kaynak[k]`` kopyalayıcısı (deepMerge/extend)."""
    own = qual.rsplit(".", 1)[-1]
    if not own or own.startswith("<"):
        return False
    recursive = False
    for child in _walk(node.get("body"), limit=20_000):
        kind = _t(child)
        if kind == "StringLiteral" and child.get("value") in _PROTO_KEYS:
            return False
        if kind == "Identifier" and child.get("name") in {"hasOwnProperty", "hasOwn", "__proto__"}:
            return False
        if kind in {"CallExpression", "OptionalCallExpression"} and _callee_name(child.get("callee")).rsplit(".", 1)[-1] == own:
            recursive = True
    return recursive


def _walk(node: Any, limit: int = 200_000) -> Iterable[Node]:
    # 19. tur hız: _children üreteci satır içi (aynı çocuk sırası ve aynı ön-sıra yürüyüş).
    stack = [node]
    count = 0
    pop, extend = stack.pop, stack.extend
    while stack and count < limit:
        current = pop()
        if not isinstance(current, dict):
            continue
        count += 1
        yield current
        kids = []
        for key, value in current.items():
            if key == "type" or key == "l":
                continue
            if isinstance(value, dict):
                if "type" in value:
                    kids.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "type" in item:
                        kids.append(item)
        if kids:
            kids.reverse()
            extend(kids)


def _has_html_literal(node: Any) -> bool:
    for child in _walk(node, 5_000):
        if _t(child) == "StringLiteral" and _HTML_RE.search(str(child.get("value", ""))):
            return True
        if _t(child) == "TemplateElement" and _HTML_RE.search(str((child.get("value") or {}).get("cooked") or "")):
            return True
    return False


# Express res.send(dize): İçerik türü atanmamışsa Express dize gövdeye text/html verir (yansıtılmış XSS).
# Yalnız kesin dize ifadeleri (sabit parçalı birleştirme, şablon dizgesi, dize yöntemi sonucu, dizeye atanmış ad)
# ve dize olan istek alanları (req.query.x, req.params.x) — nesne/dizi gönderimi JSON olur.
_EXPRESS_SEND_ROOTS = frozenset({"res", "response"})
_STRING_RESULT_METHODS = frozenset({"toString", "join", "replace", "replaceAll", "trim", "toUpperCase", "toLowerCase",
                                    "substring", "substr", "padStart", "padEnd", "normalize", "repeat"})
_STRING_REQUEST_MEMBERS = frozenset({"query", "params"})
# Projede urlencoded gövde ayrıştırıcısı (express.urlencoded / bodyParser.urlencoded) varsa req.body alanları da
# dize olabilir: saldırgan çapraz siteden form gönderimiyle (CORS ön uçuşu olmadan) dize değer gönderir.
_STRING_BODY_MEMBERS = _STRING_REQUEST_MEMBERS | {"body"}
# res.type / res.set('Content-Type') / res.setHeader / res.contentType / res.header / res.writeHead
_CONTENT_TYPE_SETTERS = frozenset({"type", "contentType", "set", "setHeader", "header", "writeHead"})
# Zincirde bu çağrılar varsa (res.status(404).send) gövde yöntemine indirgenir; içerik türü atayan
# zincirlerde (res.type('json').send) indirgeme yapılmaz.
_RESPONSE_CHAIN_RE = re.compile(r"^(res|response)((?:\.(?:status|vary|cookie|clearCookie|location|append|links|attachment)\(\))+)\.(\w+)$")


# XPath sorgusunun sonucu belgedeki düğümlerdir; ifadenin (istek) taint'ini taşımaz — ifade XPath hedefinde
# ayrıca denetlenir (DB sorgu sonucu ile aynı ilke).
_XPATH_QUERY_FUNCS = frozenset({"xpath.evaluate", "xpath.select", "xpath.select1", "xpath.useNamespaces", "document.evaluate"})
_INDEX_ARG_METHODS = frozenset({"slice", "substring", "substr", "at", "charAt", "charCodeAt", "codePointAt"})


def _string_expr(node: Any, string_vars: set[str], depth: int = 0,
                 members: frozenset[str] = _STRING_REQUEST_MEMBERS) -> bool:
    """İfade kesin olarak dize mi (sözdizimsel)? ``members``: değeri dize olan istek alanları (req.query.x …)."""
    if depth > 8 or not isinstance(node, dict):
        return False
    kind = _t(node)
    if kind in {"StringLiteral", "TemplateLiteral"}:
        return True
    if kind == "BinaryExpression" and node.get("operator") == "+":
        return _string_expr(node.get("left"), string_vars, depth + 1, members) or _string_expr(node.get("right"), string_vars, depth + 1, members)
    if kind == "Identifier":
        return node.get("name", "") in string_vars
    if kind in {"ParenthesizedExpression", "TSAsExpression"}:
        return _string_expr(node.get("expression"), string_vars, depth + 1, members)
    if kind == "ConditionalExpression":
        return _string_expr(node.get("consequent"), string_vars, depth + 1, members) and _string_expr(node.get("alternate"), string_vars, depth + 1, members)
    if kind == "CallExpression":
        callee = node.get("callee") or {}
        if _t(callee) == "Identifier" and callee.get("name") == "String":
            return True
        if _t(callee) in {"MemberExpression", "OptionalMemberExpression"} and not callee.get("computed"):
            return (callee.get("property") or {}).get("name") in _STRING_RESULT_METHODS
        return False
    if kind in {"MemberExpression", "OptionalMemberExpression"}:
        chain = _dotted(node).split(".")
        return len(chain) == 3 and chain[0] in _REQUEST_ROOTS and chain[1] in members
    return False


def _non_html_type(value: Any) -> bool | None:
    """İçerik türü sabiti HTML dışı mı? (sabit değilse None)."""
    if _t(value) != "StringLiteral":
        return None
    text = str(value.get("value", "")).strip().lower()
    if not text:
        return None
    return "html" not in text and "xml" not in text and text not in {"htm"}


# Sayfanın kendi adresi: saldırgan bu değerlerin ana makinesini/yolunu seçemez (yönlendirme/SSRF
# için temiz); bunlardan türetilen sorgu (search) ve parça (hash) bölümleri yeniden kirlenir.
_SAME_PAGE_SOURCES = frozenset({
    "location.href", "location.pathname", "location.origin", "location.host", "location.hostname",
    "window.location.href", "window.location.pathname", "window.location.origin",
    "document.location.href", "document.location.pathname", "document.URL", "document.documentURI", "document.baseURI",
})
_SECONDARY_STORE_PACKAGES = frozenset({"redis", "ioredis", "memcached", "keyv", "bull", "bullmq", "amqplib"})
_SECONDARY_STORE_CALL_FACTORIES = frozenset({
    "redis.createClient", "redis.createCluster", "redis.createClientPool", "redis.createSentinel",
    "ioredis", "ioredis.Redis", "ioredis.Cluster", "amqplib.connect",
})
_SECONDARY_STORE_NEW_FACTORIES = frozenset({
    "ioredis", "ioredis.Redis", "ioredis.Cluster", "memcached", "memcached.Memcached",
    "keyv", "keyv.Keyv", "bull", "bull.Queue", "bullmq.Queue",
})
_SECONDARY_STORE_READS = frozenset({
    "get", "getBuffer", "mGet", "mget", "hGet", "hget", "hGetAll", "hgetall", "lPop", "lpop", "rPop",
    "rpop", "brPop", "brpop", "xRead", "xread", "getJob", "getJobs", "getNextJob",
})
_SANITIZER_VERSION_MINIMUMS = {"dompurify": (2, 4, 0)}
_EXACT_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _supported_exact_version(value: Any, minimum: tuple[int, int, int]) -> bool:
    match = _EXACT_VERSION_RE.fullmatch(value) if isinstance(value, str) else None
    return bool(match and tuple(map(int, match.groups())) >= minimum)


def _javascript_lock_sanitizer_versions(name: str, text: str) -> list[Any]:
    """Return bounded, exact DOMPurify versions from a pnpm/Yarn lockfile.

    Lock selectors may contain ranges, but only the resolved ``version`` value
    (Yarn) or the package snapshot key (pnpm) is evidence.  A lockfile that
    mentions DOMPurify without such evidence returns an unknown marker so the
    caller fails closed for that package scope.
    """
    if "dompurify" not in text.lower():
        return [None]
    versions: list[Any] = []
    if name == "pnpm-lock.yaml":
        # pnpm 6 uses /dompurify/2.4.0; pnpm 7+ uses dompurify@2.4.0.
        package_key = re.compile(
            r"(?im)^\s{1,12}['\"]?/?dompurify(?:@|/)([^:\s'\"]+)['\"]?\s*:\s*(?:\{[^\n]*\})?\s*$"
        )
        versions.extend(match.group(1).split("(", 1)[0] for match in package_key.finditer(text))
    else:
        # Yarn v1 and Berry both group a selector header with an indented,
        # concrete version line.  Do not confuse another package's version.
        header = re.compile(r"(?im)^([^ \t\n]*dompurify@[^\n]*):\s*$")
        for match in header.finditer(text):
            end = re.search(r"(?m)^[^ \t\n][^\n]*:\s*$", text[match.end():])
            block_end = match.end() + end.start() if end else len(text)
            block = text[match.end():block_end]
            version = re.search(r"(?im)^\s+version\s*:?\s*['\"]?([^\s'\"]+)['\"]?\s*$", block)
            versions.append(version.group(1) if version else None)
    return versions or [None]


def _pnpm_importer_sanitizer_versions(text: str) -> dict[str, list[Any]]:
    """Extract importer-specific DOMPurify resolutions from pnpm lock v6-v9."""
    result: dict[str, list[Any]] = {}
    lines = text.splitlines()
    importers_indent: int | None = None
    importer: str | None = None
    importer_indent = -1
    dependency_indent = -1
    for raw in lines[:200_000]:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if importers_indent is None:
            if stripped == "importers:":
                importers_indent = indent
            continue
        if indent <= importers_indent:
            if importer is not None and dependency_indent >= 0:
                result.setdefault(importer, []).append(None)
                dependency_indent = -1
            break
        if indent == importers_indent + 2 and stripped.endswith(":"):
            if importer is not None and dependency_indent >= 0:
                result.setdefault(importer, []).append(None)
            importer = stripped[:-1].strip("'\"")
            importer_indent = indent
            dependency_indent = -1
            continue
        if importer is None or indent <= importer_indent:
            continue
        match = re.match(r"['\"]?dompurify['\"]?\s*:\s*(.*?)\s*$", stripped, re.I)
        if match:
            dependency_indent = indent
            inline = match.group(1).strip("'\"")
            if inline and inline not in {"{}", "null"}:
                result.setdefault(importer, []).append(inline.split("(", 1)[0])
                dependency_indent = -1
            continue
        if dependency_indent >= 0 and indent > dependency_indent:
            version = re.match(r"version\s*:\s*['\"]?([^\s'\"]+)['\"]?\s*$", stripped, re.I)
            if version:
                result.setdefault(importer, []).append(version.group(1).split("(", 1)[0])
                dependency_indent = -1
        elif dependency_indent >= 0 and indent <= dependency_indent:
            result.setdefault(importer, []).append(None)
            dependency_indent = -1
    if importer is not None and dependency_indent >= 0:
        result.setdefault(importer, []).append(None)
    return result


def _yarn_sanitizer_resolutions(text: str) -> dict[str, list[Any]]:
    """Map DOMPurify selector strings to exact resolved Yarn versions."""
    result: dict[str, list[Any]] = {}
    header = re.compile(r"(?im)^([^ \t\n]*dompurify@[^\n]*):\s*$")
    for match in header.finditer(text):
        end = re.search(r"(?m)^[^ \t\n][^\n]*:\s*$", text[match.end():])
        block_end = match.end() + end.start() if end else len(text)
        block = text[match.end():block_end]
        resolved = re.search(r"(?im)^\s+version\s*:?\s*['\"]?([^\s'\"]+)['\"]?\s*$", block)
        value: Any = resolved.group(1) if resolved else None
        for selector in re.findall(r"dompurify@(?:npm:)?([^,\s'\"]+)", match.group(1), re.I):
            result.setdefault(selector, []).append(value)
    return result


def _javascript_sanitizer_version_scopes(files: dict[str, str]) -> dict[str, dict[str, bool]]:
    """Read exact sanitizer versions by nearest local package root.

    A monorepo's legacy package must not disable a supported sanitizer in a
    sibling package.  Root lock evidence remains an ancestor fallback.
    """
    locked: dict[str, list[Any]] = {}
    manifests: dict[str, list[Any]] = {}
    manifest_ranges: dict[str, list[str]] = {}
    yarn_locks: dict[str, dict[str, list[Any]]] = {}
    candidates = sorted(
        (relpath, text) for relpath, text in files.items()
        if PurePosixPath(relpath).name.lower() in {
            "package-lock.json", "package.json", "pnpm-lock.yaml", "yarn.lock",
        }
        and isinstance(text, str)
    )
    total = 0
    for index, (relpath, text) in enumerate(candidates):
        # Monorepos can contain many package roots.  Keep manifest processing
        # deterministic and bounded; an explicit DOMPurify reference beyond a
        # safety bound cannot establish a trusted version.
        size = len(text.encode("utf-8", "ignore"))
        total += size
        parent = str(PurePosixPath(relpath).parent)
        parent = "" if parent == "." else parent.strip("/")
        if index >= 256 or size > 2_000_000 or total > 16_000_000:
            if PurePosixPath(relpath).name.lower() in {"pnpm-lock.yaml", "yarn.lock"} \
                    or "dompurify" in text[:2_000_000].lower():
                locked.setdefault(parent, []).append(None)
            continue
        lock_name = PurePosixPath(relpath).name.lower()
        if lock_name in {"pnpm-lock.yaml", "yarn.lock"}:
            locked.setdefault(parent, []).extend(_javascript_lock_sanitizer_versions(lock_name, text))
            if lock_name == "pnpm-lock.yaml":
                for importer, values in _pnpm_importer_sanitizer_versions(text).items():
                    importer = "" if importer == "." else importer.strip("/")
                    scope = "/".join(part for part in (parent, importer) if part)
                    locked.setdefault(scope, []).extend(values or [None])
            else:
                yarn_locks[parent] = _yarn_sanitizer_resolutions(text)
            continue
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, RecursionError, MemoryError):
            if "dompurify" in text.lower():
                locked.setdefault(parent, []).append(None)
            continue
        if not isinstance(payload, dict):
            continue
        if PurePosixPath(relpath).name.lower() == "package-lock.json":
            packages = payload.get("packages")
            if isinstance(packages, dict):
                for package_path, item in packages.items():
                    normalized = str(package_path).replace("\\", "/").rstrip("/").lower()
                    if (normalized == "node_modules/dompurify" or normalized.endswith("/node_modules/dompurify")) \
                            and isinstance(item, dict):
                        prefix = normalized[:-len("/node_modules/dompurify")].strip("/") \
                            if normalized != "node_modules/dompurify" else ""
                        scope = "/".join(part for part in (parent, prefix) if part)
                        locked.setdefault(scope, []).append(item.get("version"))
            dependencies = payload.get("dependencies")
            item = dependencies.get("dompurify") if isinstance(dependencies, dict) else None
            if isinstance(item, dict):
                locked.setdefault(parent, []).append(item.get("version"))
        else:
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                dependencies = payload.get(group)
                candidate = dependencies.get("dompurify") if isinstance(dependencies, dict) else None
                if isinstance(candidate, str) and _EXACT_VERSION_RE.fullmatch(candidate):
                    manifests.setdefault(parent, []).append(candidate)
                    break
                if isinstance(candidate, str):
                    manifest_ranges.setdefault(parent, []).append(candidate)
                    break
    for scope, selectors in manifest_ranges.items():
        ancestors = [
            lock_scope for lock_scope in yarn_locks
            if not lock_scope or scope == lock_scope or scope.startswith(lock_scope + "/")
        ]
        if not ancestors:
            # A range declaration alone is not exact version evidence.
            manifests.setdefault(scope, []).append(None)
            continue
        lock_scope = max(ancestors, key=lambda value: (value.count("/"), len(value)))
        resolutions = yarn_locks[lock_scope]
        for selector in selectors:
            locked.setdefault(scope, []).extend(resolutions.get(selector) or [None])
    result: dict[str, dict[str, bool]] = {}
    for scope in sorted(set(locked) | set(manifests)):
        evidence = locked.get(scope) or manifests.get(scope) or []
        if evidence:
            result[scope] = {
                "dompurify": all(
                    _supported_exact_version(value, _SANITIZER_VERSION_MINIMUMS["dompurify"])
                    for value in evidence
                )
            }
    return result


def _javascript_sanitizer_versions(files: dict[str, str]) -> dict[str, bool]:
    """Root-package compatibility wrapper for direct program analysis."""
    return _javascript_sanitizer_version_scopes(files).get("", {})
_URL_TARGET_KINDS = frozenset({"redirect", "ssrf"})
_QUERY_MARK_RE = re.compile(r"[?#]")
_URL_PART_MEMBERS = frozenset({"search", "hash", "searchParams"})
# URL nesnesinin ana makineyi değiştirmeyen bölümleri: bunlara yazmak yönlendirme/SSRF hedefini kirletmez.
_URL_LOCAL_PARTS = frozenset({"search", "hash", "searchParams", "pathname"})
# Alıcıyı yerinde değiştiren metotlar: alıcı argümanların taint'ini taşır.
_JS_MUTATORS = frozenset({"push", "unshift", "splice", "set", "add", "append", "fill"})
# JS'e özgü ek hedef türleri (taint_models.KNOWN_KINDS dışında; yalnız koddan üretilir).
_JS_EXTRA_KINDS = frozenset({"nosql", "prototype", "template_object", "ssrf_partial"})
# DynamoDB (aws-sdk v2/v3) parametre nesnesinde metni girdiden kurulursa enjeksiyona açık anahtarlar.
_DYNAMO_OBJECT_KEYS = frozenset({
    "FilterExpression", "KeyConditionExpression", "ConditionExpression", "UpdateExpression", "ProjectionExpression",
    "TableName", "Statement",
})
_DYNAMO_PACKAGES = frozenset({"aws-sdk", "@aws-sdk/client-dynamodb", "@aws-sdk/lib-dynamodb", "dynamodb-toolbox"})
# Kısmi SSRF: sabit önekten sonra gelen URL parçası (yol/sorgu). Köken `cleaned` kümesine işaret olarak yazılır:
# sabit mutlak ana makine ('https://api.x/' + x) ya da göreli yol ('/v1/' + x; ancak çağrının tabanı sabitse kısmi).
_URL_ABS_MARK = "§url_abs"
_URL_REL_MARK = "§url_rel"
_BASE_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/{}\s%?#]+(?:[/?#]|$)")
_AXIOS_INSTANCE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
# Express/Koa/Fastify görünüm çağrıları: res.render(görünüm, yereller).
_RENDER_CALLS = frozenset({"res.render", "response.render", "ctx.render", "reply.view", "reply.render"})
_MAX_VIEW_TEMPLATES = 5_000
# İkinci derece kaynak: üçüncü taraf HTTP yanıtı (sunucunun yaptığı isteğin cevabı).
_SECOND_ORDER = "second_order"
# İkinci derece kaynak yalnız bu hedeflerde akış üretir (HTML/yönlendirme vb. için yanıt verisi gürültüdür).
_SECOND_ORDER_KINDS = frozenset({"eval", "command", "deserialize", "sql"})
_JS_ALL = tf._ALL_KINDS | _JS_EXTRA_KINDS
_WEAK = "weakrand"
_NOSQL_METHODS = frozenset({
    "find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "findOneAndRemove",
    "findAndModify", "update", "updateOne", "updateMany", "deleteOne", "deleteMany", "remove", "replaceOne",
    "countDocuments", "count", "distinct", "where", "aggregate", "exists",
})
_NOSQL_SANITIZERS = frozenset({
    "mongoSanitize", "mongoSanitize.sanitize", "mongo-sanitize", "sanitizeFilter", "mongoose.sanitizeFilter",
    "ExpressMongoSanitize.sanitize", "express-mongo-sanitize.sanitize",
})
# Nesne (işleç) taşıyabilen istek kaynakları: gövde/sorgu (qs) ve JSON.parse; yol parametresi ve başlık dizgedir.
_OBJECT_SOURCE_RE = re.compile(r"(?:^|[.{@(])(?:body|query|Body|Query|request\.body)\b|JSON\.parse|qs\.parse|querystring\.parse")
_NOT_MODEL_OWNERS = frozenset({
    "Math", "Object", "JSON", "Promise", "Array", "Reflect", "Date", "String", "Number", "Boolean", "Buffer",
    "Symbol", "Map", "Set", "URL", "Intl", "React", "Vue", "Error", "RegExp", "Proxy", "WeakMap", "Atomics",
    "URLSearchParams", "FormData", "Headers", "Response", "Request", "Blob", "File", "BigInt", "Function",
})
# Derin birleştirme (prototip kirletme, CWE-1321): kanonik ad → kaynak argümanların başladığı indeks.
_PROTO_MERGE = {
    "lodash.merge": 1, "lodash.mergeWith": 1, "lodash.defaultsDeep": 1, "deepmerge": 0, "deepmerge.all": 0,
    "merge.recursive": 1, "deep-extend": 1, "deepExtend": 1, "mixin-deep": 1, "merge-deep": 1,
    "defaults-deep": 1, "lodash.merge.default": 1, "hoek.merge": 1, "Hoek.merge": 1, "@hapi.hoek.merge": 1,
}
# Yol ile değer atayan API'ler: kanonik ad → yol argümanının indeksi.
_PROTO_SETTERS = {
    "lodash.set": 1, "lodash.setWith": 1, "lodash.zipObjectDeep": 0, "dot-prop.setProperty": 1, "dot-prop.set": 1,
    "dotProp.set": 1, "object-path.set": 1, "objectPath.set": 1, "set-value": 1, "dset": 1, "dset.dset": 1,
}
_PROTO_KEYS = frozenset({"__proto__", "constructor", "prototype"})
# NoSQL alıcı türü çıkarımı: paketler, TS tür adları ve fabrika çağrıları.
_MONGO_PACKAGES = frozenset({
    "mongoose", "mongodb", "monk", "mongojs", "marsdb", "@nestjs/mongoose", "@typegoose/typegoose", "typegoose",
    "mongoist", "mquery", "nedb", "@seald-io/nedb", "nedb-promises", "mongodb-memory-server",
})
_SQL_ORM_PACKAGES = frozenset({
    "sequelize", "sequelize-typescript", "typeorm", "@nestjs/typeorm", "@nestjs/sequelize", "@prisma/client", "knex",
    "objection", "@mikro-orm/core", "bookshelf", "pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "drizzle-orm",
    "kysely", "pg-promise", "tedious", "mssql", "oracledb",
})
_MONGO_TYPES = frozenset({
    "Collection", "MongoCollection", "ReturnModelType", "PaginateModel", "AggregatePaginateModel", "SoftDeleteModel",
    "MongoRepository", "AnyParamConstructor",
})
_ORM_TYPES = frozenset({
    "Repository", "EntityRepository", "TreeRepository", "EntityManager", "DataSource", "Connection", "PrismaClient",
    "Knex", "ModelStatic", "ModelCtor", "ModelDefined", "Sequelize", "QueryBuilder", "SelectQueryBuilder",
    "Pool", "PoolClient", "Client", "Kysely",
})
# TS tür açıklamasıyla gelen istek nesnesi (işleyici adla eşlenmese de; ör. Next.js API, Fastify).
_REQUEST_TYPES = frozenset({"NextApiRequest", "NextRequest", "FastifyRequest", "IncomingMessage"})
_RESPONSE_TYPES = frozenset({"NextApiResponse", "FastifyReply", "ServerResponse"})
_EXPRESS_PACKAGES = frozenset({"express", "express-serve-static-core", "@nestjs/common", "koa", "@koa/router"})
_NEXT_ROUTE_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_NEXT_ROUTE_RE = re.compile(r"(?:^|/)route\.(?:ts|js|mts|mjs)$")
# 17. tur (W1-JS): React bileşen prop'ları, URL durum kancaları, Hono, MCP araçları, Next.js sunucu eylemleri, JWT başlığı.
_PROP = "§prop"  # bileşen prop'u: yalnız bileşen özetinde hedef (prop adı → hedef); kendisi kaynak değildir
_COMPONENT_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9_$]*$")
_URL_STATE_HOOKS = frozenset({"useSearchParams", "useParams", "useLocation", "useRouter", "useQueryState"})
_URL_HOOK_PACKAGES = frozenset({"react-router", "react-router-dom", "next", "@remix-run/react", "@tanstack/react-router",
                                "wouter", "nuqs"})
_HONO_REQ_METHODS = frozenset({"query", "queries", "param", "json", "parseBody", "formData", "text", "header", "valid",
                               "arrayBuffer", "blob", "cookie"})
_HONO_ROUTER_CLASSES = frozenset({"Hono", "OpenAPIHono", "Elysia"})
_MCP_PACKAGES = frozenset({"@modelcontextprotocol/sdk"})
_MCP_ARG_METHODS = frozenset({"tool", "registerTool", "prompt", "registerPrompt"})
_MCP_RESOURCE_METHODS = frozenset({"resource", "registerResource"})
_JWT_PACKAGES = frozenset({"jsonwebtoken", "jose"})
_JWT_KEY_CALLBACK_CALLS = frozenset({"verify", "jwtVerify"})
_REPLY_CHAIN_RE = re.compile(r"^(res|response|reply|rep)((?:\.(?:code|status|type|header|headers|set|vary|cookie|location)\(\))+)\.send$")
_NEXT_NAV_REDIRECTS = frozenset({"redirect", "permanentRedirect"})
_LOCATION_APP_STATE = frozenset({"state", "key"})


def _only_location_hook(taint: Any) -> bool:
    return bool(taint) and all(o.source.startswith("useLocation()") for o in taint)
# NestJS: dönüştüren/doğrulayan boru hatları ve class-validator alan doğrulayıcıları (değer sayı/UUID/sabit kümeye indirgenir).
_NEST_SAFE_PIPES = frozenset({"ParseIntPipe", "ParseFloatPipe", "ParseBoolPipe", "ParseUUIDPipe", "ParseEnumPipe"})
_DTO_SAFE_VALIDATORS = frozenset({
    "IsInt", "IsNumber", "IsNumberString", "IsBoolean", "IsBooleanString", "IsUUID", "IsMongoId", "IsIn", "IsEnum",
    "IsDate", "IsDateString", "IsISO8601", "IsPositive", "IsNegative", "Min", "Max", "IsHexadecimal", "IsAlphanumeric",
    "IsAlpha", "IsNumeric", "IsDecimal", "IsLatLong", "IsPort", "IsISO31661Alpha2", "IsCurrency", "IsHexColor",
})
_NEXT_APP_PAGE_RE = re.compile(r"(?:^|/)app/(?:.*/)?(?:page|layout|default)\.(?:tsx|jsx|ts|js)$")
_NEXT_SSR_EXPORTS = frozenset({"getServerSideProps", "generateMetadata"})
_PREPARE_SQL_PACKAGES = frozenset({"better-sqlite3", "sqlite3", "sqlite", "mysql2", "bun:sqlite", "@libsql/client", "libsql"})
# TypeORM sorgu oluşturucu: dize koşul/sıralama ifadesi ham SQL parçasıdır (parametre bağlama :ad ile).
_QUERY_BUILDER_SQL_METHODS = frozenset({
    "where", "andWhere", "orWhere", "having", "andHaving", "orHaving", "orderBy", "addOrderBy", "groupBy",
    "addGroupBy", "select", "addSelect", "innerJoin", "leftJoin", "innerJoinAndSelect", "leftJoinAndSelect",
})
# Angular HttpClient (DI ile this.http): yanıt sunucudan gelen veridir (ikinci derece, "stored").
_HTTP_CLIENT_FIELDS = frozenset({"http", "httpclient", "_http", "httpservice", "client"})
_HTTP_CLIENT_METHODS = frozenset({"get", "post", "put", "patch", "delete", "request", "jsonp", "head"})
# DomSanitizer'ı atlatan bilinen boru (pipe) adları; projedeki @Pipe sınıfları ayrıca incelenir.
_BYPASS_PIPES = frozenset({"safe", "safeHtml", "safeUrl", "safeResourceUrl", "trustHtml", "trusted", "bypassHtml", "noSanitize", "bypassSecurityTrust"})
_MONGO_FACTORIES = frozenset({"collection", "getCollection", "getModelForClass", "getMongoRepository", "getDiscriminatorModelForClass"})
_ORM_FACTORIES = frozenset({"define", "getRepository", "getCustomRepository", "getTreeRepository", "getManager",
                            "createQueryBuilder", "withRepository", "PrismaClient"})
_ORM_CLASS_DECORATORS = frozenset({"Entity", "Table", "ViewEntity", "Model"})


def _static_path(node: Any, module_dir: PurePosixPath, depth: int = 0) -> str | None:
    """Statik yol ifadesi: dize, `__dirname`, `path.join/resolve(...)`, `${__dirname}/x`, `${handlerPath(__dirname)}/x`.

    Sonuç proje köküne göre normalleştirilmiş göreli yoldur (kök dışına çıkan yol None); `__dirname` içermeyen
    göreli dizeler olduğu gibi döner (çağıran bunları sonek olarak eşler)."""
    if depth > 6 or not isinstance(node, dict):
        return None
    kind = _t(node)
    if kind in {"StringLiteral", "Literal"} and isinstance(node.get("value"), str):
        return node["value"]
    if kind == "Identifier" and node.get("name") == "__dirname":
        return "\0" + str(module_dir)
    if kind == "CallExpression":
        name = _callee_name(node.get("callee"))
        args = node.get("arguments") or []
        if name in {"path.join", "path.resolve", "join", "resolve", "path.posix.join"} and args:
            parts = [_static_path(a, module_dir, depth + 1) for a in args]
            if any(part is None for part in parts):
                return None
            return _join_static(parts)
        if name.rsplit(".", 1)[-1] == "handlerPath" and len(args) == 1:
            return _static_path(args[0], module_dir, depth + 1)
        return None
    if kind == "TemplateLiteral":
        quasis = node.get("quasis") or []
        expressions = node.get("expressions") or []
        parts: list[str] = []
        for index, quasi in enumerate(quasis):
            parts.append(((quasi.get("value") or {}).get("cooked") or ""))
            if index < len(expressions):
                value = _static_path(expressions[index], module_dir, depth + 1)
                if value is None:
                    return None
                parts.append(value)
        return "".join(parts)
    return None


def _join_static(parts: list[str]) -> str:
    """path.join: `__dirname` işaretli (\\0) parça kökü sıfırlar ve işaret sonuca taşınır."""
    joined = PurePosixPath("")
    rooted = False
    for part in parts:
        if part.startswith("\0"):
            joined, rooted = PurePosixPath(part[1:]), True
        else:
            joined = joined / part.lstrip("/")
    return ("\0" if rooted else "") + str(joined)


def _normalize_static(value: str) -> tuple[str, bool] | None:
    """(normal yol, kökten mi) — `__dirname` içerenler proje köküne göre, diğerleri göreli sonektir."""
    rooted = "\0" in value
    if rooted:
        value = value[value.rindex("\0") + 1:]
    value = value.replace("\0", "")
    normal = os.path.normpath(value.strip("/") or ".").replace(os.sep, "/")
    if normal.startswith("../") or normal == ".." or normal == ".":
        return None
    return normal.removeprefix("./"), rooted


def _package_root(spec: str) -> str:
    spec = spec.removeprefix("node:")
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]
_PROTO_ASSIGN = "obj[key][key] ="
# Dizge döndüren metotlar: sonuç NoSQL işleç nesnesi olamaz.
_STRING_METHODS = frozenset({
    "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase",
    "toString", "slice", "substring", "substr", "padStart", "padEnd", "normalize", "replace", "replaceAll",
    "charAt", "concat", "repeat", "toFixed", "join", "String",
})
# Şablon motorları: şablon metni kod olarak derlenir (sunucu tarafı şablon enjeksiyonu).
_DERIVING_CALLS = frozenset({
    "URL", "new URL", "url.parse", "url.URL", "new url.URL", "path.resolve", "path.normalize", "path.join",
    "fs.realpathSync", "path.posix.resolve", "path.posix.normalize", "path.posix.join",
})
_QUOTE_CHARS = frozenset({"'", '"'})
_LDAP_OWNER_RE = re.compile(r"ldap", re.IGNORECASE)


class _Undefined:
    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"


_UNDEF = _Undefined()
_UNKNOWN: Any = object()
_MAX_CONST_STR = 10_000


def _js_type(value: Any) -> str:
    if value is None:
        return "null"
    if value is _UNDEF:
        return "undefined"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "object"


def _js_truthy(value: Any) -> bool:
    if value is None or value is _UNDEF:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == value and value != 0
    if isinstance(value, str):
        return value != ""
    return True


def _js_str(value: Any) -> str:
    if value is None:
        return "null"
    if value is _UNDEF:
        return "undefined"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value != value:
            return "NaN"
        if value in (float("inf"), float("-inf")):
            return "Infinity" if value > 0 else "-Infinity"
        if value.is_integer() and abs(value) < 1e21:
            return str(int(value))
        return repr(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return ",".join("" if item is None or item is _UNDEF else _js_str(item) for item in value)
    if isinstance(value, dict):
        return "[object Object]"
    return str(value)


def _js_num(value: Any) -> float | int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return 0
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(text, 0) if text.lower().startswith(("0x", "0o", "0b")) else float(text)
        except ValueError:
            return float("nan")
    return float("nan")


def _js_strict_eq(left: Any, right: Any) -> bool:
    if _js_type(left) != _js_type(right):
        return False
    if isinstance(left, (list, dict)):
        return left is right
    return left == right


def _js_loose_eq(left: Any, right: Any) -> Any:
    lt, rt = _js_type(left), _js_type(right)
    if lt == rt:
        return _js_strict_eq(left, right)
    if {lt, rt} == {"null", "undefined"}:
        return True
    if "null" in (lt, rt) or "undefined" in (lt, rt):
        return False
    if {lt, rt} <= {"number", "string", "boolean"}:
        return _js_num(left) == _js_num(right)
    return _UNKNOWN


def _const_key(value: Any) -> str | None:
    """Sabit dizin/anahtar değeri → alan adı (dize veya tam sayı)."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool) and float(value).is_integer():
        return str(int(value))
    return None


def _assigned_names(node: Any, limit: int = 50_000, *, declarations: bool = True) -> set[str]:
    """Bir gövdede atanan/artırılan yerel adlar (döngü ve iç fonksiyon sabitlerini unutmak için)."""
    names: set[str] = set()
    for child in _walk(node, limit):
        kind = _t(child)
        if kind == "AssignmentExpression":
            names.update(_pattern_names(child.get("left")))
            if _t(child.get("left")) in {"MemberExpression", "OptionalMemberExpression"}:
                chain = _chain(child.get("left"))
                if chain:
                    names.add(chain[0])
        elif kind == "UpdateExpression":
            names.update(_pattern_names(child.get("argument")))
        elif kind == "VariableDeclarator" and declarations:
            names.update(_pattern_names(child.get("id")))
        elif kind in {"ForInStatement", "ForOfStatement"} and _t(child.get("left")) != "VariableDeclaration":
            names.update(_pattern_names(child.get("left")))
        elif kind == "CallExpression":
            callee = child.get("callee")
            if _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
                chain = _chain(callee.get("object"))
                method = (callee.get("property") or {}).get("name", "")
                if chain and method in _JS_MUTATORS | {"pop", "shift", "reverse", "sort", "delete", "clear"}:
                    names.add(chain[0])
    return names


def _declared_locals(body: Any) -> set[str]:
    """Gövdede bildirilen yerel adlar (var/let/const, fonksiyon bildirimleri, catch parametresi)."""
    names: set[str] = set()
    for child in _walk(body, 50_000):
        kind = _t(child)
        if kind == "VariableDeclarator":
            names.update(_pattern_names(child.get("id")))
        elif kind in {"FunctionDeclaration", "ClassDeclaration"} and child.get("id"):
            names.add(child["id"].get("name", ""))
        elif kind == "CatchClause" and child.get("param"):
            names.update(_pattern_names(child.get("param")))
    return names


def _nested_function_writes(body: Any, inner_cache: dict[int, set[str]] | None = None) -> set[str]:
    """İç fonksiyonların (closure) yazdığı adlar: bunlar dışta sabit sayılmaz.

    ``inner_cache``: iç fonksiyon gövdesi (id) → atanan adlar. İç içe kapanışlarda aynı iç gövde her dış gövde
    için yeniden yürünüyordu (19. tur hız); önbellek ağacı tutan proje nesnesinde yaşar, sonuç aynıdır."""
    names: set[str] = set()
    for child in _walk(body, 100_000):
        if child is not body and _is_function(child):
            inner = child.get("body")
            if inner_cache is None:
                names |= _assigned_names(inner, 20_000, declarations=False)
                continue
            written = inner_cache.get(id(inner))
            if written is None:
                written = inner_cache[id(inner)] = _assigned_names(inner, 20_000, declarations=False)
            names |= written
    return names


def _object_capable(taint: Taint) -> Taint:
    """İşleç/anahtar nesnesi taşıyabilen kökenler (gövde/sorgu/JSON.parse; sembolik kökenler korunur)."""
    return tuple(o for o in taint if o.label != "request" or _OBJECT_SOURCE_RE.search(o.source))


def _quote_pattern(node: Any) -> bool:
    """'\'' / '"' / /'/g / /["']/g: yalnız tırnak karakterini eşleyen desen."""
    literal = _string_value(node)
    if literal is not None:
        return literal in _QUOTE_CHARS
    if _t(node) == "RegExpLiteral":
        pattern = str(node.get("pattern", ""))
        core = pattern[1:-1] if pattern.startswith("[") and pattern.endswith("]") else pattern
        core = core.replace("\\", "")
        return bool(core) and set(core) <= _QUOTE_CHARS
    return False


def _safe_url_prefix(first: str) -> bool:
    """URL'nin sabit ilk parçası hedef ana makineyi sabitliyor mu?

    "/yol/" (ama "//" veya "/\\" değil: protokol-göreli taşma), "?" veya "#" (yalnız sorgu/parça)
    ya da sabit şema+ana makine+"/" ile başlayan URL'de girdi hedefi değiştiremez."""
    if first.startswith(("?", "#")):
        return True
    if len(first) >= 2 and first[0] == "/" and first[1] not in "/\\":
        return True
    return bool(tf._URL_FIXED_HOST_RE.match(first))


def _url_prefix_literal(node: Any) -> str | None:
    """Birleştirme/şablon dizesinin sabit ilk parçası (yoksa None)."""
    if _t(node) == "TemplateLiteral":
        quasis = node.get("quasis") or []
        if quasis and node.get("expressions"):
            return (quasis[0].get("value") or {}).get("cooked") or ""
        return None
    if _t(node) == "BinaryExpression" and node.get("operator") == "+":
        left = node.get("left")
        while _t(left) == "BinaryExpression" and left.get("operator") == "+":
            left = left.get("left")
        return _string_value(left)
    return None


def _fixed_url_target(node: Any) -> bool:
    first = _url_prefix_literal(node)
    return isinstance(first, str) and _safe_url_prefix(first)


def _fixed_url_prefix(node: Any) -> bool:
    first: Any = None
    if _t(node) == "TemplateLiteral":
        quasis = node.get("quasis") or []
        if quasis and node.get("expressions"):
            first = (quasis[0].get("value") or {}).get("cooked") or ""
    elif _t(node) == "BinaryExpression" and node.get("operator") == "+":
        left = node.get("left")
        while _t(left) == "BinaryExpression" and left.get("operator") == "+":
            left = left.get("left")
        first = _string_value(left)
    return isinstance(first, str) and bool(tf._URL_FIXED_HOST_RE.match(first))


def _url_mark(first: str) -> frozenset[str]:
    """Güvenli URL önekinin kısmi SSRF işareti: sabit mutlak ana makine ya da göreli yol/sorgu."""
    return frozenset({_URL_ABS_MARK if tf._URL_FIXED_HOST_RE.match(first) else _URL_REL_MARK})


def _pattern_names(pattern: Any) -> list[str]:
    names: list[str] = []
    stack = [pattern]
    while stack:
        node = stack.pop()
        kind = _t(node)
        if kind == "Identifier":
            names.append(node.get("name", ""))
        elif kind == "ObjectPattern":
            for prop in node.get("properties", []):
                stack.append(prop.get("value") if _t(prop) == "ObjectProperty" else prop.get("argument"))
        elif kind == "ArrayPattern":
            stack.extend(item for item in node.get("elements", []) if item)
        elif kind == "AssignmentPattern":
            stack.append(node.get("left"))
        elif kind == "RestElement":
            stack.append(node.get("argument"))
        elif kind == "TSParameterProperty":
            stack.append(node.get("parameter"))
    return [name for name in names if name]


def _is_constant_collection(node: Any) -> bool:
    kind = _t(node)
    if kind == "ArrayExpression":
        elements = node.get("elements") or []
        return bool(elements) and all(_t(e) in {"StringLiteral", "NumericLiteral", "BooleanLiteral"} for e in elements)
    if kind == "ObjectExpression":
        return bool(node.get("properties"))
    if kind == "NewExpression" and _dotted(node.get("callee")) == "Set":
        args = node.get("arguments") or []
        return bool(args) and _is_constant_collection(args[0])
    if kind in {"Identifier", "MemberExpression"}:
        last = (_chain(node) or [""])[-1]
        return bool(last) and (last.isupper() or bool(tf._ALLOWLIST_NAME_RE.search(last)))
    if kind == "CallExpression" and _callee_name(node.get("callee")).endswith(("Object.keys", "Object.values")):
        return True
    return False


def _guard_names(node: Any) -> list[str]:
    """Koşulda doğrulanan adlar: en dıştaki ad/üye zinciri (req.body.id doğrulanınca req.body değil)."""
    names: list[str] = []
    stack = [node]
    count = 0
    while stack and count < 2_000:
        child = stack.pop()
        count += 1
        kind = _t(child)
        if kind == "Identifier":
            names.append(child.get("name", ""))
            continue
        if kind in {"MemberExpression", "OptionalMemberExpression"}:
            dotted = _dotted(child)
            if dotted:
                names.append(dotted)
                continue
        if kind in {"CallExpression", "OptionalCallExpression"}:
            callee = child.get("callee")
            if _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
                stack.append(callee.get("object"))
            stack.extend(child.get("arguments") or [])
            continue
        stack.extend(_children(child))
    return [name for name in names if name]


def _terminates(body: Any) -> bool:
    statements = body.get("body") if _t(body) == "BlockStatement" else [body]
    if not statements:
        return False
    last = statements[-1]
    kind = _t(last)
    if kind in {"ReturnStatement", "ThrowStatement", "ContinueStatement", "BreakStatement"}:
        return True
    if kind == "ExpressionStatement" and _t(last.get("expression")) == "CallExpression":
        return _callee_name(last["expression"].get("callee")) == "process.exit"
    if kind == "IfStatement" and last.get("alternate"):
        return _terminates(last["consequent"]) and _terminates(last["alternate"])
    if kind == "BlockStatement":
        return _terminates(last)
    return False


# ---------------------------------------------------------------------------
# Modül dizini
# ---------------------------------------------------------------------------


class JsModule:
    def __init__(self, relpath: str, program: Node) -> None:
        self.relpath = relpath
        self.program = program
        self.functions: dict[str, Node] = {}
        self.classes: dict[str, Node] = {}
        self.class_bases: dict[str, Node] = {}
        self.objects: dict[str, dict[str, str]] = {}
        self.instances: dict[str, str] = {}
        # function X(db) { this.m = function () {} } biçimindeki yapıcı fonksiyonlar
        self.ctor_functions: set[str] = set()
        self.exports: dict[str, tuple[str, ...]] = {}
        self.star_exports: list[str] = []
        self.imports: dict[str, tuple[str, str]] = {}
        self.immutable_imports: set[str] = set()
        # Üst düzey adların ilk değer düğümleri (NoSQL model/koleksiyon türü çıkarımı için).
        self.values: dict[str, Node] = {}
        self.const_values: set[str] = set()
        for statement in program.get("body", []):
            self._index(statement)
        # A ``const`` binding can still point at a mutated array.  Expanding it
        # into Express middleware would then invent registration order, so only
        # declarations never assigned or mutated anywhere in the module qualify.
        assigned = _assigned_names(program, declarations=False)
        self.static_values = self.const_values - assigned
        self.immutable_imports -= assigned

    # -- yerel tanımlar ---------------------------------------------------------
    def _index_class(self, name: str, node: Node) -> None:
        self.classes[name] = node
        if node.get("superClass"):
            self.class_bases[name] = node["superClass"]
        for member in (node.get("body") or {}).get("body", []):
            key = _key_name(member)
            if not key:
                continue
            if _t(member) in {"ClassMethod", "ClassPrivateMethod"}:
                accessor = member.get("kind") if member.get("kind") in {"get", "set"} else ""
                self.functions[f"{name}.{accessor} {key}" if accessor else f"{name}.{key}"] = member
            elif _t(member) in {"ClassProperty", "ClassPrivateProperty"} and _is_function(member.get("value")):
                self.functions[f"{name}.{key}"] = member["value"]

    def _index_object(self, name: str, node: Node) -> None:
        members: dict[str, str] = {}
        for prop in node.get("properties", []):
            key = _key_name(prop)
            if not key:
                continue
            if _t(prop) == "ObjectMethod":
                self.functions[f"{name}.{key}"] = prop
                members[key] = f"{name}.{key}"
            elif _t(prop) == "ObjectProperty":
                value = prop.get("value")
                if _is_function(value):
                    self.functions[f"{name}.{key}"] = value
                    members[key] = f"{name}.{key}"
                elif _t(value) == "Identifier":
                    members[key] = "@" + value.get("name", "")
        self.objects[name] = members

    def _require_source(self, node: Any) -> tuple[str, str] | None:
        """require('x') → ('x', '*'); require('x').y → ('x', 'y')."""
        if _t(node) == "CallExpression" and _dotted(node.get("callee")) == "require":
            args = node.get("arguments") or []
            spec = _string_value(args[0]) if args else None
            return (spec, "*") if spec else None
        if _t(node) == "MemberExpression" and not node.get("computed"):
            inner = self._require_source(node.get("object"))
            prop = (node.get("property") or {}).get("name", "")
            if inner and inner[1] == "*" and prop:
                return (inner[0], prop)
        if _t(node) == "AwaitExpression" and _t(node.get("argument")) == "ImportExpression":
            return None
        return None

    def _index_ctor_methods(self, name: str, fn: Node) -> None:
        body = fn.get("body")
        if _t(body) != "BlockStatement":
            return
        for statement in body.get("body", []):
            expression = statement.get("expression") if _t(statement) == "ExpressionStatement" else None
            if _t(expression) != "AssignmentExpression":
                continue
            chain = _chain(expression.get("left"))
            if chain and len(chain) == 2 and chain[0] == "this" and _is_function(expression.get("right")):
                self.functions[f"{name}.{chain[1]}"] = expression["right"]
                self.ctor_functions.add(name)

    def _index_value(self, name: str, init: Any) -> None:
        kind = _t(init)
        if isinstance(init, dict):
            self.values.setdefault(name, init)
        if _is_function(init):
            self.functions[name] = init
            self._index_ctor_methods(name, init)
        elif kind == "ObjectExpression":
            self._index_object(name, init)
        elif kind == "ClassExpression":
            self._index_class(name, init)
        elif kind == "NewExpression" and _t(init.get("callee")) == "Identifier":
            self.instances[name] = init["callee"].get("name", "")
        else:
            source = self._require_source(init)
            if source is not None:
                self.imports[name] = source

    def _index(self, node: Node) -> None:
        kind = _t(node)
        if kind == "FunctionDeclaration" and node.get("id"):
            self.functions[node["id"].get("name", "")] = node
            self._index_ctor_methods(node["id"].get("name", ""), node)
        elif kind == "ClassDeclaration" and node.get("id"):
            self._index_class(node["id"].get("name", ""), node)
        elif kind == "VariableDeclaration":
            for declarator in node.get("declarations", []):
                target, init = declarator.get("id"), declarator.get("init")
                if _t(target) == "Identifier":
                    if node.get("kind") == "const":
                        self.const_values.add(target.get("name", ""))
                    self._index_value(target.get("name", ""), init)
                elif _t(target) == "ObjectPattern":
                    source = self._require_source(init)
                    if source is not None and source[1] == "*":
                        for prop in target.get("properties", []):
                            if _t(prop) == "ObjectProperty" and _t(prop.get("value")) == "Identifier":
                                local = prop["value"].get("name", "")
                                self.imports[local] = (source[0], _key_name(prop))
                                if node.get("kind") == "const":
                                    self.immutable_imports.add(local)
        elif kind == "ImportDeclaration":
            spec = str((node.get("source") or {}).get("value", ""))
            for item in node.get("specifiers", []):
                local = (item.get("local") or {}).get("name", "")
                self.immutable_imports.add(local)
                if _t(item) == "ImportDefaultSpecifier":
                    self.imports[local] = (spec, "default")
                elif _t(item) == "ImportNamespaceSpecifier":
                    self.imports[local] = (spec, "*")
                else:
                    imported = item.get("imported") or {}
                    self.imports[local] = (spec, imported.get("name") or str(imported.get("value", "")))
        elif kind == "ExportNamedDeclaration":
            declaration = node.get("declaration")
            source = (node.get("source") or {}).get("value")
            if declaration:
                self._index(declaration)
                for name in self._declared_names(declaration):
                    self.exports[name] = ("local", name)
            for item in node.get("specifiers", []):
                local = (item.get("local") or {}).get("name", "")
                exported = (item.get("exported") or {}).get("name") or str((item.get("exported") or {}).get("value", ""))
                if source:
                    self.exports[exported] = ("reexport", str(source), local or "*")
                else:
                    self.exports[exported] = ("local", local)
        elif kind == "ExportAllDeclaration":
            self.star_exports.append(str((node.get("source") or {}).get("value", "")))
        elif kind == "ExportDefaultDeclaration":
            declaration = node.get("declaration") or {}
            if _t(declaration) in {"FunctionDeclaration", "ClassDeclaration"} and declaration.get("id"):
                self._index(declaration)
                self.exports["default"] = ("local", declaration["id"].get("name", ""))
            elif _t(declaration) == "Identifier":
                self.exports["default"] = ("local", declaration.get("name", ""))
            elif _t(declaration) in {"FunctionDeclaration", "ClassDeclaration"}:
                self._index_value("default", {**declaration, "type": "ClassExpression" if _t(declaration) == "ClassDeclaration" else "FunctionExpression"})
                self.exports["default"] = ("local", "default")
            else:
                self._index_value("default", declaration)
                self.exports["default"] = ("local", "default")
        elif kind == "ExpressionStatement" and _t(node.get("expression")) == "AssignmentExpression":
            self._index_assignment(node["expression"])
        elif kind == "TSExportAssignment":
            self._index_value("module.exports", node.get("expression"))
            self.exports["*"] = ("local", "module.exports")

    def _index_assignment(self, assign: Node) -> None:
        chain = _chain(assign.get("left"))
        value = assign.get("right")
        if chain == ["module", "exports"]:
            if _t(value) == "Identifier":
                self.exports["*"] = ("local", value.get("name", ""))
            else:
                self._index_value("module.exports", value)
                self.exports["*"] = ("local", "module.exports")
        elif chain and len(chain) == 3 and chain[:2] == ["module", "exports"] or chain and len(chain) == 2 and chain[0] == "exports":
            name = chain[-1]
            if _t(value) == "Identifier":
                self.exports[name] = ("local", value.get("name", ""))
            else:
                self._index_value(f"exports.{name}", value)
                self.exports[name] = ("local", f"exports.{name}")
        elif chain and len(chain) == 2 and chain[0] in self.objects and _is_function(value):
            # const ctrl = {}; ctrl.create = (req, res) => ...
            self.functions[".".join(chain)] = value
            self.objects[chain[0]][chain[1]] = ".".join(chain)

    @staticmethod
    def _declared_names(node: Node) -> list[str]:
        if _t(node) in {"FunctionDeclaration", "ClassDeclaration"} and node.get("id"):
            return [node["id"].get("name", "")]
        if _t(node) == "VariableDeclaration":
            return [name for d in node.get("declarations", []) for name in _pattern_names(d.get("id"))]
        return []


# Çözümlenmiş başvuru: ("func", modül, nitelikli ad) | ("class", modül, ad) | ("object", modül, ad)
# | ("module", modül, "") | ("instance", modül, sınıf) | ("router", modül, yerel ad)
Ref = tuple[str, JsModule, str]


class JsProject:
    MAX_DEPTH = 30
    # Re-export resolution alternates through lookup/export and therefore uses
    # roughly two steps per barrel.  Keep a separate finite budget large enough
    # for ordinary monorepo barrel trees while still terminating cycles.
    MAX_RESOLVE_DEPTH = 32

    def __init__(self, pii: tf.PiiClassifier | None, *, max_steps: int, handler_names: frozenset[str] = frozenset()) -> None:
        self.pii = pii
        self.models = taint_models.models_for("javascript")
        self.modules: dict[str, JsModule] = {}
        self.flows: dict[str, list[tf.Flow]] = {}
        # 25. tur (kalıcı depo modeli): ORM yazımında istek verisi alan alanlar → ilk yazım yeri; kayıtlı veri bu
        # alanlardan okunup gövde olarak gönderilirse (res.send(kayit.alan)) yazma kanıtıyla raporlanır.
        self.user_written_attrs: dict[str, tuple[str, int]] = {}
        self.pending_stored_sends: list[tuple[str, int, str, str, Taint]] = []
        self.clean: dict[str, set[tuple[str, int]]] = {}
        self.summaries: dict[int, tf._PySummary] = {}
        self.handlers: set[int] = set()
        self.handler_names = handler_names
        # Giriş noktası parametreleri: fonksiyon düğümü → {parametre indeksi: kaynak tanımı} (bütün parametre
        # istemci verisidir: Lambda event, GraphQL args, onCall data) ve istek kökü sayılacak indeksler.
        self.entry_params: dict[int, dict[int, str]] = {}
        self.entry_roots: dict[int, set[int]] = {}
        # Projede en az bir çağrı yerinde uygulanan fonksiyon düğümleri (çağıranı olmayan dışa aktarmalar için).
        self.called: set[int] = set()
        # Hedefe parametre izi ulaşan ama projede çağıranı olmayan dışa aktarılmış fonksiyonlar: modellenmemiş
        # bir çatının giriş noktası olabilir → "temiz" hükmü verilmez (hotspot düşürülmez).
        self.uncertain: dict[str, set[tuple[str, int]]] = {}
        self._emitted: dict[str, set[tuple[str, int, str, int, str]]] = {}
        self._active: set[int] = set()
        self._depth = 0
        self.steps = 0
        self.max_steps = max_steps
        self.extra: list[tuple[JsModule, str, Node, str | None, dict[str, Taint], dict[str, Ref]]] = []
        self._field_types: dict[tuple[str, str], dict[str, Ref]] = {}
        self._closure_writes: dict[int, set[str]] = {}
        self._program_walks: dict[tuple[str, int], list[Node]] = {}  # modül → program düğümleri (ön-sıra, ≤400.000)
        self._inner_writes: dict[int, set[str]] = {}  # iç fonksiyon gövdesi → atanan adlar (closure_writes için)
        # Yardımcı işlevin içerik türü etkisi proje AST'sine aittir. Modül geneli ``id(node)`` önbelleği,
        # önceki AST serbest kalınca aynı kimliği alan başka projenin sonucunu taşıyabiliyordu.
        self._content_type_params: dict[int, tuple[Node, dict[int, bool]]] = {}
        self._value_kinds: dict[tuple[str, str], str | None] = {}
        # classify → _returns_kind önbellekleri: fonksiyonun return argümanları (bir kez gezilir) ve
        # (fonksiyon, derinlik) → tür. Hesaplanmakta olan value_kind döngü korumasına dayanan sonuç saklanmaz.
        self._return_args: dict[int, list[Any]] = {}
        self._returns_kinds: dict[tuple[int, int], str | None] = {}
        self._value_kinds_active: set[tuple[str, str]] = set()
        self._value_kind_guard_hits = 0
        self._field_kinds: dict[tuple[str, str], dict[str, str | None]] = {}
        self._db_packages: tuple[bool, bool] | None = None
        self._string_members: frozenset[str] | None = None
        self._uses_dynamodb: bool | None = None
        self._package_roots: frozenset[str] | None = None
        # React bileşeni mi? (fonksiyon düğümü kimliği → bool)
        self._components: dict[int, bool] = {}
        self._router_names: dict[str, frozenset[str]] = {}
        # Fields populated from request data by a registered middleware,
        # expressed relative to the request root (for example context.name).
        # Handler function id -> request fields supplied by middleware registered
        # on the same app/router before that handler.
        self.handler_middleware_paths: dict[int, set[tuple[str, ...]]] = {}
        # Exact locally locked sanitizer versions.  Missing entries deliberately
        # preserve the long-standing model behaviour for compatibility.
        self.sanitizer_versions: dict[str, bool] = {}
        self.sanitizer_version_scopes: dict[str, dict[str, bool]] = {}
        self._validation_pipe: bool | None = None
        # Angular şablonları: {göreli yol: metin} (verilmezse etkin proje kökünden güvenle okunur).
        self.templates: dict[str, str] | None = None
        self.template_root: Path | None = None
        # Sunucu tarafı görünüm şablonları (res.render): envanter, app.set('views' / 'view engine'), kaçışsız çıktılar.
        self._view_inventory: frozenset[str] | None = None
        self._view_config: tuple[list[str], list[str]] | None = None
        self._view_outputs: dict[str, list[tuple[int, str, list[tuple[str, ...]]]]] = {}

    def sanitizer_version(self, module: JsModule, package: str) -> bool | None:
        """Nearest ancestor package-root verdict for a source module."""
        parent = str(PurePosixPath(module.relpath).parent)
        parent = "" if parent == "." else parent.strip("/")
        matches = [
            scope for scope, versions in self.sanitizer_version_scopes.items()
            if package in versions and (not scope or parent == scope or parent.startswith(scope + "/"))
        ]
        if matches:
            scope = max(matches, key=lambda value: (value.count("/"), len(value)))
            return self.sanitizer_version_scopes[scope][package]
        return self.sanitizer_versions.get(package)

    # -- sunucu tarafı görünüm şablonları ----------------------------------------------
    def view_inventory(self) -> frozenset[str]:
        """Projedeki EJS/Pug/Handlebars şablonlarının göreli yolları (bir kez toplanır)."""
        if self._view_inventory is None:
            found: set[str] = set()
            exts = taint_js_views.TEMPLATE_EXTS
            if "nunjucks" in self.view_config()[1]:
                exts = exts + taint_js_views.NUNJUCKS_HTML_EXTS  # Nunjucks .html şablonları
            if self.templates is not None:
                found = {path for path in self.templates if path.lower().endswith(exts)}
            elif self.template_root is not None:
                state = tf._PROJECT.get()
                skip = getattr(state, "skip_dirs", frozenset({"node_modules", ".git"}))
                try:
                    walker = tf._walk_project_files(Path(self.template_root), skip, frozenset(exts))
                    for index, path in enumerate(walker):
                        if index >= _MAX_VIEW_TEMPLATES:
                            break
                        found.add(path.relative_to(self.template_root).as_posix())
                except (OSError, ValueError):
                    pass
            self._view_inventory = frozenset(found)
        return self._view_inventory

    def view_config(self) -> tuple[list[str], list[str]]:
        """``app.set('views', …)`` dizinleri ve ``app.set('view engine', …)`` motorları (proje geneli)."""
        if self._view_config is None:
            dirs: list[str] = []
            engines: list[str] = []
            for module in self.modules.values():
                module_dir = PurePosixPath(module.relpath).parent
                nunjucks = False
                for node in self._program_nodes(module, 200_000):
                    if _t(node) != "CallExpression":
                        continue
                    callee = node.get("callee")
                    args = node.get("arguments") or []
                    if _t(callee) == "Identifier" and callee.get("name") == "require" and args \
                            and _string_value(args[0]) in ("nunjucks", "express-nunjucks"):
                        nunjucks = True
                        if "nunjucks" not in engines:
                            engines.append("nunjucks")
                        continue
                    if nunjucks and _t(callee) == "MemberExpression" and (callee.get("property") or {}).get("name") == "configure" \
                            and args and _t(args[0]) != "ObjectExpression":
                        raw = _static_path(args[0], module_dir)  # nunjucks.configure('şablonlar', { express: app })
                        normal = _normalize_static(raw) if raw is not None else None
                        if normal is not None and normal[0] not in dirs:
                            dirs.append(normal[0])
                        continue
                    if _t(callee) != "MemberExpression" or (callee.get("property") or {}).get("name") != "set":
                        continue
                    args = node.get("arguments") or []
                    key = _string_value(args[0]) if len(args) >= 2 else None
                    if key == "view engine":
                        engine = _string_value(args[1])
                        if engine and engine not in engines:
                            engines.append(engine)
                    elif key == "views":
                        values = args[1].get("elements") if _t(args[1]) == "ArrayExpression" else [args[1]]
                        for value in values or []:
                            raw = _static_path(value, module_dir)
                            normal = _normalize_static(raw) if raw is not None else None
                            if normal is not None and normal[0] not in dirs:
                                dirs.append(normal[0])
            self._view_config = (dirs, engines)
        return self._view_config

    def view_outputs(self, relpath: str) -> list[tuple[int, str, list[tuple[str, ...]]]]:
        if relpath not in self._view_outputs:
            text = None
            if self.templates is not None:
                text = self.templates.get(relpath)
            elif self.template_root is not None:
                text = taint_angular.read_template(self.template_root, relpath)
            self._view_outputs[relpath] = taint_js_views.unescaped_outputs(relpath, text) if text else []
        return self._view_outputs[relpath]

    # -- NoSQL alıcı türü ("mongo" | "orm" | "other" | None: bilinmiyor) ---------------
    def uses_dynamodb(self) -> bool:
        """Projede AWS SDK (DynamoDB istemcisi) içe aktarılıyor mu?"""
        if self._uses_dynamodb is None:
            roots = {_package_root(spec) for module in self.modules.values() for spec, _ in module.imports.values()}
            for module in self.modules.values():
                for node in module.program.get("body", []):
                    if _t(node) == "ImportDeclaration":
                        roots.add(str((node.get("source") or {}).get("value", "")))
            self._uses_dynamodb = bool(roots & _DYNAMO_PACKAGES) or any(r.startswith("@aws-sdk/") and "dynamodb" in r for r in roots)
        return self._uses_dynamodb

    def package_roots(self) -> frozenset[str]:
        """Projede içe aktarılan paket kökleri (import / require; bir kez toplanır)."""
        if self._package_roots is None:
            roots = {_package_root(spec) for module in self.modules.values() for spec, _ in module.imports.values()}
            for module in self.modules.values():
                for node in module.program.get("body", []):
                    if _t(node) == "ImportDeclaration":
                        roots.add(_package_root(str((node.get("source") or {}).get("value", ""))))
            self._package_roots = frozenset(roots)
        return self._package_roots

    def router_names(self, module: JsModule) -> frozenset[str]:
        """Modülde yönlendirici nesnesine bağlanan adlar: const users = express.Router() / Router() /
        new Router() (koa-router) / new Hono() / new Elysia() (adı 'router'/'app' ile bitmese de)."""
        cached = self._router_names.get(module.relpath)
        if cached is not None:
            return cached
        names: set[str] = set()
        for node in self._program_nodes(module, 100_000):
            if _t(node) != "VariableDeclarator" or _t(node.get("id")) != "Identifier":
                continue
            init = node.get("init") or {}
            if _t(init) not in {"CallExpression", "NewExpression"}:
                continue
            callee = _callee_name(init.get("callee"))
            last = callee.rsplit(".", 1)[-1]
            if last == "Router" or (_t(init) == "NewExpression" and last in _HONO_ROUTER_CLASSES):
                names.add(node["id"].get("name", ""))
        result = frozenset(names)
        self._router_names[module.relpath] = result
        return result

    def validation_pipe(self) -> bool:
        """Projede class-validator doğrulaması etkin mi (ValidationPipe kullanılıyor)?"""
        if self._validation_pipe is None:
            self._validation_pipe = any(
                _t(node) in {"NewExpression", "Identifier"} and (
                    _callee_name(node.get("callee")) if _t(node) == "NewExpression" else node.get("name", "")
                ).rsplit(".", 1)[-1] == "ValidationPipe"
                for module in self.modules.values() for node in self._program_nodes(module, 100_000))
        return self._validation_pipe

    def dto_safe_fields(self, module: JsModule, type_name: str | None) -> frozenset[str]:
        """DTO sınıfının güvenli türe doğrulanmış alanları (ValidationPipe etkinse)."""
        if not type_name:
            return frozenset()
        ref = self.lookup(module, type_name)
        if ref is None or ref[0] != "class" or not self.validation_pipe():
            return frozenset()
        node = ref[1].classes.get(ref[2])
        fields: set[str] = set()
        for member in ((node or {}).get("body") or {}).get("body", []):
            if _t(member) not in {"ClassProperty", "ClassPrivateProperty"}:
                continue
            names = {_callee_name(d["expression"].get("callee")).rsplit(".", 1)[-1]
                     for d in (member.get("decorators") or []) if _t(d.get("expression")) == "CallExpression"}
            if names & _DTO_SAFE_VALIDATORS:
                key = (member.get("key") or {}).get("name", "")
                if key:
                    fields.add(key)
        return frozenset(fields)

    def react_component(self, qual: str, node: Any) -> bool:
        """Fonksiyon bir React/Preact bileşeni mi: büyük harfli ad, (props[, ref]) parametresi, gövdede JSX."""
        key = id(node)
        cached = self._components.get(key)
        if cached is not None:
            return cached
        result = False
        params = node.get("params") or [] if isinstance(node, dict) else []
        if _COMPONENT_NAME_RE.match(qual.rsplit(".", 1)[-1]) and 1 <= len(params) <= 2:
            first = params[0]
            if _t(first) == "AssignmentPattern":
                first = first.get("left") or {}
            if _t(first) in {"Identifier", "ObjectPattern"}:
                result = any(_t(child) in {"JSXElement", "JSXFragment"} for child in _walk(node.get("body"), 20_000))
        self._components[key] = result
        return result

    def string_request_members(self) -> frozenset[str]:
        """Değeri dize olan istek alanları: query/params; urlencoded gövde ayrıştırıcısı kullanılıyorsa body de."""
        if self._string_members is None:
            urlencoded = False
            for module in self.modules.values():
                for node in self._program_nodes(module, 400_000):
                    if _t(node) == "CallExpression" and _callee_name(node.get("callee")).rsplit(".", 1)[-1] == "urlencoded":
                        urlencoded = True
                        break
                if urlencoded:
                    break
            self._string_members = _STRING_BODY_MEMBERS if urlencoded else _STRING_REQUEST_MEMBERS
        return self._string_members

    def db_packages(self) -> tuple[bool, bool]:
        """Projede (MongoDB kitaplığı, SQL ORM/sürücü) içe aktarılıyor mu?"""
        if self._db_packages is None:
            roots = {_package_root(spec) for module in self.modules.values() for spec, _ in module.imports.values()}
            for module in self.modules.values():
                for node in module.program.get("body", []):
                    if _t(node) == "ImportDeclaration":
                        roots.add(_package_root(str((node.get("source") or {}).get("value", ""))))
            self._db_packages = (bool(roots & _MONGO_PACKAGES), bool(roots & _SQL_ORM_PACKAGES))
        return self._db_packages

    def request_typed(self, module: JsModule, type_name: str | None, qual: str = "") -> bool:
        """Parametre türü gelen HTTP isteği mi? (Express/Nest `Request`, Next.js, Fastify, Node http)."""
        if not type_name:
            return False
        if type_name in _REQUEST_TYPES:
            return True
        if type_name != "Request":
            return False
        imported = module.imports.get("Request")
        if imported is not None:
            return _package_root(imported[0]) in _EXPRESS_PACKAGES
        if any(_package_root(spec) in _EXPRESS_PACKAGES for spec, _ in module.imports.values()):
            return True  # express.Request (nitelikli ad)
        # Next.js uygulama yönlendiricisi: app/**/route.ts içindeki dışa aktarılan GET/POST(request: Request)
        return bool(_NEXT_ROUTE_RE.search(module.relpath)) and qual in _NEXT_ROUTE_METHODS

    def response_typed(self, module: JsModule, type_name: str | None) -> bool:
        if type_name in _RESPONSE_TYPES:
            return True
        if type_name != "Response":
            return False
        imported = module.imports.get("Response")
        if imported is not None:
            return _package_root(imported[0]) in _EXPRESS_PACKAGES
        return any(_package_root(spec) in _EXPRESS_PACKAGES for spec, _ in module.imports.values())

    def type_kind(self, type_name: str | None) -> str | None:
        if not type_name:
            return None
        if type_name in _MONGO_TYPES:
            return "mongo"
        if type_name == "Model":
            # mongoose Model<T>; Sequelize'da Model türü sorgu alıcısı olarak nadiren yazılır.
            mongo, sql = self.db_packages()
            return "mongo" if mongo or not sql else "orm"
        if type_name in _ORM_TYPES:
            return "orm"
        return None

    def value_kind(self, module: JsModule, name: str, depth: int = 0) -> str | None:
        key = (module.relpath, name)
        if key in self._value_kinds:
            if key in self._value_kinds_active:
                self._value_kind_guard_hits += 1
            return self._value_kinds[key]
        self._value_kinds[key] = None  # döngü koruması
        self._value_kinds_active.add(key)
        result: str | None = None
        if depth <= self.MAX_RESOLVE_DEPTH:
            if name in module.classes:
                result = self.class_kind(module, module.classes[name])
            elif name in module.values:
                result = self.classify(module, module.values[name], depth + 1)
            elif name in module.functions or name in module.objects:
                result = "other"
            elif name in module.imports:
                spec, imported = module.imports[name]
                result = self.module_kind(module, spec, imported, depth + 1)
        self._value_kinds_active.discard(key)
        self._value_kinds[key] = result
        return result

    def module_kind(self, module: JsModule, spec: str, name: str, depth: int = 0) -> str | None:
        if not spec.startswith("."):
            root = _package_root(spec)
            if root in _MONGO_PACKAGES:
                return None
            return "orm" if root in _SQL_ORM_PACKAGES else "other"
        target = self.module_for(module, spec)
        if target is None or depth > self.MAX_RESOLVE_DEPTH:
            return None
        entry = target.exports.get(name)
        if entry is None and name == "default":
            entry = target.exports.get("*")
        if entry is None and name == "*":
            return "other"  # ad alanı nesnesi
        if entry is not None:
            if entry[0] == "reexport":
                return self.module_kind(target, entry[1], entry[2], depth + 1)
            return self.value_kind(target, entry[1], depth + 1)
        whole = target.exports.get("*")
        if whole is not None:
            value = target.values.get(whole[1])
            if _t(value) == "ObjectExpression":
                for prop in value.get("properties", []):
                    if _t(prop) == "ObjectProperty" and _key_name(prop) == name:
                        return self.classify(target, prop.get("value"), depth + 1)
        for star in target.star_exports:
            found = self.module_kind(target, star, name, depth + 1)
            if found is not None:
                return found
        return None

    def class_kind(self, module: JsModule, node: Node) -> str:
        decorators = {
            (_callee_name(d.get("expression", {}).get("callee")) if _t(d.get("expression")) == "CallExpression"
             else _dotted(d.get("expression"))).rsplit(".", 1)[-1]
            for d in node.get("decorators") or []
        }
        if decorators & _ORM_CLASS_DECORATORS:
            return "orm"
        base = _dotted(node.get("superClass")) if node.get("superClass") else ""
        if base.rsplit(".", 1)[-1] == "Model":
            root = base.split(".")[0]
            imported = module.imports.get(root)
            if imported is not None and _package_root(imported[0]) in _MONGO_PACKAGES:
                return "mongo"
            return "orm"  # Sequelize/Objection Model sınıfı
        return "other"

    def classify(self, module: JsModule, node: Any, depth: int = 0) -> str | None:
        """Bir değer ifadesinin NoSQL alıcı türü: Mongoose modeli/Mongo koleksiyonu mu, SQL ORM mu, başka mı?"""
        if depth > self.MAX_RESOLVE_DEPTH or not isinstance(node, dict):
            return None
        kind = _t(node)
        if kind in {"AwaitExpression", "TSAsExpression", "TSNonNullExpression", "ParenthesizedExpression",
                    "TSSatisfiesExpression", "TSTypeAssertion"}:
            typed = self.type_kind(node.get("tn")) if kind in {"TSAsExpression", "TSTypeAssertion", "TSSatisfiesExpression"} else None
            return typed or self.classify(module, node.get("expression") or node.get("argument"), depth + 1)
        if kind == "CallExpression":
            callee = node.get("callee")
            name = _callee_name(callee)
            last = name.rsplit(".", 1)[-1]
            source = module._require_source(node)
            if source is not None:
                return self.module_kind(module, source[0], source[1], depth + 1)
            if last in _MONGO_FACTORIES:
                return "mongo"
            if last in {"model", "discriminator"}:
                root = name.split(".")[0]
                imported = module.imports.get(root)
                if imported is not None and _package_root(imported[0]) in _SQL_ORM_PACKAGES:
                    return "orm"
                return "mongo"
            if last in _ORM_FACTORIES:
                return "orm"
            if _t(callee) == "Identifier":
                ref = self.lookup(module, callee.get("name", ""))
                fn = ref[1].functions.get(ref[2]) if ref is not None and ref[0] == "func" else None
                if fn is not None:
                    return self._returns_kind(ref[1], fn, depth + 1)
            return None
        if kind == "NewExpression":
            last = _callee_name(node.get("callee")).rsplit(".", 1)[-1]
            if last in {"Collection", "Datastore"}:
                return "mongo"  # new MarsDB.Collection('x') / new Datastore() (NeDB): Mongo benzeri koleksiyon
            return "orm" if last in _ORM_TYPES else "other"
        if kind == "Identifier":
            return self.value_kind(module, node.get("name", ""), depth + 1)
        if kind == "MemberExpression":
            source = module._require_source(node)
            if source is not None:
                return self.module_kind(module, source[0], source[1], depth + 1)
            chain = _chain(node)
            if chain and len(chain) == 2 and chain[0] in module.imports:
                spec, imported = module.imports[chain[0]]
                if imported == "*":
                    return self.module_kind(module, spec, chain[1], depth + 1)
            return None
        if kind in {"ClassExpression", "ClassDeclaration"}:
            return self.class_kind(module, node)
        if _is_function(node) or kind in {"ObjectExpression", "ArrayExpression", "StringLiteral", "TemplateLiteral",
                                         "NumericLiteral", "BooleanLiteral", "NullLiteral", "BinaryExpression"}:
            return "other"
        return None

    def _returns_kind(self, module: JsModule, fn: Node, depth: int) -> str | None:
        key = (id(fn), depth)
        if key in self._returns_kinds:
            return self._returns_kinds[key]
        hits = self._value_kind_guard_hits
        body = fn.get("body")
        if _t(body) != "BlockStatement":
            result = self.classify(module, body, depth)
        else:
            args = self._return_args.get(id(fn))
            if args is None:
                args = [child.get("argument") for child in _walk(body, 5_000)
                        if _t(child) == "ReturnStatement" and child.get("argument") is not None]
                self._return_args[id(fn)] = args
            kinds = {self.classify(module, arg, depth) for arg in args}
            result = kinds.pop() if len(kinds) == 1 else None
        if hits == self._value_kind_guard_hits:
            self._returns_kinds[key] = result
        return result

    def field_kinds(self, module: JsModule, cls: str) -> dict[str, str | None]:
        """Sınıf/yapıcı fonksiyon alanlarının (this.x) ve yapıcı yerellerinin NoSQL alıcı türü."""
        key = (module.relpath, cls)
        cached = self._field_kinds.get(key)
        if cached is not None:
            return cached
        kinds: dict[str, str | None] = {}
        self._field_kinds[key] = kinds
        node = module.classes.get(cls)
        ctor = module.functions.get(f"{cls}.constructor") if node is not None else module.functions.get(cls)
        if node is not None:
            for member in (node.get("body") or {}).get("body", []):
                if _t(member) not in {"ClassProperty", "ClassPrivateProperty"} or not _key_name(member):
                    continue
                kind = self._decorated_kind(member) or self.type_kind((member.get("key") or {}).get("tn") or member.get("tn"))
                if kind is None and member.get("value") is not None:
                    kind = self.classify(module, member.get("value"))
                if kind is not None:
                    kinds[_key_name(member)] = kind
        if ctor is not None:
            for param in ctor.get("params") or []:
                inner = param.get("parameter") if _t(param) == "TSParameterProperty" else param
                kind = self._decorated_kind(param) or self._decorated_kind(inner or {}) or self.type_kind((inner or {}).get("tn"))
                if kind is not None:
                    for name in _pattern_names(inner):
                        kinds.setdefault(name, kind)
            body = ctor.get("body")
            for statement in (body.get("body", []) if _t(body) == "BlockStatement" else []):
                if _t(statement) == "VariableDeclaration":
                    for declarator in statement.get("declarations", []):
                        if _t(declarator.get("id")) == "Identifier" and declarator.get("init") is not None:
                            kind = self.classify(module, declarator["init"])
                            if kind is not None:
                                kinds.setdefault("<local>." + declarator["id"].get("name", ""), kind)
                expression = statement.get("expression") if _t(statement) == "ExpressionStatement" else None
                if _t(expression) == "AssignmentExpression":
                    chain = _chain(expression.get("left"))
                    if chain and len(chain) == 2 and chain[0] == "this":
                        value = expression.get("right")
                        kind = self.classify(module, value)
                        if kind is None and _t(value) == "Identifier":
                            kind = kinds.get(value.get("name", "")) or kinds.get("<local>." + value.get("name", ""))
                        if kind is not None:
                            kinds[chain[1]] = kind
        return kinds

    @staticmethod
    def _decorated_kind(node: Node) -> str | None:
        for decorator in node.get("decorators") or []:
            expression = decorator.get("expression") or {}
            name = _callee_name(expression.get("callee")) if _t(expression) == "CallExpression" else _dotted(expression)
            last = name.rsplit(".", 1)[-1]
            if last in {"InjectModel", "InjectCollection"}:
                return "mongo"
            if last in {"InjectRepository", "InjectDataSource", "InjectEntityManager", "InjectConnection"}:
                return "orm"
        return None

    def _program_nodes(self, module: "JsModule", limit: int) -> list[Node]:
        """``list(_walk(module.program, limit))`` ile aynı (19. tur hız): proje geneli toplayıcılar programı ayrı ayrı
        yürüyordu; ön-sıra yürüyüş belirlenimci ve ağaç değişmediği için tek yürüyüşün öneki kullanılır."""
        assert limit <= self._program_walk_cap
        key = (module.relpath, id(module.program))
        nodes = self._program_walks.get(key)
        if nodes is None:
            nodes = self._program_walks[key] = list(_walk(module.program, self._program_walk_cap))
        return nodes if limit >= len(nodes) else nodes[:limit]

    _program_walk_cap = 400_000

    def closure_writes(self, body: Any) -> set[str]:
        key = id(body)
        cached = self._closure_writes.get(key)
        if cached is None:
            cached = self._closure_writes[key] = _nested_function_writes(body, self._inner_writes)
        return cached

    def type_ref(self, module: JsModule, type_name: str | None) -> Ref | None:
        """TS tür adı / sınıf adı → örnek başvurusu (yalnız proje sınıfları)."""
        if not type_name:
            return None
        ref = self.lookup(module, type_name)
        if ref is not None and (ref[0] == "class" or (ref[0] == "func" and ref[2] in ref[1].ctor_functions)):
            return ("instance", ref[1], ref[2])
        return None

    def field_types(self, module: JsModule, cls: str) -> dict[str, Ref]:
        """Sınıf alanlarının türleri: TS açıklaması, `this.x = new X()` ve yapıcı parametre özellikleri."""
        key = (module.relpath, cls)
        cached = self._field_types.get(key)
        if cached is not None:
            return cached
        types: dict[str, Ref] = {}
        self._field_types[key] = types
        node = module.classes.get(cls)
        ctor = module.functions.get(f"{cls}.constructor") if node is not None else module.functions.get(cls)
        if node is not None:
            for member in (node.get("body") or {}).get("body", []):
                if _t(member) in {"ClassProperty", "ClassPrivateProperty"}:
                    value = member.get("value")
                    ref = self.type_ref(module, (member.get("key") or {}).get("tn") or member.get("tn"))
                    if ref is None and _t(value) == "NewExpression":
                        ref = self.type_ref(module, _dotted(value.get("callee")))
                    if ref is not None and _key_name(member):
                        types[_key_name(member)] = ref
        if ctor is not None:
            params: dict[str, Ref] = {}
            for param in ctor.get("params") or []:
                inner = param.get("parameter") if _t(param) == "TSParameterProperty" else param
                ref = self.type_ref(module, (inner or {}).get("tn"))
                if ref is None:
                    continue
                for name in _pattern_names(inner):
                    params[name] = ref
                    if _t(param) == "TSParameterProperty":
                        types[name] = ref
            for child in _walk(ctor.get("body"), 20_000):
                if _t(child) != "AssignmentExpression":
                    continue
                chain = _chain(child.get("left"))
                if not chain or len(chain) != 2 or chain[0] != "this":
                    continue
                value = child.get("right")
                if _t(value) == "NewExpression":
                    ref = self.type_ref(module, _dotted(value.get("callee")))
                elif _t(value) == "Identifier":
                    ref = params.get(value.get("name", ""))
                else:
                    ref = None
                if ref is not None:
                    types.setdefault(chain[1], ref)
        return types

    def tick(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise RecursionError("taint adım sınırı")

    def add_module(self, relpath: str, program: Node) -> JsModule:
        module = JsModule(relpath, program)
        self.modules[relpath] = module
        self.flows.setdefault(relpath, [])
        self.clean.setdefault(relpath, set())
        return module

    def add_flow(self, flow: tf.Flow) -> None:
        if flow.source_label == _PROP:
            return  # bileşen prop'u kaynak değildir (yalnız JSX çağrı yerinde gerçek değerle eşlenir)
        key = (flow.sink_kind, flow.line, flow.source, flow.source_line, flow.source_file)
        emitted = self._emitted.setdefault(flow.file, set())
        if key not in emitted:
            emitted.add(key)
            self.flows.setdefault(flow.file, []).append(flow)

    def mark_evaluated(self, relpath: str, kind: str, line: int) -> None:
        self.clean.setdefault(relpath, set()).add((kind, line))

    def analysis_for(self, relpath: str) -> tf.Analysis:
        return tf.Analysis(
            "javascript", list(self.flows.get(relpath, [])), set(self.clean.get(relpath, set())),
            set(self.uncertain.get(relpath, set())),
        )

    def collect_uncalled_entry_sinks(self) -> None:
        """Çağıranı olmayan dışa aktarılmış fonksiyonlarda parametreden hedefe ulaşan izler belirsizdir."""
        for module in self.modules.values():
            for _, fn in self._exported_functions(module):
                if id(fn) in self.called or id(fn) in self.handlers or id(fn) in self.entry_params \
                        or id(fn) in self.entry_roots:
                    continue
                summary = self.summaries.get(id(fn))
                if summary is None:
                    continue
                for sink in summary.sinks.values():
                    if (sink.index >= 0 or sink.index == -2) and sink.file:
                        self.uncertain.setdefault(sink.file, set()).add((sink.kind, sink.line))

    # -- çözümleme ------------------------------------------------------------------
    def module_for(self, importer: JsModule, spec: str) -> JsModule | None:
        if not spec.startswith("."):
            return None
        base = PurePosixPath(importer.relpath).parent / spec
        parts: list[str] = []
        for part in base.parts:
            if part == "..":
                if parts:
                    parts.pop()
            elif part not in {".", ""}:
                parts.append(part)
        stem = "/".join(parts)
        candidates = [stem]
        lowered = stem.lower()
        for ext in _JS_EXTENSIONS:
            if lowered.endswith(ext):
                candidates.extend(stem[: -len(ext)] + alt for alt in _JS_EXTENSIONS)
                break
        candidates.extend(stem + ext for ext in _JS_EXTENSIONS)
        candidates.extend(f"{stem}/index{ext}" for ext in _JS_EXTENSIONS)
        for candidate in candidates:
            module = self.modules.get(candidate)
            if module is not None:
                return module
        return None

    def lookup(self, module: JsModule, name: str, depth: int = 0) -> Ref | None:
        if depth > self.MAX_RESOLVE_DEPTH or not name:
            return None
        if name in module.functions:
            return ("func", module, name)
        if name in module.classes:
            return ("class", module, name)
        if name in module.objects:
            return ("object", module, name)
        if name in module.instances:
            cls = self.lookup(module, module.instances[name], depth + 1)
            return ("instance", cls[1], cls[2]) if cls and cls[0] == "class" else None
        if name in self.router_names(module):
            return ("router", module, name)
        value = module.values.get(name) or {}
        if _t(value) in {"CallExpression", "NewExpression"}:
            last = _callee_name(value.get("callee")).rsplit(".", 1)[-1]
            if last == "Router" or (_t(value) == "NewExpression" and last in _HONO_ROUTER_CLASSES):
                return ("router", module, name)
        imported = module.imports.get(name)
        if imported is not None:
            target = self.module_for(module, imported[0])
            if target is None:
                return None
            return self.export(target, imported[1], depth + 1)
        return None

    def export(self, module: JsModule, name: str, depth: int = 0) -> Ref | None:
        if depth > self.MAX_RESOLVE_DEPTH:
            return None
        if name == "*" and "*" not in module.exports:
            return ("module", module, "")
        entry = module.exports.get(name)
        if entry is None and name == "default" and "*" in module.exports:
            entry = module.exports["*"]
        if entry is not None:
            if entry[0] == "reexport":
                target = self.module_for(module, entry[1])
                return self.export(target, entry[2], depth + 1) if target else None
            return self.lookup(module, entry[1], depth + 1)
        if "*" in module.exports:
            whole = self.lookup(module, module.exports["*"][1], depth + 1)
            if whole is not None:
                return self.member(whole, name, depth + 1)
        for spec in module.star_exports:
            target = self.module_for(module, spec)
            found = self.export(target, name, depth + 1) if target else None
            if found is not None:
                return found
        return None

    def member(self, ref: Ref, name: str, depth: int = 0) -> Ref | None:
        kind, module, qual = ref
        if depth > self.MAX_RESOLVE_DEPTH:
            return None
        if kind == "module":
            return self.export(module, name, depth + 1)
        if kind == "object":
            target = module.objects.get(qual, {}).get(name)
            if target is None:
                return None
            if target.startswith("@"):
                return self.lookup(module, target[1:], depth + 1)
            return ("func", module, target)
        if kind in {"class", "instance"} or (kind == "func" and qual in module.ctor_functions):
            found = self.method(module, qual, name, depth + 1)
            return ("func", found[0], found[1]) if found else None
        return None

    def method(self, module: JsModule, cls: str, name: str, depth: int = 0) -> tuple[JsModule, str] | None:
        if f"{cls}.{name}" in module.functions:
            return module, f"{cls}.{name}"
        base = module.class_bases.get(cls)
        if base is None or depth > 6:
            return None
        chain = _chain(base)
        ref = self.lookup(module, chain[0], depth + 1) if chain else None
        for part in (chain or [])[1:]:
            ref = self.member(ref, part, depth + 1) if ref else None
        if ref is not None and ref[0] == "class":
            return self.method(ref[1], ref[2], name, depth + 1)
        return None

    # -- özetler --------------------------------------------------------------------
    def summary(self, module: JsModule, qual: str, node: Node, class_name: str | None,
                captured: dict[str, Taint] | None = None, refs: dict[str, Ref] | None = None) -> tf._PySummary:
        key = id(node)
        cached = self.summaries.get(key)
        if cached is not None:
            return cached
        if key in self._active or self._depth > self.MAX_DEPTH:
            return tf._PySummary(())
        self._active.add(key)
        self._depth += 1
        try:
            summary = self._analyze_function(module, qual, node, class_name, captured or {}, refs or {})
        finally:
            self._active.discard(key)
            self._depth -= 1
        self.summaries[key] = summary
        return summary

    def _is_handler(self, qual: str, node: Node) -> bool:
        if id(node) in self.handlers:
            return True
        return bool(self.handler_names) and qual.rsplit(".", 1)[-1] in self.handler_names

    def _analyze_function(self, module: JsModule, qual: str, node: Node, class_name: str | None,
                          captured: dict[str, Taint], refs: dict[str, Ref]) -> tf._PySummary:
        params = node.get("params") or []
        names = tuple((_pattern_names(p) or [""])[0] if _t(p) in {"Identifier", "AssignmentPattern"} else "" for p in params)
        summary = tf._PySummary(names)
        env: dict[str, Taint] = dict(captured)
        roots: set[str] = set()
        param_refs: dict[str, Ref] = {}
        is_handler = self._is_handler(qual, node)
        entry = self.entry_params.get(id(node), {})
        entry_roots = self.entry_roots.get(id(node), set())
        component = self.react_component(qual, node)
        prop_roots: set[str] = set()
        for index, param in enumerate(params):
            if index in entry:
                for name in _pattern_names(param):
                    env[name] = (tf._Origin("request", entry[index], _line(param), (), frozenset(), module.relpath),)
                continue
            if index in entry_roots and _t(param) == "Identifier":
                roots.add(param.get("name", ""))
                continue
            decorated = {
                _callee_name(d.get("expression", {}).get("callee")) if _t(d.get("expression")) == "CallExpression" else _dotted(d.get("expression"))
                for d in (param.get("decorators") or [])
            }
            bound = _pattern_names(param)
            if decorated & _NEST_PARAM_DECORATORS:
                pipes = {_dotted(arg) or _callee_name(arg.get("callee")) if isinstance(arg, dict) else ""
                         for d in (param.get("decorators") or []) if _t(d.get("expression")) == "CallExpression"
                         for arg in d["expression"].get("arguments", [])}
                if {pipe.rsplit(".", 1)[-1] for pipe in pipes if pipe} & _NEST_SAFE_PIPES:
                    # @Param('id', ParseIntPipe) id: number → yalnız sayı/UUID/mantıksal ulaşır.
                    for name in bound:
                        env[name] = _EMPTY
                    continue
                safe_fields = self.dto_safe_fields(module, param.get("tn"))
                for name in bound:
                    env[name] = (tf._Origin("request", f"@{sorted(decorated & _NEST_PARAM_DECORATORS)[0]}()", _line(param), (), frozenset(), module.relpath),)
                    for field in safe_fields:
                        env[f"{name}.{field}"] = _EMPTY  # @IsInt()/@IsUUID()/@IsIn([...]) ile doğrulanmış DTO alanı
                continue
            inner_param = param.get("parameter") if _t(param) == "TSParameterProperty" else param
            if _t(inner_param) == "Identifier" and self.request_typed(module, inner_param.get("tn"), qual):
                roots.add(inner_param.get("name", ""))
                continue
            if is_handler and index == 0:
                if _t(param) == "Identifier":
                    roots.add(param.get("name", ""))
                elif _t(param) == "ObjectPattern":
                    for prop in param.get("properties", []):
                        key = _key_name(prop) if _t(prop) == "ObjectProperty" else ""
                        if key in _REQUEST_MEMBERS:
                            for name in _pattern_names(prop.get("value")):
                                env[name] = (tf._Origin("request", f"{{{key}}}", _line(param), (), frozenset(), module.relpath),)
                continue
            if component and index == 0:
                # Bileşen prop'ları ad bazında izlenir (alan duyarlı): {html} / props.html → §prop("html").
                pattern = param.get("left") if _t(param) == "AssignmentPattern" else param
                if _t(pattern) == "ObjectPattern":
                    for prop in pattern.get("properties", []):
                        key = _key_name(prop) if _t(prop) == "ObjectProperty" else ""
                        for name in _pattern_names(prop.get("value") if key else prop):
                            env[name] = (tf._Origin(_PROP, key, _line(param), (), frozenset(), module.relpath),) if key \
                                else (tf._Origin(_PARAM, str(index), _line(node), (), frozenset(), module.relpath),)
                    continue
                if _t(pattern) == "Identifier":
                    prop_roots.add(pattern.get("name", ""))
            for name in bound:
                env[name] = (tf._Origin(_PARAM, str(index), _line(node), (), frozenset(), module.relpath),)
            inner = param.get("parameter") if _t(param) == "TSParameterProperty" else param
            typed = self.type_ref(module, (inner or {}).get("tn"))
            if typed is not None:
                for name in bound:
                    param_refs[name] = typed
            if _t(param) == "TSParameterProperty" and class_name:
                # constructor(private repo: Repo): this.repo = repo
                for name in bound:
                    summary.add_field_write(name, env[name])
        scope = JsScope(
            self, module, env, summary=summary, class_name=class_name, qual=qual, roots=roots,
            middleware_paths=self.handler_middleware_paths.get(id(node), set()),
        )
        scope.prop_roots = prop_roots
        scope.unsafe_merge = _unsafe_recursive_merge(node, qual)
        scope.refs.update(refs)
        scope.refs.update(param_refs)
        for param in params:
            inner = param.get("parameter") if _t(param) == "TSParameterProperty" else param
            if _t(inner) == "Identifier" and self.response_typed(module, inner.get("tn")):
                scope.responses.add(inner.get("name", ""))
            hinted = self.type_kind((inner or {}).get("tn"))
            for name in _pattern_names(param):
                scope.callback_aliases.pop(name, None)
                scope.kinds[name] = hinted
        scope.run_function_body(node)
        return summary

    # -- çalıştırma -------------------------------------------------------------------
    def collect_handlers(self) -> None:
        """Router çağrılarında (dosyalar arası) adıyla geçen işleyicileri işaretle."""
        receiver_ops: dict[tuple[str, str], list[dict[tuple[str, ...], bool]]] = {}
        handler_sequences: dict[int, list[tuple[tuple[str, str], tuple[dict[tuple[str, ...], bool], ...]]]] = {}
        mounts: dict[tuple[str, str], list[tuple[tuple[str, str], tuple[dict[tuple[str, ...], bool], ...]]]] = {}
        for module in self.modules.values():
            scope = JsScope(self, module, {})
            router_names = self.router_names(module)
            for node in self._program_nodes(module, 200_000):
                if _t(node) != "CallExpression" or not scope.is_router_call(node):
                    continue
                callee = node.get("callee") or {}
                method = (callee.get("property") or {}).get("name", "")
                chain = _chain(callee) or []
                receiver = chain[0] if len(chain) >= 2 else ""
                receiver_key = (module.relpath, receiver)
                operations = list(receiver_ops.get(receiver_key, ()))
                for arg in _router_arguments(node.get("arguments", []), scope._static_router_array):
                    fnode = None
                    if _is_function(arg):
                        fnode = arg
                    else:
                        ref = scope.resolve_ref(arg)
                        if ref is not None and ref[0] == "func":
                            fnode = ref[1].functions.get(ref[2])
                    if fnode is not None:
                        # Keep middleware operations in argument order.  A safe
                        # child middleware can therefore overwrite a tainted
                        # field inherited from a parent router.
                        handler_sequences.setdefault(id(fnode), []).append((receiver_key, tuple(operations)))
                        writes = self._middleware_request_writes(fnode)
                        if writes:
                            operations.append(writes)
                        self.handlers.add(id(fnode))
                        continue
                    if method == "use":
                        child_ref = scope.resolve_ref(arg)
                        child_key = None
                        if child_ref is not None and child_ref[0] == "router":
                            child_key = (child_ref[1].relpath, child_ref[2])
                        elif _t(arg) == "Identifier":
                            child = arg.get("name", "")
                            if child in router_names:
                                child_key = (module.relpath, child)
                        if child_key is not None and child_key != receiver_key:
                            mounts.setdefault(child_key, []).append((receiver_key, tuple(operations)))
                if method == "use":
                    receiver_ops[receiver_key] = operations

        inherited_cache: dict[tuple[str, str], list[tuple[dict[tuple[str, ...], bool], ...]]] = {}

        def inherited(receiver: tuple[str, str], stack: frozenset[tuple[str, str]] = frozenset()):
            cached = inherited_cache.get(receiver)
            if cached is not None and not stack:
                return cached
            paths: list[tuple[dict[tuple[str, ...], bool], ...]] = [tuple()]
            if receiver not in stack and len(stack) < 16:
                for parent, prefix in mounts.get(receiver, ()):
                    for base in inherited(parent, stack | {receiver}):
                        paths.append(base + prefix)
                        if len(paths) >= 128:
                            break
                    if len(paths) >= 128:
                        break
            if not stack:
                inherited_cache[receiver] = paths
            return paths

        for handler_id, registrations in handler_sequences.items():
            active_union: set[tuple[str, ...]] = set()
            for receiver, local_ops in registrations:
                for prefix in inherited(receiver):
                    active: set[tuple[str, ...]] = set()
                    for writes in (*prefix, *local_ops):
                        for path, tainted in writes.items():
                            if tainted:
                                active.add(path)
                            else:
                                active.discard(path)
                    active_union.update(active)
            if active_union:
                self.handler_middleware_paths.setdefault(handler_id, set()).update(active_union)

    def _middleware_request_writes(self, fn: Node) -> dict[tuple[str, ...], bool]:
        """Return exact middleware request-field writes (path -> tainted).

        This deliberately records object-literal members separately, so a safe
        sibling such as ``req.context.role = 'reader'`` does not inherit the
        taint of ``req.context.name``.
        """
        params = fn.get("params") or []
        names = _pattern_names(params[0]) if params else []
        if not names:
            return {}
        root = names[0]
        writes: dict[tuple[str, ...], bool] = {}

        def request_value(value: Any) -> bool:
            return any(
                (_chain(child) or [None, None])[:1] == [root]
                and len(_chain(child) or []) >= 2
                and (_chain(child) or ["", ""])[1] in _REQUEST_MEMBERS
                for child in _walk(value, 2_000)
                if _t(child) in {"MemberExpression", "OptionalMemberExpression"}
            )

        for child in _walk(fn.get("body"), 20_000):
            if _t(child) != "AssignmentExpression" or child.get("operator") != "=":
                continue
            left = _chain(child.get("left"))
            if not left or left[0] != root or len(left) < 2:
                continue
            right = child.get("right")
            if _t(right) == "ObjectExpression":
                for prop in right.get("properties", []):
                    key = _key_name(prop)
                    if key and _t(prop) == "ObjectProperty":
                        writes[tuple([*left[1:], key])] = request_value(prop.get("value"))
            else:
                writes[tuple(left[1:])] = request_value(right)
        return writes

    def _apply_middleware_writes(self, paths: set[tuple[str, ...]], fn: Node) -> None:
        for path, tainted in self._middleware_request_writes(fn).items():
            if tainted:
                paths.add(path)
            else:
                paths.discard(path)

    # -- sunucusuz / GraphQL giriş noktaları ------------------------------------------
    def _mark_entry(self, fn: Any, index: int, desc: str) -> None:
        if _is_function(fn) or _t(fn) in {"ObjectMethod", "ClassMethod"}:
            if len(fn.get("params") or []) > index:
                self.entry_params.setdefault(id(fn), {})[index] = desc

    def _serverless_configs(self) -> list[tuple[str, str]]:
        """serverless.yml / SAM template.yaml metinleri: (göreli yol, metin); proje kökü içinden güvenle okunur."""
        found: list[tuple[str, str]] = []
        if self.templates is not None:
            for relpath, text in self.templates.items():
                if PurePosixPath(relpath).name in _SERVERLESS_CONFIGS:
                    found.append((relpath, text))
            return found[:_MAX_SERVERLESS_CONFIGS]
        if self.template_root is None:
            return found
        state = tf._PROJECT.get()
        skip = getattr(state, "skip_dirs", frozenset({"node_modules", ".git"}))
        try:
            for path in tf._walk_project_files(Path(self.template_root), skip, frozenset({".yml", ".yaml"})):
                if path.name not in _SERVERLESS_CONFIGS:
                    continue
                relpath = path.relative_to(self.template_root).as_posix()
                text = taint_angular.read_template(self.template_root, relpath)
                if text is not None:
                    found.append((relpath, text))
                if len(found) >= _MAX_SERVERLESS_CONFIGS:
                    break
        except (OSError, ValueError):
            pass
        return found

    def _serverless_handlers(self) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        """Yapılandırmadaki handler: 'yol/dosya.fonksiyon' → ({(tam kök yolu, fonksiyon)}, {(göreli yol, fonksiyon)})."""
        exact: set[tuple[str, str]] = set()
        suffix: set[tuple[str, str]] = set()
        for relpath, text in self._serverless_configs():
            base = PurePosixPath(relpath).parent
            code_uris = [u.strip("/") for u in _SAM_CODEURI_RE.findall(text)]
            for value in _SERVERLESS_HANDLER_RE.findall(text):
                path, _, fn = value.rpartition(".")
                if not path or not fn or ".." in PurePosixPath(path).parts:
                    continue
                path = path.lstrip("./") if path.startswith("./") else path
                for prefix in [""] + code_uris:
                    exact.add((os.path.normpath(str(base / prefix / path)).replace(os.sep, "/").lstrip("./"), fn))
                suffix.add((path.strip("/"), fn))
        return exact, suffix

    def _ast_handler_mappings(self) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        """serverless.ts (`functions: { f: { handler: 'src/a.main', events } }`) ve AWS CDK
        (`new lambda.Function(…, { handler: 'index.h', code: Code.fromAsset(dir) })`,
        `new NodejsFunction(…, { entry, handler })`) eşlemeleri: ({(kök yolu, fn)}, {(sonek yolu, fn)})."""
        exact: set[tuple[str, str]] = set()
        suffix: set[tuple[str, str]] = set()

        def add(raw: str | None, fn: str, module_dir: PurePosixPath, *, strip_ext: bool) -> None:
            if not raw or not fn or not re.fullmatch(r"[A-Za-z_$][\w$]*", fn):
                return
            normal = _normalize_static(raw)
            if normal is None:
                return
            path, rooted = normal
            if strip_ext:
                path = _JS_SOURCE_EXT_RE.sub("", path)
            (exact if rooted else suffix).add((path, fn))

        def handler_string(value: Any, module_dir: PurePosixPath) -> None:
            raw = _static_path(value, module_dir)
            if raw and "." in raw.rsplit("/", 1)[-1]:
                path, _, fn = raw.rpartition(".")
                add(path, fn, module_dir, strip_ext=False)

        for module in self.modules.values():
            module_dir = PurePosixPath(module.relpath).parent
            serverless_file = bool(_SERVERLESS_TS_RE.search(module.relpath))
            packages = {_package_root(spec) for spec, _ in module.imports.values()}
            for node in module.program.get("body", []):
                if _t(node) == "ImportDeclaration":
                    packages.add(_package_root(str((node.get("source") or {}).get("value", ""))))
            cdk = bool(packages & _CDK_PACKAGES) or any(p.startswith("@aws-cdk/") for p in packages)
            # serverless-typescript şablonu: src/functions/x/index.ts → { handler: `${handlerPath(__dirname)}/handler.main`, events }
            function_config = "handlerPath" in module.imports or "@serverless/typescript" in packages
            if not serverless_file and not cdk and not function_config:
                continue
            for node in self._program_nodes(module, 100_000):
                kind = _t(node)
                if kind == "ObjectExpression" and (serverless_file or function_config):
                    keys = {_key_name(p): p for p in node.get("properties", []) if _t(p) == "ObjectProperty"}
                    if "handler" in keys and (serverless_file or "events" in keys):
                        handler_string(keys["handler"].get("value"), module_dir)
                elif kind == "NewExpression" and cdk:
                    cls = _callee_name(node.get("callee")).rsplit(".", 1)[-1]
                    args = node.get("arguments") or []
                    if cls not in _CDK_FUNCTION_CLASSES or len(args) < 3 or _t(args[2]) != "ObjectExpression":
                        continue
                    props = {_key_name(p): p.get("value") for p in args[2].get("properties", []) if _t(p) == "ObjectProperty"}
                    handler = _string_value(props.get("handler")) if "handler" in props else None
                    if cls == "NodejsFunction":
                        entry = _static_path(props.get("entry"), module_dir) if "entry" in props else None
                        add(entry, handler or "handler", module_dir, strip_ext=True)
                        continue
                    code = props.get("code")
                    asset = None
                    if _t(code) == "CallExpression" and _callee_name(code.get("callee")).rsplit(".", 1)[-1] == "fromAsset":
                        asset = _static_path((code.get("arguments") or [None])[0], module_dir)
                    if handler and "." in handler and asset is not None:
                        file, _, fn = handler.rpartition(".")
                        add(_join_static([asset, file]), fn, module_dir, strip_ext=False)
        return exact, suffix

    def _mark_type_map(self, scope: "JsScope", obj: Node) -> None:
        """{ Tür: { alan: (parent, args) => … } }: her tür nesnesindeki çözücülerin args parametresi kaynak."""
        for prop in obj.get("properties", []):
            if _t(prop) == "SpreadElement":
                inner = self._resolve_object(scope, prop.get("argument"))
                if inner is not None:
                    self._mark_type_map(scope, inner)
                continue
            inner = self._resolve_object(scope, prop.get("value")) if _t(prop) == "ObjectProperty" else None
            if inner is not None:
                self._mark_resolver_map(scope, inner, 1)

    def _mark_resolver_collection(self, scope: "JsScope", node: Any) -> None:
        """mergeResolvers([...]) / resolvers: [a, b] / resolvers: obj — her öğe bir tür haritasıdır."""
        if _t(node) == "ArrayExpression":
            for element in node.get("elements") or []:
                target = element.get("argument") if _t(element) == "SpreadElement" else element
                obj = self._resolve_object(scope, target)
                if obj is not None:
                    self._mark_type_map(scope, obj)
            return
        if _t(node) == "CallExpression" and _callee_name(node.get("callee")).rsplit(".", 1)[-1] in _RESOLVER_MERGE_CALLS:
            for arg in node.get("arguments") or []:
                self._mark_resolver_collection(scope, arg)
            return
        obj = self._resolve_object(scope, node)
        if obj is not None:
            self._mark_type_map(scope, obj)

    def _exported_functions(self, module: JsModule) -> list[tuple[str, Node]]:
        """Dışa aktarılan fonksiyonlar: (dışa aktarma adı, düğüm); module.exports = {handler} ve = fn dahil."""
        out: list[tuple[str, Node]] = []
        for exported, entry in module.exports.items():
            if entry[0] != "local":
                continue
            local = entry[1]
            fn = module.functions.get(local)
            if fn is not None:
                out.append((exported, fn))
                continue
            for key, qual in module.objects.get(local, {}).items():
                target = module.functions.get(qual[1:] if qual.startswith("@") else qual)
                if target is not None:
                    out.append((key, target))
        return out

    def _resolve_fn(self, scope: "JsScope", node: Any) -> Node | None:
        if _is_function(node) or _t(node) == "ObjectMethod":
            return node
        ref = scope.resolve_ref(node)
        if ref is not None and ref[0] == "func":
            return ref[1].functions.get(ref[2])
        return None

    def _resolve_object(self, scope: "JsScope", node: Any, depth: int = 0) -> Node | None:
        """Nesne ifadesi ya da (dosyalar arası) bir nesneye çözülen ad / ad.özellik."""
        if depth > 4 or not isinstance(node, dict):
            return None
        if _t(node) == "ObjectExpression":
            return node
        if _t(node) == "Identifier":
            ref = scope.resolve_ref(node)
            if ref is not None and ref[0] in {"object", "func"}:
                value = ref[1].values.get(ref[2])
                return value if _t(value) == "ObjectExpression" else None
            value = scope.m.values.get(node.get("name", ""))
            return value if _t(value) == "ObjectExpression" else None
        if _t(node) == "MemberExpression" and not node.get("computed"):
            # 18. tur: başka modülden dışa aktarılan nesne (require("./ctrl").graphqlroot / ctrl.graphqlroot)
            ref = scope.resolve_ref(node)
            if ref is not None and ref[0] in {"object", "func"}:
                value = ref[1].values.get(ref[2])
                if _t(value) == "ObjectExpression":
                    return value
            owner = self._resolve_object(scope, node.get("object"), depth + 1)
            prop = (node.get("property") or {}).get("name", "")
            if owner is not None:
                for item in owner.get("properties", []):
                    if _key_name(item) == prop and _t(item) == "ObjectProperty":
                        return self._resolve_object(scope, item.get("value"), depth + 1)
        return None

    def _mark_resolver_map(self, scope: "JsScope", obj: Node, index: int, depth: int = 0) -> None:
        """{ alan: (parent, args) => … } ya da { alan: { resolve, subscribe } }: args parametresi kaynak."""
        if depth > 3:
            return
        for prop in obj.get("properties", []):
            if _t(prop) == "SpreadElement":
                inner = self._resolve_object(scope, prop.get("argument"))
                if inner is not None:
                    self._mark_resolver_map(scope, inner, index, depth + 1)
                continue
            value = prop if _t(prop) == "ObjectMethod" else prop.get("value")
            fn = self._resolve_fn(scope, value)
            if fn is not None:
                self._mark_entry(fn, index, "args")
                continue
            if _t(value) == "ObjectExpression":
                for sub in value.get("properties", []):
                    if _key_name(sub) in {"resolve", "subscribe"}:
                        target = self._resolve_fn(scope, sub if _t(sub) == "ObjectMethod" else sub.get("value"))
                        if target is not None:
                            self._mark_entry(target, index, "args")

    def collect_entrypoints(self) -> None:
        """Express dışı giriş noktaları: AWS Lambda/Netlify (event), Firebase/GCP/Azure/Vercel HTTP işlevleri,
        GraphQL çözücüleri (Apollo/graphql-tools resolver haritası, graphql-js resolve, rootValue)."""
        exact, suffix = self._serverless_handlers()
        ast_exact, ast_suffix = self._ast_handler_mappings()
        exact |= ast_exact
        suffix |= ast_suffix
        for module in self.modules.values():
            stem = re.sub(r"\.(?:[cm]?[jt]sx?)$", "", module.relpath)
            packages = {_package_root(spec) for spec, _ in module.imports.values()}
            for node in module.program.get("body", []):
                if _t(node) == "ImportDeclaration":
                    packages.add(_package_root(str((node.get("source") or {}).get("value", ""))))
            # 0) Next.js sunucu eylemleri: 'use server' dosyasının dışa aktarılan async fonksiyonları istemciden
            # doğrudan (keyfi argümanlarla) çağrılabilir → bütün parametreler istemci verisidir.
            if "use server" in (module.program.get("dirs") or []):
                for _, fn in self._exported_functions(module):
                    if fn.get("async"):
                        for index in range(len(fn.get("params") or [])):
                            self._mark_entry(fn, index, "sunucu eylemi argümanı")
            # Next.js uygulama yönlendiricisi: page/layout bileşeninin { params, searchParams } prop'ları ve
            # route.ts işleyicisinin ikinci parametresi ({ params }) adresten gelir; getServerSideProps(context).
            for exported, fn in self._exported_functions(module):
                params = fn.get("params") or []
                if exported == "default" and _NEXT_APP_PAGE_RE.search(module.relpath) and params \
                        and _t(params[0]) == "ObjectPattern" and {_key_name(p) for p in params[0].get("properties", [])
                                                                   if _t(p) == "ObjectProperty"} & {"params", "searchParams"}:
                    self._mark_entry(fn, 0, "Next.js params/searchParams")
                elif exported in _NEXT_SSR_EXPORTS and params:
                    self._mark_entry(fn, 0, f"{exported}(context)")
                elif _NEXT_ROUTE_RE.search(module.relpath) and exported in _NEXT_ROUTE_METHODS and len(params) >= 2:
                    self._mark_entry(fn, 1, "Next.js dinamik rota parçası (params)")
            # 1) Lambda / Netlify / Azure v3 / Vercel-Next pages API: dışa aktarılan fonksiyonlar
            for exported, fn in self._exported_functions(module):
                params = fn.get("params") or []
                if not params:
                    continue
                first = params[0]
                first_name = first.get("name", "") if _t(first) == "Identifier" else ""
                mapped = (stem, exported) in exact or any(
                    exported == name and (stem == path or stem.endswith("/" + path)) for path, name in suffix)
                typed = first.get("tn") in _LAMBDA_EVENT_TYPES
                named = bool(_LAMBDA_HANDLER_NAME_RE.search(exported)) and (
                    first_name in _LAMBDA_EVENT_PARAMS or _t(first) == "ObjectPattern")
                if (mapped or typed or named) and first_name not in {"req", "request", "ctx", "context"}:
                    self._mark_entry(fn, 0, "event")
                    continue
                second = params[1] if len(params) > 1 else {}
                if exported == "*" and first_name in {"context", "ctx"} and _t(second) == "Identifier" \
                        and second.get("name") in {"req", "request"}:
                    self.entry_roots.setdefault(id(fn), set()).add(1)  # Azure Functions v3 (context, req)
                elif exported == "default" and first_name in {"req", "request"} and _NEXT_PAGES_API_RE.search(module.relpath):
                    self.handlers.add(id(fn))  # Vercel / Next.js pages/api (req, res)
            scope = JsScope(self, module, {})
            for node in self._program_nodes(module, 200_000):
                kind = _t(node)
                # export const handler: APIGatewayProxyHandler = async (event) => …
                if kind == "VariableDeclarator" and (node.get("id") or {}).get("tn") in _LAMBDA_HANDLER_TYPES:
                    self._mark_entry(node.get("init"), 0, "event")
                elif _is_function(node) and node.get("async") and \
                        "use server" in ((node.get("body") or {}).get("dirs") or []):
                    # Bileşen içindeki satır içi sunucu eylemi: async function act(formData) { 'use server'; … }
                    for index in range(len(node.get("params") or [])):
                        self._mark_entry(node, index, "sunucu eylemi argümanı")
                elif kind == "CallExpression":
                    self._entry_call(scope, node, packages)
                    if _callee_name(node.get("callee")).rsplit(".", 1)[-1] in _RESOLVER_MERGE_CALLS:
                        self._mark_resolver_collection(scope, node)
                elif kind == "ObjectExpression":
                    keys = {_key_name(p): p for p in node.get("properties", []) if _t(p) in {"ObjectProperty", "ObjectMethod"}}
                    if _GRAPHQL_ROOT_TYPES & set(keys):
                        # Apollo/graphql-tools/yoga/mercurius resolver haritası: Tür → alan → (parent, args, ctx).
                        for prop in keys.values():
                            inner = self._resolve_object(scope, prop.get("value")) if _t(prop) == "ObjectProperty" else None
                            if inner is not None:
                                self._mark_resolver_map(scope, inner, 1)
                    if "resolvers" in keys and ("typeDefs" in keys or "schema" in keys) \
                            and _t(keys["resolvers"]) == "ObjectProperty":
                        # makeExecutableSchema / ApolloServer / createYoga({ typeDefs, resolvers: [a, b] | obj })
                        self._mark_resolver_collection(scope, keys["resolvers"].get("value"))
                    if "resolve" in keys and ("type" in keys or "args" in keys):
                        # graphql-js: { type, args, resolve(source, args) }
                        prop = keys["resolve"]
                        fn = self._resolve_fn(scope, prop if _t(prop) == "ObjectMethod" else prop.get("value"))
                        if fn is not None:
                            self._mark_entry(fn, 1, "args")
                    if "rootValue" in keys and _t(keys["rootValue"]) == "ObjectProperty":
                        # buildSchema + rootValue: kök çözücülerin ilk parametresi argümanlardır.
                        rv = keys["rootValue"].get("value")
                        root = self._resolve_object(scope, rv)
                        if root is not None:
                            # 18. tur: kök nesne başka modülde tanımlıysa çözücü adları o modülün kapsamında çözülür
                            ref = scope.resolve_ref(rv) if _t(rv) in {"Identifier", "MemberExpression"} else None
                            root_scope = JsScope(self, ref[1], {}) if ref is not None and ref[0] == "object" \
                                and ref[1] is not module else scope
                            self._mark_resolver_map(root_scope, root, 0)

    def _entry_call(self, scope: "JsScope", node: Node, packages: set[str]) -> None:
        name = _callee_name(node.get("callee"))
        last = name.rsplit(".", 1)[-1]
        args = node.get("arguments") or []
        if not args:
            return
        fn_arg = next((a for a in reversed(args) if _is_function(a) or _t(a) == "Identifier"), None)
        if packages & _MCP_PACKAGES and fn_arg is not None and len(args) >= 3:
            middle = args[1:-1]
            if last in _MCP_ARG_METHODS and any(_t(a) != "StringLiteral" and _t(a) != "TemplateLiteral" for a in middle):
                # MCP sunucusu: server.tool(ad, şema, ({arg}) => …) / registerTool(ad, {inputSchema}, …):
                # araç/istem argümanları istemciden (LLM ajanı; istem enjeksiyonuyla saldırgan) gelir.
                fn = self._resolve_fn(scope, fn_arg)
                if fn is not None:
                    self._mark_entry(fn, 0, "MCP araç argümanları (tools/call)")
                return
            if last in _MCP_RESOURCE_METHODS and any(
                    _t(a) == "NewExpression" and _callee_name(a.get("callee")).rsplit(".", 1)[-1] == "ResourceTemplate"
                    for a in middle):
                fn = self._resolve_fn(scope, fn_arg)
                if fn is not None:
                    self._mark_entry(fn, 1, "MCP kaynak şablonu değişkenleri")
                return
        if packages & _JWT_PACKAGES and last in _JWT_KEY_CALLBACK_CALLS and len(args) >= 2 \
                and (_is_function(args[1]) or _t(args[1]) == "Identifier"):
            # jwt.verify(token, getKey) / jose.jwtVerify(token, getKey): anahtar seçme geri çağrısının ilk
            # parametresi (header: kid/jku/x5u) imza doğrulanmadan önce, saldırganın token'ından okunur.
            fn = self._resolve_fn(scope, args[1])
            if fn is not None:
                self._mark_entry(fn, 0, "JWT başlığı (imza doğrulanmadan)")
            return
        firebase = any(p.startswith("firebase-functions") for p in packages)
        if firebase and last == "onRequest" and fn_arg is not None:
            fn = self._resolve_fn(scope, fn_arg)
            if fn is not None:
                self.handlers.add(id(fn))
        elif firebase and last == "onCall" and fn_arg is not None:
            fn = self._resolve_fn(scope, fn_arg)
            if fn is not None:
                self._mark_entry(fn, 0, "data")  # v1 (data, context) / v2 (request): istemci verisi
        elif "@google-cloud/functions-framework" in packages and last in {"http", "cloudEvent"} and len(args) >= 2:
            fn = self._resolve_fn(scope, args[1])
            if fn is not None:
                if last == "http":
                    self.handlers.add(id(fn))
                else:
                    self._mark_entry(fn, 0, "cloudEvent")
        elif "@azure/functions" in packages and len(args) >= 2 and _t(args[1]) == "ObjectExpression" and \
                last in {"http", "get", "post", "put", "patch", "deleteRequest"}:
            # Azure Functions v4: app.http('ad', { handler: async (request, context) => … })
            for prop in args[1].get("properties", []):
                if _key_name(prop) == "handler":
                    fn = self._resolve_fn(scope, prop if _t(prop) == "ObjectMethod" else prop.get("value"))
                    if fn is not None:
                        self._mark_entry(fn, 0, "request")

    def run(self) -> None:
        self.collect_handlers()
        self.collect_entrypoints()
        for module in list(self.modules.values()):
            JsScope(self, module, {}).run_module()
            for qual, node in list(module.functions.items()):
                head = qual.split(".")[0]
                cls = head if head in module.classes or head in module.ctor_functions else None
                self.summary(module, qual, node, cls)
        while self.extra:
            module, qual, node, cls, captured, refs = self.extra.pop(0)
            self.summary(module, qual, node, cls, captured, refs)
        self.run_angular()
        self.collect_uncalled_entry_sinks()

    # -- Angular şablonları -----------------------------------------------------------
    def _template_text(self, module: JsModule, url: str) -> tuple[str, str] | None:
        relpath = taint_angular.resolve_template_path(module.relpath, url)
        if relpath is None:
            return None
        if self.templates is not None and relpath in self.templates:
            return relpath, self.templates[relpath]
        if self.template_root is not None:
            text = taint_angular.read_template(self.template_root, relpath)
            if text is not None:
                return relpath, text
        return None

    def _component_template(self, module: JsModule, node: Node) -> tuple[str, str, int, int] | None:
        """@Component şablonu: (şablon yolu, metin, rapor satırı, şablonun dosyadaki ilk satırı)."""
        for decorator in node.get("decorators") or []:
            expression = decorator.get("expression") or {}
            if _t(expression) != "CallExpression" or _callee_name(expression.get("callee")).rsplit(".", 1)[-1] != "Component":
                continue
            options = (expression.get("arguments") or [None])[0]
            if _t(options) != "ObjectExpression":
                return None
            for prop in options.get("properties", []):
                key = _key_name(prop)
                value = prop.get("value")
                if key == "templateUrl":
                    url = _string_value(value)
                    found = self._template_text(module, url or "")
                    if found is not None:
                        return found[0], found[1], _line(prop), 0
                elif key == "template":
                    text = _string_value(value)
                    if text is None and _t(value) == "TemplateLiteral" and not value.get("expressions"):
                        text = "".join(((q.get("value") or {}).get("cooked") or "") for q in value.get("quasis") or [])
                    if text is not None:
                        return module.relpath, text, _line(prop), _line(value) - 1
            return None
        return None

    def _bypass_pipes(self) -> set[str]:
        names = set(_BYPASS_PIPES)
        for module in self.modules.values():
            for cls, node in module.classes.items():
                for decorator in node.get("decorators") or []:
                    expression = decorator.get("expression") or {}
                    if _t(expression) != "CallExpression" or _callee_name(expression.get("callee")).rsplit(".", 1)[-1] != "Pipe":
                        continue
                    options = (expression.get("arguments") or [None])[0]
                    pipe = next((_string_value(p.get("value")) for p in (options or {}).get("properties", [])
                                 if _key_name(p) == "name"), None) if _t(options) == "ObjectExpression" else None
                    transform = module.functions.get(f"{cls}.transform")
                    if pipe and transform is not None and any(
                        _t(c) == "CallExpression" and _callee_name(c.get("callee")).rsplit(".", 1)[-1].startswith("bypassSecurityTrust")
                        for c in _walk(transform, 5_000)
                    ):
                        names.add(pipe)
        return names

    def _component_state(self, module: JsModule, cls: str, node: Node) -> tuple[dict[str, Taint], set[str]]:
        """Bileşen alanlarının somut taint'i (tüm metot yazımları + ilk değerler) ve bypass'lı alanlar."""
        writes: dict[str, Taint] = {}
        trusted: set[str] = set()
        scope = JsScope(self, module, {}, class_name=cls)
        for member in (node.get("body") or {}).get("body", []):
            if _t(member) in {"ClassProperty", "ClassPrivateProperty"} and member.get("value") is not None \
                    and not _is_function(member.get("value")) and _key_name(member):
                writes[_key_name(member)] = tf._union(writes.get(_key_name(member), _EMPTY), scope.expr(member["value"]))
        prefix = f"{cls}."
        for qual, fn in module.functions.items():
            if not qual.startswith(prefix):
                continue
            summary = self.summaries.get(id(fn))
            if summary is not None:
                for field, taint in summary.field_writes.items():
                    writes[field] = tf._union(writes.get(field, _EMPTY), taint)
            for child in _walk(fn, 20_000):
                if _t(child) == "AssignmentExpression":
                    chain = _chain(child.get("left"))
                    if chain and len(chain) == 2 and chain[0] == "this" and any(
                        _t(c) == "CallExpression" and _callee_name(c.get("callee")).rsplit(".", 1)[-1].startswith("bypassSecurityTrust")
                        for c in _walk(child.get("right"), 2_000)
                    ):
                        trusted.add(chain[1])
        # this.a = this.b: sembolik alan kökenlerini (sabit noktaya kadar, sınırlı) çöz.
        resolved = {field: tuple(o for o in taint if o.label not in {_PARAM, tf._FIELD}) for field, taint in writes.items()}
        for _ in range(4):
            changed = False
            for field, taint in writes.items():
                extra = tf._union(*(tf._clean(resolved.get(o.source, _EMPTY), o.cleaned) for o in taint if o.label == tf._FIELD))
                merged = tf._union(resolved.get(field, _EMPTY), extra)
                if merged != resolved.get(field, _EMPTY):
                    resolved[field] = merged
                    changed = True
            if not changed:
                break
        return resolved, trusted

    @staticmethod
    def _component_options(node: Node) -> Node | None:
        for decorator in node.get("decorators") or []:
            expression = decorator.get("expression") or {}
            if _t(expression) == "CallExpression" and _callee_name(expression.get("callee")).rsplit(".", 1)[-1] == "Component":
                options = (expression.get("arguments") or [None])[0]
                return options if _t(options) == "ObjectExpression" else None
        return None

    def _component_inputs(self, module: JsModule, cls: str, node: Node) -> tuple[dict[str, str], dict[str, Node], set[str]]:
        """@Input alanları: (bağlama adı → alan), (bağlama adı → set erişimcisi), sinyal girdileri (`x = input()`)."""
        fields: dict[str, str] = {}
        setters: dict[str, Node] = {}
        signals: set[str] = set()
        for member in (node.get("body") or {}).get("body", []):
            key = _key_name(member)
            if not key:
                continue
            for decorator in member.get("decorators") or []:
                expression = decorator.get("expression") or {}
                if _t(expression) != "CallExpression" or _callee_name(expression.get("callee")).rsplit(".", 1)[-1] != "Input":
                    continue
                args = expression.get("arguments") or []
                alias = _string_value(args[0]) if args else None
                if alias is None and args and _t(args[0]) == "ObjectExpression":
                    alias = next((_string_value(p.get("value")) for p in args[0].get("properties", []) if _key_name(p) == "alias"), None)
                bind = alias or key
                if _t(member) in {"ClassMethod", "ClassPrivateMethod"} and member.get("kind") == "set":
                    setters[bind] = member
                else:
                    fields[bind] = key
            value = member.get("value")
            if _t(member) in {"ClassProperty", "ClassPrivateProperty"} and _t(value) == "CallExpression" and \
                    _callee_name(value.get("callee")) in {"input", "input.required", "model", "model.required"}:
                fields[key] = key
                signals.add(key)
        return fields, setters, signals

    def _binding_taint(self, module: JsModule, cls: str, fields: dict[str, Taint], root: str, call: bool,
                       signals: set[str]) -> tuple[Taint, Node | None]:
        """Şablon ifadesi kökünün taint'i (alan, getter, metot dönüşü ya da sinyal girdisi) ve metot düğümü."""
        if call and root not in signals:
            fn = module.functions.get(f"{cls}.{root}")
            summary = self.summaries.get(id(fn)) if fn is not None else None
            if summary is None:
                return _EMPTY, None
            return tf._union(summary.ret_sources, *(tf._clean(fields.get(f, _EMPTY), c) for f, c in summary.ret_fields.items())), fn
        taint = fields.get(root, _EMPTY)
        getter = module.functions.get(f"{cls}.get {root}")
        if not taint and getter is not None and self.summaries.get(id(getter)) is not None:
            taint = self.summaries[id(getter)].ret_sources
        return taint, None

    def run_angular(self) -> None:
        if self.templates is None and self.template_root is None:
            return
        components: list[dict[str, Any]] = []
        for module in list(self.modules.values()):
            for cls, node in module.classes.items():
                options = self._component_options(node)
                if options is None:
                    continue
                selector = next((_string_value(p.get("value")) for p in options.get("properties", [])
                                 if _key_name(p) == "selector"), None) or ""
                inputs, setters, signals = self._component_inputs(module, cls, node)
                components.append({
                    "module": module, "cls": cls, "node": node, "template": self._component_template(module, node),
                    "tags": taint_angular.element_selectors(selector), "inputs": inputs, "setters": setters,
                    "signals": signals, "inherited": {},
                })
        if not components:
            return
        states: dict[int, tuple[dict[str, Taint], set[str]]] = {}

        def state_of(component: dict[str, Any]) -> tuple[dict[str, Taint], set[str]]:
            key = id(component["node"])
            if key not in states:
                states[key] = self._component_state(component["module"], component["cls"], component["node"])
            return states[key]

        def fields_of(component: dict[str, Any]) -> dict[str, Taint]:
            fields = dict(state_of(component)[0])
            for field, taint in component["inherited"].items():
                fields[field] = tf._union(fields.get(field, _EMPTY), taint)
            return fields

        # @Input: ebeveyn şablonundaki `<alt-bilesen [girdi]="ifade">` değeri alt bileşenin alanına akar
        # (iç içe bileşen zincirleri için sınırlı sabit nokta). Bağlanmamış @Input alanı kaynak sayılmaz.
        by_tag: dict[str, list[dict[str, Any]]] = {}
        for component in components:
            if component["inputs"] or component["setters"]:
                for tag in component["tags"]:
                    by_tag.setdefault(tag, []).append(component)
        if by_tag:
            for _ in range(3):
                changed = False
                for parent in components:
                    if parent["template"] is None:
                        continue
                    text = parent["template"][1]
                    lowered = text.lower()
                    parent_fields = None
                    for tag, children in by_tag.items():
                        if f"<{tag}" not in lowered:
                            continue
                        bindings = taint_angular.element_input_bindings(text, tag)
                        if not bindings:
                            continue
                        if parent_fields is None:
                            parent_fields = fields_of(parent)
                        for binding in bindings:
                            taint, _ = self._binding_taint(parent["module"], parent["cls"], parent_fields, binding.root,
                                                           binding.call, parent["signals"])
                            taint = tuple(o for o in taint if o.label not in {_PARAM, tf._FIELD})
                            if not taint:
                                continue
                            for child in children:
                                targets: dict[str, Taint] = {}
                                if binding.prop in child["inputs"]:
                                    targets[child["inputs"][binding.prop]] = taint
                                setter = child["setters"].get(binding.prop)
                                summary = self.summaries.get(id(setter)) if setter is not None else None
                                if summary is not None:
                                    # @Input() set x(v) { this.y = v }: parametre kökenleri ebeveyn değeriyle değişir.
                                    for field, written in summary.field_writes.items():
                                        mapped = tf._union(*(tf._clean(taint, o.cleaned) for o in written
                                                             if o.label == _PARAM and o.source == "0"),
                                                           tuple(o for o in written if o.label not in {_PARAM, tf._FIELD}))
                                        if mapped:
                                            targets[field] = mapped
                                for field, value in targets.items():
                                    merged = tf._union(child["inherited"].get(field, _EMPTY), value)
                                    if merged != child["inherited"].get(field, _EMPTY):
                                        child["inherited"][field] = merged
                                        changed = True
                if not changed:
                    break

        bypass_pipes: set[str] | None = None
        for component in components:
            if component["template"] is None:
                continue
            module, cls, node = component["module"], component["cls"], component["node"]
            template_path, text, report_line, offset = component["template"]
            bindings = taint_angular.html_bindings(text)
            if not bindings:
                continue
            if bypass_pipes is None:
                bypass_pipes = self._bypass_pipes()
            fields = fields_of(component)
            trusted = state_of(component)[1]
            anchors = self._member_lines(module, cls, node)
            for binding in bindings:
                taint, fn = self._binding_taint(module, cls, fields, binding.root, binding.call, component["signals"])
                if binding.call and binding.root not in component["signals"]:
                    if fn is None:
                        continue
                    bypassed = any(_t(c) == "CallExpression" and _callee_name(c.get("callee")).rsplit(".", 1)[-1].startswith("bypassSecurityTrust")
                                   for c in _walk(fn, 5_000))
                else:
                    bypassed = binding.root in trusted
                piped = any(pipe in bypass_pipes for pipe in binding.pipes)
                if bypassed and not piped:
                    continue  # bypassSecurityTrust* çağrısının kendisi hedef olarak raporlanır
                kind = "html" if piped else "angular_html"
                where = template_path if template_path != module.relpath else "satır içi şablon"
                sink = f"[{binding.prop}] ({where}:{binding.line + offset})"
                # Rapor satırı: bağlanan alanın/metodun bileşendeki satırı (yoksa şablon özelliği).
                line = anchors.get(binding.root, report_line)
                for origin in tf._live(taint, "html"):
                    if origin.label in {_PARAM, tf._FIELD}:
                        continue
                    self.add_flow(tf.Flow(
                        "javascript", kind, sink, line, origin.source, origin.label, origin.line, origin.via,
                        module.relpath, origin.file,
                    ))

    @staticmethod
    def _member_lines(module: JsModule, cls: str, node: Node) -> dict[str, int]:
        """Bileşen üyelerinin satırı: alan bildirimi, metot ya da ilk `this.alan =` ataması."""
        lines: dict[str, int] = {}
        for member in (node.get("body") or {}).get("body", []):
            key = _key_name(member)
            if key and _line(member):
                lines.setdefault(key, _line(member))
        prefix = f"{cls}."
        for qual, fn in module.functions.items():
            if not qual.startswith(prefix):
                continue
            for child in _walk(fn, 20_000):
                if _t(child) == "AssignmentExpression":
                    chain = _chain(child.get("left"))
                    if chain and len(chain) == 2 and chain[0] == "this" and _line(child):
                        lines.setdefault(chain[1], _line(child))
        return lines


class JsScope:
    def __init__(self, project: JsProject, module: JsModule, env: dict[str, Taint], *,
                 summary: tf._PySummary | None = None, class_name: str | None = None,
                 qual: str = "<module>", roots: set[str] | None = None,
                 middleware_paths: set[tuple[str, ...]] | None = None) -> None:
        self.p = project
        self.m = module
        self.env = env
        self.summary = summary
        self.class_name = class_name
        self.qual = qual
        self.roots = set(_REQUEST_ROOTS) | (roots or set())
        self.middleware_paths = set(middleware_paths or ())
        self.refs: dict[str, Ref] = {}
        # Özyinelemeli, korumasız anahtar kopyalayıcı (bkz. _unsafe_recursive_merge): tek düzey obj[k] = v
        # ataması, özyinelemeyle obj[k1][k2] = v'ye eşdeğerdir.
        self.unsafe_merge = False
        self.local_funcs: dict[str, Node] = {}
        # Fonksiyon içindeki require: const u = require('node-serialize') → u.unserialize = node-serialize.unserialize.
        self.local_imports: dict[str, tuple[str, str]] = {}
        self.immutable_local_imports: set[str] = set()
        # Immutable callable aliases used as callbacks or scheduler callees.
        # Mutable bindings deliberately stay unresolved.
        self.callback_aliases: dict[str, Node] = {
            name: module.values[name]
            for name in module.static_values
            if name in module.values
        }
        # Bütün istek gövdesi/sorgusu nesnesini tutan adlar (const profile = req.body).
        self.request_objects: set[str] = set()
        self.returns: list[Taint] = []
        # Satır içi geri çağrı kapsamı (_closure): özeti dış fonksiyonla paylaşır (hedefler, alan/global yazımları),
        # ama `return` dış fonksiyondan dönmez — dönüş yalnız geri çağrının değeridir.
        self.closure = False
        # Sabit değerli yerel adlar (ölü dal budama), alanları tam bilinen nesne/Map'ler, öğeleri izlenen diziler.
        self.consts: dict[str, Any] = {}
        self.exact: set[str] = set()
        self.lists: dict[str, list[Taint]] = {}
        # u = new URL(x): u üzerindeki doğrulama x'i de doğrular.
        self.derived: dict[str, str] = {}
        # Dış sınıf örnekleri (new URLSearchParams() …) ve ldap istemcileri.
        self.ctors: dict[str, str] = {}
        self.unstable: set[str] = set()
        # Değeri kesin olarak güvenli URL önekiyle başlayan adlar (let u = '/app/'; u += x).
        self.url_safe: set[str] = set()
        self.url_abs: set[str] = set()
        # Yerel adların NoSQL alıcı türü (None: yerel ama türü bilinmiyor; modül adına düşülmez).
        self.kinds: dict[str, str | None] = {}
        self.loop_depth = 0
        # TS türü yanıt nesnesi olan adlar (rs: NextApiResponse → rs.redirect = res.redirect).
        self.responses: set[str] = set()
        # Değeri kesin dize olan yerel adlar (res.send(msg) → text/html) ve HTML dışı içerik türü atanmış yanıtlar.
        self.string_vars: set[str] = set()
        self.non_html: set[str] = set()
        # Çağrı etkileri: yapıcının yazdığı alanlar, fabrikanın döndürdüğü sınıf; ifadelerin biçimleri.
        self.call_fields: dict[int, dict[str, Taint]] = {}
        self.call_refs: dict[int, Ref] = {}
        self.shapes: dict[int, Any] = {}
        # NestJS @Redirect() işleyicisi: dönen nesnenin url alanı yönlendirme adresidir.
        self.nest_redirect = False
        # React bileşeninin props parametresi (props.x → §prop("x")).
        self.prop_roots: set[str] = set()
        # Yalnız alan yazımıyla (form.action = location.href) kirlenen nesne kökleri: kökene → kirleten kökenler.
        # Nesnenin kendisi ($(form)) ya da yazılmamış başka alanı ($(options.target)) HTML dizgesi değildir.
        self.field_added: dict[str, set[tuple]] = {}

    # -- giriş noktaları -------------------------------------------------------------
    def run_module(self) -> None:
        self.unstable |= self.p.closure_writes(self.m.program)
        self.block(self.m.program.get("body", []), top=True)

    def run_function_body(self, node: Node) -> None:
        self.nest_redirect = any(
            _t(d.get("expression")) == "CallExpression"
            and _callee_name(d["expression"].get("callee")).rsplit(".", 1)[-1] == "Redirect"
            for d in node.get("decorators") or [])
        body = node.get("body")
        self.unstable |= self.p.closure_writes(body)
        if _t(body) == "BlockStatement":
            self.block(body.get("body", []))
        elif body is not None:
            taint = self.expr(body)
            self._return(taint, body)

    def _return(self, taint: Taint, node: Any = None) -> None:
        self.returns.append(taint)
        if self.nest_redirect and not self.closure and _t(node) == "ObjectExpression":
            for prop in node.get("properties", []):
                if _key_name(prop) == "url":
                    # @Redirect() işleyicisinin dönüşü { url }: Nest yanıtı bu adrese yönlendirir.
                    self._emit("redirect", "@Redirect() { url }", _line(prop) or _line(node), self.expr(prop.get("value")))
        if self.summary is not None and not self.closure:
            self.summary.add_return(taint)
            ref = self._value_ref(node)
            if ref is not None and ref[0] == "instance" and getattr(self.summary, "js_ret_ref", None) is None:
                # Fabrika: return new Repo() → çağıranda dönen değer Repo örneği.
                self.summary.js_ret_ref = ref
            fields = self._value_fields(node)
            if fields:
                merged = dict(getattr(self.summary, "js_ret_fields", None) or {})
                for field, taint in fields.items():
                    merged[field] = tf._union(merged.get(field, _EMPTY), taint)
                self.summary.js_ret_fields = merged

    def _value_fields(self, node: Any) -> dict[str, Taint]:
        """Döndürülen değerin bilinen alanları (yeni örnek / izlenen yerel nesne)."""
        if _t(node) in {"NewExpression", "CallExpression"}:
            return dict(self.call_fields.get(id(node)) or {})
        if _t(node) == "Identifier":
            prefix = node.get("name", "") + "."
            return {key[len(prefix):]: value for key, value in self.env.items()
                    if key.startswith(prefix) and "." not in key[len(prefix):] and value}
        return {}

    def _value_ref(self, node: Any) -> Ref | None:
        if _t(node) == "NewExpression":
            return self.p.type_ref(self.m, _dotted(node.get("callee")))
        if _t(node) == "Identifier":
            ref = self.refs.get(node.get("name", ""))
            return ref if ref is not None and ref[0] == "instance" else None
        if _t(node) in {"CallExpression", "AwaitExpression"}:
            inner = node.get("argument") if _t(node) == "AwaitExpression" else node
            return self.call_refs.get(id(inner))
        return None

    # -- durum (dallar) ---------------------------------------------------------------
    def _snapshot(self) -> tuple[dict[str, Taint], dict[str, Any], set[str], dict[str, list[Taint]]]:
        return dict(self.env), dict(self.consts), set(self.exact), {k: list(v) for k, v in self.lists.items()}

    def _restore(self, state: tuple[dict[str, Taint], dict[str, Any], set[str], dict[str, list[Taint]]]) -> None:
        env, consts, exact, lists = state
        self.env, self.consts, self.exact = dict(env), dict(consts), set(exact)
        self.lists = {k: list(v) for k, v in lists.items()}

    def _merge_states(self, states: list[tuple[dict[str, Taint], dict[str, Any], set[str], dict[str, list[Taint]]]]) -> None:
        self.env = self._merge([state[0] for state in states])
        first = states[0]
        self.consts = {
            name: value for name, value in first[1].items()
            if all(name in other[1] and _js_strict_eq(other[1][name], value) and _js_type(other[1][name]) == _js_type(value)
                   for other in states[1:])
        }
        self.exact = set.intersection(*(state[2] for state in states))
        lists: dict[str, list[Taint]] = {}
        for name, items in first[3].items():
            others = [state[3].get(name) for state in states[1:]]
            if all(other is not None and len(other) == len(items) for other in others):
                lists[name] = [tf._union(item, *(other[i] for other in others if other is not None)) for i, item in enumerate(items)]
        self.lists = lists

    # -- kaynaklar ------------------------------------------------------------------
    def _source(self, text: str, line: int) -> Taint:
        return (tf._Origin("request", text, line, (), frozenset(), self.m.relpath),)

    def _pii(self, name: str, line: int) -> Taint:
        if self.p.pii and name and self.p.pii(name):
            return (tf._Origin("pii", name, line, (), frozenset(), self.m.relpath),)
        return _EMPTY

    def _member_source(self, chain: list[str], line: int) -> Taint | None:
        root = chain[0]
        if len(chain) >= 2:
            if root in self.roots and chain[1] in _REQUEST_MEMBERS:
                return self._source(f"{root}.{chain[1]}", line)
            if root in self.roots and tuple(chain[1:]) in self.middleware_paths:
                return self._source(".".join(chain), line)
            if root in _CTX_ROOTS:
                if chain[1] in _CTX_MEMBERS:
                    return self._source(f"{root}.{chain[1]}", line)
                if chain[1] == "request" and len(chain) >= 3 and chain[2] in _REQUEST_MEMBERS:
                    return self._source(f"{root}.request.{chain[2]}", line)
            for index in range(1, len(chain) - 1):
                if chain[index] == "snapshot" and "route" in chain[index - 1].lower() and chain[index + 1] in _ANGULAR_ROUTE_MEMBERS:
                    return self._source(".".join(chain[index - 1:index + 2]), line)
            if root in {"window", "document"} and len(chain) >= 3 and chain[1] == "location" and chain[2] in _BROWSER_SOURCES["location"]:
                return self._browser_source(f"{root}.location.{chain[2]}", line)
            if root in _BROWSER_SOURCES and chain[1] in _BROWSER_SOURCES[root] and root not in self.env:
                return self._browser_source(f"{root}.{chain[1]}", line)
        return None

    def _browser_source(self, text: str, line: int) -> Taint:
        taint = self._source(text, line)
        return tf._clean(taint, _URL_TARGET_KINDS) if text in _SAME_PAGE_SOURCES else taint

    # -- sabit değerlendirme ----------------------------------------------------------
    def _const(self, node: Any, depth: int = 0) -> Any:
        """İfadenin derleme anı değeri (dize/sayı/mantıksal/null/undefined/dizi/nesne) ya da _UNKNOWN."""
        if depth > 40 or not isinstance(node, dict):
            return _UNKNOWN
        kind = _t(node)
        nxt = depth + 1
        if kind == "StringLiteral":
            return str(node.get("value", ""))
        if kind == "NumericLiteral":
            value = node.get("value")
            return value if isinstance(value, (int, float)) and not isinstance(value, bool) else _UNKNOWN
        if kind == "BooleanLiteral":
            return bool(node.get("value"))
        if kind == "NullLiteral":
            return None
        if kind == "TemplateLiteral":
            out: list[str] = []
            expressions = node.get("expressions") or []
            for index, quasi in enumerate(node.get("quasis") or []):
                out.append((quasi.get("value") or {}).get("cooked") or "")
                if index < len(expressions):
                    value = self._const(expressions[index], nxt)
                    if value is _UNKNOWN:
                        return _UNKNOWN
                    out.append(_js_str(value))
            text = "".join(out)
            return text if len(text) <= _MAX_CONST_STR else _UNKNOWN
        if kind == "Identifier":
            name = node.get("name", "")
            if name in self.consts:
                return self.consts[name]
            if name == "undefined" and name not in self.env:
                return _UNDEF
            return _UNKNOWN
        if kind in {"ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression", "TSSatisfiesExpression", "TypeCastExpression"}:
            return self._const(node.get("expression"), nxt)
        if kind == "UnaryExpression":
            operator = node.get("operator")
            if operator == "void":
                return _UNDEF
            value = self._const(node.get("argument"), nxt)
            if value is _UNKNOWN:
                return _UNKNOWN
            if operator == "!":
                return not _js_truthy(value)
            if operator == "typeof":
                kind_name = _js_type(value)
                return "object" if kind_name == "null" else kind_name
            if operator == "-":
                return -_js_num(value)
            if operator == "+":
                return _js_num(value)
            return _UNKNOWN
        if kind == "BinaryExpression":
            left = self._const(node.get("left"), nxt)
            if left is _UNKNOWN:
                return _UNKNOWN
            right = self._const(node.get("right"), nxt)
            if right is _UNKNOWN:
                return _UNKNOWN
            return self._binary(node.get("operator", ""), left, right)
        if kind == "LogicalExpression":
            left = self._const(node.get("left"), nxt)
            if left is _UNKNOWN:
                return _UNKNOWN
            operator = node.get("operator")
            if operator == "&&":
                return self._const(node.get("right"), nxt) if _js_truthy(left) else left
            if operator == "||":
                return left if _js_truthy(left) else self._const(node.get("right"), nxt)
            return self._const(node.get("right"), nxt) if left is None or left is _UNDEF else left
        if kind == "ConditionalExpression":
            test = self._const(node.get("test"), nxt)
            if test is _UNKNOWN:
                return _UNKNOWN
            return self._const(node.get("consequent") if _js_truthy(test) else node.get("alternate"), nxt)
        if kind == "ArrayExpression":
            items: list[Any] = []
            for element in node.get("elements") or []:
                value = self._const(element, nxt) if element is not None and _t(element) != "SpreadElement" else _UNKNOWN
                if value is _UNKNOWN:
                    return _UNKNOWN
                items.append(value)
            return items
        if kind == "ObjectExpression":
            result: dict[str, Any] = {}
            for prop in node.get("properties") or []:
                key = _key_name(prop) if _t(prop) == "ObjectProperty" else ""
                value = self._const(prop.get("value"), nxt) if key else _UNKNOWN
                if value is _UNKNOWN:
                    return _UNKNOWN
                result[key] = value
            return result
        if kind in {"MemberExpression", "OptionalMemberExpression"}:
            base = self._const(node.get("object"), nxt)
            if base is _UNKNOWN:
                return _UNKNOWN
            prop = node.get("property") or {}
            key = self._const(prop, nxt) if node.get("computed") else prop.get("name", "")
            if key is _UNKNOWN:
                return _UNKNOWN
            if key == "length" and isinstance(base, (str, list)):
                return len(base)
            if isinstance(base, (str, list)):
                if isinstance(key, (int, float)) and not isinstance(key, bool) and float(key).is_integer():
                    index = int(key)
                    return base[index] if 0 <= index < len(base) else _UNDEF
                return _UNKNOWN
            if isinstance(base, dict):
                name = _const_key(key)
                return base.get(name, _UNDEF) if name is not None else _UNKNOWN
            return _UNKNOWN
        if kind == "CallExpression":
            return self._const_call(node, nxt)
        return _UNKNOWN

    @staticmethod
    def _binary(operator: str, left: Any, right: Any) -> Any:
        if operator == "+":
            if isinstance(left, (str, list, dict)) or isinstance(right, (str, list, dict)):
                text = _js_str(left) + _js_str(right)
                return text if len(text) <= _MAX_CONST_STR else _UNKNOWN
            return _js_num(left) + _js_num(right)
        if operator in {"-", "*", "/", "%", "**"}:
            a, b = _js_num(left), _js_num(right)
            try:
                if operator == "-":
                    return a - b
                if operator == "*":
                    return a * b
                if operator == "/":
                    if b == 0:
                        return float("nan") if a == 0 or a != a else (float("inf") if a > 0 else float("-inf"))
                    return a / b
                if operator == "%":
                    if b == 0:
                        return float("nan")
                    result = math.fmod(a, b)
                    return int(result) if isinstance(a, int) and isinstance(b, int) else result
                if abs(b) > 64:
                    return _UNKNOWN
                return a ** b
            except (OverflowError, ValueError, ZeroDivisionError):
                return _UNKNOWN
        if operator == "===":
            return _js_strict_eq(left, right)
        if operator == "!==":
            return not _js_strict_eq(left, right)
        if operator in {"==", "!="}:
            equal = _js_loose_eq(left, right)
            if equal is _UNKNOWN:
                return _UNKNOWN
            return equal if operator == "==" else not equal
        if operator in {"<", ">", "<=", ">="}:
            if isinstance(left, str) and isinstance(right, str):
                a, b = left, right
            else:
                a, b = _js_num(left), _js_num(right)
                if a != a or b != b:
                    return False
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[operator]
        return _UNKNOWN

    def _const_call(self, node: Node, depth: int) -> Any:
        callee = node.get("callee")
        args = node.get("arguments") or []
        values = [self._const(a, depth) for a in args]
        if any(v is _UNKNOWN for v in values):
            return _UNKNOWN
        if _t(callee) == "Identifier":
            name = callee.get("name", "")
            if name in self.env or name in self.local_funcs:
                return _UNKNOWN
            if name == "String" and values:
                return _js_str(values[0])
            if name == "Number" and values:
                return _js_num(values[0])
            return _UNKNOWN
        if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"} or callee.get("computed"):
            return _UNKNOWN
        method = (callee.get("property") or {}).get("name", "")
        base = self._const(callee.get("object"), depth)
        ints = [int(_js_num(v)) if isinstance(v, (int, float)) and not isinstance(v, bool) and float(v).is_integer() else None for v in values]
        if isinstance(base, str):
            if method in {"toUpperCase", "toLocaleUpperCase"}:
                return base.upper()
            if method in {"toLowerCase", "toLocaleLowerCase"}:
                return base.lower()
            if method == "trim":
                return base.strip()
            if method == "toString":
                return base
            if method == "charAt":
                index = ints[0] if ints else 0
                return base[index] if index is not None and 0 <= index < len(base) else ""
            if method in {"substring", "slice"} and all(i is not None for i in ints):
                start = ints[0] if ints else 0
                end = ints[1] if len(ints) > 1 else len(base)
                if method == "substring":
                    start, end = max(0, min(start, len(base))), max(0, min(end, len(base)))
                    start, end = min(start, end), max(start, end)
                return base[start:end]
            if method == "concat":
                return base + "".join(_js_str(v) for v in values)
            if method in {"indexOf", "includes", "startsWith", "endsWith"} and values and isinstance(values[0], str):
                return {"indexOf": base.find(values[0]), "includes": values[0] in base,
                        "startsWith": base.startswith(values[0]), "endsWith": base.endswith(values[0])}[method]
            if method == "split" and values and isinstance(values[0], str) and values[0]:
                return base.split(values[0])
            if method == "replace" and len(values) == 2 and all(isinstance(v, str) for v in values):
                return base.replace(values[0], values[1], 1)
        if isinstance(base, list):
            if method == "join":
                separator = values[0] if values and isinstance(values[0], str) else ","
                return separator.join("" if v is None or v is _UNDEF else _js_str(v) for v in base)
            if method == "includes" and values:
                return any(_js_strict_eq(item, values[0]) for item in base)
            if method == "indexOf" and values:
                return next((i for i, item in enumerate(base) if _js_strict_eq(item, values[0])), -1)
        return _UNKNOWN

    def _cchain(self, node: Any) -> list[str] | None:
        """Sabit anahtarlı zincir: ``o[k]`` (k sabit) ve ``a[0]`` dahil; çözülemezse None."""
        parts: list[str] = []
        current = node
        while _t(current) in {"MemberExpression", "OptionalMemberExpression"}:
            prop = current.get("property") or {}
            if current.get("computed"):
                key = _const_key(self._const(prop))
                if key is None:
                    return None
                parts.append(key)
            elif _t(prop) in {"Identifier", "PrivateName"}:
                parts.append(prop.get("name") or (prop.get("id") or {}).get("name", ""))
            else:
                return None
            current = current.get("object")
        if _t(current) == "Identifier":
            parts.append(current.get("name", ""))
        elif _t(current) == "ThisExpression":
            parts.append("this")
        else:
            return None
        parts.reverse()
        return parts

    def _exact_miss(self, chain: list[str]) -> bool:
        """Alanları tam bilinen nesnede (o = {a: …}) bulunmayan alan: değer undefined (temiz)."""
        for index in range(1, len(chain)):
            prefix = ".".join(chain[:index])
            if prefix in self.exact:
                return f"{prefix}.{chain[index]}" not in self.env
        return False

    def _field_origin(self, field: str, line: int) -> Taint:
        return (tf._Origin(tf._FIELD, field, line, (), frozenset(), self.m.relpath),)

    def _accessor(self, owner: str, prop: str, kind: str) -> tuple[JsModule, str, Node, str | None] | None:
        """Sınıf get/set erişimcisi: ``obj.ad`` okuma/yazma → erişimci fonksiyon hedefi."""
        if owner == "this":
            ref: Ref | None = ("instance", self.m, self.class_name) if self.class_name else None
        else:
            ref = self.refs.get(owner)
        if ref is None or ref[0] != "instance":
            return None
        found = self.p.method(ref[1], ref[2], f"{kind} {prop}")
        if found is None:
            return None
        module, qual = found
        node = module.functions.get(qual)
        return (module, qual, node, ref[2]) if node is not None else None

    # -- ifadeler -------------------------------------------------------------------
    def expr(self, node: Any) -> Taint:
        if not isinstance(node, dict):
            return _EMPTY
        self.p.tick()
        method = getattr(self, f"_e_{_t(node)}", None)
        if method is not None:
            return method(node)
        return tf._union(*(self.expr(child) for child in _children(node)))

    def _e_Identifier(self, node: Node) -> Taint:
        name = node.get("name", "")
        return tf._union(self.env.get(name, _EMPTY), self._pii(name, _line(node)))

    def _e_MemberExpression(self, node: Node) -> Taint:
        chain = self._cchain(node)
        line = _line(node)
        if chain:
            if chain[-1] in _CLEAN_MEMBERS and not (
                    # req.body.size / req.query.size: istek alanı (ör. resim boyutu), Map/Set.size özelliği değil.
                    len(chain) == 3 and chain[-1] != "length" and chain[0] in self.roots and chain[1] in _REQUEST_MEMBERS):
                self.expr(node.get("object"))
                return _EMPTY
            dotted = ".".join(chain)
            if dotted in self.env:
                return self.env[dotted]
            if len(chain) >= 2 and chain[0] in self.prop_roots and chain[1]:
                return (tf._Origin(_PROP, chain[1], line, (), frozenset(), self.m.relpath),)
            if len(chain) == 2 and chain[0] in self.lists and node.get("computed"):
                items = self.lists[chain[0]]
                index = int(chain[1]) if chain[1].isdigit() else -1
                return items[index] if 0 <= index < len(items) else _EMPTY
            if self._exact_miss(chain):
                return _EMPTY
            if len(chain) == 2:
                getter = self._accessor(chain[0], chain[1], "get")
                if getter is not None:
                    return self._apply_summary(getter, [], {"type": "CallExpression", "callee": node, "arguments": []})
                if chain[0] == "this" and self.summary is not None and self.qual != "<module>":
                    # Metot içinde this.<alan>: çağıranın nesne durumuna göre çözülecek sembolik kaynak.
                    return self._field_origin(chain[1], line)
            source = self._member_source(chain, line)
            if source is not None:
                return source
            attribute_source_for = getattr(self.p.models, "attribute_source_for", None)
            label = attribute_source_for(dotted) if attribute_source_for is not None and chain[0] not in self.env else None
            if label:
                return (tf._Origin(label, dotted, line, (), frozenset(), self.m.relpath),)
        prop = node.get("property") or {}
        if node.get("computed") and _t(node.get("object")) == "ArrayExpression":
            # ['safe', x][0]: dizi değişmezinin sabit indeksli öğesi.
            whole = self.expr(node.get("object"))
            items = self.shapes.get(id(node.get("object")))
            index = self._const(prop)
            if isinstance(items, list) and isinstance(index, (int, float)) and not isinstance(index, bool) and float(index).is_integer():
                return items[int(index)] if 0 <= int(index) < len(items) else _EMPTY
            return tf._union(whole, self.expr(prop))
        if node.get("computed"):
            self.expr(prop)
        name = prop.get("name", "") if not node.get("computed") else ""
        if name in _CLEAN_MEMBERS:
            self.expr(node.get("object"))
            return _EMPTY
        base = self.expr(node.get("object"))
        if name in _LOCATION_APP_STATE and _only_location_hook(base):
            return _EMPTY  # useLocation().state: uygulamanın navigate(…, {state}) ile koyduğu değer, adresten gelmez
        if name in _URL_PART_MEMBERS and base:
            # new URL(location.href).search / .searchParams: sorgu bölümü saldırgan denetiminde.
            # Parametre/alan kökenlerinin kaynağı indeks/alan adıdır (özet eşlemesi için): adı değiştirilmez.
            base = tuple(tf._Origin(o.label, o.source if o.label in {_PARAM, tf._FIELD} or o.source.endswith(f".{name}")
                                    else f"{o.source}.{name}", o.line, o.via,
                                    o.cleaned - _URL_TARGET_KINDS, o.file) for o in base)
        return tf._union(base, self._pii(name, line))

    _e_OptionalMemberExpression = _e_MemberExpression

    def _e_StringLiteral(self, node: Node) -> Taint:
        return _EMPTY

    _e_NumericLiteral = _e_BooleanLiteral = _e_NullLiteral = _e_RegExpLiteral = _e_StringLiteral
    _e_BigIntLiteral = _e_ThisExpression = _e_Super = _e_Import = _e_MetaProperty = _e_StringLiteral

    def _e_TemplateLiteral(self, node: Node) -> Taint:
        parts: list[Taint] = []
        in_query = False
        quasis = node.get("quasis") or []
        first = ((quasis[0].get("value") or {}).get("cooked") or "") if quasis else ""
        fixed_host = bool(first) and _safe_url_prefix(first)
        for index, expression in enumerate(node.get("expressions", [])):
            if index < len(quasis) and _QUERY_MARK_RE.search((quasis[index].get("value") or {}).get("cooked") or ""):
                in_query = True
            taint = self.expr(expression)
            # `${base}?q=${x}`: '?'/'#' sonrası yalnız sorgu/parça; `/app/${x}`: sabit önek ana makineyi sabitler.
            if fixed_host:
                taint = tf._clean(taint, _URL_TARGET_KINDS | _url_mark(first))
            elif in_query:
                taint = tf._clean(taint, _URL_TARGET_KINDS)
            parts.append(taint)
        return tf._clean(tf._union(*parts), frozenset({"nosql"}))

    def _e_TaggedTemplateExpression(self, node: Node) -> Taint:
        taint = self.expr(node.get("quasi"))
        tag = _callee_name(node.get("tag"))
        if tag in _SAFE_SQL_TAGS or tag.endswith(".sql") or tag == "html":
            return _EMPTY
        kinds = self.p.models.sanitizer_kinds(tag) or self.p.models.sanitizer_kinds(self.canonical(tag))
        # ldapEscape.filter`(uid=${x})`: etiket fonksiyonu modeldeki arındırıcıysa.
        return tf._clean(taint, kinds) if kinds else taint

    def _e_BinaryExpression(self, node: Node) -> Taint:
        if node.get("operator") != "+":
            left = self.expr(node.get("left"))
            right = self.expr(node.get("right"))
            # Aritmetik değer taşımaz; yalnız zayıf rastgele kökeni (Math.random() * n) korunur.
            return _weak(tf._union(left, right)) if node.get("operator") in {"-", "*", "/", "%", "**", "|", "^", "&", ">>", "<<", ">>>"} else _EMPTY
        operands: list[Any] = []
        current: Any = node
        while _t(current) == "BinaryExpression" and current.get("operator") == "+":
            operands.append(current.get("right"))
            current = current.get("left")
        operands.append(current)
        operands.reverse()
        parts: list[Taint] = []
        in_query = False
        # Sabit güvenli önek ('/app/' + x, 'https://api.example.com/' + x ya da öyle başlayan bir değişken):
        # sonraki parçalar hedef ana makineyi değiştiremez (yönlendirme/SSRF için temiz).
        fixed_host = self._url_safe_node(operands[0])
        mark = frozenset({_URL_ABS_MARK if self._url_abs_node(operands[0]) else _URL_REL_MARK})
        for index, operand in enumerate(operands):
            literal = _string_value(operand)
            if literal is not None and _QUERY_MARK_RE.search(literal):
                in_query = True
            taint = self.expr(operand)
            # base + '?q=' + x: '?'/'#' sonrası yalnız sorgu/parça, ana makineyi değiştiremez.
            if fixed_host and index > 0:
                taint = tf._clean(taint, _URL_TARGET_KINDS | mark)
            elif in_query:
                taint = tf._clean(taint, _URL_TARGET_KINDS)
            parts.append(taint)
        return tf._clean(tf._union(*parts), frozenset({"nosql"}))

    def _url_safe_node(self, node: Any) -> bool:
        """Değer ana makineyi sabitleyen güvenli bir URL önekiyle mi başlıyor?"""
        literal = _string_value(node)
        if literal is not None:
            return bool(literal) and _safe_url_prefix(literal)
        kind = _t(node)
        if kind == "TemplateLiteral":
            quasis = node.get("quasis") or []
            first = ((quasis[0].get("value") or {}).get("cooked") or "") if quasis else ""
            return bool(first) and _safe_url_prefix(first)
        if kind == "BinaryExpression" and node.get("operator") == "+":
            left = node.get("left")
            while _t(left) == "BinaryExpression" and left.get("operator") == "+":
                left = left.get("left")
            return self._url_safe_node(left)
        if kind == "Identifier":
            return node.get("name", "") in self.url_safe
        if kind in {"ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression"}:
            return self._url_safe_node(node.get("expression"))
        return False

    def _url_abs_node(self, node: Any) -> bool:
        """Değer sabit mutlak ana makineli bir URL önekiyle mi başlıyor ('https://api.x/' …)?"""
        literal = _string_value(node)
        if literal is not None:
            return bool(tf._URL_FIXED_HOST_RE.match(literal))
        kind = _t(node)
        if kind == "TemplateLiteral":
            quasis = node.get("quasis") or []
            return bool(quasis) and bool(tf._URL_FIXED_HOST_RE.match((quasis[0].get("value") or {}).get("cooked") or ""))
        if kind == "BinaryExpression" and node.get("operator") == "+":
            left = node.get("left")
            while _t(left) == "BinaryExpression" and left.get("operator") == "+":
                left = left.get("left")
            return self._url_abs_node(left)
        if kind == "Identifier":
            return node.get("name", "") in self.url_abs
        if kind in {"ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression"}:
            return self._url_abs_node(node.get("expression"))
        return False

    def _fixed_base(self, node: Any) -> bool:
        """Sabit mutlak taban: 'https://api.x' dizgesi/sabiti."""
        value = _string_value(node)
        if value is None and node is not None:
            const = self._const(node)
            value = const if isinstance(const, str) else None
        return bool(value) and bool(_BASE_URL_RE.match(value))

    def _fixed_base_call(self, node: Node, args: list[Node]) -> bool:
        """Çağrının hedef tabanı sabit mi: axios {baseURL: sabit}, axios.create({baseURL}) örneği, new URL(yol, sabit)?"""
        callee = node.get("callee")
        if _t(callee) in {"MemberExpression", "OptionalMemberExpression"} and _t(callee.get("object")) == "Identifier" \
                and self.ctors.get(callee["object"].get("name", "")) == "axios_fixed_base":
            return True
        for arg in args:
            if _t(arg) == "ObjectExpression" and any(
                    _t(p) == "ObjectProperty" and _key_name(p) == "baseURL" and self._fixed_base(p.get("value"))
                    for p in arg.get("properties", [])):
                return True
            if _t(arg) == "NewExpression" and _callee_name(arg.get("callee")) in {"URL", "url.URL"}:
                url_args = arg.get("arguments") or []
                if len(url_args) >= 2 and self._fixed_base(url_args[1]):
                    return True
            if _t(arg) == "Identifier" and self.ctors.get(arg.get("name", "")) == "url_fixed_base":
                return True
        return False

    def _partial_ssrf(self, node: Node, args: list[Node], taint: Taint) -> Taint:
        """Sabit ana makineli isteğin yol/sorgu bölümüne ulaşan kökenler (kısmi SSRF)."""
        base = None
        partial = []
        for origin in taint:
            if "ssrf" not in origin.cleaned:
                continue
            if _URL_ABS_MARK in origin.cleaned:
                partial.append(origin)
            elif _URL_REL_MARK in origin.cleaned:
                if base is None:
                    base = self._fixed_base_call(node, args)
                if base:
                    partial.append(origin)
        return tuple(partial)

    def _e_LogicalExpression(self, node: Node) -> Taint:
        left = self._const(node.get("left"))
        operator = node.get("operator")
        if left is not _UNKNOWN:
            # Sabit sol taraf: sağ taraf ya hiç değerlendirilmez ya da sonucun kendisidir.
            if (operator == "&&" and _js_truthy(left)) or (operator == "||" and not _js_truthy(left)) or (
                operator == "??" and (left is None or left is _UNDEF)
            ):
                return self.expr(node.get("right"))
            return _EMPTY
        return tf._union(self.expr(node.get("left")), self.expr(node.get("right")))

    def _e_ConditionalExpression(self, node: Node) -> Taint:
        test = self._const(node.get("test"))
        if test is not _UNKNOWN:
            # Ölü dal budama: sabit koşulda yalnız seçilen dal.
            return self.expr(node.get("consequent") if _js_truthy(test) else node.get("alternate"))
        self.expr(node.get("test"))
        when_true, when_false = self._guard(node.get("test"))
        results = []
        start = self._snapshot()
        for branch, guard in ((node.get("consequent"), when_true), (node.get("alternate"), when_false)):
            self._restore(start)
            self._apply_guard(guard)
            results.append(self.expr(branch))
        self._restore(start)
        return tf._union(*results)

    def _e_UnaryExpression(self, node: Node) -> Taint:
        taint = self.expr(node.get("argument"))
        if node.get("operator") in {"-", "+", "~"}:
            return _weak(taint)
        return _EMPTY if node.get("operator") in {"typeof", "!", "void", "delete"} else taint

    def _e_UpdateExpression(self, node: Node) -> Taint:
        self.expr(node.get("argument"))
        for name in _pattern_names(node.get("argument")):
            self.consts.pop(name, None)
        return _EMPTY

    def _e_ObjectExpression(self, node: Node) -> Taint:
        parts = []
        shape: dict[str, Taint] | None = {}
        for prop in node.get("properties", []):
            if _t(prop) == "ObjectProperty":
                key = _key_name(prop)
                if prop.get("computed"):
                    self.expr(prop.get("key"))
                    if not key:
                        key = _const_key(self._const(prop.get("key"))) or ""
                value = self.expr(prop.get("value"))
                if key in {"$eq", "$search"} and value:
                    # { alan: { $eq: x } }: x bir nesne olsa da işleç değil, eşitlik değeri olarak karşılaştırılır;
                    # $text.$search yalnız dize kabul eder (nesne sorgu hatası verir), işleç taşıyamaz.
                    value = tf._clean(value, frozenset({"nosql"}))
                if key in _DYNAMO_OBJECT_KEYS and value and self.p.uses_dynamodb() and (
                        key != "Statement" or _string_expr(prop.get("value"), self.string_vars)):
                    # DynamoDB parametre nesnesi: ifade metni / PartiQL deyimi / tablo adı girdiden (değerler
                    # ExpressionAttributeValues ile bağlanmalı). IAM ilke belgesindeki Statement dizisi hedef değildir.
                    self._emit("nosql_expr", f"DynamoDB {key}", _line(prop), value)
                if key == "$where":
                    # MongoDB $where: değer sunucuda JavaScript olarak çalışır (NoSQL kod enjeksiyonu).
                    self._emit("eval", "$where (MongoDB)", _line(prop), value)
                parts.append(value)
                if shape is not None and key:
                    shape[key] = value
                else:
                    shape = None
            elif _t(prop) == "SpreadElement":
                parts.append(self.expr(prop.get("argument")))
                shape = None
            elif _t(prop) == "ObjectMethod":
                self._closure(prop, {})
                if shape is not None and _key_name(prop):
                    shape[_key_name(prop)] = _EMPTY
        if shape is not None:
            self.shapes[id(node)] = shape
        return tf._union(*parts)

    def _e_ArrayExpression(self, node: Node) -> Taint:
        items: list[Taint] = []
        exact = True
        for element in node.get("elements", []):
            if element is None:
                items.append(_EMPTY)
                continue
            if _t(element) == "SpreadElement":
                exact = False
            items.append(self.expr(element))
        if exact:
            self.shapes[id(node)] = items
        return tf._union(*items)

    def _e_SequenceExpression(self, node: Node) -> Taint:
        result: Taint = _EMPTY
        for item in node.get("expressions", []):
            result = self.expr(item)
        return result

    def _passthrough(self, node: Node) -> Taint:
        return self.expr(node.get("expression") or node.get("argument"))

    _e_AwaitExpression = _e_YieldExpression = _e_SpreadElement = _e_ParenthesizedExpression = _passthrough
    _e_TSAsExpression = _e_TSNonNullExpression = _e_TSSatisfiesExpression = _e_TSTypeAssertion = _passthrough
    _e_TypeCastExpression = _e_TSInstantiationExpression = _passthrough

    def _e_ArrowFunctionExpression(self, node: Node) -> Taint:
        self._closure(node, {})
        return _EMPTY

    _e_FunctionExpression = _e_ArrowFunctionExpression

    def _e_ClassExpression(self, node: Node) -> Taint:
        return _EMPTY

    def _e_JSXElement(self, node: Node) -> Taint:
        for child in _walk(node, 20_000):
            if _t(child) == "JSXAttribute" and (child.get("name") or {}).get("name") == "dangerouslySetInnerHTML":
                container = (child.get("value") or {}).get("expression") or {}
                html = None
                if _t(container) == "ObjectExpression":
                    html = next((p.get("value") for p in container.get("properties", []) if _key_name(p) == "__html"), None)
                self._emit("html", "dangerouslySetInnerHTML", _line(child), self.expr(html if html is not None else container))
            elif _t(child) == "JSXExpressionContainer":
                expression = child.get("expression")
                if _t(expression) in {"CallExpression", "ArrowFunctionExpression", "FunctionExpression", "AssignmentExpression"}:
                    self.expr(expression)
        self._jsx_components(node)
        return _EMPTY

    @staticmethod
    def _jsx_callee(name: Any) -> Node | None:
        """JSX etiket adı → çağrı ifadesi (yalnız bileşenler: büyük harfli ad ya da Ns.Ad)."""
        kind = _t(name)
        if kind == "JSXIdentifier":
            value = name.get("name", "")
            return {"type": "Identifier", "name": value} if _COMPONENT_NAME_RE.match(value) else None
        if kind == "JSXMemberExpression":
            obj = name.get("object")
            prop = (name.get("property") or {}).get("name", "")
            inner = {"type": "Identifier", "name": obj.get("name", "")} if _t(obj) == "JSXIdentifier" \
                else JsScope._jsx_callee(obj) if _t(obj) == "JSXMemberExpression" else None
            if inner is None or not prop:
                return None
            return {"type": "MemberExpression", "object": inner, "property": {"type": "Identifier", "name": prop}}
        return None

    def _jsx_components(self, root: Node) -> None:
        """<Bileşen html={x} />: bileşen özetindeki prop hedefleri (§prop) çağrı yerindeki değerlerle eşlenir.
        İç fonksiyonlara inilmez (onların JSX'i kendi kapsamlarında değerlendirilir)."""
        stack: list[Any] = [root]
        visited = 0
        while stack and visited < 5_000:
            node = stack.pop()
            visited += 1
            if _t(node) == "JSXElement":
                self._jsx_component_call(node)
            for child in _children(node):
                if _is_function(child) or _t(child) in {"ObjectMethod", "ClassMethod"}:
                    continue
                stack.append(child)

    def _jsx_component_call(self, element: Node) -> None:
        opening = element.get("openingElement") or {}
        callee = self._jsx_callee(opening.get("name"))
        if callee is None:
            return
        target = self._function_target(callee, False)
        if target is None:
            return
        module, qual, fnode, cls = target
        if not self.p.react_component(qual, fnode):
            return
        local = qual.startswith(f"{self.qual}.<locals>.")
        summary = self.p.summary(module, qual, fnode, cls, dict(self.env) if local else None, dict(self.refs) if local else None)
        prop_sinks = [sink for sink in summary.sinks.values() if sink.index == -2]
        if not prop_sinks:
            return
        props: dict[str, Taint] = {}
        spread: Taint = _EMPTY
        for attr in opening.get("attributes", []):
            if _t(attr) == "JSXSpreadAttribute":
                spread = tf._union(spread, self.expr(attr.get("argument")))
            elif _t(attr) == "JSXAttribute" and _t(attr.get("name")) == "JSXIdentifier":
                value = attr.get("value")
                if _t(value) == "JSXExpressionContainer" and not _is_function(value.get("expression")):
                    props[(attr.get("name") or {}).get("name", "")] = self.expr(value.get("expression"))
        kids = [c.get("expression") for c in element.get("children", []) if _t(c) == "JSXExpressionContainer"]
        if kids and "children" not in props:
            props["children"] = tf._union(*(self.expr(k) for k in kids if not _is_function(k)))
        label = f"<{qual.rsplit('.', 1)[-1]}>"
        for sink in prop_sinks:
            taint = tf._union(props.get(sink.field, _EMPTY), spread)
            for origin in tf._live(taint, sink.kind):
                via = (origin.via + (label,) + sink.via)[-tf.MAX_VIA:]
                if origin.label in {_PARAM, tf._FIELD, _PROP}:
                    if self.summary is not None:
                        index = int(origin.source) if origin.label == _PARAM else (-1 if origin.label == tf._FIELD else -2)
                        field = "" if origin.label == _PARAM else origin.source
                        self.summary.add_sink(tf._ParamSink(index, sink.kind, sink.sink, sink.file, sink.line, via, field))
                    continue
                self.p.add_flow(tf.Flow(
                    "javascript", sink.kind, sink.sink, sink.line, origin.source, origin.label, origin.line,
                    via, sink.file, origin.file,
                ))

    _e_JSXFragment = _e_JSXElement

    def _e_AssignmentExpression(self, node: Node) -> Taint:
        left, right = node.get("left"), node.get("right")
        operator = node.get("operator", "=")
        const_value = _UNKNOWN
        if _t(left) == "Identifier" and left.get("name", "") not in self.unstable:
            if operator == "=":
                const_value = self._const(right)
            elif operator in {"+=", "-=", "*=", "/=", "%="}:
                const_value = self._const({"type": "BinaryExpression", "operator": operator[:-1], "left": left, "right": right})
        taint = self.expr(right)
        chain = self._cchain(left)
        line = _line(node)
        if chain and len(chain) == 2 and _t(left.get("object")) in {"Identifier", "ThisExpression"}:
            setter = self._accessor(chain[0], chain[1], "set")
            if setter is not None:
                self._apply_summary(setter, [taint], {"type": "CallExpression", "callee": left, "arguments": [right]})
        self._check_assignment_sinks(left, chain, taint, line)
        keep_safe = operator == "+=" and _t(left) == "Identifier" and left.get("name", "") in self.url_safe
        keep_abs = keep_safe and left.get("name", "") in self.url_abs
        if keep_safe:
            # u = '/app/'; u += x: önek ana makineyi sabitler, eklenen parça hedefi değiştiremez.
            taint = tf._clean(taint, _URL_TARGET_KINDS | {_URL_ABS_MARK if keep_abs else _URL_REL_MARK})
        if operator in {"+=", "||=", "??=", "&&="}:
            taint = tf._union(self.expr(left), taint)
        elif operator != "=":
            taint = _EMPTY
        prop = (left.get("property") or {}).get("name", "") if _t(left) in {"MemberExpression", "OptionalMemberExpression"} and not left.get("computed") else ""
        if prop in {"innerHTML", "outerHTML"}:
            # document.getElementById('x').innerHTML = ... (nesne bir çağrı da olabilir)
            if chain is None:
                self.expr(left.get("object"))
            self._emit("html", prop, line, taint)
        elif chain:
            last = chain[-1]
            if chain in (["location"], ["window", "location"], ["document", "location"]) or (
                last == "href" and chain[:-1] in (["location"], ["window", "location"], ["document", "location"])
            ):
                self._emit("redirect", ".".join(chain), line, _EMPTY if _fixed_url_target(right) else taint)
            elif chain == ["ctx", "body"] and _has_html_literal(right):
                self._emit("html", "ctx.body", line, taint)
            elif last == "onmessage" and _is_function(right):
                pass
        self.assign(left, taint, right if operator == "=" else None)
        for assigned in _pattern_names(left):
            self.callback_aliases.pop(assigned, None)
            self.local_imports.pop(assigned, None)
            self.immutable_local_imports.discard(assigned)
        if keep_safe:
            self.url_safe.add(left.get("name", ""))
            if keep_abs:
                self.url_abs.add(left.get("name", ""))
        if const_value is not _UNKNOWN:
            self.consts[left.get("name", "")] = const_value
        return taint

    def _jquery_value(self, name: str, args: list[Any], arg_taints: list[Taint], receiver: Taint) -> Taint | None:
        """jQuery öğe kurucuları ve ayarlayıcı zincirleri: dönen değer DOM öğesidir (bkz. _JQ_ELEMENT_METHODS)."""
        if name in {"$", "jQuery"}:
            if args and _html_literal_start(args[0]):
                return tf._clean(tf._union(*arg_taints), _JQ_ELEMENT_CLEAN)
            return None
        last = name.rsplit(".", 1)[-1]
        count = len(args)
        if not _jq_chain(name):
            # el = $('<div/>').text(x); el.text(): öğe tutan değişken üzerinden okuyucu → işaret geri açılır.
            if any(_JQEL in o.cleaned for o in receiver):
                if (last in _JQ_GETTERS_0 and count == 0) or (last in _JQ_GETTERS_1 and count == 1 and _t(args[0]) == "StringLiteral"):
                    return _jq_reopen(receiver)
                if last in _JQ_ELEMENT_METHODS:
                    return tf._clean(tf._union(receiver, *arg_taints), _JQ_ELEMENT_CLEAN)
            return None
        if (last in _JQ_GETTERS_0 and count == 0) or (last in _JQ_GETTERS_1 and count == 1 and _t(args[0]) == "StringLiteral"):
            return _jq_reopen(receiver)
        if last in _JQ_ELEMENT_METHODS:
            return tf._clean(tf._union(receiver, *arg_taints), _JQ_ELEMENT_CLEAN)
        return None

    def _strip_field_only(self, node: Any, taint: Taint) -> Taint:
        """$(form) / $(options.target): kök yalnız başka alanlarına yazımla kirlendiyse o kökenler HTML dizgesi değildir."""
        root = ""
        if _t(node) == "Identifier":
            root = node.get("name", "")
        elif _t(node) in {"MemberExpression", "OptionalMemberExpression"} and not node.get("computed") \
                and _t(node.get("object")) == "Identifier":
            dotted = _dotted(node)
            root = node["object"].get("name", "")
            if dotted and dotted in self.env:
                return taint
        added = self.field_added.get(root)
        if not added:
            return taint
        return tuple(o for o in taint if _okey(o) not in added)

    def _check_assignment_sinks(self, left: Any, chain: list[str] | None, taint: Taint, line: int) -> None:
        """req.session.x = v (güven sınırı) ve obj[k1][k2] = v (prototip kirletme)."""
        session_chain = chain or _chain(left.get("object")) if _t(left) in {"MemberExpression", "OptionalMemberExpression"} else None
        if session_chain and len(session_chain) >= 2 and session_chain[1] == "session" and (
            session_chain[0] in self.roots or session_chain[0] in _CTX_ROOTS
        ):
            self._emit("session", f"{session_chain[0]}.session", line, taint)
        if _t(left) == "MemberExpression" and left.get("computed") and _t(left.get("object")) == "MemberExpression" \
                and left["object"].get("computed"):
            outer_key = left["object"].get("property")
            inner_key = left.get("property")
            if self._const(outer_key) is _UNKNOWN and self._const(inner_key) is _UNKNOWN:
                outer = self.expr(outer_key)
                inner = self.expr(inner_key)
                # obj[k1][k2] = v: k1 '__proto__' ve k2 saldırgan denetimindeyse Object.prototype kirlenir (CWE-1321).
                if any(o.label not in {_PARAM, tf._FIELD} for o in tf._live(inner, "prototype")):
                    self._emit("prototype", _PROTO_ASSIGN, line, outer)
                else:
                    # İç anahtar parametreyse karar çağıranda: hedef adı iç anahtarın parametre indeksini taşır.
                    params = sorted({int(o.source) for o in tf._live(inner, "prototype") if o.label == _PARAM})
                    if params:
                        self._emit("prototype", f"{_PROTO_ASSIGN}#{params[0]}", line,
                                   tuple(o for o in outer if o.label == _PARAM))
        elif self.unsafe_merge and _t(left) == "MemberExpression" and left.get("computed") \
                and _t(left.get("object")) == "Identifier" and self._const(left.get("property")) is _UNKNOWN:
            # deepMerge(target, source): for (k of Object.keys(source)) target[k] = source[k] + özyineleme.
            # Anahtar parametreden geliyorsa karar çağıranda (o parametre saldırgan nesnesi mi?).
            key = tf._live(self.expr(left.get("property")), "prototype")
            if any(o.label not in {_PARAM, tf._FIELD} for o in key):
                self._emit("prototype", _PROTO_ASSIGN, line, key)
            else:
                params = sorted({int(o.source) for o in key if o.label == _PARAM})
                if params:
                    self._emit("prototype", f"{_PROTO_ASSIGN}#{params[0]}", line,
                               tuple(o for o in key if o.label == _PARAM))

    def _e_CallExpression(self, node: Node) -> Taint:
        return self._call(node, is_new=False)

    _e_OptionalCallExpression = _e_CallExpression

    def _e_NewExpression(self, node: Node) -> Taint:
        return self._call(node, is_new=True)

    # -- çağrılar -------------------------------------------------------------------
    def _static_router_array(self, name: str) -> Node | None:
        """Resolve only immutable module-level ``const`` array declarations."""
        value = self.m.values.get(name)
        if name not in self.m.static_values or _t(value) != "ArrayExpression":
            return None
        return value

    def is_router_call(self, node: Node) -> bool:
        callee = node.get("callee")
        if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"} or callee.get("computed"):
            return False
        method = (callee.get("property") or {}).get("name", "")
        if method not in _ROUTER_METHODS or method == "route":
            return False
        owner = callee.get("object")
        owner_name = _dotted(owner)
        if _t(owner) == "CallExpression" and _callee_name(owner.get("callee")).endswith(".route"):
            return True
        last = owner_name.rsplit(".", 1)[-1] if owner_name else ""
        if not (last in _ROUTER_OBJECTS or last.lower().endswith(("router", "app"))
                or (_t(owner) == "Identifier" and last in self.p.router_names(self.m))):
            return False
        args = list(_router_arguments(node.get("arguments") or [], self._static_router_array))
        return any(
            _is_function(a) or _t(a) in {"Identifier", "MemberExpression"}
            or (method == "use" and _t(a) == "CallExpression" and _dotted(a.get("callee")) == "require")
            for a in args[1:] or args
        )

    def resolve_ref(self, node: Any) -> Ref | None:
        kind = _t(node)
        if kind == "AwaitExpression":
            return self.resolve_ref(node.get("argument"))
        if kind == "CallExpression" and _t(node.get("callee")) == "Import":
            args = node.get("arguments") or []
            spec = _string_value(args[0]) if args else None
            target = self.p.module_for(self.m, spec) if spec else None
            return ("module", target, "") if target is not None else None
        if kind == "CallExpression" and _dotted(node.get("callee")) == "require":
            source = self.m._require_source(node)
            target = self.p.module_for(self.m, source[0]) if source else None
            if target is None:
                return None
            return self.p.export(target, source[1]) or ("module", target, "")
        if kind in {"TSAsExpression", "TSTypeAssertion", "TSSatisfiesExpression"}:
            # (x as Repo).m() / <Repo>x: TS dönüşümünün türü proje sınıfıysa örnek başvurusu.
            return self.p.type_ref(self.m, node.get("tn")) or self.resolve_ref(node.get("expression"))
        if kind in {"ParenthesizedExpression", "TSNonNullExpression"}:
            return self.resolve_ref(node.get("expression"))
        if kind == "Identifier":
            name = node.get("name", "")
            if name in self.refs:
                return self.refs[name]
            if name in self.local_funcs:
                return ("func", self.m, f"{self.qual}.<locals>.{name}")
            if name in self.env and self.env[name]:
                return None
            return self.p.lookup(self.m, name)
        if kind in {"MemberExpression", "OptionalMemberExpression"} and not node.get("computed"):
            prop = (node.get("property") or {}).get("name", "")
            owner = node.get("object")
            if _t(owner) == "ThisExpression" and self.class_name:
                found = self.p.method(self.m, self.class_name, prop)
                if found:
                    return ("func", found[0], found[1])
                # this.repo: yapıcıda/TS açıklamasında türü bilinen alan.
                return self.p.field_types(self.m, self.class_name).get(prop)
            if _t(owner) == "NewExpression":
                cls = self.resolve_ref(owner.get("callee"))
                return self.p.member(("instance", cls[1], cls[2]), prop) if cls and cls[0] == "class" else None
            if _t(owner) in {"CallExpression", "AwaitExpression"}:
                inner = owner.get("argument") if _t(owner) == "AwaitExpression" else owner
                base = self.call_refs.get(id(inner))
            else:
                base = self.resolve_ref(owner)
            if base is None or not prop:
                return None
            found_ref = self.p.member(base, prop)
            if found_ref is None and base[0] == "instance":
                return self.p.field_types(base[1], base[2]).get(prop)
            return found_ref
        return None

    def _function_target(self, callee: Any, is_new: bool) -> tuple[JsModule, str, Node, str | None] | None:
        ref = self.resolve_ref(callee)
        if ref is None:
            return None
        kind, module, qual = ref
        if kind == "class" and is_new:
            found = self.p.method(module, qual, "constructor")
            if found is None:
                return None
            module, qual = found
        elif kind != "func":
            return None
        if qual.startswith(f"{self.qual}.<locals>."):
            node = self.local_funcs.get(qual.rsplit(".", 1)[-1])
        else:
            node = module.functions.get(qual)
        if node is None:
            return None
        head = qual.split(".")[0]
        cls = head if head in module.classes or head in module.ctor_functions else None
        return module, qual, node, cls

    def _secondary_store_handle(self, name: str) -> bool:
        """Recognize a package-backed store handle captured by a helper function.

        Function summaries start with parameter/capture taint rather than replaying
        top-level variable declarations.  A module-level ``redis.createClient()``
        handle therefore needs a bounded lookup in the indexed initializer.  A
        local binding always wins, which keeps lookalike objects and rebinding
        negative controls clean.
        """
        if self.ctors.get(name) == "secondary_store":
            return True
        if not name or name in self.env:
            return False
        value = self.m.values.get(name)
        while _t(value) in {"AwaitExpression", "TSAsExpression", "TSNonNullExpression",
                            "ParenthesizedExpression", "TSSatisfiesExpression", "TSTypeAssertion"}:
            value = value.get("argument") or value.get("expression")
        if _t(value) not in {"CallExpression", "NewExpression"}:
            return False
        return self._secondary_store_factory(value)

    def _secondary_store_factory(self, value: Any) -> bool:
        """Only recognize documented client/channel factories from supported packages."""
        kind = _t(value)
        if kind not in {"CallExpression", "NewExpression"}:
            return False
        callee_name = _callee_name(value.get("callee"))
        imported_root = callee_name.split(".", 1)[0]
        imported = self.m.imports.get(imported_root)
        if not imported or imported[0].startswith(".") \
                or _package_root(imported[0]) not in _SECONDARY_STORE_PACKAGES:
            return False
        canonical = self.canonical(callee_name)
        factories = _SECONDARY_STORE_NEW_FACTORIES if kind == "NewExpression" \
            else _SECONDARY_STORE_CALL_FACTORIES
        return canonical in factories

    @staticmethod
    def _promise_settlement(callee: Any) -> str | None:
        """Return the statically certain state of ``Promise.resolve/reject``."""
        if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"}:
            return None
        owner = callee.get("object")
        while _t(owner) in {"ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression",
                            "TSSatisfiesExpression", "TSTypeAssertion"}:
            owner = owner.get("expression")
        if _t(owner) not in {"CallExpression", "OptionalCallExpression"}:
            return None
        name = _callee_name(owner.get("callee"))
        return {"Promise.resolve": "resolved", "Promise.reject": "rejected"}.get(name)

    def _callback_seed(
        self,
        callee_name: str,
        receiver: Taint,
        args: list[Node],
        index: int,
        callee: Any = None,
    ) -> dict[int, Taint]:
        method = callee_name.rsplit(".", 1)[-1]
        owner = callee_name.rsplit(".", 1)[0] if "." in callee_name else ""
        scheduler_start = self._scheduler_callback_start(callee_name, callee)
        if index == 0 and scheduler_start is not None:
            return {
                position: self.expr(argument)
                for position, argument in enumerate(args[scheduler_start:])
            }
        if method == "finally":
            # Promise.prototype.finally invokes its callback without the
            # fulfillment value or rejection reason.
            return {}
        if method in {"then", "catch"}:
            state = self._promise_settlement(callee)
            if method == "then":
                if index == 0 and state != "rejected" and receiver:
                    return {0: receiver}
                if index == 1 and state != "resolved" and receiver:
                    return {0: receiver}
                return {}
            if index == 0 and state != "resolved" and receiver:
                return {0: receiver}
            return {}
        if method in _ITERATION_METHODS and receiver:
            return {0: receiver}
        if method == "reduce" and receiver:
            return {1: receiver}
        first = _string_value(args[0]) if args else None
        if method in {"on", "once", "addListener", "prependListener", "prependOnceListener"} \
                and owner.rsplit(".", 1)[-1] in self.roots and first == "data":
            return {0: self._source(f"{owner}.on('data')", _line(args[0]))}
        owner_parts = owner.split(".")
        if method == "subscribe" and len(owner_parts) >= 2 and owner_parts[-1] in _ANGULAR_ROUTE_MEMBERS \
                and "route" in owner_parts[-2].lower():
            # this.route.queryParams.subscribe(params => …): params adres çubuğundan gelir.
            return {0: self._source(".".join(owner_parts[-2:]), _line(args[0]) if args else 0)}
        if method == "subscribe" and receiver:
            # this.http.get(…).subscribe(data => …) / servis gözlemlenebiliri: değer alıcıdan gelir.
            return {0: receiver}
        root = owner_parts[0] if owner_parts else ""
        if method in _SECONDARY_STORE_READS and self._secondary_store_handle(root) \
                and index == len(args) - 1:
            callback_params = args[index].get("params") or []
            # Legacy Redis/memcached callbacks are (error, storedValue).  A
            # single callback parameter represents the error, so do not invent
            # payload provenance for that ambiguous form.
            if len(callback_params) >= 2:
                return {1: (tf._Origin(
                    "stored", f"{owner}.{method}() callback payload", _line(args[index]), (),
                    frozenset(), self.m.relpath,
                ),)}
        if method in {"consume", "process"} and self._secondary_store_handle(root):
            return {0: (tf._Origin("stored", f"{owner}.{method}() payload", _line(args[index]), (),
                                   frozenset(), self.m.relpath),)}
        if method == "addEventListener" and first == "message" and index == 1:
            return {0: self._source("message.data", _line(args[0]))}
        return {}

    def _callback_reference(
        self,
        callback: Any,
        *,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
    ) -> tuple[Node, list[Node]] | None:
        """Resolve a bounded immutable callback alias and its bound arguments."""
        if depth > 12 or not isinstance(callback, dict):
            return None
        kind = _t(callback)
        if kind in {"ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression",
                    "TSSatisfiesExpression", "TSTypeAssertion", "TypeCastExpression"}:
            return self._callback_reference(
                callback.get("expression"), depth=depth + 1, seen=seen,
            )
        if kind == "Identifier":
            name = callback.get("name", "")
            alias = self.callback_aliases.get(name)
            if alias is not None and name not in seen and name not in self.local_funcs:
                return self._callback_reference(
                    alias, depth=depth + 1, seen=seen | frozenset({name}),
                )
            return callback, []
        if kind in {"MemberExpression", "OptionalMemberExpression"}:
            return callback, []
        if kind not in {"CallExpression", "OptionalCallExpression"}:
            return None
        binder = callback.get("callee")
        if _t(binder) not in {"MemberExpression", "OptionalMemberExpression"} \
                or binder.get("computed") \
                or (binder.get("property") or {}).get("name") != "bind":
            return None
        resolved = self._callback_reference(
            binder.get("object"), depth=depth + 1, seen=seen,
        )
        if resolved is None:
            return None
        target, earlier = resolved
        bound = [item for item in (callback.get("arguments") or [])[1:]
                 if isinstance(item, dict)]
        return target, [*earlier, *bound]

    def _scheduler_callback_start(self, callee_name: str, callee: Any = None) -> int | None:
        """Return the first runtime callback argument for a genuine global scheduler."""
        starts = {
            "setTimeout": 2,
            "setInterval": 2,
            "setImmediate": 1,
            "queueMicrotask": 1,
            "process.nextTick": 1,
        }
        resolved = self._callback_reference(callee) if callee is not None else None
        if resolved is not None and not resolved[1]:
            callee_name = _callee_name(resolved[0])
        canonical = self.canonical(callee_name)
        imported_starts = {
            "timers.setTimeout": 2,
            "timers.setInterval": 2,
            "timers.setImmediate": 1,
        }
        imported_root = callee_name.split(".", 1)[0]
        immutable_import = imported_root in self.m.immutable_imports \
            or imported_root in self.m.static_values \
            or imported_root in self.immutable_local_imports
        if canonical in imported_starts and immutable_import:
            return imported_starts[canonical]
        start = starts.get(callee_name)
        if start is None:
            return None
        root = callee_name.split(".", 1)[0]
        # A project declaration/import/value with the same spelling shadows the
        # platform scheduler contract and must keep ordinary call semantics.
        if root in self.env or root in self.local_funcs or root in self.m.functions \
                or root in self.m.imports or root in self.m.values:
            return None
        return start

    def _invoke_callback_reference(
        self,
        call: Node,
        callback: Node,
        runtime_nodes: list[Node],
        runtime_taints: list[Taint],
    ) -> None:
        """Invoke a scheduler callback reference with bound then runtime arguments."""
        resolved = self._callback_reference(callback)
        if resolved is None:
            return
        target_node, bound_nodes = resolved
        callback_taints = [*(self.expr(item) for item in bound_nodes), *runtime_taints]
        callback_args = [*bound_nodes, *runtime_nodes]
        callback_target = self._function_target(target_node, False)
        if callback_target is not None:
            self._apply_summary(callback_target, callback_taints)
            return
        callback_name = _callee_name(target_node)
        callback_canonical = self.canonical(callback_name)
        self._check_sinks(call, callback_canonical, callback_args, callback_taints, _EMPTY, False)
        self._check_js_sinks(
            call, callback_name, callback_canonical, target_node, callback_args, callback_taints,
        )

    def _closure(self, node: Node, seeds: dict[int, Taint], *, handler: bool = False) -> Taint:
        """Satır içi fonksiyon: dış ortamı yakalayarak çözümle; dönüş taint'ini ver.

        ``handler`` ise (router çağrısındaki işleyici) ilk parametre istek nesnesidir."""
        env = dict(self.env)
        roots = set(self.roots)
        handler = handler or id(node) in self.p.handlers
        entry = self.p.entry_params.get(id(node), {})
        entry_roots = self.p.entry_roots.get(id(node), set())
        for index, param in enumerate(node.get("params") or []):
            if index in entry:
                for name in _pattern_names(param):
                    env[name] = self._source(entry[index], _line(param))
                continue
            if index in entry_roots and _t(param) == "Identifier":
                roots.add(param.get("name", ""))
                env.pop(param.get("name", ""), None)
                continue
            if _t(param) == "Identifier" and self.p.request_typed(self.m, param.get("tn")):
                roots.add(param.get("name", ""))
                env.pop(param.get("name", ""), None)
                continue
            if handler and index == 0:
                if _t(param) == "Identifier":
                    roots.add(param.get("name", ""))
                    env.pop(param.get("name", ""), None)
                    continue
                if _t(param) == "ObjectPattern":
                    for prop in param.get("properties", []):
                        key = _key_name(prop) if _t(prop) == "ObjectProperty" else ""
                        for name in _pattern_names(prop.get("value") if key else prop):
                            env[name] = self._source(f"{{{key}}}", _line(param)) if key in _REQUEST_MEMBERS else _EMPTY
                    continue
            for name in _pattern_names(param):
                env[name] = tf._via(seeds[index], name) if seeds.get(index) else _EMPTY
        middleware_paths = set(self.middleware_paths)
        middleware_paths.update(self.p.handler_middleware_paths.get(id(node), set()))
        inner = JsScope(
            self.p, self.m, env, summary=self.summary, class_name=self.class_name, qual=self.qual,
            middleware_paths=middleware_paths,
        )
        inner.closure = True
        inner.roots = roots
        shadowed = {name for param in (node.get("params") or []) for name in _pattern_names(param)}
        inner.prop_roots = set(self.prop_roots) - shadowed
        inner.refs = dict(self.refs)
        inner.local_funcs = dict(self.local_funcs)
        inner.local_imports = dict(self.local_imports)
        inner.immutable_local_imports = set(self.immutable_local_imports) - shadowed
        inner.callback_aliases = {
            name: value for name, value in self.callback_aliases.items()
            if name not in shadowed
        }
        inner.request_objects = {name for name in self.request_objects if name not in env or env[name]}
        inner.consts = {k: v for k, v in self.consts.items() if k not in env or not env[k]}
        inner.exact = set(self.exact)
        inner.lists = {k: list(v) for k, v in self.lists.items()}
        inner.derived = dict(self.derived)
        inner.ctors = dict(self.ctors)
        inner.url_safe = set(self.url_safe)
        inner.url_abs = set(self.url_abs)
        inner.kinds = dict(self.kinds)
        inner.loop_depth = self.loop_depth
        inner.responses = set(self.responses)
        inner.string_vars = {name for name in self.string_vars if name not in env or env[name]}
        inner.non_html = set(self.non_html)
        for param in node.get("params") or []:
            for name in _pattern_names(param):
                inner.string_vars.discard(name)
        for param in node.get("params") or []:
            if _t(param) == "Identifier" and self.p.response_typed(self.m, param.get("tn")):
                inner.responses.add(param.get("name", ""))
        for param in node.get("params") or []:
            hinted = self.p.type_kind((param.get("parameter") if _t(param) == "TSParameterProperty" else param).get("tn"))
            for name in _pattern_names(param):
                inner.kinds[name] = hinted
        for param in node.get("params") or []:
            for name in _pattern_names(param):
                inner.consts.pop(name, None)
                inner.lists.pop(name, None)
                inner.exact.discard(name)
            typed = self.p.type_ref(self.m, (param.get("parameter") if _t(param) == "TSParameterProperty" else param).get("tn"))
            if typed is not None:
                for name in _pattern_names(param):
                    inner.refs[name] = typed
        inner.run_function_body(node)
        if not handler:
            self._write_back(inner, node)
        return tf._union(*inner.returns)

    def _write_back(self, inner: "JsScope", node: Node) -> None:
        """Geri çağrının dış kaplara/değişkenlere yazdıkları (forEach içinde out.push(x), o[k] = v).

        Geri çağrı sıfır ya da daha çok kez çalışabilir: dış değer eskisiyle birleştirilir; öğe/alan
        kesinliği bozulur. Geri çağrının kendi parametreleri ve yerel bildirimleri dışarı taşmaz."""
        local = {name for param in node.get("params") or [] for name in _pattern_names(param)}
        local |= _declared_locals(node.get("body"))
        for key, value in inner.env.items():
            root = key.split(".", 1)[0]
            if root in local or not value or root in self.roots:
                continue
            old = self.env.get(key, _EMPTY)
            if value != old:
                self.env[key] = tf._union(old, value)
                self.consts.pop(root, None)
        for name, items in inner.lists.items():
            if name.split(".", 1)[0] not in local and name in self.lists and items != self.lists[name]:
                del self.lists[name]
                self.env[name] = tf._union(self.env.get(name, _EMPTY), *items)
        for name in list(self.lists):
            if name not in inner.lists and name.split(".", 1)[0] not in local:
                del self.lists[name]
        for name in self.exact - inner.exact:
            if name.split(".", 1)[0] not in local:
                self.exact.discard(name)

    def _call(self, node: Node, *, is_new: bool) -> Taint:
        callee = node.get("callee")
        args = [a for a in node.get("arguments", []) if isinstance(a, dict)]
        name = _callee_name(callee)
        if self.responses and name.split(".", 1)[0] in self.responses and "." in name:
            name = "res." + name.split(".", 1)[1]
        if is_new and name in {"URL", "url.URL"} and len(args) == 2 and self._own_request_url(args[1]):
            first = _string_value(args[0])
            first = first if first is not None else _url_prefix_literal(args[0])
            if isinstance(first, str) and first[:1] in {"/", "?", "#"} and first[1:2] not in {"/", "\\"}:
                # new URL('/login?from=' + x, req.url): göreli yol isteğin kendi adresine çözülür → ana makine
                # saldırganca seçilemez (yönlendirme/SSRF hedefi temiz; değer diğer türler için kirli kalır).
                return tf._clean(tf._union(self.expr(args[0]), self.expr(args[1])), _URL_TARGET_KINDS)
        receiver: Taint = _EMPTY
        if _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
            receiver = self.expr(callee.get("object"))
        elif _t(callee) not in {"Identifier"}:
            receiver = self.expr(callee)
        if (_t(callee) == "MemberExpression" and _t(callee.get("object")) == "Identifier"
                and callee["object"].get("name") in self.roots and name.rsplit(".", 1)[-1] in {"get", "header", "param"}
                and len(args) == 1 and re.fullmatch(r"[A-Za-z][\w-]{0,63}", _string_value(args[0]) or "")
                and not ("hono" in self.p.package_roots() and name.rsplit(".", 1)[-1] == "get")):
            # Express req.get('Referer') / req.header(...) / req.param(...): istek başlığı/parametresi.
            for arg in args:
                self.expr(arg)
            member = "params" if name.endswith(".param") else "headers"
            taint = self._source(f"{callee['object'].get('name')}.{member}", _line(node))
            if (_string_value(args[0]) or "").lower() in {"referer", "referrer"}:
                # Geldiği sayfaya geri yönlendirme (res.redirect(req.get('Referer'))): kullanıcı zaten oradan
                # geldi; açık yönlendirme sayılmaz (başlık HTML/SQL vb. için kirli kalır).
                taint = tf._clean(taint, frozenset({"redirect"}))
            return taint
        owner_chain = (_chain(callee.get("object")) or []) if _t(callee) == "MemberExpression" else []
        if (len(owner_chain) == 2 and owner_chain[0] in self.roots and owner_chain[1] == "request"
                and name.rsplit(".", 1)[-1] in {"get", "header"} and len(args) == 1
                and re.fullmatch(r"[A-Za-z][\w-]{0,63}", _string_value(args[0]) or "")):
            # Koa: ctx.request.get('Header') / ctx.request.header('Header').
            self.expr(args[0])
            taint = self._source(f"{owner_chain[0]}.request.headers", _line(node))
            if (_string_value(args[0]) or "").lower() in {"referer", "referrer"}:
                taint = tf._clean(taint, frozenset({"redirect"}))
            return taint
        if (_t(callee) == "MemberExpression" and _t(callee.get("object")) == "Identifier"
                and callee["object"].get("name") in self.roots
                and name.rsplit(".", 1)[-1] in {"accepts", "acceptsCharsets", "acceptsEncodings", "acceptsLanguages", "range"}):
            for arg in args:
                self.expr(arg)
            return self._source(f"{callee['object'].get('name')}.{name.rsplit('.', 1)[-1]}", _line(node))
        if (_t(callee) == "MemberExpression" and self._request_receiver(callee.get("object")) is not None and not args
                and name.rsplit(".", 1)[-1] in {"json", "text", "formData", "arrayBuffer", "blob", "bytes"}):
            # Fetch API / Next.js isteği: await request.json() gövdeyi döndürür.
            return self._source(f"{callee['object'].get('name')}.body", _line(node))
        if _t(callee) == "Identifier" and name in _URL_STATE_HOOKS and name not in self.env:
            imported = self.m.imports.get(name)
            if imported is not None and _package_root(imported[0]) in _URL_HOOK_PACKAGES:
                # React Router / Next.js / Remix: useSearchParams() / useParams() / useLocation() / useRouter().query
                # adres çubuğundan gelir (DOM tabanlı kaynak).
                for arg in args:
                    self.expr(arg)
                return self._browser_source(f"{name}()", _line(node))
        if _t(callee) in {"MemberExpression", "OptionalMemberExpression"} and "hono" in self.p.package_roots():
            owner = _chain(callee.get("object")) or []
            method = name.rsplit(".", 1)[-1]
            if len(owner) == 2 and owner[0] in self.roots and owner[1] == "req" and method in _HONO_REQ_METHODS:
                # Hono: c.req.query('q') / c.req.param('id') / await c.req.json() / c.req.valid('json').
                for arg in args:
                    self.expr(arg)
                return self._source(f"{owner[0]}.req.{method}", _line(node))
        if self.is_router_call(node):
            for arg in _router_arguments(args, self._static_router_array):
                if _is_function(arg):
                    self.p.handlers.add(id(arg))
                    self._closure(arg, {}, handler=True)
                else:
                    self.expr(arg)
            return _EMPTY
        arg_taints: list[Taint] = []
        callback_returns: list[Taint] = []
        for index, arg in enumerate(args):
            if _is_function(arg):
                callback_returns.append(self._closure(
                    arg, self._callback_seed(name, receiver, args, index, callee),
                ))
                arg_taints.append(_EMPTY)
            else:
                arg_taints.append(self.expr(arg))
        target = self._function_target(callee, is_new)
        if target is None and self.summary is not None and _t(callee) == "Identifier" and name in self.summary.params:
            # A project helper may invoke a callback parameter with values
            # derived from its other parameters.  Store the symbolic callback
            # arguments in the helper summary; the caller maps and executes
            # its actual closure below.
            callback_index = self.summary.params.index(name)
            calls = getattr(self.summary, "js_callback_calls", None)
            if calls is None:
                calls = {}
                setattr(self.summary, "js_callback_calls", calls)
            invocations = calls.setdefault(callback_index, [])
            current = tuple(arg_taints)
            if len(invocations) < 8:
                invocations.append(current)
            else:
                # İlk yedi çağrıyı kesin tut, sekizinci yuvada kalan tüm
                # çağrıları argüman konumuna göre birleştir. Böylece geç gelen
                # kirli çağrı kaybolmaz ve büyük yardımcılar özeti büyütemez.
                previous = invocations[7]
                width = max(len(previous), len(current))
                invocations[7] = tuple(
                    tf._union(*(item[index] for item in (previous, current) if index < len(item)))
                    for index in range(width)
                )
        last = name.rsplit(".", 1)[-1] if name else ""
        canonical = self.canonical(name)
        root = name.split(".", 1)[0] if name else ""
        if last in {"on", "once", "addListener", "prependListener", "prependOnceListener"} and len(args) >= 2 \
                and not _is_function(args[1]):
            # Node request streams invoke a referenced listener with the
            # incoming body chunk.  Reuse the same exact request/data guard as
            # inline callbacks, while preserving arguments supplied by bind().
            seeds = self._callback_seed(name, receiver, args, 1, callee)
            if seeds:
                width = max(seeds) + 1
                self._invoke_callback_reference(
                    node,
                    args[1],
                    [args[1]] * width,
                    [seeds.get(index, _EMPTY) for index in range(width)],
                )
        if last in {"then", "catch"} and receiver:
            # Promise callbacks may be project helpers, imported members, or a
            # bound form such as ``cp.exec.bind(null)``.  Apply only the value
            # argument the ECMAScript callback actually receives.  Bound
            # arguments precede that value; ``thisArg`` is not an argument.
            for index, callback in enumerate(args[:2] if last == "then" else args[:1]):
                seed = self._callback_seed(name, receiver, args, index, callee).get(0, _EMPTY)
                if not seed or _is_function(callback):
                    continue
                resolved = self._callback_reference(callback)
                if resolved is None:
                    continue
                target_node, bound_nodes = resolved
                bound_taints = [self.expr(item) for item in bound_nodes]
                callback_taints = [*bound_taints, seed]
                callback_args = [*bound_nodes, callback]
                callback_target = self._function_target(target_node, False)
                if callback_target is not None:
                    self._apply_summary(callback_target, callback_taints)
                    continue
                callback_name = _callee_name(target_node)
                callback_canonical = self.canonical(callback_name)
                self._check_sinks(
                    node, callback_canonical, callback_args, callback_taints, _EMPTY, False,
                )
                self._check_js_sinks(
                    node, callback_name, callback_canonical, target_node,
                    callback_args, callback_taints,
                )
        scheduler_start = self._scheduler_callback_start(name, callee)
        if scheduler_start is not None and args and not _is_function(args[0]):
            self._invoke_callback_reference(
                node,
                args[0],
                [item for item in args[scheduler_start:] if isinstance(item, dict)],
                arg_taints[scheduler_start:],
            )
        dompurify_sanitize = last == "sanitize" and (
            canonical in {"dompurify.sanitize", "dompurify.default.sanitize", "DOMPurify.sanitize"}
            or self.ctors.get(root) == "dompurify"
        )
        if target is not None:
            # asJson(res): yardımcı işlev yanıtın içerik türünü atıyorsa çağıranda da geçerli (W2-XSS).
            for index, verdict in _content_type_params(target[2], self.p._content_type_params).items():
                if index < len(args) and _t(args[index]) == "Identifier":
                    (self.non_html.add if verdict else self.non_html.discard)(args[index].get("name", ""))
        if target is None:
            self._check_sinks(node, name, args, arg_taints, receiver, is_new)
            self._check_js_sinks(node, name, canonical, callee, args, arg_taints)
            self._check_framework_sinks(node, name, callee, args, arg_taints)
            if name in _RENDER_CALLS and len(args) >= 2:
                self._check_render(node, name, args, arg_taints)
        all_args = tf._union(*arg_taints)
        if _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
            root = (_chain(callee.get("object")) or [""])[0]
            if root in self.consts and isinstance(self.consts[root], (list, dict)) and last in _JS_MUTATORS | {"pop", "shift", "reverse", "sort", "delete", "clear"}:
                self.consts.pop(root, None)
        if target is None and name:
            element = self._jquery_value(name, args, arg_taints, receiver)
            if element is not None:
                return element
        if target is None and last in _SECONDARY_STORE_READS and _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
            root = (_chain(callee.get("object")) or [""])[0]
            if self._secondary_store_handle(root):
                return (tf._Origin("stored", f"{name}()", _line(node), (), frozenset(), self.m.relpath),)
        if name in _FULL_SANITIZERS:
            return _weak(all_args)
        if last in _CLEAN_MEMBERS:
            return _EMPTY
        if target is None and (name in _XPATH_QUERY_FUNCS or canonical in _XPATH_QUERY_FUNCS):
            return tf._union(receiver, *callback_returns)
        if target is None and name in _DECODERS:
            return _reopen(tf._union(receiver, all_args), _DECODE_REOPEN_KINDS)
        if target is None:
            contained = self._container_call(callee, name, last, args, arg_taints, receiver)
            if contained is not None:
                return contained
        if last in {"ObjectId", "ObjectID"} or canonical in _NOSQL_SANITIZERS or name in _NOSQL_SANITIZERS:
            # ObjectId(x) geçersiz girdide hata verir; mongo-sanitize '$' anahtarlarını atar.
            return _EMPTY if last in {"ObjectId", "ObjectID"} else tf._clean(tf._union(receiver, all_args), frozenset({"nosql"}))
        if target is None and last in {"replace", "replaceAll"} and len(args) >= 2 and _quote_pattern(args[0]):
            replacement = _string_value(args[1])
            if replacement is not None and not set(replacement) & _QUOTE_CHARS:
                # Tırnak karakterini kaldıran değiştirme: değer tırnaklı XPath değişmezinden taşamaz.
                return tf._clean(tf._union(receiver, *arg_taints[2:]), frozenset({"xpath", "nosql"}))
        model_kinds = self.p.models.sanitizer_kinds(name) if name else None
        if model_kinds is None and canonical != name:
            model_kinds = self.p.models.sanitizer_kinds(canonical)
        if model_kinds is None and dompurify_sanitize:
            # The rule model uses the browser-global spelling.  Canonicalized
            # ESM/CJS aliases and instances returned by createDOMPurify are the
            # same API and must share the version policy.
            model_kinds = self.p.models.sanitizer_kinds("DOMPurify.sanitize")
        if model_kinds is None and last and name.count(".") == 1:
            model_kinds = self.p.models.sanitizer_kinds(last) if last in {"basename", "escape", "sanitize"} else None
        if model_kinds is not None:
            sanitizer_name = canonical or name
            if (dompurify_sanitize or sanitizer_name in {"DOMPurify.sanitize", "dompurify.sanitize", "purify.sanitize"}) \
                    and self.p.sanitizer_version(self.m, "dompurify") is False:
                return tf._union(receiver, all_args)
            if model_kinds >= taint_models.KNOWN_KINDS:
                return _EMPTY  # boolean/sayı/void döndüren API: değer taşımaz
            return tf._clean(tf._union(receiver, all_args), model_kinds)
        named = tf._named_sanitizer_kinds(name) if name else None
        if named is not None and named >= tf._ALL_KINDS:
            named = _JS_ALL
        if target is not None:
            result = self._apply_summary(target, arg_taints, node)
            return tf._clean(result, named) if named is not None else result
        if named is not None:
            return tf._clean(tf._union(receiver, all_args), named)
        if last in _PREDICATE_METHODS and callback_returns:
            return receiver
        if last in _ITERATION_METHODS or last == "reduce":
            return tf._union(receiver, *callback_returns)
        if target is None and _t(callee) in {"MemberExpression", "OptionalMemberExpression"} and last in _HTTP_CLIENT_METHODS:
            owner_chain = _chain(callee.get("object")) or []
            if len(owner_chain) == 2 and owner_chain[0] == "this" and owner_chain[1].lower() in _HTTP_CLIENT_FIELDS:
                stored = (tf._Origin("stored", f"HttpClient.{last}()", _line(node), (), frozenset(), self.m.relpath),)
                return tf._union(stored, *callback_returns)
        if name == "Math.random":
            # Kriptografik olmayan rastgele değer: oturum/çereze yazılırsa bulgu (bkz. project_analyzer).
            return (tf._Origin(_WEAK, "Math.random()", _line(node), (), frozenset(), self.m.relpath),)
        if name in {"require", "Symbol", "Date.now", "crypto.randomUUID"}:
            return _EMPTY
        if target is None:
            label = self._model_source(name, canonical)
            if label is not None:
                origin = (tf._Origin(label, f"{name}()", _line(node), (), frozenset(), self.m.relpath),)
                return tf._union(origin, *callback_returns)
        if target is None and any(m.kind == "ssrf" for m in self._models_for(name, canonical, is_new)):
            # Ağ isteğinin yanıtı istek URL'sinin taint'ini taşımaz (yanıt sunucudan gelir); yanıt üçüncü
            # taraf verisidir: ayrı, düşük öncelikli "ikinci derece" kaynak.
            response = (tf._Origin(_SECOND_ORDER, f"{name}() yanıtı", _line(node), (), frozenset(), self.m.relpath),)
            return tf._union(response, *callback_returns)
        if target is None and last in _JS_MUTATORS and _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
            self._mutate(callee.get("object"), last, args, arg_taints)
        if target is None and last in _INDEX_ARG_METHODS and _t(callee) in {"MemberExpression", "OptionalMemberExpression"} \
                and all(_t(a) not in {"StringLiteral", "TemplateLiteral"} for a in args):
            # Konum argümanlı yöntemler (dizi/dize slice, substring, at, charAt): sonuç alıcının öğeleridir;
            # sınır/indis argümanının taint'i değere karışmaz (users.slice(req.query.from) → sabit adlar).
            return receiver if last in {"slice", "at"} else tf._clean(receiver, frozenset({"nosql"}))
        if name == "String" or (last in _STRING_METHODS and _t(callee) in {"MemberExpression", "OptionalMemberExpression"}):
            return tf._clean(tf._union(receiver, all_args, *callback_returns), frozenset({"nosql"}))
        if last in _ORM_READ_METHODS or (last in _SQL_METHODS and "." in name and name.split(".")[-2] not in {"document", "URLSearchParams", "window", "$", "jQuery"}):
            stored = (tf._Origin("stored", f"{name}()", _line(node), (), frozenset(), self.m.relpath),)
            if last in _ORM_READ_METHODS or last in _DB_RESULT_METHODS:
                # Sorgu sonucu veritabanındaki satırlardır; sorgu argümanlarının (istek) taint'ini taşımaz.
                # Argüman sink'te ayrıca denetlendi (SQL/NoSQL). Sorgu kurucuları (raw/whereRaw…) argümanı taşır.
                return tf._union(stored, receiver, *callback_returns)
            return tf._union(stored, receiver, all_args, *callback_returns)
        if last in _XML_PARSE_METHODS or canonical in _XML_PARSE_FUNCS:
            # XML'den ayrıştırılan değerler dize/dize ağacıdır: XML adlarında '$' olamaz, Mongo işleci taşıyamaz.
            return tf._clean(tf._union(receiver, all_args, *callback_returns), frozenset({"nosql"}))
        return tf._union(receiver, all_args, *callback_returns)

    def canonical(self, name: str) -> str:
        """İçe aktarma takma adını paket adına çevir: ``cp.exec`` → ``child_process.exec``."""
        if not name or "()" in name:
            return name
        root, _, rest = name.partition(".")
        imported = self.local_imports.get(root) or self.m.imports.get(root)
        if imported is None or imported[0].startswith(".") or root in self.env and self.env[root]:
            return name
        package = imported[0].removeprefix("node:").replace("/", ".")
        if imported[1] in {"*", "default"}:
            base = package
            if imported[1] == "*" and rest.startswith("default."):
                rest = rest[len("default."):]  # 18. tur: import * as m → m.default.f (ESM/CJS birlikte çalışma) = m.f
        else:
            base = f"{package}.{imported[1]}"
        return f"{base}.{rest}" if rest else base

    def _model_source(self, name: str, canonical: str) -> str | None:
        """Kullanıcı/hazır modeldeki kaynak çağrısı (``sources``): etiket ya da None."""
        source_for = getattr(self.p.models, "source_for", None)
        if source_for is None or not name:
            return None
        return source_for(name) or (source_for(canonical) if canonical != name else None)

    def _models_for(self, name: str, canonical: str, is_new: bool) -> list[taint_models.SinkModel]:
        models = self.p.models.sinks_for(name)
        if not models and canonical != name:
            models = self.p.models.sinks_for(canonical)
        if not models and is_new:
            models = self.p.models.sinks_for(f"new {name}") or self.p.models.sinks_for(f"new {canonical}")
        return models

    def _container_call(self, callee: Any, name: str, last: str, args: list[Node], arg_taints: list[Taint],
                        receiver: Taint) -> Taint | None:
        """Öğeleri izlenen dizi (push/pop/shift/unshift/at) ve alanları tam bilinen nesne/Map (get/set/delete)."""
        if name == "Object.assign" and args:
            target = _dotted(args[0])
            if target and "()" not in target:
                for source, taint in zip(args[1:], arg_taints[1:]):
                    shape = self.shapes.get(id(source))
                    if target in self.exact and isinstance(shape, dict):
                        for key, value in shape.items():
                            self.env[f"{target}.{key}"] = value
                        self.env[target] = tf._union(self.env.get(target, _EMPTY), taint)
                    elif taint:
                        self.exact.discard(target)
                        self.env[target] = tf._union(self.env.get(target, _EMPTY), taint)
                return self.env.get(target, _EMPTY)
            return None
        if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"}:
            return None
        owner = _dotted(callee.get("object"))
        if not owner or "()" in owner:
            return None
        items = self.lists.get(owner)
        if items is not None:
            result: Taint | None = None
            if last == "push":
                items.extend(arg_taints)
                result = _EMPTY
            elif last == "unshift":
                items[:0] = arg_taints
                result = _EMPTY
            elif last == "pop":
                result = items.pop() if items else _EMPTY
            elif last == "shift":
                result = items.pop(0) if items else _EMPTY
            elif last == "at" and args:
                index = self._const(args[0])
                if isinstance(index, (int, float)) and not isinstance(index, bool) and float(index).is_integer():
                    index = int(index)
                    result = items[index] if -len(items) <= index < len(items) else _EMPTY
            elif last in {"splice", "reverse", "sort", "fill", "copyWithin"}:
                self.lists.pop(owner, None)
                if any(arg_taints):
                    self.env[owner] = tf._union(self.env.get(owner, _EMPTY), *arg_taints)
                return None
            if result is not None:
                if owner in self.lists:
                    self.env[owner] = tf._union(*items)
                return result
            return None
        if owner in self.exact and args:
            key = _const_key(self._const(args[0]))
            if last == "get":
                return self.env.get(f"{owner}.{key}", _EMPTY) if key is not None else receiver
            if last == "set" and len(args) >= 2:
                if key is not None:
                    self.env[f"{owner}.{key}"] = arg_taints[1]
                else:
                    self.exact.discard(owner)
                self.env[owner] = tf._union(self.env.get(owner, _EMPTY), *arg_taints[:2])
                return receiver
            if last == "delete" and key is not None:
                self.env.pop(f"{owner}.{key}", None)
                return _EMPTY
        return None

    def _owner_kind(self, owner: Any) -> str | None:
        """Alıcının çıkarılan türü: yerel atama/TS türü, sınıf alanı, modül adı ya da içe aktarma (dosyalar arası)."""
        if _t(owner) in {"CallExpression", "OptionalCallExpression", "AwaitExpression", "TSAsExpression", "ParenthesizedExpression"}:
            return self.p.classify(self.m, owner)
        dotted = _dotted(owner)
        if not dotted or "()" in dotted:
            return None
        if dotted in self.kinds:
            return self.kinds[dotted]
        parts = dotted.split(".")
        if parts[0] == "this" and len(parts) == 2 and self.class_name:
            fields = self.p.field_kinds(self.m, self.class_name)
            if parts[1] in fields:
                return fields[parts[1]]
            return None
        if len(parts) == 1 and self.class_name:
            local = self.p.field_kinds(self.m, self.class_name).get("<local>." + parts[0])
            if local is not None:
                return local
        if parts[0] in self.env and parts[0] not in self.m.values and parts[0] not in self.m.imports:
            return None  # yerel/parametre: türü bilinmiyor
        if len(parts) == 1:
            return self.p.value_kind(self.m, parts[0])
        if len(parts) == 2 and parts[0] in self.m.imports:
            spec, imported = self.m.imports[parts[0]]
            if imported == "*" or not spec.startswith("."):
                return self.p.module_kind(self.m, spec, parts[1]) if spec.startswith(".") else None
        return None

    def _mongo_owner(self, owner: Any) -> bool:
        """Alıcı bir MongoDB koleksiyonu/Mongoose modeli mi?

        Önce tür çıkarımı (mongoose.model / db.collection / TS türü / @InjectModel, dosyalar arası
        require/import); bilinmiyorsa ad sezgisi — projede SQL ORM olup MongoDB kitaplığı yoksa sezgi kapalı."""
        if _t(owner) in {"CallExpression", "OptionalCallExpression"}:
            last = _callee_name(owner.get("callee")).rsplit(".", 1)[-1]
            if last in {"collection", "model", "getCollection"}:
                return True
        dotted = _dotted(owner)
        if dotted and "()" not in dotted and (dotted.split(".")[0] in self.roots or self.ctors.get(dotted) == "ldap"):
            return False
        if dotted and self.ctors.get(dotted) == "collection":
            return True
        kind = self._owner_kind(owner)
        if kind is not None:
            return kind == "mongo"
        if not dotted or "()" in dotted:
            return False
        mongo, sql = self.p.db_packages()
        if sql and not mongo:
            return False
        parts = dotted.split(".")
        last = parts[-1]
        if last in _NOT_MODEL_OWNERS:
            return False
        if last[:1].isupper() and not last.isupper():
            return True
        lowered = last.lower()
        if lowered.endswith(("model", "collection", "coll")) or (lowered.endswith("col") and lowered != "protocol"):
            return True
        return parts[0] == "db" and len(parts) == 2

    def _query_builder(self, owner: Any) -> bool:
        """Alıcı bir TypeORM sorgu oluşturucusu mu (createQueryBuilder zinciri ya da ona atanmış ad)?"""
        steps = 0
        while isinstance(owner, dict) and steps < 40:
            steps += 1
            kind = _t(owner)
            if kind in {"CallExpression", "OptionalCallExpression"}:
                callee = owner.get("callee")
                if _callee_name(callee).rsplit(".", 1)[-1] == "createQueryBuilder":
                    return True
                owner = callee.get("object") if _t(callee) in {"MemberExpression", "OptionalMemberExpression"} else None
            elif kind in {"AwaitExpression", "ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression"}:
                owner = owner.get("expression") or owner.get("argument")
            else:
                dotted = _dotted(owner)
                return bool(dotted) and self.ctors.get(dotted) == "querybuilder"
        return False

    def _own_request_url(self, node: Any) -> bool:
        """İfade gelen isteğin kendi adresi mi (req.url / request.nextUrl / request.nextUrl.origin)?"""
        chain = _chain(node) or []
        return len(chain) >= 2 and chain[0] in self.roots and chain[1] in {"url", "nextUrl", "originalUrl", "href", "origin"} \
            and all(part in {"url", "nextUrl", "originalUrl", "href", "origin"} for part in chain[1:])

    def _chain_content_type(self, call: Any) -> str | None:
        """res.status(200).type('text/html') / reply.header('content-type', …) zincirinde atanan içerik türü."""
        node = call
        for _ in range(12):
            if _t(node) != "CallExpression":
                return None
            callee = node.get("callee") or {}
            if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"}:
                return None
            method = (callee.get("property") or {}).get("name", "")
            args = node.get("arguments") or []
            if method in {"type", "contentType"} and args:
                return _string_value(args[0])
            if method in {"header", "set", "setHeader"} and len(args) >= 2 \
                    and (_string_value(args[0]) or "").lower() == "content-type":
                return _string_value(args[1])
            if method == "headers" and args and _t(args[0]) == "ObjectExpression":
                for prop in args[0].get("properties", []):
                    if _key_name(prop).lower() == "content-type":
                        return _string_value(prop.get("value"))
            node = callee.get("object")
        return None

    def _check_framework_sinks(self, node: Node, name: str, callee: Any, args: list[Node], arg_taints: list[Taint]) -> None:
        """Model dosyasıyla ifade edilemeyen çatı hedefleri (17. tur)."""
        if not args or not name:
            return
        line = _line(node)
        last = name.rsplit(".", 1)[-1]
        obj = callee.get("object") if _t(callee) in {"MemberExpression", "OptionalMemberExpression"} else None
        if _t(obj) == "Identifier" and obj.get("name") in self.roots and last in {"html", "redirect"} \
                and "hono" in self.p.package_roots():
            # Hono bağlamı: c.html(x) HTML yanıtı, c.redirect(x) yönlendirme.
            if last == "html":
                self._emit("html", f"{obj.get('name')}.html", line, arg_taints[0])
            elif not _fixed_url_target(args[0]):
                self._emit("redirect", f"{obj.get('name')}.redirect", line, arg_taints[0])
            return
        chained = _REPLY_CHAIN_RE.match(name)
        if chained and _t(obj) == "CallExpression":
            content_type = self._chain_content_type(obj)
            if content_type is None:
                if chained.group(1) in {"res", "response"}:
                    return  # Express zinciri (status/cookie …) mevcut res.send kuralıyla değerlendirilir
                if _has_html_literal(args[0]):
                    self._emit("html", f"{chained.group(1)}.send", line, arg_taints[0])
                return
            if "html" in content_type.lower():
                # reply.type('text/html').send(x) / res.type('html').send(x): açıkça HTML yanıtı.
                self._emit("html", f"{chained.group(1)}.send", line, arg_taints[0])
            return
        if last == "prepare" and _t(obj) in {"Identifier", "MemberExpression"} and \
                self.p.package_roots() & _PREPARE_SQL_PACKAGES and \
                re.search(r"(?i)(?:^|\.)(?:\w*db|database|sqlite\w*|\w*sql\w*|conn\w*|client|pool)$", _dotted(obj) or ""):
            # better-sqlite3 / sqlite3 / mysql2: db.prepare("… " + x): hazırlanan metnin kendisi kirli → SQL enjeksiyonu.
            self._emit("sql", name, line, self._sql_arg(args[0], arg_taints[0]))
            return
        if _t(callee) == "Identifier" and name in _NEXT_NAV_REDIRECTS and name not in self.env:
            imported = self.m.imports.get(name)
            if imported is not None and imported[0].startswith("next/navigation") and not _fixed_url_target(args[0]):
                self._emit("redirect", f"{name} (next/navigation)", line, arg_taints[0])

    def _check_js_sinks(self, node: Node, name: str, canonical: str, callee: Any, args: list[Node],
                        arg_taints: list[Taint]) -> None:
        """NoSQL işleç enjeksiyonu, prototip kirletme ve LDAP (JS'e özgü, adla/yapıyla eşlenen hedefler)."""
        if not name or not args:
            return
        line = _line(node)
        last = name.rsplit(".", 1)[-1]
        if last in _QUERY_BUILDER_SQL_METHODS and _t(callee) in {"MemberExpression", "OptionalMemberExpression"} \
                and _t(args[0]) not in {"ObjectExpression", "ArrowFunctionExpression", "FunctionExpression", "NewExpression", "ArrayExpression"} \
                and self._query_builder(callee.get("object")):
            self._emit("sql", name, line, arg_taints[0])
            return
        if last in _NOSQL_METHODS and _t(callee) in {"MemberExpression", "OptionalMemberExpression"} \
                and self._mongo_owner(callee.get("object")):
            first = args[0]
            orm = _t(first) == "ObjectExpression" and any(
                _key_name(p) in {"where", "include", "attributes", "select", "relations", "order"} for p in first.get("properties", []))
            if not orm:
                # Gövde/sorgudan gelen nesne { $ne: null } gibi işleç taşıyabilir (CWE-943).
                self._emit("nosql", name, line, _object_capable(arg_taints[0]))
        proto = "lodash." + canonical[2:] if canonical.startswith("_.") else canonical
        if proto in _PROTO_MERGE and (canonical != name or name.startswith("_.") or "." in proto):
            start = _PROTO_MERGE[proto]
            self._emit("prototype", name, line, _object_capable(tf._union(*arg_taints[start:])))
        elif name in {"$.extend", "jQuery.extend"} and len(args) >= 3 and _t(args[0]) == "BooleanLiteral" and args[0].get("value"):
            self._emit("prototype", name, line, _object_capable(tf._union(*arg_taints[2:])))
        elif proto in _PROTO_SETTERS and _PROTO_SETTERS[proto] < len(args):
            self._emit("prototype", name, line, arg_taints[_PROTO_SETTERS[proto]])
        if last == "search" and _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
            owner = _dotted(callee.get("object"))
            if owner and (self.ctors.get(owner) == "ldap" or _LDAP_OWNER_RE.search(owner)):
                taint = arg_taints[0]
                if len(args) > 1:
                    options = args[1]
                    if _t(options) == "ObjectExpression":
                        values = [p.get("value") for p in options.get("properties", []) if _key_name(p) == "filter"]
                        taint = tf._union(taint, *(self.expr(v) for v in values))
                    else:
                        taint = tf._union(taint, arg_taints[1])
                self._emit("ldap", name, line, taint)

    def _receiver(self, callee: Any, node: Any) -> tuple[str, dict[str, Taint] | None, str]:
        """Çağrının alıcısı: ("self"|"var"|"new"|"tmp"|"", alanlar, sahip adı)."""
        if _t(node) == "NewExpression":
            return "new", {}, ""
        if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"}:
            return "", None, ""
        owner = callee.get("object")
        if _t(owner) == "ThisExpression" and self.summary is not None and self.qual != "<module>":
            return "self", None, ""
        if _t(owner) == "NewExpression" and id(owner) in self.call_fields:
            return "tmp", dict(self.call_fields[id(owner)]), ""
        dotted = _dotted(owner)
        if dotted and "()" not in dotted:
            prefix = dotted + "."
            fields = {key[len(prefix):]: value for key, value in self.env.items()
                      if key.startswith(prefix) and "." not in key[len(prefix):]}
            return "var", fields, dotted
        return "", {}, ""

    def _map_effect(self, taint: Taint, bound: dict[int, Taint], fields: dict[str, Taint] | None, label: str) -> Taint:
        """Özet içindeki sembolik kökenleri çağrı yerindeki değerlere eşle."""
        parts: list[Taint] = []
        for origin in taint:
            if origin.label == _PARAM:
                value = bound.get(int(origin.source))
                if value:
                    parts.append(tf._via(tf._clean(value, origin.cleaned), label))
            elif origin.label == tf._FIELD:
                if fields is None:
                    parts.append((origin,))  # this.m(): aynı nesne, sembolik kalır
                elif fields.get(origin.source):
                    parts.append(tf._via(tf._clean(fields[origin.source], origin.cleaned), label))
            else:
                parts.append((origin,))
        return tf._union(*parts)

    def _mutate(self, owner: Any, method: str, args: list[Node], arg_taints: list[Taint]) -> None:
        """arr.push(x) / map.set(k, v) / params.append(k, v): alıcı yerinde kirlenir."""
        dotted = _dotted(owner)
        if not dotted or not any(arg_taints):
            return
        if _t(owner) == "Identifier":
            self.env[dotted] = tf._union(self.env.get(dotted, _EMPTY), *arg_taints)
        else:
            self.assign(owner, tf._union(self.env.get(dotted, _EMPTY), *arg_taints))

    def _apply_summary(self, target: tuple[JsModule, str, Node, str | None], arg_taints: list[Taint],
                       call: Node | None = None) -> Taint:
        module, qual, node, cls = target
        self.p.called.add(id(node))
        local = qual.startswith(f"{self.qual}.<locals>.")
        summary = self.p.summary(module, qual, node, cls, dict(self.env) if local else None, dict(self.refs) if local else None)
        label = qual.replace(".<locals>", "").replace("get ", "").replace("set ", "") + "()"
        bound = {index: taint for index, taint in enumerate(arg_taints) if taint and index < len(summary.params)}
        kind, fields, owner = self._receiver(call.get("callee"), call) if call is not None else ("", None, "")
        if call is not None:
            ret_ref = getattr(summary, "js_ret_ref", None)
            if ret_ref is not None:
                self.call_refs[id(call)] = ret_ref
            ret_fields_map = getattr(summary, "js_ret_fields", None)
            if ret_fields_map and _t(call) != "NewExpression":
                self.call_fields[id(call)] = {field: self._map_effect(taint, bound, {}, label) for field, taint in ret_fields_map.items()}
        receiver_map = None if kind == "self" else (fields if fields is not None else {})
        if call is not None:
            actual_args = call.get("arguments") or []
            for callback_index, invocations in getattr(summary, "js_callback_calls", {}).items():
                if callback_index >= len(actual_args) or not _is_function(actual_args[callback_index]):
                    continue
                callback = actual_args[callback_index]
                bounded = list(invocations[:7])
                if len(invocations) > 8:
                    width = max((len(item) for item in invocations[7:]), default=0)
                    bounded.append(tuple(
                        tf._union(*(item[index] for item in invocations[7:] if index < len(item)))
                        for index in range(width)
                    ))
                else:
                    bounded.extend(invocations[7:])
                for invocation in bounded:
                    seeds = {
                        index: self._map_effect(symbolic, bound, receiver_map, label)
                        for index, symbolic in enumerate(invocation)
                    }
                    self._closure(callback, seeds)
        new_fields: dict[str, Taint] = {}
        for field, written in summary.field_writes.items():
            # Metodun this.<alan> yazdıkları: aynı nesne (this), izlenen değişken ya da yeni örnek.
            mapped = self._map_effect(written, bound, receiver_map, label)
            if kind == "self":
                if self.summary is not None:
                    self.summary.add_field_write(field, mapped)
            elif kind == "new":
                new_fields[field] = tf._union(new_fields.get(field, _EMPTY), mapped)
            elif kind == "var" and fields is not None and mapped:
                key = f"{owner}.{field}"
                self.env[key] = tf._union(self.env.get(key, _EMPTY), mapped)
                fields[field] = self.env[key]
            elif kind == "tmp" and fields is not None:
                fields[field] = tf._union(fields.get(field, _EMPTY), mapped)
        field_values: dict[str, Taint]
        if kind == "new":
            if call is not None:
                self.call_fields[id(call)] = new_fields
            field_values = new_fields
        elif kind == "self":
            field_values = {s.field: self._field_origin(s.field, s.line) for s in summary.sinks.values() if s.index == -1}
        else:
            field_values = fields or {}
        ret_fields = [
            self._map_effect((tf._Origin(tf._FIELD, field, 0, (), cleaned, self.m.relpath),), bound, receiver_map, label)
            for field, cleaned in summary.ret_fields.items()
        ]
        if not bound and not field_values:
            return tf._union(summary.ret_sources, *ret_fields)
        for sink in summary.sinks.values():
            taint = field_values.get(sink.field) if sink.index == -1 else bound.get(sink.index)
            if not taint:
                continue
            sink_name, real_ok = sink.sink, True
            if sink.kind == "prototype" and sink.sink.startswith(f"{_PROTO_ASSIGN}#"):
                # obj[k1][k2]: iç anahtar (k2) bu çağrıda da kirli olmalı.
                inner = tf._live(bound.get(int(sink.sink.rpartition("#")[2]), _EMPTY), "prototype")
                real_ok = any(o.label not in {_PARAM, tf._FIELD} for o in inner)
                inner_params = sorted({int(o.source) for o in inner if o.label == _PARAM})
                if real_ok:
                    sink_name = _PROTO_ASSIGN
                elif inner_params:
                    sink_name = f"{_PROTO_ASSIGN}#{inner_params[0]}"
                else:
                    continue
            for origin in tf._live(taint, sink.kind):
                via = (origin.via + (label,) + sink.via)[-tf.MAX_VIA:]
                if origin.label == _PARAM:
                    if self.summary is not None:
                        self.summary.add_sink(tf._ParamSink(int(origin.source), sink.kind, sink_name, sink.file, sink.line, via))
                elif not real_ok:
                    continue
                elif origin.label == tf._FIELD:
                    if self.summary is not None:
                        self.summary.add_sink(tf._ParamSink(-1, sink.kind, sink_name, sink.file, sink.line, via, origin.source))
                elif origin.label == _PROP:
                    if self.summary is not None:
                        self.summary.add_sink(tf._ParamSink(-2, sink.kind, sink_name, sink.file, sink.line, via, origin.source))
                else:
                    self.p.add_flow(tf.Flow(
                        "javascript", sink.kind, sink_name, sink.line, origin.source, origin.label, origin.line,
                        via, sink.file, origin.file,
                    ))
        returned = [
            tf._via(tf._clean(bound[index], cleaned), label)
            for index, cleaned in summary.ret_params.items()
            if index in bound
        ]
        return tf._union(*returned, *ret_fields, summary.ret_sources)

    # -- hedefler -------------------------------------------------------------------
    # -- sunucu tarafı görünümler (res.render) --------------------------------------------
    def _request_object(self, node: Any) -> bool:
        """İfade bütün istek gövdesi/sorgu nesnesi mi (req.body, req.query, ctx.request.body, {...req.body})?"""
        while _t(node) in {"TSAsExpression", "TSNonNullExpression", "ParenthesizedExpression", "AwaitExpression"}:
            node = node.get("expression") or node.get("argument")
        kind = _t(node)
        if kind == "Identifier":
            return node.get("name", "") in self.request_objects
        if kind == "ObjectExpression":
            return any(_t(prop) == "SpreadElement" and self._request_object(prop.get("argument"))
                       for prop in node.get("properties", []))
        chain = _chain(node) if kind in {"MemberExpression", "OptionalMemberExpression"} else None
        if not chain:
            return False
        if len(chain) == 2 and chain[1] in {"body", "query"} and (chain[0] in self.roots or chain[0] in _CTX_ROOTS and chain[1] == "query"):
            return chain[0] not in self.env or not self.env[chain[0]]
        return len(chain) == 3 and chain[0] in _CTX_ROOTS and chain[1] == "request" and chain[2] in {"body", "query"}

    def _locals_path(self, node: Any, path: tuple[str, ...], depth: int = 0) -> Taint:
        """res.render(görünüm, yereller): şablonda kullanılan yerel değişken yolunun taint'i (bilinmeyen alan: boş)."""
        while _t(node) in {"TSAsExpression", "TSNonNullExpression", "ParenthesizedExpression", "AwaitExpression"}:
            node = node.get("expression") or node.get("argument")
        kind = _t(node)
        if depth > 6 or not isinstance(node, dict):
            return _EMPTY
        if self._request_object(node):
            # Bütün istek nesnesi: her anahtar istemcinin denetiminde.
            return self.env.get(node.get("name", ""), _EMPTY) if kind == "Identifier" else self.expr(node) if kind != "ObjectExpression" else tf._union(
                *(self.expr(prop.get("argument")) for prop in node.get("properties", []) if _t(prop) == "SpreadElement"))
        if not path:
            if kind == "Identifier":
                return self.env.get(node.get("name", ""), _EMPTY)
            if kind in {"MemberExpression", "OptionalMemberExpression"}:
                return self.expr(node)
            shape = self.shapes.get(id(node))
            return tf._union(*shape.values()) if isinstance(shape, dict) else _EMPTY
        if kind == "ObjectExpression":
            shape = self.shapes.get(id(node))
            for prop in reversed(node.get("properties", [])):
                if _t(prop) == "SpreadElement":
                    found = self._locals_path(prop.get("argument"), path, depth + 1)
                    if found:
                        return found
                    continue
                if _t(prop) != "ObjectProperty" or _key_name(prop) != path[0]:
                    continue
                value = prop.get("value")
                if len(path) > 1 and _t(value) in {"ObjectExpression", "Identifier", "MemberExpression"}:
                    return self._locals_path(value, path[1:], depth + 1)
                if isinstance(shape, dict) and path[0] in shape:
                    return shape[path[0]]
                return self._locals_path(value, (), depth + 1)
            return _EMPTY
        if kind == "Identifier":
            name = node.get("name", "")
            for size in range(len(path), 0, -1):
                key = name + "." + ".".join(path[:size])
                if key in self.env:
                    return self.env[key]
            return _EMPTY
        if kind in {"MemberExpression", "OptionalMemberExpression"}:
            chain = _chain(node)
            if chain:
                for size in range(len(path), 0, -1):
                    key = ".".join([*chain, *path[:size]])
                    if key in self.env:
                        return self.env[key]
            return self.expr(node)
        return _EMPTY

    def _check_render(self, node: Node, name: str, args: list[Node], arg_taints: list[Taint]) -> None:
        """Bütün istek nesnesi şablon yerelleri olarak (EJS ayar/seçenek enjeksiyonu) ve şablonda kaçışsız basılan
        istek verisi (XSS); şablon dosyası görünüm adından çözülür."""
        line = _line(node)
        locals_node = args[1]
        whole = self._request_object(locals_node)
        if whole:
            self._emit("template_object", f"{name}(görünüm, istek nesnesi)", line, arg_taints[1])
        view = _string_value(args[0])
        if view is None:
            value = self._const(args[0])
            view = value if isinstance(value, str) else None
        if not view:
            return
        relpath = taint_js_views.resolve_view(view, self.m.relpath, self.p.view_inventory(), *self.p.view_config())
        if relpath is None:
            return
        for out_line, shown, paths in self.p.view_outputs(relpath):
            taint = arg_taints[1] if whole else tf._union(*(self._locals_path(locals_node, path) for path in paths))
            if taint:
                self._emit("html", f"{name}('{view}') → {relpath}:{out_line} {shown}", line, taint)

    def _emit(self, kind: str, sink: str, line: int, taint: Taint) -> None:
        self.p.mark_evaluated(self.m.relpath, kind, line)
        for origin in tf._live(taint, kind):
            if origin.label == _SECOND_ORDER and kind not in _SECOND_ORDER_KINDS:
                continue
            if origin.label == _PARAM:
                if self.summary is not None:
                    self.summary.add_sink(tf._ParamSink(int(origin.source), kind, sink, self.m.relpath, line, origin.via))
                continue
            if origin.label == tf._FIELD:
                if self.summary is not None:
                    self.summary.add_sink(tf._ParamSink(-1, kind, sink, self.m.relpath, line, origin.via, origin.source))
                continue
            if origin.label == _PROP:
                if self.summary is not None:
                    self.summary.add_sink(tf._ParamSink(-2, kind, sink, self.m.relpath, line, origin.via, origin.source))
                continue
            self.p.add_flow(tf.Flow(
                "javascript", kind, sink, line, origin.source, origin.label, origin.line, origin.via,
                self.m.relpath, origin.file,
            ))

    def _sql_arg(self, arg: Node, taint: Taint) -> Taint:
        if _t(arg) == "ObjectExpression":
            values = [p.get("value") for p in arg.get("properties", []) if _key_name(p) in {"text", "sql", "query"}]
            return tf._union(*(self.expr(v) for v in values))
        return taint

    @staticmethod
    def _orm_write_values(method: str, args: list[Node]) -> Node | None:
        """ORM yazımında alan değerlerini taşıyan nesne düğümü (bilinmiyorsa None)."""
        def obj(n: Any) -> Node | None:
            return n if _t(n) == "ObjectExpression" else None
        second = args[1] if len(args) > 1 else None
        if method in {"updateOne", "updateMany", "findOneAndUpdate", "findByIdAndUpdate"} or (
                method == "update" and obj(second) is not None
                and not any(_key_name(p) == "where" for p in second.get("properties", []))):
            update = obj(second)
            if update is None:
                return None
            for prop in update.get("properties", []):
                if _key_name(prop) == "$set":
                    return obj(prop.get("value"))
            return update
        return obj(args[0]) if args else None

    def _request_node(self, node: Any) -> bool:
        """Düğüm doğrudan istek verisi mi (req.body.x / ctx.request.body.x / istekten gelen yerel değişken)?"""
        if _t(node) == "Identifier":
            return any(o.label == "request" for o in self.env.get(node.get("name"), ()))
        dotted = _dotted(node)
        return bool(dotted) and dotted.split(".", 1)[0] in {"req", "request", "ctx"} and "." in dotted

    def _check_sinks(self, node: Node, name: str, args: list[Node], arg_taints: list[Taint],
                     receiver: Taint, is_new: bool) -> None:
        if not name or not args:
            return
        line = _line(node)
        parts = name.split(".")
        last = parts[-1]
        owner = parts[-2] if len(parts) >= 2 else ""
        owner_full = ".".join(parts[:-1])
        if last in _ORM_WRITE_METHODS and owner:
            # 25. tur: Model.create({ad: req.body.ad}) / Sequelize update(değerler, {where}) / Mongo
            # updateOne(süzgeç, {$set: {...}}): istek verisi alan alanlar (yazma kanıtı)
            values = self._orm_write_values(last, args)
            for prop in values.get("properties", []) if values is not None else ():
                key, value = _key_name(prop), prop.get("value")
                if key and self._request_node(value):
                    self.p.user_written_attrs.setdefault(key, (self.m.relpath, line))
        if (owner == "console" and last in {"log", "info", "warn", "error", "debug", "trace"}) or (
            (owner in _LOG_OBJECTS or owner_full in _LOG_OBJECTS) and last in _LOG_METHODS
        ):
            self._emit("log", name, line, tf._union(*arg_taints))
        elif last in _SQL_METHODS and owner and owner not in {"document", "URLSearchParams", "window", "$", "jQuery"}:
            self._emit("sql", name, line, self._sql_arg(args[0], arg_taints[0]))
        elif name in {"exec", "execSync", "child_process.exec", "child_process.execSync"} or (
            owner in {"child_process", "cp", "childProcess", "shell", "proc"} and last in {"exec", "execSync"}
        ):
            self._emit("command", name, line, arg_taints[0])
        elif name in {"eval", "Function", "window.eval", "globalThis.eval"}:
            self._emit("eval", name, line, arg_taints[-1] if name == "Function" else arg_taints[0])
        elif name in {"setTimeout", "setInterval", "setImmediate"} and _t(args[0]) in {"StringLiteral", "TemplateLiteral", "BinaryExpression", "Identifier", "MemberExpression"}:
            if not _is_function(args[0]) and arg_taints[0]:
                self._emit("eval", name, line, arg_taints[0])
        elif name in {"document.write", "document.writeln"}:
            self._emit("html", name, line, tf._union(*arg_taints))
        elif last == "insertAdjacentHTML":
            self._emit("html", name, line, arg_taints[1] if len(arg_taints) > 1 else _EMPTY)
        elif last in {"html", "append", "prepend", "after", "before", "replaceWith"} and (owner in {"$", "jQuery"} or name.startswith(("$().", "jQuery().", "_call_().")) or ")." in name and name.split("().")[0] in {"$", "jQuery"}):
            self._emit("html", name, line, self._strip_field_only(args[0], arg_taints[0]))
        elif name in {"$", "jQuery"} and _t(args[0]) not in {"StringLiteral", "FunctionExpression", "ArrowFunctionExpression"}:
            if not _selector_only(args[0]):
                self._emit("html", name, line, self._strip_field_only(args[0], arg_taints[0]))
        elif name == "RegExp":
            self._emit("regex", "new RegExp" if is_new else "RegExp", line, arg_taints[0])
        elif last.startswith("bypassSecurityTrust"):
            # Angular DomSanitizer.bypassSecurityTrust*: değer arındırılmadan DOM'a güvenilir olarak verilir.
            self._emit("html", name, line, arg_taints[0])
        if last == "mv" and len(parts) >= 2 and any(".files" in o.source or o.source.endswith("files") for o in receiver):
            # express-fileupload: req.files.x.mv(hedef) dosyayı yazar; hedef yolu yüklenen ad içeriyorsa yol geçişi.
            self._emit("path", name, line, arg_taints[0])
        if owner in _EXPRESS_SEND_ROOTS and last == "attachment" and len(parts) == 2:
            self.non_html.add(owner)  # res.attachment(): Content-Disposition: attachment → indirilir, sayfa olarak açılmaz
        elif owner in _EXPRESS_SEND_ROOTS and last in _CONTENT_TYPE_SETTERS and len(parts) == 2 and args:
            self._note_content_type(owner, last, args)
        self._check_model_sinks(node, name, args, arg_taints)

    def _express_string_send(self, name: str, nodes: list[Node]) -> bool:
        """Express res.send(dize): içerik türü atanmamış dize gövde text/html olarak gider."""
        root, _, last = name.partition(".")
        if last != "send" or root not in _EXPRESS_SEND_ROOTS or root in self.non_html:
            return False
        members = self.p.string_request_members()
        return any(_string_expr(n, self.string_vars, members=members) for n in nodes)

    @staticmethod
    def _attachment_header(method: str, args: list[Node]) -> bool:
        """res.set/setHeader/header('Content-Disposition', 'attachment…') ya da nesne/writeHead biçimi: yanıt ek
        olarak indirilir (tarayıcı belgeyi işlemez) → gövde XSS hedefi değil."""
        props: list[Any] = []
        if method == "writeHead":
            headers = args[1] if len(args) > 1 and _t(args[1]) == "ObjectExpression" else (args[2] if len(args) > 2 else None)
            props = headers.get("properties", []) if _t(headers) == "ObjectExpression" else []
        elif args and _t(args[0]) == "ObjectExpression":
            props = args[0].get("properties", [])
        elif len(args) > 1 and _t(args[0]) == "StringLiteral" and str(args[0].get("value", "")).lower() == "content-disposition":
            value = args[1]
            return _t(value) == "StringLiteral" and str(value.get("value", "")).strip().lower().startswith("attachment")
        for prop in props:
            if _key_name(prop).lower() == "content-disposition":
                value = prop.get("value")
                return _t(value) == "StringLiteral" and str(value.get("value", "")).strip().lower().startswith("attachment")
        return False

    def _note_content_type(self, owner: str, method: str, args: list[Node]) -> None:
        """res.type('json') / res.set('Content-Type', 'text/plain') …: yanıtın HTML olup olmadığını izle."""
        verdict = self._content_type_verdict(method, args)
        if verdict is True:
            self.non_html.add(owner)
        elif verdict is False:
            self.non_html.discard(owner)

    @classmethod
    def _content_type_verdict(cls, method: str, args: list[Node]) -> bool | None:
        """İçerik türü atayan çağrının kararı: True HTML dışı (ya da ek), False HTML/bilinmeyen değer, None ilgisiz."""
        value: Any = None
        if method in {"type", "contentType"}:
            value = args[0]
        elif method == "writeHead":
            headers = args[1] if len(args) > 1 and _t(args[1]) == "ObjectExpression" else (args[2] if len(args) > 2 else None)
            if _t(headers) == "ObjectExpression":
                value = next((p.get("value") for p in headers.get("properties", []) if _key_name(p).lower() == "content-type"), None)
        elif _t(args[0]) == "ObjectExpression":
            value = next((p.get("value") for p in args[0].get("properties", []) if _key_name(p).lower() == "content-type"), None)
        elif len(args) > 1 and _t(args[0]) == "StringLiteral" and str(args[0].get("value", "")).lower() == "content-type":
            value = args[1]
        verdict = _non_html_type(value) if value is not None else None
        if cls._attachment_header(method, args):
            return True
        if verdict is True:
            return True
        if verdict is False or (value is not None and verdict is None):
            return False
        return None

    def _check_process_sinks(self, node: Node, name: str, args: list[Node], arg_taints: list[Taint]) -> None:
        """child_process.spawn/execFile kabuksuz da: program adının kendisi girdiden geliyorsa saldırgan istediği
        programı çalıştırır (komut enjeksiyonu); program curl/wget ise argümanlardaki adres giden istektir (SSRF)."""
        canonical = self.canonical(name) or name
        last = canonical.rsplit(".", 1)[-1]
        if last not in _PROCESS_SPAWN_CALLS or not args or not (canonical == last or canonical.startswith("child_process.")):
            return
        line = _line(node)
        if _t(args[0]) != "StringLiteral":
            self._emit("command", name, line, arg_taints[0])
            return
        program = (_string_value(args[0]) or "").rsplit("/", 1)[-1]
        if program in {"curl", "wget"} and len(args) > 1:
            self._emit("ssrf", f"{name}('{program}', …)", line, arg_taints[1])

    def _check_model_sinks(self, node: Node, name: str, args: list[Node], arg_taints: list[Taint]) -> None:
        self._check_process_sinks(node, name, args, arg_taints)
        chained = _RESPONSE_CHAIN_RE.match(name or "")
        attachment_chain = False
        if chained:
            attachment_chain = ".attachment()" in chained.group(2)
            name = f"{chained.group(1)}.{chained.group(3)}"
        models = self._models_for(name, self.canonical(name), _t(node) == "NewExpression")
        for model in models:
            if model.unless_object_key is not None:
                index, keys = model.unless_object_key
                arg = args[index] if -len(args) <= index < len(args) else None
                if _t(arg) == "ObjectExpression" and any(_key_name(p) in keys for p in arg.get("properties", [])):
                    continue
            if model.required_object_key is not None:
                index, key, values = model.required_object_key
                arg = args[index] if -len(args) <= index < len(args) else None
                if _t(arg) != "ObjectExpression":
                    continue
                prop = next((p for p in arg.get("properties", []) if _key_name(p) == key), None)
                value = (prop or {}).get("value") or {}
                literal = str(value.get("value")).lower() if _t(value) in {"BooleanLiteral", "StringLiteral"} else ("true" if value.get("value") is True else None)
                if literal not in values:
                    continue
            indices = [len(args) - 1] if model.last_arg and args else [i for i in model.args if i < len(args)]
            parts: list[Taint] = []
            nodes: list[Node] = []
            for index in indices:
                arg = args[index]
                if model.object_keys and _t(arg) == "ObjectExpression":
                    for prop in arg.get("properties", []):
                        if _key_name(prop) in model.object_keys:
                            parts.append(self.expr(prop.get("value")))
                            nodes.append(prop.get("value"))
                else:
                    parts.append(arg_taints[index])
                    nodes.append(arg)
            if not nodes:
                continue
            if model.html_literal and not any(_has_html_literal(n) for n in nodes) and not self._express_string_send(name, nodes):
                stored = tuple(o for o in tf._union(*parts) if o.label == "stored")
                if model.kind == "html" and stored and len(nodes) == 1 \
                        and _t(nodes[0]) in {"MemberExpression", "OptionalMemberExpression"} \
                        and not nodes[0].get("computed") and name.partition(".")[0] not in self.non_html:
                    # 25. tur: res.send(kayit.alan) — gövdenin dize olduğu yazma kanıtıyla belli olur (proje sonunda)
                    attr = _key_name({"key": nodes[0].get("property")})
                    if attr:
                        self.p.pending_stored_sends.append((self.m.relpath, _line(node), name, attr, stored))
                continue
            if model.kind == "html" and attachment_chain:
                continue  # res.attachment().send(…): ek olarak indirilir
            if model.kind == "html" and name.partition(".")[0] in self.non_html and name.partition(".")[0] in _EXPRESS_SEND_ROOTS:
                continue  # res.type('text/plain') / JSON içerik türü atanmış yanıt HTML olarak yorumlanmaz
            taint = tf._union(*parts)
            if model.kind == "ssrf":
                partial = self._partial_ssrf(node, args, taint)
                if partial:
                    self._emit("ssrf_partial", name, _line(node), partial)
            if model.kind in _URL_TARGET_KINDS and all(_fixed_url_target(n) for n in nodes):
                taint = _EMPTY
            self._emit(model.kind, name, _line(node), taint)
        if not models and args and _t(node.get("callee")) in {"MemberExpression", "OptionalMemberExpression"} \
                and name.rsplit(".", 1)[-1] in _AXIOS_INSTANCE_METHODS and self._fixed_base_call(node, []):
            # axios.create({ baseURL: sabit }) örneği: mutlak URL tabanı geçersiz kılar (tam SSRF); göreli yol kısmidir.
            taint = arg_taints[0]
            partial = self._partial_ssrf(node, args, taint)
            if partial:
                self._emit("ssrf_partial", name, _line(node), partial)
            self._emit("ssrf", name, _line(node), _EMPTY if _fixed_url_target(args[0]) else taint)

    # -- doğrulama koşulları ------------------------------------------------------------
    def _guard(self, test: Any) -> tuple[tf.Guard, tf.Guard]:
        kind = _t(test)
        if kind == "UnaryExpression" and test.get("operator") == "!":
            when_true, when_false = self._guard(test.get("argument"))
            return when_false, when_true
        if kind == "ParenthesizedExpression":
            return self._guard(test.get("expression"))
        if kind == "LogicalExpression":
            left_t, left_f = self._guard(test.get("left"))
            right_t, right_f = self._guard(test.get("right"))
            if test.get("operator") == "&&":
                return left_t + right_t, []
            if test.get("operator") == "||":
                return [], left_f + right_f
            return [], []
        if kind == "BinaryExpression":
            operator = test.get("operator")
            left, right = test.get("left"), test.get("right")
            if operator in {"===", "==", "!==", "!="}:
                if _t(left) == "UnaryExpression" and left.get("operator") == "typeof":
                    literal = _string_value(right)
                    if literal in {"number", "boolean", "bigint"}:
                        entry = [(n, _JS_ALL) for n in _guard_names(left.get("argument"))]
                        return (entry, []) if operator in {"===", "=="} else ([], entry)
                    if literal == "string":
                        # Dize olduğu doğrulanan değer NoSQL işleç nesnesi ({$ne: …}) olamaz.
                        entry = [(n, frozenset({"nosql"})) for n in _guard_names(left.get("argument"))]
                        return (entry, []) if operator in {"===", "=="} else ([], entry)
                    return [], []
                if _t(left) == "CallExpression" and _callee_name(left.get("callee")).endswith(".indexOf") \
                        and _quote_pattern((left.get("arguments") or [None])[0]) and self._const(right) == -1:
                    # x.indexOf("'") === -1: tırnak içermeyen değer XPath değişmezinden taşamaz.
                    owner_names = [(n, frozenset({"xpath"})) for n in _guard_names((left.get("callee") or {}).get("object"))]
                    return (owner_names, []) if operator in {"===", "=="} else ([], owner_names)
                literal_side = right if _string_value(right) is not None or _t(right) in {"NumericLiteral", "BooleanLiteral"} else (
                    left if _string_value(left) is not None or _t(left) in {"NumericLiteral", "BooleanLiteral"} else None)
                if literal_side is not None:
                    other = left if literal_side is right else right
                    entry = [(n, _JS_ALL) for n in _guard_names(other)]
                    if _string_value(literal_side) in _PROTO_KEYS:
                        # key !== '__proto__': eşit değilse prototip anahtarı değildir.
                        differs = [(n, frozenset({"prototype"})) for n in _guard_names(other)]
                        return (entry, differs) if operator in {"===", "=="} else (differs, entry)
                    return (entry, []) if operator in {"===", "=="} else ([], entry)
                if _t(left) == "CallExpression" and _callee_name(left.get("callee")).endswith(".indexOf"):
                    return self._includes_guard(left, negate=(operator in {"===", "=="}))
            if operator == "in" and _is_constant_collection(right):
                return [(n, _JS_ALL) for n in _guard_names(left)], []
            return [], []
        if kind in {"CallExpression", "OptionalCallExpression"}:
            callee = test.get("callee")
            name = _callee_name(callee)
            last = name.rsplit(".", 1)[-1] if name else ""
            args = test.get("arguments") or []
            if last in {"hasOwnProperty", "hasOwn"} and args or name == "Object.prototype.hasOwnProperty.call" and len(args) >= 2:
                # Kendi özelliği olan anahtar '__proto__'/'constructor' olamaz (normal nesnelerde).
                return [(n, frozenset({"prototype"})) for n in _guard_names(args[-1])], []
            if _t(callee) in {"MemberExpression", "OptionalMemberExpression"}:
                owner = callee.get("object")
                if last in {"includes", "has"} and args and _is_constant_collection(owner):
                    entry = [(n, _JS_ALL) for n in _guard_names(args[0])]
                    elements = {_string_value(e) for e in (owner.get("elements") or [])} if _t(owner) == "ArrayExpression" else set()
                    if elements & _PROTO_KEYS:
                        # ['__proto__', 'constructor'].includes(k) yanlışsa k prototip anahtarı değildir.
                        return entry, [(n, frozenset({"prototype"})) for n in _guard_names(args[0])]
                    return entry, []
                if last == "includes" and args and _quote_pattern(args[0]):
                    # x.includes("'") yanlışsa değer tırnak içermez: XPath değişmezinden taşamaz.
                    return [], [(n, frozenset({"xpath"})) for n in _guard_names(owner)]
                if last == "test" and args and _quote_pattern(owner):
                    return [], [(n, frozenset({"xpath"})) for n in _guard_names(args[0])]
                if last == "includes" and args and _string_value(args[0]) in tf._PATH_TRAVERSAL_LITERALS:
                    return [], [(n, frozenset({"path"})) for n in _guard_names(owner)]
                if last == "test" and args and _t(owner) == "RegExpLiteral":
                    pattern = str(owner.get("pattern", ""))
                    if pattern.startswith("^") and pattern.endswith("$"):
                        return [(n, _JS_ALL) for n in _guard_names(args[0])], []
                if last == "startsWith":
                    # Sabit önek ancak ana makineyi sabitliyorsa (https://alan/…, tek '/' ile göreli yol) SSRF/
                    # yönlendirme için güvenlidir; 'http' / 'https://' gibi şema öneki her konağa izin verir.
                    literal = _string_value(args[0]) if args else None
                    kinds = tf._PREFIX_KINDS if literal is None or _FIXED_HOST_PREFIX_RE.match(literal) \
                        else tf._PREFIX_KINDS - {"ssrf", "redirect"}
                    return [(n, kinds) for n in _guard_names(owner)], []
            if name in {"Number.isInteger", "Number.isSafeInteger", "Number.isFinite", "isFinite"} and args:
                return [(n, _JS_ALL) for n in _guard_names(args[0])], []
            if (name.startswith("validator.is") or _JS_VALIDATOR_RE.search(last or "")) and args:
                return [(n, _JS_ALL) for a in args for n in _guard_names(a)], []
        return [], []

    def _includes_guard(self, call: Node, *, negate: bool) -> tuple[tf.Guard, tf.Guard]:
        owner = (call.get("callee") or {}).get("object")
        args = call.get("arguments") or []
        if args and _is_constant_collection(owner):
            entry = [(n, _JS_ALL) for n in _guard_names(args[0])]
            return ([], entry) if negate else (entry, [])
        return [], []

    def _apply_guard(self, entries: tf.Guard) -> None:
        for name, kinds in entries:
            self._clean_name(name, kinds)
            # u = new URL(x) / p = path.resolve(x) doğrulandıysa x de (ve u) yol/SSRF/yönlendirme için doğrulanmıştır.
            root = name.split(".")[0]
            source = self.derived.get(root)
            derived_kinds = kinds & tf._PREFIX_KINDS
            if source and derived_kinds:
                self._clean_name(source, derived_kinds)
                if root != name:
                    self._clean_name(root, derived_kinds)

    def _clean_name(self, name: str, kinds: frozenset[str]) -> None:
        taint = self.env.get(name)
        if taint is None and "." in name:
            # req.query.x gibi doğrudan kaynak üyesi: temizlenmiş hali ortama yazılır.
            taint = self._member_source(name.split("."), 0)
        if taint:
            self.env[name] = tf._clean(taint, kinds)

    # -- atama ----------------------------------------------------------------------
    def assign(self, target: Any, taint: Taint, value: Any = None) -> None:
        kind = _t(target)
        if kind == "Identifier":
            name = target.get("name", "")
            self.env[name] = tf._via(taint, name) if taint else _EMPTY
            self.field_added.pop(name, None)
            self.refs.pop(name, None)
            self._forget(name)
            if value is not None and taint and self._request_object(value):
                self.request_objects.add(name)
            else:
                self.request_objects.discard(name)
            if value is not None and _string_expr(value, self.string_vars, members=self.p.string_request_members()):
                self.string_vars.add(name)
            else:
                self.string_vars.discard(name)
            if value is not None and self._url_safe_node(value):
                self.url_safe.add(name)
                if self._url_abs_node(value):
                    self.url_abs.add(name)
            if value is not None:
                self.kinds[name] = self.p.classify(self.m, value)
            if value is not None:
                self._bind_value(name, value)
                if _is_function(value):
                    self.local_funcs[name] = value
                elif _t(value) == "NewExpression":
                    cls = self.resolve_ref(value.get("callee"))
                    if cls is not None and (cls[0] == "class" or (cls[0] == "func" and cls[2] in cls[1].ctor_functions)):
                        self.refs[name] = ("instance", cls[1], cls[2])
                elif _t(value) in {"Identifier", "MemberExpression", "CallExpression", "AwaitExpression"}:
                    ref = self.resolve_ref(value)
                    if ref is None and _t(value) == "CallExpression" and _dotted(value.get("callee")) == "require":
                        source = self.m._require_source(value)
                        target_module = self.p.module_for(self.m, source[0]) if source else None
                        ref = ("module", target_module, "") if target_module else None
                    if ref is not None:
                        self.refs[name] = ref
        elif kind in {"MemberExpression", "OptionalMemberExpression"}:
            chain = self._cchain(target)
            dotted = ".".join(chain) if chain else ""
            if dotted:
                parts = dotted.split(".")
                root = parts[0]
                self.consts.pop(root, None)
                if root == "this" and self.summary is not None and len(parts) >= 2 and self.qual != "<module>":
                    # this.<alan> = v: çağıranın nesnesine yazılan alan (alan duyarlı özet).
                    self.summary.add_field_write(parts[1], taint if len(parts) == 2 else tf._union(self.env.get(f"this.{parts[1]}", _EMPTY), taint))
                if root in self.lists and len(parts) == 2:
                    items = self.lists[root]
                    index = int(parts[1]) if parts[1].isdigit() else -1
                    if 0 <= index < len(items):
                        items[index] = taint
                    elif index == len(items):
                        items.append(taint)
                    else:
                        self.lists.pop(root, None)
                    if root in self.lists:
                        self.env[root] = tf._union(*items)
                        return
                self.env[dotted] = tf._via(taint, dotted) if taint else _EMPTY
                if taint and root != "this" and root in self.env and root not in self.roots:
                    merged = tf._via(taint, root)
                    if any(part in _URL_LOCAL_PARTS for part in parts[1:]):
                        # url.search = x: yalnız sorgu/parça/yol değişir, hedef ana makine aynı kalır.
                        merged = tf._clean(merged, _URL_TARGET_KINDS)
                    self.env[root] = tf._union(self.env[root], merged)
                    self.field_added.setdefault(root, set()).update(_okey(o) for o in taint)
            else:
                container = _dotted(target.get("object"))
                if container:
                    self.exact.discard(container)
                    self.lists.pop(container, None)
                    self.consts.pop(container.split(".")[0], None)
                if container and taint:
                    self.env[container] = tf._union(self.env.get(container, _EMPTY), tf._via(taint, container))
        elif kind == "ObjectPattern":
            source_member = None
            chain = _chain(value) if value is not None else None
            base_ref = self.resolve_ref(value) if value is not None else None
            for prop in target.get("properties", []):
                if _t(prop) == "RestElement":
                    self.assign(prop.get("argument"), taint)
                    continue
                key = _key_name(prop)
                inner = prop.get("value")
                if key in _LOCATION_APP_STATE and _only_location_hook(taint):
                    self.assign(inner, _EMPTY)
                    continue
                if chain and len(chain) == 1 and chain[0] in self.prop_roots and key:
                    self.assign(inner, (tf._Origin(_PROP, key, _line(prop), (), frozenset(), self.m.relpath),))
                    continue
                if chain and key and not taint:
                    source_member = self._member_source(chain + [key], _line(prop))
                if source_member:
                    self.assign(inner, source_member)
                    source_member = None
                else:
                    self.assign(inner, taint)
                if base_ref is not None and key and _t(inner) == "Identifier":
                    member_ref = self.p.member(base_ref, key)
                    if member_ref is not None:
                        self.refs[inner.get("name", "")] = member_ref
                if _t(inner) == "Identifier" and chain and len(chain) == 2 and chain[0] in _REQUEST_ROOTS \
                        and chain[1] in self.p.string_request_members() and self.env.get(inner.get("name", "")):
                    # const { x } = req.query: req.query.x gibi dize alanı (res.send(x) → text/html).
                    self.string_vars.add(inner.get("name", ""))
        elif kind == "ArrayPattern":
            for element in target.get("elements", []):
                if element:
                    self.assign(element, taint)
        elif kind == "AssignmentPattern":
            self.assign(target.get("left"), tf._union(taint, self.expr(target.get("right"))))
        elif kind == "RestElement":
            self.assign(target.get("argument"), taint)

    def _forget(self, name: str) -> None:
        """Ada yeni değer atandı: eski alan/öğe/sabit/türetme bilgisi geçersiz."""
        self.consts.pop(name, None)
        self.exact.discard(name)
        self.lists.pop(name, None)
        self.derived.pop(name, None)
        self.ctors.pop(name, None)
        self.url_safe.discard(name)
        self.url_abs.discard(name)
        self.kinds.pop(name, None)
        prefix = name + "."
        stale = [key for key in self.env if key.startswith(prefix)]
        for key in stale:
            del self.env[key]
        if self.exact:
            self.exact = {key for key in self.exact if not key.startswith(prefix)}

    def _bind_shape(self, prefix: str, value: Any) -> None:
        shape = self.shapes.get(id(value))
        if isinstance(shape, dict) and _t(value) == "ObjectExpression":
            self.exact.add(prefix)
            nodes = {_key_name(p): p.get("value") for p in value.get("properties", []) if _t(p) == "ObjectProperty"}
            for key, taint in shape.items():
                self.env[f"{prefix}.{key}"] = tf._via(taint, prefix) if taint else _EMPTY
                if key in nodes and prefix.count(".") < 4:
                    self._bind_shape(f"{prefix}.{key}", nodes[key])

    def _bind_value(self, name: str, value: Any) -> None:
        """Atanan değerin biçimi: nesne alanları, dizi öğeleri, Map, örnek alanları, türetme, fabrika sınıfı."""
        if _t(value) in {"AwaitExpression", "TSAsExpression", "TSNonNullExpression", "ParenthesizedExpression"}:
            value = value.get("argument") or value.get("expression")
        kind = _t(value)
        if kind == "ObjectExpression":
            self._bind_shape(name, value)
        elif kind == "ArrayExpression":
            shape = self.shapes.get(id(value))
            if isinstance(shape, list):
                self.lists[name] = list(shape)
        elif kind in {"NewExpression", "CallExpression"}:
            callee_name = _callee_name(value.get("callee"))
            canonical = self.canonical(callee_name)
            args = value.get("arguments") or []
            fields = self.call_fields.get(id(value))
            if fields is not None:
                for field, taint in fields.items():
                    self.env[f"{name}.{field}"] = taint
            ref = self.call_refs.get(id(value))
            if ref is not None:
                self.refs[name] = ref
            if kind == "NewExpression" and callee_name:
                self.ctors[name] = callee_name
                copied_request = self._request_copy_input(value)
                if copied_request is not None and self._request_receiver(copied_request) is not None:
                    self.ctors[name] = "request"
                if callee_name in {"Map", "WeakMap"}:
                    self.exact.add(name)
                    entries = args[0] if args else None
                    if _t(entries) == "ArrayExpression":
                        for entry in entries.get("elements") or []:
                            pair = (entry or {}).get("elements") or []
                            key = _const_key(self._const(pair[0])) if len(pair) == 2 else None
                            if key is None:
                                self.exact.discard(name)
                                break
                            self.env[f"{name}.{key}"] = self.expr(pair[1])
            if kind == "CallExpression" and not args and callee_name.rsplit(".", 1)[-1] == "clone":
                owner = self._request_receiver((value.get("callee") or {}).get("object"))
                if owner is not None:
                    self.ctors[name] = "request"
            imported_root = callee_name.split(".", 1)[0]
            if self._secondary_store_factory(value):
                self.ctors[name] = "secondary_store"
            elif self.ctors.get(imported_root) == "secondary_store" and \
                    callee_name.rsplit(".", 1)[-1] in {"createChannel", "channel", "duplicate"}:
                # Store clients often return another handle before the actual
                # consume/read call (amqplib connection -> channel, Redis
                # client -> duplicate). Preserve the package-backed identity.
                self.ctors[name] = "secondary_store"
            if kind == "CallExpression" and canonical in {"dompurify", "dompurify.default"}:
                self.ctors[name] = "dompurify"
            if kind == "CallExpression" and canonical == "axios.create" and args and _t(args[0]) == "ObjectExpression" and any(
                    _t(p) == "ObjectProperty" and _key_name(p) == "baseURL" and self._fixed_base(p.get("value"))
                    for p in args[0].get("properties", [])):
                self.ctors[name] = "axios_fixed_base"
            elif kind == "NewExpression" and callee_name in {"URL", "url.URL"} and len(args) >= 2 and self._fixed_base(args[1]):
                self.ctors[name] = "url_fixed_base"
            if canonical.endswith("createClient") and "ldap" in canonical.lower():
                self.ctors[name] = "ldap"
            elif callee_name.rsplit(".", 1)[-1] in {"collection", "getCollection"} or callee_name.endswith(".model"):
                self.ctors[name] = "collection"
            elif kind == "CallExpression" and self._query_builder(value):
                self.ctors[name] = "querybuilder"
            derived = ("new " + canonical) if kind == "NewExpression" else canonical
            if (derived in _DERIVING_CALLS or callee_name in _DERIVING_CALLS) and args:
                source = args[-1] if canonical.startswith("path.") or "join" in canonical else args[0]
                source_name = _dotted(source)
                if source_name and "()" not in source_name:
                    self.derived[name] = source_name

    # -- deyimler -------------------------------------------------------------------
    @staticmethod
    def _merge(envs: list[dict[str, Taint]]) -> dict[str, Taint]:
        merged: dict[str, Taint] = {}
        for env in envs:
            for key, value in env.items():
                merged[key] = tf._union(merged.get(key, _EMPTY), value)
        return merged

    def _branches(self, items: list[tuple[Any, tf.Guard]]) -> None:
        start = self._snapshot()
        start_safe = set(self.url_safe)
        start_non_html = set(self.non_html)
        results = []
        for body, guard in items:
            self._restore(start)
            self.url_safe = set(start_safe)
            self.non_html = set(start_non_html)
            self._apply_guard(guard)
            if body is not None:
                self.stmt(body)
            results.append((self._snapshot(), body is not None and _terminates(body), set(self.url_safe), set(self.non_html)))
        live_types = [types for _, terminated, _, types in results if not terminated] or [types for *_, types in results]
        # HTML dışı içerik türü yalnız tüm canlı dallarda atandıysa geçerli (sonlanan dalın res.json()'u taşınmaz).
        self.non_html = set.intersection(*live_types) if live_types else start_non_html
        results = [(state, terminated, safe) for state, terminated, safe, _ in results]
        live = [(state, safe) for state, terminated, safe in results if not terminated] or [(state, safe) for state, _, safe in results]
        self._merge_states([state for state, _ in live])
        # Güvenli önek bilgisi yalnız tüm canlı dallarda geçerliyse korunur.
        self.url_safe = set.intersection(*(safe for _, safe in live))
        self.url_abs &= self.url_safe

    def block(self, statements: list[Any], *, top: bool = False) -> None:
        for statement in statements:
            if _t(statement) == "FunctionDeclaration" and statement.get("id") and not top:
                self.local_funcs[statement["id"].get("name", "")] = statement
        for statement in statements:
            self.stmt(statement, top=top)

    def _loop(self, body: Any, before_each: Any = None, scope: Any = None) -> None:
        # Döngüde değişen adlar: sabit/öğe/alan bilgisi döngü boyunca geçerli değildir.
        for name in _assigned_names(scope if scope is not None else body):
            self.consts.pop(name, None)
            self.lists.pop(name, None)
            self.exact.discard(name)
        # Sabit noktaya kadar (sınırlı) yineleme: döngüde taşınan değerler (d = c; c = b; b = x) ve
        # öğe/alan kapları; iç içe döngülerde maliyet için tur sayısı azalır.
        self.loop_depth += 1
        try:
            for _ in range(max(2, 6 - 2 * self.loop_depth)):
                before = (dict(self.env), {k: list(v) for k, v in self.lists.items()})
                if before_each is not None:
                    before_each()
                self._branches([(body, []), (None, [])])
                if (self.env, self.lists) == before:
                    break
        finally:
            self.loop_depth -= 1

    def stmt(self, node: Any, *, top: bool = False) -> None:
        if not isinstance(node, dict):
            return
        self.p.tick()
        kind = _t(node)
        if kind == "ExpressionStatement":
            self.expr(node.get("expression"))
        elif kind == "VariableDeclaration":
            for declarator in node.get("declarations", []):
                init = declarator.get("init")
                target = declarator.get("id")
                taint = self.expr(init) if init is not None else _EMPTY
                self.assign(target, taint, init)
                if _t(target) == "Identifier":
                    name = target.get("name", "")
                    if node.get("kind") == "const" and init is not None:
                        self.callback_aliases[name] = init
                    else:
                        self.callback_aliases.pop(name, None)
                    imported = self.m._require_source(init) if init is not None and not top else None
                    if imported is not None:
                        self.local_imports[name] = imported
                        if node.get("kind") == "const":
                            self.immutable_local_imports.add(name)
                        else:
                            self.immutable_local_imports.discard(name)
                    else:
                        self.local_imports.pop(name, None)
                        self.immutable_local_imports.discard(name)
                    if init is not None and name not in self.unstable:
                        value = self._const(init)
                        if value is not _UNKNOWN:
                            self.consts[name] = value
                    type_name = target.get("tn") or (init.get("tn") if _t(init) in {"TSAsExpression", "TSTypeAssertion"} else None)
                    typed = self.p.type_ref(self.m, type_name)
                    if typed is not None:
                        self.refs[name] = typed
                    hinted = self.p.type_kind(type_name)
                    if hinted is not None:
                        self.kinds[name] = hinted
                    elif init is None:
                        self.kinds[name] = None
                elif _t(target) == "ObjectPattern":
                    imported = self.m._require_source(init) if init is not None and not top else None
                    for prop in target.get("properties", []):
                        if _t(prop) != "ObjectProperty" or _t(prop.get("value")) != "Identifier":
                            continue
                        name = prop["value"].get("name", "")
                        if imported is not None and imported[1] == "*":
                            self.local_imports[name] = (imported[0], _key_name(prop))
                            if node.get("kind") == "const":
                                self.immutable_local_imports.add(name)
                            else:
                                self.immutable_local_imports.discard(name)
                        else:
                            self.local_imports.pop(name, None)
                            self.immutable_local_imports.discard(name)
        elif kind == "ReturnStatement":
            self._return(self.expr(node.get("argument")), node.get("argument"))
        elif kind == "IfStatement":
            test = self._const(node.get("test"))
            if test is not _UNKNOWN:
                # Ölü dal budama: sabit koşulda yalnız seçilen dal çalışır.
                branch = node.get("consequent") if _js_truthy(test) else node.get("alternate")
                if branch is not None:
                    self.stmt(branch)
                return
            self.expr(node.get("test"))
            when_true, when_false = self._guard(node.get("test"))
            self._branches([(node.get("consequent"), when_true), (node.get("alternate"), when_false)])
        elif kind == "BlockStatement":
            self.block(node.get("body", []))
        elif kind in {"ForOfStatement", "ForInStatement"}:
            right = node.get("right")
            iterable = self.expr(right)
            request_root = self._request_stream_root(right)
            if kind == "ForOfStatement" and node.get("await") is True and request_root is not None and not iterable:
                iterable = self._source(f"{request_root}.asyncIterator", _line(right))
            left = node.get("left")
            target = (left.get("declarations") or [{}])[0].get("id") if _t(left) == "VariableDeclaration" else left
            self._loop(node.get("body"), lambda: self.assign(target, iterable), node)
        elif kind == "ForStatement":
            if node.get("init") is not None:
                (self.stmt if _t(node["init"]) == "VariableDeclaration" else self.expr)(node["init"])
            self._loop(node.get("body"), lambda: (self.expr(node.get("test")), self.expr(node.get("update"))), node)
        elif kind in {"WhileStatement", "DoWhileStatement"}:
            if kind == "WhileStatement" and self._const(node.get("test")) is not _UNKNOWN and not _js_truthy(self._const(node.get("test"))):
                return
            self._loop(node.get("body"), lambda: self.expr(node.get("test")), node)
        elif kind == "SwitchStatement":
            self._switch(node)
        elif kind == "TryStatement":
            self.stmt(node.get("block"))
            handler = node.get("handler") or {}
            self._branches([(handler.get("body"), []), (None, [])])
            if node.get("finalizer"):
                self.stmt(node["finalizer"])
        elif kind == "ThrowStatement":
            self.expr(node.get("argument"))
        elif kind == "LabeledStatement":
            self.stmt(node.get("body"))
        elif kind == "FunctionDeclaration":
            if not top and node.get("id"):
                name = node["id"].get("name", "")
                self.local_funcs[name] = node
                self.p.extra.append((self.m, f"{self.qual}.<locals>.{name}", node, self.class_name, dict(self.env), dict(self.refs)))
        elif kind in {"ClassDeclaration", "ImportDeclaration", "ExportAllDeclaration", "EmptyStatement", "DebuggerStatement"}:
            if kind == "ClassDeclaration" and not top:
                for member in (node.get("body") or {}).get("body", []):
                    if _is_function(member) or _is_function(member.get("value")):
                        fn = member if _is_function(member) else member["value"]
                        self.p.extra.append((self.m, f"{self.qual}.<locals>.class.{_key_name(member)}", fn, None, {}, dict(self.refs)))
        elif kind == "ExportNamedDeclaration":
            if node.get("declaration"):
                self.stmt(node["declaration"], top=top)
        elif kind == "ExportDefaultDeclaration":
            declaration = node.get("declaration") or {}
            if _t(declaration) not in {"FunctionDeclaration", "ClassDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ClassExpression"}:
                self.expr(declaration)
        elif kind == "TSExportAssignment":
            self.expr(node.get("expression"))
        elif kind in {"TSModuleDeclaration", "TSEnumDeclaration", "TSImportEqualsDeclaration"}:
            return
        else:
            for child in _children(node):
                if _t(child).endswith(("Statement", "Declaration")):
                    self.stmt(child)
                else:
                    self.expr(child)

    def _request_stream_root(self, node: Any) -> str | None:
        """Resolve a bounded chain of immutable local aliases to a request root."""
        current = node
        for _ in range(4):
            if _t(current) not in {"TSNonNullExpression", "TSAsExpression", "TSTypeAssertion", "TypeCastExpression"}:
                break
            current = current.get("expression")
        if _t(current) in {"MemberExpression", "OptionalMemberExpression"} \
                and _callee_name(current).rsplit(".", 1)[-1] == "body":
            owner = self._request_receiver(current.get("object"))
            if owner is not None:
                return owner
        seen: set[str] = set()
        for _ in range(8):
            if _t(current) != "Identifier":
                return None
            name = current.get("name", "")
            if name in self.roots:
                return name
            if not name or name in seen:
                return None
            seen.add(name)
            current = self.callback_aliases.get(name)
        return None

    def _request_receiver(self, node: Any) -> str | None:
        """Recognize a request identifier, copy constructor, or bounded clone chain."""
        current = node
        for _ in range(8):
            if _t(current) == "Identifier":
                name = current.get("name", "")
                return name if name in self.roots or self.ctors.get(name) == "request" else None
            if _t(current) == "NewExpression" and self._platform_request_constructor(current):
                copied_request = self._request_copy_input(current)
                if copied_request is None:
                    return None
                current = copied_request
                continue
            if _t(current) != "CallExpression" or current.get("arguments"):
                return None
            callee = current.get("callee")
            if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"} \
                    or _callee_name(callee).rsplit(".", 1)[-1] != "clone":
                return None
            current = callee.get("object")
        return None

    def _platform_request_constructor(self, node: Any) -> bool:
        """True for the unshadowed Fetch Request constructor."""
        if _t(node) != "NewExpression":
            return False
        name = _callee_name(node.get("callee"))
        if name == "globalThis.Request":
            return "globalThis" not in self.env
        if name != "Request":
            return False
        return not any((
            "Request" in self.env,
            "Request" in self.local_funcs,
            "Request" in self.m.functions,
            "Request" in self.m.classes,
            "Request" in self.m.imports,
            "Request" in self.m.values,
        ))

    def _request_copy_input(self, node: Any) -> Any | None:
        """Return the copied request when static options cannot replace its body."""
        if not self._platform_request_constructor(node):
            return None
        args = node.get("arguments") or []
        if len(args) == 1:
            return args[0]
        if len(args) != 2 or _t(args[1]) != "ObjectExpression":
            return None
        properties = args[1].get("properties") or []
        for prop in properties:
            key = _key_name(prop) if _t(prop) == "ObjectProperty" else ""
            if not key:
                return None
            if key != "body":
                continue
            value = prop.get("value")
            static_void = _t(value) == "UnaryExpression" and value.get("operator") == "void"
            global_undefined = _t(value) == "Identifier" and value.get("name") == "undefined" and not any((
                "undefined" in self.env,
                "undefined" in self.local_funcs,
                "undefined" in self.m.functions,
                "undefined" in self.m.classes,
                "undefined" in self.m.imports,
                "undefined" in self.m.values,
            ))
            if not (static_void or global_undefined):
                return None
        return args[0]


    def _switch(self, node: Node) -> None:
        cases = node.get("cases", [])
        discriminant = self._const(node.get("discriminant"))
        tests = [self._const(case["test"]) if case.get("test") is not None else None for case in cases]

        def run_from(index: int) -> dict[str, Any]:
            statements: list[Any] = []
            for case in cases[index:]:
                body = case.get("consequent", [])
                statements.extend(item for item in body if _t(item) != "BreakStatement")
                block = {"type": "BlockStatement", "body": body}
                if body and (_terminates(block) or any(_t(item) == "BreakStatement" for item in body)):
                    break
            return {"type": "BlockStatement", "body": statements}

        if discriminant is not _UNKNOWN and all(t is not _UNKNOWN for t in tests):
            # Sabit switch: yalnız eşleşen (ya da default) durum ve düşüşleri çalışır.
            start = next((i for i, (case, test) in enumerate(zip(cases, tests))
                          if case.get("test") is not None and _js_strict_eq(test, discriminant)), None)
            if start is None:
                start = next((i for i, case in enumerate(cases) if case.get("test") is None), None)
            if start is not None:
                self.stmt(run_from(start))
            return
        self.expr(node.get("discriminant"))
        branches: list[tuple[Any, tf.Guard]] = [(run_from(i), []) for i in range(len(cases))]
        if not any(case.get("test") is None for case in cases):
            branches.append((None, []))
        self._branches(branches or [(None, [])])


# Kod çözücüler: önceki içerik denetimini geçersiz kılar ('%2e%2e%2f' denetimden sonra '../' olur).
_DECODERS = frozenset({"decodeURIComponent", "decodeURI", "unescape", "querystring.unescape", "qs.unescape"})
_DECODE_REOPEN_KINDS = frozenset({"path", "html", "xpath"})


def _reopen(taint: Taint, kinds: frozenset[str]) -> Taint:
    """Kod çözme sonrası: içerik denetimiyle temizlenmiş türleri yeniden kirli say (sayısal/zayıf kökenler hariç)."""
    return tuple(o if o.label == _WEAK else tf._Origin(o.label, o.source, o.line, o.via, o.cleaned - kinds, o.file) for o in taint)


# jQuery öğe nesneleri (W2-XSS): $('<a/>', {href: x}) ve $(…).attr('href', x).text(y) gibi ayarlayıcı zincirleri
# HTML dizgesi değil DOM öğesi üretir; öğenin append/prepend/html ile eklenmesi HTML ayrıştırması yapmaz. Değer
# "html" için temiz sayılır ve §jqel işaretlenir; .text()/.html()/.val()/.attr(ad) okuyucuları işareti geri açar.
_JQEL = "§jqel"
_JQ_ELEMENT_CLEAN = frozenset({"html", _JQEL})
_JQ_ELEMENT_METHODS = frozenset({
    "attr", "attr2", "prop", "text", "val", "css", "data", "addClass", "removeClass", "toggleClass", "removeAttr",
    "removeProp", "show", "hide", "toggle", "append", "prepend", "after", "before", "appendTo", "prependTo",
    "insertAfter", "insertBefore", "html", "empty", "on", "off", "one", "find", "children", "parent", "parents",
    "closest", "siblings", "eq", "first", "last", "filter", "not", "each", "wrap", "click", "focus", "trigger",
})
_JQ_GETTERS_0 = frozenset({"text", "html", "val"})
_JQ_GETTERS_1 = frozenset({"attr", "attr2", "prop", "data", "css"})


def _jq_reopen(taint: Taint) -> Taint:
    """Öğe okuyucusu (.text()/.attr(ad)…): yalnız öğe işaretiyle temizlenmiş kökenlerde "html"i geri aç."""
    return tuple(tf._Origin(o.label, o.source, o.line, o.via, o.cleaned - _JQ_ELEMENT_CLEAN, o.file)
                 if _JQEL in o.cleaned else o for o in taint)


def _jq_chain(name: str) -> bool:
    return name.startswith(("$().", "jQuery().")) or (")." in name and name.split("().")[0] in {"$", "jQuery"})


def _html_literal_start(node: Any) -> bool:
    """$('<li class="x"/>') / $(`<a></a>`): ilk bağımsız değişken '<' ile başlayan sabit (ifade içermeyen) dizge."""
    if _t(node) == "StringLiteral":
        return str(node.get("value", "")).lstrip().startswith("<")
    if _t(node) == "TemplateLiteral" and not node.get("expressions"):
        quasis = node.get("quasis") or []
        return bool(quasis) and str(((quasis[0].get("value") or {}).get("cooked")) or "").lstrip().startswith("<")
    return False


def _selector_only(node: Any) -> bool:
    """$('#' + x) / $(`.c-${x}`): sabit, '<' ile başlamayan bir önekle başlayan dizge jQuery ≥1.9'da HTML olarak
    ayrıştırılmaz (yalnız '<' ile başlayan dizge HTML'dir) → seçici; XSS hedefi değil."""
    current = node
    while _t(current) == "BinaryExpression" and current.get("operator") == "+":
        current = current.get("left")
    if _t(current) == "StringLiteral" and current is not node:
        text = str(current.get("value", "")).lstrip()
        return bool(text) and not text.startswith("<")
    if _t(node) == "TemplateLiteral" and node.get("expressions"):
        quasis = node.get("quasis") or []
        text = str(((quasis[0].get("value") or {}).get("cooked")) or "").lstrip() if quasis else ""
        return bool(text) and not text.startswith("<")
    return False


def _content_type_params(fn: Any, cache: dict[int, tuple[Any, dict[int, bool]]] | None = None) -> dict[int, bool]:
    """Yardımcı işlev içerik türü atıyor mu? function asJson(res) { res.set('Content-Type', 'application/json') }:
    parametre indeksi → karar (True: HTML dışı). Yalnız gövdenin koşulsuz üst düzey deyimleri sayılır (W2-XSS)."""
    key = id(fn)
    cache = cache if cache is not None else {}
    cached = cache.get(key)
    if cached is not None and cached[0] is fn:
        return cached[1]
    params = {p.get("name", ""): i for i, p in enumerate(fn.get("params") or []) if _t(p) == "Identifier"}
    body = fn.get("body")
    out: dict[int, bool] = {}
    if params and _t(body) == "BlockStatement":
        for statement in body.get("body") or []:
            expr = statement.get("expression") if _t(statement) == "ExpressionStatement" else None
            if _t(expr) != "CallExpression":
                continue
            callee = expr.get("callee")
            if _t(callee) not in {"MemberExpression", "OptionalMemberExpression"} or callee.get("computed"):
                continue
            method = (callee.get("property") or {}).get("name", "")
            root = callee.get("object")
            while _t(root) == "CallExpression" and _t(root.get("callee")) in {"MemberExpression", "OptionalMemberExpression"}:
                root = root["callee"].get("object")  # res.status(200).type('json')
            if _t(root) != "Identifier" or root.get("name") not in params or method not in _CONTENT_TYPE_SETTERS:
                continue
            verdict = JsScope._content_type_verdict(method, expr.get("arguments") or [])
            if verdict is not None:
                out[params[root["name"]]] = verdict
    cache[key] = (fn, out)
    return out


def _okey(origin: Any) -> tuple:
    return (origin.label, origin.source, origin.line, origin.file)


def _weak(taint: Taint) -> Taint:
    """Yalnız zayıf rastgele kökenleri (sayısal dönüşümden geçse de) koru."""
    return tuple(o for o in taint if o.label == _WEAK)


# ---------------------------------------------------------------------------
# Giriş noktaları
# ---------------------------------------------------------------------------

_FILE_STEPS = 400_000
_STEPS_PER_PROJECT_FILE = 60_000


class ParsedPrograms(dict[str, Node]):
    """AST programları ve proje ayrıştırma kapsamı."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.analysis_complete = True
        self.limitations: tuple[str, ...] = ()

    def mark_incomplete(self, *limitations: str) -> "ParsedPrograms":
        self.analysis_complete = False
        self.limitations = tuple(dict.fromkeys((*self.limitations, *(x for x in limitations if x))))
        return self


def analyze_programs(programs: dict[str, Node], *, pii: tf.PiiClassifier | None = None,
                     handler_names: frozenset[str] = frozenset(),
                     templates: dict[str, str] | None = None,
                     sanitizer_versions: dict[str, bool] | None = None,
                     sanitizer_version_scopes: dict[str, dict[str, bool]] | None = None,
                     ) -> dict[str, tf.Analysis] | None:
    project = JsProject(
        pii,
        max_steps=min(8_000_000, _FILE_STEPS + _STEPS_PER_PROJECT_FILE * len(programs)),
        handler_names=handler_names,
    )
    project.sanitizer_versions = dict(sanitizer_versions or {})
    project.sanitizer_version_scopes = {
        scope: dict(versions) for scope, versions in (sanitizer_version_scopes or {}).items()
    }
    project.templates = templates
    if templates is None:
        state = tf._PROJECT.get()
        # Proje taraması: Angular templateUrl dosyaları doğrulanmış kök içinden okunur.
        project.template_root = getattr(state, "root", None)
    for relpath, program in programs.items():
        project.add_module(relpath, program)
    try:
        project.run()
    except RecursionError:
        return None
    _resolve_stored_sends(project)
    return {relpath: project.analysis_for(relpath) for relpath in project.modules}


def _resolve_stored_sends(project: "JsProject") -> None:
    """25. tur: res.send(kayit.alan) adayları — alan projede istek verisiyle yazılıyorsa (yazma kanıtı) kayıtlı XSS;
    kimlik/sayı/tarih alanları ve kanıtsız alanlar raporlanmaz."""
    for relpath, line, sink, attr, stored in project.pending_stored_sends:
        site = project.user_written_attrs.get(attr)
        if site is None or tf._PY_CLEAN_COLUMN_RE.search(attr) or re.search(r"(?:Id|At|Date|Count)$", attr):
            continue
        for origin in stored[:1]:
            project.add_flow(tf.Flow(
                "javascript", "html", sink, line,
                f"{origin.source}.{attr} ({tf.USER_WRITTEN_FIELD_MARK}: {attr}; yazıldığı yer: {site[0]}:{site[1]})",
                "stored", origin.line, origin.via, relpath, origin.file,
            ))


def parse_files(files: dict[str, str], *, budget: float = PROJECT_PARSE_BUDGET) -> ParsedPrograms:
    """Dosyaları tek Node sürecinde ayrıştır; ayrıştırılamayanlar sonuçta yer almaz."""
    programs = ParsedPrograms()
    deadline = time.monotonic() + budget
    if budget <= 0:
        return programs.mark_incomplete("parse-budget")
    with NodeParser() as parser:
        for relpath, text in files.items():
            if not relpath.lower().endswith(_JS_EXTENSIONS):
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                programs.mark_incomplete("parse-budget")
                break
            program = parser.parse(relpath, text, timeout=min(PARSE_TIMEOUT, remaining))
            missing = text.count("{") - text.count("}")
            if program is None and 0 < missing <= 3 and time.monotonic() < deadline:
                # Kesilmiş parça (kod parçacığı/eksik kapanış): eksik süslü parantezlerle bir kez daha dene.
                program = parser.parse(relpath, text + "\n}" * missing, timeout=min(PARSE_TIMEOUT, max(0.1, deadline - time.monotonic())))
            if program is not None:
                programs[relpath] = program
    return programs


def analyze_files(files: dict[str, str], *, pii: tf.PiiClassifier | None = None,
                  handler_names: frozenset[str] = frozenset(),
                  templates: dict[str, str] | None = None) -> dict[str, tf.Analysis] | None:
    """{göreli yol: kaynak} → {göreli yol: Analysis}; Node yoksa JsParserUnavailable.

    ``templates``: Angular şablonları ({göreli yol: metin}); verilmezse etkin proje kökünden okunur."""
    scopes = _javascript_sanitizer_version_scopes(files)
    versions = scopes.get("", {})
    programs = parse_files(files)
    results = analyze_programs(
        programs, pii=pii, handler_names=handler_names, templates=templates,
        sanitizer_versions=versions, sanitizer_version_scopes=scopes,
    )
    if results is not None and not programs.analysis_complete:
        for relpath in sorted(path for path in files if path.lower().endswith(_JS_EXTENSIONS)):
            results.setdefault(relpath, tf.Analysis(language="javascript")) \
                .mark_incomplete(*programs.limitations)
    return results
