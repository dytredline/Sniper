"""Rota yetki envanteri: eksik yetki denetimi (CWE-862) ve nesne düzeyi yetki / IDOR adayları (CWE-639).

Yalnız statik analiz. Python (Flask, FastAPI, Django, DRF) için ``ast``; JavaScript/TypeScript (Express, Koa,
NestJS) için taint motorunun JS sözcük çözümleyicisi; Ruby/Rails için route/controller yapısına bağlı dar bir
satır çözümleyici; Spring ve ASP.NET için yalnız literal controller/minimal-route sözleşmelerini kabul eden
fail-closed çözümleyici kullanılır. Kesinlik önceliklidir:

* Korumasız hassas rota yalnız aynı uygulamada (üst dizin + dil) rotaların çoğunluğu korunuyorsa raporlanır;
  tamamen açık API'lerde (kimlik doğrulama ağ geçidinde olabilir) gürültü yapılmaz.
* IDOR adayı, kayıt istekteki kimlikle aranıp işleyicide geçerli kullanıcıya (request.user, current_user, req.user …)
  hiç başvurulmuyorsa ve yönetici denetimi yoksa raporlanır; bulgular "gözden geçirme" niteliğindedir.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
from typing import Any, Iterable
import warnings

import authz_jvm_dotnet
from rails_authz_inheritance import analyze_rails_controller_inheritance

PY_SUFFIXES = (".py",)
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
RUBY_SUFFIXES = (".rb",)
JAVA_SUFFIXES = (".java",)
CSHARP_SUFFIXES = (".cs",)
MAX_ROUTES_REPORTED = 300
MAX_SOURCE_BYTES = 1_000_000

MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Kimlik doğrulama / yetki dekoratörü, bağımlılığı ya da ara katman adı.
_AUTH_NAME_RE = re.compile(
    r"(?i)(auth|login|logged|signed_?in|jwt|token|passport|session_?user|guard|verif(?:y|ied)_?(user|token|jwt|session|admin|role)"
    r"|permission|role|admin|staff|superuser|ensure|is_?user|acl|authori[sz]|restrict|private|protect|require_?user"
    r"|current_?user|check_?user|get_?user(?:_?id)?|user_?id|get_?request_?context|is_?member|is_?owner"
    r"|user_passes_test|requires?_|access_?required|api_?key|principal|identity|scim_?auth"
    r"|allows\.requires|moderator|IsAtleast|has_?access)"
)
# Kimlikle ilgisiz ara katmanlar (adında "protect", "token" geçse bile).
_NOT_AUTH_RE = re.compile(r"(?i)(csrf|xsrf|rate|limit|upload|multer|valid|cors|parser|helmet|compress|static|cache|logger|morgan|i18n)")
# Bilerek açık bırakılmış rota.
_PUBLIC_MARK_RE = re.compile(r"(?i)^(public|allow_?any|allow_?anonymous|login_not_required|skip_?auth|no_?auth|anonymous)")
# Kimlik doğrulama uçları ve olağan açık yollar: korumasız olmaları beklenir.
_PUBLIC_PATH_RE = re.compile(
    r"(?i)(log_?in|log_?out|sign_?(in|up|out|on)|register|auth|token|oauth|sso|saml|callback|webhook|health|status"
    r"|ping|metrics|public|forgot|reset|password|passwd|verify|confirm|activat|csrf|captcha|static|assets|favicon"
    r"|robots|docs|openapi|swagger|graphql|signup|join|contact|subscribe|feedback|newsletter|unsubscribe|ws$|socket"
    r"|hook|(^|/)bot(/|$)|badge|preview|embed|(^|/)(api_?)?keys?/?$|keygen)"
)
_PRIVATE_RESOURCE_RE = re.compile(
    r"(?i)(user|account|profile|order|invoice|payment|message|inbox|note|file|document|address|card|wallet|ticket|booking"
    r"|cart|transaction|receipt|bank|balance|salary|medical|record|secret|token|key|setting|private|draft|task|project|report"
    r"|subscription|billing|payout|refund|webhook|api_key|apikey|credential|tenant|organization|workspace|member|audit|backup"
    r"|prompt|conversation|thread|session|kyc|iban|patient)"
)
_READ_POST_RE = re.compile(r"(?i)(search|filter|query|lookup|find|list|preview|export|report)")
_ADMIN_PATH_RE = re.compile(
    r"(?i)(^|/)(admin|manage|management|internal|debug|console|superuser|staff|backoffice|ops"
    r"|actuator|pprof|phpmyadmin|adminer|impersonate|sudo|feature_flag|migration)(/|$|[-_])"
)
_ID_NAME_RE = re.compile(r"(?i)(^(id|pk|uuid|guid|oid)$|_id$|_pk$|_uuid$|[a-z0-9]Id$|^id_)")
_ADMIN_CHECK_RE = re.compile(r"(?i)(is_?admin|is_?staff|is_?superuser|has_?perm|has_?role|\brole\b|\broles\b|permission(?!_classes)|isAdmin|is_?owner|can_?(edit|view|delete|access))")

# Python: işleyicide geçerli kullanıcıya başvuru (sahiplik bağlaması olabilir).
_PY_USER_REF_RE = re.compile(
    r"(request\.user|self\.request\.user|current_user|g\.user|get_jwt_identity|get_current_user|current_identity"
    r"|session\s*\[\s*['\"](user|uid|user_id|userid|username|account|login)|session\.get\(\s*['\"](user|uid|user_id|userid|username|account|login)"
    r"|request\.auth\b|info\.context\.user|\buser\s*:\s*\w+\s*=\s*Depends)"
)
# Python: işleyici içi kimlik doğrulama denetimi.
_PY_INLINE_AUTH_RE = re.compile(
    r"(is_authenticated|is_anonymous|current_user|request\.user|g\.user|verify_jwt_in_request|get_jwt_identity|login_url"
    r"|abort\(\s*40[13]|PermissionDenied|status_code\s*=\s*40[13]|HTTP_40[13]|redirect\([^)]*login"
    r"|session\s*\[\s*['\"](user|uid|user_id|userid|username|logged_in|loggedin|login|auth)"
    r"|session\.get\(\s*['\"](user|uid|user_id|userid|username|logged_in|loggedin|login|auth)|check_auth|require_login"
    r"|\bauthenticate\w*\(|\b_?authori[sz]e\w*\("
    r"|\b(?:check|verify|require|ensure|assert)_?(?:permission|auth|access|role|member|owner)\w*\("
    r"|return\s[^\n]*\b40[13]\b)"
)
_PY_ROUTE_ATTRS = frozenset({"get", "post", "put", "patch", "delete", "route", "api_route"})
_PY_LOOKUP_ATTRS = frozenset({
    "get", "filter", "filter_by", "get_or_404", "first_or_404", "get_object_or_404", "get_list_or_404", "exclude",
    "find_one", "find", "find_one_and_update", "find_one_and_delete", "delete_one", "update_one", "replace_one",
    "execute", "raw", "select", "update", "delete", "where",
    "scalar", "scalars", "one_or_none", "scalar_one", "scalar_one_or_none", "get_one", "get_or_none", "fetchrow", "fetchval",
})
_PY_STRICT_RECEIVER = frozenset({"get", "filter", "exclude", "select", "update", "delete", "where"})
_DJANGO_CBV_OBJECT_BASES = re.compile(r"(DetailView|UpdateView|DeleteView|RetrieveAPIView|RetrieveUpdateAPIView|RetrieveDestroyAPIView|RetrieveUpdateDestroyAPIView|UpdateAPIView|DestroyAPIView|ModelViewSet|ReadOnlyModelViewSet|GenericViewSet)$")
_CLASS_PERMISSION_SIGNAL_RE = re.compile(
    r"\b(permission_policy|permission_required|any_permission_required|required_permission|get_permission_required"
    r"|has_permission|check_permissions?|test_func|PermissionDenied|login_required|user_passes_test|permission_classes"
    r"|is_authenticated|raise_exception)\b"
)
# Rol/izin tabanlı yetki (nesne sahipliği değil): IDOR kavramı bu görünümlerde uygulanmaz.
_ROLE_SIGNAL_RE = re.compile(r"(permission_policy|permission_required|any_permission_required|PermissionRequired|has_perm|IsAdminUser"
                             r"|DjangoModelPermissions|has_permission|check_permissions?|is_staff|is_superuser|staff_member_required)")
_DJANGO_AUTH_MIXIN_RE = re.compile(r"(LoginRequired|PermissionRequired|UserPassesTest|AccessMixin|StaffRequired|SuperuserRequired|.*Required.*Mixin)")

# JS
_JS_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "del": "DELETE", "all": "ALL"}
_JS_NOT_ROUTERS = frozenset({
    "axios", "http", "https", "request", "superagent", "got", "needle", "fetch", "client", "$http", "httpClient",
    "map", "cache", "redis", "localStorage", "sessionStorage", "params", "headers", "config", "res", "req", "ctx",
    "response", "url", "searchParams", "store", "db", "knex", "collection", "Model", "model", "this", "$", "jQuery",
    "storage", "settings", "nconf", "env", "process", "window", "document", "chai", "supertest", "agent",
})
_JS_USER_REF_RE = re.compile(
    r"(req\.user\b|req\.session\.(user|userId|user_id|uid|username|account|passport)|ctx\.state\.user|res\.locals\.(user|currentUser)"
    r"|req\.auth\b|currentUser|request\.user\b|req\.decoded|req\.userId|req\.jwt|req\.payload|req\.token|ctx\.session\.(user|userId))"
)
_JS_INLINE_AUTH_RE = re.compile(
    r"(isAuthenticated\s*\(|req\.user\b|req\.session\.(user|userId|user_id|uid|loggedIn|logged_in|username|authenticated)"
    r"|ctx\.state\.user|ctx\.isAuthenticated|res\.locals\.(user|currentUser)|req\.auth\b|jwt\.verify\s*\(|status\(\s*40[13]\s*\)"
    r"|redirect\(\s*['\"`][^'\"`]*login)"
)
_JS_LOOKUP_METHODS = frozenset({
    "findById", "findByPk", "findOne", "find", "findOneAndUpdate", "findByIdAndUpdate", "findByIdAndDelete",
    "findByIdAndRemove", "findOneAndDelete", "findOneAndRemove", "deleteOne", "updateOne", "deleteMany", "updateMany",
    "destroy", "update", "remove", "get", "query", "execute", "run", "all", "findUnique", "findFirst", "where", "getById",
    "findUniqueOrThrow", "findFirstOrThrow", "findOneBy", "findOneByOrFail", "findOneOrFail", "deleteById", "updateById",
})
_JS_ID_SOURCES = ("params", "query", "body")
_DATABASE_RECEIVER_SUFFIXES = (
    "db", "model", "repo", "collection", "knex", "sql", "pool", "conn", "client", "prisma", "schema",
)


def _is_database_receiver(receiver: str) -> bool:
    """Equivalent to the former suffix regex, without repeated suffix backtracking."""
    if receiver.casefold().endswith(_DATABASE_RECEIVER_SUFFIXES):
        return True
    # The previous IGNORECASE ``[A-Z]\w*$`` branch accepted any suffix that
    # starts with an ASCII letter and otherwise contains only word characters.
    for character in reversed(receiver):
        if character != "_" and not character.isalnum():
            break
        if character.isascii() and character.isalpha():
            return True
    return False


@dataclass
class Route:
    file: str
    line: int
    framework: str
    methods: tuple[str, ...]
    path: str
    handler: str
    protection: str | None = None
    public_mark: bool = False
    idor: dict[str, Any] | None = None
    group: str = ""
    asymmetric_authz: bool = False
    status: str = ""
    reason: str = ""

    def public(self) -> dict[str, Any]:
        computed_status = self.status or (
            "public"
            if (self.public_mark or _is_public_path(self))
            else (
                "protected"
                if self.protection
                else ("unprotected" if self.asymmetric_authz else "review")
            )
        )
        return {
            "file": self.file, "line": self.line, "framework": self.framework, "methods": list(self.methods),
            "path": self.path, "handler": self.handler, "protection": self.protection,
            "public": self.public_mark, "idor_candidate": bool(self.idor),
            "status": computed_status, "asymmetric_authz": self.asymmetric_authz,
            "reason": self.reason,
        }


@dataclass
class _Project:
    py_protected_routers: set[tuple[str, str]] = field(default_factory=set)  # (modül kökü, ad)
    js_protected_modules: set[str] = field(default_factory=set)  # göreli dosya yolları (uzantısız)
    django_paths: dict[str, str] = field(default_factory=dict)  # görünüm adı → URL kalıbı
    flask_views: dict[str, tuple[str, str, str]] = field(default_factory=dict)  # MethodView adı → (yol, blueprint, modül kökü)
    django_global_login: bool = False
    django_protected_views: set[str] = field(default_factory=set)  # URL düzeyinde login_required(...) ile sarılan görünüm adları
    django_protected_dirs: dict[str, bool] = field(default_factory=dict)  # decorate_urlpatterns(..., denetim) paket dizini → rol tabanlı mı
    # sınıf adı → tanımlar listesi: (tabanlar, kendi koruma işareti, rol/izin işareti); ad çakışmasında herhangi biri yeter
    py_classes: dict[str, list[tuple[tuple[str, ...], bool, bool]]] = field(default_factory=dict)
    drf_default_auth: bool = False
    nest_global_guard: bool = False
    # (controller yolu, action) → [(HTTP yöntemleri, rota)]. Yalnız config/routes.rb içindeki açık Rails DSL
    # kayıtları eklenir; controller adı/action tahmininden hayali rota üretilmez.
    rails_routes: dict[tuple[str, str], list[tuple[tuple[str, ...], str]]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
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


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# "validateToken", "verifyJwtValid" gibi adlar: "valid" geçse de kimlik doğrulamadır (girdi doğrulayıcısı değil).
_VALIDATES_IDENTITY_RE = re.compile(r"(?i)(valid\w*(token|jwt|session|auth|user|login|api_?key)|(token|jwt|session|auth)\w*valid)")
_NOT_AUTH_STRICT_RE = re.compile(r"(?i)(csrf|xsrf|rate|limit|upload|multer|cors|parser|helmet|compress|static|cache|logger|morgan|i18n)")


def _is_auth_name(name: str) -> bool:
    if not name or not _AUTH_NAME_RE.search(name):
        return False
    if _NOT_AUTH_RE.search(name):
        return bool(_VALIDATES_IDENTITY_RE.search(name)) and not _NOT_AUTH_STRICT_RE.search(name)
    return True


def _group(relpath: str, language: str) -> str:
    """Aynı uygulama sayılan rota grubu: dosyanın ilk iki dizin düzeyi + dil (monorepo / çok uygulamalı depolar ayrışır)."""
    parts = PurePosixPath(relpath).parts[:-1]
    return f"{'/'.join(parts[:2]) or '.'}:{language}"


def _module_stem(relpath: str) -> str:
    path = PurePosixPath(relpath)
    return path.parent.name if path.stem == "__init__" else path.stem


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------
_PREPASS_CALL_NAMES = frozenset({"add_url_rule", "register_view", "register", "path", "re_path", "url"})


def _py_prepass(relpath: str, tree: ast.Module, project: _Project, nodes: list[ast.AST] | None = None,
                text: str | None = None) -> None:
    """Proje geneli: korunan Flask blueprint / FastAPI router adları, Django URL kalıpları, genel ayarlar.
    ``nodes``: ağacın ``ast.walk`` sırasındaki düğümleri (verilmezse yürünür)."""
    stem = _module_stem(relpath)
    text_name = PurePosixPath(relpath).name
    if nodes is None:
        nodes = list(ast.walk(tree))
    for node in nodes:
        # @bp.before_request ile kimlik denetimi → bp'nin tüm rotaları korunur.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr in {"before_request", "before_app_request"}:
                    body = ast.unparse(node)
                    if _PY_INLINE_AUTH_RE.search(body):
                        project.py_protected_routers.add((stem, _dotted(target.value)))
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            ctor = _dotted(node.value.func).rsplit(".", 1)[-1]
            if ctor in {"APIRouter", "FastAPI"}:
                for keyword in node.value.keywords:
                    if keyword.arg == "dependencies" and _has_auth_depends(keyword.value):
                        for target in node.targets:
                            project.py_protected_routers.add((stem, _dotted(target)))
        if isinstance(node, ast.Call):
            # 19. tur hız: _dotted'in son parçası Attribute için attr, Name için id'dir (diğerlerinde ilgili koşulların
            # hiçbiri sağlanamaz); son parça ilgisizse tam ad hesaplanmaz (aynı sonuç).
            callee = node.func
            last = callee.attr if isinstance(callee, ast.Attribute) else callee.id if isinstance(callee, ast.Name) else None
            if last is None or not (last.endswith("include_router") or last in _PREPASS_CALL_NAMES):
                continue
            func = _dotted(node.func)
            if func.endswith("include_router") and node.args:
                if any(k.arg == "dependencies" and _has_auth_depends(k.value) for k in node.keywords):
                    router = _dotted(node.args[0])
                    if "." in router:
                        module, name = router.rsplit(".", 1)
                        project.py_protected_routers.add((module.rsplit(".", 1)[-1], name))
                    else:
                        project.py_protected_routers.add(("*", router))
            if func.rsplit(".", 1)[-1] in {"add_url_rule", "register_view"}:
                view_func = next((k.value for k in node.keywords if k.arg == "view_func"), None)
                if isinstance(view_func, ast.Call) and isinstance(view_func.func, ast.Attribute) and view_func.func.attr == "as_view":
                    cls = _dotted(view_func.func.value).rsplit(".", 1)[-1]
                    rule = next((_const_str(a) for a in node.args if _const_str(a)), None)
                    routes_kw = next((k.value for k in node.keywords if k.arg == "routes"), None)
                    if rule is None and isinstance(routes_kw, (ast.List, ast.Tuple)) and routes_kw.elts:
                        rule = _const_str(routes_kw.elts[0])
                    if func.rsplit(".", 1)[-1] == "register_view":
                        blueprint = _dotted(node.args[0]) if node.args else ""
                    else:
                        blueprint = _dotted(node.func.value) if isinstance(node.func, ast.Attribute) else ""
                    project.flask_views.setdefault(cls, (rule or "", blueprint, stem))
            if func.endswith(".register") and len(node.args) >= 2 and _const_str(node.args[0]) is not None:
                name = _dotted(node.args[1]).rsplit(".", 1)[-1]
                if name and name not in project.django_paths:
                    project.django_paths[name] = "/" + str(_const_str(node.args[0])).lstrip("^").rstrip("$")
            if func.rsplit(".", 1)[-1] in {"path", "re_path", "url"} and len(node.args) >= 2:
                pattern = _const_str(node.args[0])
                view = node.args[1]
                if isinstance(view, ast.Call):  # Klas.as_view()
                    view = view.func.value if isinstance(view.func, ast.Attribute) else view.func
                name = _dotted(view).rsplit(".", 1)[-1]
                if pattern is not None and name and name not in project.django_paths:
                    project.django_paths[name] = "/" + pattern.lstrip("^").rstrip("$")
    lines: list[str] | None = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = tuple(_dotted(b).rsplit(".", 1)[-1] for b in node.bases)
            own = any(_DJANGO_AUTH_MIXIN_RE.search(b) for b in bases)
            if lines is None and text is not None:
                lines = _AST_NEWLINE_RE.split(text)
            body_text = _class_signal_text(node, lines)  # sınıf başına bir kez (pahalı; sinyal yoksa atlanır)
            if not own:
                perm = re.search(r"permission_classes\s*=\s*[\[(]([^\])]*)", body_text)
                own = bool(_CLASS_PERMISSION_SIGNAL_RE.search(body_text)) and not (perm and re.fullmatch(r"\s*(\w+\.)?AllowAny\s*,?\s*", perm.group(1)))
                own = own or any(_is_auth_name(n.rsplit(".", 1)[-1]) for n in _py_decorator_names(node))
            perm_flag = bool(_ROLE_SIGNAL_RE.search(body_text)) or any(_ROLE_SIGNAL_RE.search(b) for b in bases)
            project.py_classes.setdefault(node.name, []).append((bases, own, perm_flag))
    if text_name == "urls.py" or "urls" in PurePosixPath(relpath).parts:
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            func = _dotted(node.func).rsplit(".", 1)[-1]
            if func == "decorate_urlpatterns" and len(node.args) >= 2 and _is_auth_name(_dotted(node.args[1]).rsplit(".", 1)[-1]):
                package = PurePosixPath(relpath).parent
                if package.name == "urls":
                    package = package.parent
                decorator = _dotted(node.args[1]).rsplit(".", 1)[-1]
                project.django_protected_dirs[str(package)] = bool(re.search(r"(?i)(admin|staff|superuser|permission|role)", decorator))
            elif _is_auth_name(func) and node.args:  # path("x", login_required(views.f))
                inner = node.args[0]
                if isinstance(inner, ast.Call):
                    inner = inner.func.value if isinstance(inner.func, ast.Attribute) else inner.func
                name = _dotted(inner).rsplit(".", 1)[-1]
                if name:
                    project.django_protected_views.add(name)
    if text_name == "settings.py" or "settings" in PurePosixPath(relpath).parts:
        source = ast.unparse(tree)
        if "LoginRequiredMiddleware" in source:
            project.django_global_login = True
        match = re.search(r"DEFAULT_PERMISSION_CLASSES['\"]?\s*:\s*[\[(]([^\])]*)", source)
        if match and re.search(r"IsAuthenticated|IsAdminUser|DjangoModelPermissions(?!OrAnon)", match.group(1)):
            project.drf_default_auth = True
        # Özel varsayılan izin sınıfı (ör. authentik ObjectPermissions): AllowAny / anonim okuma serbest değilse korumalı.
        elif match and re.search(r"Permission", match.group(1)) and not re.search(r"AllowAny|OrAnon|ReadOnly", match.group(1)):
            project.drf_default_auth = True


# Sınıf metninde aranan sinyallerin (permission_classes / _CLASS_PERMISSION_SIGNAL_RE / _ROLE_SIGNAL_RE) hepsi bu
# kelimelerden birini içerir; kaynak dilimde hiçbiri yoksa ast.unparse çıktısında da olamaz (unparse yalnız kaynaktaki
# adları/dizgeleri yeniden yazar). Kaçış dizisi (\\) olan dilimde dizge değeri farklı yazılabileceği için ön süzgeç
# uygulanmaz.
_CLASS_SIGNAL_WORDS_RE = re.compile(
    r"permission_classes|permission_policy|permission_required|any_permission_required|required_permission"
    r"|get_permission_required|has_permission|check_permission|test_func|PermissionDenied|login_required"
    r"|user_passes_test|is_authenticated|raise_exception|PermissionRequired|has_perm|IsAdminUser"
    r"|DjangoModelPermissions|is_staff|is_superuser|staff_member_required")


_AST_NEWLINE_RE = re.compile(r"\r\n|\r|\n")  # ast satır numaraları yalnız bu ayraçları sayar (splitlines daha fazlasını)


def _class_signal_text(node: ast.ClassDef, lines: list[str] | None) -> str:
    """Sınıfın ``ast.unparse`` metni; kaynak dilimde hiçbir sinyal kelimesi yoksa boş dizge (aynı sonuç, ucuz)."""
    if lines is not None and getattr(node, "end_lineno", None):
        first = min([node.lineno] + [d.lineno for d in node.decorator_list])
        segment = "\n".join(lines[first - 1:node.end_lineno])
        if "\\" not in segment and not _CLASS_SIGNAL_WORDS_RE.search(segment):
            return ""
    return ast.unparse(node)


def _has_auth_depends(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            dep_kind = _dotted(sub.func).rsplit(".", 1)[-1]
            if dep_kind in {"Depends", "Security"} and sub.args:
                dep_target = _dotted(sub.args[0])
                if dep_kind == "Security" and dep_target and not _NOT_AUTH_RE.search(dep_target):
                    return True
                if _is_auth_name(dep_target):
                    return True
    return False


def _py_decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[str]:
    names = []
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _dotted(target)
        names.append(name)
        if isinstance(decorator, ast.Call):  # method_decorator(login_required), permission_classes([IsAuthenticated])
            for arg in decorator.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, (ast.Name, ast.Attribute)):
                        names.append(_dotted(sub))
    return names


def _py_route_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str, tuple[str, ...], ast.Call] | None:
    for decorator in func.decorator_list:
        if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
            continue
        attr = decorator.func.attr
        if attr not in _PY_ROUTE_ATTRS:
            continue
        router = _dotted(decorator.func.value)
        if not router or router.split(".")[0] in {"requests", "httpx", "session", "client", "self"}:
            continue
        path = _const_str(decorator.args[0]) if decorator.args else None
        if path is None:
            path = next((_const_str(k.value) for k in decorator.keywords if k.arg in {"path", "rule"}), None)
        if path is None or not path.startswith("/"):
            continue
        if attr in {"route", "api_route"}:
            methods: tuple[str, ...] = ("GET",)
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                    found = tuple(str(e.value).upper() for e in keyword.value.elts if isinstance(e, ast.Constant))
                    methods = found or methods
        else:
            methods = (attr.upper(),)
        return router, path, methods, decorator
    return None


def _py_function_protection(func: ast.FunctionDef | ast.AsyncFunctionDef, decorator: ast.Call | None) -> tuple[str | None, bool]:
    names = _py_decorator_names(func)
    if any(_PUBLIC_MARK_RE.search(n.rsplit(".", 1)[-1]) for n in names) or any("AllowAny" in n for n in names):
        return None, True
    for name in names:
        last = name.rsplit(".", 1)[-1]
        if last in _PY_ROUTE_ATTRS or last in {"csrf_exempt", "cache_page", "require_http_methods", "require_POST", "require_GET", "api_view"}:
            continue
        if _is_auth_name(last) or last in {"permission_classes"} and any("IsAuthenticated" in n or "IsAdmin" in n for n in names):
            return f"decorator:{last}", False
    if decorator is not None and any(k.arg == "dependencies" and _has_auth_depends(k.value) for k in decorator.keywords):
        return "dependency", False
    arguments = func.args.args + func.args.kwonlyargs
    defaults = list(func.args.defaults) + [d for d in func.args.kw_defaults if d is not None]
    for node in [a.annotation for a in arguments if a.annotation is not None] + defaults:
        if _has_auth_depends(node):
            return "dependency", False
    body = "\n".join(ast.unparse(statement) for statement in func.body)  # imza/dekoratör hariç
    if _PY_INLINE_AUTH_RE.search(body):
        return "inline", False
    return None, False


def _py_id_vars(func: ast.FunctionDef | ast.AsyncFunctionDef, path: str) -> set[str]:
    ids = {a.arg for a in func.args.args + func.args.kwonlyargs if _ID_NAME_RE.search(a.arg)}
    for name in re.findall(r"[<{](?:\w+:)?(\w+)[>}]", path or ""):
        if _ID_NAME_RE.search(name):
            ids.add(name)
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if _py_is_request_id(node.value):
                ids.add(node.targets[0].id)
    return ids


def _py_is_request_id(node: ast.AST) -> bool:
    """request.args.get("x_id"), request.form["id"], request.GET.get("pk"), self.kwargs["pk"], request.json["id"] …"""
    key = None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
        key, base = _const_str(node.args[0]), _dotted(node.func.value)
    elif isinstance(node, ast.Subscript):
        key, base = _const_str(node.slice), _dotted(node.value)
    else:
        return False
    if key is None or not _ID_NAME_RE.search(key):
        return False
    return bool(re.search(r"(request\.(args|form|values|json|GET|POST|data|query_params|path_params|query)|self\.kwargs|kwargs|get_json\(\))", base))


def _py_lookup(func: ast.AST, ids: set[str]) -> tuple[int, str] | None:
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        last = name.rsplit(".", 1)[-1]
        if last not in _PY_LOOKUP_ATTRS:
            continue
        if last in _PY_STRICT_RECEIVER and not re.search(r"(objects|query|session|\bdb\b|[A-Z]\w*$)", name.rsplit(".", 1)[0] if "." in name else ""):
            continue
        refs = False
        for sub in [*node.args, *(k.value for k in node.keywords)]:
            for inner in ast.walk(sub):
                if isinstance(inner, ast.Name) and inner.id in ids:
                    refs = True
                elif _py_is_request_id(inner):
                    refs = True
        if refs:
            return node.lineno, name
    return None


def _py_routes(relpath: str, tree: ast.Module, project: _Project) -> list[Route]:
    routes: list[Route] = []
    stem = _module_stem(relpath)
    imports: dict[str, str] = {}  # yerel ad → kaynak modül kökü
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imports[alias.asname or alias.name] = node.module.rsplit(".", 1)[-1]
    is_django_views = PurePosixPath(relpath).stem == "views" or "views" in PurePosixPath(relpath).parts
    group = _group(relpath, "py")
    module_funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def callee_protected(func: ast.AST) -> bool:
        """İşi korumalı modül fonksiyonuna devreden görünüm (ör. checks(request) → create_check(request))."""
        for sub in ast.walk(func):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in module_funcs and sub.func.id != getattr(func, "name", ""):
                callee = module_funcs[sub.func.id]
                if _py_function_protection(callee, None)[0]:
                    return True
        return False

    def router_protected(router: str) -> bool:
        head = router.split(".")[0]
        return ((stem, router) in project.py_protected_routers or ("*", router) in project.py_protected_routers
                or (imports.get(head, ""), router) in project.py_protected_routers)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info = _py_route_decorator(node)
            if info is not None:
                router, path, methods, decorator = info
                protection, public = _py_function_protection(node, decorator)
                if protection is None and not public and router_protected(router):
                    protection = "router"
                if protection is None and not public and callee_protected(node):
                    protection = "inline"
                route = Route(relpath, node.lineno, "flask/fastapi", methods, path, node.name, protection, public, group=group)
                routes.append(route)
            elif is_django_views and node.args.args and node.args.args[0].arg == "request" and not node.name.startswith("_") \
                    and (not project.django_paths or node.name in project.django_paths):
                methods_found = sorted(set(re.findall(r"request\.method\s*==\s*['\"](\w+)['\"]", ast.unparse(node))))
                names = _py_decorator_names(node)
                for name in names:
                    if name.endswith("require_POST"):
                        methods_found = ["POST"]
                decorated = next((d for d in node.decorator_list if isinstance(d, ast.Call) and _dotted(d.func).endswith(("require_http_methods", "api_view"))), None)
                if decorated is not None and decorated.args and isinstance(decorated.args[0], (ast.List, ast.Tuple)):
                    methods_found = [str(e.value).upper() for e in decorated.args[0].elts if isinstance(e, ast.Constant)]
                restricted = decorated is not None or any(n.endswith(("require_POST", "require_GET", "require_safe")) for n in names)
                methods = tuple(methods_found) if restricted and methods_found else tuple(dict.fromkeys(["GET", *methods_found]))
                protection, public = _py_function_protection(node, None)
                is_drf = any(n.endswith("api_view") for n in names)
                if protection is None and not public and (project.django_global_login or (is_drf and project.drf_default_auth)):
                    protection = "global"
                if protection is None and not public and (node.name in project.django_protected_views or _dir_protected(relpath, project)):
                    protection = "urlconf"
                if protection is None and not public and callee_protected(node):
                    protection = "delegated"
                path = project.django_paths.get(node.name, "")
                routes.append(Route(relpath, node.lineno, "django", methods, path, node.name, protection, public, group=group))
        elif isinstance(node, ast.ClassDef):
            routes.extend(_py_class_routes(relpath, node, project, group))
    # IDOR adayları
    by_line = {r.line: r for r in routes}
    for node in tree.body:
        candidates: list[tuple[ast.AST, Route]] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno in by_line:
            candidates.append((node, by_line[node.lineno]))
        for func, route in candidates:
            text = ast.unparse(func)
            body_text = "\n".join(ast.unparse(statement) for statement in func.body)
            auth_params = [a.arg for a, default in _py_param_defaults(func) if default is not None and _has_auth_depends(default)]
            if any(re.search(rf"\b{re.escape(name)}\b", body_text) for name in auth_params):
                continue  # Depends ile alınan geçerli kullanıcı gövdede kullanılıyor (sahiplik bağlaması olabilir)
            if _PY_USER_REF_RE.search(body_text) or _ADMIN_CHECK_RE.search(text) or _ROLE_SIGNAL_RE.search(text):
                continue
            if _py_helper_checks_owner(func, module_funcs):
                continue
            if route.protection == "urlconf" and _dir_protected(relpath, project, role_only=True):
                continue  # yönetici paneli (rol tabanlı yetki): nesne sahipliği kavramı uygulanmaz
            ids = _py_id_vars(func, route.path)
            if not ids:
                continue
            found = _py_lookup(func, ids)
            if found:
                route.idor = {"line": found[0], "lookup": found[1]}
    return routes


def _class_flag(name: str, project: _Project, index: int, depth: int = 0, seen: set[str] | None = None) -> bool:
    """Sınıf ya da proje içindeki atalarından biri işareti taşıyor mu (index 1: koruma, 2: rol/izin).
    Ad tabanlı ve döngüye dayanıklı; aynı adlı tanımlardan herhangi biri yeterli (kesinlik öncelikli)."""
    if depth > 12:
        return False
    seen = seen if seen is not None else set()
    if name in seen or name not in project.py_classes:
        return False
    seen.add(name)
    for definition in project.py_classes[name]:
        bases = definition[0]
        if definition[index]:
            return True
        if index == 1 and any(_DJANGO_AUTH_MIXIN_RE.search(b) for b in bases):
            return True
        if any(_class_flag(b, project, index, depth + 1, seen) for b in bases):
            return True
    return False


def _class_protected(name: str, project: _Project) -> bool:
    return _class_flag(name, project, 1)


def _class_role_based(name: str, project: _Project) -> bool:
    return _class_flag(name, project, 2)


def _dir_protected(relpath: str, project: _Project, role_only: bool = False) -> bool:
    parent = str(PurePosixPath(relpath).parent)
    return any((parent == d or parent.startswith(d + "/")) and (role or not role_only) for d, role in project.django_protected_dirs.items())


def _py_param_defaults(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, ast.AST | None]]:
    """(parametre, varsayılan ya da Annotated türü) çiftleri."""
    positional = func.args.args
    defaults = [None] * (len(positional) - len(func.args.defaults)) + list(func.args.defaults)
    pairs = list(zip(positional, defaults)) + list(zip(func.args.kwonlyargs, func.args.kw_defaults))
    return [(arg, default if default is not None else arg.annotation) for arg, default in pairs]


def _py_helper_checks_owner(func: ast.AST, module_funcs: dict[str, ast.AST]) -> bool:
    """İşleyicinin çağırdığı aynı modüldeki yardımcı geçerli kullanıcıya bakıyor ya da 403/404 ile reddediyor mu."""
    for sub in ast.walk(func):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in module_funcs:
            helper = ast.unparse(module_funcs[sub.func.id])
            if _PY_USER_REF_RE.search(helper) or _ADMIN_CHECK_RE.search(helper) or re.search(r"abort\(\s*403|PermissionDenied|Forbidden", helper):
                return True
    return False


def _ancestors(bases: list[str], project: _Project, depth: int = 0, seen: set[str] | None = None) -> set[str]:
    """Proje içindeki sınıf tanımlarından ata adlarını topla (ad tabanlı)."""
    seen = seen if seen is not None else set()
    out: set[str] = set()
    for base in bases:
        if base in seen or depth > 12:
            continue
        seen.add(base)
        out.add(base)
        for definition in project.py_classes.get(base, []):
            out |= _ancestors(list(definition[0]), project, depth + 1, seen)
    return out


def _py_class_routes(relpath: str, node: ast.ClassDef, project: _Project, group: str) -> list[Route]:
    direct = [_dotted(b).rsplit(".", 1)[-1] for b in node.bases]
    # Ata listesi taban demeti başına bir kez (19. tur: büyük projelerde milyonlarca yineleme çağrısıydı).
    # Ön geçiş bittikten sonra py_classes değişmez; önbellek proje nesnesinde tutulur.
    cache = project.__dict__.setdefault("_ancestor_cache", {})
    key = tuple(direct)
    bases = cache.get(key)
    if bases is None:
        bases = cache[key] = sorted(_ancestors(direct, project))
    bases = list(bases)
    if not any(b.endswith(("View", "ViewSet", "APIView", "Resource", "ViewSetMixin")) for b in bases):
        return []
    method_view = "MethodView" in direct
    if method_view:
        if node.name not in project.flask_views:
            return []  # add_url_rule / register_view ile kaydı bulunmayan Flask MethodView
    elif project.django_paths and node.name not in project.django_paths:
        return []  # URL tanımlarında adı geçmeyen sınıf: taban/yardımcı sınıf ya da başka mekanizmayla kayıtlı
    method_names = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    methods = [m.upper() for m in method_names if m in {"get", "post", "put", "patch", "delete"}]
    if any("ModelViewSet" == b for b in bases):
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    elif any(b in {"UpdateView", "DeleteView", "CreateView", "FormView"} for b in bases):
        methods = methods or ["GET", "POST"]
    elif not methods and any(_DJANGO_CBV_OBJECT_BASES.search(b) for b in bases):
        methods = ["GET"]
    if not methods:
        return []
    text = ast.unparse(node)
    protection: str | None = None
    public = False
    if any(_DJANGO_AUTH_MIXIN_RE.search(b) for b in bases):
        protection = "mixin"
    perm = re.search(r"permission_classes\s*=\s*[\[(]([^\])]*)", text)
    if perm:
        if re.fullmatch(r"\s*(\w+\.)?AllowAny\s*,?\s*", perm.group(1)):
            public = True
        elif perm.group(1).strip():
            protection = protection or "permission_classes"
    names = _py_decorator_names(node)
    if protection is None and any(_is_auth_name(n.rsplit(".", 1)[-1]) for n in names):
        protection = "decorator"
    if protection is None and not public and (_class_protected(node.name, project) or any(_class_protected(b, project) for b in bases)):
        protection = "inherited"
    if protection is None and not public and (node.name in project.django_protected_views or _dir_protected(relpath, project)):
        protection = "urlconf"
    if protection is None and not public:
        is_drf = any(re.search(r"(APIView|ViewSet)$", b) for b in bases)
        if project.django_global_login or (is_drf and project.drf_default_auth):
            protection = "global"
        elif _PY_INLINE_AUTH_RE.search(text):
            protection = "inline"
    if protection is None and not public:
        # Yöntem düzeyi dekoratörler (17. tur): tüm HTTP yöntemleri (ya da dispatch) kimlik dekoratörlüyse korumalı
        # (ör. crAPI: @jwt_auth_required def get(self, request, user)).
        funcs = {n.name: n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

        def _decorated(func: ast.AST) -> bool:
            return any(_is_auth_name(n.rsplit(".", 1)[-1]) for n in _py_decorator_names(func))

        if "get_permissions" in funcs and re.search(r"(Permission|IsAuthenticated|IsAdmin)", ast.unparse(funcs["get_permissions"])) \
                and not re.search(r"AllowAny", ast.unparse(funcs["get_permissions"])):
            protection = "get_permissions"
        handlers = [funcs[m.lower()] for m in methods if m.lower() in funcs]
        if protection is None and (("dispatch" in funcs and _decorated(funcs["dispatch"])) or (
                handlers and len(handlers) == len(methods) and all(_decorated(f) for f in handlers))):
            protection = "method_decorator"
    if protection is None and not public:
        for statement in node.body:  # Flask MethodView.decorators = [...]
            if isinstance(statement, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "decorators" for t in statement.targets):
                names = [_dotted(sub) for sub in ast.walk(statement.value) if isinstance(sub, (ast.Name, ast.Attribute))]
                if any(_is_auth_name(name) for name in names):
                    protection = "decorator"
    if method_view:
        rule, blueprint, stem = project.flask_views[node.name]
        if protection is None and not public and ((stem, blueprint) in project.py_protected_routers or ("*", blueprint) in project.py_protected_routers):
            protection = "router"
        path = rule
    else:
        path = project.django_paths.get(node.name, "")
    route = Route(relpath, node.lineno, "flask-methodview" if method_view else "django-cbv", tuple(methods), path, node.name, protection, public, group=group)
    # Nesne görünümü: queryset/model kullanıcıyla daraltılmıyorsa IDOR adayı.
    role_based = _class_role_based(node.name, project) or any(_class_role_based(b, project) for b in bases)
    if not role_based and any(_DJANGO_CBV_OBJECT_BASES.search(b) for b in bases) and not (_PY_USER_REF_RE.search(text) or _ADMIN_CHECK_RE.search(text)):
        if re.search(r"\b(queryset|model)\s*=", text) and "IsAdminUser" not in text:
            route.idor = {"line": node.lineno, "lookup": "queryset/model (kullanıcıya göre daraltılmamış)"}
    return [route]


# ---------------------------------------------------------------------------
# Ruby / Rails
# ---------------------------------------------------------------------------
_RAILS_REST_ROUTES: dict[str, tuple[tuple[str, ...], str]] = {
    "index": (("GET",), ""),
    "show": (("GET",), "/:id"),
    "new": (("GET",), "/new"),
    "create": (("POST",), ""),
    "edit": (("GET",), "/:id/edit"),
    "update": (("PATCH", "PUT"), "/:id"),
    "destroy": (("DELETE",), "/:id"),
}
_RAILS_ROUTE_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE"}
_RUBY_METHOD_START_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?:self\.)?([a-zA-Z_]\w*[!?=]?)(?!\w)")
_RUBY_BLOCK_START_RE = re.compile(r"^\s*(?:def|class|module|if|unless|case|begin|while|until|for)\b")
_RUBY_LOOKUP_RE = re.compile(
    r"(?P<receiver>(?:[A-Z]\w*(?:::\w+)*|(?:current_user|Current\.(?:tenant|account|organization|workspace|user))"
    r"(?:\.[a-zA-Z_]\w*)+))\.(?P<method>find|find_by!?|find_by_id!?|where)\s*\([^\n]*"
    r"params\s*\[\s*:(?:id|\w+_id|uuid|guid)\s*\]"
)
_RUBY_OWNER_CONTEXT_RE = re.compile(
    r"\bcurrent_user\b|\bCurrent\.(?:tenant|account|organization|workspace|user)\b|"
    r"\b(?:authorize|policy_scope|authorized_scope|accessible_by|can\?)\b|"
    r"\b(?:owner|user|account|tenant|organization|workspace)_id\s*:"
)


def _ruby_underscore(name: str) -> str:
    """Rails controller sabitini route DSL'deki ``admin/orders`` biçimine indirger."""
    parts = []
    for component in name.split("::"):
        component = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", component)
        component = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", component)
        parts.append(component.casefold())
    return "/".join(parts)


def _ruby_symbols(option: str | None) -> set[str] | None:
    if option is None:
        return None
    return set(re.findall(r":([a-zA-Z_]\w*[!?]?)", option))


def _rails_add_route(project: _Project, controller: str, action: str, methods: tuple[str, ...], path: str) -> None:
    key = (controller.strip("/"), action)
    item = (methods, path if path.startswith("/") else "/" + path)
    if item not in project.rails_routes.setdefault(key, []):
        project.rails_routes[key].append(item)


def _ruby_strip_comment(line: str) -> str:
    """Remove a Ruby line comment without truncating ``controller#action`` strings."""
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "#":
            return line[:index]
    return line


def _rails_prepass(relpath: str, text: str, project: _Project) -> None:
    """Açık Rails route DSL kayıtlarını çıkarır; belirsiz dinamik DSL/kapsamlar bilerek atlanır."""
    path = PurePosixPath(relpath)
    if path.name != "routes.rb" or "config" not in path.parts:
        return
    for raw in text.splitlines():
        line = _ruby_strip_comment(raw).strip()
        if not line:
            continue
        resources = re.match(r"resources\s+:(\w+)\b(.*)$", line)
        if resources:
            resource, options = resources.groups()
            controller_option = re.search(r"\bcontroller:\s*['\"]([^'\"]+)['\"]", options)
            controller = controller_option.group(1) if controller_option else resource
            only_match = re.search(r"\bonly:\s*(\[[^\]]*\]|:\w+)", options)
            except_match = re.search(r"\bexcept:\s*(\[[^\]]*\]|:\w+)", options)
            selected = set(_RAILS_REST_ROUTES)
            only = _ruby_symbols(only_match.group(1) if only_match else None)
            excluded = _ruby_symbols(except_match.group(1) if except_match else None)
            if only is not None:
                selected &= only
            if excluded:
                selected -= excluded
            base = "/" + resource
            for action in _RAILS_REST_ROUTES:
                if action in selected:
                    methods, suffix = _RAILS_REST_ROUTES[action]
                    _rails_add_route(project, controller, action, methods, base + suffix)
            continue
        singular = re.match(r"resource\s+:(\w+)\b(.*)$", line)
        if singular:
            resource, options = singular.groups()
            controller_option = re.search(r"\bcontroller:\s*['\"]([^'\"]+)['\"]", options)
            controller = controller_option.group(1) if controller_option else resource + "s"
            only_match = re.search(r"\bonly:\s*(\[[^\]]*\]|:\w+)", options)
            except_match = re.search(r"\bexcept:\s*(\[[^\]]*\]|:\w+)", options)
            selected = set(_RAILS_REST_ROUTES) - {"index"}
            only = _ruby_symbols(only_match.group(1) if only_match else None)
            excluded = _ruby_symbols(except_match.group(1) if except_match else None)
            if only is not None:
                selected &= only
            if excluded:
                selected -= excluded
            base = "/" + resource
            for action in _RAILS_REST_ROUTES:
                if action in selected:
                    methods, suffix = _RAILS_REST_ROUTES[action]
                    _rails_add_route(project, controller, action, methods, base + suffix.replace("/:id", ""))
            continue
        explicit = re.match(
            r"(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]\s*,?\s*(?:to:\s*|=>\s*)['\"]([^'#]+)#(\w+[!?]?)['\"]",
            line,
        )
        if explicit:
            verb, route_path, controller, action = explicit.groups()
            _rails_add_route(project, controller, action, (_RAILS_ROUTE_METHODS[verb],), route_path)


def _ruby_method_blocks(text: str) -> dict[str, tuple[int, str]]:
    """Controller action gövdelerini satır numarasıyla ayıran sınırlı Ruby blok çözümleyicisi."""
    lines = text.splitlines()
    methods: dict[str, tuple[int, str]] = {}
    i = 0
    while i < len(lines):
        match = _RUBY_METHOD_START_RE.match(lines[i])
        if match is None:
            i += 1
            continue
        name = match.group(1)
        depth = 1
        j = i + 1
        while j < len(lines):
            code = lines[j].split("#", 1)[0]
            if re.match(r"^\s*end\b", code):
                depth -= 1
                if depth == 0:
                    break
            else:
                if _RUBY_BLOCK_START_RE.match(code):
                    depth += 1
                depth += len(re.findall(r"\bdo\s*(?:\|[^|]*\|)?\s*(?:$|#)", code))
            j += 1
        if depth == 0:
            methods[name] = (i + 1, "\n".join(lines[i:j + 1]))
            i = j + 1
        else:
            i += 1
    return methods


def _ruby_lookup(method_line: int, method_text: str) -> tuple[int, str] | None:
    """İstek kimliğini kullanan ilk ActiveRecord lookup'ını döndürür; sahiplik/policy bağlamında gürültü yapmaz."""
    if _RUBY_OWNER_CONTEXT_RE.search(method_text):
        return None
    for offset, line in enumerate(method_text.splitlines()):
        match = _RUBY_LOOKUP_RE.search(line)
        if match:
            return method_line + offset, f"{match.group('receiver')}.{match.group('method')}"
    return None


def _ruby_routes(
    relpath: str,
    text: str,
    project: _Project,
    controller_contexts: dict[str, Any],
) -> list[Route]:
    if "controllers" not in PurePosixPath(relpath).parts:
        return []
    class_match = re.search(r"^\s*class\s+([A-Z]\w*(?:::[A-Z]\w*)*)Controller\s*<\s*[A-Z]\w*(?:::[A-Z]\w*)*", text, re.MULTILINE)
    if class_match is None:
        return []
    controller_class = class_match.group(1) + "Controller"
    controller = _ruby_underscore(class_match.group(1))
    methods = _ruby_method_blocks(text)
    load_and_authorize = bool(re.search(r"^\s*load_and_authorize_resource\b", text, re.MULTILINE))
    routes: list[Route] = []
    group = _group(relpath, "ruby")
    for action, (line, body) in methods.items():
        definitions = project.rails_routes.get((controller, action), [])
        if not definitions:
            continue
        protection: str | None = None
        public = False
        context = controller_contexts.get(controller_class)
        action_context = context.action(action) if context is not None else None
        # Only statically guaranteed effective callbacks can protect a route.
        # The inheritance resolver has already applied base-to-child order,
        # only/except scopes and skip_before_action removal. Dynamic predicates
        # remain in uncertain_filters and intentionally do not enter this list.
        applicable = [item.name for item in action_context.effective_filters] \
            if action_context is not None else []
        auth_filters = [name for name in applicable if _is_auth_name(name)]
        if auth_filters:
            protection = f"before_action:{auth_filters[0]}"
        elif load_and_authorize:
            protection = "load_and_authorize_resource"
        elif re.search(r"\b(?:authenticate_user!|authorize|authorize!|verify_authorized)\b", body):
            protection = "inline"
        if re.search(r"^\s*(?:skip_before_action\s+:authenticate|allow_unauthenticated_access\b)", body, re.MULTILINE):
            protection, public = None, True
        lookup = None if load_and_authorize else _ruby_lookup(line, body)
        if lookup is None and not load_and_authorize:
            for callback in applicable:
                helper = methods.get(callback)
                if helper is None:
                    continue
                lookup = _ruby_lookup(helper[0], helper[1])
                if lookup is not None:
                    break
        for route_methods, path in definitions:
            route = Route(
                relpath, line, "rails", route_methods, path, f"{controller_class}#{action}", protection, public,
                group=group,
            )
            if lookup is not None:
                route.idor = {"line": lookup[0], "lookup": lookup[1]}
            routes.append(route)
    return routes


# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------
def _js_tokens(text: str):
    import taint_flow

    try:
        return taint_flow._JsTokenizer(text).tokens()
    except Exception:  # sözcük çözümleyici sınırı / bozuk kaynak
        return None


def _match_close(toks, i: int) -> int:
    """toks[i] açılış ayracı; eşleşen kapanış dizinini döndür."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = toks[i].value
    closer = pairs[opener]
    depth = 0
    for j in range(i, len(toks)):
        tok = toks[j]
        if tok.kind != "punct":
            continue
        if tok.value == opener:
            depth += 1
        elif tok.value == closer:
            depth -= 1
            if depth == 0:
                return j
    return len(toks) - 1


def _split_args(toks, open_i: int, close_i: int) -> list[tuple[int, int]]:
    args: list[tuple[int, int]] = []
    depth = 0
    start = open_i + 1
    for j in range(open_i + 1, close_i):
        tok = toks[j]
        if tok.kind == "punct" and tok.value in "([{":
            depth += 1
        elif tok.kind == "punct" and tok.value in ")]}":
            depth -= 1
        elif tok.kind == "punct" and tok.value == "," and depth == 0:
            args.append((start, j))
            start = j + 1
    if start < close_i:
        args.append((start, close_i))
    return args


def _tok_text(toks, a: int, b: int) -> str:
    out = []
    for tok in toks[a:b]:
        out.append(tok.value if tok.kind != "str" else repr(tok.value))
    return "".join(v if v in ".()[]{},;" else f" {v} " for v in out).replace(" . ", ".")


def _js_arg_is_auth(toks, a: int, b: int) -> bool:
    ids = [t.value for t in toks[a:b] if t.kind == "id"]
    if not ids:
        return False
    if ids[0] in {"function", "async"} or any(t.kind == "punct" and t.value == "=>" for t in toks[a:b]):
        body = _tok_text(toks, a, b)
        return bool(_JS_INLINE_AUTH_RE.search(body)) and ("next" in ids)
    return any(_is_auth_name(name) for name in ids if name not in {"require", "new"})


def _js_is_function_arg(toks, a: int, b: int) -> bool:
    if b <= a:
        return False
    first = toks[a]
    if first.kind == "id" and first.value in {"function", "async"}:
        return True
    return any(t.kind == "punct" and t.value == "=>" for t in toks[a:b])


def _js_require_map(toks, relpath: str) -> dict[str, str]:
    """yerel ad → çözümlenmiş göreli modül yolu (uzantısız)."""
    out: dict[str, str] = {}
    base = PurePosixPath(relpath).parent
    n = len(toks)
    for i, tok in enumerate(toks):
        # const X = require('./y')
        if tok.kind == "id" and tok.value == "require" and i + 2 < n and toks[i + 1].value == "(" and toks[i + 2].kind == "str":
            spec = toks[i + 2].value
            if i >= 2 and toks[i - 1].value == "=" and toks[i - 2].kind == "id" and spec.startswith("."):
                out[toks[i - 2].value] = _norm_module(base, spec)
        # import X from './y'
        if tok.kind == "id" and tok.value == "import" and i + 3 < n and toks[i + 1].kind == "id" and toks[i + 2].value == "from" and toks[i + 3].kind == "str":
            spec = toks[i + 3].value
            if spec.startswith("."):
                out[toks[i + 1].value] = _norm_module(base, spec)
    return out


def _norm_module(base: PurePosixPath, spec: str) -> str:
    parts: list[str] = list(base.parts)
    for piece in PurePosixPath(spec).parts:
        if piece == ".":
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    text = "/".join(parts)
    return re.sub(r"\.(js|mjs|cjs|ts|mts|cts)$", "", text)


def _js_prepass(relpath: str, toks, project: _Project) -> None:
    """app.use('/x', auth, xRouter) / app.use(auth) öncesi bağlanan içe aktarılmış yönlendiricileri işaretle."""
    requires = _js_require_map(toks, relpath)
    n = len(toks)
    for i in range(n - 3):
        tok = toks[i]
        if tok.kind == "id" and tok.value in {"useGlobalGuards", "APP_GUARD"}:
            project.nest_global_guard = True
        if not (tok.kind == "id" and toks[i + 1].value == "." and toks[i + 2].value == "use" and toks[i + 3].value == "("):
            continue
        close = _match_close(toks, i + 3)
        args = _split_args(toks, i + 3, close)
        if toks[args[0][0]].kind == "str" if args else False:
            args = args[1:]
        auth = any(_js_arg_is_auth(toks, a, b) for a, b in args[:-1])
        if not auth:
            continue
        last_a, last_b = args[-1]
        names = [t.value for t in toks[last_a:last_b] if t.kind == "id"]
        if names and names[0] == "require" and toks[last_a + 2].kind == "str":
            project.js_protected_modules.add(_norm_module(PurePosixPath(relpath).parent, toks[last_a + 2].value))
        elif names and names[0] in requires:
            project.js_protected_modules.add(requires[names[0]])


def _js_routes(relpath: str, toks, project: _Project) -> list[Route]:
    routes: list[Route] = []
    group = _group(relpath, "js")
    module_key = re.sub(r"\.(js|mjs|cjs|ts|mts|cts)$", "", relpath)
    module_protected = module_key in project.js_protected_modules
    n = len(toks)
    # Yönlendirici düzeyi koruma: X.use(auth) / X.use('/p', auth) sonrasında tanımlanan rotalar.
    guarded: list[tuple[int, str, str]] = []  # (dizin, yönlendirici, önek)
    i = 0
    while i < n - 3:
        tok = toks[i]
        if tok.kind == "id" and toks[i + 1].value == "." and toks[i + 2].kind == "id" and toks[i + 3].value == "(":
            router, method = tok.value, toks[i + 2].value
            if (i >= 1 and toks[i - 1].value == ".") or router in _JS_NOT_ROUTERS:
                i += 1
                continue
            if method == "use":
                close = _match_close(toks, i + 3)
                args = _split_args(toks, i + 3, close)
                prefix = ""
                if args and toks[args[0][0]].kind == "str":
                    prefix = toks[args[0][0]].value
                    args = args[1:]
                mw = args if (len(args) == 1 or not args) else args
                if any(_js_arg_is_auth(toks, a, b) for a, b in mw) and not (len(args) >= 2 and _js_is_router_ref(toks, *args[-1])):
                    guarded.append((i, router, prefix))
                i = close
                continue
            if method in _JS_METHODS:
                close = _match_close(toks, i + 3)
                args = _split_args(toks, i + 3, close)
                if len(args) >= 2 and toks[args[0][0]].kind in {"str", "tpl"} and toks[args[0][0]].value.startswith("/") \
                        and _js_handler_like(toks, *args[-1]):
                    path = toks[args[0][0]].value
                    route = _js_make_route(relpath, toks, tok.line, router, _JS_METHODS[method], path, args[1:], guarded, i, module_protected, group)
                    routes.append(route)
                i = close
                continue
            if method == "route":  # router.route('/x').get(h).post(h)
                close = _match_close(toks, i + 3)
                args = _split_args(toks, i + 3, close)
                if args and toks[args[0][0]].kind == "str" and toks[args[0][0]].value.startswith("/"):
                    path = toks[args[0][0]].value
                    j = close + 1
                    while j + 2 < n and toks[j].value == "." and toks[j + 1].kind == "id" and toks[j + 1].value in _JS_METHODS and toks[j + 2].value == "(":
                        cclose = _match_close(toks, j + 2)
                        cargs = _split_args(toks, j + 2, cclose)
                        if cargs:
                            routes.append(_js_make_route(relpath, toks, toks[j + 1].line, router, _JS_METHODS[toks[j + 1].value], path, cargs, guarded, i, module_protected, group))
                        j = cclose + 1
                    i = j
                    continue
        i += 1
    routes.extend(_nest_routes(relpath, toks, project, group))
    return routes


def _js_is_router_ref(toks, a: int, b: int) -> bool:
    ids = [t.value for t in toks[a:b] if t.kind == "id"]
    return bool(ids) and (ids[0] == "require" or re.search(r"(?i)(router|routes|api|controller)", ids[-1]) is not None) and not _js_is_function_arg(toks, a, b)


def _js_handler_like(toks, a: int, b: int) -> bool:
    if _js_is_function_arg(toks, a, b):
        return True
    ids = [t for t in toks[a:b]]
    return bool(ids) and all(t.kind == "id" or (t.kind == "punct" and t.value in {".", "(", ")"}) for t in ids)


def _js_make_route(relpath, toks, line, router, method, path, handler_args, guarded, index, module_protected, group) -> Route:
    protection: str | None = None
    public = False
    middleware = handler_args[:-1]
    for a, b in middleware:
        ids = [t.value for t in toks[a:b] if t.kind == "id"]
        if any(_PUBLIC_MARK_RE.search(x) for x in ids):
            public = True
        if _js_arg_is_auth(toks, a, b):
            protection = "middleware:" + (ids[0] if ids else "?")
            break
    if protection is None:
        for g_index, g_router, prefix in guarded:
            if g_index < index and g_router == router and path.startswith(prefix or "/"):
                protection = "router.use"
                break
    if protection is None and module_protected:
        protection = "mounted"
    ha, hb = handler_args[-1]
    body = _tok_text(toks, ha, hb)
    if protection is None and _js_is_function_arg(toks, ha, hb) and _JS_INLINE_AUTH_RE.search(body):
        protection = "inline"
    if _js_is_function_arg(toks, ha, hb):
        named = toks[ha + 1].value if toks[ha].value == "function" and ha + 1 < hb and toks[ha + 1].kind == "id" else ""
        handler = named or "(anonim)"
    else:
        handler = "".join(t.value for t in toks[ha:hb] if t.kind == "id" or t.value == ".") or "?"
    route = Route(relpath, line, "express/koa", (method,), path, handler, protection, public, group=group)
    if _js_is_function_arg(toks, ha, hb):
        idor = _js_idor(toks, ha, hb, path, body)
        if idor:
            route.idor = idor
    return route


def _js_idor(toks, a: int, b: int, path: str, body: str) -> dict[str, Any] | None:
    if _JS_USER_REF_RE.search(body) or _ADMIN_CHECK_RE.search(body):
        return None
    ids: set[str] = {m for m in re.findall(r":(\w+)", path) if _ID_NAME_RE.search(m)}
    direct: set[tuple[int, int]] = set()
    for j in range(a, b - 4):
        # req.params.id / ctx.params.id / req.body.userId
        if toks[j].kind == "id" and toks[j].value in {"req", "ctx", "request"} and toks[j + 1].value == "." \
                and toks[j + 2].kind == "id" and toks[j + 2].value in _JS_ID_SOURCES and toks[j + 3].value == "." \
                and toks[j + 4].kind == "id" and _ID_NAME_RE.search(toks[j + 4].value):
            direct.add((j, j + 5))
            if j >= 2 and toks[j - 1].value == "=" and toks[j - 2].kind == "id":
                ids.add(toks[j - 2].value)
        # const { id } = req.params
        if toks[j].value == "{" and toks[j].kind == "punct":
            close = _match_close(toks, j)
            if close + 4 < b and toks[close + 1].value == "=" and toks[close + 2].kind == "id" and toks[close + 2].value in {"req", "ctx"} \
                    and toks[close + 3].value == "." and toks[close + 4].kind == "id" and toks[close + 4].value in _JS_ID_SOURCES:
                for t in toks[j + 1:close]:
                    if t.kind == "id" and _ID_NAME_RE.search(t.value):
                        ids.add(t.value)
    if not ids and not direct:
        return None
    for j in range(a, b - 2):
        if toks[j].value == "." and toks[j + 1].kind == "id" and toks[j + 1].value in _JS_LOOKUP_METHODS and toks[j + 2].value == "(":
            k = j - 1
            if k >= 0 and toks[k].kind == "punct" and toks[k].value == ")":
                depth = 0
                while k >= 0:
                    if toks[k].value == ")":
                        depth += 1
                    elif toks[k].value == "(":
                        depth -= 1
                        if depth == 0:
                            break
                    k -= 1
                k -= 1
            receiver = toks[k].value if k >= 0 else ""
            if receiver in {"req", "res", "ctx", "params", "query", "body", "headers", "Object", "Array", "Promise", "JSON", "console", "router", "app"}:
                continue
            close = _match_close(toks, j + 2)
            arg_ids = {t.value for t in toks[j + 3:close] if t.kind == "id"}
            uses_id = bool(arg_ids & ids) or any(s >= j + 3 and e <= close for s, e in direct)
            if not uses_id:
                # SQL dizesi içinde birleştirme: "… WHERE id = " + id
                for t in toks[j + 3:close]:
                    if t.kind == "tpl" and any(any(p.kind == "id" and p.value in ids for p in part) for part in t.parts):
                        uses_id = True
            if uses_id and toks[j + 1].value in {"get", "all", "run", "query", "execute", "where", "update", "remove", "find"}:
                # Genel adlı yöntemler: yalnız veritabanı benzeri alıcıda.
                if not _is_database_receiver(receiver):
                    continue
            if uses_id:
                return {"line": toks[j + 1].line, "lookup": f"{receiver}.{toks[j + 1].value}"}
    return None


def _nest_routes(relpath: str, toks, project: _Project, group: str) -> list[Route]:
    """NestJS: @Controller sınıfı + @Get/@Post… yöntemleri; @UseGuards (sınıf/yöntem) ya da genel guard koruma sayılır."""
    routes: list[Route] = []
    n = len(toks)
    decorators: list[tuple[str, int, int]] = []  # (ad, açılış, kapanış)
    class_ctx: list[tuple[int, str, bool, bool]] = []  # (gövde sonu, önek, korunan, açık)
    guard_names = {"UseGuards", "Auth", "Roles", "Authorized", "Authenticated"}
    modifiers = {"async", "public", "private", "protected", "static", "readonly", "export", "default", "abstract", "get", "set"}
    i = 0
    while i < n:
        while class_ctx and i > class_ctx[-1][0]:
            class_ctx.pop()
        tok = toks[i]
        if tok.kind == "punct" and tok.value == "@" and i + 1 < n and toks[i + 1].kind == "id":
            name = toks[i + 1].value
            j = i + 2
            while j + 1 < n and toks[j].value == "." and toks[j + 1].kind == "id":
                name = toks[j + 1].value
                j += 2
            if j < n and toks[j].value == "(":
                close = _match_close(toks, j)
                decorators.append((name, j, close))
                i = close + 1
            else:
                decorators.append((name, j, j))
                i = j
            continue
        if tok.kind == "id" and tok.value == "class":
            names = [d[0] for d in decorators]
            if "Controller" in names:
                ctl = next(d for d in decorators if d[0] == "Controller")
                prefix = toks[ctl[1] + 1].value if ctl[2] > ctl[1] + 1 and toks[ctl[1] + 1].kind == "str" else ""
                guarded = any(d[0] in guard_names for d in decorators)
                public = any(_PUBLIC_MARK_RE.search(d[0]) for d in decorators)
                k = i
                while k < n and toks[k].value != "{":
                    k += 1
                if k < n:
                    class_ctx.append((_match_close(toks, k), prefix, guarded, public))
                    decorators = []
                    i = k + 1
                    continue
            decorators = []
        elif decorators and class_ctx and tok.kind == "id" and tok.value not in modifiers and i + 1 < n and toks[i + 1].value == "(":
            http = next((d for d in decorators if d[0] in {"Get", "Post", "Put", "Patch", "Delete", "All"}), None)
            if http is not None:
                _end, prefix, cls_guard, cls_public = class_ctx[-1]
                sub = toks[http[1] + 1].value if http[2] > http[1] + 1 and toks[http[1] + 1].kind == "str" else ""
                path = "/" + "/".join(p.strip("/") for p in (prefix, sub) if p.strip("/"))
                guard = cls_guard or any(d[0] in guard_names for d in decorators)
                public = cls_public or any(_PUBLIC_MARK_RE.search(d[0]) for d in decorators)
                protection = "guard" if guard else ("global-guard" if project.nest_global_guard and not public else None)
                routes.append(Route(relpath, tok.line, "nestjs", (http[0].upper(),), path, tok.value, protection, public, group=group))
            decorators = []
        elif decorators and tok.kind == "punct" and tok.value in {";", ",", ")", "=", "{", "}"}:
            decorators = []
        i += 1
    return routes


# ---------------------------------------------------------------------------
# Proje analizi
# ---------------------------------------------------------------------------
def analyze_sources(sources: Iterable[tuple[str, str] | tuple[str, str, ast.Module, list[ast.AST]]]) -> dict[str, Any]:
    """``(göreli_yol, metin)`` çiftlerinden rota envanteri ve bulgu adayları üret. Python için ek öğeler olarak
    aynı metnin ayrıştırılmış ağacı ve ``ast.walk`` sırasındaki düğüm listesi verilebilir (proje analizi zaten
    ayrıştırdı; ikisi de değiştirilmez)."""
    files = [item for item in sources if len(item[1]) <= MAX_SOURCE_BYTES]
    rails_controller_contexts = analyze_rails_controller_inheritance(files)
    project = _Project()
    parsed_py: list[tuple[str, ast.Module]] = []
    parsed_js: list[tuple[str, Any]] = []
    parsed_ruby: list[tuple[str, str]] = []
    parsed_jvm_dotnet: list[dict[str, Any]] = []
    for item in files:
        rel, text = item[0], item[1]
        if rel.endswith(PY_SUFFIXES):
            nodes = None
            if len(item) > 2:
                tree, nodes = item[2], item[3]
            else:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        tree = ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    continue
            parsed_py.append((rel, tree))
            _py_prepass(rel, tree, project, nodes, text)
        elif rel.endswith(JS_SUFFIXES) and not rel.endswith(".d.ts"):
            if not re.search(r"\.(get|post|put|patch|delete|del|all|route|use)\s*\(|@(Controller|Get|Post)\b|useGlobalGuards|APP_GUARD", text):
                continue
            toks = _js_tokens(text)
            if toks is None:
                continue
            parsed_js.append((rel, toks))
            _js_prepass(rel, toks, project)
        elif rel.endswith(RUBY_SUFFIXES):
            parsed_ruby.append((rel, text))
        elif rel.endswith(JAVA_SUFFIXES):
            parsed_jvm_dotnet.extend(authz_jvm_dotnet.spring_routes(rel, text))
        elif rel.endswith(CSHARP_SUFFIXES):
            parsed_jvm_dotnet.extend(authz_jvm_dotnet.aspnet_routes(rel, text))
    for rel, text in parsed_ruby:
        _rails_prepass(rel, text, project)
    routes: list[Route] = []
    for rel, tree in parsed_py:
        try:
            routes.extend(_py_routes(rel, tree, project))
        except RecursionError:
            continue
    for rel, toks in parsed_js:
        routes.extend(_js_routes(rel, toks, project))
    for rel, text in parsed_ruby:
        routes.extend(_ruby_routes(rel, text, project, rails_controller_contexts))
    for item in parsed_jvm_dotnet:
        item["group"] = _group(str(item["file"]), "java" if item["framework"] == "spring" else "csharp")
        routes.append(Route(**item))
    asymmetric_resources = detect_asymmetric_resource_authz(routes)
    findings = _findings(routes)
    inv = inventory(routes, asymmetric_resources=asymmetric_resources)
    return {
        "routes": routes,
        "findings": findings,
        "summary": inv["summary"],
        "asymmetric_resources": asymmetric_resources,
        "rails_controller_contexts": rails_controller_contexts,
    }


_PUBLIC_FILE_RE = re.compile(r"(?i)(^|[/._-])(auth|login|logout|register|signup|signin|sessions?|oauth|sso|webhooks?|public)([/._-]|$)")
_PARAM_SEGMENT_RE = re.compile(
    r"^(?:\{[^}]+\}|<[^>]+>|:[A-Za-z0-9_]+|\[+\.?\.?\.?[A-Za-z0-9_]+\]+|\$\{?[A-Za-z0-9_]+\}?|\([0-9a-zA-Z_\\+.*?|]+\))$"
)
_TRAILING_ACTION_VERBS = frozenset({
    "delete", "cancel", "abort", "update", "remove", "destroy", "edit",
    "archive", "approve", "reject", "close", "revoke", "reset", "disable", "enable",
})
_ASYMMETRIC_REASON_SUFFIX = (
    "[Asimetrik Yetki: Aynı kaynağın kardeş uçlarında yetki denetimi varken bu uçta unutulmuş (CWE-862/CWE-639)]"
)


def _normalize_resource_key(path: str) -> str:
    """Rota yolundaki parametreleri (/{id}, /<int:id>, /:id, /[id]) ve sondaki eylem fiillerini
    (/delete, /cancel, /abort, /update vb.) soyarak temel REST kaynağını belirler."""
    if not isinstance(path, str) or not path.strip():
        return "/"
    clean = path.strip().split("?", 1)[0].split("#", 1)[0].strip()
    raw_segments = [seg.strip() for seg in clean.strip("^$/ ").split("/") if seg.strip()]
    segments = [seg for seg in raw_segments if not _PARAM_SEGMENT_RE.match(seg)]
    while len(segments) > 1 and segments[-1].casefold() in _TRAILING_ACTION_VERBS:
        segments.pop()
    if not segments:
        return "/"
    return "/" + "/".join(seg.casefold() for seg in segments)


def _is_public_path(route: Route) -> bool:
    if _PUBLIC_FILE_RE.search(route.file):
        return True
    return bool(_PUBLIC_PATH_RE.search(route.path or "") or _PUBLIC_PATH_RE.search(route.handler or "")) or route.path in {"*", "/*"}


def _route_path(r: Any) -> str:
    return str(r.get("path") or "") if isinstance(r, dict) else str(r.path or "")


def _route_app_key(r: Any) -> str:
    if isinstance(r, dict):
        key = r.get("app_key") or r.get("group") or r.get("app")
        if key:
            return str(key)
        rel = str(r.get("file") or "")
        return _group(rel, "py") if rel else "default"
    return r.group or (_group(r.file, "py") if r.file else "default")


def _route_is_public(r: Any) -> bool:
    if isinstance(r, dict):
        if r.get("public") or r.get("public_mark") or r.get("status") == "public":
            return True
        path = str(r.get("path") or "")
        handler = str(r.get("handler") or "")
        file_rel = str(r.get("file") or "")
        if file_rel and _PUBLIC_FILE_RE.search(file_rel):
            return True
        return bool(_PUBLIC_PATH_RE.search(path) or _PUBLIC_PATH_RE.search(handler)) or path in {"*", "/*"}
    return bool(r.public_mark or _is_public_path(r))


def _route_is_protected(r: Any) -> bool:
    if isinstance(r, dict):
        return bool(r.get("protection") or r.get("protected") or r.get("status") == "protected")
    return bool(r.protection or r.status == "protected")


def _route_endpoint_label(r: Any) -> str:
    if isinstance(r, dict):
        methods = r.get("methods") or ([r["method"]] if r.get("method") else ["GET"])
        if isinstance(methods, str):
            methods = [methods]
        path = str(r.get("path") or r.get("handler") or "")
    else:
        methods = list(r.methods) or ["GET"]
        path = str(r.path or r.handler or "")
    return f"{'/'.join(str(m).upper() for m in methods)} {path}".strip()


def detect_asymmetric_resource_authz(routes: list[Any]) -> list[dict[str, Any]]:
    """Rotaları (app_key, _normalize_resource_key(path)) ile gruplar. Aynı kaynak üzerinde en az bir
    korumalı (protected) uç ve en az bir korumasız kardeş uç varsa, korumasız kardeş uçları
    asymmetric_authz=True ve status='unprotected' olarak işaretler."""
    resource_groups: dict[tuple[str, str], list[Any]] = {}
    for r in routes:
        res_key = _normalize_resource_key(_route_path(r))
        if not res_key or res_key == "/":
            continue
        app_key = _route_app_key(r)
        resource_groups.setdefault((app_key, res_key), []).append(r)

    asymmetric_resources: list[dict[str, Any]] = []
    for (app_key, res_key), grp in resource_groups.items():
        protected_routes = [r for r in grp if _route_is_protected(r)]
        unprotected_routes = [
            r for r in grp if not _route_is_protected(r) and not _route_is_public(r)
        ]
        if not protected_routes or not unprotected_routes:
            continue
        for r in unprotected_routes:
            if isinstance(r, dict):
                r["asymmetric_authz"] = True
                r["status"] = "unprotected"
                cur_reason = str(r.get("reason") or "")
                if _ASYMMETRIC_REASON_SUFFIX not in cur_reason:
                    r["reason"] = cur_reason + " " + _ASYMMETRIC_REASON_SUFFIX
            else:
                r.asymmetric_authz = True
                r.status = "unprotected"
                cur_reason = str(r.reason or "")
                if _ASYMMETRIC_REASON_SUFFIX not in cur_reason:
                    r.reason = cur_reason + " " + _ASYMMETRIC_REASON_SUFFIX
        prot_eps = [_route_endpoint_label(r) for r in protected_routes]
        unprot_eps = [_route_endpoint_label(r) for r in unprotected_routes]
        asymmetric_resources.append({
            "resource": res_key,
            "app_key": app_key,
            "protected_Endpoints": prot_eps,
            "unprotected_Endpoints": unprot_eps,
            "protected_endpoints": prot_eps,
            "unprotected_endpoints": unprot_eps,
        })
    return asymmetric_resources


def _findings(routes: list[Route]) -> list[dict[str, Any]]:
    detect_asymmetric_resource_authz(routes)
    findings: list[dict[str, Any]] = []
    groups: dict[str, list[Route]] = {}
    for route in routes:
        groups.setdefault(route.group, []).append(route)
    for group_routes in groups.values():
        considered = [r for r in group_routes if not r.public_mark and not _is_public_path(r)]
        protected = [r for r in considered if r.protection]
        majority = len(considered) >= 4 and len(protected) >= 3 and len(protected) * 2 >= len(considered)
        flagged: set[int] = set()
        for route in considered:
            if route.protection or not (majority or route.asymmetric_authz):
                continue
            admin = bool(_ADMIN_PATH_RE.search(route.path or ""))
            mutating = bool(set(route.methods) & MUTATING) or "ALL" in route.methods
            if mutating and set(route.methods) <= {"GET", "POST"} and _READ_POST_RE.search(f"{route.path} {route.handler}"):
                mutating = False  # arama/süzme formu: POST ama okuma
            if not (admin or mutating or (route.asymmetric_authz and _PRIVATE_RESOURCE_RE.search(route.path or ""))):
                continue
            flagged.add(id(route))
            extra_reason = f" {route.reason.strip()}" if route.asymmetric_authz and route.reason else ""
            findings.append({
                "file": route.file, "line": route.line, "severity": "medium",
                "title": "Korumasız hassas rota: kimlik doğrulama/yetki denetimi görülmedi (gözden geçirme)",
                "evidence": (
                    f"{'/'.join(route.methods)} {route.path or route.handler} ({route.framework}); aynı uygulamadaki "
                    f"{len(considered)} rotanın {len(protected)} tanesi korumalı, bu rota için dekoratör/ara katman/satır içi denetim bulunamadı.{extra_reason}"
                ),
                "recommendation": (
                    "Rotanın bilerek açık olup olmadığını doğrulayın; değilse uygulamanın diğer rotalarındaki kimlik doğrulama ve "
                    "yetki denetimini (dekoratör, ara katman, guard, permission_classes) ekleyin."
                ),
                "reference": "CWE-862",
            })
        for route in group_routes:
            if not route.idor or route.public_mark or id(route) in flagged or _is_public_path(route):
                continue
            if not route.protection:  # IDOR yalnız kimliği doğrulanmış (açıkça korunan) rotada anlamlı
                continue
            lookup_name = str(route.idor.get("lookup") or "").rsplit(".", 1)[-1]
            write_lookup = bool(re.match(r"(?i)(remove|delete|destroy|update|replace|save|findOneAnd|findByIdAnd)", lookup_name))
            mutating = bool(set(route.methods) & MUTATING) or write_lookup
            if not mutating and not _PRIVATE_RESOURCE_RE.search(f"{route.path} {route.handler} {route.idor.get('lookup')}"):
                continue  # herkese açık olabilecek kaynağın okunması (ör. resim beğenileri): gürültü yapma
            findings.append({
                "file": route.file, "line": int(route.idor.get("line") or route.line),
                "severity": "medium" if mutating else "low",
                "title": "Nesne düzeyi yetki adayı (IDOR): istekteki kimlikle kayıt erişimi, sahiplik denetimi görülmedi (gözden geçirme)",
                "evidence": (
                    f"{'/'.join(route.methods)} {route.path or route.handler}: {route.idor.get('lookup')} çağrısı istekten gelen kimliği "
                    "kullanıyor; işleyicide geçerli kullanıcıya bağlı filtre ya da sahiplik/rol denetimi görülmedi. Statik tahmin; düşük kesinlik."
                ),
                "recommendation": (
                    "Kaydı geçerli kullanıcıya göre daraltın (ör. filter(owner=request.user), { _id, owner: req.user.id }) ya da "
                    "erişimden önce sahiplik/rol denetimi yapın; yetkisiz erişimde 404/403 döndürün."
                ),
                "reference": "CWE-639",
            })
    return findings


def inventory(routes: list[Route], asymmetric_resources: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if asymmetric_resources is None:
        asymmetric_resources = detect_asymmetric_resource_authz(routes)
    considered = [r for r in routes if not r.public_mark and not _is_public_path(r)]
    frameworks: dict[str, int] = {}
    for route in routes:
        frameworks[route.framework] = frameworks.get(route.framework, 0) + 1
    ordered = sorted(routes, key=lambda r: (bool(r.protection), r.file, r.line))
    unprotected_sensitive = sum(
        1 for r in considered
        if not r.protection and (r.asymmetric_authz or r.status == "unprotected" or set(r.methods) & MUTATING or _ADMIN_PATH_RE.search(r.path or ""))
    )
    return {
        "summary": {
            "total": len(routes),
            "protected": sum(1 for r in routes if r.protection),
            "unprotected": unprotected_sensitive,
            "unprotected_sensitive": unprotected_sensitive,
            "public_marked": sum(1 for r in routes if r.public_mark),
            "idor_candidates": sum(1 for r in routes if r.idor),
            "asymmetric_resources": len(asymmetric_resources),
            "frameworks": dict(sorted(frameworks.items())),
            "truncated": len(routes) > MAX_ROUTES_REPORTED,
        },
        "routes": [r.public() for r in ordered[:MAX_ROUTES_REPORTED]],
        "asymmetric_resources": asymmetric_resources,
    }


def analyze_routes(
    sources_or_routes: Iterable[Any] | str,
    *,
    filename: str = "routes.py",
) -> dict[str, Any]:
    """Kaynak çiftlerini, kaynak metnini veya önceden çıkarılmış rota sözlüklerini/nesnelerini analiz eder;
    asimetrik kaynak yetkilendirme matrisini (asymmetric_resources) ve summary['unprotected'] sayısını üretir."""
    if isinstance(sources_or_routes, str):
        analyzed = analyze_sources([(filename, sources_or_routes)])
        inv = inventory(analyzed["routes"], asymmetric_resources=analyzed["asymmetric_resources"])
        return {
            "summary": inv["summary"],
            "routes": inv["routes"],
            "findings": analyzed["findings"],
            "asymmetric_resources": analyzed["asymmetric_resources"],
        }
    items = list(sources_or_routes)
    if not items:
        return {
            "summary": {
                "total": 0,
                "protected": 0,
                "unprotected": 0,
                "unprotected_sensitive": 0,
                "public_marked": 0,
                "idor_candidates": 0,
                "asymmetric_resources": 0,
                "frameworks": {},
                "truncated": False,
            },
            "routes": [],
            "findings": [],
            "asymmetric_resources": [],
        }
    first = items[0]
    if isinstance(first, tuple):
        analyzed = analyze_sources(items)
        inv = inventory(analyzed["routes"], asymmetric_resources=analyzed["asymmetric_resources"])
        return {
            "summary": inv["summary"],
            "routes": inv["routes"],
            "findings": analyzed["findings"],
            "asymmetric_resources": analyzed["asymmetric_resources"],
        }
    if isinstance(first, Route):
        asymmetric_resources = detect_asymmetric_resource_authz(items)
        inv = inventory(items, asymmetric_resources=asymmetric_resources)
        return {
            "summary": inv["summary"],
            "routes": inv["routes"],
            "findings": _findings(items),
            "asymmetric_resources": asymmetric_resources,
        }
    if isinstance(first, dict):
        asymmetric_resources = detect_asymmetric_resource_authz(items)
        unprotected_count = sum(
            1 for r in items
            if r.get("status") == "unprotected" or r.get("asymmetric_authz")
        )
        protected_count = sum(1 for r in items if _route_is_protected(r))
        public_count = sum(1 for r in items if _route_is_public(r))
        idor_count = sum(1 for r in items if r.get("idor_candidate") or r.get("idor"))
        frameworks: dict[str, int] = {}
        for r in items:
            fw = str(r.get("framework") or "unknown")
            frameworks[fw] = frameworks.get(fw, 0) + 1
        return {
            "summary": {
                "total": len(items),
                "protected": protected_count,
                "unprotected": unprotected_count,
                "unprotected_sensitive": unprotected_count,
                "public_marked": public_count,
                "idor_candidates": idor_count,
                "asymmetric_resources": len(asymmetric_resources),
                "frameworks": dict(sorted(frameworks.items())),
                "truncated": len(items) > MAX_ROUTES_REPORTED,
            },
            "routes": items[:MAX_ROUTES_REPORTED],
            "findings": [],
            "asymmetric_resources": asymmetric_resources,
        }
    return {
        "summary": {"total": 0, "protected": 0, "unprotected": 0, "asymmetric_resources": 0},
        "routes": [],
        "findings": [],
        "asymmetric_resources": [],
    }

_SPRING_MAPPING_RE = re.compile(
    r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\b"
)
_SPRING_LOOKUP_RE = re.compile(
    r"\b(?:\w*(?:Repository|Repo|Service|Dao|repository|repo)\s*\.\s*(?:findById|getById|getReferenceById)"
    r"|entityManager\s*\.\s*find)\s*\("
)
_SPRING_SAFE_RE = re.compile(
    r"(?:@PreAuthorize\b|@PostAuthorize\b|@Secured\b|@RolesAllowed\b|@AuthenticationPrincipal\b"
    r"|\bPrincipal\b|\bSecurityContextHolder\b|\b(?:tenantId|organizationId|userId|ownerId)\b"
    r"|\bfindByIdAnd(?:Tenant|User|Owner|Organization)\w*\b)"
)

_ASPNET_ROUTE_RE = re.compile(
    r"\[Http(?:Get|Post|Put|Delete|Patch)\b[^\]]*\]"
)
_ASPNET_LOOKUP_RE = re.compile(
    r"\b(?:_context|dbContext|_db|context)\s*\.\s*\w+\s*\.\s*(?:FindAsync|Find|FirstOrDefaultAsync|FirstOrDefault|SingleOrDefaultAsync|SingleOrDefault)\s*\("
)
_ASPNET_SAFE_RE = re.compile(
    r"(?:\bUser\.FindFirst\b|\bUser\.Identity\b|\bClaimTypes\b|\bAuthorizeAsync\b"
    r"|\b(?:TenantId|tenantId|OrganizationId|organizationId|UserId|userId|OwnerId|ownerId)\b"
    r"|\[Authorize\s*\(\s*(?:Policy|Roles)\s*=)"
)

_NEST_EXPRESS_ROUTE_RE = re.compile(
    r"(?:@(?:Get|Post|Put|Delete|Patch)\s*\(|\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\()"
)
_PRISMA_ID_LOOKUP_RE = re.compile(
    r"\b(?:this\.)?prisma\s*\.\s*\w+\s*\.\s*(?:findUnique|findFirst|update|delete)\s*\(\s*\{\s*where\s*:\s*\{([^}]*)\}",
    re.DOTALL,
)
_NEST_TENANT_SAFE_RE = re.compile(
    r"\b(?:userId|tenantId|organizationId|ownerId|accountId)\b"
)

_PY_ID_LOOKUP_RE = re.compile(
    r"(?:\b[A-Z]\w*\.objects\.get\s*\(([^)]*)"
    r"|\bget_object_or_404\s*\(\s*[A-Z]\w*\s*,([^)]*)"
    r"|\b(?:session|db)\.get\s*\(\s*[A-Z]\w*\s*,\s*([^)]*)\))"
)
_PY_TENANT_SAFE_RE = re.compile(
    r"(?:\b(?:user|owner|tenant|tenant_id|organization|organization_id|user_id|account_id)\s*="
    r"|\b(?:tenant_id|user_id|owner_id|organization_id)\s*==\s*(?:request\.user|current_user)"
    r"|\bDepends\s*\(\s*get_current_user\s*\))"
)


def audit_multilang_route_tenant_authz(
    raw_content: str,
    *,
    filename: str = "OrderController.java",
) -> dict[str, Any]:
    """Audit Spring Boot, ASP.NET Core, Express/NestJS, and Django/FastAPI routes for unscoped IDOR/tenant lookups."""
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {
            "format": "sniper-multilang-route-tenant-authz/1",
            "filename": filename,
            "finding_count": 0,
            "findings": [],
        }

    ext = PurePosixPath(str(filename or "").replace("\\", "/")).suffix.casefold()
    findings: list[dict[str, Any]] = []

    # (a) Spring Boot (Java / Kotlin)
    if ext in {".java", ".kt"} or _SPRING_MAPPING_RE.search(raw_content):
        mapping_matches = list(_SPRING_MAPPING_RE.finditer(raw_content))
        for idx, m in enumerate(mapping_matches):
            start = max(0, m.start() - 160)
            end = mapping_matches[idx + 1].start() if idx + 1 < len(mapping_matches) else min(len(raw_content), m.end() + 700)
            window = raw_content[start:end]
            lookup = _SPRING_LOOKUP_RE.search(window)
            if lookup and not _SPRING_SAFE_RE.search(window):
                line_no = raw_content.count("\n", 0, m.start()) + 1
                findings.append({
                    "id": "SNIPER-AUTHZ-SPRING-01",
                    "rule_id": "SNIPER-AUTHZ-SPRING-01",
                    "control_id": "SNIPER-AUTHZ-SPRING-01",
                    "severity": "high",
                    "cwe": "CWE-639",
                    "reference": "CWE-639",
                    "framework": "spring",
                    "title": "Spring Boot yönlendirmesinde @PreAuthorize veya tenant/sahiplik kontrolü olmadan doğrudan ID sorgusu",
                    "evidence": lookup.group(0).strip(),
                    "filename": filename,
                    "line": line_no,
                    "location": f"{filename}:{line_no}",
                })

    # (b) ASP.NET Core (C#)
    if ext == ".cs" or _ASPNET_ROUTE_RE.search(raw_content):
        route_matches = list(_ASPNET_ROUTE_RE.finditer(raw_content))
        for idx, m in enumerate(route_matches):
            start = max(0, m.start() - 160)
            end = route_matches[idx + 1].start() if idx + 1 < len(route_matches) else min(len(raw_content), m.end() + 700)
            window = raw_content[start:end]
            lookup = _ASPNET_LOOKUP_RE.search(window)
            if lookup and not _ASPNET_SAFE_RE.search(window):
                line_no = raw_content.count("\n", 0, m.start()) + 1
                findings.append({
                    "id": "SNIPER-AUTHZ-ASPNET-02",
                    "rule_id": "SNIPER-AUTHZ-ASPNET-02",
                    "control_id": "SNIPER-AUTHZ-ASPNET-02",
                    "severity": "high",
                    "cwe": "CWE-639",
                    "reference": "CWE-639",
                    "framework": "aspnet",
                    "title": "ASP.NET Core aksiyonunda User/TenantId filtresi olmadan doğrudan varlık ID sorgusu",
                    "evidence": lookup.group(0).strip(),
                    "filename": filename,
                    "line": line_no,
                    "location": f"{filename}:{line_no}",
                })

    # (c) Express / NestJS (TypeScript / JavaScript)
    if ext in {".ts", ".js", ".mts", ".mjs"} or _PRISMA_ID_LOOKUP_RE.search(raw_content):
        if _NEST_EXPRESS_ROUTE_RE.search(raw_content):
            for lookup in _PRISMA_ID_LOOKUP_RE.finditer(raw_content):
                where_clause = lookup.group(1) or ""
                if re.search(r"\bid\b", where_clause) and not _NEST_TENANT_SAFE_RE.search(where_clause):
                    window = raw_content[max(0, lookup.start() - 220):min(len(raw_content), lookup.end() + 200)]
                    if not _NEST_TENANT_SAFE_RE.search(window):
                        line_no = raw_content.count("\n", 0, lookup.start()) + 1
                        findings.append({
                            "id": "SNIPER-AUTHZ-NEST-03",
                            "rule_id": "SNIPER-AUTHZ-NEST-03",
                            "control_id": "SNIPER-AUTHZ-NEST-03",
                            "severity": "high",
                            "cwe": "CWE-639",
                            "reference": "CWE-639",
                            "framework": "nestjs",
                            "title": "Express/NestJS Prisma sorgusunda tenantId/userId kapsamı olmadan doğrudan id erişimi",
                            "evidence": lookup.group(0).splitlines()[0].strip(),
                            "filename": filename,
                            "line": line_no,
                            "location": f"{filename}:{line_no}",
                        })

    # (d) Django / FastAPI (Python)
    if ext == ".py" or _PY_ID_LOOKUP_RE.search(raw_content):
        for lookup in _PY_ID_LOOKUP_RE.finditer(raw_content):
            args_text = (lookup.group(1) or lookup.group(2) or lookup.group(3) or "").strip()
            if not re.search(r"\b(?:id|pk|\w+_id)\b", args_text):
                continue
            window = raw_content[max(0, lookup.start() - 260):min(len(raw_content), lookup.end() + 220)]
            if not _PY_TENANT_SAFE_RE.search(args_text) and not _PY_TENANT_SAFE_RE.search(window):
                line_no = raw_content.count("\n", 0, lookup.start()) + 1
                findings.append({
                    "id": "SNIPER-AUTHZ-PY-04",
                    "rule_id": "SNIPER-AUTHZ-PY-04",
                    "control_id": "SNIPER-AUTHZ-PY-04",
                    "severity": "high",
                    "cwe": "CWE-639",
                    "reference": "CWE-639",
                    "framework": "python",
                    "title": "Django/FastAPI yönlendirmesinde kullanıcı veya tenant kapsamı olmadan doğrudan nesne sorgusu",
                    "evidence": lookup.group(0).strip(),
                    "filename": filename,
                    "line": line_no,
                    "location": f"{filename}:{line_no}",
                })

    return {
        "format": "sniper-multilang-route-tenant-authz/1",
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }



