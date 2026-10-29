"""Bounded, fail-closed Spring and ASP.NET authorization route extraction.

The parser intentionally accepts only literal route templates and direct controller or
minimal-API declarations.  It is not a Java/C# compiler; ambiguous syntax produces no
route rather than an inferred security claim.
"""

from __future__ import annotations

import re
from typing import Any


_SPRING_HTTP = {
    "GetMapping": ("GET",),
    "PostMapping": ("POST",),
    "PutMapping": ("PUT",),
    "PatchMapping": ("PATCH",),
    "DeleteMapping": ("DELETE",),
}
_CS_HTTP = {
    "HttpGet": ("GET",),
    "HttpPost": ("POST",),
    "HttpPut": ("PUT",),
    "HttpPatch": ("PATCH",),
    "HttpDelete": ("DELETE",),
}
_MINIMAL_HTTP = {
    "Get": ("GET",),
    "Post": ("POST",),
    "Put": ("PUT",),
    "Patch": ("PATCH",),
    "Delete": ("DELETE",),
}
_ID_RE = re.compile(r"(?i)(?:^|_)(?:id|pk|uuid|guid)(?:$|_)|(?:Id|ID|Guid|UUID)$")
_PATH_ID_RE = re.compile(r"\{\s*([A-Za-z_]\w*)(?::[^}]*)?\}")
_LOOKUP_RE = re.compile(
    r"(?P<receiver>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*"
    r"(?P<method>findById(?:And[A-Za-z_]\w*)?|deleteById|findOne|find|FindAsync|"
    r"Single(?:OrDefault)?(?:Async)?|First(?:OrDefault)?(?:Async)?|Remove|Update)\s*\(",
    re.IGNORECASE,
)
_JAVA_SUBJECT_RE = re.compile(
    r"(?i)(Authentication|Principal|SecurityContextHolder|currentUser|current_user|"
    r"getPrincipal|getAuthentication|getName\s*\(|owner(?:Id|Name)|tenant(?:Id|Name))"
)
_CS_SUBJECT_RE = re.compile(
    r"(?i)(HttpContext\s*\.\s*User|\bUser\s*\.|ClaimsPrincipal|FindFirst|Identity\s*\.\s*Name|"
    r"owner(?:Id|Name)|tenant(?:Id|Name))"
)
_ROLE_RE = re.compile(r"(?i)(has(?:Any)?Role|hasAuthority|ROLE_|Roles?\s*=|Policy\s*=|Secured|RolesAllowed)")


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _join_path(prefix: str, suffix: str) -> str:
    parts = [part.strip("/") for part in (prefix, suffix) if part.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


def _annotations(block: str, *, square: bool = False) -> list[tuple[str, str]]:
    if square:
        pattern = re.compile(
            r"^[ \t]*+\[[ \t]*+(?P<name>[A-Za-z_]\w*)"
            r"(?P<args>[ \t]*+\((?:[^)\"'\n]++|\"(?:[^\"\\]++|\\.)*+\"|'(?:[^'\\]++|\\.)*+')*+\))?[ \t]*+\][ \t]*+$",
            re.MULTILINE,
        )
    else:
        pattern = re.compile(
            r"^[ \t]*+@(?P<name>[A-Za-z_]\w*)"
            r"(?P<args>[ \t]*+\((?:[^)\"'\n]++|\"(?:[^\"\\]++|\\.)*+\"|'(?:[^'\\]++|\\.)*+')*+\))?"
            r"[ \t]*+$",
            re.MULTILINE,
        )
    return [(match.group("name"), match.group("args") or "") for match in pattern.finditer(block)]


def _literal_arg(args: str, *, allow_empty: bool = True) -> str | None:
    if not args.strip():
        return "" if allow_empty else None
    values = re.findall(r'"((?:[^"\\]++|\\.)*+)"', args)
    if len(values) != 1:
        return None
    # A single literal is accepted only when every non-literal token is an ordinary
    # named-argument wrapper.  Concatenation/interpolation is deliberately rejected.
    scrubbed = re.sub(r'"(?:[^"\\]++|\\.)*+"', '""', args)
    if "+" in scrubbed or "$" in scrubbed or re.search(r"\b[A-Za-z_]\w*\s*\(", scrubbed):
        return None
    return values[0].replace(r'\"', '"').replace(r"\\", "\\")


def _preceding_annotation_block(text: str, start: int, opener: str) -> str:
    lines = text[:start].splitlines()
    selected: list[str] = []
    while lines:
        line = lines.pop()
        stripped = line.strip()
        if not stripped:
            if selected:
                break
            continue
        if (opener == "@" and stripped.startswith("@")) or (opener == "[" and stripped.startswith("[")):
            selected.append(line)
            continue
        break
    return "\n".join(reversed(selected))


def _match_pair(text: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
        index += 1
    return None


def _auth(annotations: list[tuple[str, str]], *, spring: bool) -> tuple[str | None, bool, bool]:
    public_names = {"PermitAll", "AllowAnonymous"}
    for name, _args in annotations:
        if name in public_names:
            return None, True, False
    accepted = {"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed"} if spring else {"Authorize"}
    for name, args in annotations:
        if name in accepted:
            return (f"annotation:{name}" if spring else "attribute:Authorize"), False, bool(_ROLE_RE.search(name + args))
    return None, False, False


def _lookup(body: str, ids: set[str], *, subject_re: re.Pattern[str], base_line: int) -> dict[str, Any] | None:
    if not ids or subject_re.search(body):
        return None
    for match in _LOOKUP_RE.finditer(body):
        close = _match_pair(body, body.find("(", match.start()), "(", ")")
        if close is None:
            continue
        arguments = body[body.find("(", match.start()) + 1:close]
        if any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", arguments) for name in ids):
            return {
                "line": base_line + body.count("\n", 0, match.start()),
                "lookup": f"{match.group('receiver')}.{match.group('method')}",
            }
    return None


def spring_routes(relpath: str, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    class_re = re.compile(r"\bclass\s++(?P<name>[A-Za-z_]\w*+)[^\{;]*+\{", re.MULTILINE)
    method_re = re.compile(
        r"(?P<attrs>(?:^[ \t]*+@[A-Za-z_]\w*(?:\((?:[^)\"'\n]++|\"(?:[^\"\\]++|\\.)*+\"|'(?:[^'\\]++|\\.)*+')*+\))?[ \t]*+\n)++)"
        r"[ \t]*+(?:(?:public|protected|private|static|final|synchronized|abstract)\s++)*+"
        r"[A-Za-z_$][\w.$<>, ?\[\]]{0,512}?[ \t]++(?P<name>[A-Za-z_]\w*)\s*+\("
        r"(?P<params>(?:[^()]++|\([^()]*+\))*+)\)"
        r"(?:\s++throws\s++[^\{]++)?\s*+\{",
        re.MULTILINE,
    )
    for class_match in class_re.finditer(text):
        class_end = _match_pair(text, class_match.end() - 1, "{", "}")
        if class_end is None:
            continue
        declaration_line = text.rfind("\n", 0, class_match.start()) + 1
        class_attrs = _annotations(_preceding_annotation_block(text, declaration_line, "@"))
        if not any(name in {"RestController", "Controller"} for name, _ in class_attrs):
            continue
        request = next((args for name, args in class_attrs if name == "RequestMapping"), "")
        prefix = _literal_arg(request) if any(name == "RequestMapping" for name, _ in class_attrs) else ""
        if prefix is None:
            continue
        class_protection, class_public, class_role = _auth(class_attrs, spring=True)
        body_start = class_match.end()
        class_body = text[body_start:class_end]
        for method in method_re.finditer(class_body):
            attrs = _annotations(method.group("attrs"))
            mapping = next(((name, args) for name, args in attrs if name in _SPRING_HTTP or name == "RequestMapping"), None)
            if mapping is None:
                continue
            name, args = mapping
            path = _literal_arg(args)
            if path is None:
                continue
            methods = _SPRING_HTTP.get(name)
            if methods is None:
                values = sorted(set(re.findall(r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE)", args)))
                if not values:
                    continue
                methods = tuple(values)
            absolute = body_start + method.start()
            brace = body_start + method.end() - 1
            method_end = _match_pair(text, brace, "{", "}")
            if method_end is None or method_end > class_end:
                continue
            method_body = text[brace + 1:method_end]
            own_protection, own_public, own_role = _auth(attrs, spring=True)
            public = own_public or (class_public and own_protection is None)
            protection = None if public else (own_protection or class_protection)
            role_based = own_role or (own_protection is None and class_role)
            params = method.group("params")
            ids = set(_PATH_ID_RE.findall(path))
            ids.update(name for name in re.findall(r"\b([A-Za-z_]\w*)\s*(?:,|$)", params) if _ID_RE.search(name))
            idor = None if role_based else _lookup(
                method_body, ids, subject_re=_JAVA_SUBJECT_RE, base_line=_line(text, brace + 1)
            )
            routes.append({
                "file": relpath,
                "line": _line(text, absolute),
                "framework": "spring",
                "methods": methods,
                "path": _join_path(prefix, path),
                "handler": method.group("name"),
                "protection": protection,
                "public_mark": public,
                "idor": idor,
            })
    return routes


def _controller_token(path: str, class_name: str) -> str:
    controller = re.sub(r"Controller$", "", class_name)
    return re.sub(r"(?i)\[controller\]", controller.casefold(), path)


def aspnet_routes(relpath: str, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    class_re = re.compile(r"\bclass\s++(?P<name>[A-Za-z_]\w*+)[^\{;]*+\{", re.MULTILINE)
    method_re = re.compile(
        r"(?P<attrs>(?:^[ \t]*+\[(?:[^\]\"\n]++|\"(?:[^\"\\]++|\\.)*+\")++\][ \t]*+\n)++)"
        r"[ \t]*+(?:(?:public|protected|private|internal|static|sealed|virtual|override|async)\s++)*+"
        r"[A-Za-z_$][\w.$<>, ?\[\]]{0,512}?[ \t]++(?P<name>[A-Za-z_]\w*)\s*+\("
        r"(?P<params>(?:[^()]++|\([^()]*+\))*+)\)\s*+\{",
        re.MULTILINE,
    )
    for class_match in class_re.finditer(text):
        class_end = _match_pair(text, class_match.end() - 1, "{", "}")
        if class_end is None:
            continue
        declaration_line = text.rfind("\n", 0, class_match.start()) + 1
        class_attrs = _annotations(_preceding_annotation_block(text, declaration_line, "["), square=True)
        if not any(name in {"ApiController", "Route", "Authorize"} for name, _ in class_attrs):
            continue
        route_args = next((args for name, args in class_attrs if name == "Route"), None)
        prefix = _literal_arg(route_args, allow_empty=False) if route_args is not None else ""
        if prefix is None:
            continue
        prefix = _controller_token(prefix, class_match.group("name"))
        class_protection, class_public, class_role = _auth(class_attrs, spring=False)
        body_start = class_match.end()
        class_body = text[body_start:class_end]
        for method in method_re.finditer(class_body):
            attrs = _annotations(method.group("attrs"), square=True)
            mapping = next(((name, args) for name, args in attrs if name in _CS_HTTP), None)
            if mapping is None:
                continue
            name, args = mapping
            path = _literal_arg(args)
            if path is None:
                continue
            absolute = body_start + method.start()
            brace = body_start + method.end() - 1
            method_end = _match_pair(text, brace, "{", "}")
            if method_end is None or method_end > class_end:
                continue
            method_body = text[brace + 1:method_end]
            own_protection, own_public, own_role = _auth(attrs, spring=False)
            public = own_public or (class_public and own_protection is None)
            protection = None if public else (own_protection or class_protection)
            role_based = own_role or (own_protection is None and class_role)
            ids = set(_PATH_ID_RE.findall(path))
            ids.update(re.findall(r"\b(?:Guid|int|long|string)\s+([A-Za-z_]\w*)", method.group("params"), re.IGNORECASE))
            ids = {value for value in ids if _ID_RE.search(value)}
            idor = None if role_based else _lookup(
                method_body, ids, subject_re=_CS_SUBJECT_RE, base_line=_line(text, brace + 1)
            )
            routes.append({
                "file": relpath,
                "line": _line(text, absolute),
                "framework": "aspnet",
                "methods": _CS_HTTP[name],
                "path": _join_path(prefix, path),
                "handler": method.group("name"),
                "protection": protection,
                "public_mark": public,
                "idor": idor,
            })
    routes.extend(_aspnet_minimal_routes(relpath, text))
    return routes


def _aspnet_minimal_routes(relpath: str, text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    start_re = re.compile(r"\b[A-Za-z_]\w*\.Map(Get|Post|Put|Patch|Delete)\s*+\(\s*+\"((?:[^\"\\]++|\\.)*+)\"\s*+,")
    for match in start_re.finditer(text):
        opening = text.find("(", match.start())
        close = _match_pair(text, opening, "(", ")")
        if close is None:
            continue
        tail = text[close + 1:close + 256]
        require = re.match(r"\s*+\.\s*+RequireAuthorization\s*+\([^)]*+\)", tail)
        anonymous = re.match(r"\s*+\.\s*+AllowAnonymous\s*+\(\s*+\)", tail)
        path = match.group(2).replace(r'\"', '"').replace(r"\\", "\\")
        body = text[match.end():close]
        ids = set(_PATH_ID_RE.findall(path))
        idor = _lookup(body, ids, subject_re=_CS_SUBJECT_RE, base_line=_line(text, match.end()))
        routes.append({
            "file": relpath,
            "line": _line(text, match.start()),
            "framework": "aspnet-minimal",
            "methods": _MINIMAL_HTTP[match.group(1)],
            "path": _join_path("", path),
            "handler": f"Map{match.group(1)}",
            "protection": "RequireAuthorization" if require else None,
            "public_mark": bool(anonymous),
            "idor": idor,
        })
    return routes


DI_AUTHZ_FORMAT = "sniper-di-authz-resolution/1"
DI_IDOR_CONTROL_ID = "SNIPER-AUTHZ-DI-IDOR-01"

_DI_INTERFACE_DEF_RE = re.compile(r"\binterface\s+(?P<iface>[A-Za-z_]\w*)\b")
_DI_CLASS_HEADER_RE = re.compile(
    r"\bclass\s+(?P<impl>[A-Za-z_]\w*)(?:<[^>\{;]*>)?(?:\s*\([^)]*\))?"
    r"(?:\s+extends\s+[A-Za-z_][\w.<>,\s]*)?"
    r"(?:\s+(?:implements|:)\s*(?P<bases>[A-Za-z_][\w.<>,\s()]*))?\s*\{",
    re.MULTILINE,
)
_DI_CSHARP_REG_RE = re.compile(
    r"\bAdd(?:Scoped|Transient|Singleton)\s*<\s*(?P<iface>[A-Za-z_]\w*)\s*,\s*(?P<impl>[A-Za-z_]\w*)\s*>"
)
_DI_CSHARP_TYPEOF_REG_RE = re.compile(
    r"\bAdd(?:Scoped|Transient|Singleton)\s*\(\s*typeof\(\s*(?P<iface>[A-Za-z_]\w*)\s*\)\s*,\s*typeof\(\s*(?P<impl>[A-Za-z_]\w*)\s*\)\s*\)"
)
_DI_TS_PROVIDER_RE = re.compile(
    r"provide\s*:\s*['\"]?(?P<iface>[A-Za-z_]\w*)['\"]?\s*,\s*useClass\s*:\s*(?P<impl>[A-Za-z_]\w*)"
)
_DI_SPRING_BEAN_RE = re.compile(
    r"\b(?P<iface>[A-Za-z_]\w*)\s+[A-Za-z_]\w*\s*\([^)]*\)\s*\{\s*return\s+new\s+(?P<impl>[A-Za-z_]\w*)\b"
)
_DI_FIELD_JAVA_CS_RE = re.compile(
    r"(?:@(?:Autowired|Inject)\s+)?(?:private|protected|public|internal)\s+"
    r"(?:(?:final|readonly)\s+)?(?P<type>[A-Za-z_]\w*)\s+(?P<field>[A-Za-z_]\w*)\s*(?:;|=|\{\s*get;)"
)
_DI_CTOR_TS_KT_RE = re.compile(
    r"\b(?:private|protected|public|readonly|val|var)\s+(?:readonly\s+)?"
    r"(?P<field>[A-Za-z_]\w*)\s*:\s*(?P<type>[A-Za-z_]\w*)"
)
_DI_OWNERSHIP_RE = re.compile(
    r"(?i)(SecurityContext|SecurityContextHolder|Principal|Authentication|"
    r"getAuthentication|getPrincipal|currentUser|current_user|"
    r"HttpContext\s*\.\s*User|\bUser\s*\.\s*FindFirst|ClaimsPrincipal|FindFirst|"
    r"Identity\s*\.\s*Name|tenantId|tenant_id|ownerId|owner_id|organizationId|org_id|"
    r"findByIdAnd(?:Owner|Tenant|User)|Where\s*\([^)]*(?:Owner|Tenant|UserId))"
)
_DI_UNSCOPED_LOOKUP_RE = re.compile(
    r"(?i)\b(?P<lookup>findById|deleteById|getById|getOne|findOne|find|FindAsync|"
    r"FirstOrDefault(?:Async)?|SingleOrDefault(?:Async)?|First(?:Async)?|Single(?:Async)?|"
    r"Remove|Update|queryForObject|selectById|FromSqlRaw|ExecuteQuery)\s*\("
)
_CONTROLLER_HINT_RE = re.compile(
    r"(@RestController|@Controller\b|\[ApiController\]|\[Controller\]|"
    r"@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping|@RequestMapping|"
    r"\[HttpGet|\[HttpPost|\[HttpPut|\[HttpDelete|\[HttpPatch|"
    r"@Get\s*\(|@Post\s*\(|@Put\s*\(|@Delete\s*\(|@Patch\s*\()"
)
_ROUTE_DECORATOR_RE = re.compile(
    r"(@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|"
    r"Get|Post|Put|Delete|Patch)\b|\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch)\b)"
)


def _clean_type_tokens(raw_bases: str) -> list[str]:
    cleaned = re.sub(r"<[^>]*>", "", raw_bases or "")
    cleaned = re.sub(r"\([^)]*\)", "", cleaned)
    tokens: list[str] = []
    for part in cleaned.split(","):
        token = part.strip().split(".")[-1].strip()
        if re.fullmatch(r"[A-Za-z_]\w*", token) and token not in {
            "ControllerBase", "Controller", "Object", " Component"
        }:
            tokens.append(token)
    return tokens


def _extract_method_block(class_body: str, method_name: str) -> str:
    pattern = re.compile(
        rf"\b{re.escape(method_name)}\s*\([^)]*\)\s*(?:throws\s+[^\{{\n]+|:\s*[^\{{\n]+)?\s*\{{",
        re.MULTILINE,
    )
    match = pattern.search(class_body)
    if match is not None:
        brace = class_body.rfind("{", match.start(), match.end())
        if brace >= 0:
            end = _match_pair(class_body, brace, "{", "}")
            if end is not None:
                return class_body[brace + 1:end]
    expr_pattern = re.compile(
        rf"\b{re.escape(method_name)}\s*\([^)]*\)\s*=>\s*(?P<expr>[^;]+);",
        re.MULTILINE,
    )
    expr_match = expr_pattern.search(class_body)
    if expr_match is not None:
        return expr_match.group("expr")
    return class_body


def resolve_di_interface_implementations(files_map: dict[str, str]) -> dict[str, Any]:
    """Resolve DI interfaces to concrete implementations and detect cross-file unscoped IDOR lookups."""
    if not isinstance(files_map, dict):
        return {"format": DI_AUTHZ_FORMAT, "bindings": [], "finding_count": 0, "findings": []}

    interface_files: dict[str, str] = {}
    class_defs: dict[str, dict[str, Any]] = {}
    explicit_pairs: list[tuple[str, str]] = []

    for relpath, content in sorted(files_map.items()):
        text = str(content or "")
        for m in _DI_INTERFACE_DEF_RE.finditer(text):
            interface_files.setdefault(m.group("iface"), relpath)

        for reg_re in (_DI_CSHARP_REG_RE, _DI_CSHARP_TYPEOF_REG_RE, _DI_TS_PROVIDER_RE, _DI_SPRING_BEAN_RE):
            for m in reg_re.finditer(text):
                explicit_pairs.append((m.group("iface"), m.group("impl")))

        for m in _DI_CLASS_HEADER_RE.finditer(text):
            impl_name = m.group("impl")
            brace_idx = m.end() - 1
            end_idx = _match_pair(text, brace_idx, "{", "}")
            class_body = text[brace_idx + 1:end_idx] if end_idx is not None else text[brace_idx + 1:]
            class_defs[impl_name] = {
                "file": relpath,
                "body": class_body,
                "line": _line(text, m.start()),
                "bases": _clean_type_tokens(m.group("bases") or ""),
            }
            for base in class_defs[impl_name]["bases"]:
                explicit_pairs.append((base, impl_name))

    # Naming convention fallback (e.g. OrderService -> OrderServiceImpl, IOrderRepository -> SqlOrderRepository)
    for impl_name, info in sorted(class_defs.items()):
        if impl_name.endswith("Impl") and len(impl_name) > 4:
            stem = impl_name[:-4]
            explicit_pairs.append((stem, impl_name))
            if f"I{stem}" in interface_files:
                explicit_pairs.append((f"I{stem}", impl_name))
        for iface_name in sorted(interface_files):
            core = iface_name[1:] if iface_name.startswith("I") and len(iface_name) > 1 and iface_name[1].isupper() else iface_name
            if core and impl_name != iface_name and impl_name.endswith(core) and not impl_name.endswith("Controller"):
                explicit_pairs.append((iface_name, impl_name))

    iface_to_impls: dict[str, list[str]] = {}
    for iface, impl in explicit_pairs:
        if iface == impl or impl.endswith("Controller"):
            continue
        bucket = iface_to_impls.setdefault(iface, [])
        if impl not in bucket:
            bucket.append(impl)

    controller_injections: dict[str, dict[str, str]] = {}
    iface_controllers: dict[str, set[str]] = {}

    for relpath, content in sorted(files_map.items()):
        text = str(content or "")
        is_controller = bool(_CONTROLLER_HINT_RE.search(text)) or "controller" in relpath.lower()
        if not is_controller:
            continue
        fields: dict[str, str] = {}
        for m in _DI_FIELD_JAVA_CS_RE.finditer(text):
            t_name, f_name = m.group("type"), m.group("field")
            if t_name in iface_to_impls or t_name in interface_files or t_name in class_defs:
                fields[f_name] = t_name
                iface_controllers.setdefault(t_name, set()).add(relpath)
        for m in _DI_CTOR_TS_KT_RE.finditer(text):
            t_name, f_name = m.group("type"), m.group("field")
            if t_name in iface_to_impls or t_name in interface_files or t_name in class_defs:
                fields[f_name] = t_name
                iface_controllers.setdefault(t_name, set()).add(relpath)
        # Also detect constructor parameter assignments `this._repo = repo` or `this.service = service`
        for assign in re.finditer(
            r"\b(?P<type>[A-Za-z_]\w*)\s+(?P<param>[A-Za-z_]\w*)\s*[,)][^{]*\{[^}]*"
            r"(?:this\.)?(?P<field>[A-Za-z_]\w*)\s*=\s*(?P=param)\b",
            text,
            re.DOTALL,
        ):
            t_name = assign.group("type")
            if t_name in iface_to_impls or t_name in interface_files or t_name in class_defs:
                fields[assign.group("field")] = t_name
                fields[assign.group("param")] = t_name
                iface_controllers.setdefault(t_name, set()).add(relpath)
        if fields:
            controller_injections[relpath] = fields

    bindings: list[dict[str, Any]] = []
    seen_bindings: set[tuple[str, str]] = set()
    for iface in sorted(iface_to_impls):
        for impl in iface_to_impls[iface]:
            if (iface, impl) in seen_bindings:
                continue
            seen_bindings.add((iface, impl))
            impl_info = class_defs.get(impl, {})
            bindings.append({
                "interface": iface,
                "implementation": impl,
                "interface_file": interface_files.get(iface, ""),
                "implementation_file": str(impl_info.get("file") or ""),
                "controllers": sorted(iface_controllers.get(iface, set())),
            })

    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str, str]] = set()

    for ctrl_file, fields in sorted(controller_injections.items()):
        text = str(files_map.get(ctrl_file) or "")
        for field_name, iface_name in sorted(fields.items()):
            impl_candidates = list(iface_to_impls.get(iface_name, []))
            if not impl_candidates and iface_name in class_defs:
                impl_candidates = [iface_name]
            if not impl_candidates:
                continue

            call_re = re.compile(
                rf"(?:this\.)?\b{re.escape(field_name)}\s*\.\s*(?P<method>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)"
            )
            for call_match in call_re.finditer(text):
                called_method = call_match.group("method")
                call_args = call_match.group("args").strip()
                if not call_args:
                    continue
                call_line = _line(text, call_match.start())
                # Inspect enclosing controller window around the call for route/ownership context
                window_start = max(0, text.rfind("{", 0, call_match.start()))
                window_end = _match_pair(text, window_start, "{", "}") if window_start < len(text) and text[window_start] == "{" else min(len(text), call_match.end() + 400)
                ctrl_method_body = text[window_start : (window_end or min(len(text), call_match.end() + 400))]
                header_window = text[max(0, window_start - 350) : window_start]
                if not _ROUTE_DECORATOR_RE.search(header_window) and not _ROUTE_DECORATOR_RE.search(text):
                    continue
                if _DI_OWNERSHIP_RE.search(ctrl_method_body) or _ROLE_RE.search(header_window):
                    continue

                for impl_name in impl_candidates:
                    impl_info = class_defs.get(impl_name)
                    if not impl_info:
                        continue
                    impl_body = str(impl_info.get("body") or "")
                    impl_file = str(impl_info.get("file") or "")
                    target_method_body = _extract_method_block(impl_body, called_method)
                    if _DI_OWNERSHIP_RE.search(target_method_body) or _DI_OWNERSHIP_RE.search(impl_body):
                        continue
                    lookup_match = _DI_UNSCOPED_LOOKUP_RE.search(target_method_body) or _DI_UNSCOPED_LOOKUP_RE.search(
                        f"{called_method}("
                    )
                    if lookup_match is None:
                        continue
                    dedup_key = (ctrl_file, iface_name, impl_name, called_method)
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)
                    lookup_op = lookup_match.group("lookup")
                    findings.append({
                        "id": DI_IDOR_CONTROL_ID,
                        "control_id": DI_IDOR_CONTROL_ID,
                        "rule_id": DI_IDOR_CONTROL_ID,
                        "cwe": "CWE-639",
                        "category": "authz",
                        "severity": "high",
                        "file": ctrl_file,
                        "line": call_line,
                        "implementation_file": impl_file,
                        "interface": iface_name,
                        "implementation": impl_name,
                        "service_method": called_method,
                        "lookup": lookup_op,
                        "title": f"DI arayüzü üzerinden kapsam dışı nesne erişimi (IDOR): {iface_name}.{called_method} -> {impl_name}",
                        "description": (
                            f"Controller '{ctrl_file}' içindeki '{field_name}.{called_method}({call_args})' çağrısı "
                            f"DI arayüzü '{iface_name}' üzerinden '{impl_name}' ({impl_file}) sınıfına çözümlendi; "
                            f"somut sınıfta kiracı/özne sahiplik doğrulaması olmadan '{lookup_op}' çalıştırılıyor."
                        ),
                        "evidence": f"{field_name}.{called_method}({call_args}) -> {impl_name}.{lookup_op}",
                        "recommendation": (
                            "Somut servis veya repository katmanında kimliği doğrulanmış kullanıcı/kiracı bağlamını "
                            "(SecurityContext, Principal, ClaimsPrincipal, tenantId) zorunlu filtre olarak uygulayın."
                        ),
                    })

    return {
        "format": DI_AUTHZ_FORMAT,
        "bindings": bindings,
        "finding_count": len(findings),
        "findings": findings,
    }


