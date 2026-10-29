from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import re
from typing import Any, Iterator

from project_analyzer import ProjectRejected, SKIP_DIRS, validate_project_path
from project_tree import ProjectTree, ProjectTreeError
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups


MAX_CONTRACT_BYTES = 2_000_000
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}
SEVERITY_DEDUCTION = {"critical": 24, "high": 14, "medium": 7, "low": 3, "info": 0}

OPENAPI_CONTRACT_FILENAMES = {
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
}
GRAPHQL_EXTENSIONS = {".graphql", ".gql"}
MAX_GRAPHQL_RUBY_SOURCE_BYTES = 512_000
MAX_GRAPHQL_RUBY_SOURCE_FILES = 1_000
MAX_GRAPHQL_RUBY_TOTAL_BYTES = 8_000_000

GRAPHQL_AUTH_DIRECTIVES = {"auth", "authorized", "hasrole"}
GRAPHQL_SENSITIVE_FIELDS = {
    "password",
    "passwordhash",
    "password_hash",
    "secret",
    "privatekey",
    "private_key",
    "ssn",
    "creditcard",
    "credit_card",
}

_RUBY_GRAPHQL_PATH_PARTS = {"graphql", "resolvers", "mutations"}
_RUBY_GRAPHQL_FILENAMES = {"query_type.rb", "mutation_type.rb", "subscription_type.rb"}
_RUBY_METHOD_RE = re.compile(
    r"^\s*def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_]*[!?=]?)\s*(?:\(([^)]*)\)|\s+([^#\n]+))?",
    re.MULTILINE,
)
_RUBY_UNSCOPED_LOOKUP_RE = re.compile(
    r"(?<![A-Za-z0-9_:.])([A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)*)"
    r"\s*\.\s*(find|find_by!?)\s*\("
)
_RUBY_ID_ARGUMENT_RE = re.compile(
    r"(?:\b(?:id|node_id|global_id)\b|\b[A-Za-z_][A-Za-z0-9_]*_id\b|\bargs\s*\[\s*:?[A-Za-z_][A-Za-z0-9_]*id\s*\])",
    re.IGNORECASE,
)
_RUBY_AUTHORIZATION_GUARD_RE = re.compile(
    r"(?:\b(?:authorize|authorize!|authorized\?|policy|policy_scope|can\?|allowed\?)\s*\(|"
    r"\b(?:authorize|authorize!)\s+[A-Za-z_])",
    re.IGNORECASE,
)
_RUBY_TENANT_SCOPE_RE = re.compile(
    r"(?:"
    r"\b(?:user|owner|account|tenant|organization|workspace|project)_id\s*:"
    r"[^\n,)]*(?:current_|context\s*\[)"
    r"|(?:current_(?:user|account|tenant|organization|workspace)|"
    r"context\s*\[\s*:current_(?:user|account|tenant|organization|workspace)\s*\])"
    r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:find|find_by!?)\s*\("
    r")",
    re.IGNORECASE,
)
_RUBY_GRAPHQL_FIELD_RE = re.compile(
    r"^\s*field\s+(?::([A-Za-z_][A-Za-z0-9_]*)|['\"]([A-Za-z_][A-Za-z0-9_]*)['\"])"
    r"\s*,([^\n]*(?:\n[ \t]+(?!field\b|def\b|end\b)[^\n]*){0,8})",
    re.MULTILINE,
)
_RUBY_RESOLVER_REF_RE = re.compile(
    r"\bresolver\s*:\s*(?:::)?([A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)*)"
)
_RUBY_BASE_RESOLVER_CLASS_RE = re.compile(
    r"^\s*class\s+[A-Z][A-Za-z0-9_:]*\s*<\s*(?:::)?"
    r"(?:(?:[A-Z][A-Za-z0-9_]*)::)*BaseResolver\b",
    re.MULTILINE,
)


@contextmanager
def _opened_project_tree(root: Path) -> Iterator[ProjectTree]:
    try:
        with ProjectTree(str(root)) as tree:
            yield tree
    except ProjectTreeError as exc:
        raise ProjectRejected("Proje ağacı güvenli biçimde okunamadı.") from exc


GRAPHQL_BUILTIN_SCALARS = {"String", "Int", "Float", "Boolean", "ID"}

OPENAPI_SENSITIVE_RESPONSE_FIELDS = {
    "password",
    "password_hash",
    "passwordhash",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "token",
    "ssn",
    "cvv",
}

BOLA_PARAM_NAMES = {
    "id",
    "user_id",
    "userid",
    "account_id",
    "accountid",
    "order_id",
    "orderid",
}

SSRF_PARAM_NAMES = {
    "url",
    "uri",
    "webhook",
    "webhook_url",
    "webhookurl",
    "callback",
    "callback_url",
    "callbackurl",
    "target_url",
    "targeturl",
    "redirect_url",
    "redirect_uri",
    "fetch_url",
    "endpoint_url",
}


class ApiContractAuditError(ValueError):
    pass


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _score_findings(findings: list[dict[str, Any]]) -> tuple[int, str]:
    total_deduction = sum(SEVERITY_DEDUCTION.get(str(f.get("severity", "low")).casefold(), 3) for f in findings)
    score = max(0, 100 - total_deduction)
    return score, _grade(score)


def _parse_scalar(raw: str) -> Any:
    val = raw.strip()
    if not val:
        return ""
    if val in ("true", "True"):
        return True
    if val in ("false", "False"):
        return False
    if val in ("null", "Null", "~"):
        return None
    if val == "[]":
        return []
    if val == "{}":
        return {}
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in inner.split(",")]
    if val.startswith("{") and val.endswith("}"):
        try:
            return json.loads(val)
        except Exception:
            inner = val[1:-1].strip()
            if not inner:
                return {}
            out: dict[str, Any] = {}
            for pair in inner.split(","):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    out[str(_parse_scalar(k)).strip()] = _parse_scalar(v)
            return out
    unsigned = val[1:] if val.startswith("-") else val
    if unsigned and unsigned.isdigit():
        try:
            return int(val)
        except ValueError:
            pass
    integer, dot, fraction = unsigned.partition(".")
    if dot and integer and fraction and integer.isdigit() and fraction.isdigit() and "." not in fraction:
        try:
            return float(val)
        except ValueError:
            pass
    return val


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict):
            return loaded
    except Exception:
        pass

    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        cleaned = _strip_yaml_comment(raw_line)
        if not cleaned.strip() or cleaned.strip() == "---":
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        lines.append((indent, cleaned.strip()))

    if not lines:
        raise ApiContractAuditError("YAML sözleşmesi boş.")

    def _parse_block(index: int, min_indent: int) -> tuple[Any, int]:
        if index >= len(lines):
            return {}, index
        first_indent, first_content = lines[index]
        if first_indent < min_indent:
            return {}, index

        if first_content.startswith("- ") or first_content == "-":
            items: list[Any] = []
            while index < len(lines):
                indent, content = lines[index]
                if indent < first_indent or not (content.startswith("- ") or content == "-"):
                    break
                if indent > first_indent:
                    break
                rest = content[1:].strip()
                index += 1
                if not rest:
                    sub_val, index = _parse_block(index, indent + 1)
                    items.append(sub_val)
                elif ":" in rest and not (rest.startswith('"') or rest.startswith("'")):
                    k, v = rest.split(":", 1)
                    item_dict: dict[str, Any] = {}
                    key_str = str(_parse_scalar(k)).strip()
                    v_str = v.strip()
                    if v_str:
                        item_dict[key_str] = _parse_scalar(v_str)
                    else:
                        nested_val, index = _parse_block(index, indent + 2)
                        item_dict[key_str] = nested_val
                    if index < len(lines) and lines[index][0] > indent:
                        extra_map, index = _parse_block(index, indent + 1)
                        if isinstance(extra_map, dict):
                            item_dict.update(extra_map)
                    items.append(item_dict)
                else:
                    items.append(_parse_scalar(rest))
            return items, index

        mapping: dict[str, Any] = {}
        while index < len(lines):
            indent, content = lines[index]
            if indent < first_indent:
                break
            if indent > first_indent:
                index += 1
                continue
            if content.startswith("- ") or content == "-":
                break
            if ":" not in content:
                index += 1
                continue
            k, v = content.split(":", 1)
            key_str = str(_parse_scalar(k)).strip()
            v_str = v.strip()
            index += 1
            if v_str:
                mapping[key_str] = _parse_scalar(v_str)
            else:
                if index < len(lines) and lines[index][0] > indent:
                    sub_val, index = _parse_block(index, indent + 1)
                    mapping[key_str] = sub_val
                else:
                    mapping[key_str] = {}
        return mapping, index

    parsed, _ = _parse_block(0, 0)
    if not isinstance(parsed, dict):
        raise ApiContractAuditError("API sözleşmesi kökü bir nesne olmalıdır.")
    return parsed


def _graphql_type_blocks(text: str) -> list[tuple[str, str, str]]:
    """Extract GraphQL type bodies with forward-only delimiter scans."""
    kinds = ("type", "input", "interface")
    blocks: list[tuple[str, str, str]] = []
    cursor = 0
    while cursor < len(text):
        candidates = [(text.find(kind, cursor), kind) for kind in kinds]
        candidates = [(position, kind) for position, kind in candidates if position >= 0]
        if not candidates:
            break
        found, kind = min(candidates)
        before = text[found - 1] if found else ""
        after_kind = found + len(kind)
        if before == "_" or before.isalnum() or after_kind >= len(text) or not text[after_kind].isspace():
            cursor = after_kind
            continue
        index = after_kind
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or not (text[index] == "_" or "A" <= text[index] <= "Z" or
                                      "a" <= text[index] <= "z"):
            cursor = after_kind
            continue
        name_start = index
        index += 1
        while index < len(text) and (text[index] == "_" or "A" <= text[index] <= "Z" or
                                     "a" <= text[index] <= "z" or "0" <= text[index] <= "9"):
            index += 1
        type_name = text[name_start:index]
        if index < len(text) and text[index] == "{":
            opening = index
        elif index < len(text) and text[index].isspace():
            opening = text.find("{", index)
            if opening < 0:
                break
        else:
            cursor = index
            continue
        closing = text.find("}", opening + 1)
        if closing < 0:
            break
        blocks.append((kind, type_name, text[opening + 1:closing]))
        cursor = closing + 1
    return blocks


def _graphql_field(line: str) -> tuple[str, str, str] | None:
    """Parse ``name(args): Type @directives`` without adjacent wildcard regexes."""
    if not line or not (line[0] == "_" or "A" <= line[0] <= "Z" or "a" <= line[0] <= "z"):
        return None
    index = 1
    while index < len(line) and (line[index] == "_" or "A" <= line[index] <= "Z" or
                                 "a" <= line[index] <= "z" or "0" <= line[index] <= "9"):
        index += 1
    field_name = line[:index]
    while index < len(line) and line[index].isspace():
        index += 1
    if index < len(line) and line[index] == "(":
        closing = line.find(")", index + 1)
        if closing < 0:
            return None
        index = closing + 1
    while index < len(line) and line[index].isspace():
        index += 1
    if index >= len(line) or line[index] != ":":
        return None
    index += 1
    while index < len(line) and line[index].isspace():
        index += 1
    type_start = index
    while index < len(line) and not line[index].isspace() and line[index] != "@":
        index += 1
    if index == type_start:
        return None
    return field_name, line[type_start:index], line[index:]


def _looks_like_graphql(raw_content: str) -> bool:
    stripped = raw_content.strip()
    if stripped.startswith("{"):
        return False
    return bool(
        re.search(
            r"\b(?:type\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:@[^{]+)?\{|schema\s*\{|extend\s+type\s+[A-Za-z_]|input\s+[A-Za-z_][A-Za-z0-9_]*\s*\{)",
            stripped,
        )
    )


def _audit_graphql_sdl(raw_content: str, source_name: str) -> dict[str, Any]:
    cleaned = re.sub(r"#[^\n]*", "", raw_content)
    type_blocks = _graphql_type_blocks(cleaned)
    if not type_blocks:
        raise ApiContractAuditError("Geçerli bir GraphQL SDL şeması bulunamadı.")

    findings: list[dict[str, Any]] = []
    object_types: dict[str, list[tuple[str, str, str]]] = {}
    endpoint_count = 0

    for kind, type_name, body in type_blocks:
        fields: list[tuple[str, str, str]] = []
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            field = _graphql_field(line)
            if field is None:
                continue
            field_name, field_type, directives_tail = field
            fields.append((field_name, field_type, directives_tail or ""))
        if kind == "type":
            object_types.setdefault(type_name, []).extend(fields)
            if type_name in ("Query", "Mutation", "Subscription"):
                endpoint_count += len(fields)

    # 1. Check mutations without @auth / @authorized / @hasRole
    for field_name, _field_type, directives_tail in object_types.get("Mutation", []):
        found_directives = {
            d.casefold() for d in re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", directives_tail)
        }
        if not (found_directives & GRAPHQL_AUTH_DIRECTIVES):
            findings.append({
                "rule_id": "SNIPER-APIT-02",
                "owasp_category": "OWASP API2:2023",
                "severity": "medium",
                "title": "GraphQL mutasyon alanında yetkilendirme direktifi (@auth/@authorized/@hasRole) eksik",
                "location": f"Mutation.{field_name}",
                "source_name": source_name,
            })

    # 2. Check self-referential / cyclic object types enabling deep nested query DoS
    domain_types = {
        t: fields for t, fields in object_types.items()
        if t not in ("Query", "Mutation", "Subscription")
    }
    adj: dict[str, set[str]] = {}
    for type_name, fields in domain_types.items():
        targets: set[str] = set()
        for _fname, ftype, _directives in fields:
            base_type = re.sub(r"[\[\]!]", "", ftype).strip()
            if base_type in domain_types and base_type not in GRAPHQL_BUILTIN_SCALARS:
                targets.add(base_type)
        adj[type_name] = targets

    def _has_cycle_to_self(start: str) -> bool:
        visited: set[str] = set()
        stack = list(adj.get(start, ()))
        while stack:
            curr = stack.pop()
            if curr == start:
                return True
            if curr not in visited:
                visited.add(curr)
                stack.extend(adj.get(curr, ()))
        return False

    for type_name in sorted(domain_types):
        if _has_cycle_to_self(type_name):
            findings.append({
                "rule_id": "SNIPER-APIT-06",
                "owasp_category": "OWASP API4:2023",
                "severity": "medium",
                "title": "GraphQL şemasında döngüsel tip referansı (Derin sorgu DoS riski)",
                "location": f"type {type_name}",
                "source_name": source_name,
            })

    # 3. Check sensitive fields exposed on GraphQL object types
    for type_name, fields in object_types.items():
        if type_name in ("Query", "Mutation", "Subscription"):
            continue
        for field_name, _field_type, _directives in fields:
            normalized = field_name.casefold().replace("-", "_")
            if normalized in GRAPHQL_SENSITIVE_FIELDS or field_name.casefold() in GRAPHQL_SENSITIVE_FIELDS:
                findings.append({
                    "rule_id": "SNIPER-APIT-09",
                    "owasp_category": "OWASP API3:2023",
                    "severity": "high",
                    "title": "GraphQL nesne tipinde hassas veri alanı maruziyeti",
                    "location": f"{type_name}.{field_name}",
                    "source_name": source_name,
                })

    if endpoint_count == 0:
        endpoint_count = sum(len(v) for v in object_types.values())

    score, grade = _score_findings(findings)
    return {
        "format": "sniper-api-contract-audit-v1",
        "source_name": source_name,
        "contract_type": "graphql",
        "score": score,
        "grade": grade,
        "endpoint_count": endpoint_count,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-APIT-02",
            "SNIPER-APIT-06",
            "SNIPER-APIT-09",
        ],
    }


def _graphql_root_fields(raw_content: str) -> dict[str, set[str]]:
    """Return GraphQL root field names without exposing schema content."""
    cleaned = re.sub(r"#[^\n]*", "", raw_content)
    fields: dict[str, set[str]] = {}
    for kind, type_name, body in _graphql_type_blocks(cleaned):
        if kind != "type" or type_name not in {"Query", "Mutation", "Subscription"}:
            continue
        for raw_line in body.splitlines():
            field = _graphql_field(raw_line.strip())
            if field is not None:
                fields.setdefault(field[0], set()).add(type_name)
    return fields


def _ruby_graphql_candidate(path: Path) -> bool:
    if path.suffix.casefold() != ".rb":
        return False
    lowered_parts = {part.casefold() for part in path.parts}
    return bool(lowered_parts & _RUBY_GRAPHQL_PATH_PARTS) or path.name.casefold() in _RUBY_GRAPHQL_FILENAMES


def _ruby_graphql_method_name(field_name: str) -> str:
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", field_name).casefold()
    return snake.replace("-", "_")


def _ruby_class_name(raw_content: str) -> str:
    namespace: list[str] = []
    for line in raw_content.splitlines():
        module_match = re.match(r"^\s*module\s+([A-Z][A-Za-z0-9_]*)\b", line)
        if module_match:
            namespace.append(module_match.group(1))
            continue
        class_match = re.match(r"^\s*class\s+([A-Z][A-Za-z0-9_:]*)\b", line)
        if not class_match:
            continue
        class_name = class_match.group(1)
        if "::" in class_name or not namespace:
            return class_name
        return "::".join((*namespace, class_name))
    return "GraphQLResolver"


def _ruby_method_slices(raw_content: str) -> list[tuple[str, str, str]]:
    matches = list(_RUBY_METHOD_RE.finditer(raw_content))
    methods: list[tuple[str, str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(raw_content)
        signature = " ".join(part for part in match.groups()[1:] if part)
        methods.append((match.group(1), signature, raw_content[match.start():end]))
    return methods


def _ruby_method_has_authorization(raw_content: str, method_body: str) -> bool:
    if _RUBY_AUTHORIZATION_GUARD_RE.search(method_body):
        return True
    if _RUBY_TENANT_SCOPE_RE.search(method_body):
        return True
    return bool(re.search(r"^\s*def\s+self\.authorized\?\b", raw_content, re.MULTILINE))


def _ruby_resolver_class_links(
    root_fields: dict[str, set[str]],
    ruby_sources: list[tuple[str, str]],
) -> dict[str, set[str]]:
    """Map explicit GraphQL-Ruby resolver classes to referenced SDL root fields."""
    method_to_field = {_ruby_graphql_method_name(field): field for field in root_fields}
    links: dict[str, set[str]] = {}
    for _source_name, raw_content in ruby_sources:
        for match in _RUBY_GRAPHQL_FIELD_RE.finditer(raw_content):
            ruby_field = match.group(1) or match.group(2) or ""
            field_name = method_to_field.get(ruby_field)
            if field_name is None:
                continue
            resolver_match = _RUBY_RESOLVER_REF_RE.search(match.group(3))
            if resolver_match is not None:
                links.setdefault(resolver_match.group(1), set()).add(field_name)
    return links


def _append_ruby_lookup_findings(
    findings: list[dict[str, Any]],
    *,
    root_fields: dict[str, set[str]],
    field_name: str,
    class_name: str,
    method_name: str,
    source_name: str,
    method_body: str,
) -> None:
    for lookup in _RUBY_UNSCOPED_LOOKUP_RE.finditer(method_body):
        call_tail = method_body[lookup.end():].split(")", 1)[0]
        if not _RUBY_ID_ARGUMENT_RE.search(call_tail):
            continue
        for root_type in sorted(root_fields[field_name]):
            findings.append({
                "rule_id": "SNIPER-APIT-10",
                "owasp_category": "OWASP API1:2023",
                "severity": "high",
                "title": "GraphQL resolver nesne sorgusunda görünür sahiplik/tenant yetkilendirmesi eksik",
                "location": f"{root_type}.{field_name} -> {class_name}#{method_name}",
                "source_name": source_name,
                "lookup": f"{lookup.group(1)}.{lookup.group(2)}",
                "confidence": "high",
            })
        break


def _audit_graphql_ruby_resolvers(
    root_fields: dict[str, set[str]],
    ruby_sources: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Correlate SDL roots with method and explicit resolver-class lookups."""
    method_to_field = {_ruby_graphql_method_name(field): field for field in root_fields}
    resolver_links = _ruby_resolver_class_links(root_fields, ruby_sources)
    findings: list[dict[str, Any]] = []

    for source_name, raw_content in ruby_sources:
        class_name = _ruby_class_name(raw_content)
        methods = _ruby_method_slices(raw_content)

        for method_name, signature, method_body in methods:
            field_name = method_to_field.get(method_name)
            if field_name is None or not _RUBY_ID_ARGUMENT_RE.search(signature):
                continue
            if _ruby_method_has_authorization(raw_content, method_body):
                continue
            _append_ruby_lookup_findings(
                findings,
                root_fields=root_fields,
                field_name=field_name,
                class_name=class_name,
                method_name=method_name,
                source_name=source_name,
                method_body=method_body,
            )

        linked_fields = resolver_links.get(class_name, set())
        if not linked_fields or not _RUBY_BASE_RESOLVER_CLASS_RE.search(raw_content):
            continue
        for method_name, signature, method_body in methods:
            if method_name != "resolve" or not _RUBY_ID_ARGUMENT_RE.search(signature):
                continue
            if _ruby_method_has_authorization(raw_content, method_body):
                continue
            for field_name in sorted(linked_fields):
                _append_ruby_lookup_findings(
                    findings,
                    root_fields=root_fields,
                    field_name=field_name,
                    class_name=class_name,
                    method_name=method_name,
                    source_name=source_name,
                    method_body=method_body,
                )
    return findings


def _resolve_schema_ref(doc: dict[str, Any], schema: Any, depth: int = 0) -> dict[str, Any]:
    if not isinstance(schema, dict) or depth > 8:
        return {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        parts = ref[2:].split("/")
        curr: Any = doc
        for part in parts:
            if isinstance(curr, dict):
                curr = curr.get(part)
            else:
                curr = None
                break
        if isinstance(curr, dict):
            return _resolve_schema_ref(doc, curr, depth + 1)
    return schema


def _schema_lacks_bounds(schema: dict[str, Any]) -> bool:
    stype = str(schema.get("type", "")).casefold()
    if stype == "array":
        return "maxItems" not in schema
    if stype == "string":
        if "enum" in schema:
            return False
        return "maxLength" not in schema
    if stype in ("integer", "number"):
        return "maximum" not in schema
    return False


def _collect_schema_sensitive_fields(
    doc: dict[str, Any],
    schema: Any,
    visited: set[int] | None = None,
) -> list[str]:
    if visited is None:
        visited = set()
    resolved = _resolve_schema_ref(doc, schema)
    if not resolved or id(resolved) in visited:
        return []
    visited.add(id(resolved))
    exposed: list[str] = []
    props = resolved.get("properties")
    if isinstance(props, dict):
        for prop_name, prop_schema in props.items():
            norm = str(prop_name).casefold().replace("-", "_")
            if norm in OPENAPI_SENSITIVE_RESPONSE_FIELDS or str(prop_name).casefold() in OPENAPI_SENSITIVE_RESPONSE_FIELDS:
                exposed.append(str(prop_name))
            if isinstance(prop_schema, dict):
                exposed.extend(_collect_schema_sensitive_fields(doc, prop_schema, visited))
    items = resolved.get("items")
    if isinstance(items, dict):
        exposed.extend(_collect_schema_sensitive_fields(doc, items, visited))
    return exposed


def _audit_openapi_or_swagger(doc: dict[str, Any], detected_type: str, source_name: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    # 1. Cleartext http:// server / scheme check
    if detected_type == "openapi3":
        servers = doc.get("servers")
        if isinstance(servers, list):
            for srv in servers:
                url = srv.get("url", "") if isinstance(srv, dict) else str(srv)
                if isinstance(url, str) and url.strip().casefold().startswith("http://"):
                    findings.append({
                        "rule_id": "SNIPER-CRYP-02",
                        "owasp_category": "OWASP API8:2023",
                        "severity": "high",
                        "title": "API sözleşmesinde şifrelenmemiş HTTP sunucu adresi",
                        "location": f"servers ({url.strip()})",
                        "source_name": source_name,
                    })
    else:
        schemes = doc.get("schemes")
        if isinstance(schemes, list):
            for scheme in schemes:
                if str(scheme).strip().casefold() == "http":
                    findings.append({
                        "rule_id": "SNIPER-CRYP-02",
                        "owasp_category": "OWASP API8:2023",
                        "severity": "high",
                        "title": "API sözleşmesinde şifrelenmemiş HTTP sunucu adresi",
                        "location": "schemes (http)",
                        "source_name": source_name,
                    })

    global_security = doc.get("security")
    has_global_security = isinstance(global_security, list) and len(global_security) > 0

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        paths = {}

    endpoint_count = 0

    for path_key, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_str = str(path_key)
        path_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []

        # Path template BOLA parameter signal
        template_params = re.findall(r"\{([A-Za-z0-9_.-]+)\}", path_str)

        for method_key, operation in path_item.items():
            method = str(method_key).casefold()
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            endpoint_count += 1
            op_loc = f"{method.upper()} {path_str}"

            # 2. Authentication check (security: [] or state-changing operation without security)
            op_has_security_key = "security" in operation
            op_security = operation.get("security")
            if op_has_security_key and isinstance(op_security, list) and len(op_security) == 0:
                findings.append({
                    "rule_id": "SNIPER-APIT-02",
                    "owasp_category": "OWASP API2:2023",
                    "severity": "high",
                    "title": "Durum değiştiren API uç noktasında kimlik doğrulama tanımı yok",
                    "location": op_loc,
                    "source_name": source_name,
                })
            elif method in STATE_CHANGING_METHODS:
                effective_security = (
                    isinstance(op_security, list) and len(op_security) > 0
                ) if op_has_security_key else has_global_security
                if not effective_security:
                    findings.append({
                        "rule_id": "SNIPER-APIT-02",
                        "owasp_category": "OWASP API2:2023",
                        "severity": "high",
                        "title": "Durum değiştiren API uç noktasında kimlik doğrulama tanımı yok",
                        "location": op_loc,
                        "source_name": source_name,
                    })

            # Combine path-level and operation-level parameters
            op_params = operation.get("parameters") if isinstance(operation.get("parameters"), list) else []
            all_params = list(path_params) + list(op_params)

            # 3. BOLA / IDOR check on object ID path parameters
            bola_flagged = False
            for t_param in template_params:
                norm_t = t_param.casefold()
                if norm_t in BOLA_PARAM_NAMES or norm_t.endswith("_id") or t_param.endswith("Id"):
                    bola_flagged = True
                    break
            if not bola_flagged:
                for param in all_params:
                    if not isinstance(param, dict):
                        continue
                    if str(param.get("in", "")).casefold() == "path":
                        pname = str(param.get("name", ""))
                        norm_p = pname.casefold()
                        if norm_p in BOLA_PARAM_NAMES or norm_p.endswith("_id") or pname.endswith("Id"):
                            bola_flagged = True
                            break
            if bola_flagged:
                findings.append({
                    "rule_id": "SNIPER-APIT-03",
                    "owasp_category": "OWASP API1:2023",
                    "severity": "medium",
                    "title": "Nesne kimliği parametresi alan uç noktada BOLA/IDOR yetki doğrulaması gerekli",
                    "location": op_loc,
                    "source_name": source_name,
                })

            # 4. Unbounded parameters & request schemas check (maxItems / maxLength / maximum)
            unbounded_flagged = False
            for param in all_params:
                if not isinstance(param, dict):
                    continue
                p_in = str(param.get("in", "")).casefold()
                if p_in == "body":
                    body_schema = _resolve_schema_ref(doc, param.get("schema"))
                    if isinstance(body_schema, dict):
                        if (body_schema.get("type") == "object" or "properties" in body_schema) and body_schema.get("additionalProperties") is not False:
                            findings.append({
                                "rule_id": "SNIPER-APIT-09",
                                "owasp_category": "OWASP API3:2023",
                                "severity": "low",
                                "title": "API girdi şemasında additionalProperties: false kısıtlaması yok (Mass Assignment riski)",
                                "location": op_loc,
                                "source_name": source_name,
                            })
                        props = body_schema.get("properties")
                        if isinstance(props, dict):
                            for prop_schema in props.values():
                                resolved_prop = _resolve_schema_ref(doc, prop_schema)
                                if _schema_lacks_bounds(resolved_prop):
                                    unbounded_flagged = True
                    continue
                p_schema = _resolve_schema_ref(doc, param.get("schema")) if isinstance(param.get("schema"), dict) else param
                if isinstance(p_schema, dict) and _schema_lacks_bounds(p_schema):
                    unbounded_flagged = True

            # Check OpenAPI 3.x requestBody
            req_body = operation.get("requestBody")
            if isinstance(req_body, dict):
                content_map = req_body.get("content")
                if isinstance(content_map, dict):
                    for media_obj in content_map.values():
                        if not isinstance(media_obj, dict):
                            continue
                        raw_schema = media_obj.get("schema")
                        resolved_schema = _resolve_schema_ref(doc, raw_schema)
                        if not resolved_schema:
                            continue
                        if _schema_lacks_bounds(resolved_schema):
                            unbounded_flagged = True
                        props = resolved_schema.get("properties")
                        if isinstance(props, dict):
                            for prop_schema in props.values():
                                resolved_prop = _resolve_schema_ref(doc, prop_schema)
                                if _schema_lacks_bounds(resolved_prop):
                                    unbounded_flagged = True
                        # 5. Mass Assignment check (additionalProperties: false missing on object requestBody)
                        if (resolved_schema.get("type") == "object" or isinstance(props, dict)) and resolved_schema.get("additionalProperties") is not False:
                            findings.append({
                                "rule_id": "SNIPER-APIT-09",
                                "owasp_category": "OWASP API3:2023",
                                "severity": "low",
                                "title": "API girdi şemasında additionalProperties: false kısıtlaması yok (Mass Assignment riski)",
                                "location": op_loc,
                                "source_name": source_name,
                            })

            if unbounded_flagged:
                findings.append({
                    "rule_id": "SNIPER-APIT-05",
                    "owasp_category": "OWASP API4:2023",
                    "severity": "medium",
                    "title": "API parametresinde veya dizi şemasında üst sınır (maxItems/maxLength/maximum) eksik",
                    "location": op_loc,
                    "source_name": source_name,
                })

            # 5b. OWASP API7:2023 SSRF / Unconstrained URL or Webhook parameter check
            ssrf_params: list[str] = []
            for param in all_params:
                if not isinstance(param, dict):
                    continue
                p_in = str(param.get("in", "")).casefold()
                if p_in == "body":
                    body_schema = _resolve_schema_ref(doc, param.get("schema"))
                    if isinstance(body_schema, dict) and isinstance(body_schema.get("properties"), dict):
                        for prop_name, prop_schema in body_schema["properties"].items():
                            norm_prop = str(prop_name).casefold()
                            resolved_prop = _resolve_schema_ref(doc, prop_schema)
                            if (
                                norm_prop in SSRF_PARAM_NAMES
                                or norm_prop.endswith(("_url", "_uri", "webhookurl", "callbackurl"))
                            ) and not (isinstance(resolved_prop, dict) and (resolved_prop.get("enum") or resolved_prop.get("pattern"))):
                                ssrf_params.append(str(prop_name))
                    continue
                pname = str(param.get("name", ""))
                norm_p = pname.casefold()
                p_schema = _resolve_schema_ref(doc, param.get("schema")) if isinstance(param.get("schema"), dict) else param
                if (
                    norm_p in SSRF_PARAM_NAMES
                    or norm_p.endswith(("_url", "_uri", "webhookurl", "callbackurl"))
                ) and not (isinstance(p_schema, dict) and (p_schema.get("enum") or p_schema.get("pattern"))):
                    ssrf_params.append(pname)

            if isinstance(req_body, dict) and isinstance(req_body.get("content"), dict):
                for media_obj in req_body["content"].values():
                    if not isinstance(media_obj, dict):
                        continue
                    resolved_schema = _resolve_schema_ref(doc, media_obj.get("schema"))
                    if isinstance(resolved_schema, dict) and isinstance(resolved_schema.get("properties"), dict):
                        for prop_name, prop_schema in resolved_schema["properties"].items():
                            norm_prop = str(prop_name).casefold()
                            resolved_prop = _resolve_schema_ref(doc, prop_schema)
                            if (
                                norm_prop in SSRF_PARAM_NAMES
                                or norm_prop.endswith(("_url", "_uri", "webhookurl", "callbackurl"))
                            ) and not (isinstance(resolved_prop, dict) and (resolved_prop.get("enum") or resolved_prop.get("pattern"))):
                                ssrf_params.append(str(prop_name))

            if ssrf_params:
                findings.append({
                    "rule_id": "SNIPER-APIT-07",
                    "owasp_category": "OWASP API7:2023",
                    "severity": "high",
                    "title": "API sözleşmesinde kısıtlanmamış dış URL/Webhook parametresi (SSRF riski - OWASP API7:2023)",
                    "location": f"{op_loc} ({', '.join(sorted(set(ssrf_params)))})",
                    "source_name": source_name,
                })

            # 6. Check 2xx response schemas for sensitive field exposure
            responses = operation.get("responses")
            if isinstance(responses, dict):
                sensitive_exposed: list[str] = []
                for status_code, resp_obj in responses.items():
                    code_str = str(status_code).strip().casefold()
                    if not (code_str.startswith("2") or code_str == "default"):
                        continue
                    if not isinstance(resp_obj, dict):
                        continue
                    # Swagger 2.0 direct schema
                    if isinstance(resp_obj.get("schema"), dict):
                        sensitive_exposed.extend(_collect_schema_sensitive_fields(doc, resp_obj["schema"]))
                    # OpenAPI 3.x content.*.schema
                    resp_content = resp_obj.get("content")
                    if isinstance(resp_content, dict):
                        for media_obj in resp_content.values():
                            if isinstance(media_obj, dict) and isinstance(media_obj.get("schema"), dict):
                                sensitive_exposed.extend(_collect_schema_sensitive_fields(doc, media_obj["schema"]))
                if sensitive_exposed:
                    findings.append({
                        "rule_id": "SNIPER-APIT-09",
                        "owasp_category": "OWASP API3:2023",
                        "severity": "high",
                        "title": "API yanıt şemasında hassas veri alanı maruziyeti",
                        "location": f"{op_loc} ({', '.join(sorted(set(sensitive_exposed)))})",
                        "source_name": source_name,
                    })

    score, grade = _score_findings(findings)
    return {
        "format": "sniper-api-contract-audit-v1",
        "source_name": source_name,
        "contract_type": detected_type,
        "score": score,
        "grade": grade,
        "endpoint_count": endpoint_count,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "controls_evaluated": [
            "SNIPER-CRYP-02",
            "SNIPER-APIT-02",
            "SNIPER-APIT-03",
            "SNIPER-APIT-05",
            "SNIPER-APIT-07",
            "SNIPER-APIT-09",
        ],
    }


def audit_api_contract(
    raw_content: str,
    *,
    contract_type: str = "auto",
    source_name: str = "inline-contract",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ApiContractAuditError("API sözleşmesi boş olamaz.")
    if len(raw_content.encode("utf-8")) > MAX_CONTRACT_BYTES:
        raise ApiContractAuditError("API sözleşmesi 2 MB boyut sınırını aşıyor.")

    requested_type = (contract_type or "auto").strip().casefold()
    if requested_type not in {"auto", "openapi", "openapi3", "swagger", "swagger2", "graphql"}:
        raise ApiContractAuditError("Desteklenmeyen sözleşme tipi.")

    if requested_type == "graphql" or (requested_type == "auto" and _looks_like_graphql(raw_content)):
        return _audit_graphql_sdl(raw_content, source_name)

    stripped = raw_content.strip()
    doc: dict[str, Any] | None = None
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                doc = parsed
            else:
                raise ApiContractAuditError("JSON API sözleşmesi kökü bir nesne olmalıdır.")
        except json.JSONDecodeError as exc:
            raise ApiContractAuditError("API sözleşmesi geçerli JSON değil.") from exc
    else:
        doc = _parse_simple_yaml(stripped)

    if not isinstance(doc, dict):
        raise ApiContractAuditError("API sözleşmesi ayrıştırılamadı.")

    if "openapi" in doc or requested_type in ("openapi", "openapi3"):
        detected = "openapi3"
    elif "swagger" in doc or requested_type in ("swagger", "swagger2"):
        detected = "swagger2"
    else:
        raise ApiContractAuditError("Sözleşme OpenAPI 3.x, Swagger 2.0 veya GraphQL şemasına uymuyor.")

    return _audit_openapi_or_swagger(doc, detected, source_name)


def audit_project_api_contracts(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots)
    contract_reports: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    graphql_root_fields: dict[str, set[str]] = {}
    ruby_sources: list[tuple[str, str]] = []
    ruby_source_bytes = 0

    with _opened_project_tree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=tuple(SKIP_DIRS), reject_unsafe=False):
            filename = project_file.name
            lower_name = filename.casefold()
            ext = project_file.path.suffix.casefold()
            is_openapi_file = lower_name in OPENAPI_CONTRACT_FILENAMES
            is_graphql_file = ext in GRAPHQL_EXTENSIONS
            if (
                _ruby_graphql_candidate(project_file.path)
                and len(ruby_sources) < MAX_GRAPHQL_RUBY_SOURCE_FILES
                and 0 < project_file.size <= MAX_GRAPHQL_RUBY_SOURCE_BYTES
                and ruby_source_bytes + project_file.size <= MAX_GRAPHQL_RUBY_TOTAL_BYTES
            ):
                try:
                    ruby_content = tree.read_text(project_file, MAX_GRAPHQL_RUBY_SOURCE_BYTES, errors="strict")
                except UnicodeDecodeError:
                    continue
                ruby_sources.append((project_file.path.as_posix(), ruby_content))
                ruby_source_bytes += project_file.size
                continue
            if not (is_openapi_file or is_graphql_file):
                continue
            if project_file.size == 0 or project_file.size > MAX_CONTRACT_BYTES:
                continue
            try:
                content = tree.read_text(project_file, MAX_CONTRACT_BYTES, errors="strict")
            except UnicodeDecodeError:
                continue
            rel_name = project_file.path.as_posix()
            try:
                ctype = "graphql" if is_graphql_file else "auto"
                report = audit_api_contract(content, contract_type=ctype, source_name=rel_name)
                contract_reports.append(report)
                all_findings.extend(report["findings"])
                if is_graphql_file:
                    for field_name, root_types in _graphql_root_fields(content).items():
                        graphql_root_fields.setdefault(field_name, set()).update(root_types)
            except ApiContractAuditError:
                continue

    resolver_findings = _audit_graphql_ruby_resolvers(graphql_root_fields, ruby_sources)
    all_findings.extend(resolver_findings)

    score, grade = _score_findings(all_findings)
    return {
        "format": "sniper-project-api-contract-audit-v1",
        "project_path": str(root),
        "contracts_audited": len(contract_reports),
        "resolver_files_audited": len(ruby_sources) if graphql_root_fields else 0,
        "resolver_finding_count": len(resolver_findings),
        "finding_count": len(all_findings),
        "score": score,
        "grade": grade,
        "contracts": contract_reports,
        "findings": all_findings,
    }


_SHADOW_ROUTE_RE = re.compile(
    r"(?:@?\b(?:app|router|bp|api)\.(?:get|post|put|delete|patch|route))\s*\(\s*[\"'](/[^\"']+)[\"']"
)
_BOPLA_CODE_RE = re.compile(
    r"(?:"
    r"\b[A-Z]\w*\s*\(\s*\*\*\s*(?:request\.(?:json\b|form\b|get_json\s*\(\s*\)|data\b)|(?:payload|body|data)\b)"
    r"|Object\.assign\s*\(\s*\w+\s*,\s*req\.body\b"
    r"|\.create\s*\(\s*req\.body\s*\)"
    r"|\.update\s*\(\s*req\.body\b"
    r"|\.permit!(?!\w)"
    r")"
)


def audit_shadow_api_and_bopla(
    raw_content: str,
    *,
    contract_paths: list[str] | None = None,
    filename: str = "routes.py",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {
            "format": "sniper-shadow-api-bopla-audit/1",
            "filename": filename,
            "count": 0,
            "findings": [],
        }

    findings: list[dict[str, Any]] = []

    if contract_paths:
        known_paths = {str(p).strip() for p in contract_paths if str(p).strip()}
        if known_paths:
            for match in _SHADOW_ROUTE_RE.finditer(raw_content):
                route_path = match.group(1)
                if route_path not in known_paths:
                    line_no = raw_content.count("\n", 0, match.start()) + 1
                    findings.append({
                        "id": "SNIPER-OPENAPI-SHADOW-01",
                        "rule_id": "SNIPER-OPENAPI-SHADOW-01",
                        "control_id": "SNIPER-OPENAPI-SHADOW-01",
                        "severity": "high",
                        "cwe": "CWE-285",
                        "reference": "CWE-285",
                        "category": "api_security",
                        "owasp_category": "OWASP API9:2023",
                        "title": "OpenAPI sözleşmesinde tanımlı olmayan gölge uç nokta (Shadow / Zombie API)",
                        "description": (
                            f"Uygulama kodunda tanımlı '{route_path}' uç noktası OpenAPI sözleşmesinde "
                            "yer almıyor; belgesiz veya unutulmuş (Shadow/Zombie) API uç noktası güvenlik kontrollerini atlatabilir."
                        ),
                        "evidence": match.group(0).strip(),
                        "path": route_path,
                        "location": f"{filename}:{line_no} ({route_path})",
                        "recommendation": (
                            "Tüm aktif uç noktaları OpenAPI sözleşmesine dahil edin ve kullanımdan kalkmış "
                            "(zombie/debug) yönlendirmeleri kod tabanından kaldırın."
                        ),
                        "filename": filename,
                        "line": line_no,
                    })

    for match in _BOPLA_CODE_RE.finditer(raw_content):
        line_no = raw_content.count("\n", 0, match.start()) + 1
        findings.append({
            "id": "SNIPER-API-BOPLA-03",
            "rule_id": "SNIPER-API-BOPLA-03",
            "control_id": "SNIPER-API-BOPLA-03",
            "severity": "high",
            "cwe": "CWE-915",
            "reference": "CWE-915",
            "category": "api_security",
            "owasp_category": "OWASP API3:2023",
            "title": "Sınırsız toplu atama (Mass Assignment / BOPLA — OWASP API3:2023)",
            "description": (
                "İstemciden gelen istek gövdesi (request.json / req.body / payload) alan bazlı "
                "allowlist uygulanmadan doğrudan ORM modeline veya nesneye aktarılıyor."
            ),
            "evidence": match.group(0).strip(),
            "location": f"{filename}:{line_no}",
            "recommendation": (
                "İstek verisini doğrudan modele açmak yerine yalnızca izin verilen alanları içeren "
                "açık DTO / Pydantic şeması (allowlist) kullanın."
            ),
            "filename": filename,
            "line": line_no,
        })

    return {
        "format": "sniper-shadow-api-bopla-audit/1",
        "filename": filename,
        "count": len(findings),
        "findings": findings,
    }


_GQL_FRAGMENT_OR_SUB_RE = re.compile(
    r"(?:\bfragment\s+[A-Za-z_][A-Za-z0-9_]*\s+on\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|\btype\s+(Subscription)\b\s*\{)",
    re.MULTILINE,
)
_GQL_UNSCOPED_LOOKUP_RE = re.compile(
    r"\b(?:find\s*\(|find_by_gid\b|GlobalID\b|findById\s*\(|findUnique\s*\(|objects\.get\s*\()"
)
_GQL_TENANT_GUARD_RE = re.compile(
    r"(?:\bauthorize!?|\bin_organization\b|Ability\.allowed\?|\bcurrent_user\.can\?"
    r"|\bcontext\.(?:tenantId|organizationId)\b|\btenant_id\s*==)"
)
_GQL_FED_KEY_RE = re.compile(r"@key\s*\(\s*fields\s*:")
_GQL_FED_RESOLVER_RE = re.compile(
    r"\b(?:__resolveReference|resolve_reference)\b[\s\S]{0,600}?"
    r"\b(?:findById|findUnique|findOne|find|\.get)\s*\("
)
_GQL_FED_AUTH_RE = re.compile(
    r"\b(?:context\.(?:user|tenantId|organizationId)|current_user\b|in_organization\b|authorize!?\b|Ability\.allowed\?)"
)
_GQL_PERSISTED_SENSITIVE_OP_RE = re.compile(
    r"(?:\bmutation\b|\b(?:admin|delete|destroy|promote|grant|impersonate|updateRole|reset\w*|purge)\w*\b)",
    re.IGNORECASE,
)
_GQL_RESOLVER_AUTH_GUARD_RE = re.compile(
    r"(?:\bauthorize!?|@UseGuards\b|\brequireAuth\b|\bisAdmin\b|Ability\.allowed\?"
    r"|\bcheck_admin\b|\bensure_admin\b|\bcontext\.(?:user|isAdmin|roles)\b|\bcurrent_user\.admin\?)"
)


def audit_graphql_advanced_authorization(
    schema_sdl: str,
    resolver_sources: dict[str, str] | str = "",
    *,
    persisted_Manifest: dict[str, str] | None = None,
    persisted_manifest: dict[str, str] | None = None,
) -> dict[str, Any]:
    sdl_text = schema_sdl if isinstance(schema_sdl, str) else ""
    if isinstance(resolver_sources, dict):
        source_items = [(str(k), str(v)) for k, v in resolver_sources.items() if isinstance(v, str)]
    elif isinstance(resolver_sources, str) and resolver_sources.strip():
        source_items = [("resolvers", resolver_sources)]
    else:
        source_items = []

    combined_resolvers = "\n".join(text for _, text in source_items)
    manifest = persisted_Manifest if persisted_Manifest is not None else persisted_manifest
    findings: list[dict[str, Any]] = []

    # (a) SNIPER-GQL-FRAG-01: Fragment/Spread or Subscription unscoped tenant lookup
    frag_or_sub_match = _GQL_FRAGMENT_OR_SUB_RE.search(sdl_text) or _GQL_FRAGMENT_OR_SUB_RE.search(combined_resolvers)
    if frag_or_sub_match and combined_resolvers:
        target_type = frag_or_sub_match.group(1) or frag_or_sub_match.group(2) or "Subscription"
        lookup_match = _GQL_UNSCOPED_LOOKUP_RE.search(combined_resolvers)
        if lookup_match and not _GQL_TENANT_GUARD_RE.search(combined_resolvers):
            findings.append({
                "id": "SNIPER-GQL-FRAG-01",
                "rule_id": "SNIPER-GQL-FRAG-01",
                "control_id": "SNIPER-GQL-FRAG-01",
                "severity": "high",
                "cwe": "CWE-862",
                "reference": "CWE-862",
                "category": "api_security",
                "owasp_category": "OWASP API1:2023",
                "title": "GraphQL Fragment/Spread veya Subscription üzerinden yetkisiz/tenant-dışı alan erişimi",
                "description": (
                    f"GraphQL '{target_type}' fragment/subscription alanı, authorize veya tenant kapsam kontrolü "
                    "olmadan doğrudan nesne/GlobalID sorgusu ile çözümleniyor."
                ),
                "evidence": lookup_match.group(0).strip(),
                "location": f"graphql:{target_type}",
            })

    # (b) SNIPER-GQL-FED-02: Apollo Federation (@key / __resolveReference) missing tenant/owner check
    if _GQL_FED_KEY_RE.search(sdl_text) and combined_resolvers:
        for src_name, src_text in source_items:
            fed_match = _GQL_FED_RESOLVER_RE.search(src_text)
            if fed_match:
                window = src_text[max(0, fed_match.start() - 100):min(len(src_text), fed_match.end() + 300)]
                if not _GQL_FED_AUTH_RE.search(window):
                    findings.append({
                        "id": "SNIPER-GQL-FED-02",
                        "rule_id": "SNIPER-GQL-FED-02",
                        "control_id": "SNIPER-GQL-FED-02",
                        "severity": "critical",
                        "cwe": "CWE-639",
                        "reference": "CWE-639",
                        "category": "api_security",
                        "owasp_category": "OWASP API1:2023",
                        "title": "Apollo Federation (__resolveReference / @key) varlık çözümleyicisinde tenant/sahiplik kontrolü eksikliği",
                        "description": (
                            "Federation @key varlık çözümleyicisi (__resolveReference), context.user / context.tenantId "
                            "kontrolü yapmadan doğrudan ID ile kayıt döndürüyor."
                        ),
                        "evidence": fed_match.group(0).splitlines()[0].strip(),
                        "location": f"{src_name}:__resolveReference",
                    })
                    break

    # (c) SNIPER-GQL-PERSIST-03: Persisted GraphQL query manifest unprotected mutation / admin query
    if isinstance(manifest, dict) and manifest:
        for query_id, query_body in manifest.items():
            q_text = str(query_body or "")
            if _GQL_PERSISTED_SENSITIVE_OP_RE.search(q_text):
                if not _GQL_RESOLVER_AUTH_GUARD_RE.search(combined_resolvers):
                    findings.append({
                        "id": "SNIPER-GQL-PERSIST-03",
                        "rule_id": "SNIPER-GQL-PERSIST-03",
                        "control_id": "SNIPER-GQL-PERSIST-03",
                        "severity": "high",
                        "cwe": "CWE-285",
                        "reference": "CWE-285",
                        "category": "api_security",
                        "owasp_category": "OWASP API5:2023",
                        "title": "Persisted GraphQL sorgu manifestinde (persisted_queries) korumasız mutasyon veya yönetici operasyonu",
                        "description": (
                            f"Persisted query '{query_id}' hassas bir mutasyon veya yönetici operasyonu içeriyor "
                            "ancak hedef çözümleyicide yetki doğrulaması bulunmuyor."
                        ),
                        "evidence": q_text.strip()[:160],
                        "location": f"persisted_queries:{query_id}",
                    })
                    break

    return {
        "format": "sniper-graphql-advanced-authz/1",
        "finding_count": len(findings),
        "findings": findings,
    }



