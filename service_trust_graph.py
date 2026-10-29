"""Seçili yerel depolar arasında kanıtlı, sınırlı servis güven ilişkileri.

İlk sözleşme yalnız OpenAPI JSON ``servers`` + ``paths`` üreticisini ve başka
bir depodaki aynı origin/path'e giden sabit HTTP istemci çağrısını bağlar.
Ağ isteği yapmaz; origin/URL değerlerini çıktıya koymaz.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Iterable
from urllib.parse import urlsplit


FORMAT = "sniper-service-trust-graph-v1"
MAX_REPOSITORIES = 300
MAX_CONTRACT_FILES_PER_REPO = 20
MAX_CONTRACT_BYTES = 1_000_000
MAX_SOURCE_FILES_PER_REPO = 2_000
MAX_SOURCE_BYTES = 1_000_000
MAX_EDGES = 1_000
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
SOURCE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php", ".cs"})
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__"})
_REPO_NAME_RE = re.compile(r"[^A-Za-z0-9._/\-]+")
_CALL_RE = re.compile(
    r"\b(?:requests|httpx|axios|client|ky)\.(?P<method>get|post|put|patch|delete|options|head)\s*\(\s*"
    r"(?P<quote>['\"])(?P<url>https?://[^'\"\s]+)(?P=quote)",
    re.IGNORECASE,
)
_FETCH_RE = re.compile(r"\bfetch\s*\(\s*(?P<quote>['\"])(?P<url>https?://[^'\"\s]+)(?P=quote)", re.IGNORECASE)


@dataclass(frozen=True)
class _Operation:
    repository: str
    origin: tuple[str, str, int | None]
    method: str
    path_template: str
    path_regex: re.Pattern[str]


@dataclass(frozen=True)
class _ClientCall:
    repository: str
    origin: tuple[str, str, int | None]
    method: str
    path: str
    file: str
    line: int


def _repository_name(value: str, root: Path) -> str:
    text = _REPO_NAME_RE.sub("-", str(value).replace("\\", "/")).strip("-/")[:160]
    return text or _REPO_NAME_RE.sub("-", root.name).strip("-")[:160] or "repository"


def _origin(url: str) -> tuple[tuple[str, str, int | None], str] | None:
    if not isinstance(url, str) or len(url) > 4_096 or "{" in url or "}" in url:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return None
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    base = "/" + parsed.path.strip("/") if parsed.path.strip("/") else ""
    return (scheme, host, effective_port), base


def _join_path(base: str, path: str) -> str:
    return "/" + "/".join(part.strip("/") for part in (base, path) if part.strip("/"))


def _path_regex(template: str) -> re.Pattern[str] | None:
    if not isinstance(template, str) or not template.startswith("/") or len(template) > 2_048:
        return None
    pieces: list[str] = []
    position = 0
    for match in re.finditer(r"\{[A-Za-z_][A-Za-z0-9_.\-]*\}", template):
        pieces.append(re.escape(template[position:match.start()]))
        pieces.append(r"[^/]+")
        position = match.end()
    pieces.append(re.escape(template[position:]))
    try:
        return re.compile("^" + "".join(pieces) + "/?$")
    except re.error:
        return None


def _walk(root: Path, *, contract: bool) -> tuple[list[Path], bool]:
    limit = MAX_CONTRACT_FILES_PER_REPO if contract else MAX_SOURCE_FILES_PER_REPO
    found: list[Path] = []
    truncated = False
    try:
        iterator = os.walk(root, topdown=True, followlinks=False)
        for directory, directories, files in iterator:
            directories[:] = sorted(name for name in directories if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file():
                    continue
                lower = name.casefold()
                wanted = (path.suffix.casefold() == ".json" and ("openapi" in lower or "swagger" in lower)) \
                    if contract else path.suffix.casefold() in SOURCE_SUFFIXES
                if not wanted:
                    continue
                if len(found) >= limit:
                    truncated = True
                    return found, truncated
                found.append(path)
    except OSError:
        return found, truncated
    return found, truncated


def _read(path: Path, maximum: int) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None


def _operations(repository: str, root: Path) -> tuple[list[_Operation], bool]:
    operations: list[_Operation] = []
    files, truncated = _walk(root, contract=True)
    for path in files:
        text = _read(path, MAX_CONTRACT_BYTES)
        if text is None:
            continue
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            continue
        if not isinstance(document, dict) or not isinstance(document.get("openapi") or document.get("swagger"), str):
            continue
        servers = document.get("servers")
        if not isinstance(servers, list):
            continue
        origins = []
        for server in servers[:20]:
            parsed = _origin(server.get("url")) if isinstance(server, dict) else None
            if parsed and parsed not in origins:
                origins.append(parsed)
        paths = document.get("paths")
        if not origins or not isinstance(paths, dict):
            continue
        for contract_path, item in sorted(paths.items(), key=lambda pair: str(pair[0])):
            if not isinstance(contract_path, str) or not isinstance(item, dict):
                continue
            for method in sorted(key.casefold() for key in item if isinstance(key, str) and key.casefold() in HTTP_METHODS):
                for origin, base in origins:
                    full_path = _join_path(base, contract_path)
                    matcher = _path_regex(full_path)
                    if matcher is not None:
                        operations.append(_Operation(repository, origin, method.upper(), full_path, matcher))
    return operations, truncated


def _client_calls(repository: str, root: Path) -> tuple[list[_ClientCall], bool]:
    calls: list[_ClientCall] = []
    files, truncated = _walk(root, contract=False)
    for path in files:
        text = _read(path, MAX_SOURCE_BYTES)
        if text is None:
            continue
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            matches = [(match.group("method").upper(), match.group("url")) for match in _CALL_RE.finditer(line)]
            matches.extend(("GET", match.group("url")) for match in _FETCH_RE.finditer(line))
            for method, url in matches:
                parsed = _origin(url)
                if parsed is None:
                    continue
                origin, _base = parsed
                try:
                    request = urlsplit(url)
                except ValueError:
                    continue
                request_path = request.path or "/"
                calls.append(_ClientCall(repository, origin, method, request_path, relative, line_number))
    return calls, truncated


def build(repositories: Iterable[tuple[str, Path]]) -> dict:
    """Depo ad/yol çiftlerinden deterministik, redacted servis grafiği üretir."""
    normalized: list[tuple[str, Path]] = []
    truncated = False
    for raw_name, raw_root in repositories:
        if len(normalized) >= MAX_REPOSITORIES:
            truncated = True
            break
        root = Path(raw_root)
        try:
            if root.is_symlink() or not root.is_dir():
                continue
        except OSError:
            continue
        name = _repository_name(str(raw_name), root)
        if all(existing != name for existing, _path in normalized):
            normalized.append((name, root))

    operations: list[_Operation] = []
    calls: list[_ClientCall] = []
    for name, root in normalized:
        produced, contract_truncated = _operations(name, root)
        consumed, source_truncated = _client_calls(name, root)
        operations.extend(produced)
        calls.extend(consumed)
        truncated = truncated or contract_truncated or source_truncated

    edges: list[dict] = []
    seen: set[tuple[str, str, str, str, str, int]] = set()
    for call in calls:
        for operation in operations:
            if call.repository == operation.repository or call.origin != operation.origin \
                    or call.method != operation.method or not operation.path_regex.fullmatch(call.path):
                continue
            key = (call.repository, operation.repository, operation.method, operation.path_template, call.file, call.line)
            if key in seen:
                continue
            if len(edges) >= MAX_EDGES:
                truncated = True
                break
            seen.add(key)
            edges.append({
                "consumer": "repo:" + call.repository,
                "producer": "repo:" + operation.repository,
                "protocol": "http",
                "operation": f"{operation.method} {operation.path_template}",
                "evidence": {"file": call.file, "line": call.line, "kind": "openapi+literal-client"},
            })
        if len(edges) >= MAX_EDGES:
            break
    edges.sort(key=lambda edge: (edge["consumer"], edge["producer"], edge["operation"], edge["evidence"]["file"], edge["evidence"]["line"]))

    roles: dict[str, set[str]] = {}
    for edge in edges:
        roles.setdefault(edge["consumer"][5:], set()).add("consumer")
        roles.setdefault(edge["producer"][5:], set()).add("producer")
    nodes = [{"id": "repo:" + name, "repository": name, "roles": sorted(node_roles)}
             for name, node_roles in sorted(roles.items())]
    return {
        "format": FORMAT,
        "summary": {"repositories": len(normalized), "nodes": len(nodes), "edges": len(edges), "truncated": truncated},
        "nodes": nodes,
        "edges": edges,
    }


def _norm_svc_id(raw: object) -> str:
    val = str(raw or "").strip()
    for prefix in ("repo:", "service:", "svc:"):
        if val.casefold().startswith(prefix):
            val = val[len(prefix):]
            break
    return val.strip().casefold()


def _extract_edge_method_path(edge: dict) -> tuple[str, str, str]:
    topic = str(edge.get("topic") or "").strip()
    method = str(edge.get("method") or "").strip().upper()
    path = str(edge.get("path") or "").strip()
    operation = str(edge.get("operation") or "").strip()
    if operation and (not method or not path):
        parts = operation.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
            method = method or parts[0].upper()
            path = path or parts[1].strip()
        elif not path and operation.startswith("/"):
            path = operation
    return method, path, topic


def _edge_path_matches(edge_path: str, trace_path: str) -> bool:
    if not edge_path or not trace_path:
        return not edge_path and not trace_path
    normalized_template = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", edge_path.strip())
    matcher = _path_regex(normalized_template)
    if matcher is not None and matcher.fullmatch(trace_path.strip()):
        return True
    return edge_path.strip().rstrip("/") == trace_path.strip().rstrip("/")


def correlate_service_graph_with_runtime_traces(
    static_graph: dict[str, object],
    runtime_traces: list[dict[str, object]],
) -> dict[str, object]:
    """Statik servis güven grafiğini yerel çalışma zamanı izleriyle (runtime traces) ilişkilendirir."""
    raw_edges = static_graph.get("edges") if isinstance(static_graph, dict) else []
    edges_list = raw_edges if isinstance(raw_edges, list) else []
    traces_list = runtime_traces if isinstance(runtime_traces, list) else []

    correlated_edges: list[dict[str, object]] = []
    state_counts: dict[str, int] = {
        "runtime_confirmed": 0,
        "contradicted": 0,
        "static_only": 0,
    }

    for raw_edge in edges_list:
        if not isinstance(raw_edge, dict):
            continue
        edge_copy = dict(raw_edge)
        edge_producer = _norm_svc_id(edge_copy.get("producer"))
        edge_consumer = _norm_svc_id(edge_copy.get("consumer"))
        edge_method, edge_path, edge_topic = _extract_edge_method_path(edge_copy)

        matched_traces: list[dict[str, object]] = []
        for trace in traces_list:
            if not isinstance(trace, dict):
                continue
            if _norm_svc_id(trace.get("producer")) != edge_producer:
                continue
            if _norm_svc_id(trace.get("consumer")) != edge_consumer:
                continue
            trace_topic = str(trace.get("topic") or "").strip()
            if edge_topic or trace_topic:
                if edge_topic != trace_topic:
                    continue
            else:
                trace_method = str(trace.get("method") or "").strip().upper()
                trace_path = str(trace.get("path") or "").strip()
                if edge_method and trace_method and edge_method != trace_method:
                    continue
                if edge_path and trace_path and not _edge_path_matches(edge_path, trace_path):
                    continue
            matched_traces.append(trace)

        if not matched_traces:
            state = "static_only"
        else:
            contradicted = False
            confirmed = False
            static_auth = edge_copy.get("authenticated")
            for tr in matched_traces:
                raw_status = tr.get("status_code")
                status_code = int(raw_status) if isinstance(raw_status, int) else 200
                tr_auth = tr.get("authenticated")
                if status_code in {401, 403}:
                    contradicted = True
                    break
                if static_auth is not None and tr_auth is not None and bool(static_auth) != bool(tr_auth):
                    contradicted = True
                    break
                if status_code < 400:
                    confirmed = True
            if contradicted:
                state = "contradicted"
            elif confirmed:
                state = "runtime_confirmed"
            else:
                state = "static_only"

        edge_copy["verification_state"] = state
        state_counts[state] = state_counts.get(state, 0) + 1
        correlated_edges.append(edge_copy)

    return {
        "format": "sniper-runtime-correlated-service-graph/1",
        "edge_count": len(correlated_edges),
        "counts": state_counts,
        "edges": correlated_edges,
    }

