"""Yerel depolar arasında redacted webhook producer/receiver korelasyonu.

Yalnız OpenAPI JSON ile açıkça webhook-benzeri POST/PUT receiver path'lerini
ve başka depodaki sabit URL'li HTTP çağrılarını bağlar. Ağ isteği yapmaz.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import urlsplit


FORMAT = "sniper-webhook-trust-graph-v1"
MAX_REPOSITORIES = 300
MAX_CONTRACT_FILES_PER_REPO = 20
MAX_CONTRACT_BYTES = 1_000_000
MAX_SOURCE_FILES_PER_REPO = 2_000
MAX_SOURCE_BYTES = 1_000_000
MAX_EDGES = 1_000
SOURCE_SUFFIXES = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb", ".php", ".cs"})
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__"})
_REPO_NAME_RE = re.compile(r"[^A-Za-z0-9._/\-]+")
_WEBHOOK_PATH_RE = re.compile(r"(?i)(?:^|/)(?:webhooks?|callbacks?|hooks?)(?:/|$)")
_CLIENT_RE = re.compile(
    r"\b(?:requests|httpx|axios|client|ky)\.(?P<method>post|put)\s*\(\s*"
    r"(?P<quote>['\"])(?P<url>https?://[^'\"\s]+)(?P=quote)",
    re.IGNORECASE,
)
_SIGNATURE_RE = re.compile(r"(?i)(?:x[-_]?(?:hub[-_]?)?signature|webhook[-_]?signature|hmac|signature|webhook[-_]?secret)")


@dataclass(frozen=True)
class _Receiver:
    repository: str
    origin: tuple[str, str, int]
    method: str
    template: str
    matcher: re.Pattern[str]
    auth_declared: bool


@dataclass(frozen=True)
class _ProducerCall:
    repository: str
    origin: tuple[str, str, int]
    method: str
    path: str
    file: str
    line: int
    signature_signal: bool


def _repository_name(value: str, root: Path) -> str:
    normalized = _REPO_NAME_RE.sub("-", str(value).replace("\\", "/")).strip("-/")[:160]
    return normalized or _REPO_NAME_RE.sub("-", root.name).strip("-")[:160] or "repository"


def _split_url(value: object) -> tuple[tuple[str, str, int], str] | None:
    if not isinstance(value, str) or len(value) > 4_096 or "{" in value or "}" in value:
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return None
    return (scheme, host, port if port is not None else (443 if scheme == "https" else 80)), parsed.path or "/"


def _join_path(base: str, route: str) -> str:
    return "/" + "/".join(part.strip("/") for part in (base, route) if part.strip("/"))


def _compile_template(template: str) -> re.Pattern[str] | None:
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


def _walk(root: Path, *, contracts: bool) -> tuple[list[Path], bool]:
    limit = MAX_CONTRACT_FILES_PER_REPO if contracts else MAX_SOURCE_FILES_PER_REPO
    found: list[Path] = []
    try:
        for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
            directories[:] = sorted(name for name in directories if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file():
                    continue
                lower = name.casefold()
                wanted = path.suffix.casefold() == ".json" and ("openapi" in lower or "swagger" in lower) \
                    if contracts else path.suffix.casefold() in SOURCE_SUFFIXES
                if not wanted:
                    continue
                if len(found) >= limit:
                    return found, True
                found.append(path)
    except OSError:
        return found, False
    return found, False


def _read(path: Path, maximum: int) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None


def _auth_declared(operation: dict, document: dict) -> bool:
    security = operation.get("security") if "security" in operation else document.get("security")
    return bool(security) if isinstance(security, (list, dict)) else False


def _receivers(repository: str, root: Path) -> tuple[list[_Receiver], bool]:
    receivers: list[_Receiver] = []
    files, truncated = _walk(root, contracts=True)
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
        raw_servers = document.get("servers")
        paths = document.get("paths")
        if not isinstance(raw_servers, list) or not isinstance(paths, dict):
            continue
        servers = []
        for raw in raw_servers[:20]:
            parsed = _split_url(raw.get("url")) if isinstance(raw, dict) else None
            if parsed and parsed not in servers:
                servers.append(parsed)
        for route, path_item in sorted(paths.items(), key=lambda pair: str(pair[0])):
            if not isinstance(route, str) or not _WEBHOOK_PATH_RE.search(route) or not isinstance(path_item, dict):
                continue
            for method in ("post", "put"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                for (origin, base) in servers:
                    template = _join_path(base, route)
                    matcher = _compile_template(template)
                    if matcher is not None:
                        receivers.append(_Receiver(repository, origin, method.upper(), template, matcher,
                                                   _auth_declared(operation, document)))
    return receivers, truncated


def _producer_calls(repository: str, root: Path) -> tuple[list[_ProducerCall], bool]:
    calls: list[_ProducerCall] = []
    files, truncated = _walk(root, contracts=False)
    for path in files:
        text = _read(path, MAX_SOURCE_BYTES)
        if text is None:
            continue
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in _CLIENT_RE.finditer(line):
                parsed = _split_url(match.group("url"))
                if parsed is None:
                    continue
                origin, request_path = parsed
                calls.append(_ProducerCall(
                    repository, origin, match.group("method").upper(), request_path, relative, line_number,
                    bool(_SIGNATURE_RE.search(line)),
                ))
    return calls, truncated


def build(repositories: Iterable[tuple[str, Path]]) -> dict:
    """Yerel depo çiftlerinden bounded ve redacted webhook trust graph üretir."""
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

    receivers: list[_Receiver] = []
    calls: list[_ProducerCall] = []
    for name, root in normalized:
        repo_receivers, contract_truncated = _receivers(name, root)
        repo_calls, source_truncated = _producer_calls(name, root)
        receivers.extend(repo_receivers)
        calls.extend(repo_calls)
        truncated = truncated or contract_truncated or source_truncated

    edges: list[dict] = []
    seen: set[tuple[str, str, str, str, str, int]] = set()
    for call in calls:
        for receiver in receivers:
            if call.repository == receiver.repository or call.origin != receiver.origin \
                    or call.method != receiver.method or not receiver.matcher.fullmatch(call.path):
                continue
            key = (call.repository, receiver.repository, receiver.method, receiver.template, call.file, call.line)
            if key in seen:
                continue
            if len(edges) >= MAX_EDGES:
                truncated = True
                break
            seen.add(key)
            signals_present = receiver.auth_declared and call.signature_signal
            edges.append({
                "producer": "repo:" + call.repository,
                "receiver": "repo:" + receiver.repository,
                "protocol": "webhook-http",
                "operation": f"{receiver.method} {receiver.template}",
                "trust_signals": {
                    "receiver_auth_declared": receiver.auth_declared,
                    "producer_signature_signal": call.signature_signal,
                    "status": "signals-present" if signals_present else "review",
                },
                "evidence": {"file": call.file, "line": call.line, "kind": "openapi-webhook+literal-post"},
            })
        if len(edges) >= MAX_EDGES:
            break
    edges.sort(key=lambda edge: (edge["producer"], edge["receiver"], edge["operation"], edge["evidence"]["file"], edge["evidence"]["line"]))

    roles: dict[str, set[str]] = {}
    for edge in edges:
        roles.setdefault(edge["producer"][5:], set()).add("producer")
        roles.setdefault(edge["receiver"][5:], set()).add("receiver")
    nodes = [{"id": "repo:" + name, "repository": name, "roles": sorted(role_set)}
             for name, role_set in sorted(roles.items())]
    return {
        "format": FORMAT,
        "summary": {
            "repositories": len(normalized),
            "nodes": len(nodes),
            "edges": len(edges),
            "review_edges": sum(1 for edge in edges if edge["trust_signals"]["status"] == "review"),
            "truncated": truncated,
        },
        "nodes": nodes,
        "edges": edges,
    }
