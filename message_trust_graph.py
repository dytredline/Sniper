"""Yerel depolar arasında redacted Kafka publisher/consumer korelasyonu."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable


FORMAT = "sniper-message-trust-graph-v1"
MAX_REPOSITORIES = 300
MAX_SOURCE_FILES_PER_REPO = 2_000
MAX_SOURCE_BYTES = 1_000_000
MAX_EDGES = 1_000
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__",
})
_REPO_NAME_RE = re.compile(r"[^A-Za-z0-9._/\-]+")
_TOPIC_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,248}\Z")
_CONSTRUCTORS = {
    ("kafka", "KafkaProducer"): ("publisher", "KafkaProducer"),
    ("kafka", "KafkaConsumer"): ("consumer", "KafkaConsumer"),
    ("confluent_kafka", "Producer"): ("publisher", "Producer"),
    ("confluent_kafka", "Consumer"): ("consumer", "Consumer"),
}


@dataclass(frozen=True)
class _Endpoint:
    repository: str
    role: str
    channel: str
    file: str
    line: int
    kind: str


def _repository_name(value: str, root: Path) -> str:
    normalized = _REPO_NAME_RE.sub("-", str(value).replace("\\", "/")).strip("-/")[:160]
    return normalized or _REPO_NAME_RE.sub("-", root.name).strip("-")[:160] or "repository"


def _walk(root: Path) -> tuple[list[Path], bool]:
    found: list[Path] = []
    try:
        for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
            directories[:] = sorted(
                name for name in directories
                if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink()
            )
            for name in sorted(files):
                path = Path(directory) / name
                if path.suffix.casefold() != ".py" or path.is_symlink() or not path.is_file():
                    continue
                if len(found) >= MAX_SOURCE_FILES_PER_REPO:
                    return found, True
                found.append(path)
    except OSError:
        return found, False
    return found, False


def _read(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None


def _literal_topic(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    value = node.value.strip()
    return value if _TOPIC_RE.fullmatch(value) else None


def _call_topic(call: ast.Call) -> str | None:
    if call.args:
        topic = _literal_topic(call.args[0])
        if topic is not None:
            return topic
    for keyword in call.keywords:
        if keyword.arg == "topic":
            return _literal_topic(keyword.value)
    return None


def _subscription_topics(call: ast.Call) -> list[str]:
    value: ast.AST | None = call.args[0] if call.args else None
    if value is None:
        for keyword in call.keywords:
            if keyword.arg == "topics":
                value = keyword.value
                break
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        topics = [_literal_topic(item) for item in value.elts]
        return [topic for topic in topics if topic is not None]
    topic = _literal_topic(value)
    return [topic] if topic is not None else []


def _imports(tree: ast.Module) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    symbols: dict[str, tuple[str, str]] = {}
    modules: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module in {"kafka", "confluent_kafka"}:
            for alias in node.names:
                key = (node.module, alias.name)
                if key in _CONSTRUCTORS:
                    symbols[alias.asname or alias.name] = key
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"kafka", "confluent_kafka"}:
                    modules[alias.asname or alias.name] = alias.name
    return symbols, modules


def _constructor(func: ast.AST, symbols: dict[str, tuple[str, str]], modules: dict[str, str]) \
        -> tuple[str, str] | None:
    key: tuple[str, str] | None = None
    if isinstance(func, ast.Name):
        key = symbols.get(func.id)
    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = modules.get(func.value.id)
        if module is not None:
            key = (module, func.attr)
    return _CONSTRUCTORS.get(key) if key is not None else None


def _assignment_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


def _analyze(repository: str, root: Path) -> tuple[list[_Endpoint], bool]:
    endpoints: list[_Endpoint] = []
    files, truncated = _walk(root)
    for path in files:
        text = _read(path)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
            relative = path.relative_to(root).as_posix()
        except (SyntaxError, ValueError, RecursionError):
            continue
        symbols, modules = _imports(tree)
        publisher_vars: dict[str, str] = {}
        consumer_vars: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                continue
            constructor = _constructor(node.value.func, symbols, modules)
            if constructor is None:
                continue
            role, kind = constructor
            for name in _assignment_names(node):
                (publisher_vars if role == "publisher" else consumer_vars)[name] = kind

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            constructor = _constructor(node.func, symbols, modules)
            if constructor == ("consumer", "KafkaConsumer"):
                for argument in node.args:
                    topic = _literal_topic(argument)
                    if topic is None:
                        break
                    endpoints.append(_Endpoint(repository, "consumer", topic, relative, node.lineno, "KafkaConsumer"))
                continue
            if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name):
                continue
            variable = node.func.value.id
            method = node.func.attr
            if variable in publisher_vars and method in {"send", "produce"}:
                topic = _call_topic(node)
                if topic is not None:
                    endpoints.append(_Endpoint(
                        repository, "publisher", topic, relative, node.lineno,
                        f"{publisher_vars[variable]}.{method}",
                    ))
            elif variable in consumer_vars and method == "subscribe":
                for topic in _subscription_topics(node):
                    endpoints.append(_Endpoint(
                        repository, "consumer", topic, relative, node.lineno,
                        f"{consumer_vars[variable]}.subscribe",
                    ))
    unique = sorted(
        set(endpoints),
        key=lambda item: (item.role, item.channel, item.file, item.line, item.kind),
    )
    return unique, truncated


def build(repositories: Iterable[tuple[str, Path]]) -> dict:
    """Yerel depo çiftlerinden bounded ve broker-credential içermeyen Kafka graph üretir."""
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

    endpoints: list[_Endpoint] = []
    for name, root in normalized:
        repo_endpoints, repo_truncated = _analyze(name, root)
        endpoints.extend(repo_endpoints)
        truncated = truncated or repo_truncated
    publishers = [endpoint for endpoint in endpoints if endpoint.role == "publisher"]
    consumers = [endpoint for endpoint in endpoints if endpoint.role == "consumer"]

    edges: list[dict] = []
    for publisher in publishers:
        for consumer in consumers:
            if publisher.repository == consumer.repository or publisher.channel != consumer.channel:
                continue
            if len(edges) >= MAX_EDGES:
                truncated = True
                break
            edges.append({
                "publisher": "repo:" + publisher.repository,
                "consumer": "repo:" + consumer.repository,
                "broker": "kafka",
                "channel": publisher.channel,
                "evidence": {
                    "publisher": {"file": publisher.file, "line": publisher.line, "kind": publisher.kind},
                    "consumer": {"file": consumer.file, "line": consumer.line, "kind": consumer.kind},
                },
            })
        if len(edges) >= MAX_EDGES:
            break
    edges.sort(key=lambda edge: (
        edge["publisher"], edge["consumer"], edge["channel"],
        edge["evidence"]["publisher"]["file"], edge["evidence"]["consumer"]["file"],
    ))

    roles: dict[str, set[str]] = {}
    for edge in edges:
        roles.setdefault(edge["publisher"][5:], set()).add("publisher")
        roles.setdefault(edge["consumer"][5:], set()).add("consumer")
    nodes = [
        {"id": "repo:" + name, "repository": name, "roles": sorted(role_set)}
        for name, role_set in sorted(roles.items())
    ]
    return {
        "format": FORMAT,
        "summary": {
            "repositories": len(normalized), "nodes": len(nodes), "edges": len(edges), "truncated": truncated,
        },
        "nodes": nodes,
        "edges": edges,
    }
