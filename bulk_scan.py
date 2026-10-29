"""25. tur: toplu depo taraması — bir kök dizindeki git depolarını / proje köklerini keşfet, seçilenleri sırayla ya da
sınırlı eşzamanlılıkla tara, her depoyu ayrı proje olarak bulgu takibine ve portföye işle.

Keşif (salt okunur, ağ yok):
* Kök dizin izinli kökler kuralıyla doğrulanır (``project_analyzer.validate_project_path``).
* Aday: ``.git`` (dizin ya da worktree/alt modül dosyası), bağımlılık bildirimi ya da monorepo bildirimi olan dizin.
  Aday bulunan dizinin altına inilmez (depo bir bütün olarak taranır; monorepo alt projeleri bilgi olarak verilir).
* Sınırlar: derinlik, aday sayısı, gezilen dizin sayısı, süre ve depo boyutu. Sembolik bağ izlenmez; varsayılan
  atlanan dizinler (node_modules, vendor, build …) ve gizli dizinler gezilmez.
* git yalnız nesne veritabanını okuyan komutlarla çalışır (``rev-parse``, ``cat-file``; changed_scan'in sertleştirilmiş
  ortamı: kanca/fsmonitor/ağ yok). ``git log``/``status`` kullanılmaz (depo yapılandırması imza doğrulama ya da
  clean süzgeci gibi komutlar tanımlayabilir). Uzak adres ``.git/config`` dosyasından okunur; yalnız türetilmiş ad
  (``sahip/depo``) ve sunucu adı döner — ham adres ve içindeki kimlik bilgisi hiçbir çıktıya yazılmaz.

Tarama (iş kuyruğunda tek iş): her depo için proje analizi (``/api/project-audits``) + çevrimdışı SCA
(``/api/dependency-security/offline-scan``) ve isteğe bağlı konteyner imajı (depodaki docker save / OCI arşivi).
IaC denetimleri (Dockerfile, Terraform, Kubernetes, Helm) proje analizinin parçasıdır. Bir deponun hatası
diğerlerini durdurmaz; iptal, sıradaki depoları başlatmaz ve çalışan alt süreçleri durdurur. "Yalnız değişenler":
HEAD commit'i son başarılı taramayla aynıysa depo atlanır; isteğe bağlı git tabanlı değişen dosya modu son taranan
commit'i taban alır. Başarılı/atlanan depolar için altı bağımsız ve sınırlı yerel korelasyon üretilir: OpenAPI ile
sabit HTTP istemci çağrısı, webhook producer/receiver, Kafka publisher/consumer, açık auth-contract manifestleri,
exact-pinned PyPI sürüm drift'i ve GraphQL SDL root alanı/literal operation eşleşmesi. Bir grafiğin çözümlenememesi
diğer grafiklerin sonuçlarını silmez; ham origin, broker endpoint'i, özel paket indeksi, GraphQL endpoint'i ve kimlik
bilgisi graph çıktılarına taşınmaz. Seçili depo kökündeki exact-name, bütünlüğü doğrulanmış yerel runtime trace
manifestleri yalnız birebir statik edge anahtarlarını gözlemli olarak işaretleyebilir; trace olmaması veya geçersizliği
statik edge'i düşürmez.

Durum ``$SNIPER_DATA_DIR/bulk-scans.json`` (0600, kilitli) dosyasında: çalıştırmalar, depo başına son commit ve
portföy grupları (grup adı → kök dizin + proje yolları).
"""
from __future__ import annotations

from collections import Counter, deque
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tarfile
import threading
import time
from typing import Any, Callable
import urllib.parse

import dependency_lineage_graph
import message_trust_graph
import ops_files
import runtime_service_trace
import scan_scope
import service_trust_graph
import webhook_trust_graph

STATE_FILE = "bulk-scans.json"
MAX_RUNS = 30
MAX_GROUP_PATHS = 2_000

DEFAULT_MAX_DEPTH = 4
HARD_MAX_DEPTH = 8
DEFAULT_MAX_REPOS = 100
HARD_MAX_REPOS = 300
MAX_PARALLEL = 4
MAX_DIRS_VISITED = 20_000
DISCOVERY_SECONDS = 30.0
INVENTORY_ENTRIES = 40_000  # aday başına boyut/dil tahmini için en çok dizin girdisi
DEFAULT_MAX_REPO_MB = 500
MAX_CONFIG_BYTES = 256_000
MAX_IMAGES_PER_REPO = 3
MAX_IMAGE_TAR_MEMBERS = 5_000
AUTH_CONTRACT_MANIFEST = "sniper-auth-contracts.json"
AUTH_CONTRACT_FORMAT = "sniper-auth-contracts/1"
AUTH_GRAPH_FORMAT = "sniper-bulk-auth-contract-graph/1"
MAX_AUTH_CONTRACTS_PER_REPO = 16
MAX_AUTH_GRAPH_FINDINGS = 500
GRAPHQL_SERVICE_GRAPH_FORMAT = "sniper-bulk-graphql-service-graph/1"
GRAPHQL_SUFFIXES = frozenset({".graphql", ".gql", ".graphqls"})
GRAPHQL_PERSISTED_MANIFEST = "persisted-query-manifest.json"
MAX_GRAPHQL_FILE_BYTES = 128_000
MAX_GRAPHQL_MANIFEST_BYTES = 256_000
MAX_GRAPHQL_PERSISTED_OPERATIONS = 128
MAX_GRAPHQL_FILES_PER_REPO = 128
MAX_GRAPHQL_SCAN_ENTRIES = 20_000
MAX_GRAPHQL_SCAN_DEPTH = 8
MAX_GRAPHQL_GRAPH_EDGES = 1_000

# Monorepo bildirimleri (package.json "workspaces" ayrıca monorepo.detect ile görülür).
MONOREPO_FILES = frozenset({"pnpm-workspace.yaml", "lerna.json", "go.work", "nx.json", "turbo.json", "rush.json"})
_SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_GROUP_RE = re.compile(r"[\w .:/+\-]{1,60}\Z", re.UNICODE)
_RUN_ID_RE = re.compile(r"blk_[0-9a-f]{12}\Z")
_NAME_PART_RE = re.compile(r"[^A-Za-z0-9._\-]+")
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.\-]{0,98}[a-z0-9])?\Z")
_AUTH_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/\-]{0,119}\Z")
_AUTH_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,79}\Z")
_AUTH_SECRET_PREFIX_RE = re.compile(r"(?:gh[pousr]_|github_pat_|glpat-|sk_(?:live|test)_|sk-|AKIA)", re.IGNORECASE)
_GRAPHQL_NAME = r"[_A-Za-z][_0-9A-Za-z]*"
_GRAPHQL_TOKEN_RE = re.compile(rf"\.\.\.|{_GRAPHQL_NAME}|[!$():=@\[\]{{|}}]")
_GRAPHQL_SCHEMA_RE = re.compile(r"\bschema\b[^{}]*\{")
_GRAPHQL_TYPE_RE = re.compile(rf"\b(?:extend\s+)?type\s+({_GRAPHQL_NAME})\b[^{{}}]*\{{")
_GRAPHQL_FIELD_DEF_RE = re.compile(
    rf"(?m)^[ \t]*({_GRAPHQL_NAME})[ \t]*(?:\([^{{}}\n]*\))?[ \t]*:"
)
FINAL_ITEM_STATES = frozenset({"succeeded", "skipped", "failed", "cancelled"})


class BulkScanError(ValueError):
    """Geçersiz toplu tarama isteği ya da depo taranamadı."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.environ.get(name, default))))
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# git meta verisi (ağ yok; yalnız nesne okuyan komutlar)
# ---------------------------------------------------------------------------
def _git_dir(repo: Path) -> Path | None:
    """``.git`` dizini ya da ``gitdir: …`` dosyasının gösterdiği dizin (sembolik bağ izlenmez)."""
    marker = repo / ".git"
    try:
        if marker.is_symlink():
            return None
        if marker.is_dir():
            return marker
        if marker.is_file() and marker.stat().st_size <= 4096:
            first = marker.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
            if first and first[0].startswith("gitdir:"):
                target = Path(first[0][7:].strip())
                target = target if target.is_absolute() else repo / target
                if target.is_dir():
                    return target.resolve()
    except OSError:
        return None
    return None


def _read_small(path: Path, limit: int = MAX_CONFIG_BYTES) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _mask_graphql_noncode(source: str) -> str | None:
    """Mask comments and string values so schema/query decoys cannot create graph contracts."""
    if not isinstance(source, str) or "\x00" in source or "${" in source or "`" in source:
        return None
    output = list(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        if state == "code":
            if char == "#":
                output[index] = " "
                state = "comment"
                index += 1
                continue
            if source.startswith('"""', index):
                output[index:index + 3] = "   "
                state = "block_string"
                index += 3
                continue
            if char == '"':
                output[index] = " "
                state = "string"
                index += 1
                continue
            index += 1
            continue
        if state == "comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block_string":
            if source.startswith('"""', index):
                output[index:index + 3] = "   "
                index += 3
                state = "code"
            else:
                if char != "\n":
                    output[index] = " "
                index += 1
            continue
        if char == "\\" and index + 1 < len(source):
            output[index] = " "
            if source[index + 1] != "\n":
                output[index + 1] = " "
            index += 2
        elif char == '"':
            output[index] = " "
            index += 1
            state = "code"
        elif char == "\n":
            return None
        else:
            output[index] = " "
            index += 1
    if state not in {"code", "comment"}:
        return None
    return "".join(output)


def _matching_graphql_brace(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _graphql_sdl_contracts(masked: str) -> set[tuple[str, str]] | None:
    root_types = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}
    schema_blocks = list(_GRAPHQL_SCHEMA_RE.finditer(masked))
    declared_operations: set[str] = set()
    for schema_block in schema_blocks:
        opening = schema_block.end() - 1
        closing = _matching_graphql_brace(masked, opening)
        if closing is None:
            return None
        declarations = re.findall(
            rf"\b(query|mutation|subscription)\s*:\s*({_GRAPHQL_NAME})\b",
            masked[opening + 1:closing],
        )
        for operation, type_name in declarations:
            if operation in declared_operations:
                return None
            declared_operations.add(operation)
            root_types[operation] = type_name

    contracts: set[tuple[str, str]] = set()
    for match in _GRAPHQL_TYPE_RE.finditer(masked):
        root_operation = next(
            (operation for operation, type_name in root_types.items() if type_name == match.group(1)),
            None,
        )
        if root_operation is None:
            continue
        opening = match.end() - 1
        closing = _matching_graphql_brace(masked, opening)
        if closing is None:
            return None
        body = masked[opening + 1:closing]
        for field in _GRAPHQL_FIELD_DEF_RE.findall(body):
            if not field.startswith("__"):
                contracts.add((root_operation, field))
    return contracts


def _matching_graphql_token_brace(tokens: list[str], opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index] == "{":
            depth += 1
        elif tokens[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _graphql_root_selections(tokens: list[str]) -> tuple[set[str], set[str]] | None:
    fields: set[str] = set()
    spreads: set[str] = set()
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0
    skip_directive_name = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "{":
            brace_depth += 1
            index += 1
            continue
        if token == "}":
            if brace_depth == 0:
                return None
            brace_depth -= 1
            index += 1
            continue
        if brace_depth:
            index += 1
            continue
        if token == "(":
            paren_depth += 1
            index += 1
            continue
        if token == ")":
            if paren_depth == 0:
                return None
            paren_depth -= 1
            index += 1
            continue
        if token == "[":
            bracket_depth += 1
            index += 1
            continue
        if token == "]":
            if bracket_depth == 0:
                return None
            bracket_depth -= 1
            index += 1
            continue
        if paren_depth or bracket_depth:
            index += 1
            continue
        if token == "...":
            if index + 1 >= len(tokens) \
                    or re.fullmatch(_GRAPHQL_NAME, tokens[index + 1]) is None \
                    or tokens[index + 1] == "on":
                return None
            spreads.add(tokens[index + 1])
            index += 2
            continue
        if token == "$":
            return None
        if token == "@":
            skip_directive_name = True
            index += 1
            continue
        if re.fullmatch(_GRAPHQL_NAME, token):
            if skip_directive_name:
                skip_directive_name = False
                index += 1
                continue
            field = token
            if index + 2 < len(tokens) and tokens[index + 1] == ":" \
                    and re.fullmatch(_GRAPHQL_NAME, tokens[index + 2]):
                field = tokens[index + 2]
                index += 3
            else:
                index += 1
            if not field.startswith("__"):
                fields.add(field)
            continue
        index += 1
    if brace_depth or paren_depth or bracket_depth or skip_directive_name:
        return None
    return fields, spreads


def _graphql_fragment_root_matches(operation_type: str, type_name: str) -> bool:
    canonical = operation_type.casefold()
    candidate = type_name.casefold()
    return candidate == canonical or candidate.endswith(canonical)


def _graphql_top_level_headers(tokens: list[str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    depth = 0
    for index, token in enumerate(tokens):
        if token == "{":
            depth += 1
            continue
        if token == "}":
            depth = max(0, depth - 1)
            continue
        if depth == 0 and token in {"query", "mutation", "subscription"} \
                and index + 1 < len(tokens) \
                and re.fullmatch(_GRAPHQL_NAME, tokens[index + 1]):
            headers.append((token, tokens[index + 1]))
    return headers


def _graphql_document_contracts(masked: str) -> set[tuple[str, str]]:
    tokens = _GRAPHQL_TOKEN_RE.findall(masked)
    contracts: set[tuple[str, str]] = set()
    fragments: dict[str, tuple[str, set[str], set[str]]] = {}
    depth = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "{":
            depth += 1
            index += 1
            continue
        if token == "}":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth != 0 or token != "fragment":
            index += 1
            continue
        if index + 3 >= len(tokens) \
                or re.fullmatch(_GRAPHQL_NAME, tokens[index + 1]) is None \
                or tokens[index + 2] != "on" \
                or re.fullmatch(_GRAPHQL_NAME, tokens[index + 3]) is None:
            return set()
        fragment_name = tokens[index + 1]
        if fragment_name in fragments:
            return set()
        opening = index + 4
        while opening < len(tokens) and tokens[opening] != "{":
            if tokens[opening] in {"fragment", "query", "mutation", "subscription", "type", "schema"}:
                return set()
            opening += 1
        if opening >= len(tokens):
            return set()
        closing = _matching_graphql_token_brace(tokens, opening)
        if closing is None:
            return set()
        selections = _graphql_root_selections(tokens[opening + 1:closing])
        if selections is None:
            return set()
        fields, spreads = selections
        fragments[fragment_name] = (tokens[index + 3], fields, spreads)
        index = closing + 1

    def resolve_fragment(name: str, operation_type: str, resolving: frozenset[str]) -> set[str] | None:
        if name in resolving:
            return None
        fragment = fragments.get(name)
        if fragment is None:
            return None
        type_name, direct_fields, child_spreads = fragment
        if not _graphql_fragment_root_matches(operation_type, type_name):
            return None
        fields = set(direct_fields)
        next_resolving = resolving | {name}
        for child in child_spreads:
            resolved = resolve_fragment(child, operation_type, next_resolving)
            if resolved is None:
                return None
            fields.update(resolved)
        return fields

    depth = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "{":
            depth += 1
            index += 1
            continue
        if token == "}":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth != 0 or token not in {"query", "mutation", "subscription"}:
            index += 1
            continue
        operation_type = token
        if index + 1 >= len(tokens) or re.fullmatch(_GRAPHQL_NAME, tokens[index + 1]) is None:
            index += 1
            continue
        opening = index + 2
        paren_depth = 0
        bracket_depth = 0
        while opening < len(tokens):
            current = tokens[opening]
            if current == "(":
                paren_depth += 1
            elif current == ")":
                paren_depth -= 1
                if paren_depth < 0:
                    break
            elif current == "[":
                bracket_depth += 1
            elif current == "]":
                bracket_depth -= 1
                if bracket_depth < 0:
                    break
            elif current == "{" and paren_depth == 0 and bracket_depth == 0:
                break
            elif current in {"query", "mutation", "subscription", "fragment", "type", "schema"} \
                    and paren_depth == 0 and bracket_depth == 0:
                break
            opening += 1
        if opening >= len(tokens) or tokens[opening] != "{" or paren_depth or bracket_depth:
            index += 1
            continue
        closing = _matching_graphql_token_brace(tokens, opening)
        if closing is None:
            index += 1
            continue
        selections = _graphql_root_selections(tokens[opening + 1:closing])
        if selections is not None:
            fields, spreads = selections
            valid = True
            for spread in spreads:
                resolved = resolve_fragment(spread, operation_type, frozenset())
                if resolved is None:
                    valid = False
                    break
                fields.update(resolved)
            if valid:
                contracts.update((operation_type, field) for field in fields)
        index = closing + 1
    return contracts


def _graphql_persisted_manifest_contracts(source: str) -> set[tuple[str, str]] | None:
    try:
        payload = json.loads(source)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) \
            or set(payload) != {"format", "version", "operations"} \
            or payload.get("format") != "apollo-persisted-query-manifest" \
            or payload.get("version") != 1:
        return None
    operations = payload.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_GRAPHQL_PERSISTED_OPERATIONS:
        return None
    contracts: set[tuple[str, str]] = set()
    operation_ids: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict) \
                or not {"id", "body", "name", "type"}.issubset(operation) \
                or not set(operation).issubset({"id", "body", "name", "type"}):
            return None
        operation_id = operation.get("id")
        body = operation.get("body")
        name = operation.get("name")
        operation_type = operation.get("type")
        if not isinstance(operation_id, str) \
                or re.fullmatch(r"[0-9a-f]{64}", operation_id) is None \
                or operation_id in operation_ids \
                or not isinstance(body, str) \
                or not 1 <= len(body.encode("utf-8")) <= MAX_GRAPHQL_FILE_BYTES \
                or not isinstance(name, str) \
                or re.fullmatch(_GRAPHQL_NAME, name) is None \
                or not isinstance(operation_type, str) \
                or operation_type not in {"query", "mutation", "subscription"}:
            return None
        if hashlib.sha256(body.encode("utf-8")).hexdigest() != operation_id:
            return None
        masked = _mask_graphql_noncode(body)
        if masked is None:
            return None
        headers = _graphql_top_level_headers(_GRAPHQL_TOKEN_RE.findall(masked))
        if headers != [(operation_type, name)]:
            return None
        operation_contracts = _graphql_document_contracts(masked)
        if not operation_contracts \
                or any(contract_type != operation_type for contract_type, _field in operation_contracts):
            return None
        operation_ids.add(operation_id)
        contracts.update(operation_contracts)
    return contracts


def _graphql_files(repo: Path) -> tuple[list[Path], int, bool]:
    files: list[Path] = []
    skipped = 0
    truncated = False
    visited = 0
    stack: list[tuple[Path, int]] = [(repo, 0)]
    while stack and not truncated:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            visited += 1
            if visited > MAX_GRAPHQL_SCAN_ENTRIES:
                truncated = True
                break
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < MAX_GRAPHQL_SCAN_DEPTH and not _skip_dir(entry.name):
                        stack.append((Path(entry.path), depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                name = entry.name.casefold()
                is_manifest = name == GRAPHQL_PERSISTED_MANIFEST
                if Path(name).suffix.casefold() not in GRAPHQL_SUFFIXES and not is_manifest:
                    continue
                size_limit = MAX_GRAPHQL_MANIFEST_BYTES if is_manifest else MAX_GRAPHQL_FILE_BYTES
                if entry.stat(follow_symlinks=False).st_size > size_limit:
                    skipped += 1
                    continue
            except OSError:
                continue
            if len(files) >= MAX_GRAPHQL_FILES_PER_REPO:
                truncated = True
                break
            files.append(Path(entry.path))
    return sorted(files), skipped, truncated


def _graphql_contracts_for_repo(repo: Path) -> tuple[set[tuple[str, str]], set[tuple[str, str]], int, bool]:
    producers: set[tuple[str, str]] = set()
    consumers: set[tuple[str, str]] = set()
    files, skipped, truncated = _graphql_files(repo)
    for path in files:
        is_manifest = path.name.casefold() == GRAPHQL_PERSISTED_MANIFEST
        size_limit = MAX_GRAPHQL_MANIFEST_BYTES if is_manifest else MAX_GRAPHQL_FILE_BYTES
        source = _read_small(path, size_limit)
        if source is None:
            skipped += 1
            continue
        if is_manifest:
            persisted = _graphql_persisted_manifest_contracts(source)
            if persisted is None:
                skipped += 1
            else:
                consumers.update(persisted)
            continue
        masked = _mask_graphql_noncode(source)
        if masked is None:
            skipped += 1
            continue
        declared = _graphql_sdl_contracts(masked)
        if declared is None:
            skipped += 1
            continue
        producers.update(declared)
        consumers.update(_graphql_document_contracts(masked))
    return producers, consumers, skipped, truncated


def audit_graphql_service_graph(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate bounded local SDL roots with literal operations across distinct repositories."""
    producer_rows: dict[tuple[str, str], list[tuple[str, str]]] = {}
    consumer_rows: list[tuple[tuple[str, str], str, str]] = []
    producer_count = 0
    consumer_count = 0
    skipped_files = 0
    files_truncated = False
    for item in items[:HARD_MAX_REPOS]:
        path = item.get("path")
        if not isinstance(path, str):
            continue
        repo = Path(path)
        try:
            if repo.is_symlink() or not repo.is_dir():
                continue
        except OSError:
            continue
        label = str(item.get("rel") or item.get("name") or repo.name)[:160]
        repo_key = str(repo)
        producers, consumers, skipped, truncated = _graphql_contracts_for_repo(repo)
        producer_count += len(producers)
        consumer_count += len(consumers)
        skipped_files += skipped
        files_truncated = files_truncated or truncated
        for contract in producers:
            producer_rows.setdefault(contract, []).append((repo_key, label))
        consumer_rows.extend((contract, repo_key, label) for contract in consumers)

    edges: list[dict[str, str]] = []
    edge_keys: set[tuple[str, str, str, str]] = set()
    ambiguous_producers = 0
    for contract, rows in producer_rows.items():
        if len({repo_key for repo_key, _label in rows}) > 1:
            ambiguous_producers += 1
    for contract, consumer_key, consumer_label in consumer_rows:
        producers = list(dict.fromkeys(producer_rows.get(contract, [])))
        if len(producers) != 1:
            continue
        producer_key, producer_label = producers[0]
        if producer_key == consumer_key:
            continue
        operation_type, root_field = contract
        edge_key = (producer_label, consumer_label, operation_type, root_field)
        if edge_key in edge_keys:
            continue
        edge_keys.add(edge_key)
        if len(edges) < MAX_GRAPHQL_GRAPH_EDGES:
            edges.append({
                "producer_repo": producer_label,
                "consumer_repo": consumer_label,
                "operation_type": operation_type,
                "root_field": root_field,
            })
    edges.sort(key=lambda edge: (
        edge["producer_repo"], edge["consumer_repo"], edge["operation_type"], edge["root_field"],
    ))
    return {
        "format": GRAPHQL_SERVICE_GRAPH_FORMAT,
        "status": "evaluated",
        "producer_operation_count": producer_count,
        "consumer_operation_count": consumer_count,
        "edge_count": len(edge_keys),
        "edges_truncated": len(edge_keys) > len(edges),
        "skipped_file_count": skipped_files,
        "files_truncated": files_truncated,
        "ambiguous_producer_count": ambiguous_producers,
        "edges": edges,
    }


def _literal_auth_issuer(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 240:
        return None
    if (
        any(char in value for char in ("$", "{", "}"))
        or any(char.isspace() for char in value)
        or _looks_like_auth_secret(value)
    ):
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    return value


def _looks_like_auth_secret(value: str) -> bool:
    if _AUTH_SECRET_PREFIX_RE.search(value):
        return True
    parts = value.split(".")
    return len(parts) == 3 and all(len(part) >= 8 for part in parts) and value.startswith("eyJ")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _auth_contracts_for_repo(repo: Path, label: str) -> tuple[list[dict[str, Any]], bool]:
    """Read one bounded literal-only manifest; invalid/partial manifests contribute nothing."""
    manifest = repo / AUTH_CONTRACT_MANIFEST
    try:
        present = manifest.exists() or manifest.is_symlink()
    except OSError:
        present = False
    if not present:
        return [], False
    raw = _read_small(manifest, 64_000)
    if raw is None:
        return [], True
    try:
        document = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (TypeError, ValueError):
        return [], True
    if (
        not isinstance(document, dict)
        or set(document) != {"format", "contracts"}
        or document.get("format") != AUTH_CONTRACT_FORMAT
        or not isinstance(document.get("contracts"), list)
        or not 1 <= len(document["contracts"]) <= MAX_AUTH_CONTRACTS_PER_REPO
    ):
        return [], True

    parsed_contracts: list[dict[str, Any]] = []
    for contract in document["contracts"]:
        if not isinstance(contract, dict) or set(contract) != {"role", "issuer", "audience", "scopes", "tenant"}:
            return [], True
        role = contract.get("role")
        issuer = _literal_auth_issuer(contract.get("issuer"))
        audience = contract.get("audience")
        tenant = contract.get("tenant")
        scopes = contract.get("scopes")
        if (
            role not in {"producer", "consumer"}
            or issuer is None
            or not isinstance(audience, str)
            or _AUTH_VALUE_RE.fullmatch(audience) is None
            or _looks_like_auth_secret(audience)
            or not isinstance(tenant, str)
            or _AUTH_TENANT_RE.fullmatch(tenant) is None
            or _looks_like_auth_secret(tenant)
            or not isinstance(scopes, list)
            or not 1 <= len(scopes) <= 64
            or not all(
                isinstance(scope, str)
                and _AUTH_VALUE_RE.fullmatch(scope)
                and not _looks_like_auth_secret(scope)
                for scope in scopes
            )
            or len(set(scopes)) != len(scopes)
        ):
            return [], True
        parsed_contracts.append({
            "role": role,
            "issuer": issuer,
            "audience": audience,
            "scopes": tuple(sorted(scopes)),
            "tenant": tenant,
            "repo_key": str(repo),
            "repo_label": label[:160],
        })
    return parsed_contracts, False


def audit_auth_contract_graph(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate literal producer/consumer auth expectations across distinct repositories."""
    contracts: list[dict[str, Any]] = []
    skipped_manifests = 0
    for item in items[:HARD_MAX_REPOS]:
        if item.get("status") not in {"succeeded", "skipped"}:
            continue
        path = item.get("path")
        if not isinstance(path, str):
            continue
        repo = Path(path)
        label = str(item.get("rel") or item.get("name") or repo.name)
        parsed, skipped = _auth_contracts_for_repo(repo, label)
        contracts.extend(parsed)
        skipped_manifests += int(skipped)

    producers: dict[tuple[str, str], list[dict[str, Any]]] = {}
    consumers: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for contract in contracts:
        key = (contract["issuer"], contract["audience"])
        target = producers if contract["role"] == "producer" else consumers
        target.setdefault(key, []).append(contract)

    findings: list[dict[str, Any]] = []
    total_findings = 0
    links = 0
    ambiguous = 0
    for key in sorted(set(producers) & set(consumers)):
        producer_set = producers[key]
        consumer_set = consumers[key]
        if len(producer_set) != 1:
            ambiguous += 1
            continue
        producer = producer_set[0]
        producer_scopes = set(producer["scopes"])
        for consumer in sorted(consumer_set, key=lambda row: (row["repo_label"], row["tenant"])):
            if consumer["repo_key"] == producer["repo_key"]:
                continue
            links += 1
            missing_scopes = sorted(set(consumer["scopes"]) - producer_scopes)
            tenant_mismatch = consumer["tenant"] != producer["tenant"]
            if not missing_scopes and not tenant_mismatch:
                continue
            total_findings += 1
            if len(findings) >= MAX_AUTH_GRAPH_FINDINGS:
                continue
            findings.append({
                "rule_id": "SNIPER-BULK-AUTH-01",
                "severity": "high",
                "category": "authorization",
                "title": "Depolar arası kimlik doğrulama sözleşmesi uyumsuz",
                "producer_repo": producer["repo_label"],
                "consumer_repo": consumer["repo_label"],
                "issuer": key[0],
                "audience": key[1],
                "missing_scopes": missing_scopes,
                "producer_tenant": producer["tenant"],
                "consumer_tenant": consumer["tenant"],
            })

    return {
        "format": AUTH_GRAPH_FORMAT,
        "status": "evaluated",
        "manifest": AUTH_CONTRACT_MANIFEST,
        "contract_count": len(contracts),
        "link_count": links,
        "finding_count": total_findings,
        "findings_truncated": total_findings > len(findings),
        "skipped_manifest_count": skipped_manifests,
        "ambiguous_pair_count": ambiguous,
        "findings": findings,
    }


def _empty_edge_graph(graph_format: str, repositories: int, *, review: bool = False,
                      dependency: bool = False) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "repositories": repositories, "nodes": 0, "edges": 0, "truncated": True,
    }
    if review:
        summary["review_edges"] = 0
    if dependency:
        summary["packages_with_drift"] = 0
    return {"format": graph_format, "summary": summary, "nodes": [], "edges": []}


def _edge_graph(builder: Callable[[Any], Any], repositories: list[tuple[str, Path]], graph_format: str,
                *, review: bool = False, dependency: bool = False) -> dict[str, Any]:
    """Bir graph arızasını diğerlerinden yalıtır; hata ayrıntısını/olası sırrı çıktılamaz."""
    try:
        graph = builder(repositories)
        if (
            not isinstance(graph, dict)
            or graph.get("format") != graph_format
            or not isinstance(graph.get("summary"), dict)
            or not isinstance(graph.get("nodes"), list)
            or not isinstance(graph.get("edges"), list)
        ):
            raise ValueError("invalid graph result")
        return graph
    except Exception:  # noqa: BLE001 - bağımsız graph sonucunu fail-closed yalıtır
        return _empty_edge_graph(
            graph_format, len(repositories), review=review, dependency=dependency,
        )


def _empty_auth_contract_graph(reason: str) -> dict[str, Any]:
    return {
        "format": AUTH_GRAPH_FORMAT,
        "status": "not_evaluated",
        "reason": reason,
        "manifest": AUTH_CONTRACT_MANIFEST,
        "contract_count": 0,
        "link_count": 0,
        "finding_count": 0,
        "findings_truncated": False,
        "skipped_manifest_count": 0,
        "ambiguous_pair_count": 0,
        "findings": [],
    }


def _auth_graph(items: list[dict[str, Any]], *, cancelled: bool) -> dict[str, Any]:
    if cancelled:
        return _empty_auth_contract_graph("cancelled")
    try:
        graph = audit_auth_contract_graph(items)
        if not isinstance(graph, dict) or graph.get("format") != AUTH_GRAPH_FORMAT \
                or not isinstance(graph.get("findings"), list):
            raise ValueError("invalid auth graph result")
        return graph
    except Exception:  # noqa: BLE001 - hata/olası sır API sonucuna taşınmaz
        return _empty_auth_contract_graph("analysis_error")


def _empty_graphql_service_graph(reason: str) -> dict[str, Any]:
    return {
        "format": GRAPHQL_SERVICE_GRAPH_FORMAT,
        "status": "not_evaluated",
        "reason": reason,
        "producer_operation_count": 0,
        "consumer_operation_count": 0,
        "edge_count": 0,
        "edges_truncated": False,
        "skipped_file_count": 0,
        "files_truncated": False,
        "ambiguous_producer_count": 0,
        "edges": [],
    }


def _graphql_graph(items: list[dict[str, Any]], *, cancelled: bool) -> dict[str, Any]:
    if cancelled:
        return _empty_graphql_service_graph("cancelled")
    eligible = [item for item in items if item.get("status") in {"succeeded", "skipped"}]
    try:
        graph = audit_graphql_service_graph(eligible)
        if (
            not isinstance(graph, dict)
            or graph.get("format") != GRAPHQL_SERVICE_GRAPH_FORMAT
            or graph.get("status") != "evaluated"
            or not isinstance(graph.get("edges"), list)
        ):
            raise ValueError("invalid GraphQL graph result")
        return graph
    except Exception:  # noqa: BLE001 - hata/olası sır API sonucuna taşınmaz
        return _empty_graphql_service_graph("analysis_error")


def _common_dir(git_dir: Path) -> Path:
    """Worktree'lerde yapılandırma ortak dizindedir (``commondir``)."""
    text = _read_small(git_dir / "commondir", 4096)
    if text and text.strip():
        target = Path(text.strip())
        target = target if target.is_absolute() else git_dir / target
        try:
            if target.is_dir():
                return target.resolve()
        except OSError:
            pass
    return git_dir


_REMOTE_SECTION_RE = re.compile(r'^\s*\[\s*remote\s+"([^"\]]{1,100})"\s*\]\s*$')
_SECTION_RE = re.compile(r"^\s*\[")
_URL_RE = re.compile(r"^\s*url\s*=\s*(.+?)\s*$", re.IGNORECASE)


def remote_urls(config_text: str) -> dict[str, str]:
    """``.git/config`` içinden uzak adlar → adres (yalnız iç kullanım; dışarıya ham adres verilmez)."""
    out: dict[str, str] = {}
    current: str | None = None
    for line in config_text.splitlines()[:5_000]:
        match = _REMOTE_SECTION_RE.match(line)
        if match:
            current = match.group(1)
            continue
        if _SECTION_RE.match(line):
            current = None
            continue
        if current and current not in out:
            url = _URL_RE.match(line)
            if url:
                out[current] = url.group(1).strip().strip('"')
    return out


def derive_remote_name(url: str) -> dict[str, str] | None:
    """Uzak adresten görünen ad: ``{"name": "sahip/depo", "host": "github.com"}``. Kimlik bilgisi, kapı numarası,
    sorgu dizgesi atılır; yerel yol uzaklarında yalnız son dizin adı verilir (sunucu yok)."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        return None
    url = url.strip()
    host = ""
    scheme_match = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*)://(.*)\Z", url, re.DOTALL)
    if scheme_match:
        scheme, rest = scheme_match.group(1).lower(), scheme_match.group(2)
        authority, _sep, path = rest.partition("/")
        authority = authority.rsplit("@", 1)[-1]  # kullanıcı:parola@ ya da belirteç@ atılır
        if authority.startswith("["):
            host = authority[1:].split("]", 1)[0]
        else:
            host = authority.split(":", 1)[0]
        if scheme == "file":
            host = ""
    elif re.match(r"[^/\\\s:]+:", url) and not re.match(r"[A-Za-z]:[\\/]", url):
        # scp biçimi: [kullanıcı@]sunucu:yol
        before, _sep, path = url.partition(":")
        host = before.rsplit("@", 1)[-1]
    else:
        path = url
    path = re.split(r"[?#]", path, 1)[0].replace("\\", "/")
    parts = [part for part in path.split("/") if part and part not in (".", "..")]
    if not parts:
        return None
    last = parts[-1][:-4] if parts[-1].lower().endswith(".git") else parts[-1]
    pieces = ([parts[-2]] if host and len(parts) >= 2 else []) + [last]
    clean = [_NAME_PART_RE.sub("-", piece).strip("-")[:60] for piece in pieces]
    clean = [piece for piece in clean if piece]
    if not clean:
        return None
    host = host.lower()
    return {"name": "/".join(clean), "host": host if _HOST_RE.fullmatch(host) else ""}


def remote_info(repo: Path) -> dict[str, str] | None:
    git_dir = _git_dir(repo)
    if git_dir is None:
        return None
    text = _read_small(_common_dir(git_dir) / "config")
    if not text:
        return None
    urls = remote_urls(text)
    if not urls:
        return None
    remote = "origin" if "origin" in urls else sorted(urls)[0]
    derived = derive_remote_name(urls[remote])
    if not derived:
        return None
    return {**derived, "remote": _NAME_PART_RE.sub("-", remote)[:40]}


def _branch(git_dir: Path) -> str | None:
    text = _read_small(git_dir / "HEAD", 4096)
    if text and text.startswith("ref: refs/heads/"):
        name = text[len("ref: refs/heads/"):].strip()
        return name[:120] if name and "\n" not in name else None
    return None


def repo_head(repo: Path) -> dict[str, Any]:
    """HEAD commit'i, committer tarihi (ISO) ve dal. Commit yoksa ya da git okunamazsa ``git_error``."""
    import changed_scan

    git_dir = _git_dir(repo)
    if git_dir is None:
        return {}
    out: dict[str, Any] = {"branch": _branch(git_dir)}
    try:
        sha = changed_scan._git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}") \
            .decode("ascii", "replace").strip()
    except changed_scan.ChangedScanError as exc:
        message = str(exc)
        out["git_error"] = "depo başka bir kullanıcıya ait" if "başka bir kullanıcıya" in message else "henüz commit yok"
        return out
    if not _SHA_RE.fullmatch(sha):
        out["git_error"] = "HEAD çözülemedi"
        return out
    out["commit"] = sha
    try:
        raw = changed_scan._git(repo, "cat-file", "commit", sha)
    except changed_scan.ChangedScanError:
        return out
    for line in raw.split(b"\n")[:50]:
        if not line:
            break  # başlık bitti; ileti okunmaz
        if line.startswith(b"committer "):
            # Ad/e-posta okunmaz (kişisel veri); yalnız zaman damgası ve dilim.
            match = re.search(rb" (\d{1,12}) ([+-])(\d{2})(\d{2})\Z", line)
            if match:
                offset = dt.timedelta(hours=int(match.group(3)), minutes=int(match.group(4)))
                zone = dt.timezone(offset if match.group(2) == b"+" else -offset)
                when = dt.datetime.fromtimestamp(int(match.group(1)), tz=zone)
                out["committed_at"] = when.isoformat()
            break
    return out


# ---------------------------------------------------------------------------
# Keşif
# ---------------------------------------------------------------------------
def _manifest_names() -> frozenset[str]:
    import monorepo
    import project_analyzer

    return frozenset(project_analyzer.MANIFEST_NAMES) | monorepo.DEPENDENCY_MANIFESTS | {AUTH_CONTRACT_MANIFEST}


def _project_kind(directory: Path, names: set[str]) -> str | None:
    if ".git" in names and _git_dir(directory) is not None:
        return "git"
    folded = {name.casefold() for name in names}
    if folded & MONOREPO_FILES or any(name.endswith(".sln") for name in folded):
        return "monorepo"
    if folded & _manifest_names():
        return "manifest"
    return None


def _skip_dir(name: str) -> bool:
    return name.startswith(".") or name.casefold() in scan_scope.DEFAULT_SKIP_DIRS


def _looks_like_image_tar(path: Path) -> bool:
    """docker save ya da OCI arşivi mi? (yalnız üye adlarına bakılır; içerik açılmaz)"""
    try:
        with tarfile.open(path, "r:") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_IMAGE_TAR_MEMBERS:
                    return False
                if member.name.lstrip("./") in {"manifest.json", "oci-layout"}:
                    return True
    except (OSError, tarfile.TarError, EOFError):
        return False
    return False


def inventory(repo: Path, *, max_entries: int = INVENTORY_ENTRIES, find_images: bool = True) -> dict[str, Any]:
    """Boyut/dosya sayısı tahmini, diller, bildirim dosyaları (derinlik ≤2) ve konteyner imajı adayları."""
    import project_analyzer

    manifests_set = _manifest_names()
    languages: Counter[str] = Counter()
    manifests: list[str] = []
    images: list[str] = []
    files = size = seen = tar_checks = 0
    truncated = False
    stack: list[tuple[Path, int]] = [(repo, 0)]
    while stack and not truncated:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda e: e.name)
        except OSError:
            continue
        if find_images and depth <= 2 and any(e.name == "oci-layout" for e in entries) and directory != repo:
            images.append(str(directory))
        for entry in entries:
            seen += 1
            if seen > max_entries:
                truncated = True
                break
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if not _skip_dir(entry.name):
                        stack.append((Path(entry.path), depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                stat = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            files += 1
            size += stat.st_size
            name = entry.name.casefold()
            language = project_analyzer.LANGUAGES.get(os.path.splitext(name)[1])
            if language is None and project_analyzer._is_containerfile_name(name):  # noqa: SLF001 - ortak kural
                language = "Container"
            if language:
                languages[language] += 1
            if depth <= 2 and name in manifests_set and len(manifests) < 200:
                manifests.append(Path(entry.path).relative_to(repo).as_posix())
            if find_images and depth <= 2 and name.endswith(".tar") and len(images) < MAX_IMAGES_PER_REPO \
                    and tar_checks < 10:
                tar_checks += 1  # arşiv başlıkları okunur; deneme sayısı sınırlı
                if _looks_like_image_tar(Path(entry.path)):
                    images.append(entry.path)
    return {
        "file_count": files, "size_bytes": size, "estimate_truncated": truncated,
        "languages": [{"name": name, "files": count} for name, count in languages.most_common(6)],
        "manifests": manifests[:20], "_manifests_all": manifests, "images": images[:MAX_IMAGES_PER_REPO],
    }


def _monorepo_info(repo: Path, manifests: list[str]) -> dict[str, Any] | None:
    import monorepo

    try:
        found = monorepo.detect(repo, manifests)
    except (OSError, ValueError, RecursionError):
        return None
    if not found:
        return None
    return {"declared": found["declared"], "kinds": found["kinds"], "subprojects": len(found["subprojects"])}


def describe(repo: Path, root: Path, kind: str, *, last: dict[str, Any] | None = None,
             max_repo_bytes: int | None = None) -> dict[str, Any]:
    """Aday depo kartı: ad, yol, uzak addan türetilen ad, son commit, diller, tahmini boyut, son tarama durumu."""
    max_repo_bytes = max_repo_bytes or _env_int("SNIPER_BULK_MAX_REPO_MB", DEFAULT_MAX_REPO_MB, 1, 100_000) * 1_000_000
    stats = inventory(repo)
    head = repo_head(repo) if kind == "git" else {}
    try:
        rel = repo.relative_to(root).as_posix()
    except ValueError:
        rel = repo.name
    item: dict[str, Any] = {
        "name": repo.name, "path": str(repo), "rel": "." if rel in ("", ".") else rel, "kind": kind,
        "remote": remote_info(repo) if kind == "git" else None,
        "commit": head.get("commit"), "committed_at": head.get("committed_at"), "branch": head.get("branch"),
        "git_error": head.get("git_error"),
        **{key: value for key, value in stats.items() if not key.startswith("_")},
        "monorepo": _monorepo_info(repo, stats["_manifests_all"]),
    }
    item["image_count"] = len(item.pop("images"))
    reasons = []
    if stats["size_bytes"] > max_repo_bytes:
        reasons.append("size")
    if stats["file_count"] > scan_scope.DEFAULT_MAX_FILES:
        reasons.append("files")
    item["too_large"] = reasons
    last = last or {}
    item["last_scan"] = {key: last.get(key) for key in ("last_commit", "last_scanned_at", "last_status", "last_audit_id")} \
        if last else None
    item["unchanged"] = bool(item["commit"] and last.get("last_commit") == item["commit"] and last.get("last_status") == "succeeded")
    item["selected"] = not reasons
    return item


def discover(root_value: str, *, max_depth: int = DEFAULT_MAX_DEPTH, max_repos: int = DEFAULT_MAX_REPOS,
             allowed_roots: tuple[Path, ...] | None = None, max_repo_bytes: int | None = None,
             deadline_seconds: float = DISCOVERY_SECONDS, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Kök altındaki depo/proje adaylarını bul (önizleme). Dosya yazılmaz, ağ kullanılmaz."""
    import project_analyzer

    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 0 <= max_depth <= HARD_MAX_DEPTH:
        raise BulkScanError(f"max_depth 0–{HARD_MAX_DEPTH} arası tam sayı olmalı.")
    if not isinstance(max_repos, int) or isinstance(max_repos, bool) or not 1 <= max_repos <= HARD_MAX_REPOS:
        raise BulkScanError(f"max_repos 1–{HARD_MAX_REPOS} arası tam sayı olmalı.")
    root = project_analyzer.validate_project_path(root_value, allowed_roots)
    started = time.monotonic()
    repos_state = load_state(environ).get("repos", {})
    candidates: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    truncated: list[str] = []
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    visited = 0
    while queue:
        if visited >= MAX_DIRS_VISITED:
            truncated.append("dirs")
            break
        if time.monotonic() - started > deadline_seconds:
            truncated.append("time")
            break
        directory, depth = queue.popleft()
        visited += 1
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda e: e.name)
        except OSError:
            skipped["unreadable"] += 1
            continue
        names = {entry.name for entry in entries}
        kind = _project_kind(directory, names)
        if kind:
            if len(candidates) >= max_repos:
                truncated.append("count")
                break
            candidates.append(describe(directory, root, kind, last=repos_state.get(str(directory)),
                                       max_repo_bytes=max_repo_bytes))
            continue  # depo bir bütün olarak taranır; içine inilmez
        for entry in entries:
            try:
                if entry.is_symlink():
                    if entry.is_dir():
                        skipped["symlink"] += 1
                    continue
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if _skip_dir(entry.name):
                skipped["skip_dir"] += 1
                continue
            if depth + 1 > max_depth:
                skipped["depth"] += 1
                continue
            queue.append((Path(entry.path), depth + 1))
    return {
        "root": str(root), "candidates": candidates, "count": len(candidates),
        "selected_count": sum(1 for c in candidates if c["selected"]),
        "truncated": truncated, "skipped": dict(skipped), "visited_dirs": visited,
        "limits": {"max_depth": max_depth, "max_repos": max_repos, "max_dirs": MAX_DIRS_VISITED,
                   "max_repo_mb": (max_repo_bytes or _env_int("SNIPER_BULK_MAX_REPO_MB", DEFAULT_MAX_REPO_MB, 1, 100_000)
                                   * 1_000_000) // 1_000_000},
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


# ---------------------------------------------------------------------------
# Seçenekler ve doğrulama
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class BulkOptions:
    sca: bool = True
    container: bool = False
    skip_unchanged: bool = True
    changed_files: bool = False
    parallel: int = 1

    @classmethod
    def parse(cls, raw: Any) -> "BulkOptions":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise BulkScanError("options bir JSON nesnesi olmalı.")
        fields = {f.name: f for f in dataclasses.fields(cls)}
        unknown = set(raw) - set(fields)
        if unknown:
            raise BulkScanError("Bilinmeyen seçenek: " + ", ".join(sorted(map(str, unknown))))
        values: dict[str, Any] = {}
        for key, value in raw.items():
            if key == "parallel":
                if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_PARALLEL:
                    raise BulkScanError(f"parallel 1–{MAX_PARALLEL} arası tam sayı olmalı.")
            elif not isinstance(value, bool):
                raise BulkScanError(f"{key} true ya da false olmalı.")
            values[key] = value
        return cls(**values)

    def public(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def validate_group(value: Any, root: Path) -> str:
    if value in (None, ""):
        return (root.name or "kök")[:60]
    if not isinstance(value, str) or not _GROUP_RE.fullmatch(value.strip()):
        raise BulkScanError("Grup adı en çok 60 karakter; harf, rakam ve sınırlı noktalama.")
    return value.strip()


def validate_selection(root_value: str, paths: Any, *, allowed_roots: tuple[Path, ...] | None = None) -> tuple[Path, list[Path]]:
    """Kök ve seçilen depo yolları: hepsi kök altında (ya da kökün kendisi), var olan dizin, izinli kökler içinde."""
    import project_analyzer

    root = project_analyzer.validate_project_path(root_value, allowed_roots)
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
        raise BulkScanError("paths en az bir depo yolu içeren liste olmalı.")
    if len(paths) > HARD_MAX_REPOS:
        raise BulkScanError(f"Tek seferde en çok {HARD_MAX_REPOS} depo taranabilir.")
    out: list[Path] = []
    for value in paths:
        repo = project_analyzer.validate_project_path(value, allowed_roots)
        if repo != root and root not in repo.parents:
            raise BulkScanError("Seçilen depo kök dizinin altında değil.")
        if repo not in out:
            out.append(repo)
    return root, out


# ---------------------------------------------------------------------------
# Durum dosyası
# ---------------------------------------------------------------------------
def _default_state() -> dict[str, Any]:
    return {"runs": [], "repos": {}, "groups": {}}


def _normalize(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        data = _default_state()
    for key, kind in (("runs", list), ("repos", dict), ("groups", dict)):
        if not isinstance(data.get(key), kind):
            data[key] = kind()
    return data


def load_state(environ: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        return _normalize(ops_files.read_json(STATE_FILE, _default_state, environ))
    except ops_files.OpsStoreError:
        return _default_state()


def _update(change: Callable[[dict[str, Any]], Any], environ: dict[str, str] | None = None) -> dict[str, Any]:
    return ops_files.update_json(STATE_FILE, _default_state, lambda data: change(_normalize(data)), environ)


def create_run(root: Path, repos: list[Path], *, group: str, options: BulkOptions, actor: str | None = None,
               trigger: str = "manual", environ: dict[str, str] | None = None) -> dict[str, Any]:
    run = {
        "id": "blk_" + secrets.token_hex(6), "root": str(root), "group": group, "created_at": _now(),
        "status": "queued", "trigger": trigger, "actor": (str(actor)[:80] if actor else None), "job_id": None,
        "options": options.public(),
        "items": [{"name": repo.name, "path": str(repo),
                   "rel": "." if repo == root else repo.relative_to(root).as_posix(), "status": "pending"}
                  for repo in repos],
    }

    def change(data: dict[str, Any]) -> None:
        data["runs"] = [run] + [r for r in data["runs"] if isinstance(r, dict)][: MAX_RUNS - 1]
        entry = data["groups"].get(group) if isinstance(data["groups"].get(group), dict) else {}
        paths = list(dict.fromkeys([str(repo) for repo in repos] + [p for p in entry.get("paths", []) if isinstance(p, str)]))
        data["groups"][group] = {"root": str(root), "paths": paths[:MAX_GROUP_PATHS], "updated_at": _now()}

    _update(change, environ)
    return run


def _patch_run(run_id: str, change: Callable[[dict[str, Any]], None], environ: dict[str, str] | None = None) -> None:
    def apply(data: dict[str, Any]) -> None:
        for run in data["runs"]:
            if isinstance(run, dict) and run.get("id") == run_id:
                change(run)
                return

    _update(apply, environ)


def discard_run(run_id: str, environ: dict[str, str] | None = None) -> None:
    """Kuyruğa alınamayan (kuyruk dolu / aynı kökte etkin iş) çalıştırma kaydını sil."""
    _update(lambda data: data.update(runs=[r for r in data["runs"] if not (isinstance(r, dict) and r.get("id") == run_id)]),
            environ)


def attach_job(run_id: str, job_id: str, environ: dict[str, str] | None = None) -> None:
    _patch_run(run_id, lambda run: run.update(job_id=job_id), environ)


def get_run(run_id: str, environ: dict[str, str] | None = None) -> dict[str, Any] | None:
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        return None
    for run in load_state(environ)["runs"]:
        if isinstance(run, dict) and run.get("id") == run_id:
            return run
    return None


def _totals(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(item.get("status", "pending") for item in items)
    severity: Counter[str] = Counter()
    sca = 0
    for item in items:
        severity.update({k: int(v) for k, v in (item.get("severity_counts") or {}).items() if isinstance(v, int)})
        sca += int((item.get("sca") or {}).get("finding_count") or 0)
    return {"total": len(items), **{state: counts.get(state, 0) for state in
                                   ("pending", "running", "succeeded", "skipped", "failed", "cancelled")},
            "severity_counts": dict(severity), "sca_findings": sca}


def public_run(run: dict[str, Any], job_state: str | None = None) -> dict[str, Any]:
    """API görünümü; iş artık etkin değilse (yeniden başlatma) yarıda kalan çalıştırma 'interrupted' görünür."""
    out = dict(run)
    out["totals"] = _totals(run.get("items") or [])
    if out.get("status") in {"queued", "running"} and job_state not in {"queued", "running"}:
        out["status"] = "interrupted" if job_state in (None, "interrupted", "failed", "expired") else job_state
    return out


def list_runs(environ: dict[str, str] | None = None) -> list[dict[str, Any]]:
    out = []
    for run in load_state(environ)["runs"]:
        if isinstance(run, dict):
            summary = {key: run.get(key) for key in ("id", "root", "group", "created_at", "finished_at", "status",
                                                      "trigger", "job_id", "options")}
            summary["totals"] = _totals(run.get("items") or [])
            auth_graph = run.get("auth_contract_graph")
            if isinstance(auth_graph, dict):
                summary["auth_contract_graph"] = {
                    key: auth_graph.get(key) for key in
                    ("format", "status", "contract_count", "link_count", "finding_count",
                     "skipped_manifest_count", "ambiguous_pair_count")
                }
            graphql_graph = run.get("graphql_service_graph")
            if isinstance(graphql_graph, dict):
                summary["graphql_service_graph"] = {
                    key: graphql_graph.get(key) for key in (
                        "format", "status", "producer_operation_count", "consumer_operation_count", "edge_count",
                        "skipped_file_count", "ambiguous_producer_count",
                    )
                }
            runtime_trace = run.get("runtime_service_trace")
            if isinstance(runtime_trace, dict):
                summary["runtime_service_trace"] = {
                    key: runtime_trace.get(key) for key in (
                        "format", "status", "accepted_manifest_count", "rejected_manifest_count",
                        "observation_count", "matched_edge_count", "unmatched_observation_count", "truncated",
                    )
                }
            for graph_key in ("service_graph", "webhook_graph", "message_graph", "dependency_lineage"):
                graph = run.get(graph_key)
                if isinstance(graph, dict) and isinstance(graph.get("summary"), dict):
                    summary[graph_key] = dict(graph["summary"])
            out.append(summary)
    return out


def groups(environ: dict[str, str] | None = None) -> list[dict[str, Any]]:
    data = load_state(environ)["groups"]
    return [{"name": name, "root": entry.get("root"), "project_count": len(entry.get("paths") or []),
             "updated_at": entry.get("updated_at")}
            for name, entry in sorted(data.items()) if isinstance(entry, dict)]


def group_paths(name: str, environ: dict[str, str] | None = None) -> set[str] | None:
    entry = load_state(environ)["groups"].get(name)
    if not isinstance(entry, dict):
        return None
    return {p for p in entry.get("paths") or [] if isinstance(p, str)}


def project_filter(*, group: str | None = None, root: str | None = None,
                   environ: dict[str, str] | None = None) -> Callable[[str], bool] | None:
    """Portföy süzgeci: grup üyeleri ve/veya kök dizin altındaki projeler (ikisi verilirse kesişim)."""
    if not group and not root:
        return None
    members = group_paths(group, environ) if group else None
    if group and members is None:
        members = set()
    prefix = root.rstrip("/") if root else None

    def keep(path: str) -> bool:
        if members is not None and path not in members:
            return False
        if prefix is not None and not (path == prefix or path.startswith(prefix + "/")):
            return False
        return True

    return keep


# ---------------------------------------------------------------------------
# Tarama yürütücüsü (iş kuyruğundaki tek iş)
# ---------------------------------------------------------------------------
RunRoute = Callable[[str, dict[str, Any]], tuple[int, Any]]


def _error_text(body: Any, status: int) -> str:
    message = body.get("error") if isinstance(body, dict) else None
    return str(message)[:300] if isinstance(message, str) and message else f"Rota {status} durum koduyla döndü."


def _audit_summary(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    findings = body.get("findings")
    if isinstance(findings, list):
        severity = Counter(str(f.get("severity") or "info") for f in findings if isinstance(f, dict))
        count = len(findings)
    else:
        severity = Counter({k: int(v) for k, v in (body.get("severity_counts") or {}).items() if isinstance(v, int)})
        count = int(body.get("finding_count") or sum(severity.values()))
    return {"audit_id": body.get("id"), "project_name": body.get("project_name"), "score": body.get("score"),
            "grade": body.get("grade"), "finding_count": count, "severity_counts": dict(severity),
            "changed_files": len(((body.get("changed_scan") or {}).get("changed_files")) or [])
            if isinstance(body.get("changed_scan"), dict) else None}


def _sca(run_route: RunRoute, path: str) -> dict[str, Any]:
    status, body = run_route("/api/dependency-security/offline-scan", {"confirm_local": True, "project_path": path})
    if status in (200, 201) and isinstance(body, dict):
        priority = body.get("priority") if isinstance(body.get("priority"), dict) else {}
        return {"status": "succeeded", "finding_count": int(body.get("finding_count") or 0),
                "component_count": int(body.get("component_count") or 0),
                "fix_first": int(priority.get("fix_first") or 0) if isinstance(priority.get("fix_first"), int) else 0}
    if status == 503:
        return {"status": "unavailable", "error": _error_text(body, status)}
    return {"status": "failed", "error": _error_text(body, status)}


def _images(run_route: RunRoute, repo: Path) -> list[dict[str, Any]]:
    out = []
    for image in inventory(repo, max_entries=5_000)["images"]:
        status, body = run_route("/api/container-images", {"image_path": image})
        rel = Path(image).relative_to(repo).as_posix() if Path(image).is_relative_to(repo) else Path(image).name
        if status in (200, 201) and isinstance(body, dict):
            out.append({"path": rel, "status": "succeeded", "audit_id": body.get("id"),
                        "finding_count": len(body.get("findings") or [])})
        else:
            out.append({"path": rel, "status": "failed", "error": _error_text(body, status)})
    return out


def scan_repo(item: dict[str, Any], options: BulkOptions, run_route: RunRoute, last: dict[str, Any],
              *, cancelled: Callable[[], bool] = lambda: False) -> dict[str, Any]:
    """Tek depo: (değişmediyse atla) → proje analizi → çevrimdışı SCA → isteğe bağlı konteyner imajları."""
    repo = Path(item["path"])
    try:
        if repo.is_symlink() or not repo.is_dir():
            return {"status": "failed", "error": "Depo dizini bulunamadı."}
        head = repo_head(repo)
        commit = head.get("commit")
        if options.skip_unchanged and commit and last.get("last_commit") == commit and last.get("last_status") == "succeeded":
            return {"status": "skipped", "reason": "unchanged", "commit": commit, "audit_id": last.get("last_audit_id")}
        payload: dict[str, Any] = {"project_path": str(repo)}
        mode = "full"
        base = last.get("last_commit")
        if options.changed_files and commit and isinstance(base, str) and _SHA_RE.fullmatch(base) and base != commit \
                and last.get("last_status") == "succeeded":
            payload["scope"] = {"changed_only": True, "base_ref": base}
            mode = "changed"
        status, body = run_route("/api/project-audits", payload)
        if mode == "changed" and status == 400 and not cancelled():
            # Taban commit artık yok (geçmiş yeniden yazılmış / sığ klon): tam analize düş.
            mode = "full"
            status, body = run_route("/api/project-audits", {"project_path": str(repo)})
        if status not in (200, 201):
            return {"status": "failed", "commit": commit, "error": _error_text(body, status)}
        out: dict[str, Any] = {"status": "succeeded", "commit": commit, "committed_at": head.get("committed_at"),
                               "mode": mode, **_audit_summary(body)}
        if options.sca and not cancelled():
            out["sca"] = _sca(run_route, str(repo))
        if options.container and not cancelled():
            out["images"] = _images(run_route, repo)
        return out
    except Exception as exc:  # noqa: BLE001 - bir deponun hatası diğerlerini durdurmaz
        if cancelled():
            return {"status": "cancelled"}
        # RuntimeError: iş sürecinin kendi iletisi ("iş süreci başarısız oldu"); yol/sır içermez.
        known = isinstance(exc, (BulkScanError, OSError, ValueError, RuntimeError))
        return {"status": "failed", "error": str(exc)[:300] if known and not isinstance(exc, OSError)
                else f"Depo taranamadı ({type(exc).__name__})."}


def execute(run_id: str, run_route: RunRoute, *, job: Any = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Çalıştırmadaki depoları tara. ``job`` (job_queue.Job) iptal/ilerleme/alt süreç takibi içindir."""
    import job_queue

    run = get_run(run_id, environ)
    if run is None:
        raise BulkScanError("Toplu tarama kaydı bulunamadı.")
    options = BulkOptions.parse(run.get("options"))
    items = [dict(item) for item in run.get("items") or []]
    repos_state = load_state(environ)["repos"]
    total = len(items)
    lock = threading.Lock()
    pending: deque[dict[str, Any]] = deque(items)
    done = [0]

    def cancelled() -> bool:
        return bool(job is not None and (getattr(job, "cancel_requested", False) or getattr(job, "expired", False)))

    def progress(detail: str = "") -> None:
        if job is None:
            return
        percent = round(100.0 * done[0] / total, 1) if total else 100.0
        data = {"stage": "bulk", "label": "Toplu depo taraması", "percent": percent, "done": done[0], "total": total}
        if detail:
            data["detail"] = detail[:200]
        job.set_progress(data)

    def save_item(path: str, changes: dict[str, Any], finished: bool) -> None:
        def change(data: dict[str, Any]) -> None:
            for stored_run in data["runs"]:
                if isinstance(stored_run, dict) and stored_run.get("id") == run_id:
                    for stored in stored_run.get("items") or []:
                        if stored.get("path") == path:
                            stored.update(changes)
            if finished and changes.get("status") == "succeeded":
                data["repos"][path] = {"last_commit": changes.get("commit"), "last_scanned_at": changes.get("finished_at"),
                                       "last_status": "succeeded", "last_audit_id": changes.get("audit_id"),
                                       "last_run_id": run_id}
            elif finished and changes.get("status") == "failed":
                entry = data["repos"].get(path) if isinstance(data["repos"].get(path), dict) else {}
                data["repos"][path] = {**entry, "last_failed_at": changes.get("finished_at"), "last_run_id": run_id}

        try:
            _update(change, environ)
        except ops_files.OpsStoreError:
            pass  # durum dosyası yazılamazsa tarama sürer (sonuç iş kaydında)

    bind = job is not None and hasattr(job, "_track")

    def worker() -> None:
        if bind:
            job_queue._CURRENT.job = job  # noqa: SLF001 - alt süreçler işe bağlanır (iptal/süre aşımı durdurur)
        try:
            while True:
                with lock:
                    if not pending or cancelled():
                        return
                    item = pending.popleft()
                started = _now()
                item.update(status="running", started_at=started)
                save_item(item["path"], {"status": "running", "started_at": started}, False)
                with lock:
                    progress(item["name"])
                outcome = scan_repo(item, options, run_route, repos_state.get(item["path"]) or {}, cancelled=cancelled)
                if cancelled() and outcome.get("status") == "failed":
                    outcome = {"status": "cancelled"}
                outcome["finished_at"] = _now()
                item.update(outcome)
                save_item(item["path"], outcome, True)
                with lock:
                    done[0] += 1
                    progress(item["name"])
        finally:
            if bind:
                job_queue._CURRENT.job = None  # noqa: SLF001

    _patch_run(run_id, lambda r: r.update(status="running", started_at=_now()), environ)
    progress()
    threads = [threading.Thread(target=worker, name=f"sniper-bulk-{index}", daemon=True)
               for index in range(max(1, min(options.parallel, total or 1)))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for item in items:
        if item.get("status") in {"pending", "running"}:
            item["status"] = "cancelled"
            save_item(item["path"], {"status": "cancelled"}, False)
    final = "cancelled" if cancelled() else "succeeded"
    totals = _totals(items)
    if final == "succeeded" and totals["failed"] and not (totals["succeeded"] or totals["skipped"]):
        final = "failed"
    graph_repositories = [
        (str(item.get("rel") or item.get("name") or "repository"), Path(item["path"]))
        for item in items
        if item.get("status") in {"succeeded", "skipped"} and isinstance(item.get("path"), str)
    ]
    service_graph = _edge_graph(
        service_trust_graph.build, graph_repositories, service_trust_graph.FORMAT,
    )
    webhook_graph = _edge_graph(
        webhook_trust_graph.build, graph_repositories, webhook_trust_graph.FORMAT, review=True,
    )
    message_graph = _edge_graph(
        message_trust_graph.build, graph_repositories, message_trust_graph.FORMAT,
    )
    dependency_lineage = _edge_graph(
        dependency_lineage_graph.build, graph_repositories, dependency_lineage_graph.FORMAT, dependency=True,
    )
    auth_contract_graph = _auth_graph(items, cancelled=final == "cancelled")
    graphql_service_graph = _graphql_graph(items, cancelled=final == "cancelled")
    try:
        correlated_graphs, runtime_trace_summary = runtime_service_trace.correlate(
            graph_repositories,
            {
                "service_graph": service_graph,
                "webhook_graph": webhook_graph,
                "message_graph": message_graph,
                "graphql_service_graph": graphql_service_graph,
            },
        )
        service_graph = correlated_graphs["service_graph"]
        webhook_graph = correlated_graphs["webhook_graph"]
        message_graph = correlated_graphs["message_graph"]
        graphql_service_graph = correlated_graphs["graphql_service_graph"]
    except Exception:  # noqa: BLE001 - trace veya olası sır API sonucuna taşınmaz
        runtime_trace_summary = runtime_service_trace.empty_summary("not_evaluated")
    finished = _now()
    _patch_run(
        run_id,
        lambda r: r.update(
            status=final,
            finished_at=finished,
            service_graph=service_graph,
            webhook_graph=webhook_graph,
            message_graph=message_graph,
            auth_contract_graph=auth_contract_graph,
            dependency_lineage=dependency_lineage,
            graphql_service_graph=graphql_service_graph,
            runtime_service_trace=runtime_trace_summary,
        ),
        environ,
    )
    return {"bulk_id": run_id, "status": final, "root": run.get("root"), "group": run.get("group"), "totals": totals,
            "service_graph": service_graph,
            "webhook_graph": webhook_graph,
            "message_graph": message_graph,
            "auth_contract_graph": auth_contract_graph,
            "dependency_lineage": dependency_lineage,
            "graphql_service_graph": graphql_service_graph,
            "runtime_service_trace": runtime_trace_summary,
            "items": [{key: item.get(key) for key in ("name", "status", "audit_id", "finding_count", "error", "reason")}
                      for item in items][:HARD_MAX_REPOS]}
