"""Sıfır Güven (Zero Trust) ağ ve servis ağı (service mesh) yapılandırma denetçisi.

Kubernetes NetworkPolicy / Service, Istio (PeerAuthentication, DestinationRule,
AuthorizationPolicy, Gateway), Linkerd enjeksiyon açıklamaları ve Envoy statik
önyükleme (bootstrap) yapılandırmalarını yalnızca yerel metin olarak inceler.

Kubernetes Gateway API (gateway.networking.k8s.io Gateway / HTTPRoute) dinleyicileri de
denetlenir.

PyYAML kullanılmaz: Kubernetes manifestleri için yeterli, sınırlı ve güvenli bir
YAML alt kümesi okuyucusu (blok eşlemeler/diziler, satır içi skalerler, tırnaklı
dizgeler, tek veya çok satırlı akış listeleri/eşlemeleri, çapa/takma ad (&a / *a) ve
`<<` birleştirme anahtarı, sekme girintisi) içerir. JSON belgeleri de kabul
edilir. Ayrıştırılamayan bir belge için istisna fırlatılmaz; o belgeye satır
tabanlı sezgisel denetim uygulanır. Ağ erişimi, alt süreç veya veritabanı yazımı
yoktur.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Callable

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
MAX_DOCUMENTS = 2_000
_MAX_PARSE_STEPS = 400_000
_MAX_FLOW_DEPTH = 64
_MAX_ALIASES = 10_000
_TAB_SIZE = 8

ZERO_TRUST_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-ZT-01",
    "SNIPER-ZT-02",
    "SNIPER-ZT-03",
    "SNIPER-ZT-04",
    "SNIPER-ZT-05",
    "SNIPER-ZT-06",
]

ZERO_TRUST_EXTENSIONS: set[str] = {".yaml", ".yml", ".json"}

WORKLOAD_KINDS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob", "ReplicaSet"}
)

CLUSTER_SCOPED_KINDS = frozenset(
    {
        "Namespace",
        "ClusterRole",
        "ClusterRoleBinding",
        "CustomResourceDefinition",
        "Node",
        "PersistentVolume",
        "StorageClass",
        "PriorityClass",
        "MutatingWebhookConfiguration",
        "ValidatingWebhookConfiguration",
        "IngressClass",
        "RuntimeClass",
        "APIService",
        "List",
    }
)

OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

INTERNAL_LB_ANNOTATIONS: tuple[str, ...] = (
    "networking.gke.io/load-balancer-type",
    "cloud.google.com/load-balancer-type",
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/aws-load-balancer-scheme",
    "service.beta.kubernetes.io/azure-load-balancer-internal",
    "service.beta.kubernetes.io/oci-load-balancer-internal",
)

LINKERD_SKIP_PORT_ANNOTATIONS: tuple[str, ...] = (
    "config.linkerd.io/skip-inbound-ports",
    "config.linkerd.io/skip-outbound-ports",
)

_LOCAL_UPSTREAM_ADDRESSES = frozenset({"localhost", "::1", "127.0.0.1"})


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


# ---------------------------------------------------------------------------
# Sınırlı YAML alt kümesi okuyucusu
# ---------------------------------------------------------------------------


class _YamlError(ValueError):
    """YAML alt kümesi dışında kalan veya bozuk belge."""


class _YMap(dict):
    """Satır numarası bilgisini taşıyan eşleme."""

    __slots__ = ("line", "key_lines")

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line
        self.key_lines: dict[str, int] = {}


class _YSeq(list):
    """Satır numarası bilgisini taşıyan dizi."""

    __slots__ = ("line",)

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line


_INT_RE = re.compile(r"^[-+]?\d+$")
_FLOAT_RE = re.compile(r"^[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?$")
_DOC_SEPARATOR_RE = re.compile(r"^(---|\.\.\.)(\s.*)?$")
_BLOCK_SCALAR_RE = re.compile(r"^[|>][-+0-9]*$")


def _scalar(token: str) -> Any:
    text = token.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "~"}:
        return None
    if _INT_RE.match(text):
        try:
            return int(text)
        except ValueError:
            return text
    if _FLOAT_RE.match(text):
        try:
            return float(text)
        except ValueError:
            return text
    return text


def _find_closing_quote(text: str, start: int) -> int:
    quote = text[start]
    i = start + 1
    length = len(text)
    while i < length:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                if i + 1 < length and text[i + 1] == "'":
                    i += 2
                    continue
                return i
        else:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                return i
        i += 1
    return -1


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1].replace("''", "'")
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        try:
            value = json.loads(token)
            if isinstance(value, str):
                return value
        except ValueError:
            pass
        return token[1:-1]
    return token


class _FlowParser:
    """Tek satırlık YAML akış (flow) koleksiyonlarını ayrıştırır: [a, "b"], {k: v}."""

    def __init__(
        self,
        text: str,
        resolve: Callable[[str], Any] | None = None,
        on_anchor: Callable[[str, Any], None] | None = None,
    ) -> None:
        self.s = text
        self.i = 0
        self.depth = 0
        self.resolve = resolve
        self.on_anchor = on_anchor

    def _ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def parse(self) -> Any:
        value = self._value(",]}")
        self._ws()
        if self.i != len(self.s):
            raise _YamlError("akış koleksiyonu sonrası beklenmeyen içerik")
        return value

    def _value(self, stops: str) -> Any:
        self._ws()
        anchor = ""
        # Özellikler: etiket (!tag) atlanır, çapa (&ad) değerle birlikte kaydedilir.
        while self.i < len(self.s) and self.s[self.i] in "&!":
            start = self.i
            while self.i < len(self.s) and self.s[self.i] not in " \t" + stops:
                self.i += 1
            if self.s[start] == "&":
                anchor = self.s[start + 1 : self.i]
            self._ws()
        value = self._node(stops)
        if anchor and self.on_anchor is not None:
            self.on_anchor(anchor, value)
        return value

    def _node(self, stops: str) -> Any:
        if self.i >= len(self.s) or self.s[self.i] in stops:
            if self.i >= len(self.s):
                raise _YamlError("akış değeri eksik")
            return None
        ch = self.s[self.i]
        if ch == "[":
            return self._seq()
        if ch == "{":
            return self._map()
        if ch in "\"'":
            end = _find_closing_quote(self.s, self.i)
            if end < 0:
                raise _YamlError("kapanmamış tırnak")
            token = self.s[self.i : end + 1]
            self.i = end + 1
            return _unquote(token)
        start = self.i
        while self.i < len(self.s) and self.s[self.i] not in stops:
            self.i += 1
        raw = self.s[start : self.i].strip()
        if raw.startswith("*") and self.resolve is not None:
            return self.resolve(raw[1:])
        return _scalar(raw)

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > _MAX_FLOW_DEPTH:
            raise _YamlError("akış iç içe geçme sınırı aşıldı")

    def _seq(self) -> list[Any]:
        self._enter()
        self.i += 1
        out: list[Any] = []
        self._ws()
        if self.i < len(self.s) and self.s[self.i] == "]":
            self.i += 1
            self.depth -= 1
            return out
        while True:
            out.append(self._value(",]"))
            self._ws()
            if self.i >= len(self.s):
                raise _YamlError("kapanmamış akış dizisi")
            if self.s[self.i] == ",":
                self.i += 1
                self._ws()
                if self.i < len(self.s) and self.s[self.i] == "]":
                    self.i += 1
                    break
                continue
            if self.s[self.i] == "]":
                self.i += 1
                break
            raise _YamlError("akış dizisinde beklenmeyen karakter")
        self.depth -= 1
        return out

    def _key(self) -> str:
        self._ws()
        if self.i >= len(self.s):
            raise _YamlError("akış anahtarı eksik")
        if self.s[self.i] in "\"'":
            end = _find_closing_quote(self.s, self.i)
            if end < 0:
                raise _YamlError("kapanmamış tırnak")
            token = self.s[self.i : end + 1]
            self.i = end + 1
            return _unquote(token)
        start = self.i
        while self.i < len(self.s) and self.s[self.i] not in ":,}":
            self.i += 1
        return self.s[start : self.i].strip()

    def _map(self) -> dict[str, Any]:
        self._enter()
        self.i += 1
        out: dict[str, Any] = {}
        self._ws()
        if self.i < len(self.s) and self.s[self.i] == "}":
            self.i += 1
            self.depth -= 1
            return out
        while True:
            key = self._key()
            self._ws()
            value: Any = None
            if self.i < len(self.s) and self.s[self.i] == ":":
                self.i += 1
                value = self._value(",}")
            out[str(key)] = value
            self._ws()
            if self.i >= len(self.s):
                raise _YamlError("kapanmamış akış eşlemesi")
            if self.s[self.i] == ",":
                self.i += 1
                self._ws()
                if self.i < len(self.s) and self.s[self.i] == "}":
                    self.i += 1
                    break
                continue
            if self.s[self.i] == "}":
                self.i += 1
                break
            raise _YamlError("akış eşlemesinde beklenmeyen karakter")
        self.depth -= 1
        return out


def _parse_inline(text: str) -> Any:
    token = text.strip()
    # Etiket (!tag) ve çapa (&anchor) öneklerini atla; takma adlar (*alias) dizge kalır.
    while token.startswith(("!", "&")):
        parts = token.split(None, 1)
        token = parts[1] if len(parts) > 1 else ""
    if not token:
        return None
    if token[0] in "[{":
        try:
            return _FlowParser(token).parse()
        except _YamlError:
            return token
    if token[0] in "\"'":
        end = _find_closing_quote(token, 0)
        if end == len(token) - 1:
            return _unquote(token)
        return token
    return _scalar(token)


def _strip_comment(text: str) -> str:
    in_single = False
    in_double = False
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "\\" and in_double:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def _is_seq_item(text: str) -> bool:
    return text == "-" or text.startswith("- ")


def _split_props(text: str) -> tuple[str, str]:
    """Baştaki etiket (!tag) ve çapa (&ad) özelliklerini ayır: (çapa, kalan)."""
    anchor = ""
    body = text.strip()
    while body.startswith(("!", "&")):
        parts = body.split(None, 1)
        if parts[0].startswith("&"):
            anchor = parts[0][1:]
        body = parts[1].strip() if len(parts) > 1 else ""
    return anchor, body


def _flow_balance(text: str) -> int:
    """Tırnak dışındaki açık akış parantezi ([ / {) sayısı."""
    depth = 0
    quote = ""
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                if quote == "'" and i + 1 < length and text[i + 1] == "'":
                    i += 2
                    continue
                quote = ""
        elif ch in "\"'" and (i == 0 or text[i - 1] in " \t[{,:"):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        i += 1
    return depth


def _split_key(text: str) -> tuple[str, str] | None:
    if not text or text[0] in "[{":
        return None
    if text[0] in "\"'":
        end = _find_closing_quote(text, 0)
        if end < 0:
            return None
        after = text[end + 1 :].lstrip(" ")
        if after.startswith(":") and (len(after) == 1 or after[1] in " \t"):
            return _unquote(text[: end + 1]), after[1:].strip()
        return None
    match = re.search(r":(\s|$)", text)
    if not match:
        return None
    key = text[: match.start()].strip()
    if not key or '"' in key or "'" in key:
        return None
    return key, text[match.end() :].strip()


class _MiniYaml:
    """Girinti tabanlı, özyinelemeli blok YAML alt kümesi ayrıştırıcısı."""

    def __init__(self, tokens: list[list[Any]]) -> None:
        # token: [girinti, metin (yorumsuz), satır_no, ham_satır]
        self.lines = tokens
        self.n = len(tokens)
        self.steps = 0
        self.anchors: dict[str, Any] = {}
        self.alias_count = 0

    def _tick(self) -> None:
        self.steps += 1
        if self.steps > _MAX_PARSE_STEPS:
            raise _YamlError("ayrıştırma adım sınırı aşıldı")

    def parse(self) -> Any:
        if not self.lines:
            return None
        value, idx = self._block(0, self.lines[0][0])
        if idx < self.n:
            raise _YamlError(f"beklenmeyen girinti (satır {self.lines[idx][2]})")
        return value

    def _alias(self, name: str) -> Any:
        self.alias_count += 1
        if self.alias_count > _MAX_ALIASES:
            raise _YamlError("takma ad sınırı aşıldı")
        key = name.strip()
        if key not in self.anchors:
            raise _YamlError(f"tanımsız takma ad: *{key}")
        return self.anchors[key]

    def _register(self, anchor: str, value: Any) -> None:
        if anchor:
            self.anchors[anchor] = value

    def _inline(self, text: str) -> Any:
        """Satır içi değer: takma ad, akış koleksiyonu (çapalarıyla) veya skaler."""
        anchor, body = _split_props(text)
        if body.startswith("*"):
            value = self._alias(body[1:])
        elif body[:1] in ("[", "{"):
            try:
                value = _FlowParser(body, self._alias, self._register).parse()
            except _YamlError:
                value = body
        else:
            value = _parse_inline(body)
        self._register(anchor, value)
        return value

    def _join_flow(self, idx: int, text: str, indent: int) -> tuple[str, int]:
        """Birden çok satıra yayılan akış koleksiyonunu tek satırda birleştir."""
        _anchor, body = _split_props(text)
        if body[:1] not in ("[", "{"):
            return text, idx
        depth = _flow_balance(text)
        if depth <= 0:
            return text, idx
        parts = [text]
        while depth > 0 and idx < self.n and self.lines[idx][0] >= indent:
            self._tick()
            parts.append(str(self.lines[idx][1]))
            depth += _flow_balance(str(self.lines[idx][1]))
            idx += 1
        if depth != 0:
            raise _YamlError("kapanmamış çok satırlı akış koleksiyonu")
        return " ".join(parts), idx

    def _block(self, idx: int, indent: int) -> tuple[Any, int]:
        self._tick()
        text = self.lines[idx][1]
        if _is_seq_item(text):
            return self._seq(idx, indent)
        if _split_key(text) is None:
            joined, next_idx = self._join_flow(idx + 1, text, indent)
            return self._inline(joined), next_idx
        return self._mapping(idx, indent)

    def _block_scalar(self, idx: int, indent: int, indicator: str) -> tuple[str, int]:
        collected: list[str] = []
        while idx < self.n and self.lines[idx][0] > indent:
            self._tick()
            collected.append(str(self.lines[idx][3]).strip())
            idx += 1
        joiner = " " if indicator.startswith(">") else "\n"
        return joiner.join(collected), idx

    def _seq(self, idx: int, indent: int) -> tuple[list[Any], int]:
        node = _YSeq(self.lines[idx][2])
        while idx < self.n:
            self._tick()
            ind, text, line_no, raw = self.lines[idx]
            if ind < indent:
                break
            if ind > indent:
                raise _YamlError(f"beklenmeyen girinti (satır {line_no})")
            if not _is_seq_item(text):
                break
            rest = text[1:].lstrip(" ")
            new_indent = ind + (len(text) - len(rest))
            anchor = ""
            if rest.startswith(("&", "!")):
                anchor, rest = _split_props(rest)
            if not rest:
                idx += 1
                if idx < self.n and self.lines[idx][0] > indent:
                    value, idx = self._block(idx, self.lines[idx][0])
                else:
                    value = None
            elif rest.startswith("*"):
                value = self._alias(rest[1:])
                idx += 1
            elif _BLOCK_SCALAR_RE.match(rest):
                value, idx = self._block_scalar(idx + 1, indent, rest)
            elif _is_seq_item(rest) or _split_key(rest) is not None:
                self.lines[idx] = [new_indent, rest, line_no, raw]
                value, idx = self._block(idx, new_indent)
            else:
                joined, idx = self._join_flow(idx + 1, rest, indent)
                value = self._inline(joined)
            self._register(anchor, value)
            node.append(value)
        return node, idx

    def _mapping(self, idx: int, indent: int) -> tuple[dict[str, Any], int]:
        node = _YMap(self.lines[idx][2])
        merges: list[tuple[Any, int]] = []
        while idx < self.n:
            self._tick()
            ind, text, line_no, _raw = self.lines[idx]
            if ind < indent:
                break
            if ind > indent:
                raise _YamlError(f"beklenmeyen girinti (satır {line_no})")
            if _is_seq_item(text):
                break
            pair = _split_key(text)
            if pair is None:
                raise _YamlError(f"eşleme anahtarı bekleniyordu (satır {line_no})")
            key, rest = pair
            idx += 1
            value: Any
            anchor, body = _split_props(rest)
            if body == "":
                if idx < self.n and self.lines[idx][0] > indent:
                    value, idx = self._block(idx, self.lines[idx][0])
                elif idx < self.n and self.lines[idx][0] == indent and _is_seq_item(self.lines[idx][1]):
                    value, idx = self._seq(idx, indent)
                else:
                    value = None
                self._register(anchor, value)
            elif _BLOCK_SCALAR_RE.match(body):
                value, idx = self._block_scalar(idx, indent, body)
                self._register(anchor, value)
            else:
                joined, idx = self._join_flow(idx, rest, indent)
                value = self._inline(joined)
            if key == "<<":
                merges.append((value, line_no))
                continue
            node[key] = value
            node.key_lines[key] = line_no
        # YAML birleştirme anahtarı: açık anahtarlar önceliklidir, kaynaklar sırayla uygulanır.
        for merged, merge_line in merges:
            for source in merged if isinstance(merged, list) else [merged]:
                if not isinstance(source, dict):
                    raise _YamlError(f"birleştirme anahtarı (<<) eşleme bekliyor (satır {merge_line})")
                source_lines = getattr(source, "key_lines", {})
                for merged_key, merged_value in source.items():
                    if merged_key not in node:
                        node[merged_key] = merged_value
                        node.key_lines[merged_key] = source_lines.get(merged_key, merge_line)
        return node, idx


def _tokenize(doc_lines: list[tuple[int, str]]) -> list[list[Any]]:
    tokens: list[list[Any]] = []
    for line_no, raw_line in doc_lines:
        if not tokens and raw_line.lstrip().startswith("%"):
            continue  # YAML yönergeleri (%YAML, %TAG)
        content = _strip_comment(raw_line)
        if not content.strip():
            continue
        body = content.lstrip(" \t")
        # Sekme girintisi (YAML dışı ama yaygın) sabit sekme duraklarıyla boşluğa çevrilir.
        indent = len(content[: len(content) - len(body)].expandtabs(_TAB_SIZE))
        tokens.append([indent, content.strip(), line_no, raw_line])
    return tokens


def _split_yaml_documents(raw_content: str) -> list[tuple[int, list[tuple[int, str]]]]:
    documents: list[tuple[int, list[tuple[int, str]]]] = []
    current: list[tuple[int, str]] = []
    start_line = 1
    for line_no, raw_line in enumerate(raw_content.splitlines(), 1):
        if _DOC_SEPARATOR_RE.match(raw_line.rstrip()):
            if current:
                documents.append((start_line, current))
                if len(documents) >= MAX_DOCUMENTS:
                    return documents
            current = []
            start_line = line_no + 1
            continue
        current.append((line_no, raw_line))
    if current and len(documents) < MAX_DOCUMENTS:
        documents.append((start_line, current))
    return documents


def _expand_document(value: Any) -> list[Any]:
    """`kind: List` sarmalayıcılarını ve üst düzey dizileri tekil belgelere aç."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        items = value.get("items")
        kind = value.get("kind")
        if isinstance(items, list) and isinstance(kind, str) and kind.endswith("List"):
            return [item for item in items if isinstance(item, dict)]
        return [value]
    return []


def _load_documents(raw_content: str) -> list[dict[str, Any]]:
    """Belgeleri yükle; her biri {line, doc, lines, ok} sözlüğüdür."""
    loaded: list[dict[str, Any]] = []
    stripped = raw_content.lstrip()
    if stripped[:1] in {"{", "["}:
        try:
            whole = json.loads(raw_content)
        except ValueError:
            whole = None
        if whole is not None:
            for item in _expand_document(whole)[:MAX_DOCUMENTS]:
                loaded.append({"line": 1, "doc": item, "lines": [], "ok": True})
            return loaded

    for start_line, doc_lines in _split_yaml_documents(raw_content):
        if len(loaded) >= MAX_DOCUMENTS:
            break
        tokens = _tokenize(doc_lines)
        if not tokens:
            continue
        first_line = int(tokens[0][2])
        parsed: Any = None
        ok = False
        doc_text = "\n".join(text for _no, text in doc_lines)
        if doc_text.lstrip()[:1] in {"{", "["}:
            try:
                parsed = json.loads(doc_text)
                ok = True
            except ValueError:
                ok = False
        if not ok:
            try:
                parsed = _MiniYaml(tokens).parse()
                ok = True
            except (_YamlError, RecursionError, IndexError, TypeError):
                ok = False
        if not ok:
            loaded.append({"line": first_line, "doc": None, "lines": doc_lines, "ok": False})
            continue
        for item in _expand_document(parsed):
            if len(loaded) >= MAX_DOCUMENTS:
                break
            loaded.append({"line": first_line, "doc": item, "lines": doc_lines, "ok": True})
    return loaded


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------


def _get(node: Any, *path: str) -> Any:
    current = node
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ln(node: Any, default: int) -> int:
    value = getattr(node, "line", None)
    if isinstance(value, int) and value > 0:
        return value
    return default


def _kln(node: Any, key: str, default: int) -> int:
    key_lines = getattr(node, "key_lines", None)
    if isinstance(key_lines, dict):
        value = key_lines.get(key)
        if isinstance(value, int) and value > 0:
            return value
    return default


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "1"}
    return False


def _upper(value: Any) -> str:
    return str(value).strip().upper() if value is not None else ""


def _make_zt_finding(
    *,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    clean_ev = evidence.strip()[:320]
    reference = (
        "NIST SP 800-207 Zero Trust · CIS Kubernetes Benchmark §5.3 · "
        f"Istio Security Best Practices · {cwe}"
    )
    item = _finding(
        severity,
        "infrastructure",
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, f"{cwe}|{clean_ev[:80]}"),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    return item


class _MeshContext:
    """Dosya(lar) boyunca ad alanı düzeyinde toplu denetim durumunu tutar."""

    def __init__(self) -> None:
        self.kinds: set[str] = set()
        self.namespaces: set[str] = set()
        self.workloads: dict[str, list[tuple[str, int, str, str]]] = {}
        self.deny_ingress: set[str] = set()
        self.deny_egress: set[str] = set()
        self.linkerd_enabled_ns: set[str] = set()
        self.linkerd_disabled: list[tuple[str, str, int, str, str]] = []
        self.documents = 0
        self.heuristic_documents = 0
        # Gateway API: (ns, gateway, dinleyici, port, dosya, satır, aynı Gateway'de HTTPS var mı)
        self.gateway_http_listeners: list[tuple[str, str, str, str, str, int, bool]] = []
        # HTTPRoute RequestRedirect scheme=https hedefleri: (ns, gateway, sectionName veya "*")
        self.https_redirect_targets: set[tuple[str, str, str]] = set()


_AddFn = Callable[[dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Kaynak türüne özgü denetimler
# ---------------------------------------------------------------------------


def _check_network_policy(
    spec: Any, *, name: str, namespace: str, filename: str, line: int, ctx: _MeshContext, add: _AddFn
) -> None:
    spec_d = _as_dict(spec)
    selector = spec_d.get("podSelector")
    selects_all = selector is None or (
        isinstance(selector, dict)
        and not _as_dict(selector.get("matchLabels"))
        and not _as_list(selector.get("matchExpressions"))
    )
    raw_types = spec_d.get("policyTypes")
    if raw_types:
        types = {str(item).strip().lower() for item in _as_list(raw_types)}
    else:
        types = {"ingress"} | ({"egress"} if "egress" in spec_d else set())

    ingress_allow_all = False
    for rule in _as_list(spec_d.get("ingress")):
        rule_line = _ln(rule, line)
        rule_d = _as_dict(rule)
        peers = _as_list(rule_d.get("from"))
        if not peers:
            ingress_allow_all = True
            add(
                _make_zt_finding(
                    severity="medium",
                    title="NetworkPolicy giriş (ingress) kuralı tüm kaynaklara izin veriyor",
                    description=(
                        f"'{namespace}/{name}' NetworkPolicy içindeki giriş kuralında 'from' boş veya eksik; "
                        "seçilen podlara küme içindeki ve dışındaki her kaynaktan trafik kabul edilir."
                    ),
                    evidence=f"NetworkPolicy {namespace}/{name} ingress kuralı: {json.dumps(rule_d, ensure_ascii=False)[:160]}",
                    recommendation="Giriş kuralına açık podSelector / namespaceSelector kaynakları ekleyin; `- {}` ile herkese izin vermeyin.",
                    cwe="CWE-284",
                    control_id="SNIPER-ZT-02",
                    filename=filename,
                    line=rule_line,
                )
            )
            continue
        for peer in peers:
            cidr = _get(peer, "ipBlock", "cidr")
            if str(cidr).strip() in OPEN_CIDRS:
                add(
                    _make_zt_finding(
                        severity="high",
                        title="NetworkPolicy girişte tüm internete (0.0.0.0/0) ipBlock izni veriyor",
                        description=(
                            f"'{namespace}/{name}' NetworkPolicy giriş kuralı {cidr} CIDR bloğuna izin veriyor; "
                            "iş yükü tüm internetten erişilebilir hale gelir."
                        ),
                        evidence=f"NetworkPolicy {namespace}/{name} ingress ipBlock.cidr: {cidr}",
                        recommendation="ipBlock kaynağını yalnızca bilinen yük dengeleyici / ofis CIDR aralıklarıyla sınırlandırın.",
                        cwe="CWE-284",
                        control_id="SNIPER-ZT-02",
                        filename=filename,
                        line=_ln(peer, rule_line),
                    )
                )

    egress_allow_all = False
    for rule in _as_list(spec_d.get("egress")):
        rule_line = _ln(rule, line)
        rule_d = _as_dict(rule)
        peers = _as_list(rule_d.get("to"))
        ports = _as_list(rule_d.get("ports"))
        if not peers and not ports:
            egress_allow_all = True
            add(
                _make_zt_finding(
                    severity="medium",
                    title="NetworkPolicy tüm hedeflere tüm portlarda çıkışa (egress) izin veriyor",
                    description=(
                        f"'{namespace}/{name}' NetworkPolicy çıkış kuralında hedef ve port kısıtı yok; "
                        "ele geçirilmiş bir pod herhangi bir adrese veri sızdırabilir veya yanal hareket edebilir."
                    ),
                    evidence=f"NetworkPolicy {namespace}/{name} egress kuralı: {json.dumps(rule_d, ensure_ascii=False)[:160]}",
                    recommendation="Çıkışı yalnızca gerekli hedeflerle (DNS, bağımlı servisler) ve portlarla sınırlandırın.",
                    cwe="CWE-284",
                    control_id="SNIPER-ZT-02",
                    filename=filename,
                    line=rule_line,
                )
            )
        for peer in peers:
            ip_block = _as_dict(_as_dict(peer).get("ipBlock"))
            cidr = ip_block.get("cidr")
            if str(cidr).strip() in OPEN_CIDRS:
                if not ports and not _as_list(ip_block.get("except")):
                    egress_allow_all = True
                add(
                    _make_zt_finding(
                        severity="medium",
                        title="NetworkPolicy çıkışta tüm internete (0.0.0.0/0) ipBlock izni veriyor",
                        description=(
                            f"'{namespace}/{name}' NetworkPolicy çıkış kuralı {cidr} hedefine izin veriyor; "
                            "veri sızdırma ve komuta-kontrol trafiği engellenmez."
                        ),
                        evidence=f"NetworkPolicy {namespace}/{name} egress ipBlock.cidr: {cidr}",
                        recommendation="Çıkış hedeflerini açık CIDR / FQDN izin listesiyle veya egress gateway üzerinden sınırlandırın.",
                        cwe="CWE-284",
                        control_id="SNIPER-ZT-02",
                        filename=filename,
                        line=_ln(peer, rule_line),
                    )
                )

    if selects_all and "ingress" in types and not ingress_allow_all:
        ctx.deny_ingress.add(namespace)
    if selects_all and "egress" in types and not egress_allow_all:
        ctx.deny_egress.add(namespace)


def _check_peer_authentication(
    spec: Any, *, name: str, namespace: str, filename: str, line: int, add: _AddFn
) -> None:
    spec_d = _as_dict(spec)
    mtls = _as_dict(spec_d.get("mtls"))
    mode = _upper(mtls.get("mode"))
    has_selector = bool(_as_dict(_as_dict(spec_d.get("selector")).get("matchLabels")))
    if has_selector:
        scope_text = "iş yükü seçicisiyle (workload düzeyi)"
    elif namespace == "istio-system":
        scope_text = "mesh genelinde (istio-system kök ad alanı, seçicisiz)"
    else:
        scope_text = f"'{namespace}' ad alanı genelinde (seçicisiz)"
    mode_line = _kln(mtls, "mode", _ln(mtls, line))
    if mode == "DISABLE":
        add(
            _make_zt_finding(
                severity="critical",
                title="Istio PeerAuthentication mTLS devre dışı (DISABLE)",
                description=(
                    f"'{namespace}/{name}' PeerAuthentication karşılıklı TLS'i tamamen kapatıyor; servisler arası "
                    "trafik şifresiz ve kimlik doğrulamasız akar."
                ),
                evidence=f"PeerAuthentication {namespace}/{name} mtls.mode: DISABLE · kapsam: {scope_text}",
                recommendation="mtls.mode değerini STRICT yapın; geçiş gerekiyorsa yalnızca belirli port/iş yükü için sınırlı süreli istisna tanımlayın.",
                cwe="CWE-319",
                control_id="SNIPER-ZT-03",
                filename=filename,
                line=mode_line,
            )
        )
    elif mode == "PERMISSIVE":
        add(
            _make_zt_finding(
                severity="high",
                title="Istio PeerAuthentication mTLS PERMISSIVE modunda",
                description=(
                    f"'{namespace}/{name}' PeerAuthentication düz metin bağlantıları da kabul ediyor; mesh dışındaki "
                    "veya sidecar'sız istemciler kimlik doğrulaması olmadan iş yüklerine ulaşabilir."
                ),
                evidence=f"PeerAuthentication {namespace}/{name} mtls.mode: PERMISSIVE · kapsam: {scope_text}",
                recommendation="Geçiş tamamlandığında mtls.mode: STRICT uygulayın ve mesh genelinde istio-system içinde STRICT varsayılanı tanımlayın.",
                cwe="CWE-319",
                control_id="SNIPER-ZT-03",
                filename=filename,
                line=mode_line,
            )
        )
    port_level = spec_d.get("portLevelMtls")
    if isinstance(port_level, dict):
        for port, cfg in port_level.items():
            port_mode = _upper(_as_dict(cfg).get("mode"))
            port_line = _kln(port_level, str(port), _ln(port_level, line))
            if port_mode == "DISABLE":
                add(
                    _make_zt_finding(
                        severity="high",
                        title="Istio PeerAuthentication port düzeyinde mTLS devre dışı",
                        description=f"'{namespace}/{name}' PeerAuthentication {port} numaralı port için mTLS'i kapatıyor.",
                        evidence=f"PeerAuthentication {namespace}/{name} portLevelMtls[{port}].mode: DISABLE · kapsam: {scope_text}",
                        recommendation="Port düzeyi istisnayı kaldırın veya yalnızca sağlık denetimi gibi zorunlu durumlarla sınırlandırıp belgeleyin.",
                        cwe="CWE-319",
                        control_id="SNIPER-ZT-03",
                        filename=filename,
                        line=port_line,
                    )
                )
            elif port_mode == "PERMISSIVE":
                add(
                    _make_zt_finding(
                        severity="medium",
                        title="Istio PeerAuthentication port düzeyinde mTLS PERMISSIVE",
                        description=f"'{namespace}/{name}' PeerAuthentication {port} numaralı portta düz metin trafiği kabul ediyor.",
                        evidence=f"PeerAuthentication {namespace}/{name} portLevelMtls[{port}].mode: PERMISSIVE · kapsam: {scope_text}",
                        recommendation="Port düzeyinde STRICT mTLS uygulayın.",
                        cwe="CWE-319",
                        control_id="SNIPER-ZT-03",
                        filename=filename,
                        line=port_line,
                    )
                )


def _check_destination_rule(
    spec: Any, *, name: str, namespace: str, filename: str, line: int, add: _AddFn
) -> None:
    spec_d = _as_dict(spec)
    host = str(spec_d.get("host") or "?")
    policies: list[tuple[str, Any]] = []
    traffic_policy = spec_d.get("trafficPolicy")
    policies.append(("trafficPolicy", traffic_policy))
    for idx, pls in enumerate(_as_list(_as_dict(traffic_policy).get("portLevelSettings"))):
        policies.append((f"trafficPolicy.portLevelSettings[{idx}]", pls))
    for subset in _as_list(spec_d.get("subsets")):
        subset_d = _as_dict(subset)
        subset_name = str(subset_d.get("name") or "?")
        subset_tp = subset_d.get("trafficPolicy")
        policies.append((f"subsets[{subset_name}].trafficPolicy", subset_tp))
        for idx, pls in enumerate(_as_list(_as_dict(subset_tp).get("portLevelSettings"))):
            policies.append((f"subsets[{subset_name}].portLevelSettings[{idx}]", pls))

    for label, policy in policies:
        tls_node = _as_dict(policy).get("tls")
        tls = _as_dict(tls_node)
        if not tls:
            continue
        tls_line = _kln(tls, "mode", _ln(tls_node, line))
        mode = _upper(tls.get("mode"))
        if mode == "DISABLE":
            add(
                _make_zt_finding(
                    severity="high",
                    title="Istio DestinationRule TLS devre dışı (DISABLE)",
                    description=(
                        f"'{namespace}/{name}' DestinationRule '{host}' hedefine giden trafikte TLS'i kapatıyor; "
                        "istemci tarafı mTLS devre dışı kalır ve trafik düz metin akar."
                    ),
                    evidence=f"DestinationRule {namespace}/{name} host={host} {label}.tls.mode: DISABLE",
                    recommendation="tls.mode değerini ISTIO_MUTUAL (mesh içi) veya doğrulamalı SIMPLE/MUTUAL (mesh dışı) yapın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=tls_line,
                )
            )
        elif mode == "SIMPLE" and not tls.get("caCertificates") and not tls.get("credentialName"):
            add(
                _make_zt_finding(
                    severity="medium",
                    title="Istio DestinationRule SIMPLE TLS için caCertificates tanımlı değil",
                    description=(
                        f"'{namespace}/{name}' DestinationRule '{host}' hedefine SIMPLE TLS kullanıyor ancak sunucu "
                        "sertifikasını doğrulamak için CA belirtilmemiş; Istio sürümüne/yapılandırmasına bağlı olarak "
                        "sunucu kimliği doğrulanmayabilir (MITM riski)."
                    ),
                    evidence=f"DestinationRule {namespace}/{name} host={host} {label}.tls.mode: SIMPLE (caCertificates/credentialName yok)",
                    recommendation="tls.caCertificates veya credentialName ile güvenilen CA'yı ve gerekiyorsa subjectAltNames/sni değerlerini tanımlayın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=tls_line,
                )
            )
        if _truthy(tls.get("insecureSkipVerify")):
            add(
                _make_zt_finding(
                    severity="high",
                    title="Istio DestinationRule insecureSkipVerify etkin",
                    description=(
                        f"'{namespace}/{name}' DestinationRule '{host}' hedefinin sunucu sertifikası ve ana makine adı "
                        "doğrulamasını atlıyor."
                    ),
                    evidence=f"DestinationRule {namespace}/{name} host={host} {label}.tls.insecureSkipVerify: true",
                    recommendation="insecureSkipVerify ayarını kaldırın ve caCertificates ile doğrulama yapın.",
                    cwe="CWE-295",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=_kln(tls, "insecureSkipVerify", tls_line),
                )
            )


def _check_authorization_policy(
    spec: Any, *, name: str, namespace: str, filename: str, line: int, add: _AddFn
) -> None:
    if spec is None or (isinstance(spec, dict) and not spec):
        return  # Boş spec: tümünü reddet (deny-all) — güvenli varsayılan.
    spec_d = _as_dict(spec)
    action = _upper(spec_d.get("action") or "ALLOW")
    if action != "ALLOW":
        return
    rules = spec_d.get("rules")
    if not isinstance(rules, list):
        return  # Kural yoksa ALLOW politikası seçilen iş yükleri için hiçbir isteğe izin vermez.
    for rule in rules:
        rule_line = _ln(rule, _kln(spec_d, "rules", line))
        rule_d = _as_dict(rule)
        if not rule_d:
            add(
                _make_zt_finding(
                    severity="high",
                    title="Istio AuthorizationPolicy tüm isteklere izin veren boş kural ({}) içeriyor",
                    description=(
                        f"'{namespace}/{name}' ALLOW politikasındaki boş kural, kaynak/işlem/koşul ayırt etmeksizin "
                        "her isteğe izin verir; sıfır güven yetkilendirmesi etkisiz kalır."
                    ),
                    evidence=f"AuthorizationPolicy {namespace}/{name} action: ALLOW rules: - {{}}",
                    recommendation="Boş kuralı kaldırın; from.source.principals, to.operation ve when koşullarıyla en az ayrıcalık tanımlayın.",
                    cwe="CWE-863",
                    control_id="SNIPER-ZT-04",
                    filename=filename,
                    line=rule_line,
                )
            )
            continue
        wildcard_fields: list[str] = []
        for src in _as_list(rule_d.get("from")):
            source = _as_dict(_as_dict(src).get("source"))
            for field in ("principals", "namespaces"):
                values = [str(v).strip() for v in _as_list(source.get(field))]
                if "*" in values and field not in wildcard_fields:
                    wildcard_fields.append(field)
        if wildcard_fields:
            unrestricted = not rule_d.get("to") and not rule_d.get("when")
            scope_note = "to/when kısıtı yok (tüm işlemler)" if unrestricted else "to/when kısıtı mevcut"
            add(
                _make_zt_finding(
                    severity="high",
                    title="Istio AuthorizationPolicy joker (*) kaynak kimliğine izin veriyor",
                    description=(
                        f"'{namespace}/{name}' ALLOW politikası {', '.join(wildcard_fields)} alanında '*' kullanıyor; "
                        "mesh içindeki herhangi bir kimlik/ad alanı iş yüküne erişebilir."
                    ),
                    evidence=(
                        f"AuthorizationPolicy {namespace}/{name} action: ALLOW from.source."
                        f"{'/'.join(wildcard_fields)}: ['*'] · {scope_note}"
                    ),
                    recommendation="Joker yerine açık SPIFFE kimlikleri (cluster.local/ns/<ns>/sa/<sa>) ve gerekli ad alanlarını listeleyin.",
                    cwe="CWE-863",
                    control_id="SNIPER-ZT-04",
                    filename=filename,
                    line=rule_line,
                )
            )


def _check_gateway(spec: Any, *, name: str, namespace: str, filename: str, line: int, add: _AddFn) -> None:
    spec_d = _as_dict(spec)
    for server in _as_list(spec_d.get("servers")):
        server_d = _as_dict(server)
        server_line = _ln(server, line)
        port = _as_dict(server_d.get("port"))
        protocol = _upper(port.get("protocol"))
        tls = _as_dict(server_d.get("tls"))
        hosts = ", ".join(str(h) for h in _as_list(server_d.get("hosts")))[:120] or "?"
        if protocol == "HTTP" and not _truthy(tls.get("httpsRedirect")):
            add(
                _make_zt_finding(
                    severity="medium",
                    title="Istio Gateway düz HTTP sunucusu HTTPS yönlendirmesi olmadan yayında",
                    description=(
                        f"'{namespace}/{name}' Gateway {port.get('number', '?')} portunda HTTP sunuyor ve "
                        "tls.httpsRedirect etkin değil; kimlik bilgileri ve oturum çerezleri düz metin taşınabilir."
                    ),
                    evidence=f"Gateway {namespace}/{name} port.protocol: HTTP hosts: {hosts}",
                    recommendation="HTTP sunucusuna `tls: {httpsRedirect: true}` ekleyin ve HTTPS sunucusu tanımlayın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-05",
                    filename=filename,
                    line=server_line,
                )
            )
        tls_mode = _upper(tls.get("mode"))
        if tls_mode == "PASSTHROUGH":
            add(
                _make_zt_finding(
                    severity="info",
                    title="Istio Gateway TLS PASSTHROUGH modunda",
                    description=(
                        f"'{namespace}/{name}' Gateway TLS'i sonlandırmadan arka uca iletiyor; ağ geçidinde L7 "
                        "yetkilendirme ve denetim uygulanamaz, TLS güvenliği arka uca bağlıdır."
                    ),
                    evidence=f"Gateway {namespace}/{name} tls.mode: PASSTHROUGH hosts: {hosts}",
                    recommendation="Arka uç TLS yapılandırmasının güçlü olduğunu doğrulayın veya SIMPLE/MUTUAL ile ağ geçidinde sonlandırın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-05",
                    filename=filename,
                    line=server_line,
                )
            )
        min_version = _upper(tls.get("minProtocolVersion"))
        if min_version in {"TLSV1_0", "TLSV1_1"}:
            add(
                _make_zt_finding(
                    severity="medium",
                    title="Istio Gateway eski TLS sürümüne (TLS 1.0/1.1) izin veriyor",
                    description=f"'{namespace}/{name}' Gateway minProtocolVersion {min_version}; kullanımdan kaldırılmış protokoller kabul edilir.",
                    evidence=f"Gateway {namespace}/{name} tls.minProtocolVersion: {min_version}",
                    recommendation="minProtocolVersion değerini en az TLSV1_2 (tercihen TLSV1_3) yapın.",
                    cwe="CWE-327",
                    control_id="SNIPER-ZT-05",
                    filename=filename,
                    line=_kln(tls, "minProtocolVersion", server_line),
                )
            )


GATEWAY_API_GROUP = "gateway.networking.k8s.io"


def _is_gateway_api(doc: dict[str, Any]) -> bool:
    return str(doc.get("apiVersion") or "").strip().lower().startswith(GATEWAY_API_GROUP + "/")


def _check_gateway_api(
    spec: Any, *, name: str, namespace: str, filename: str, line: int, ctx: _MeshContext, add: _AddFn
) -> None:
    """Kubernetes Gateway API Gateway dinleyicileri (listeners)."""
    listeners = [_as_dict(item) for item in _as_list(_as_dict(spec).get("listeners"))]
    has_tls_listener = any(_upper(item.get("protocol")) in {"HTTPS", "TLS"} for item in listeners)
    for raw_listener, listener in zip(_as_list(_as_dict(spec).get("listeners")), listeners):
        listener_line = _ln(raw_listener, line)
        listener_name = str(listener.get("name") or "?")
        protocol = _upper(listener.get("protocol"))
        port = str(listener.get("port") or "?")
        hostname = str(listener.get("hostname") or "*")[:120]
        if protocol == "HTTP":
            ctx.gateway_http_listeners.append(
                (namespace, name, listener_name, port, filename, listener_line, has_tls_listener)
            )
        tls_mode = str(_as_dict(listener.get("tls")).get("mode") or "").strip().lower()
        if protocol == "TLS" and tls_mode == "passthrough":
            add(
                _make_zt_finding(
                    severity="info",
                    title="Gateway API dinleyicisi TLS Passthrough modunda",
                    description=(
                        f"'{namespace}/{name}' Gateway '{listener_name}' dinleyicisi TLS'i sonlandırmadan arka uca "
                        "iletiyor; ağ geçidinde L7 yetkilendirme ve denetim uygulanamaz."
                    ),
                    evidence=f"Gateway {namespace}/{name} listener {listener_name} protocol: TLS tls.mode: Passthrough hostname: {hostname}",
                    recommendation="Arka uç TLS yapılandırmasını doğrulayın veya mümkünse tls.mode: Terminate kullanın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-05",
                    filename=filename,
                    line=listener_line,
                )
            )
        namespaces_from = str(_get(listener, "allowedRoutes", "namespaces", "from") or "").strip()
        if namespaces_from == "All":
            add(
                _make_zt_finding(
                    severity="medium",
                    title="Gateway API dinleyicisi tüm ad alanlarından rota bağlanmasına izin veriyor",
                    description=(
                        f"'{namespace}/{name}' Gateway '{listener_name}' dinleyicisinde allowedRoutes.namespaces.from: All; "
                        "kümedeki herhangi bir ad alanı bu ağ geçidine HTTPRoute bağlayıp trafiği kendi servisine "
                        "yönlendirebilir (en az yetki ve kiracı yalıtımı ihlali)."
                    ),
                    evidence=f"Gateway {namespace}/{name} listener {listener_name} allowedRoutes.namespaces.from: All",
                    recommendation=(
                        "from: Same veya etiket seçicili from: Selector kullanın; paylaşılan ağ geçitlerinde "
                        "rota sahipliğini ReferenceGrant ve ad alanı etiketleriyle sınırlandırın."
                    ),
                    cwe="CWE-284",
                    control_id="SNIPER-ZT-05",
                    filename=filename,
                    line=listener_line,
                )
            )


def _record_http_route(doc: dict[str, Any], *, namespace: str, ctx: _MeshContext) -> None:
    """HTTPRoute'taki HTTPS'e RequestRedirect kurallarını bağlı Gateway dinleyicileriyle eşle."""
    spec = _as_dict(doc.get("spec"))
    redirects_to_https = False
    for rule in _as_list(spec.get("rules")):
        for item in _as_list(_as_dict(rule).get("filters")):
            item_d = _as_dict(item)
            if str(item_d.get("type") or "") != "RequestRedirect":
                continue
            if str(_get(item_d, "requestRedirect", "scheme") or "").strip().lower() == "https":
                redirects_to_https = True
    if not redirects_to_https:
        return
    for parent in _as_list(spec.get("parentRefs")):
        parent_d = _as_dict(parent)
        kind = str(parent_d.get("kind") or "Gateway")
        if kind != "Gateway" or not parent_d.get("name"):
            continue
        parent_ns = str(parent_d.get("namespace") or namespace)
        section = str(parent_d.get("sectionName") or "*")
        ctx.https_redirect_targets.add((parent_ns, str(parent_d["name"]), section))


def _check_service(
    spec: Any, meta: dict[str, Any], *, name: str, namespace: str, filename: str, line: int, add: _AddFn
) -> None:
    spec_d = _as_dict(spec)
    service_type = str(spec_d.get("type") or "ClusterIP").strip()
    if service_type not in {"LoadBalancer", "NodePort"}:
        return
    annotations = _as_dict(meta.get("annotations"))
    internal = False
    for key in INTERNAL_LB_ANNOTATIONS:
        if key in annotations and str(annotations[key]).strip().lower() in {"internal", "true"}:
            internal = True
    if "service.beta.kubernetes.io/load-balancer-source-ranges" in annotations:
        internal = True
    ranges = [str(r).strip() for r in _as_list(spec_d.get("loadBalancerSourceRanges"))]
    type_line = _kln(spec_d, "type", line)
    if not ranges and not internal:
        add(
            _make_zt_finding(
                severity="medium",
                title="Kubernetes Service kaynak IP kısıtı olmadan dışa açık",
                description=(
                    f"'{namespace}/{name}' Service türü {service_type} ve loadBalancerSourceRanges tanımlı değil; "
                    "servis tüm ağlardan erişilebilir olabilir."
                ),
                evidence=f"Service {namespace}/{name} spec.type: {service_type} (loadBalancerSourceRanges yok)",
                recommendation="loadBalancerSourceRanges ile izinli CIDR'leri tanımlayın, iç yük dengeleyici kullanın veya Ingress/Gateway arkasına alın.",
                cwe="CWE-284",
                control_id="SNIPER-ZT-06",
                filename=filename,
                line=type_line,
            )
        )
    elif any(r in OPEN_CIDRS for r in ranges):
        add(
            _make_zt_finding(
                severity="medium",
                title="Kubernetes Service loadBalancerSourceRanges tüm interneti kapsıyor",
                description=f"'{namespace}/{name}' Service kaynak aralığı 0.0.0.0/0 veya ::/0 içeriyor; kısıt etkisiz.",
                evidence=f"Service {namespace}/{name} loadBalancerSourceRanges: {', '.join(ranges)[:120]}",
                recommendation="Kaynak aralığını yalnızca gerekli istemci CIDR'leriyle sınırlandırın.",
                cwe="CWE-284",
                control_id="SNIPER-ZT-06",
                filename=filename,
                line=_kln(spec_d, "loadBalancerSourceRanges", type_line),
            )
        )


def _linkerd_skip_port_findings(
    annotations: dict[str, Any], *, owner: str, filename: str, line: int, add: _AddFn
) -> None:
    for key in LINKERD_SKIP_PORT_ANNOTATIONS:
        if key in annotations and str(annotations[key]).strip():
            add(
                _make_zt_finding(
                    severity="low",
                    title="Linkerd mTLS dışı port atlama (skip-ports) yapılandırması",
                    description=(
                        f"{owner} üzerinde {key} tanımlı; bu portlardaki trafik Linkerd proxy'sini atlar ve mTLS / "
                        "kimlik doğrulaması uygulanmaz."
                    ),
                    evidence=f"{owner} {key}: {str(annotations[key])[:80]}",
                    recommendation="Atlanan portları en aza indirin, nedenini belgeleyin ve bu portları NetworkPolicy ile ayrıca kısıtlayın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=_kln(annotations, key, line),
                )
            )


def _workload_annotations(kind: str, doc: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    meta_ann = _as_dict(_get(doc, "metadata", "annotations"))
    merged.update(meta_ann)
    if kind == "CronJob":
        template_ann = _get(doc, "spec", "jobTemplate", "spec", "template", "metadata", "annotations")
    elif kind == "Pod":
        template_ann = None
    else:
        template_ann = _get(doc, "spec", "template", "metadata", "annotations")
    if isinstance(template_ann, dict):
        merged.update(template_ann)
        # Satır bilgisini korumak için şablon eşlemesini döndürmeyi tercih et.
        if getattr(template_ann, "key_lines", None) is not None and not meta_ann:
            return template_ann
    if not template_ann and isinstance(meta_ann, dict) and getattr(meta_ann, "key_lines", None) is not None:
        return meta_ann
    return merged


def _envoy_cluster_addresses(cluster: dict[str, Any]) -> list[str]:
    addresses: list[str] = []
    load_assignment = _as_dict(cluster.get("load_assignment"))
    for endpoint_group in _as_list(load_assignment.get("endpoints")):
        for lb_endpoint in _as_list(_as_dict(endpoint_group).get("lb_endpoints")):
            address = _get(lb_endpoint, "endpoint", "address", "socket_address", "address")
            if address is not None:
                addresses.append(str(address).strip())
    for host in _as_list(cluster.get("hosts")):
        address = _get(host, "socket_address", "address")
        if address is not None:
            addresses.append(str(address).strip())
    return addresses


def _check_envoy(doc: dict[str, Any], *, filename: str, line: int, add: _AddFn) -> None:
    static = _as_dict(doc.get("static_resources"))
    for cluster in _as_list(static.get("clusters")):
        cluster_d = _as_dict(cluster)
        if cluster_d.get("transport_socket") or cluster_d.get("transport_socket_matches"):
            continue
        remote = [
            addr
            for addr in _envoy_cluster_addresses(cluster_d)
            if addr.lower() not in _LOCAL_UPSTREAM_ADDRESSES and not addr.startswith("127.")
        ]
        if not remote:
            continue
        cluster_name = str(cluster_d.get("name") or "?")
        add(
            _make_zt_finding(
                severity="medium",
                title="Envoy upstream kümesi düz metin bağlantı kullanıyor (transport_socket yok)",
                description=(
                    f"Envoy kümesi '{cluster_name}' uzak adrese ({', '.join(remote[:3])}) TLS transport_socket "
                    "olmadan bağlanıyor; servisler arası trafik şifresiz ve karşılıklı kimlik doğrulamasız."
                ),
                evidence=f"Envoy cluster {cluster_name} → {', '.join(remote[:3])} (transport_socket yok)",
                recommendation="Kümeye envoy.transport_sockets.tls (UpstreamTlsContext) ile doğrulamalı TLS/mTLS ekleyin.",
                cwe="CWE-319",
                control_id="SNIPER-ZT-03",
                filename=filename,
                line=_ln(cluster, line),
            )
        )

    for listener in _as_list(static.get("listeners")):
        listener_d = _as_dict(listener)
        filter_names: set[str] = set()
        has_http_manager = False
        chains = list(_as_list(listener_d.get("filter_chains")))
        if isinstance(listener_d.get("default_filter_chain"), dict):
            chains.append(listener_d["default_filter_chain"])
        for chain in chains:
            for network_filter in _as_list(_as_dict(chain).get("filters")):
                nf = _as_dict(network_filter)
                nf_name = str(nf.get("name") or "").lower()
                typed = _as_dict(nf.get("typed_config"))
                filter_names.add(nf_name)
                filter_names.add(str(typed.get("@type") or "").lower())
                if "http_connection_manager" in nf_name or "http_filters" in typed:
                    has_http_manager = True
                for http_filter in _as_list(typed.get("http_filters")):
                    hf = _as_dict(http_filter)
                    filter_names.add(str(hf.get("name") or "").lower())
                    filter_names.add(str(_as_dict(hf.get("typed_config")).get("@type") or "").lower())
        if not has_http_manager:
            continue
        if any("rbac" in n or "ext_authz" in n for n in filter_names):
            continue
        listener_name = str(listener_d.get("name") or "?")
        add(
            _make_zt_finding(
                severity="low",
                title="Envoy dinleyicisinde RBAC / ext_authz yetkilendirme filtresi yok",
                description=(
                    f"Envoy dinleyicisi '{listener_name}' HTTP trafiğini işliyor ancak envoy.filters.http.rbac veya "
                    "ext_authz filtresi tanımlı değil; istek düzeyinde yetkilendirme proxy katmanında uygulanmıyor."
                ),
                evidence=f"Envoy listener {listener_name} http_filters: rbac/ext_authz yok",
                recommendation="HTTP filtre zincirine envoy.filters.http.rbac veya envoy.filters.http.ext_authz ekleyin (router filtresinden önce).",
                cwe="CWE-863",
                control_id="SNIPER-ZT-04",
                filename=filename,
                line=_ln(listener, line),
            )
        )


def _analyze_document(
    doc: Any, *, filename: str, doc_line: int, ctx: _MeshContext, add: _AddFn
) -> None:
    if not isinstance(doc, dict):
        return
    line = _ln(doc, doc_line)
    if "static_resources" in doc:
        ctx.kinds.add("EnvoyBootstrap")
        _check_envoy(doc, filename=filename, line=line, add=add)
        return
    kind_raw = doc.get("kind")
    if not isinstance(kind_raw, str) or not kind_raw.strip():
        return
    kind = kind_raw.strip()
    meta = _as_dict(doc.get("metadata"))
    name = str(meta.get("name") or "<adsız>")
    ns_raw = meta.get("namespace")
    namespace = str(ns_raw).strip() if ns_raw not in (None, "") else "default"
    ctx.kinds.add(kind)
    if kind == "Namespace":
        if meta.get("name"):
            ctx.namespaces.add(name)
    elif kind not in CLUSTER_SCOPED_KINDS:
        ctx.namespaces.add(namespace)
    spec = doc.get("spec")
    kind_line = _kln(doc, "kind", line)

    if kind == "NetworkPolicy":
        _check_network_policy(
            spec, name=name, namespace=namespace, filename=filename, line=kind_line, ctx=ctx, add=add
        )
    elif kind == "PeerAuthentication":
        _check_peer_authentication(spec, name=name, namespace=namespace, filename=filename, line=kind_line, add=add)
    elif kind == "DestinationRule":
        _check_destination_rule(spec, name=name, namespace=namespace, filename=filename, line=kind_line, add=add)
    elif kind == "AuthorizationPolicy":
        _check_authorization_policy(spec, name=name, namespace=namespace, filename=filename, line=kind_line, add=add)
    elif kind == "Gateway" and "istio" in str(doc.get("apiVersion") or "").lower():
        _check_gateway(spec, name=name, namespace=namespace, filename=filename, line=kind_line, add=add)
    elif kind == "Gateway" and _is_gateway_api(doc):
        _check_gateway_api(spec, name=name, namespace=namespace, filename=filename, line=kind_line, ctx=ctx, add=add)
    elif kind == "HTTPRoute" and _is_gateway_api(doc):
        _record_http_route(doc, namespace=namespace, ctx=ctx)
    elif kind == "Service":
        _check_service(spec, meta, name=name, namespace=namespace, filename=filename, line=kind_line, add=add)
    elif kind == "Namespace":
        annotations = _as_dict(meta.get("annotations"))
        if str(annotations.get("linkerd.io/inject") or "").strip().lower() == "enabled":
            ctx.linkerd_enabled_ns.add(name)
        _linkerd_skip_port_findings(
            annotations, owner=f"Namespace {name}", filename=filename, line=kind_line, add=add
        )

    if kind in WORKLOAD_KINDS:
        ctx.workloads.setdefault(namespace, []).append((filename, kind_line, kind, name))
        annotations = _workload_annotations(kind, doc)
        if str(annotations.get("linkerd.io/inject") or "").strip().lower() == "disabled":
            ctx.linkerd_disabled.append(
                (namespace, filename, _kln(annotations, "linkerd.io/inject", kind_line), kind, name)
            )
        _linkerd_skip_port_findings(
            annotations, owner=f"{kind} {namespace}/{name}", filename=filename, line=kind_line, add=add
        )


_HEUR_KIND_RE = re.compile(r"^kind:\s*['\"]?([A-Za-z0-9]+)")
_HEUR_NS_RE = re.compile(r"^\s+namespace:\s*['\"]?([a-z0-9][a-z0-9.-]*)")
_HEUR_MODE_RE = re.compile(r"\bmode:\s*['\"]?(DISABLE|PERMISSIVE)\b")
_HEUR_WILDCARD_FLOW_RE = re.compile(r"\b(principals|namespaces):\s*\[\s*['\"]\*['\"]\s*\]")
_HEUR_WILDCARD_ITEM_RE = re.compile(r"^-\s*['\"]\*['\"]\s*$")
_HEUR_OPEN_CIDR_RE = re.compile(r"\bcidr:\s*['\"]?(0\.0\.0\.0/0|::/0)")


def _heuristic_document(
    doc_lines: list[tuple[int, str]], *, filename: str, doc_line: int, ctx: _MeshContext, add: _AddFn
) -> None:
    """Ayrıştırılamayan belge için satır tabanlı, ihtiyatlı sezgisel denetim."""
    kind = ""
    namespace = "default"
    for _no, raw_line in doc_lines:
        kind_match = _HEUR_KIND_RE.match(raw_line)
        if kind_match and not kind:
            kind = kind_match.group(1)
        ns_match = _HEUR_NS_RE.match(raw_line)
        if ns_match and namespace == "default":
            namespace = ns_match.group(1)
    if kind:
        ctx.kinds.add(kind)
        if kind not in CLUSTER_SCOPED_KINDS:
            ctx.namespaces.add(namespace)
    prefix = "(sezgisel ayrıştırma) "
    last_key = ""
    for line_no, raw_line in doc_lines:
        stripped = _strip_comment(raw_line).strip()
        if not stripped:
            continue
        mode_match = _HEUR_MODE_RE.search(stripped)
        if mode_match and kind == "PeerAuthentication":
            mode = mode_match.group(1)
            add(
                _make_zt_finding(
                    severity="critical" if mode == "DISABLE" else "high",
                    title=(
                        "Istio PeerAuthentication mTLS devre dışı (DISABLE)"
                        if mode == "DISABLE"
                        else "Istio PeerAuthentication mTLS PERMISSIVE modunda"
                    ),
                    description="Ayrıştırılamayan PeerAuthentication belgesinde zayıf mTLS modu tespit edildi.",
                    evidence=f"{prefix}{stripped}",
                    recommendation="mtls.mode değerini STRICT yapın ve manifest sözdizimini düzeltin.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=line_no,
                )
            )
        elif mode_match and kind == "DestinationRule" and mode_match.group(1) == "DISABLE":
            add(
                _make_zt_finding(
                    severity="high",
                    title="Istio DestinationRule TLS devre dışı (DISABLE)",
                    description="Ayrıştırılamayan DestinationRule belgesinde TLS'in kapatıldığı tespit edildi.",
                    evidence=f"{prefix}{stripped}",
                    recommendation="tls.mode değerini ISTIO_MUTUAL veya doğrulamalı SIMPLE/MUTUAL yapın.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=line_no,
                )
            )
        if kind == "AuthorizationPolicy" and (
            _HEUR_WILDCARD_FLOW_RE.search(stripped)
            or (last_key in {"principals", "namespaces"} and _HEUR_WILDCARD_ITEM_RE.match(stripped))
        ):
            add(
                _make_zt_finding(
                    severity="high",
                    title="Istio AuthorizationPolicy joker (*) kaynak kimliğine izin veriyor",
                    description="Ayrıştırılamayan AuthorizationPolicy belgesinde joker kaynak kimliği tespit edildi.",
                    evidence=f"{prefix}{stripped}",
                    recommendation="Joker yerine açık SPIFFE kimliklerini listeleyin.",
                    cwe="CWE-863",
                    control_id="SNIPER-ZT-04",
                    filename=filename,
                    line=line_no,
                )
            )
        if kind == "NetworkPolicy" and _HEUR_OPEN_CIDR_RE.search(stripped):
            add(
                _make_zt_finding(
                    severity="medium",
                    title="NetworkPolicy tüm internete (0.0.0.0/0) ipBlock izni veriyor",
                    description="Ayrıştırılamayan NetworkPolicy belgesinde açık CIDR bloğu tespit edildi (yön belirlenemedi).",
                    evidence=f"{prefix}{stripped}",
                    recommendation="ipBlock aralığını bilinen CIDR'lerle sınırlandırın.",
                    cwe="CWE-284",
                    control_id="SNIPER-ZT-02",
                    filename=filename,
                    line=line_no,
                )
            )
        key_match = re.match(r"^([A-Za-z_][\w.-]*):", stripped)
        if key_match:
            last_key = key_match.group(1)


def _scan_content(raw_content: str, *, filename: str, ctx: _MeshContext, add: _AddFn) -> None:
    for entry in _load_documents(raw_content):
        ctx.documents += 1
        if entry["ok"]:
            _analyze_document(entry["doc"], filename=filename, doc_line=entry["line"], ctx=ctx, add=add)
        else:
            ctx.heuristic_documents += 1
            _heuristic_document(entry["lines"], filename=filename, doc_line=entry["line"], ctx=ctx, add=add)


def _aggregate_findings(ctx: _MeshContext, add: _AddFn) -> None:
    for namespace in sorted(ctx.workloads):
        entries = ctx.workloads[namespace]
        first_file, first_line, _kind, _name = entries[0]
        workload_list = ", ".join(f"{k}/{n}" for _f, _l, k, n in entries[:5])
        if len(entries) > 5:
            workload_list += f" (+{len(entries) - 5})"
        if namespace not in ctx.deny_ingress:
            add(
                _make_zt_finding(
                    severity="medium",
                    title="Ad alanında varsayılan tümünü reddet (default-deny) NetworkPolicy yok",
                    description=(
                        f"'{namespace}' ad alanında iş yükleri var ancak tüm podları seçen (podSelector: {{}}) ve "
                        "Ingress içeren varsayılan reddet NetworkPolicy bulunamadı; doğu-batı trafiği varsayılan "
                        "olarak serbesttir ve yanal hareket kısıtlanmaz."
                    ),
                    evidence=f"namespace={namespace} iş yükleri: {workload_list} · default-deny ingress yok",
                    recommendation=(
                        "Ad alanına `podSelector: {}` ve `policyTypes: [Ingress]` içeren kuralsız bir default-deny "
                        "NetworkPolicy ekleyin; ardından yalnızca gerekli akışlara açık izin verin."
                    ),
                    cwe="CWE-923",
                    control_id="SNIPER-ZT-01",
                    filename=first_file,
                    line=first_line,
                )
            )
        if namespace not in ctx.deny_egress:
            add(
                _make_zt_finding(
                    severity="low",
                    title="Ad alanında varsayılan çıkış (egress) default-deny NetworkPolicy yok",
                    description=(
                        f"'{namespace}' ad alanında tüm podları seçen ve Egress içeren varsayılan reddet "
                        "NetworkPolicy bulunamadı; ele geçirilmiş podlar her hedefe bağlanabilir."
                    ),
                    evidence=f"namespace={namespace} iş yükleri: {workload_list} · default-deny egress yok",
                    recommendation=(
                        "`podSelector: {}` ve `policyTypes: [Egress]` içeren default-deny çıkış politikası ekleyin; "
                        "DNS ve gerekli bağımlılıklara açık izin verin."
                    ),
                    cwe="CWE-923",
                    control_id="SNIPER-ZT-01",
                    filename=first_file,
                    line=first_line,
                )
            )
    for namespace, gateway, listener, port, filename, line, has_tls in ctx.gateway_http_listeners:
        if (
            (namespace, gateway, listener) in ctx.https_redirect_targets
            or (namespace, gateway, "*") in ctx.https_redirect_targets
        ):
            continue
        add(
            _make_zt_finding(
                severity="low" if has_tls else "medium",
                title="Gateway API dinleyicisi düz HTTP sunuyor, HTTPS yönlendirmesi bulunamadı",
                description=(
                    f"'{namespace}/{gateway}' Gateway '{listener}' dinleyicisi {port} portunda HTTP sunuyor ve "
                    "taranan dosyalarda bu dinleyiciye bağlı, scheme: https RequestRedirect içeren bir HTTPRoute "
                    "bulunamadı; kimlik bilgileri ve oturum çerezleri düz metin taşınabilir."
                    + (" Aynı Gateway'de HTTPS/TLS dinleyicisi var." if has_tls else "")
                ),
                evidence=f"Gateway {namespace}/{gateway} listener {listener} protocol: HTTP port: {port}",
                recommendation=(
                    "HTTP dinleyicisine bağlı bir HTTPRoute'ta `filters: [{type: RequestRedirect, requestRedirect: "
                    "{scheme: https, statusCode: 301}}]` tanımlayın ve uygulama trafiğini HTTPS dinleyicisine taşıyın."
                ),
                cwe="CWE-319",
                control_id="SNIPER-ZT-05",
                filename=filename,
                line=line,
            )
        )
    for namespace, filename, line, kind, name in ctx.linkerd_disabled:
        if namespace in ctx.linkerd_enabled_ns:
            add(
                _make_zt_finding(
                    severity="medium",
                    title="Linkerd proxy enjeksiyonu mesh ad alanında devre dışı bırakılmış",
                    description=(
                        f"'{namespace}' ad alanında linkerd.io/inject: enabled olmasına rağmen {kind}/{name} "
                        "iş yükü enjeksiyonu kapatıyor; bu iş yükünün trafiği mTLS ve kimlik doğrulaması dışında kalır."
                    ),
                    evidence=f"{kind} {namespace}/{name} linkerd.io/inject: disabled (namespace: enabled)",
                    recommendation="İstisnayı kaldırın veya iş yükünü ayrı bir ad alanına taşıyıp NetworkPolicy ile izole edin.",
                    cwe="CWE-319",
                    control_id="SNIPER-ZT-03",
                    filename=filename,
                    line=line,
                )
            )


def _collector() -> tuple[list[dict[str, Any]], _AddFn]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int, str]] = set()

    def _add(finding: dict[str, Any]) -> None:
        key = (
            str(finding.get("control_id")),
            str(finding.get("title")),
            str(finding.get("file")),
            int(finding.get("line") or 0),
            str(finding.get("evidence"))[:200],
        )
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    return findings, _add


# ---------------------------------------------------------------------------
# Genel API
# ---------------------------------------------------------------------------


def audit_zero_trust_inline(
    raw_content: str,
    *,
    filename: str = "networkpolicy.yaml",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek Kubernetes / service mesh manifest içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "networkpolicy.yaml"
    clean_filename = filename.strip()

    ctx = _MeshContext()
    findings, add = _collector()
    _scan_content(raw_content, filename=clean_filename, ctx=ctx, add=add)
    _aggregate_findings(ctx, add)

    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-zero-trust-mesh-inline-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(ZERO_TRUST_CONTROLS_EVALUATED),
        "kinds_detected": sorted(ctx.kinds),
        "namespaces_detected": sorted(ctx.namespaces),
        "document_count": ctx.documents,
        "heuristic_documents": ctx.heuristic_documents,
    }


def _is_mesh_candidate(content: str) -> bool:
    return ("apiVersion" in content and "kind" in content) or "static_resources" in content


@project_scan_scope
def audit_zero_trust_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    ctx = _MeshContext()
    findings, add = _collector()
    scanned_files = 0

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            if scanned_files >= MAX_PROJECT_FILES:
                break
            file_path = Path(current) / name
            if file_path.is_symlink():
                continue
            if file_path.suffix.lower() not in ZERO_TRUST_EXTENSIONS:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip() or not _is_mesh_candidate(content):
                continue
            rel_name = str(file_path.relative_to(root))
            scanned_files += 1
            _scan_content(content, filename=rel_name, ctx=ctx, add=add)

    _aggregate_findings(ctx, add)
    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    return {
        "format": "sniper-zero-trust-mesh-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "controls_evaluated": list(ZERO_TRUST_CONTROLS_EVALUATED),
        "kinds_detected": sorted(ctx.kinds),
        "namespaces_detected": sorted(ctx.namespaces),
        "document_count": ctx.documents,
        "heuristic_documents": ctx.heuristic_documents,
    }
