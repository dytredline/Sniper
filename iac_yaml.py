"""Satır numaralı, güvenli YAML okuyucu (IaC motoru için).

Yalnız ``SafeLoader`` ile *compose* edilir (nesne kurulmaz). Takma ad (&anchor/*alias) düğümleri tek kez
dönüştürülür ve toplam düğüm bütçesi aşılırsa ayrıştırma bırakılır (YAML bombasına karşı). Helm şablonları için
``{{ ... }}`` ifadeleri yer tutucuyla değiştirilir; denetimler yer tutucuyu bilinmeyen değer sayar.
"""
from __future__ import annotations

from typing import Any

try:  # PyYAML sistem paketinde var; yoksa YAML IaC denetimi eski desen kurallarına düşer
    import yaml
except ImportError:  # pragma: no cover - ortama bağlı
    yaml = None  # type: ignore[assignment]

MAX_NODES = 200_000
HELM_PLACEHOLDER = "__SNIPER_HELM__"


class YamlError(ValueError):
    pass


class LDict(dict):
    """Anahtar → satır bilgisi taşıyan sözlük."""
    line: int = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lines: dict[str, int] = {}

    def line_of(self, key: str) -> int:
        return self.lines.get(key, self.line)


class LList(list):
    line: int = 0

    def __init__(self, *args):
        super().__init__(*args)
        self.lines: list[int] = []

    def line_of(self, index: int) -> int:
        return self.lines[index] if 0 <= index < len(self.lines) else self.line


_LOADER = (getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader) if yaml is not None else None
_BOOL_TRUE = {"true", "yes", "on", "y"}
_BOOL_FALSE = {"false", "no", "off", "n"}


def _scalar(node: Any) -> Any:
    tag = node.tag or ""
    value = node.value
    if tag.endswith(":bool"):
        low = value.casefold()
        if low in _BOOL_TRUE:
            return True
        if low in _BOOL_FALSE:
            return False
    if tag.endswith(":int"):
        for base in (10, 0):
            try:
                return int(value.replace("_", ""), base)
            except ValueError:
                continue
        return value
    if tag.endswith(":null"):
        return None
    if tag.endswith(":float"):
        try:
            return float(value)
        except ValueError:
            return value
    return value


def _convert(node: Any, memo: dict[int, Any], budget: list[int]) -> Any:
    key = id(node)
    if key in memo:
        return memo[key]
    budget[0] += 1
    if budget[0] > MAX_NODES:
        raise YamlError("düğüm bütçesi aşıldı")
    line = node.start_mark.line + 1 if node.start_mark is not None else 0
    if isinstance(node, yaml.MappingNode):
        out = LDict()
        out.line = line
        memo[key] = out
        for k_node, v_node in node.value:
            if isinstance(k_node, yaml.ScalarNode) and k_node.value == "<<":  # birleştirme anahtarı
                merged = _convert(v_node, memo, budget)
                for src in (merged if isinstance(merged, list) else [merged]):
                    if isinstance(src, LDict):
                        for mk, mv in src.items():
                            out.setdefault(mk, mv)
                            out.lines.setdefault(mk, src.line_of(mk))
                continue
            k = _convert(k_node, memo, budget)
            if not isinstance(k, (str, int, float, bool)) and k is not None:
                continue
            k = str(k) if not isinstance(k, str) else k
            out[k] = _convert(v_node, memo, budget)
            out.lines[k] = k_node.start_mark.line + 1
        return out
    if isinstance(node, yaml.SequenceNode):
        out_list = LList()
        out_list.line = line
        memo[key] = out_list
        for item in node.value:
            out_list.append(_convert(item, memo, budget))
            out_list.lines.append(item.start_mark.line + 1)
        return out_list
    value = _scalar(node)
    memo[key] = value
    return value


def load_all(text: str) -> list[Any]:
    """Tüm belgeleri (satır bilgili) döndürür; bozuk YAML'de YamlError."""
    if yaml is None:
        raise YamlError("PyYAML yok")
    docs: list[Any] = []
    budget = [0]
    try:
        for node in yaml.compose_all(text, Loader=_LOADER):
            if node is None:
                continue
            docs.append(_convert(node, {}, budget))
    except yaml.YAMLError as exc:
        raise YamlError(str(exc).splitlines()[0] if str(exc) else "YAML hatası") from None
    except RecursionError:
        raise YamlError("çok derin iç içe yapı") from None
    return docs


def helm_action_spans(text: str) -> list[tuple[int, int, str]]:
    """Return complete ``{{ ... }}`` actions with trim markers removed.

    Searching always resumes after the previous closing delimiter. An
    unterminated opener stops the scan because no later opener can have a
    closing delimiter that the earlier opener would not also consume.
    """
    actions: list[tuple[int, int, str]] = []
    cursor = 0
    while cursor < len(text):
        start = text.find("{{", cursor)
        if start < 0:
            break
        closing = text.find("}}", start + 2)
        if closing < 0:
            break
        body = text[start + 2:closing]
        if body.startswith("-"):
            body = body[1:]
        if body.endswith("-"):
            body = body[:-1]
        end = closing + 2
        actions.append((start, end, body))
        cursor = end
    return actions


def helm_action_line(line: str) -> str | None:
    """Return the body when the entire non-whitespace line is one action."""
    stripped = line.strip()
    if not stripped.startswith("{{") or not stripped.endswith("}}"):
        return None
    body = stripped[2:-2]
    if body.startswith("-"):
        body = body[1:]
    if body.endswith("-"):
        body = body[:-1]
    return body


def replace_helm_actions(text: str, replacement: str) -> str:
    """Replace complete actions in one forward pass; leave malformed text intact."""
    actions = helm_action_spans(text)
    if not actions:
        return text
    out: list[str] = []
    cursor = 0
    for start, end, _body in actions:
        out.extend((text[cursor:start], replacement))
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def mask_multiline_helm_actions(text: str) -> str:
    """Blank complete multiline actions while preserving their newline count."""
    out: list[str] = []
    cursor = 0
    changed = False
    for start, end, _body in helm_action_spans(text):
        action = text[start:end]
        if "\n" not in action:
            continue
        out.extend((text[cursor:start], "\n" * action.count("\n")))
        cursor = end
        changed = True
    if not changed:
        return text
    out.append(text[cursor:])
    return "".join(out)


def render_helm_lite(text: str) -> str:
    """Helm şablonunu satır sayısını koruyarak YAML'e yaklaştırır: yalnız denetim ifadesinden oluşan satırlar
    boşaltılır, satır içi ifadeler yer tutucuya çevrilir. Değerler bilinmediği için yalnız sabit yazılmış
    ayarlar denetlenebilir."""
    # Birden çok satıra yayılan ifadeler ({{/* yorum */}}, uzun include) satır sayısı korunarak boşaltılır.
    text = mask_multiline_helm_actions(text)
    out: list[str] = []
    for raw in text.split("\n"):
        if helm_action_line(raw) is not None:
            out.append("")
        elif "{{" in raw:
            replaced = replace_helm_actions(raw, HELM_PLACEHOLDER)
            # "anahtar: __X__ | yyy" gibi kalıntılarda bile tek dizge kalsın
            out.append(replaced.replace("{{", "").replace("}}", ""))
        else:
            out.append(raw)
    return "\n".join(out)


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and HELM_PLACEHOLDER in value
