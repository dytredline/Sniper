"""Helm şablonları için basit, güvenli render (IaC motoru, 19. tur).

Grafiğin ``values.yaml`` değerleriyle ``templates/*.yaml`` dosyaları satır tabanlı işlenir:

* ``{{ .Values.a.b }}`` / ``{{ $.Values.x }}`` / ``{{ .x }}`` (with/range bağlamında) yerine koyma,
  ``| quote``, ``| default "x"`` (ve ``default "x" .Values.y``), ``| toString``, ``| int``, ``| trim``;
* ``{{- if KOŞUL }}`` / ``else`` / ``end`` — koşul ``.Values.x``, ``not .Values.x``, ``eq .Values.x "y"``,
  ``and``/``or`` (iki işlenen); bilinen yanlış dal atlanır; bilinmeyen koşullar en çok altı kontrol noktası için
  ayrı ve güvenli YAML varyantları olarak değerlendirilir;
* ``{{- with .Values.x }}`` — değer boşsa blok atlanır, değilse ``.`` o değer olur;
* ``{{- range .Values.liste }}`` — bilinen liste (en çok 20 öğe) için gövde öğe başına tekrarlanır;
* ``{{- toYaml .Values.x | nindent N }}`` (ve ``indent``) — değer YAML olarak girintili satırlara açılır.

Desteklenmeyen her ifade (``include``, ``template``, ``.Release``, ``tpl`` …) eski yer tutucuya
(``iac_yaml.HELM_PLACEHOLDER``) dönüşür; denetimler onu bilinmeyen sayar. Çıktı satırlarının şablon satırlarına
eşlemi döndürülür (bulgu satırları şablondaki satıra çevrilir). Kod çalıştırılmaz; şablon başka dosya okumaz.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any

import iac_yaml

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

MAX_OUTPUT_LINES = 20_000
MAX_RANGE_ITEMS = 20
MAX_UNKNOWN_BRANCHES = 6
MAX_LINEAR_BRANCHES = 64
PH = iac_yaml.HELM_PLACEHOLDER


class RenderVariants(list[tuple[str, list[int]]]):
    """Render listesi ve kapsam sinyali.

    Altı bilinmeyene kadar bütün kombinasyonlar kapsanır. Daha büyük şablonlarda her kontrolün iki dalını
    doğrusal sayıda örnekle kapsarız; dal kombinasyonları tam olmadığı için çağırana açık eksiklik sinyali verilir.
    """

    def __init__(self, items=(), *, analysis_complete: bool = True, strategy: str = "exhaustive",
                 unknown_controls: int = 0, covered_controls: int = 0, partial_ranges: int = 0):
        super().__init__(items)
        self.analysis_complete = analysis_complete
        self.strategy = strategy
        self.unknown_controls = unknown_controls
        self.covered_controls = covered_controls
        self.partial_ranges = partial_ranges


class _Unknown:
    pass


UNKNOWN = _Unknown()
_ACTION = re.compile(r"\{\{-?(.*?)-?\}\}", re.S)
_CONTROL = re.compile(r"^\s*\{\{-?\s*(if|else if|else|end|with|range|define|block)\b(.*?)-?\}\}\s*$")
_COMMENT_LINE = re.compile(r"^\s*\{\{-?\s*/\*.*\*/\s*-?\}\}\s*$")
_ONLY_ACTION = re.compile(r"^\s*\{\{-?.*-?\}\}\s*$")
_VAR_ASSIGN_LINE = re.compile(r"^\s*\{\{-?\s*(\$[A-Za-z_]\w*)\s*:=\s*(.*?)\s*-?\}\}\s*$")


_SafeLoader = (getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader) if yaml is not None else None


def load_values(text: str) -> dict | None:
    if yaml is None:
        return None
    try:
        data = yaml.load(text, Loader=_SafeLoader)  # yalnız (C)SafeLoader: Python nesnesi kurulmaz
    except (yaml.YAMLError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _lookup(path: str, scope: dict) -> Any:
    """``.Values.a.b``, ``$.Values.x``, ``.x`` (bağlam), ``.`` → değer ya da UNKNOWN."""
    path = path.strip()
    if path == ".":
        return scope["dot"]
    if path.startswith("$."):
        base, rest = scope["root"], path[2:]
    elif path.startswith("$"):
        match = re.match(r"^(\$[A-Za-z_]\w*)(?:\.(.*))?$", path)
        if not match:
            return UNKNOWN
        base = scope.get("vars", {}).get(match.group(1), UNKNOWN)
        rest = match.group(2) or ""
    elif path.startswith("."):
        base, rest = scope["dot"], path[1:]
    else:
        return UNKNOWN
    if base is UNKNOWN:
        return UNKNOWN
    if not rest:
        return base
    node: Any = base
    for part in rest.split("."):
        if not part or not re.fullmatch(r"[A-Za-z_][\w-]*", part):
            return UNKNOWN
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, dict):
            return None  # Helm: tanımsız anahtar boş (nil) değerdir
        else:
            return UNKNOWN
    return node


def _empty(value: Any) -> bool | None:
    if value is UNKNOWN:
        return None
    return value in (None, False, 0, "", [], {})


def _atom(token: str, scope: dict) -> Any:
    if token.startswith(('"', "'", "`")):
        try:
            return shlex.split(token)[0] if token[0] != "`" else token.strip("`")
        except ValueError:
            return UNKNOWN
    if token in ("true", "false"):
        return token == "true"
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if token.startswith((".", "$")) or token == ".":
        if token.startswith(".Values") or token.startswith("$.Values") or not token.startswith((".Release", ".Chart",
                                                                                                 ".Capabilities",
                                                                                                 ".Template", ".Files")):
            return _lookup(token, scope)
    return UNKNOWN


def _binding_expr(expr: str) -> tuple[tuple[str, ...], str]:
    """Split a bounded Go-template ``$name [, $value] := expression`` initializer."""
    if ":=" not in expr:
        return (), expr.strip()
    left, right = expr.split(":=", 1)
    names = tuple(part.strip() for part in left.split(","))
    if not 1 <= len(names) <= 2 or any(not re.fullmatch(r"\$[A-Za-z_]\w*", name) for name in names):
        return (), expr.strip()
    return names, right.strip()


def _words(expr: str) -> list[str]:
    try:
        lex = shlex.shlex(expr, posix=False)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return []


def _eval_command(words: list[str], scope: dict, piped: Any = None, has_piped: bool = False) -> Any:
    """Tek komut (boru öncesi değer ``piped``)."""
    if not words:
        return piped if has_piped else UNKNOWN
    head, args = words[0], words[1:]
    vals = [_atom(a, scope) for a in args] + ([piped] if has_piped else [])
    if head.startswith(("(", ")")):
        return UNKNOWN
    if not args and not has_piped:
        return _atom(head, scope)
    if head == "default" and len(vals) == 2:
        dflt, value = vals
        e = _empty(value)
        return UNKNOWN if e is None else (dflt if e else value)
    if head == "quote" and len(vals) == 1:
        value = vals[0]
        if value is UNKNOWN or isinstance(value, (dict, list)):
            return UNKNOWN
        return json.dumps("" if value is None else (str(value).lower() if isinstance(value, bool) else str(value)))
    if head in ("toString", "trim") and len(vals) == 1:
        value = vals[0]
        if value is UNKNOWN or isinstance(value, (dict, list)):
            return UNKNOWN
        return (str(value).lower() if isinstance(value, bool) else str(value)).strip() if value is not None else ""
    if head == "int" and len(vals) == 1:
        try:
            return int(vals[0])
        except (TypeError, ValueError):
            return UNKNOWN
    if head == "not" and len(vals) == 1:
        e = _empty(vals[0])
        return UNKNOWN if e is None else e
    if head in ("eq", "ne") and len(vals) == 2:
        if UNKNOWN in vals:
            return UNKNOWN
        return (vals[0] == vals[1]) if head == "eq" else (vals[0] != vals[1])
    if head in ("and", "or") and len(vals) >= 2:
        flags = [_empty(v) for v in vals]
        if head == "and":
            if any(f is True for f in flags):
                return False
            return True if all(f is False for f in flags) else UNKNOWN
        if any(f is False for f in flags):
            return True
        return False if all(f is True for f in flags) else UNKNOWN
    if head == "toYaml" and len(vals) == 1:
        return ("__TOYAML__", vals[0])
    if head in ("nindent", "indent") and len(vals) == 2 and isinstance(vals[0], int):
        return ("__INDENT__", head, vals[0], vals[1])
    return UNKNOWN


def evaluate(expr: str, scope: dict) -> Any:
    expr = expr.strip()
    if not expr or expr.startswith("/*") or ":=" in expr or "(" in expr:
        return UNKNOWN
    value: Any = None
    first = True
    for part in expr.split("|"):
        words = _words(part.strip())
        value = _eval_command(words, scope) if first else _eval_command(words, scope, value, True)
        first = False
        if value is UNKNOWN:
            return UNKNOWN
    return value


def _scalar_text(value: Any) -> str | None:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return None


def _yaml_block(value: Any, indent: int) -> list[str] | None:
    if yaml is None or value is UNKNOWN:
        return None
    if value is None or value == {} or value == []:
        return []
    try:
        dumped = yaml.safe_dump(value, default_flow_style=False, sort_keys=False)
    except yaml.YAMLError:
        return None
    return [(" " * indent + line) if line else line for line in dumped.rstrip("\n").split("\n")]


def _render_inline(line: str, scope: dict) -> list[str]:
    """Satır içi eylemler. ``anahtar: {{ toYaml X | nindent N }}`` çok satıra açılır."""
    if scope.get("uncertain"):
        return [""] if _ONLY_ACTION.match(line) else [_ACTION.sub(PH, line).replace("{{", "").replace("}}", "")]
    actions = list(_ACTION.finditer(line))
    if len(actions) == 1:
        value = evaluate(actions[0].group(1), scope)
        if isinstance(value, tuple) and value[0] == "__INDENT__":
            inner = value[3]
            payload = inner[1] if isinstance(inner, tuple) and inner and inner[0] == "__TOYAML__" else inner
            block = _yaml_block(payload, value[2]) if not isinstance(payload, str) else \
                [(" " * value[2] + x) for x in payload.split("\n")]
            prefix = line[:actions[0].start()]
            if block is not None and not line[actions[0].end():].strip():
                if value[1] == "nindent":
                    return ([prefix.rstrip()] if prefix.strip() else []) + block
                if block:
                    return [prefix + block[0].lstrip()] + block[1:]
                return [prefix.rstrip()]
            return [_ACTION.sub(PH, line)]
    out = line
    for match in reversed(actions):
        value = evaluate(match.group(1), scope)
        text = _scalar_text(value) if not isinstance(value, tuple) else None
        if value is UNKNOWN or text is None:
            text = PH
        elif text and re.search(r"[:#{}\[\],&*!|>'\"%@`]|^\s|\s$", text) and not text.startswith('"'):
            text = json.dumps(text)
        out = out[:match.start()] + text + out[match.end():]
    return [out.replace("{{", "").replace("}}", "")]


def _range_values(value: Any, line: int, partials: set[int] | None) -> list[Any]:
    """Bir Helm range değeri için bütçeli, iki uçlu örnek kümesi.

    Bilinmeyen ya da bütçeyi aşan aralıklar sessizce tam sayılmaz. Büyük bir aralığın ilk ve son yarısını
    örneklemek, dosyanın sonundaki riskli öğeleri yalnız ilk N öğeyi almaya göre görünür tutar.
    """
    return [item for _key, item in _range_entries(value, line, partials)]


def _range_entries(value: Any, line: int, partials: set[int] | None) -> list[tuple[Any, Any]]:
    if isinstance(value, dict):
        items = list(value.items())
    elif isinstance(value, list):
        items = list(enumerate(value))
    else:
        if partials is not None:
            partials.add(line)
        return [(UNKNOWN, UNKNOWN)]
    if len(items) <= MAX_RANGE_ITEMS:
        return items
    if partials is not None:
        partials.add(line)
    first = MAX_RANGE_ITEMS // 2
    return items[:first] + items[-(MAX_RANGE_ITEMS - first):]


def render(text: str, values: dict, *, _choices: dict[int, bool] | None = None,
           _unknowns: set[int] | None = None,
           _partials: set[int] | None = None,
           _limits: set[str] | None = None) -> tuple[str, list[int]] | None:
    """(render edilmiş metin, çıktı satırı → şablon satırı) ya da işlenemezse None."""
    root = {"Values": values, "Release": {}, "Chart": {}}
    lines = text.split("\n")
    # Birden çok satıra yayılan eylemler eski yaklaşımla boşaltılır (satır sayısı korunur).
    joined = iac_yaml._HELM_MULTILINE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    lines = joined.split("\n")
    out: list[str] = []
    mapping: list[int] = []
    # Yığın öğesi: (tür, etkin: True/False/None, bağlam, ...)
    stack: list[dict] = []
    root_vars: dict[str, Any] = {}

    def active() -> bool:
        return all(frame["on"] is not False for frame in stack)

    def scope() -> dict:
        dot: Any = root
        variables = dict(root_vars)
        for frame in stack:
            if "dot" in frame:
                dot = frame["dot"]
            variables.update(frame.get("vars", {}))
        # Koşulu bilinmeyen bir dalın içindeysek değerler yerine konmaz (blok hiç oluşmayabilir): eski yer tutuculu
        # davranış korunur, yalnız kesin oluşan dallarda değerlerle denetim yapılır.
        return {"root": root, "dot": dot, "vars": variables,
                "uncertain": any(frame["on"] is None for frame in stack)}

    def emit(body: list[tuple[int, str]], sc: dict) -> None:
        for number, raw in body:
            for rendered in _render_inline(raw, sc) if "{{" in raw else [raw]:
                out.append(rendered)
                mapping.append(number)
                if len(out) > MAX_OUTPUT_LINES:
                    raise ValueError("çıktı sınırı")

    i = 0
    try:
        while i < len(lines):
            raw = lines[i]
            number = i + 1
            if _COMMENT_LINE.match(raw):
                i += 1
                continue
            assignment = _VAR_ASSIGN_LINE.match(raw)
            if assignment:
                if active():
                    target = stack[-1].setdefault("vars", {}) if stack else root_vars
                    target[assignment.group(1)] = evaluate(assignment.group(2), scope())
                i += 1
                continue
            control = _CONTROL.match(raw)
            if control:
                kind, arg = control.group(1), control.group(2)
                if kind in ("if",):
                    parent_active = active()
                    names, expr = _binding_expr(arg)
                    cond = evaluate(expr, scope()) if parent_active else UNKNOWN
                    e = _empty(cond)
                    if e is None and parent_active and _unknowns is not None:
                        _unknowns.add(number)
                    chosen = _choices.get(number) if e is None and _choices is not None else None
                    on = chosen if chosen is not None else (None if e is None else (not e))
                    frame = {"t": "if", "on": on, "done": on is True}
                    if names:
                        frame["vars"] = {names[0]: cond}
                    stack.append(frame)
                elif kind == "else if":
                    if stack and stack[-1]["t"] == "if":
                        frame = stack[-1]
                        if frame["done"]:
                            frame["on"] = False
                        else:
                            stack.pop()
                            names, expr = _binding_expr(arg)
                            cond = evaluate(expr, scope()) if active() else UNKNOWN
                            stack.append(frame)
                            e = _empty(cond)
                            if e is None and active() and _unknowns is not None:
                                _unknowns.add(number)
                            chosen = _choices.get(number) if e is None and _choices is not None else None
                            frame["on"] = chosen if chosen is not None else (None if e is None else (not e))
                            frame["done"] = frame["done"] or frame["on"] is True
                            if names:
                                frame.setdefault("vars", {})[names[0]] = cond
                elif kind == "else":
                    if stack and stack[-1]["t"] in ("if", "with"):
                        frame = stack[-1]
                        frame["on"] = None if frame["on"] is None and not frame["done"] else (not frame["done"])
                        frame.pop("dot", None)
                elif kind in ("with",):
                    parent_active = active()
                    names, expr = _binding_expr(arg)
                    value = evaluate(expr, scope()) if parent_active else UNKNOWN
                    e = _empty(value)
                    if e is None and parent_active and _unknowns is not None:
                        _unknowns.add(number)
                    chosen = _choices.get(number) if e is None and _choices is not None else None
                    on = chosen if chosen is not None else (None if e is None else (not e))
                    frame = {"t": "with", "on": on, "done": on is True}
                    if names:
                        frame["vars"] = {names[0]: value}
                    if e is False and not isinstance(value, tuple):
                        frame["dot"] = value
                    else:
                        frame["dot"] = UNKNOWN
                    stack.append(frame)
                elif kind == "range":
                    # gövdeyi topla (iç içe yapılar dahil) ve öğe başına işle
                    depth, j = 1, i + 1
                    while j < len(lines) and depth:
                        c = _CONTROL.match(lines[j])
                        if c and c.group(1) in ("if", "with", "range", "define", "block"):
                            depth += 1
                        elif c and c.group(1) == "end":
                            depth -= 1
                        j += 1
                    body = list(enumerate(lines[i + 1:j - 1], start=i + 2))
                    names, target = _binding_expr(arg)
                    items = evaluate(target, scope()) if active() else UNKNOWN
                    if active():
                        for key, item in _range_entries(items, number, _partials):
                            variables = {}
                            if len(names) == 1:
                                variables[names[0]] = item
                            elif len(names) == 2:
                                variables.update({names[0]: key, names[1]: item})
                            stack.append({"t": "range", "on": None if item is UNKNOWN else True,
                                          "dot": item, "vars": variables})
                            _render_body(body, stack, emit, scope, active, _choices, _unknowns, _partials)
                            stack.pop()
                    i = j
                    continue
                elif kind in ("define", "block"):
                    stack.append({"t": kind, "on": False})
                elif kind == "end":
                    if stack:
                        stack.pop()
                i += 1
                continue
            if active():
                if _ONLY_ACTION.match(raw) and "toYaml" not in raw and "indent" not in raw:
                    i += 1  # yalnız eylemden oluşan satır (include, template …): eski davranış gibi boş
                    continue
                emit([(number, raw)], scope())
            i += 1
    except ValueError:
        if _limits is not None:
            _limits.add("output-budget")
        return None
    except RecursionError:
        if _limits is not None:
            _limits.add("recursion-budget")
        return None
    return "\n".join(out), mapping


def render_variants(text: str, values: dict) -> RenderVariants:
    """Bilinmeyen ``if``/``with`` dallarını ayrı YAML varyantları olarak render eder.

    Aynı belgede iki dalı birden tutmak yinelenen YAML anahtarlarında son dalın ilkini ezmesine ve riskli
    dalın kaçmasına yol açıyordu. En fazla altı kontrol noktası (64 varyant) eksiksiz denenir. Daha büyük
    şablonlarda tüm-yanlış/tüm-doğru tabanları ve bütçeli tek-dal çevrimleri doğrusal sayıda varyant üretir;
    Kartezyen kombinasyonlar tamamlanmadığı için sonuç ``analysis_complete=False`` taşır.
    """
    unknowns: set[int] = set()
    partials: set[int] = set()
    limits: set[str] = set()
    baseline = render(text, values, _unknowns=unknowns, _partials=partials, _limits=limits)
    controls = sorted(unknowns)
    if not controls:
        complete = not partials and not limits
        strategy = "+".join([*(sorted(limits)), *( ["range-budget-partial"] if partials else [])]) or "exhaustive"
        return RenderVariants([baseline] if baseline is not None else [], analysis_complete=complete,
                              strategy=strategy,
                              unknown_controls=0, covered_controls=0, partial_ranges=len(partials))
    variants: list[tuple[str, list[int]]] = []
    seen: set[str] = set()

    if len(controls) <= MAX_UNKNOWN_BRANCHES:
        choice_sets = [
            {line: bool(mask & (1 << index)) for index, line in enumerate(controls)}
            for mask in range(1 << len(controls))
        ]
        strategy = "exhaustive"
        complete = True
        covered = len(controls)
    else:
        # Kartesyen çarpım 2**N büyür. Tüm-yanlış/tüm-doğru ve her kontrolün bu iki tabandan tek tek
        # çevrildiği örnekler, her doğrudan dalı en az bir kez görür ve yalnız O(N) varyant üretir. İç içe
        # koşulların tüm kombinasyonları denenmediği için sonuç açıkça kısmi işaretlenir.
        selected = controls[:MAX_LINEAR_BRANCHES]
        all_false = {line: False for line in controls}
        all_true = {line: True for line in controls}
        choice_sets = [all_false, all_true]
        for line in selected:
            from_false = dict(all_false)
            from_false[line] = True
            choice_sets.append(from_false)
            from_true = dict(all_true)
            from_true[line] = False
            choice_sets.append(from_true)
        strategy = "linear-branch-coverage"
        complete = False
        covered = len(selected)

    for choices in choice_sets:
        item = render(text, values, _choices=choices, _limits=limits)
        if item is not None and item[0] not in seen:
            seen.add(item[0])
            variants.append(item)
    if partials:
        complete = False
        strategy += "+range-budget-partial"
    if limits:
        complete = False
        strategy += "+" + "+".join(sorted(limits))
    return RenderVariants(variants, analysis_complete=complete, strategy=strategy,
                          unknown_controls=len(controls), covered_controls=covered,
                          partial_ranges=len(partials))


def _render_body(body: list[tuple[int, str]], stack: list[dict], emit, scope, active,
                 choices: dict[int, bool] | None = None, unknowns: set[int] | None = None,
                 partials: set[int] | None = None) -> None:
    """range gövdesi: iç denetim yapıları da işlenir (yeni yığın çerçeveleriyle)."""
    local_lines = [raw for _, raw in body]
    numbers = [n for n, _ in body]
    k = 0
    base = len(stack)
    while k < len(local_lines):
        raw = local_lines[k]
        assignment = _VAR_ASSIGN_LINE.match(raw)
        if assignment:
            if active() and stack:
                stack[-1].setdefault("vars", {})[assignment.group(1)] = evaluate(assignment.group(2), scope())
            k += 1
            continue
        control = _CONTROL.match(raw)
        if control:
            kind, arg = control.group(1), control.group(2)
            if kind == "if":
                parent_active = active()
                names, expr = _binding_expr(arg)
                value = evaluate(expr, scope()) if parent_active else UNKNOWN
                e = _empty(value)
                line = numbers[k]
                if e is None and parent_active and unknowns is not None:
                    unknowns.add(line)
                chosen = choices.get(line) if e is None and choices is not None else None
                on = chosen if chosen is not None else (None if e is None else (not e))
                frame = {"t": "if", "on": on, "done": on is True}
                if names:
                    frame["vars"] = {names[0]: value}
                stack.append(frame)
            elif kind == "else if" and len(stack) > base and stack[-1]["t"] == "if":
                frame = stack[-1]
                if frame.get("done"):
                    frame["on"] = False
                else:
                    stack.pop()
                    parent_active = active()
                    names, expr = _binding_expr(arg)
                    value = evaluate(expr, scope()) if parent_active else UNKNOWN
                    e = _empty(value)
                    stack.append(frame)
                    line = numbers[k]
                    if e is None and parent_active and unknowns is not None:
                        unknowns.add(line)
                    chosen = choices.get(line) if e is None and choices is not None else None
                    frame["on"] = chosen if chosen is not None else (None if e is None else (not e))
                    frame["done"] = frame.get("done", False) or frame["on"] is True
                    if names:
                        frame.setdefault("vars", {})[names[0]] = value
            elif kind == "else" and len(stack) > base:
                frame = stack[-1]
                frame["on"] = None if frame["on"] is None and not frame.get("done") else (not frame.get("done"))
            elif kind == "with":
                parent_active = active()
                names, expr = _binding_expr(arg)
                value = evaluate(expr, scope()) if parent_active else UNKNOWN
                e = _empty(value)
                line = numbers[k]
                if e is None and parent_active and unknowns is not None:
                    unknowns.add(line)
                chosen = choices.get(line) if e is None and choices is not None else None
                on = chosen if chosen is not None else (None if e is None else (not e))
                frame = {"t": "with", "on": on, "done": on is True,
                         "dot": value if e is False else UNKNOWN}
                if names:
                    frame["vars"] = {names[0]: value}
                stack.append(frame)
            elif kind == "range":
                depth, end = 1, k + 1
                while end < len(local_lines) and depth:
                    nested = _CONTROL.match(local_lines[end])
                    if nested and nested.group(1) in ("if", "with", "range", "define", "block"):
                        depth += 1
                    elif nested and nested.group(1) == "end":
                        depth -= 1
                    end += 1
                nested_body = list(zip(numbers[k + 1:end - 1], local_lines[k + 1:end - 1]))
                names, target = _binding_expr(arg)
                value = evaluate(target, scope()) if active() else UNKNOWN
                if active():
                    for key, item in _range_entries(value, numbers[k], partials):
                        variables = {}
                        if len(names) == 1:
                            variables[names[0]] = item
                        elif len(names) == 2:
                            variables.update({names[0]: key, names[1]: item})
                        stack.append({"t": "range", "on": None if item is UNKNOWN else True,
                                      "dot": item, "vars": variables})
                        _render_body(nested_body, stack, emit, scope, active, choices, unknowns, partials)
                        stack.pop()
                k = end
                continue
            elif kind in ("define", "block"):
                stack.append({"t": kind, "on": False, "dot": UNKNOWN})
            elif kind == "end" and len(stack) > base:
                stack.pop()
            k += 1
            continue
        if active() and not (_ONLY_ACTION.match(raw) and "toYaml" not in raw and "indent" not in raw):
            emit([(numbers[k], raw)], scope())
        k += 1
    del stack[base:]
