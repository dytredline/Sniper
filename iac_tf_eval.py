"""Terraform ifadelerinin sınırlı, güvenli değerlendirmesi (IaC motoru, 19. tur).

Ayrıştırıcı (``iac_hcl``) değişken/başvuru içeren her ifadeyi ``Unknown`` olarak bırakır. Burada aynı modüldeki
``variable`` varsayılanları, ``*.tfvars``/``*.auto.tfvars`` değerleri, ``locals`` ve yerel modül çağrılarının
girdileriyle bu ifadeler yeniden değerlendirilir:

* ``var.x`` / ``local.x`` / yerel ``module.x.output`` (+ ``.alan`` / ``["anahtar"]`` / ``[0]`` erişimi),
  ara değerli dizge (``"${var.a}-b"``),
* ``koşul ? a : b`` (koşul biliniyorsa seçilir; bilinmiyorsa iki dal aynı değeri veriyorsa o değer),
* ``==``, ``!=``, ``&&``, ``||``, ``!``, karşılaştırmalar, eksi işareti,
* ``lookup``, ``merge``, ``coalesce``, ``concat``, ``try``, ``tostring``/``tobool``/``tonumber``/``tolist``/``toset``,
  ``lower``/``upper``, ``jsonencode`` (politika denetimleri için ``Call`` olarak kalır).

Bilinmeyen her şey yine ``Unknown`` kalır: denetimler bilinmeyende susar (yanlış alarm yerine kaçırma). Kaynak
başvuruları (``aws_x.y.id``), ``data.``, uzaktaki ya da hazırlanmış çıktısı olmayan ``module.`` başvuruları,
``each.``, ``count.``, ``path.``, ``for`` ifadeleri ve ``%{ }`` yönergeleri değerlendirilmez. Kod çalıştırılmaz,
dosya okunmaz.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

import iac_hcl
from iac_hcl import Attr, Block, Call, Tok, Unknown

MAX_DEPTH = 24  # locals birbirine başvurabilir; döngüye karşı derinlik sınırı
_FAIL = Unknown("")


@dataclass
class Ctx:
    """Bir modül örneğinin değerlendirme bağlamı."""
    variables: dict[str, Any] = field(default_factory=dict)  # ad → değer (bilinmeyen: Unknown)
    locals_raw: dict[str, Any] = field(default_factory=dict)  # ad → ayrıştırılmış (çözülmemiş) değer
    _locals: dict[str, Any] = field(default_factory=dict)
    _active: set[str] = field(default_factory=set)
    depth: int = 0
    # Yerel modül çağrısı → tekil çıktı nesnesi ya da statik ``count``/``for_each`` örnek şekli.
    modules: dict[str, Any] = field(default_factory=dict)

    def local(self, name: str) -> Any:
        if name in self._locals:
            return self._locals[name]
        if name not in self.locals_raw or name in self._active or len(self._active) > MAX_DEPTH:
            return _FAIL
        self._active.add(name)
        try:
            value = resolve(self.locals_raw[name], self)
        finally:
            self._active.discard(name)
        self._locals[name] = value
        return value


def known(value: Any) -> bool:
    """Değer (iç içe dahil) tamamen bilinen bir değişmez mi?"""
    if isinstance(value, (Unknown, Call)):
        return False
    if isinstance(value, list):
        return all(known(v) for v in value)
    if isinstance(value, dict):
        return all(known(v) for v in value.values())
    return True


def resolve(value: Any, ctx: Ctx) -> Any:
    """Ayrıştırılmış değeri bağlamda çözer (yeni nesne; girdi değiştirilmez)."""
    if isinstance(value, Unknown):
        if not value.toks:
            return value
        try:
            out = _Eval(list(value.toks), ctx).run()
        except (_EvalError, RecursionError, ValueError, TypeError, IndexError, KeyError):
            return value
        return value if isinstance(out, Unknown) else out  # bilinmeyen: özgün (belirteçli) değer korunur
    if isinstance(value, Call):
        return _call(value.name, [resolve(a, ctx) for a in value.args])
    if isinstance(value, list):
        return [resolve(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: resolve(v, ctx) for k, v in value.items()}
    return value


def resolve_block(block: Block, ctx: Ctx) -> Block:
    """Bloğun özniteliklerini (iç içe bloklar dahil) çözülmüş bir kopyasını döndürür."""
    out = Block(block.type, list(block.labels), block.line)
    for name, attr in block.attrs.items():
        out.attrs[name] = Attr(resolve(attr.value, ctx), attr.line)
    out.blocks = [resolve_block(b, ctx) for b in block.blocks]
    return out


class _EvalError(Exception):
    pass


def _truthy(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.casefold() in ("true", "false"):
        return value.casefold() == "true"
    return None


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _to_str(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else str(value)
    if isinstance(value, str):
        return value
    return None


def _call(name: str, args: list[Any]) -> Any:
    """Bilinen saf işlevler; bilinmeyen argüman ya da işlevde Unknown/Call döner."""
    if name == "jsonencode":
        return Call(name, args)
    if name == "try":
        for arg in args:
            if not isinstance(arg, Unknown):
                return arg
        return Unknown(f"try(...)")
    if name == "coalesce":
        for arg in args:
            if isinstance(arg, Unknown):
                return Unknown("coalesce(...)")
            if arg is not None and arg != "":
                return arg
        return None
    if not all(known(a) for a in args):
        return Call(name, args) if name not in ("lookup", "merge", "concat") else Unknown(f"{name}(...)")
    if name == "lookup" and len(args) in (2, 3) and isinstance(args[0], dict):
        if isinstance(args[1], str) and args[1] in args[0]:
            return args[0][args[1]]
        return args[2] if len(args) == 3 else Unknown("lookup(...)")
    if name == "merge" and all(isinstance(a, dict) or a is None for a in args):
        merged: dict[str, Any] = {}
        for arg in args:
            merged.update(arg or {})
        return merged
    if name == "concat" and all(isinstance(a, list) for a in args):
        return [v for a in args for v in a]
    if name in ("tolist", "toset") and len(args) == 1 and isinstance(args[0], list):
        return list(args[0])
    if name == "tomap" and len(args) == 1 and isinstance(args[0], dict):
        return dict(args[0])
    if name == "tostring" and len(args) == 1:
        text = _to_str(args[0])
        return text if text is not None else Unknown("tostring(...)")
    if name == "tobool" and len(args) == 1:
        flag = _truthy(args[0])
        return flag if flag is not None else Unknown("tobool(...)")
    if name == "tonumber" and len(args) == 1:
        number = _num(args[0])
        return number if number is not None else Unknown("tonumber(...)")
    if name in ("lower", "upper") and len(args) == 1 and isinstance(args[0], str):
        return args[0].lower() if name == "lower" else args[0].upper()
    if name == "length" and len(args) == 1 and isinstance(args[0], (list, dict, str)):
        return len(args[0])
    return Call(name, args)


def render_template(text: str, ctx: Ctx) -> Any:
    """``"önek-${ifade}-sonek"``; ``%{ }`` yönergesi ya da bilinmeyen parça → Unknown."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("$${", i) or text.startswith("%%{", i):
            out.append(text[i + 1:i + 3])
            i += 3
            continue
        if text.startswith("%{", i):
            return Unknown(text)
        if text.startswith("${", i):
            depth, j = 0, i + 1
            while j < n:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif text[j] == '"':  # iç dizge
                    k = j + 1
                    while k < n and text[k] != '"':
                        k += 2 if text[k] == "\\" else 1
                    j = k
                j += 1
            if j >= n:
                return Unknown(text)
            inner = text[i + 2:j].strip().lstrip("~").rstrip("~")
            try:
                toks = [t for t in iac_hcl.tokenize(inner) if t.kind != "eof"]
                value = _Eval(toks, ctx).run()
            except (iac_hcl.HclError, _EvalError, RecursionError, ValueError, TypeError, IndexError, KeyError):
                return Unknown(text)
            part = _to_str(value) if known(value) else None
            if part is None:
                return Unknown(text)
            out.append(part)
            i = j + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


_PREC = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, ">": 4, "<=": 4, ">=": 4, "+": 5, "-": 5, "*": 6, "/": 6, "%": 6}


class _Eval:
    """Küçük öncelik ayrıştırıcısı (Pratt) — yalnız yukarıda sayılan yapılar."""

    def __init__(self, toks: list[Tok], ctx: Ctx):
        self.toks = [t for t in toks if t.kind != "nl"]
        self.i = 0
        self.ctx = ctx
        if ctx.depth > MAX_DEPTH:
            raise _EvalError("derinlik")

    def peek(self, k: int = 0) -> Tok | None:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def is_p(self, value: str, k: int = 0) -> bool:
        tok = self.peek(k)
        return tok is not None and tok.kind == "p" and tok.value == value

    def run(self) -> Any:
        value = self.ternary()
        if self.i != len(self.toks):
            raise _EvalError("artık belirteç")
        return value

    def ternary(self) -> Any:
        cond = self.binary(0)
        if not self.is_p("?"):
            return cond
        self.i += 1
        a = self.ternary()
        if not self.is_p(":"):
            raise _EvalError("':' yok")
        self.i += 1
        b = self.ternary()
        flag = _truthy(cond)
        if flag is not None:
            return a if flag else b
        if known(a) and known(b) and a == b and type(a) is type(b):
            return a  # iki dal da aynı (ör. ikisi de güvensiz) → koşuldan bağımsız
        return Unknown("?:")

    def binary(self, min_prec: int) -> Any:
        left = self.unary()
        while True:
            tok = self.peek()
            if tok is None or tok.kind != "p" or tok.value not in _PREC or _PREC[tok.value] < min_prec:
                return left
            prec = _PREC[tok.value]
            self.i += 1
            right = self.binary(prec + 1)
            left = self._apply(tok.value, left, right)

    @staticmethod
    def _apply(op: str, a: Any, b: Any) -> Any:
        if op in ("||", "&&"):
            fa, fb = _truthy(a), _truthy(b)
            if op == "||":
                if fa is True or fb is True:
                    return True
                return False if fa is False and fb is False else Unknown("||")
            if fa is False or fb is False:
                return False
            return True if fa is True and fb is True else Unknown("&&")
        if not (known(a) and known(b)):
            return Unknown(op)
        if op in ("==", "!="):
            same = a == b and (type(a) is type(b) or {type(a), type(b)} <= {int, float})
            return same if op == "==" else not same
        na, nb = _num(a), _num(b)
        if na is None or nb is None:
            return Unknown(op)
        if op == "<":
            return na < nb
        if op == ">":
            return na > nb
        if op == "<=":
            return na <= nb
        if op == ">=":
            return na >= nb
        if op == "+":
            return na + nb
        if op == "-":
            return na - nb
        if op == "*":
            return na * nb
        if op in ("/", "%") and nb:
            return na / nb if op == "/" else na % nb
        return Unknown(op)

    def unary(self) -> Any:
        if self.is_p("!"):
            self.i += 1
            flag = _truthy(self.unary())
            return (not flag) if flag is not None else Unknown("!")
        if self.is_p("-"):
            self.i += 1
            number = _num(self.unary())
            return -number if number is not None else Unknown("-")
        return self.postfix(self.primary())

    def primary(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise _EvalError("ifade bekleniyor")
        if tok.kind in ("str", "heredoc"):
            self.i += 1
            return render_template(str(tok.value), self.ctx) if tok.interp else tok.value
        if tok.kind == "num":
            self.i += 1
            return tok.value
        if tok.kind == "p" and tok.value == "(":
            self.i += 1
            value = self.ternary()
            if not self.is_p(")"):
                raise _EvalError("')' yok")
            self.i += 1
            return value
        if tok.kind == "p" and tok.value in ("[", "{"):
            end = iac_hcl._matching(self.toks, self.i)
            if end < 0:
                raise _EvalError("eşleşmeyen parantez")
            inner = self.toks[self.i:end + 1]
            self.i = end + 1
            return resolve(iac_hcl.interpret(inner), self.ctx)
        if tok.kind == "id":
            self.i += 1
            if tok.value == "true":
                return True
            if tok.value == "false":
                return False
            if tok.value == "null":
                return None
            if self.is_p("("):  # işlev çağrısı
                end = iac_hcl._matching(self.toks, self.i)
                if end < 0:
                    raise _EvalError("eşleşmeyen parantez")
                parts = iac_hcl._split(self.toks[self.i + 1:end], (",",))
                self.i = end + 1
                args = []
                for part in parts:
                    if part and part[-1].kind == "p" and part[-1].value == "...":
                        return Unknown(f"{tok.value}(...)")
                    sub = _Eval(part, Ctx(self.ctx.variables, self.ctx.locals_raw, self.ctx._locals,
                                          self.ctx._active, self.ctx.depth + 1, self.ctx.modules))
                    args.append(sub.run())
                return _call(tok.value, args)
            if tok.value in ("var", "local") and self.is_p(".") and self.peek(1) is not None \
                    and self.peek(1).kind == "id":
                name = self.peek(1).value
                self.i += 2
                if tok.value == "var":
                    return self.ctx.variables.get(name, Unknown(f"var.{name}"))
                return self.ctx.local(name)
            if tok.value == "module" and self.is_p(".") and self.peek(1) is not None \
                    and self.peek(1).kind == "id":
                name = self.peek(1).value
                self.i += 2
                return self.ctx.modules.get(name, Unknown(f"module.{name}"))
            # kaynak/veri/modül başvurusu, each/count/path… — değerlendirilmez; erişim zinciri tüketilir
            self.postfix(Unknown(tok.value))
            return Unknown(tok.value)
        raise _EvalError(f"beklenmeyen belirteç {tok.value!r}")

    def postfix(self, value: Any) -> Any:
        while True:
            if self.is_p(".") and self.peek(1) is not None and self.peek(1).kind in ("id", "num"):
                key = self.peek(1).value
                self.i += 2
                if isinstance(value, dict) and isinstance(key, str):
                    value = value.get(key, Unknown(f".{key}"))
                elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
                    value = value[key]
                elif not isinstance(value, Unknown):
                    value = Unknown(f".{key}")
                continue
            if self.is_p("["):
                end = iac_hcl._matching(self.toks, self.i)
                if end < 0:
                    raise _EvalError("eşleşmeyen parantez")
                inner = self.toks[self.i + 1:end]
                self.i = end + 1
                if len(inner) == 1 and inner[0].kind == "p" and inner[0].value == "*":
                    value = Unknown("[*]")
                    continue
                key = _Eval(inner, self.ctx).run() if inner else Unknown("[]")
                if isinstance(value, dict) and isinstance(key, str):
                    value = value.get(key, Unknown("[k]"))
                elif isinstance(value, list) and isinstance(key, (int, float)) and not isinstance(key, bool) \
                        and 0 <= int(key) < len(value):
                    value = value[int(key)]
                else:
                    value = Unknown("[k]")
                continue
            return value


def deep_copy_block(block: Block) -> Block:
    return copy.deepcopy(block)
