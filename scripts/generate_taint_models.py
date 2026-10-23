#!/usr/bin/env python3
"""typeshed tip tanımlarından Python standart kütüphanesi için taint yayıcı modelleri üret.

Kural: modül düzeyindeki bir fonksiyon dize/bayt (str, bytes, AnyStr, LiteralString, yol türleri …)
alan bir parametreye sahip ve dönüş türü dize/bayt (ya da bunların listesi/demeti/yineleyicisi)
ise "argüman → dönüş" yayıcısıdır. Arındırıcı/hash/rastgelelik modülleri ve kaynak/hedef olarak
modellenen adlar hariç tutulur (onlar elle yazılmış modellerde). Çıktı:
``rules/taint/python-stdlib.json`` (biçim sniper-taint-models-v1, yalnız ``propagators``).

Kullanım: python3 scripts/generate_taint_models.py /yol/typeshed [--out rules/taint/python-stdlib.json]

``--thirdparty``: typeshed ``stubs/`` (üçüncü taraf paketler) için ``rules/taint/python-thirdparty.json``:
  * modül fonksiyonu yayıcıları (aynı dize kuralı; ``from .x import f as f`` yeniden dışa aktarımlarıyla),
  * ELLE doğrulanmış küçük hedef/arındırıcı listesi (``CURATED``; adlar typeshed'de bulunamazsa üretim durur),
  * ``returns``: çağrı → sınıf (ör. ``requests.Session`` → ``requests.sessions.Session``,
    ``psycopg2.connect`` → ``psycopg2._psycopg.connection``). Motor bununla alıcı türünü izler ve
    ``s = requests.Session(); s.get(u)`` çağrısını ``requests.sessions.Session.get`` olarak eşler.
  Dize döndüren her metot otomatik hedef SAYILMAZ; hedefler yalnız CURATED listesindendir.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys

STRINGY = {
    "str", "bytes", "bytearray", "AnyStr", "LiteralString", "StrPath", "BytesPath", "StrOrBytesPath",
    "GenericPath", "ReadableBuffer", "_StrType", "_AnyStr", "PathLike", "_PathLike", "SupportsRichComparisonT",
}
CONTAINERS = {"list", "List", "tuple", "Tuple", "Iterator", "Iterable", "Sequence", "Generator", "dict", "Dict",
              "Mapping", "set", "frozenset"}
EXCLUDED_MODULES = {
    "random", "secrets", "hashlib", "hmac", "uuid", "_random", "zlib", "binascii.crc32", "crypt", "ssl",
    "subprocess", "os.system", "pickle", "marshal", "shelve", "builtins", "typing", "abc", "ctypes",
    "_typeshed", "importlib", "socket", "select", "signal", "gc", "sys", "_thread", "threading",
}
EXCLUDED_NAMES = {"escape", "quote", "quote_plus", "quote_from_bytes", "basename", "normcase", "hexdigest",
                  "digest", "compare_digest", "getpass", "getuser", "gethostname", "mkdtemp", "mkstemp",
                  "gettempdir", "getcwd", "urandom", "token_hex"}


def _names(node: ast.AST | None) -> set[str]:
    found: set[str] = set()
    for child in ast.walk(node) if node is not None else ():
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.update(part.strip() for part in child.value.replace("[", " ").replace("]", " ").replace("|", " ").split())
    return found


def _stringy(node: ast.AST | None) -> bool:
    names = _names(node)
    return bool(names & STRINGY) and not (names - STRINGY - CONTAINERS - {"None", "Optional", "Union", "Literal", "int", "Self"})


def _module_name(stub: Path, root: Path) -> str:
    parts = list(stub.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def generate(typeshed: Path) -> list[str]:
    root = typeshed / "stdlib"
    propagators: set[str] = set()
    for stub in sorted(root.rglob("*.pyi")):
        module = _module_name(stub, root)
        if not module or any(module == m or module.startswith(m + ".") for m in EXCLUDED_MODULES) or module.startswith("_"):
            continue
        try:
            tree = ast.parse(stub.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name.startswith("_"):
                continue
            if node.name in EXCLUDED_NAMES or f"{module}.{node.name}" in EXCLUDED_MODULES:
                continue
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg is not None:
                args.append(node.args.vararg)
            if not any(_stringy(arg.annotation) for arg in args):
                continue
            if _stringy(node.returns):
                propagators.add(f"{module}.{node.name}")
    return sorted(propagators)


# ---------------------------------------------------------------------------
# Üçüncü taraf (typeshed stubs/)
# ---------------------------------------------------------------------------

# Elle doğrulanmış hedef ve arındırıcılar (typeshed imzalarına bakılarak; tanım yolu biçiminde).
CURATED: dict[str, list[dict]] = {
    "sinks": [
        {"kind": "ssrf", "names": [f"requests.sessions.Session.{m}" for m in
                                   ("get", "post", "put", "patch", "delete", "head", "options")],
         "args": [0], "keywords": ["url"]},
        {"kind": "ssrf", "names": ["requests.sessions.Session.request"], "args": [1], "keywords": ["url"]},
        {"kind": "ssrf", "names": ["httplib2.Http.request"], "args": [0], "keywords": ["uri"]},
        {"kind": "command", "names": ["paramiko.client.SSHClient.exec_command"], "args": [0], "keywords": ["command"]},
        {"kind": "command", "names": ["pexpect.pty_spawn.spawn", "pexpect.run.run", "pexpect.run.runu"],
         "args": [0], "keywords": ["command"]},
        {"kind": "sql", "names": ["peewee.Database.execute_sql"], "args": [0], "keywords": ["sql"]},
        {"kind": "ldap", "names": ["ldap3.core.connection.Connection.search"], "args": [1], "keywords": ["search_filter"]},
    ],
    "sanitizers": [
        {"names": ["psycopg2.sql.Literal", "psycopg2.sql.Identifier"], "kinds": ["sql"]},
        {"names": ["pymysql.converters.escape_string", "pymysql.converters.escape_str", "MySQLdb._mysql.escape_string"],
         "kinds": ["sql"]},
    ],
}
# Kendi tip bilgisini taşıyan (typeshed'de olmayan) paketler: elle doğrulanmış, belgelerine göre.
MANUAL: dict = {
    "sinks": [
        {"kind": "ssrf", "names": [f"httpx.{c}.{m}" for c in ("Client", "AsyncClient")
                                   for m in ("get", "post", "put", "patch", "delete", "head", "options", "stream")],
         "args": [0], "keywords": ["url"]},
        {"kind": "ssrf", "names": ["httpx.Client.request", "httpx.AsyncClient.request"], "args": [1], "keywords": ["url"]},
        {"kind": "sql", "names": ["*.exec_driver_sql"], "args": [0], "keywords": ["statement"]},
        {"kind": "eval", "names": ["jinja2.Environment.from_string", "jinja2.environment.Environment.from_string"],
         "args": [0], "keywords": ["source"]},
    ],
    "returns": {"httpx.Client": "httpx.Client", "httpx.AsyncClient": "httpx.AsyncClient",
                "jinja2.Environment": "jinja2.Environment", "jinja2.environment.Environment": "jinja2.Environment"},
}
SANITIZER_LIKE = ("escape", "quote", "clean", "sanitize", "safe", "hash", "digest", "encrypt", "sign")


class _Stubs:
    """typeshed stubs/ dizinindeki tüm paketlerin sembol tablosu (yalnız AST; kod çalıştırılmaz)."""

    def __init__(self, root: Path) -> None:
        self.functions: dict[str, ast.FunctionDef] = {}          # modül fonksiyonları (tanım yolu)
        self.classes: dict[str, ast.ClassDef] = {}
        self.methods: dict[str, list[ast.FunctionDef]] = {}      # Sınıf.metot → aşırı yüklemeler
        self.bases: dict[str, list[str]] = {}
        self.imports: dict[str, dict[str, str]] = {}             # modül → yerel ad → hedef yol
        self.module_of: dict[str, str] = {}                      # tanım yolu → modül
        for dist in sorted(p for p in root.iterdir() if p.is_dir()):
            for stub in sorted(dist.rglob("*.pyi")):
                if "@tests" in stub.parts:
                    continue
                module = _module_name(stub, dist)
                try:
                    tree = ast.parse(stub.read_text(encoding="utf-8"))
                except (SyntaxError, UnicodeDecodeError):
                    continue
                self._index(module, stub.name == "__init__.pyi", tree)
        for cls, node in self.classes.items():
            module = self.module_of[cls]
            self.bases[cls] = [b for b in (self.resolve(module, _dotted_name(base)) for base in node.bases) if b in self.classes]

    def _index(self, module: str, is_package: bool, tree: ast.Module) -> None:
        names = self.imports.setdefault(module, {})
        package = module if is_package else module.rpartition(".")[0]
        for node in _flat(tree.body):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(f"{module}.{node.name}", node)
                self.module_of[f"{module}.{node.name}"] = module
            elif isinstance(node, ast.ClassDef):
                path = f"{module}.{node.name}"
                self.classes[path] = node
                self.module_of[path] = module
                for item in _flat(node.body):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.methods.setdefault(f"{path}.{item.name}", []).append(item)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parts = package.split(".") if package else []
                    parts = parts[: len(parts) - (node.level - 1)] if node.level > 1 else parts
                    base = ".".join([*parts, *([node.module] if node.module else [])])
                for alias in node.names:
                    if alias.name != "*":
                        names[alias.asname or alias.name] = f"{base}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def resolve(self, module: str, name: str, depth: int = 0) -> str:
        """Modül ad alanındaki adı tanım yoluna çevir (yeniden dışa aktarımları izleyerek)."""
        if not name or depth > 8:
            return name
        head, _, rest = name.partition(".")
        local = f"{module}.{head}"
        if local in self.classes or local in self.functions:
            full = local
        elif head in self.imports.get(module, {}):
            full = self.imports[module][head]
        else:
            full = head
        full = f"{full}.{rest}" if rest else full
        return self.canonical(full, depth + 1)

    def canonical(self, path: str, depth: int = 0) -> str:
        """``paket.Ad`` (yeniden dışa aktarma) → tanım yolu; çözülemezse olduğu gibi."""
        if path in self.classes or path in self.functions or path in self.methods or depth > 8:
            return path
        parts = path.split(".")
        for cut in range(len(parts) - 1, 0, -1):
            module, name = ".".join(parts[:cut]), parts[cut]
            if module in self.imports and name in self.imports[module]:
                target = self.imports[module][name]
                if target != path:
                    return self.canonical(".".join([target, *parts[cut + 1:]]), depth + 1)
            if f"{module}.{name}" in self.classes and cut + 1 < len(parts):
                return ".".join(parts)  # Sınıf.metot
        return path

    def aliases(self) -> dict[str, set[str]]:
        """Tanım yolu → onu yeniden dışa aktaran genel adlar (ör. requests.sessions.Session → requests.Session)."""
        out: dict[str, set[str]] = {}
        for module, names in self.imports.items():
            for local, target in names.items():
                if local.startswith("_"):
                    continue
                full = self.canonical(target)
                if full in self.classes or full in self.functions:
                    out.setdefault(full, set()).add(f"{module}.{local}")
        return out

    def mro(self, cls: str) -> list[str]:
        seen, order, stack = set(), [], [cls]
        while stack:
            item = stack.pop(0)
            if item in seen:
                continue
            seen.add(item)
            order.append(item)
            stack.extend(self.bases.get(item, []))
        return order

    def method_owner(self, cls: str, name: str) -> str | None:
        for owner in self.mro(cls):
            if f"{owner}.{name}" in self.methods:
                return owner
        return None

    def exists(self, path: str) -> bool:
        path = self.canonical(path)
        if path in self.classes or path in self.functions:
            return True
        cls, _, name = path.rpartition(".")
        return cls in self.classes and self.method_owner(cls, name) is not None

    def return_class(self, module: str, nodes: list[ast.FunctionDef], owner: str | None) -> str | None:
        for node in nodes:
            ann = node.returns
            if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
                try:
                    ann = ast.parse(ann.value, mode="eval").body
                except SyntaxError:
                    continue
            name = _dotted_name(ann)
            if name in {"Self", "typing.Self", "typing_extensions.Self"} and owner:
                return owner
            if node.name == "__enter__" and owner:
                continue
            resolved = self.resolve(module, name) if name else ""
            if resolved in self.classes:
                return resolved
        return None


def _dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else ""
    if isinstance(node, ast.Subscript):
        return ""
    return ""


def _flat(body: list[ast.stmt]) -> list[ast.stmt]:
    """sys.version_info / TYPE_CHECKING koşullarının içindeki tanımlar da dahil."""
    out: list[ast.stmt] = []
    for node in body:
        if isinstance(node, ast.If):
            out.extend(_flat(node.body))
            out.extend(_flat(node.orelse))
        else:
            out.append(node)
    return out


def _is_propagator(node: ast.FunctionDef, *, method: bool = False) -> bool:
    if node.name.startswith("_") or node.name in EXCLUDED_NAMES or any(w in node.name.lower() for w in SANITIZER_LIKE):
        return False
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if method:
        args = args[1:]
    if node.args.vararg is not None:
        args.append(node.args.vararg)
    return any(_stringy(arg.annotation) for arg in args) and _stringy(node.returns)


def generate_thirdparty(typeshed: Path) -> dict:
    stubs = _Stubs(typeshed / "stubs")
    aliases = stubs.aliases()
    missing = [name for group in ("sinks", "sanitizers") for entry in CURATED[group] for name in entry["names"]
               if not stubs.exists(name)]
    if missing:
        raise SystemExit(f"CURATED adları typeshed'de bulunamadı: {', '.join(missing)}")

    def public(path: str) -> list[str]:
        """Tanım yolu + genel takma adları (sınıf takma adı altında metot da)."""
        names = {path}
        names.update(aliases.get(path, ()))
        cls, _, attr = path.rpartition(".")
        for alias in aliases.get(cls, ()):
            names.add(f"{alias}.{attr}")
        return sorted(names)

    # Hedef sınıfları ve alt sınıfları: Alt.metot adları da hedef (motor somut sınıf adını kurar).
    sink_classes: set[str] = set()
    sinks = []
    for entry in CURATED["sinks"]:
        names: set[str] = set()
        for name in entry["names"]:
            path = stubs.canonical(name)
            names.update(public(path))
            cls, _, attr = path.rpartition(".")
            if cls in stubs.classes:
                sink_classes.add(cls)
                for sub in stubs.classes:
                    if cls in stubs.mro(sub) and stubs.method_owner(sub, attr) == stubs.method_owner(cls, attr):
                        names.add(f"{sub}.{attr}")
                        sink_classes.add(sub)
        sinks.append({**entry, "names": sorted(names)})
    sanitizers = [{**entry, "names": sorted({n for name in entry["names"] for n in public(stubs.canonical(name))})}
                  for entry in CURATED["sanitizers"]]

    # İlginç sınıflar (sabit nokta): hedef sınıfları + ilginç sınıf döndüren metodu olan sınıflar.
    returns: dict[str, str] = {}
    interesting = set(sink_classes)
    changed = True
    while changed:
        changed = False
        for method, nodes in stubs.methods.items():
            cls = method.rpartition(".")[0]
            target = stubs.return_class(stubs.module_of[cls], nodes, cls)
            if target in interesting and cls not in interesting and not method.rpartition(".")[2].startswith("_"):
                interesting.add(cls)
                changed = True
    for cls in sorted(interesting):
        for name in public(cls):
            returns[name] = cls
        for sub in stubs.classes:
            pass
    for method, nodes in stubs.methods.items():
        cls, _, attr = method.rpartition(".")
        if cls not in interesting or (attr.startswith("_") and attr != "__enter__"):
            continue
        target = stubs.return_class(stubs.module_of[cls], nodes, cls)
        if target in interesting:
            returns[method] = target
    for function, node in stubs.functions.items():
        target = stubs.return_class(stubs.module_of[function], [node], None)
        if target in interesting and not function.rpartition(".")[2].startswith("_"):
            for name in public(function):
                returns[name] = target
    for name, target in MANUAL["returns"].items():
        returns[name] = target

    curated_names = {n for entry in sinks + sanitizers for n in entry["names"]}
    propagators: set[str] = set()
    for function, node in stubs.functions.items():
        module = stubs.module_of[function]
        if module.split(".")[-1].startswith("_") and not aliases.get(function):
            continue
        if _is_propagator(node):
            propagators.update(n for n in public(function) if n not in curated_names)
    for method, nodes in stubs.methods.items():
        cls = method.rpartition(".")[0]
        if cls in interesting and any(_is_propagator(node, method=True) for node in nodes):
            propagators.update(n for n in public(method) if n not in curated_names)
    return {
        "sinks": sinks + MANUAL["sinks"],
        "sanitizers": sanitizers,
        "propagators": sorted(propagators),
        "returns": dict(sorted(returns.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="typeshed'den taint yayıcı modelleri üret")
    parser.add_argument("typeshed", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "rules" / "taint" / "python-stdlib.json")
    parser.add_argument("--source-ref", default="")
    parser.add_argument("--thirdparty", action="store_true", help="stubs/ için python-thirdparty.json üret")
    args = parser.parse_args(argv)
    if args.thirdparty:
        out = args.out if args.out.name != "python-stdlib.json" else args.out.with_name("python-thirdparty.json")
        models = generate_thirdparty(args.typeshed)
        document = {
            "format": "sniper-taint-models-v1",
            "language": "python",
            "description": "typeshed stubs/ (üçüncü taraf) yayıcıları ve alıcı türleri otomatik; hedef/arındırıcılar "
                           "elle doğrulanmış CURATED/MANUAL listesinden (scripts/generate_taint_models.py --thirdparty). "
                           "Elle düzenlemeyin; yeniden üretin."
                           + (f" Kaynak: python/typeshed@{args.source_ref}." if args.source_ref else ""),
            **models,
        }
        out.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{len(models['propagators'])} yayıcı, {sum(len(s['names']) for s in models['sinks'])} hedef adı, "
              f"{sum(len(s['names']) for s in models['sanitizers'])} arındırıcı adı, {len(models['returns'])} dönüş türü → {out}")
        return 0
    names = generate(args.typeshed)
    document = {
        "format": "sniper-taint-models-v1",
        "language": "python",
        "description": "typeshed tip tanımlarından otomatik üretilmiş standart kütüphane yayıcıları "
                       "(scripts/generate_taint_models.py). Elle düzenlemeyin; yeniden üretin."
                       + (f" Kaynak: python/typeshed@{args.source_ref}." if args.source_ref else ""),
        "propagators": names,
    }
    args.out.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(names)} yayıcı → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
