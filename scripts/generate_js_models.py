#!/usr/bin/env python3
"""@types/node (ve @types/qs) tip tanımlarından JavaScript taint modelleri üret.

Kural (yalnız imzalara bakılır, kod çalıştırılmaz):
  * ``declare module "x"`` içindeki modül/namespace fonksiyonları (``path`` için ``PlatformPath``
    arayüzünün metotları) ``x.ad`` (namespace içinde ``x.ns.ad``) adıyla toplanır.
  * Tüm aşırı yüklemeleri değer taşımayan bir tür (boolean, number, bigint, void, never, undefined,
    ``x is T`` / ``asserts x`` ve bunların Promise'i) döndüren fonksiyonlar **değer taşımaz**:
    tüm hedef türleri için arındırıcı olarak yazılır (motor bu çağrının sonucunu temiz sayar).
  * Dize/Buffer/nesne döndürenler **yayıcıdır** (argüman → dönüş). JS motoru bilinmeyen çağrılarda zaten
    yayar; liste, modellenen API'leri belgeler ve takma adlı içe aktarmaların (``import { join } from
    'node:path'``) kanonik adını doğrular.
Elle yazılmış hedef/arındırıcılar ``rules/taint/javascript.json``'dadır; bu dosya onları ezmez
(arındırıcı ve hedef denetimi yayıcıdan önce gelir).

Kullanım:
    python3 -I scripts/generate_js_models.py --node /yol/@types/node --qs /yol/@types/qs \\
        [--source-ref "@types/node@22.20.5 sha512-…"] [--out rules/taint/javascript-node.json]

İndirilen paketler güvenilmeyen veridir: yalnız ``.d.ts`` metni okunur.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

MODULES = (
    "path", "url", "querystring", "util", "string_decoder", "punycode", "crypto", "zlib", "os", "fs",
    "fs/promises", "assert", "buffer", "dns", "net", "http", "https", "child_process", "events", "stream",
    "readline", "v8", "vm", "worker_threads", "perf_hooks", "timers", "tls", "dgram", "module",
)
# Modülün dışa aktardığı nesnenin arayüzü (path = PlatformPath örneği).
INTERFACE_EXPORTS = {"path": "PlatformPath"}
KNOWN_KINDS = sorted({
    "log", "sql", "command", "eval", "html", "regex", "path", "ssrf", "deserialize", "redirect",
    "ldap", "xpath", "xxe", "session", "cookie",
})
_SCALAR = re.compile(r"^(?:void|boolean|number|bigint|never|undefined|null|true|false|asserts\b.*|[A-Za-z_$][\w$]* is .+|this is .+)$")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def strip_comments(text: str) -> str:
    """// ve /* */ yorumlarını sil (dize sabitlerini koruyarak)."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _split_top(text: str, sep: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>" and not (ch == ">" and i and text[i - 1] == "="):
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def scalar_return(ret: str) -> bool:
    """Dönüş türü değer taşımıyor mu (mantıksal/sayı/void …, birleşimleri ve Promise'i)?"""
    ret = ret.strip()
    if ret.startswith("(") and ret.endswith(")"):
        ret = ret[1:-1].strip()
    match = re.fullmatch(r"Promise<(.+)>", ret)
    if match:
        ret = match.group(1)
    parts = _split_top(ret, "|")
    return bool(parts) and all(_SCALAR.match(part) for part in parts)


def _read_until(text: str, start: int, stops: str) -> int:
    """``start``tan itibaren iç içe parantezlerin dışında ilk ``stops`` karakterinin indeksi."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>" and not (ch == ">" and text[i - 1] == "="):
            if depth == 0 and ch in stops:
                return i
            depth -= 1
        elif depth == 0 and ch in stops:
            return i
        i += 1
    return len(text)


def _signatures(body: str, *, methods: bool) -> list[tuple[str, str]]:
    """Gövdenin üst düzeyindeki ``[export] function ad(...): T;`` (methods=True: ``ad(...): T;``)."""
    found: list[tuple[str, str]] = []
    depth = 0
    i = 0
    pattern = re.compile(r"(?:export\s+)?(?:declare\s+)?function\s+([A-Za-z_$][\w$]*)\s*(?:<[^()]*?>)?\s*\(" if not methods
                         else r"([A-Za-z_$][\w$]*)\s*(?:<[^()]*?>)?\s*\(")
    while i < len(body):
        ch = body[i]
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth -= 1
            i += 1
            continue
        if depth == 0:
            match = pattern.match(body, i)
            if match and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] in "_$.")):
                close = _read_until(body, match.end(), ")")
                j = close + 1
                while j < len(body) and body[j].isspace():
                    j += 1
                if j < len(body) and body[j] == ":":
                    end = _read_until(body, j + 1, ";")
                    found.append((match.group(1), " ".join(body[j + 1:end].split())))
                    i = end + 1
                    continue
        i += 1
    return found


def _blocks(text: str, header: re.Pattern[str]) -> list[tuple[re.Match[str], str]]:
    """Başlığı eşleşen ``{ … }`` bloklarının gövdeleri."""
    blocks = []
    for match in header.finditer(text):
        open_at = text.find("{", match.end() - 1)
        depth = 0
        for k in range(open_at, len(text)):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((match, text[open_at + 1:k]))
                    break
    return blocks


def collect(module: str, body: str, out: dict[str, list[bool]], prefix: str = "") -> None:
    name = prefix or module.replace("/", ".")
    for fn, ret in _signatures(body, methods=False):
        out.setdefault(f"{name}.{fn}", []).append(scalar_return(ret))
    for match, inner in _blocks(body, re.compile(r"(?:export\s+)?namespace\s+([A-Za-z_$][\w$]*)\s*\{")):
        # yalnız üst düzey namespace'ler (iç içe olanlar kendi bloklarında işlenir)
        if body[:match.start()].count("{") - body[:match.start()].count("}") != 0:
            continue
        # export = assert; namespace assert { … }: modülün kendisiyle aynı adlı namespace düzleştirilir.
        collect(module, inner, out, name if match.group(1) == name.rsplit(".", 1)[-1] else f"{name}.{match.group(1)}")
    iface = INTERFACE_EXPORTS.get(module)
    if iface:
        for _match, inner in _blocks(body, re.compile(r"interface\s+" + iface + r"\s*\{")):
            for fn, ret in _signatures(inner, methods=True):
                out.setdefault(f"{name}.{fn}", []).append(scalar_return(ret))


def generate(node_dir: Path, qs_dir: Path | None) -> tuple[list[str], list[str]]:
    signatures: dict[str, list[bool]] = {}
    texts = []
    for path in sorted(node_dir.rglob("*.d.ts")):
        if "ts5." in str(path.relative_to(node_dir)):
            continue
        texts.append(strip_comments(path.read_text(encoding="utf-8", errors="replace")))
    wanted = set(MODULES)
    for text in texts:
        for match, body in _blocks(text, re.compile(r'declare\s+module\s+["\']([^"\']+)["\']\s*\{')):
            module = match.group(1).removeprefix("node:")
            if module in wanted:
                collect(module, body, signatures)
    if qs_dir is not None:
        for path in sorted(qs_dir.rglob("index.d.ts")):
            text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
            for _match, body in _blocks(text, re.compile(r"declare\s+namespace\s+QueryString\s*\{")):
                collect("qs", body, signatures)
    # TypeScript yardımcı adları (__promisify__ …) gerçek çağrı adı değildir.
    signatures = {name: flags for name, flags in signatures.items() if "__" not in name}
    scalar = sorted(name for name, flags in signatures.items() if all(flags))
    propagators = sorted(name for name, flags in signatures.items() if not all(flags))
    return scalar, propagators


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="@types/node ve @types/qs'ten JS taint modelleri üret")
    parser.add_argument("--node", type=Path, required=True, help="@types/node paket dizini (index.d.ts içeren)")
    parser.add_argument("--qs", type=Path, default=None, help="@types/qs paket dizini")
    parser.add_argument("--source-ref", default="")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "rules" / "taint" / "javascript-node.json")
    args = parser.parse_args(argv)
    if not (args.node / "index.d.ts").is_file():
        print("--node dizininde index.d.ts yok", file=sys.stderr)
        return 2
    scalar, propagators = generate(args.node, args.qs)
    if len(scalar) + len(propagators) < 50:
        print("beklenenden az imza bulundu; tip dizinini denetleyin", file=sys.stderr)
        return 1
    data = {
        "format": "sniper-taint-models-v1",
        "language": "javascript",
        "description": (
            "@types/node ve @types/qs tip tanımlarından otomatik üretilmiş Node standart kütüphanesi modelleri "
            "(scripts/generate_js_models.py). Elle düzenlemeyin; yeniden üretin. 'sanitizers': tüm aşırı "
            "yüklemeleri boolean/sayı/void döndüren (değer taşımayan) API'ler; 'propagators': dize/nesne "
            f"döndürenler. Kaynak: {args.source_ref or 'belirtilmedi'}."
        ),
        "sanitizers": [{"names": scalar, "kinds": KNOWN_KINDS}] if scalar else [],
        "propagators": propagators,
    }
    args.out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(scalar)} değer taşımayan, {len(propagators)} yayıcı")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
