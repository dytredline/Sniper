"""Sunucu tarafı dil katmanı: HTML raporlarını `?lang=en` ile İngilizce verir.

Arayüzdeki `static/i18n.js` ile aynı sözlüğü (`static/i18n-en.tsv`) ve aynı eşleştirme sırasını kullanır:
tam eşleşme → yer tutuculu kalıp → madde imi → tarih → çok cümleli metin → ayırıcıyla bölme.
Yalnız etiketler arasındaki metin ve title/aria-label/alt/placeholder öznitelikleri çevrilir;
script/style/code/pre içerikleri ve sözlükte olmayan veriler (dosya yolları, bulgu kanıtı) değişmez.
"""
from __future__ import annotations

from functools import lru_cache
import html
from pathlib import Path
import re

DICTIONARY_PATH = Path(__file__).resolve().parent / "static" / "i18n-en.tsv"
SUPPORTED = frozenset({"tr", "en"})
SEPARATORS = (": ", " · ", " — ", " → ", " | ", "; ")
_BULLET = re.compile(r"^([•·—–\-*]\s+|\[[A-Za-z_]+\]\s+)(.+)$", re.S)  # 22. tur: küçük harfli [critical] önekleri de
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-ZÇĞİÖŞÜ0-9\"“(])")
_MONTHS = {"oca": "Jan", "şub": "Feb", "mar": "Mar", "nis": "Apr", "may": "May", "haz": "Jun",
           "tem": "Jul", "ağu": "Aug", "eyl": "Sep", "eki": "Oct", "kas": "Nov", "ara": "Dec"}
_DATE = re.compile(r"^(\d{1,2})[ .](Oca|Şub|Mar|Nis|May|Haz|Tem|Ağu|Eyl|Eki|Kas|Ara)[a-zçğıöşü]*\.?[ ](\d{4})(.*)$", re.I)
_SKIP_BLOCK = re.compile(r"(<(script|style|code|pre)\b[^>]*>.*?</\2\s*>)", re.S | re.I)
_TAG_OR_TEXT = re.compile(r"(<[^>]*>)")
_ATTR = re.compile(r'(\s(?:title|aria-label|alt|placeholder)=")([^"]*)(")')
_HTML_LANG = re.compile(r'(<html\b[^>]*\blang=")tr(")', re.I)


def normalize_lang(value: str | None) -> str:
    value = (value or "tr").strip().lower()
    return value if value in SUPPORTED else "tr"


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


class Translator:
    def __init__(self, data: dict):
        self.strings: dict[str, str] = dict(data.get("strings") or {})
        self.patterns = sorted((self._compile(src, dst) for src, dst in data.get("patterns") or []),
                               key=lambda p: -p["weight"])
        self._keys: list[str] | None = None
        self.fragments = sorted(((str(a), str(b)) for a, b in data.get("fragments") or []), key=lambda f: -len(f[0]))

    @staticmethod
    def _compile(source: str, target: str) -> dict:
        source = _normalize(source)
        parts = re.split(r"(\{\d+\})", source)
        names, literal, body = [], "", ""
        for part in parts:
            m = re.fullmatch(r"\{(\d+)\}", part)
            if m:
                names.append(m.group(1))
                body += "\0"
            else:
                literal += part
                body += re.escape(part)
        short = len(re.sub(r"[\s·:.,()/%-]", "", literal)) < 4
        group = r"([-+\d.,:%/ ]*?)" if short else r"([\s\S]*?)"
        regex = re.compile("^" + body.replace("\0", group) + "$")
        first, last = parts[0], parts[-1]
        return {"prefix": "" if re.fullmatch(r"\{\d+\}", first or "x") else first,
                "suffix": "" if re.fullmatch(r"\{\d+\}", last or "x") else last,
                "re": regex, "names": names, "out": target, "weight": len(literal)}

    def exact(self, core: str) -> str | None:
        hit = self.strings.get(core)
        if hit is not None:
            return hit
        m = re.match(r"^(.*?)(\s*(?:[:…—–]|\.\.\.))$", core, re.S)
        if m and m.group(1) and m.group(1) in self.strings:
            return self.strings[m.group(1)] + m.group(2)
        return None

    def pattern(self, core: str, depth: int) -> str | None:
        for p in self.patterns:
            if p["prefix"] and not core.startswith(p["prefix"]):
                continue
            if p["suffix"] and not core.endswith(p["suffix"]):
                continue
            m = p["re"].match(core)
            if not m:
                continue
            values = {}
            for i, name in enumerate(p["names"]):
                raw = m.group(i + 1)
                value = _normalize(raw)
                inner = self.core(value, depth + 1) if value and depth < 3 else None
                values[name] = raw if inner is None else inner
            return re.sub(r"\{(\d+)\}", lambda mm: values.get(mm.group(1), ""), p["out"])
        return None

    def sentences(self, core: str) -> str | None:
        parts = _SENTENCE.split(core)
        if len(parts) < 2:
            return None
        out, i, changed = [], 0, 0
        while i < len(parts):
            for j in range(len(parts), i, -1):
                hit = self.exact(" ".join(parts[i:j]))
                if hit is not None:
                    out.append(hit)
                    i, changed = j, changed + 1
                    break
            else:
                out.append(parts[i])
                i += 1
        return " ".join(out) if changed else None

    def truncated(self, core: str) -> str | None:
        """"Kullanıcı / istemci…" gibi kırpılmış etiketler (static/i18n.js lookupTruncated ile aynı): önekiyle
        başlayan tek sözlük girdisi varsa çevirisi aynı uzunlukta kırpılır."""
        if not core.endswith("…") or len(core) < 8:
            return None
        head = core[:-1]
        if self._keys is None:
            self._keys = list(self.strings)
        hits = [k for k in self._keys if len(k) > len(head) and k.startswith(head)]
        if len(hits) != 1:
            return None
        full = self.strings[hits[0]]
        return full[: max(len(head), 6)].rstrip() + "…" if len(full) > len(head) + 1 else full

    def comma_list(self, core: str, depth: int) -> str | None:
        """Virgüllü liste ("14 kritik, 19 yüksek"): yalnız her öğe çevrilebiliyorsa öğe öğe (i18n.js ile aynı; 22. tur)."""
        if depth >= 3 or ", " not in core:
            return None
        out = []
        for part in core.split(", "):
            part = part.strip()
            # Öğe yalnız tam eşleşme ya da kalıpla ve Türkçe harf kalmadan çevrilirse kabul edilir; cümle/ayırıcı ile
            # kısmi çeviri sayılmaz (yoksa "İzinli hedef, seçili …" gibi sözlükte tam karşılığı olan metinleri bölerdi).
            t = (self.exact(part) or self.pattern(part, depth + 1)) if part else None
            if t is None or re.search(r"[çğıöşüÇĞİÖŞÜ]", t):
                return None
            out.append(t)
        return ", ".join(out) if len(out) >= 2 else None

    def core(self, core: str, depth: int = 0) -> str | None:
        hit = self.exact(core)
        if hit is None:
            hit = self.comma_list(core, depth)
        if hit is None:
            hit = self.pattern(core, depth)
        if hit is None:
            b = _BULLET.match(core)
            if b:
                inner = self.core(b.group(2), depth)
                if inner is not None:
                    hit = b.group(1) + inner
        if hit is None:
            d = _DATE.match(core)
            if d and d.group(2).lower() in _MONTHS:
                hit = f"{d.group(1)} {_MONTHS[d.group(2).lower()]} {d.group(3)}{d.group(4)}"
        if hit is None:
            hit = self.sentences(core)
        if hit is None:
            hit = self.truncated(core)
        if hit is None and depth < 3:
            best, best_count = None, 0
            for sep in SEPARATORS:
                if sep not in core:
                    continue
                count, pieces = 0, []
                for piece in core.split(sep):
                    trimmed = piece.strip()
                    t = self.core(trimmed, depth + 1) if trimmed else None
                    if t is None:
                        pieces.append(piece)
                    else:
                        count += 1
                        pieces.append(piece.replace(trimmed, t, 1))
                if count > best_count:
                    best, best_count = sep.join(pieces), count
            hit = best
        return hit

    def fragments_applied(self, hit: str | None, core: str) -> str | None:
        """Çevrilemeyen ya da Türkçe kalan serbest metinde yalnız sözlükteki kanıt parçalarını (F) değiştirir."""
        base = core if hit is None else hit
        if not self.fragments or not re.search(r"[çğıöşüÇĞİÖŞÜ]", base):
            return hit
        out = base
        for src, dst in self.fragments:
            if src in out:
                out = out.replace(src, dst)
        return hit if out == base else out

    def text(self, text: str) -> str:
        """Türkçe metni çevirir; çeviri yoksa metni aynen döndürür (baştaki/sondaki boşluk korunur)."""
        core = _normalize(text)
        if not core or not re.search(r"[A-Za-zÇĞİÖŞÜçğıöşü]", core):
            return text
        hit = self.fragments_applied(self.core(core), core)
        if hit is None or hit == core:
            return text
        lead = text[: len(text) - len(text.lstrip())]
        trail = text[len(text.rstrip()):]
        return lead + hit + trail


def parse_dictionary(text: str) -> dict:
    """Sekmeyle ayrılmış sözlük: 'S<TAB>tr<TAB>en' tam metin, 'P<TAB>tr<TAB>en' kalıp, 'F<TAB>tr<TAB>en' kanıt parçası; '#' başlık."""
    data: dict = {"strings": {}, "patterns": [], "fragments": []}
    for line in text.split("\n"):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not fields[1]:
            continue
        if fields[0] == "S":
            data["strings"][fields[1]] = fields[2]
        elif fields[0] == "P":
            data["patterns"].append((fields[1], fields[2]))
        elif fields[0] == "F":
            data["fragments"].append((fields[1], fields[2]))
    return data


@lru_cache(maxsize=1)
def translator() -> Translator:
    return Translator(parse_dictionary(DICTIONARY_PATH.read_text(encoding="utf-8")))


def _translate_markup(chunk: str, tr: Translator) -> str:
    out = []
    for piece in _TAG_OR_TEXT.split(chunk):
        if not piece:
            continue
        if piece.startswith("<"):
            out.append(_ATTR.sub(lambda m: m.group(1) + html.escape(tr.text(html.unescape(m.group(2))), quote=True) + m.group(3), piece))
        else:
            raw = html.unescape(piece)
            translated = tr.text(raw)
            out.append(piece if translated == raw else html.escape(translated, quote=False))
    return "".join(out)


def localize_html(document: str, lang: str | None) -> str:
    """HTML belgeyi istenen dile çevirir; 'tr' (varsayılan) için belge değişmeden döner."""
    if normalize_lang(lang) != "en":
        return document
    tr = translator()
    parts = _SKIP_BLOCK.split(document)
    out = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if _SKIP_BLOCK.fullmatch(part or ""):
            out.append(part)
            i += 2  # yakalanan etiket adı grubunu atla
            continue
        out.append(_translate_markup(part, tr))
        i += 1
    return _HTML_LANG.sub(r"\1en\2", "".join(out))
