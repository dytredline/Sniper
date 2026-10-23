"""Sunucu tarafı dil katmanı: HTML raporlarını ``?lang=...`` ile yerelleştirir.

Arayüzdeki ``static/i18n.js`` ile aynı TSV dil paketlerini ve aynı eşleştirme sırasını kullanır:
tam eşleşme → yer tutuculu kalıp → madde imi → tarih → çok cümleli metin → ayırıcıyla bölme.
Yalnız etiketler arasındaki metin ve title/aria-label/alt/placeholder öznitelikleri çevrilir;
script/style/code/pre içerikleri ve sözlükte olmayan veriler (dosya yolları, bulgu kanıtı) değişmez.

İngilizce temel/fallback pakettir; görünür arayüz dizgelerinin tamamını kapsadığı iddia edilmez.
Japonca, Korece ve Basitleştirilmiş Çince paketleri yerelleştirilmiş dizgeleri bunun üzerine yazar.
Seçili pakette bulunmayan metin, İngilizce girdisi varsa İngilizceye düşer; o da yoksa özgün Türkçe
kaynak metin korunur. Yeni bir dil eklemek için yalnız paket kaydı, TSV dosyası ve sözleşme testi gerekir.
"""
from __future__ import annotations

from functools import lru_cache
import html
from pathlib import Path
import re

STATIC_DIR = Path(__file__).resolve().parent / "static"
DICTIONARY_PATHS = {
    "en": STATIC_DIR / "i18n-en.tsv",
    "ja": STATIC_DIR / "i18n-ja.tsv",
    "ko": STATIC_DIR / "i18n-ko.tsv",
    "zh-CN": STATIC_DIR / "i18n-zh-CN.tsv",
}
DICTIONARY_PATH = DICTIONARY_PATHS["en"]  # geriye uyumlu dışa aktarım
SUPPORTED = frozenset({"tr", *DICTIONARY_PATHS})
_LANG_ALIASES = {
    "tr": "tr",
    "tr-tr": "tr",
    "en": "en",
    "en-us": "en",
    "en-gb": "en",
    "ja": "ja",
    "ja-jp": "ja",
    "ko": "ko",
    "ko-kr": "ko",
    "zh": "zh-CN",
    "zh-cn": "zh-CN",
    "zh-hans": "zh-CN",
    "zh-hans-cn": "zh-CN",
}
SEPARATORS = (": ", " · ", " — ", " → ", " | ", "; ")
_MONTHS = {"oca": "Jan", "şub": "Feb", "mar": "Mar", "nis": "Apr", "may": "May", "haz": "Jun",
           "tem": "Jul", "ağu": "Aug", "eyl": "Sep", "eki": "Oct", "kas": "Nov", "ara": "Dec"}
_MONTH_NUMBERS = {name: index for index, name in enumerate(_MONTHS, start=1)}
_DATE = re.compile(r"^(\d{1,2})[ .](Oca|Şub|Mar|Nis|May|Haz|Tem|Ağu|Eyl|Eki|Kas|Ara)[a-zçğıöşü]*\.?[ ](\d{4})(.*)$", re.I)
_SKIP_BLOCK = re.compile(r"(<(script|style|code|pre)\b[^>]*>.*?</\2\s*>)", re.S | re.I)
_ATTR = re.compile(r'(\s(?:title|aria-label|alt|placeholder)=")([^"]*)(")')
_HTML_LANG = re.compile(r'(<html\b[^>]*\blang=")[^"]*(")', re.I)
_SENTENCE_START = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZÇĞİÖŞÜ0123456789"“(')
_BULLET_MARKS = frozenset("•·—–-*")


def normalize_lang(value: str | None) -> str:
    value = (value or "tr").strip().replace("_", "-").lower()
    return _LANG_ALIASES.get(value, "tr")


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _bullet_parts(text: str) -> tuple[str, str] | None:
    """Split a supported bullet prefix from non-empty body text."""
    content = 0
    if text[:1] in _BULLET_MARKS:
        content = 1
    elif text.startswith("["):
        closing = text.find("]", 1)
        label = text[1:closing] if closing >= 0 else ""
        if label and all(char == "_" or "A" <= char <= "Z" or "a" <= char <= "z" for char in label):
            content = closing + 1
    if not content or content >= len(text) or not text[content].isspace():
        return None
    while content < len(text) and text[content].isspace():
        content += 1
    return (text[:content], text[content:]) if content < len(text) else None


def _markup_pieces(text: str) -> list[str]:
    """Split ``<...>`` tags and text in one forward pass."""
    pieces: list[str] = []
    cursor = 0
    while cursor < len(text):
        opening = text.find("<", cursor)
        if opening < 0:
            break
        closing = text.find(">", opening + 1)
        if closing < 0:
            break
        if opening > cursor:
            pieces.append(text[cursor:opening])
        pieces.append(text[opening:closing + 1])
        cursor = closing + 1
    if cursor < len(text):
        pieces.append(text[cursor:])
    return pieces


class Translator:
    def __init__(self, data: dict, locale: str = "en"):
        self.locale = locale
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
        punctuation = "..." if core.endswith("...") else core[-1:] if core.endswith((":", "…", "—", "–")) else ""
        if punctuation:
            split = len(core) - len(punctuation)
            while split and core[split - 1].isspace():
                split -= 1
            prefix = core[:split]
            if prefix and prefix in self.strings:
                return self.strings[prefix] + core[split:]
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
        parts: list[str] = []
        start = 0
        index = 0
        while index < len(core):
            if not core[index].isspace():
                index += 1
                continue
            end = index + 1
            while end < len(core) and core[end].isspace():
                end += 1
            if index and core[index - 1] in ".!?" and end < len(core) and core[end] in _SENTENCE_START:
                parts.append(core[start:index])
                start = end
            index = end
        parts.append(core[start:])
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
            bullet = _bullet_parts(core)
            if bullet:
                prefix, body = bullet
                inner = self.core(body, depth)
                if inner is not None:
                    hit = prefix + inner
        if hit is None:
            d = _DATE.match(core)
            if d and d.group(2).lower() in _MONTHS:
                month_key = d.group(2).lower()
                month_number = _MONTH_NUMBERS[month_key]
                if self.locale in {"ja", "zh-CN"}:
                    hit = f"{d.group(3)}年{month_number}月{d.group(1)}日{d.group(4)}"
                elif self.locale == "ko":
                    hit = f"{d.group(3)}년 {month_number}월 {d.group(1)}일{d.group(4)}"
                else:
                    hit = f"{d.group(1)} {_MONTHS[month_key]} {d.group(3)}{d.group(4)}"
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


def _merged_dictionary(locale: str) -> dict:
    """Return the English base with locale overrides, keyed by Turkish source text."""
    base = parse_dictionary(DICTIONARY_PATHS["en"].read_text(encoding="utf-8"))
    if locale == "en":
        return base
    overlay = parse_dictionary(DICTIONARY_PATHS[locale].read_text(encoding="utf-8"))
    strings = dict(base["strings"])
    strings.update(overlay["strings"])

    patterns = dict(base["patterns"])
    patterns.update(dict(overlay["patterns"]))
    fragments = dict(base["fragments"])
    fragments.update(dict(overlay["fragments"]))
    return {
        "strings": strings,
        "patterns": list(patterns.items()),
        "fragments": list(fragments.items()),
    }


@lru_cache(maxsize=len(DICTIONARY_PATHS))
def translator(lang: str = "en") -> Translator:
    locale = normalize_lang(lang)
    if locale == "tr":
        locale = "en"
    return Translator(_merged_dictionary(locale), locale=locale)


def _translate_markup(chunk: str, tr: Translator) -> str:
    out = []
    for piece in _markup_pieces(chunk):
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
    """HTML belgeyi desteklenen dile çevirir; ``tr`` için belge değişmeden döner."""
    locale = normalize_lang(lang)
    if locale == "tr":
        return document
    tr = translator(locale)
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
    return _HTML_LANG.sub(lambda match: f'{match.group(1)}{locale}{match.group(2)}', "".join(out))
