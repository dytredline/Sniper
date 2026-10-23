"""Bağımlılık lisans uyumu (çevrimdışı).

Lisans bilgisi yalnız proje dizinindeki yerel dosyalardan okunur; ağ erişimi yoktur:

* npm: ``package-lock.json`` paket kayıtlarındaki ``license`` alanı, kurulu ``node_modules/*/package.json``
  (``license`` / eski ``licenses`` dizisi); kök ``package.json`` projenin kendi lisansıdır.
* Python: proje içindeki sanal ortamların ``*.dist-info/METADATA`` dosyaları (``License-Expression``,
  ``License``, ``Classifier: License ::``); ``pyproject.toml`` projenin lisansıdır.
* Rust: ``Cargo.toml`` (proje) ve ``vendor/*/Cargo.toml`` (``cargo vendor``).
* Go: ``vendor/modules.txt`` modüllerinin ``LICENSE`` dosyaları (metin sezgisi).
* Java: ``pom.xml`` ``<licenses>`` (proje).  PHP: ``composer.lock`` paketleri, ``composer.json`` (proje).
* Ruby: ``*.gemspec`` (proje) ve ``vendor/bundle/**/specifications/*.gemspec``.
* Kökteki ``LICENSE``/``COPYING`` metni sezgiyle tanınır.
* 20. tur — yerel paket önbellekleri (yalnız okunur, koordinatla hesaplanan tam yol, ağ yok):
  Maven ``~/.m2/repository`` (pom ``<licenses>``, üst pom zinciri), Cargo ``~/.cargo/registry/src``,
  NuGet ``~/.nuget/packages`` (``.nuspec``), Go modül önbelleği (açılmış dizin ya da ``cache/download`` zip'i),
  kurulu RubyGems ``specifications``. Alt dizinlerdeki ``composer.lock`` ve projedeki üst ``pom.xml`` de okunur.
  ``SNIPER_LICENSE_CACHE_HOME`` boş verilirse önbellekler kullanılmaz (testler böyle çalışır).

Lisans adları SPDX kimliklerine normalleştirilir; ``A OR B`` ifadesinde en uygun, ``A AND B`` ifadesinde en
kısıtlayıcı seçenek esas alınır. Politika (izinli / dikkat / yasak) kullanıcı tarafından değiştirilebilir ve
``$SNIPER_DATA_DIR/license-policy.json`` (0600) dosyasında saklanır. Tanınmayan ya da bulunamayan lisans
"inceleme" sayılır. Bu bir hukuki görüş değildir; dağıtım biçimine göre yükümlülük değişir.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Iterable

from safe_file_read import read_bytes_bounded

FORMAT = "sniper-license-report-v1"
POLICY_FORMAT = "sniper-license-policy/1"
POLICY_FILE = "license-policy.json"
CATEGORIES = ("allowed", "caution", "review", "denied")
CATEGORY_LABELS = {"allowed": "İzinli", "caution": "Dikkat", "review": "İnceleme", "denied": "Yasak"}
_RANK = {"allowed": 0, "caution": 1, "review": 2, "denied": 3}
MAX_FILE_BYTES = 256 * 1024
MAX_LICENSE_TEXT = 64 * 1024
MAX_READS = 12_000
MAX_ITEMS_REPORTED = 300
MAX_PATTERNS = 200
_PATTERN_RE = re.compile(r"[A-Za-z0-9.+\-* ]{1,100}\Z")

# Varsayılan politika: izin verici ve zayıf copyleft lisanslar izinli; güçlü copyleft, ağ copyleft'i ve
# kaynak-erişilebilir (ticari kısıtlı) lisanslar "dikkat". Yasak listesi boş: kuruma göre doldurulur.
DEFAULT_POLICY: dict[str, Any] = {
    "format": POLICY_FORMAT,
    "allowed": [
        "MIT", "MIT-0", "Apache-2.0", "Apache-1.1", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "0BSD",
        "ISC", "Zlib", "Unlicense", "CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "PSF-2.0", "Python-2.0", "Python-2.0.1",
        "BSL-1.0", "BlueOak-1.0.0", "Unicode-DFS-2016", "Unicode-3.0", "X11", "curl", "NCSA", "UPL-1.0", "WTFPL",
        "OFL-1.1", "Artistic-2.0", "Ruby", "PHP-3.01", "MulanPSL-2.0", "AFL-2.1", "AFL-3.0", "PostgreSQL",
        "LicenseRef-Public-Domain", "LGPL-*", "MPL-*", "EPL-*", "CDDL-*",
        "GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0-or-later WITH Classpath-exception-2.0",
    ],
    "caution": ["GPL-*", "AGPL-*", "SSPL-*", "EUPL-*", "OSL-*", "CC-BY-SA-*", "CC-BY-NC*", "CC-BY-ND-*",
                "BUSL-*", "Elastic-2.0", "JSON", "Hippocratic-*", "LicenseRef-Commons-Clause"],
    "denied": [],
}

_KNOWN_IDS = {
    "MIT", "MIT-0", "Apache-2.0", "Apache-1.1", "Apache-1.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
    "BSD-4-Clause", "0BSD", "ISC", "Zlib", "Unlicense", "CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-SA-3.0",
    "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0", "PSF-2.0", "Python-2.0", "Python-2.0.1",
    "BSL-1.0", "BlueOak-1.0.0", "Unicode-DFS-2016", "Unicode-3.0", "X11", "curl", "NCSA", "UPL-1.0", "WTFPL",
    "OFL-1.1", "Artistic-1.0", "Artistic-2.0", "Ruby", "PHP-3.0", "PHP-3.01", "MulanPSL-2.0", "AFL-2.1", "AFL-3.0",
    "PostgreSQL", "MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL-2.0-no-copyleft-exception", "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1", "EUPL-1.1", "EUPL-1.2", "OSL-3.0", "SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "JSON",
    "Hippocratic-2.1", "Beerware", "OpenSSL", "Vim", "Zlib-acknowledgement", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "GPL-1.0-only", "GPL-1.0-or-later",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-1.0-only", "AGPL-1.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "Classpath-exception-2.0", "GCC-exception-3.1", "LLVM-exception",
    "Autoconf-exception-3.0", "Bison-exception-2.2",
}
_CANON = {item.casefold(): item for item in _KNOWN_IDS}
# Eski SPDX kimlikleri (+ ile) ve yaygın serbest yazımlar → SPDX.
_DEPRECATED = {
    "gpl-1.0": "GPL-1.0-only", "gpl-1.0+": "GPL-1.0-or-later", "gpl-2.0": "GPL-2.0-only", "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-3.0": "GPL-3.0-only", "gpl-3.0+": "GPL-3.0-or-later", "lgpl-2.0": "LGPL-2.0-only", "lgpl-2.0+": "LGPL-2.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only", "lgpl-2.1+": "LGPL-2.1-or-later", "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0+": "LGPL-3.0-or-later", "agpl-3.0": "AGPL-3.0-only", "agpl-3.0+": "AGPL-3.0-or-later",
    "agpl-1.0": "AGPL-1.0-only", "gpl-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
}
_ALIASES = {
    "mit license": "MIT", "the mit license": "MIT", "mit licence": "MIT", "expat": "MIT", "mit/x11": "MIT",
    "mit no attribution": "MIT-0",
    "apache": "Apache-2.0", "apache 2": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0",
    "apache2": "Apache-2.0", "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0", "apache software license": "Apache-2.0", "asl 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0", "apache license (2.0)": "Apache-2.0", "apache-2.0 license": "Apache-2.0",
    "the apache software license, version 2.0": "Apache-2.0", "the apache license, version 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "new bsd": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "3-clause bsd": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause", "modified bsd": "BSD-3-Clause", "revised bsd": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause", "simplified bsd": "BSD-2-Clause", "2-clause bsd": "BSD-2-Clause", "freebsd": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause", "bsd 2-clause license": "BSD-2-Clause",
    "isc license": "ISC", "isc license (iscl)": "ISC", "zlib license": "Zlib", "zlib/libpng": "Zlib",
    "the unlicense": "Unlicense", "unlicense": "Unlicense", "the unlicense (unlicense)": "Unlicense",
    "public domain": "LicenseRef-Public-Domain", "cc0": "CC0-1.0", "cc0 1.0 universal": "CC0-1.0",
    "psf": "PSF-2.0", "psfl": "PSF-2.0", "python software foundation license": "PSF-2.0", "psf license": "PSF-2.0",
    "boost software license": "BSL-1.0", "boost software license 1.0 (bsl-1.0)": "BSL-1.0", "boost": "BSL-1.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl 2.0": "MPL-2.0", "mpl-2": "MPL-2.0", "mpl2": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0", "mozilla public license 1.1 (mpl 1.1)": "MPL-1.1",
    "eclipse public license 2.0": "EPL-2.0", "eclipse public license 1.0": "EPL-1.0", "epl 2.0": "EPL-2.0",
    "eclipse public license - v 2.0": "EPL-2.0", "eclipse public license - v 1.0": "EPL-1.0",
    "cddl": "CDDL-1.0", "common development and distribution license 1.0 (cddl-1.0)": "CDDL-1.0",
    "gpl": "GPL-1.0-or-later", "gnu gpl": "GPL-1.0-or-later", "gnu general public license (gpl)": "GPL-1.0-or-later",
    "gplv2": "GPL-2.0-only", "gpl v2": "GPL-2.0-only", "gpl-2": "GPL-2.0-only", "gpl2": "GPL-2.0-only",
    "gnu gpl v2": "GPL-2.0-only", "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later", "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-only", "gpl v3": "GPL-3.0-only", "gpl-3": "GPL-3.0-only", "gpl3": "GPL-3.0-only",
    "gnu gpl v3": "GPL-3.0-only", "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later", "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "lgpl": "LGPL-2.0-or-later", "gnu lesser general public license (lgpl)": "LGPL-2.0-or-later",
    "gnu library or lesser general public license (lgpl)": "LGPL-2.0-or-later", "lgplv2": "LGPL-2.0-only",
    "lgplv2+": "LGPL-2.0-or-later", "lgplv2.1": "LGPL-2.1-only", "lgpl-2.1+": "LGPL-2.1-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "lgplv3": "LGPL-3.0-only", "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later", "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "agpl": "AGPL-3.0-or-later", "agplv3": "AGPL-3.0-only", "agpl v3": "AGPL-3.0-only", "agpl-3": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only", "agplv3+": "AGPL-3.0-or-later",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "sspl": "SSPL-1.0", "server side public license": "SSPL-1.0", "elastic license 2.0": "Elastic-2.0",
    "business source license 1.1": "BUSL-1.1", "bsl 1.1": "BUSL-1.1", "commons clause": "LicenseRef-Commons-Clause",
    "eupl 1.2": "EUPL-1.2", "european union public licence 1.2 (eupl 1.2)": "EUPL-1.2",
    "artistic license 2.0": "Artistic-2.0", "the perl 5 license (artistic 1 & gpl 1)": "Artistic-1.0 OR GPL-1.0-or-later",
    "python software foundation": "PSF-2.0", "historical permission notice and disclaimer (hpnd)": "LicenseRef-HPND",
    "wtfpl": "WTFPL", "universal permissive license 1.0 (upl-1.0)": "UPL-1.0", "blue oak model license 1.0.0": "BlueOak-1.0.0",
}
_NO_LICENSE = {"", "unknown", "none", "noassertion", "n/a", "na", "other", "other/proprietary license", "proprietary",
               "unlicensed", "see license", "see license file", "license.txt", "license", "custom"}


# ---------------------------------------------------------------------------
# SPDX normalleştirme ve ifade ayrıştırma
# ---------------------------------------------------------------------------
def _canonical_id(token: str) -> str | None:
    """Tek bir lisans adını SPDX kimliğine çevirir; tanınmazsa None."""
    text = " ".join(str(token).strip().strip(",;").split())
    if not text:
        return None
    key = text.casefold()
    if key in _CANON:
        return _CANON[key]
    if key in _DEPRECATED:
        return _DEPRECATED[key]
    if key.endswith("+") and key[:-1] in _CANON and _CANON[key[:-1]].endswith("-only"):
        return _CANON[key[:-1]][: -len("-only")] + "-or-later"
    if key in _ALIASES:
        return _ALIASES[key]
    stripped = re.sub(r"\s*\((?:[^()]*)\)\s*$", "", text).strip()
    if stripped != text:
        return _canonical_id(stripped)
    if key.startswith("licenseref-") and re.fullmatch(r"licenseref-[a-z0-9.\-]{1,80}", key):
        return "LicenseRef-" + text[len("licenseref-"):]
    return None


_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens, self.pos = tokens, 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expr(self) -> Any:
        node = self.term()
        while (self.peek() or "").upper() == "OR":
            self.take()
            node = ("OR", node, self.term())
        return node

    def term(self) -> Any:
        node = self.factor()
        while (self.peek() or "").upper() == "AND":
            self.take()
            node = ("AND", node, self.factor())
        return node

    def factor(self) -> Any:
        token = self.peek()
        if token is None:
            raise ValueError("eksik ifade")
        if token == "(":
            self.take()
            node = self.expr()
            if self.peek() != ")":
                raise ValueError("kapanmayan parantez")
            self.take()
            return node
        if token == ")" or token.upper() in {"AND", "OR", "WITH"}:
            raise ValueError("beklenmeyen işleç")
        self.take()
        ident = _canonical_id(token)
        if ident is None or " " in ident:
            raise ValueError("tanınmayan kimlik")
        if (self.peek() or "").upper() == "WITH":
            self.take()
            exception = self.take() if self.peek() not in (None, "(", ")") else ""
            exc_id = _canonical_id(exception) or exception
            return ("WITH", ident, exc_id)
        return ("ID", ident)


def _to_text(node: Any, top: bool = True) -> str:
    kind = node[0]
    if kind == "ID":
        return node[1]
    if kind == "WITH":
        return f"{node[1]} WITH {node[2]}"
    inner = f"{_to_text(node[1], False)} {kind} {_to_text(node[2], False)}"
    return inner if top else f"({inner})"


def _parse(text: str) -> Any | None:
    tokens = _TOKEN_RE.findall(text)
    if not tokens or len(tokens) > 60:
        return None
    parser = _Parser(tokens)
    try:
        node = parser.expr()
    except (ValueError, IndexError):
        return None
    return node if parser.pos == len(tokens) else None


def normalize(raw: Any) -> dict[str, Any]:
    """Ham lisans bilgisini (dize, liste = seçmeli, npm ``{type}`` nesnesi) normalleştirir.

    Dönen: ``{"expression": SPDX ifadesi ya da None, "raw": kısa ham metin, "known": bool}``.
    """
    if isinstance(raw, dict):
        raw = raw.get("type") or raw.get("name") or raw.get("id") or ""
    if isinstance(raw, (list, tuple)):
        parts = [normalize(item) for item in raw[:10]]
        known = [p["expression"] for p in parts if p["expression"]]
        raw_text = " OR ".join(p["raw"] for p in parts if p["raw"])
        if not known:
            return {"expression": None, "raw": raw_text[:200], "known": False}
        expression = known[0] if len(known) == 1 else " OR ".join(f"({k})" if " " in k else k for k in known)
        return {"expression": expression, "raw": raw_text[:200], "known": len(known) == len(parts)}
    text = " ".join(str(raw or "").split())[:300]
    if text.casefold() in _NO_LICENSE or text.casefold().startswith("see license in"):
        return {"expression": None, "raw": text[:200], "known": False}
    single = _canonical_id(text)
    if single:
        return {"expression": single, "raw": text[:200], "known": not single.startswith("LicenseRef-")}
    node = _parse(text)
    if node is None and re.search(r"\s(?:or|and)\s|/", text, re.I):
        # "MIT/Apache-2.0", "MIT or Apache 2.0" gibi serbest yazımlar.
        pieces = [p for p in re.split(r"\s+or\s+|/", text, flags=re.I) if p.strip()]
        canon = [_canonical_id(p) for p in pieces]
        if pieces and all(canon):
            return normalize(canon)
    if node is None:
        return {"expression": None, "raw": text[:200], "known": False}
    return {"expression": _to_text(node), "raw": text[:200], "known": True}


# ---------------------------------------------------------------------------
# Politika
# ---------------------------------------------------------------------------
def _clean_patterns(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_PATTERNS:
        raise LicensePolicyError(f"{name} en çok {MAX_PATTERNS} öğelik liste olmalı.")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _PATTERN_RE.fullmatch(item.strip()):
            raise LicensePolicyError(f"{name}: geçersiz lisans kalıbı (SPDX kimliği, '*' joker, 'A WITH B').")
        text = " ".join(item.split())
        if text not in out:
            out.append(text)
    return out


class LicensePolicyError(ValueError):
    """Geçersiz lisans politikası."""


def validate_policy(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LicensePolicyError("Politika bir JSON nesnesi olmalı.")
    unknown = set(raw) - {"format", "allowed", "caution", "denied"}
    if unknown:
        raise LicensePolicyError("Bilinmeyen alan: " + ", ".join(sorted(unknown)))
    return {
        "format": POLICY_FORMAT,
        "allowed": _clean_patterns(raw.get("allowed", DEFAULT_POLICY["allowed"]), "allowed"),
        "caution": _clean_patterns(raw.get("caution", DEFAULT_POLICY["caution"]), "caution"),
        "denied": _clean_patterns(raw.get("denied", DEFAULT_POLICY["denied"]), "denied"),
    }


def load_policy(environ: dict[str, str] | None = None) -> tuple[dict[str, Any], bool]:
    """(politika, özelleştirilmiş mi). Veri dizini yoksa ya da dosya bozuksa varsayılan."""
    import ops_files

    try:
        data = ops_files.read_json(POLICY_FILE, lambda: None, environ)
    except ops_files.OpsStoreError:
        return json.loads(json.dumps(DEFAULT_POLICY)), False
    if data is None:
        return json.loads(json.dumps(DEFAULT_POLICY)), False
    try:
        return validate_policy(data), True
    except LicensePolicyError:
        return json.loads(json.dumps(DEFAULT_POLICY)), False


def save_policy(raw: Any, environ: dict[str, str] | None = None) -> dict[str, Any]:
    import ops_files

    policy = validate_policy(raw)
    ops_files.update_json(POLICY_FILE, lambda: None, lambda _current: policy, environ)
    return policy


def reset_policy(environ: dict[str, str] | None = None) -> dict[str, Any]:
    return save_policy(DEFAULT_POLICY, environ)


def _matches(patterns: Iterable[str], ident: str, *, with_clause: bool = False) -> bool:
    """Kalıp eşleşmesi. ``A WITH B`` kalıpları yalnız istisnalı ifadeye, diğerleri yalnız tek kimliğe uygulanır
    (``GPL-*`` kalıbı "GPL-2.0-only WITH Classpath-exception-2.0" ifadesini yutmasın)."""
    key = ident.casefold()
    return any(fnmatch.fnmatchcase(key, p.casefold()) for p in patterns if (" with " in p.casefold()) == with_clause)


def classify_id(ident: str, policy: dict[str, Any]) -> str:
    for category in ("denied", "caution", "allowed"):
        if _matches(policy.get(category) or [], ident):
            return category
    return "review"


def _classify_node(node: Any, policy: dict[str, Any]) -> str:
    kind = node[0]
    if kind == "ID":
        return classify_id(node[1], policy)
    if kind == "WITH":
        full = f"{node[1]} WITH {node[2]}"
        for category in ("denied", "caution", "allowed"):
            if _matches(policy.get(category) or [], full, with_clause=True):
                return category
        return classify_id(node[1], policy)
    left, right = _classify_node(node[1], policy), _classify_node(node[2], policy)
    pick = min if kind == "OR" else max
    return pick((left, right), key=_RANK.__getitem__)


def classify(expression: str | None, policy: dict[str, Any]) -> str:
    if not expression:
        return "review"
    node = _parse(expression)
    if node is None:
        return classify_id(expression, policy) if " " not in expression else "review"
    return _classify_node(node, policy)


# ---------------------------------------------------------------------------
# Lisans metni sezgisi
# ---------------------------------------------------------------------------
_TEXT_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AGPL-3.0-only", ("gnu affero general public license", "version 3")),
    ("LGPL-3.0-only", ("gnu lesser general public license", "version 3")),
    ("LGPL-2.1-only", ("gnu lesser general public license", "version 2.1")),
    ("LGPL-2.0-only", ("gnu library general public license", "version 2")),
    ("GPL-3.0-only", ("gnu general public license", "version 3")),
    ("GPL-2.0-only", ("gnu general public license", "version 2")),
    ("SSPL-1.0", ("server side public license",)),
    ("BUSL-1.1", ("business source license",)),
    ("Elastic-2.0", ("elastic license 2.0",)),
    ("MPL-2.0", ("mozilla public license", "2.0")),
    ("EPL-2.0", ("eclipse public license", "2.0")),
    ("EPL-1.0", ("eclipse public license", "1.0")),
    ("Apache-2.0", ("apache license", "version 2.0")),
    ("BSL-1.0", ("boost software license",)),
    ("CC0-1.0", ("cc0 1.0 universal",)),
    ("Unlicense", ("this is free and unencumbered software released into the public domain",)),
    ("MIT", ("permission is hereby granted, free of charge",)),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "neither the name")),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms",)),
    ("ISC", ("permission to use, copy, modify, and/or distribute this software for any purpose",
             "provided that the above copyright notice")),
    ("0BSD", ("permission to use, copy, modify, and/or distribute this software for any purpose",)),
    ("Zlib", ("altered source versions must be plainly marked",)),
)
LICENSE_FILE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE.rst", "LICENCE", "LICENCE.md", "LICENCE.txt",
                      "COPYING", "COPYING.md", "COPYING.txt", "UNLICENSE", "license", "license.md", "license.txt")


def detect_license_text(text: str) -> str | None:
    """Lisans metninden SPDX kimliği (yalnız açık ifadelerle; emin değilse None)."""
    lowered = " ".join(text[:MAX_LICENSE_TEXT].casefold().split())
    if "gnu general public license" in lowered and "gnu lesser general public license" in lowered:
        lowered = lowered.replace("gnu general public license", "")  # LGPL metni GPL'ye atıf yapar
    for ident, phrases in _TEXT_RULES:
        if all(phrase in lowered for phrase in phrases):
            return ident
    return None


# ---------------------------------------------------------------------------
# Toplayıcı
# ---------------------------------------------------------------------------
class _Reader:
    """Kök altında, sembolik bağla dışarı çıkmadan ve okuma bütçesiyle dosya okur."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.reads = 0
        self.exhausted = False

    def inside(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.root)
            return True
        except (ValueError, OSError):
            return False

    def read(self, path: Path, limit: int = MAX_FILE_BYTES) -> str | None:
        if self.reads >= MAX_READS:
            self.exhausted = True
            return None
        if not self.inside(path):
            return None
        self.reads += 1
        data = read_bytes_bounded(path, limit)
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")

    def json(self, path: Path) -> Any:
        text = self.read(path)
        if text is None:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return None


MAX_CACHE_READS = 4000


def _cache_home() -> Path | None:
    raw = os.environ.get("SNIPER_LICENSE_CACHE_HOME")
    if raw is None:
        return Path.home()
    return Path(raw).expanduser() if raw.strip() else None


class _CacheReader:
    """Yerel paket önbelleklerinden (izinli kökler) sınırlı okuma; kök dışına sembolik bağla çıkılmaz."""

    def __init__(self, home: Path | None):
        self.home = home
        self.roots: dict[str, list[Path]] = {}
        self.reads = 0
        if home is None:
            return
        gomod = os.environ.get("GOMODCACHE") or str(home / "go" / "pkg" / "mod")
        gem_dirs = [home / ".gem", home / ".local" / "share" / "gem"]
        if os.environ.get("GEM_HOME"):
            gem_dirs.append(Path(os.environ["GEM_HOME"]))
        if os.environ.get("SNIPER_LICENSE_CACHE_HOME") is None:  # gerçek ortamda sistem gem dizinleri de
            gem_dirs += [Path("/var/lib/gems"), Path("/usr/share/rubygems-integration"), Path("/usr/lib/ruby/gems")]
        candidates = {
            "maven": [home / ".m2" / "repository"],
            "cargo": [home / ".cargo" / "registry" / "src"],
            "nuget": [Path(os.environ["NUGET_PACKAGES"])] if os.environ.get("NUGET_PACKAGES") else [home / ".nuget" / "packages"],
            "go": [Path(gomod)],
            "gem": gem_dirs,
        }
        for kind, paths in candidates.items():
            found = []
            for path in paths:
                try:
                    if path.is_dir():
                        found.append(path.resolve())
                except OSError:
                    continue
            if found:
                self.roots[kind] = found

    def allowed(self, kind: str, path: Path) -> Path | None:
        for root in self.roots.get(kind, []):
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
                return resolved
            except (ValueError, OSError):
                continue
        return None

    def read(self, kind: str, path: Path, limit: int = MAX_FILE_BYTES) -> str | None:
        if self.reads >= MAX_CACHE_READS:
            return None
        resolved = self.allowed(kind, path)
        if resolved is None or not resolved.is_file():
            return None
        self.reads += 1
        data = read_bytes_bounded(resolved, limit)
        return None if data is None else data.decode("utf-8", errors="replace")

    def label(self, path: Path) -> str:
        try:
            return "~/" + path.relative_to(self.home).as_posix() if self.home else path.as_posix()
        except ValueError:
            return path.as_posix()


def _go_escape(module: str) -> str:
    """Go modül önbelleği yol kaçışı: büyük harf → ``!`` + küçük harf."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


_POM_LICENSE_NAMES = re.compile(r"<licenses>(.*?)</licenses>", re.S)


def _pom_licenses(text: str) -> list[str]:
    block = _POM_LICENSE_NAMES.search(text or "")
    if not block:
        return []
    return [n.strip() for n in re.findall(r"<name>\s*([^<]{1,120}?)\s*</name>", block.group(1)) if n.strip()][:5]


def _pom_parent(text: str) -> tuple[str, str, str, str] | None:
    match = re.search(r"<parent>(.*?)</parent>", text or "", re.S)
    if not match:
        return None
    body = match.group(1)
    get = lambda tag: (re.search(rf"<{tag}>\s*([^<\s]+)\s*</{tag}>", body) or [None, ""])[1]  # noqa: E731
    rel = re.search(r"<relativePath>\s*([^<]*)\s*</relativePath>", body)
    return get("groupId"), get("artifactId"), get("version"), (rel.group(1).strip() if rel else "../pom.xml")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def component_key(ecosystem: str, name: str, version: str) -> tuple[str, str, str]:
    eco = ecosystem.casefold()
    return eco, (_pep503(name) if eco == "pypi" else name.casefold()), str(version or "")


class _Collector:
    def __init__(self, root: Path, manifests: Iterable[str], components: Iterable[dict[str, Any]] | None = None):
        self.root = root
        self.reader = _Reader(root)
        self.manifests = [m for m in manifests if isinstance(m, str)]
        self.items: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.project_license: dict[str, Any] | None = None
        self.components = [c for c in (components or []) if isinstance(c, dict)]
        self.cache = _CacheReader(_cache_home()) if self.components else _CacheReader(None)

    def add(self, ecosystem: str, name: str, version: str, raw: Any, source: str, *, dev: bool = False,
            heuristic: bool = False) -> None:
        if not name or not isinstance(name, str) or len(name) > 214:
            return
        version = str(version or "")[:80]
        key = component_key(ecosystem, name, version)
        info = normalize(raw)
        if info["expression"] is None and not info["raw"]:
            return
        previous = self.items.get(key)
        if previous is not None:
            # Açık üst veri sezgiyi, bilinen ifade bilinmeyeni geçer; geliştirme işareti ancak hepsi dev ise kalır.
            better = (previous.get("heuristic") and not heuristic) or (not previous["expression"] and info["expression"])
            previous["dev"] = previous["dev"] and dev
            if not better:
                return
            dev = previous["dev"]
        self.items[key] = {
            "ecosystem": ecosystem, "name": name[:214], "version": version, "expression": info["expression"],
            "raw": info["raw"], "known": info["known"], "source": source, "dev": bool(dev), "heuristic": heuristic,
        }

    def set_project(self, raw: Any, source: str, *, heuristic: bool = False) -> None:
        info = normalize(raw)
        if not info["expression"] and not info["raw"]:
            return
        if self.project_license and not self.project_license.get("heuristic") and heuristic:
            return
        if self.project_license and self.project_license.get("expression") and not info["expression"]:
            return
        self.project_license = {"expression": info["expression"], "raw": info["raw"], "source": source,
                                "heuristic": heuristic}

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.name

    # -- kaynaklar ---------------------------------------------------------
    def manifest_dirs(self, filename: str) -> list[Path]:
        dirs = {self.root} if (self.root / filename).is_file() else set()
        for rel in self.manifests:
            if Path(rel).name.casefold() == filename.casefold():
                dirs.add((self.root / rel).parent)
        return sorted(dirs)

    def npm(self) -> None:
        for directory in self.manifest_dirs("package.json"):
            doc = self.reader.json(directory / "package.json")
            if isinstance(doc, dict) and directory == self.root:
                self.set_project(doc.get("license") or doc.get("licenses"), "package.json")
        for directory in self.manifest_dirs("package-lock.json"):
            lock = self.reader.json(directory / "package-lock.json")
            packages = lock.get("packages") if isinstance(lock, dict) else None
            if not isinstance(packages, dict):
                continue
            prefix = self.rel(directory / "package-lock.json")
            for path, item in list(packages.items())[:20_000]:
                if not path or not isinstance(item, dict) or "node_modules/" not in path:
                    continue
                name = item.get("name") if isinstance(item.get("name"), str) else path.rsplit("node_modules/", 1)[-1]
                raw = item.get("license") or item.get("licenses")
                source = prefix
                if not raw:
                    installed = directory / path / "package.json"
                    doc = self.reader.json(installed) if installed.is_file() else None
                    if isinstance(doc, dict):
                        raw = doc.get("license") or doc.get("licenses")
                        source = self.rel(installed)
                if raw:
                    self.add("npm", name, str(item.get("version") or ""), raw, source,
                             dev=bool(item.get("dev") or item.get("devOptional")))
        # Kilit dosyası olmayan (yarn/pnpm) kurulumlar: kök node_modules üst düzeyi.
        modules = self.root / "node_modules"
        if modules.is_dir() and not modules.is_symlink():
            try:
                entries = sorted(modules.iterdir())[:5000]
            except OSError:
                entries = []
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                candidates = [entry]
                if entry.name.startswith("@") and entry.is_dir():
                    try:
                        candidates = sorted(entry.iterdir())[:500]
                    except OSError:
                        candidates = []
                for package_dir in candidates:
                    manifest = package_dir / "package.json"
                    if not manifest.is_file():
                        continue
                    doc = self.reader.json(manifest)
                    if not isinstance(doc, dict) or not isinstance(doc.get("name"), str):
                        continue
                    key = component_key("npm", doc["name"], str(doc.get("version") or ""))
                    if key in self.items:
                        continue
                    self.add("npm", doc["name"], str(doc.get("version") or ""), doc.get("license") or doc.get("licenses"),
                             self.rel(manifest))

    def python(self) -> None:
        for directory in self.manifest_dirs("pyproject.toml"):
            if directory != self.root:
                continue
            text = self.reader.read(directory / "pyproject.toml")
            try:
                doc = tomllib.loads(text) if text else {}
            except tomllib.TOMLDecodeError:
                doc = {}
            project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
            raw = project.get("license-expression") or project.get("license")
            if isinstance(raw, dict):
                raw = raw.get("text") if isinstance(raw.get("text"), str) and len(raw["text"]) < 100 else None
            poetry = ((doc.get("tool") or {}).get("poetry") or {}) if isinstance(doc.get("tool"), dict) else {}
            self.set_project(raw or (poetry.get("license") if isinstance(poetry, dict) else None), "pyproject.toml")
        site_dirs: list[Path] = []
        for venv in (".venv", "venv", "env", ".env", ".tox", "."):
            base = self.root / venv / "lib" if venv != "." else self.root / "lib"
            if not base.is_dir() or base.is_symlink() and not self.reader.inside(base):
                continue
            try:
                site_dirs.extend(p / "site-packages" for p in sorted(base.glob("python*"))[:4])
            except OSError:
                continue
        for site in site_dirs:
            if not site.is_dir() or not self.reader.inside(site):
                continue
            try:
                infos = sorted(site.glob("*.dist-info"))[:5000]
            except OSError:
                continue
            for info in infos:
                text = self.reader.read(info / "METADATA", MAX_FILE_BYTES)
                if text is None:
                    continue
                headers = text.split("\n\n", 1)[0]
                fields: dict[str, list[str]] = {}
                for line in headers.splitlines():
                    if ":" in line and not line.startswith((" ", "\t")):
                        key, _, value = line.partition(":")
                        fields.setdefault(key.strip().casefold(), []).append(value.strip())
                name = (fields.get("name") or [""])[0]
                version = (fields.get("version") or [""])[0]
                raw: Any = (fields.get("license-expression") or [None])[0]
                if not raw:
                    classifiers = [c.split("::")[-1].strip() for c in fields.get("classifier", [])
                                   if c.startswith("License ::") and c.count("::") >= 2]
                    if classifiers:
                        raw = classifiers if len(classifiers) > 1 else classifiers[0]
                if not raw:
                    lic = (fields.get("license") or [""])[0]
                    raw = lic if lic and len(lic) <= 100 else None
                if name and raw:
                    self.add("PyPI", name, version, raw, self.rel(info / "METADATA"))

    def cargo(self) -> None:
        text = self.reader.read(self.root / "Cargo.toml") if (self.root / "Cargo.toml").is_file() else None
        if text:
            try:
                package = tomllib.loads(text).get("package") or {}
            except tomllib.TOMLDecodeError:
                package = {}
            if isinstance(package, dict):
                self.set_project(package.get("license"), "Cargo.toml")
        vendor = self.root / "vendor"
        if not vendor.is_dir():
            return
        try:
            crates = sorted(vendor.glob("*/Cargo.toml"))[:3000]
        except OSError:
            return
        for manifest in crates:
            text = self.reader.read(manifest)
            try:
                package = tomllib.loads(text).get("package") if text else None
            except tomllib.TOMLDecodeError:
                package = None
            if isinstance(package, dict) and isinstance(package.get("name"), str):
                version = package.get("version") if isinstance(package.get("version"), str) else ""
                self.add("cargo", package["name"], version, package.get("license"), self.rel(manifest))

    def go(self) -> None:
        modules_txt = self.root / "vendor" / "modules.txt"
        if not modules_txt.is_file():
            return
        text = self.reader.read(modules_txt, 2 * MAX_FILE_BYTES) or ""
        for line in text.splitlines()[:20_000]:
            match = re.match(r"# (\S+) (v\S+)", line)
            if not match:
                continue
            module, version = match.groups()
            directory = self.root / "vendor" / module
            if ".." in module or not directory.is_dir():
                continue
            for name in LICENSE_FILE_NAMES[:10]:
                path = directory / name
                if path.is_file():
                    ident = detect_license_text(self.reader.read(path, MAX_LICENSE_TEXT) or "")
                    if ident:
                        self.add("Golang", module, version, ident, self.rel(path), heuristic=True)
                    break

    def maven(self) -> None:
        if not (self.root / "pom.xml").is_file():
            return
        path = self.root / "pom.xml"
        for _ in range(4):  # 20. tur: lisansı olmayan pom'da proje içindeki üst pom zinciri (relativePath)
            text = self.reader.read(path) or ""
            names = _pom_licenses(text)
            if names:
                self.set_project(names if len(names) > 1 else names[0], self.rel(path))
                return
            parent = _pom_parent(text)
            if not parent or not parent[3]:
                return
            nxt = (path.parent / parent[3])
            nxt = nxt / "pom.xml" if not nxt.name.endswith(".xml") else nxt
            if not nxt.is_file() or not self.reader.inside(nxt):
                return
            path = nxt

    def composer(self) -> None:
        if (self.root / "composer.json").is_file():
            doc = self.reader.json(self.root / "composer.json")
            if isinstance(doc, dict):
                self.set_project(doc.get("license"), "composer.json")
        for directory in self.manifest_dirs("composer.lock"):  # 20. tur: alt dizinlerdeki kilit dosyaları da
            lock = self.reader.json(directory / "composer.lock")
            if not isinstance(lock, dict):
                continue
            source = self.rel(directory / "composer.lock")
            for section, dev in (("packages", False), ("packages-dev", True)):
                for item in (lock.get(section) or [])[:10_000] if isinstance(lock.get(section), list) else []:
                    if isinstance(item, dict) and isinstance(item.get("name"), str):
                        self.add("Packagist", item["name"], str(item.get("version") or ""), item.get("license"),
                                 source, dev=dev)

    _GEMSPEC_LICENSE = re.compile(r"\.licen[cs]es?\s*=\s*(\[[^\]]{0,300}\]|['\"][^'\"]{1,100}['\"])")

    def _gemspec_license(self, text: str) -> Any:
        match = self._GEMSPEC_LICENSE.search(text)
        if not match:
            return None
        values = re.findall(r"['\"]([^'\"]{1,100})['\"]", match.group(1))
        return values if len(values) > 1 else (values[0] if values else None)

    def ruby(self) -> None:
        try:
            specs = sorted(self.root.glob("*.gemspec"))[:5]
        except OSError:
            specs = []
        for spec in specs:
            self.set_project(self._gemspec_license(self.reader.read(spec) or ""), spec.name)
        bundle = self.root / "vendor" / "bundle"
        if not bundle.is_dir():
            return
        try:
            installed = sorted(bundle.glob("ruby/*/specifications/*.gemspec"))[:5000]
        except OSError:
            return
        for spec in installed:
            match = re.fullmatch(r"(.+)-(\d[\w.]*)\.gemspec", spec.name)
            if match:
                raw = self._gemspec_license(self.reader.read(spec) or "")
                if raw:
                    self.add("RubyGems", match.group(1), match.group(2), raw, self.rel(spec))

    def license_file(self) -> None:
        for name in LICENSE_FILE_NAMES:
            path = self.root / name
            if path.is_file():
                ident = detect_license_text(self.reader.read(path, MAX_LICENSE_TEXT) or "")
                if ident:
                    self.set_project(ident, name, heuristic=True)
                return

    # -- 20. tur: yerel paket önbellekleri ---------------------------------
    def _missing(self, ecosystems: set[str]) -> list[dict[str, Any]]:
        return [c for c in self.components if str(c.get("ecosystem") or "").casefold() in ecosystems
                and c.get("name") and c.get("version")
                and component_key(str(c["ecosystem"]), str(c["name"]), str(c["version"])) not in self.items]

    def maven_cache(self) -> None:
        base = (self.cache.roots.get("maven") or [None])[0]
        if base is None:
            return
        for comp in self._missing({"maven"})[:3000]:
            name = str(comp["name"])
            if ":" not in name:
                continue
            group, artifact = name.split(":", 1)
            version = str(comp["version"])
            if not re.fullmatch(r"[\w.-]+", group + artifact + version):
                continue
            g, a, v = group, artifact, version
            for _depth in range(4):  # pom → üst pom zinciri (önbellekte varsa)
                pom = base.joinpath(*g.split("."), a, v, f"{a}-{v}.pom")
                text = self.cache.read("maven", pom)
                if text is None:
                    break
                names = _pom_licenses(text)
                if names:
                    self.add("Maven", name, version, names if len(names) > 1 else names[0], self.cache.label(pom))
                    break
                parent = _pom_parent(text)
                if not parent or not all(parent[:3]) or not re.fullmatch(r"[\w.-]+", "".join(parent[:3])):
                    break
                g, a, v = parent[:3]

    def cargo_cache(self) -> None:
        roots = self.cache.roots.get("cargo") or []
        if not roots:
            return
        try:
            indexes = [d for root in roots for d in sorted(root.iterdir())[:10] if d.is_dir()]
        except OSError:
            return
        for comp in self._missing({"cargo", "crates.io"})[:3000]:
            name, version = str(comp["name"]), str(comp["version"])
            if not re.fullmatch(r"[\w.+-]+", name + version):
                continue
            for index in indexes:
                text = self.cache.read("cargo", index / f"{name}-{version}" / "Cargo.toml")
                if text is None:
                    continue
                try:
                    package = tomllib.loads(text).get("package") or {}
                except tomllib.TOMLDecodeError:
                    package = {}
                if isinstance(package, dict) and package.get("license"):
                    self.add("cargo", name, version, package["license"], self.cache.label(index / f"{name}-{version}" / "Cargo.toml"))
                break

    def nuget_cache(self) -> None:
        base = (self.cache.roots.get("nuget") or [None])[0]
        if base is None:
            return
        for comp in self._missing({"nuget"})[:3000]:
            name, version = str(comp["name"]), str(comp["version"])
            if not re.fullmatch(r"[\w.+-]+", name + version):
                continue
            directory = base / name.lower() / version.lower()
            text = self.cache.read("nuget", directory / f"{name.lower()}.nuspec")
            if text is None or re.search(r"<!DOCTYPE|<!ENTITY", text[:4096], re.I):
                continue
            expr = re.search(r'<license\s+type="expression"\s*>\s*([^<]{1,200}?)\s*</license>', text)
            if expr:
                self.add("NuGet", name, version, expr.group(1), self.cache.label(directory))
                continue
            url = re.search(r"<licenseUrl>\s*([^<]{1,300}?)\s*</licenseUrl>", text)
            known = re.search(r"(?:licenses\.nuget\.org|opensource\.org/licenses|spdx\.org/licenses)/([A-Za-z0-9.+-]+)",
                              url.group(1) if url else "")
            if known:
                self.add("NuGet", name, version, known.group(1), self.cache.label(directory), heuristic=True)

    def go_cache(self) -> None:
        base = (self.cache.roots.get("go") or [None])[0]
        if base is None:
            return
        import zipfile

        for comp in self._missing({"golang", "go"})[:2000]:
            module, version = str(comp["name"]), str(comp["version"])
            if ".." in module or not re.fullmatch(r"[\w.~/+-]+", module + version):
                continue
            escaped = _go_escape(module)
            directory = base / f"{escaped}@{_go_escape(version)}"
            ident = None
            source = ""
            for name in LICENSE_FILE_NAMES[:8]:
                text = self.cache.read("go", directory / name, MAX_LICENSE_TEXT)
                if text is not None:
                    ident, source = detect_license_text(text), self.cache.label(directory / name)
                    break
            if ident is None and not source:
                archive = base / "cache" / "download" / escaped / "@v" / f"{_go_escape(version)}.zip"
                resolved = self.cache.allowed("go", archive)
                if resolved is not None and resolved.is_file() and self.cache.reads < MAX_CACHE_READS:
                    self.cache.reads += 1
                    try:
                        with zipfile.ZipFile(resolved) as zf:
                            prefix = f"{module}@{version}/"
                            for name in LICENSE_FILE_NAMES[:8]:
                                try:
                                    info = zf.getinfo(prefix + name)
                                except KeyError:
                                    continue
                                if info.file_size <= MAX_LICENSE_TEXT:
                                    ident = detect_license_text(zf.read(info).decode("utf-8", errors="replace"))
                                    source = self.cache.label(resolved) + "#" + name
                                break
                    except (OSError, zipfile.BadZipFile, RuntimeError):
                        ident = None
            if ident:
                self.add("Golang", module, version, ident, source, heuristic=True)

    def gem_cache(self) -> None:
        roots = self.cache.roots.get("gem") or []
        if not roots:
            return
        spec_dirs: list[Path] = []
        for root in roots:
            try:
                spec_dirs += sorted(p for p in root.glob("*/specifications") if p.is_dir())[:8]
                spec_dirs += sorted(p for p in root.glob("ruby/*/specifications") if p.is_dir())[:8]
                spec_dirs += [root / "specifications"] if (root / "specifications").is_dir() else []
            except OSError:
                continue
        for comp in self._missing({"rubygems", "gem"})[:3000]:
            name, version = str(comp["name"]), str(comp["version"])
            if not re.fullmatch(r"[\w.+-]+", name + version):
                continue
            for spec_dir in spec_dirs:
                text = self.cache.read("gem", spec_dir / f"{name}-{version}.gemspec")
                if text is None:
                    continue
                raw = self._gemspec_license(text)
                if raw:
                    self.add("RubyGems", name, version, raw, self.cache.label(spec_dir / f"{name}-{version}.gemspec"))
                break

    def run(self) -> None:
        for step in (self.license_file, self.npm, self.python, self.cargo, self.go, self.maven, self.composer, self.ruby,
                     self.maven_cache, self.cargo_cache, self.nuget_cache, self.go_cache, self.gem_cache):
            try:
                step()
            except (OSError, ValueError, RecursionError):
                continue


def collect(root: Path, manifests: Iterable[str] = (), components: Iterable[dict[str, Any]] | None = None,
            ) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool]:
    """(bileşen lisansları, proje lisansı, okuma bütçesi tükendi mi). ``components`` verilirse yerel paket
    önbelleklerinden (Maven/Cargo/NuGet/Go/RubyGems) eksik lisanslar tamamlanır."""
    collector = _Collector(Path(root), manifests, components)
    collector.run()
    return list(collector.items.values()), collector.project_license, collector.reader.exhausted


def component_license_map(root: Path, components: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    """CycloneDX için: bileşen anahtarı → lisans bilgisi (yalnız bulunanlar)."""
    items, _project, _exhausted = collect(root, [c.get("manifest", "") for c in components], components)
    return {component_key(i["ecosystem"], i["name"], i["version"]): i for i in items}


def cyclonedx_licenses(info: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    """CycloneDX 1.5 ``licenses`` alanı: tek SPDX kimliği → ``license.id``; ifade → ``expression``; diğer → ``name``."""
    if not info:
        return None
    expression = info.get("expression")
    if expression and expression in _KNOWN_IDS:
        return [{"license": {"id": expression}}]
    if expression and not expression.startswith("LicenseRef-") and _parse(expression) is not None:
        return [{"expression": expression}]
    name = info.get("raw") or expression
    return [{"license": {"name": str(name)[:200]}}] if name else None


# ---------------------------------------------------------------------------
# Rapor
# ---------------------------------------------------------------------------
def _inventory(root: Path) -> list[dict[str, str]]:
    try:
        import dependency_security

        _root, components, _skipped = dependency_security.discover_inventory(str(root), allowed_roots=(root.parent,))
        return components
    except Exception:  # noqa: BLE001 — envanter okunamazsa lisans raporu yine üretilir
        return []


def analyze(root: Path, manifests: Iterable[str] = (), *, policy: dict[str, Any] | None = None,
            customized: bool | None = None, environ: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Proje için lisans raporu; hiç bağımlılık ve proje lisansı bilgisi yoksa None."""
    root = Path(root)
    if policy is None:
        policy, loaded_custom = load_policy(environ)
        customized = loaded_custom if customized is None else customized
    inventory = _inventory(root)
    items, project_license, exhausted = collect(root, list(manifests) + [c.get("manifest", "") for c in inventory],
                                                inventory)
    if not items and not inventory and not project_license:
        return None
    known_keys = {component_key(i["ecosystem"], i["name"], i["version"]) for i in items}
    missing = [c for c in inventory if component_key(c["ecosystem"], c["name"], c["version"]) not in known_keys]
    by_category = {category: 0 for category in CATEGORIES}
    by_license: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for item in items:
        category = classify(item["expression"], policy)
        by_category[category] += 1
        label = item["expression"] or (item["raw"] or "?")
        entry = by_license.setdefault(label, {"license": label, "count": 0, "category": category})
        entry["count"] += 1
        rows.append({key: item[key] for key in ("ecosystem", "name", "version", "expression", "raw", "source", "dev")}
                    | {"category": category, "heuristic": bool(item.get("heuristic"))})
    by_category["review"] += len(missing)
    rows.sort(key=lambda r: (-_RANK[r["category"]], r["dev"], r["ecosystem"], r["name"].casefold()))
    project = None
    if project_license:
        project = dict(project_license)
        project["category"] = classify(project_license.get("expression"), policy)
    notes = []
    if missing:
        notes.append(f"{len(missing)} bileşenin lisansı yerel dosyalardan belirlenemedi (paketler kurulu değil ya da "
                     "kilit dosyasında lisans alanı yok); bunlar 'inceleme' sayıldı.")
    if exhausted:
        notes.append("Okuma bütçesi doldu; bazı paketlerin lisansı okunmadı.")
    if project and project["category"] == "allowed" and by_category["caution"]:
        notes.append("Proje izin verici lisanslı; 'dikkat' grubundaki güçlü copyleft bağımlılıklar dağıtımda "
                     "kaynak açma yükümlülüğü getirebilir.")
    notes.append("Bu bir hukuki görüş değildir; yükümlülük dağıtım biçimine (SaaS, ikili dağıtım, iç kullanım) göre değişir.")
    return {
        "format": FORMAT,
        "project_license": project,
        "policy": {"customized": bool(customized), "denied": len(policy.get("denied") or []),
                   "caution": len(policy.get("caution") or []), "allowed": len(policy.get("allowed") or [])},
        "component_count": len(items) + len(missing),
        "with_license": sum(1 for i in items if i["expression"]),
        "unknown": len(missing) + sum(1 for i in items if not i["expression"]),
        "by_category": by_category,
        "by_license": sorted(by_license.values(), key=lambda e: (-e["count"], e["license"]))[:40],
        "items": [r for r in rows if r["category"] != "allowed"][:MAX_ITEMS_REPORTED],
        "unresolved": [{k: c[k] for k in ("ecosystem", "name", "version")} for c in missing[:100]],
        "truncated": len([r for r in rows if r["category"] != "allowed"]) > MAX_ITEMS_REPORTED,
        "notes": notes,
    }


def findings(report: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Politika ihlali bulguları: lisans × kategori başına bir bulgu (yalnız yasak ve dikkat; çalışma zamanı
    bağımlılıkları). Geliştirme bağımlılığı yalnız yasak lisansta, düşük önemle raporlanır."""
    if not report:
        return []
    groups: dict[tuple[str, str, bool], list[dict[str, Any]]] = {}
    for item in report.get("items") or []:
        if item["category"] not in {"denied", "caution"}:
            continue
        if item["dev"] and item["category"] != "denied":
            continue
        groups.setdefault((item["category"], item["expression"] or item["raw"], item["dev"]), []).append(item)
    out = []
    for (category, license_id, dev), items in sorted(groups.items(), key=lambda kv: (-_RANK[kv[0][0]], kv[0][1])):
        names = ", ".join(f"{i['name']}@{i['version']}" if i["version"] else i["name"] for i in items[:8])
        more = f" (+{len(items) - 8})" if len(items) > 8 else ""
        manifest = items[0]["source"] if "node_modules/" not in items[0]["source"] else "package-lock.json"
        if category == "denied":
            severity = "low" if dev else "high"
            title = f"Bağımlılık lisansı politika gereği yasak: {license_id}"
            recommendation = ("Bu paketleri izinli lisanslı bir alternatifle değiştirin ya da hukuk/uyum ekibinden yazılı "
                              "istisna alın; istisna alınırsa lisans politikasını güncelleyin.")
        else:
            severity = "low"
            title = f"Bağımlılık lisansı dikkat gerektiriyor: {license_id}"
            recommendation = ("Güçlü copyleft / kaynak-erişilebilir lisanslar dağıtım biçimine göre kaynak açma ya da kullanım "
                              "kısıtı getirebilir. Kullanım biçimini doğrulayın; uygunsa politikada izinli listesine alın.")
        out.append({
            "category": "license", "severity": severity, "title": title, "file": manifest, "line": 0,
            "evidence": f"{len(items)} {'geliştirme ' if dev else ''}bileşen: {names}{more}.",
            "recommendation": recommendation, "reference": "Lisans politikası (SPDX)",
        })
    return out


def executive_summary(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    flagged = [i for i in report.get("items") or [] if i["category"] in {"denied", "caution"} and not i["dev"]]
    return {
        "project_license": (report.get("project_license") or {}).get("expression")
        or (report.get("project_license") or {}).get("raw"),
        "component_count": report.get("component_count", 0),
        "by_category": report.get("by_category") or {},
        "top": [{k: i[k] for k in ("name", "version", "expression", "raw", "category")} for i in flagged[:5]],
    }
