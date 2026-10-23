"""İşletim sistemi paket sürümü karşılaştırmaları (18. tur, konteyner taraması).

* dpkg (Debian/Ubuntu): ``[epoch:]upstream[-revision]``; dpkg'nin ``verrevcmp`` algoritması — ``~`` her şeyden
  (sondan bile) önce gelir, harfler harf olmayanlardan önce sıralanır, sayılar sayısal karşılaştırılır.
* apk (Alpine/Wolfi): ``1.2.3[a][_suffix[N]]...[-rN]``; ön sürüm ekleri (alpha < beta < pre < rc) eksiz sürümden
  önce, sonrakiler (cvs < svn < git < hg < p) sonra gelir.
* rpm (AlmaLinux/Rocky): ``[epoch:]version-release``; ``rpmvercmp`` — ``~`` önce, ``^`` sonra, rakam bölümü harf
  bölümünden büyüktür.

Hepsi ``-1 / 0 / 1`` döndürür; çözümlenemeyen sürüm ``ValueError``.
"""
from __future__ import annotations

import re
from typing import Callable

__all__ = ["dpkg_compare", "apk_compare", "rpm_compare", "comparator_for"]


# ---------------------------------------------------------------------------
# dpkg
# ---------------------------------------------------------------------------
def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _is_alpha(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _dpkg_order(ch: str) -> int:
    if not ch or _is_digit(ch):
        return 0
    if _is_alpha(ch):
        return ord(ch)
    if ch == "~":
        return -1
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _is_digit(a[i])) or (j < lb and not _is_digit(b[j])):
            ac = _dpkg_order(a[i]) if i < la else 0
            bc = _dpkg_order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and _is_digit(a[i]) and j < lb and _is_digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _is_digit(a[i]):
            return 1
        if j < lb and _is_digit(b[j]):
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_parse(version: str) -> tuple[int, str, str]:
    text = (version or "").strip()
    if not text or any(ch.isspace() for ch in text):
        raise ValueError("geçersiz dpkg sürümü")
    epoch = 0
    if ":" in text:
        head, text = text.split(":", 1)
        if not head.isdigit():
            raise ValueError("geçersiz dpkg epoch")
        epoch = int(head)
    upstream, revision = (text.rsplit("-", 1) if "-" in text else (text, ""))
    if not upstream:
        raise ValueError("boş upstream sürüm")
    return epoch, upstream, revision


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_parse(a)
    eb, ub, rb = _dpkg_parse(b)
    if ea != eb:
        return _sign(ea - eb)
    result = _verrevcmp(ua, ub)
    if result:
        return _sign(result)
    return _sign(_verrevcmp(ra, rb))


# ---------------------------------------------------------------------------
# apk
# ---------------------------------------------------------------------------
_APK_PRE = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3}
_APK_POST = {"cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}
_APK_NONE = 4
_APK_RE = re.compile(r"(?P<nums>\d+(?:\.\d+)*)(?P<letter>[a-z])?(?P<suf>(?:_[a-z]+\d*)*)(?:-r(?P<rev>\d+))?\Z")
_APK_SUF_RE = re.compile(r"_([a-z]+)(\d*)")


def _apk_parse(version: str) -> tuple[list[str], str, list[tuple[int, int]], int]:
    text = (version or "").strip()
    match = _APK_RE.fullmatch(text)
    if not match:
        raise ValueError("geçersiz apk sürümü")
    nums = match.group("nums").split(".")
    suffixes: list[tuple[int, int]] = []
    for name, number in _APK_SUF_RE.findall(match.group("suf") or ""):
        if name in _APK_PRE:
            rank = _APK_PRE[name]
        elif name in _APK_POST:
            rank = _APK_POST[name]
        else:
            raise ValueError("bilinmeyen apk sürüm eki")
        suffixes.append((rank, int(number or 0)))
    return nums, match.group("letter") or "", suffixes, int(match.group("rev") or 0)


def _apk_num_cmp(a: str, b: str, first: bool) -> int:
    # apk-tools: ilk bileşenden sonraki baştaki sıfırlı bileşen ondalık kesir gibi (metin olarak) karşılaştırılır.
    if not first and (a.startswith("0") or b.startswith("0")) and (len(a) > 1 or len(b) > 1):
        return _sign((a > b) - (a < b))
    return _sign(int(a) - int(b))


def apk_compare(a: str, b: str) -> int:
    na, la, sa, ra = _apk_parse(a)
    nb, lb, sb, rb = _apk_parse(b)
    for index, (x, y) in enumerate(zip(na, nb)):
        result = _apk_num_cmp(x, y, index == 0)
        if result:
            return result
    if len(na) != len(nb):
        return 1 if len(na) > len(nb) else -1
    if la != lb:
        return 1 if la > lb else -1
    for position in range(max(len(sa), len(sb))):
        x = sa[position] if position < len(sa) else (_APK_NONE, 0)
        y = sb[position] if position < len(sb) else (_APK_NONE, 0)
        if x != y:
            return 1 if x > y else -1
    return _sign(ra - rb)


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------
def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not (a[i].isalnum() and a[i].isascii()) and a[i] not in "~^":
            i += 1
        while j < len(b) and not (b[j].isalnum() and b[j].isascii()) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < len(a) else ""
        cb = b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not ca or not cb:
            break
        start_i, start_j = i, j
        if _is_digit(ca):
            while i < len(a) and _is_digit(a[i]):
                i += 1
            while j < len(b) and _is_digit(b[j]):
                j += 1
            is_num = True
        else:
            while i < len(a) and _is_alpha(a[i]):
                i += 1
            while j < len(b) and _is_alpha(b[j]):
                j += 1
            is_num = False
        seg_a, seg_b = a[start_i:i], b[start_j:j]
        if not seg_b:
            return 1 if is_num else -1
        if is_num:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    rest_a, rest_b = a[i:], b[j:]
    if not rest_a and not rest_b:
        return 0
    return -1 if not rest_a else 1


def _rpm_parse(version: str) -> tuple[int, str, str]:
    text = (version or "").strip()
    if not text or any(ch.isspace() for ch in text):
        raise ValueError("geçersiz rpm sürümü")
    epoch = 0
    if ":" in text:
        head, text = text.split(":", 1)
        if not head.isdigit():
            raise ValueError("geçersiz rpm epoch")
        epoch = int(head)
    version_part, release = (text.rsplit("-", 1) if "-" in text else (text, ""))
    return epoch, version_part, release


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _rpm_parse(a)
    eb, vb, rb = _rpm_parse(b)
    if ea != eb:
        return _sign(ea - eb)
    result = _rpmvercmp(va, vb)
    if result or not ra or not rb:
        return result
    return _rpmvercmp(ra, rb)


def comparator_for(package_type: str) -> Callable[[str, str], int]:
    return {"deb": dpkg_compare, "apk": apk_compare, "rpm": rpm_compare}[package_type]
