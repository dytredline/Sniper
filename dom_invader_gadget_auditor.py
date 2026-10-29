"""Sniper DOM Invader & Client-Side Gadget Auditor (Burp DOM Invader karşılığı).

İstemci tarafı JavaScript/TypeScript/HTML kodlarında:
1. Client-Side Prototype Pollution (CSPP) kaynak -> derin birleştirme (deep merge) zincirlerini,
2. Tanımsız özellik (undefined property fallback) üzerinden tetiklenen DOM Script Gadget'larını,
3. DOM Clobbering (window.GLOBAL || document.getElementById / document.forms) hedeflerini,
4. Origin kontrolsüz window.addEventListener('message') postMessage kanarya akışlarını
tespit eder.
"""
from __future__ import annotations

import re
from typing import Any


FORMAT = "sniper-dom-invader-gadget-audit/1"

_URL_SOURCE_RE = re.compile(
    r"\b(?:location\.(?:search|hash|href)|URLSearchParams|deparam|qs\.parse|queryString\.parse)\b"
)
_DEEP_MERGE_RE = re.compile(
    r"\b(?:deepMerge|merge|extend|_\.merge|_\.defaultsDeep|Object\.assign)\s*\(|"
    r"\b\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*="
)
_PROTO_GUARD_RE = re.compile(
    r"""(?:__proto__|prototype|constructor|Object\.create\s*\(\s*null\s*\)|Object\.freeze\s*\(\s*Object\.prototype)"""
)
_GADGET_SINK_RE = re.compile(
    r"""(?:\.src\s*=\s*(?:\w+\.)?(?:transport_url|scriptUrl|sdkUrl|bundleUrl|url)\b|"""
    r"""\.innerHTML\s*=\s*(?:\w+\.)?(?:template|html|content)\b)"""
)
_DOM_CLOBBER_RE = re.compile(
    r"""\bwindow\.([A-Za-z_]\w*)\s*\|\|\s*(?:document\.getElementById|document\.getElementsByName|document\.forms|window\.\1)"""
)
_POSTMESSAGE_LISTENER_RE = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\(\s*(\w+)\s*\)|(?:\(\s*(\w+)\s*\)|(\w+))\s*=>)"""
)
_DOM_EXEC_SINK_RE = re.compile(
    r"""\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|setTimeout|setInterval|location\.href|location\.assign|location\.replace)\b"""
)


def _line_no(text: str, pos: int) -> int:
    return text[:max(0, pos)].count("\n") + 1


def audit_dom_invader_cspp_and_gadgets(raw_content: str, *, filename: str = "app.js") -> dict[str, Any]:
    """İstemci tarafı kaynak kodunu CSPP, Script Gadget, DOM Clobbering ve postMessage akışları açısından denetler."""
    text = str(raw_content or "")
    findings: list[dict[str, Any]] = []

    # 1. Client-Side Prototype Pollution (CSPP): URL/Hash kaynağı + derin nesne birleştirme (__proto__ korumasız)
    src_m = _URL_SOURCE_RE.search(text)
    merge_m = _DEEP_MERGE_RE.search(text)
    if src_m and merge_m and not _PROTO_GUARD_RE.search(text):
        findings.append({
            "control_id": "SNIPER-DOM-CSPP-01",
            "cwe": "CWE-1321",
            "reference": "CWE-1321",
            "severity": "high",
            "category": "web_hardening",
            "file": filename,
            "line": _line_no(text, merge_m.start()),
            "title": "İstemci Tarafı Prototype Pollution (CSPP): URL/Hash girdisinden korumasız derin nesne birleştirme",
            "evidence": f"URL/Hash kaynağı ({src_m.group(0)}) ile '{merge_m.group(0)}' birleştirmesi '__proto__/constructor' filtresi olmadan kullanılıyor.",
            "recommendation": "Derin nesne birleştirmede '__proto__', 'constructor' ve 'prototype' anahtarlarını reddedin veya Object.create(null) kullanın.",
        })

    # 2. Script Gadget Execution (Object.prototype üzerinden devralınan transport_url / scriptUrl / template)
    gadget_m = _GADGET_SINK_RE.search(text)
    if gadget_m and "hasOwnProperty" not in text and "Object.hasOwn" not in text:
        findings.append({
            "control_id": "SNIPER-DOM-GADGET-02",
            "cwe": "CWE-79",
            "reference": "CWE-79",
            "severity": "high",
            "category": "web_hardening",
            "file": filename,
            "line": _line_no(text, gadget_m.start()),
            "title": "DOM Invader Script Gadget: Object.hasOwn kontrolsüz yapılandırma özelliğinin DOM/Script hedefine akışı",
            "evidence": f"Gadget hedefi '{gadget_m.group(0)}' Object.hasOwn / hasOwnProperty doğrulaması olmadan atanıyor.",
            "recommendation": "Yapılandırma nesnelerini Object.create(null) ile oluşturun veya özellik okumalarında Object.hasOwn() kontrolü uygulayın.",
        })

    # 3. DOM Clobbering -> Dynamic Script / URL Sink
    clobber_m = _DOM_CLOBBER_RE.search(text)
    if clobber_m and re.search(r"\b(?:src|href|innerHTML|fetch|import)\b", text):
        findings.append({
            "control_id": "SNIPER-DOM-CLOBBER-03",
            "cwe": "CWE-79",
            "reference": "CWE-79",
            "severity": "high",
            "category": "web_hardening",
            "file": filename,
            "line": _line_no(text, clobber_m.start()),
            "title": "DOM Clobbering zinciri: HTML id/name çakışmasına açık global değişkenin script/URL hedefine akışı",
            "evidence": f"DOM Clobbering deseni '{clobber_m.group(0)}' dinamik kaynak/DOM hedefiyle aynı kapsamda bulundu.",
            "recommendation": "Global yapılandırma nesnelerini HTML öğeleriyle ezilmeyecek şekilde (instanceof / typeof kontrolü veya DOMPurify SANITIZE_NAMED_PROPS) doğrulayın.",
        })

    # 4. postMessage Canary Flow without Origin Check
    for pm in _POSTMESSAGE_LISTENER_RE.finditer(text):
        ev_var = pm.group(1) or pm.group(2) or pm.group(3) or "event"
        window_slice = text[pm.start() : pm.start() + 600]
        has_origin_check = bool(re.search(rf"\b{re.escape(ev_var)}\.origin\b", window_slice))
        has_sink = bool(_DOM_EXEC_SINK_RE.search(window_slice))
        if has_sink and not has_origin_check:
            findings.append({
                "control_id": "SNIPER-DOM-POSTMSG-04",
                "cwe": "CWE-346",
                "reference": "CWE-346",
                "severity": "high",
                "category": "web_hardening",
                "file": filename,
                "line": _line_no(text, pm.start()),
                "title": "Origin doğrulamasız postMessage dinleyicisinden DOM/Yönlendirme hedefine veri akışı",
                "evidence": f"addEventListener('message') içinde '{ev_var}.origin' doğrulanmadan DOM çalıştırma hedefine akış görüldü.",
                "recommendation": f"Mesaj işleyicisinin başında '{ev_var}.origin === \"https://trusted.example\"' kontrolünü zorunlu kılın.",
            })

    return {
        "format": FORMAT,
        "filename": filename,
        "finding_count": len(findings),
        "findings": findings,
    }
