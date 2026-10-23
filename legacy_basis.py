"""23. tur: eski (M01–M52) üretici uçların veri dayanağı.

Bu uçlar önceden veri olmadan da 200 dönüp "A notu", "geçti" ya da bulguya bağlı olmayan şablon çıktılar
veriyordu; kullanıcıya gerçek analiz gibi görünüyordu. Artık:

* gerçek veri kaynağı (tarama, proje analizi, manuel denetim, açık bulgu listesi, proje klasörü) yoksa
  ``NoSourceError`` → HTTP 400;
* her yanıtta ``data_basis`` alanı çıktının neye dayandığını söyler: ``real`` (gerçek bulgu/veri),
  ``template`` (şablon/örnek; hiçbir bulguya bağlı değil) ya da ``mixed`` (gerçek + açıkça istenen şablon).
"""
from __future__ import annotations

from typing import Any, Iterable

BASIS_LABELS = {
    "real": "Gerçek veri",
    "template": "Şablon / örnek (bulguya bağlı değil)",
    "mixed": "Gerçek veri + şablon öğeler",
}

NO_SOURCE_MESSAGE = ("Bu araç gerçek veri gerektirir: tarama, proje analizi ya da manuel denetim kimliği "
                     "(project_audit_id, scan_id, engagement_id; en son kayıt için 'latest') veya bulgu listesi gönderin.")


class NoSourceError(ValueError):
    """Değerlendirilecek gerçek veri yok (HTTP 400)."""


def data_basis(kind: str, sources: Iterable[str] = (), note: str = "") -> dict[str, Any]:
    if kind not in BASIS_LABELS:
        raise ValueError(f"Bilinmeyen veri dayanağı: {kind}")
    return {"kind": kind, "label": BASIS_LABELS[kind], "sources": [s for s in sources if s], "note": note}


def source_labels(*, scan: Any = None, project_audit: Any = None, engagement: Any = None,
                  findings: Any = None, mobile_audit: Any = None, project_path: str | None = None,
                  extra: Iterable[str] = ()) -> list[str]:
    """Çözümlenmiş kaynakların okunur etiketleri (boşsa gerçek veri yok demektir)."""
    out: list[str] = []
    if isinstance(project_audit, dict):
        out.append(f"proje analizi {project_audit.get('id') or ''}".strip())
    if isinstance(scan, dict):
        out.append(f"tarama {scan.get('id') or ''}".strip())
    if isinstance(engagement, dict):
        out.append(f"manuel denetim {engagement.get('id') or ''}".strip())
    if isinstance(mobile_audit, dict):
        out.append("mobil denetim")
    if isinstance(findings, list) and findings:
        out.append(f"istekteki {len(findings)} bulgu")
    if project_path:
        out.append("proje klasörü")
    out.extend(e for e in extra if e)
    return out


def require_sources(sources: list[str], message: str = NO_SOURCE_MESSAGE) -> None:
    if not sources:
        raise NoSourceError(message)
