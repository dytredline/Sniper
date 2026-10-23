"""
Scan Diff Module - Storage canonical metodlarını kullanan thin wrapper.

Sıralama, sayım ve filtre yardımcıları storage_canonical içinde tek kaynak
olarak tutulur; bu modül yalnızca geriye uyumlu adları dışa aktarır.
"""

from __future__ import annotations

from typing import Any

from storage import Store
from storage_canonical import (  # noqa: F401 - geriye uyumlu dışa aktarım
    KNOWN_SEVERITIES,
    SEVERITY_ORDER,
    _count_by_severity,
    _normalize_severity,
    _severity_key,
)


class ScanDiff:
    """İki tarama sonucunu karşılaştırmak için wrapper sınıfı."""

    def __init__(self, store: Store):
        self.store = store

    def compare_scans(
        self,
        scan_id_1: str,
        scan_id_2: str,
        *,
        include_details: bool = True,
    ) -> dict[str, Any]:
        """Canonical storage.compare_scans() metodunu çağırır."""
        return self.store.compare_scans(scan_id_1, scan_id_2, include_details=include_details)

    def get_diff_summary(self, scan_id_1: str, scan_id_2: str) -> dict[str, Any]:
        """İki tarama arasındaki farkın özet bilgisini döndürür."""
        return self.compare_scans(scan_id_1, scan_id_2, include_details=False)

    def get_new_findings(
        self,
        scan_id_1: str,
        scan_id_2: str,
        *,
        severity_filter: str | None = None,
    ) -> list[dict]:
        """Yeni bulguları döndürür."""
        return self.store.get_new_findings(scan_id_1, scan_id_2, severity_filter=severity_filter)

    def get_resolved_findings(
        self,
        scan_id_1: str,
        scan_id_2: str,
        *,
        severity_filter: str | None = None,
    ) -> list[dict]:
        """Giderilmiş bulguları döndürür."""
        return self.store.get_resolved_findings(scan_id_1, scan_id_2, severity_filter=severity_filter)

    def get_persistent_findings(
        self,
        scan_id_1: str,
        scan_id_2: str,
        *,
        severity_filter: str | None = None,
    ) -> list[dict]:
        """Devam eden bulguları döndürür."""
        return self.store.get_persistent_findings(scan_id_1, scan_id_2, severity_filter=severity_filter)

    # Geriye uyumlu statik erişim; tek kaynak storage_canonical._count_by_severity.
    _count_by_severity = staticmethod(_count_by_severity)


def create_scan_diff(store: Store) -> ScanDiff:
    """ScanDiff örneği oluşturur."""
    return ScanDiff(store)
