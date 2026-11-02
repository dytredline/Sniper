"""Versiyon ve sürüm bilgisi yönetimi."""

__version__ = "1.2.1"
__build_date__ = "2026-11-02"


def get_version():
    """Görsel versiyon string'i döndür."""
    return f"VulKill Community v{__version__} ({__build_date__})"
