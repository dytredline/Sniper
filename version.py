"""Versiyon ve sürüm bilgisi yönetimi."""

__version__ = "1.0.0"
__build_date__ = "2026-09-20"


def get_version():
    """Görsel versiyon string'i döndür."""
    return f"Sniper Community v{__version__} ({__build_date__})"
