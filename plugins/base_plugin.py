"""Public contract for explicitly enabled, locally trusted Sniper plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class PluginInfo:
    name: str
    version: str
    author: str
    description: str
    min_sniper_version: str = "2.0"

    def public_dict(self) -> dict[str, str]:
        return asdict(self)


class BasePlugin(ABC):
    """A trusted plugin that can add passive findings to a baseline scan."""

    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Return stable plugin metadata."""

    def initialize(self, config: dict[str, Any]) -> None:
        """Receive this plugin's local configuration before its first scan."""

    @abstractmethod
    def scan(self, target: str) -> list[dict[str, Any]]:
        """Return passive findings for the normalized target URL."""

    def cleanup(self) -> None:
        """Release resources during a plugin reload or server shutdown."""
