"""Time-bounded regular expressions for attacker-controlled source text.

VulKill's auditors intentionally inspect untrusted project files.  The stdlib
``re`` engine has no execution deadline, so a syntactically valid project can
otherwise turn an auditor rule into a denial of service.  This module exposes
the small ``re`` surface used by the product while enforcing a per-operation
deadline through the pinned ``regex`` runtime.

A timeout is a non-match.  Transforming operations preserve the original
input.  That fail-safe contract keeps an audit available and never expands or
rewrites attacker-controlled data after a deadline.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import regex as _regex


TIMEOUT_SECONDS = 0.05

I = IGNORECASE = _regex.IGNORECASE
M = MULTILINE = _regex.MULTILINE
S = DOTALL = _regex.DOTALL
ASCII = _regex.ASCII
VERBOSE = X = _regex.VERBOSE
Match = _regex.Match
RegexFlag = _regex.RegexFlag
error = _regex.error


def escape(pattern: str | bytes, special_only: bool = True, literal_spaces: bool = False) -> str | bytes:
    return _regex.escape(pattern, special_only=special_only, literal_spaces=literal_spaces)


class Pattern:
    """Deadline-enforcing wrapper for a compiled ``regex.Pattern``."""

    __slots__ = ("_compiled",)

    def __init__(self, compiled: Any) -> None:
        self._compiled = compiled

    @classmethod
    def __class_getitem__(cls, item: object) -> type[Pattern]:
        return cls

    @property
    def pattern(self) -> str | bytes:
        return self._compiled.pattern

    @property
    def flags(self) -> int:
        return self._compiled.flags

    @property
    def groups(self) -> int:
        return self._compiled.groups

    @property
    def groupindex(self) -> dict[str, int]:
        return self._compiled.groupindex

    def search(self, string: Any, pos: int = 0, endpos: int | None = None) -> Any:
        try:
            if endpos is None:
                return self._compiled.search(string, pos, timeout=TIMEOUT_SECONDS)
            return self._compiled.search(string, pos, endpos, timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            return None

    def match(self, string: Any, pos: int = 0, endpos: int | None = None) -> Any:
        try:
            if endpos is None:
                return self._compiled.match(string, pos, timeout=TIMEOUT_SECONDS)
            return self._compiled.match(string, pos, endpos, timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            return None

    def fullmatch(self, string: Any, pos: int = 0, endpos: int | None = None) -> Any:
        try:
            if endpos is None:
                return self._compiled.fullmatch(string, pos, timeout=TIMEOUT_SECONDS)
            return self._compiled.fullmatch(string, pos, endpos, timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            return None

    def findall(self, string: Any, pos: int = 0, endpos: int | None = None,
                overlapped: bool = False) -> list[Any]:
        try:
            kwargs = {"overlapped": overlapped, "timeout": TIMEOUT_SECONDS}
            if endpos is None:
                return self._compiled.findall(string, pos, **kwargs)
            return self._compiled.findall(string, pos, endpos, **kwargs)
        except TimeoutError:
            return []

    def finditer(self, string: Any, pos: int = 0, endpos: int | None = None,
                 overlapped: bool = False) -> Iterator[Any]:
        try:
            kwargs = {"overlapped": overlapped, "timeout": TIMEOUT_SECONDS}
            iterator = (self._compiled.finditer(string, pos, **kwargs) if endpos is None
                        else self._compiled.finditer(string, pos, endpos, **kwargs))
            yield from iterator
        except TimeoutError:
            return

    def split(self, string: Any, maxsplit: int = 0) -> list[Any]:
        try:
            return self._compiled.split(string, maxsplit=maxsplit, timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            return [string]

    def sub(self, repl: str | bytes | Callable[..., Any], string: Any, count: int = 0) -> Any:
        try:
            return self._compiled.sub(repl, string, count=count, timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            return string

    def subn(self, repl: str | bytes | Callable[..., Any], string: Any, count: int = 0) -> tuple[Any, int]:
        try:
            return self._compiled.subn(repl, string, count=count, timeout=TIMEOUT_SECONDS)
        except TimeoutError:
            return string, 0

    def __repr__(self) -> str:
        return repr(self._compiled)


def compile(pattern: Any, flags: int = 0, **kwargs: Any) -> Pattern:
    if isinstance(pattern, Pattern):
        if flags or kwargs:
            raise ValueError("cannot process flags or keyword arguments with a compiled pattern")
        return pattern
    return Pattern(_regex.compile(pattern, flags, **kwargs))


def _pattern(pattern: Any, flags: int = 0) -> Pattern:
    return compile(pattern, flags)


def search(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _pattern(pattern, flags).search(string)


def match(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _pattern(pattern, flags).match(string)


def fullmatch(pattern: Any, string: Any, flags: int = 0) -> Any:
    return _pattern(pattern, flags).fullmatch(string)


def findall(pattern: Any, string: Any, flags: int = 0) -> list[Any]:
    return _pattern(pattern, flags).findall(string)


def finditer(pattern: Any, string: Any, flags: int = 0) -> Iterator[Any]:
    return _pattern(pattern, flags).finditer(string)


def split(pattern: Any, string: Any, maxsplit: int = 0, flags: int = 0) -> list[Any]:
    return _pattern(pattern, flags).split(string, maxsplit=maxsplit)


def sub(pattern: Any, repl: str | bytes | Callable[..., Any], string: Any,
        count: int = 0, flags: int = 0) -> Any:
    return _pattern(pattern, flags).sub(repl, string, count=count)


def subn(pattern: Any, repl: str | bytes | Callable[..., Any], string: Any,
         count: int = 0, flags: int = 0) -> tuple[Any, int]:
    return _pattern(pattern, flags).subn(repl, string, count=count)


def purge() -> None:
    _regex.purge()
