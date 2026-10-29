"""Deterministic Rails controller callback inheritance for route authorization review.

This module does not decide whether a callback name is an authentication or
authorization policy.  It provides the cross-file Rails semantics needed by a
route analyzer: exact superclass resolution, ``only``/``except`` scopes and
``skip_before_action`` removal.  Callers can then apply their own conservative
guard-name policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable, Mapping

from taint_goruby import parse_ruby_file


MAX_RAILS_CONTROLLER_FILES = 2_000
MAX_RUBY_SOURCE_BYTES = 1_000_000
_FRAMEWORK_ROOTS = frozenset({"ActionController::Base", "ActionController::API"})


@dataclass(frozen=True)
class RailsCallback:
    """One callback declaration with enough provenance for evidence output."""

    name: str
    owner: str
    file: str
    line: int
    kind: str
    only: tuple[str, ...] = ()
    except_actions: tuple[str, ...] = ()
    certainty: str = "always"

    def applies_to(self, action: str) -> bool:
        return (not self.only or action in self.only) and action not in self.except_actions


@dataclass(frozen=True)
class RailsActionContext:
    """Effective callback chain for one controller action."""

    controller: str
    action: str
    effective_filters: tuple[RailsCallback, ...]
    uncertain_filters: tuple[RailsCallback, ...]
    skipped_filters: tuple[RailsCallback, ...]

    @property
    def local_filters(self) -> tuple[RailsCallback, ...]:
        return tuple(item for item in self.effective_filters if item.owner == self.controller)

    @property
    def inherited_filters(self) -> tuple[RailsCallback, ...]:
        return tuple(item for item in self.effective_filters if item.owner != self.controller)


@dataclass(frozen=True)
class RailsControllerContext:
    """Resolved inheritance metadata for one declared Rails controller."""

    controller: str
    superclass: str
    ancestry: tuple[str, ...]
    inheritance_complete: bool
    local_filters: tuple[RailsCallback, ...]
    local_skips: tuple[RailsCallback, ...]
    _events: tuple[RailsCallback, ...] = field(repr=False, compare=False)

    def action(self, action: str) -> RailsActionContext:
        """Resolve guaranteed, conditional and skipped filters for ``action``.

        Dynamic callback predicates are deliberately not promoted to guaranteed
        guards.  A dynamic skip similarly demotes a previously guaranteed
        callback to uncertain rather than claiming protection.
        """
        if not isinstance(action, str) or not action:
            return RailsActionContext(self.controller, "", (), (), ())
        effective: list[RailsCallback] = []
        uncertain: list[RailsCallback] = []
        skipped: list[RailsCallback] = []
        for item in self._events:
            if not item.applies_to(action) or item.certainty == "never":
                continue
            if item.kind == "skip:before":
                skipped.append(item)
                matched = [old for old in effective if old.name == item.name]
                effective = [old for old in effective if old.name != item.name]
                uncertain = [old for old in uncertain if old.name != item.name]
                if item.certainty != "always":
                    uncertain.extend(matched)
                continue
            if item.kind not in {"before", "prepend:before"}:
                continue
            target = effective if item.certainty == "always" else uncertain
            target.append(item)
        return RailsActionContext(
            controller=self.controller,
            action=action,
            effective_filters=tuple(effective),
            uncertain_filters=tuple(uncertain),
            skipped_filters=tuple(skipped),
        )


def _source_items(
    sources: Mapping[str, str] | Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    raw_items = sources.items() if isinstance(sources, Mapping) else sources
    found: list[tuple[str, str]] = []
    for item in raw_items:
        try:
            rel, text = item[0], item[1]
        except (IndexError, TypeError):
            continue
        if not isinstance(rel, str) or not isinstance(text, str):
            continue
        normalized = str(PurePosixPath(rel.replace("\\", "/")))
        try:
            source_size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            continue
        if not normalized.endswith(".rb") or source_size > MAX_RUBY_SOURCE_BYTES:
            continue
        if "/controllers/" not in f"/{normalized}" and not normalized.endswith("_controller.rb"):
            continue
        found.append((normalized, text))
        if len(found) >= MAX_RAILS_CONTROLLER_FILES:
            break
    return sorted(found)


def _resolve_parent(owner: str, raw_parent: str, declared: frozenset[str]) -> str | None:
    if not raw_parent:
        return None
    if "::" in raw_parent:
        return raw_parent if raw_parent in declared else None
    namespace = owner.split("::")[:-1]
    for size in range(len(namespace), 0, -1):
        candidate = "::".join([*namespace[:size], raw_parent])
        if candidate in declared:
            return candidate
    return raw_parent if raw_parent in declared else None


def _certainty(value: bool | None) -> str:
    if value is True:
        return "always"
    if value is False:
        return "never"
    return "maybe"


def analyze_rails_controller_inheritance(
    sources: Mapping[str, str] | Iterable[tuple[str, str]],
) -> dict[str, RailsControllerContext]:
    """Return exact cross-file callback contexts keyed by controller constant.

    Conflicting superclass declarations fail closed: the affected controller
    keeps only its own callbacks and ``inheritance_complete`` is false.  An
    undeclared custom superclass also marks the chain incomplete; no short-name
    guess across unrelated namespaces is made.
    """
    ruby_files = []
    for rel, text in _source_items(sources):
        try:
            ruby_files.append(parse_ruby_file(rel, text))
        except (IndexError, RecursionError, TypeError, ValueError):
            continue

    class_parents: dict[str, set[str]] = {}
    callbacks: dict[str, list[RailsCallback]] = {}
    for ruby_file in ruby_files:
        for name, superclass, is_class in ruby_file.classes:
            if is_class and name and name.endswith("Controller"):
                class_parents.setdefault(name, set()).add(superclass or "")
        for owner, items in ruby_file.callbacks.items():
            if not owner.endswith("Controller"):
                continue
            for kind, name, only, exclude, condition, line in items:
                if kind not in {"before", "prepend:before", "skip:before"}:
                    continue
                callbacks.setdefault(owner, []).append(RailsCallback(
                    name=str(name),
                    owner=owner,
                    file=ruby_file.rel,
                    line=int(line),
                    kind=str(kind),
                    only=tuple(sorted(str(value) for value in only)),
                    except_actions=tuple(sorted(str(value) for value in exclude)),
                    certainty=_certainty(condition),
                ))

    declared = frozenset(class_parents)
    contexts: dict[str, RailsControllerContext] = {}
    for controller in sorted(declared):
        lineage = [controller]
        complete = True
        current = controller
        seen = {controller}
        raw_superclass = ""
        conflict = False
        for _depth in range(32):
            candidates = class_parents.get(current, set())
            nonempty = {item for item in candidates if item}
            if len(nonempty) > 1:
                conflict = True
                complete = False
                break
            parent = next(iter(nonempty), "")
            if current == controller:
                raw_superclass = parent
            if not parent:
                break
            if parent in _FRAMEWORK_ROOTS:
                break
            resolved = _resolve_parent(current, parent, declared)
            if resolved is None or resolved in seen:
                complete = False
                break
            lineage.append(resolved)
            seen.add(resolved)
            current = resolved
        else:
            complete = False

        # A conflicting Ruby superclass declaration cannot define a stable
        # ancestor chain.  Keep local evidence only instead of borrowing a
        # filter from either possible base.
        if conflict:
            lineage = [controller]
        ancestry = tuple(reversed(lineage))
        events = tuple(item for owner in ancestry for item in callbacks.get(owner, ()))
        local = tuple(callbacks.get(controller, ()))
        contexts[controller] = RailsControllerContext(
            controller=controller,
            superclass=raw_superclass,
            ancestry=ancestry,
            inheritance_complete=complete,
            local_filters=tuple(item for item in local if item.kind != "skip:before"),
            local_skips=tuple(item for item in local if item.kind == "skip:before"),
            _events=events,
        )
    return contexts


__all__ = [
    "RailsActionContext",
    "RailsCallback",
    "RailsControllerContext",
    "analyze_rails_controller_inheritance",
]


