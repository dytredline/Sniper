"""Bounded, conservative binding check for the local Semgrep TLS rule.

The Semgrep pattern is a candidate generator. Only exact AST calls on a
single, unaliased top-level requests import with literal verify=False survive.
Ambiguous imports, bindings, and dynamic namespace operations suppress this
rule's findings for the whole source file. Source is never executed or returned
through the API.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from project_analyzer import MAX_FILE_BYTES
from tool_report_semgrep import MAX_FINDINGS


_RULE_SUFFIX = "sniper.python.requests-get-verify-false"
_DYNAMIC_NAMESPACE_CALLS = {
    "exec", "eval", "globals", "locals", "vars", "__import__", "setattr", "delattr"
}


def _is_rule(check_id: object) -> bool:
    return isinstance(check_id, str) and (
        check_id == _RULE_SUFFIX or check_id.endswith("." + _RULE_SUFFIX)
    )


def _requests_attribute_target(node: ast.AST) -> bool:
    """Detect syntactic writes such as requests.get = replacement."""
    if not isinstance(node, (ast.Attribute, ast.Subscript)):
        return False
    value = node.value
    while isinstance(value, (ast.Attribute, ast.Subscript)):
        value = value.value
    return isinstance(value, ast.Name) and value.id == "requests"


def _qualified_calls(tree: ast.Module) -> set[tuple[int, int]]:
    imports = [
        node
        for node in tree.body
        if isinstance(node, ast.Import)
        and any(alias.name == "requests" and alias.asname is None for alias in node.names)
    ]
    if len(imports) != 1:
        return set()
    imported_line = imports[0].lineno
    ambiguous = False
    qualified: set[tuple[int, int]] = set()

    # One walk per source file, independent of the number of Semgrep findings.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "requests" and not isinstance(node.ctx, ast.Load):
            ambiguous = True
        elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)) and _requests_attribute_target(node):
            ambiguous = True
        elif isinstance(node, ast.arg) and node.arg == "requests":
            ambiguous = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == "requests":
            ambiguous = True
        elif isinstance(node, ast.ExceptHandler) and node.name == "requests":
            ambiguous = True
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and "requests" in node.names:
            ambiguous = True
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == "requests":
            ambiguous = True
        elif isinstance(node, ast.MatchMapping) and node.rest == "requests":
            ambiguous = True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "requests" and alias.asname is None:
                    if node is not imports[0]:
                        ambiguous = True
                elif alias.asname == "requests" or alias.name.startswith("requests."):
                    ambiguous = True
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" or (alias.asname or alias.name) == "requests" for alias in node.names):
                ambiguous = True

        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in _DYNAMIC_NAMESPACE_CALLS:
            ambiguous = True
        if node.lineno <= imported_line:
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and isinstance(func.value, ast.Name)
            and func.value.id == "requests"
        ):
            continue
        if any(keyword.arg is None for keyword in node.keywords):
            continue
        verifies = [keyword.value for keyword in node.keywords if keyword.arg == "verify"]
        if len(verifies) == 1 and isinstance(verifies[0], ast.Constant) and verifies[0].value is False:
            qualified.add((node.lineno, node.col_offset + 1))
    return set() if ambiguous else qualified


def filter_direct_requests_tls_findings(results: list[Any], input_dir: Path) -> list[Any]:
    # Apply the existing parser's 500-finding cap before opening or parsing
    # source, including candidate-rule findings that might later be suppressed.
    if len(results) > MAX_FINDINGS:
        raise ValueError("Semgrep raporu geçerli JSON değil.")
    root = input_dir.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Semgrep raporu geçerli JSON değil.")
    cache: dict[Path, tuple[set[tuple[int, int]], tuple[int, ...]]] = {}
    accepted: list[Any] = []
    for finding in results:
        if not isinstance(finding, dict):
            raise ValueError("Semgrep raporu geçerli JSON değil.")
        check_id = finding.get("check_id")
        if not _is_rule(check_id):
            accepted.append(finding)
            continue
        raw_path = finding.get("path")
        start = finding.get("start")
        if not (
            isinstance(raw_path, str) and raw_path and isinstance(start, dict)
            and type(start.get("line")) is int and start["line"] > 0
            and type(start.get("col")) is int and start["col"] > 0
        ):
            raise ValueError("Semgrep raporu geçerli JSON değil.")
        source_path = Path(raw_path)
        if not source_path.is_absolute():
            source_path = root / source_path
        try:
            if source_path.is_symlink() or not source_path.is_file():
                raise ValueError("Semgrep raporu geçerli JSON değil.")
            source_path = source_path.resolve(strict=True)
            if not source_path.is_relative_to(root) or source_path.suffix != ".py":
                raise ValueError("Semgrep raporu geçerli JSON değil.")
            if source_path not in cache:
                if source_path.stat().st_size > MAX_FILE_BYTES:
                    raise ValueError("Semgrep raporu geçerli JSON değil.")
                source = source_path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename="<local-snapshot>")
                line_lengths = tuple(len(line.encode("utf-8")) for line in source.splitlines())
                cache[source_path] = (_qualified_calls(tree), line_lengths)
        except (OSError, UnicodeError, SyntaxError, RuntimeError) as exc:
            raise ValueError("Semgrep raporu geçerli JSON değil.") from exc
        qualified, line_lengths = cache[source_path]
        if start["line"] > len(line_lengths) or start["col"] > line_lengths[start["line"] - 1] + 1:
            raise ValueError("Semgrep raporu geçerli JSON değil.")
        if (start["line"], start["col"]) in qualified:
            accepted.append(finding)
    return accepted
