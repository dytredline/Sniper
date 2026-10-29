"""Symbolic path constraint solver and concrete witness input synthesizer.

Evaluates guard predicates along multi-hop attack paths and execution branches
to eliminate algebraically unreachable (UNSAT) false-positive chains and
synthesize concrete triggering inputs (witnesses) for reachable (SAT) paths.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
import re
from typing import Any


PROOF_FORMAT = "sniper-symbolic-path-constraint-proof/1"
CHAIN_FILTER_FORMAT = "sniper-symbolic-chain-filter/1"

_IDENT_RE = r"[A-Za-z_][A-Za-z0-9_.]*"
_NUM_RE = r"-?\d+(?:\.\d+)?"

_CHAINED_CMP_RE = re.compile(
    rf"^\s*({_NUM_RE})\s*(<=|<|>=|>)\s*({_IDENT_RE})\s*(<=|<|>=|>)\s*({_NUM_RE})\s*$"
)
_VAR_NUM_CMP_RE = re.compile(
    rf"^\s*({_IDENT_RE})\s*(==|!=|<=|>=|<|>)\s*({_NUM_RE})\s*$"
)
_NUM_VAR_CMP_RE = re.compile(
    rf"^\s*({_NUM_RE})\s*(==|!=|<=|>=|<|>)\s*({_IDENT_RE})\s*$"
)
_STARTSWITH_RE = re.compile(
    rf"^\s*(not\s+)?({_IDENT_RE})\.startswith\(\s*(['\"])(.*?)\3\s*\)\s*$"
)
_ENDSWITH_RE = re.compile(
    rf"^\s*(not\s+)?({_IDENT_RE})\.endswith\(\s*(['\"])(.*?)\3\s*\)\s*$"
)
_IN_COLLECTION_RE = re.compile(
    rf"^\s*({_IDENT_RE})\s+(not\s+in|in)\s+(\[.*\]|\(.*\)|\\{{.*?\\}})\s*$"
)
_IS_BOOL_RE = re.compile(
    rf"^\s*({_IDENT_RE})\s+(is\s+not|is|==|!=)\s+(True|False|true|false|None|null)\s*$"
)
_VAR_STR_CMP_RE = re.compile(
    rf"^\s*({_IDENT_RE})\s*(==|!=)\s*(['\"])(.*?)\3\s*$"
)
_STR_VAR_CMP_RE = re.compile(
    rf"^\s*(['\"])(.*?)\1\s*(==|!=)\s*({_IDENT_RE})\s*$"
)
_NOT_VAR_RE = re.compile(
    rf"^\s*(?:not\s+|!\s*)({_IDENT_RE})\s*$"
)
_BARE_VAR_RE = re.compile(
    rf"^\s*({_IDENT_RE})\s*$"
)

_REVERSE_OP = {
    "<": ">",
    "<=": ">=",
    ">": "<",
    ">=": "<=",
    "==": "==",
    "!=": "!=",
}

_KEYWORDS = frozenset({
    "and", "or", "not", "in", "is", "if", "elif", "else", "True", "False",
    "None", "true", "false", "null", "return", "pass", "break", "continue",
})


def _parse_number(raw: str) -> int | float:
    if "." in raw:
        val = float(raw)
        return int(val) if val.is_integer() else val
    return int(raw)


def _strip_outer_parens(expr: str) -> str:
    text = expr.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        balanced = True
        for idx, ch in enumerate(text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx < len(text) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            text = text[1:-1].strip()
        else:
            break
    return text


def _split_conjunctions(expr: str) -> list[str]:
    """Split a guard line on top-level `and` or `&&` operators."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if quote is not None:
            buf.append(ch)
            if ch == quote and (i == 0 or expr[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
            continue
        if depth == 0:
            if expr[i : i + 2] == "&&":
                piece = "".join(buf).strip()
                if piece:
                    parts.append(piece)
                buf = []
                i += 2
                continue
            if ch.isspace():
                token_start = i
                while token_start < n and expr[token_start].isspace():
                    token_start += 1
                token_end = token_start + 3
                if (
                    expr[token_start:token_end] == "and"
                    and token_end < n
                    and expr[token_end].isspace()
                ):
                    while token_end < n and expr[token_end].isspace():
                        token_end += 1
                    piece = "".join(buf).strip()
                    if piece:
                        parts.append(piece)
                    buf = []
                    i = token_end
                    continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_atomic_guards(guards: list[str] | str) -> list[str]:
    raw_lines: list[str] = []
    if isinstance(guards, str):
        raw_lines.extend(guards.splitlines())
    elif isinstance(guards, (list, tuple, set)):
        for item in guards:
            if isinstance(item, str):
                raw_lines.extend(item.splitlines())

    atomic: list[str] = []
    for line in raw_lines:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith(("#", "//", "/*")):
            continue
        # Strip inline comments outside quotes
        statement_body: str | None = None
        for keyword in ("if", "elif", "while", "assert", "guard"):
            if cleaned.startswith(keyword):
                boundary = len(keyword)
                if boundary == len(cleaned) or not (
                    cleaned[boundary] == "_" or cleaned[boundary].isalnum()
                ):
                    statement_body = cleaned[boundary:].strip()
                    break
        if statement_body is not None:
            cleaned = statement_body
            if cleaned.endswith(":"):
                cleaned = cleaned[:-1].strip()
            if cleaned.endswith("{"):
                cleaned = cleaned[:-1].strip()
        elif cleaned.endswith((":", "{", ";")):
            cleaned = cleaned[:-1].strip()

        if not cleaned or cleaned in ("else", "try", "finally"):
            continue
        cleaned = _strip_outer_parens(cleaned)
        for sub in _split_conjunctions(cleaned):
            sub_clean = _strip_outer_parens(sub)
            if sub_clean:
                atomic.append(sub_clean)
    return atomic


def _new_domain(var: str) -> dict[str, Any]:
    return {
        "variable": var,
        "type": "unknown",
        "lower_bound": None,
        "lower_inclusive": True,
        "upper_bound": None,
        "upper_inclusive": True,
        "is_float": False,
        "exact_values": [],
        "allowed_set": None,
        "excluded_values": [],
        "prefixes": [],
        "excluded_prefixes": [],
        "suffixes": [],
        "truthy": None,
        "raw_guards": [],
    }


def _add_unique(seq: list[Any], val: Any) -> None:
    if not any(type(x) is type(val) and x == val for x in seq):
        seq.append(val)


def _apply_numeric_constraint(dom: dict[str, Any], op: str, num: int | float) -> None:
    if dom["type"] == "unknown":
        dom["type"] = "numeric"
    if isinstance(num, float) and not num.is_integer():
        dom["is_float"] = True

    if op == "==":
        _add_unique(dom["exact_values"], num)
        if dom["lower_bound"] is None or num > dom["lower_bound"]:
            dom["lower_bound"] = num
            dom["lower_inclusive"] = True
        elif num == dom["lower_bound"]:
            pass
        if dom["upper_bound"] is None or num < dom["upper_bound"]:
            dom["upper_bound"] = num
            dom["upper_inclusive"] = True
    elif op == "!=":
        _add_unique(dom["excluded_values"], num)
    elif op == ">":
        if dom["lower_bound"] is None or num > dom["lower_bound"] or (num == dom["lower_bound"] and dom["lower_inclusive"]):
            dom["lower_bound"] = num
            dom["lower_inclusive"] = False
    elif op == ">=":
        if dom["lower_bound"] is None or num > dom["lower_bound"]:
            dom["lower_bound"] = num
            dom["lower_inclusive"] = True
    elif op == "<":
        if dom["upper_bound"] is None or num < dom["upper_bound"] or (num == dom["upper_bound"] and dom["upper_inclusive"]):
            dom["upper_bound"] = num
            dom["upper_inclusive"] = False
    elif op == "<=":
        if dom["upper_bound"] is None or num < dom["upper_bound"]:
            dom["upper_bound"] = num
            dom["upper_inclusive"] = True


def _value_in_numeric_bounds(val: Any, dom: dict[str, Any]) -> bool:
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        return True
    lb = dom["lower_bound"]
    ub = dom["upper_bound"]
    if lb is not None:
        if val < lb or (val == lb and not dom["lower_inclusive"]):
            return False
    if ub is not None:
        if val > ub or (val == ub and not dom["upper_inclusive"]):
            return False
    return True


def _value_excluded(val: Any, excluded: list[Any]) -> bool:
    for ex in excluded:
        if isinstance(val, (int, float)) and not isinstance(val, bool) and isinstance(ex, (int, float)) and not isinstance(ex, bool):
            if val == ex:
                return True
        elif type(val) is type(ex) and val == ex:
            return True
    return False


def _evaluate_domain_and_witness(
    var: str,
    dom: dict[str, Any],
    contradictions: list[str],
) -> Any:
    """Validate a single variable domain for algebraic satisfiability and synthesize a witness value."""
    local_contradictions: list[str] = []

    # 1. Multiple conflicting exact values (var == A and var == B)
    exact_vals = dom["exact_values"]
    if len(exact_vals) > 1:
        first = exact_vals[0]
        for other in exact_vals[1:]:
            if first != other or (type(first) is not type(other) and not (isinstance(first, (int, float)) and isinstance(other, (int, float)))):
                local_contradictions.append(
                    f"Conflicting equality assignments on '{var}': {first!r} != {other!r}"
                )

    # 2. Exact value in excluded_values (var == A and var != A)
    for ev in exact_vals:
        if _value_excluded(ev, dom["excluded_values"]):
            local_contradictions.append(
                f"Direct equality/inequality contradiction on '{var}': {var} == {ev!r} and {var} != {ev!r}"
            )
        if not _value_in_numeric_bounds(ev, dom):
            local_contradictions.append(
                f"Equality value {var} == {ev!r} violates numeric bounds [{dom['lower_bound']}, {dom['upper_bound']}]"
            )

    # 3. Numeric interval bounds check
    lb = dom["lower_bound"]
    ub = dom["upper_bound"]
    lb_inc = dom["lower_inclusive"]
    ub_inc = dom["upper_inclusive"]
    if lb is not None and ub is not None:
        if lb > ub:
            local_contradictions.append(
                f"Unsatisfiable numeric interval on '{var}': lower_bound ({lb}) > upper_bound ({ub})"
            )
        elif lb == ub and not (lb_inc and ub_inc):
            local_contradictions.append(
                f"Unsatisfiable strict numeric interval on '{var}': lower_bound == upper_bound ({lb}) with strict inequality"
            )
        elif not dom["is_float"]:
            min_int = int(math.ceil(lb)) if lb_inc else int(math.floor(lb)) + 1
            max_int = int(math.floor(ub)) if ub_inc else int(math.ceil(ub)) - 1
            if min_int > max_int:
                local_contradictions.append(
                    f"Empty integer interval on '{var}': no integer satisfies bounds ({lb}, {ub})"
                )
            elif max_int - min_int <= 64:
                candidates = [
                    c for c in range(min_int, max_int + 1)
                    if not _value_excluded(c, dom["excluded_values"])
                ]
                if not candidates:
                    local_contradictions.append(
                        f"All integer values in interval [{min_int}, {max_int}] for '{var}' are excluded"
                    )

    # 4. Prefix compatibility checks
    prefixes: list[str] = dom["prefixes"]
    longest_prefix = ""
    if prefixes:
        longest_prefix = max(prefixes, key=len)
        for p in prefixes:
            if not longest_prefix.startswith(p):
                local_contradictions.append(
                    f"Conflicting string prefixes on '{var}': startswith({p!r}) vs startswith({longest_prefix!r})"
                )
        for ep in dom["excluded_prefixes"]:
            if longest_prefix.startswith(ep) or ep.startswith(longest_prefix):
                if longest_prefix.startswith(ep):
                    local_contradictions.append(
                        f"Contradictory startswith constraint on '{var}': requires prefix {longest_prefix!r} but forbids {ep!r}"
                    )
        for ev in exact_vals:
            if isinstance(ev, str) and not ev.startswith(longest_prefix):
                local_contradictions.append(
                    f"Value {var} == {ev!r} does not satisfy startswith({longest_prefix!r})"
                )

    # 5. Truthiness contradictions
    truthy = dom["truthy"]
    if truthy is False:
        if longest_prefix:
            local_contradictions.append(
                f"Truthiness contradiction on '{var}': requires falsy value but also non-empty prefix {longest_prefix!r}"
            )
        for ev in exact_vals:
            if bool(ev) is True:
                local_contradictions.append(
                    f"Truthiness contradiction on '{var}': requires falsy value but {var} == {ev!r}"
                )
        if lb is not None and (lb > 0 or (lb == 0 and not lb_inc)):
            local_contradictions.append(
                f"Truthiness contradiction on '{var}': requires falsy (0) but numeric bound forces > 0"
            )
    elif truthy is True:
        for ev in exact_vals:
            if bool(ev) is False:
                local_contradictions.append(
                    f"Truthiness contradiction on '{var}': requires truthy value but {var} == {ev!r}"
                )
        if lb == 0 and ub == 0 and lb_inc and ub_inc:
            local_contradictions.append(
                f"Truthiness contradiction on '{var}': requires truthy value but numeric bounds force 0"
            )

    # 6. Allowed set validation
    allowed_set = dom["allowed_set"]
    valid_allowed: list[Any] = []
    if allowed_set is not None:
        for item in allowed_set:
            if _value_excluded(item, dom["excluded_values"]):
                continue
            if not _value_in_numeric_bounds(item, dom):
                continue
            if exact_vals and not any(item == ev for ev in exact_vals):
                continue
            if longest_prefix and isinstance(item, str) and not item.startswith(longest_prefix):
                continue
            if truthy is not None and bool(item) is not truthy:
                continue
            valid_allowed.append(item)
        if not valid_allowed:
            local_contradictions.append(
                f"All allowed set members for '{var}' ({allowed_set!r}) are excluded or violate bounds"
            )

    if local_contradictions:
        contradictions.extend(local_contradictions)
        return None

    # Synthesize concrete witness value
    if exact_vals:
        return exact_vals[0]

    if allowed_set is not None and valid_allowed:
        return valid_allowed[0]

    if dom["type"] == "numeric" or lb is not None or ub is not None:
        if lb is not None and ub is not None:
            if not dom["is_float"]:
                start = int(math.ceil(lb)) if lb_inc else int(math.floor(lb)) + 1
                end = int(math.floor(ub)) if ub_inc else int(math.ceil(ub)) - 1
                for cand in range(start, end + 1):
                    if truthy is True and cand == 0:
                        continue
                    if not _value_excluded(cand, dom["excluded_values"]):
                        return cand
            mid = (float(lb) + float(ub)) / 2.0
            if _value_excluded(mid, dom["excluded_values"]):
                mid = (float(lb) + mid) / 2.0
            return mid
        if lb is not None:
            if not dom["is_float"]:
                cand = int(math.ceil(lb)) if lb_inc else int(math.floor(lb)) + 1
                while _value_excluded(cand, dom["excluded_values"]) or (truthy is True and cand == 0):
                    cand += 1
                return cand
            cand_f = float(lb) if lb_inc else float(lb) + 1.0
            while _value_excluded(cand_f, dom["excluded_values"]):
                cand_f += 1.0
            return cand_f
        if ub is not None:
            if not dom["is_float"]:
                cand = int(math.floor(ub)) if ub_inc else int(math.ceil(ub)) - 1
                while _value_excluded(cand, dom["excluded_values"]) or (truthy is True and cand == 0):
                    cand -= 1
                return cand
            cand_f = float(ub) if ub_inc else float(ub) - 1.0
            while _value_excluded(cand_f, dom["excluded_values"]):
                cand_f -= 1.0
            return cand_f
        cand = 0 if truthy is False else 1
        while _value_excluded(cand, dom["excluded_values"]):
            cand += 1
        return cand

    if longest_prefix:
        suffix = dom["suffixes"][0] if dom["suffixes"] else "probe"
        sep = "" if longest_prefix.endswith(("/", "_", "-", ":")) else "_"
        cand_str = f"{longest_prefix}{sep}{suffix}" if not longest_prefix.endswith("/") else f"{longest_prefix}{suffix}"
        idx = 1
        while _value_excluded(cand_str, dom["excluded_values"]) or any(
            cand_str.startswith(ep) for ep in dom["excluded_prefixes"]
        ):
            cand_str = f"{longest_prefix}{sep}{suffix}_{idx}"
            idx += 1
        return cand_str

    if dom["type"] == "string" or any(isinstance(x, str) for x in dom["excluded_values"]):
        if truthy is False:
            return ""
        for candidate in ("guest_probe", "user_probe", "probe_value", "synthetic_witness"):
            if not _value_excluded(candidate, dom["excluded_values"]) and not any(
                candidate.startswith(ep) for ep in dom["excluded_prefixes"]
            ):
                return candidate
        return "probe_fallback_1"

    if truthy is not None:
        return bool(truthy)

    return "probe"


def solve_path_constraints_and_synthesize_input(
    guards: list[str] | str,
    *,
    route_params: list[str] | None = None,
) -> dict[str, Any]:
    """Parse path guard predicates, check satisfiability (SAT/UNSAT), and synthesize a concrete witness."""
    atomic_guards = _extract_atomic_guards(guards)
    domains: dict[str, dict[str, Any]] = {}
    contradictions: list[str] = []

    def _dom(name: str) -> dict[str, Any]:
        if name not in domains:
            domains[name] = _new_domain(name)
        return domains[name]

    for guard in atomic_guards:
        # 1. Chained numeric comparisons: e.g. 10 < x <= 20
        m_chain = _CHAINED_CMP_RE.match(guard)
        if m_chain:
            n1_raw, op1, var, op2, n2_raw = m_chain.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            _apply_numeric_constraint(d, _REVERSE_OP[op1], _parse_number(n1_raw))
            _apply_numeric_constraint(d, op2, _parse_number(n2_raw))
            continue

        # 2. var.startswith('prefix') / not var.startswith('prefix')
        m_sw = _STARTSWITH_RE.match(guard)
        if m_sw:
            neg, var, _q, prefix = m_sw.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            d["type"] = "string"
            if neg:
                _add_unique(d["excluded_prefixes"], prefix)
            else:
                _add_unique(d["prefixes"], prefix)
            continue

        # 3. var.endswith('suffix')
        m_ew = _ENDSWITH_RE.match(guard)
        if m_ew:
            neg, var, _q, suffix = m_ew.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            d["type"] = "string"
            if not neg:
                _add_unique(d["suffixes"], suffix)
            continue

        # 4. var in (...) / var not in (...)
        m_in = _IN_COLLECTION_RE.match(guard)
        if m_in:
            var, op_in, coll_raw = m_in.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            try:
                parsed_coll = list(ast.literal_eval(coll_raw))
            except Exception:
                parsed_coll = [
                    s.strip().strip("'\"")
                    for s in coll_raw.strip("()[]{}").split(",")
                    if s.strip()
                ]
            if any(isinstance(x, str) for x in parsed_coll):
                d["type"] = "string"
            elif any(isinstance(x, (int, float)) for x in parsed_coll):
                d["type"] = "numeric"

            is_not_in = "not" in op_in.split()
            if is_not_in:
                for item in parsed_coll:
                    _add_unique(d["excluded_values"], item)
            else:
                if d["allowed_set"] is None:
                    d["allowed_set"] = list(parsed_coll)
                else:
                    d["allowed_set"] = [x for x in d["allowed_set"] if x in parsed_coll]
            continue

        # 5. Boolean / None identity or equality: var is True, var == False, etc.
        m_bool = _IS_BOOL_RE.match(guard)
        if m_bool:
            var, op_b, literal_raw = m_bool.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            lit_low = literal_raw.lower()
            target_truth = lit_low == "true"
            is_neg_op = op_b in ("!=", "is not") or "not" in op_b.split()
            effective_truth = (not target_truth) if is_neg_op else target_truth
            if d["truthy"] is not None and d["truthy"] != effective_truth:
                contradictions.append(
                    f"Boolean truthiness contradiction on '{var}': requires both {d['truthy']} and {effective_truth}"
                )
            d["truthy"] = effective_truth
            if d["type"] == "unknown":
                d["type"] = "boolean"
            continue

        # 6. Numeric comparison: var op N
        m_vn = _VAR_NUM_CMP_RE.match(guard)
        if m_vn:
            var, op, num_raw = m_vn.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            _apply_numeric_constraint(d, op, _parse_number(num_raw))
            continue

        # 7. Reversed numeric comparison: N op var
        m_nv = _NUM_VAR_CMP_RE.match(guard)
        if m_nv:
            num_raw, op, var = m_nv.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            _apply_numeric_constraint(d, _REVERSE_OP[op], _parse_number(num_raw))
            continue

        # 8. String equality / inequality: var == 'val' or var != 'val'
        m_vs = _VAR_STR_CMP_RE.match(guard)
        if m_vs:
            var, op, _q, val = m_vs.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            d["type"] = "string"
            if op == "==":
                _add_unique(d["exact_values"], val)
            else:
                _add_unique(d["excluded_values"], val)
            continue

        m_sv = _STR_VAR_CMP_RE.match(guard)
        if m_sv:
            _q, val, op, var = m_sv.groups()
            d = _dom(var)
            d["raw_guards"].append(guard)
            d["type"] = "string"
            if op == "==":
                _add_unique(d["exact_values"], val)
            else:
                _add_unique(d["excluded_values"], val)
            continue

        # 9. Negated variable: not var / !var
        m_not = _NOT_VAR_RE.match(guard)
        if m_not:
            var = m_not.group(1)
            if var not in _KEYWORDS:
                d = _dom(var)
                d["raw_guards"].append(guard)
                if d["truthy"] is True:
                    contradictions.append(
                        f"Boolean truthiness contradiction on '{var}': both truthy ({var}) and falsy (not {var})"
                    )
                d["truthy"] = False
            continue

        # 10. Bare truthy variable: var
        m_bare = _BARE_VAR_RE.match(guard)
        if m_bare:
            var = m_bare.group(1)
            if var not in _KEYWORDS:
                d = _dom(var)
                d["raw_guards"].append(guard)
                if d["truthy"] is False:
                    contradictions.append(
                        f"Boolean truthiness contradiction on '{var}': both falsy (not {var}) and truthy ({var})"
                    )
                d["truthy"] = True
            continue

    concrete_witness: dict[str, Any] = {}
    variable_domains: dict[str, dict[str, Any]] = {}

    for var, dom in domains.items():
        witness_val = _evaluate_domain_and_witness(var, dom, contradictions)
        variable_domains[var] = {
            "type": dom["type"],
            "lower_bound": dom["lower_bound"],
            "lower_inclusive": dom["lower_inclusive"],
            "upper_bound": dom["upper_bound"],
            "upper_inclusive": dom["upper_inclusive"],
            "exact_values": list(dom["exact_values"]),
            "allowed_set": list(dom["allowed_set"]) if dom["allowed_set"] is not None else None,
            "excluded_values": list(dom["excluded_values"]),
            "prefixes": list(dom["prefixes"]),
            "truthy": dom["truthy"],
        }
        if witness_val is not None:
            concrete_witness[var] = witness_val

    satisfiable = len(contradictions) == 0

    if satisfiable and route_params:
        for param in route_params:
            if not isinstance(param, str) or not param.strip():
                continue
            p_name = param.strip()
            if p_name not in concrete_witness:
                low_p = p_name.lower()
                if any(tok in low_p for tok in ("id", "count", "num", "step", "amount", "limit", "page")):
                    concrete_witness[p_name] = 1
                else:
                    concrete_witness[p_name] = f"{p_name}_probe"

    canonical_payload = json.dumps(
        {
            "guards": atomic_guards,
            "satisfiable": satisfiable,
            "contradictions": contradictions,
            "concrete_witness": concrete_witness if satisfiable else {},
        },
        sort_keys=True,
        default=str,
    )
    evidence_sha256 = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

    return {
        "format": PROOF_FORMAT,
        "status": "SAT" if satisfiable else "UNSAT",
        "satisfiability": "SAT" if satisfiable else "UNSAT",
        "satisfiable": satisfiable,
        "false_positive_eliminated": not satisfiable,
        "contradictions": contradictions,
        "variable_domains": variable_domains,
        "concrete_witness": concrete_witness if satisfiable else {},
        "evidence_sha256": evidence_sha256,
    }


def _collect_chain_guards(chain: dict[str, Any]) -> list[str]:
    collected: list[str] = []
    for key in ("guards", "conditions", "path_constraints", "predicates"):
        val = chain.get(key)
        if isinstance(val, str) and val.strip():
            collected.append(val)
        elif isinstance(val, (list, tuple, set)):
            for item in val:
                if isinstance(item, str) and item.strip():
                    collected.append(item)

    for step_key in ("steps", "hops"):
        steps = chain.get(step_key)
        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                for g_key in ("guard", "condition", "guards", "conditions", "predicate"):
                    g_val = step.get(g_key)
                    if isinstance(g_val, str) and g_val.strip():
                        collected.append(g_val)
                    elif isinstance(g_val, (list, tuple, set)):
                        for item in g_val:
                            if isinstance(item, str) and item.strip():
                                collected.append(item)
    return collected


def filter_unreachable_attack_chains(chains: list[dict[str, Any]]) -> dict[str, Any]:
    """Filter multi-hop attack chains by solving path guard constraints (SAT vs UNSAT)."""
    reachable_chains: list[dict[str, Any]] = []
    eliminated_unsat_chains: list[dict[str, Any]] = []

    if not isinstance(chains, list):
        chains = []

    for chain in chains:
        if not isinstance(chain, dict):
            continue
        guards = _collect_chain_guards(chain)
        route_params = chain.get("route_params") if isinstance(chain.get("route_params"), list) else None
        proof = solve_path_constraints_and_synthesize_input(guards, route_params=route_params)

        enriched = dict(chain)
        enriched["symbolic_status"] = proof["status"]
        enriched["symbolic_proof"] = proof
        if proof["satisfiable"]:
            enriched["concrete_witness"] = proof["concrete_witness"]
            enriched["false_positive_eliminated"] = False
            reachable_chains.append(enriched)
        else:
            enriched["concrete_witness"] = {}
            enriched["contradictions"] = proof["contradictions"]
            enriched["false_positive_eliminated"] = True
            eliminated_unsat_chains.append(enriched)

    return {
        "format": CHAIN_FILTER_FORMAT,
        "total_chains": len(reachable_chains) + len(eliminated_unsat_chains),
        "reachable_count": len(reachable_chains),
        "eliminated_unsat_count": len(eliminated_unsat_chains),
        "reachable_chains": reachable_chains,
        "eliminated_unsat_chains": eliminated_unsat_chains,
    }
