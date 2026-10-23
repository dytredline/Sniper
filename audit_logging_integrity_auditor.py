from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
from scanner import _finding, calculate_score as _scanner_calculate_score
import taint_flow
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500
MAX_CHAIN_ENTRIES = 100_000
MAX_CHAIN_ISSUES = 1_000
FUNCTION_WINDOW_LINES = 40

AUDIT_LOGGING_CONTROLS_EVALUATED: list[str] = [
    "SNIPER-LOGG-01",
    "SNIPER-LOGG-03",
    "SNIPER-LOGG-04",
    "SNIPER-LOGG-05",
    "SNIPER-LOGG-06",
]

AUDIT_LOGGING_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".java",
    ".kt",
    ".kts",
    ".gradle",
    ".rb",
    ".php",
    ".cs",
}

# Build manifests that may pin a vulnerable log4j-core version.
AUDIT_LOGGING_EXTRA_FILENAMES: set[str] = {"pom.xml"}

AUDIT_CHAIN_REQUIRED_FIELDS: tuple[str, ...] = ("actor", "action", "timestamp", "outcome")
AUDIT_CHAIN_GENESIS_VALUES: frozenset[str] = frozenset({"", "0" * 64})

_CATEGORY = "audit_logging"

# --- Detector patterns -------------------------------------------------------

LOG_SINK_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:logger|logging|log|LOG|LOGGER|Log)\."
    r"(?:info|warning|warn|error|debug|critical|exception|fatal|trace|notice|"
    r"Printf|Println|Print|Fatalf|Fatal|Panicf|i|e|d|w|v)\s*\("
    r"|\bconsole\.(?:log|warn|error|info|debug)\s*\("
    r"|\bSystem\.(?:out|err)\.print(?:ln|f)?\s*\("
    r"|\bRails\.logger\.\w+"
    r"|\berror_log\s*\("
)

REQUEST_INPUT_RE = re.compile(
    r"\brequest\.(?:args|form|json|get_json|headers|values|data|cookies|GET|POST|query_params|body|params|query)\b"
    r"|\breq\.(?:query|body|params|headers|cookies)\b"
    r"|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b"
    r"|\br\.URL\.Query\b|\br\.FormValue\b|\br\.Header\.Get\b"
    r"|\bgetParameter\s*\(|\bgetHeader\s*\("
    r"|\bparams\["
)

INTERPOLATION_RE = re.compile(
    r"""\b[rR]?[fF][rR]?["']"""          # Python f-string
    r"""|["']\s*%\s*[\w(\[{]"""          # "..." % value
    r"""|%[-+0-9.]*[sdvqifx]"""          # printf-style placeholder
    r"""|\+"""                           # concatenation
    r"""|\$\{|#\{"""                     # JS template literal / Ruby interpolation
    r"""|\.format\s*\("""                # str.format
    r"""|\{\}"""                         # slf4j / format placeholder
    r"""|["']\s*\.\s*\$|\$\w+\s*\.\s*["']"""  # PHP concatenation
)

SANITIZE_RE = re.compile(
    r"""replace\s*\(\s*(?:['"]\\[rn]|/)|replaceAll\s*\(|sanitiz|escape|strip_control"""
    r"""|repr\s*\(|json\.dumps\s*\(|JSON\.stringify\s*\(|%r|!r\b|encodeURIComponent|quote\s*\(""",
    re.IGNORECASE,
)

ANSI_STRIP_RE = re.compile(r"\\x1b|\\u001b|\\033|\\e\[", re.IGNORECASE)

LOG4J_GRADLE_RE = re.compile(
    r"""log4j-core\s*['"]?\s*[:,]\s*(?:version\s*[:=]\s*)?['"]?(\d+)\.(\d+)(?:\.(\d+))?""",
    re.IGNORECASE,
)
LOG4J_MAVEN_RE = re.compile(
    r"<artifactId>\s*log4j-core\s*</artifactId>\s*(?:<[^>]+>[^<]*</[^>]+>\s*){0,2}?"
    r"<version>\s*(\d+)\.(\d+)(?:\.(\d+))?",
    re.IGNORECASE,
)
JNDI_RE = re.compile(r"\$\{\s*jndi\s*:|\$\{\s*\$\{\s*(?:lower|upper|::-)", re.IGNORECASE)

SENSITIVE_ENDPOINT_RE = re.compile(
    r"admin|delete|remove|transfer|payment|payout|refund|password|role|permission|grant|"
    r"user|account|token|key|export|settings",
    re.IGNORECASE,
)

LOG_CALL_RE = re.compile(
    r"(?i:audit)"
    r"|logger\."
    r"|(?<![A-Za-z])log(?:ging)?\."
    r"|console\.(?:log|info|warn|error)"
    r"|record_event|security_event"
    r"|Log\.[iedwv]\s*\("
    r"|\berror_log\s*\("
    r"|\b(?:slog|zap|logrus)\."
)

PY_ROUTE_VERB_RE = re.compile(r"^\s*@[\w.]+\.(post|put|patch|delete)\s*\(", re.IGNORECASE)
PY_ROUTE_GENERIC_RE = re.compile(r"^\s*@[\w.]+\.(?:route|api_route|add_url_rule)\s*\(", re.IGNORECASE)
PY_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
PY_DECORATOR_RE = re.compile(r"^\s*@")
DJANGO_DELETE_RE = re.compile(r"^\s*(?:async\s+)?def\s+delete\s*\(\s*self\b")
PATH_LITERAL_RE = re.compile(r"""\(\s*[rRbBuU]?['"`]([^'"`]*)['"`]""")

SPRING_ROUTE_RE = re.compile(
    r"^\s*@(?:(?:Post|Put|Delete|Patch)Mapping\b|RequestMapping\s*\([^)]*RequestMethod\.(?:POST|PUT|DELETE|PATCH))"
)
JAVA_METHOD_NAME_RE = re.compile(r"\b(\w+)\s*\(")

AUTH_FUNC_RE = re.compile(
    r"^\s*(?:async\s+)?def\s+(?P<py>(?:log_?in|authenticate|sign_?in)\w*)\s*\("
    r"|\bfunction\s+(?P<js>(?:log_?in|authenticate|sign_?in)\w*)\s*\("
    r"|\b(?:const|let|var)\s+(?P<jsv>(?:log_?in|authenticate|sign_?in)\w*)\s*=\s*(?:async\s*)?(?:function\b|\()"
    r"|\bfunc\s+(?:\([^)]*\)\s*)?(?P<go>(?:log_?in|authenticate|sign_?in)\w*)\s*\("
    r"|^\s*(?:async\s+)?(?P<method>(?:log_?in|authenticate|sign_?in)\w*)\s*\([^)]*\)\s*\{",
    re.IGNORECASE,
)
AUTH_FUNC_EXCLUDE_RE = re.compile(r"required|url|manager|page|template|form|redirect|test", re.IGNORECASE)

AUDIT_CALL_RE = re.compile(r"(?<![\w])(audit_log|audit|AuditLog|record_event)\s*\(")
AUDIT_DEFINITION_LINE_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:def|function|func|fun|class|interface|type|import|from|public|private|protected|static)\b"
)
AUDIT_ACTOR_RE = re.compile(r"user|actor|principal|subject|uid", re.IGNORECASE)
AUDIT_OUTCOME_RE = re.compile(r"outcome|status|result", re.IGNORECASE)

_LOG_TARGET = r"(?:\blog|_log|\.log\b|audit)"
TAMPER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""\bopen\s*\(\s*[^,)]*""" + _LOG_TARGET + r"""[^,)]*,\s*(?:mode\s*=\s*)?['"]w[bt+]*['"]""", re.IGNORECASE),
    re.compile(r"""FileHandler\s*\([^)]*mode\s*=\s*['"]w""", re.IGNORECASE),
    re.compile(
        r"""\b(?:os\.remove|os\.unlink|shutil\.rmtree|fs\.unlinkSync|fs\.unlink|fs\.rmSync|unlink|File\.Delete|Files\.delete(?:IfExists)?)"""
        r"""\s*\([^)]*""" + _LOG_TARGET,
        re.IGNORECASE,
    ),
    re.compile(r"""\b(?:truncate|ftruncate)\s*\([^\n]*""" + _LOG_TARGET, re.IGNORECASE),
    re.compile(_LOG_TARGET + r"""[^\n]*\.truncate\s*\(""", re.IGNORECASE),
    re.compile(r"""writeFileSync\s*\(\s*[^,]*""" + _LOG_TARGET, re.IGNORECASE),
)


# --- Helpers -----------------------------------------------------------------


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _make_logg_finding(
    *,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    clean_ev = evidence.strip()[:320]
    reference = f"OWASP ASVS V7 · OWASP Logging Cheat Sheet · {cwe}"
    item = _finding(
        severity,
        _CATEGORY,
        title,
        description,
        f"{filename}:{line} · {clean_ev}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), control_id, cwe),
    )
    item["cwe"] = cwe
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    return item


def _is_comment(stripped: str) -> bool:
    if stripped.startswith("#{"):
        return False
    return stripped.startswith(("#", "//", "/*", "*", "--"))


def _strip_py_comment(text: str) -> str:
    return text.split("#", 1)[0]


def _indent_of(text: str) -> int:
    return len(text) - len(text.lstrip())


def _single_line_python_body(code: str) -> str | None:
    """Return text after a top-level signature colon using one forward pass."""
    depth = 0
    saw_open = False
    quote = ""
    escaped = False
    for index, character in enumerate(code):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in "([{":
            depth += 1
            saw_open = True
        elif character in ")]}" and depth:
            depth -= 1
        elif character == ":" and saw_open and depth == 0:
            body = code[index + 1:].lstrip()
            return body or None
    return None


def _has_mutating_python_methods(block: str) -> bool:
    """Parse decorator ``methods=`` lists without scanning suffixes repeatedly."""
    folded = block.casefold()
    cursor = 0
    while True:
        marker = folded.find("methods", cursor)
        if marker < 0:
            return False
        position = marker + len("methods")
        while position < len(block) and block[position].isspace():
            position += 1
        if position >= len(block) or block[position] != "=":
            cursor = marker + len("methods")
            continue
        position += 1
        while position < len(block) and block[position].isspace():
            position += 1
        if position >= len(block) or block[position] not in "[({":
            cursor = marker + len("methods")
            continue
        end = position + 1
        while end < len(block) and block[end] not in "])}":
            end += 1
        values = folded[position + 1:end]
        for method in ("post", "put", "patch", "delete"):
            if any(left + method + right in values for left in ("'", '"') for right in ("'", '"')):
                return True
        if end >= len(block):
            return False
        cursor = end + 1


def _javascript_mutation_route(line: str) -> tuple[str, str, int] | None:
    """Return ``(method, path, match_end)`` for the first JS mutation route."""
    cursor = 0
    while True:
        dot = line.find(".", cursor)
        if dot < 0:
            return None
        start = dot
        while start > 0 and (line[start - 1] == "_" or line[start - 1].isalnum()):
            start -= 1
        receiver = line[start:dot]
        valid_receiver = receiver in {"app", "router", "server", "route", "routes"} or (
            bool(receiver)
            and (receiver[0] == "_" or receiver[0].isascii() and receiver[0].isalpha())
            and receiver.endswith("Router")
            and all(character == "_" or character.isalnum() for character in receiver)
        )
        if not valid_receiver:
            cursor = dot + 1
            continue
        method = next((name for name in ("post", "put", "patch", "delete") if line.startswith(name, dot + 1)), None)
        if method is None:
            cursor = dot + 1
            continue
        position = dot + 1 + len(method)
        while position < len(line) and line[position].isspace():
            position += 1
        if position >= len(line) or line[position] != "(":
            cursor = dot + 1
            continue
        position += 1
        while position < len(line) and line[position].isspace():
            position += 1
        if position >= len(line) or line[position] not in "'\"`":
            cursor = dot + 1
            continue
        path_start = position + 1
        path_end = path_start
        while path_end < len(line) and line[path_end] not in "'\"`":
            path_end += 1
        if path_end >= len(line):
            return None
        return method, line[path_start:path_end], path_end + 1


def _java_auth_function_name(line: str) -> str | None:
    """Extract a Java auth-method name without a whitespace-ambiguous regex."""
    stripped = line.lstrip()
    modifier = next(
        (value for value in ("public", "private", "protected") if stripped.startswith(value) and
         len(stripped) > len(value) and stripped[len(value)].isspace()),
        None,
    )
    if modifier is None or ";" in stripped:
        return None
    opening = stripped.find("(", len(modifier))
    if opening < 0:
        return None
    end = opening
    while end > 0 and stripped[end - 1].isspace():
        end -= 1
    start = end
    while start > 0 and (stripped[start - 1] == "_" or stripped[start - 1].isalnum()):
        start -= 1
    name = stripped[start:end]
    prefix = stripped[len(modifier):start]
    if not prefix or not prefix[-1].isspace() or not prefix.strip():
        return None
    folded = name.casefold()
    prefixes = ("login", "log_in", "authenticate", "signin", "sign_in")
    if not any(folded.startswith(prefix) for prefix in prefixes):
        return None
    if not all(character == "_" or character.isalnum() for character in name):
        return None
    return name


def _python_body(lines: list[str], def_idx: int, max_lines: int = FUNCTION_WINDOW_LINES) -> str:
    """Return the body of a Python function (indentation based, capped)."""
    indent = _indent_of(lines[def_idx])
    sig_end = None
    for j in range(def_idx, min(len(lines), def_idx + 10)):
        code = _strip_py_comment(lines[j]).rstrip()
        if code.endswith(":"):
            sig_end = j
            break
        if j == def_idx:
            single = _single_line_python_body(code)
            if single is not None:
                return single
    if sig_end is None:
        return ""
    body: list[str] = []
    for k in range(sig_end + 1, min(len(lines), sig_end + 1 + max_lines)):
        text = lines[k]
        if not text.strip():
            continue
        if _indent_of(text) <= indent:
            break
        body.append(text)
    return "\n".join(body)


def _brace_body(lines: list[str], start_idx: int, max_lines: int = FUNCTION_WINDOW_LINES) -> tuple[str, bool]:
    """Return (body, opened) for a brace-delimited block starting near start_idx.

    `opened` is False when no opening brace is found within the first four lines,
    which usually means the handler is a reference defined elsewhere.
    """
    depth = 0
    opened = False
    collected: list[str] = []
    for k in range(start_idx, min(len(lines), start_idx + max_lines)):
        text = lines[k]
        if not opened and k >= start_idx + 4:
            break
        if opened:
            collected.append(text)
        elif "{" in text:
            collected.append(text[text.index("{") + 1:])
        for ch in text:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if opened and depth <= 0:
            break
    return "\n".join(collected), opened


def _has_log_call(body: str) -> bool:
    code_lines = [
        text for text in body.splitlines() if text.strip() and not _is_comment(text.strip())
    ]
    return bool(LOG_CALL_RE.search("\n".join(code_lines)))


def _call_arguments(lines: list[str], idx: int, open_col: int, max_lines: int = 4) -> str:
    depth = 0
    out: list[str] = []
    for k in range(idx, min(len(lines), idx + max_lines)):
        segment = lines[k][open_col:] if k == idx else lines[k]
        for ch in segment:
            out.append(ch)
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return "".join(out)
        out.append("\n")
    return "".join(out)


def _is_vulnerable_log4j(major: int, minor: int, patch: int) -> bool:
    if major != 2:
        return False
    if (minor, patch) >= (17, 1):
        return False
    # Backported fixes for older Java runtimes.
    if minor == 12 and patch >= 4:
        return False
    if minor == 3 and patch >= 2:
        return False
    return True


def _detect_mutation_routes(lines: list[str], is_python: bool) -> list[dict[str, Any]]:
    """Find state-changing route handlers and whether their body emits a log/audit call."""
    routes: list[dict[str, Any]] = []
    processed_defs: set[int] = set()
    total = len(lines)

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue

        if is_python:
            verb = PY_ROUTE_VERB_RE.match(line)
            generic = PY_ROUTE_GENERIC_RE.match(line)
            if verb or generic:
                def_idx = None
                for k in range(idx, min(total, idx + 12)):
                    if PY_DEF_RE.match(lines[k]):
                        def_idx = k
                        break
                if def_idx is None or def_idx in processed_defs:
                    continue
                block = "\n".join(lines[idx:def_idx + 1])
                if not (verb or _has_mutating_python_methods(block)):
                    continue
                processed_defs.add(def_idx)
                def_match = PY_DEF_RE.match(lines[def_idx])
                name = def_match.group(2) if def_match else ""
                path_match = PATH_LITERAL_RE.search(line)
                path = path_match.group(1) if path_match else ""
                body = _python_body(lines, def_idx)
                routes.append(
                    {
                        "line": idx + 1,
                        "def_idx": def_idx,
                        "name": name,
                        "path": path,
                        "sensitive": bool(SENSITIVE_ENDPOINT_RE.search(f"{path} {name}")),
                        "analyzable": True,
                        "logged": _has_log_call(body),
                        "evidence": stripped,
                    }
                )
                continue
            if DJANGO_DELETE_RE.match(line) and idx not in processed_defs:
                processed_defs.add(idx)
                body = _python_body(lines, idx)
                routes.append(
                    {
                        "line": idx + 1,
                        "def_idx": idx,
                        "name": "delete",
                        "path": "",
                        "sensitive": True,
                        "analyzable": True,
                        "logged": _has_log_call(body),
                        "evidence": stripped,
                    }
                )
            continue

        js_match = _javascript_mutation_route(line)
        if js_match and not stripped.startswith("@"):
            _method, path, match_end = js_match
            rest = line[match_end:]
            reference_only = "{" not in line and stripped.rstrip(";").endswith(")")
            if reference_only:
                body, opened = "", False
            else:
                body, opened = _brace_body(lines, idx)
            routes.append(
                {
                    "line": idx + 1,
                    "def_idx": idx,
                    "name": "",
                    "path": path,
                    "sensitive": bool(SENSITIVE_ENDPOINT_RE.search(f"{path} {rest}")),
                    "analyzable": opened,
                    "logged": _has_log_call(body) if opened else True,
                    "evidence": stripped,
                }
            )
            continue

        if SPRING_ROUTE_RE.match(line):
            sig_idx = idx + 1
            while sig_idx < total and sig_idx < idx + 6 and lines[sig_idx].strip().startswith("@"):
                sig_idx += 1
            if sig_idx >= total:
                continue
            name_match = JAVA_METHOD_NAME_RE.search(lines[sig_idx])
            name = name_match.group(1) if name_match else ""
            path_match = PATH_LITERAL_RE.search(line)
            path = path_match.group(1) if path_match else ""
            body, opened = _brace_body(lines, sig_idx)
            routes.append(
                {
                    "line": idx + 1,
                    "def_idx": sig_idx,
                    "name": name,
                    "path": path,
                    "sensitive": bool(SENSITIVE_ENDPOINT_RE.search(f"{path} {name}")),
                    "analyzable": opened,
                    "logged": _has_log_call(body) if opened else True,
                    "evidence": stripped,
                }
            )
    return routes


# --- Public API --------------------------------------------------------------


def compute_entry_hash(entry: dict[str, Any], *, hash_field: str = "hash") -> str:
    """SHA-256 over canonical JSON of the entry without its own hash field."""
    if not isinstance(entry, dict):
        raise ValueError("Günlük kaydı bir sözlük (dict) olmalıdır.")
    payload = {key: value for key, value in entry.items() if key != hash_field}
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def verify_hash_chained_log(
    entries: list[dict[str, Any]],
    *,
    hash_field: str = "hash",
    prev_field: str = "prev_hash",
) -> dict[str, Any]:
    if not isinstance(entries, list):
        raise ValueError("Denetim günlüğü kayıtları bir liste olmalıdır.")
    if len(entries) > MAX_CHAIN_ENTRIES:
        raise ValueError(f"Kayıt sayısı güvenli sınırı ({MAX_CHAIN_ENTRIES}) aşıyor.")
    if any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("Denetim günlüğündeki her kayıt bir sözlük (dict) olmalıdır.")
    if not isinstance(hash_field, str) or not hash_field.strip():
        raise ValueError("Özet (hash) alan adı boş olamaz.")
    if not isinstance(prev_field, str) or not prev_field.strip() or prev_field == hash_field:
        raise ValueError("Önceki özet alan adı boş olamaz ve özet alanından farklı olmalıdır.")

    issues: list[dict[str, Any]] = []
    state = {"count": 0, "first": None}

    def _issue(index: int, kind: str, detail: str) -> None:
        state["count"] += 1
        if state["first"] is None or index < state["first"]:
            state["first"] = index
        if len(issues) < MAX_CHAIN_ISSUES:
            issues.append({"index": index, "kind": kind, "detail": detail})

    previous_hash: str | None = None
    previous_ts: datetime | None = None

    for index, entry in enumerate(entries):
        for field in AUDIT_CHAIN_REQUIRED_FIELDS:
            value = entry.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                _issue(index, "missing_field", f"Zorunlu '{field}' alanı eksik veya boş.")

        stored = entry.get(hash_field)
        stored_valid = isinstance(stored, str) and bool(stored.strip())
        if not stored_valid:
            _issue(index, "missing_field", f"'{hash_field}' özet alanı eksik veya boş.")
        else:
            try:
                expected = compute_entry_hash(entry, hash_field=hash_field)
            except (TypeError, ValueError):
                _issue(index, "hash_mismatch", "Kayıt kanonik JSON biçimine dönüştürülemedi.")
            else:
                if not hmac.compare_digest(
                    expected.encode("ascii"), stored.strip().lower().encode("utf-8")
                ):
                    _issue(
                        index,
                        "hash_mismatch",
                        "Saklanan özet, kaydın kanonik SHA-256 özetiyle eşleşmiyor (kayıt değiştirilmiş olabilir).",
                    )

        prev_value = entry.get(prev_field)
        if index == 0:
            if not isinstance(prev_value, str) or prev_value not in AUDIT_CHAIN_GENESIS_VALUES:
                _issue(
                    index,
                    "chain_break",
                    f"İlk kaydın '{prev_field}' alanı boş dize veya 64 sıfır olmalıdır.",
                )
        elif previous_hash is not None:
            if not isinstance(prev_value, str) or prev_value != previous_hash:
                _issue(
                    index,
                    "chain_break",
                    f"'{prev_field}' önceki kaydın özetiyle eşleşmiyor (kayıt silinmiş, eklenmiş veya yeniden sıralanmış olabilir).",
                )

        raw_ts = entry.get("timestamp")
        if raw_ts is not None and not (isinstance(raw_ts, str) and not raw_ts.strip()):
            parsed = _parse_timestamp(raw_ts)
            if parsed is None:
                _issue(index, "bad_timestamp", "Zaman damgası ISO-8601 biçiminde ayrıştırılamadı.")
            else:
                if previous_ts is not None and parsed < previous_ts:
                    _issue(index, "time_regression", "Zaman damgası önceki kayıttan daha eski (zaman geriye gidiyor).")
                if previous_ts is None or parsed >= previous_ts:
                    previous_ts = parsed

        previous_hash = stored if stored_valid else None

    return {
        "format": "sniper-hash-chained-log-verification-v1",
        "entry_count": len(entries),
        "hash_algorithm": "sha256",
        "valid": state["count"] == 0,
        "first_broken_index": state["first"],
        "issue_count": state["count"],
        "issues_truncated": state["count"] > len(issues),
        "issues": issues,
    }


def audit_logging_inline(
    raw_content: str,
    *,
    filename: str = "app.py",
) -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek günlükleme (logging) kaynak içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "app.py"
    clean_filename = filename.strip()
    is_python = clean_filename.lower().endswith(".py")
    lines = raw_content.splitlines()

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int]] = set()

    def _add(finding: dict[str, Any]) -> None:
        key = (finding["control_id"], finding["cwe"], int(finding["line"]))
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(finding)

    has_ansi_strip = bool(ANSI_STRIP_RE.search(raw_content))
    analysis = taint_flow.analyze_source(raw_content, clean_filename)

    def _log_injection_description(flow: taint_flow.Flow | None) -> str:
        text = (
            "İstek kaynaklı veri, satır sonu (CR/LF) ve kontrol karakterleri temizlenmeden günlük "
            "çağrısına biçimlendirilerek aktarılıyor. Saldırgan sahte günlük satırları üretebilir, "
            "SIEM ayrıştırmasını bozabilir veya olay izini gizleyebilir."
        )
        if flow is not None:
            text += f" Veri akışı: {flow.describe()}."
        if not has_ansi_strip:
            text += (
                " Dosyada ANSI kaçış dizisi (\\x1b) temizliği de görülmüyor; günlükler terminalde "
                "görüntülendiğinde terminal enjeksiyonu mümkündür."
            )
        return text

    # 1a. Veri akışı (taint): değişkene atanmış veya çok satırlı çağrıdaki istek girdisi.
    if analysis is not None:
        for flow in analysis.flows_of("log", "request"):
            if flow.sink == "print" or not 1 <= flow.line <= len(lines):
                continue
            finding = _make_logg_finding(
                severity="medium",
                title="Günlük enjeksiyonu: istek verisi temizlenmeden günlüğe yazılıyor",
                description=_log_injection_description(flow),
                evidence=lines[flow.line - 1].strip(),
                recommendation=(
                    "Kullanıcı girdisini günlüğe yazmadan önce \\r, \\n ve \\x1b karakterlerini kaldırın "
                    "veya kodlayın (ör. repr()/json.dumps()); yapılandırılmış (JSON) günlük biçimi kullanın."
                ),
                cwe="CWE-117",
                control_id="SNIPER-LOGG-03",
                filename=clean_filename,
                line=flow.line,
            )
            finding["taint_flow"] = flow.as_dict()
            _add(finding)

    # 1b. Satır tabanlı sezgisel (taint analizinin desteklemediği diller / ayrıştırılamayan dosyalar).
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue
        sink = LOG_SINK_RE.search(line)
        if not sink:
            continue
        args = line[sink.start():]
        if not REQUEST_INPUT_RE.search(args):
            continue
        if not INTERPOLATION_RE.search(args):
            continue
        if SANITIZE_RE.search(args):
            continue
        if analysis is not None and analysis.is_clean_sink("log", idx + 1, "request"):
            # Taint analizi bu günlük çağrısını değerlendirdi ve istek verisinin arındırıldığını
            # (ör. int()/len()/.length) gösterdi: satır tabanlı yanlış pozitif bastırılır.
            continue
        description = _log_injection_description(None)
        _add(
            _make_logg_finding(
                severity="medium",
                title="Günlük enjeksiyonu: istek verisi temizlenmeden günlüğe yazılıyor",
                description=description,
                evidence=stripped,
                recommendation=(
                    "Kullanıcı girdisini günlüğe yazmadan önce \\r, \\n ve \\x1b karakterlerini kaldırın "
                    "veya kodlayın (ör. repr()/json.dumps()); yapılandırılmış (JSON) günlük biçimi kullanın."
                ),
                cwe="CWE-117",
                control_id="SNIPER-LOGG-03",
                filename=clean_filename,
                line=idx + 1,
            )
        )

    # 2. Log4Shell: vulnerable log4j-core (critical) and literal JNDI lookups (high), CWE-917, SNIPER-LOGG-04.
    for regex in (LOG4J_GRADLE_RE, LOG4J_MAVEN_RE):
        for match in regex.finditer(raw_content):
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3) or 0)
            if not _is_vulnerable_log4j(major, minor, patch):
                continue
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_logg_finding(
                    severity="critical",
                    title=f"Log4Shell'e açık log4j-core sürümü ({major}.{minor}.{patch})",
                    description=(
                        "log4j-core 2.17.1 öncesi sürümler JNDI arama (lookup) özelliği üzerinden uzaktan "
                        "kod yürütmeye (CVE-2021-44228, CVE-2021-45046, CVE-2021-44832) açıktır. "
                        "Günlüğe yazılan herhangi bir saldırgan girdisi istismar tetikleyebilir."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "log4j-core bağımlılığını en az 2.17.1 (Java 8+) sürümüne yükseltin; geçiş sürecinde "
                        "JndiLookup sınıfını kaldırın ve bağımlılık ağacını (transitive) doğrulayın."
                    ),
                    cwe="CWE-917",
                    control_id="SNIPER-LOGG-04",
                    filename=clean_filename,
                    line=line_no,
                )
            )
    for match in JNDI_RE.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_logg_finding(
                severity="high",
                title="Kaynakta JNDI arama ifadesi (${jndi:...}) bulundu",
                description=(
                    "Kodda veya yapılandırmada '${jndi:' (veya gizlenmiş varyantı) ifadesi yer alıyor. "
                    "Bu, Log4Shell istismar yükü, test kalıntısı ya da güvensiz mesaj araması (lookup) olabilir."
                ),
                evidence=snippet,
                recommendation=(
                    "İfadenin kaynağını doğrulayın; günlükleme kütüphanesinde mesaj aramalarını devre dışı bırakın "
                    "(log4j2.formatMsgNoLookups / 2.17.1+) ve test yüklerini üretim kodundan kaldırın."
                ),
                cwe="CWE-917",
                control_id="SNIPER-LOGG-04",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 4. Unlogged sensitive mutation endpoints ("sessiz uç nokta"), CWE-778, SNIPER-LOGG-01.
    routes = _detect_mutation_routes(lines, is_python)
    covered_defs: set[int] = set()
    sensitive_count = 0
    unlogged_count = 0
    for route in routes:
        if not route["analyzable"]:
            continue
        covered_defs.add(int(route["def_idx"]))
        if not route["sensitive"]:
            continue
        sensitive_count += 1
        if route["logged"]:
            continue
        unlogged_count += 1
        label = route["path"] or route["name"] or "?"
        _add(
            _make_logg_finding(
                severity="medium",
                title="Sessiz uç nokta: hassas değişiklik denetim kaydı üretmiyor",
                description=(
                    f"Durum değiştiren hassas uç nokta ({label}) gövdesinde herhangi bir denetim/günlük "
                    "çağrısı bulunamadı. Yetki, ödeme, silme veya hesap değişiklikleri iz bırakmadan "
                    "gerçekleşebilir; olay müdahalesi ve inkâr edilemezlik zayıflar."
                ),
                evidence=route["evidence"],
                recommendation=(
                    "Hassas işlemlerde kim (actor), ne (action), hangi kaynak (target), ne zaman (timestamp) "
                    "ve sonuç (outcome) alanlarını içeren yapılandırılmış bir denetim kaydı üretin."
                ),
                cwe="CWE-778",
                control_id="SNIPER-LOGG-01",
                filename=clean_filename,
                line=int(route["line"]),
            )
        )

    # 5. Audit calls missing actor / outcome fields (low, CWE-778, SNIPER-LOGG-05).
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped) or AUDIT_DEFINITION_LINE_RE.match(line):
            continue
        match = AUDIT_CALL_RE.search(line)
        if not match:
            continue
        before = line[:match.start()]
        if re.search(r"\b(?:def|function|func|fun)\s+$", before):
            continue
        arguments = _call_arguments(lines, idx, match.end() - 1)
        missing: list[str] = []
        if not AUDIT_ACTOR_RE.search(arguments):
            missing.append("actor (kullanıcı/özne)")
        if not AUDIT_OUTCOME_RE.search(arguments):
            missing.append("outcome (sonuç/durum)")
        if not missing:
            continue
        _add(
            _make_logg_finding(
                severity="low",
                title="Denetim kaydında zorunlu alanlar eksik",
                description=(
                    f"'{match.group(1)}(...)' çağrısında şu alanlar görülmüyor: {', '.join(missing)}. "
                    "Eksik alanlar olayın kim tarafından ve hangi sonuçla yapıldığının kanıtlanmasını engeller."
                ),
                evidence=stripped,
                recommendation=(
                    "Her denetim kaydına actor, action, target, timestamp ve outcome alanlarını ekleyin "
                    "(OWASP Logging Cheat Sheet 'Which events to log' bölümü)."
                ),
                cwe="CWE-778",
                control_id="SNIPER-LOGG-05",
                filename=clean_filename,
                line=idx + 1,
            )
        )

    # 6. Log tampering surface (medium, CWE-117, SNIPER-LOGG-06).
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped):
            continue
        if not any(pattern.search(line) for pattern in TAMPER_PATTERNS):
            continue
        _add(
            _make_logg_finding(
                severity="medium",
                title="Denetim günlüğü üzerine yazılıyor veya siliniyor",
                description=(
                    "Günlük/denetim dosyası yazma ('w') kipinde açılıyor, kırpılıyor (truncate) veya siliniyor. "
                    "Önceki kayıtlar kaybolur ve ele geçirilmiş bir süreç izlerini silebilir (CWE-117 / CWE-779)."
                ),
                evidence=stripped,
                recommendation=(
                    "Günlükleri yalnızca ekleme ('a') kipinde açın, döndürmeyi (rotation) logrotate/RotatingFileHandler "
                    "ile yapın ve denetim kayıtlarını değiştirilemez (WORM / hash zincirli) bir depoya iletin."
                ),
                cwe="CWE-117",
                control_id="SNIPER-LOGG-06",
                filename=clean_filename,
                line=idx + 1,
            )
        )

    # 7. Authentication functions without any log call (low, CWE-778, SNIPER-LOGG-01).
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_comment(stripped) or idx in covered_defs:
            continue
        match = AUTH_FUNC_RE.search(line)
        java_name = _java_auth_function_name(line)
        if not match and java_name is None:
            continue
        name = java_name or next((value for value in match.groupdict().values() if value), "")
        if not name or AUTH_FUNC_EXCLUDE_RE.search(name):
            continue
        is_python_match = bool(match and match.group("py"))
        if is_python or is_python_match:
            if not is_python_match:
                continue
            body = _python_body(lines, idx)
            if not body.strip():
                continue
        else:
            body, opened = _brace_body(lines, idx)
            if not opened:
                continue
        if _has_log_call(body):
            continue
        _add(
            _make_logg_finding(
                severity="low",
                title="Kimlik doğrulama olayı günlüğe yazılmıyor",
                description=(
                    f"'{name}' kimlik doğrulama fonksiyonunda başarılı/başarısız giriş denemelerini kaydeden "
                    "bir günlük çağrısı bulunamadı. Kaba kuvvet ve kimlik bilgisi doldurma (credential stuffing) "
                    "saldırıları fark edilmeyebilir."
                ),
                evidence=stripped,
                recommendation=(
                    "Başarılı ve başarısız oturum açma denemelerini kullanıcı kimliği (parola olmadan), kaynak IP, "
                    "zaman ve sonuç alanlarıyla günlüğe yazın."
                ),
                cwe="CWE-778",
                control_id="SNIPER-LOGG-01",
                filename=clean_filename,
                line=idx + 1,
            )
        )

    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, INLINE_FINDING_LIMIT)
    return {
        "format": "sniper-audit-logging-inline-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "mutation_endpoint_count": len(routes),
        "sensitive_mutation_count": sensitive_count,
        "unlogged_mutation_count": unlogged_count,
        "controls_evaluated": list(AUDIT_LOGGING_CONTROLS_EVALUATED),
    }


@project_scan_scope
@taint_flow.project_context
def audit_logging_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    taint_flow.activate_project_js_handlers(root, SKIP_DIRS)
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    mutation_endpoint_count = 0
    sensitive_mutation_count = 0
    unlogged_mutation_count = 0

    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() not in SKIP_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(files):
            if scanned_files >= MAX_PROJECT_FILES:
                break
            file_path = Path(current) / name
            if file_path.is_symlink():
                continue
            ext = file_path.suffix.lower()
            if ext not in AUDIT_LOGGING_EXTENSIONS and name.casefold() not in AUDIT_LOGGING_EXTRA_FILENAMES:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            rel_name = str(file_path.relative_to(root))
            scanned_files += 1
            try:
                file_report = audit_logging_inline(content, filename=rel_name)
            except ValueError:
                continue
            findings.extend(file_report["findings"])
            mutation_endpoint_count += int(file_report["mutation_endpoint_count"])
            sensitive_mutation_count += int(file_report["sensitive_mutation_count"])
            unlogged_mutation_count += int(file_report["unlogged_mutation_count"])

    score, grade = calculate_score(findings)
    finding_groups = summarize_finding_groups(findings)
    findings, total_finding_count, findings_truncated = cap_findings(findings, PROJECT_FINDING_LIMIT)
    return {
        "format": "sniper-audit-logging-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": total_finding_count,
        "findings_truncated": findings_truncated,
        "finding_groups": finding_groups,
        "findings": findings,
        "mutation_endpoint_count": mutation_endpoint_count,
        "sensitive_mutation_count": sensitive_mutation_count,
        "unlogged_mutation_count": unlogged_mutation_count,
        "controls_evaluated": list(AUDIT_LOGGING_CONTROLS_EVALUATED),
    }
