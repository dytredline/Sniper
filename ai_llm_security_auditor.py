from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from project_tree import ProjectTree
from scanner import _finding, calculate_score as _scanner_calculate_score
from finding_limits import INLINE_FINDING_LIMIT, PROJECT_FINDING_LIMIT, cap_findings, summarize_finding_groups, project_scan_scope


MAX_INLINE_BYTES = 512_000
MAX_PROJECT_FILES = 1_500

OWASP_LLM_TOP_10_2025: dict[str, str] = {
    "LLM01": "LLM01: Prompt Injection",
    "LLM02": "LLM02: Hassas Bilgi İfşası (Sensitive Information Disclosure)",
    "LLM03": "LLM03: Yapay Zeka Tedarik Zinciri (Supply Chain)",
    "LLM04": "LLM04: Veri ve Model Zehirlenmesi (Data and Model Poisoning)",
    "LLM05": "LLM05: Güvensiz Çıktı İşleme (Improper Output Handling)",
    "LLM06": "LLM06: Aşırı Ajan Yetkisi (Excessive Agency)",
    "LLM07": "LLM07: Sistem Promptu Sızıntısı (System Prompt Leakage)",
    "LLM08": "LLM08: Vektör ve Gömme Zafiyetleri (Vector and Embedding Weaknesses)",
    "LLM09": "LLM09: Yanlış Bilgi / Halüsinasyon Güvenliği (Misinformation)",
    "LLM10": "LLM10: Sınırsız Tüketim (Unbounded Consumption)",
}

DEFAULT_CONTROLS_EVALUATED: set[str] = {
    "SNIPER-INPV-07",
    "SNIPER-CRYP-04",
    "SNIPER-SRVR-06",
    "SNIPER-AUTHZ-02",
    "SNIPER-APIT-05",
}

AI_SCAN_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".vue",
    ".svelte",
    ".html",
}

FRONTEND_EXTENSIONS: set[str] = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".vue",
    ".svelte",
    ".html",
}

_UNTRUSTED_INPUT_VARS = (
    r"(?:user_input|user_prompt|user_message|user_query|raw_prompt|prompt_param|"
    r"input_text|untrusted_input|req\.body(?:\.[A-Za-z0-9_]+)?|req\.query(?:\.[A-Za-z0-9_]+)?|"
    r"request\.args(?:\.get\([^)]*\)|\[[^\]]+\])?|request\.form(?:\.get\([^)]*\)|\[[^\]]+\])?|"
    r"request\.json(?:\.get\([^)]*\)|\[[^\]]+\])?|query)"
)

_AI_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI Project API Key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{8,}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-(?!proj-|ant-)[A-Za-z0-9]{16,}\b")),
    ("Google Gemini API Key", re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b")),
    ("HuggingFace Access Token", re.compile(r"\bhf_[A-Za-z0-9]{14,}\b")),
    ("Replicate API Token", re.compile(r"\br8_[A-Za-z0-9]{14,}\b")),
    ("Groq API Key", re.compile(r"\bgsk_[A-Za-z0-9]{14,}\b")),
    ("xAI API Key", re.compile(r"\bxai-[A-Za-z0-9_-]{14,}\b")),
    (
        "AI Provider API Key",
        re.compile(
            r"(?i)\b(?:cohere_api_key|groq_api_key|openai_api_key|anthropic_api_key|"
            r"huggingface_api_key|replicate_api_token|gemini_api_key|mistral_api_key|"
            r"deepseek_api_key|xai_api_key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{14,})[\"']"
        ),
    ),
)

_SECRET_REDACT_RE = re.compile(
    r"\b(?:sk-proj-[A-Za-z0-9_-]{4,}|sk-ant-[A-Za-z0-9_-]{4,}|sk-[A-Za-z0-9]{10,}|"
    r"AIzaSy[A-Za-z0-9_-]{10,}|hf_[A-Za-z0-9]{8,}|r8_[A-Za-z0-9]{8,}|"
    r"gsk_[A-Za-z0-9]{8,}|xai-[A-Za-z0-9_-]{8,})\b"
)

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_WHITESPACE_RUN = re.compile(r"\s*")
_SYSTEM_PROMPT_NAMES = ("system_prompt", "systemprompt")
_LLM_OUTPUT_ASSIGNMENT_MARKERS = (
    "response.choices",
    "chat.completions.create",
    "messages.create",
    "generate_content",
    ".invoke(",
)
_AI_SIGNAL_MARKERS = (
    "prompt", "messages", "user_input", "user_query", "req.body", "req.query", "request.args",
    "request.form", "request.json", "sk-", "aizasy", "hf_", "r8_", "gsk_", "xai-", "_api_key",
    "replicate_api_token", "torch.load", "pickle.", "joblib.", "dill.", "cloudpickle.",
    "trust_remote_code", "load_dataset", "trainer", "response.choices", "chat.completions",
    "messages.create", "generate_content", ".invoke(", "llm_", "ai_reply", "completion", "model_output",
    "agent_output", "assistant_reply", "generated_", "@tool", ".tool(", "mcp", "structuredtool",
    "function_declarations", "tools", "pyautogui", "xdotool", "pynput", "computer_use",
    "similarity_search", "vector", "qdrant", "pinecone", "chromadb", "weaviate", "temperature",
)


def calculate_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    score, grade, _counts = _scanner_calculate_score(findings)
    return score, grade


def _redact_secrets(text: str) -> str:
    def _mask(match: re.Match[str]) -> str:
        val = match.group(0)
        if val.startswith("sk-proj-"):
            return "sk-proj-***[REDACTED]***"
        if val.startswith("sk-ant-"):
            return "sk-ant-***[REDACTED]***"
        if val.startswith("sk-"):
            return "sk-***[REDACTED]***"
        if val.startswith("hf_"):
            return "hf_***[REDACTED]***"
        if val.startswith("r8_"):
            return "r8_***[REDACTED]***"
        if val.startswith("gsk_"):
            return "gsk_***[REDACTED]***"
        if val.startswith("AIzaSy"):
            return "AIzaSy***[REDACTED]***"
        if val.startswith("xai-"):
            return "xai-***[REDACTED]***"
        return "***[REDACTED]***"

    redacted = _SECRET_REDACT_RE.sub(_mask, text)
    redacted = re.sub(
        r"(?i)((?:cohere_api_key|groq_api_key|openai_api_key|anthropic_api_key|"
        r"huggingface_api_key|replicate_api_token|gemini_api_key|mistral_api_key|"
        r"deepseek_api_key|xai_api_key)\s*[:=]\s*[\"'])([^\"']+)([\"'])",
        r"\1***[REDACTED]***\3",
        redacted,
    )
    return redacted


def _make_llm_finding(
    *,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    cwe: str,
    control_id: str,
    llm_risk: str,
    filename: str,
    line: int,
) -> dict[str, Any]:
    safe_evidence = _redact_secrets(evidence.strip())[:320]
    reference = f"OWASP {OWASP_LLM_TOP_10_2025.get(llm_risk, llm_risk)} · {cwe}"
    item = _finding(
        severity,
        category,
        title,
        description,
        f"{filename}:{line} · {safe_evidence}",
        recommendation,
        reference,
        cookie_identity=(filename, str(line), llm_risk, control_id),
    )
    item["cwe"] = cwe
    item["owasp"] = OWASP_LLM_TOP_10_2025.get(llm_risk, llm_risk)
    item["llm_risk"] = llm_risk
    item["control_id"] = control_id
    item["file"] = filename
    item["line"] = line
    return item


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, max(0, offset)) + 1


def _system_prompt_exposure_offset(source_line: str) -> int | None:
    """Find a client-visible system-prompt marker with bounded forward scans.

    This intentionally replaces a regex whose ``localStorage.setItem(...)``
    branch combined overlapping unbounded repetitions. A missing closing token
    then caused quadratic backtracking on attacker-controlled project text.
    """
    lowered = source_line.translate(_ASCII_LOWER)
    candidates: list[int] = []

    # Public frontend environment variable names. The variable tail is the
    # same ASCII identifier alphabet previously accepted by ``[A-Z0-9_]*``.
    for prefix in ("next_public_", "vite_", "react_app_"):
        cursor = 0
        while True:
            start = lowered.find(prefix, cursor)
            if start < 0:
                break
            tail_start = start + len(prefix)
            tail_end = tail_start
            while tail_end < len(lowered) and (
                "a" <= lowered[tail_end] <= "z"
                or "0" <= lowered[tail_end] <= "9"
                or lowered[tail_end] == "_"
            ):
                tail_end += 1
            if lowered.find("system_prompt", tail_start, tail_end) >= 0:
                candidates.append(start)
                break
            cursor = max(tail_end, tail_start)

    def _prompt_name_at(offset: int) -> bool:
        return any(lowered.startswith(name, offset) for name in _SYSTEM_PROMPT_NAMES)

    # ``export const`` and ``window.`` forms have only bounded literal checks
    # plus a single whitespace pass.
    cursor = 0
    while True:
        start = lowered.find("export", cursor)
        if start < 0:
            break
        offset = start + len("export")
        if offset < len(lowered) and lowered[offset].isspace():
            offset = _WHITESPACE_RUN.match(lowered, offset).end()
            if lowered.startswith("const", offset):
                offset += len("const")
                offset = _WHITESPACE_RUN.match(lowered, offset).end()
                if _prompt_name_at(offset):
                    candidates.append(start)
                    break
        cursor = start + len("export")

    cursor = 0
    while True:
        start = lowered.find("window.", cursor)
        if start < 0:
            break
        offset = start + len("window.")
        offset = _WHITESPACE_RUN.match(lowered, offset).end()
        if _prompt_name_at(offset):
            candidates.append(start)
            break
        cursor = start + len("window.")

    # Examine each non-overlapping call segment once. If a call is unterminated,
    # the remainder is inspected once and the scan ends.
    cursor = 0
    local_storage = "localstorage.setitem("
    while True:
        start = lowered.find(local_storage, cursor)
        if start < 0:
            break
        content_start = start + len(local_storage)
        close = lowered.find(")", content_start)
        content_end = len(lowered) if close < 0 else close
        if any(lowered.find(name, content_start, content_end) >= 0 for name in _SYSTEM_PROMPT_NAMES):
            candidates.append(start)
            break
        if close < 0:
            break
        cursor = close + 1

    # Quoted direct assignment: SYSTEM_PROMPT = "at least eight characters".
    cursor = 0
    assignment_name = "system_prompt"
    while True:
        start = lowered.find(assignment_name, cursor)
        if start < 0:
            break
        previous = source_line[start - 1] if start else ""
        offset = start + len(assignment_name)
        offset = _WHITESPACE_RUN.match(source_line, offset).end()
        if (not previous or not (previous == "_" or previous.isalnum())) \
                and offset < len(source_line) and source_line[offset] in ":=":
            offset += 1
            offset = _WHITESPACE_RUN.match(source_line, offset).end()
            if offset < len(source_line) and source_line[offset] in "\"'":
                value_start = offset + 1
                value_end = value_start
                while value_end < len(source_line) and source_line[value_end] not in "\"'":
                    value_end += 1
                if value_end < len(source_line) and value_end - value_start >= 8:
                    candidates.append(start)
                    break
        cursor = start + len(assignment_name)

    return min(candidates) if candidates else None


def _system_prompt_exposure_lines(lines: list[str]):
    """Yield at most one exposure offset per source line."""
    for line_no, source_line in enumerate(lines, 1):
        offset = _system_prompt_exposure_offset(source_line)
        if offset is not None and "#" not in source_line[:offset]:
            yield line_no, offset


def _assigned_llm_output_name(source_line: str) -> str | None:
    """Return the assignment target when an LLM-result marker follows it."""
    positions = [source_line.find(marker) for marker in _LLM_OUTPUT_ASSIGNMENT_MARKERS]
    positions = [position for position in positions if position >= 0]
    if not positions:
        return None
    prefix = source_line[: min(positions)]
    cursor = 0
    while True:
        equals = prefix.find("=", cursor)
        if equals < 0:
            return None
        end = equals
        while end > 0 and prefix[end - 1].isspace():
            end -= 1
        start = end
        while start > 0 and (prefix[start - 1] == "_" or prefix[start - 1].isalnum()):
            start -= 1
        name = prefix[start:end]
        if name and (name[0] == "_" or name[0].isascii() and name[0].isalpha()) \
                and all(character == "_" or character.isascii() and character.isalnum() for character in name):
            return name
        cursor = equals + 1


def _extract_call_block(content: str, start_idx: int, max_chars: int = 1200) -> str:
    snippet = content[start_idx : start_idx + max_chars]
    paren_depth = 0
    started = False
    for idx, ch in enumerate(snippet):
        if ch == "(":
            paren_depth += 1
            started = True
        elif ch == ")":
            paren_depth -= 1
            if started and paren_depth <= 0:
                return snippet[: idx + 1]
    return snippet.splitlines()[0] if snippet else ""


def _build_llm_top10_summary(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    counts: dict[str, int] = {key: 0 for key in OWASP_LLM_TOP_10_2025}
    for finding in findings:
        risk = finding.get("llm_risk")
        if risk in counts:
            counts[risk] += 1
        for extra in finding.get("secondary_llm_risks", ()):
            if extra in counts:
                counts[extra] += 1

    summary: dict[str, dict[str, Any]] = {}
    for llm_id, title in OWASP_LLM_TOP_10_2025.items():
        cnt = counts[llm_id]
        summary[llm_id] = {
            "id": llm_id,
            "title": title,
            "status": "fail" if cnt > 0 else "pass",
            "finding_count": cnt,
            "count": cnt,
        }
    return summary


def _empty_inline_report(filename: str) -> dict[str, Any]:
    score, grade = calculate_score([])
    return {
        "format": "sniper-ai-llm-inline-audit-v1",
        "filename": filename,
        "score": score,
        "grade": grade,
        "finding_count": 0,
        "findings_truncated": False,
        "finding_groups": summarize_finding_groups([]),
        "findings": [],
        "llm_top10_summary": _build_llm_top10_summary([]),
        "controls_evaluated": sorted(DEFAULT_CONTROLS_EVALUATED),
    }


def audit_ai_llm_inline(raw_content: str, *, filename: str = "agent.py") -> dict[str, Any]:
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Denetlenecek yapay zeka / LLM kaynak içeriği boş olamaz.")
    encoded = raw_content.encode("utf-8", errors="replace")
    if len(encoded) > MAX_INLINE_BYTES:
        raise ValueError(f"İçerik boyutu güvenli sınırı ({MAX_INLINE_BYTES} bayt) aşıyor.")
    if not isinstance(filename, str) or not filename.strip():
        filename = "agent.py"
    clean_filename = filename.strip()
    ext = Path(clean_filename).suffix.lower()
    lines = raw_content.splitlines()

    lowered_content = raw_content.casefold()
    if "mcp" not in clean_filename.casefold() and not any(
        marker in lowered_content for marker in _AI_SIGNAL_MARKERS
    ):
        return _empty_inline_report(clean_filename)

    findings: list[dict[str, Any]] = []
    seen_fingerprints: set[tuple[str, int, str]] = set()

    def _add(finding: dict[str, Any]) -> None:
        key = (finding["llm_risk"], int(finding["line"]), finding["control_id"])
        if key not in seen_fingerprints:
            seen_fingerprints.add(key)
            findings.append(finding)

    # 1. LLM01: Prompt Injection (direct f-string / .format() / + / template literal with untrusted input)
    prompt_injection_patterns = (
        re.compile(
            rf"(?is)(?:[\"']role[\"']\s*:\s*[\"'](?:system|developer|user)[\"']\s*,\s*[\"']content[\"']\s*:\s*)"
            rf"(?:f[\"'][^\"']*\{{\s*{_UNTRUSTED_INPUT_VARS}[^}}]*\}}|"
            rf"[\"'][^\"']*[\"']\s*(?:\.format\([^)]*{_UNTRUSTED_INPUT_VARS}|\+\s*{_UNTRUSTED_INPUT_VARS})|"
            rf"`[^`]*\$\{{\s*{_UNTRUSTED_INPUT_VARS}[^}}]*\}})"
        ),
        re.compile(
            rf"(?im)^[^\n#]*(?:system_prompt|prompt_template|prompt|messages)\s*[:=]\s*"
            rf"(?:f[\"'][^\n\"']*\{{\s*{_UNTRUSTED_INPUT_VARS}[^}}]*\}}|"
            rf"[^\n]*\.format\([^)\n]*{_UNTRUSTED_INPUT_VARS}|"
            rf"[^\n]*\+\s*{_UNTRUSTED_INPUT_VARS}|"
            rf"`[^`]*\$\{{\s*{_UNTRUSTED_INPUT_VARS}[^}}]*\}})"
        ),
    )
    for pattern in prompt_injection_patterns:
        for match in pattern.finditer(raw_content):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_llm_finding(
                    severity="high",
                    category="input_validation",
                    title="Doğrudan kullanıcı girdisi ile Prompt Injection riski (LLM01)",
                    description=(
                        "Güvenilmeyen kullanıcı girdisi sınırlandırıcı (delimiter), şema doğrulaması veya rol "
                        "izolasyonu olmadan doğrudan sistem/kullanıcı prompt şablonuna birleştiriliyor."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Sistem talimatlarını kullanıcı girdisinden kesin olarak ayırın; kullanıcı verisini "
                        "yapılandırılmış mesaj katmanında sınırlandırıcı etiketler ve girdi doğrulaması ile iletin."
                    ),
                    cwe="CWE-77",
                    control_id="SNIPER-INPV-07",
                    llm_risk="LLM01",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 2. LLM02 & LLM07: Hardcoded AI API Keys & Client-Side System Prompt Exposure
    for label, key_re in _AI_KEY_PATTERNS:
        for match in key_re.finditer(raw_content):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_llm_finding(
                    severity="critical",
                    category="cryptography",
                    title=f"Kod içinde sabit kodlanmış yapay zeka API anahtarı ({label}) (LLM02)",
                    description=(
                        f"Kaynak kod içinde {label} biçimine uyan açık bir API anahtarı tespit edildi. "
                        "Sır değeri güvenlik amacıyla maskelendi."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "API anahtarını derhal iptal edip yenileyin (rotate); anahtarları kaynak kod yerine "
                        "güvenli sır yöneticisi (Vault/KMS) veya sunucu ortam değişkenlerinden yükleyin."
                    ),
                    cwe="CWE-798",
                    control_id="SNIPER-CRYP-04",
                    llm_risk="LLM02",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    for line_no, match in _system_prompt_exposure_lines(lines):
        snippet = lines[line_no - 1]
        is_frontend_context = (
            ext in FRONTEND_EXTENSIONS
            or any(prefix in snippet for prefix in ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "window.", "export const"))
        )
        if is_frontend_context:
            _add(
                _make_llm_finding(
                    severity="high",
                    category="cryptography",
                    title="İstemci tarafında sistem promptu (SYSTEM_PROMPT) ifşası (LLM07)",
                    description=(
                        "Sistem promptu istemci tarafı (frontend) kodunda veya genel ortam değişkeninde "
                        "tanımlanarak son kullanıcılara açık hale getirilmiş."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Sistem promptlarını yalnızca arka uç (backend) sunucusunda tutun; istemci paketlerine "
                        "veya NEXT_PUBLIC_/VITE_ değişkenlerine gizli iş kurallarını yerleştirmeyin."
                    ),
                    cwe="CWE-798",
                    control_id="SNIPER-CRYP-04",
                    llm_risk="LLM07",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 3. LLM03: Unsafe Model Deserialization & Supply Chain
    for match in re.finditer(r"\btorch\.load\s*\(", raw_content):
        call_block = _extract_call_block(raw_content, match.start())
        if not re.search(r"\bweights_only\s*=\s*True\b", call_block):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_block
            _add(
                _make_llm_finding(
                    severity="critical",
                    category="supplychain",
                    title="Güvensiz model seriden çıkarma: torch.load weights_only=True eksik (LLM03)",
                    description=(
                        "torch.load() çağrısı weights_only=True parametresi olmadan kullanılıyor; "
                        "kötü amaçlı model dosyaları pickle üzerinden rastgele kod çalıştırabilir (RCE)."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "torch.load(..., weights_only=True) kullanın veya modelleri SafeTensors (.safetensors) "
                        "biçiminde doğrulamalı olarak yükleyin."
                    ),
                    cwe="CWE-502",
                    control_id="SNIPER-SRVR-06",
                    llm_risk="LLM03",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    unsafe_Supply_re = re.compile(
        r"\b(?:pickle\.loads?|joblib\.load|dill\.loads?|cloudpickle\.loads?)\s*\([^)]*\)"
        r"|\btrust_remote_code\s*=\s*True\b"
    )
    for match in unsafe_Supply_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_llm_finding(
                severity="critical",
                category="supplychain",
                title="Güvensiz yapay zeka modeli yükleme veya uzaktan kod yürütme (LLM03)",
                description=(
                    "Model veya kontrol noktası yüklenirken pickle/joblib seriden çıkarma ya da "
                    "trust_remote_code=True kullanımı rastgele kod çalıştırılmasına yol açabilir."
                ),
                evidence=snippet,
                recommendation=(
                    "Model ağırlıkları için SafeTensors kullanın, trust_remote_code=False ayarlayın ve "
                    "model özetlerini (SHA-256) sabitleyin."
                ),
                cwe="CWE-502",
                control_id="SNIPER-SRVR-06",
                llm_risk="LLM03",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 3b. LLM04: Data and Model Poisoning
    load_dataset_re = re.compile(r"\bload_dataset\s*\(")
    for match in load_dataset_re.finditer(raw_content):
        call_block = _extract_call_block(raw_content, match.start())
        has_pinned_revision = bool(re.search(r"\brevision\s*=\s*['\"][0-9a-fA-F]{7,40}['\"]", call_block)) or bool(
            re.search(r"\brevision\s*=\s*['\"][^'\"]+['\"]", call_block)
            and not re.search(r"\brevision\s*=\s*['\"](?:main|master|latest|HEAD)['\"]", call_block, re.IGNORECASE)
        )
        has_integrity_check = bool(
            re.search(r"\b(?:verification_mode|sha256|expected_sha256|checksum)\b", call_block)
        )
        has_remote_url = bool(re.search(r"https?://", call_block))
        if has_remote_url and not has_integrity_check or not (has_pinned_revision or has_integrity_check):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_block
            _add(
                _make_llm_finding(
                    severity="high",
                    category="supplychain",
                    title="Sabitlenmemiş revizyon veya doğrulamasız eğitim/RAG veri kümesi yüklemesi (LLM04)",
                    description=(
                        "load_dataset() çağrısı sabitlenmiş bir commit/tag (revision=...) veya bütünlük "
                        "doğrulaması olmadan kullanılıyor; uzak veri kümesi değişiklikleri veri ve model "
                        "zehirlenmesine (Data & Model Poisoning) yol açabilir."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "load_dataset(..., revision='<commit-sha>') ile veri kümesi sürümünü sabitleyin "
                        "ve eğitim/RAG öncesi SHA-256 özeti ile veri kümesi bütünlüğünü doğrulayın."
                    ),
                    cwe="CWE-494",
                    control_id="SNIPER-SRVR-06",
                    llm_risk="LLM04",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    finetune_call_re = re.compile(
        r"\b(?:fine_tuning\.jobs\.create|SFTTrainer|DPOTrainer|RewardTrainer|ORPOTrainer)\s*\("
    )
    untrusted_training_re = re.compile(
        r"\b(?:user_feedback|raw_feedback|unverified_dataset|untrusted_data|scraped_data|"
        r"user_input|raw_logs|unfiltered_corpus)\b",
        re.IGNORECASE,
    )
    dataset_validation_re = re.compile(
        r"\b(?:validate_dataset|sanitize_dataset|moderation|filter_poison|verify_signature|"
        r"curated_dataset|approved_only)\b",
        re.IGNORECASE,
    )
    for match in finetune_call_re.finditer(raw_content):
        call_block = _extract_call_block(raw_content, match.start())
        window_start = max(0, match.start() - 300)
        window = raw_content[window_start : match.start() + len(call_block) + 200]
        if untrusted_training_re.search(window) and not dataset_validation_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_block
            _add(
                _make_llm_finding(
                    severity="critical",
                    category="input_validation",
                    title="Doğrulanmamış kullanıcı geri bildirimi veya ham veri ile model ince ayarı (LLM04)",
                    description=(
                        "Model ince ayarı (fine-tuning / SFT / DPO) çağrısında doğrulanmamış kullanıcı "
                        "geri bildirimi veya kazınmış ham veri sanitizasyon/moderasyon olmadan eğitim "
                        "hattına veriliyor; arka kapı veya davranış zehirlenmesi (Model Poisoning) oluşabilir."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Eğitim/fine-tuning verilerini modele vermeden önce toksisite/anomali taramasından, "
                        "şema doğrulamasından (validate_dataset) ve insan onaylı kürasyon sürecinden geçirin."
                    ),
                    cwe="CWE-20",
                    control_id="SNIPER-INPV-07",
                    llm_risk="LLM04",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 4. LLM05: Improper Output Handling
    llm_output_vars: set[str] = {
        "llm_output",
        "ai_reply",
        "completion",
        "model_output",
        "agent_output",
        "assistant_reply",
        "llm_response",
        "generated_code",
        "generated_sql",
    }
    for source_line in lines:
        assigned_name = _assigned_llm_output_name(source_line)
        if assigned_name is not None:
            llm_output_vars.add(assigned_name)

    var_union = "|".join(re.escape(v) for v in sorted(llm_output_vars))
    llm_expr = rf"(?:response\.choices[^\n,)]*|(?:{var_union})(?:\.[A-Za-z0-9_\[\].]+)?)"
    output_sink_re = re.compile(
        rf"(?:\b(?:eval|exec)\s*\([^)]*{llm_expr}|"
        rf"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|os\.popen|child_process\.exec)\s*\([^)]*{llm_expr}|"
        rf"\b(?:cursor|session|conn|db)\.execute\s*\([^)]*{llm_expr}|"
        rf"\b(?:innerHTML|outerHTML)\s*=\s*[^\n;]*{llm_expr}|"
        rf"\bdangerouslySetInnerHTML\s*=\s*\{{[^}}]*{llm_expr})"
    )
    for match in output_sink_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add(
            _make_llm_finding(
                severity="critical",
                category="input_validation",
                title="LLM çıktısının doğrulamasız tehlikeli yürütme/DOM hedefine aktarılması (LLM05)",
                description=(
                    "Modelden dönen yanıt (LLM output) doğrulama veya kaçışlama yapılmadan doğrudan "
                    "eval/exec, sistem komutu, SQL sorgusu veya innerHTML/dangerouslySetInnerHTML hedefine veriliyor."
                ),
                evidence=snippet,
                recommendation=(
                    "LLM çıktılarını güvenilmeyen girdi olarak ele alın; eval/exec/shell çağrılarından kaçının, "
                    "parametreli sorgular ve sıkı çıktı şema doğrulaması uygulayın."
                ),
                cwe="CWE-94",
                control_id="SNIPER-INPV-07",
                llm_risk="LLM05",
                filename=clean_filename,
                line=line_no,
            )
        )

    # 5. LLM06: Excessive Agency (including MCP tools & Computer-Use desktop agents)
    tool_marker_re = re.compile(
        r"(?:@(?:[A-Za-z0-9_]+\.)?tool\b|\b(?:server|mcp)\.tool\s*\(|\b(?:McpServer|FastMCP)\b"
        r"|\bStructuredTool\b|\bfunction_declarations\b|\btools\s*=\s*\["
        r"|\b(?:pyautogui|xdotool|pynput|computer_use)\b)"
    )
    dangerous_agency_re = re.compile(
        r"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|os\.popen|"
        r"os\.remove|os\.unlink|shutil\.rmtree|cursor\.execute|db\.execute|"
        r"child_process\.(?:exec|execSync|spawn)|execSync\s*\(|"
        r"pyautogui\.(?:write|typewrite|hotkey|press|click)|xdotool\s+(?:type|key|exec)|"
        r"write_bytes|write_text|exec_module)\b"
    )
    hil_approval_re = re.compile(
        r"\b(?:confirm|approval|human_in_the_loop|require_approval|ask_human|HumanInTheLoop)\b",
        re.IGNORECASE,
    )
    for match in tool_marker_re.finditer(raw_content):
        window = raw_content[match.start() : match.start() + 900]
        if dangerous_agency_re.search(window) and not hil_approval_re.search(window):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
            _add(
                _make_llm_finding(
                    severity="high",
                    category="authorization",
                    title="İnsan onayı (HITL) olmadan yıkıcı yetkiye sahip yapay zeka aracı (LLM06)",
                    description=(
                        "Yapay zeka ajanı veya MCP aracı; kabuk komutu çalıştırma, dosya silme veya doğrudan "
                        "veritabanı işlemi yapma yetkisini insan onayı (human-in-the-loop) olmadan barındırıyor."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Yüksek etkili ajan araçlarında açık insan onayı (approval/confirm) zorunluluğu, "
                        "en az ayrıcalık ilkesi ve salt-okunur kısıtlamalar uygulayın."
                    ),
                    cwe="CWE-250",
                    control_id="SNIPER-AUTHZ-02",
                    llm_risk="LLM06",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 5b. LLM01 -> LLM06: Indirect Prompt Injection to Tool / CUA Execution Chain
    indirect_ingestion_re = re.compile(
        r"\b(?:requests\.(?:get|post)|httpx\.(?:get|post|AsyncClient)|BeautifulSoup|"
        r"playwright|imaplib|read_email|pytesseract|image_to_string|similarity_search|"
        r"WebBaseLoader|fetch_url|scrape)\b"
    )
    indirect_match = indirect_ingestion_re.search(raw_content)
    agency_match = dangerous_agency_re.search(raw_content)
    if (
        indirect_match is not None
        and tool_marker_re.search(raw_content) is not None
        and agency_match is not None
        and not hil_approval_re.search(raw_content)
    ):
        src_line_no = _line_number_for_offset(raw_content, indirect_match.start())
        sink_line_no = _line_number_for_offset(raw_content, agency_match.start())
        src_snippet = lines[src_line_no - 1].strip() if 1 <= src_line_no <= len(lines) else indirect_match.group(0)
        sink_snippet = lines[sink_line_no - 1].strip() if 1 <= sink_line_no <= len(lines) else agency_match.group(0)
        chain_evidence = f"{src_snippet} -> {sink_snippet}" if src_line_no != sink_line_no else sink_snippet
        _add(
            _make_llm_finding(
                severity="critical",
                category="authorization",
                title="Dolaylı Prompt Injection üzerinden otonom araç / masaüstü komutu çalıştırma zinciri (LLM01 -> LLM06)",
                description=(
                    "Harici ve güvenilmeyen bir veri kaynağından (web kazıma, e-posta, OCR/görsel metni veya "
                    "vektör araması) alınan içerik, insan onayı (HITL) bulunmayan yüksek yetkili bir ajan/MCP "
                    "veya masaüstü (Computer-Use) yürütme aracına bağlanıyor; dolaylı prompt enjeksiyonu "
                    "uzaktan komut çalıştırmaya (RCE) dönüşebilir."
                ),
                evidence=chain_evidence,
                recommendation=(
                    "Harici içerik okuyan ajan akışları ile kabuk/dosya/masaüstü komutu çalıştıran araçları "
                    "ayrıcalık sınırlarıyla ayırın ve yıkıcı araç çağrılarında zorunlu insan onayı (HITL) uygulayın."
                ),
                cwe="CWE-77",
                control_id="SNIPER-AI-CHAIN-01",
                llm_risk="LLM01",
                filename=clean_filename,
                line=sink_line_no,
            )
        )

    for mcp_finding in audit_mcp_config_privileges(raw_content, filename=clean_filename)["findings"]:
        _add(mcp_finding)

    # 6. LLM08: Vector / RAG Tenant Isolation Weakness
    vector_call_re = re.compile(
        r"(?:\.(?:similarity_search(?:_with_score)?|max_marginal_relevance_search)\s*\("
        r"|\b(?:collection|index|vector_store|vectorstore|qdrant|pinecone|chromadb|weaviate)\.(?:query|search|similarity_search)\s*\()"
    )
    tenant_filter_re = re.compile(
        r"\b(?:filter|where|namespace|tenant_id|tenant|partition_key)\s*[=:]",
        re.IGNORECASE,
    )
    for match in vector_call_re.finditer(raw_content):
        call_block = _extract_call_block(raw_content, match.start())
        if not tenant_filter_re.search(call_block):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_block
            _add(
                _make_llm_finding(
                    severity="high",
                    category="authorization",
                    title="Vektör / RAG sorgusunda kiracı veya erişim filtresi eksikliği (LLM08)",
                    description=(
                        "Vektör veritabanı benzerlik araması (similarity_search / query) kiracı (tenant_id), "
                        "namespace veya metadata erişim filtresi olmadan çalıştırılıyor; kiracılar arası veri sızıntısı oluşabilir."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Her RAG ve vektör sorgusunda oturum açmış kullanıcının kiracı/yetki kapsamını "
                        "filter=, namespace= veya tenant_id= parametresiyle zorunlu kılın."
                    ),
                    cwe="CWE-284",
                    control_id="SNIPER-AUTHZ-04",
                    llm_risk="LLM08",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    # 6b. LLM09: Misinformation / Hallucination Risk
    llm_model_or_call_re = re.compile(
        r"\b(?:chat\.completions\.create|completions\.create|messages\.create|generate_content|"
        r"ChatOpenAI|ChatAnthropic|GenerativeModel)\s*\("
    )
    grounding_control_re = re.compile(
        r"\b(?:grounding|grounding_config|citations|fact_check|verify_facts|rag_sources|"
        r"source_citations|google_search_retrieval)\b",
        re.IGNORECASE,
    )
    temp_param_re = re.compile(r"\btemperature\s*=\s*([0-9]+(?:\.[0-9]+)?)")
    for match in llm_model_or_call_re.finditer(raw_content):
        call_block = _extract_call_block(raw_content, match.start())
        temp_match = temp_param_re.search(call_block)
        if temp_match is not None:
            try:
                temp_val = float(temp_match.group(1))
            except ValueError:
                temp_val = 0.0
            window_start = max(0, match.start() - 200)
            window = raw_content[window_start : match.start() + len(call_block) + 200]
            if temp_val > 1.0 and not grounding_control_re.search(window):
                line_no = _line_number_for_offset(raw_content, match.start())
                snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_block
                _add(
                    _make_llm_finding(
                        severity="medium",
                        category="configuration",
                        title="Yüksek yaratıcılık sıcaklığı (temperature > 1.0) ve kaynak doğrulama eksikliği (LLM09)",
                        description=(
                            f"LLM çağrısında temperature={temp_match.group(1)} (> 1.0) ayarlanmış ve kaynak "
                            "dayanağı (grounding/citations) kontrolü bulunmuyor; bu yapılandırma halüsinasyon "
                            "ve yanıltıcı bilgi üretimi (Misinformation) riskini ciddi biçimde artırır."
                        ),
                        evidence=snippet,
                        recommendation=(
                            "Olgusal doğruluk gerektiren akışlarda temperature değerini 0.0–0.3 aralığında "
                            "tutun ve yanıtları doğrulanmış RAG kaynakları (grounding/citations) ile sınırlandırın."
                        ),
                        cwe="CWE-1188",
                        control_id="SNIPER-INPV-07",
                        llm_risk="LLM09",
                        filename=clean_filename,
                        line=line_no,
                    )
                )

    # 7. LLM10: Unbounded Consumption / DoS
    completion_call_re = re.compile(
        r"\b(?:chat\.completions\.create|completions\.create|messages\.create|generate_content)\s*\("
    )
    for match in completion_call_re.finditer(raw_content):
        call_block = _extract_call_block(raw_content, match.start())
        has_max_tokens = bool(
            re.search(r"\b(?:max_tokens|max_completion_tokens|max_output_tokens)\s*=", call_block)
        )
        has_timeout = bool(re.search(r"\b(?:timeout|request_timeout)\s*=", call_block))
        if not (has_max_tokens and has_timeout):
            line_no = _line_number_for_offset(raw_content, match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else call_block
            _add(
                _make_llm_finding(
                    severity="medium",
                    category="availability",
                    title="Sınırsız LLM tüketimi: max_tokens veya timeout sınırı eksik (LLM10)",
                    description=(
                        "LLM tamamlama çağrısında üretim jetonu üst sınırı (max_tokens) ve/veya zaman aşımı "
                        "(timeout) tanımlanmamış; maliyet patlaması (Denial of Wallet) ve kaynak tükenmesi riski var."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "Tüm LLM API çağrılarında açık max_tokens / max_completion_tokens, timeout ve "
                        "kullanıcı bazlı hız sınırlandırma (rate limit) parametrelerini zorunlu kılın."
                    ),
                    cwe="CWE-400",
                    control_id="SNIPER-APIT-05",
                    llm_risk="LLM10",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    score, grade = calculate_score(findings)
    llm_top10_summary = _build_llm_top10_summary(findings)
    controls_evaluated = sorted(
        {f["control_id"] for f in findings} | DEFAULT_CONTROLS_EVALUATED
    )
    return {
        "format": "sniper-ai-llm-inline-audit-v1",
        "filename": clean_filename,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > INLINE_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, INLINE_FINDING_LIMIT)[0],
        "llm_top10_summary": llm_top10_summary,
        "controls_evaluated": controls_evaluated,
    }


@project_scan_scope
def audit_ai_llm_project(
    project_path: str,
    *,
    allowed_roots: tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    root = validate_project_path(project_path, allowed_roots=allowed_roots)
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    with ProjectTree(root) as tree:
        for project_file in tree.iter_files(skip_dirs=SKIP_DIRS, reject_unsafe=False):
            if scanned_files >= MAX_PROJECT_FILES:
                continue
            if any(part.casefold() in SKIP_DIRS for part in project_file.path.parts[:-1]):
                continue
            ext = project_file.path.suffix.lower()
            if ext not in AI_SCAN_EXTENSIONS:
                continue
            if project_file.size == 0 or project_file.size > MAX_INLINE_BYTES:
                continue
            content = tree.read_text(project_file, MAX_INLINE_BYTES, errors="replace")
            if not content.strip():
                continue
            rel_name = project_file.path.as_posix()
            scanned_files += 1
            file_report = audit_ai_llm_inline(content, filename=rel_name)
            findings.extend(file_report["findings"])

    score, grade = calculate_score(findings)
    llm_top10_summary = _build_llm_top10_summary(findings)
    controls_evaluated = sorted(
        {f["control_id"] for f in findings} | DEFAULT_CONTROLS_EVALUATED
    )
    return {
        "format": "sniper-ai-llm-security-audit-v1",
        "project": root.name,
        "project_path": str(root),
        "scanned_files": scanned_files,
        "score": score,
        "grade": grade,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > PROJECT_FINDING_LIMIT,
        "finding_groups": summarize_finding_groups(findings),
        "findings": cap_findings(findings, PROJECT_FINDING_LIMIT)[0],
        "llm_top10_summary": llm_top10_summary,
        "controls_evaluated": controls_evaluated,
    }


def audit_mcp_config_privileges(
    raw_content: str,
    *,
    filename: str = "mcp.json",
) -> dict[str, Any]:
    clean_filename = filename.strip() if isinstance(filename, str) and filename.strip() else "mcp.json"
    if not isinstance(raw_content, str) or not raw_content.strip():
        return {"findings": [], "count": 0, "filename": clean_filename}

    lines = raw_content.splitlines()
    findings: list[dict[str, Any]] = []
    seen_controls: set[tuple[str, int]] = set()

    def _add_mcp(finding: dict[str, Any]) -> None:
        key = (finding["control_id"], int(finding["line"]))
        if key not in seen_controls:
            seen_controls.add(key)
            findings.append(finding)

    has_mcp_context = bool(
        re.search(
            r"(?i)(?:server-filesystem|mcpServers|mcp_servers|StdioServerParameters|"
            r"@modelcontextprotocol|fastmcp|McpServer|server-everything|mcp-server-shell|"
            r"mcp-server-commands|mcp_server_shell|mcp_server_commands|\bmcp\b)",
            raw_content,
        )
    ) or "mcp" in clean_filename.lower()
    if not has_mcp_context:
        return {"findings": [], "count": 0, "filename": clean_filename}
    has_fs_or_args = bool(
        re.search(r"(?i)(?:server-filesystem|\bargs\b)", raw_content)
    )
    sensitive_mount_re = re.compile(
        r"""(?m)(?:["'](?:/|/home(?:/[^"'\s]*)?|/etc(?:/[^"'\s]*)?|/var(?:/[^"'\s]*)?|/root(?:/[^"'\s]*)?|[A-Za-z]:\\+|[A-Za-z]:/)["']"""
        r"""|^\s*-\s*(?:/|/home(?:/\S*)?|/etc(?:/\S*)?|/var(?:/\S*)?|/root(?:/\S*)?|[A-Za-z]:\\+)\s*$)"""
    )
    if has_mcp_context and has_fs_or_args:
        mount_match = sensitive_mount_re.search(raw_content)
        if mount_match is not None:
            line_no = _line_number_for_offset(raw_content, mount_match.start())
            snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else mount_match.group(0)
            _add_mcp(
                _make_llm_finding(
                    severity="critical",
                    category="authorization",
                    title="MCP sunucu yapılandırmasında kısıtsız ana bilgisayar kök/ev dizini erişimi",
                    description=(
                        "MCP dosya sistemi sunucusuna (server-filesystem) veya argümanlarına kök dizin ('/', 'C:\\\\') "
                        "ya da kritik sistem/kullanıcı dizini ('/home', '/etc', '/var', '/root') doğrudan bağlanmış."
                    ),
                    evidence=snippet,
                    recommendation=(
                        "MCP dosya sistemi erişimini yalnızca izole bir çalışma alanı alt diziniyle sınırlandırın "
                        "ve hassas sistem dizinlerini kesin olarak hariç tutun."
                    ),
                    cwe="CWE-250",
                    control_id="SNIPER-MCP-PRIV-01",
                    llm_risk="LLM06",
                    filename=clean_filename,
                    line=line_no,
                )
            )

    dangerous_mcp_server_re = re.compile(
        r"(?i)(?:\b(?:server-everything|mcp-server-shell|mcp-server-commands|"
        r"mcp_server_shell|mcp_server_commands)\b|--(?:allow-all|dangerously-skip-permissions)\b)"
    )
    for match in dangerous_mcp_server_re.finditer(raw_content):
        line_no = _line_number_for_offset(raw_content, match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else match.group(0)
        _add_mcp(
            _make_llm_finding(
                severity="high",
                category="authorization",
                title="MCP sunucu yapılandırmasında aşırı yetkili kabuk/komut yürütme eklentisi",
                description=(
                    "MCP yapılandırmasında kısıtsız komut çalıştırma veya tüm izinleri atlama "
                    "(server-everything, mcp-server-shell, --allow-all, --dangerously-skip-permissions) "
                    "yetkisi tanımlanmış."
                ),
                evidence=snippet,
                recommendation=(
                    "Genel amaçlı kabuk/everything MCP sunucularını devre dışı bırakın; yalnızca dar kapsamlı, "
                    "izin listeli (allowlist) ve insan onaylı araçları etkinleştirin."
                ),
                cwe="CWE-78",
                control_id="SNIPER-MCP-PRIV-02",
                llm_risk="LLM06",
                filename=clean_filename,
                line=line_no,
            )
        )

    bind_all_match = re.search(r"\b0\.0\.0\.0\b", raw_content)
    remote_transport_match = re.search(r"(?i)\b(?:sse|streamable[-_]http)\b", raw_content)
    auth_guard_re = re.compile(
        r"(?i)\b(?:auth|authentication|bearer|token|api_key|apikey|oauth|jwt|verify_token|auth_middleware)\b"
    )
    if (
        bind_all_match is not None
        and remote_transport_match is not None
        and not auth_guard_re.search(raw_content)
    ):
        line_no = _line_number_for_offset(raw_content, bind_all_match.start())
        snippet = lines[line_no - 1] if 1 <= line_no <= len(lines) else bind_all_match.group(0)
        _add_mcp(
            _make_llm_finding(
                severity="high",
                category="authorization",
                title="Kimlik doğrulamasız genel ağa açık MCP SSE/HTTP sunucu bağlaması",
                description=(
                    "MCP sunucusu SSE veya streamable-http taşıyıcısı ile tüm ağ arayüzlerine (0.0.0.0) "
                    "kimlik doğrulama/token kontrolü olmadan bağlanıyor."
                ),
                evidence=snippet,
                recommendation=(
                    "MCP sunucularını varsayılan olarak 127.0.0.1 (localhost) adresine bağlayın; ağ üzerinden "
                    "erişim gerekiyorsa zorunlu Bearer/OAuth token doğrulaması ve TLS uygulayın."
                ),
                cwe="CWE-306",
                control_id="SNIPER-MCP-PRIV-03",
                llm_risk="LLM06",
                filename=clean_filename,
                line=line_no,
            )
        )

    return {"findings": findings, "count": len(findings), "filename": clean_filename}
