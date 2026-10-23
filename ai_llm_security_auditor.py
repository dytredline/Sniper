from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from project_analyzer import SKIP_DIRS, validate_project_path
from safe_file_read import read_text_bounded
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
    ("HuggingFace Access Token", re.compile(r"\bhf_[A-Za-z0-9]{14,}\b")),
    ("Replicate API Token", re.compile(r"\br8_[A-Za-z0-9]{14,}\b")),
    ("Groq API Key", re.compile(r"\bgsk_[A-Za-z0-9]{14,}\b")),
    (
        "AI Provider API Key",
        re.compile(
            r"(?i)\b(?:cohere_api_key|groq_api_key|openai_api_key|anthropic_api_key|"
            r"huggingface_api_key|replicate_api_token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{14,})[\"']"
        ),
    ),
)

_SECRET_REDACT_RE = re.compile(
    r"\b(?:sk-proj-[A-Za-z0-9_-]{4,}|sk-ant-[A-Za-z0-9_-]{4,}|sk-[A-Za-z0-9]{10,}|"
    r"hf_[A-Za-z0-9]{8,}|r8_[A-Za-z0-9]{8,}|gsk_[A-Za-z0-9]{8,})\b"
)

_SYSTEM_PROMPT_EXPOSURE_RE = re.compile(
    r"(?:(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*SYSTEM_PROMPT|"
    r"(?:export\s+const|window\.|localStorage\.setItem\([^)]*)\s*(?:SYSTEM_PROMPT|systemPrompt)|"
    r"\bSYSTEM_PROMPT\s*[:=]\s*[\"'][^\"']{8,}[\"'])",
    re.IGNORECASE,
)
_LLM_OUTPUT_ASSIGNMENT_MARKERS = (
    "response.choices",
    "chat.completions.create",
    "messages.create",
    "generate_content",
    ".invoke(",
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
        return "***[REDACTED]***"

    redacted = _SECRET_REDACT_RE.sub(_mask, text)
    redacted = re.sub(
        r"(?i)((?:cohere_api_key|groq_api_key|openai_api_key|anthropic_api_key|"
        r"huggingface_api_key|replicate_api_token)\s*[:=]\s*[\"'])([^\"']+)([\"'])",
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


def _system_prompt_exposure_lines(lines: list[str]):
    """Yield at most one match per source line without a greedy line prefix."""
    for line_no, source_line in enumerate(lines, 1):
        match = _SYSTEM_PROMPT_EXPOSURE_RE.search(source_line)
        if match is not None and "#" not in source_line[:match.start()]:
            yield line_no, match


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

    # 5. LLM06: Excessive Agency
    tool_marker_re = re.compile(
        r"(?:@(?:[A-Za-z0-9_]+\.)?tool\b|\bStructuredTool\b|\bfunction_declarations\b|\btools\s*=\s*\[)"
    )
    dangerous_agency_re = re.compile(
        r"\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|os\.popen|"
        r"os\.remove|os\.unlink|shutil\.rmtree|cursor\.execute|db\.execute)\b"
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
            if ext not in AI_SCAN_EXTENSIONS:
                continue
            content = read_text_bounded(file_path, MAX_INLINE_BYTES)
            if content is None:
                continue
            if not content.strip():
                continue
            rel_name = str(file_path.relative_to(root))
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
