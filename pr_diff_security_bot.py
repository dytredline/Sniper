"""Wave 6 — Gerçek Zamanlı Git Diff / Pull Request Güvenlik Botu (PR Security Regression & Sibling Parity Bot).

Birleşik Git yamalarını (`unified_diff`) satır ve hunk düzeyinde ayrıştırarak:
1. `SNIPER-PR-GUARD-REMOVED-01` (CWE-862, critical): PR yamasında güvenlik muhafızı
   (`@PreAuthorize`, `WithSSRFFilter`, `before_action`, `Ability.allowed?`, `NOFOLLOW_LINKS`,
   `verify_signature`, `ENABLE ROW LEVEL SECURITY` vb.) kaldırılması veya `verify=False` /
   `skip_before_action` / `InsecureSkipVerify: true` eklenmesi.
2. `SNIPER-PR-NEW-SINK-02` (CWE-78, high): PR yamasında sanitizasyon olmadan tehlikeli
   yürütme/sorgu noktası (`shell=True`, `os.system(`, `eval(`, `exec(`, `innerHTML =`,
   `dangerouslySetInnerHTML`, `pickle.loads(`, `yaml.load(`, raw SQL f-string) eklenmesi.
3. `SNIPER-PR-INCOMPLETE-SIBLING-03` (CWE-863, high): PR bir dosyada güvenlik yaması
   uygularken `sibling_files` içindeki kardeş dosyada aynı zafiyetin açık bırakılması.

Ayrıca GitHub / GitLab PR incelemelerine doğrudan gönderilebilecek satır içi
`review_comments` (````suggestion` bloğu içeren) üretir.
"""

from __future__ import annotations

import re
from typing import Any

FORMAT_VERSION = "sniper-pr-diff-security-review/1"

_DIFF_GIT_RE = re.compile(r"^diff\s+--git\s+a/(\S+)\s+b/(\S+)")
_PLUS_FILE_RE = re.compile(r"^\+\+\+\s+(?:b/)?(\S+)")
_MINUS_FILE_RE = re.compile(r"^---\s+(?:a/)?(\S+)")
_HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@"
)

_SECURITY_GUARD_SPECS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("@PreAuthorize", re.compile(r"@PreAuthorize\b")),
    ("@Secured", re.compile(r"@Secured\b")),
    ("@UseGuards", re.compile(r"@UseGuards\b")),
    (
        "before_action",
        re.compile(r"\b(?:before_action|prepend_before_action|before_filter)\b"),
    ),
    ("authorize!", re.compile(r"\bauthorize!\b")),
    ("Ability.allowed?", re.compile(r"\bAbility\.allowed\?")),
    ("WithSSRFFilter", re.compile(r"\b(?:WithSSRFFilter|UrlBlocker)\b")),
    (
        "verify_signature",
        re.compile(r"\bverify_signature['\"]?\s*(?!\s*[:=]\s*(?:False|false|0))"),
    ),
    ("hmac.compare_digest", re.compile(r"\bhmac\.compare_digest\b")),
    (
        "NOFOLLOW_LINKS",
        re.compile(r"\b(?:NOFOLLOW_LINKS|Files\.isSymbolicLink)\b"),
    ),
    ("filepath.Clean", re.compile(r"\bfilepath\.(?:Clean|Rel)\b")),
    ("commonpath", re.compile(r"\bcommonpath\b")),
    ("validateBackupFile", re.compile(r"\bvalidateBackupFile\b")),
    (
        "ENABLE ROW LEVEL SECURITY",
        re.compile(r"\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b", re.IGNORECASE),
    ),
)

_ADDED_BYPASS_SPECS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "skip_before_action",
        re.compile(r"\b(?:skip_before_action|skip_before_filter)\b"),
        "before_action",
    ),
    (
        "verify=False",
        re.compile(r"\bverify\s*=\s*False\b"),
        "verify=True",
    ),
    (
        "InsecureSkipVerify: true",
        re.compile(r"\bInsecureSkipVerify\s*:\s*true\b", re.IGNORECASE),
        "InsecureSkipVerify: false",
    ),
    (
        "verify_signature: False",
        re.compile(r"\bverify_signature['\"]?\s*[:=]\s*(?:False|false)\b"),
        "verify_signature: True",
    ),
)

_DANGEROUS_SINK_SPECS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell=True", re.compile(r"\bshell\s*=\s*True\b")),
    ("os.system(", re.compile(r"\bos\.system\s*\(")),
    ("eval(", re.compile(r"\beval\s*\(")),
    ("exec(", re.compile(r"\bexec\s*\(")),
    ("innerHTML =", re.compile(r"\.innerHTML\s*=")),
    ("dangerouslySetInnerHTML", re.compile(r"\bdangerouslySetInnerHTML\b")),
    ("pickle.loads(", re.compile(r"\bpickle\.loads\s*\(")),
    (
        "yaml.load(",
        re.compile(r"\byaml\.load\s*\((?![^\n)]*(?:SafeLoader|CSafeLoader))"),
    ),
    (
        "raw_sql_fstring",
        re.compile(
            r"""\bf["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{""",
            re.IGNORECASE,
        ),
    ),
)

_HUNK_SANITIZER_RE = re.compile(
    r"\b(?:shlex\.quote|DOMPurify\.sanitize|customHtmlSanitizer\.sanitize|HtmlSanitizer|SafeLoader|CSafeLoader)\b"
)

_SIBLING_PATCH_GUARD_SPECS: tuple[tuple[str, re.Pattern[str], re.Pattern[str]], ...] = (
    (
        "WithSSRFFilter",
        re.compile(r"\b(?:WithSSRFFilter|UrlBlocker)\b"),
        re.compile(
            r"\b(?:http\.Client|NewRequest|http\.Get|fetch|requests\.(?:get|post)|processExecutor|URL_TO_PDF|Convert)\b"
        ),
    ),
    (
        "customHtmlSanitizer.sanitize",
        re.compile(r"\b(?:customHtmlSanitizer\.sanitize|HtmlSanitizer|DOMPurify\.sanitize)\b"),
        re.compile(
            r"\b(?:processExecutor|weasyprint|chromium|libreoffice|wkhtmltopdf|URL_TO_PDF|Convert|render|html)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "--allowed-protocols",
        re.compile(r"--allowed-protocols\b"),
        re.compile(
            r"\b(?:processExecutor|weasyprint|chromium|libreoffice|wkhtmltopdf|URL_TO_PDF|Convert)\b"
        ),
    ),
    (
        "verify_confirmed_email!",
        re.compile(r"\bverify_confirmed_email!\b"),
        re.compile(r"\b(?:Controller|ApplicationController|before_action)\b"),
    ),
    (
        "in_organization",
        re.compile(r"\bin_organization\b"),
        re.compile(r"\b(?:organization|user|member|project|find|where)\b", re.IGNORECASE),
    ),
    (
        "Ability.allowed?",
        re.compile(r"\bAbility\.allowed\?"),
        re.compile(r"\b(?:execute|find|update|destroy|item_version|ItemConsumersFinder)\b"),
    ),
    (
        "NOFOLLOW_LINKS",
        re.compile(r"\b(?:NOFOLLOW_LINKS|Files\.isSymbolicLink|validateBackupFile)\b"),
        re.compile(
            r"\b(?:Files\.|FileInputStream|readAllBytes|isRegularFile|os\.ReadFile|backup|restore)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "shell=False",
        re.compile(r"\bshell\s*=\s*False\b"),
        re.compile(r"\bshell\s*=\s*True\b|\bos\.system\s*\("),
    ),
)


def _build_sink_suggestion(line_text: str, sink_name: str) -> str:
    """Tehlikeli sink satırı için güvenli kod önerisi üretir."""
    indent_match = re.match(r"^(\s*)", line_text)
    indent = indent_match.group(1) if indent_match else ""
    if sink_name == "shell=True":
        return re.sub(r"\bshell\s*=\s*True\b", "shell=False", line_text)
    if sink_name == "yaml.load(":
        if "Loader=" not in line_text:
            return re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", line_text)
    if sink_name == "innerHTML =":
        return re.sub(r"\.innerHTML\s*=", ".textContent =", line_text)
    if sink_name == "os.system(":
        inner = re.sub(r"^.*?\bos\.system\s*\((.*)\)\s*$", r"\1", line_text)
        return f"{indent}subprocess.run(shlex.split({inner}), shell=False, check=True)"
    if sink_name == "eval(":
        return re.sub(r"\beval\s*\(", "ast.literal_eval(", line_text)
    if sink_name == "pickle.loads(":
        return re.sub(r"\bpickle\.loads\s*\(", "json.loads(", line_text)
    if sink_name == "raw_sql_fstring":
        return f"{indent}cursor.execute( parameterized_query, (param,) )"
    return f"{indent}# FIX: Sanitize or parameterize '{sink_name}' before execution"


def _parse_unified_diff(unified_diff: str) -> list[dict[str, Any]]:
    """Birleşik git diff metnini dosya ve hunk yapılarına ayrıştırır."""
    files: list[dict[str, Any]] = []
    current_file: dict[str, Any] | None = None
    current_hunk: dict[str, Any] | None = None
    old_line = 1
    new_line = 1

    def ensure_file(default_path: str = "unknown_file") -> dict[str, Any]:
        nonlocal current_file
        if current_file is None:
            current_file = {"path": default_path, "hunks": []}
            files.append(current_file)
        return current_file

    def ensure_hunk() -> dict[str, Any]:
        nonlocal current_hunk
        f_obj = ensure_file()
        if current_hunk is None:
            current_hunk = {
                "old_start": old_line,
                "new_start": new_line,
                "removed_lines": [],
                "added_lines": [],
                "context_lines": [],
            }
            f_obj["hunks"].append(current_hunk)
        return current_hunk

    for raw_line in (unified_diff or "").splitlines():
        m_git = _DIFF_GIT_RE.match(raw_line)
        if m_git:
            b_path = m_git.group(2)
            current_file = {"path": b_path, "hunks": []}
            files.append(current_file)
            current_hunk = None
            old_line = 1
            new_line = 1
            continue

        m_minus = _MINUS_FILE_RE.match(raw_line)
        if m_minus:
            m_path = m_minus.group(1)
            if m_path != "/dev/null":
                f_obj = ensure_file(m_path)
                if f_obj["path"] == "unknown_file":
                    f_obj["path"] = m_path
            continue

        m_plus = _PLUS_FILE_RE.match(raw_line)
        if m_plus:
            p_path = m_plus.group(1)
            if p_path != "/dev/null":
                f_obj = ensure_file(p_path)
                f_obj["path"] = p_path
            continue

        m_hunk = _HUNK_HEADER_RE.match(raw_line)
        if m_hunk:
            old_line = int(m_hunk.group(1))
            new_line = int(m_hunk.group(3))
            f_obj = ensure_file()
            current_hunk = {
                "old_start": old_line,
                "new_start": new_line,
                "removed_lines": [],
                "added_lines": [],
                "context_lines": [],
            }
            f_obj["hunks"].append(current_hunk)
            continue

        if raw_line.startswith(("index ", "new file mode", "deleted file mode", "similarity index", "rename from", "rename to")):
            continue

        if raw_line.startswith("+"):
            hunk = ensure_hunk()
            hunk["added_lines"].append((new_line, raw_line[1:]))
            new_line += 1
        elif raw_line.startswith("-"):
            hunk = ensure_hunk()
            anchor_line = max(1, new_line)
            hunk["removed_lines"].append((old_line, anchor_line, raw_line[1:]))
            old_line += 1
        elif current_hunk is not None:
            text = raw_line[1:] if raw_line.startswith(" ") else raw_line
            current_hunk["context_lines"].append((new_line, text))
            old_line += 1
            new_line += 1

    return files


def audit_git_diff_security_regressions(
    unified_diff: str,
    *,
    sibling_files: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Birleşik git diff (`unified_diff`) üzerindeki güvenlik gerilemelerini ve eksik kardeş yamaları denetler."""
    parsed_files = _parse_unified_diff(unified_diff or "")
    findings: list[dict[str, Any]] = []
    review_comments: list[dict[str, Any]] = []

    sibling_map: dict[str, str] = {
        str(k): str(v or "") for k, v in (sibling_files or {}).items()
    }
    patched_file_paths = {f["path"] for f in parsed_files}

    for file_entry in parsed_files:
        file_path = file_entry["path"]
        all_added_text_in_file = "\n".join(
            text
            for hunk in file_entry["hunks"]
            for _ln, text in hunk["added_lines"]
        )
        all_removed_text_in_file = "\n".join(
            text
            for hunk in file_entry["hunks"]
            for _oln, _nln, text in hunk["removed_lines"]
        )

        for hunk in file_entry["hunks"]:
            hunk_added_text = "\n".join(text for _ln, text in hunk["added_lines"])

            # 1a) SNIPER-PR-GUARD-REMOVED-01: Güvenlik muhafızının kaldırılması (- satırı)
            for _old_ln, anchor_new_ln, rem_text in hunk["removed_lines"]:
                for guard_name, guard_re in _SECURITY_GUARD_SPECS:
                    if guard_re.search(rem_text) and not guard_re.search(all_added_text_in_file):
                        stripped_rem = rem_text.strip()
                        suggestion_line = rem_text
                        comment_body = (
                            f"**[SNIPER-PR-GUARD-REMOVED-01]** `{guard_name}` güvenlik muhafızı bu PR ile kaldırılmış. "
                            "Yetkilendirme/SSRF/imza doğrulama gerilemesini önlemek için muhafızı koruyun:\n"
                            f"```suggestion\n{suggestion_line}\n```"
                        )
                        findings.append(
                            {
                                "rule_id": "SNIPER-PR-GUARD-REMOVED-01",
                                "cwe": "CWE-862",
                                "reference": "CWE-862",
                                "severity": "critical",
                                "category": "authz",
                                "title": "Pull Request yamasında güvenlik muhafızı (Authz / SSRF / İmza / Symlink kontrolü) kaldırıldı",
                                "description": (
                                    f"`{file_path}` dosyasında `{guard_name}` güvenlik kontrolü (`{stripped_rem}`) "
                                    "kaldırılmış ve aynı yamada eşdeğer bir muhafız eklenmemiş."
                                ),
                                "remediation": (
                                    f"`{guard_name}` güvenlik muhafızını geri yükleyin veya eşdeğer merkezi "
                                    "doğrulama katmanı ekleyin."
                                ),
                                "filename": file_path,
                                "path": file_path,
                                "line": anchor_new_ln,
                                "evidence": stripped_rem,
                                "removed_guard": guard_name,
                            }
                        )
                        review_comments.append(
                            {
                                "path": file_path,
                                "line": anchor_new_ln,
                                "severity": "critical",
                                "rule_id": "SNIPER-PR-GUARD-REMOVED-01",
                                "body": comment_body,
                            }
                        )
                        break

            # 1b) SNIPER-PR-GUARD-REMOVED-01: Güvenlik muhafızını devre dışı bırakan ekleme (+ satırı)
            for add_ln, add_text in hunk["added_lines"]:
                for bypass_name, bypass_re, replacement_token in _ADDED_BYPASS_SPECS:
                    if bypass_re.search(add_text):
                        fixed_line = bypass_re.sub(replacement_token, add_text)
                        comment_body = (
                            f"**[SNIPER-PR-GUARD-REMOVED-01]** `{bypass_name}` ile güvenlik doğrulaması devre dışı bırakılıyor:\n"
                            f"```suggestion\n{fixed_line}\n```"
                        )
                        findings.append(
                            {
                                "rule_id": "SNIPER-PR-GUARD-REMOVED-01",
                                "cwe": "CWE-862",
                                "reference": "CWE-862",
                                "severity": "critical",
                                "category": "authz",
                                "title": "Pull Request yamasında güvenlik muhafızı (Authz / SSRF / İmza / Symlink kontrolü) kaldırıldı",
                                "description": (
                                    f"`{file_path}` dosyasına `{bypass_name}` eklenerek mevcut güvenlik "
                                    "kontrolü devre dışı bırakılmış."
                                ),
                                "remediation": (
                                    f"`{bypass_name}` ifadesini kaldırın ve doğrulamayı (`{replacement_token}`) zorunlu tutun."
                                ),
                                "filename": file_path,
                                "path": file_path,
                                "line": add_ln,
                                "evidence": add_text.strip(),
                                "removed_guard": bypass_name,
                            }
                        )
                        review_comments.append(
                            {
                                "path": file_path,
                                "line": add_ln,
                                "severity": "critical",
                                "rule_id": "SNIPER-PR-GUARD-REMOVED-01",
                                "body": comment_body,
                            }
                        )
                        break

            # 2) SNIPER-PR-NEW-SINK-02: Korumasız tehlikeli yürütme/sorgu noktası (Sink) eklenmesi
            for add_ln, add_text in hunk["added_lines"]:
                for sink_name, sink_re in _DANGEROUS_SINK_SPECS:
                    if sink_re.search(add_text):
                        # Eğer hunk'ta açık bir sanitizasyon varsa (shell=True hariç) atla
                        if sink_name != "shell=True" and _HUNK_SANITIZER_RE.search(hunk_added_text):
                            continue
                        suggested_fix = _build_sink_suggestion(add_text, sink_name)
                        comment_body = (
                            f"**[SNIPER-PR-NEW-SINK-02]** Korumasız tehlikeli yürütme/sorgu noktası (`{sink_name}`) tespit edildi. "
                            "Komut/kod enjeksiyonunu önlemek için güvenli alternatif kullanın:\n"
                            f"```suggestion\n{suggested_fix}\n```"
                        )
                        findings.append(
                            {
                                "rule_id": "SNIPER-PR-NEW-SINK-02",
                                "cwe": "CWE-78",
                                "reference": "CWE-78",
                                "severity": "high",
                                "category": "command_data",
                                "title": "Pull Request yamasında korumasız tehlikeli yürütme/sorgu noktası (Sink) eklendi",
                                "description": (
                                    f"`{file_path}:{add_ln}` satırında sanitizasyon olmadan tehlikeli "
                                    f"`{sink_name}` yürütme/sorgu noktası eklendi."
                                ),
                                "remediation": (
                                    f"`{sink_name}` kullanımını kaldırın; parametreli çağrı veya `shell=False` kullanın."
                                ),
                                "filename": file_path,
                                "path": file_path,
                                "line": add_ln,
                                "evidence": add_text.strip(),
                                "sink": sink_name,
                                "suggestion": suggested_fix.strip(),
                            }
                        )
                        review_comments.append(
                            {
                                "path": file_path,
                                "line": add_ln,
                                "severity": "high",
                                "rule_id": "SNIPER-PR-NEW-SINK-02",
                                "body": comment_body,
                            }
                        )
                        break

        # 3) SNIPER-PR-INCOMPLETE-SIBLING-03: Eksik Kardeş Dosya Yaması
        if sibling_map and all_added_text_in_file:
            first_added_ln = (
                file_entry["hunks"][0]["added_lines"][0][0]
                if file_entry["hunks"] and file_entry["hunks"][0]["added_lines"]
                else 1
            )
            for guard_label, guard_re, sink_context_re in _SIBLING_PATCH_GUARD_SPECS:
                if not guard_re.search(all_added_text_in_file):
                    continue
                # Bu PR bu dosyada `guard_label` güvenlik yamasını eklemiş!
                # Kardeş dosyalarda bu muhafızın eksik olup olmadığını kontrol et.
                for sib_path, sib_content in sibling_map.items():
                    if sib_path == file_path or sib_path in patched_file_paths:
                        continue
                    if guard_re.search(sib_content):
                        continue
                    # Kardeş dosyada ya aynı sink bağlamı ya da kaldırılan güvensiz kalıp bulunuyor mu?
                    removed_lines_stripped = [
                        r.strip()
                        for r in all_removed_text_in_file.splitlines()
                        if len(r.strip()) >= 6
                    ]
                    shares_removed_vuln = any(
                        rem_line in sib_content for rem_line in removed_lines_stripped
                    )
                    shares_sink_context = bool(sink_context_re.search(sib_content))
                    if not (shares_removed_vuln or shares_sink_context):
                        continue

                    sib_match = sink_context_re.search(sib_content)
                    sib_line = (
                        sib_content.count("\n", 0, sib_match.start()) + 1
                        if sib_match
                        else 1
                    )
                    sib_evidence = (
                        sib_content.splitlines()[sib_line - 1].strip()
                        if sib_content.splitlines()
                        else sib_path
                    )
                    comment_body = (
                        f"**[SNIPER-PR-INCOMPLETE-SIBLING-03]** `{file_path}` dosyasına `{guard_label}` güvenlik yaması "
                        f"uygulanırken kardeş `{sib_path}` dosyasında aynı zafiyet yamalanmadan bırakılmış:\n"
                        f"```suggestion\n// TODO: Apply {guard_label} parity fix to {sib_path} (line {sib_line})\n```"
                    )
                    findings.append(
                        {
                            "rule_id": "SNIPER-PR-INCOMPLETE-SIBLING-03",
                            "cwe": "CWE-863",
                            "reference": "CWE-863",
                            "severity": "high",
                            "category": "authz",
                            "title": "Eksik Güvenlik Yaması: PR bir dosyayı yamarken kardeş dosyadaki aynı zafiyet açık bırakıldı",
                            "description": (
                                f"PR `{file_path}` dosyasına `{guard_label}` güvenlik korumasını ekliyor ancak "
                                f"kardeş `{sib_path}` dosyası aynı tehlikeli kalıbı korumasız biçimde sürdürüyor."
                            ),
                            "remediation": (
                                f"`{file_path}` dosyasına uygulanan `{guard_label}` güvenlik yamasını kardeş "
                                f"`{sib_path}` dosyasına da simetrik olarak uygulayın."
                            ),
                            "filename": sib_path,
                            "path": sib_path,
                            "patched_file": file_path,
                            "sibling_file": sib_path,
                            "added_guard": guard_label,
                            "line": sib_line,
                            "patched_line": first_added_ln,
                            "evidence": sib_evidence,
                        }
                    )
                    review_comments.append(
                        {
                            "path": file_path,
                            "line": first_added_ln,
                            "severity": "high",
                            "rule_id": "SNIPER-PR-INCOMPLETE-SIBLING-03",
                            "sibling_path": sib_path,
                            "sibling_line": sib_line,
                            "body": comment_body,
                        }
                    )

    return {
        "format": FORMAT_VERSION,
        "files_changed": len(parsed_files),
        "merge_decision": "BLOCK_MERGE" if findings else "APPROVE",
        "finding_count": len(findings),
        "findings": findings,
        "review_comments": review_comments,
    }
