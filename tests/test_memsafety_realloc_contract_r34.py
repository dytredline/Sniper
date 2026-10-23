"""R34: realloc sonrası eski işaretçi yaşam süresi sözleşmesi."""
from __future__ import annotations

import textwrap

import memsafety_c


def _findings(source: str) -> list[memsafety_c.MemFinding]:
    return memsafety_c.analyze_text(textwrap.dedent(source), "realloc_contract.c")


def _lifetime(findings: list[memsafety_c.MemFinding]) -> list[tuple[str, int, bool]]:
    return sorted((finding.kind, finding.line, finding.certain) for finding in findings
                  if finding.kind in {"uaf", "double_free"})


def test_realloc_reassignment_uses_only_the_new_pointer() -> None:
    findings = _findings("""
        #include <stdlib.h>
        void resize(size_t size) {
            char *buffer = malloc(8);
            buffer = realloc(buffer, size);
            if (buffer) buffer[0] = 'x';
            free(buffer);
        }
    """)
    assert _lifetime(findings) == []


def test_positive_size_realloc_failure_keeps_the_old_pointer_live() -> None:
    findings = _findings("""
        #include <stdlib.h>
        void resize(void) {
            char *buffer = malloc(8);
            char *grown = realloc(buffer, 16);
            if (!grown) {
                buffer[0] = 'x';
                free(buffer);
                return;
            }
            free(grown);
        }
    """)
    assert _lifetime(findings) == []


def test_zero_size_null_result_does_not_prove_the_old_pointer_is_live() -> None:
    findings = _findings("""
        #include <stdlib.h>
        void resize(void) {
            char *buffer = malloc(8);
            char *grown = realloc(buffer, 0);
            if (!grown) {
                buffer[0] = 'x';
            }
        }
    """)
    assert _lifetime(findings) == [("uaf", 7, False)]


def test_reallocf_failure_frees_the_old_pointer() -> None:
    findings = _findings("""
        #include <stdlib.h>
        void resize(void) {
            char *buffer = malloc(8);
            char *grown = reallocf(buffer, 16);
            if (!grown) {
                buffer[0] = 'x';
            }
        }
    """)
    assert _lifetime(findings) == [("uaf", 7, True)]


def test_realloc_success_invalidates_every_old_alias() -> None:
    findings = _findings("""
        #include <stdlib.h>
        void resize(size_t size) {
            char *buffer = malloc(8);
            char *alias = buffer;
            char *grown = realloc(buffer, size);
            if (grown) {
                alias[0] = 'x';
            }
            free(grown);
        }
    """)
    assert _lifetime(findings) == [("uaf", 8, True)]


def test_unchecked_realloc_result_makes_old_pointer_a_possible_uaf() -> None:
    findings = _findings("""
        #include <stdlib.h>
        void resize(size_t size) {
            char *buffer = malloc(8);
            char *grown = realloc(buffer, size);
            buffer[0] = 'x';
            free(grown);
        }
    """)
    assert _lifetime(findings) == [("uaf", 6, False)]
