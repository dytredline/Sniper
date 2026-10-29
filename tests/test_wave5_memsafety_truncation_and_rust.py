"""Wave-5 Agent 1 — C/C++ Integer Truncation (`SNIPER-MEM-TRUNC-01`) ve
Rust Stride / Uzaktan Panic-DoS (`SNIPER-RUST-STRIDE-01` & `SNIPER-RUST-PANIC-02`) Test Paketi.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import memsafety_c
import memsafety_rust


class TestWave5MemsafetyTruncationAndRust(unittest.TestCase):
    def test_sniper_mem_trunc_01_red_and_green(self) -> None:
        vuln_c = """
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int load_chiapos_table_vuln(const uint8_t *src, uint64_t total_size) {
    uint32_t alloc_len = (uint32_t)total_size;
    uint8_t *buf = (uint8_t *)malloc(alloc_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, src, total_size);
    free(buf);
    return 0;
}
"""
        findings = memsafety_c.analyze_c_memory(vuln_c, "chiapos_table.c")
        trunc_findings = [f for f in findings if f.kind == "integer_truncation_alloc"]
        self.assertEqual(len(trunc_findings), 1, f"SNIPER-MEM-TRUNC-01 bekleniyordu, bulunan: {findings}")
        tf = trunc_findings[0]
        self.assertEqual(tf.cwe, "CWE-190")
        self.assertEqual(tf.severity, "critical")
        self.assertEqual(
            tf.title,
            "64-bit uzunluk değerinin 32-bit tamsayıya daraltılması (Integer Truncation) sonrası yığın taşması",
        )
        self.assertIn("SNIPER-MEM-TRUNC-01", tf.evidence)

        vuln_cpp = """
#include <cstdint>
#include <cstring>

uint8_t *alloc_plot_entries_vuln(uint64_t total_size, const uint8_t *src) {
    uint32_t alloc_len = static_cast<uint32_t>(total_size);
    uint8_t *buf = new uint8_t[alloc_len];
    memcpy(buf, src, total_size);
    return buf;
}
"""
        cpp_ext = memsafety_c.detect_extended_c_memory_hazards(vuln_cpp, "chiapos_table.cpp")
        self.assertTrue(any(f.kind == "integer_truncation_alloc" and f.cwe == "CWE-190" for f in cpp_ext))

        safe_c = """
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int load_chiapos_table_safe(const uint8_t *src, uint64_t total_size) {
    if (total_size > UINT32_MAX) {
        return -1;
    }
    uint32_t alloc_len = (uint32_t)total_size;
    uint8_t *buf = (uint8_t *)malloc(alloc_len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, src, alloc_len);
    free(buf);
    return 0;
}
"""
        safe_findings = memsafety_c.analyze_c_memory(safe_c, "chiapos_table_safe.c")
        self.assertEqual(safe_findings, [], f"Güvenli kodda yanlış pozitif üretildi: {safe_findings}")

    def test_sniper_rust_stride_01_red_and_green(self) -> None:
        vuln_stride_rs = """
pub fn copy_bgra_frame_vuln(src: &[u8], stride: usize, w: usize, h: usize) -> Vec<u8> {
    let row_bytes = w * 4;
    let required = stride * (h - 1) + row_bytes;
    if src.len() < required {
        return Vec::new();
    }
    let mut dst = vec![0u8; row_bytes * h];
    for row in 0..h {
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr().add(row * stride),
                dst.as_mut_ptr().add(row * row_bytes),
                row_bytes,
            );
        }
    }
    dst
}

pub fn copy_nv12_planes_vuln(
    y: &[u8],
    y_stride: usize,
    uv: &[u8],
    uv_stride: usize,
    w: usize,
    h: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; w * h + w * (h / 2)];
    for row in 0..h {
        unsafe {
            std::ptr::copy_nonoverlapping(
                y.as_ptr().add(row * y_stride),
                out.as_mut_ptr().add(row * w),
                w,
            );
        }
    }
    for row in 0..(h / 2) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                uv.as_ptr().add(row * uv_stride),
                out.as_mut_ptr().add(w * h + row * w),
                w,
            );
        }
    }
    out
}
"""
        audit_red = memsafety_rust.audit_rust_binary_parser_and_stride_hazards(
            vuln_stride_rs,
            filename="videotoolbox.rs",
        )
        self.assertEqual(audit_red["format"], "sniper-rust-parser-stride-audit/1")
        stride_hits = [f for f in audit_red["findings"] if f["rule_id"] == "SNIPER-RUST-STRIDE-01"]
        self.assertEqual(len(stride_hits), 2, f"İki SNIPER-RUST-STRIDE-01 bulgusu bekleniyordu: {audit_red}")
        for hit in stride_hits:
            self.assertEqual(hit["cwe"], "CWE-190")
            self.assertEqual(hit["severity"], "high")
            self.assertEqual(hit["category"], "memory_safety")

        safe_stride_rs = """
pub fn copy_nv12_planes_safe(
    y: &[u8],
    y_stride: usize,
    uv: &[u8],
    uv_stride: usize,
    w: usize,
    h: usize,
) -> Option<Vec<u8>> {
    if w == 0 || h == 0 || y_stride < w || uv_stride < w {
        return None;
    }
    let uv_h = h / 2;
    let y_req = y_stride.checked_mul(h - 1)?.checked_add(w)?;
    let uv_req = uv_stride.checked_mul(uv_h.saturating_sub(1))?.checked_add(w)?;
    if y.len() < y_req || uv.len() < uv_req {
        return None;
    }
    let y_out_len = w.checked_mul(h)?;
    let uv_out_len = w.checked_mul(uv_h)?;
    let total_out = y_out_len.checked_add(uv_out_len)?;
    let mut out = vec![0u8; total_out];
    for row in 0..h {
        let src_off = row.checked_mul(y_stride)?;
        let dst_off = row.checked_mul(w)?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                y.as_ptr().add(src_off),
                out.as_mut_ptr().add(dst_off),
                w,
            );
        }
    }
    for row in 0..uv_h {
        let src_off = row.checked_mul(uv_stride)?;
        let dst_off = y_out_len.checked_add(row.checked_mul(w)?)?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                uv.as_ptr().add(src_off),
                out.as_mut_ptr().add(dst_off),
                w,
            );
        }
    }
    Some(out)
}
"""
        audit_green = memsafety_rust.audit_rust_binary_parser_and_stride_hazards(
            safe_stride_rs,
            filename="videotoolbox_safe.rs",
        )
        self.assertEqual(audit_green["finding_count"], 0, f"Güvenli stride kodunda yanlış pozitif: {audit_green}")

    def test_sniper_rust_panic_02_red_and_green(self) -> None:
        vuln_parser_rs = """
use std::convert::TryInto;

pub fn parse_packet(data: &[u8]) -> Result<&[u8], &'static str> {
    let len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let payload = &data[4..4 + len];
    Ok(payload)
}
"""
        audit_red = memsafety_rust.audit_rust_binary_parser_and_stride_hazards(
            vuln_parser_rs,
            filename="parser.rs",
        )
        panic_hits = [f for f in audit_red["findings"] if f["rule_id"] == "SNIPER-RUST-PANIC-02"]
        self.assertEqual(len(panic_hits), 1, f"SNIPER-RUST-PANIC-02 bekleniyordu: {audit_red}")
        self.assertEqual(panic_hits[0]["cwe"], "CWE-248")
        self.assertEqual(panic_hits[0]["severity"], "high")
        self.assertEqual(panic_hits[0]["category"], "dos")

        safe_parser_rs = """
use std::convert::TryInto;

pub fn parse_packet(data: &[u8]) -> Result<&[u8], &'static str> {
    let hdr = data.get(0..4).ok_or("truncated header")?;
    let raw_arr: [u8; 4] = hdr.try_into().map_err(|_| "bad header")?;
    let len = u32::from_be_bytes(raw_arr) as usize;
    let end = 4usize.checked_add(len).ok_or("length overflow")?;
    let payload = data.get(4..end).ok_or("truncated payload")?;
    Ok(payload)
}
"""
        audit_green = memsafety_rust.audit_rust_binary_parser_and_stride_hazards(
            safe_parser_rs,
            filename="parser_safe.rs",
        )
        self.assertEqual(audit_green["finding_count"], 0, f"Güvenli ayrıştırıcıda yanlış pozitif: {audit_green}")


if __name__ == "__main__":
    unittest.main()
