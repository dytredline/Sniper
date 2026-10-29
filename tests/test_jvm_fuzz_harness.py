"""Fail-closed Jazzer harness synthesis for one local Java parser-style method."""
from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asan_project_proof  # noqa: E402


BYTE_SOURCE = textwrap.dedent(
    """
    package com.acme.codec;
    public final class PacketDecoder {
        public static byte[] decode(byte[] input) {
            return input;
        }
    }
    """
).strip() + "\n"


def synthesize(source: str, symbol: str = "PacketDecoder#decode(byte[])") -> dict:
    return asan_project_proof.synthesize_sanitizer_fuzz_harness(
        {
            "file": "src/main/java/com/acme/codec/PacketDecoder.java",
            "reference": "CWE-20",
            "symbol": symbol,
        },
        source_snippet=source,
    )


class JvmFuzzHarnessTests(unittest.TestCase):
    def test_byte_array_target_is_bound_to_exact_package_class_and_method(self) -> None:
        result = synthesize(BYTE_SOURCE)

        self.assertEqual(result["format"], "sniper-sanitizer-fuzz-harness/1")
        self.assertEqual(result["language"], "java")
        self.assertEqual(result["target_class"], "com.acme.codec.PacketDecoder")
        self.assertEqual(result["target_method"], "decode")
        self.assertEqual(result["target_signature"], "byte[]")
        self.assertEqual(result["harness_class"], "com.acme.codec.SniperJazzerHarness")
        self.assertEqual(result["source_sha256"], hashlib.sha256(BYTE_SOURCE.encode("utf-8")).hexdigest())
        self.assertIn("PacketDecoder.decode(data);", result["harness_code"])
        self.assertIn("fuzzerTestOneInput(byte[] data)", result["harness_code"])
        self.assertIn("--target_class=com.acme.codec.SniperJazzerHarness", result["compile_command"])
        self.assertEqual(result["execution"], "not_run")

    def test_string_target_uses_deterministic_utf8_input(self) -> None:
        source = textwrap.dedent(
            """
            package com.acme.codec;
            public final class PacketDecoder {
                public static String normalize(String input) { return input.trim(); }
            }
            """
        )
        result = synthesize(source, "com.acme.codec.PacketDecoder#normalize(String)")

        self.assertEqual(result["target_signature"], "String")
        self.assertIn("StandardCharsets.UTF_8", result["harness_code"])
        self.assertIn("PacketDecoder.normalize(input);", result["harness_code"])

    def test_comments_and_string_literals_cannot_supply_a_decoy_method(self) -> None:
        source = textwrap.dedent(
            '''
            package com.acme.codec;
            public final class PacketDecoder {
                // public static byte[] decode(byte[] data) { return data; }
                private static final String DECOY = "public static byte[] decode(byte[] data) { }";
                public static String normalize(String input) { return input; }
            }
            '''
        )

        with self.assertRaisesRegex(asan_project_proof.AsanProjectProofError, "decode"):
            synthesize(source)
        result = synthesize(source, "PacketDecoder#normalize(String)")
        self.assertEqual((result["target_method"], result["target_signature"]), ("normalize", "String"))

    def test_overload_without_signature_is_ambiguous_but_exact_signature_resolves(self) -> None:
        source = textwrap.dedent(
            """
            package com.acme.codec;
            public final class PacketDecoder {
                public static byte[] decode(byte[] input) { return input; }
                public static String decode(String input) { return input; }
            }
            """
        )

        with self.assertRaisesRegex(asan_project_proof.AsanProjectProofError, "belirsiz"):
            synthesize(source, "PacketDecoder#decode")
        result = synthesize(source, "PacketDecoder#decode(byte[])")
        self.assertEqual(result["target_signature"], "byte[]")

    def test_private_or_instance_methods_fail_closed(self) -> None:
        private = BYTE_SOURCE.replace("public static byte[] decode", "private static byte[] decode")
        instance = BYTE_SOURCE.replace("public static byte[] decode", "public byte[] decode")

        with self.assertRaisesRegex(asan_project_proof.AsanProjectProofError, "public static"):
            synthesize(private)
        with self.assertRaisesRegex(asan_project_proof.AsanProjectProofError, "public static"):
            synthesize(instance)

    def test_generated_byte_harness_compiles_with_local_javac(self) -> None:
        javac = shutil.which("javac")
        if javac is None:
            self.skipTest("javac yok")
        result = synthesize(BYTE_SOURCE)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "com" / "acme" / "codec"
            package.mkdir(parents=True)
            target = package / "PacketDecoder.java"
            harness = package / result["harness_filename"]
            target.write_text(BYTE_SOURCE, encoding="utf-8")
            harness.write_text(result["harness_code"], encoding="utf-8")
            completed = subprocess.run(
                [javac, "-d", str(root / "classes"), str(target), str(harness)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
