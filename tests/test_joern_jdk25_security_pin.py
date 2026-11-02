from __future__ import annotations

import os
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import tool_pins
from scripts import install_joern


JDK_ARCHIVE_SHA256 = "bb5b2ded252f21c6090cf780b0a408ad0d83bbb557e702955643557f13231880"
JAVA_SHA256 = "9773d145ea1adce8da70e0f9e87ecddad5446f7e5ac05b44a95cecf902b42cb9"
JAVA = Path(__file__).resolve().parents[2] / "runtimes" / "jdk" / "25.0.5+8" / "bin" / "java"


class JoernJdk25SecurityPinTests(unittest.TestCase):
    def test_installer_and_runtime_pin_have_one_temurin_25_contract(self):
        pin = tool_pins.PINS["joern-jdk"]
        self.assertEqual(pin.version, "25.0.5+8")
        self.assertEqual(pin.source_url, "https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8")
        self.assertIn(JAVA_SHA256, pin.digests["aarch64"])
        self.assertEqual(install_joern.JDK_VERSION, pin.version)
        self.assertEqual(
            install_joern.JDK_ARCHIVES["aarch64"],
            ("OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.5_8.tar.gz", JDK_ARCHIVE_SHA256),
        )

    @unittest.skipUnless(JAVA.is_file(), "yerel Temurin 25 kanıt ikilisi yok")
    def test_real_java_binary_is_pinned_and_runs_from_verified_descriptor(self):
        with mock.patch.dict(os.environ, {"SNIPER_JOERN_JDK_SHA256": ""}), \
                mock.patch.object(tool_pins, "machine", return_value="aarch64"):
            status = tool_pins.pin_status("joern-jdk", str(JAVA))
            self.assertEqual((status["state"], status["reason_code"]), ("pinned", "digest_matches_pin"))
            with tool_pins.open_pinned("joern-jdk", str(JAVA)) as runtime:
                result = subprocess.run(
                    [runtime.argv0, "-version"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    **runtime.popen_kwargs(env={"PATH": "/usr/bin:/bin"}),
                )
        self.assertIn('openjdk version "25.0.5"', result.stderr)
        self.assertIn("Temurin-25.0.5+8", result.stderr)

    def test_operator_pinned_java_still_obeys_25_security_floor_and_major(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            binary = Path(temp) / "java"

            def write_version(version: str, *, vendor: str = "Temurin", build: str | None = None) -> str:
                build = build or version
                binary.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' 'openjdk version \"{version}\" 2026-10-20 LTS' >&2\n"
                    f"printf '%s\\n' 'OpenJDK Runtime Environment {vendor}-{build} (build {build}-LTS)' >&2\n"
                    f"printf '%s\\n' 'OpenJDK 64-Bit Server VM {vendor}-{build} "
                    f"(build {build}-LTS, mixed mode, sharing)' >&2\n",
                    encoding="utf-8",
                )
                binary.chmod(0o700)
                return hashlib.sha256(binary.read_bytes()).hexdigest()

            for version, vendor, build in (
                ("25.0.3", "Temurin", "25.0.3+9"),
                ("21.0.12.1", "Temurin", "21.0.12.1+1"),
                ("25.0.5-ea", "Temurin", "25.0.5-ea+8"),
                ("25.0.5", "Temurin", "25.0.5+8-internal"),
                ("25.0.5", "OpenLogic", "25.0.5+8"),
            ):
                with self.subTest(version=version, vendor=vendor, build=build):
                    digest = write_version(version, vendor=vendor, build=build)
                    with mock.patch.dict(os.environ, {"SNIPER_JOERN_JDK_SHA256": digest}):
                        with self.assertRaises(tool_pins.VerificationError) as raised:
                            tool_pins.open_pinned("joern-jdk", str(binary))
                    self.assertIn(raised.exception.reason, {"binary_version_unsupported", "binary_version_output_invalid"})

            digest = write_version("25.0.5", build="25.0.5+8")
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_JDK_SHA256": digest}):
                with tool_pins.open_pinned("joern-jdk", str(binary)) as verified:
                    self.assertEqual(verified.sha256, digest)


if __name__ == "__main__":
    unittest.main()
