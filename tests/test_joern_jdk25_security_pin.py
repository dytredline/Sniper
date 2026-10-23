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


JDK_ARCHIVE_SHA256 = "69df11a02cfa3ef7d7ca645e03edce6778ec090e100f6ae2b42097865730ac52"
JAVA_SHA256 = "e8201aed7118cbf3a77b9cb308a3cbe135fe97b055968b3b4797162fed1ca818"
JAVA = Path.home() / ".local" / "opt" / "temurin-jdk-25.0.4.1+1" / "bin" / "java"


class JoernJdk25SecurityPinTests(unittest.TestCase):
    def test_installer_and_runtime_pin_have_one_temurin_25_contract(self):
        pin = tool_pins.PINS["joern-jdk"]
        self.assertEqual(pin.version, "25.0.4.1+1")
        self.assertEqual(pin.source_url, "https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4%2B1")
        self.assertIn(JAVA_SHA256, pin.digests["aarch64"])
        self.assertEqual(install_joern.JDK_VERSION, pin.version)
        self.assertEqual(
            install_joern.JDK_ARCHIVES["aarch64"],
            ("OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.4.1_1.tar.gz", JDK_ARCHIVE_SHA256),
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
        self.assertIn('openjdk version "25.0.4.1"', result.stderr)
        self.assertIn("Temurin-25.0.4.1+1", result.stderr)

    def test_operator_pinned_java_still_obeys_25_security_floor_and_major(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            binary = Path(temp) / "java"

            def write_version(version: str, *, vendor: str = "Temurin", build: str | None = None) -> str:
                build = build or version
                binary.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' 'openjdk version \"{version}\" 2026-08-18 LTS' >&2\n"
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
                ("25.0.4.1-ea", "Temurin", "25.0.4.1-ea+1"),
                ("25.0.4.1", "Temurin", "25.0.4.1+1-internal"),
                ("25.0.4.1", "OpenLogic", "25.0.4.1+1"),
            ):
                with self.subTest(version=version, vendor=vendor, build=build):
                    digest = write_version(version, vendor=vendor, build=build)
                    with mock.patch.dict(os.environ, {"SNIPER_JOERN_JDK_SHA256": digest}):
                        with self.assertRaises(tool_pins.VerificationError) as raised:
                            tool_pins.open_pinned("joern-jdk", str(binary))
                    self.assertIn(raised.exception.reason, {"binary_version_unsupported", "binary_version_output_invalid"})

            digest = write_version("25.0.4.1", build="25.0.4.1+1")
            with mock.patch.dict(os.environ, {"SNIPER_JOERN_JDK_SHA256": digest}):
                with tool_pins.open_pinned("joern-jdk", str(binary)) as verified:
                    self.assertEqual(verified.sha256, digest)


if __name__ == "__main__":
    unittest.main()
